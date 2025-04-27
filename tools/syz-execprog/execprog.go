// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// execprog executes a single program or a set of programs
// and optionally prints information about execution.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/host"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/ipc/ipcconfig"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/tool"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

var (
	flagOS        = flag.String("os", runtime.GOOS, "target os")
	flagArch      = flag.String("arch", runtime.GOARCH, "target arch")
	flagCoverFile = flag.String("coverfile", "", "write coverage to the file")
	flagRepeat    = flag.Int("repeat", 1, "repeat execution that many times (0 for infinite loop)")
	flagProcs     = flag.Int("procs", 2*runtime.NumCPU(), "number of parallel processes to execute programs")
	flagOutput    = flag.Bool("output", false, "write programs and results to stdout")
	flagHints     = flag.Bool("hints", false, "do a hints-generation run")
	flagEnable    = flag.String("enable", "none", "enable only listed additional features")
	flagDisable   = flag.String("disable", "none", "enable all additional features except listed")

	// added by SyzGPT
	flagSemantic   = flag.Bool("semantic", false, "semantic mode: compare the coverage of prog and prog.rev")
	flagProgDir    = flag.String("progdir", "", "specify a dir that includes progs to be calc")
	flagNoDumpCall = flag.Bool("nodumpcall", false, "do not dump call level coverage to save space")
	flagMaxRetry   = flag.Int("retry", 10, "max retry for execution failure (default 10, use 2 for semantic mode)")
	// end

	// The following flag is only kept to let syzkaller remain compatible with older execprog versions.
	// In order to test incoming patches or perform bug bisection, syz-ci must use the exact syzkaller
	// version that detected the bug (as descriptions and syntax could've already been changed), and
	// therefore it must be able to invoke older versions of syz-execprog.
	// Unfortunately there's no clean way to drop that flag from newer versions of syz-execprog. If it
	// were false by default, it would be easy - we could modify `instance.ExecprogCmd` only to pass it
	// when it's true - which would never be the case in the newer versions (this is how we got rid of
	// fault injection args). But the collide flag was true by default, so it must be passed by value
	// (-collide=%v). The least kludgy solution is to silently accept this flag also in the newer versions
	// of syzkaller, but do not process it, as there's no such functionality anymore.
	// Note, however, that we do not have to do the same for `syz-prog2c`, as `collide` was there false
	// by default.
	flagCollide = flag.Bool("collide", false, "(DEPRECATED) collide syscalls to provoke data races")
)

// added by SyzGPT
// Global Map, storing coverage of [origin_prog, reverse_prog]
var coverRecord map[string][3]int // cov0_of_origin, cov1_of_reverse, prog_line_num
var coverRecordMu sync.Mutex
var execFailCnt int

// end

func main() {
	coverRecord = make(map[string][3]int)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: execprog [flags] file-with-programs-or-corpus.db+\n")
		flag.PrintDefaults()
		csource.PrintAvailableFeaturesFlags()
	}
	defer tool.Init()()
	if *flagProgDir == "" && len(flag.Args()) == 0 {
		flag.Usage()
		os.Exit(1)
	}
	if *flagCoverFile != "" {
		covDir, _ := filepath.Split(*flagCoverFile)
		if covDir != "" {
			os.MkdirAll(covDir, 0644)
		}
	}
	featuresFlags, err := csource.ParseFeaturesFlags(*flagEnable, *flagDisable, true)
	if err != nil {
		log.Fatalf("%v", err)
	}

	target, err := prog.GetTarget(*flagOS, *flagArch)
	if err != nil {
		log.Fatalf("%v", err)
	}
	// added by SyzGPT
	// we consider executing a prog in reverse order as executing each syscall separately
	var progs []*prog.Prog
	var reverseProgs []*prog.Prog
	var filePathList []string
	var reverseFilePathList []string
	var fileNameList []string
	var reverseFileNameList []string
	if *flagProgDir != "" {
		// load progs from directory
		files, errdir := os.ReadDir(*flagProgDir)
		if errdir != nil {
			log.Fatalf("%v", err)
		}
		for _, file := range files {
			if file.IsDir() {
				continue
			}
			if *flagSemantic {
				if strings.HasSuffix(file.Name(), ".rev") {
					reverseFilePathList = append(reverseFilePathList, filepath.Join(*flagProgDir, file.Name()))
					reverseFileNameList = append(reverseFileNameList, file.Name())
					index := strings.LastIndex(file.Name(), ".rev")
					origName := file.Name()[:index]
					fileNameList = append(fileNameList, origName)
					filePathList = append(filePathList, filepath.Join(*flagProgDir, origName))
				}
			} else {
				fileNameList = append(fileNameList, file.Name())
				filePathList = append(filePathList, filepath.Join(*flagProgDir, file.Name()))
			}
		}
	} else {
		// load progs from command line
		for _, filePath := range flag.Args() {
			fileName := filepath.Base(filePath)
			fileNameList = append(fileNameList, fileName)
			filePathList = append(filePathList, filePath)
			if *flagSemantic {
				reverseFilePath := filePath + ".rev"
				reverseFilePathList = append(reverseFilePathList, reverseFilePath)
				reverseFileNameList = append(reverseFileNameList, filepath.Base(reverseFilePath))
			}
		}
	}
	progs = loadPrograms(target, filePathList)
	reverseProgs = loadPrograms(target, reverseFilePathList)
	if len(progs) == 0 && len(reverseProgs) == 0 {
		return
	} else {
		log.Logf(0, "[success] load %d progs and %d rev_progs", len(progs), len(reverseProgs))
	}
	// end

	features, err := host.Check(target)
	if err != nil {
		log.Fatalf("%v", err)
	}
	if *flagOutput {
		for _, feat := range features.Supported() {
			log.Logf(0, "%-24v: %v", feat.Name, feat.Reason)
		}
	}
	if *flagCollide {
		log.Logf(0, "note: setting -collide to true is deprecated now and has no effect")
	}
	config, execOpts := createConfig(target, features, featuresFlags)
	if err = host.Setup(target, features, featuresFlags, config.Executor); err != nil {
		log.Fatal(err)
	}
	var gateCallback func()
	if features[host.FeatureLeak].Enabled {
		gateCallback = func() {
			output, err := osutil.RunCmd(10*time.Minute, "", config.Executor, "leak")
			if err != nil {
				os.Stdout.Write(output)
				os.Exit(1)
			}
		}
	}
	ctx := &Context{
		progs:    progs,
		progFns:  fileNameList,
		config:   config,
		execOpts: execOpts,
		gate:     ipc.NewGate(2**flagProcs, gateCallback),
		shutdown: make(chan struct{}),
		repeat:   *flagRepeat,
	}
	var wg sync.WaitGroup
	wg.Add(*flagProcs)
	for p := 0; p < *flagProcs; p++ {
		pid := p
		go func() {
			defer wg.Done()
			ctx.run(pid, 0)
		}()
	}
	osutil.HandleInterrupts(ctx.shutdown)
	wg.Wait()

	// added by SyzGPT
	if *flagSemantic {
		// added by SyzGPT
		revCtx := &Context{
			progs:    reverseProgs,
			progFns:  reverseFileNameList,
			config:   config,
			execOpts: execOpts,
			gate:     ipc.NewGate(2**flagProcs, gateCallback),
			shutdown: make(chan struct{}),
			repeat:   *flagRepeat,
		}
		// end
		var revWg sync.WaitGroup
		revWg.Add(*flagProcs)
		for p := 0; p < *flagProcs; p++ {
			pid := p
			go func() {
				defer revWg.Done()
				revCtx.run(pid, 1)
			}()
		}
		osutil.HandleInterrupts(revCtx.shutdown)
		revWg.Wait()
	}
	// end

	// added by SyzGPT
	if *flagSemantic && *flagCoverFile != "" {
		coverRecordFile := fmt.Sprintf("%s_Evaluation_Results", *flagCoverFile)
		err := saveToFile(coverRecordFile)
		if err != nil {
			log.Logf(0, "failed to save coverRecord.")
			log.Fatal(err)
			return
		}

		log.Logf(0, "context effectiveness evaluation results saved to %s", coverRecordFile)
	}
	// end
}

// added by SyzGPT
// save coverRecord to file
func saveToFile(fileName string) error {
	file, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer file.Close()

	// define the counters
	// we regard a prog with cover greater than reverse cover as context effective (win)
	totalProgCnt := 0
	totalWinCnt := 0
	totalEqualCnt := 0
	totalLoseCnt := 0

	// we do take the prog with length of 1 into account, as they have no context
	oneLineProgCnt := 0
	oneLineWinCnt := 0
	oneLineEqualCnt := 0
	oneLineLoseCnt := 0

	// write the header
	line := "Program Name" + "," + "Cover" + "," + "ReverseCover" + "," + "Program Length" + "\n"
	if _, err := file.WriteString(line); err != nil {
		return err
	}
	for key, value := range coverRecord {
		cov0 := value[0]
		cov1 := value[1]
		progLength := value[2]

		totalProgCnt += 1
		if progLength == 1 {
			oneLineProgCnt += 1
		}
		if cov0 > cov1 {
			totalWinCnt += 1
			if progLength == 1 {
				oneLineWinCnt += 1
			}
		} else if cov0 == cov1 {
			totalEqualCnt += 1
			if progLength == 1 {
				oneLineEqualCnt += 1
			}
		} else {
			totalLoseCnt += 1
			if progLength == 1 {
				oneLineLoseCnt += 1
			}
		}

		line := key + "," + strconv.Itoa(cov0) + "," + strconv.Itoa(cov1) + "," + strconv.Itoa(progLength) + "\n"
		if _, err := file.WriteString(line); err != nil {
			return err
		}
	}

	// OCER: Overall Context Effectiveness Rate
	// ECER: Exclusive Context Effectiveness Rate
	// CER: Context Effectiveness Rate
	OCER := float64(totalWinCnt) / float64(totalProgCnt) * 100
	ECER := float64(totalWinCnt-oneLineWinCnt) / float64(totalProgCnt-oneLineWinCnt) * 100
	CER := float64(totalWinCnt-oneLineWinCnt) / float64(totalProgCnt) * 100
	line = "\nEvaluation Results of Contextual Effectiveness:\n" +
		"Execution Fails:" + strconv.Itoa(execFailCnt) + "\n" +
		"Total Progs: " + strconv.Itoa(totalProgCnt) + "\n" +
		"Total Win: " + strconv.Itoa(totalWinCnt) + "\n" +
		"Total Equal: " + strconv.Itoa(totalEqualCnt) + "\n" +
		"Total Lose: " + strconv.Itoa(totalLoseCnt) + "\n\n" +
		"One-line Progs:" + strconv.Itoa(oneLineProgCnt) + "\n" +
		"One-line Win:" + strconv.Itoa(oneLineWinCnt) + "\n" +
		"One-line Equal:" + strconv.Itoa(oneLineEqualCnt) + "\n" +
		"One-line Lose:" + strconv.Itoa(oneLineLoseCnt) + "\n\n" +
		"Overall Context Effective Rate (OCER): " + fmt.Sprintf("%.2f%%", OCER) + "\n" +
		"Exclusive Context Effective Rate (ECER): " + fmt.Sprintf("%.2f%%", ECER) + "\n" +
		"Context Effective Rate (CER): " + fmt.Sprintf("%.2f%%", CER) + "\n"
	if _, err := file.WriteString(line); err != nil {
		return err
	}
	return nil
}

func setCoverRecord(fileName string, value1, value2, progLength int) {
	coverRecordMu.Lock()
	defer coverRecordMu.Unlock()

	coverRecord[fileName] = [3]int{value1, value2, progLength}
}

func getCoverRecord(fileName string) (bool, int, int) {
	coverRecordMu.Lock()
	defer coverRecordMu.Unlock()

	values, ok := coverRecord[fileName]
	if ok {
		return ok, values[0], values[1]
	}

	return ok, 0, 0
}

// end

type Context struct {
	progs     []*prog.Prog
	progFns   []string
	config    *ipc.Config
	execOpts  *ipc.ExecOpts
	gate      *ipc.Gate
	shutdown  chan struct{}
	logMu     sync.Mutex
	posMu     sync.Mutex
	repeat    int
	pos       int
	lastPrint time.Time
}

func (ctx *Context) run(pid int, covType int) {
	env, err := ipc.MakeEnv(ctx.config, pid)
	if err != nil {
		log.Fatalf("failed to create ipc env: %v", err)
	}
	defer env.Close()
	for {
		select {
		case <-ctx.shutdown:
			return
		default:
		}
		idx := ctx.getProgramIndex()
		if ctx.repeat > 0 && idx >= len(ctx.progs)*ctx.repeat {
			return
		}
		entry := ctx.progs[idx%len(ctx.progs)]
		ctx.execute(pid, env, entry, idx, covType)
	}
}

func (ctx *Context) execute(pid int, env *ipc.Env, p *prog.Prog, progIndex int, covType int) {
	// Limit concurrency window.
	ticket := ctx.gate.Enter()
	defer ctx.gate.Leave(ticket)

	callOpts := ctx.execOpts
	if *flagOutput {
		ctx.logProgram(pid, p, callOpts)
	}
	// This mimics the syz-fuzzer logic. This is important for reproduction.
	for try := 0; ; try++ {
		output, info, hanged, err := env.Exec(callOpts, p)
		if err != nil && err != prog.ErrExecBufferTooSmall {
			if try > *flagMaxRetry {
				if *flagProgDir != "" {
					log.Logf(0, "executor failed %v times: %v\n%s", try, err, output)
					log.Logf(0, "[semantic dump mode] the %d prog failed, skip it", progIndex)
					execFailCnt += 1
					break
				} else {
					log.Fatalf("executor failed %v times: %v\n%s", try, err, output)
				}
			}
			// Don't print err/output in this case as it may contain "SYZFAIL" and we want to fail yet.
			log.Logf(1, "executor failed, retrying")
			time.Sleep(time.Second)
			continue
		}
		if ctx.config.Flags&ipc.FlagDebug != 0 || err != nil {
			log.Logf(0, "result: hanged=%v err=%v\n\n%s", hanged, err, output)
		}
		if info != nil {
			ctx.printCallResults(info)
			if *flagHints {
				ctx.printHints(p, info)
			}
			if *flagCoverFile != "" {
				var covFile string
				if *flagProgDir != "" {
					covFile = fmt.Sprintf("%s_%s", *flagCoverFile, ctx.progFns[progIndex%len(ctx.progFns)])
				} else {
					covFile = fmt.Sprintf("%s_prog%d", *flagCoverFile, progIndex)
				}
				// log.Logf(0, "[debug] dumpCoverage for %s", covFile)
				ctx.dumpCoverage(covFile, info, covType)
			}
		} else {
			log.Logf(1, "RESULT: no calls executed")
		}
		break
	}
}

func (ctx *Context) logProgram(pid int, p *prog.Prog, callOpts *ipc.ExecOpts) {
	data := p.Serialize()
	ctx.logMu.Lock()
	log.Logf(0, "executing program %v:\n%s", pid, data)
	ctx.logMu.Unlock()
}

func (ctx *Context) printCallResults(info *ipc.ProgInfo) {
	for i, inf := range info.Calls {
		if inf.Flags&ipc.CallExecuted == 0 {
			continue
		}
		flags := ""
		if inf.Flags&ipc.CallFinished == 0 {
			flags += " unfinished"
		}
		if inf.Flags&ipc.CallBlocked != 0 {
			flags += " blocked"
		}
		if inf.Flags&ipc.CallFaultInjected != 0 {
			flags += " faulted"
		}
		log.Logf(1, "CALL %v: signal %v, coverage %v errno %v%v",
			i, len(inf.Signal), len(inf.Cover), inf.Errno, flags)
	}
}

func (ctx *Context) printHints(p *prog.Prog, info *ipc.ProgInfo) {
	ncomps, ncandidates := 0, 0
	for i := range p.Calls {
		if *flagOutput {
			fmt.Printf("call %v:\n", i)
		}
		comps := info.Calls[i].Comps
		for v, args := range comps {
			ncomps += len(args)
			if *flagOutput {
				fmt.Printf("comp 0x%x:", v)
				for arg := range args {
					fmt.Printf(" 0x%x", arg)
				}
				fmt.Printf("\n")
			}
		}
		p.MutateWithHints(i, comps, func(p *prog.Prog) {
			ncandidates++
			if *flagOutput {
				log.Logf(1, "PROGRAM:\n%s", p.Serialize())
			}
		})
	}
	log.Logf(0, "ncomps=%v ncandidates=%v", ncomps, ncandidates)
}

func (ctx *Context) dumpCallCoverage(coverFile string, info *ipc.CallInfo) {
	if len(info.Cover) == 0 {
		return
	}
	buf := new(bytes.Buffer)
	for _, pc := range info.Cover {
		fmt.Fprintf(buf, "0x%x\n", cover.RestorePC(pc, 0xffffffff))
	}
	err := osutil.WriteFile(coverFile, buf.Bytes())
	if err != nil {
		log.Fatalf("failed to write coverage file: %v", err)
	}
}

func (ctx *Context) dumpCoverage(coverFile string, info *ipc.ProgInfo, covType int) {
	for i, inf := range info.Calls {
		log.Logf(0, "call #%v: signal %v, coverage %v", i, len(inf.Signal), len(inf.Cover))
		if !*flagNoDumpCall && !*flagSemantic {
			ctx.dumpCallCoverage(fmt.Sprintf("%v.%v", coverFile, i), &inf)
		}
	}

	// added by SyzGPT
	totalMap := make(map[string]int)
	covNum := 0
	progLength := 0
	for _, inf := range info.Calls {
		progLength += 1
		for _, pc := range inf.Cover {
			newPC := fmt.Sprintf("0x%x", cover.RestorePC(pc, 0xffffffff))
			if _, ok := totalMap[newPC]; !ok {
				totalMap[newPC] = 1
				covNum += 1
			}
		}
	}

	// record pc coverage to global map
	recordKey := strings.TrimSuffix(coverFile, ".rev")
	ok, cov0, cov1 := getCoverRecord(recordKey)
	if covType == 0 {
		if ok {
			log.Logf(0, "cover map error, repeated prog. %s", recordKey)
		} else {
			cov0 = covNum
			setCoverRecord(recordKey, cov0, cov1, progLength)
		}
	} else {
		if ok {
			cov1 = covNum
			setCoverRecord(recordKey, cov0, cov1, progLength)
		} else {
			log.Logf(0, "cover map error: non-existed origin prog. %s", recordKey)
		}
	}

	// make a buffer to output
	buf := new(bytes.Buffer)
	for pc := range totalMap {
		fmt.Fprintf(buf, "%s\n", pc)
	}

	// write cover pcs to file
	err := osutil.WriteFile(coverFile+".total", buf.Bytes())
	if err != nil {
		log.Fatalf("SyzGPT failed to write total coverage file: %v", err)
	}
	log.Logf(0, "[debug] total coverage done for the %d prog %s", ctx.pos, coverFile)
	// end

	log.Logf(0, "extra: signal %v, coverage %v", len(info.Extra.Signal), len(info.Extra.Cover))
	ctx.dumpCallCoverage(fmt.Sprintf("%v.extra", coverFile), &info.Extra)
}

func (ctx *Context) getProgramIndex() int {
	ctx.posMu.Lock()
	idx := ctx.pos
	ctx.pos++
	if idx%len(ctx.progs) == 0 && time.Since(ctx.lastPrint) > 5*time.Second {
		log.Logf(0, "executed programs: %v", idx)
		ctx.lastPrint = time.Now()
	}
	ctx.posMu.Unlock()
	return idx
}

func loadPrograms(target *prog.Target, files []string) []*prog.Prog {
	var progs []*prog.Prog
	for _, fn := range files {
		if corpus, err := db.Open(fn, false); err == nil {
			for _, rec := range corpus.Records {
				p, err := target.Deserialize(rec.Val, prog.NonStrict)
				if err != nil {
					continue
				}
				progs = append(progs, p)
			}
			continue
		}
		data, err := os.ReadFile(fn)
		if err != nil {
			log.Fatalf("failed to read log file: %v", err)
		}
		for _, entry := range target.ParseLog(data) {
			progs = append(progs, entry.P)
		}
	}
	log.Logf(0, "parsed %v programs", len(progs))
	return progs
}

func createConfig(target *prog.Target, features *host.Features, featuresFlags csource.Features) (
	*ipc.Config, *ipc.ExecOpts) {
	config, execOpts, err := ipcconfig.Default(target)
	if err != nil {
		log.Fatalf("%v", err)
	}
	if config.Flags&ipc.FlagSignal != 0 {
		execOpts.Flags |= ipc.FlagCollectCover
	}
	if *flagCoverFile != "" {
		config.Flags |= ipc.FlagSignal
		execOpts.Flags |= ipc.FlagCollectCover
		execOpts.Flags &^= ipc.FlagDedupCover
	}
	if *flagHints {
		if execOpts.Flags&ipc.FlagCollectCover != 0 {
			execOpts.Flags ^= ipc.FlagCollectCover
		}
		execOpts.Flags |= ipc.FlagCollectComps
	}
	if features[host.FeatureExtraCoverage].Enabled {
		config.Flags |= ipc.FlagExtraCover
	}
	if features[host.FeatureDelayKcovMmap].Enabled {
		config.Flags |= ipc.FlagDelayKcovMmap
	}
	if featuresFlags["tun"].Enabled && features[host.FeatureNetInjection].Enabled {
		config.Flags |= ipc.FlagEnableTun
	}
	if featuresFlags["net_dev"].Enabled && features[host.FeatureNetDevices].Enabled {
		config.Flags |= ipc.FlagEnableNetDev
	}
	if featuresFlags["net_reset"].Enabled {
		config.Flags |= ipc.FlagEnableNetReset
	}
	if featuresFlags["cgroups"].Enabled {
		config.Flags |= ipc.FlagEnableCgroups
	}
	if featuresFlags["close_fds"].Enabled {
		config.Flags |= ipc.FlagEnableCloseFds
	}
	if featuresFlags["devlink_pci"].Enabled && features[host.FeatureDevlinkPCI].Enabled {
		config.Flags |= ipc.FlagEnableDevlinkPCI
	}
	if featuresFlags["nic_vf"].Enabled && features[host.FeatureNicVF].Enabled {
		config.Flags |= ipc.FlagEnableNicVF
	}
	if featuresFlags["vhci"].Enabled && features[host.FeatureVhciInjection].Enabled {
		config.Flags |= ipc.FlagEnableVhciInjection
	}
	if featuresFlags["wifi"].Enabled && features[host.FeatureWifiEmulation].Enabled {
		config.Flags |= ipc.FlagEnableWifi
	}
	return config, execOpts
}
