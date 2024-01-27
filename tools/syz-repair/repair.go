// Build:
// Just make

package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

type repairer struct {
	target        *prog.Target
	callMap       map[string][]string
	genHistoryRev map[string]string
	curTargetCall string
	curFilename   string
	startT        time.Time
	dirMode       bool
}

func main() {
	start := time.Now()
	var (
		flagOS   = flag.String("os", "linux", "target OS")
		flagArch = flag.String("arch", "amd64", "target arch")
		flagLog  = flag.String("log", "", "log file")
	)
	flag.Parse()
	args := flag.Args()
	if len(args) != 2 {
		usage()
	}
	inputPath := args[0]
	outputPath := args[1]

	if *flagLog == "" {
		log.SetOutput(os.Stdout)
	} else {
		logFile, err := os.OpenFile(*flagLog, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
		if err != nil {
			log.Fatal(err)
		}
		defer logFile.Close()
		multiOut := io.MultiWriter(logFile, os.Stdout)
		log.SetOutput(multiOut)
	}

	fmt.Printf("[%v] preprocess done\n", time.Since(start))

	var target *prog.Target
	var rpr *repairer
	rpr = &repairer{
		target:        target,
		callMap:       make(map[string][]string),
		genHistoryRev: make(map[string]string),
		dirMode:       false,
	}
	rpr.init(*flagOS, *flagArch, inputPath, outputPath)

	dirMode := rpr.dirMode

	var err error
	if dirMode {
		// check and repair a directory of programs
		// errTypes := rpr.analyzeErrorDir(inputPath)
		// for errType, num := range errTypes {
		// 	fmt.Printf("%s: %d\n", errType, num)
		// }
		validCnt, totalCnt := rpr.checkProgDir(inputPath)
		fmt.Printf("\n%d/%d are valid program, rate = %.2f%%\n\n", validCnt, totalCnt, float64(validCnt)/float64(totalCnt)*100)

		// start to repair
		rpr.repairProgDir(inputPath, outputPath)
		// errTypes = rpr.analyzeErrorDir(outputPath)
		// for errType, num := range errTypes {
		// 	fmt.Printf("%s: %d\n", errType, num)
		// }
		validCnt, totalCnt = rpr.checkProgDir(outputPath)
		fmt.Printf("\n%d/%d are valid program, rate = %.2f%%\n\n", validCnt, totalCnt, float64(validCnt)/float64(totalCnt)*100)
	} else {
		// check and repair one program
		err = rpr.checkProgram(args[0])
		re := regexp.MustCompile(`unknown syscall (\S+)`)
		if err != nil {
			log.Printf("%v", err)
			match := re.FindStringSubmatch(err.Error())
			if len(match) > 1 {
				syscallName := match[1]
				fmt.Printf("match unknown syscall: %s\n", syscallName)
			} else {
				fmt.Println("Not found match")
			}
		}
	}

	fmt.Printf("[%v] Execution done\n", rpr.timeElapse())
}

func usage() {
	fmt.Fprintf(os.Stderr, "usage: syz-repair -os <OS> -arch <ARCH> -log <log_path> INPUT OUTPUT\n")
	fmt.Fprintf(os.Stderr, "       syz-repair /path/invalid.prog /path/repaired.prog\n")
	fmt.Fprintf(os.Stderr, "       syz-repair /dir/to/invalid_progs/ /dir/to/repaired_progs/  (Recommended)\n")
	os.Exit(1)
}

func (rpr *repairer) init(OS, Arch, inputPath, outputPath string) {
	rpr.startT = time.Now()
	var err error
	// init target
	rpr.target, err = prog.GetTarget(OS, Arch)
	if err != nil {
		log.Fatalf("failed to find target: %v", err)
	}
	// init callMap
	for _, c := range rpr.target.Syscalls {
		rpr.callMap[c.CallName] = append(rpr.callMap[c.CallName], c.Name)
	}

	// check input
	inputInfo, err := os.Stat(inputPath)
	if os.IsNotExist(err) {
		log.Fatalf("input %v does not exist: %v", inputPath, err)
	}
	rpr.dirMode = inputInfo.IsDir()

	// check output
	outputInfo, err := os.Stat(outputPath)
	if os.IsNotExist(err) && rpr.dirMode {
		if err := os.MkdirAll(outputPath, 0755); err != nil {
			log.Fatalf("failed to create dir %v: %v", outputPath, err)
		}
	}
	outputInfo, _ = os.Stat(outputPath)
	if rpr.dirMode && outputInfo.IsDir() == false {
		log.Fatalf("output should also be a dir when input is dir")
	}

	// init genHistoryRev
	if rpr.dirMode {
		tmpInputPath := inputPath
		if strings.HasSuffix(inputPath, "/") {
			tmpInputPath = inputPath[:len(inputPath)-1]
		}
		inputParentDir := filepath.Dir(tmpInputPath)
		jsonFilePath := filepath.Join(inputParentDir, "generation_history.json")
		jsonData, err := os.ReadFile(jsonFilePath)
		if err != nil {
			fmt.Printf("[%v] failed to read JSON file: %v\n", rpr.timeElapse(), err)
		} else {
			var historyMap map[string][]string
			if err := json.Unmarshal(jsonData, &historyMap); err != nil {
				log.Fatalf("failed to decode JSON data: %v", err)
			}
			for syscall, filenameList := range historyMap {
				for _, filename := range filenameList {
					rpr.genHistoryRev[filename] = syscall
				}
			}
		}
	}

	fmt.Printf("[%v] rpr.init done\n", rpr.timeElapse())
}

func (rpr *repairer) timeElapse() time.Duration {
	return time.Since(rpr.startT)
}

func (rpr *repairer) getCurTargetCall(filename string) string {
	return rpr.genHistoryRev[filename]
}

func (rpr *repairer) repairProgDir(inDir, outDir string) {
	inFiles, err := os.ReadDir(inDir)
	if err != nil {
		log.Fatalf("failed to read dir: %v", err)
	}

	validCnt := 0
	for _, file := range inFiles {
		rpr.curFilename = file.Name()
		rpr.curTargetCall = rpr.getCurTargetCall(rpr.curFilename)
		repaLines := rpr.repairProgram(filepath.Join(inDir, file.Name()))
		repaData := lines2Data(repaLines)
		err := rpr.checkProgramData(repaData)
		if err == nil {
			validCnt += 1
		}
		writeProg(repaLines, filepath.Join(outDir, file.Name()))
	}
	fmt.Printf("[%v] rpr.repairProgDir done\n", rpr.timeElapse())
}

func (rpr *repairer) repairProgram(inFile string) (repairedLines []string) {
	failRepairMax := 2
	repairMax := 25
	lines := readLines(inFile)
	for _, line := range lines {
		// repalce " to '
		modifiedLine := strings.ReplaceAll(line, "\"", "'")
		repairedLines = append(repairedLines, modifiedLine)
	}

	repairCnt := 0
	failRepairCnt := 0
	for {
		repairCnt += 1
		data := lines2Data(repairedLines)
		err := rpr.checkProgramData(data)
		if err == nil {
			return repairedLines
		}
		errType, errName, errDetail := classifyErrorType(err)
		switch {
		case errType == "unknown syscall SYSCALL":
			repairedLines = rpr.repairSyscall(repairedLines, errName)
		case errType == "want A got B":
			repairedLines = rpr.repairWant(repairedLines, errName, errDetail)
		case errType == "call SYSCALL: escaping filename FILENAME":
			repairedLines = rpr.repairFilename(repairedLines, errName)
		case errType == "unexpected eof":
			repairedLines = rpr.repairEOF(repairedLines, errName, errDetail)
		case errType == "Out of MaxCalls":
			repairedLines = rpr.repairOutMax(repairedLines, errName)
		default:
			failRepairCnt += 1
		}
		if failRepairCnt >= failRepairMax || repairCnt >= repairMax {
			// fmt.Printf("[%v] rpr.repairProgram reaches repair maximum %d for %s\n", rpr.timeElapse(), repairMax, inFile)
			break
		}
	}
	// if repairCnt >= repairMax {
	// 	fmt.Printf("[%v] rpr.repairProgram repairCnt %d for %s\n", rpr.timeElapse(), repairCnt, inFile)
	// }
	return repairedLines
}

func (rpr *repairer) repairFilename(lines []string, errName string) (repairedLines []string) {
	escapFilename := strings.Split(errName, "escaping filename ")[1]
	escapFilename = escapFilename[1 : len(escapFilename)-1]
	var replaceFilename string
	if escapFilename[0:1] == "/" {
		replaceFilename = "." + escapFilename
	} else if escapFilename[0:2] == ".." {
		replaceFilename = escapFilename[1:]
	}
	for _, line := range lines {
		modifiedLine := strings.ReplaceAll(line, escapFilename, replaceFilename)
		repairedLines = append(repairedLines, modifiedLine)
	}
	return repairedLines
}

func (rpr *repairer) repairOutMax(lines []string, errName string) (repairedLines []string) {
	for i, line := range lines {
		if i >= prog.MaxCalls {
			break
		}
		repairedLines = append(repairedLines, line)
	}
	return repairedLines
}

func (rpr *repairer) repairEOF(lines []string, errName, errDetail string) (repairedLines []string) {
	var lineNumber int
	var err error

	re := regexp.MustCompile(`#(\d+):(\d+)`)
	matches := re.FindStringSubmatch(errDetail)
	if len(matches) == 3 {
		lineNumber, err = strconv.Atoi(matches[1])
		// lineOffset, err = strconv.Atoi(matches[2])
		if err != nil {
			fmt.Printf("[%v] rpr.repairEOF failed to atoi line #N:M in %s\n", rpr.timeElapse(), errDetail)
			return lines
		}
	} else {
		fmt.Printf("[%v] rpr.repairEOF failed to match line #N:M in %s\n", rpr.timeElapse(), errDetail)
		return lines
	}

	// alway true, do not care about deleting target syscall
	containTarget := true
	for i, line := range lines {
		if i+1 == lineNumber {
			var modifiedLine string
			modifiedLine = fixUnbalancedParentheses(line)
			repairedLines = append(repairedLines, modifiedLine)
			continue
		} else if strings.Contains(line, rpr.curTargetCall) {
			containTarget = true
		}
		repairedLines = append(repairedLines, line)
	}
	repairedData := lines2Data(repairedLines)
	err = rpr.checkProgramData(repairedData)
	if err != nil {
		if lineNumber >= 50 && containTarget == true {
			repairedLines = repairedLines[:prog.MaxCalls]
		}
		// repairedLines = make([]string, 0)
		// for i, line := range lines {
		// 	if i+1 == lineNumber {
		// 		if lineNumber >= 50 && containTarget == true {
		// 			// fmt.Printf("[%v] rpr.repairEOF skip line %d: %s\n", rpr.timeElapse(), lineNumber, line)
		// 			continue
		// 		}
		// 	}
		// 	repairedLines = append(repairedLines, line)
		// }
	}
	return repairedLines
}

func (rpr *repairer) repairWant(lines []string, errName, errDetail string) (repairedLines []string) {
	var wantChar string
	var lineNumber, lineOffset int
	var err error

	re1 := regexp.MustCompile(`want ('[^']'|[^']{1})`)
	matches1 := re1.FindStringSubmatch(errName)
	if len(matches1) == 2 {
		wantChar = matches1[1]
		if len(wantChar) == 3 {
			wantChar = wantChar[1:2]
		}
	} else {
		fmt.Printf("[%v] rpr.repairWant failed to match want A in %s\n", rpr.timeElapse(), errName)
		return lines
	}

	re2 := regexp.MustCompile(`#(\d+):(\d+)`)
	matches2 := re2.FindStringSubmatch(errDetail)
	if len(matches2) == 3 {
		lineNumber, err = strconv.Atoi(matches2[1])
		lineOffset, err = strconv.Atoi(matches2[2])
		if err != nil {
			fmt.Printf("[%v] rpr.repairWant failed to atoi line #N:M in %s\n", rpr.timeElapse(), errDetail)
			return lines
		}
	} else {
		fmt.Printf("[%v] rpr.repairWant failed to match line #N:M in %s\n", rpr.timeElapse(), errDetail)
		return lines
	}

	// fmt.Printf("[%v] rpr.repairWant match want %s at line #%d:%d for %s\n", rpr.timeElapse(), wantChar, lineNumber, lineOffset, rpr.curFilename)

	for i, line := range lines {
		if i+1 == lineNumber {
			if wantChar == "=" && lineOffset >= 4 && line[lineOffset-4:lineOffset] == "=ANY" {
				modifiedLine := strings.ReplaceAll(line, "=ANY", "=ANY=[]")
				repairedLines = append(repairedLines, modifiedLine)
				fmt.Printf("[%v] rpr.repairWant repalce =ANY to =ANY=: %s\n", rpr.timeElapse(), modifiedLine)
				continue
			}
			modifiedLine := replaceCharAtIndex(line, lineOffset, wantChar)
			repairedLines = append(repairedLines, modifiedLine)
			// fmt.Printf("[%v] rpr.repairWant repalce line #%d:%d to %s: %s\n", rpr.timeElapse(), lineNumber, lineOffset, wantChar, modifiedLine)
			continue
		}
		repairedLines = append(repairedLines, line)
	}
	return repairedLines
}

func (rpr *repairer) repairSyscall(lines []string, errName string) (repairedLines []string) {
	re := regexp.MustCompile(`unknown syscall (\S+)`)
	match := re.FindStringSubmatch(errName)
	var syscallName string
	if len(match) > 1 {
		syscallName = match[1]
		// fmt.Printf("match unknown syscall: %s\n", syscallName)
	} else {
		fmt.Printf("[%v] rpr.repairSyscall failed to match unknown syscall in %s\n", rpr.timeElapse(), errName)
		return lines
	}
	var syscallCandidates []string
	syscallBase := extractBaseCall(syscallName)
	// fmt.Printf("[DEBUG] %s is the base of %s\n", syscallBase, syscallName)
	syscallCandidates, ok := rpr.callMap[syscallBase]
	if !ok {
		// fmt.Printf("[%v] rpr.repairSyscall base syscall %s is not a valid syscall\n", rpr.timeElapse(), syscallBase)
		if rpr.curTargetCall != "" && syscallName != rpr.curTargetCall {
			for _, line := range lines {
				if strings.Contains(line, syscallName) {
					// fmt.Printf("[%v] rpr.repairSyscall choose to remove the line: %s\n", rpr.timeElapse(), line)
					continue
				}
				repairedLines = append(repairedLines, line)
			}
			return repairedLines
		}
		return lines
	}
	k := 5
	kSims := maxKSim(syscallName, syscallCandidates, k)
	for _, simCall := range kSims {
		repairedLines = make([]string, 0)
		for _, line := range lines {
			modifiedLine := strings.ReplaceAll(line, syscallName, simCall)
			repairedLines = append(repairedLines, modifiedLine)
		}
		repairedData := lines2Data(repairedLines)
		err := rpr.checkProgramData(repairedData)
		if err == nil {
			return repairedLines
		} else {
			_, newErrName, _ := classifyErrorType(err)
			if newErrName != errName {
				// fmt.Printf("[%v] rpr.repairSyscall fixes the unknown syscall %s but raises another err: %s\n", rpr.timeElapse(), syscallName, newErrName)
				return repairedLines
			}
		}
	}
	// replace to syscallBase
	repairedLines = make([]string, 0)
	for _, line := range lines {
		modifiedLine := strings.ReplaceAll(line, syscallName, syscallBase)
		repairedLines = append(repairedLines, modifiedLine)
	}
	return repairedLines
	// return lines
}

func (rpr *repairer) checkProgram(file string) (err error) {
	data, err := os.ReadFile(file)
	if err != nil {
		log.Fatalf("failed to read file %v: %v", file, err)
	}

	return rpr.checkProgramData(data)
}

func (rpr *repairer) checkProgramData(data []byte) (err error) {
	p, err := rpr.target.Deserialize(data, prog.NonStrict)
	if err != nil {
		return err
	}
	if len(p.Calls) > prog.MaxCalls {
		return errors.New("Out of MaxCalls")
	}
	return nil
}

func (rpr *repairer) checkProgDir(dir string) (validCnt, totalCnt int) {
	validCnt = 0
	files, err := os.ReadDir(dir)
	if err != nil {
		log.Fatalf("failed to read dir: %v", err)
	}

	for _, file := range files {
		err := rpr.checkProgram(filepath.Join(dir, file.Name()))
		if err == nil {
			validCnt += 1
		}
	}
	return validCnt, len(files)
}

func (rpr *repairer) analyzeErrorDir(dir string) (errTypes map[string]int) {
	errTypes = make(map[string]int)
	files, err := os.ReadDir(dir)
	if err != nil {
		log.Fatalf("failed to read dir: %v", err)
	}

	for _, file := range files {
		err := rpr.checkProgram(filepath.Join(dir, file.Name()))
		if err == nil {
			continue
		}
		errType, _, _ := classifyErrorType(err)
		// if errDetail != "" {
		// 	fmt.Printf("errType: %s\nerrDetail: %s\n", errType, errDetail)
		// }
		if count, found := errTypes[errType]; !found {
			errTypes[errType] = 1
		} else {
			errTypes[errType] = count + 1
		}
	}
	return errTypes
}

func classifyErrorType(err error) (errType, errName, errDetail string) {
	errSplt := strings.Split(err.Error(), "\n")
	errType = errSplt[0]
	errName = errSplt[0]
	if len(errSplt) == 2 {
		errDetail = errSplt[1]
	}

	switch {
	case strings.Contains(errType, "unknown syscall"):
		errType = "unknown syscall SYSCALL"
	case strings.Contains(errType, "want") && strings.Contains(errType, "got"):
		errType = "want A got B"
	case strings.Contains(errType, "failed to parse identifier at pos"):
		errType = "failed to parse identifier at pos POS"
	case strings.Contains(errType, "failed to parse argument at"):
		errType = "failed to parse argument at"
	case strings.HasPrefix(errType, "call") && strings.Contains(errType, "has bad type") && strings.Contains(errType, "result arg"):
		errType = "call SYSCALL: result arg ARG has bad type TYPE"
	case strings.Contains(errType, "use of a disabled call"):
		errType = "call SYSCALL: use of a disabled call"
	case strings.Contains(errType, "escaping filename"):
		errType = "call SYSCALL: escaping filename FILENAME"
	}
	return errType, errName, errDetail
}
