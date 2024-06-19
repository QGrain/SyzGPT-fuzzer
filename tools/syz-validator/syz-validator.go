// Build:
// Just make

// TODO
// Add invalid types for each invalid prog

package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

func main() {
	start := time.Now()
	var (
		flagOS   = flag.String("os", "linux", "target OS")
		flagArch = flag.String("arch", "amd64", "target arch")
		flagLog  = flag.String("log", "", "log file")
	)
	flag.Parse()
	args := flag.Args()
	if len(args) == 0 {
		usage()
	}

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

	var target *prog.Target
	target, err := prog.GetTarget(*flagOS, *flagArch)
	if err != nil {
		log.Fatalf("failed to find target: %v", err)
	}

	switch args[0] {
	case "file":
		if len(args) != 2 {
			usage()
		}
		log.Printf("Start to verify the file: %v", args[1])
		data, err := os.ReadFile(args[1])
		if err != nil {
			log.Fatalf("failed to read file %v: %v", args[1], err)
		} else {
			bad := checkProgram(target, data)
			if bad {
				log.Printf("Program is invalid!")
			} else {
				log.Printf("Program is valid!")
			}
		}

	case "dir":
		if len(args) != 2 && len(args) != 3 {
			usage()
		}
		log.Printf("Start to verify the files in dir: %v", args[1])
		var outDir string
		if len(args) == 3 {
			outDir = args[2]
		} else {
			outDir = ""
		}
		checkPrograms(target, args[1], outDir)
	case "debug":
		debug(target)
	default:
		usage()
	}
	elapsed := time.Since(start)
	fmt.Println("Execution cost: ", elapsed)
}

func usage() {
	fmt.Fprintf(os.Stderr, "usage: syz-validator -os <OS> -arch <ARCH> -log <log_path> [args...]\n")
	fmt.Fprintf(os.Stderr, "       syz-validator file syzprog\n")
	fmt.Fprintf(os.Stderr, "       syz-validator dir /dir/to/syzprogs [out_dir]\n")
	fmt.Fprintf(os.Stderr, "       syz-validator debug\n")
	os.Exit(1)
}

func checkProgram(target *prog.Target, data []byte) (bad bool) {
	if len(data) == 0 {
		log.Printf("Program is blank")
		return true
	}
	p, err := target.Deserialize(data, prog.NonStrict)
	if err != nil {
		log.Printf("Deserialize error: %v", err)
		return true
	}
	if len(p.Calls) > prog.MaxCalls {
		log.Printf("Out of MaxCalls")
		return true
	}
	return false
}

func checkPrograms(target *prog.Target, dir, outDir string) (badCnt int32) {
	files, err := os.ReadDir(dir)
	if err != nil {
		log.Fatalf("failed to read dir: %v", err)
		return -1
	}

	if outDir != "" {
		_, err = os.Stat(outDir)
		if os.IsNotExist(err) {
			// directory does not exist, create it
			err = os.MkdirAll(outDir, 0755)
			if err != nil {
				log.Printf("[DEBUG] create dir %s error: %v", outDir, err)
				return
			}
		}
	}

	badCnt = 0

	for _, file := range files {
		data, err := os.ReadFile(filepath.Join(dir, file.Name()))
		if err != nil {
			log.Fatalf("failed to read file %v: %v", file.Name(), err)
		} else {
			bad := checkProgram(target, data)
			if bad {
				badCnt += 1
				log.Printf("%v is invalid!", file.Name())
			} else if outDir != "" {
				outFile := filepath.Join(outDir, file.Name())
				// log.Printf("%v is valid!", file.Name())
				osutil.WriteFile(outFile, data)
			}
		}
	}
	log.Printf("Invalid programs %v / %v, Syntax Valid Rate: %.2f%%", badCnt, len(files), (float64(len(files)-int(badCnt)) / float64(len(files)) * 100))
	return badCnt
}

func debug(target *prog.Target) {
	f, err := os.OpenFile("debug.log", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	multiOut := io.MultiWriter(f, os.Stdout)
	log.SetOutput(multiOut)

	f2, err2 := os.OpenFile("builtin_syscalls", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err2 != nil {
		log.Fatal(err2)
	}
	defer f2.Close()

	// var call_map map[string]int32
	call_map := make(map[string]int32)
	for i, c := range target.Syscalls {
		c.ID = i
		r := ""
		if c.Ret != nil {
			r = c.Ret.Name()
		} else {
			r = "<nil>"
		}

		if _, ok := call_map[c.CallName]; ok {
			call_map[c.CallName] += 1
		} else {
			call_map[c.CallName] = 1
			f2.WriteString(c.CallName + "\n")
		}

		log.Printf("ID=%v, NR=%v, Name=%v, CallName=%v, MissingArgs=%v, Ret.Name()=%v", c.ID, c.NR, c.Name, c.CallName, c.MissingArgs, r)
		for _, arg := range c.Args {
			log.Printf("\targ.Name=%v, arg.Type=%v, arg.HasDirection=%v, arg.Direction=%v", arg.Name, arg.Type, arg.HasDirection, arg.Direction)
		}
	}
	log.Printf("Summary: Call Amount = %v, Variant Amount = %v", len(call_map), len(target.Syscalls))
}
