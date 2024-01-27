// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/tool"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

func main() {
	var (
		flagVersion = flag.Uint64("version", 0, "database version")
		flagOS      = flag.String("os", "", "target OS")
		flagArch    = flag.String("arch", "", "target arch")
	)
	flag.Parse()
	args := flag.Args()
	if len(args) == 0 {
		usage()
	}
	if args[0] == "bench" {
		if len(args) != 2 {
			usage()
		}
		target, err := prog.GetTarget(*flagOS, *flagArch)
		if err != nil {
			tool.Failf("failed to find target: %v", err)
		}
		bench(target, args[1])
		return
	}
	var target *prog.Target
	if *flagOS != "" || *flagArch != "" {
		var err error
		target, err = prog.GetTarget(*flagOS, *flagArch)
		if err != nil {
			tool.Failf("failed to find target: %v", err)
		}
	}
	switch args[0] {
	case "pack":
		if len(args) != 3 {
			usage()
		}
		pack(args[1], args[2], target, *flagVersion)
	case "unpack":
		if len(args) != 3 {
			usage()
		}
		unpack(args[1], args[2])
	case "parse":
		if len(args) != 3 {
			usage()
		}
		parse(args[1], args[2])
	case "merge":
		if len(args) < 3 {
			usage()
		}
		merge(args[1], args[2:], target)
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "usage:\n")
	fmt.Fprintf(os.Stderr, "  syz-db pack dir corpus.db\n")
	fmt.Fprintf(os.Stderr, "  syz-db unpack corpus.db dir\n")
	fmt.Fprintf(os.Stderr, "  syz-db parse corpus.db dir\n")
	fmt.Fprintf(os.Stderr, "  syz-db merge dst-corpus.db add-corpus.db* add-prog*\n")
	fmt.Fprintf(os.Stderr, "  syz-db bench corpus.db\n")
	os.Exit(1)
}

func pack(dir, file string, target *prog.Target, version uint64) {
	files, err := os.ReadDir(dir)
	if err != nil {
		tool.Failf("failed to read dir: %v", err)
	}
	var records []db.Record
	for _, file := range files {
		data, err := os.ReadFile(filepath.Join(dir, file.Name()))
		if err != nil {
			tool.Failf("failed to read file %v: %v", file.Name(), err)
		}
		var seq uint64
		key := file.Name()
		if parts := strings.Split(file.Name(), "-"); len(parts) == 2 {
			var err error
			if seq, err = strconv.ParseUint(parts[1], 10, 64); err == nil {
				key = parts[0]
			}
		}
		if sig := hash.String(data); key != sig {
			if target != nil {
				p, err := target.Deserialize(data, prog.NonStrict)
				if err != nil {
					tool.Failf("failed to deserialize %v: %v", file.Name(), err)
				}
				data = p.Serialize()
				sig = hash.String(data)
			}
			fmt.Fprintf(os.Stderr, "fixing hash %v -> %v\n", key, sig)
			key = sig
		}
		records = append(records, db.Record{
			Val: data,
			Seq: seq,
		})
	}
	if err := db.Create(file, version, records); err != nil {
		tool.Fail(err)
	}
}

func unpack(file, dir string) {
	db, err := db.Open(file, false)
	if err != nil {
		tool.Failf("failed to open database: %v", err)
	}
	osutil.MkdirAll(dir)
	for key, rec := range db.Records {
		fname := filepath.Join(dir, key)
		if rec.Seq != 0 {
			fname += fmt.Sprintf("-%v", rec.Seq)
		}
		if err := osutil.WriteFile(fname, rec.Val); err != nil {
			tool.Failf("failed to output file: %v", err)
		}
	}
}

func parse(file, dir string) {
	// workDir := filepath.Dir(file)
	workDir := filepath.Dir(dir)
	var target *prog.Target
	target, err := prog.GetTarget("linux", "amd64")
	if err != nil {
		tool.Failf("[syz-db] failed to find target: %v", err)
	}
	progLenThreshold := 1000

	// preload the stuffs
	db, err := db.Open(file, false)
	if err != nil {
		tool.Failf("[syz-db] failed to open database: %v", err)
	}

	if !osutil.IsExist(dir) {
		osutil.MkdirAll(dir)
	} else {
		fmt.Fprintf(os.Stderr, "[syz-db] dir already exist: %v\n", dir)
	}
	seeds, err := os.ReadDir(dir)
	if err != nil {
		tool.Failf("[syz-db] failed to read unpack corpus dir: %v", err)
	}
	existSeedNames := make(map[string]struct{})
	for _, seed := range seeds {
		existSeedNames[seed.Name()] = struct{}{}
	}

	// load reverseIndex, if not exist then returen map[string][]string
	reverseIndexPath := filepath.Join(workDir, "reverse_index.json")
	reverseIndex := loadReverseIndex(reverseIndexPath)

	for key, rec := range db.Records {
		fname := filepath.Join(dir, key)
		if rec.Seq != 0 {
			fname += fmt.Sprintf("-%v", rec.Seq)
			key += fmt.Sprintf("-%v", rec.Seq)
		}
		// new seed unpack from corpus, do something for it
		if _, exist := existSeedNames[key]; !exist {
			// fmt.Fprintf(os.Stderr, "new seed unpack from corpus: %v\n", key)
			if err := osutil.WriteFile(fname, rec.Val); err != nil {
				tool.Failf("[syz-db] failed to output file: %v", err)
			}
			// skip the progs with len larger than threshold
			if len(rec.Val) >= progLenThreshold {
				continue
			}
			// complete reverseIndex
			p, err := target.Deserialize(rec.Val, prog.NonStrict)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[syz-db] failed to deserialize %v for building reverseIndex: %v. continue.\n", fname, err)
				continue
			}
			for _, call := range p.Calls {
				name := call.Meta.Name
				_, exist := reverseIndex[name]
				if !exist {
					var blank []string
					reverseIndex[name] = append(blank, fname)
				} else {
					reverseIndex[name] = append(reverseIndex[name], fname)
				}
			}
		}
	}
	// save the reverseIndex
	if err := saveReverseIndex(reverseIndex, reverseIndexPath); err != nil {
		tool.Failf("[syz-db] failed to save reverseIndex: %v", err)
	} else {
		fmt.Fprintf(os.Stderr, "[syz-db] success to save reverseIndex: %v\n", reverseIndexPath)
	}
}

// loadReverseIndex loads the reverse index from a file.
func loadReverseIndex(file string) map[string][]string {
	reverseIndex := make(map[string][]string)
	if osutil.IsExist(file) {
		fp, _ := os.OpenFile(file, os.O_CREATE|os.O_RDWR, 0644)
		defer fp.Close()
		decoder := json.NewDecoder(fp)
		if err := decoder.Decode(&reverseIndex); err != nil {
			return reverseIndex
		}
	}
	return reverseIndex
}

// saveReverseIndex saves the reverse index to a file.
func saveReverseIndex(reverseIndex map[string][]string, file string) error {
	fp, _ := os.OpenFile(file, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0644)
	defer fp.Close()
	encoder := json.NewEncoder(fp)
	err := encoder.Encode(reverseIndex)
	return err
}

func merge(file string, adds []string, target *prog.Target) {
	dstDB, err := db.Open(file, false)
	if err != nil {
		tool.Failf("failed to open database: %v", err)
	}
	for _, add := range adds {
		if addDB, err := db.Open(add, false); err == nil {
			for key, rec := range addDB.Records {
				dstDB.Save(key, rec.Val, rec.Seq)
			}
			continue
		} else if target == nil {
			tool.Failf("failed to open db %v: %v", add, err)
		}
		data, err := os.ReadFile(add)
		if err != nil {
			tool.Fail(err)
		}
		if _, err := target.Deserialize(data, prog.NonStrict); err != nil {
			tool.Failf("failed to deserialize %v: %v", add, err)
		}
		dstDB.Save(hash.String(data), data, 0)
	}
	if err := dstDB.Flush(); err != nil {
		tool.Failf("failed to save db: %v", err)
	}
}

func bench(target *prog.Target, file string) {
	start := time.Now()
	db, err := db.Open(file, false)
	if err != nil {
		tool.Failf("failed to open database: %v", err)
	}
	var corpus []*prog.Prog
	for _, rec := range db.Records {
		p, err := target.Deserialize(rec.Val, prog.NonStrict)
		if err != nil {
			tool.Failf("failed to deserialize: %v\n%s", err, rec.Val)
		}
		corpus = append(corpus, p)
	}
	runtime.GC()
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	fmt.Printf("allocs %v MB (%v M), next GC %v MB, sys heap %v MB, live allocs %v MB (%v M), time %v\n",
		stats.TotalAlloc>>20,
		stats.Mallocs>>20,
		stats.NextGC>>20,
		stats.HeapSys>>20,
		stats.Alloc>>20,
		(stats.Mallocs-stats.Frees)>>20,
		time.Since(start))
	sink = corpus
	_ = sink
}

var sink interface{}
