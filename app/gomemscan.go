package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"regexp"
	"sync"
	"time"

	"github.com/lcostantino/gomemscan/memscan"
	"github.com/logrusorgru/aurora"
)

var version = "replace"

//For each Match on a chunk all found locations
type MemMatchResult struct {
	Chunk    *[]byte
	Location memscan.MemRange
	Name     string
}

type MemScanResult struct {
	Bsize     uint64
	Pid       int
	ImageName string
	cmdLine   string
	Matches   []MemMatchResult //this matches will be modified
}

type GoMemScanArgs struct {
	pattern             string
	pid                 int
	bucketLen           uint64
	startAddress        uint64
	bytesToRead         uint64
	maxMatchesPerChunk  int
	contextLength       int
	colors              bool
	fullScan            bool
	verbose             bool
	includeRawDump      bool
	outputFile          string
	stopAfterFirstMatch bool
	permMap             int
	justMatch           bool
	printOutput         bool
	totalGoRoutines     int
}

var au aurora.Aurora

//Very basic flag logic, use cobra, clapper , pflags , etc if really needed in the future
func parseCommandLineAndValidate() GoMemScanArgs {

	args := GoMemScanArgs{}

	flag.StringVar(&args.pattern, "pattern", "", "Pattern to match Ex: \\x41\\x41 - Warning: a match all pattern will hold all the chunks in memory!")
	flag.IntVar(&args.pid, "pid", 0, "(*required) Pid to read memory from")
	flag.IntVar(&args.totalGoRoutines, "go-routines", 6, "Go routines to use during scanning")
	flag.Uint64Var(&args.bucketLen, "blen", 1024*1024, "Bucket size where the pattern is applied")
	flag.Uint64Var(&args.startAddress, "from", 0, "Start address (0x4444444)")
	flag.Uint64Var(&args.bytesToRead, "length", 1024*1024, "Bytes to read")
	flag.IntVar(&args.maxMatchesPerChunk, "matches", 10, "Max matches per chunk")
	flag.IntVar(&args.contextLength, "context-bytes", 16, "Bytes to print after and before a match")
	flag.BoolVar(&args.colors, "colors", true, "enable or disable colors")
	flag.BoolVar(&args.fullScan, "fullscan", false, "Scan all mapped sections")
	flag.IntVar(&args.permMap, "mapperm", 0, "When scanning mapped sections filter those that match specific permission bit(ex: 4 for read). 0 to ignore it")
	flag.BoolVar(&args.stopAfterFirstMatch, "stop-first-match", false, "Stop after the first chunk match")
	flag.BoolVar(&args.verbose, "verbose", false, "Verbose")
	flag.BoolVar(&args.includeRawDump, "raw-dump", false, "Generate a file per chunk that matched with binary data")
	flag.StringVar(&args.outputFile, "output", "", "Output file name. It will be used as prefix for raw output if selected")
	flag.BoolVar(&args.justMatch, "justmatch", false, "If enabled memory won't be held nor raw data will be availble. Usefully just for initial inspection (match or not)")
	flag.BoolVar(&args.printOutput, "print-output", true, "Print json output if file not provided")
	flag.Parse()

	if args.pid == 0 {
		fmt.Println(au.Red("Error: Target PID is required\n"))
		os.Exit(1)
	}

	if args.pattern == "" {
		fmt.Println(au.Red("Error: Missing Scan Pattern\n"))
		os.Exit(1)
	}

	if args.includeRawDump && args.outputFile == "" {
		fmt.Println(au.Red("Error: Provider an output file name to also generate raw dumps"))
		os.Exit(1)
	}
	if _, err := regexp.Compile(args.pattern); err != nil {
		fmt.Println(au.Sprintf(au.Red("Error: Invalid Pattern => %s"), au.BrightBlue(err)))
		os.Exit(1)
	}

	if _, err := os.Stat(fmt.Sprintf("/proc/%d", args.pid)); err != nil {
		fmt.Println(au.Sprintf(au.Red("Error: Cannot find PID => %s"), au.BrightBlue(err)))
		os.Exit(1)
	}

	if args.bytesToRead < args.bucketLen && args.fullScan == false {
		args.bucketLen = args.bytesToRead
	}

	if args.colors == false {
		au = aurora.NewAurora(args.colors)
	}

	if args.justMatch {
		fmt.Println(au.BrightGreen("Raw data and mem context disabled"))
		args.includeRawDump = false
	}
	if args.verbose {
		fmt.Println(au.Sprintf(au.BrightYellow("Pattern: %s"), au.White(args.pattern)))
	}
	return args
}

func main() {
	au = aurora.NewAurora(true)
	fmt.Println(au.Sprintf(au.Green("---- [ GoMemScan Ver: %s ] ----\n"), au.BrightGreen(version)))
	args := parseCommandLineAndValidate()

	var mRanges []memscan.MemRange
	scanner := new(memscan.MemReader)
	if args.fullScan {
		var err error

		mRanges, err = scanner.GetScanRangeForPidMaps(args.pid, uint8(args.permMap), args.bucketLen)
		if err != nil {
			fmt.Println(au.Sprintf(au.Red("Error: Cannot read process mmap => %s\n"), au.BrightBlue(err)))
			os.Exit(1)
		}
	} else {
		mRanges = scanner.GenScanRange(args.startAddress, args.bytesToRead, args.bucketLen, "")
	}

	if len(mRanges) == 0 {
		fmt.Println(au.Red("Error: Not valid memory ranges to scan\n"))
		os.Exit(1)
	}

	imageName := memscan.GetProcessExecPath(args.pid)
	cmdLine := memscan.GetProcessCmdLine(args.pid)
	//From here you can use this as a module, this is the main logic for this cli tool
	smutex := sync.Mutex{}
	matches := make([]memscan.MemMatch, 0, args.maxMatchesPerChunk)

	sreg := regexp.MustCompile(args.pattern)
	memInspect := func(chunk *[]byte, location memscan.MemRange, err error) uint8 {
		// Here it will be possible to cancel the execution of next matches if needed
		if err != nil {
			fmt.Println(au.Sprintf(au.Red("-> Error scanning address at 0x%x (%s)"), au.BrightBlue(location.Start), au.BrightBlue(err)))
			if errors.Is(err, os.ErrNotExist) {
				return memscan.StopScan
			}
		}

		if args.verbose {
			fmt.Println(au.Sprintf(au.BrightYellow("Retrieved memory from: 0x%x to 0x%x"), au.White(location.Start), au.White(location.End)))
		}
		if matchPositions := sreg.FindAllIndex(*chunk, args.maxMatchesPerChunk); matchPositions != nil {
			smutex.Lock()
			defer smutex.Unlock()
			//Warning: this store all memory regardeless contextLength
			if args.justMatch {
				chunk = nil
			}
			matches = append(matches, memscan.MemMatch{Chunk: chunk, Pos: matchPositions, Location: location})
			if args.stopAfterFirstMatch {
				return memscan.StopScan
			}

		}
		return memscan.ContinueScan
	}
	st := time.Now()
	scanner.ScanMemory(args.pid, &mRanges, args.bucketLen, memInspect, args.totalGoRoutines)
	fmt.Println(au.Sprintf(au.BrightYellow("Scan time %d ms"), au.White(time.Since(st).Milliseconds())))

	/* Output results */
	result := MemScanResult{Bsize: args.bucketLen, Pid: args.pid, ImageName: imageName, cmdLine: cmdLine}
	processOutput(&result, matches, args.includeRawDump, args.outputFile, args.contextLength)
	resultJson, err := json.MarshalIndent(result, "", "\t")
	if args.outputFile != "" {
		if err == nil {
			saveRawChunk(&resultJson, args.outputFile)
		} else {
			fmt.Println(au.Sprintf(au.Red("-> Error generating json output (%s)"), au.BrightBlue(err)))
		}
	} else if args.printOutput {
		fmt.Println(string(resultJson))
	}
	if len(result.Matches) > 0 {
		os.Exit(0)
	}
	os.Exit(2)

}

func saveRawChunk(data *[]byte, outputFile string) {

	f, err := os.OpenFile(outputFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)

	if err != nil {
		fmt.Println(au.Sprintf(au.Red("Error: cannot save raw data to file %s (%s)"), au.BrightBlue(outputFile), au.BrightBlue(err)))
		return
	}
	defer f.Close()
	if _, err := f.Write(*data); err != nil {
		fmt.Println(au.Sprintf(au.Red("Error: failed writing data to file (%s)"), au.BrightBlue(err)))
	}
}
func processOutput(result *MemScanResult, matches []memscan.MemMatch, rawDump bool, outputFile string, contextLength int) {

	for _, match := range matches {

		chunkLength := 0
		if match.Chunk != nil {
			chunkLength = len(*match.Chunk)
		}
		if rawDump {
			saveRawChunk(match.Chunk, fmt.Sprintf("%s_start_%x_end_%x.raw", outputFile, match.Location.Start, match.Location.Start))
		}
		for _, plocation := range match.Pos {

			spos := plocation[0] - contextLength
			if spos < 0 {
				spos = 0
			}
			epos := plocation[1] + contextLength
			if epos > chunkLength-1 {
				epos = chunkLength - 1
			}

			mtr := MemMatchResult{}
			//plocation is int, so check if this work with larger chunks..
			mtr.Location.Start = match.Location.Start + (uint64)(plocation[0])
			mtr.Location.End = match.Location.Start + (uint64)(plocation[1])
			if match.Chunk != nil {
				mtr.Chunk = new(([]byte))
				*mtr.Chunk = (*match.Chunk)[spos:epos]
			}
			mtr.Name = match.Location.Name
			result.Matches = append(result.Matches, mtr)

		}

	}

}
