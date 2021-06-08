package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"regexp"
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
	CmdLine   string
	Engine    string
	Error     bool
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
	maxResults          int
	yaraFile            string
	allPids             bool
}

func init() {
	SupportedModes = make(map[string]MemScanner)
}

var au aurora.Aurora

//Very basic flag logic, use cobra, clapper , pflags , etc if really needed in the future
func parseCommandLineAndValidate() GoMemScanArgs {

	args := GoMemScanArgs{}

	flag.StringVar(&args.pattern, "pattern", "", "Pattern to match Ex: \\x41\\x41 - Warning: a match all pattern will hold all the chunks in memory!")
	flag.StringVar(&args.yaraFile, "yara-file", "", "Use a yara rule for matching instead (Only if built with yara support)")
	flag.IntVar(&args.pid, "pid", 0, "(*required) Pid to read memory from")
	flag.IntVar(&args.totalGoRoutines, "go-routines", 6, "Go routines to use during scanning")
	flag.Uint64Var(&args.bucketLen, "blen", 1024*1024, "Bucket size where the pattern is applied")
	flag.Uint64Var(&args.startAddress, "from", 0, "Start address (0x4444444)")
	flag.Uint64Var(&args.bytesToRead, "length", 1024*1024, "Bytes to read")
	flag.IntVar(&args.maxMatchesPerChunk, "matches", 10, "Max matches per chunk")
	flag.IntVar(&args.maxResults, "max-results", 30, "Max results per scan")
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
	flag.BoolVar(&args.allPids, "all-pids", false, "Scan all pids")
	flag.Parse()

	if args.pid == 0 && args.allPids == false {
		fmt.Println(au.Red("Error: Target PID is required\n"))
		os.Exit(1)
	}

	if args.pattern == "" && args.yaraFile == "" || args.pattern != "" && args.yaraFile != "" {
		fmt.Println(au.Red("Error: You need to provide either Scan Pattern or Yara rule\n"))
		os.Exit(1)
	}

	if args.includeRawDump && args.outputFile == "" {
		fmt.Println(au.Red("Error: Provide an output file name to also generate raw dumps"))
		os.Exit(1)
	}

	if _, err := regexp.Compile(args.pattern); err != nil {
		fmt.Println(au.Sprintf(au.Red("Error: Invalid Pattern => %s"), au.BrightBlue(err)))
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

var SupportedModes map[string]MemScanner

func initiPidScan(pid int, args GoMemScanArgs, scannerMatch MemScanner) (MemScanResult, *[]memscan.MemMatch, error) {

	process, err := memscan.GetProcess(pid)

	if process == nil {
		return MemScanResult{Pid: pid}, nil, errors.New(au.Sprintf(au.Red("Error: Cannot open process => %s"), au.BrightBlue(err)))
	}
	defer process.Close()
	imageName, cmdLine, err := memscan.GetProcessPathAndCmdline(process)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			//It may be a kernel process or non existent anymore, just ignore it
			return MemScanResult{Pid: 0}, nil, nil
		}
		fmt.Println(au.Sprintf(au.Red("Error: Cannot read cmdlined/image path: (%s) - Will try to continue\n"), au.BrightBlue(err)))
	}
	var mRanges []memscan.MemRange
	scanner := new(memscan.MemReader)
	if args.fullScan {
		var err error
		mRanges, err = scanner.GetScanRangeForPidMaps(process, uint8(args.permMap), args.bucketLen)
		if err != nil {
			return MemScanResult{Pid: args.pid, ImageName: imageName, CmdLine: cmdLine}, nil, errors.New(au.Sprintf(au.Red("Error: Cannot read process mmap => %s\n"), au.BrightBlue(err)))
		}
	} else {
		mRanges = scanner.GenScanRange(args.startAddress, args.bytesToRead, args.bucketLen, "")
	}

	if len(mRanges) == 0 && args.startAddress == 0 {
		return MemScanResult{Pid: pid, ImageName: imageName, CmdLine: cmdLine}, nil, errors.New(au.Sprintf("%s", au.Red("Error: Not valid memory ranges to scan\n")))
	}

	memInspect := func(chunk *[]byte, location memscan.MemRange, err error, workerNum int) uint8 {
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

		if scannerMatch.Match(chunk, location, workerNum) {
			if args.stopAfterFirstMatch {
				return memscan.StopScan
			}

		}
		return memscan.ContinueScan
	}
	scanner.ScanMemory(process, &mRanges, args.bucketLen, memInspect, args.totalGoRoutines)
	/* Output results */
	matches := scannerMatch.GetMatches()
	return MemScanResult{Bsize: args.bucketLen, Pid: pid, ImageName: imageName, CmdLine: cmdLine}, &matches, nil

}

func saveRawChunk(data *[][]byte, outputFile string) {

	f, err := os.OpenFile(outputFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		fmt.Println(au.Sprintf(au.Red("Error: cannot save raw data to file %s (%s)"), au.BrightBlue(outputFile), au.BrightBlue(err)))
		return
	}
	defer f.Close()
	pLen := len(*data)
	/* It's manual to avoid holding the entire struct, a iowriter or buffer may be better suited to implement this logic*/
	extraChar := ","
	f.Write([]byte("["))
	for idx, bData := range *data {
		if idx+1 == pLen {
			extraChar = ""
		}
		if _, err := f.Write(bData); err != nil {
			fmt.Println(au.Sprintf(au.Red("Error: failed writing data to file (%s)"), au.BrightBlue(err)))
		}
		f.Write([]byte(extraChar))
	}
	f.Write([]byte("]"))
}
func processOutput(result *MemScanResult, matches []memscan.MemMatch, rawDump bool, outputFile string, contextLength, maxResults int) {
	for _, match := range matches {
		chunkLength := 0
		if match.Chunk != nil {
			chunkLength = len(*match.Chunk)
		}
		maxResults--
		if chunkLength == 0 || maxResults < 0 {
			continue
		}
		if rawDump {
			rData := make([][]byte, 1, 1)
			rData[0] = *match.Chunk
			saveRawChunk(&rData, fmt.Sprintf("%s_start_%x_end_%x.raw", outputFile, match.Location.Start, match.Location.Start))
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

func main() {
	au = aurora.NewAurora(true)
	fmt.Println(au.Sprintf(au.Green("---- [ GoMemScan Ver: %s ] ----\n"), au.BrightGreen(version)))
	args := parseCommandLineAndValidate()

	/* Init Scanners */
	var scannerMatch MemScanner
	engine := ""
	if args.pattern != "" {
		engine = RE_SCANNER_NAME
		scannerMatch, _ = SupportedModes[RE_SCANNER_NAME]

		scannerMatch.Init(map[string]interface{}{"pattern": args.pattern, "maxMatchesPerChunk": args.maxMatchesPerChunk, "justMatch": args.justMatch})
	} else if args.yaraFile != "" {
		engine = "yara"
		var ok bool
		scannerMatch, ok = SupportedModes[engine]
		if !ok {
			fmt.Println(au.Red("Error: YARA support not enabled\n"))
			os.Exit(1)
		}
		if err := scannerMatch.Init(map[string]interface{}{
			"yaraFile":           args.yaraFile,
			"maxMatchesPerChunk": args.maxMatchesPerChunk,
			"justMatch":          args.justMatch,
			"totalGoRoutines":    args.totalGoRoutines}); err != nil {

			fmt.Println(au.Sprintf(au.Red("Error: YARA initialization failed : %s\n"), au.BrightBlue(err)))
			os.Exit(1)
		}
	}

	if scannerMatch == nil {
		fmt.Println(au.Sprintf(au.Red("Not valid match engine selected - Available modes: %v\n"), au.BrightBlue(SupportedModes)))
		os.Exit(1)
	}
	st := time.Now()
	atLeastOneMatch := false
	var jsonResults [][]byte
	allPids, err := memscan.GetProcessPidToScan(args.pid, args.allPids)
	if err != nil {
		fmt.Println(au.Sprintf(au.Red("Couldnt get processes id: %v\n"), au.BrightBlue(err)))
		os.Exit(1)
	}
	for _, pid := range allPids {
		result, matches, err := initiPidScan(pid, args, scannerMatch)
		if err != nil {
			fmt.Println(au.Sprintf(au.Red("Error scanning pid %d: %v\n"), pid, au.BrightBlue(err)))
			if args.allPids == false {
				os.Exit(1)
			}
			result.Error = true
		}
		if result.Pid == 0 {
			continue
		}
		result.Engine = engine
		if len(result.Matches) > 0 {
			atLeastOneMatch = true
		}
		if matches != nil {
			processOutput(&result, *matches, args.includeRawDump, args.outputFile, args.contextLength, args.maxResults)
		}
		rJson, err := json.MarshalIndent(result, "", "\t")
		if err != nil {
			fmt.Println(au.Sprintf(au.Red("-> Error generating json output (%s)"), au.BrightBlue(err)))
			continue
		}
		jsonResults = append(jsonResults, rJson)
	}
	fmt.Println(au.Sprintf(au.BrightYellow("Scan time %d ms"), au.White(time.Since(st).Milliseconds())))
	if args.outputFile != "" {
		saveRawChunk(&jsonResults, args.outputFile)
	} else if args.printOutput {
		fmt.Println("[")
		//this is to avoid holding the entire mem matches while all pids are scanned
		totalResults := len(jsonResults)
		cChar := ","
		for idx, rData := range jsonResults {
			if idx+1 == totalResults {
				cChar = ""
			}
			fmt.Println(string(rData) + cChar)
		}
		fmt.Println("]")
	}
	if atLeastOneMatch == true {
		os.Exit(0)
	}
	os.Exit(2)
}
