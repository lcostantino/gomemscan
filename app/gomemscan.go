package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"regexp"
	"sync"

	"github.com/lcostantino/gomemscan/memscan"
	"github.com/logrusorgru/aurora"
)

var version = "replace"

//For each Match on a chunk all found locations
type MemMatchResult struct {
	Chunk    *[]byte
	Location memscan.MemRange
}

type MemScanResult struct {
	bsize      int
	pid        uint
	image_name string
	matches    []MemMatchResult //this matches will be modified
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
}

var au aurora.Aurora

//Very basic flag logic, use cobra, clapper , pflags , etc if really needed in the future
func parseCommandLineAndValite() GoMemScanArgs {

	args := GoMemScanArgs{}

	flag.StringVar(&args.pattern, "pattern", "", "(*required) Pattern to match Ex: \\x41\\x41 - Warning: a match all pattern will hold all the chunks in memory!")
	flag.IntVar(&args.pid, "pid", 0, "(*required) Pid to read memory from")
	flag.Uint64Var(&args.bucketLen, "blen", 4096, "Bucket size where the pattern is applied")
	flag.Uint64Var(&args.startAddress, "from", 0, "Start address (0x4444444)")
	flag.Uint64Var(&args.bytesToRead, "length", 4096, "Bytes to read")
	flag.IntVar(&args.maxMatchesPerChunk, "matches", 10, "Max matches per chunk")
	flag.IntVar(&args.contextLength, "context-bytes", 16, "Bytes to print after and before a match")
	flag.BoolVar(&args.colors, "colors", true, "enable or disable colors")
	flag.BoolVar(&args.fullScan, "fullscan", false, "Scan all mapped sections")
	flag.BoolVar(&args.stopAfterFirstMatch, "stop-first-match", false, "Stop after the first chunk match")
	flag.BoolVar(&args.verbose, "verbose", false, "Verbose")
	flag.BoolVar(&args.includeRawDump, "raw-dump", false, "Generate a file per chunk that matched with binary data")
	flag.StringVar(&args.outputFile, "output", "", "Output file name. It will be used as prefix for raw output if selected")

	flag.Parse()

	if args.pid == 0 {
		fmt.Println(au.Red("-> Error: Target PID is required\n"))
		os.Exit(1)
	}
	if args.pattern == "" {
		fmt.Println(au.Red("-> Error: Missing Scan Pattern\n"))
		os.Exit(1)
	}

	if args.includeRawDump && args.outputFile == "" {
		fmt.Println(au.Red("Error-> Provider an output file name to also generate raw dumps"))
		os.Exit(1)
	}
	if _, err := regexp.Compile(args.pattern); err != nil {
		fmt.Println(au.Sprintf(au.Red("Error-> Invalid Pattern => %s"), au.White(err)))
		os.Exit(1)
	}

	if args.bytesToRead < args.bucketLen {
		args.bucketLen = args.bytesToRead
	}

	if args.fullScan == true {
		log.Panic("Not supported bu - aca generar el array de genscan range mas facil")
	}
	return args
}

func main() {

	args := parseCommandLineAndValite()
	au = aurora.NewAurora(args.colors)
	fmt.Println(au.Sprintf(au.Green("---- [ GoMemScan Ver: %s ] ----\n"), au.White(version)))

	mRanges := memscan.GenScanRange(args.startAddress, args.bytesToRead, args.bucketLen)

	if len(mRanges) == 0 {
		fmt.Println(au.Red("Error-> Not valid memory ranges to scan\n"))
		os.Exit(1)
	}

	//From here you can use this as a module, this is the main logic for this cli tool
	smutex := sync.Mutex{}
	matches := make([]memscan.MemMatch, 0, args.maxMatchesPerChunk)

	sreg := regexp.MustCompile(args.pattern)
	memInspect := func(chunk *[]byte, location memscan.MemRange, err error) uint8 {
		// Here it will be possible to cancel the execution of next matches if needed
		if err != nil {
			fmt.Println(au.Sprintf(au.Red("-> Error scanning address at 0x%x (%s)"), au.White(location.Start), au.White(err)))
			return memscan.StopScan
		}

		if args.verbose {
			fmt.Println(au.Sprintf(au.BrightYellow("Retrieved memory from: 0x%x to 0x%x"), au.White(location.Start), au.White(location.End)))
		}
		if matchPositions := sreg.FindAllIndex(*chunk, args.maxMatchesPerChunk); matchPositions != nil {
			smutex.Lock()
			defer smutex.Unlock()
			//We store all memory regardeless contextLength
			matches = append(matches, memscan.MemMatch{Chunk: chunk, Pos: matchPositions, Location: location})
			if args.stopAfterFirstMatch {
				return memscan.StopScan
			}

		}
		return memscan.ContinueScan
	}

	memscan.ScanMemory(args.pid, &mRanges, args.bucketLen, memInspect)

	/* Output results */
	result := MemScanResult{bsize: 0, pid: 0, image_name: "@"}
	processOutput(&result, matches, args.includeRawDump, args.outputFile, args.contextLength)

	resultJson, err := json.Marshal(result)
	if args.outputFile != "" {
		if err == nil {
			saveRawChunk(&resultJson, args.outputFile)
		} else {
			fmt.Println(au.Sprintf(au.Red("-> Error generating json output (%s)"), au.White(err)))
		}
	} else {
		fmt.Println(string(resultJson))
	}

}

func saveRawChunk(data *[]byte, outputFile string) {

	f, err := os.OpenFile(outputFile, os.O_WRONLY|os.O_CREATE, 0755)

	if err != nil {
		fmt.Println(au.Sprintf(au.Red("-> Error saving raw data to file %s (%s)"), au.White(outputFile), au.White(err)))
		return
	}
	defer f.Close()
	if _, err := f.Write(*data); err != nil {
		fmt.Println(au.Sprintf(au.Red("-> Error writing  data to file (%s)"), au.White(err)))
	}

}
func processOutput(result *MemScanResult, matches []memscan.MemMatch, rawDump bool, outputFile string, contextLength int) {

	for _, match := range matches {
		//fmt.Println(match)

		chunkLength := len(*match.Chunk)
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
			mtr.Chunk = new(([]byte))
			*mtr.Chunk = (*match.Chunk)[spos:epos]
			result.matches = append(result.matches, mtr)

		}

	}

}
