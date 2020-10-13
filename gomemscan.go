package main

import (
	"flag"
	"fmt"
	"os"
	"regexp"
	"sync"

	"github.com/lcostantino/gomemscan/memscan"
	"github.com/logrusorgru/aurora"
)

var version = "replace"

func main() {

	pattern := flag.String("pattern", "", "(*required) Pattern to match")
	pid := flag.Int("pid", 0, "(*required) Pid to read memory from")
	bucketLen := flag.Uint64("blen", 4096, "Bucket size where the pattern is applied")
	startAddress := flag.Uint64("from", 0, "Start address (0x4444444)")
	bytesToRead := flag.Uint64("length", 4096, "Bytes to read")
	maxMatchesPerChunk := flag.Int("matches", 25, "Max matches per chunk")
	contextLength := flag.Int("bytes after and before each find", 32, "Bytes after and before context. -1 dump print full chunk")
	colors := flag.Bool("colors", true, "enable or disable colors")
	//fullScan := flag.Bool("fullscan", false, "Scan all mapped sections")

	flag.Parse()
	au := aurora.NewAurora(*colors)
	fmt.Println(au.Sprintf(au.Green("---- [ GoMemScan Ver: %s ] ----"), au.White(version)))
	//Very basic flag logic, use cobra, clapper , pflags , etc if really needed in the future
	if *pid == 0 {
		fmt.Println(au.Red("Error: Missing PID\n"))
		os.Exit(1)
	}
	if *pattern == "" {
		fmt.Println(au.Red("Error: Missing Pattern\n"))
		os.Exit(1)
	}
	sreg, err := regexp.Compile(*pattern)
	if err != nil {
		fmt.Println(au.Sprintf(au.Red("Error: Invalid Pattern => %s"), au.White(err)))
		os.Exit(1)
	}

	if *bytesToRead < *bucketLen {
		*bucketLen = *bytesToRead
	}

	mRanges := memscan.GenScanRange(*startAddress, *bytesToRead, *bucketLen)

	if len(mRanges) == 0 {
		fmt.Println(au.Red("Error: Not valid memory ranges to scan\n"))
		os.Exit(1)
	}
	fmt.Println(mRanges)
	//Agregar un matxMatches para limiter el -1 de findAllIndex

	//cancellation channel, not used right now
	done := make(chan int)
	defer close(done)
	//we can use channel as well..
	//This define the callback function
	smutex := sync.Mutex{}
	matches := make([]memscan.MemMatch, 0, 25)
	memInspect := func(chunk *[]byte, location memscan.MemRange) bool {
		// Here it will be possible to cancel the execution of next matches if needed
		if matchPositions := sreg.FindAllIndex(*chunk, *maxMatchesPerChunk); matchPositions != nil {
			smutex.Lock()
			defer smutex.Unlock()
			//We store all memory regardeless contextLength
			matches = append(matches, memscan.MemMatch{Chunk: chunk, Pos: matchPositions, Location: location})

			return true
		}
		return false
	}

	memscan.ScanMemory(*pid, &mRanges, *bucketLen, memInspect, done)

	/* Output results */

	*contextLength = 0

	fmt.Println(matches)
	fmt.Println("END?")
	//invocar el scan, leer tambien el /proc :), agrear colores
	//scanFullMemoryForRegexp(*pid, *startAddress, *lenghtRead, *bucketLen, sreg)
	//wanna cancel scan from callback? use this channel

}
