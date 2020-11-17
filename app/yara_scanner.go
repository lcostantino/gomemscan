// +build yara

package main

import (
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/hillu/go-yara/v4"
	"github.com/lcostantino/gomemscan/memscan"
)

type YaraScanner struct {
	smutex    sync.Mutex
	matches   []memscan.MemMatch
	yscanners []*yara.Scanner
	Cfg       ScannerConfig
}

const YARA_SCANNER_NAME = "yara"

//Init with different arguments based on scanner
func (s *YaraScanner) Init(args map[string]interface{}) error {
	if r, ok := args["yaraFile"]; ok == true {

		c, err := yara.NewCompiler()
		if err != nil {
			return nil
		}
		f, err := os.Open(r.(string))
		defer f.Close()
		if err != nil {
			return fmt.Errorf("Error: Cannot open yara rule file => %s", err)
		}
		err = c.AddFile(f, "main")

		if err != nil {
			return fmt.Errorf("Error: Cannot parse yara rule => %s", err)
		}
		rules, err := c.GetRules()

		if err != nil {
			return fmt.Errorf("Error: Cannot compile rules => %s", err)
		}
		croutines := args["totalGoRoutines"].(int)

		//This is not "thread safe nor routine safe, etc" we need to keep track of each yara result on each goroutine
		s.yscanners = make([]*yara.Scanner, croutines)
		for x := 0; x < croutines; x++ {
			s.yscanners[x], _ = yara.NewScanner(rules)
		}

	} else {
		return errors.New("Yara rule file missing")
	}
	s.Cfg.justMatch = args["justMatch"].(bool)
	s.Cfg.maxMatchesPerChunk = args["maxMatchesPerChunk"].(int)
	s.matches = make([]memscan.MemMatch, 0, s.Cfg.maxMatchesPerChunk)
	return nil
}

//This is Actually the callback invoked by  memscan
func (s *YaraScanner) Match(chunk *[]byte, location memscan.MemRange, workerNum int) bool {
	var m yara.MatchRules

	s.yscanners[workerNum].SetCallback(&m).ScanMem(*chunk)
	if len(m) > 0 {
		//simulate same positions data as regex find all
		matchPositions := make([][]int, 0, len(m))
		for _, match := range m {
			for _, pos := range match.Strings {
				sindex := []int{int(pos.Offset), int(pos.Offset) + len(pos.Data)}
				matchPositions = append(matchPositions, sindex)
			}

		}
		s.smutex.Lock()
		defer s.smutex.Unlock()
		//I don't really like this logic here but it's more clear this way
		if s.Cfg.justMatch {
			chunk = nil
		}
		s.matches = append(s.matches, memscan.MemMatch{Chunk: chunk, Pos: matchPositions, Location: location})
		return true
	}

	return false
}

//Return found matches
func (s *YaraScanner) GetMatches() []memscan.MemMatch {
	return s.matches
}

func init() {

	SupportedModes[YARA_SCANNER_NAME] = &YaraScanner{}
}
