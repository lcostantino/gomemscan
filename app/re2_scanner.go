package main

import (
	"regexp"
	"sync"

	"github.com/lcostantino/gomemscan/memscan"
)

type Re2Scanner struct {
	smutex  sync.Mutex
	matches []memscan.MemMatch
	sreg    *regexp.Regexp
	Cfg     ScannerConfig
}

const RE_SCANNER_NAME = "regex"

//Init with different arguments based on scanner
func (s *Re2Scanner) Init(args map[string]interface{}) error {
	if r, ok := args["pattern"]; ok == true {
		s.sreg = regexp.MustCompile(r.(string))
	}
	s.Cfg.justMatch = args["justMatch"].(bool)
	s.Cfg.maxMatchesPerChunk = args["maxMatchesPerChunk"].(int)
	s.matches = make([]memscan.MemMatch, 0, s.Cfg.maxMatchesPerChunk)
	return nil
}

//This is Actually the callback invoked by  memscan
func (s *Re2Scanner) Match(chunk *[]byte, location memscan.MemRange, workerNum int) bool {
	if matchPositions := s.sreg.FindAllIndex(*chunk, s.Cfg.maxMatchesPerChunk); matchPositions != nil {
		s.smutex.Lock()
		defer s.smutex.Unlock()
		//Warning: this store all memory regardeless contextLength
		if s.Cfg.justMatch {
			chunk = nil
		}
		s.matches = append(s.matches, memscan.MemMatch{Chunk: chunk, Pos: matchPositions, Location: location})
		return true
	}
	return false
}

func (s *Re2Scanner) GetMatches() []memscan.MemMatch {
	return s.matches
}

func init() {

	SupportedModes[RE_SCANNER_NAME] = new(Re2Scanner)

}
