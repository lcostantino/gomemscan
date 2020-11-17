package main

import (
	"github.com/lcostantino/gomemscan/memscan"
)

type MemScanner interface {
	Match(chunk *[]byte, location memscan.MemRange, workerNum int) bool
	GetMatches() []memscan.MemMatch
	Init(args map[string]interface{}) error
}

type ScannerConfig struct {
	justMatch          bool
	maxMatchesPerChunk int
}
