package memscan

type iovec struct {
	base uintptr
	size uint64 //probably we can use C.size_t as well if using Cgo
}

//Simple memrange structure
type MemRange struct {
	Start uint64 `json:"Start"`
	End   uint64 `json:"End"`
	bsize uint64 `json:"-"`
}

//For each Match on a chunk all found locations
type MemMatch struct {
	Chunk    *[]byte
	Pos      [][]int
	Location MemRange
}

const (
	WorkerExit uint8 = iota
	ContinueScan
	StopScan
)