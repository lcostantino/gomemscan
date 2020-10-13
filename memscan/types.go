package memscan

type iovec struct {
	base uintptr
	size uint64 //probably we can use C.size_t as well if using Cgo
}

type MemRange struct {
	start uint64
	end   uint64 //or can be calculated start+bsize
	bsize uint64 //can be calculated from end-start, it's for convenience
}

type MemMatch struct {
	Chunk    *[]byte
	Pos      [][]int
	Location MemRange
}
