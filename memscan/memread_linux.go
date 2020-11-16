package memscan

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"regexp"
	"syscall"
	"unsafe"
)

const (
	VM_READ_SYSCALL = 310
	IGNORE_PERM     = "---p"
	IGNORE_NAME     = "[vvar]"
)

//Linux Only
func (ms *MemReader) readMemoryAddress(p *MemScanProcess, m MemRange) (*[]byte, error) {
	srcAddr, dstAddr := new(iovec), new(iovec)

	srcAddr.base = uintptr(m.Start)
	srcAddr.size = m.bsize

	//we need to create the dst buffer
	mdata := make([]byte, m.bsize)
	dstAddr.base = uintptr(unsafe.Pointer(&mdata[0]))
	dstAddr.size = m.bsize

	_, _, e1 := syscall.RawSyscall6(VM_READ_SYSCALL, uintptr(p.Pid), uintptr(unsafe.Pointer(dstAddr)), 1, uintptr(unsafe.Pointer(srcAddr)), 1, 0)
	var err error
	if e1 != 0 {
		err = e1
	}

	return &mdata, err
}

func buildStringFromPermBits(permMap uint8) string {

	perms := make([]byte, 3)
	vals := []struct {
		n uint8
		s byte
	}{{4, 'r'}, {2, 'w'}, {1, 'x'}}

	if permMap == 0 {
		return ".*"
	}
	for idx, v := range vals {
		if permMap&v.n == v.n {
			perms[idx] = v.s
		} else {
			perms[idx] = '-'
		}
	}
	return string(perms)
}
func (ms *MemReader) parseMapReader(ior *bufio.Reader, permMap uint8) []MemRange {
	mRanges := make([]MemRange, 0, 10)

	var start, end, ig uint64
	var perm, image string

	regPerm := buildStringFromPermBits(permMap)
	for {
		line, err := ior.ReadString('\n')

		if err != nil && err == io.EOF {
			break
		}
		image = ""
		if _, err := fmt.Sscanf(line, "%x-%x %s %x %d:%d %d\t%s", &start, &end, &perm, &ig, &ig, &ig, &ig, &image); err != nil {
			if _, err = fmt.Sscanf(line, "%x-%x %s %x %d:%d %d\t", &start, &end, &perm, &ig, &ig, &ig, &ig); err != nil {
				continue
			}
		}

		//not really needed but can be handy in the future
		if perm != IGNORE_PERM && image != IGNORE_NAME {
			if m, _ := regexp.MatchString(regPerm, perm); m {
				mRanges = append(mRanges, MemRange{Start: start, End: end, Name: image})
			}
		}
	}

	return mRanges
}

//returns memory maps from /proc/pid/maps
// MemRange is just a holder for MAPS will be recreated properly with bsize afterwards
func (ms *MemReader) readMemoryMapFromProc(p *MemScanProcess, permMap uint8) ([]MemRange, error) {
	var fp *os.File
	var err error
	if fp, err = os.Open(fmt.Sprintf("/proc/%d/maps", p.Pid)); err != nil {
		return nil, err
	}
	defer fp.Close()
	ranges := ms.parseMapReader(bufio.NewReader(fp), permMap)

	return ranges, err

}

//For a given PID returns the memory mapped
func (ms *MemReader) GetScanRangeForPidMaps(p *MemScanProcess, permMap uint8, bucketLen uint64) ([]MemRange, error) {
	ranges, err := ms.readMemoryMapFromProc(p, permMap)
	if err != nil {
		return nil, err
	}
	scanRanges := make([]MemRange, 0, len(ranges))
	//build the real Ranges
	for _, memMap := range ranges {
		scanRanges = append(scanRanges, ms.GenScanRange(memMap.Start, memMap.End-memMap.Start, bucketLen, memMap.Name)...)
	}
	return scanRanges, nil

}
