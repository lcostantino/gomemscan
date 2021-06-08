package memscan

import (
	"syscall"

	"github.com/0xrawsec/golang-win32/win32"
	"github.com/0xrawsec/golang-win32/win32/kernel32"

	//for SystemInfo & NtProcessInfo
	"github.com/elastic/go-windows"
)

const (
	IGNORE_PERM  = "---p"
	IGNORE_NAME  = "[vvar]"
	PARTIAL_READ = 299
)

func (ms *MemReader) readMemoryAddress(p *MemScanProcess, m MemRange) (*[]byte, error) {

	readSize := uintptr(m.End - m.Start)

	data := make([]byte, readSize)
	nread, err := windows.ReadProcessMemory(syscall.Handle(p.Handle), uintptr(m.Start), data)
	if nread < readSize {
		data = data[0:nread]
	}
	if interr, ok := err.(syscall.Errno); ok {
		if interr == PARTIAL_READ {
			err = nil
		}
	}

	return &data, err
}

//This is confusing on windows, try to just use 0 or the octal linux combination
//TODO: add test
func getFilteredStates(permMap uint8) uint32 {

	var perms uint32 = 0
	vals := []struct {
		n uint8
		s uint32
	}{
		{4, win32.PAGE_READONLY},
		{2, win32.PAGE_READWRITE | win32.PAGE_WRITECOPY},
		{1, win32.PAGE_EXECUTE_READ | win32.PAGE_EXECUTE | win32.PAGE_EXECUTE_READWRITE | win32.PAGE_EXECUTE_WRITECOPY | win32.PAGE_EXECUTE_READ},
	}
	for _, v := range vals {
		if permMap&v.n == v.n || permMap == 0 {
			perms |= v.s
		}
	}
	return perms
}

func (ms *MemReader) readMemoryMapFromProc(p *MemScanProcess, permMap uint8) ([]MemRange, error) {
	var pAddr uintptr = 0
	var err error
	mRanges := make([]MemRange, 0, 15)

	if sysinfo, err := windows.GetNativeSystemInfo(); err == nil {
		states := getFilteredStates(permMap)
		for pAddr = sysinfo.MinimumApplicationAddress; pAddr < sysinfo.MaximumApplicationAddress; {
			if mRegion, err := kernel32.VirtualQueryEx(win32.HANDLE(p.Handle), win32.LPCVOID(pAddr)); err == nil {
				if (mRegion.State&win32.MEM_COMMIT) == win32.MEM_COMMIT && (win32.DWORD(states)&mRegion.AllocationProtect == mRegion.AllocationProtect) {
					mRanges = append(mRanges, MemRange{Start: uint64(mRegion.BaseAddress), End: uint64(mRegion.BaseAddress) + uint64(mRegion.RegionSize), Name: ""})
				}
				pAddr += uintptr(mRegion.RegionSize)
			} else {
				break
			}
		}
	}

	return mRanges, err
}

//For a given PID returns the memory mapped
func (ms *MemReader) GetScanRangeForPidMaps(process *MemScanProcess, permMap uint8, bucketLen uint64) ([]MemRange, error) {
	ranges, err := ms.readMemoryMapFromProc(process, permMap)

	if err != nil {
		return nil, err
	}
	scanRanges := make([]MemRange, 0, len(ranges))
	//build the real Ranges
	//NOTE: In normal cases, windows will return smaller sections so this won't have additional effects
	for _, memMap := range ranges {
		scanRanges = append(scanRanges, ms.GenScanRange(memMap.Start, memMap.End-memMap.Start, bucketLen, memMap.Name)...)
	}

	return scanRanges, nil

}
