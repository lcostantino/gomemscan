package memscan

import (
	"syscall"
	"unsafe"
)

const vmreadSyscall = 310

//Linux Only
func readMemoryAddress(pid int, m MemRange) (*[]byte, error) {
	srcAddr, dstAddr := new(iovec), new(iovec)

	srcAddr.base = uintptr(m.Start)
	srcAddr.size = m.bsize

	//we need to create the dst buffer
	mdata := make([]byte, m.bsize)
	dstAddr.base = uintptr(unsafe.Pointer(&mdata[0]))
	dstAddr.size = m.bsize

	_, _, e1 := syscall.RawSyscall6(vmreadSyscall, uintptr(pid), uintptr(unsafe.Pointer(dstAddr)), 1, uintptr(unsafe.Pointer(srcAddr)), 1, 0)
	var err error
	if e1 != 0 {
		err = e1
	}

	return &mdata, err
}
