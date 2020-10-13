//Mem scan utlities
package memscan

import (
	"fmt"
	"math"
	"sync"
	"syscall"
	"unsafe"
)

//Generate a slice of mem scan ranges
//
//Starting at address "from", generatin chunks of bsize length until from+length is reached
//
//Improvement: Add a function to allow inline scan, in case if needed
func GenScanRange(from uint64, length uint64, bsize uint64) []MemRange {

	var endAddr uint64
	to := from + length
	totalBuckets := uint64(math.Ceil(float64(length) / float64(bsize)))
	mranges := make([]MemRange, 0, totalBuckets)

	for from < to {
		endAddr = (from + bsize)
		if endAddr > to {
			bsize = (bsize - (endAddr - to))
			endAddr = to
		}
		mranges = append(mranges, MemRange{start: from, end: endAddr, bsize: bsize})
		from = endAddr
	}

	return mranges
}

func readMemoryAddress(pid int, m MemRange) (*[]byte, error) {
	srcAddr, dstAddr := new(iovec), new(iovec)

	srcAddr.base = uintptr(m.start)
	srcAddr.size = m.bsize

	//we need to create the dst buffer
	mdata := make([]byte, m.bsize)
	dstAddr.base = uintptr(unsafe.Pointer(&mdata[0]))
	dstAddr.size = m.bsize

	_, _, e1 := syscall.RawSyscall6(310, uintptr(pid), uintptr(unsafe.Pointer(dstAddr)), 1, uintptr(unsafe.Pointer(srcAddr)), 1, 0)
	var err error
	if e1 != 0 {
		err = e1
	}

	return &mdata, err
}

//agregar un channel de cancle
//Scan a process for the given memory ranges , invoking callback function with cunks of bsize bytes
func ScanMemory(pid int, mranges *[]MemRange, bsize uint64, callback func(data *[]byte, mrange MemRange) bool, done <-chan int) {

	var wg sync.WaitGroup
	wg.Add(len(*mranges))

	scanWork := func(m MemRange) {
		defer wg.Done()
		fmt.Printf("Scanning %x to %x\n", m.start, m.end)

		select {
		case <-done:
			return
		default:
			if data, err := readMemoryAddress(pid, m); err == nil {
				callback(data, m)

			} else {
				fmt.Printf("ERROR: %v\n", err)
			}
		}
	}
	for _, mRange := range *mranges {
		go scanWork(mRange)
	}

	wg.Wait()
}

/* Look for Text Patterns actually on each read bucket
func scanFullMemoryForRegexp(pid int, from uint64, lenght uint64, bsize uint64, sreg *regexp.Regexp) {

	var i, endAddr uint64
	to := from + lenght
	totalBuckets := (lenght / bsize) + 1

	if totalBuckets == 0 {
		totalBuckets = 1
	}
	fmt.Printf("To is %x And Bsize is %x and From\n", to, bsize)
	for i = 0; i < totalBuckets; i++ {

		endAddr = (from + bsize)
		fmt.Printf("and end addr is %x and From: %x\n", endAddr, from)
		if from >= to {
			break
		}
		if endAddr > to {
			bsize = (bsize - (endAddr - to))
			fmt.Printf("Correcting size since %x  > %x and bsize now is %v\n", endAddr, to, bsize)

			endAddr = to

		}
		fmt.Printf("Going to scan bucket %d - Start: %x End: %x\n", i, from, endAddr)
		if data, err := readMemoryAddress(pid, from, endAddr, bsize); err == nil {
			if sreg.Match(data) {
				fmt.Println("Data: %v\n", data)
			}

		} else {
			fmt.Printf("ERROR: %v\n", err)
		}

		from = endAddr

	}
}
*/
