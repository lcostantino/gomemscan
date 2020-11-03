//Mem scan utlities
package memscan

import (
	"context"
	"math"
)

//Struct holder
type MemReader struct {
}

//Generate a slice of mem scan ranges
//
//Starting at address "from", generatin chunks of bsize length until from+length is reached
//
//Improvement: Add a function to allow inline scan, in case if needed
func (ms *MemReader) GenScanRange(from uint64, length uint64, bsize uint64, name string) []MemRange {

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
		mranges = append(mranges, MemRange{Start: from, End: endAddr, bsize: bsize, Name: name})
		from = endAddr
	}
	return mranges
}

//Scan a process for the given memory ranges , invoking callback function with cunks of bsize bytes
func (ms *MemReader) ScanMemory(pid int, mranges *[]MemRange, bsize uint64, callback func(data *[]byte, mrange MemRange, err error) uint8) {

	totalGoRoutines := 6
	scanWork := func(mRangeChannel chan MemRange, ctx context.Context, resultChan chan uint8) {
		for {
			select {
			case <-ctx.Done(): // Done returns a channel that's closed when work done on behalf of this context is canceled
				resultChan <- WorkerExit
				return
			case m, ok := <-mRangeChannel:
				if !ok {
					resultChan <- WorkerExit
					return
				}
				data, err := ms.readMemoryAddress(pid, m)
				if ret := callback(data, m, err); ret == StopScan {
					//this is to Cancel without blocking with waitGroup()
					resultChan <- ret

				}
			}
		}
	}

	//Note: all this mess could be replaced by just wg.Wait() if you don't want to cancel
	mRangeChannel := make(chan MemRange, totalGoRoutines)
	resultChan := make(chan uint8, 1)

	ctx, cancel := context.WithCancel(context.Background())
	for i := 0; i < totalGoRoutines; i++ {

		go scanWork(mRangeChannel, ctx, resultChan)
	}

	for _, mRange := range *mranges {
		mRangeChannel <- mRange
	}

	close(mRangeChannel)
	defer close(resultChan)
	for total := totalGoRoutines; total != 0; {
		select {
		case v, _ := <-resultChan:
			if v == StopScan {
				cancel()
			} else if v == WorkerExit {

				total--
			}
		}
	}
}
