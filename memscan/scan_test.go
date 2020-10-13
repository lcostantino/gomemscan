package memscan

import (
	"fmt"
	"reflect"
	"testing"
)

func Test_GenScanRanges(t *testing.T) {
	type args struct {
		from   uint64
		length uint64
		bsize  uint64
	}
	tests := []struct {
		name string
		args args
		want []MemRange
	}{
		{
			name: "Scan Ranges generated properly when buffer size is equal to length",
			args: args{from: 0x4000, length: 0x10, bsize: 0x10},
			want: []MemRange{{start: 0x4000, end: 0x4010, bsize: 0x10}},
		},
		{
			name: "Memory Scan not potentially aligned buff size",
			args: args{from: 0x4000, length: 0x30, bsize: 0x5},
			want: []MemRange{
				{start: 0x4000, end: 0x4005, bsize: 0x5}, {start: 0x4005, end: 0x400A, bsize: 0x5}, {start: 0x400A, end: 0x400F, bsize: 0x5},
				{start: 0x400F, end: 0x4014, bsize: 0x5}, {start: 0x4014, end: 0x4019, bsize: 0x5}, {start: 0x4019, end: 0x401E, bsize: 0x5},
				{start: 0x401E, end: 0x4023, bsize: 0x5}, {start: 0x4023, end: 0x4028, bsize: 0x5}, {start: 0x4028, end: 0x402D, bsize: 0x5},
				{start: 0x402D, end: 0x4030, bsize: 0x3}},
		},
		{
			name: "Buffer larger that length will return just length",
			args: args{from: 0x4000, length: 0x12, bsize: 0x1000},
			want: []MemRange{{start: 0x4000, end: 0x4012, bsize: 0x12}},
		},
		{
			name: "Scan Ranges generated",
			args: args{from: 0x5639f5bfd000, length: 8096, bsize: 4096},
			want: []MemRange{{start: 0x5639f5bfd000, end: 0x5639f5bfe000, bsize: 4096}, {start: 0x5639f5bfe000, end: 0x5639f5bfefa0, bsize: 4000}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GenScanRange(tt.args.from, tt.args.length, tt.args.bsize); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("genScanRange() = %v\n want %v", got, tt.want)
			}
		})
	}
}

func ExampleGenScanRange() {

	for _, rr := range GenScanRange(0x40, 0x20, 0x10) {
		fmt.Printf("0x%x 0x%x ", rr.start, rr.end)
	}
	// Output: 0x40 0x50 0x50 0x60
}
