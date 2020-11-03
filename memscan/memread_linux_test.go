package memscan

import (
	"bufio"
	"reflect"
	"strings"
	"testing"
)

func Test_buildStringFromPermBits(t *testing.T) {
	type args struct {
		permMap uint8
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Read & Exec Memory bits",
			args: args{permMap: 5},
			want: "r-x",
		},
		{
			name: "Read only",
			args: args{permMap: 4},
			want: "r--",
		},
		{
			name: "Write & Exec only",
			args: args{permMap: 3},
			want: "-wx",
		},
		{
			name: "Read & Write & Exec",
			args: args{permMap: 7},
			want: "rwx",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildStringFromPermBits(tt.args.permMap); got != tt.want {
				t.Errorf("buildStringFromPermBits() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMemReader_parseMapReader(t *testing.T) {

	sampleData := `
	5606b6290000-5606b6291000 r--p 00000000 08:02 11541679                   /home/obelisco/a
	5606b6291000-5606b6292000 r-xp 00001000 08:02 11541679                   /home/obelisco/a
	5606b6292000-5606b6293000 r--p 00002000 08:02 11541679                   /home/obelisco/a
	5606b6294000-5606b6295000 rw-p 00003000 08:02 11541679                   /home/obelisco/a
	5606b7b2e000-5606b7b4f000 rw-p 00000000 00:00 0                          [heap]
	7f2aee4e0000-7f2aee502000 r--p 00000000 08:02 6295228                    /usr/lib/x86_64-linux-gnu/libc-2.28.so
	7f2aee64a000-7f2aee696000 r--p 0016a000 08:02 6295228                    /usr/lib/x86_64-linux-gnu/libc-2.28.so
	7f2aee696000-7f2aee697000 ---p 001b6000 08:02 6295228                    /usr/lib/x86_64-linux-gnu/libc-2.28.so
	7f2aee69d000-7f2aee6a3000 rw-p 00000000 00:00 0 
	7f2aee6e6000-7f2aee6ee000 r--p 0001f000 08:02 6294572                    /usr/lib/x86_64-linux-gnu/ld-2.28.so
	7f2aee6ee000-7f2aee6ef000 r--p 00026000 08:02 6294572                    /usr/lib/x86_64-linux-gnu/ld-2.28.so
	7f2aee6f0000-7f2aee6f1000 rw-p 00000000 00:00 0 
	7fff92103000-7fff92124000 rw-p 00000000 00:00 0                          [stack]
	7fff921d5000-7fff921d9000 r--p 00000000 00:00 0                          [vvar]
	7fff921d9000-7fff921db000 r-xp 00000000 00:00 0                          [vdso]
	`

	rd := bufio.NewReader(strings.NewReader(sampleData))
	ps := new(MemReader)
	got := ps.parseMapReader(rd, 0)

	expected := []MemRange{
		{
			Start: 0x5606b6290000, End: 0x5606b6291000, Name: "/home/obelisco/a",
		},
		{
			Start: 0x5606b6291000, End: 0x5606b6292000, Name: "/home/obelisco/a",
		},
		{
			Start: 0x5606b6292000, End: 0x5606b6293000, Name: "/home/obelisco/a",
		},
		{
			Start: 0x5606b6294000, End: 0x5606b6295000, Name: "/home/obelisco/a",
		},
		{
			Start: 0x5606b7b2e000, End: 0x5606b7b4f000, Name: "[heap]",
		},
		{
			Start: 0x7f2aee4e0000, End: 0x7f2aee502000, Name: "/usr/lib/x86_64-linux-gnu/libc-2.28.so",
		},
		{
			Start: 0x7f2aee64a000, End: 0x7f2aee696000, Name: "/usr/lib/x86_64-linux-gnu/libc-2.28.so",
		},
		{
			Start: 0x7f2aee69d000, End: 0x7f2aee6a3000, Name: "",
		},
		{
			Start: 0x7f2aee6e6000, End: 0x7f2aee6ee000, Name: "/usr/lib/x86_64-linux-gnu/ld-2.28.so",
		},
		{
			Start: 0x7f2aee6ee000, End: 0x7f2aee6ef000, Name: "/usr/lib/x86_64-linux-gnu/ld-2.28.so",
		},
		{
			Start: 0x7f2aee6f0000, End: 0x7f2aee6f1000, Name: "",
		},
		{
			Start: 0x7fff92103000, End: 0x7fff92124000, Name: "[stack]",
		},
		{
			Start: 0x7fff921d9000, End: 0x7fff921db000, Name: "[vdso]",
		},
	}

	if !reflect.DeepEqual(got, expected) {
		t.Errorf("MemReader.parseMapReader() = %v, want %v", got, expected)
		return
	}

}
