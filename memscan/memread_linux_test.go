package memscan

import (
	"bufio"
	"reflect"
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
	type args struct {
		ior     *bufio.Reader
		permMap uint8
	}
	tests := []struct {
		name string
		ms   *MemReader
		args args
		want []MemRange
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ms := &MemReader{}
			if got := ms.parseMapReader(tt.args.ior, tt.args.permMap); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("MemReader.parseMapReader() = %v, want %v", got, tt.want)
			}
		})
	}
}
