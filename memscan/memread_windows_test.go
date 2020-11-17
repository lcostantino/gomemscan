package memscan

import (
	"testing"
	"github.com/0xrawsec/golang-win32/win32"
)

func Test_getFilteredStates(t *testing.T) {
	type args struct {
		permMap uint8
	}
	tests := []struct {
		name string
		args args
		want uint32
	}{
	
			{
				name: "Read & Exec Memory bits",
				args: args{permMap: 5},
				want: win32.PAGE_READONLY |  win32.PAGE_EXECUTE_READ | win32.PAGE_EXECUTE | win32.PAGE_EXECUTE_READWRITE | win32.PAGE_EXECUTE_WRITECOPY | win32.PAGE_EXECUTE_READ,
			},
			{
				name: "Read only",
				args: args{permMap: 4},
				want: win32.PAGE_READONLY,
			},
			{
				name: "Write & Exec only",
				args: args{permMap: 3},
				want: win32.PAGE_READWRITE | win32.PAGE_WRITECOPY |win32.PAGE_EXECUTE_READ | win32.PAGE_EXECUTE | win32.PAGE_EXECUTE_READWRITE | win32.PAGE_EXECUTE_WRITECOPY | win32.PAGE_EXECUTE_READ ,
			},
			{
				name: "Read & Write & Exec",
				args: args{permMap: 7},
				want: win32.PAGE_READONLY|win32.PAGE_READWRITE | win32.PAGE_WRITECOPY | win32.PAGE_EXECUTE_READ | win32.PAGE_EXECUTE | win32.PAGE_EXECUTE_READWRITE | win32.PAGE_EXECUTE_WRITECOPY | win32.PAGE_EXECUTE_READ,
			},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getFilteredStates(tt.args.permMap); got != tt.want {
				t.Errorf("getFilteredStates() = %v, want %v", got, tt.want)
			}
		})
	}
}
