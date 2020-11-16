package memscan

import (
	"fmt"
	"io/ioutil"
	"os"
)

func GetProcessPathAndCmdline(process *MemScanProcess) (string, string, error) {
	var err error
	var name, cmdLine string
	if name, err = os.Readlink(fmt.Sprintf("/proc/%d/exe", process.Pid)); err == nil {

		if bt, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/cmdline", process.Pid)); err == nil {
			cmdLine = string(bt)
		}
	}
	return name, cmdLine, err
}

func GetProcess(pid int) (*MemScanProcess, error) {
	if _, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); err != nil {
		return nil, err
	}
	ps := new(MemScanProcess)
	ps.Pid = pid
	return ps, nil
}

func (p *MemScanProcess) Close() {}
