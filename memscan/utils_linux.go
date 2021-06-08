package memscan

import (
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
)

func GetProcessPathAndCmdline(process *MemScanProcess) (string, string, error) {
	var err error
	var name, cmdLine string
	if name, err = os.Readlink(fmt.Sprintf("/proc/%d/exe", process.Pid)); err == nil {

		if bt, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/cmdline", process.Pid)); err == nil {
			cmdLine = string(bt)
			cmdLine = strings.ReplaceAll(cmdLine, string([]byte{0x00}), "")
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

func GetProcessPidToScan(pid int, allPids bool) ([]int, error) {
	if allPids == false {
		return []int{pid}, nil
	}
	var pidsList []int
	me := os.Getpid()
	if oFileInfo, err := ioutil.ReadDir("/proc"); err != nil {
		return pidsList, err
	} else {
		for _, ff := range oFileInfo {
			if numericPid, err := strconv.Atoi(ff.Name()); err == nil && numericPid > 1 && numericPid != me {
				pidsList = append(pidsList, numericPid)
			}
		}
	}
	return pidsList, nil
}
func (p *MemScanProcess) Close() {}
