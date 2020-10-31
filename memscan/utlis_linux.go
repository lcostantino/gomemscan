package memscan

import (
	"fmt"
	"io/ioutil"
	"os"
)

//Return bin path
func GetProcessExecPath(pid int) string {
	name, _ := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	return name
}

//Return process cmdline (as it's with nuls)
func GetProcessCmdLine(pid int) string {
	if bt, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid)); err != nil {
		return ""
	} else {
		return string(bt)
	}
}
