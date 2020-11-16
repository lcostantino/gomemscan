package memscan

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"github.com/elastic/go-windows"
	elas "github.com/elastic/go-windows"
	win "golang.org/x/sys/windows"
)

const (
	PROCESS_ALL_ACCESS = syscall.STANDARD_RIGHTS_REQUIRED | syscall.SYNCHRONIZE | 0xfff
)

func init() {

	if err := memscan.EnableDebugPrivileges(); err != nil {
		fmt.Printf("Error: Need debug privileges on windows => %s", err)
		os.Exit(1)
	}

}
func EnableDebugPrivileges() error {
	var tk win.Token
	var luid win.LUID
	p := new(win.Tokenprivileges)
	defer tk.Close()

	ps, _ := win.GetCurrentProcess()
	if err := win.OpenProcessToken(ps, win.TOKEN_ADJUST_PRIVILEGES|win.TOKEN_QUERY, &tk); err != nil {
		return err
	}
	if err := win.LookupPrivilegeValue(nil, win.StringToUTF16Ptr("SeDebugPrivilege"), &luid); err == nil {
		p.PrivilegeCount = 1
		p.Privileges[0] = win.LUIDAndAttributes{Luid: luid, Attributes: win.SE_PRIVILEGE_ENABLED}
		return win.AdjustTokenPrivileges(tk, false, p, 0, nil, nil)
	} else {
		return err
	}

}

func getAddress(pdata *[]byte, offset uint, size uint) uint {
	var pAddr uint

	if pdata == nil || offset+size > uint(len(*pdata)) {
		return pAddr
	}
	for x := 0; x < 8; x++ {
		pAddr |= uint((*pdata)[offset+uint(x)]) << (x * 8)
	}
	return pAddr
}

// Read a unicode struct from a given offset
func readUnicodeStruct(process *MemScanProcess, pdata *[]byte, offset uintptr, size uint) (string, error) {
	var us windows.UnicodeString
	var str string

	bufferOffset := offset + unsafe.Offsetof(us.Buffer)
	//Extract Unicode String structure (size, maxlength, buffer)
	mSize := uint((*pdata)[offset]) | uint((*pdata)[offset+1])<<8

	buffAddress := getAddress(pdata, uint(bufferOffset), size)
	asBytes := make([]byte, mSize)

	rsize, err := windows.ReadProcessMemory(syscall.Handle(process.Handle), uintptr(buffAddress), asBytes)

	if err != nil {
		return str, err
	}
	//This is what happens when we need to work with internals :)
	if uint(rsize) == mSize {
		as16 := make([]uint16, rsize/2)
		tsize := int(rsize)
		for x, j := 0, 0; x < tsize; x, j = x+2, j+1 {
			as16[j] = uint16(asBytes[x]) | uint16(asBytes[x+1])<<8
		}
		str = win.UTF16ToString(as16)
	}
	return str, err

}

//More complex and robust method can be found at https://github.com/shirou/gopsutil/blob/7e5409b1310ad25ab30db1bc270534f3776a5851/v3/process/process_windows.go
func GetProcessPathAndCmdline(process *MemScanProcess) (string, string, error) {
	infoClass := windows.ProcessBasicInformation

	var info windows.ProcessBasicInformationStruct
	infoLen := uint32(unsafe.Sizeof(info))

	if _, err := elas.NtQueryInformationProcess(syscall.Handle(process.Handle), infoClass, unsafe.Pointer(&info), infoLen); err != nil {
		return "", "", err
	}

	asBytes := make([]byte, windows.SizeOfRtlUserProcessParameters)

	var offset uint = 0x20

	//Read ProcessParameters
	//TODO: create a proper PebBase structure to avoid this offset if possible
	rdata, err := windows.ReadProcessMemory(syscall.Handle(process.Handle), info.PebBaseAddress, asBytes)
	//TODO: 32 bits if needed. Wow64 should work

	//Get PEB process address field to read the struct
	processParametersAddress := getAddress(&asBytes, offset, 8)

	rdata, err = windows.ReadProcessMemory(syscall.Handle(process.Handle), uintptr(processParametersAddress), asBytes)
	if err != nil {
		return "", "", err
	}

	pName, cmdLine := "", ""

	if rdata == windows.SizeOfRtlUserProcessParameters {
		var upp windows.RtlUserProcessParameters
		if pName, err = readUnicodeStruct(process, &asBytes, unsafe.Offsetof(upp.ImagePathName), 8); err == nil {
			cmdLine, err = readUnicodeStruct(process, &asBytes, unsafe.Offsetof(upp.CommandLine), 8)
		}
	}
	return pName, cmdLine, nil
}

//same as FindProcess with different flags
func GetProcess(pid int) (*MemScanProcess, error) {

	const flagsOpen = PROCESS_ALL_ACCESS
	h, e := syscall.OpenProcess(flagsOpen, false, uint32(pid))
	if e != nil {
		return nil, e
	}
	ps := &MemScanProcess{Pid: pid, Handle: uintptr(h)}
	return ps, nil
}

func (p *MemScanProcess) Close() {
	win.CloseHandle(win.Handle(p.Handle))
}
