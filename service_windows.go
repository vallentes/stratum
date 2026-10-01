//go:build windows

package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const serviceName = "StratumCollector"

type svcHandler struct{ run func() }

func (h svcHandler) Execute(args []string, r <-chan svc.ChangeRequest, s chan<- svc.Status) (bool, uint32) {
	s <- svc.Status{State: svc.StartPending}
	go h.run()
	s <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for c := range r {
		switch c.Cmd {
		case svc.Interrogate:
			s <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			s <- svc.Status{State: svc.StopPending}
			return false, 0
		}
	}
	return false, 0
}

// runService runs fn under the Windows service manager when started by it.
func runService(fn func()) bool {
	is, err := svc.IsWindowsService()
	if err != nil || !is {
		return false
	}
	svc.Run(serviceName, svcHandler{fn})
	return true
}

func isElevated() bool { return windows.GetCurrentProcessToken().IsElevated() }

var (
	user32          = windows.NewLazySystemDLL("user32.dll")
	procMessageBoxW = user32.NewProc("MessageBoxW")
)

func messageBox(title, text string, isErr bool) {
	t, _ := windows.UTF16PtrFromString(title)
	m, _ := windows.UTF16PtrFromString(text)
	flags := uintptr(0x40) // MB_ICONINFORMATION
	if isErr {
		flags = 0x10 // MB_ICONERROR
	}
	procMessageBoxW.Call(0, uintptr(unsafe.Pointer(m)), uintptr(unsafe.Pointer(t)), flags)
}

// relaunchElevated re-runs this exact command through the UAC prompt.
func relaunchElevated(args []string) error {
	exe, _ := os.Executable()
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = syscall.EscapeArg(a)
	}
	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(exe)
	params, _ := windows.UTF16PtrFromString(strings.Join(quoted, " "))
	dir, _ := windows.UTF16PtrFromString(filepath.Dir(exe))
	return windows.ShellExecute(0, verb, file, params, dir, windows.SW_HIDE)
}

func installDirs() (bin, data string) {
	pf := os.Getenv("ProgramFiles")
	if pf == "" {
		pf = `C:\Program Files`
	}
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	return filepath.Join(pf, "Stratum"), filepath.Join(pd, "Stratum", "collector-data")
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".new"
	out, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	out.Close()
	os.Remove(dst)
	return os.Rename(tmp, dst)
}

// installService copies the binary to Program Files, (re)registers the auto-start
// LocalSystem service with restart-on-failure, and starts it. From a normal prompt it
// raises the UAC prompt itself and reports the outcome in a message box.
func installService(args []string) error {
	if !isElevated() {
		full := append([]string{"collector", "-install"}, args...)
		if err := relaunchElevated(full); err != nil {
			return fmt.Errorf("could not request administrator rights: %w", err)
		}
		fmt.Println("Approve the Windows administrator prompt. A message box confirms the install.")
		return errAsyncInstall
	}
	err := doInstall(args)
	if err != nil {
		messageBox("Stratum collector", "Install failed:\n\n"+err.Error(), true)
	} else {
		bin, data := installDirs()
		messageBox("Stratum collector", "Installed and running as the StratumCollector service.\n\nProgram: "+bin+"\nLog: "+filepath.Join(data, "collector.log")+
			"\n\nIt shows as online on the Index page within a few seconds.", false)
	}
	return err
}

// svcSpec describes one of the two services this binary can install.
type svcSpec struct {
	name, display, desc string
	binDir, dataDir     string
	args                func(dataDir string) []string
}

func collectorSpec(args []string) svcSpec {
	binDir, dataDir := installDirs()
	return svcSpec{name: serviceName, display: "Stratum Collector",
		desc:   "Indexes file share metadata and forwards file audit events to the Stratum server.",
		binDir: binDir, dataDir: dataDir,
		args: func(dataDir string) []string {
			// The service always keeps its state under ProgramData, whatever -data said.
			var out []string
			for i := 0; i < len(args); i++ {
				if args[i] == "-data" || args[i] == "--data" {
					i++
					continue
				}
				out = append(out, args[i])
			}
			return append([]string{"collector"}, append(out, "-data", dataDir)...)
		}}
}

const serverServiceName = "StratumServer"

func serverSpec() svcSpec {
	pf, pd := os.Getenv("ProgramFiles"), os.Getenv("ProgramData")
	if pf == "" {
		pf = `C:\Program Files`
	}
	if pd == "" {
		pd = `C:\ProgramData`
	}
	return svcSpec{name: serverServiceName, display: "Stratum Server",
		desc:   "Stratum File Analytics: metadata index, reports and web UI on port 8470.",
		binDir: filepath.Join(pf, "Stratum Server"), dataDir: filepath.Join(pd, "Stratum", "server-data"),
		args: func(dataDir string) []string { return []string{"-addr", ":8470", "-data", dataDir} }}
}

func doInstall(args []string) error { return installAs(collectorSpec(args)) }

// installAs copies the binary, (re)registers the auto-start LocalSystem service with
// restart-on-failure, and starts it.
func installAs(sp svcSpec) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	binDir, dataDir := sp.binDir, sp.dataDir
	os.MkdirAll(binDir, 0o755)
	os.MkdirAll(dataDir, 0o700)
	target := filepath.Join(binDir, "stratum.exe")

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("open service manager: %w", err)
	}
	defer m.Disconnect()
	// Upgrade in place: stop and remove an existing service first.
	if s, err := m.OpenService(sp.name); err == nil {
		s.Control(svc.Stop)
		for i := 0; i < 20; i++ {
			if st, err := s.Query(); err != nil || st.State == svc.Stopped {
				break
			}
			time.Sleep(500 * time.Millisecond)
		}
		s.Delete()
		s.Close()
		time.Sleep(time.Second)
	}
	if !strings.EqualFold(filepath.Clean(exe), filepath.Clean(target)) {
		if err := copyFile(exe, target); err != nil {
			return fmt.Errorf("copy to %s: %w", target, err)
		}
	}
	os.Remove(target + ":Zone.Identifier") // downloaded-from-internet mark
	s, err := m.CreateService(sp.name, target, mgr.Config{
		DisplayName: sp.display,
		Description: sp.desc,
		StartType:   mgr.StartAutomatic,
	}, sp.args(dataDir)...)
	if err != nil {
		return err
	}
	defer s.Close()
	s.SetRecoveryActions([]mgr.RecoveryAction{{Type: mgr.ServiceRestart, Delay: 10 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second}, {Type: mgr.ServiceRestart, Delay: 60 * time.Second}}, 86400)
	return s.Start()
}

func uninstallService() error {
	if !isElevated() {
		if err := relaunchElevated([]string{"collector", "-uninstall"}); err != nil {
			return err
		}
		fmt.Println("Approve the Windows administrator prompt to remove the service.")
		return nil
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("service %s is not installed", serviceName)
	}
	defer s.Close()
	s.Control(svc.Stop)
	time.Sleep(2 * time.Second)
	err = s.Delete()
	if err == nil {
		messageBox("Stratum collector", "The StratumCollector service was removed.", false)
	}
	return err
}

// installServer installs the Stratum server as the StratumServer service and opens it
// in the browser. From a normal prompt it raises the UAC prompt itself.
func installServer() error {
	if !isElevated() {
		if err := relaunchElevated([]string{"-install-server"}); err != nil {
			return fmt.Errorf("could not request administrator rights: %w", err)
		}
		fmt.Println("Approve the Windows administrator prompt. A message box confirms the install.")
		return errAsyncInstall
	}
	sp := serverSpec()
	if err := installAs(sp); err != nil {
		messageBox("Stratum", "Install failed:\n\n"+err.Error(), true)
		return err
	}
	time.Sleep(2 * time.Second)
	openBrowser("http://localhost:8470")
	messageBox("Stratum", "Stratum is installed and running as the StratumServer service.\n\n"+
		"Open http://localhost:8470 and sign in as admin / admin. You will choose a new password straight away.\n\n"+
		"Program: "+sp.binDir+"\nData and log: "+sp.dataDir, false)
	return nil
}

func uninstallServer() error {
	if !isElevated() {
		return relaunchElevated([]string{"-uninstall-server"})
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(serverServiceName)
	if err != nil {
		return fmt.Errorf("service %s is not installed", serverServiceName)
	}
	defer s.Close()
	s.Control(svc.Stop)
	time.Sleep(2 * time.Second)
	if err = s.Delete(); err == nil {
		messageBox("Stratum", "The StratumServer service was removed. Your index is still in "+serverSpec().dataDir+".", false)
	}
	return err
}

func openBrowser(url string) {
	verb, _ := windows.UTF16PtrFromString("open")
	u, _ := windows.UTF16PtrFromString(url)
	windows.ShellExecute(0, verb, u, nil, nil, windows.SW_SHOWNORMAL)
}

func isWindowsService() bool {
	is, _ := svc.IsWindowsService()
	return is
}

var procGetConsoleProcessList = kernel32Svc.NewProc("GetConsoleProcessList")
var kernel32Svc = windows.NewLazySystemDLL("kernel32.dll")

// startedByDoubleClick is true when this process owns its console alone, which is
// what happens when the exe is opened from Explorer rather than typed in a terminal.
func startedByDoubleClick() bool {
	var pids [4]uint32
	n, _, _ := procGetConsoleProcessList.Call(uintptr(unsafe.Pointer(&pids[0])), 4)
	return n == 1
}

var procGetProcessIoCounters = kernel32Svc.NewProc("GetProcessIoCounters")

type ioCounters struct {
	ReadOps, WriteOps, OtherOps, ReadBytes, WriteBytes, OtherBytes uint64
}

// processOps is the number of I/O operations a process has issued so far.
func processOps(pid int) int64 {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return 0
	}
	defer windows.CloseHandle(h)
	var c ioCounters
	if r, _, _ := procGetProcessIoCounters.Call(uintptr(h), uintptr(unsafe.Pointer(&c))); r == 0 {
		return 0
	}
	return int64(c.ReadOps + c.WriteOps + c.OtherOps)
}

// physicalDisks returns the physical disk numbers a volume ("E:") lives on.
func physicalDisks(vol string) []uint32 {
	p, _ := windows.UTF16PtrFromString(`\\.\` + vol)
	h, err := windows.CreateFile(p, 0, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(h)
	// VOLUME_DISK_EXTENTS: DWORD count, padding, then {DWORD disk; LARGE_INTEGER start; LARGE_INTEGER length}[]
	buf := make([]byte, 8+24*8)
	var n uint32
	const ioctlGetVolumeDiskExtents = 0x00560000
	if err := windows.DeviceIoControl(h, ioctlGetVolumeDiskExtents, nil, 0, &buf[0], uint32(len(buf)), &n, nil); err != nil {
		return nil
	}
	count := *(*uint32)(unsafe.Pointer(&buf[0]))
	var out []uint32
	for i := uint32(0); i < count && 8+24*(i+1) <= uint32(len(buf)); i++ {
		out = append(out, *(*uint32)(unsafe.Pointer(&buf[8+24*i])))
	}
	return out
}
