package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	exitServiceNotActive      = 1062
	exitServiceAlreadyRunning = 1056
)

func main() {
	setConsoleTitle("Reset AnyDesk")
	_ = exec.Command("chcp", "437").Run()

	ensureAdministrator()

	allUsersAnyDesk := filepath.Join(os.Getenv("ALLUSERSPROFILE"), "AnyDesk")
	appDataAnyDesk := filepath.Join(os.Getenv("APPDATA"), "AnyDesk")
	tempDir := os.TempDir()
	tempUserConf := filepath.Join(tempDir, "user.conf")
	tempThumbnails := filepath.Join(tempDir, "thumbnails")

	stopAnyDesk()

	_ = os.Remove(filepath.Join(allUsersAnyDesk, "service.conf"))
	_ = os.Remove(filepath.Join(appDataAnyDesk, "service.conf"))

	_ = copyFile(filepath.Join(appDataAnyDesk, "user.conf"), tempUserConf)
	_ = os.RemoveAll(tempThumbnails)
	_ = copyDir(filepath.Join(appDataAnyDesk, "thumbnails"), tempThumbnails)

	_ = deleteFilesInDir(allUsersAnyDesk)
	_ = deleteFilesInDir(appDataAnyDesk)

	startAnyDesk()

	systemConf := filepath.Join(allUsersAnyDesk, "system.conf")
	for !systemConfHasAnynetID(systemConf) {
		time.Sleep(200 * time.Millisecond)
	}

	stopAnyDesk()

	_ = os.MkdirAll(appDataAnyDesk, 0o755)
	_ = moveFile(tempUserConf, filepath.Join(appDataAnyDesk, "user.conf"))
	_ = copyDir(tempThumbnails, filepath.Join(appDataAnyDesk, "thumbnails"))
	_ = os.RemoveAll(tempThumbnails)

	startAnyDesk()

	fmt.Println("*********")
	fmt.Println("Success Process")
	fmt.Println()
	waitForExit()
}

func isAdministrator() bool {
	key, err := registry.OpenKey(registry.USERS, `S-1-5-19`, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	_ = key.Close()
	return true
}

const shellExecuteUserCancelled = 1223

func ensureAdministrator() {
	if isAdministrator() {
		return
	}
	if err := relaunchElevated(); err != nil {
		if errors.Is(err, errElevationCancelled) {
			fmt.Println("Administrator permission was cancelled.")
		} else {
			fmt.Println("Please Run as administrator.")
			fmt.Println(err)
		}
		waitForExit()
		os.Exit(1)
	}
	os.Exit(0)
}

var errElevationCancelled = errors.New("elevation cancelled by user")

func relaunchElevated() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return err
	}

	verb, err := windows.UTF16PtrFromString("runas")
	if err != nil {
		return err
	}
	lpFile, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return err
	}
	lpDir, err := windows.UTF16PtrFromString(filepath.Dir(exe))
	if err != nil {
		return err
	}

	shellExecuteW := windows.NewLazySystemDLL("shell32.dll").NewProc("ShellExecuteW")
	ret, _, _ := shellExecuteW.Call(
		0,
		uintptr(unsafe.Pointer(verb)),
		uintptr(unsafe.Pointer(lpFile)),
		0,
		uintptr(unsafe.Pointer(lpDir)),
		1,
	)
	if ret <= 32 {
		if ret == shellExecuteUserCancelled {
			return errElevationCancelled
		}
		return fmt.Errorf("elevation failed (error %d)", ret)
	}
	return nil
}

func scExitCode(action, serviceName string) int {
	cmd := exec.Command("sc", action, serviceName)
	err := cmd.Run()
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return -1
}

func stopAnyDesk() {
	for {
		scExitCode("stop", "AnyDesk")
		if scExitCode("stop", "AnyDesk") == exitServiceNotActive {
			break
		}
	}
	_ = exec.Command("taskkill", "/f", "/im", "AnyDesk.exe").Run()
}

func startAnyDesk() {
	for {
		scExitCode("start", "AnyDesk")
		if scExitCode("start", "AnyDesk") == exitServiceAlreadyRunning {
			break
		}
	}

	sysDrive := os.Getenv("SystemDrive")
	if sysDrive == "" {
		sysDrive = "C:"
	}
	candidates := []string{
		filepath.Join(sysDrive, "Program Files (x86)", "AnyDesk", "AnyDesk.exe"),
		filepath.Join(sysDrive, "Program Files", "AnyDesk", "AnyDesk.exe"),
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			_ = exec.Command(p).Start()
		}
	}
}

func systemConfHasAnynetID(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return strings.Contains(string(data), "ad.anynet.id=")
}

func deleteFilesInDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		_ = os.Remove(filepath.Join(dir, e.Name()))
	}
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}

func moveFile(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	if err := copyFile(src, dst); err != nil {
		return err
	}
	return os.Remove(src)
}

func copyDir(src, dst string) error {
	info, err := os.Stat(src)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if !info.IsDir() {
		return copyFile(src, dst)
	}

	if err := os.MkdirAll(dst, info.Mode()); err != nil {
		return err
	}

	return filepath.WalkDir(src, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		return copyFile(path, target)
	})
}

func setConsoleTitle(title string) {
	p, _ := windows.UTF16PtrFromString(title)
	proc := windows.NewLazySystemDLL("kernel32.dll").NewProc("SetConsoleTitleW")
	_, _, _ = proc.Call(uintptr(unsafe.Pointer(p)))
}

func waitForExit() {
	fmt.Print("Press Enter to exit...")
	_, _ = bufio.NewReader(os.Stdin).ReadBytes('\n')
}
