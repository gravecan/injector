package injector

import (
	"errors"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

func (i *Injector) diskLoadDLLWithSpoofing() error {
	i.logger.Info("Using path spoofing method")

	hProcess, err := windows.OpenProcess(
		windows.PROCESS_CREATE_THREAD|
			windows.PROCESS_VM_OPERATION|
			windows.PROCESS_VM_WRITE|
			windows.PROCESS_VM_READ|
			windows.PROCESS_QUERY_INFORMATION,
		false, i.processID)
	if err != nil {
		errMsg := "Failed to open target process: " + err.Error()
		newErr := errors.New(errMsg)
		i.logger.Error("Path spoofing failed", "error", newErr)
		return newErr
	}
	defer windows.CloseHandle(hProcess)

	i.logger.Info("Successfully opened target process")


	systemDir, err := windows.GetSystemDirectory()
	if err != nil {
		i.logger.Warn("Failed to get system directory, using C:\\Windows\\System32", "error", err)
		systemDir = "C:\\Windows\\System32"
	}

	spoofedNames := []string{
		"kernel32.dll",
		"user32.dll",
		"advapi32.dll",
		"gdi32.dll",
		"shell32.dll",
	}

	spoofedName := spoofedNames[0]
	spoofedPath := filepath.Join(systemDir, spoofedName)

	i.logger.Info("Using spoofed path",
		"original_path", i.dllPath,
		"spoofed_path", spoofedPath)

	tempDir := os.TempDir()
	tempFile := filepath.Join(tempDir, spoofedName)

	dllData, err := os.ReadFile(i.dllPath)
	if err != nil {
		errMsg := "Failed to read original DLL: " + err.Error()
		newErr := errors.New(errMsg)
		i.logger.Error("Path spoofing failed", "error", newErr)
		return newErr
	}

	err = os.WriteFile(tempFile, dllData, 0644)
	if err != nil {
		errMsg := "Failed to write temporary DLL: " + err.Error()
		newErr := errors.New(errMsg)
		i.logger.Error("Path spoofing failed", "error", newErr)
		return newErr
	}

	defer os.Remove(tempFile)

	spoofedPathBytes := []byte(spoofedPath + "\x00")

	var memFlags uint32 = windows.MEM_RESERVE | windows.MEM_COMMIT
	var memProt uint32 = windows.PAGE_READWRITE

	pathAddr, err := VirtualAllocEx(hProcess, 0, uintptr(len(spoofedPathBytes)),
		memFlags, memProt)
	if err != nil {
		errMsg := "Failed to allocate memory: " + err.Error()
		newErr := errors.New(errMsg)
		i.logger.Error("Path spoofing failed", "error", newErr)
		return newErr
	}

	var bytesWritten uintptr
	err = WriteProcessMemory(hProcess, pathAddr, unsafe.Pointer(&spoofedPathBytes[0]),
		uintptr(len(spoofedPathBytes)), &bytesWritten)
	if err != nil {
		errMsg := "Failed to write to memory: " + err.Error()
		newErr := errors.New(errMsg)
		i.logger.Error("Path spoofing failed", "error", newErr)
		return newErr
	}

	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	loadLibraryA := kernel32.NewProc("LoadLibraryA")
	loadLibraryAddr := loadLibraryA.Addr()

	var threadID uint32
	threadHandle, err := CreateRemoteThread(hProcess, nil, 0,
		loadLibraryAddr, pathAddr, 0, &threadID)
	if err != nil {
		errMsg := "Failed to create remote thread: " + err.Error()
		newErr := errors.New(errMsg)
		i.logger.Error("Path spoofing failed", "error", newErr)
		return newErr
	}
	defer windows.CloseHandle(threadHandle)

	i.logger.Info("Successfully created remote thread with spoofed path", "thread_id", threadID)

	return nil
}
