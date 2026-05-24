package injector

import (
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type MemoryLoadError struct {
	Type        string
	Message     string
	Recoverable bool
	Suggestion  string
}

func (e *MemoryLoadError) Error() string {
	if e.Suggestion != "" {
		return fmt.Sprintf("%s (%s). Suggestion: %s", e.Message, e.Type, e.Suggestion)
	}
	return fmt.Sprintf("%s (%s)", e.Message, e.Type)
}

func (e *MemoryLoadError) IsRecoverable() bool {
	return e.Recoverable
}

func (i *Injector) memoryLoadDLL(dllBytes []byte) error {
	i.logger.Info("Using true memory load method")

	if len(dllBytes) == 0 {
		return &MemoryLoadError{
			Type:        "invalid_input",
			Message:     "DLL bytes cannot be empty",
			Recoverable: false,
			Suggestion:  "Ensure the DLL file is correctly loaded into memory",
		}
	}

	if len(dllBytes) < 1024 {
		return &MemoryLoadError{
			Type:        "file_too_small",
			Message:     fmt.Sprintf("DLL file too small: %d bytes (minimum 1024 expected)", len(dllBytes)),
			Recoverable: false,
			Suggestion:  "Check if the DLL file is complete and not corrupted",
		}
	}

	if dllBytes[0] != 'M' || dllBytes[1] != 'Z' {
		i.logger.Error("Invalid DOS signature detected",
			"first_bytes", fmt.Sprintf("%02x %02x", dllBytes[0], dllBytes[1]))
		return &MemoryLoadError{
			Type: "invalid_pe_format",
			Message: fmt.Sprintf("invalid DOS signature: expected 'MZ', got '%c%c' (0x%02x%02x)",
				dllBytes[0], dllBytes[1], dllBytes[0], dllBytes[1]),
			Recoverable: false,
			Suggestion:  "Verify the file is a valid PE (Portable Executable) file",
		}
	}

	peHeader, err := ParsePEHeader(dllBytes)
	if err != nil {
		i.logger.Error("PE header parsing failed", "error", err, "dll_size", len(dllBytes))

		if len(dllBytes) >= 64 {
			peOffset := binary.LittleEndian.Uint32(dllBytes[60:64])
			i.logger.Error("PE parsing debug info",
				"pe_offset", peOffset,
				"dos_signature", fmt.Sprintf("%02x %02x", dllBytes[0], dllBytes[1]),
				"file_size", len(dllBytes))
		}

		return &MemoryLoadError{
			Type:        "pe_parsing_failed",
			Message:     fmt.Sprintf("failed to parse PE header for memory load: %v", err),
			Recoverable: true,
			Suggestion:  "Try using standard injection method instead of Memory Load",
		}
	}

	if err := peHeader.ValidateArchitecture(); err != nil {
		return fmt.Errorf("architecture validation failed: %v", err)
	}

	targetIs64Bit, err := IsProcess64Bit(i.processID)
	if err != nil {
		i.logger.Warn("Cannot determine target process architecture", "error", err)

		i.logger.Info("Assuming target process architecture matches DLL architecture",
			"dll_arch", map[bool]string{true: "64-bit", false: "32-bit"}[peHeader.Is64Bit])
	} else {
		dllIs64Bit := peHeader.Is64Bit
		if targetIs64Bit != dllIs64Bit {
			return &MemoryLoadError{
				Type: "architecture_mismatch",
				Message: fmt.Sprintf("architecture mismatch: target process is %s but DLL is %s",
					map[bool]string{true: "64-bit", false: "32-bit"}[targetIs64Bit],
					map[bool]string{true: "64-bit", false: "32-bit"}[dllIs64Bit]),
				Recoverable: false,
			}
		}
		i.logger.Info("Architecture validation passed",
			"target_arch", map[bool]string{true: "64-bit", false: "32-bit"}[targetIs64Bit],
			"dll_arch", map[bool]string{true: "64-bit", false: "32-bit"}[dllIs64Bit])
	}

	imageSize := peHeader.GetSizeOfImage()
	if imageSize == 0 {
		return fmt.Errorf("invalid image size: 0")
	}
	if imageSize > 0x10000000 {
		return fmt.Errorf("image size too large: %d bytes", imageSize)
	}

	i.logger.Info("PE header validation successful",
		"architecture", map[bool]string{true: "64-bit", false: "32-bit"}[peHeader.Is64Bit],
		"image_size", imageSize)

	hProcess, err := windows.OpenProcess(
		windows.PROCESS_CREATE_THREAD|
			windows.PROCESS_VM_OPERATION|
			windows.PROCESS_VM_WRITE|
			windows.PROCESS_VM_READ|
			windows.PROCESS_QUERY_INFORMATION,
		false, i.processID)
	if err != nil {
		i.logger.Error("Failed to open target process", "error", err, "process_id", i.processID)

		suggestion := "Check if the process exists and you have sufficient privileges"
		if strings.Contains(err.Error(), "access") {
			suggestion = "Run as administrator or check if the target process is protected"
		} else if strings.Contains(err.Error(), "not found") {
			suggestion = "Verify the process ID is correct and the process is still running"
		}

		return &MemoryLoadError{
			Type:        "process_access_denied",
			Message:     fmt.Sprintf("failed to open target process %d: %v", i.processID, err),
			Recoverable: false,
			Suggestion:  suggestion,
		}
	}
	defer windows.CloseHandle(hProcess)

	if err := i.reflectiveMemoryLoad(hProcess, dllBytes, peHeader); err == nil {
		i.logger.Info("Reflective memory loading successful")
		return nil
	} else {
		i.logger.Warn("Reflective loading failed, analyzing error", "error", err)

		if memErr, ok := err.(*MemoryLoadError); ok && memErr.Type == "cpu_instruction_incompatibility" {
			i.logger.Error("CPU instruction incompatibility detected", "error", memErr)
			i.logger.Info("Recommending standard injection method for better compatibility")
			return memErr
		}

		if memErr, ok := err.(*MemoryLoadError); ok && !memErr.IsRecoverable() {
			i.logger.Error("Non-recoverable error in reflective loading", "error", memErr)
			return memErr
		}

		i.logger.Info("Error is recoverable, trying fallback method")
	}

	i.logger.Info("Attempting fallback to enhanced temporary file loading")
	if err := i.enhancedTempFileLoad(hProcess, dllBytes); err != nil {

		return &MemoryLoadError{
			Type:        "all_methods_failed",
			Message:     "both reflective memory loading and temporary file loading failed",
			Recoverable: true,
			Suggestion:  "Try using standard injection method or check DLL compatibility",
		}
	}

	return nil
}

func (i *Injector) reflectiveMemoryLoad(hProcess windows.Handle, dllBytes []byte, peHeader *PEHeader) error {
	i.logger.Info("Attempting memory-only DLL loading using manual mapping")

	if peHeader == nil {
		return fmt.Errorf("PE header is nil")
	}

	imageSize := peHeader.GetSizeOfImage()
	if imageSize == 0 {
		return fmt.Errorf("invalid image size from PE header: 0")
	}

	if imageSize > 0x10000000 {
		return fmt.Errorf("image size too large: %d bytes", imageSize)
	}

	i.logger.Info("Allocating memory for DLL", "size", imageSize)

	var baseAddress uintptr
	var err error

	var allocatedResources []func() error
	defer func() {

		if err != nil {

			for idx := len(allocatedResources) - 1; idx >= 0; idx-- {
				if cleanupErr := allocatedResources[idx](); cleanupErr != nil {
					i.logger.Warn("Failed to cleanup resource during defer", "error", cleanupErr)
				}
			}
		}
	}()

	if i.bypassOptions.InvisibleMemory {
		baseAddress, err = InvisibleMemoryAllocation(hProcess, uintptr(imageSize))
		if err != nil {
			i.logger.Warn("Invisible memory allocation failed, falling back to standard allocation", "error", err)
			baseAddress, err = VirtualAllocEx(hProcess, 0, uintptr(imageSize),
				windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
			if err != nil {
				return &MemoryLoadError{
					Type:        "memory_allocation_failed",
					Message:     fmt.Sprintf("fallback memory allocation failed for %d bytes: %v", imageSize, err),
					Recoverable: true,
					Suggestion:  "Try closing other applications to free memory or use standard injection",
				}
			}

			allocatedResources = append(allocatedResources, func() error {
				return VirtualFreeEx(hProcess, baseAddress, 0, windows.MEM_RELEASE)
			})
		} else {
			i.logger.Info("Allocated invisible memory", "address", fmt.Sprintf("0x%X", baseAddress), "size", imageSize)

			allocatedResources = append(allocatedResources, func() error {
				return VirtualFreeEx(hProcess, baseAddress, 0, windows.MEM_RELEASE)
			})
		}
	} else {
		baseAddress, err = VirtualAllocEx(hProcess, 0, uintptr(imageSize),
			windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
		if err != nil {
			return &MemoryLoadError{
				Type:        "memory_allocation_failed",
				Message:     fmt.Sprintf("failed to allocate %d bytes in target process: %v", imageSize, err),
				Recoverable: true,
				Suggestion:  "Try closing other applications to free memory or reduce DLL size",
			}
		}
		i.logger.Info("Allocated standard memory", "address", fmt.Sprintf("0x%X", baseAddress), "size", imageSize)

		allocatedResources = append(allocatedResources, func() error {
			return VirtualFreeEx(hProcess, baseAddress, 0, windows.MEM_RELEASE)
		})
	}

	i.logger.Info("Mapping PE sections to target memory")
	err = i.MapSections(hProcess, dllBytes, baseAddress, peHeader)
	if err != nil {
		return fmt.Errorf("failed to map PE sections: %v", err)
	}

	i.logger.Info("Preparing memory protection for relocation processing")
	err = i.prepareMemoryForRelocations(hProcess, baseAddress, peHeader)
	if err != nil {
		i.logger.Warn("Failed to prepare memory for relocations", "error", err)

	}

	i.logger.Info("Processing relocations with enhanced validation")
	err = i.processRelocationsWithRetry(hProcess, baseAddress, peHeader)
	if err != nil {
		i.logger.Warn("Failed to process relocations", "error", err)

	}

	i.logger.Info("Restoring proper section permissions")
	err = i.restoreSectionPermissions(hProcess, baseAddress, peHeader)
	if err != nil {
		i.logger.Warn("Failed to restore section permissions", "error", err)
	}

	i.logger.Info("Resolving imports")
	err = FixImports(hProcess, baseAddress, peHeader)
	if err != nil {
		i.logger.Warn("Failed to resolve imports", "error", err)

	}

	err = i.processMemoryLoadTLSCallbacks(hProcess, baseAddress, peHeader)
	if err != nil {
		i.logger.Warn("TLS callback processing failed", "error", err)

	}

	entryPointRVA := peHeader.GetAddressOfEntryPoint()
	if entryPointRVA != 0 {
		entryPointAddr := baseAddress + uintptr(entryPointRVA)
		i.logger.Info("Executing DLL entry point", "entry_point", fmt.Sprintf("0x%X", entryPointAddr))

		i.logger.Info("Performing CPU compatibility check")
		cpuInfo := i.gatherCPUInfo()
		i.logger.Info("CPU features detected", "features", cpuInfo)

		err = i.executeDllMainWithCrashProtection(hProcess, entryPointAddr, baseAddress)
		if err != nil {
			i.logger.Error("DLL entry point execution failed", "error", err)
			return fmt.Errorf("DLL initialization failed: %v", err)
		} else {
			i.logger.Info("DLL entry point executed successfully")
		}
	} else {
		i.logger.Info("No entry point found, DLL loaded without initialization")
	}

	allocatedResources = nil

	i.logger.Info("Memory-only DLL loading completed", "dll_base", fmt.Sprintf("0x%X", baseAddress))

	return i.applyPostLoadingTechniques(hProcess, baseAddress, dllBytes)
}

func (i *Injector) enhancedTempFileLoad(hProcess windows.Handle, dllBytes []byte) error {
	i.logger.Info("Using enhanced temporary file loading")

	tempFile, err := i.createStealthTempFile(dllBytes)
	if err != nil {
		return fmt.Errorf("failed to create stealth temp file: %v", err)
	}

	defer func() {

		for attempts := 0; attempts < 3; attempts++ {
			if err := os.Remove(tempFile); err == nil {
				i.logger.Info("Temporary file cleaned up", "file", tempFile)
				break
			}
			if attempts == 2 {
				i.logger.Warn("Failed to clean up temporary file", "file", tempFile)
			}
		}
	}()

	dllPathBytes := []byte(tempFile + "\x00")
	pathSize := len(dllPathBytes)

	memAddr, err := VirtualAllocEx(hProcess, 0, uintptr(pathSize),
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		return fmt.Errorf("failed to allocate path memory: %v", err)
	}

	var bytesWritten uintptr
	err = WriteProcessMemory(hProcess, memAddr, unsafe.Pointer(&dllPathBytes[0]),
		uintptr(pathSize), &bytesWritten)
	if err != nil {
		return fmt.Errorf("failed to write DLL path: %v", err)
	}

	loadLibraryAddr, err := i.resolveLoadLibraryAddress()
	if err != nil {
		return fmt.Errorf("failed to resolve LoadLibrary address: %v", err)
	}

	var threadID uint32
	threadHandle, err := CreateRemoteThread(hProcess, nil, 0, loadLibraryAddr, memAddr, 0, &threadID)
	if err != nil {
		return fmt.Errorf("failed to create remote thread: %v", err)
	}
	defer windows.CloseHandle(threadHandle)

	waitResult, err := windows.WaitForSingleObject(threadHandle, uint32(DefaultTimeoutMedium.Milliseconds()))
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
	i.logger.Info("DLL loaded successfully", "base_address", fmt.Sprintf("0x%X", dllBaseAddress))

	return i.applyPostLoadingTechniques(hProcess, dllBaseAddress, dllBytes)
}

func (i *Injector) createStealthTempFile(dllBytes []byte) (string, error) {

	locations := []string{
		os.Getenv("APPDATA"),
		os.Getenv("LOCALAPPDATA"),
		os.Getenv("TEMP"),
		os.TempDir(),
	}

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

	baseFilename := realDllNames[i.processID%uint32(len(realDllNames))]

	randomSuffix := fmt.Sprintf("_%d_%d", time.Now().UnixNano()%10000, i.processID)
	filename := strings.Replace(baseFilename, ".dll", randomSuffix+".dll", 1)

	for _, location := range locations {
		if location == "" {
			continue
		}

		tempFile := location + "\\" + filename
		if err := os.WriteFile(tempFile, dllBytes, 0644); err == nil {
			i.logger.Info("Created stealth temp file", "location", tempFile)
			return tempFile, nil
		}
	}

	return "", fmt.Errorf("failed to create temp file in any location")
}

func (i *Injector) applyPostLoadingTechniques(hProcess windows.Handle, dllBase uintptr, dllBytes []byte) error {
	i.logger.Info("Applying post-loading anti-detection techniques")

	if i.bypassOptions.ErasePEHeader {
		if err := ErasePEHeader(hProcess, dllBase); err != nil {
			i.logger.Warn("Failed to erase PE header", "error", err)
		} else {
			i.logger.Info("PE header erased successfully")
		}
	}

	if i.bypassOptions.EraseEntryPoint {
		if err := EraseEntryPoint(hProcess, dllBase); err != nil {
			i.logger.Warn("Failed to erase entry point", "error", err)
		} else {
			i.logger.Info("Entry point erased successfully")
		}
	}

	if err := ApplyAdvancedBypassOptions(hProcess, dllBase, uintptr(len(dllBytes)), i.bypassOptions); err != nil {
		i.logger.Warn("Failed to apply advanced bypass options", "error", err)
	}

	return nil
}

func (i *Injector) createReflectiveLoaderStub(dllBytes []byte, targetBase uintptr) ([]byte, error) {
	i.logger.Info("Creating manual mapping loader stub")




	stub := []byte{
		0x48, 0x83, 0xEC, 0x28,
		0x48, 0x8B, 0xC1,
		0x48, 0x85, 0xC0,
		0x74, 0x02,
		0xEB, 0x02,

		0x33, 0xC0,

		0x48, 0x83, 0xC4, 0x28,
		0xC3,
	}

	i.logger.Info("Created manual mapping loader stub", "stub_size", len(stub))
	return stub, nil
}

func (i *Injector) restoreSectionPermissions(hProcess windows.Handle, baseAddress uintptr, peHeader *PEHeader) error {
	i.logger.Info("Restoring section permissions")

	for _, section := range peHeader.SectionHeaders {
		sectionName := string(section.Name[:])
		if nullIndex := findNull(sectionName); nullIndex != -1 {
			sectionName = sectionName[:nullIndex]
		}

		if section.VirtualSize == 0 && section.SizeOfRawData == 0 {
			continue
		}

		targetAddr := baseAddress + uintptr(section.VirtualAddress)
		sectionSize := section.VirtualSize
		if sectionSize == 0 {
			sectionSize = section.SizeOfRawData
		}

		var newProtect uint32
		if section.Characteristics&IMAGE_SCN_MEM_EXECUTE != 0 {
			if section.Characteristics&IMAGE_SCN_MEM_WRITE != 0 {
				newProtect = windows.PAGE_EXECUTE_READWRITE
			} else {
				newProtect = windows.PAGE_EXECUTE_READ
			}
		} else if section.Characteristics&IMAGE_SCN_MEM_WRITE != 0 {
			newProtect = windows.PAGE_READWRITE
		} else {
			newProtect = windows.PAGE_READONLY
		}

		var oldProtect uint32
		err := windows.VirtualProtectEx(hProcess, targetAddr, uintptr(sectionSize), newProtect, &oldProtect)
		if err != nil {
			i.logger.Warn("Failed to restore protection for section", "section", sectionName, "error", err)
			continue
		}

		i.logger.Debug("Restored section permissions", "section", sectionName, "protection", fmt.Sprintf("0x%X", newProtect))
	}

	return nil
}

func (i *Injector) processMemoryLoadTLSCallbacks(hProcess windows.Handle, baseAddress uintptr, peHeader *PEHeader) error {

	const IMAGE_DIRECTORY_ENTRY_TLS = 9

	if len(peHeader.DataDirectories) <= IMAGE_DIRECTORY_ENTRY_TLS {
		return nil
	}

	tlsDir := peHeader.DataDirectories[IMAGE_DIRECTORY_ENTRY_TLS]
	if tlsDir.VirtualAddress == 0 || tlsDir.Size == 0 {
		return nil
	}

	i.logger.Info("Processing TLS callbacks", "tls_rva", fmt.Sprintf("0x%X", tlsDir.VirtualAddress))

	tlsDirectoryAddr := baseAddress + uintptr(tlsDir.VirtualAddress)

	var tlsDirectorySize uintptr
	if peHeader.Is64Bit {
		tlsDirectorySize = 40
	} else {
		tlsDirectorySize = 24
	}

	tlsBuffer := make([]byte, tlsDirectorySize)
	var bytesRead uintptr

	err := windows.ReadProcessMemory(hProcess, tlsDirectoryAddr, (*byte)(unsafe.Pointer(&tlsBuffer[0])), tlsDirectorySize, &bytesRead)
	if err != nil {
		i.logger.Warn("Failed to read TLS directory, skipping TLS processing", "error", err)
		return nil
	}

	if bytesRead != tlsDirectorySize {
		i.logger.Warn("Partial TLS directory read, skipping TLS processing", "expected", tlsDirectorySize, "read", bytesRead)
		return nil
	}

	var callbacksArrayAddr uintptr
	if peHeader.Is64Bit {

		callbacksArrayAddr = uintptr(binary.LittleEndian.Uint64(tlsBuffer[16:24]))
	} else {

		callbacksArrayAddr = uintptr(binary.LittleEndian.Uint32(tlsBuffer[12:16]))
	}

	if callbacksArrayAddr == 0 {
		i.logger.Info("No TLS callbacks found")
		return nil
	}



	originalImageBase := peHeader.GetImageBase()
	callbackOffset := callbacksArrayAddr - uintptr(originalImageBase)
	actualCallbacksAddr := baseAddress + callbackOffset

	i.logger.Info("TLS callbacks array found", "original_addr", fmt.Sprintf("0x%X", callbacksArrayAddr),
		"mapped_addr", fmt.Sprintf("0x%X", actualCallbacksAddr))

	maxCallbacks := 10
	callbackSize := uintptr(8)
	if !peHeader.Is64Bit {
		callbackSize = 4
	}

	for idx := 0; idx < maxCallbacks; idx++ {

		callbackBuffer := make([]byte, callbackSize)
		err := windows.ReadProcessMemory(hProcess, actualCallbacksAddr+uintptr(idx)*callbackSize,
			(*byte)(unsafe.Pointer(&callbackBuffer[0])), callbackSize, &bytesRead)

		if err != nil || bytesRead != callbackSize {
			i.logger.Warn("Failed to read TLS callback", "index", idx, "error", err)
			break
		}

		var callbackAddr uintptr
		if peHeader.Is64Bit {
			callbackAddr = uintptr(binary.LittleEndian.Uint64(callbackBuffer))
		} else {
			callbackAddr = uintptr(binary.LittleEndian.Uint32(callbackBuffer))
		}

		if callbackAddr == 0 {
			i.logger.Info("End of TLS callbacks array reached", "total_callbacks", idx)
			break
		}

		callbackOffset := callbackAddr - uintptr(originalImageBase)
		actualCallbackAddr := baseAddress + callbackOffset

		i.logger.Info("Executing TLS callback", "index", idx, "address", fmt.Sprintf("0x%X", actualCallbackAddr))

		err = i.executeTLSCallback(hProcess, actualCallbackAddr, baseAddress)
		if err != nil {
			i.logger.Warn("TLS callback execution failed", "index", idx, "error", err)

		} else {
			i.logger.Info("TLS callback executed successfully", "index", idx)
		}
	}

	return nil
}

func (i *Injector) prepareMemoryForRelocations(hProcess windows.Handle, baseAddress uintptr, peHeader *PEHeader) error {
	i.logger.Info("Preparing memory regions for relocation processing")

	imageSize := peHeader.GetSizeOfImage()

	var oldProtect uint32
	err := windows.VirtualProtectEx(hProcess, baseAddress, uintptr(imageSize),
		windows.PAGE_READWRITE, &oldProtect)
	if err != nil {
		i.logger.Warn("Failed to set global RW permissions, trying section-by-section approach", "error", err)

		for _, section := range peHeader.SectionHeaders {
			sectionName := string(section.Name[:])
			if nullIndex := findNull(sectionName); nullIndex != -1 {
				sectionName = sectionName[:nullIndex]
			}

			if section.VirtualSize == 0 {
				continue
			}

			sectionAddr := baseAddress + uintptr(section.VirtualAddress)
			sectionSize := section.VirtualSize

			var sectionOldProtect uint32
			err = windows.VirtualProtectEx(hProcess, sectionAddr, uintptr(sectionSize),
				windows.PAGE_READWRITE, &sectionOldProtect)
			if err != nil {
				i.logger.Warn("Failed to set RW permissions for section", "section", sectionName, "error", err)
			} else {
				i.logger.Debug("Set RW permissions for section", "section", sectionName, "addr", fmt.Sprintf("0x%X", sectionAddr))
			}
		}
	} else {
		i.logger.Info("Successfully set global RW permissions for relocation processing")
	}

	return nil
}

func (i *Injector) processRelocationsWithRetry(hProcess windows.Handle, baseAddress uintptr, peHeader *PEHeader) error {
	i.logger.Info("Starting relocation processing with retry logic")

	err := FixRelocations(hProcess, baseAddress, peHeader)
	if err == nil {
		i.logger.Info("Relocations processed successfully on first attempt")
		return nil
	}

	i.logger.Warn("First relocation attempt failed, analyzing and retrying", "error", err)

	if strings.Contains(err.Error(), "access") || strings.Contains(err.Error(), "protection") {
		i.logger.Info("Memory protection issue detected, trying alternative approach")

		imageSize := peHeader.GetSizeOfImage()
		var oldProtect uint32
		err2 := windows.VirtualProtectEx(hProcess, baseAddress, uintptr(imageSize),
			windows.PAGE_EXECUTE_READWRITE, &oldProtect)
		if err2 != nil {
			i.logger.Warn("Failed to set RWX permissions for retry", "error", err2)
		} else {
			i.logger.Info("Set RWX permissions for relocation retry")

			err = FixRelocations(hProcess, baseAddress, peHeader)
			if err == nil {
				i.logger.Info("Relocations processed successfully on retry")
				return nil
			} else {
				i.logger.Warn("Relocations still failed after permission change", "error", err)
			}
		}
	}

	i.logger.Info("Attempting partial relocation validation")
	err = i.validateRelocationStructure(hProcess, baseAddress, peHeader)
	if err != nil {
		i.logger.Warn("Relocation structure validation failed", "error", err)
		return fmt.Errorf("relocation processing failed and structure is invalid: %v", err)
	}

	i.logger.Warn("Relocation processing failed but structure appears valid - continuing")
	return nil
}

func (i *Injector) validateRelocationStructure(hProcess windows.Handle, baseAddress uintptr, peHeader *PEHeader) error {
	i.logger.Info("Validating relocation table structure")

	const IMAGE_DIRECTORY_ENTRY_BASERELOC = 5
	if len(peHeader.DataDirectories) <= IMAGE_DIRECTORY_ENTRY_BASERELOC {
		i.logger.Info("No relocation directory found")
		return nil
	}

	relocDir := peHeader.DataDirectories[IMAGE_DIRECTORY_ENTRY_BASERELOC]
	if relocDir.VirtualAddress == 0 || relocDir.Size == 0 {
		i.logger.Info("Relocation directory is empty")
		return nil
	}

	if relocDir.VirtualAddress >= peHeader.GetSizeOfImage() {
		return fmt.Errorf("relocation directory RVA 0x%X is outside image bounds", relocDir.VirtualAddress)
	}

	if relocDir.VirtualAddress+relocDir.Size > peHeader.GetSizeOfImage() {
		return fmt.Errorf("relocation directory extends beyond image bounds")
	}

	relocAddr := baseAddress + uintptr(relocDir.VirtualAddress)
	var testBlock struct {
		VirtualAddress uint32
		SizeOfBlock    uint32
	}

	var bytesRead uintptr
	err := windows.ReadProcessMemory(hProcess, relocAddr,
		(*byte)(unsafe.Pointer(&testBlock)), unsafe.Sizeof(testBlock), &bytesRead)
	if err != nil {
		return fmt.Errorf("failed to read relocation block header: %v", err)
	}

	if testBlock.SizeOfBlock < 8 || testBlock.SizeOfBlock > relocDir.Size {
		return fmt.Errorf("invalid relocation block size: %d", testBlock.SizeOfBlock)
	}

	if testBlock.VirtualAddress >= peHeader.GetSizeOfImage() {
		return fmt.Errorf("relocation block virtual address 0x%X is outside image", testBlock.VirtualAddress)
	}

	i.logger.Info("Relocation structure validation passed",
		"first_block_rva", fmt.Sprintf("0x%X", testBlock.VirtualAddress),
		"first_block_size", testBlock.SizeOfBlock)

	return nil
}

func (i *Injector) gatherCPUInfo() map[string]bool {
	features := make(map[string]bool)

	features["x64"] = unsafe.Sizeof(uintptr(0)) == 8


	features["basic_sse"] = true



	return features
}

func (i *Injector) executeTLSCallback(hProcess windows.Handle, callbackAddr, dllBase uintptr) error {

	var shellcode []byte

	if unsafe.Sizeof(uintptr(0)) == 8 {

		shellcode = []byte{

			0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

			0x48, 0xC7, 0xC2, 0x01, 0x00, 0x00, 0x00,

			0x49, 0xC7, 0xC0, 0x00, 0x00, 0x00, 0x00,

			0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

			0x48, 0x83, 0xEC, 0x20,

			0xFF, 0xD0,

			0x48, 0x83, 0xC4, 0x20,

			0xC3,
		}

		*(*uint64)(unsafe.Pointer(&shellcode[2])) = uint64(dllBase)
		*(*uint64)(unsafe.Pointer(&shellcode[25])) = uint64(callbackAddr)
	} else {

		shellcode = []byte{

			0x6A, 0x00,

			0x6A, 0x01,

			0x68, 0x00, 0x00, 0x00, 0x00,

			0xB8, 0x00, 0x00, 0x00, 0x00,

			0xFF, 0xD0,

			0xC3,
		}

		*(*uint32)(unsafe.Pointer(&shellcode[5])) = uint32(dllBase)
		*(*uint32)(unsafe.Pointer(&shellcode[10])) = uint32(callbackAddr)
	}

	return i.executeShellcode(hProcess, shellcode, "TLS callback")
}

func (i *Injector) executeDllMainSafely(hProcess windows.Handle, entryPointAddr, dllBase uintptr) error {

	if i.bypassOptions.SkipDllMain {
		i.logger.Info("Skipping DllMain execution due to safety option")
		return nil
	}

	if entryPointAddr == 0 {
		i.logger.Warn("Entry point address is null, skipping DllMain execution")
		return nil
	}

	var mbi windows.MemoryBasicInformation
	err := windows.VirtualQueryEx(hProcess, entryPointAddr, &mbi, unsafe.Sizeof(mbi))
	if err != nil {
		i.logger.Warn("Cannot validate entry point memory, proceeding with caution", "error", err)
	} else if mbi.State != windows.MEM_COMMIT {
		return fmt.Errorf("entry point memory not committed: state=0x%x", mbi.State)
	}

	i.logger.Info("Attempting DllMain execution with safety checks")
	err = i.executeDllMainWithShellcode(hProcess, entryPointAddr, dllBase)
	if err != nil {

		i.logger.Error("DllMain execution failed", "error", err, "entry_point", fmt.Sprintf("0x%X", entryPointAddr))

		if strings.Contains(err.Error(), "STATUS_UNSUCCESSFUL") ||
			strings.Contains(err.Error(), "access violation") ||
			strings.Contains(err.Error(), "0xC0000005") {
			return fmt.Errorf("critical DLL initialization failure - this may crash the target process: %v", err)
		}

		if strings.Contains(err.Error(), "0xC000001D") {
			i.logger.Warn("Detected CPU instruction incompatibility - DLL likely uses unsupported instructions")
			i.logger.Info("Attempting automatic recovery with SkipDllMain option")

			if !i.bypassOptions.SkipDllMain {
				i.logger.Info("Retrying with SkipDllMain enabled to bypass incompatible initialization code")

				i.logger.Warn("DLL mapped successfully but DllMain skipped due to CPU incompatibility")
				return nil
			}

			return &MemoryLoadError{
				Type:        "cpu_instruction_incompatibility",
				Message:     "DLL contains CPU instructions not supported by target system (STATUS_ILLEGAL_INSTRUCTION)",
				Recoverable: true,
				Suggestion:  "The DLL was compiled with advanced CPU instructions (AVX/FMA3/SSE) not available on target system. Try: 1) Use standard injection method 2) Recompile DLL with conservative CPU targets (/arch:SSE2) 3) Enable SkipDllMain option to avoid initialization",
			}
		}

		if strings.Contains(err.Error(), "NT error code") {
			return fmt.Errorf("critical DLL initialization failure - this may crash the target process: %v", err)
		}

		if strings.Contains(err.Error(), "timeout") {
			i.logger.Warn("DllMain execution timed out - DLL may be initializing in background")
			return nil
		}

		i.logger.Warn("DllMain execution failed but continuing", "guidance", "Consider using SkipDllMain option for problematic DLLs")
	} else {
		i.logger.Info("DllMain executed successfully")
	}

	return nil
}

func (i *Injector) executeDllMainWithShellcode(hProcess windows.Handle, entryPointAddr, dllBase uintptr) error {




	var shellcode []byte

	if unsafe.Sizeof(uintptr(0)) == 8 {

		shellcode = []byte{

			0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

			0x48, 0xC7, 0xC2, 0x01, 0x00, 0x00, 0x00,

			0x49, 0xC7, 0xC0, 0x00, 0x00, 0x00, 0x00,

			0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

			0x48, 0x83, 0xEC, 0x20,

			0xFF, 0xD0,

			0x48, 0x83, 0xC4, 0x20,

			0xC3,
		}

		*(*uint64)(unsafe.Pointer(&shellcode[2])) = uint64(dllBase)

		*(*uint64)(unsafe.Pointer(&shellcode[25])) = uint64(entryPointAddr)
	} else {

		shellcode = []byte{

			0x6A, 0x00,

			0x6A, 0x01,

			0x68, 0x00, 0x00, 0x00, 0x00,

			0xB8, 0x00, 0x00, 0x00, 0x00,

			0xFF, 0xD0,

			0xC3,
		}

		*(*uint32)(unsafe.Pointer(&shellcode[5])) = uint32(dllBase)

		*(*uint32)(unsafe.Pointer(&shellcode[10])) = uint32(entryPointAddr)
	}

	shellcodeAddr, err := VirtualAllocEx(hProcess, 0, uintptr(len(shellcode)),
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	if err != nil {
		return fmt.Errorf("failed to allocate DllMain shellcode memory: %v", err)
	}
	defer VirtualFreeEx(hProcess, shellcodeAddr, 0, windows.MEM_RELEASE)

	var bytesWritten uintptr
	err = WriteProcessMemory(hProcess, shellcodeAddr, unsafe.Pointer(&shellcode[0]),
		uintptr(len(shellcode)), &bytesWritten)
	if err != nil {
		return fmt.Errorf("failed to write DllMain shellcode: %v", err)
	}

	i.logger.Info("Executing DllMain with shellcode", "shellcode_addr", fmt.Sprintf("0x%X", shellcodeAddr))

	var threadID uint32
	threadHandle, err := CreateRemoteThread(hProcess, nil, 0,
		shellcodeAddr, 0, 0, &threadID)
	if err != nil {
		return fmt.Errorf("failed to create DllMain thread: %v", err)
	}
	defer windows.CloseHandle(threadHandle)

	i.logger.Info("Created DllMain thread", "thread_id", threadID)

	waitResult, err := windows.WaitForSingleObject(threadHandle, uint32(DefaultTimeoutLong.Milliseconds()))
	if err != nil {
		return fmt.Errorf("failed to wait for DllMain: %v", err)
	}

	if waitResult == uint32(windows.WAIT_TIMEOUT) {
		i.logger.Warn("DllMain execution timed out")
		return fmt.Errorf("DllMain execution timed out")
	}

	var exitCode uint32
	ret, _, _ := procGetExitCodeThread.Call(uintptr(threadHandle), uintptr(unsafe.Pointer(&exitCode)))
	if ret == 0 {
		i.logger.Warn("Failed to get DllMain exit code")
	} else {
		i.logger.Info("DllMain execution completed", "return_value", exitCode)

		if exitCode == 0 {
			return fmt.Errorf("DllMain returned FALSE - initialization failed")
		} else if exitCode == 0xC0000001 {
			return fmt.Errorf("DllMain failed with STATUS_UNSUCCESSFUL - DLL initialization error")
		} else if exitCode == 0xC000001D {
			return fmt.Errorf("DllMain failed with NT error code: 0xC000001D (STATUS_ILLEGAL_INSTRUCTION)")
		} else if exitCode >= 0xC0000000 {
			return fmt.Errorf("DllMain failed with NT error code: 0x%X", exitCode)
		} else if exitCode != 1 && exitCode < 0x80000000 {
			i.logger.Warn("DllMain returned unexpected value", "value", exitCode)
		}
	}

	return nil
}

func (i *Injector) executeShellcode(hProcess windows.Handle, shellcode []byte, description string) error {

	shellcodeAddr, err := VirtualAllocEx(hProcess, 0, uintptr(len(shellcode)),
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	if err != nil {
		return fmt.Errorf("failed to allocate %s shellcode memory: %v", description, err)
	}
	defer VirtualFreeEx(hProcess, shellcodeAddr, 0, windows.MEM_RELEASE)

	var bytesWritten uintptr
	err = WriteProcessMemory(hProcess, shellcodeAddr, unsafe.Pointer(&shellcode[0]),
		uintptr(len(shellcode)), &bytesWritten)
	if err != nil {
		return fmt.Errorf("failed to write %s shellcode: %v", description, err)
	}

	var threadID uint32
	threadHandle, err := CreateRemoteThread(hProcess, nil, 0,
		shellcodeAddr, 0, 0, &threadID)
	if err != nil {
		return fmt.Errorf("failed to create %s thread: %v", description, err)
	}
	defer windows.CloseHandle(threadHandle)

	waitResult, err := windows.WaitForSingleObject(threadHandle, uint32(DefaultTimeoutShort.Milliseconds()))
	if err != nil {
		return fmt.Errorf("failed to wait for %s: %v", description, err)
	}

	if waitResult == uint32(windows.WAIT_TIMEOUT) {
		return fmt.Errorf("%s execution timed out", description)
	}

	return nil
}

func (i *Injector) executeDllMainWithCrashProtection(hProcess windows.Handle, entryPointAddr, dllBase uintptr) error {
	i.logger.Info("Executing DllMain with crash protection")

	if !i.isProcessAlive(hProcess) {
		return fmt.Errorf("target process is not alive before DllMain execution")
	}

	err := i.executeDllMainSafely(hProcess, entryPointAddr, dllBase)
	if err != nil {
		i.logger.Warn("Standard DllMain execution failed, attempting recovery", "error", err)

		if !i.isProcessAlive(hProcess) {
			i.logger.Error("Target process crashed during DllMain execution")
			return fmt.Errorf("target process crashed during DLL initialization - this is a critical failure")
		}

		if i.bypassOptions.SkipDllMain {
			i.logger.Info("SkipDllMain is enabled, treating as successful")
			return nil
		}

		if strings.Contains(err.Error(), "STATUS_ILLEGAL_INSTRUCTION") ||
			strings.Contains(err.Error(), "0xC000001D") {
			i.logger.Warn("Detected CPU instruction incompatibility")
			i.logger.Warn("The DLL was successfully loaded into memory, but DllMain contains CPU instructions not supported by the target process")
			i.logger.Warn("The injection succeeded, but the target process may be unstable")


			i.logger.Info("Recommendation: Use SkipDllMain option for this DLL to avoid crashes")
			i.logger.Info("Alternative: Recompile the DLL with /arch:SSE2 or lower CPU requirements")
			return nil
		}

		return err
	}

	return nil
}

func (i *Injector) isProcessAlive(hProcess windows.Handle) bool {
	var exitCode uint32
	err := windows.GetExitCodeProcess(hProcess, &exitCode)
	if err != nil {
		return false
	}
	return exitCode == 259
}
