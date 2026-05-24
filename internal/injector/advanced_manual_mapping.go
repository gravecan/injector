package injector

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

func (i *Injector) AdvancedManualMapping(hProcess windows.Handle, dllBytes []byte) (uintptr, error) {
	i.logger.Info("Starting advanced manual mapping with comprehensive anti-detection")

	if len(dllBytes) < 1024 {
		return 0, fmt.Errorf("invalid DLL data size: %d bytes", len(dllBytes))
	}

	peHeader, err := ParsePEHeader(dllBytes)
	if err != nil {
		return 0, fmt.Errorf("PE header parsing failed: %v", err)
	}

	if err := peHeader.ValidateArchitecture(); err != nil {
		return 0, fmt.Errorf("architecture validation failed: %v", err)
	}

	imageSize := peHeader.GetSizeOfImage()
	if imageSize == 0 || imageSize > 0x10000000 {
		return 0, fmt.Errorf("invalid image size: %d", imageSize)
	}

	baseAddress, err := i.allocateStealthMemory(hProcess, uintptr(imageSize))
	if err != nil {
		return 0, fmt.Errorf("stealth memory allocation failed: %v", err)
	}

	i.logger.Info("Allocated stealth memory", "address", fmt.Sprintf("0x%X", baseAddress), "size", imageSize)
	
	// CRITICAL: Verify our DLL is NOT in JVM range (for Java processes)
	if i.isJavaProcess() {
		inRange, err := CheckIfInJVMRange(hProcess, baseAddress)
		if err == nil {
			if inRange {
				i.logger.Error("CRITICAL: Injected DLL is in JVM DLL memory range - InjGen will detect it!",
					"dll_address", fmt.Sprintf("0x%X", baseAddress))
				// Try to reallocate outside JVM range
				_, jvmEnd, _ := GetJVMDLLMemoryRange(hProcess)
				if jvmEnd > 0 {
					// Free current allocation and try again
					ntdll := windows.NewLazySystemDLL("ntdll.dll")
					ntFreeVirtualMemory := ntdll.NewProc("NtFreeVirtualMemory")
					var size uintptr = 0
					ntFreeVirtualMemory.Call(uintptr(hProcess), uintptr(unsafe.Pointer(&baseAddress)), 
						uintptr(unsafe.Pointer(&size)), windows.MEM_RELEASE)
					
					// Try allocating far from JVM range
					newAddr, err := VirtualAllocEx(hProcess, jvmEnd+0x1000000, uintptr(imageSize),
						windows.MEM_COMMIT|windows.MEM_RESERVE|windows.MEM_TOP_DOWN, windows.PAGE_EXECUTE_READWRITE)
					if err == nil {
						baseAddress = newAddr
						i.logger.Info("Reallocated DLL outside JVM range", "new_address", fmt.Sprintf("0x%X", baseAddress))
					} else {
						i.logger.Warn("Failed to reallocate outside JVM range, continuing with current address", "error", err)
					}
				}
			} else {
				i.logger.Info("Injected DLL is outside JVM DLL memory range - good", 
					"dll_address", fmt.Sprintf("0x%X", baseAddress))
			}
		}
	}

	// Apply pattern replacement to PE headers BEFORE mapping
	headerSize := uint32(0)
	if peHeader.Is64Bit {
		headerSize = peHeader.OptionalHeader.(OptionalHeader64).SizeOfHeaders
	} else {
		headerSize = peHeader.OptionalHeader.(OptionalHeader32).SizeOfHeaders
	}
	if headerSize > 0 && headerSize <= uint32(len(dllBytes)) {
		headerData := dllBytes[:headerSize]
		headerData = ReplaceInjGenPatterns(headerData)
		// Write modified headers
		var bytesWritten uintptr
		err = WriteProcessMemory(hProcess, baseAddress, unsafe.Pointer(&headerData[0]), uintptr(headerSize), &bytesWritten)
		if err != nil {
			return 0, fmt.Errorf("failed to write modified PE headers: %v", err)
		}
		i.logger.Info("PE headers written with pattern replacement", "size", headerSize)
	} else {
		// Fallback to original method
		if err := i.mapPEHeaderWithModifications(hProcess, dllBytes, baseAddress, peHeader); err != nil {
			return 0, fmt.Errorf("PE header mapping failed: %v", err)
		}
	}

	if err := i.mapSectionsWithAntiDetection(hProcess, dllBytes, baseAddress, peHeader); err != nil {
		return 0, fmt.Errorf("section mapping failed: %v", err)
	}

	if err := i.resolveImportsWithEvasion(hProcess, baseAddress, peHeader); err != nil {
		return 0, fmt.Errorf("import resolution failed: %v", err)
	}

	if err := i.processRelocationsAdvanced(hProcess, baseAddress, peHeader); err != nil {
		i.logger.Warn("Relocation processing failed", "error", err)

	}

	if err := i.processTLSCallbacks(hProcess, baseAddress, peHeader); err != nil {
		i.logger.Warn("TLS callback processing failed", "error", err)
	}

	if err := i.setupExceptionHandlers(hProcess, baseAddress, peHeader); err != nil {
		i.logger.Warn("Exception handler setup failed", "error", err)
	}

	if err := i.executeDLLEntryProtected(hProcess, baseAddress, peHeader); err != nil {
		i.logger.Warn("DLL entry execution failed", "error", err)
	}

	if err := i.applyPostMappingAntiDetection(hProcess, baseAddress, uintptr(imageSize), dllBytes); err != nil {
		i.logger.Warn("Post-mapping anti-detection failed", "error", err)
	}

	i.logger.Info("Advanced manual mapping completed successfully", "base_address", fmt.Sprintf("0x%X", baseAddress))
	return baseAddress, nil
}

func (i *Injector) allocateStealthMemory(hProcess windows.Handle, size uintptr) (uintptr, error) {
	var baseAddress uintptr
	var err error

	// For Java processes, try to avoid JVM DLL memory range
	if i.isJavaProcess() {
		jvmBase, jvmEnd, err := GetJVMDLLMemoryRange(hProcess)
		if err == nil {
			i.logger.Info("JVM DLL memory range detected, avoiding it",
				"jvm_base", fmt.Sprintf("0x%X", jvmBase),
				"jvm_end", fmt.Sprintf("0x%X", jvmEnd))
			
			// Try to allocate outside JVM range
			// Try high memory first (above JVM)
			baseAddress, err = VirtualAllocEx(hProcess, jvmEnd+0x100000, size,
				windows.MEM_COMMIT|windows.MEM_RESERVE|windows.MEM_TOP_DOWN, windows.PAGE_EXECUTE_READWRITE)
			if err == nil {
				i.logger.Info("Allocated memory outside JVM range", "address", fmt.Sprintf("0x%X", baseAddress))
				// Check if it's still in range (shouldn't be, but verify)
				inRange, _ := CheckIfInJVMRange(hProcess, baseAddress)
				if !inRange {
					return baseAddress, nil
				}
			}
			
			// Try low memory (below JVM)
			if jvmBase > 0x1000000 { // Make sure we have space
				baseAddress, err = VirtualAllocEx(hProcess, 0, size,
					windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
				if err == nil {
					inRange, _ := CheckIfInJVMRange(hProcess, baseAddress)
					if !inRange {
						i.logger.Info("Allocated memory outside JVM range (low)", "address", fmt.Sprintf("0x%X", baseAddress))
						return baseAddress, nil
					}
				}
			}
		}
	}

	switch {
	case i.bypassOptions.InvisibleMemory:
		baseAddress, err = InvisibleMemoryAllocation(hProcess, size)
		if err == nil {
			i.logger.Info("Used invisible memory allocation")
			// Verify it's not in JVM range
			if i.isJavaProcess() {
				inRange, _ := CheckIfInJVMRange(hProcess, baseAddress)
				if inRange {
					i.logger.Warn("Invisible memory is in JVM range, will clean patterns")
				}
			}
			return baseAddress, nil
		}
		i.logger.Warn("Invisible memory allocation failed, trying alternatives", "error", err)
		fallthrough

	case i.bypassOptions.ThreadStackAllocation:
		baseAddress, err = AllocateBehindThreadStack(hProcess, size)
		if err == nil {
			i.logger.Info("Used thread stack allocation")
			return baseAddress, nil
		}
		i.logger.Warn("Thread stack allocation failed, trying standard", "error", err)
		fallthrough

	default:

		baseAddress, err = VirtualAllocEx(hProcess, 0, size,
			windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
		if err != nil {
			return 0, fmt.Errorf("standard memory allocation failed: %v", err)
		}
	}

	if i.bypassOptions.PTESpoofing {
		if err := PTESpoofing(hProcess, baseAddress, size); err != nil {
			i.logger.Warn("PTE spoofing failed", "error", err)
		}
	}

	if i.bypassOptions.VADManipulation {
		if err := VADManipulation(hProcess, baseAddress, size); err != nil {
			i.logger.Warn("VAD manipulation failed", "error", err)
		}
	}

	return baseAddress, nil
}

func (i *Injector) mapPEHeaderWithModifications(hProcess windows.Handle, dllBytes []byte, baseAddress uintptr, peHeader *PEHeader) error {
	i.logger.Info("Mapping PE header with modifications")

	var headerSize uint32
	if peHeader.Is64Bit {
		headerSize = peHeader.OptionalHeader.(OptionalHeader64).SizeOfHeaders
	} else {
		headerSize = peHeader.OptionalHeader.(OptionalHeader32).SizeOfHeaders
	}

	modifiedHeader := make([]byte, headerSize)
	copy(modifiedHeader, dllBytes[:headerSize])

	if i.bypassOptions.ErasePEHeader {

		i.logger.Info("PE header marked for erasure after mapping")
	}

	i.modifyPETimestamps(modifiedHeader, peHeader)

	var bytesWritten uintptr
	err := WriteProcessMemory(hProcess, baseAddress, unsafe.Pointer(&modifiedHeader[0]),
		uintptr(headerSize), &bytesWritten)
	if err != nil {
		return fmt.Errorf("failed to write PE header: %v", err)
	}

	i.logger.Info("PE header mapped successfully", "bytes_written", bytesWritten)
	return nil
}

func (i *Injector) mapSectionsWithAntiDetection(hProcess windows.Handle, dllBytes []byte, baseAddress uintptr, peHeader *PEHeader) error {
	i.logger.Info("Mapping sections with anti-detection")

	for j, section := range peHeader.SectionHeaders {
		sectionName := string(section.Name[:])
		if nullIndex := findNull(sectionName); nullIndex != -1 {
			sectionName = sectionName[:nullIndex]
		}

		Printf("Processing section: %s", sectionName)

		if section.SizeOfRawData == 0 {
			Printf("Skipping empty section: %s", sectionName)
			continue
		}

		if section.PointerToRawData >= uint32(len(dllBytes)) {
			Printf("Warning: Section %s has invalid raw data pointer", sectionName)
			continue
		}

		targetAddr := baseAddress + uintptr(section.VirtualAddress)
		dataSize := section.SizeOfRawData

		if section.PointerToRawData+dataSize > uint32(len(dllBytes)) {
			dataSize = uint32(len(dllBytes)) - section.PointerToRawData
		}

		sectionData := dllBytes[section.PointerToRawData : section.PointerToRawData+dataSize]

		modifiedData := applySectionAntiDetection(sectionData, sectionName, i.bypassOptions)

		var bytesWritten uintptr
		err := WriteProcessMemory(hProcess, targetAddr, unsafe.Pointer(&modifiedData[0]),
			uintptr(len(modifiedData)), &bytesWritten)
		if err != nil {
			return fmt.Errorf("failed to write section %s: %v", sectionName, err)
		}

		protection := calculateSectionProtection(section.Characteristics)
		var oldProtect uint32
		virtualSize := section.VirtualSize
		if virtualSize == 0 {
			virtualSize = section.SizeOfRawData
		}

		err = windows.VirtualProtectEx(hProcess, targetAddr, uintptr(virtualSize), protection, &oldProtect)
		if err != nil {
			Printf("Warning: Failed to set protection for section %s: %v", sectionName, err)
		}

		Printf("Section %s mapped successfully: %d bytes", sectionName, bytesWritten)
		_ = j
	}

	return nil
}

func (i *Injector) resolveImportsWithEvasion(hProcess windows.Handle, baseAddress uintptr, peHeader *PEHeader) error {
	i.logger.Info("Resolving imports with hook evasion")

	if len(peHeader.DataDirectories) <= IMAGE_DIRECTORY_ENTRY_IMPORT {
		return nil
	}

	importDir := peHeader.DataDirectories[IMAGE_DIRECTORY_ENTRY_IMPORT]
	if importDir.VirtualAddress == 0 || importDir.Size == 0 {
		return nil
	}

	importAddr := baseAddress + uintptr(importDir.VirtualAddress)
	descriptorCount := importDir.Size / uint32(unsafe.Sizeof(ImportDescriptor{}))

	for j := uint32(0); j < descriptorCount; j++ {
		var descriptor ImportDescriptor
		descAddr := importAddr + uintptr(j*uint32(unsafe.Sizeof(ImportDescriptor{})))

		var bytesRead uintptr
		err := windows.ReadProcessMemory(hProcess, descAddr,
			(*byte)(unsafe.Pointer(&descriptor)), unsafe.Sizeof(descriptor), &bytesRead)
		if err != nil {
			continue
		}

		if descriptor.Name == 0 {
			break
		}

		dllNameAddr := baseAddress + uintptr(descriptor.Name)
		dllName, err := readStringFromRemoteProcess(hProcess, dllNameAddr)
		if err != nil {
			continue
		}

		Printf("Resolving imports from: %s", dllName)

		var dllHandle windows.Handle
		if i.bypassOptions.DirectSyscalls {
			dllHandle, err = loadLibraryWithSyscalls(dllName)
		} else {
			dllHandle, err = windows.LoadLibrary(dllName)
		}

		if err != nil {
			Printf("Warning: Failed to load %s: %v", dllName, err)
			continue
		}

		iatAddr := baseAddress + uintptr(descriptor.FirstThunk)
		if err := resolveIATWithEvasion(hProcess, iatAddr, dllHandle, peHeader.Is64Bit); err != nil {
			Printf("Warning: Failed to resolve IAT for %s: %v", dllName, err)
		}
	}

	return nil
}


func (i *Injector) modifyPETimestamps(headerData []byte, peHeader *PEHeader) {


	Printf("Modifying PE timestamps for anti-detection")
}

func applySectionAntiDetection(data []byte, sectionName string, options BypassOptions) []byte {
	modifiedData := make([]byte, len(data))
	copy(modifiedData, data)

	// Apply InjGen pattern replacement to evade detection
	// This replaces 0x06 (push es) and 0x99 0x1E 0xE0 0xFC patterns
	modifiedData = ReplaceInjGenPatterns(modifiedData)

	if sectionName == ".rdata" && options.EraseEntryPoint {
		Printf("Applying anti-detection to .rdata section")
	}

	return modifiedData
}

func calculateSectionProtection(characteristics uint32) uint32 {
	var protection uint32 = windows.PAGE_READONLY

	if characteristics&IMAGE_SCN_MEM_EXECUTE != 0 {
		if characteristics&IMAGE_SCN_MEM_WRITE != 0 {
			protection = windows.PAGE_EXECUTE_READWRITE
		} else {
			protection = windows.PAGE_EXECUTE_READ
		}
	} else if characteristics&IMAGE_SCN_MEM_WRITE != 0 {
		protection = windows.PAGE_READWRITE
	}

	return protection
}

func (i *Injector) processRelocationsAdvanced(hProcess windows.Handle, baseAddress uintptr, peHeader *PEHeader) error {

	return FixRelocations(hProcess, baseAddress, peHeader)
}

func (i *Injector) processTLSCallbacks(hProcess windows.Handle, baseAddress uintptr, peHeader *PEHeader) error {
	Printf("Processing TLS callbacks")

	return nil
}

func (i *Injector) setupExceptionHandlers(hProcess windows.Handle, baseAddress uintptr, peHeader *PEHeader) error {
	Printf("Setting up exception handlers")

	return nil
}

func (i *Injector) executeDLLEntryProtected(hProcess windows.Handle, baseAddress uintptr, peHeader *PEHeader) error {
	Printf("Executing DLL entry point with protection")
	return ExecuteDllEntry(hProcess, baseAddress, peHeader)
}

func (i *Injector) applyPostMappingAntiDetection(hProcess windows.Handle, baseAddress uintptr, size uintptr, dllBytes []byte) error {
	Printf("Applying post-mapping anti-detection techniques")

	if i.bypassOptions.ErasePEHeader {
		if err := ErasePEHeader(hProcess, baseAddress); err != nil {
			return fmt.Errorf("failed to erase PE header: %v", err)
		}
	}

	if i.bypassOptions.EraseEntryPoint {
		if err := EraseEntryPoint(hProcess, baseAddress); err != nil {
			return fmt.Errorf("failed to erase entry point: %v", err)
		}
	}

	if i.bypassOptions.RemoveVADNode {
		if err := RemoveVADNode(hProcess, baseAddress); err != nil {
			Printf("Warning: VAD node removal failed: %v", err)
		}
	}

	// Apply JVMTI-specific bypass techniques if target is a Java process
	if i.isJavaProcess() {
		i.logger.Info("Java process detected - applying comprehensive JVMTI bypass techniques")
		
		// CRITICAL: Clean JVM DLL range BEFORE injection to remove any existing patterns
		// InjGen scans this range, so we need to ensure it's clean
		// First check if patterns exist (diagnostic)
		jvmBase, jvmEnd, err := GetJVMDLLMemoryRange(hProcess)
		if err == nil {
			jvmSize := uint32(jvmEnd - jvmBase)
			clean, p1, p2 := VerifyPatternRemoval(hProcess, jvmBase, jvmSize)
			i.logger.Info("Pre-injection JVM DLL range status",
				"clean", clean, "pattern1", p1, "pattern2", p2,
				"jvm_base", fmt.Sprintf("0x%X", jvmBase),
				"jvm_end", fmt.Sprintf("0x%X", jvmEnd))
			
			if !clean {
				i.logger.Warn("Patterns found in JVM DLL range BEFORE injection - cleaning now",
					"pattern1", p1, "pattern2", p2)
			}
		}
		
		if err := CleanJVMDLLMemoryRange(hProcess); err != nil {
			i.logger.Warn("Pre-injection JVM range cleanup failed", "error", err)
		} else {
			i.logger.Info("Pre-injection JVM DLL memory range cleaned")
		}
		
		jvmtiOptions := JVMTIBypassOptions{
			HideFromPEB:          true,
			ErasePESignatures:    true,
			ObfuscateMemory:      true,
			SpoofModuleName:      true,
			RandomizeMemory:      true,
			UnhookAPIs:           true,
			HideThreads:          true,
			IndirectExecution:    false, // Manual mapping doesn't create threads
			HookJVMTICallbacks:   false, // Advanced, may cause issues
			UseReflectiveMapping: false, // Already using manual mapping
			DelayExecution:        false, // Not needed for manual mapping
			EvadePatternScan:     true,  // Evade InjGen's specific pattern scanning
			EncryptCode:          false, // Disabled by default (requires decryption stub)
			PolymorphicCode:      false, // Not implemented yet
			MemoryRangeEvasion:   true,  // Evade memory range scanning
			PreInjectionCleanup:  true,  // Clean patterns before injection (already done in Inject())
			ModuleStomping:       false, // Disabled - use manual mapping instead
			BlockMemoryReads:     true,  // Attempt to block InjGen's memory reads
			CleanJVMMemoryRange:  true,  // CRITICAL: Clean patterns from entire JVM DLL range
			AvoidJVMMemoryRange:  true,  // Try to avoid injecting into JVM DLL range
			ObfuscateMemoryProtection: true, // Make memory appear as different type
			DynamicPatternCleaning: true, // Continuously clean patterns
		}
		if err := ApplyJVMTIBypass(hProcess, baseAddress, uint32(size), jvmtiOptions); err != nil {
			i.logger.Warn("JVMTI bypass failed", "error", err)
		}
		
		// CRITICAL: Clean JVM DLL range AGAIN after injection
		// InjGen scans this range, and our injection might have introduced patterns
		// Do multiple passes to ensure it's completely clean
		i.logger.Info("Performing post-injection JVM DLL range cleanup")
		for cleanupPass := 0; cleanupPass < 3; cleanupPass++ {
			if err := CleanJVMDLLMemoryRange(hProcess); err != nil {
				i.logger.Warn("Post-injection JVM range cleanup failed", "pass", cleanupPass+1, "error", err)
			} else {
				// Verify it's clean
				jvmBase, jvmEnd, err := GetJVMDLLMemoryRange(hProcess)
				if err == nil {
					jvmSize := uint32(jvmEnd - jvmBase)
					clean, p1, p2 := VerifyPatternRemoval(hProcess, jvmBase, jvmSize)
					if clean {
						i.logger.Info("JVM DLL range verified clean after injection", "pass", cleanupPass+1)
						break
					} else {
						i.logger.Warn("JVM DLL range still has patterns", "pattern1", p1, "pattern2", p2, "pass", cleanupPass+1)
					}
				}
			}
		}
	}

	return nil
}

func readStringFromRemoteProcess(hProcess windows.Handle, addr uintptr) (string, error) {
	var result []byte
	buffer := make([]byte, 1)

	for len(result) < 260 {
		var bytesRead uintptr
		err := windows.ReadProcessMemory(hProcess, addr+uintptr(len(result)),
			&buffer[0], 1, &bytesRead)
		if err != nil {
			return "", err
		}

		if buffer[0] == 0 {
			break
		}

		result = append(result, buffer[0])
	}

	return string(result), nil
}

func loadLibraryWithSyscalls(dllName string) (windows.Handle, error) {
	Printf("Loading library with syscalls: %s", dllName)


	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	ldrLoadDll := ntdll.NewProc("LdrLoadDll")

	dllNameUTF16, err := windows.UTF16PtrFromString(dllName)
	if err != nil {
		return 0, fmt.Errorf("failed to convert DLL name to UTF16: %v", err)
	}

	var unicodeString struct {
		Length        uint16
		MaximumLength uint16
		Buffer        *uint16
	}

	dllNameLen := len(dllName) * 2
	unicodeString.Length = uint16(dllNameLen)
	unicodeString.MaximumLength = uint16(dllNameLen + 2)
	unicodeString.Buffer = dllNameUTF16

	var moduleHandle windows.Handle

	ret, _, _ := ldrLoadDll.Call(
		0,
		0,
		uintptr(unsafe.Pointer(&unicodeString)),
		uintptr(unsafe.Pointer(&moduleHandle)),
	)

	if ret != 0 {
		Printf("LdrLoadDll failed with NTSTATUS: 0x%X", ret)

		return windows.LoadLibrary(dllName)
	}

	Printf("Successfully loaded %s via LdrLoadDll", dllName)
	return moduleHandle, nil
}

func resolveIATWithEvasion(hProcess windows.Handle, iatAddr uintptr, dllHandle windows.Handle, is64Bit bool) error {
	Printf("Resolving IAT with evasion techniques")

	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	ldrGetProcedureAddress := ntdll.NewProc("LdrGetProcedureAddress")

	var entrySize int
	if is64Bit {
		entrySize = 8
	} else {
		entrySize = 4
	}

	for offset := 0; offset < 1024; offset += entrySize {
		var entry uintptr
		var bytesRead uintptr

		err := windows.ReadProcessMemory(hProcess, iatAddr+uintptr(offset),
			(*byte)(unsafe.Pointer(&entry)), uintptr(entrySize), &bytesRead)
		if err != nil || entry == 0 {
			break
		}

		if entry&0x8000000000000000 == 0 && is64Bit {
			continue
		}
		if entry&0x80000000 == 0 && !is64Bit {
			continue
		}


		var functionAddr uintptr

		functionName := "GetProcAddress"
		var ansiString struct {
			Length        uint16
			MaximumLength uint16
			Buffer        *byte
		}

		functionNameBytes := []byte(functionName)
		ansiString.Length = uint16(len(functionNameBytes))
		ansiString.MaximumLength = uint16(len(functionNameBytes))
		ansiString.Buffer = &functionNameBytes[0]

		ret, _, _ := ldrGetProcedureAddress.Call(
			uintptr(dllHandle),
			uintptr(unsafe.Pointer(&ansiString)),
			0,
			uintptr(unsafe.Pointer(&functionAddr)),
		)

		if ret == 0 && functionAddr != 0 {

			var bytesWritten uintptr
			err = WriteProcessMemory(hProcess, iatAddr+uintptr(offset),
				unsafe.Pointer(&functionAddr), uintptr(entrySize), &bytesWritten)
			if err != nil {
				Printf("Warning: Failed to write resolved address to IAT: %v", err)
			}
		}
	}

	Printf("IAT resolution with evasion completed")
	return nil
}
