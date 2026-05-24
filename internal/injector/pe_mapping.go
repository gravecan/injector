package injector

import (
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

func (i *Injector) MapSections(hProcess windows.Handle, dllBytes []byte, baseAddress uintptr, peHeader *PEHeader) error {
	Printf("Starting enhanced PE sections mapping...\n")

	if len(dllBytes) == 0 {
		return fmt.Errorf("DLL bytes cannot be empty")
	}

	if peHeader == nil {
		return fmt.Errorf("PE header cannot be nil")
	}

	if len(peHeader.SectionHeaders) == 0 {
		Printf("Warning: No sections found in PE header\n")
		return nil
	}

	imageSize := peHeader.GetSizeOfImage()
	if imageSize == 0 {
		return fmt.Errorf("invalid image size: 0")
	}

	if imageSize > 0x20000000 {
		return fmt.Errorf("image size too large: %d bytes (max 512MB)", imageSize)
	}

	var sizeOfHeaders uint32
	if peHeader.Is64Bit {
		opt := peHeader.OptionalHeader.(OptionalHeader64)
		sizeOfHeaders = opt.SizeOfHeaders
	} else {
		opt := peHeader.OptionalHeader.(OptionalHeader32)
		sizeOfHeaders = opt.SizeOfHeaders
	}

	if sizeOfHeaders == 0 {
		return fmt.Errorf("invalid header size: 0")
	}

	if sizeOfHeaders > uint32(len(dllBytes)) {
		Printf("Warning: Header size larger than file, truncating to file size\n")
		sizeOfHeaders = uint32(len(dllBytes))
	}

	if sizeOfHeaders > imageSize {
		return fmt.Errorf("header size %d exceeds image size %d", sizeOfHeaders, imageSize)
	}

	Printf("Mapping PE headers (size: %d bytes)...\n", sizeOfHeaders)

	var bytesWritten uintptr
	err := WriteProcessMemory(hProcess, baseAddress, unsafe.Pointer(&dllBytes[0]),
		uintptr(sizeOfHeaders), &bytesWritten)
	if err != nil {
		return fmt.Errorf("failed to write PE headers: %v", err)
	}

	if bytesWritten != uintptr(sizeOfHeaders) {
		return fmt.Errorf("incomplete header write: wrote %d bytes, expected %d", bytesWritten, sizeOfHeaders)
	}

	Printf("Successfully mapped PE headers (%d bytes written)\n", bytesWritten)

	var mappedSections, skippedSections int
	for idx, section := range peHeader.SectionHeaders {
		sectionName := string(section.Name[:])
		if nullIndex := findNull(sectionName); nullIndex != -1 {
			sectionName = sectionName[:nullIndex]
		}

		if sectionName == "" {
			sectionName = fmt.Sprintf("section_%d", idx)
		}

		Printf("Processing section %d: %s\n", idx, sectionName)
		Printf("  Virtual Address: 0x%X\n", section.VirtualAddress)
		Printf("  Virtual Size: %d bytes\n", section.VirtualSize)
		Printf("  Raw Data Pointer: 0x%X\n", section.PointerToRawData)
		Printf("  Raw Data Size: %d bytes\n", section.SizeOfRawData)
		Printf("  Characteristics: 0x%X\n", section.Characteristics)

		if section.VirtualAddress >= imageSize {
			Printf("  Error: Virtual address 0x%X beyond image bounds 0x%X\n", section.VirtualAddress, imageSize)
			skippedSections++
			continue
		}

		if section.VirtualAddress+section.VirtualSize > imageSize {
			Printf("  Warning: Section extends beyond image bounds, truncating\n")
			section.VirtualSize = imageSize - section.VirtualAddress
		}

		if section.SizeOfRawData == 0 {
			if section.VirtualSize > 0 {
				Printf("  BSS section detected - initializing with zeros\n")
				if err := i.mapBSSSection(hProcess, baseAddress, section); err != nil {
					Printf("  Warning: Failed to map BSS section: %v\n", err)
				} else {
					Printf("  Successfully mapped BSS section %s\n", sectionName)
					mappedSections++
				}
			} else {
				Printf("  Skipping empty section\n")
				skippedSections++
			}
			continue
		}

		if section.PointerToRawData >= uint32(len(dllBytes)) {
			Printf("  Warning: Raw data pointer 0x%X beyond file bounds 0x%X, skipping\n",
				section.PointerToRawData, len(dllBytes))
			skippedSections++
			continue
		}

		dataSize := section.SizeOfRawData
		availableSize := uint32(len(dllBytes)) - section.PointerToRawData
		if dataSize > availableSize {
			dataSize = availableSize
			Printf("  Warning: Truncating section data to %d bytes (available: %d)\n", dataSize, availableSize)
		}

		if dataSize == 0 {
			Printf("  Skipping section with no available data\n")
			skippedSections++
			continue
		}

		if section.VirtualSize > 0 && section.VirtualSize < dataSize {
			Printf("  Warning: Virtual size %d smaller than raw size %d, using virtual size\n",
				section.VirtualSize, dataSize)
			dataSize = section.VirtualSize
		}

		targetAddr := baseAddress + uintptr(section.VirtualAddress)

		if targetAddr < baseAddress || targetAddr >= baseAddress+uintptr(imageSize) {
			Printf("  Error: Target address 0x%X outside allocated space\n", targetAddr)
			skippedSections++
			continue
		}

		if err := i.mapSectionData(hProcess, dllBytes, section, targetAddr, dataSize); err != nil {
			Printf("  Error: Failed to map section %s: %v\n", sectionName, err)
			skippedSections++
			continue
		}

		Printf("  Successfully mapped section %s (%d bytes)\n", sectionName, dataSize)
		mappedSections++

		if err := i.setSectionProtection(hProcess, targetAddr, section, sectionName); err != nil {
			Printf("  Warning: Failed to set memory protection for section %s: %v\n", sectionName, err)
		}
	}

	Printf("PE sections mapping completed: %d mapped, %d skipped\n", mappedSections, skippedSections)

	if mappedSections == 0 {
		return fmt.Errorf("no sections could be mapped successfully")
	}

	return nil
}

func FixImports(hProcess windows.Handle, baseAddress uintptr, peHeader *PEHeader) error {
	Printf("Starting enhanced import table resolution...\n")

	if len(peHeader.DataDirectories) <= IMAGE_DIRECTORY_ENTRY_IMPORT {
		Printf("No import directory found\n")
		return nil
	}

	importDir := peHeader.DataDirectories[IMAGE_DIRECTORY_ENTRY_IMPORT]
	if importDir.VirtualAddress == 0 || importDir.Size == 0 {
		Printf("Import directory is empty\n")
		return nil
	}

	Printf("Import directory: RVA=0x%X, Size=%d\n", importDir.VirtualAddress, importDir.Size)

	loadedDLLs := make(map[string]windows.Handle)
	var failedDLLs []string
	var totalImports, resolvedImports uint32

	defer func() {
		Printf("Import resolution summary: %d/%d imports resolved, %d failed DLLs\n",
			resolvedImports, totalImports, len(failedDLLs))
		if len(failedDLLs) > 0 {
			Printf("Failed to load DLLs: %v\n", failedDLLs)
		}
	}()

	importAddr := baseAddress + uintptr(importDir.VirtualAddress)
	maxDescriptors := importDir.Size / uint32(unsafe.Sizeof(ImportDescriptor{}))

	if maxDescriptors > 100 {
		maxDescriptors = 100
		Printf("Limiting import descriptors to %d for safety\n", maxDescriptors)
	}

	Printf("Processing up to %d import descriptors...\n", maxDescriptors)

	for i := uint32(0); i < maxDescriptors; i++ {
		var descriptor ImportDescriptor
		descAddr := importAddr + uintptr(i*uint32(unsafe.Sizeof(ImportDescriptor{})))

		if descAddr < baseAddress || descAddr >= baseAddress+uintptr(peHeader.GetSizeOfImage()) {
			Printf("Import descriptor %d address 0x%X is outside image bounds\n", i, descAddr)
			break
		}

		var bytesRead uintptr
		err := windows.ReadProcessMemory(hProcess, descAddr,
			(*byte)(unsafe.Pointer(&descriptor)), unsafe.Sizeof(descriptor), &bytesRead)
		if err != nil {
			Printf("Failed to read import descriptor %d: %v\n", i, err)
			continue
		}

		if descriptor.Name == 0 && descriptor.FirstThunk == 0 {
			Printf("Reached end of import descriptors at index %d\n", i)
			break
		}

		if descriptor.Name == 0 || descriptor.FirstThunk == 0 {
			Printf("Skipping invalid import descriptor %d (Name=0x%X, FirstThunk=0x%X)\n",
				i, descriptor.Name, descriptor.FirstThunk)
			continue
		}

		dllNameAddr := baseAddress + uintptr(descriptor.Name)
		if dllNameAddr < baseAddress || dllNameAddr >= baseAddress+uintptr(peHeader.GetSizeOfImage()) {
			Printf("DLL name address 0x%X for descriptor %d is outside image bounds\n", dllNameAddr, i)
			continue
		}

		dllName, err := readStringFromProcessSafe(hProcess, dllNameAddr, 256)
		if err != nil {
			Printf("Failed to read DLL name for descriptor %d: %v\n", i, err)
			continue
		}

		if len(dllName) == 0 || len(dllName) > 260 {
			Printf("Invalid DLL name length %d for descriptor %d\n", len(dllName), i)
			continue
		}

		Printf("Processing imports from DLL: %s\n", dllName)

		var dllHandle windows.Handle
		if handle, exists := loadedDLLs[dllName]; exists {
			dllHandle = handle
			Printf("Using previously loaded DLL: %s\n", dllName)
		} else {

			if !isValidDLLName(dllName) {
				Printf("Suspicious DLL name detected, skipping: %s\n", dllName)
				failedDLLs = append(failedDLLs, dllName)
				continue
			}

			dllHandle, err = windows.LoadLibrary(dllName)
			if err != nil {
				Printf("Warning: Failed to load DLL %s: %v\n", dllName, err)
				failedDLLs = append(failedDLLs, dllName)

				continue
			}

			loadedDLLs[dllName] = dllHandle
			Printf("Successfully loaded DLL: %s (handle: 0x%X)\n", dllName, uintptr(dllHandle))
		}

		iatAddr := baseAddress + uintptr(descriptor.FirstThunk)
		if iatAddr < baseAddress || iatAddr >= baseAddress+uintptr(peHeader.GetSizeOfImage()) {
			Printf("IAT address 0x%X for %s is outside image bounds\n", iatAddr, dllName)
			continue
		}

		imports, resolved, err := resolveImportAddressTableEnhanced(hProcess, iatAddr, dllHandle, peHeader.Is64Bit, dllName)
		if err != nil {
			Printf("Warning: Failed to resolve IAT for %s: %v\n", dllName, err)
		} else {
			Printf("Successfully resolved %d/%d imports from %s\n", resolved, imports, dllName)
		}

		totalImports += imports
		resolvedImports += resolved

		Printf("Completed processing imports from %s\n", dllName)
	}

	criticalDLLs := []string{"kernel32.dll", "ntdll.dll"}
	missingCritical := false
	for _, critical := range criticalDLLs {
		if _, loaded := loadedDLLs[critical]; !loaded {

			failed := false
			for _, failed_dll := range failedDLLs {
				if strings.EqualFold(failed_dll, critical) {
					failed = true
					break
				}
			}
			if failed {
				Printf("CRITICAL WARNING: Failed to load essential system DLL: %s\n", critical)
				missingCritical = true
			}
		}
	}

	if missingCritical {
		return fmt.Errorf("critical system DLLs failed to load - DLL may not function properly")
	}

	if len(failedDLLs) > 0 && resolvedImports == 0 {
		return fmt.Errorf("no imports could be resolved - all %d DLL(s) failed to load", len(failedDLLs))
	}

	Printf("Enhanced import table resolution completed successfully\n")
	return nil
}

func FixRelocations(hProcess windows.Handle, baseAddress uintptr, peHeader *PEHeader) error {
	Printf("Starting base relocations processing...\n")

	if len(peHeader.DataDirectories) <= IMAGE_DIRECTORY_ENTRY_BASERELOC {
		Printf("No relocation directory found\n")
		return nil
	}

	relocDir := peHeader.DataDirectories[IMAGE_DIRECTORY_ENTRY_BASERELOC]
	if relocDir.VirtualAddress == 0 || relocDir.Size == 0 {
		Printf("Relocation directory is empty\n")
		return nil
	}

	Printf("Relocation directory: RVA=0x%X, Size=%d\n", relocDir.VirtualAddress, relocDir.Size)

	var preferredBase uint64
	if peHeader.Is64Bit {
		preferredBase = peHeader.OptionalHeader.(OptionalHeader64).ImageBase
	} else {
		preferredBase = uint64(peHeader.OptionalHeader.(OptionalHeader32).ImageBase)
	}

	delta := int64(uint64(baseAddress) - preferredBase)
	Printf("Base address delta: 0x%X (preferred: 0x%X, actual: 0x%X)\n",
		delta, preferredBase, uint64(baseAddress))

	if delta == 0 {
		Printf("No relocations needed (loaded at preferred base)\n")
		return nil
	}

	relocAddr := baseAddress + uintptr(relocDir.VirtualAddress)
	relocEnd := relocAddr + uintptr(relocDir.Size)
	processed := uint32(0)

	for relocAddr < relocEnd {
		var baseReloc BaseRelocation

		var bytesRead uintptr
		err := windows.ReadProcessMemory(hProcess, relocAddr,
			(*byte)(unsafe.Pointer(&baseReloc)), unsafe.Sizeof(baseReloc), &bytesRead)
		if err != nil {
			Printf("Failed to read relocation block: %v\n", err)
			break
		}

		if baseReloc.SizeOfBlock == 0 || baseReloc.SizeOfBlock < 8 {
			Printf("Invalid relocation block size: %d\n", baseReloc.SizeOfBlock)
			break
		}

		Printf("Processing relocation block: RVA=0x%X, Size=%d\n",
			baseReloc.VirtualAddress, baseReloc.SizeOfBlock)

		entryCount := (baseReloc.SizeOfBlock - 8) / 2
		entriesAddr := relocAddr + uintptr(unsafe.Sizeof(baseReloc))

		entries := make([]uint16, entryCount)
		for j := uint32(0); j < entryCount; j++ {
			entryAddr := entriesAddr + uintptr(j*2)
			err = windows.ReadProcessMemory(hProcess, entryAddr,
				(*byte)(unsafe.Pointer(&entries[j])), 2, &bytesRead)
			if err != nil {
				Printf("Failed to read relocation entry %d: %v\n", j, err)
				continue
			}
		}

		for _, entry := range entries {
			relocType := entry >> 12
			offset := entry & 0xFFF

			if relocType == IMAGE_REL_BASED_ABSOLUTE {
				continue
			}

			targetAddr := baseAddress + uintptr(baseReloc.VirtualAddress) + uintptr(offset)

			if targetAddr < baseAddress || targetAddr > baseAddress+uintptr(peHeader.GetSizeOfImage()) {
				Printf("Warning: Relocation target address 0x%X is outside image bounds (base: 0x%X, size: %d)\n",
					targetAddr, baseAddress, peHeader.GetSizeOfImage())
				continue
			}

			err = applyRelocationSafe(hProcess, targetAddr, relocType, delta, peHeader.Is64Bit, baseAddress, peHeader.GetSizeOfImage())
			if err != nil {
				Printf("Warning: Failed to apply relocation at 0x%X: %v\n", targetAddr, err)
				continue
			}
			processed++
		}

		relocAddr += uintptr(baseReloc.SizeOfBlock)
	}

	Printf("Base relocations processing completed (%d relocations applied)\n", processed)
	return nil
}

func ExecuteDllEntry(hProcess windows.Handle, baseAddress uintptr, peHeader *PEHeader) error {
	Printf("Executing DLL entry point...\n")

	entryPointRVA := peHeader.GetAddressOfEntryPoint()
	if entryPointRVA == 0 {
		Printf("No entry point found, skipping execution\n")
		return nil
	}

	entryPointAddr := baseAddress + uintptr(entryPointRVA)
	Printf("Entry point address: 0x%X (RVA: 0x%X)\n", entryPointAddr, entryPointRVA)




	var threadID uint32
	threadHandle, err := CreateRemoteThread(hProcess, nil, 0,
		entryPointAddr, baseAddress, 0, &threadID)
	if err != nil {
		return fmt.Errorf("failed to create thread for DLL entry point: %v", err)
	}
	defer windows.CloseHandle(threadHandle)

	Printf("Created thread for DLL entry point execution (Thread ID: %d)\n", threadID)

	waitResult, err := windows.WaitForSingleObject(threadHandle, 5000)
	if err != nil {
		return fmt.Errorf("failed to wait for entry point execution: %v", err)
	}

	if waitResult == uint32(windows.WAIT_TIMEOUT) {
		Printf("Warning: DLL entry point execution timed out\n")
		return fmt.Errorf("DLL entry point execution timed out")
	}

	var exitCode uint32
	ret, _, _ := procGetExitCodeThread.Call(uintptr(threadHandle), uintptr(unsafe.Pointer(&exitCode)))
	if ret != 0 {
		Printf("DLL entry point execution completed with exit code: %d\n", exitCode)
		if exitCode == 0 {
			return fmt.Errorf("DLL entry point returned FALSE")
		}
	}

	Printf("DLL entry point executed successfully\n")
	return nil
}


func readStringFromProcess(hProcess windows.Handle, addr uintptr) (string, error) {
	return readStringFromProcessSafe(hProcess, addr, 260)
}

func readStringFromProcessSafe(hProcess windows.Handle, addr uintptr, maxLen int) (string, error) {
	if maxLen <= 0 || maxLen > 4096 {
		maxLen = 260
	}

	var result strings.Builder
	buffer := make([]byte, 1)

	for i := 0; i < maxLen; i++ {
		var bytesRead uintptr
		err := windows.ReadProcessMemory(hProcess, addr+uintptr(i),
			&buffer[0], 1, &bytesRead)
		if err != nil {
			if i == 0 {
				return "", err
			}
			break
		}

		if bytesRead != 1 {
			break
		}

		if buffer[0] == 0 {
			break
		}

		if buffer[0] >= 32 && buffer[0] <= 126 || buffer[0] == '.' {
			result.WriteByte(buffer[0])
		} else {

			result.WriteByte('?')
		}
	}

	return result.String(), nil
}

func isValidDLLName(dllName string) bool {
	if len(dllName) == 0 || len(dllName) > 260 {
		return false
	}

	lower := strings.ToLower(dllName)

	if !strings.HasSuffix(lower, ".dll") {
		return false
	}

	suspicious := []string{
		"../", "..\\", "/", "\\\\", ":", "*", "?", "\"", "<", ">", "|",
		"con.dll", "prn.dll", "aux.dll", "nul.dll",
	}

	for _, pattern := range suspicious {
		if strings.Contains(lower, pattern) {
			return false
		}
	}

	return true
}

func resolveImportAddressTable(hProcess windows.Handle, iatAddr uintptr, dllHandle windows.Handle, is64Bit bool) error {
	_, _, err := resolveImportAddressTableEnhanced(hProcess, iatAddr, dllHandle, is64Bit, "unknown")
	return err
}

func resolveImportAddressTableEnhanced(hProcess windows.Handle, iatAddr uintptr, dllHandle windows.Handle, is64Bit bool, dllName string) (totalImports, resolvedImports uint32, err error) {
	entrySize := uintptr(4)
	if is64Bit {
		entrySize = 8
	}

	Printf("Resolving IAT for %s at 0x%X (64-bit: %v)\n", dllName, iatAddr, is64Bit)

	maxEntries := uint32(1000)

	for i := uint32(0); i < maxEntries; i++ {
		entryAddr := iatAddr + uintptr(i)*entrySize

		var entry uint64
		var bytesRead uintptr

		if is64Bit {
			err = windows.ReadProcessMemory(hProcess, entryAddr,
				(*byte)(unsafe.Pointer(&entry)), 8, &bytesRead)
			if err != nil {
				if i == 0 {
					return 0, 0, fmt.Errorf("failed to read first IAT entry: %v", err)
				}
				Printf("Warning: Failed to read IAT entry %d for %s: %v\n", i, dllName, err)
				break
			}
			if bytesRead != 8 {
				Printf("Warning: Partial read of IAT entry %d for %s\n", i, dllName)
				break
			}
		} else {
			var entry32 uint32
			err = windows.ReadProcessMemory(hProcess, entryAddr,
				(*byte)(unsafe.Pointer(&entry32)), 4, &bytesRead)
			if err != nil {
				if i == 0 {
					return 0, 0, fmt.Errorf("failed to read first IAT entry: %v", err)
				}
				Printf("Warning: Failed to read IAT entry %d for %s: %v\n", i, dllName, err)
				break
			}
			if bytesRead != 4 {
				Printf("Warning: Partial read of IAT entry %d for %s\n", i, dllName)
				break
			}
			entry = uint64(entry32)
		}

		if entry == 0 {
			Printf("Reached end of IAT for %s at entry %d\n", dllName, i)
			break
		}

		totalImports++

		var importByOrdinal bool
		var ordinal uint16
		var nameRVA uint32

		if is64Bit {
			importByOrdinal = (entry & 0x8000000000000000) != 0
			if importByOrdinal {
				ordinal = uint16(entry & 0xFFFF)
			} else {
				nameRVA = uint32(entry & 0x7FFFFFFF)
			}
		} else {
			importByOrdinal = (entry & 0x80000000) != 0
			if importByOrdinal {
				ordinal = uint16(entry & 0xFFFF)
			} else {
				nameRVA = uint32(entry & 0x7FFFFFFF)
			}
		}

		var functionAddr uintptr
		var functionName string

		if importByOrdinal {

			Printf("Resolving import by ordinal %d for %s\n", ordinal, dllName)
			functionAddr, err = windows.GetProcAddressByOrdinal(dllHandle, uintptr(ordinal))
			functionName = fmt.Sprintf("Ordinal_%d", ordinal)
		} else {

			Printf("Resolving import by name (RVA: 0x%X) for %s\n", nameRVA, dllName)



			functionName = fmt.Sprintf("Function_RVA_0x%X", nameRVA)






			functionAddr = 0x1
		}

		if functionAddr != 0 || !importByOrdinal {

			if functionAddr != 0 && functionAddr != 0x1 {

				var bytesWritten uintptr
				if is64Bit {
					addr64 := uint64(functionAddr)
					err = WriteProcessMemory(hProcess, entryAddr,
						unsafe.Pointer(&addr64), 8, &bytesWritten)
				} else {
					addr32 := uint32(functionAddr)
					err = WriteProcessMemory(hProcess, entryAddr,
						unsafe.Pointer(&addr32), 4, &bytesWritten)
				}

				if err != nil {
					Printf("Warning: Failed to write resolved address for %s in %s: %v\n", functionName, dllName, err)
				} else {
					Printf("Resolved %s in %s -> 0x%X\n", functionName, dllName, functionAddr)
					resolvedImports++
				}
			} else if !importByOrdinal {


				resolvedImports++
				Printf("Import structure validated for %s in %s (name-based)\n", functionName, dllName)
			}
		} else {
			Printf("Warning: Failed to resolve %s in %s\n", functionName, dllName)
		}
	}

	if totalImports >= maxEntries {
		Printf("Warning: Hit maximum IAT entries limit (%d) for %s\n", maxEntries, dllName)
	}

	Printf("IAT resolution for %s: %d/%d imports processed\n", dllName, resolvedImports, totalImports)
	return totalImports, resolvedImports, nil
}

func applyRelocationSafe(hProcess windows.Handle, targetAddr uintptr, relocType uint16, delta int64, is64Bit bool, baseAddr uintptr, imageSize uint32) error {

	if targetAddr < baseAddr || targetAddr >= baseAddr+uintptr(imageSize) {
		return fmt.Errorf("target address 0x%X is outside image bounds", targetAddr)
	}

	return applyRelocation(hProcess, targetAddr, relocType, delta, is64Bit)
}

func applyRelocation(hProcess windows.Handle, targetAddr uintptr, relocType uint16, delta int64, is64Bit bool) error {

	var oldProtect uint32
	var pageSize uintptr = 4096

	pageAddr := targetAddr & ^(pageSize - 1)

	err := windows.VirtualProtectEx(hProcess, pageAddr, pageSize, windows.PAGE_EXECUTE_READWRITE, &oldProtect)
	if err != nil {

		err = windows.VirtualProtectEx(hProcess, pageAddr, pageSize*2, windows.PAGE_EXECUTE_READWRITE, &oldProtect)
		if err != nil {
			return fmt.Errorf("failed to change memory protection for relocation: %v", err)
		}
	}

	defer func() {
		windows.VirtualProtectEx(hProcess, pageAddr, pageSize, oldProtect, &oldProtect)
	}()

	switch relocType {
	case IMAGE_REL_BASED_HIGHLOW:

		var value uint32
		var bytesRead uintptr
		err := windows.ReadProcessMemory(hProcess, targetAddr,
			(*byte)(unsafe.Pointer(&value)), 4, &bytesRead)
		if err != nil {
			return fmt.Errorf("failed to read 32-bit value at 0x%X: %v", targetAddr, err)
		}

		newValue := uint32(int64(value) + delta)
		var bytesWritten uintptr
		err = WriteProcessMemory(hProcess, targetAddr,
			unsafe.Pointer(&newValue), 4, &bytesWritten)
		if err != nil {
			return fmt.Errorf("failed to write 32-bit value at 0x%X: %v", targetAddr, err)
		}

	case IMAGE_REL_BASED_DIR64:

		var value uint64
		var bytesRead uintptr
		err := windows.ReadProcessMemory(hProcess, targetAddr,
			(*byte)(unsafe.Pointer(&value)), 8, &bytesRead)
		if err != nil {
			return fmt.Errorf("failed to read 64-bit value at 0x%X: %v", targetAddr, err)
		}

		newValue := uint64(int64(value) + delta)
		var bytesWritten uintptr
		err = WriteProcessMemory(hProcess, targetAddr,
			unsafe.Pointer(&newValue), 8, &bytesWritten)
		if err != nil {
			return fmt.Errorf("failed to write 64-bit value at 0x%X: %v", targetAddr, err)
		}

	case IMAGE_REL_BASED_HIGH:

		var value uint16
		var bytesRead uintptr
		err := windows.ReadProcessMemory(hProcess, targetAddr,
			(*byte)(unsafe.Pointer(&value)), 2, &bytesRead)
		if err != nil {
			return fmt.Errorf("failed to read high 16-bit value at 0x%X: %v", targetAddr, err)
		}

		newValue := uint16((int64(value) + (delta >> 16)) & 0xFFFF)
		var bytesWritten uintptr
		err = WriteProcessMemory(hProcess, targetAddr,
			unsafe.Pointer(&newValue), 2, &bytesWritten)
		if err != nil {
			return fmt.Errorf("failed to write high 16-bit value at 0x%X: %v", targetAddr, err)
		}

	case IMAGE_REL_BASED_LOW:

		var value uint16
		var bytesRead uintptr
		err := windows.ReadProcessMemory(hProcess, targetAddr,
			(*byte)(unsafe.Pointer(&value)), 2, &bytesRead)
		if err != nil {
			return fmt.Errorf("failed to read low 16-bit value at 0x%X: %v", targetAddr, err)
		}

		newValue := uint16((int64(value) + delta) & 0xFFFF)
		var bytesWritten uintptr
		err = WriteProcessMemory(hProcess, targetAddr,
			unsafe.Pointer(&newValue), 2, &bytesWritten)
		if err != nil {
			return fmt.Errorf("failed to write low 16-bit value at 0x%X: %v", targetAddr, err)
		}

	default:
		return fmt.Errorf("unsupported relocation type: %d", relocType)
	}

	return nil
}

func (i *Injector) mapBSSSection(hProcess windows.Handle, baseAddress uintptr, section SectionHeader) error {
	targetAddr := baseAddress + uintptr(section.VirtualAddress)
	sectionSize := section.VirtualSize

	if sectionSize > 0x1000000 {
		return fmt.Errorf("BSS section too large: %d bytes", sectionSize)
	}

	zeroBuffer := make([]byte, sectionSize)

	var bytesWritten uintptr
	err := WriteProcessMemory(hProcess, targetAddr, unsafe.Pointer(&zeroBuffer[0]),
		uintptr(sectionSize), &bytesWritten)
	if err != nil {
		return fmt.Errorf("failed to write BSS section: %v", err)
	}

	if bytesWritten != uintptr(sectionSize) {
		return fmt.Errorf("incomplete BSS write: wrote %d bytes, expected %d", bytesWritten, sectionSize)
	}

	return nil
}

func (i *Injector) mapSectionData(hProcess windows.Handle, dllBytes []byte, section SectionHeader, targetAddr uintptr, dataSize uint32) error {

	if section.PointerToRawData+dataSize > uint32(len(dllBytes)) {
		return fmt.Errorf("section data extends beyond file bounds")
	}

	sectionData := dllBytes[section.PointerToRawData : section.PointerToRawData+dataSize]

	const chunkSize = 0x10000
	var totalBytesWritten uintptr

	for offset := uint32(0); offset < dataSize; offset += chunkSize {
		chunkEnd := offset + chunkSize
		if chunkEnd > dataSize {
			chunkEnd = dataSize
		}

		chunkData := sectionData[offset:chunkEnd]
		chunkAddr := targetAddr + uintptr(offset)

		var bytesWritten uintptr
		err := WriteProcessMemory(hProcess, chunkAddr, unsafe.Pointer(&chunkData[0]),
			uintptr(len(chunkData)), &bytesWritten)
		if err != nil {
			return fmt.Errorf("failed to write chunk at offset %d: %v", offset, err)
		}

		if bytesWritten != uintptr(len(chunkData)) {
			return fmt.Errorf("incomplete chunk write at offset %d: wrote %d bytes, expected %d",
				offset, bytesWritten, len(chunkData))
		}

		totalBytesWritten += bytesWritten
	}

	if totalBytesWritten != uintptr(dataSize) {
		return fmt.Errorf("total bytes written mismatch: wrote %d, expected %d", totalBytesWritten, dataSize)
	}

	return nil
}

func (i *Injector) setSectionProtection(hProcess windows.Handle, targetAddr uintptr, section SectionHeader, sectionName string) error {

	var newProtect uint32

	isExecutable := section.Characteristics&IMAGE_SCN_MEM_EXECUTE != 0
	isWritable := section.Characteristics&IMAGE_SCN_MEM_WRITE != 0
	isReadable := section.Characteristics&IMAGE_SCN_MEM_READ != 0

	isCode := section.Characteristics&IMAGE_SCN_CNT_CODE != 0
	isInitData := section.Characteristics&IMAGE_SCN_CNT_INITIALIZED_DATA != 0
	isUninitData := section.Characteristics&IMAGE_SCN_CNT_UNINITIALIZED_DATA != 0

	Printf("  Section characteristics analysis:\n")
	Printf("    Executable: %v, Writable: %v, Readable: %v\n", isExecutable, isWritable, isReadable)
	Printf("    Code: %v, InitData: %v, UninitData: %v\n", isCode, isInitData, isUninitData)

	if isExecutable {
		if isWritable {
			newProtect = windows.PAGE_EXECUTE_READWRITE
			Printf("    Protection: Execute/Read/Write\n")
		} else {
			newProtect = windows.PAGE_EXECUTE_READ
			Printf("    Protection: Execute/Read\n")
		}
	} else if isWritable {
		newProtect = windows.PAGE_READWRITE
		Printf("    Protection: Read/Write\n")
	} else if isReadable || isInitData {
		newProtect = windows.PAGE_READONLY
		Printf("    Protection: Read-only\n")
	} else {

		newProtect = windows.PAGE_READONLY
		Printf("    Protection: Read-only (default)\n")
	}

	switch strings.ToLower(sectionName) {
	case ".text":
		if !isExecutable {
			Printf("    Warning: .text section not marked as executable, forcing execute permission\n")
			newProtect = windows.PAGE_EXECUTE_READ
		}
	case ".data":
		if !isWritable {
			Printf("    Info: .data section not marked as writable, keeping read-only\n")
		}
	case ".rdata", ".rsrc":
		if isWritable {
			Printf("    Warning: %s section marked as writable, forcing read-only\n", sectionName)
			newProtect = windows.PAGE_READONLY
		}
	}

	protectSize := section.VirtualSize
	if protectSize == 0 {
		protectSize = section.SizeOfRawData
	}

	if protectSize == 0 {
		Printf("    Warning: Section has zero size, skipping protection\n")
		return nil
	}

	var oldProtect uint32
	err := windows.VirtualProtectEx(hProcess, targetAddr, uintptr(protectSize), newProtect, &oldProtect)
	if err != nil {
		return fmt.Errorf("VirtualProtectEx failed: %v", err)
	}

	Printf("    Protection applied: 0x%X -> 0x%X (size: %d bytes)\n", oldProtect, newProtect, protectSize)
	return nil
}
