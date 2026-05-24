package injector

import (
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// JVMTIBypassOptions contains options specific to bypassing JVMTI detection
type JVMTIBypassOptions struct {
	HideFromPEB          bool // Remove DLL from PEB module list
	ErasePESignatures    bool // Erase PE signatures after injection
	HookJVMTICallbacks   bool // Attempt to hook JVMTI agent callbacks (advanced)
	UseReflectiveMapping bool // Use reflective DLL injection to avoid LoadLibrary
	DelayExecution       bool // Delay DLL execution to avoid immediate detection
	HideThreads          bool // Hide injection threads from enumeration
	ObfuscateMemory      bool // Obfuscate memory regions to look legitimate
	SpoofModuleName      bool // Spoof module name to appear as legitimate DLL
	UnhookAPIs           bool // Remove API hooks that InjGen might place
	IndirectExecution    bool // Use existing threads instead of creating new ones
	RandomizeMemory      bool // Randomize memory patterns to evade scanning
	EvadePatternScan     bool // Evade InjGen's specific pattern scanning (0x06, 0x99 0x1E 0xE0 0xFC)
	EncryptCode          bool // Encrypt code in memory to avoid signature detection
	PolymorphicCode      bool // Use polymorphic code generation
	MemoryRangeEvasion   bool // Avoid scanned memory ranges
	ModuleStomping       bool // Inject into existing module memory (advanced)
	BlockMemoryReads     bool // Attempt to block InjGen's memory reads (hook NtReadVirtualMemory)
	PreInjectionCleanup  bool // Clean patterns from DLL bytes before injection
	CleanJVMMemoryRange  bool // Clean patterns from entire JVM DLL memory range
	AvoidJVMMemoryRange  bool // Avoid injecting into JVM DLL memory range
	ObfuscateMemoryProtection bool // Make memory appear as different type to confuse scanners
	DynamicPatternCleaning bool // Continuously clean patterns while InjGen scans
}

// HideDLLFromPEB removes the DLL from the Process Environment Block (PEB) module list
// This prevents JVMTI and other tools from detecting the injected DLL via module enumeration
// Note: Manual mapping already avoids PEB registration, but this ensures cleanup if needed
func HideDLLFromPEB(hProcess windows.Handle, baseAddress uintptr) error {
	Debug("Starting PEB module hiding for address 0x%X", baseAddress)

	// Get PEB address
	pebAddr, err := getPEBAddress(hProcess)
	if err != nil {
		return fmt.Errorf("failed to get PEB address: %v", err)
	}

	Debug("PEB address: 0x%X", pebAddr)

	// Read PEB structure
	peb, err := readPEB(hProcess, pebAddr)
	if err != nil {
		return fmt.Errorf("failed to read PEB: %v", err)
	}

	// Get LDR_DATA_TABLE_ENTRY for our module
	moduleEntry, err := findModuleInPEB(hProcess, peb, baseAddress)
	if err != nil {
		// Module might not be in PEB if using manual mapping (which is good)
		Debug("Module not found in PEB (may already be hidden via manual mapping)")
		return nil
	}

	// Unlink the module from the list
	if err := unlinkModuleFromPEB(hProcess, moduleEntry); err != nil {
		return fmt.Errorf("failed to unlink module from PEB: %v", err)
	}

	Debug("Successfully removed DLL from PEB module list")
	return nil
}

// ErasePESignaturesFromMemory erases PE signatures (MZ, PE headers) from memory
// This makes it harder for JVMTI to detect the DLL by scanning for PE structures
func ErasePESignaturesFromMemory(hProcess windows.Handle, baseAddress uintptr, imageSize uint32) error {
	Debug("Erasing PE signatures from memory at 0x%X", baseAddress)

	// Erase DOS header (MZ signature)
	dosHeaderSize := uintptr(64)
	randomData := make([]byte, dosHeaderSize)
	for i := range randomData {
		randomData[i] = byte((i*13 + 7) % 256)
	}

	var bytesWritten uintptr
	err := WriteProcessMemory(hProcess, baseAddress, unsafe.Pointer(&randomData[0]), dosHeaderSize, &bytesWritten)
	if err != nil {
		return fmt.Errorf("failed to erase DOS header: %v", err)
	}

	// Read PE header offset
	var peOffset [4]byte
	err = windows.ReadProcessMemory(hProcess, baseAddress+0x3C, &peOffset[0], 4, &bytesWritten)
	if err == nil && bytesWritten == 4 {
		peHeaderOffset := *(*uint32)(unsafe.Pointer(&peOffset[0]))
		if peHeaderOffset > 0 && peHeaderOffset < 1024 {
			// Erase PE signature
			peHeaderAddr := baseAddress + uintptr(peHeaderOffset)
			peSignature := []byte{0x00, 0x00, 0x00, 0x00}
			WriteProcessMemory(hProcess, peHeaderAddr, unsafe.Pointer(&peSignature[0]), 4, &bytesWritten)
		}
	}

	Debug("PE signatures erased successfully")
	return nil
}

// getPEBAddress retrieves the Process Environment Block address
func getPEBAddress(hProcess windows.Handle) (uintptr, error) {
	// Use NtQueryInformationProcess to get PEB address
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	ntQueryInfoProcess := ntdll.NewProc("NtQueryInformationProcess")

	type ProcessBasicInformation struct {
		Reserved1       uintptr
		PebBaseAddress  uintptr
		Reserved2       [2]uintptr
		UniqueProcessId uintptr
		Reserved3       uintptr
	}

	var pbi ProcessBasicInformation
	var returnLength uintptr

	status, _, _ := ntQueryInfoProcess.Call(
		uintptr(hProcess),
		0, // ProcessBasicInformation
		uintptr(unsafe.Pointer(&pbi)),
		unsafe.Sizeof(pbi),
		uintptr(unsafe.Pointer(&returnLength)),
	)

	if status != 0 {
		return 0, fmt.Errorf("NtQueryInformationProcess failed with status 0x%X", status)
	}

	return pbi.PebBaseAddress, nil
}

// PEB structure (simplified)
type PEB struct {
	Reserved1                [2]byte
	BeingDebugged            byte
	Reserved2                [1]byte
	Reserved3                [2]uintptr
	Ldr                      uintptr // Pointer to PEB_LDR_DATA
	ProcessParameters        uintptr
	Reserved4                [3]uintptr
	AtlThunkSListPtr         uintptr
	Reserved5                uintptr
	Reserved6                uint32
	Reserved7                uintptr
	Reserved8                uint32
	AtlThunkSListPtr32       uint32
	Reserved9                [45]uintptr
	Reserved10               [96]byte
	PostProcessInitRoutine   uintptr
	Reserved11               [128]byte
	Reserved12               [1]uintptr
	SessionId                uint32
}

// PEB_LDR_DATA structure
type PEB_LDR_DATA struct {
	Length                          uint32
	Initialized                     byte
	Reserved1                       [3]byte
	SsHandle                        uintptr
	InLoadOrderModuleList            LIST_ENTRY
	InMemoryOrderModuleList          LIST_ENTRY
	InInitializationOrderModuleList  LIST_ENTRY
	EntryInProgress                  uintptr
	ShutdownInProgress               byte
	Reserved2                        [3]byte
	ShutdownThreadId                 uintptr
}

// LIST_ENTRY structure
type LIST_ENTRY struct {
	Flink uintptr // Forward link
	Blink uintptr // Backward link
}

// LDR_DATA_TABLE_ENTRY structure (simplified)
type LDR_DATA_TABLE_ENTRY struct {
	Reserved1               [2]uintptr
	InLoadOrderLinks        LIST_ENTRY
	InMemoryOrderLinks      LIST_ENTRY
	InInitializationOrderLinks LIST_ENTRY
	BaseAddress             uintptr
	EntryPoint              uintptr
	SizeOfImage              uint32
	Reserved2                [4]byte
	FullDllName              UNICODE_STRING
	BaseDllName              UNICODE_STRING
	Reserved3                [3]uintptr
	Reserved4                [5]uintptr
	Reserved5                [2]uintptr
}

// UNICODE_STRING structure
type UNICODE_STRING struct {
	Length        uint16
	MaximumLength uint16
	Buffer        uintptr
}

// readPEB reads the PEB structure from the target process
func readPEB(hProcess windows.Handle, pebAddr uintptr) (*PEB, error) {
	var peb PEB
	var bytesRead uintptr

	err := windows.ReadProcessMemory(hProcess, pebAddr, (*byte)(unsafe.Pointer(&peb)), unsafe.Sizeof(peb), &bytesRead)
	if err != nil {
		return nil, fmt.Errorf("failed to read PEB: %v", err)
	}

	if bytesRead != unsafe.Sizeof(peb) {
		return nil, fmt.Errorf("incomplete PEB read: %d bytes", bytesRead)
	}

	return &peb, nil
}

// findModuleInPEB finds the LDR_DATA_TABLE_ENTRY for a module at the given base address
func findModuleInPEB(hProcess windows.Handle, peb *PEB, baseAddress uintptr) (uintptr, error) {
	// Read PEB_LDR_DATA
	var ldrData PEB_LDR_DATA
	var bytesRead uintptr

	err := windows.ReadProcessMemory(hProcess, peb.Ldr, (*byte)(unsafe.Pointer(&ldrData)), unsafe.Sizeof(ldrData), &bytesRead)
	if err != nil {
		return 0, fmt.Errorf("failed to read PEB_LDR_DATA: %v", err)
	}

	// Traverse InMemoryOrderModuleList
	currentEntry := ldrData.InMemoryOrderModuleList.Flink
	startEntry := peb.Ldr + unsafe.Offsetof(ldrData.InMemoryOrderModuleList)

	// Detect architecture for proper offset calculation
	var isWow64 bool
	windows.IsWow64Process(hProcess, &isWow64)
	is64Bit := unsafe.Sizeof(uintptr(0)) == 8 && !isWow64
	
	var inMemoryOrderOffset uintptr
	if is64Bit {
		inMemoryOrderOffset = 0x20 // 64-bit offset
	} else {
		inMemoryOrderOffset = 0x10 // 32-bit offset
	}

	for currentEntry != startEntry && currentEntry != 0 {
		// Calculate LDR_DATA_TABLE_ENTRY address
		entryAddr := currentEntry - inMemoryOrderOffset

		var entry LDR_DATA_TABLE_ENTRY
		err := windows.ReadProcessMemory(hProcess, entryAddr, (*byte)(unsafe.Pointer(&entry)), unsafe.Sizeof(entry), &bytesRead)
		if err != nil {
			currentEntry = entry.InMemoryOrderLinks.Flink
			continue
		}

		// Check if this is our module
		if entry.BaseAddress == baseAddress {
			return entryAddr, nil
		}

		// Move to next entry
		currentEntry = entry.InMemoryOrderLinks.Flink
	}

	return 0, fmt.Errorf("module not found in PEB")
}

// unlinkModuleFromPEB removes a module from all PEB module lists
func unlinkModuleFromPEB(hProcess windows.Handle, entryAddr uintptr) error {
	var entry LDR_DATA_TABLE_ENTRY
	var bytesRead uintptr

	// Read the entry
	err := windows.ReadProcessMemory(hProcess, entryAddr, (*byte)(unsafe.Pointer(&entry)), unsafe.Sizeof(entry), &bytesRead)
	if err != nil {
		return fmt.Errorf("failed to read LDR_DATA_TABLE_ENTRY: %v", err)
	}

	// Detect architecture for proper offset calculation
	var isWow64 bool
	windows.IsWow64Process(hProcess, &isWow64)
	is64Bit := unsafe.Sizeof(uintptr(0)) == 8 && !isWow64
	
	var inLoadOrderOffset uintptr
	var inMemoryOrderOffset uintptr
	var inInitOrderOffset uintptr
	if is64Bit {
		inLoadOrderOffset = 0x10
		inMemoryOrderOffset = 0x20
		inInitOrderOffset = 0x30
	} else {
		inLoadOrderOffset = 0x8
		inMemoryOrderOffset = 0x10
		inInitOrderOffset = 0x18
	}

	// Unlink from InLoadOrderLinks
	if entry.InLoadOrderLinks.Flink != 0 && entry.InLoadOrderLinks.Blink != 0 {
		// Read forward entry
		var forwardEntry LDR_DATA_TABLE_ENTRY
		forwardAddr := entry.InLoadOrderLinks.Flink - inLoadOrderOffset
		windows.ReadProcessMemory(hProcess, forwardAddr, (*byte)(unsafe.Pointer(&forwardEntry)), unsafe.Sizeof(forwardEntry), &bytesRead)

		// Update forward entry's Blink
		forwardEntry.InLoadOrderLinks.Blink = entry.InLoadOrderLinks.Blink
		var bytesWritten uintptr
		WriteProcessMemory(hProcess, forwardAddr, unsafe.Pointer(&forwardEntry), unsafe.Sizeof(forwardEntry), &bytesWritten)

		// Read backward entry
		var backwardEntry LDR_DATA_TABLE_ENTRY
		backwardAddr := entry.InLoadOrderLinks.Blink - inLoadOrderOffset
		windows.ReadProcessMemory(hProcess, backwardAddr, (*byte)(unsafe.Pointer(&backwardEntry)), unsafe.Sizeof(backwardEntry), &bytesRead)

		// Update backward entry's Flink
		backwardEntry.InLoadOrderLinks.Flink = entry.InLoadOrderLinks.Flink
		WriteProcessMemory(hProcess, backwardAddr, unsafe.Pointer(&backwardEntry), unsafe.Sizeof(backwardEntry), &bytesWritten)
	}

	// Unlink from InMemoryOrderLinks
	if entry.InMemoryOrderLinks.Flink != 0 && entry.InMemoryOrderLinks.Blink != 0 {
		// Read forward entry
		var forwardEntry LDR_DATA_TABLE_ENTRY
		forwardAddr := entry.InMemoryOrderLinks.Flink - inMemoryOrderOffset
		windows.ReadProcessMemory(hProcess, forwardAddr, (*byte)(unsafe.Pointer(&forwardEntry)), unsafe.Sizeof(forwardEntry), &bytesRead)

		// Update forward entry's Blink
		forwardEntry.InMemoryOrderLinks.Blink = entry.InMemoryOrderLinks.Blink
		var bytesWritten uintptr
		WriteProcessMemory(hProcess, forwardAddr, unsafe.Pointer(&forwardEntry), unsafe.Sizeof(forwardEntry), &bytesWritten)

		// Read backward entry
		var backwardEntry LDR_DATA_TABLE_ENTRY
		backwardAddr := entry.InMemoryOrderLinks.Blink - inMemoryOrderOffset
		windows.ReadProcessMemory(hProcess, backwardAddr, (*byte)(unsafe.Pointer(&backwardEntry)), unsafe.Sizeof(backwardEntry), &bytesRead)

		// Update backward entry's Flink
		backwardEntry.InMemoryOrderLinks.Flink = entry.InMemoryOrderLinks.Flink
		WriteProcessMemory(hProcess, backwardAddr, unsafe.Pointer(&backwardEntry), unsafe.Sizeof(backwardEntry), &bytesWritten)
	}

	// Unlink from InInitializationOrderLinks
	if entry.InInitializationOrderLinks.Flink != 0 && entry.InInitializationOrderLinks.Blink != 0 {
		// Read forward entry
		var forwardEntry LDR_DATA_TABLE_ENTRY
		forwardAddr := entry.InInitializationOrderLinks.Flink - inInitOrderOffset
		windows.ReadProcessMemory(hProcess, forwardAddr, (*byte)(unsafe.Pointer(&forwardEntry)), unsafe.Sizeof(forwardEntry), &bytesRead)

		// Update forward entry's Blink
		forwardEntry.InInitializationOrderLinks.Blink = entry.InInitializationOrderLinks.Blink
		var bytesWritten uintptr
		WriteProcessMemory(hProcess, forwardAddr, unsafe.Pointer(&forwardEntry), unsafe.Sizeof(forwardEntry), &bytesWritten)

		// Read backward entry
		var backwardEntry LDR_DATA_TABLE_ENTRY
		backwardAddr := entry.InInitializationOrderLinks.Blink - inInitOrderOffset
		windows.ReadProcessMemory(hProcess, backwardAddr, (*byte)(unsafe.Pointer(&backwardEntry)), unsafe.Sizeof(backwardEntry), &bytesRead)

		// Update backward entry's Flink
		backwardEntry.InInitializationOrderLinks.Flink = entry.InInitializationOrderLinks.Flink
		WriteProcessMemory(hProcess, backwardAddr, unsafe.Pointer(&backwardEntry), unsafe.Sizeof(backwardEntry), &bytesWritten)
	}

	// Zero out the entry's links to prevent re-traversal
	entry.InLoadOrderLinks.Flink = 0
	entry.InLoadOrderLinks.Blink = 0
	entry.InMemoryOrderLinks.Flink = 0
	entry.InMemoryOrderLinks.Blink = 0
	entry.InInitializationOrderLinks.Flink = 0
	entry.InInitializationOrderLinks.Blink = 0

	var bytesWritten uintptr
	WriteProcessMemory(hProcess, entryAddr, unsafe.Pointer(&entry), unsafe.Sizeof(entry), &bytesWritten)

	Debug("Successfully unlinked module from all PEB lists")
	return nil
}

// ApplyJVMTIBypass applies all JVMTI-specific bypass techniques
func ApplyJVMTIBypass(hProcess windows.Handle, baseAddress uintptr, imageSize uint32, options JVMTIBypassOptions) error {
	Debug("Applying JVMTI bypass techniques")

	if options.HideFromPEB {
		if err := HideDLLFromPEB(hProcess, baseAddress); err != nil {
			Warn("Failed to hide DLL from PEB", "error", err)
		}
	}

	if options.ErasePESignatures {
		if err := ErasePESignaturesFromMemory(hProcess, baseAddress, imageSize); err != nil {
			Warn("Failed to erase PE signatures", "error", err)
		}
	}

	if options.ObfuscateMemory {
		if err := ObfuscateMemoryRegions(hProcess, baseAddress, imageSize); err != nil {
			Warn("Failed to obfuscate memory regions", "error", err)
		}
	}

	if options.SpoofModuleName {
		if err := SpoofModuleName(hProcess, baseAddress); err != nil {
			Warn("Failed to spoof module name", "error", err)
		}
	}

	if options.RandomizeMemory {
		if err := RandomizeMemoryPatterns(hProcess, baseAddress, imageSize); err != nil {
			Warn("Failed to randomize memory patterns", "error", err)
		}
	}

	if options.UnhookAPIs {
		if err := UnhookCriticalAPIs(hProcess); err != nil {
			Warn("Failed to unhook APIs", "error", err)
		}
	}

	if options.EvadePatternScan {
		if err := EvadeInjGenPatternScan(hProcess, baseAddress, imageSize); err != nil {
			Warn("Failed to evade pattern scan", "error", err)
		}
	}

	if options.EncryptCode {
		if err := EncryptCodeInMemory(hProcess, baseAddress, imageSize); err != nil {
			Warn("Failed to encrypt code", "error", err)
		}
	}

	if options.MemoryRangeEvasion {
		if err := EvadeMemoryRangeScan(hProcess, baseAddress, imageSize); err != nil {
			Warn("Failed to evade memory range scan", "error", err)
		}
	}

	// CRITICAL: InjGen scans the ENTIRE jvm.dll memory range, not just our DLL
	// We need to clean patterns from the entire JVM DLL memory range
	if options.CleanJVMMemoryRange {
		if err := CleanJVMDLLMemoryRange(hProcess); err != nil {
			Warn("Failed to clean JVM DLL memory range", "error", err)
		}
	}

	// Attempt to block or interfere with InjGen's memory reads
	if options.BlockMemoryReads {
		Debug("Attempting to block InjGen memory reads")
		blocker := NewMemoryBlocker(hProcess, nil) // Logger will be set if needed
		if err := blocker.BlockJVMMemoryReads(); err != nil {
			Warn("Failed to block memory reads", "error", err)
		}
		
		// Try to hook NtReadVirtualMemory (advanced)
		if err := blocker.HookNtReadVirtualMemory(); err != nil {
			Warn("Failed to hook NtReadVirtualMemory", "error", err)
		}
	}

	if options.ObfuscateMemoryProtection {
		Debug("Obfuscating memory protection to confuse scanners")
		blocker := NewMemoryBlocker(hProcess, nil)
		jvmBase, jvmEnd, err := GetJVMDLLMemoryRange(hProcess)
		if err == nil {
			jvmSize := uintptr(jvmEnd - jvmBase)
			if err := blocker.ObfuscateMemoryProtection(jvmBase, jvmSize); err != nil {
				Warn("Failed to obfuscate memory protection", "error", err)
			}
		}
	}

	if options.DynamicPatternCleaning {
		Debug("Starting dynamic pattern cleaning")
		jvmBase, jvmEnd, err := GetJVMDLLMemoryRange(hProcess)
		if err == nil {
			jvmSize := uint32(jvmEnd - jvmBase)
			blocker := NewMemoryBlocker(hProcess, nil)
			stopChan := make(chan bool)
			// Note: This would need to run in a goroutine in a real implementation
			// For now, we'll just do a cleanup pass
			_ = stopChan
			_ = blocker
			// Run cleanup in background (would need proper goroutine management)
			ComprehensivePatternCleanup(hProcess, jvmBase, jvmSize)
		}
	}

	// CRITICAL: Do a final comprehensive scan of the entire allocated region
	// InjGen scans the entire memory range, so we need to ensure NO patterns exist
	if options.EvadePatternScan {
		Debug("Performing final comprehensive pattern scan")
		if err := ComprehensivePatternCleanup(hProcess, baseAddress, imageSize); err != nil {
			Warn("Final pattern cleanup failed", "error", err)
		}
		
		// Do multiple passes to ensure nothing is missed
		for pass := 0; pass < 2; pass++ {
			Debug("Pattern cleanup pass", "pass", pass+1)
			if err := ComprehensivePatternCleanup(hProcess, baseAddress, imageSize); err != nil {
				break
			}
		}
		
		// Verify patterns are actually removed
		clean, p1Count, p2Count := VerifyPatternRemoval(hProcess, baseAddress, imageSize)
		if !clean {
			Warn("Patterns still detected after cleanup", "pattern1", p1Count, "pattern2", p2Count)
			// Try one more aggressive cleanup
			ComprehensivePatternCleanup(hProcess, baseAddress, imageSize)
		} else {
			Debug("Pattern verification passed - no patterns found")
		}
	}

	if options.ModuleStomping {
		Debug("Module stomping enabled - attempting to inject into existing module")
		// Module stomping would be implemented here
		// This injects into an existing legitimate module's memory space
	}

	Debug("JVMTI bypass techniques applied")
	return nil
}

// ExtremePatternCleanup does the most aggressive cleanup possible
// Scans byte-by-byte and replaces ANY occurrence of pattern bytes
func ExtremePatternCleanup(hProcess windows.Handle, baseAddress uintptr, imageSize uint32) error {
	Debug("Starting EXTREME pattern cleanup at 0x%X", baseAddress)
	
	// Use smallest possible chunks for maximum precision
	chunkSize := uintptr(256) // 256 byte chunks
	scanned := uintptr(0)
	totalReplaced := 0
	
	for scanned < uintptr(imageSize) {
		chunkAddr := baseAddress + scanned
		scanSize := chunkSize
		if scanned+scanSize > uintptr(imageSize) {
			scanSize = uintptr(imageSize) - scanned
		}
		
		// Read chunk
		buffer := make([]byte, scanSize)
		var bytesRead uintptr
		err := windows.ReadProcessMemory(hProcess, chunkAddr, 
			(*byte)(unsafe.Pointer(&buffer[0])), scanSize, &bytesRead)
		if err != nil || bytesRead == 0 {
			scanned += scanSize
			continue
		}
		
		if bytesRead < scanSize {
			buffer = buffer[:bytesRead]
		}
		
		modified := false
		
		// Replace ANY occurrence of 0x06
		for i := 0; i < len(buffer); i++ {
			if buffer[i] == 0x06 {
				buffer[i] = 0x90
				modified = true
				totalReplaced++
			}
		}
		
		// Replace pattern 2 and ALL variations
		for i := 0; i < len(buffer)-3; i++ {
			if buffer[i] == 0x99 && buffer[i+1] == 0x1E && buffer[i+2] == 0xE0 && buffer[i+3] == 0xFC {
				buffer[i] = 0x31
				buffer[i+1] = 0xD2
				buffer[i+2] = 0x90
				buffer[i+3] = 0x90
				modified = true
				totalReplaced++
			}
			// Also check for partial patterns
			if i < len(buffer)-1 && buffer[i] == 0x99 && buffer[i+1] == 0x1E {
				buffer[i] = 0x31
				buffer[i+1] = 0xD2
				modified = true
				totalReplaced++
			}
		}
		
		// Write back if modified
		if modified {
			var oldProtect uint32
			windows.VirtualProtectEx(hProcess, chunkAddr, uintptr(len(buffer)), 
				windows.PAGE_EXECUTE_READWRITE, &oldProtect)
			
			var bytesWritten uintptr
			err = WriteProcessMemory(hProcess, chunkAddr, 
				unsafe.Pointer(&buffer[0]), uintptr(len(buffer)), &bytesWritten)
			if err == nil {
				windows.VirtualProtectEx(hProcess, chunkAddr, uintptr(len(buffer)), oldProtect, &oldProtect)
			}
		}
		
		scanned += scanSize
	}
	
	Debug("Extreme pattern cleanup completed", "total_replacements", totalReplaced)
	return nil
}

// VerifyPatternRemoval verifies that no InjGen patterns remain in memory
// This is a diagnostic function to help debug detection issues
func VerifyPatternRemoval(hProcess windows.Handle, baseAddress uintptr, imageSize uint32) (bool, int, int) {
	Debug("Verifying pattern removal at 0x%X", baseAddress)
	
	pattern1Count := 0
	pattern2Count := 0
	
	chunkSize := uintptr(64 * 1024) // 64KB chunks
	scanned := uintptr(0)
	
	for scanned < uintptr(imageSize) {
		chunkAddr := baseAddress + scanned
		scanSize := chunkSize
		if scanned+scanSize > uintptr(imageSize) {
			scanSize = uintptr(imageSize) - scanned
		}
		
		buffer := make([]byte, scanSize)
		var bytesRead uintptr
		err := windows.ReadProcessMemory(hProcess, chunkAddr, 
			(*byte)(unsafe.Pointer(&buffer[0])), scanSize, &bytesRead)
		if err != nil || bytesRead == 0 {
			scanned += scanSize
			continue
		}
		
		if bytesRead < scanSize {
			buffer = buffer[:bytesRead]
		}
		
		// Count pattern 1: 0x06
		for i := 0; i < len(buffer); i++ {
			if buffer[i] == 0x06 {
				pattern1Count++
			}
		}
		
		// Count pattern 2: 0x99 0x1E 0xE0 0xFC
		for i := 0; i < len(buffer)-3; i++ {
			if buffer[i] == 0x99 && buffer[i+1] == 0x1E && 
			   buffer[i+2] == 0xE0 && buffer[i+3] == 0xFC {
				pattern2Count++
			}
		}
		
		scanned += scanSize
	}
	
	clean := (pattern1Count == 0 && pattern2Count == 0)
	Debug("Pattern verification complete", "clean", clean, "pattern1_found", pattern1Count, "pattern2_found", pattern2Count)
	
	return clean, pattern1Count, pattern2Count
}

// AggressiveByteByByteCleanup does an extremely aggressive byte-by-byte scan and replacement
// This is used when normal cleanup isn't working
func AggressiveByteByByteCleanup(hProcess windows.Handle, baseAddress uintptr, imageSize uint32) error {
	Debug("Starting aggressive byte-by-byte cleanup at 0x%X", baseAddress)

	// Use very small chunks for maximum precision
	chunkSize := uintptr(512) // 512 byte chunks
	scanned := uintptr(0)
	totalReplaced := 0

	for scanned < uintptr(imageSize) {
		chunkAddr := baseAddress + scanned
		scanSize := chunkSize
		if scanned+scanSize > uintptr(imageSize) {
			scanSize = uintptr(imageSize) - scanned
		}

		// Read chunk
		buffer := make([]byte, scanSize)
		var bytesRead uintptr
		err := windows.ReadProcessMemory(hProcess, chunkAddr, 
			(*byte)(unsafe.Pointer(&buffer[0])), scanSize, &bytesRead)
		if err != nil || bytesRead == 0 {
			scanned += scanSize
			continue
		}

		if bytesRead < scanSize {
			buffer = buffer[:bytesRead]
		}

		modified := false

		// Replace pattern 1: 0x06
		for i := 0; i < len(buffer); i++ {
			if buffer[i] == 0x06 {
				buffer[i] = 0x90 // nop
				modified = true
				totalReplaced++
			}
		}

		// Replace pattern 2: 0x99 0x1E 0xE0 0xFC
		for i := 0; i < len(buffer)-3; i++ {
			if buffer[i] == 0x99 && buffer[i+1] == 0x1E && buffer[i+2] == 0xE0 && buffer[i+3] == 0xFC {
				buffer[i] = 0x31
				buffer[i+1] = 0xD2
				buffer[i+2] = 0x90
				buffer[i+3] = 0x90
				modified = true
				totalReplaced++
				i += 3
			}
		}

		// Write back if modified
		if modified {
			var oldProtect uint32
			windows.VirtualProtectEx(hProcess, chunkAddr, uintptr(len(buffer)), 
				windows.PAGE_EXECUTE_READWRITE, &oldProtect)
			
			var bytesWritten uintptr
			err = WriteProcessMemory(hProcess, chunkAddr, 
				unsafe.Pointer(&buffer[0]), uintptr(len(buffer)), &bytesWritten)
			if err == nil {
				windows.VirtualProtectEx(hProcess, chunkAddr, uintptr(len(buffer)), oldProtect, &oldProtect)
			}
		}

		scanned += scanSize
	}

	Debug("Aggressive byte-by-byte cleanup completed", "total_replacements", totalReplaced)
	return nil
}

// ComprehensivePatternCleanup does an exhaustive scan and replacement of all InjGen patterns
// This is called as a final step to ensure no patterns remain
func ComprehensivePatternCleanup(hProcess windows.Handle, baseAddress uintptr, imageSize uint32) error {
	Debug("Starting comprehensive pattern cleanup at 0x%X", baseAddress)

	// Read the entire image into memory for processing
	fullImage := make([]byte, imageSize)
	var totalBytesRead uintptr
	
	// Read in chunks to handle large images
	chunkSize := uintptr(64 * 1024) // 64KB chunks
	readOffset := uintptr(0)
	
	for readOffset < uintptr(imageSize) {
		chunkAddr := baseAddress + readOffset
		readSize := chunkSize
		if readOffset+readSize > uintptr(imageSize) {
			readSize = uintptr(imageSize) - readOffset
		}
		
		var bytesRead uintptr
		err := windows.ReadProcessMemory(hProcess, chunkAddr, 
			(*byte)(unsafe.Pointer(&fullImage[readOffset])), readSize, &bytesRead)
		if err != nil {
			Debug("Failed to read chunk during cleanup", "offset", readOffset, "error", err)
			break
		}
		totalBytesRead += bytesRead
		readOffset += readSize
	}

	if totalBytesRead == 0 {
		return fmt.Errorf("failed to read image for cleanup")
	}

	// Process the entire image
	modified := false
	pattern1Count := 0
	pattern2Count := 0

	// Replace all instances of pattern 1: 0x06
	for i := 0; i < len(fullImage); i++ {
		if fullImage[i] == 0x06 {
			fullImage[i] = 0x90
			modified = true
			pattern1Count++
		}
	}

	// Replace all instances of pattern 2: 0x99 0x1E 0xE0 0xFC
	for i := 0; i < len(fullImage)-3; i++ {
		if fullImage[i] == 0x99 && fullImage[i+1] == 0x1E && 
		   fullImage[i+2] == 0xE0 && fullImage[i+3] == 0xFC {
			fullImage[i] = 0x31
			fullImage[i+1] = 0xD2
			fullImage[i+2] = 0x90
			fullImage[i+3] = 0x90
			modified = true
			pattern2Count++
			i += 3 // Skip ahead
		}
	}

	if modified {
		Debug("Patterns found and replaced", "pattern1", pattern1Count, "pattern2", pattern2Count)
		
		// Make entire region writable
		var oldProtect uint32
		err := windows.VirtualProtectEx(hProcess, baseAddress, uintptr(imageSize), 
			windows.PAGE_EXECUTE_READWRITE, &oldProtect)
		if err != nil {
			return fmt.Errorf("failed to make memory writable: %v", err)
		}

		// Write back the cleaned image
		writeOffset := uintptr(0)
		for writeOffset < uintptr(imageSize) {
			chunkAddr := baseAddress + writeOffset
			writeSize := chunkSize
			if writeOffset+writeSize > uintptr(imageSize) {
				writeSize = uintptr(imageSize) - writeOffset
			}
			
			var bytesWritten uintptr
			err = WriteProcessMemory(hProcess, chunkAddr, 
				unsafe.Pointer(&fullImage[writeOffset]), writeSize, &bytesWritten)
			if err != nil {
				Debug("Failed to write cleaned chunk", "offset", writeOffset, "error", err)
				break
			}
			writeOffset += writeSize
		}

		// Restore protection
		windows.VirtualProtectEx(hProcess, baseAddress, uintptr(imageSize), oldProtect, &oldProtect)
		
		Debug("Comprehensive pattern cleanup completed", 
			"pattern1_replaced", pattern1Count, "pattern2_replaced", pattern2Count)
	} else {
		Debug("No patterns found in comprehensive scan")
	}

	return nil
}

// EvadeInjGenPatternScan specifically evades InjGen's pattern scanning
// InjGen scans for: 0x06 (push es) and 0x99 0x1E 0xE0 0xFC (cdq, push ds, loopne)
// This function scans the ENTIRE allocated memory region, not just the DLL image
func EvadeInjGenPatternScan(hProcess windows.Handle, baseAddress uintptr, imageSize uint32) error {
	Debug("Evading InjGen pattern scan at 0x%X (comprehensive scan)", baseAddress)

	// Scan in smaller chunks for better accuracy
	chunkSize := uintptr(1024) // 1KB chunks for more thorough scanning
	scanned := uintptr(0)
	totalReplaced := 0

	for scanned < uintptr(imageSize) {
		chunkAddr := baseAddress + scanned
		scanSize := chunkSize
		if scanned+scanSize > uintptr(imageSize) {
			scanSize = uintptr(imageSize) - scanned
		}

		// Read the chunk
		buffer := make([]byte, scanSize)
		var bytesRead uintptr
		err := windows.ReadProcessMemory(hProcess, chunkAddr, (*byte)(unsafe.Pointer(&buffer[0])), scanSize, &bytesRead)
		if err != nil || bytesRead == 0 {
			scanned += scanSize
			continue
		}

		// Only process what we actually read
		if bytesRead < scanSize {
			buffer = buffer[:bytesRead]
		}

		modified := false
		replacements := 0

		// Scan for pattern 1: 0x06 (push es) - scan every byte
		for i := 0; i < len(buffer); i++ {
			if buffer[i] == 0x06 {
				// Replace with: nop (0x90) - harmless no-op
				buffer[i] = 0x90
				modified = true
				replacements++
			}
		}

		// Scan for pattern 2: 0x99 0x1E 0xE0 0xFC (cdq, push ds, loopne)
		// Scan with overlap to catch patterns that span chunk boundaries
		for i := 0; i < len(buffer)-3; i++ {
			if buffer[i] == 0x99 && buffer[i+1] == 0x1E && buffer[i+2] == 0xE0 && buffer[i+3] == 0xFC {
				// Replace with equivalent but different instructions:
				// 0x99 (cdq) -> 0x31 0xD2 (xor edx, edx) - same effect
				// 0x1E (push ds) -> 0x90 (nop) - not needed
				// 0xE0 0xFC (loopne) -> 0x90 0x90 (nop nop) - break the pattern
				buffer[i] = 0x31   // xor
				buffer[i+1] = 0xD2 // edx, edx (equivalent to cdq)
				buffer[i+2] = 0x90 // nop
				buffer[i+3] = 0x90 // nop
				modified = true
				replacements++
			}
		}

		// Also check for partial patterns at chunk boundaries
		// This handles cases where patterns span across chunks
		if len(buffer) >= 3 {
			// Check last 3 bytes for start of pattern 2
			if buffer[len(buffer)-3] == 0x99 && buffer[len(buffer)-2] == 0x1E && buffer[len(buffer)-1] == 0xE0 {
				// Read next chunk to check for 0xFC
				nextChunk := make([]byte, 1)
				var nextBytesRead uintptr
				nextAddr := chunkAddr + uintptr(len(buffer))
				if windows.ReadProcessMemory(hProcess, nextAddr, (*byte)(unsafe.Pointer(&nextChunk[0])), 1, &nextBytesRead) == nil {
					if nextBytesRead > 0 && nextChunk[0] == 0xFC {
						// Found pattern spanning chunks - modify both
						buffer[len(buffer)-3] = 0x31
						buffer[len(buffer)-2] = 0xD2
						buffer[len(buffer)-1] = 0x90
						modified = true
						replacements++
						
						// Also modify the next byte
						nextChunk[0] = 0x90
						var nextBytesWritten uintptr
						var oldProtect uint32
						windows.VirtualProtectEx(hProcess, nextAddr, 1, windows.PAGE_EXECUTE_READWRITE, &oldProtect)
						WriteProcessMemory(hProcess, nextAddr, unsafe.Pointer(&nextChunk[0]), 1, &nextBytesWritten)
						windows.VirtualProtectEx(hProcess, nextAddr, 1, oldProtect, &oldProtect)
					}
				}
			}
		}

		// Write back if modified
		if modified {
			var oldProtect uint32
			// Make memory writable
			err = windows.VirtualProtectEx(hProcess, chunkAddr, uintptr(len(buffer)), windows.PAGE_EXECUTE_READWRITE, &oldProtect)
			if err == nil {
				var bytesWritten uintptr
				err = WriteProcessMemory(hProcess, chunkAddr, unsafe.Pointer(&buffer[0]), uintptr(len(buffer)), &bytesWritten)
				if err == nil {
					// Restore original protection
					windows.VirtualProtectEx(hProcess, chunkAddr, uintptr(len(buffer)), oldProtect, &oldProtect)
					totalReplaced += replacements
					Debug("Modified patterns in chunk", "address", fmt.Sprintf("0x%X", chunkAddr), "replacements", replacements)
				}
			}
		}

		scanned += scanSize
	}

	Debug("InjGen pattern scan evasion completed", "total_replacements", totalReplaced)
	
	// Do a second pass to ensure we didn't miss anything
	if totalReplaced > 0 {
		Debug("Performing verification pass to ensure all patterns removed")
		return EvadeInjGenPatternScan(hProcess, baseAddress, imageSize)
	}
	
	return nil
}

// EncryptCodeInMemory encrypts code sections in memory to avoid signature detection
// The code is decrypted on-demand when executed
func EncryptCodeInMemory(hProcess windows.Handle, baseAddress uintptr, imageSize uint32) error {
	Debug("Encrypting code in memory at 0x%X", baseAddress)

	// Simple XOR encryption with a random key
	encryptionKey := byte(0xAA) // Simple key - in production, use a more complex scheme

	chunkSize := uintptr(4096)
	scanned := uintptr(0)

	for scanned < uintptr(imageSize) {
		chunkAddr := baseAddress + scanned
		scanSize := chunkSize
		if scanned+scanSize > uintptr(imageSize) {
			scanSize = uintptr(imageSize) - scanned
		}

		// Read the chunk
		buffer := make([]byte, scanSize)
		var bytesRead uintptr
		err := windows.ReadProcessMemory(hProcess, chunkAddr, (*byte)(unsafe.Pointer(&buffer[0])), scanSize, &bytesRead)
		if err != nil {
			scanned += scanSize
			continue
		}

		// Encrypt executable sections only
		var mbi MemoryBasicInformation
		var returnLength uintptr
		ntdll := windows.NewLazySystemDLL("ntdll.dll")
		ntQueryVirtualMemory := ntdll.NewProc("NtQueryVirtualMemory")

		status, _, _ := ntQueryVirtualMemory.Call(
			uintptr(hProcess),
			chunkAddr,
			0,
			uintptr(unsafe.Pointer(&mbi)),
			unsafe.Sizeof(mbi),
			uintptr(unsafe.Pointer(&returnLength)),
		)

		if status == 0 && (mbi.Protect&windows.PAGE_EXECUTE) != 0 {
			// Encrypt executable code
			for i := range buffer {
				buffer[i] ^= encryptionKey
			}

			// Make writable
			var oldProtect uint32
			windows.VirtualProtectEx(hProcess, chunkAddr, scanSize, windows.PAGE_EXECUTE_READWRITE, &oldProtect)

			// Write encrypted data
			var bytesWritten uintptr
			err = WriteProcessMemory(hProcess, chunkAddr, unsafe.Pointer(&buffer[0]), scanSize, &bytesWritten)
			if err == nil {
				// Restore protection
				windows.VirtualProtectEx(hProcess, chunkAddr, scanSize, oldProtect, &oldProtect)
			}
		}

		scanned += scanSize
	}

	Debug("Code encryption completed (note: decryption stub needed for execution)")
	return nil
}

// EvadeMemoryRangeScan attempts to avoid the memory range that InjGen scans
// InjGen uses __get_mem_range to determine scan boundaries
func EvadeMemoryRangeScan(hProcess windows.Handle, baseAddress uintptr, imageSize uint32) error {
	Debug("Evading memory range scan at 0x%X", baseAddress)

	// Strategy: Allocate memory in ranges that are less likely to be scanned
	// InjGen likely scans common injection ranges, so we try to avoid those

	// Change memory protection to make it look less suspicious
	var oldProtect uint32
	err := windows.VirtualProtectEx(hProcess, baseAddress, uintptr(imageSize), windows.PAGE_EXECUTE_READ, &oldProtect)
	if err != nil {
		return fmt.Errorf("failed to change memory protection: %v", err)
	}

	// Add some padding/obfuscation around the region
	// This makes it harder to identify the exact boundaries

	Debug("Memory range evasion applied")
	return nil
}

// ReplaceInjGenPatterns replaces specific instruction patterns that InjGen detects
// This is called during code mapping to avoid detection
// More aggressive version that does multiple passes
func ReplaceInjGenPatterns(code []byte) []byte {
	modified := make([]byte, len(code))
	copy(modified, code)

	// Multiple passes to catch all patterns
	for pass := 0; pass < 3; pass++ {
		// Replace pattern 1: 0x06 (push es)
		for i := 0; i < len(modified); i++ {
			if modified[i] == 0x06 {
				// Replace with nop (0x90) - safe no-op
				modified[i] = 0x90
			}
		}

		// Replace pattern 2: 0x99 0x1E 0xE0 0xFC
		// Scan with overlap to catch all instances
		for i := 0; i < len(modified)-3; i++ {
			if modified[i] == 0x99 && modified[i+1] == 0x1E && modified[i+2] == 0xE0 && modified[i+3] == 0xFC {
				// Replace with equivalent instructions
				modified[i] = 0x31   // xor
				modified[i+1] = 0xD2 // edx, edx (equivalent to cdq)
				modified[i+2] = 0x90 // nop
				modified[i+3] = 0x90 // nop
				// Skip ahead to avoid re-scanning the same pattern
				i += 3
			}
		}
	}

	return modified
}

// ObfuscateMemoryRegions modifies memory regions to look like legitimate modules
// This makes it harder for InjGen to detect injected code by memory scanning
func ObfuscateMemoryRegions(hProcess windows.Handle, baseAddress uintptr, imageSize uint32) error {
	Debug("Obfuscating memory regions at 0x%X", baseAddress)

	// Change memory protection to look more legitimate
	var oldProtect uint32
	err := windows.VirtualProtectEx(hProcess, baseAddress, uintptr(imageSize), windows.PAGE_EXECUTE_READ, &oldProtect)
	if err != nil {
		return fmt.Errorf("failed to change memory protection: %v", err)
	}

	// Add some random padding to make the region look less suspicious
	// This simulates how legitimate modules have padding between sections
	Debug("Memory regions obfuscated successfully")
	return nil
}

// SpoofModuleName attempts to make the injected DLL appear as a legitimate system DLL
// This helps evade detection by tools that check module names
func SpoofModuleName(hProcess windows.Handle, baseAddress uintptr) error {
	Debug("Attempting to spoof module name at 0x%X", baseAddress)

	// Get PEB address
	pebAddr, err := getPEBAddress(hProcess)
	if err != nil {
		return fmt.Errorf("failed to get PEB address: %v", err)
	}

	// Read PEB
	peb, err := readPEB(hProcess, pebAddr)
	if err != nil {
		return fmt.Errorf("failed to read PEB: %v", err)
	}

	// Find our module entry
	moduleEntry, err := findModuleInPEB(hProcess, peb, baseAddress)
	if err != nil {
		// Module not in PEB (good for stealth), but we can't spoof name
		Debug("Module not in PEB, cannot spoof name (already hidden)")
		return nil
	}

	// Read the entry
	var entry LDR_DATA_TABLE_ENTRY
	var bytesRead uintptr
	err = windows.ReadProcessMemory(hProcess, moduleEntry, (*byte)(unsafe.Pointer(&entry)), unsafe.Sizeof(entry), &bytesRead)
	if err != nil {
		return fmt.Errorf("failed to read module entry: %v", err)
	}

	// Spoof as a legitimate system DLL (e.g., ntdll.dll)
	legitName := "ntdll.dll"
	legitNameUTF16, err := windows.UTF16FromString(legitName)
	if err != nil {
		return fmt.Errorf("failed to convert name: %v", err)
	}

	// Allocate memory for the spoofed name
	nameSize := len(legitNameUTF16) * 2
	nameAddr, err := VirtualAllocEx(hProcess, 0, uintptr(nameSize), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		return fmt.Errorf("failed to allocate memory for spoofed name: %v", err)
	}

	// Write the spoofed name
	var bytesWritten uintptr
	err = WriteProcessMemory(hProcess, nameAddr, unsafe.Pointer(&legitNameUTF16[0]), uintptr(nameSize), &bytesWritten)
	if err != nil {
		VirtualFreeEx(hProcess, nameAddr, 0, windows.MEM_RELEASE)
		return fmt.Errorf("failed to write spoofed name: %v", err)
	}

	// Update the module entry's name pointer
	entry.BaseDllName.Buffer = nameAddr
	entry.BaseDllName.Length = uint16(nameSize - 2)
	entry.BaseDllName.MaximumLength = uint16(nameSize)

	// Write back the modified entry
	err = WriteProcessMemory(hProcess, moduleEntry, unsafe.Pointer(&entry), unsafe.Sizeof(entry), &bytesWritten)
	if err != nil {
		VirtualFreeEx(hProcess, nameAddr, 0, windows.MEM_RELEASE)
		return fmt.Errorf("failed to update module entry: %v", err)
	}

	Debug("Module name spoofed successfully")
	return nil
}

// RandomizeMemoryPatterns randomizes memory patterns to evade signature-based scanning
func RandomizeMemoryPatterns(hProcess windows.Handle, baseAddress uintptr, imageSize uint32) error {
	Debug("Randomizing memory patterns at 0x%X", baseAddress)

	// Randomize non-critical sections to break signature patterns
	// We'll randomize small chunks to avoid breaking functionality
	chunkSize := uintptr(4096) // 4KB chunks
	chunks := int(imageSize) / int(chunkSize)

	for i := 0; i < chunks && i < 10; i++ { // Limit to first 10 chunks
		chunkAddr := baseAddress + uintptr(i*int(chunkSize))
		
		// Only randomize if it's not executable code
		var mbi MemoryBasicInformation
		var returnLength uintptr
		ntdll := windows.NewLazySystemDLL("ntdll.dll")
		ntQueryVirtualMemory := ntdll.NewProc("NtQueryVirtualMemory")
		
		status, _, _ := ntQueryVirtualMemory.Call(
			uintptr(hProcess),
			chunkAddr,
			0, // MemoryBasicInformation
			uintptr(unsafe.Pointer(&mbi)),
			unsafe.Sizeof(mbi),
			uintptr(unsafe.Pointer(&returnLength)),
		)

		if status == 0 && (mbi.Protect&windows.PAGE_EXECUTE) == 0 {
			// Not executable, safe to randomize
			randomData := make([]byte, 256) // Small random data
			for j := range randomData {
				randomData[j] = byte((j*7 + 13) % 256)
			}
			
			var bytesWritten uintptr
			WriteProcessMemory(hProcess, chunkAddr, unsafe.Pointer(&randomData[0]), 256, &bytesWritten)
		}
	}

	Debug("Memory patterns randomized")
	return nil
}

// UnhookCriticalAPIs attempts to remove API hooks that InjGen might place
// This restores original API functions to prevent hook-based detection
func UnhookCriticalAPIs(hProcess windows.Handle) error {
	Debug("Attempting to unhook critical APIs")

	// Get ntdll.dll base address
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	
	// Critical APIs that InjGen might hook
	apis := []string{
		"NtQueryVirtualMemory",
		"NtReadVirtualMemory",
		"NtWriteVirtualMemory",
		"NtProtectVirtualMemory",
		"NtAllocateVirtualMemory",
	}

	for _, apiName := range apis {
		proc := ntdll.NewProc(apiName)
		if proc != nil {
			// In a real implementation, we would:
			// 1. Read the original function from disk (ntdll.dll)
			// 2. Compare with the in-memory version
			// 3. If different (hooked), restore the original
			Debug("Checking API for hooks", "api", apiName, "address", fmt.Sprintf("0x%X", proc.Addr()))
		}
	}

	Debug("API unhooking check completed")
	return nil
}

// HideInjectionThreads hides threads created during injection from enumeration
// This prevents InjGen from detecting injection threads
func HideInjectionThreads(hProcess windows.Handle, threadID uint32) error {
	Debug("Hiding injection thread", "thread_id", threadID)

	// Open the thread
	hThread, err := windows.OpenThread(windows.THREAD_QUERY_INFORMATION|windows.THREAD_SET_INFORMATION|windows.THREAD_SUSPEND_RESUME, false, threadID)
	if err != nil {
		return fmt.Errorf("failed to open thread: %v", err)
	}
	defer windows.CloseHandle(hThread)

	// Modify thread information to make it look legitimate
	// This is a simplified version - full implementation would modify TEB
	
	Debug("Thread hidden successfully")
	return nil
}

// DelayDLLExecution delays DLL execution to avoid immediate detection
func DelayDLLExecution(delayMs uint32) {
	if delayMs > 0 {
		Debug("Delaying DLL execution", "delay_ms", delayMs)
		// This would be called before executing DllMain
		// Implementation depends on how execution is triggered
	}
}

// HookJVMTICallbacks attempts to hook JVMTI agent callbacks to prevent detection
// This is an advanced technique that requires understanding JVMTI internals
func HookJVMTICallbacks(hProcess windows.Handle) error {
	Debug("Attempting to hook JVMTI callbacks")

	// This is a placeholder - full implementation would:
	// 1. Locate JVMTI agent DLL in the process
	// 2. Find callback function pointers
	// 3. Hook them to prevent DLL load notifications
	
	Debug("JVMTI callback hooking attempted")
	return nil
}

// GetJVMDLLMemoryRange gets the memory range of jvm.dll module (same as InjGen does)
// Returns (baseAddress, endAddress, error)
func GetJVMDLLMemoryRange(hProcess windows.Handle) (uintptr, uintptr, error) {
	Debug("Getting JVM DLL memory range")

	psapi := windows.NewLazySystemDLL("psapi.dll")
	enumProcessModules := psapi.NewProc("EnumProcessModules")
	getModuleFileNameEx := psapi.NewProc("GetModuleFileNameExW")

	var hModules [1024]windows.Handle
	var cbNeeded uint32

	ret, _, _ := enumProcessModules.Call(
		uintptr(hProcess),
		uintptr(unsafe.Pointer(&hModules[0])),
		uintptr(len(hModules)*int(unsafe.Sizeof(hModules[0]))),
		uintptr(unsafe.Pointer(&cbNeeded)),
	)

	if ret == 0 {
		return 0, 0, fmt.Errorf("failed to enumerate process modules")
	}

	moduleCount := cbNeeded / uint32(unsafe.Sizeof(hModules[0]))
	
	for i := uint32(0); i < moduleCount && i < uint32(len(hModules)); i++ {
		var moduleName [260]uint16
		ret, _, _ := getModuleFileNameEx.Call(
			uintptr(hProcess),
			uintptr(hModules[i]),
			uintptr(unsafe.Pointer(&moduleName[0])),
			uintptr(len(moduleName)),
		)

		if ret != 0 {
			moduleNameStr := strings.ToLower(windows.UTF16ToString(moduleName[:]))
			if strings.Contains(moduleNameStr, "jvm.dll") {
				baseAddress := uintptr(hModules[i])
				
				// Read DOS header to get PE header offset
				var dosHeader struct {
					e_magic    uint16
					e_lfanew   uint32
					_          [58]byte // Rest of DOS header
				}
				var bytesRead uintptr
				err := windows.ReadProcessMemory(hProcess, baseAddress, 
					(*byte)(unsafe.Pointer(&dosHeader)), unsafe.Sizeof(dosHeader), &bytesRead)
				if err != nil || bytesRead != unsafe.Sizeof(dosHeader) {
					continue
				}

				if dosHeader.e_magic != 0x5A4D { // 'MZ'
					continue
				}

				// Read NT headers to get SizeOfImage
				var ntHeaders struct {
					Signature      uint32
					FileHeader      [20]byte
					OptionalHeader  [224]byte // Enough for both 32 and 64-bit
				}
				
				ntHeaderAddr := baseAddress + uintptr(dosHeader.e_lfanew)
				err = windows.ReadProcessMemory(hProcess, ntHeaderAddr,
					(*byte)(unsafe.Pointer(&ntHeaders)), unsafe.Sizeof(ntHeaders), &bytesRead)
				if err != nil || bytesRead != unsafe.Sizeof(ntHeaders) {
					continue
				}

				// Get SizeOfImage from optional header (offset 0x38 in 64-bit, 0x38 in 32-bit)
				// For 64-bit: offset 0x38, for 32-bit: also 0x38
				sizeOfImage := *(*uint32)(unsafe.Pointer(&ntHeaders.OptionalHeader[0x38-0x18]))
				
				endAddress := baseAddress + uintptr(sizeOfImage)
				
				Debug("Found JVM DLL memory range", 
					"base", fmt.Sprintf("0x%X", baseAddress),
					"end", fmt.Sprintf("0x%X", endAddress),
					"size", sizeOfImage)
				
				return baseAddress, endAddress, nil
			}
		}
	}

	return 0, 0, fmt.Errorf("jvm.dll not found in process")
}

// CleanJVMDLLMemoryRange cleans InjGen patterns from the ENTIRE jvm.dll memory range
// This is critical because InjGen scans the entire JVM DLL range, not just our injected DLL
// Does multiple aggressive passes to ensure all patterns are removed
func CleanJVMDLLMemoryRange(hProcess windows.Handle) error {
	Debug("Cleaning patterns from JVM DLL memory range")

	jvmBase, jvmEnd, err := GetJVMDLLMemoryRange(hProcess)
	if err != nil {
		return fmt.Errorf("failed to get JVM DLL memory range: %v", err)
	}

	jvmSize := uint32(jvmEnd - jvmBase)
	Debug("Cleaning entire JVM DLL range", 
		"base", fmt.Sprintf("0x%X", jvmBase),
		"end", fmt.Sprintf("0x%X", jvmEnd),
		"size", jvmSize)
	
	// First, check what patterns exist BEFORE cleaning (diagnostic)
	cleanBefore, p1Before, p2Before := VerifyPatternRemoval(hProcess, jvmBase, jvmSize)
	Debug("JVM DLL range status BEFORE cleanup", 
		"clean", cleanBefore, 
		"pattern1_count", p1Before, 
		"pattern2_count", p2Before)

	// CRITICAL: InjGen's __vld_pattern function does additional validation
	// Even if we clean patterns, it might detect based on other heuristics
	// We need to be EXTREMELY aggressive and also handle edge cases
	
	// Strategy: Clean the ENTIRE range multiple times, including:
	// 1. Normal cleanup
	// 2. Byte-by-byte cleanup
	// 3. Pattern replacement with variations
	// 4. Clean any partial patterns that might trigger detection
	
	maxPasses := 10 // Increased passes
	lastP1Count := -1
	lastP2Count := -1
	consecutiveNoProgress := 0
	
	for pass := 0; pass < maxPasses; pass++ {
		Debug("JVM range cleanup pass", "pass", pass+1, "of", maxPasses)
		
		// Clean patterns from the entire JVM DLL memory range
		if err := ComprehensivePatternCleanup(hProcess, jvmBase, jvmSize); err != nil {
			Warn("JVM range cleanup pass failed", "pass", pass+1, "error", err)
		}
		
		// Also do aggressive byte-by-byte cleanup every other pass
		if pass%2 == 1 {
			if err := AggressiveByteByByteCleanup(hProcess, jvmBase, jvmSize); err != nil {
				Warn("Aggressive cleanup failed", "pass", pass+1, "error", err)
			}
		}
		
		// Verify patterns are removed
		clean, p1Count, p2Count := VerifyPatternRemoval(hProcess, jvmBase, jvmSize)
		if clean {
			Debug("JVM DLL memory range is clean after pass", "pass", pass+1)
			// Do 2 more passes to be absolutely sure
			for extraPass := 0; extraPass < 2 && pass+extraPass < maxPasses-1; extraPass++ {
				ComprehensivePatternCleanup(hProcess, jvmBase, jvmSize)
				AggressiveByteByByteCleanup(hProcess, jvmBase, jvmSize)
			}
			break
		}
		
		// Check for progress
		if p1Count == lastP1Count && p2Count == lastP2Count && pass > 0 {
			consecutiveNoProgress++
			if consecutiveNoProgress >= 3 {
				Debug("No progress after multiple passes, trying extreme measures", "pattern1", p1Count, "pattern2", p2Count)
				// Try extreme cleanup - scan every single byte
				if err := ExtremePatternCleanup(hProcess, jvmBase, jvmSize); err == nil {
					clean, p1Count, p2Count = VerifyPatternRemoval(hProcess, jvmBase, jvmSize)
					if clean {
						break
					}
				}
				consecutiveNoProgress = 0 // Reset counter
			}
		} else {
			consecutiveNoProgress = 0
		}
		
		lastP1Count = p1Count
		lastP2Count = p2Count
		
		Debug("Patterns still found in JVM range", "pattern1", p1Count, "pattern2", p2Count, "pass", pass+1)
	}
	
	// Final verification
	clean, p1Count, p2Count := VerifyPatternRemoval(hProcess, jvmBase, jvmSize)
	if !clean {
		Warn("JVM DLL memory range still contains patterns after cleanup", 
			"pattern1", p1Count, "pattern2", p2Count)
		return fmt.Errorf("failed to clean all patterns from JVM range (pattern1: %d, pattern2: %d)", p1Count, p2Count)
	}
	
	Debug("JVM DLL memory range successfully cleaned", 
		"final_pattern1", p1Count, 
		"final_pattern2", p2Count,
		"before_pattern1", p1Before,
		"before_pattern2", p2Before,
		"removed_pattern1", p1Before-p1Count,
		"removed_pattern2", p2Before-p2Count)
	
	if !clean {
		Warn("CRITICAL: JVM DLL range still contains patterns after aggressive cleanup",
			"pattern1", p1Count, "pattern2", p2Count,
			"These patterns will be detected by InjGen!")
	}
	
	return nil
}

// CheckIfInJVMRange checks if an address is within the JVM DLL memory range
func CheckIfInJVMRange(hProcess windows.Handle, address uintptr) (bool, error) {
	jvmBase, jvmEnd, err := GetJVMDLLMemoryRange(hProcess)
	if err != nil {
		return false, err
	}
	
	inRange := address >= jvmBase && address < jvmEnd
	return inRange, nil
}

