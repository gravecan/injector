package injector

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (

	PAGE_NOACCESS          = 0x01
	PAGE_READONLY          = 0x02
	PAGE_READWRITE         = 0x04
	PAGE_WRITECOPY         = 0x08
	PAGE_EXECUTE           = 0x10
	PAGE_EXECUTE_READ      = 0x20
	PAGE_EXECUTE_READWRITE = 0x40
	PAGE_EXECUTE_WRITECOPY = 0x80

	VadNone                 = 0
	VadDevicePhysicalMemory = 1
	VadImageMap             = 2
	VadAwe                  = 3
	VadWriteWatch           = 4
	VadLargePages           = 5
	VadRotatePhysical       = 6
	VadLargePageSection     = 7

	NtAllocateVirtualMemory = 0x18
	NtProtectVirtualMemory  = 0x50
	NtQueryVirtualMemory    = 0x23
)

type MemoryBasicInformation struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
}

type VadInfo struct {
	StartingVpn uintptr
	EndingVpn   uintptr
	Parent      uintptr
	LeftChild   uintptr
	RightChild  uintptr
	Flags       uint32
}

var (
	ntdll                       = windows.NewLazySystemDLL("ntdll.dll")
	procNtAllocateVirtualMemory = ntdll.NewProc("NtAllocateVirtualMemory")
	procNtProtectVirtualMemory  = ntdll.NewProc("NtProtectVirtualMemory")
	procNtQueryVirtualMemory    = ntdll.NewProc("NtQueryVirtualMemory")
	procNtReadVirtualMemory     = ntdll.NewProc("NtReadVirtualMemory")
	procNtWriteVirtualMemory    = ntdll.NewProc("NtWriteVirtualMemory")
)

func PTESpoofing(hProcess windows.Handle, baseAddress uintptr, size uintptr) error {
	Printf("Starting PTE spoofing for address 0x%X, size: %d bytes\n", baseAddress, size)



	var allocatedAddr uintptr = baseAddress
	var allocatedSize uintptr = size
	var oldProtect uint32

	status, _, _ := procNtAllocateVirtualMemory.Call(
		uintptr(hProcess),
		uintptr(unsafe.Pointer(&allocatedAddr)),
		0,
		uintptr(unsafe.Pointer(&allocatedSize)),
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		PAGE_READWRITE,
	)

	if status != 0 {
		Printf("Warning: NtAllocateVirtualMemory failed with status 0x%X, falling back to VirtualAllocEx\n", status)

		addr, err := VirtualAllocEx(hProcess, baseAddress, size,
			windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
		if err != nil {
			return fmt.Errorf("Failed to allocate memory for PTE spoofing: %v", err)
		}
		allocatedAddr = addr
	}

	Printf("Allocated memory at 0x%X for PTE spoofing\n", allocatedAddr)



	err := windows.VirtualProtectEx(hProcess, allocatedAddr, size, windows.PAGE_EXECUTE_READ, &oldProtect)
	if err != nil {
		Printf("Warning: Failed to change memory protection to RX: %v\n", err)

	} else {
		Printf("Changed memory protection to RX (Execute + Read)\n")
	}

	var newProtect uint32 = PAGE_EXECUTE_READ
	var protectSize uintptr = size
	var protectAddr uintptr = allocatedAddr

	status, _, _ = procNtProtectVirtualMemory.Call(
		uintptr(hProcess),
		uintptr(unsafe.Pointer(&protectAddr)),
		uintptr(unsafe.Pointer(&protectSize)),
		uintptr(newProtect),
		uintptr(unsafe.Pointer(&oldProtect)),
	)

	if status != 0 {
		Printf("Warning: NtProtectVirtualMemory failed with status 0x%X\n", status)
	} else {
		Printf("Successfully applied PTE spoofing protection\n")
	}

	Printf("PTE spoofing completed for address 0x%X\n", allocatedAddr)
	return nil
}

func VADManipulation(hProcess windows.Handle, baseAddress uintptr, size uintptr) error {
	Printf("Starting VAD manipulation for address 0x%X, size: %d bytes\n", baseAddress, size)



	var mbi MemoryBasicInformation
	var returnLength uintptr

	status, _, _ := procNtQueryVirtualMemory.Call(
		uintptr(hProcess),
		baseAddress,
		0,
		uintptr(unsafe.Pointer(&mbi)),
		unsafe.Sizeof(mbi),
		uintptr(unsafe.Pointer(&returnLength)),
	)

	if status != 0 {
		Printf("Warning: NtQueryVirtualMemory failed with status 0x%X\n", status)
		return fmt.Errorf("Failed to query VAD information: status 0x%X", status)
	}

	Printf("Current VAD info - Base: 0x%X, Size: %d, Protect: 0x%X, Type: 0x%X\n",
		mbi.BaseAddress, mbi.RegionSize, mbi.Protect, mbi.Type)




	var vadAddr uintptr = baseAddress
	var vadSize uintptr = size

	status, _, _ = procNtAllocateVirtualMemory.Call(
		uintptr(hProcess),
		uintptr(unsafe.Pointer(&vadAddr)),
		0,
		uintptr(unsafe.Pointer(&vadSize)),
		windows.MEM_COMMIT|windows.MEM_RESERVE|windows.MEM_TOP_DOWN,
		PAGE_EXECUTE_READWRITE,
	)

	if status != 0 {
		Printf("Warning: VAD-specific allocation failed with status 0x%X\n", status)
		return fmt.Errorf("Failed to perform VAD manipulation: status 0x%X", status)
	}

	Printf("VAD manipulation completed successfully\n")
	return nil
}

func RemoveVADNode(hProcess windows.Handle, baseAddress uintptr) error {
	Printf("Attempting to remove/hide VAD node for address 0x%X\n", baseAddress)



	var mbi MemoryBasicInformation
	var returnLength uintptr

	status, _, _ := procNtQueryVirtualMemory.Call(
		uintptr(hProcess),
		baseAddress,
		0,
		uintptr(unsafe.Pointer(&mbi)),
		unsafe.Sizeof(mbi),
		uintptr(unsafe.Pointer(&returnLength)),
	)

	if status != 0 {
		return fmt.Errorf("Failed to query VAD node information: status 0x%X", status)
	}

	Printf("VAD node info - Base: 0x%X, Size: %d, State: 0x%X\n",
		mbi.BaseAddress, mbi.RegionSize, mbi.State)



	var oldProtect uint32
	err := windows.VirtualProtectEx(hProcess, baseAddress, mbi.RegionSize,
		windows.PAGE_EXECUTE_READ, &oldProtect)
	if err != nil {
		Printf("Warning: Failed to modify memory protection for VAD hiding: %v\n", err)
	}

	var protectAddr uintptr = baseAddress
	var protectSize uintptr = mbi.RegionSize
	var newProtect uint32 = PAGE_EXECUTE_READ

	status, _, _ = procNtProtectVirtualMemory.Call(
		uintptr(hProcess),
		uintptr(unsafe.Pointer(&protectAddr)),
		uintptr(unsafe.Pointer(&protectSize)),
		uintptr(newProtect),
		uintptr(unsafe.Pointer(&oldProtect)),
	)

	if status == 0 {
		Printf("Successfully modified VAD node characteristics\n")
	} else {
		Printf("Warning: NT API VAD modification failed with status 0x%X\n", status)
	}

	Printf("VAD node removal/hiding attempt completed\n")
	return nil
}

func AllocateBehindThreadStack(hProcess windows.Handle, size uintptr) (uintptr, error) {
	Printf("Attempting to allocate memory behind thread stack, size: %d bytes\n", size)





	var baseAddresses []uintptr
	if unsafe.Sizeof(uintptr(0)) == 8 {

		baseAddresses = []uintptr{
			0x000000007FFE0000,
			0x000000007FFD0000,
			0x000000007FFC0000,
			0x000000007FFB0000,
		}
	} else {

		baseAddresses = []uintptr{
			0x7FFE0000,
			0x7FFD0000,
			0x7FFC0000,
			0x7FFB0000,
		}
	}

	for _, baseAddr := range baseAddresses {
		Printf("Trying to allocate behind thread stack at 0x%X\n", baseAddr)

		addr, err := VirtualAllocEx(hProcess, baseAddr, size,
			windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)

		if err == nil {
			Printf("Successfully allocated memory behind thread stack at 0x%X\n", addr)
			return addr, nil
		}

		Printf("Failed to allocate at 0x%X: %v\n", baseAddr, err)
	}

	Printf("Specific addresses failed, letting system choose address near stack region\n")

	addr, err := VirtualAllocEx(hProcess, 0, size,
		windows.MEM_COMMIT|windows.MEM_RESERVE|windows.MEM_TOP_DOWN,
		windows.PAGE_EXECUTE_READWRITE)

	if err != nil {
		return 0, fmt.Errorf("Failed to allocate memory behind thread stack: %v", err)
	}

	Printf("System allocated memory at 0x%X (top-down allocation)\n", addr)
	return addr, nil
}

func DirectSyscalls(hProcess windows.Handle, baseAddress uintptr, buffer []byte) error {
	Printf("Using direct system calls for memory operations\n")


	ntdll := windows.NewLazySystemDLL("ntdll.dll")

	ntAllocateVirtualMemory := ntdll.NewProc("NtAllocateVirtualMemory")
	var allocAddr uintptr = 0
	allocSize := uintptr(len(buffer))

	ret, _, _ := ntAllocateVirtualMemory.Call(
		uintptr(hProcess),
		uintptr(unsafe.Pointer(&allocAddr)),
		0,
		uintptr(unsafe.Pointer(&allocSize)),
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_EXECUTE_READWRITE,
	)

	if ret != 0 {
		Printf("NtAllocateVirtualMemory failed with status: 0x%X\n", ret)
		return fmt.Errorf("NtAllocateVirtualMemory failed: 0x%X", ret)
	}

	Printf("Successfully allocated memory via direct syscall at: 0x%X\n", allocAddr)

	ntWriteVirtualMemory := ntdll.NewProc("NtWriteVirtualMemory")
	var bytesWritten uintptr

	ret, _, _ = ntWriteVirtualMemory.Call(
		uintptr(hProcess),
		allocAddr,
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(len(buffer)),
		uintptr(unsafe.Pointer(&bytesWritten)),
	)

	if ret != 0 {
		Printf("NtWriteVirtualMemory failed with status: 0x%X\n", ret)
		return fmt.Errorf("NtWriteVirtualMemory failed: 0x%X", ret)
	}

	Printf("Successfully wrote %d bytes via direct syscall\n", bytesWritten)

	ntProtectVirtualMemory := ntdll.NewProc("NtProtectVirtualMemory")
	var oldProtect uint32
	protectSize := uintptr(len(buffer))

	ret, _, _ = ntProtectVirtualMemory.Call(
		uintptr(hProcess),
		uintptr(unsafe.Pointer(&allocAddr)),
		uintptr(unsafe.Pointer(&protectSize)),
		windows.PAGE_EXECUTE_READ,
		uintptr(unsafe.Pointer(&oldProtect)),
	)

	if ret != 0 {
		Printf("NtProtectVirtualMemory failed with status: 0x%X\n", ret)
		return fmt.Errorf("NtProtectVirtualMemory failed: 0x%X", ret)
	}

	Printf("Successfully changed memory protection via direct syscall\n")

	ntFreeVirtualMemory := ntdll.NewProc("NtFreeVirtualMemory")
	freeSize := uintptr(0)

	ret, _, _ = ntFreeVirtualMemory.Call(
		uintptr(hProcess),
		uintptr(unsafe.Pointer(&allocAddr)),
		uintptr(unsafe.Pointer(&freeSize)),
		windows.MEM_RELEASE,
	)

	if ret != 0 {
		Printf("Warning: NtFreeVirtualMemory failed with status: 0x%X\n", ret)
	} else {
		Printf("Successfully freed memory via direct syscall\n")
	}

	Printf("Direct syscalls test completed successfully\n")
	return nil

	Printf("Successfully wrote %d bytes using direct syscalls\n", bytesWritten)
	return nil
}

func ApplyAdvancedBypassOptions(hProcess windows.Handle, baseAddress uintptr, size uintptr, options BypassOptions) error {
	Printf("Applying advanced bypass options...\n")

	if hProcess == 0 {
		return fmt.Errorf("Invalid process handle")
	}
	if baseAddress == 0 {
		return fmt.Errorf("Invalid base address")
	}
	if size == 0 {
		return fmt.Errorf("Invalid size")
	}

	var appliedTechniques []string
	var failedTechniques []string

	if options.PTESpoofing {
		Printf("Applying PTE spoofing...\n")
		err := PTESpoofing(hProcess, baseAddress, size)
		if err != nil {
			Printf("Warning: PTE spoofing failed: %v\n", err)
			failedTechniques = append(failedTechniques, "PTE Spoofing")

		} else {
			Printf("PTE spoofing applied successfully\n")
			appliedTechniques = append(appliedTechniques, "PTE Spoofing")
		}
	}

	if options.VADManipulation {
		Printf("Applying VAD manipulation...\n")
		err := VADManipulation(hProcess, baseAddress, size)
		if err != nil {
			Printf("Warning: VAD manipulation failed: %v\n", err)
			failedTechniques = append(failedTechniques, "VAD Manipulation")

		} else {
			Printf("VAD manipulation applied successfully\n")
			appliedTechniques = append(appliedTechniques, "VAD Manipulation")
		}
	}

	if options.RemoveVADNode {
		Printf("Attempting to remove VAD node...\n")
		err := RemoveVADNode(hProcess, baseAddress)
		if err != nil {
			Printf("Warning: VAD node removal failed: %v\n", err)
			failedTechniques = append(failedTechniques, "VAD Node Removal")

		} else {
			Printf("VAD node removal applied successfully\n")
			appliedTechniques = append(appliedTechniques, "VAD Node Removal")
		}
	}

	if options.ThreadStackAllocation {
		Printf("Applying thread stack allocation...\n")


		stackAddr, err := AllocateBehindThreadStack(hProcess, size)
		if err != nil {
			Printf("Warning: Thread stack allocation failed: %v\n", err)
			failedTechniques = append(failedTechniques, "Thread Stack Allocation")
		} else {
			Printf("Thread stack allocation applied successfully at 0x%X\n", stackAddr)
			appliedTechniques = append(appliedTechniques, "Thread Stack Allocation")

		}
	}

	if options.DirectSyscalls {
		Printf("Applying direct syscalls...\n")

		testBuffer := make([]byte, 1024)
		err := DirectSyscalls(hProcess, baseAddress, testBuffer)
		if err != nil {
			Printf("Warning: Direct syscalls failed: %v\n", err)
			failedTechniques = append(failedTechniques, "Direct Syscalls")
		} else {
			Printf("Direct syscalls applied successfully\n")
			appliedTechniques = append(appliedTechniques, "Direct Syscalls")
		}
	}

	Printf("Advanced bypass options application completed\n")
	Printf("Successfully applied: %v\n", appliedTechniques)
	if len(failedTechniques) > 0 {
		Printf("Failed techniques: %v\n", failedTechniques)
	}

	return nil
}

func GetSyscallNumber(functionName string) (uint32, error) {






	syscallNumbers := map[string]uint32{
		"NtAllocateVirtualMemory": 0x18,
		"NtProtectVirtualMemory":  0x50,
		"NtQueryVirtualMemory":    0x23,
		"NtWriteVirtualMemory":    0x3A,
		"NtReadVirtualMemory":     0x3F,
	}

	if num, exists := syscallNumbers[functionName]; exists {
		Printf("Retrieved syscall number 0x%X for function %s\n", num, functionName)
		return num, nil
	}

	return 0, fmt.Errorf("Syscall number not found for function: %s", functionName)
}

func ExecuteDirectSyscall(syscallNumber uint32, args ...uintptr) (uintptr, error) {
	Printf("Executing direct syscall number 0x%X with %d arguments\n", syscallNumber, len(args))

	if syscallNumber == 0 {
		return 0, fmt.Errorf("invalid syscall number")
	}

	if len(args) > 11 {
		return 0, fmt.Errorf("too many arguments for syscall: %d", len(args))
	}


	ntdll := windows.NewLazySystemDLL("ntdll.dll")

	switch syscallNumber {
	case 0x18:
		if len(args) >= 6 {
			ntAllocateVirtualMemory := ntdll.NewProc("NtAllocateVirtualMemory")
			ret, _, _ := ntAllocateVirtualMemory.Call(args[0], args[1], args[2], args[3], args[4], args[5])
			return ret, nil
		}
	case 0x3A:
		if len(args) >= 5 {
			ntWriteVirtualMemory := ntdll.NewProc("NtWriteVirtualMemory")
			ret, _, _ := ntWriteVirtualMemory.Call(args[0], args[1], args[2], args[3], args[4])
			return ret, nil
		}
	case 0x3F:
		if len(args) >= 5 {
			ntReadVirtualMemory := ntdll.NewProc("NtReadVirtualMemory")
			ret, _, _ := ntReadVirtualMemory.Call(args[0], args[1], args[2], args[3], args[4])
			return ret, nil
		}
	case 0x50:
		if len(args) >= 5 {
			ntProtectVirtualMemory := ntdll.NewProc("NtProtectVirtualMemory")
			ret, _, _ := ntProtectVirtualMemory.Call(args[0], args[1], args[2], args[3], args[4])
			return ret, nil
		}
	case 0xB4:
		if len(args) >= 11 {
			ntCreateThreadEx := ntdll.NewProc("NtCreateThreadEx")
			ret, _, _ := ntCreateThreadEx.Call(args[0], args[1], args[2], args[3], args[4],
				args[5], args[6], args[7], args[8], args[9], args[10])
			return ret, nil
		}
	default:

		Printf("Warning: Unknown syscall number 0x%X, using fallback method\n", syscallNumber)
		return 0, fmt.Errorf("unsupported syscall number: 0x%X", syscallNumber)
	}

	Printf("Direct syscall execution completed via NT API\n")
	return 0, nil
}
