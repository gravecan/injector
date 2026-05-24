package injector

import (
	"encoding/binary"
	"fmt"
	"unsafe"
)

type DOSHeader struct {
	Signature    [2]byte
	BytesOnPage  uint16
	PagesInFile  uint16
	Relocations  uint16
	SizeOfHeader uint16
	MinAlloc     uint16
	MaxAlloc     uint16
	SS           uint16
	SP           uint16
	CheckSum     uint16
	IP           uint16
	CS           uint16
	RelocAddr    uint16
	Overlay      uint16
	Reserved1    [4]uint16
	OEMId        uint16
	OEMInfo      uint16
	Reserved2    [10]uint16
	PEOffset     uint32
}

type COFFHeader struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

type OptionalHeader64 struct {
	Magic                       uint16
	MajorLinkerVersion          uint8
	MinorLinkerVersion          uint8
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	ImageBase                   uint64
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint64
	SizeOfStackCommit           uint64
	SizeOfHeapReserve           uint64
	SizeOfHeapCommit            uint64
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
}

type OptionalHeader32 struct {
	Magic                       uint16
	MajorLinkerVersion          uint8
	MinorLinkerVersion          uint8
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	BaseOfData                  uint32
	ImageBase                   uint32
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint32
	SizeOfStackCommit           uint32
	SizeOfHeapReserve           uint32
	SizeOfHeapCommit            uint32
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
}

type DataDirectory struct {
	VirtualAddress uint32
	Size           uint32
}

type SectionHeader struct {
	Name                 [8]byte
	VirtualSize          uint32
	VirtualAddress       uint32
	SizeOfRawData        uint32
	PointerToRawData     uint32
	PointerToRelocations uint32
	PointerToLinenumbers uint32
	NumberOfRelocations  uint16
	NumberOfLinenumbers  uint16
	Characteristics      uint32
}

type ImportDescriptor struct {
	OriginalFirstThunk uint32
	TimeDateStamp      uint32
	ForwarderChain     uint32
	Name               uint32
	FirstThunk         uint32
}

type BaseRelocation struct {
	VirtualAddress uint32
	SizeOfBlock    uint32
}

type PEHeader struct {
	DOSHeader       DOSHeader
	PESignature     [4]byte
	COFFHeader      COFFHeader
	OptionalHeader  interface{}
	DataDirectories []DataDirectory
	SectionHeaders  []SectionHeader
	Is64Bit         bool
}

const (
	IMAGE_FILE_MACHINE_I386  = 0x014c
	IMAGE_FILE_MACHINE_AMD64 = 0x8664

	IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b
	IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b

	IMAGE_DIRECTORY_ENTRY_EXPORT    = 0
	IMAGE_DIRECTORY_ENTRY_IMPORT    = 1
	IMAGE_DIRECTORY_ENTRY_RESOURCE  = 2
	IMAGE_DIRECTORY_ENTRY_BASERELOC = 5

	IMAGE_REL_BASED_ABSOLUTE = 0
	IMAGE_REL_BASED_HIGH     = 1
	IMAGE_REL_BASED_LOW      = 2
	IMAGE_REL_BASED_HIGHLOW  = 3
	IMAGE_REL_BASED_DIR64    = 10

	IMAGE_SCN_CNT_CODE               = 0x00000020
	IMAGE_SCN_CNT_INITIALIZED_DATA   = 0x00000040
	IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
	IMAGE_SCN_MEM_EXECUTE            = 0x20000000
	IMAGE_SCN_MEM_READ               = 0x40000000
	IMAGE_SCN_MEM_WRITE              = 0x80000000
)

func validatePEFile(dllBytes []byte) error {

	if len(dllBytes) < 256 {
		return fmt.Errorf("file too small: %d bytes (minimum 256 bytes required for PE header)", len(dllBytes))
	}

	if dllBytes[0] != 'M' || dllBytes[1] != 'Z' {
		return fmt.Errorf("invalid DOS signature: 0x%02x%02x (expected MZ)", dllBytes[0], dllBytes[1])
	}

	if len(dllBytes) < 64 {
		return fmt.Errorf("file too small to contain PE offset: %d bytes", len(dllBytes))
	}

	peOffset := binary.LittleEndian.Uint32(dllBytes[60:64])
	if peOffset == 0 {
		return fmt.Errorf("PE offset is zero")
	}
	if peOffset >= uint32(len(dllBytes))-4 {
		return fmt.Errorf("PE offset out of bounds: %d (file size: %d)", peOffset, len(dllBytes))
	}
	if peOffset < 64 {
		return fmt.Errorf("PE offset too small: %d (should be at least 64)", peOffset)
	}
	if peOffset > 0x1000 {
		return fmt.Errorf("PE offset suspiciously large: %d", peOffset)
	}

	if peOffset+4 <= uint32(len(dllBytes)) {
		if dllBytes[peOffset] != 'P' || dllBytes[peOffset+1] != 'E' ||
			dllBytes[peOffset+2] != 0 || dllBytes[peOffset+3] != 0 {
			return fmt.Errorf("invalid PE signature at offset %d: %02x %02x %02x %02x (expected PE\\x00\\x00)",
				peOffset, dllBytes[peOffset], dllBytes[peOffset+1],
				dllBytes[peOffset+2], dllBytes[peOffset+3])
		}
	} else {
		return fmt.Errorf("PE signature out of file bounds")
	}

	Printf("PE file validation passed - PE offset: %d, file size: %d", peOffset, len(dllBytes))
	return nil
}

func ParsePEHeader(dllBytes []byte) (*PEHeader, error) {
	if len(dllBytes) < 64 {
		return nil, fmt.Errorf("file too small to be a valid PE: %d bytes", len(dllBytes))
	}

	if err := validatePEFile(dllBytes); err != nil {
		return nil, fmt.Errorf("PE validation failed: %v", err)
	}

	header := &PEHeader{}

	if err := binary.Read(newBytesReader(dllBytes[:64]), binary.LittleEndian, &header.DOSHeader); err != nil {
		return nil, fmt.Errorf("failed to parse DOS header: %v", err)
	}

	Printf("DOS Header parsed successfully, PE offset: %d", header.DOSHeader.PEOffset)

	if header.DOSHeader.Signature[0] != 'M' || header.DOSHeader.Signature[1] != 'Z' {
		return nil, fmt.Errorf("invalid DOS signature")
	}

	peOffset := header.DOSHeader.PEOffset
	if peOffset >= uint32(len(dllBytes)) || peOffset < 64 {
		return nil, fmt.Errorf("invalid PE offset: %d", peOffset)
	}

	if peOffset+4 > uint32(len(dllBytes)) {
		return nil, fmt.Errorf("PE signature out of bounds")
	}
	copy(header.PESignature[:], dllBytes[peOffset:peOffset+4])
	if string(header.PESignature[:]) != "PE\x00\x00" {
		return nil, fmt.Errorf("invalid PE signature")
	}

	coffOffset := peOffset + 4
	if coffOffset+24 > uint32(len(dllBytes)) {
		return nil, fmt.Errorf("COFF header out of bounds: offset %d, need 24 bytes, file size %d", coffOffset, len(dllBytes))
	}

	Printf("Parsing COFF header at offset %d", coffOffset)
	if err := binary.Read(newBytesReader(dllBytes[coffOffset:coffOffset+24]), binary.LittleEndian, &header.COFFHeader); err != nil {
		return nil, fmt.Errorf("failed to parse COFF header: %v", err)
	}

	Printf("COFF Header - Machine: 0x%x, Sections: %d, OptHdrSize: %d",
		header.COFFHeader.Machine, header.COFFHeader.NumberOfSections, header.COFFHeader.SizeOfOptionalHeader)

	if header.COFFHeader.SizeOfOptionalHeader == 0 {
		return nil, fmt.Errorf("missing optional header (size is 0)")
	}
	if header.COFFHeader.SizeOfOptionalHeader > 1024 {
		return nil, fmt.Errorf("optional header size too large: %d", header.COFFHeader.SizeOfOptionalHeader)
	}
	if header.COFFHeader.NumberOfSections > 96 {
		return nil, fmt.Errorf("too many sections: %d", header.COFFHeader.NumberOfSections)
	}

	optHeaderOffset := coffOffset + 24
	if optHeaderOffset+uint32(header.COFFHeader.SizeOfOptionalHeader) > uint32(len(dllBytes)) {
		return nil, fmt.Errorf("optional header out of bounds: offset %d, size %d, file size %d",
			optHeaderOffset, header.COFFHeader.SizeOfOptionalHeader, len(dllBytes))
	}

	Printf("Parsing optional header at offset %d, size %d", optHeaderOffset, header.COFFHeader.SizeOfOptionalHeader)

	if optHeaderOffset+2 > uint32(len(dllBytes)) {
		return nil, fmt.Errorf("cannot read magic bytes from optional header")
	}

	if optHeaderOffset%2 != 0 {
		Printf("Warning: optional header offset not aligned: %d", optHeaderOffset)
	}

	magic := binary.LittleEndian.Uint16(dllBytes[optHeaderOffset : optHeaderOffset+2])
	Printf("PE Magic bytes at offset %d: 0x%x", optHeaderOffset, magic)

	Printf("Raw bytes at optional header start: %02x %02x %02x %02x",
		dllBytes[optHeaderOffset], dllBytes[optHeaderOffset+1],
		dllBytes[optHeaderOffset+2], dllBytes[optHeaderOffset+3])

	if optHeaderOffset >= 8 {
		Printf("Context before magic: %02x %02x %02x %02x",
			dllBytes[optHeaderOffset-4], dllBytes[optHeaderOffset-3],
			dllBytes[optHeaderOffset-2], dllBytes[optHeaderOffset-1])
	}

	if magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC && magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC {
		Printf("Invalid magic 0x%x detected, attempting recovery", magic)

		for offset := int(optHeaderOffset) - 4; offset <= int(optHeaderOffset)+4; offset += 2 {
			if offset >= 0 && offset+2 <= len(dllBytes) {
				testMagic := binary.LittleEndian.Uint16(dllBytes[offset : offset+2])
				if testMagic == IMAGE_NT_OPTIONAL_HDR32_MAGIC || testMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC {
					Printf("Found valid magic 0x%x at offset %d (correction: %d bytes)", testMagic, offset, offset-int(optHeaderOffset))
					optHeaderOffset = uint32(offset)
					magic = testMagic
					break
				}
			}
		}
	}

	switch magic {
	case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
		Printf("Detected 32-bit PE")
		header.Is64Bit = false
		var opt OptionalHeader32

		readSize := min(240, int(header.COFFHeader.SizeOfOptionalHeader))
		if err := binary.Read(newBytesReader(dllBytes[optHeaderOffset:optHeaderOffset+uint32(readSize)]), binary.LittleEndian, &opt); err != nil {
			return nil, fmt.Errorf("failed to parse 32-bit optional header: %v", err)
		}
		header.OptionalHeader = opt
	case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
		Printf("Detected 64-bit PE")
		header.Is64Bit = true
		var opt OptionalHeader64

		readSize := min(240, int(header.COFFHeader.SizeOfOptionalHeader))
		if err := binary.Read(newBytesReader(dllBytes[optHeaderOffset:optHeaderOffset+uint32(readSize)]), binary.LittleEndian, &opt); err != nil {
			return nil, fmt.Errorf("failed to parse 64-bit optional header: %v", err)
		}
		header.OptionalHeader = opt
	default:

		Printf("COFF header details: Machine=0x%x, SizeOfOptionalHeader=%d",
			header.COFFHeader.Machine, header.COFFHeader.SizeOfOptionalHeader)
		Printf("PE offset: %d, COFF offset: %d, Optional header offset: %d",
			peOffset, coffOffset, optHeaderOffset)
		Printf("File size: %d bytes", len(dllBytes))

		if magic == 0 {
			return nil, fmt.Errorf("optional header magic is zero - possible corrupted PE file or invalid offset calculation")
		}

		switch magic {
		case 0x9200:
			return nil, fmt.Errorf("invalid optional header magic: 0x%x (this often indicates a malformed PE file or incorrect offset calculation). File may be corrupted or not a valid PE", magic)
		case 0x0020:
			return nil, fmt.Errorf("invalid optional header magic: 0x%x (possible byte-swapped value, check file endianness)", magic)
		default:
			return nil, fmt.Errorf("unknown optional header magic: 0x%x (expected 0x%x for 32-bit or 0x%x for 64-bit). This may indicate file corruption or an unsupported PE format",
				magic, IMAGE_NT_OPTIONAL_HDR32_MAGIC, IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		}
	}

	var numDataDirs uint32
	var dataDir []DataDirectory

	if header.Is64Bit {
		opt := header.OptionalHeader.(OptionalHeader64)
		numDataDirs = opt.NumberOfRvaAndSizes
	} else {
		opt := header.OptionalHeader.(OptionalHeader32)
		numDataDirs = opt.NumberOfRvaAndSizes
	}

	Printf("Number of data directories: %d", numDataDirs)

	if numDataDirs > 0 && numDataDirs <= 16 {

		var dataDirOffset uint32
		if header.Is64Bit {
			dataDirOffset = optHeaderOffset + 112
		} else {
			dataDirOffset = optHeaderOffset + 96
		}

		Printf("Data directories offset: %d", dataDirOffset)

		if dataDirOffset+numDataDirs*8 <= uint32(len(dllBytes)) {
			dataDir = make([]DataDirectory, numDataDirs)
			for i := uint32(0); i < numDataDirs; i++ {
				offset := dataDirOffset + i*8
				if err := binary.Read(newBytesReader(dllBytes[offset:offset+8]), binary.LittleEndian, &dataDir[i]); err != nil {
					Printf("Warning: failed to parse data directory %d: %v", i, err)
					break
				}
			}
		} else {
			Printf("Warning: data directories out of bounds, skipping")
		}
	}
	header.DataDirectories = dataDir

	sectionHeaderOffset := optHeaderOffset + uint32(header.COFFHeader.SizeOfOptionalHeader)
	if sectionHeaderOffset+uint32(header.COFFHeader.NumberOfSections)*40 > uint32(len(dllBytes)) {
		return nil, fmt.Errorf("section headers out of bounds")
	}

	header.SectionHeaders = make([]SectionHeader, header.COFFHeader.NumberOfSections)
	for i := uint16(0); i < header.COFFHeader.NumberOfSections; i++ {
		offset := sectionHeaderOffset + uint32(i)*40
		if err := binary.Read(newBytesReader(dllBytes[offset:offset+40]), binary.LittleEndian, &header.SectionHeaders[i]); err != nil {
			return nil, fmt.Errorf("failed to parse section header %d: %v", i, err)
		}
	}

	return header, nil
}

func (pe *PEHeader) GetOptionalHeaderSize() uint32 {
	if pe.Is64Bit {
		return uint32(unsafe.Sizeof(OptionalHeader64{}))
	}
	return uint32(unsafe.Sizeof(OptionalHeader32{}))
}

func (pe *PEHeader) GetImageBase() uint64 {
	if pe.Is64Bit {
		return pe.OptionalHeader.(OptionalHeader64).ImageBase
	}
	return uint64(pe.OptionalHeader.(OptionalHeader32).ImageBase)
}

func (pe *PEHeader) GetSizeOfImage() uint32 {
	if pe.Is64Bit {
		return pe.OptionalHeader.(OptionalHeader64).SizeOfImage
	}
	return pe.OptionalHeader.(OptionalHeader32).SizeOfImage
}

func (pe *PEHeader) GetAddressOfEntryPoint() uint32 {
	if pe.Is64Bit {
		return pe.OptionalHeader.(OptionalHeader64).AddressOfEntryPoint
	}
	return pe.OptionalHeader.(OptionalHeader32).AddressOfEntryPoint
}

func (pe *PEHeader) GetSectionAlignment() uint32 {
	if pe.Is64Bit {
		return pe.OptionalHeader.(OptionalHeader64).SectionAlignment
	}
	return pe.OptionalHeader.(OptionalHeader32).SectionAlignment
}

func (pe *PEHeader) GetFileAlignment() uint32 {
	if pe.Is64Bit {
		return pe.OptionalHeader.(OptionalHeader64).FileAlignment
	}
	return pe.OptionalHeader.(OptionalHeader32).FileAlignment
}

func (pe *PEHeader) RvaToFileOffset(rva uint32) (uint32, error) {
	for _, section := range pe.SectionHeaders {
		if rva >= section.VirtualAddress && rva < section.VirtualAddress+section.VirtualSize {
			return rva - section.VirtualAddress + section.PointerToRawData, nil
		}
	}
	return 0, fmt.Errorf("RVA 0x%x not found in any section", rva)
}

func (pe *PEHeader) GetSection(name string) (*SectionHeader, error) {
	for i := range pe.SectionHeaders {
		sectionName := string(pe.SectionHeaders[i].Name[:])

		if nullIndex := findNull(sectionName); nullIndex != -1 {
			sectionName = sectionName[:nullIndex]
		}
		if sectionName == name {
			return &pe.SectionHeaders[i], nil
		}
	}
	return nil, fmt.Errorf("section %s not found", name)
}

func newBytesReader(data []byte) *bytesReader {
	return &bytesReader{data: data, pos: 0}
}

type bytesReader struct {
	data []byte
	pos  int
}

func (r *bytesReader) Read(p []byte) (n int, err error) {
	if r.pos >= len(r.data) {
		return 0, fmt.Errorf("EOF")
	}
	n = copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

func findNull(s string) int {
	for i, c := range s {
		if c == 0 {
			return i
		}
	}
	return -1
}

func (pe *PEHeader) ValidateArchitecture() error {
	switch pe.COFFHeader.Machine {
	case IMAGE_FILE_MACHINE_I386:
		if unsafe.Sizeof(uintptr(0)) != 4 {
			return fmt.Errorf("32-bit DLL cannot be loaded in 64-bit process")
		}
	case IMAGE_FILE_MACHINE_AMD64:
		if unsafe.Sizeof(uintptr(0)) != 8 {
			return fmt.Errorf("64-bit DLL cannot be loaded in 32-bit process")
		}
	default:
		return fmt.Errorf("unsupported machine type: 0x%x", pe.COFFHeader.Machine)
	}
	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
