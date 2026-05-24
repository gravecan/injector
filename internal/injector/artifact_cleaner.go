package injector

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	advapi32                  = windows.NewLazySystemDLL("advapi32.dll")
	procRegOpenKeyEx          = advapi32.NewProc("RegOpenKeyExW")
	procRegEnumValue          = advapi32.NewProc("RegEnumValueW")
	procRegEnumKeyEx          = advapi32.NewProc("RegEnumKeyExW")
	procRegDeleteValue        = advapi32.NewProc("RegDeleteValueW")
	procRegCloseKey           = advapi32.NewProc("RegCloseKey")
	procGetSecurityInfo       = advapi32.NewProc("GetSecurityInfo")
	procSetSecurityInfo       = advapi32.NewProc("SetSecurityInfo")
	procSetEntriesInAcl       = advapi32.NewProc("SetEntriesInAclW")
	shell32                   = windows.NewLazySystemDLL("shell32.dll")
	procSHGetKnownFolderPath  = shell32.NewProc("SHGetKnownFolderPath")
	procSHGetPathFromIDList    = shell32.NewProc("SHGetPathFromIDListW")
)

const (
	HKEY_CURRENT_USER  = 0x80000001
	HKEY_LOCAL_MACHINE = 0x80000002
	HKEY_CLASSES_ROOT  = 0x80000000

	KEY_READ       = 0x20019
	KEY_ALL_ACCESS = 0xF003F
	KEY_SET_VALUE  = 0x0002

	REG_BINARY = 3

	ERROR_SUCCESS        = 0
	ERROR_NO_MORE_ITEMS  = 259
	ERROR_MORE_DATA      = 234

	SE_REGISTRY_KEY = 0x00000001
	DACL_SECURITY_INFORMATION = 0x00000004

	GRANT_ACCESS   = 1
	NO_INHERITANCE = 0
	TRUSTEE_IS_NAME = 1
)

// ArtifactCleaner removes traces of DLL injection from registry and file system
type ArtifactCleaner struct {
	logger Logger
}

// NewArtifactCleaner creates a new artifact cleaner
func NewArtifactCleaner(logger Logger) *ArtifactCleaner {
	return &ArtifactCleaner{logger: logger}
}

// CleanAllArtifacts removes all traces of the DLL from registry and file system
func (ac *ArtifactCleaner) CleanAllArtifacts(dllPath string) error {
	dllName := filepath.Base(dllPath)
	dllNameWithoutExt := strings.TrimSuffix(dllName, filepath.Ext(dllName))
	
	ac.logger.Info("Cleaning injection artifacts", "dll", dllName)
	
	// Clean registry
	ac.CleanRegistryArtifacts(dllName)
	ac.CleanRegistryArtifacts(dllNameWithoutExt)
	
	// Clean file system
	ac.CleanFileSystemArtifacts(dllName)
	ac.CleanFileSystemArtifacts(dllNameWithoutExt)
	
	return nil
}

// CleanRegistryArtifacts removes registry traces
func (ac *ArtifactCleaner) CleanRegistryArtifacts(processName string) {
	ac.deleteValueFromRecentDocs(processName)
	ac.deleteValueFromUserAssist(processName)
	ac.deleteValueFromBAM(processName)
	ac.deleteValueFromShellBags(processName)
}

// CleanFileSystemArtifacts removes file system traces
func (ac *ArtifactCleaner) CleanFileSystemArtifacts(fileName string) {
	ac.deleteFileFromPrefetch(fileName)
	ac.deleteFileFromRecent(fileName)
}

// decodeUTF16LE decodes UTF-16LE encoded data
func decodeUTF16LE(data []byte) string {
	var result strings.Builder
	for i := 0; i+1 < len(data); i += 2 {
		ch := uint16(data[i]) | (uint16(data[i+1]) << 8)
		if ch == 0 {
			break
		}
		result.WriteRune(rune(ch))
	}
	return result.String()
}

// binaryToWString extracts printable ASCII characters from binary data
func binaryToWString(data []byte) string {
	var result strings.Builder
	for _, b := range data {
		if b >= 32 && b <= 126 {
			result.WriteByte(b)
		}
	}
	return result.String()
}

// decodeROT13 decodes ROT13 encoded string
func decodeROT13(data []uint16) string {
	var result strings.Builder
	for _, ch := range data {
		if ch == 0 {
			break
		}
		if (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') {
			var base uint16 = 'A'
			if ch >= 'a' {
				base = 'a'
			}
			ch = (ch-base+13)%26 + base
		}
		result.WriteRune(rune(ch))
	}
	return result.String()
}

// getSubKeysOfKey gets all subkeys of a registry key
func (ac *ArtifactCleaner) getSubKeysOfKey(hKey uintptr, keyPath string) []string {
	subKeys := []string{""}
	
	var hOpenedKey syscall.Handle
	ret, _, _ := procRegOpenKeyEx.Call(
		uintptr(hKey),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(keyPath))),
		0,
		KEY_READ,
		uintptr(unsafe.Pointer(&hOpenedKey)),
	)
	
	if ret == ERROR_SUCCESS {
		defer procRegCloseKey.Call(uintptr(hOpenedKey))
		
		index := uint32(0)
		for {
			var keyName [255]uint16
			keyNameSize := uint32(len(keyName))
			
			ret, _, _ := procRegEnumKeyEx.Call(
				uintptr(hOpenedKey),
				uintptr(index),
				uintptr(unsafe.Pointer(&keyName[0])),
				uintptr(unsafe.Pointer(&keyNameSize)),
				0,
				0,
				0,
				0,
			)
			
			if ret == ERROR_NO_MORE_ITEMS {
				break
			}
			
			if ret == ERROR_SUCCESS {
				keyNameStr := syscall.UTF16ToString(keyName[:keyNameSize])
				if keyPath != "" {
					subKeys = append(subKeys, keyPath+"\\"+keyNameStr)
				} else {
					subKeys = append(subKeys, keyNameStr)
				}
			}
			
			index++
		}
	}
	
	return subKeys
}

// deleteValueFromRecentDocs removes DLL from RecentDocs registry
func (ac *ArtifactCleaner) deleteValueFromRecentDocs(processName string) {
	recentDocsPath := `SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.dll`
	
	var hOpenedKey syscall.Handle
	ret, _, _ := procRegOpenKeyEx.Call(
		HKEY_CURRENT_USER,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(recentDocsPath))),
		0,
		KEY_ALL_ACCESS,
		uintptr(unsafe.Pointer(&hOpenedKey)),
	)
	
	if ret != ERROR_SUCCESS {
		return
	}
	defer procRegCloseKey.Call(uintptr(hOpenedKey))
	
	index := uint32(0)
	for {
		var valueName [255]uint16
		valueNameSize := uint32(len(valueName))
		var valueType uint32
		var data [1024]byte
		dataSize := uint32(len(data))
		
		ret, _, _ := procRegEnumValue.Call(
			uintptr(hOpenedKey),
			uintptr(index),
			uintptr(unsafe.Pointer(&valueName[0])),
			uintptr(unsafe.Pointer(&valueNameSize)),
			0,
			uintptr(unsafe.Pointer(&valueType)),
			uintptr(unsafe.Pointer(&data[0])),
			uintptr(unsafe.Pointer(&dataSize)),
		)
		
		if ret == ERROR_NO_MORE_ITEMS {
			break
		}
		
		if ret == ERROR_SUCCESS && valueType == REG_BINARY && dataSize%2 == 0 {
			decodedText := decodeUTF16LE(data[:dataSize])
			if strings.Contains(decodedText, processName) {
				valueNameStr := syscall.UTF16ToString(valueName[:valueNameSize])
				ret, _, _ := procRegDeleteValue.Call(
					uintptr(hOpenedKey),
					uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(valueNameStr))),
				)
				if ret == ERROR_SUCCESS {
					ac.logger.Info("Removed from RecentDocs", "process", processName)
					return
				}
			}
		}
		
		index++
	}
}

// getCurrentUserName gets the current Windows username
func getCurrentUserName() string {
	var size uint32 = 256
	var username [256]uint16
	user32 := windows.NewLazySystemDLL("user32.dll")
	getUserName := user32.NewProc("GetUserNameW")
	
	ret, _, _ := getUserName.Call(
		uintptr(unsafe.Pointer(&username[0])),
		uintptr(unsafe.Pointer(&size)),
	)
	
	if ret != 0 {
		return syscall.UTF16ToString(username[:size-1])
	}
	return ""
}

// grantAccessToKey grants full access to a registry key
func (ac *ArtifactCleaner) grantAccessToKey(hKey syscall.Handle) error {
	// This is a simplified version - full implementation would use GetSecurityInfo/SetSecurityInfo
	// For now, we'll just try to open with KEY_SET_VALUE
	return nil
}

// deleteValueFromUserAssist removes DLL from UserAssist registry
func (ac *ArtifactCleaner) deleteValueFromUserAssist(processName string) bool {
	userAssistPath := `SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist`
	foundValue := false
	
	userAssistKeys := ac.getSubKeysOfKey(HKEY_CURRENT_USER, userAssistPath)
	
	for _, key := range userAssistKeys {
		if key == "" {
			continue
		}
		key = key + `\Count`
		
		var hSubKey syscall.Handle
		ret, _, _ := procRegOpenKeyEx.Call(
			HKEY_CURRENT_USER,
			uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(key))),
			0,
			KEY_READ|KEY_SET_VALUE,
			uintptr(unsafe.Pointer(&hSubKey)),
		)
		
		if ret != ERROR_SUCCESS {
			continue
		}
		
		valueIndex := uint32(0)
		for {
			var valueName [255]uint16
			valueNameSize := uint32(len(valueName))
			var valueType uint32
			var data [1024]byte
			dataSize := uint32(len(data))
			
			ret, _, _ := procRegEnumValue.Call(
				uintptr(hSubKey),
				uintptr(valueIndex),
				uintptr(unsafe.Pointer(&valueName[0])),
				uintptr(unsafe.Pointer(&valueNameSize)),
				0,
				uintptr(unsafe.Pointer(&valueType)),
				uintptr(unsafe.Pointer(&data[0])),
				uintptr(unsafe.Pointer(&dataSize)),
			)
			
			if ret == ERROR_NO_MORE_ITEMS {
				break
			}
			
			if ret == ERROR_SUCCESS && valueType == REG_BINARY {
				valueNameBytes := make([]uint16, valueNameSize)
				copy(valueNameBytes, valueName[:valueNameSize])
				decodedText := decodeROT13(valueNameBytes)
				
				if strings.Contains(decodedText, processName) {
					valueNameStr := syscall.UTF16ToString(valueName[:valueNameSize])
					ret, _, _ := procRegDeleteValue.Call(
						uintptr(hSubKey),
						uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(valueNameStr))),
					)
					if ret == ERROR_SUCCESS {
						ac.logger.Info("Removed from UserAssist", "process", processName)
						foundValue = true
					}
				}
			}
			
			valueIndex++
		}
		
		procRegCloseKey.Call(uintptr(hSubKey))
	}
	
	return foundValue
}

// deleteValueFromBAM removes DLL from BAM registry
func (ac *ArtifactCleaner) deleteValueFromBAM(processName string) bool {
	bamPath := `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings`
	foundValue := false
	
	bamKeys := ac.getSubKeysOfKey(HKEY_LOCAL_MACHINE, bamPath)
	
	for _, key := range bamKeys {
		if key == "" {
			continue
		}
		
		var hSubKey syscall.Handle
		ret, _, _ := procRegOpenKeyEx.Call(
			HKEY_LOCAL_MACHINE,
			uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(key))),
			0,
			KEY_READ|KEY_SET_VALUE,
			uintptr(unsafe.Pointer(&hSubKey)),
		)
		
		if ret != ERROR_SUCCESS {
			continue
		}
		
		valueIndex := uint32(0)
		for {
			var valueName [255]uint16
			valueNameSize := uint32(len(valueName))
			var valueType uint32
			var data [1024]byte
			dataSize := uint32(len(data))
			
			ret, _, _ := procRegEnumValue.Call(
				uintptr(hSubKey),
				uintptr(valueIndex),
				uintptr(unsafe.Pointer(&valueName[0])),
				uintptr(unsafe.Pointer(&valueNameSize)),
				0,
				uintptr(unsafe.Pointer(&valueType)),
				uintptr(unsafe.Pointer(&data[0])),
				uintptr(unsafe.Pointer(&dataSize)),
			)
			
			if ret == ERROR_NO_MORE_ITEMS {
				break
			}
			
			if ret == ERROR_SUCCESS && valueType == REG_BINARY {
				valueNameStr := syscall.UTF16ToString(valueName[:valueNameSize])
				if strings.Contains(valueNameStr, processName) {
					ret, _, _ := procRegDeleteValue.Call(
						uintptr(hSubKey),
						uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(valueNameStr))),
					)
					if ret == ERROR_SUCCESS {
						ac.logger.Info("Removed from BAM", "process", processName)
						foundValue = true
					}
				}
			}
			
			valueIndex++
		}
		
		procRegCloseKey.Call(uintptr(hSubKey))
	}
	
	return foundValue
}

// deleteValueFromShellBags removes DLL from Shell Bags registry
func (ac *ArtifactCleaner) deleteValueFromShellBags(processName string) bool {
	shellBagsPath := `SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU`
	shellBagsPath2 := `Local Settings\Software\Microsoft\Windows\Shell\BagMRU`
	foundValue := false
	
	processedKeys := make(map[string]bool)
	
	var processRegistryKey func(uintptr, string)
	processRegistryKey = func(rootKey uintptr, keyPath string) {
		if processedKeys[keyPath] {
			return
		}
		processedKeys[keyPath] = true
		
		subKeys := ac.getSubKeysOfKey(rootKey, keyPath)
		subKeys = append(subKeys, keyPath)
		
		for _, key := range subKeys {
			var hOpenedKey syscall.Handle
			ret, _, _ := procRegOpenKeyEx.Call(
				rootKey,
				uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(key))),
				0,
				KEY_READ|KEY_SET_VALUE,
				uintptr(unsafe.Pointer(&hOpenedKey)),
			)
			
			if ret != ERROR_SUCCESS {
				continue
			}
			
			index := uint32(0)
			for {
				var valueName [255]uint16
				valueNameSize := uint32(len(valueName))
				var valueType uint32
				var data [1024]byte
				dataSize := uint32(len(data))
				
				ret, _, _ := procRegEnumValue.Call(
					uintptr(hOpenedKey),
					uintptr(index),
					uintptr(unsafe.Pointer(&valueName[0])),
					uintptr(unsafe.Pointer(&valueNameSize)),
					0,
					uintptr(unsafe.Pointer(&valueType)),
					uintptr(unsafe.Pointer(&data[0])),
					uintptr(unsafe.Pointer(&dataSize)),
				)
				
				if ret == ERROR_NO_MORE_ITEMS {
					break
				}
				
				if ret == ERROR_SUCCESS && valueType == REG_BINARY {
					stringArray := binaryToWString(data[:dataSize])
					if strings.Contains(stringArray, processName) {
						valueNameStr := syscall.UTF16ToString(valueName[:valueNameSize])
						ret, _, _ := procRegDeleteValue.Call(
							uintptr(hOpenedKey),
							uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(valueNameStr))),
						)
						if ret == ERROR_SUCCESS {
							ac.logger.Info("Removed from Shell Bags", "process", processName)
							foundValue = true
						}
					}
				}
				
				index++
			}
			
			procRegCloseKey.Call(uintptr(hOpenedKey))
			processRegistryKey(rootKey, key)
		}
	}
	
	processRegistryKey(HKEY_CURRENT_USER, shellBagsPath)
	processRegistryKey(HKEY_CLASSES_ROOT, shellBagsPath2)
	
	return foundValue
}

// deleteFileFromPrefetch removes DLL from Prefetch directory
func (ac *ArtifactCleaner) deleteFileFromPrefetch(fileName string) {
	prefetchPath := `C:\Windows\Prefetch`
	
	entries, err := os.ReadDir(prefetchPath)
	if err != nil {
		return
	}
	
	upperFileName := strings.ToUpper(fileName)
	
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		
		if filepath.Ext(entry.Name()) == ".pf" {
			upperEntryName := strings.ToUpper(entry.Name())
			if strings.Contains(upperEntryName, upperFileName) {
				fullPath := filepath.Join(prefetchPath, entry.Name())
				if err := os.Remove(fullPath); err == nil {
					ac.logger.Info("Removed from Prefetch", "file", entry.Name())
					return
				}
			}
		}
	}
}

// deleteFileFromRecent removes DLL from Recent files directory
func (ac *ArtifactCleaner) deleteFileFromRecent(fileName string) {
	var pathPtr uintptr
	ret, _, _ := procSHGetKnownFolderPath.Call(
		uintptr(unsafe.Pointer(&[16]byte{0xDB, 0x85, 0xB6, 0x3E, 0x65, 0xF9, 0x4C, 0xF6, 0xA0, 0x3A, 0xE3, 0xEF, 0x65, 0x72, 0x9F, 0x3D})), // FOLDERID_RoamingAppData
		0,
		0,
		uintptr(unsafe.Pointer(&pathPtr)),
	)
	
	if ret != 0 {
		return
	}
	
	defer func() {
		ole32 := windows.NewLazySystemDLL("ole32.dll")
		coTaskMemFree := ole32.NewProc("CoTaskMemFree")
		coTaskMemFree.Call(pathPtr)
	}()
	
	path := syscall.UTF16ToString((*[260]uint16)(unsafe.Pointer(pathPtr))[:])
	recentPath := filepath.Join(path, "Microsoft", "Windows", "Recent")
	
	entries, err := os.ReadDir(recentPath)
	if err != nil {
		return
	}
	
	upperFileName := strings.ToUpper(fileName)
	
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		
		upperEntryName := strings.ToUpper(entry.Name())
		if strings.Contains(upperEntryName, upperFileName) {
			fullPath := filepath.Join(recentPath, entry.Name())
			if err := os.Remove(fullPath); err == nil {
				ac.logger.Info("Removed from Recent", "file", entry.Name())
				return
			}
		}
	}
}

