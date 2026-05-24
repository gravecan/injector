package ui

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"image/color"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/AllenDang/giu"
	"jector/internal/injector"
	"jector/internal/process"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

type Application struct {
	title       string
	width       int32
	height      int32
	processInfo *process.Info
	processes   []process.ProcessEntry
	logger      *zap.Logger

	selectedDllPath     string
	selectedPID         int32
	selectedProcessName string
	searchText          string
	logText             string
	logLines            []string
	maxLogLines         int

	injectionMethod int32
	methodNames     []string

	memoryLoad             bool
	peHeaderErasure        bool
	entryPointErase        bool
	manualMapping          bool
	invisibleMemory        bool
	pathSpoofing           bool
	legitProcessInjection  bool
	pteSpoofing            bool
	vadManipulation        bool
	removeVADNode          bool
	allocBehindThreadStack bool
	directSyscalls         bool

	randomizeAllocation  bool
	delayedExecution     bool
	multiStageInjection  bool
	antiDebugTechniques  bool
	processHollowing     bool
	atomBombing          bool
	doppelgangingProcess bool
	ghostWriting         bool
	moduleStomping       bool
	threadHijacking      bool
	apcQueueing          bool
	memoryFluctuation    bool
	antiVMTechniques     bool
	processMirroring     bool
	stealthyThreads      bool

	showAboutDialog    bool
	showHelpDialog     bool
	showConfirmDialog  bool
	showProgressDialog bool
	showSuccessDialog  bool
	showProcessDialog  bool
	confirmDialogText  string
	progressText       string
	successText        string
	selectedTab        int32
	processSearchText  string

	allowedDLLHashes []string
	journalStatus    string
	cleanerStatus    string

	injectionResultChan chan InjectionResult
	logMessageChan      chan string
	uiUpdateChan        chan func()

	mu sync.RWMutex
}

type InjectionResult struct {
	Success bool
	Error   error
	Message string
}

type LoggerAdapter struct {
	logger *zap.Logger
}

func (l *LoggerAdapter) Info(msg string, fields ...interface{}) {
	zapFields := convertToZapFields(fields...)
	l.logger.Info(msg, zapFields...)
}

func (l *LoggerAdapter) Error(msg string, fields ...interface{}) {
	zapFields := convertToZapFields(fields...)
	l.logger.Error(msg, zapFields...)
}

func (l *LoggerAdapter) Warn(msg string, fields ...interface{}) {
	zapFields := convertToZapFields(fields...)
	l.logger.Warn(msg, zapFields...)
}

func (l *LoggerAdapter) Debug(msg string, fields ...interface{}) {
	zapFields := convertToZapFields(fields...)
	l.logger.Debug(msg, zapFields...)
}

func convertToZapFields(fields ...interface{}) []zap.Field {
	zapFields := make([]zap.Field, 0, len(fields)/2)
	for i := 0; i < len(fields)-1; i += 2 {
		if key, ok := fields[i].(string); ok {
			zapFields = append(zapFields, zap.Any(key, fields[i+1]))
		}
	}
	return zapFields
}

var emojiTextMap = map[string]string{
	"✅":  "[OK]",
	"❌":  "[ERROR]",
	"⚠️": "[WARN]",
	"🚫":  "[BLOCKED]",
	"🔄":  "[REFRESH]",
	"☐":  "[ ]",
	"🛡️": "[SHIELD]",
}

func NewApplication(title string, width, height int) *Application {
	app := &Application{
		title:       title,
		width:       int32(width),
		height:      int32(height),
		processInfo: process.NewInfo(),
		selectedPID: -1,
		maxLogLines: 1000,
		methodNames: []string{
			"Standard Injection",
		},

		pathSpoofing:   true,
		vadManipulation: true,
		directSyscalls: true,

		allowedDLLHashes: []string{
			"a45f35c14e0eb0acab85a0c2a8b2961ed9419ab5bd6c75f4da4f8470f6df8954",
			"81174926ede5cc97812ee6fdedb6335c538823d48f336cf89b98f69599ba0b6f",
		"b1d1070cd56729d24d1c3b9c24c243b2dd96267f5d8c5e6438e779d2d371bbb4",
		"399515997527010358aa05fbe10b3b33efe4d6247fffbc625728f2241d0bb378",
	
	
	},
		journalStatus: "Unknown",
		cleanerStatus: "Pending (will run after successful injection)",
		injectionResultChan: make(chan InjectionResult, 10),
		logMessageChan:      make(chan string, 100),
		uiUpdateChan:        make(chan func(), 50),
	}

	app.setupLogger()

	app.refreshProcessList()

	return app
}

func (app *Application) isOptionCompatible(option string) bool {
	method := app.injectionMethod


	switch option {
	case "memory_load":

		return method == 0

	case "manual_mapping":

		return method == 0

	case "pe_header_erasure":

		return method == 0

	case "entry_point_erasure":

		return method == 0

	case "invisible_memory":

		return method == 0

	case "path_spoofing":

		return method == 0

	case "legit_process":

		return method == 0

	case "pte_spoofing":

		return method == 0

	case "vad_manipulation":

		return method == 0

	case "remove_vad_node":

		return method == 0

	case "thread_stack_allocation":

		return method == 0

	case "direct_syscalls":

		return true

	case "skip_dllmain":

		return true

	case "randomize_allocation", "delayed_execution", "multi_stage_injection":

		return method == 0

	case "anti_debug", "anti_vm":

		return true

	case "process_hollowing", "thread_hijacking":

		return method == 0

	case "memory_fluctuation":

		return method == 0

	case "atom_bombing":

		return method == 0

	case "doppelganging_process":

		return method == 0

	case "ghost_writing":

		return method == 0

	case "module_stomping":

		return method == 0

	case "apc_queueing":

		return false

	case "process_mirroring":

		return method == 0

	case "stealthy_threads":

		return method == 0

	default:

		return true
	}
}

func (app *Application) checkMutualExclusivity(option string) (bool, string) {
	switch option {
	case "memory_load":
		if app.pathSpoofing {
			return false, "Memory Load is incompatible with Path Spoofing (memory-only vs disk-based)"
		}
		if app.manualMapping {
			return false, "Memory Load already includes Manual Mapping functionality"
		}

	case "manual_mapping":
		if app.memoryLoad {
			return false, "Manual Mapping is redundant when Memory Load is enabled"
		}
		if app.pathSpoofing {
			return false, "Manual Mapping is incompatible with Path Spoofing (memory-only vs disk-based)"
		}

	case "path_spoofing":
		if app.memoryLoad {
			return false, "Path Spoofing is incompatible with Memory Load (disk-based vs memory-only)"
		}
		if app.manualMapping {
			return false, "Path Spoofing is incompatible with Manual Mapping (disk-based vs memory-only)"
		}

	case "pe_header_erasure":
		if app.pathSpoofing {
			return false, "PE Header Erasure may conflict with disk-based Path Spoofing"
		}

	case "entry_point_erasure":
		if app.pathSpoofing {
			return false, "Entry Point Erasure may conflict with disk-based Path Spoofing"
		}

	case "vad_manipulation":
		if app.removeVADNode {
			return false, "VAD Manipulation conflicts with Remove VAD Node (overlapping functionality)"
		}
		if app.pteSpoofing {
			return false, "VAD Manipulation may conflict with PTE Spoofing (both modify memory structures)"
		}

	case "remove_vad_node":
		if app.vadManipulation {
			return false, "Remove VAD Node conflicts with VAD Manipulation (overlapping functionality)"
		}

	case "pte_spoofing":
		if app.vadManipulation {
			return false, "PTE Spoofing may conflict with VAD Manipulation (both modify memory structures)"
		}

	case "process_hollowing":
		if app.threadHijacking {
			return false, "Process Hollowing and Thread Hijacking are alternative techniques"
		}
		if app.doppelgangingProcess {
			return false, "Process Hollowing and Process Doppelganging are alternative process manipulation techniques"
		}

	case "thread_hijacking":
		if app.processHollowing {
			return false, "Thread Hijacking and Process Hollowing are alternative techniques"
		}

	case "atom_bombing":
		if app.apcQueueing {
			return false, "Atom Bombing and APC Queueing may conflict (both use APC mechanisms)"
		}

	case "doppelganging_process":
		if app.processHollowing {
			return false, "Process Doppelganging and Process Hollowing are alternative process manipulation techniques"
		}
		if app.processMirroring {
			return false, "Process Doppelganging and Process Mirroring are alternative process techniques"
		}

	case "ghost_writing":
		if app.moduleStomping {
			return false, "Ghost Writing and Module Stomping are alternative memory manipulation techniques"
		}

	case "module_stomping":
		if app.ghostWriting {
			return false, "Module Stomping and Ghost Writing are alternative memory manipulation techniques"
		}

	case "apc_queueing":
		if app.atomBombing {
			return false, "APC Queueing and Atom Bombing may conflict (both use APC mechanisms)"
		}

	case "process_mirroring":
		if app.doppelgangingProcess {
			return false, "Process Mirroring and Process Doppelganging are alternative process techniques"
		}
	}

	return true, ""
}

func (app *Application) getOptionWarnings(option string) []string {
	var warnings []string

	switch option {
	case "pe_header_erasure":
		if app.injectionMethod == 0 {
			warnings = append(warnings, "PE Header Erasure with Standard injection may affect stability")
		}

	case "entry_point_erasure":
		if app.injectionMethod == 0 {
			warnings = append(warnings, "Entry Point Erasure with Standard injection may affect stability")
		}

	case "invisible_memory":


	case "legit_process":


	case "skip_dllmain":
		warnings = append(warnings, "Skipping DllMain may prevent proper DLL initialization")

	case "vad_manipulation":
		if app.pteSpoofing {
			warnings = append(warnings, "Using both VAD Manipulation and PTE Spoofing may be excessive")
		}
	}

	return warnings
}

func (app *Application) buildCompatibleCheckbox(label string, option string, value *bool) giu.Widget {
	return app.buildEnhancedCheckbox(label, option, value, false)
}

func (app *Application) buildEnhancedCheckbox(label string, option string, value *bool, showWarnings bool) giu.Widget {
	isCompatible := app.isOptionCompatible(option)
	isExclusive, exclusivityReason := app.checkMutualExclusivity(option)
	warnings := app.getOptionWarnings(option)

	var tooltipLines []string

	if !isCompatible {
		tooltipLines = append(tooltipLines, fmt.Sprintf("%s %s is not compatible with %s injection", app.getEmojiText("❌"), label, app.methodNames[app.injectionMethod]))

		*value = false
	} else if !isExclusive {
		tooltipLines = append(tooltipLines, fmt.Sprintf("%s %s", app.getEmojiText("🚫"), exclusivityReason))

		*value = false
	} else {
		tooltipLines = append(tooltipLines, fmt.Sprintf("%s %s is compatible with %s injection", app.getEmojiText("✅"), label, app.methodNames[app.injectionMethod]))
	}

	if showWarnings && len(warnings) > 0 {
		for _, warning := range warnings {
			tooltipLines = append(tooltipLines, fmt.Sprintf("%s %s", app.getEmojiText("⚠️"), warning))
		}
	}

	tooltip := strings.Join(tooltipLines, "\n")

	if !isCompatible {

		return giu.Style().
			SetColor(giu.StyleColorText, color.RGBA{R: 100, G: 100, B: 100, A: 255}).
			SetColor(giu.StyleColorCheckMark, color.RGBA{R: 100, G: 100, B: 100, A: 255}).
			SetColor(giu.StyleColorFrameBg, color.RGBA{R: 40, G: 40, B: 40, A: 255}).To(
			giu.Row(
				giu.Label(fmt.Sprintf("%s %s", app.getEmojiText("☐"), label)),
				giu.Tooltip(tooltip),
			),
		)
	} else if !isExclusive {

		return giu.Style().
			SetColor(giu.StyleColorText, color.RGBA{R: 180, G: 100, B: 100, A: 255}).
			SetColor(giu.StyleColorCheckMark, color.RGBA{R: 180, G: 100, B: 100, A: 255}).
			SetColor(giu.StyleColorFrameBg, color.RGBA{R: 50, G: 30, B: 30, A: 255}).To(
			giu.Row(
				giu.Label(fmt.Sprintf("%s %s", app.getEmojiText("🚫"), label)),
				giu.Tooltip(tooltip),
			),
		)
	} else if len(warnings) > 0 && showWarnings {

		return giu.Style().
			SetColor(giu.StyleColorText, color.RGBA{R: 200, G: 180, B: 100, A: 255}).To(
			giu.Row(
				giu.Checkbox(fmt.Sprintf("%s %s", app.getEmojiText("⚠️"), label), value),
				giu.Tooltip(tooltip),
			),
		)
	} else {

		return giu.Row(
			giu.Checkbox(label, value),
			giu.Tooltip(tooltip),
		)
	}
}

func (app *Application) buildSmartCheckbox(label string, option string, value *bool) giu.Widget {
	checkbox := app.buildEnhancedCheckbox(label, option, value, true)

	if app.isOptionCompatible(option) {
		if isExclusive, _ := app.checkMutualExclusivity(option); isExclusive {
			return giu.Row(
				checkbox,
				giu.Custom(func() {

					if *value {
						app.handleMutualExclusivity(option)
					}
				}),
			)
		}
	}

	return checkbox
}

func (app *Application) handleMutualExclusivity(enabledOption string) {
	switch enabledOption {
	case "memory_load":
		if app.pathSpoofing {
			app.pathSpoofing = false
			app.addLogLine("Auto-disabled Path Spoofing (incompatible with Memory Load)")
		}
		if app.manualMapping {
			app.manualMapping = false
			app.addLogLine("Auto-disabled Manual Mapping (redundant with Memory Load)")
		}

	case "manual_mapping":
		if app.pathSpoofing {
			app.pathSpoofing = false
			app.addLogLine("Auto-disabled Path Spoofing (incompatible with Manual Mapping)")
		}

	case "path_spoofing":
		if app.memoryLoad {
			app.memoryLoad = false
			app.addLogLine("Auto-disabled Memory Load (incompatible with Path Spoofing)")
		}
		if app.manualMapping {
			app.manualMapping = false
			app.addLogLine("Auto-disabled Manual Mapping (incompatible with Path Spoofing)")
		}

	case "vad_manipulation":
		if app.removeVADNode {
			app.removeVADNode = false
			app.addLogLine("Auto-disabled Remove VAD Node (conflicts with VAD Manipulation)")
		}

	case "remove_vad_node":
		if app.vadManipulation {
			app.vadManipulation = false
			app.addLogLine("Auto-disabled VAD Manipulation (conflicts with Remove VAD Node)")
		}

	case "process_hollowing":
		if app.threadHijacking {
			app.threadHijacking = false
			app.addLogLine("Auto-disabled Thread Hijacking (alternative to Process Hollowing)")
		}

	case "thread_hijacking":
		if app.processHollowing {
			app.processHollowing = false
			app.addLogLine("Auto-disabled Process Hollowing (alternative to Thread Hijacking)")
		}
	}
}

func (app *Application) setupLogger() {
	encoderConfig := zapcore.EncoderConfig{
		TimeKey:        "time",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		MessageKey:     "msg",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.CapitalLevelEncoder,
		EncodeTime:     zapcore.TimeEncoderOfLayout("15:04:05"),
		EncodeDuration: zapcore.StringDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	core := zapcore.NewCore(
		zapcore.NewConsoleEncoder(encoderConfig),
		zapcore.AddSync(&logWriter{app: app}),
		zapcore.InfoLevel,
	)

	app.logger = zap.New(core)

	loggerAdapter := &LoggerAdapter{logger: app.logger}
	injector.SetLogger(loggerAdapter)
}

type logWriter struct {
	app *Application
}

func (lw *logWriter) Write(p []byte) (n int, err error) {
	text := strings.TrimSpace(string(p))
	if text != "" {
		lw.app.addLogLine(text)
	}
	return len(p), nil
}

func (app *Application) addLogLine(line string) {

	select {
	case app.logMessageChan <- line:

	default:

		app.addLogLineImmediate(line)
	}
}

func (app *Application) addLogLineImmediate(line string) {
	app.mu.Lock()
	defer app.mu.Unlock()

	app.logLines = append(app.logLines, line)
	if len(app.logLines) > app.maxLogLines {
		app.logLines = app.logLines[1:]
	}

	app.logText = strings.Join(app.logLines, "\n")
}

func (app *Application) processUIUpdates() {

	for {
		select {
		case logMsg := <-app.logMessageChan:
			app.addLogLineImmediate(logMsg)
		default:
			goto processFuncUpdates
		}
	}

processFuncUpdates:

	for {
		select {
		case updateFunc := <-app.uiUpdateChan:
			updateFunc()
		default:
			return
		}
	}
}

func (app *Application) scheduleUIUpdate(updateFunc func()) {
	select {
	case app.uiUpdateChan <- updateFunc:

	default:

		updateFunc()
	}
}

func (app *Application) refreshProcessList() {
	if err := app.processInfo.Refresh(); err != nil {
		app.logger.Error("Failed to refresh process list", zap.Error(err))
		return
	}

	app.mu.Lock()
	app.processes = app.processInfo.GetProcesses()
	app.mu.Unlock()

	app.logger.Info("Process list refreshed", zap.Int("count", len(app.processes)))
}

func (app *Application) Run() error {
	app.logger.Info("Starting GUI application", zap.String("title", app.title), zap.Int32("width", app.width), zap.Int32("height", app.height))

	wnd := giu.NewMasterWindow(app.title, int(app.width), int(app.height), giu.MasterWindowFlagsNotResizable)

	app.setupFonts()

	app.logger.Info("Master window created, starting main loop...")

	app.addLogLine("DLL Injector started")
	app.addLogLine("Click 'Select Process' to choose target process")

	wnd.Run(app.loop)

	app.logger.Info("GUI application finished")
	return nil
}

func (app *Application) setupFonts() {
	app.logger.Info("Font support removed from application")
}

func (app *Application) monitorFontLoading() {

}

func (app *Application) getEmojiText(emoji string) string {
	if fallback, exists := emojiTextMap[emoji]; exists {
		return fallback
	}
	return emoji
}

func (app *Application) Log() *zap.Logger {
	return app.logger
}

func (app *Application) loop() {

	app.pathSpoofing = true
	app.vadManipulation = true
	app.directSyscalls = true

	app.processUIUpdates()

	select {
	case result := <-app.injectionResultChan:
		app.handleInjectionResult(result)
	default:

	}

	giu.SingleWindow().Layout(
		giu.Style().SetStyle(giu.StyleVarWindowPadding, 15, 15).To(
			giu.Column(

				app.buildFontLoadingProgress(),

				app.buildTopRow(),
				giu.Spacing(),
				giu.Spacing(),

				app.buildInjectionMethodSection(),
				giu.Spacing(),
				giu.Spacing(),

				app.buildAntiDetectionSection(),
				giu.Spacing(),
				giu.Spacing(),

				app.buildInjectButton(),
				giu.Spacing(),

				app.buildConsoleLogsSection(),
			),
		),
	)

	app.buildProcessSelectionDialog()
	app.buildDialogs()
}

func (app *Application) handleInjectionResult(result InjectionResult) {
	app.logger.Info("=== Handling injection result ===", zap.Bool("success", result.Success))

	app.showProgressDialog = false

	if result.Success {
		app.addLogLineImmediate(fmt.Sprintf("%s Injection successful!", app.getEmojiText("✅")))
		app.logger.Info("Setting success dialog to true")

		app.successText = result.Message
		app.showSuccessDialog = true

		app.logger.Info("Success dialog should now be visible", zap.Bool("showSuccessDialog", app.showSuccessDialog))
	} else {
		if result.Error != nil {
			app.addLogLineImmediate(fmt.Sprintf("%s Injection failed: %v", app.getEmojiText("❌"), result.Error))
			app.logger.Error("Injection failed", zap.Error(result.Error))
		} else {
			app.addLogLineImmediate(fmt.Sprintf("%s Injection failed: Unknown error", app.getEmojiText("❌")))
			app.logger.Error("Injection failed with unknown error")
		}
	}
}

func (app *Application) buildTopRow() giu.Widget {
	processText := "No Process Selected"
	if app.selectedPID > 0 {
		processText = fmt.Sprintf("PID: %d - %s", app.selectedPID, app.selectedProcessName)
	}

	return giu.Row(

		giu.Column(
			giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 170, G: 170, B: 170, A: 255}).To(
				giu.Label("DLL File:"),
			),
			giu.Row(
				giu.Style().SetColor(giu.StyleColorFrameBg, color.RGBA{R: 50, G: 50, B: 50, A: 255}).To(
					giu.InputText(&app.selectedDllPath).Hint("Select DLL file path...").Size(380),
				),
				giu.Style().SetColor(giu.StyleColorButton, color.RGBA{R: 80, G: 80, B: 80, A: 255}).To(
					giu.Button("Browse").Size(80, 0).OnClick(func() {
						app.addLogLine("Opening Windows file dialog...")
						go app.openNativeFileDialog()
					}),
				),
			),
		),

		giu.Dummy(50, 0),

		giu.Column(
			giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 170, G: 170, B: 170, A: 255}).To(
				giu.Label("Target Process:"),
			),
			giu.Row(
				giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 140, G: 140, B: 140, A: 255}).To(
					giu.Label(processText),
				),
				giu.Style().SetColor(giu.StyleColorButton, color.RGBA{R: 80, G: 80, B: 80, A: 255}).To(
					giu.Button("Select Process").OnClick(func() {
						app.addLogLine("Opening process selection...")
						app.refreshProcessList()
						app.showProcessDialog = true
					}),
				),
			),
		),
	)
}

func (app *Application) buildInjectionMethodSection() giu.Widget {
	return giu.Column(
		giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 170, G: 170, B: 170, A: 255}).To(
			giu.Label("Injection Method:"),
		),
		giu.Spacing(),
		giu.Row(
			giu.Style().SetColor(giu.StyleColorCheckMark, color.RGBA{R: 0, G: 122, B: 204, A: 255}).To(
				giu.RadioButton("Standard", app.injectionMethod == 0).OnChange(func() {
					app.injectionMethod = 0
					app.addLogLine("Injection method selected: Standard Injection")
				}),
			),
		),
	)
}

func (app *Application) buildAntiDetectionSection() giu.Widget {
	return giu.Column(
		giu.Row(
			giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 170, G: 170, B: 170, A: 255}).To(
				giu.Label(">> Anti-Detection Options"),
			),
		),
		giu.Spacing(),

		giu.Row(
			giu.Style().SetColor(giu.StyleColorButton, func() color.RGBA {
				if app.selectedTab == 0 {
					return color.RGBA{R: 0, G: 122, B: 204, A: 255}
				}
				return color.RGBA{R: 80, G: 80, B: 80, A: 255}
			}()).To(
				giu.Style().SetColor(giu.StyleColorText, func() color.RGBA {
					if app.selectedTab == 0 {
						return color.RGBA{R: 255, G: 255, B: 255, A: 255}
					}
					return color.RGBA{R: 200, G: 200, B: 200, A: 255}
				}()).To(
					giu.Button("Basic").Size(100, 30).OnClick(func() {
						app.selectedTab = 0
					}),
				),
			),
			giu.Style().SetColor(giu.StyleColorButton, func() color.RGBA {
				if app.selectedTab == 1 {
					return color.RGBA{R: 0, G: 122, B: 204, A: 255}
				}
				return color.RGBA{R: 80, G: 80, B: 80, A: 255}
			}()).To(
				giu.Style().SetColor(giu.StyleColorText, func() color.RGBA {
					if app.selectedTab == 1 {
						return color.RGBA{R: 255, G: 255, B: 255, A: 255}
					}
					return color.RGBA{R: 200, G: 200, B: 200, A: 255}
				}()).To(
					giu.Button("Advanced").Size(120, 30).OnClick(func() {
						app.selectedTab = 1
					}),
				),
			),
			giu.Style().SetColor(giu.StyleColorButton, func() color.RGBA {
				if app.selectedTab == 2 {
					return color.RGBA{R: 0, G: 122, B: 204, A: 255}
				}
				return color.RGBA{R: 80, G: 80, B: 80, A: 255}
			}()).To(
				giu.Style().SetColor(giu.StyleColorText, func() color.RGBA {
					if app.selectedTab == 2 {
						return color.RGBA{R: 255, G: 255, B: 255, A: 255}
					}
					return color.RGBA{R: 200, G: 200, B: 200, A: 255}
				}()).To(
					giu.Button("Journal Bypass").Size(140, 30).OnClick(func() {
						app.selectedTab = 2
						app.checkJournalStatus()
					}),
				),
			),
			giu.Style().SetColor(giu.StyleColorButton, func() color.RGBA {
				if app.selectedTab == 3 {
					return color.RGBA{R: 0, G: 122, B: 204, A: 255}
				}
				return color.RGBA{R: 80, G: 80, B: 80, A: 255}
			}()).To(
				giu.Style().SetColor(giu.StyleColorText, func() color.RGBA {
					if app.selectedTab == 3 {
						return color.RGBA{R: 255, G: 255, B: 255, A: 255}
					}
					return color.RGBA{R: 200, G: 200, B: 200, A: 255}
				}()).To(
					giu.Button("Cleaner").Size(120, 30).OnClick(func() {
						app.selectedTab = 3
						app.checkCleanerStatus()
					}),
				),
			),
		),
		giu.Spacing(),

		app.buildTabContent(),
	)
}

func (app *Application) buildTabContent() giu.Widget {
	switch app.selectedTab {
	case 0:
		app.pathSpoofing = true
		app.vadManipulation = true
		app.directSyscalls = true

		return giu.Column(
			giu.Row(
				giu.Column(
					giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 0, G: 200, B: 0, A: 255}).To(
						giu.Label("✓ Path Spoofing (Always Enabled)"),
					),
				),
				giu.Dummy(80, 0),
				giu.Column(
					giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 0, G: 200, B: 0, A: 255}).To(
						giu.Label("✓ VAD Manipulation (Always Enabled)"),
					),
				),
				giu.Dummy(80, 0),
				giu.Column(
					giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 0, G: 200, B: 0, A: 255}).To(
						giu.Label("✓ Direct Syscalls (Always Enabled)"),
					),
				),
			),
		)
	case 1:
		return giu.Column(
			giu.Label("Advanced options (not implemented)"),
		)
	case 2:
		return app.buildJournalBypassTab()
	case 3:
		return app.buildCleanerTab()
	default:
		return giu.Label("Unknown tab")
	}
}

func (app *Application) buildJournalBypassTab() giu.Widget {
	if app.journalStatus == "" {
		app.checkJournalStatus()
	}

	statusColor := color.RGBA{R: 0, G: 200, B: 0, A: 255}
	if strings.Contains(strings.ToLower(app.journalStatus), "enabled") {
		statusColor = color.RGBA{R: 200, G: 0, B: 0, A: 255}
	}

	return giu.Column(
		giu.Spacing(),
		giu.Row(
			giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 170, G: 170, B: 170, A: 255}).To(
				giu.Label("Current Status:"),
			),
			giu.Dummy(20, 0),
			giu.Style().SetColor(giu.StyleColorText, statusColor).To(
				giu.Label(app.journalStatus),
			),
		),
		giu.Spacing(),
		giu.Row(
			giu.Style().SetColor(giu.StyleColorButton, color.RGBA{R: 0, G: 122, B: 204, A: 255}).To(
				giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 255, G: 255, B: 255, A: 255}).To(
					giu.Button("Enable Journal").Size(150, 35).OnClick(func() {
						app.enableJournal()
					}),
				),
			),
			giu.Dummy(20, 0),
			giu.Style().SetColor(giu.StyleColorButton, color.RGBA{R: 200, G: 0, B: 0, A: 255}).To(
				giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 255, G: 255, B: 255, A: 255}).To(
					giu.Button("Disable Journal").Size(150, 35).OnClick(func() {
						app.disableJournal()
					}),
				),
			),
		),
		giu.Spacing(),
		giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 150, G: 150, B: 150, A: 255}).To(
			giu.Label("Note: Registry changes require reboot to take full effect"),
		),
	)
}

func (app *Application) buildCleanerTab() giu.Widget {
	if app.cleanerStatus == "" {
		app.checkCleanerStatus()
	}

	return giu.Column(
		giu.Spacing(),
		giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 170, G: 170, B: 170, A: 255}).To(
			giu.Label("Cleaner will run automatically 5 seconds after a successful injection."),
		),
		giu.Spacing(),
		giu.Row(
			giu.Style().SetColor(giu.StyleColorButton, color.RGBA{R: 0, G: 122, B: 204, A: 255}).To(
				giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 255, G: 255, B: 255, A: 255}).To(
					giu.Button("Run Cleaner Now").Size(160, 35).OnClick(func() {
						app.runCleanerAsync(app.selectedDllPath)
					}),
				),
			),
			giu.Dummy(20, 0),
			giu.Style().SetColor(giu.StyleColorButton, color.RGBA{R: 80, G: 80, B: 80, A: 255}).To(
				giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 220, G: 220, B: 220, A: 255}).To(
					giu.Button("Refresh Status").Size(160, 35).OnClick(func() {
						app.checkCleanerStatus()
					}),
				),
			),
		),
		giu.Spacing(),
		giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 0, G: 200, B: 0, A: 255}).To(
			giu.Label(app.cleanerStatus),
		),
		giu.Spacing(),
		giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 150, G: 150, B: 150, A: 255}).To(
			giu.Label("Hardcoded cleanup targets:"),
		),
		giu.Label("- Explorer Recent Items entries for the injected DLL"),
		giu.Label("- Jump List cache entries matching the DLL name"),
		giu.Label("- RunMRU entries containing the DLL path"),
	)
}

func (app *Application) buildInjectButton() giu.Widget {
	return giu.Style().SetColor(giu.StyleColorButton, color.RGBA{R: 0, G: 122, B: 204, A: 255}).To(
		giu.Style().SetColor(giu.StyleColorButtonHovered, color.RGBA{R: 0, G: 140, B: 230, A: 255}).To(
			giu.Style().SetColor(giu.StyleColorButtonActive, color.RGBA{R: 0, G: 100, B: 180, A: 255}).To(
				giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 255, G: 255, B: 255, A: 255}).To(
					giu.Button("Inject").Size(-1, 45).OnClick(func() {
						app.onInjectClicked()
					}),
				),
			),
		),
	)
}

func (app *Application) buildConsoleLogsSection() giu.Widget {
	app.mu.RLock()
	logText := app.logText
	app.mu.RUnlock()

	return giu.Column(

		giu.Row(
			giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 170, G: 170, B: 170, A: 255}).To(
				giu.Label("Console Logs"),
			),
			giu.Dummy(-1, 0),
			giu.Style().SetColor(giu.StyleColorButton, color.RGBA{R: 80, G: 80, B: 80, A: 255}).To(
				giu.Button("Home").Size(50, 25).OnClick(func() {

				}),
			),
		),
		giu.Spacing(),

		giu.Style().SetColor(giu.StyleColorFrameBg, color.RGBA{R: 25, G: 25, B: 25, A: 255}).To(
			giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 180, G: 180, B: 180, A: 255}).To(
				giu.InputTextMultiline(&logText).Size(-1, -1).Flags(giu.InputTextFlagsReadOnly),
			),
		),
	)
}

func (app *Application) clearAllOptions() {

	app.pathSpoofing = true
	app.vadManipulation = true
	app.directSyscalls = true
}

func (app *Application) buildProcessSelectionDialog() {
	if !app.showProcessDialog {
		return
	}

	giu.Window("Select Target Process").
		IsOpen(&app.showProcessDialog).
		Size(880, 500).
		Flags(giu.WindowFlagsNoResize | giu.WindowFlagsNoCollapse).
		Layout(
			giu.Column(

				giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 0, G: 122, B: 204, A: 255}).To(
					giu.Label("Select Target Process for DLL Injection"),
				),
				giu.Separator(),
				giu.Spacing(),

				giu.Row(
					giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 170, G: 170, B: 170, A: 255}).To(
						giu.Label("Search:"),
					),
					giu.InputText(&app.processSearchText).Hint("Type process name, PID, or path...").Size(380),
					giu.Button("Refresh List").OnClick(func() {
						app.refreshProcessList()
						app.addLogLine("Process list refreshed")
					}),
				),
				giu.Spacing(),

				giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 200, G: 200, B: 200, A: 255}).To(
					giu.Row(
						giu.Label("PID"),
						giu.Dummy(80, 0),
						giu.Label("Process Name"),
						giu.Dummy(150, 0),
						giu.Label("Executable Path"),
						giu.Dummy(300, 0),
						giu.Label("Action"),
					),
				),
				giu.Separator(),

				giu.Child().Size(-1, 300).Layout(
					app.buildProcessListContent(),
				),

				giu.Spacing(),

				giu.Row(
					giu.Style().SetColor(giu.StyleColorButton, color.RGBA{R: 80, G: 80, B: 80, A: 255}).To(
						giu.Button("Cancel").Size(100, 30).OnClick(func() {
							app.showProcessDialog = false
							app.processSearchText = ""
							app.addLogLine("Process selection cancelled")
						}),
					),
				),
			),
		)
}

func (app *Application) buildProcessListContent() giu.Widget {
	app.mu.RLock()
	processes := make([]process.ProcessEntry, len(app.processes))
	copy(processes, app.processes)
	app.mu.RUnlock()

	var filteredProcesses []process.ProcessEntry
	searchLower := strings.ToLower(app.processSearchText)

	for _, proc := range processes {
		if searchLower == "" ||
			strings.Contains(strings.ToLower(proc.Name), searchLower) ||
			strings.Contains(strings.ToLower(proc.Executable), searchLower) ||
			strings.Contains(strconv.FormatInt(int64(proc.PID), 10), searchLower) {
			filteredProcesses = append(filteredProcesses, proc)
		}
	}

	maxProcesses := 50
	if len(filteredProcesses) > maxProcesses {
		filteredProcesses = filteredProcesses[:maxProcesses]
	}

	var processWidgets []giu.Widget

	for _, proc := range filteredProcesses {
		proc := proc

		execPath := proc.Executable
		if len(execPath) > 50 {
			execPath = "..." + execPath[len(execPath)-47:]
		}

		isSelected := proc.PID == app.selectedPID

		processText := fmt.Sprintf("%-8d %-20s %s", proc.PID, proc.Name, execPath)

		var rowWidget giu.Widget
		if isSelected {

			rowWidget = giu.Style().
				SetColor(giu.StyleColorText, color.RGBA{R: 255, G: 255, B: 255, A: 255}).
				SetColor(giu.StyleColorHeader, color.RGBA{R: 0, G: 100, B: 0, A: 100}).
				SetColor(giu.StyleColorHeaderHovered, color.RGBA{R: 0, G: 120, B: 0, A: 120}).
				SetColor(giu.StyleColorHeaderActive, color.RGBA{R: 0, G: 140, B: 0, A: 140}).To(
				giu.Selectable(processText).Selected(true).OnClick(func() {
					app.selectedPID = proc.PID
					app.selectedProcessName = proc.Name
					app.showProcessDialog = false
					app.processSearchText = ""
					app.addLogLine(fmt.Sprintf("%s Process selected: %s (PID: %d)", app.getEmojiText("✅"), proc.Name, proc.PID))
				}),
			)
		} else {

			rowWidget = giu.Style().
				SetColor(giu.StyleColorText, color.RGBA{R: 200, G: 200, B: 200, A: 255}).
				SetColor(giu.StyleColorHeader, color.RGBA{R: 40, G: 40, B: 40, A: 100}).
				SetColor(giu.StyleColorHeaderHovered, color.RGBA{R: 60, G: 60, B: 60, A: 120}).
				SetColor(giu.StyleColorHeaderActive, color.RGBA{R: 80, G: 80, B: 80, A: 140}).To(
				giu.Selectable(processText).Selected(false).OnClick(func() {
					app.selectedPID = proc.PID
					app.selectedProcessName = proc.Name
					app.showProcessDialog = false
					app.processSearchText = ""
					app.addLogLine(fmt.Sprintf("%s Process selected: %s (PID: %d)", app.getEmojiText("✅"), proc.Name, proc.PID))
				}),
			)
		}

		processWidgets = append(processWidgets, rowWidget)
	}

	processWidgets = append(processWidgets,
		giu.Spacing(),
		giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 150, G: 150, B: 150, A: 255}).To(
			giu.Label(fmt.Sprintf("Showing %d of %d processes", len(filteredProcesses), len(processes))),
		),
	)

	return giu.Column(processWidgets...)
}



func (app *Application) openNativeFileDialog() {

	filename, err := app.showWindowsFileDialog()
	if err != nil {
		app.addLogLine(fmt.Sprintf("Error opening file dialog: %v", err))
		return
	}

	if filename != "" {
		app.selectedDllPath = filename
		app.addLogLine(fmt.Sprintf("DLL file selected: %s", filepath.Base(filename)))
	} else {
		app.addLogLine("File selection cancelled")
	}
}

func (app *Application) showWindowsFileDialog() (string, error) {

	comdlg32 := windows.NewLazyDLL("comdlg32.dll")
	getOpenFileName := comdlg32.NewProc("GetOpenFileNameW")

	var ofn struct {
		lStructSize       uint32
		hwndOwner         uintptr
		hInstance         uintptr
		lpstrFilter       *uint16
		lpstrCustomFilter *uint16
		nMaxCustFilter    uint32
		nFilterIndex      uint32
		lpstrFile         *uint16
		nMaxFile          uint32
		lpstrFileTitle    *uint16
		nMaxFileTitle     uint32
		lpstrInitialDir   *uint16
		lpstrTitle        *uint16
		flags             uint32
		nFileOffset       uint16
		nFileExtension    uint16
		lpstrDefExt       *uint16
		lCustData         uintptr
		lpfnHook          uintptr
		lpTemplateName    *uint16
		pvReserved        uintptr
		dwReserved        uint32
		flagsEx           uint32
	}

	filter := "DLL Files\x00*.dll\x00All Files\x00*.*\x00\x00"
	filterPtr, _ := syscall.UTF16PtrFromString(filter)

	title := "Select DLL File for Injection"
	titlePtr, _ := syscall.UTF16PtrFromString(title)

	fileBuffer := make([]uint16, 260)

	ofn.lStructSize = uint32(unsafe.Sizeof(ofn))
	ofn.lpstrFilter = filterPtr
	ofn.lpstrFile = &fileBuffer[0]
	ofn.nMaxFile = uint32(len(fileBuffer))
	ofn.lpstrTitle = titlePtr
	ofn.flags = 0x00080000 | 0x00001000 | 0x00000800

	ret, _, _ := getOpenFileName.Call(uintptr(unsafe.Pointer(&ofn)))

	if ret == 0 {

		return "", nil
	}

	filename := syscall.UTF16ToString(fileBuffer)
	return filename, nil
}

func (app *Application) buildProcessTable() giu.Widget {
	app.mu.RLock()
	processes := make([]process.ProcessEntry, len(app.processes))
	copy(processes, app.processes)
	app.mu.RUnlock()

	var filteredProcesses []process.ProcessEntry
	searchLower := strings.ToLower(app.processSearchText)
	for _, proc := range processes {
		if searchLower == "" ||
			strings.Contains(strings.ToLower(proc.Name), searchLower) ||
			strings.Contains(strings.ToLower(proc.Executable), searchLower) ||
			strings.Contains(strconv.FormatInt(int64(proc.PID), 10), searchLower) {
			filteredProcesses = append(filteredProcesses, proc)
		}
	}

	maxProcesses := 100
	if len(filteredProcesses) > maxProcesses {
		filteredProcesses = filteredProcesses[:maxProcesses]
	}

	var processWidgets []giu.Widget

	processWidgets = append(processWidgets,
		giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 0, G: 122, B: 204, A: 255}).To(
			giu.Row(
				giu.Label("PID"),
				giu.Dummy(60, 0),
				giu.Label("Process Name"),
				giu.Dummy(150, 0),
				giu.Label("Executable Path"),
				giu.Dummy(200, 0),
				giu.Label("Action"),
			),
		),
		giu.Separator(),
	)

	for _, proc := range filteredProcesses {
		proc := proc
		isSelected := proc.PID == app.selectedPID

		execPath := proc.Executable
		if len(execPath) > 60 {
			execPath = "..." + execPath[len(execPath)-57:]
		}

		var rowStyle giu.Widget
		if isSelected {
			rowStyle = giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 0, G: 255, B: 0, A: 255}).To(
				giu.Row(
					giu.Label(fmt.Sprintf("%d", proc.PID)),
					giu.Dummy(60, 0),
					giu.Label(proc.Name),
					giu.Dummy(150, 0),
					giu.Label(execPath),
					giu.Dummy(200, 0),
					giu.Style().SetColor(giu.StyleColorButton, color.RGBA{R: 0, G: 122, B: 204, A: 255}).To(
						giu.Button("Selected").OnClick(func() {
							app.selectedPID = proc.PID
							app.selectedProcessName = proc.Name
							app.showProcessDialog = false
							app.processSearchText = ""
							app.addLogLine(fmt.Sprintf("Process selected: %s (PID: %d)", proc.Name, proc.PID))
						}),
					),
				),
			)
		} else {
			rowStyle = giu.Row(
				giu.Label(fmt.Sprintf("%d", proc.PID)),
				giu.Dummy(60, 0),
				giu.Label(proc.Name),
				giu.Dummy(150, 0),
				giu.Label(execPath),
				giu.Dummy(200, 0),
				giu.Style().SetColor(giu.StyleColorButton, color.RGBA{R: 80, G: 80, B: 80, A: 255}).To(
					giu.Button("Select").OnClick(func() {
						app.selectedPID = proc.PID
						app.selectedProcessName = proc.Name
						app.showProcessDialog = false
						app.processSearchText = ""
						app.addLogLine(fmt.Sprintf("Process selected: %s (PID: %d)", proc.Name, proc.PID))
					}),
				),
			)
		}

		processWidgets = append(processWidgets, rowStyle)
	}

	processWidgets = append(processWidgets,
		giu.Spacing(),
		giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 150, G: 150, B: 150, A: 255}).To(
			giu.Label(fmt.Sprintf("Showing %d of %d processes", len(filteredProcesses), len(processes))),
		),
	)

	return giu.Column(processWidgets...)
}

func (app *Application) buildLeftPanel() giu.Widget {
	return giu.Child().Size(-1, -1).Layout(
		giu.Style().SetStyle(giu.StyleVarWindowPadding, 10, 10).To(
			giu.Column(

				giu.Style().SetStyle(giu.StyleVarFramePadding, 5, 5).To(
					giu.Column(
						giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 51, G: 204, B: 255, A: 255}).To(
							giu.Label("DLL File Selection"),
						),
						giu.Separator(),
						giu.Row(
							giu.InputText(&app.selectedDllPath).Size(-80).Hint("Select DLL file..."),
							giu.Button("Browse").Size(70, 0).OnClick(func() {

								app.logger.Info("Browse button clicked - please enter DLL path manually")
							}),
						),
					),
				),

				giu.Spacing(),

				giu.Style().SetStyle(giu.StyleVarFramePadding, 5, 5).To(
					giu.Column(
						giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 51, G: 204, B: 255, A: 255}).To(
							giu.Label("Injection Method"),
						),
						giu.Separator(),
						giu.Combo("##injection_method", app.methodNames[app.injectionMethod], app.methodNames, &app.injectionMethod).Size(-1).OnChange(func() {
							app.logger.Info("Injection method changed", zap.String("method", app.methodNames[app.injectionMethod]))
						}),
					),
				),

				giu.Spacing(),

				app.buildAntiDetectionOptions(),

				giu.Spacing(),

				giu.Style().SetStyle(giu.StyleVarFramePadding, 5, 5).To(
					giu.Column(
						giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 51, G: 204, B: 255, A: 255}).To(
							giu.Label("Target Process"),
						),
						giu.Separator(),
						giu.Label(fmt.Sprintf("Selected: %s (PID: %d)", app.selectedProcessName, app.selectedPID)),
					),
				),

				giu.Spacing(),

				giu.Style().SetStyle(giu.StyleVarFramePadding, 10, 10).To(
					giu.Style().SetColor(giu.StyleColorButton, color.RGBA{R: 51, G: 179, B: 51, A: 255}).To(
						giu.Style().SetColor(giu.StyleColorButtonHovered, color.RGBA{R: 77, G: 204, B: 77, A: 255}).To(
							giu.Style().SetColor(giu.StyleColorButtonActive, color.RGBA{R: 26, G: 153, B: 26, A: 255}).To(
								giu.Button("INJECT DLL").Size(-1, 50).OnClick(app.onInjectClicked),
							),
						),
					),
				),
			),
		),
	)
}

func (app *Application) buildAntiDetectionOptions() giu.Widget {
	return giu.Style().SetStyle(giu.StyleVarFramePadding, 5, 5).To(
		giu.Column(
			giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 51, G: 204, B: 255, A: 255}).To(
				giu.Label("Anti-Detection Options"),
			),
			giu.Separator(),

			giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 255, G: 255, B: 51, A: 255}).To(
				giu.Label("Basic Options:"),
			),
			giu.Row(
				app.buildCompatibleCheckbox("Memory Load", "memory_load", &app.memoryLoad),
				app.buildCompatibleCheckbox("Manual Mapping", "manual_mapping", &app.manualMapping),
			),
			giu.Row(
				app.buildCompatibleCheckbox("Path Spoofing", "path_spoofing", &app.pathSpoofing),
				app.buildCompatibleCheckbox("PE Header Erasure", "pe_header_erasure", &app.peHeaderErasure),
			),
			giu.Row(
				app.buildCompatibleCheckbox("Entry Point Erase", "entry_point_erasure", &app.entryPointErase),
				app.buildCompatibleCheckbox("Invisible Memory", "invisible_memory", &app.invisibleMemory),
			),

			giu.Spacing(),

			giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 255, G: 255, B: 51, A: 255}).To(
				giu.Label("Advanced Options:"),
			),
			giu.Row(
				app.buildCompatibleCheckbox("PTE Spoofing", "pte_spoofing", &app.pteSpoofing),
				app.buildCompatibleCheckbox("VAD Manipulation", "vad_manipulation", &app.vadManipulation),
			),
			giu.Row(
				app.buildCompatibleCheckbox("Remove VAD Node", "remove_vad_node", &app.removeVADNode),
				app.buildCompatibleCheckbox("Thread Stack Alloc", "thread_stack_allocation", &app.allocBehindThreadStack),
			),
			giu.Row(
				app.buildCompatibleCheckbox("Direct Syscalls", "direct_syscalls", &app.directSyscalls),
				app.buildCompatibleCheckbox("Legit Process", "legit_process", &app.legitProcessInjection),
			),

			giu.Spacing(),

			giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 255, G: 255, B: 51, A: 255}).To(
				giu.Label("Enhanced Options:"),
			),
			giu.Row(
				app.buildCompatibleCheckbox("Randomize Allocation", "randomize_allocation", &app.randomizeAllocation),
				app.buildCompatibleCheckbox("Delayed Execution", "delayed_execution", &app.delayedExecution),
			),
			giu.Row(
				app.buildCompatibleCheckbox("Multi-Stage Injection", "multi_stage_injection", &app.multiStageInjection),
				app.buildCompatibleCheckbox("Anti-Debug", "anti_debug", &app.antiDebugTechniques),
			),
			giu.Row(
				app.buildCompatibleCheckbox("Process Hollowing", "process_hollowing", &app.processHollowing),
				app.buildCompatibleCheckbox("Thread Hijacking", "thread_hijacking", &app.threadHijacking),
			),
			giu.Row(
				app.buildCompatibleCheckbox("Memory Fluctuation", "memory_fluctuation", &app.memoryFluctuation),
				app.buildCompatibleCheckbox("Anti-VM", "anti_vm", &app.antiVMTechniques),
			),
		),
	)
}



func (app *Application) buildLogConsole() giu.Widget {
	app.mu.RLock()
	logText := app.logText
	app.mu.RUnlock()

	return giu.Child().Size(-1, -1).Layout(
		giu.Style().SetStyle(giu.StyleVarWindowPadding, 10, 10).To(
			giu.Column(
				giu.Row(
					giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 51, G: 204, B: 255, A: 255}).To(
						giu.Label("Console Logs"),
					),
					giu.Button("Clear").OnClick(func() {
						app.mu.Lock()
						app.logLines = nil
						app.logText = ""
						app.mu.Unlock()
						app.logger.Info("Logs cleared")
					}),
				),
				giu.Separator(),
				giu.Style().SetColor(giu.StyleColorFrameBg, color.RGBA{R: 26, G: 26, B: 26, A: 255}).To(
					giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 51, G: 255, B: 51, A: 255}).To(
						giu.InputTextMultiline(&logText).Size(-1, -1).Flags(giu.InputTextFlagsReadOnly),
					),
				),
			),
		),
	)
}

func (app *Application) buildDialogs() {

	if app.showAboutDialog {
		giu.PopupModal("About DLL Injector").IsOpen(&app.showAboutDialog).Layout(
			giu.Column(
				giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 51, G: 204, B: 255, A: 255}).To(
					giu.Label("DLL Injector v1.0.0"),
				),
				giu.Separator(),
				giu.Label("An advanced DLL injection tool with multiple"),
				giu.Label("injection methods and anti-detection features."),
				giu.Spacing(),
				giu.Label("© 2023-2024 DLL Injector Team"),
				giu.Spacing(),
				giu.Button("Close").OnClick(func() {
					app.showAboutDialog = false
				}),
			),
		)
	}

	if app.showHelpDialog {
		giu.PopupModal("Help").IsOpen(&app.showHelpDialog).Layout(
			giu.Column(
				giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 51, G: 204, B: 255, A: 255}).To(
					giu.Label("DLL Injector Help"),
				),
				giu.Separator(),
				giu.Label("1. Select a DLL file to inject"),
				giu.Label("2. Choose an injection method"),
				giu.Label("3. Configure anti-detection options"),
				giu.Label("4. Select a target process"),
				giu.Label("5. Click 'INJECT DLL' to perform injection"),
				giu.Spacing(),
				giu.Button("Close").OnClick(func() {
					app.showHelpDialog = false
				}),
			),
		)
	}

	if app.showConfirmDialog {
		giu.PopupModal("Confirm Injection").IsOpen(&app.showConfirmDialog).Layout(
			giu.Column(
				giu.Label(app.confirmDialogText),
				giu.Spacing(),
				giu.Row(
					giu.Button("Inject").OnClick(func() {
						app.showConfirmDialog = false
						app.performInjection()
					}),
					giu.Button("Cancel").OnClick(func() {
						app.showConfirmDialog = false
					}),
				),
			),
		)
	}

	if app.showProgressDialog {
		giu.PopupModal("Injecting DLL").IsOpen(&app.showProgressDialog).Layout(
			giu.Column(
				giu.Label(app.progressText),
				giu.Spacing(),
				giu.ProgressBar(0.0).Size(-1, 0),
			),
		)
	}

	if app.showSuccessDialog {
		giu.PopupModal("Injection Successful").IsOpen(&app.showSuccessDialog).Layout(
			giu.Column(
				giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 51, G: 255, B: 51, A: 255}).To(
					giu.Label("Injection Successful!"),
				),
				giu.Separator(),
				giu.Label(app.successText),
				giu.Spacing(),
				giu.Button("Close").OnClick(func() {
					app.showSuccessDialog = false
				}),
			),
		)
	}
}

func (app *Application) buildFontLoadingProgress() giu.Widget {

	return giu.Row()
}

func (app *Application) calculateFileSHA256(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	hash := sha256.New()
	buf := make([]byte, 8192)
	for {
		n, err := file.Read(buf)
		if n > 0 {
			hash.Write(buf[:n])
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			return "", fmt.Errorf("failed to read file: %v", err)
		}
	}

	hashSum := hash.Sum(nil)
	return hex.EncodeToString(hashSum), nil
}

func (app *Application) isDLLHashAllowed(filePath string) (bool, string, error) {
	hash, err := app.calculateFileSHA256(filePath)
	if err != nil {
		return false, "", err
	}

	hash = strings.ToLower(hash)

	for _, allowedHash := range app.allowedDLLHashes {
		if strings.ToLower(allowedHash) == hash {
			return true, hash, nil
		}
	}

	return false, hash, nil
}

func (app *Application) onInjectClicked() {
	if app.selectedDllPath == "" {
		app.addLogLine(fmt.Sprintf("%s Error: No DLL file selected", app.getEmojiText("❌")))
		app.logger.Error("No DLL file selected")
		return
	}

	if app.selectedPID <= 0 {
		app.addLogLine(fmt.Sprintf("%s Error: No target process selected", app.getEmojiText("❌")))
		app.logger.Error("No target process selected")
		return
	}

	if _, err := os.Stat(app.selectedDllPath); os.IsNotExist(err) {
		app.addLogLine(fmt.Sprintf("%s Error: DLL file does not exist: %s", app.getEmojiText("❌"), app.selectedDllPath))
		app.logger.Error("DLL file does not exist", zap.String("path", app.selectedDllPath))
		return
	}

	app.addLogLine("Checking DLL SHA-256 hash...")
	isAllowed, dllHash, err := app.isDLLHashAllowed(app.selectedDllPath)
	if err != nil {
		app.addLogLine(fmt.Sprintf("%s Error: Failed to calculate DLL hash: %v", app.getEmojiText("❌"), err))
		app.logger.Error("Failed to calculate DLL hash", zap.Error(err))
		return
	}

	app.addLogLine(fmt.Sprintf("DLL SHA-256: %s", dllHash))

	if !isAllowed {
		app.addLogLine(fmt.Sprintf("%s Error: DLL hash not in whitelist. Hash: %s", app.getEmojiText("❌"), dllHash))
		app.logger.Error("DLL hash not in whitelist",
			zap.String("hash", dllHash),
			zap.String("path", app.selectedDllPath))
		return
	}

	app.addLogLine(fmt.Sprintf("%s DLL hash verified - hash is in whitelist", app.getEmojiText("✅")))

	app.confirmDialogText = fmt.Sprintf(
		"Are you sure you want to inject:\n%s\n\nInto process:\n%s (PID: %d)\n\nUsing method:\n%s",
		filepath.Base(app.selectedDllPath),
		app.selectedProcessName,
		app.selectedPID,
		app.methodNames[app.injectionMethod],
	)
	app.showConfirmDialog = true
	app.performInjection()
}

func (app *Application) performInjection() {
	app.logger.Info("=== Starting performInjection ===")

	app.logger.Info("GUI Injection Parameters:",
		zap.String("dll_path", app.selectedDllPath),
		zap.Int32("process_id", app.selectedPID),
		zap.String("process_name", app.selectedProcessName),
		zap.Int32("injection_method", app.injectionMethod),
	)

	app.progressText = "Preparing injection..."
	app.showProgressDialog = true
	app.logger.Info("Progress dialog should be shown")

	go func() {
		app.logger.Info("=== Injection goroutine started ===")

		if app.selectedDllPath == "" {
			app.logger.Error("DLL path is empty in GUI")
			result := InjectionResult{
				Success: false,
				Error:   fmt.Errorf("DLL path is empty"),
				Message: "",
			}
			app.injectionResultChan <- result
			return
		}

		if app.selectedPID <= 0 {
			app.logger.Error("Invalid process ID in GUI", zap.Int32("pid", app.selectedPID))
			result := InjectionResult{
				Success: false,
				Error:   fmt.Errorf("invalid process ID: %d", app.selectedPID),
				Message: "",
			}
			app.injectionResultChan <- result
			return
		}

		app.logger.Info("Creating injector instance")
		loggerAdapter := &LoggerAdapter{logger: app.logger}
		inj := injector.NewInjector(app.selectedDllPath, uint32(app.selectedPID), loggerAdapter)

		if inj == nil {
			app.logger.Error("Failed to create injector instance")
			result := InjectionResult{
				Success: false,
				Error:   fmt.Errorf("failed to create injector instance"),
				Message: "",
			}
			app.injectionResultChan <- result
			return
		}

		app.logger.Info("Setting injection method", zap.Int32("method", app.injectionMethod))
		inj.SetMethod(injector.InjectionMethod(app.injectionMethod))

		app.pathSpoofing = true
		app.vadManipulation = true
		app.directSyscalls = true

		options := injector.BypassOptions{
			PathSpoofing:   true,
			VADManipulation: true,
			DirectSyscalls: true,
		}

		app.logger.Info("Setting bypass options (hardcoded)",
			zap.Bool("path_spoofing", options.PathSpoofing),
			zap.Bool("vad_manipulation", options.VADManipulation),
			zap.Bool("direct_syscalls", options.DirectSyscalls),
		)
		inj.SetBypassOptions(options)

		app.logger.Info("=== CALLING ACTUAL INJECTION ===")

		app.addLogLine("🔄 Starting injection process...")

		err := inj.Inject()

		app.logger.Info("=== INJECTION CALL COMPLETED ===",
			zap.Bool("success", err == nil),
			zap.Error(err),
		)

		var resultMsg string
		if err == nil {
			resultMsg = fmt.Sprintf(
				"DLL: %s\nProcess: %s (PID: %d)\nMethod: %s",
				filepath.Base(app.selectedDllPath),
				app.selectedProcessName,
				app.selectedPID,
				app.methodNames[app.injectionMethod],
			)
			app.addLogLine("🧹 Scheduling cleaner in 5 seconds...")
			app.runCleanerAsync(app.selectedDllPath)
		}

		result := InjectionResult{
			Success: err == nil,
			Error:   err,
			Message: resultMsg,
		}

		app.logger.Info("Sending injection result to main thread",
			zap.Bool("success", result.Success),
			zap.String("error_msg", func() string {
				if result.Error != nil {
					return result.Error.Error()
				}
				return "none"
			}()),
		)

		sent := false
		for attempts := 0; attempts < 3 && !sent; attempts++ {
			select {
			case app.injectionResultChan <- result:
				app.logger.Info("Injection result sent successfully")
				sent = true
			case <-time.After(2 * time.Second):
				app.logger.Warn("Injection result send timeout", zap.Int("attempt", attempts+1))
				if attempts == 2 {
					app.logger.Error("Failed to send injection result after 3 attempts")

					go func() {
						time.Sleep(100 * time.Millisecond)
						app.addLogLine("❌ Error: Failed to communicate injection result")
					}()
				}
			}
		}

		app.logger.Info("=== Injection goroutine finished ===")
	}()
}

func openURL(url string) error {
	var cmd string
	var args []string

	switch runtime.GOOS {
	case "windows":
		cmd = "cmd"
		args = []string{"/c", "start", url}
	case "darwin":
		cmd = "open"
		args = []string{url}
	default:
		cmd = "xdg-open"
		args = []string{url}
	}

	return exec.Command(cmd, args...).Start()
}

func (app *Application) checkJournalStatus() {
	regKey := `SYSTEM\CurrentControlSet\Control\FileSystem`
	valueName := "NtfsDisableUsnJournaling"

	key, err := registry.OpenKey(registry.LOCAL_MACHINE, regKey, registry.QUERY_VALUE)
	if err != nil {
		app.journalStatus = "Unknown (Registry access failed)"
		app.addLogLine(fmt.Sprintf("Failed to check journal status: %v", err))
		return
	}
	defer key.Close()

	value, _, err := key.GetIntegerValue(valueName)
	if err != nil {
		if err == registry.ErrNotExist {
			app.journalStatus = "Enabled (Not configured)"
		} else {
			app.journalStatus = "Unknown (Registry read failed)"
			app.addLogLine(fmt.Sprintf("Failed to read journal status: %v", err))
		}
		return
	}

	if value == 1 {
		app.journalStatus = "Disabled (Registry: 1)"
	} else {
		app.journalStatus = "Enabled (Registry: 0)"
	}

	gpKey := `SOFTWARE\Policies\Microsoft\Windows\FileSystems\NTFS`
	gpValueName := "DisableUsnJournaling"

	gpKeyHandle, err := registry.OpenKey(registry.LOCAL_MACHINE, gpKey, registry.QUERY_VALUE)
	if err == nil {
		defer gpKeyHandle.Close()
		gpValue, _, err := gpKeyHandle.GetIntegerValue(gpValueName)
		if err == nil {
			if gpValue == 1 {
				app.journalStatus += " | Group Policy: Disabled"
			} else {
				app.journalStatus += " | Group Policy: Enabled"
			}
		}
	}
}

func (app *Application) enableJournal() {
	app.addLogLine("Enabling USN Journal...")

	regKey := `SYSTEM\CurrentControlSet\Control\FileSystem`
	valueName := "NtfsDisableUsnJournaling"

	key, err := registry.OpenKey(registry.LOCAL_MACHINE, regKey, registry.WRITE)
	if err != nil {
		app.addLogLine(fmt.Sprintf("Error: Failed to open registry key: %v", err))
		app.logger.Error("Failed to open registry key", zap.Error(err))
		return
	}
	defer key.Close()

	err = key.SetDWordValue(valueName, 0)
	if err != nil {
		app.addLogLine(fmt.Sprintf("Error: Failed to set registry value: %v", err))
		app.logger.Error("Failed to set registry value", zap.Error(err))
		return
	}

	app.addLogLine("Registry value set to 0 (enabled)")

	gpKey := `SOFTWARE\Policies\Microsoft\Windows\FileSystems\NTFS`
	gpValueName := "DisableUsnJournaling"

	gpKeyHandle, _, err := registry.CreateKey(registry.LOCAL_MACHINE, gpKey, registry.WRITE)
	if err == nil {
		defer gpKeyHandle.Close()
		err = gpKeyHandle.SetDWordValue(gpValueName, 0)
		if err == nil {
			app.addLogLine("Group Policy value set to 0 (enabled)")
		}
	}

	app.checkJournalStatus()
	app.addLogLine("USN Journal enabled (reboot required for full effect)")
}

func (app *Application) disableJournal() {
	app.addLogLine("Disabling USN Journal...")

	regKey := `SYSTEM\CurrentControlSet\Control\FileSystem`
	valueName := "NtfsDisableUsnJournaling"

	key, err := registry.OpenKey(registry.LOCAL_MACHINE, regKey, registry.WRITE)
	if err != nil {
		app.addLogLine(fmt.Sprintf("Error: Failed to open registry key: %v", err))
		app.logger.Error("Failed to open registry key", zap.Error(err))
		return
	}
	defer key.Close()

	err = key.SetDWordValue(valueName, 1)
	if err != nil {
		app.addLogLine(fmt.Sprintf("Error: Failed to set registry value: %v", err))
		app.logger.Error("Failed to set registry value", zap.Error(err))
		return
	}

	app.addLogLine("Registry value set to 1 (disabled)")

	lastAccessKey := `SYSTEM\CurrentControlSet\Control\FileSystem`
	lastAccessValue := "NtfsDisableLastAccessUpdate"

	lastAccessHandle, err := registry.OpenKey(registry.LOCAL_MACHINE, lastAccessKey, registry.WRITE)
	if err == nil {
		defer lastAccessHandle.Close()
		err = lastAccessHandle.SetDWordValue(lastAccessValue, 1)
		if err == nil {
			app.addLogLine("Last Access Time updates disabled")
		}
	}

	gpKey := `SOFTWARE\Policies\Microsoft\Windows\FileSystems\NTFS`
	gpValueName := "DisableUsnJournaling"

	gpKeyHandle, _, err := registry.CreateKey(registry.LOCAL_MACHINE, gpKey, registry.WRITE)
	if err == nil {
		defer gpKeyHandle.Close()
		err = gpKeyHandle.SetDWordValue(gpValueName, 1)
		if err == nil {
			app.addLogLine("Group Policy value set to 1 (disabled)")
		}
	}

	app.checkJournalStatus()
	app.addLogLine("USN Journal disabled (reboot required for full effect)")
}

func (app *Application) checkCleanerStatus() {
	if app.selectedDllPath == "" {
		app.cleanerStatus = "No DLL selected for cleanup"
		return
	}
	app.cleanerStatus = fmt.Sprintf("Ready to clean traces for: %s", filepath.Base(app.selectedDllPath))
}

func (app *Application) runCleanerAsync(dllPath string) {
	if dllPath == "" {
		return
	}
	go func() {
		time.Sleep(5 * time.Second)
		app.runCleaner(dllPath)
	}()
}

func (app *Application) runCleaner(dllPath string) {
	dllBase := filepath.Base(dllPath)
	app.addLogLine(fmt.Sprintf("🧹 Cleaner: starting cleanup for %s", dllBase))

	removedRecent := app.clearRecentItems(dllPath)
	removedJump := app.clearJumpLists(dllPath)
	removedRun := app.clearRunMRU(dllPath)

	app.cleanerStatus = fmt.Sprintf("Cleanup complete. Recent: %d, JumpLists: %d, RunMRU: %d", removedRecent, removedJump, removedRun)
	app.addLogLine(app.cleanerStatus)
}

func (app *Application) clearRecentItems(dllPath string) int {
	recentDir := filepath.Join(os.Getenv("APPDATA"), "Microsoft", "Windows", "Recent")
	dllBase := strings.ToLower(filepath.Base(dllPath))
	count := 0

	entries, err := os.ReadDir(recentDir)
	if err != nil {
		app.addLogLine(fmt.Sprintf("Cleaner: failed to read Recent folder: %v", err))
		return 0
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := strings.ToLower(entry.Name())
		if strings.Contains(name, dllBase) {
			full := filepath.Join(recentDir, entry.Name())
			if err := os.Remove(full); err == nil {
				count++
				app.addLogLine(fmt.Sprintf("Cleaner: removed recent item %s", entry.Name()))
			}
		}
	}
	return count
}

func (app *Application) clearJumpLists(dllPath string) int {
	appData := os.Getenv("APPDATA")
	dirs := []string{
		filepath.Join(appData, "Microsoft", "Windows", "Recent", "AutomaticDestinations"),
		filepath.Join(appData, "Microsoft", "Windows", "Recent", "CustomDestinations"),
	}
	dllBase := strings.ToLower(filepath.Base(dllPath))
	count := 0

	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			name := strings.ToLower(entry.Name())
			if strings.Contains(name, dllBase) {
				full := filepath.Join(dir, entry.Name())
				if err := os.Remove(full); err == nil {
					count++
					app.addLogLine(fmt.Sprintf("Cleaner: removed jump list %s", entry.Name()))
				}
			}
		}
	}
	return count
}

func (app *Application) clearRunMRU(dllPath string) int {
	dllLower := strings.ToLower(dllPath)
	keyPath := `Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`
	key, err := registry.OpenKey(registry.CURRENT_USER, keyPath, registry.READ|registry.WRITE)
	if err != nil {
		app.addLogLine(fmt.Sprintf("Cleaner: failed to open RunMRU: %v", err))
		return 0
	}
	defer key.Close()

	names, err := key.ReadValueNames(-1)
	if err != nil {
		app.addLogLine(fmt.Sprintf("Cleaner: failed to read RunMRU values: %v", err))
		return 0
	}

	removed := 0
	for _, name := range names {
		val, _, err := key.GetStringValue(name)
		if err == nil && strings.Contains(strings.ToLower(val), dllLower) {
			if err := key.DeleteValue(name); err == nil {
				removed++
				app.addLogLine(fmt.Sprintf("Cleaner: removed RunMRU entry %s", name))
			}
		}
	}
	return removed
}
