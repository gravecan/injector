package main

import (
	"jector/internal/i18n"
	"jector/internal/ui"
	"go.uber.org/zap"
)

func main() {
	
	app := ui.NewApplication("DLL Injector", 1005, 650)

	
	logger := app.Log()
	logger.Info(i18n.T("dll_injector_starting"))

	
	if err := app.Run(); err != nil {
		logger.Error("Application runtime error", zap.Error(err))
	}

	
}
