package main

import (
	"fmt"
	"image/color"
	"log"
	"runtime"

	"github.com/AllenDang/giu"
)

var (
	testText = "Hello World"
	counter  = 0
)

func loop() {
	counter++

	if !fontSetupDone {
		setupFonts()
		fontSetupDone = true
	}

	giu.SingleWindow().Layout(
		giu.Column(
			giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 255, G: 255, B: 255, A: 255}).To(
				giu.Label("GIU Test Application - Emoji Test"),
			),
			giu.Separator(),
			giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 0, G: 255, B: 0, A: 255}).To(
				giu.Label("If you can see this, GIU is working correctly!"),
			),
			giu.Spacing(),
			giu.Label(fmt.Sprintf("Counter: %d", counter)),
			giu.Spacing(),

			giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 255, G: 255, B: 0, A: 255}).To(
				giu.Label("Emoji Test:"),
			),
			giu.Label("✅ Success emoji"),
			giu.Label("❌ Error emoji"),
			giu.Label("⚠️ Warning emoji"),
			giu.Label("🚫 Forbidden emoji"),
			giu.Label("🔄 Refresh emoji"),
			giu.Label("☐ Checkbox emoji"),
			giu.Label("🛡️ Shield emoji"),
			giu.Spacing(),

			giu.InputText(&testText).Size(200),
			giu.Spacing(),
			giu.Button("Click Me!").OnClick(func() {
				log.Printf("Test button clicked at iteration %d", counter)
			}),
			giu.Spacing(),
			giu.Button("Exit").OnClick(func() {
				log.Println("Test application exit requested")

			}),
		),
	)
}

func setupFonts() {
	log.Println("Setting up fonts for emoji support...")

	fontAtlas := giu.Context.FontAtlas
	if fontAtlas == nil {
		log.Println("Error: FontAtlas is nil")
		return
	}

	emojiStrings := []string{
		"✅", "❌", "⚠️", "🚫", "🔄", "☐", "🛡️",
	}

	log.Printf("Pre-registering %d emoji strings...", len(emojiStrings))
	for _, emoji := range emojiStrings {
		fontAtlas.RegisterString(emoji)
		log.Printf("Registered: %s", emoji)
	}

	if runtime.GOOS == "windows" {
		log.Println("Attempting to load Windows Unicode fonts...")

		fontCandidates := []string{
			"Segoe UI Emoji",
			"Segoe UI Symbol",
			"Arial Unicode MS",
			"Lucida Sans Unicode",
			"Tahoma",
			"Microsoft Sans Serif",
		}

		fontLoaded := false
		for _, fontName := range fontCandidates {
			log.Printf("Trying to load font: %s", fontName)
			if font := fontAtlas.AddFont(fontName, 16.0); font != nil {
				log.Printf("Successfully loaded Unicode font: %s", fontName)
				fontLoaded = true
				break
			} else {
				log.Printf("Failed to load font: %s", fontName)
			}
		}

		if !fontLoaded {
			log.Println("Warning: No Unicode fonts found, emojis may display as fallback characters")
		}
	}

	log.Println("Font atlas configured for emoji support")
}

var fontSetupDone = false

func main() {
	log.Println("Starting GIU test application...")

	wnd := giu.NewMasterWindow("GIU Test - Emoji", 500, 400, 0)

	log.Println("Starting main loop...")

	wnd.Run(loop)

	log.Println("Test application finished")
}
