package process

import (
	"image"
	"image/color"
)

func GetProcessIcon(executablePath string) image.Image {

	return GetDefaultIcon()
}

func GetDefaultIcon() image.Image {

	img := image.NewRGBA(image.Rect(0, 0, 16, 16))

	for y := 0; y < 16; y++ {
		for x := 0; x < 16; x++ {

			intensity := uint8((x + y) * 8)
			if intensity > 255 {
				intensity = 255
			}

			img.Set(x, y, color.RGBA{
				R: intensity / 4,
				G: intensity / 2,
				B: intensity,
				A: 255,
			})
		}
	}

	return img
}

func GetProcessIconResource(proc ProcessEntry) interface{} {

	return nil
}

func ClearIconCache() {

}
