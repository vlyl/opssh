package tui

import "testing"

func TestThemePaletteAdaptsToTerminalBackground(t *testing.T) {
	t.Parallel()

	palette := adaptiveThemePalette()
	colors := map[string][2]string{
		"accent":          {palette.accent.Light, palette.accent.Dark},
		"accent soft":     {palette.accentSoft.Light, palette.accentSoft.Dark},
		"text":            {palette.text.Light, palette.text.Dark},
		"muted":           {palette.muted.Light, palette.muted.Dark},
		"border":          {palette.border.Light, palette.border.Dark},
		"success":         {palette.success.Light, palette.success.Dark},
		"warning":         {palette.warning.Light, palette.warning.Dark},
		"error":           {palette.error.Light, palette.error.Dark},
		"code background": {palette.codeBackground.Light, palette.codeBackground.Dark},
	}
	for name, pair := range colors {
		if pair[0] == "" || pair[1] == "" {
			t.Errorf("%s color is missing a light or dark variant: %q", name, pair)
		}
		if pair[0] == pair[1] {
			t.Errorf("%s color does not adapt to the terminal background: %q", name, pair[0])
		}
	}
}

func TestThemeNoLongerUsesPurpleAccent(t *testing.T) {
	t.Parallel()

	palette := adaptiveThemePalette()
	for _, color := range []string{palette.accent.Light, palette.accent.Dark, palette.accentSoft.Light, palette.accentSoft.Dark} {
		if color == "#5B4FDB" || color == "#8B7CFF" || color == "#E8E5FF" || color == "#302B55" {
			t.Fatalf("theme still uses the previous purple accent %s", color)
		}
	}
}
