package apps

import (
	"encoding/json"
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/VelimirMueller/synthwerk-contracts/go/identity"
)

// MaxGreetingLen is the longest greeting in characters (contracts WidgetSettings).
const MaxGreetingLen = 280

// ErrSettings: the widget settings break a rule of contracts WidgetSettings.
var ErrSettings = errors.New("apps: widget settings not valid")

// WidgetSettings is how the widget of an app looks (synthwerk#38). Identity stores
// them in apps.widget_settings (jsonb). Colours come only from @synthwerk/tokens: a
// theme and an accent group, never free CSS.
type WidgetSettings struct {
	Position string `json:"position"`
	Theme    string `json:"theme"`
	Mode     string `json:"mode"`
	Lang     string `json:"lang"`
	Accent   string `json:"accent"`
	Greeting string `json:"greeting"`
}

// DefaultWidgetSettings are the settings of a new app.
func DefaultWidgetSettings() WidgetSettings {
	return WidgetSettings{
		Position: string(identity.WidgetSettingsPositionBottomRight),
		Theme:    string(identity.WidgetSettingsThemeDefault),
		Mode:     string(identity.WidgetSettingsModeSystem),
		Lang:     string(identity.WidgetSettingsLangAuto),
		Accent:   string(identity.WidgetSettingsAccentFlagship),
	}
}

// WidgetSettingsFrom checks settings from the API and returns them with the
// greeting trimmed. Every field must hold an allowed value.
func WidgetSettingsFrom(in identity.WidgetSettings) (WidgetSettings, error) {
	g := strings.TrimSpace(in.Greeting)
	if !in.Position.Valid() || !in.Theme.Valid() || !in.Mode.Valid() || !in.Lang.Valid() || !in.Accent.Valid() || !validGreeting(g) {
		return WidgetSettings{}, ErrSettings
	}
	return WidgetSettings{
		Position: string(in.Position), Theme: string(in.Theme), Mode: string(in.Mode),
		Lang: string(in.Lang), Accent: string(in.Accent), Greeting: g,
	}, nil
}

// validGreeting: valid UTF-8, at most MaxGreetingLen characters, no control
// character but a line break, no bidi embedding, override or isolate.
func validGreeting(s string) bool {
	if !utf8.ValidString(s) || utf8.RuneCountInString(s) > MaxGreetingLen {
		return false
	}
	for _, r := range s {
		if (r != '\n' && unicode.IsControl(r)) || isBidiControl(r) {
			return false
		}
	}
	return true
}

// isBidiControl: U+202A to U+202E (embeddings, overrides) and U+2066 to U+2069
// (isolates). They can turn the text around on the page (Trojan Source). The
// widget refuses the same set (synthwerk-widgets src/settings.ts), so a greeting
// identity stores is a greeting the widget shows.
func isBidiControl(r rune) bool {
	return (r >= '\u202A' && r <= '\u202E') || (r >= '\u2066' && r <= '\u2069')
}

// API returns the settings in the contract type.
func (s WidgetSettings) API() identity.WidgetSettings {
	return identity.WidgetSettings{
		Position: identity.WidgetSettingsPosition(s.Position),
		Theme:    identity.WidgetSettingsTheme(s.Theme),
		Mode:     identity.WidgetSettingsMode(s.Mode),
		Lang:     identity.WidgetSettingsLang(s.Lang),
		Accent:   identity.WidgetSettingsAccent(s.Accent),
		Greeting: s.Greeting,
	}
}

// readSettings reads the stored jsonb. A missing or unknown value (a row from
// before 0007, or a value a later version removed) gets the default.
func readSettings(raw []byte) WidgetSettings {
	d := DefaultWidgetSettings()
	var s WidgetSettings
	if len(raw) == 0 || json.Unmarshal(raw, &s) != nil {
		return d
	}
	if identity.WidgetSettingsPosition(s.Position).Valid() {
		d.Position = s.Position
	}
	if identity.WidgetSettingsTheme(s.Theme).Valid() {
		d.Theme = s.Theme
	}
	if identity.WidgetSettingsMode(s.Mode).Valid() {
		d.Mode = s.Mode
	}
	if identity.WidgetSettingsLang(s.Lang).Valid() {
		d.Lang = s.Lang
	}
	if identity.WidgetSettingsAccent(s.Accent).Valid() {
		d.Accent = s.Accent
	}
	if validGreeting(s.Greeting) {
		d.Greeting = s.Greeting
	}
	return d
}
