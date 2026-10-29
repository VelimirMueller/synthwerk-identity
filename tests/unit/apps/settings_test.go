package apps_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/VelimirMueller/synthwerk-contracts/go/identity"

	"github.com/VelimirMueller/synthwerk-identity/internal/apps"
)

func TestWidgetSettingsFrom(t *testing.T) {
	valid := apps.DefaultWidgetSettings().API()

	t.Run("Defaults - every field - an allowed contract value", func(t *testing.T) {
		if _, err := apps.WidgetSettingsFrom(valid); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("Greeting - 280 characters with a line break - accepted, trimmed", func(t *testing.T) {
		in := valid
		in.Greeting = " " + strings.Repeat("ä", 279) + "\n"
		got, err := apps.WidgetSettingsFrom(in)
		if err != nil || got.Greeting != strings.Repeat("ä", 279) {
			t.Fatalf("%q %v", got.Greeting, err)
		}
	})
	bad := map[string]func(*identity.WidgetSettings){
		"free colour":        func(s *identity.WidgetSettings) { s.Accent = "#ff00ff" },
		"unknown position":   func(s *identity.WidgetSettings) { s.Position = "top-left" },
		"unknown language":   func(s *identity.WidgetSettings) { s.Lang = "fr" },
		"empty mode":         func(s *identity.WidgetSettings) { s.Mode = "" },
		"greeting too long":  func(s *identity.WidgetSettings) { s.Greeting = strings.Repeat("a", 281) },
		"greeting with NUL":  func(s *identity.WidgetSettings) { s.Greeting = "a\x00b" },
		"greeting not UTF-8": func(s *identity.WidgetSettings) { s.Greeting = "a\xffb" },
	}
	for name, change := range bad {
		t.Run("Refused - "+name+" - ErrSettings", func(t *testing.T) {
			in := valid
			change(&in)
			if _, err := apps.WidgetSettingsFrom(in); !errors.Is(err, apps.ErrSettings) {
				t.Fatalf("err %v", err)
			}
		})
	}
}

func TestLimitError(t *testing.T) {
	t.Run("LimitError - errors.Is - ErrLimitReached, message names the limit", func(t *testing.T) {
		err := error(apps.LimitError{Limit: 3})
		if !errors.Is(err, apps.ErrLimitReached) || !strings.Contains(err.Error(), "3 apps") {
			t.Fatalf("%v", err)
		}
	})
}
