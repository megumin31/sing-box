package queqiao

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestProfileFileInput(t *testing.T) {
	dir := t.TempDir()
	t.Run("directory", func(t *testing.T) {
		_, _, err := loadProfile(dir)
		if err == nil || !strings.Contains(err.Error(), "regular file") {
			t.Fatalf("directory error = %v", err)
		}
	})
	t.Run("missing", func(t *testing.T) {
		_, _, err := loadProfile(filepath.Join(dir, "missing"))
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("missing file error = %v", err)
		}
	})
	profile, _, _ := testIdentity(t)
	raw, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "profile.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	check := func(t *testing.T, path string) {
		t.Helper()
		config, endpoint, err := loadProfile(path)
		if err != nil || config == nil || endpoint != profile.Endpoint {
			t.Fatalf("profile load: endpoint=%q, config present=%v, error=%v", endpoint, config != nil, err)
		}
	}
	t.Run("regular", func(t *testing.T) { check(t, path) })
	t.Run("symlink-to-regular", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("symlink creation may require Windows privileges")
		}
		link := filepath.Join(dir, "profile-link.json")
		if err := os.Symlink(path, link); err != nil {
			t.Fatal(err)
		}
		check(t, link)
	})
}
