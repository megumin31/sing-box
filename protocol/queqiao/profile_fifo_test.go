//go:build linux || darwin

package queqiao

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Run the potentially blocking open in a child process so the regression can
// terminate and reap it without leaving a goroutine blocked in open(2).
func TestProfileRejectsFIFOWithoutWriter(t *testing.T) {
	const childPath = "QUEQIAO_PROFILE_FIFO_TEST_PATH"
	if path := os.Getenv(childPath); path != "" {
		_, _, err := loadProfile(path)
		if err == nil || !strings.Contains(err.Error(), "regular file") {
			t.Fatalf("FIFO error = %v; want regular-file rejection", err)
		}
		return
	}
	path := filepath.Join(t.TempDir(), "profile.fifo")
	if err := syscall.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	runProfileFileChild(t, path, "TestProfileRejectsFIFOWithoutWriter")
}

func TestProfileNonblockingOpenAfterReplacement(t *testing.T) {
	const childPath = "QUEQIAO_PROFILE_FIFO_TEST_PATH"
	if path := os.Getenv(childPath); path != "" {
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() {
			t.Fatalf("initial path must be regular: %v", err)
		}
		fifo := path + ".fifo"
		if err := syscall.Mkfifo(fifo, 0600); err != nil {
			t.Fatal(err)
		}
		// Deterministically replace the previously inspected regular path before
		// the exact open operation used by loadProfile. No timing race is needed.
		if err := os.Rename(fifo, path); err != nil {
			t.Fatal(err)
		}
		f, err := openProfileFile(path)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		info, err = f.Stat()
		if err != nil || info.Mode()&os.ModeNamedPipe == 0 {
			t.Fatalf("opened descriptor must identify the replacement FIFO: %v", err)
		}
		return
	}
	path := filepath.Join(t.TempDir(), "profile.json")
	if err := os.WriteFile(path, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	runProfileFileChild(t, path, "TestProfileNonblockingOpenAfterReplacement")
}

func runProfileFileChild(t *testing.T, path, testName string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+testName+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), "QUEQIAO_PROFILE_FIFO_TEST_PATH="+path,
		"GORACE="+os.Getenv("GORACE")+" atexit_sleep_ms=0")
	output, err := cmd.CombinedOutput()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatal("profile loading blocked on a FIFO without a writer; child terminated and reaped")
	}
	if err != nil {
		t.Fatalf("child failed: %v\n%s", err, output)
	}
}
