//go:build unix

package queqiao

import (
	"os"
	"syscall"
)

func openProfileFile(path string) (*os.File, error) {
	// O_NONBLOCK prevents waiting for a FIFO writer, including when the path is
	// replaced concurrently. loadProfile validates the opened descriptor before
	// reading. OpenFile preserves normal symlink and close-on-exec behavior.
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}
