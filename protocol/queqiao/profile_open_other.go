//go:build !unix

package queqiao

import (
	"errors"
	"os"
)

func openProfileFile(path string) (*os.File, error) {
	// Platforms without Unix nonblocking open retain the preflight rejection.
	// This does not make path inspection and opening atomic.
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("profile must be a regular file of at most 1 MiB")
	}
	return os.Open(path)
}
