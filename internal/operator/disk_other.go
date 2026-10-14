//go:build !linux

package operator

import (
	"errors"
	"os"
)

func diskAllocated(os.FileInfo) uint64 { return 0 }

func diskFilesystem(string) (string, error) {
	return "", errors.New("filesystem capacity inspection requires Linux")
}

func diskFree(string) (uint64, error) {
	return 0, errors.New("disk capacity inspection requires Linux")
}
