//go:build !linux

package operator

import "errors"

func diskFree(string) (uint64, error) {
	return 0, errors.New("disk capacity inspection requires Linux")
}
