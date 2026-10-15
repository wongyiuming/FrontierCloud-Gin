package media

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/filelease"
)

// Caller owns the exclusive volume lease. Only unfinished staging names with
// no publication journal and no live process lease are eligible for removal.
// Publication recovery remains a separate, fail-closed startup operation.
func (s *Service) sweepAbandonedUploadStages(ctx context.Context) error {
	directory, err := s.root.Open(".")
	if err != nil {
		return err
	}
	defer directory.Close()
	cleaned := 0
	for {
		entries, readErr := directory.ReadDir(64)
		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				return err
			}
			name := entry.Name()
			if !uploadStageName.MatchString(name) && !uploadLeaseName.MatchString(name) && !uploadJournalTemporaryName.MatchString(name) {
				continue
			}
			id := strings.TrimPrefix(strings.Split(name, ".")[1], "upload-")
			if !entry.Type().IsRegular() {
				return ErrRecovery
			}
			if _, err := s.root.Lstat(journalPath(id)); err == nil {
				continue
			} else if !errors.Is(err, os.ErrNotExist) {
				return err
			}
			leaseName := ".upload-" + id + ".lease"
			if info, err := s.root.Lstat(leaseName); err == nil {
				if !info.Mode().IsRegular() {
					return ErrRecovery
				}
				file, err := s.root.OpenFile(leaseName, os.O_RDWR, 0)
				if err != nil {
					return err
				}
				release, err := filelease.Try(file, true)
				if errors.Is(err, filelease.ErrBusy) {
					continue
				}
				if err != nil {
					return err
				}
				// The volume lease prevents new admissions while this dead
				// stage is removed. Keep its process lease through unlink.
				err = s.root.Remove(entry.Name())
				release()
				if err != nil && !errors.Is(err, os.ErrNotExist) {
					return err
				}
				if err = s.root.Remove(leaseName); err != nil && !errors.Is(err, os.ErrNotExist) {
					return err
				}
			} else if errors.Is(err, os.ErrNotExist) {
				if err = s.root.Remove(entry.Name()); err != nil && !errors.Is(err, os.ErrNotExist) {
					return err
				}
			} else {
				return err
			}
			cleaned++
			if cleaned >= 50 {
				return s.syncDirectory(".")
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				break
			}
			return readErr
		}
	}
	if cleaned > 0 {
		return s.syncDirectory(".")
	}
	return nil
}
