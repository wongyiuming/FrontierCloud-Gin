package media

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type StorageAbsenceReceipt struct {
	Status   string `json:"status"`
	UploadID string `json:"upload_id"`
	ObjectID string `json:"object_id"`
	Path     string `json:"path"`
	Fence    string `json:"fence"`
}

// OwnedUploadAbsence never deletes bytes or catalog rows. Its durable fence and
// absence observations share the exact exclusive lease used by publication and
// ReserveOwnedUpload, including writers already authenticated but still queued.
func (s *Service) OwnedUploadAbsence(ctx context.Context, relationship, uploadID, id, name string) (StorageAbsenceReceipt, error) {
	if s.owned == nil {
		return StorageAbsenceReceipt{}, ErrUnavailable
	}
	if !operationID.MatchString(relationship) || !operationID.MatchString(uploadID) {
		return StorageAbsenceReceipt{}, ErrPath
	}
	if _, err := ValidateStorageObject(id, name, 1); err != nil {
		return StorageAbsenceReceipt{}, err
	}
	release, err := s.acquire(ctx, true)
	if err != nil {
		return StorageAbsenceReceipt{}, err
	}
	defer release()
	if err = s.ready(); err != nil {
		return StorageAbsenceReceipt{}, err
	}
	object, err := s.repository.ObjectByID(ctx, id)
	if err != nil {
		return StorageAbsenceReceipt{}, err
	}
	if object != nil {
		return StorageAbsenceReceipt{}, store.ErrNodeState
	}
	if _, err = s.safeInfo(name); !errors.Is(err, os.ErrNotExist) {
		if err == nil {
			return StorageAbsenceReceipt{}, os.ErrExist
		}
		return StorageAbsenceReceipt{}, err
	}
	pending, err := s.owned.OwnedPendingUploads(ctx)
	if err != nil {
		return StorageAbsenceReceipt{}, err
	}
	for _, p := range pending {
		if p.MediaID == id || p.Path == name {
			return StorageAbsenceReceipt{}, store.ErrNodeState
		}
	}
	// An unassociated stage (including a writer between stage creation and SQL
	// reservation) or journal has no safe object attribution. Defer conservatively;
	// normal owned recovery, never this endpoint, is responsible for dead stages.
	directory, err := s.root.Open(".")
	if err != nil {
		return StorageAbsenceReceipt{}, err
	}
	entries, readErr := directory.ReadDir(-1)
	directory.Close()
	if readErr != nil {
		return StorageAbsenceReceipt{}, readErr
	}
	for _, entry := range entries {
		if uploadStageName.MatchString(entry.Name()) || uploadJournalName.MatchString(entry.Name()) || uploadJournalTemporaryName.MatchString(entry.Name()) {
			return StorageAbsenceReceipt{}, store.ErrNodeState
		}
	}
	receipt := StorageAbsenceReceipt{"absent", uploadID, id, name, "durable-generation-v1"}
	payload, err := json.Marshal(receipt)
	if err != nil {
		return StorageAbsenceReceipt{}, err
	}
	// The legacy fence rejects only generation-less capabilities. Future tickets
	// carrying a different signed upload_id are unaffected, even at the same path.
	if err = s.writeOwnedFence(".storage-legacy-fence-"+id, []byte("generation-required-v1\n")); err != nil {
		return StorageAbsenceReceipt{}, err
	}
	if err = s.writeOwnedFence(".storage-abort-"+uploadID, payload); err != nil {
		return StorageAbsenceReceipt{}, err
	}
	return receipt, nil
}

// Called only while the reservation's exclusive volume lease is held.
func (s *Service) checkOwnedUploadFence(uploadID, objectID string) error {
	name := ".storage-abort-" + uploadID
	if uploadID == "" {
		name = ".storage-legacy-fence-" + objectID
	}
	if _, err := s.root.Lstat(name); err == nil {
		return store.ErrNodeState
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (s *Service) writeOwnedFence(name string, payload []byte) error {
	validName := strings.HasPrefix(name, ".storage-abort-") && operationID.MatchString(strings.TrimPrefix(name, ".storage-abort-")) || strings.HasPrefix(name, ".storage-legacy-fence-") && ownedObjectID.MatchString(strings.TrimPrefix(name, ".storage-legacy-fence-"))
	if !validName || len(payload) == 0 || len(payload) > 2048 {
		return ErrPath
	}
	// Existing markers are never unlinked or replaced: a retry must be identical.
	if info, err := s.root.Lstat(name); err == nil {
		if !info.Mode().IsRegular() || info.Size() != int64(len(payload)) {
			return ErrRecovery
		}
		file, err := s.root.OpenFile(name, os.O_RDWR, 0)
		if err != nil {
			return err
		}
		previous, err := io.ReadAll(io.LimitReader(file, 2049))
		if err != nil || string(previous) != string(payload) {
			file.Close()
			return ErrRecovery
		}
		err = file.Sync()
		closeErr := file.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		return s.syncDirectory(".")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	// An incomplete write must never become a final fence. A hard link publishes
	// the fully synced temporary inode atomically without overwriting an existing
	// name. All operations remain under the exclusive volume lease.
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return err
	}
	temporary := ".storage-fence-tmp-" + hex.EncodeToString(random)
	file, err := s.root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer s.root.Remove(temporary)
	_, err = file.Write(payload)
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = s.root.Link(temporary, name); err != nil {
		return err
	}
	if err = s.syncDirectory("."); err != nil {
		return err
	}
	if err = s.root.Remove(temporary); err != nil {
		return err
	}
	return s.syncDirectory(".")
}
