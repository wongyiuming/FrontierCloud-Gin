package media

import (
	"errors"
	"io"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// BrowserPlan runs under Download's existing shared mutation lease. It examines
// the entire ZIP selection once, retaining at most limit browser entries. An
// empty result for an oversize selection means every selected file is plaintext
// and the caller can use the existing server ZIP without the browser file cap.
// Smaller plaintext plans retain their existing per-file attachment URLs.
func (d *Download) BrowserPlan(limit int) ([]DownloadEntry, error) {
	if limit <= 0 {
		return nil, ErrPath
	}
	const batchSize = 500
	entries := []DownloadEntry{}
	pending := make([]DownloadEntry, 0, batchSize)
	seen := map[string]bool{}
	total, encrypted := 0, false
	flush := func() error {
		if len(pending) == 0 {
			return nil
		}
		objects := []store.MediaObject{}
		for _, entry := range pending {
			if entry.MediaID != "" {
				continue
			}
			kind := "audio"
			if strings.HasPrefix(entry.Path, "vido/") {
				kind = "video"
			} else if strings.HasPrefix(entry.Path, "lyrics/") {
				kind = "lyric"
			}
			objects = append(objects, store.MediaObject{Path: entry.Path, Kind: kind})
		}
		ids := map[string]string{}
		if len(objects) != 0 {
			var err error
			ids, err = d.service.repository.EnsureObjects(d.ctx, objects)
			if err != nil {
				return err
			}
		}
		identifiers := make([]string, len(pending))
		for i := range pending {
			if pending[i].MediaID == "" {
				pending[i].MediaID = ids[pending[i].Path]
			}
			if !ownedObjectID.MatchString(pending[i].MediaID) {
				return mediacrypto.ErrMetadata
			}
			identifiers[i] = pending[i].MediaID
		}
		metadata, err := d.service.Encryptions(d.ctx, identifiers)
		if err != nil {
			return err
		}
		for _, entry := range pending {
			entry.Encryption = metadata[entry.MediaID]
			if entry.Encryption != nil {
				encrypted = true
				if entry.Encryption.CiphertextSize != entry.Bytes {
					return mediacrypto.ErrMetadata
				}
			}
			// Until identities are known, Snapshot holds the immutable revision.
			entry.Snapshot = downloadSnapshot(entry.MediaID, entry.Path, entry.Bytes, entry.Snapshot)
			if len(entries) < limit {
				entries = append(entries, entry)
			}
		}
		pending = pending[:0]
		return nil
	}
	add := func(name, id string, size int64, revision string) error {
		if err := d.ctx.Err(); err != nil {
			return err
		}
		if seen[name] {
			return nil
		}
		if !managedObject(name, false) || id != "" && !ownedObjectID.MatchString(id) {
			return mediacrypto.ErrMetadata
		}
		if id == "" {
			info, err := d.service.safeInfo(name)
			if err != nil {
				return err
			}
			if !info.Mode().IsRegular() {
				return ErrPath
			}
			size, revision = info.Size(), strconv.FormatInt(info.ModTime().UnixNano(), 10)
		}
		seen[name] = true
		total++
		pending = append(pending, DownloadEntry{Path: name, MediaID: id, Filename: path.Base(name), Bytes: size, Snapshot: revision})
		if len(pending) == batchSize {
			return flush()
		}
		return nil
	}
	for _, row := range d.globals {
		// Download already resolved this logical identity under this same lease.
		// Local placements additionally require their declared bytes to exist.
		if !ownedObjectID.MatchString(row.ID) {
			return nil, mediacrypto.ErrMetadata
		}
		if row.RelationshipID == nil {
			info, err := d.service.safeInfo(row.Path)
			if err != nil {
				return nil, err
			}
			if !info.Mode().IsRegular() || info.Size() != row.Bytes {
				return nil, store.ErrNodeState
			}
		}
		if err := add(row.Path, row.ID, row.Bytes, globalDownloadRevision(row)); err != nil {
			return nil, err
		}
	}
	var visit func(string) error
	visit = func(dir string) error {
		if err := d.ctx.Err(); err != nil {
			return err
		}
		info, err := d.service.safeInfo(dir)
		if err != nil {
			return err
		}
		if !info.IsDir() {
			return ErrPath
		}
		file, err := d.service.root.Open(dir)
		if err != nil {
			return err
		}
		defer file.Close()
		for {
			children, readErr := file.ReadDir(128)
			for _, child := range children {
				if child.Type()&os.ModeSymlink != 0 || strings.HasPrefix(child.Name(), ".") {
					continue
				}
				name := dir + "/" + child.Name()
				if child.IsDir() {
					if len(strings.Split(name, "/")) <= 3 {
						if err := visit(name); err != nil {
							return err
						}
					}
				} else if child.Type().IsRegular() && managedObject(name, false) {
					if err := add(name, "", 0, ""); err != nil {
						return err
					}
				}
			}
			if errors.Is(readErr, io.EOF) {
				return nil
			}
			if readErr != nil {
				return readErr
			}
		}
	}
	for _, item := range d.Items {
		if len(d.globals) > 0 && !strings.HasPrefix(item.Path, "lyrics/") {
			continue
		}
		if item.Directory {
			if err := visit(item.Path); err != nil {
				return nil, err
			}
		} else if err := add(item.Path, "", 0, ""); err != nil {
			return nil, err
		}
	}
	if err := flush(); err != nil {
		return nil, err
	}
	if !encrypted && total > limit {
		return []DownloadEntry{}, nil
	}
	if total > limit {
		return nil, ErrUploadSize
	}
	return entries, nil
}
