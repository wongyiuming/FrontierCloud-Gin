package media

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// CryptoObject rechecks current object visibility and ownership before a key
// envelope is issued. A browser session is never a substitute for this check.
func (s *Service) CryptoObject(ctx context.Context, name, resourceID string, admin bool) (store.MediaObject, error) {
	release, err := s.acquire(ctx, false)
	if err != nil {
		return store.MediaObject{}, err
	}
	defer release()
	return s.cryptoObject(ctx, name, resourceID, admin)
}

// cryptoObject requires the caller's shared mutation lease through any local
// file open, so a rename/delete cannot substitute a path after authorization.
func (s *Service) cryptoObject(ctx context.Context, name, resourceID string, admin bool) (store.MediaObject, error) {
	var err error
	if err = s.ready(); err != nil {
		return store.MediaObject{}, err
	}
	role, err := s.role(ctx)
	if err != nil {
		return store.MediaObject{}, err
	}
	if role == "Follower" {
		return store.MediaObject{}, os.ErrNotExist
	}
	var object store.MediaObject
	if role == "Master" && !strings.HasPrefix(name, "lyrics/") {
		row, _, e := s.resolveGlobal(ctx, resourceID, name)
		if e != nil {
			return object, e
		}
		object = store.MediaObject{ID: row.ID, Path: row.Path, Kind: row.Kind}
	} else {
		if resourceID != "" {
			return object, ErrPath
		}
		if !managedObject(name, false) {
			return object, ErrPath
		}
		info, e := s.safeInfo(name)
		if e != nil {
			return object, e
		}
		if !info.Mode().IsRegular() {
			return object, ErrPath
		}
		kind := "audio"
		if strings.HasPrefix(name, "vido/") {
			kind = "video"
		}
		if strings.HasPrefix(name, "lyrics/") {
			kind = "lyric"
		}
		object = store.MediaObject{Path: name, Kind: kind}
		ids, e := s.repository.EnsureObjects(ctx, []store.MediaObject{object})
		if e != nil {
			return object, e
		}
		object.ID = ids[name]
	}
	if !admin {
		hiddenPaths, e := s.repository.HiddenPaths(ctx)
		if e != nil {
			return object, e
		}
		if hidden(object.Path, hiddenPaths) {
			return object, os.ErrNotExist
		}
	}
	object.Encryption, err = s.Encryption(ctx, object.ID)
	return object, err
}

// EncryptedLyric exposes only the existing relation. It never parses ciphertext
// as text and never moves lyric truth to a storage node.
func (s *Service) EncryptedLyric(ctx context.Context, name, resourceID string) (store.MediaObject, error) {
	// Inspect the relation before enforcing encrypted-content visibility. Plain
	// lyrics retain the existing default-lyric fallback, including hidden tracks.
	track, err := s.CryptoObject(ctx, name, resourceID, true)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, ErrPath) {
			return store.MediaObject{}, ErrLyrics
		}
		return store.MediaObject{}, err
	}
	if track.Kind != "audio" {
		return store.MediaObject{}, ErrLyrics
	}
	id := track.ID
	if resourceID != "" {
		id = resourceID
	} else if role, e := s.role(ctx); e != nil {
		return store.MediaObject{}, e
	} else if role == "Master" {
		row, _, e := s.resolveGlobal(ctx, "", track.Path)
		if e != nil {
			return store.MediaObject{}, e
		}
		id = row.ID
	}
	lyric, err := s.repository.LyricPath(ctx, id)
	if err != nil {
		return store.MediaObject{}, err
	}
	if lyric == "" || lyric == defaultLyric || !s.validLyric(lyric) {
		return store.MediaObject{}, nil
	}
	object, err := s.CryptoObject(ctx, lyric, "", true)
	if err != nil {
		return store.MediaObject{}, err
	}
	if object.Encryption == nil {
		return store.MediaObject{}, nil
	}
	if _, err = s.CryptoObject(ctx, name, resourceID, false); err != nil {
		return store.MediaObject{}, err
	}
	return s.CryptoObject(ctx, lyric, "", false)
}

// OpenCryptoLyric applies the same path and visibility checks as key delivery.
func (s *Service) OpenCryptoLyric(ctx context.Context, name string) (*os.File, os.FileInfo, error) {
	release, err := s.acquire(ctx, false)
	if err != nil {
		return nil, nil, err
	}
	defer release()
	object, err := s.cryptoObject(ctx, name, "", false)
	if err != nil {
		return nil, nil, err
	}
	if object.Kind != "lyric" || object.Encryption == nil {
		return nil, nil, os.ErrNotExist
	}
	f, err := s.root.Open(object.Path)
	if err != nil {
		return nil, nil, err
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		f.Close()
		return nil, nil, ErrPath
	}
	return f, info, nil
}

type DownloadEntry struct {
	Path       string                `json:"path"`
	MediaID    string                `json:"media_id"`
	Filename   string                `json:"filename"`
	URL        string                `json:"url"`
	Bytes      int64                 `json:"size_bytes"`
	Encryption *mediacrypto.Metadata `json:"encryption,omitempty"`
	Snapshot   string                `json:"-"`
}

// This is a digest of source identity, not media content. A browser archive must
// never follow a path to a replacement uploaded after the plan was issued.
func downloadSnapshot(id, name string, size int64, revision string) string {
	payload, _ := json.Marshal([]any{id, name, size, revision})
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
}

func globalDownloadRevision(row store.GlobalMedia) string {
	payload, _ := json.Marshal([]any{row.MemberID, row.ObjectID, row.ETag})
	return string(payload)
}

// Plan enumerates the same bounded managed tree as ZIP. Content remains on the
// existing Local/Direct/Relay path; encrypted archives are assembled by browsers.
func (d *Download) Plan(limit int) ([]DownloadEntry, error) {
	entries := []DownloadEntry{}
	seen := map[string]bool{}
	add := func(name, id string, size int64, revision string) error {
		if seen[name] {
			return nil
		}
		if len(entries) >= limit {
			return ErrUploadSize
		}
		seen[name] = true
		if id == "" {
			info, err := d.service.safeInfo(name)
			if err != nil {
				return err
			}
			if !info.Mode().IsRegular() {
				return ErrPath
			}
			size = info.Size()
			revision = strconv.FormatInt(info.ModTime().UnixNano(), 10)
			kind := "audio"
			if strings.HasPrefix(name, "vido/") {
				kind = "video"
			}
			if strings.HasPrefix(name, "lyrics/") {
				kind = "lyric"
			}
			ids, err := d.service.repository.EnsureObjects(d.ctx, []store.MediaObject{{Path: name, Kind: kind}})
			if err != nil {
				return err
			}
			id = ids[name]
		}
		meta, err := d.service.Encryption(d.ctx, id)
		if err != nil {
			return err
		}
		entries = append(entries, DownloadEntry{Path: name, MediaID: id, Filename: path.Base(name), Encryption: meta, Bytes: size, Snapshot: downloadSnapshot(id, name, size, revision)})
		return nil
	}
	for _, row := range d.globals {
		if err := add(row.Path, row.ID, row.Bytes, globalDownloadRevision(row)); err != nil {
			return nil, err
		}
	}
	var visit func(string) error
	visit = func(dir string) error {
		if err := d.ctx.Err(); err != nil {
			return err
		}
		if _, err := d.service.safeInfo(dir); err != nil {
			return err
		}
		f, err := d.service.root.Open(dir)
		if err != nil {
			return err
		}
		defer f.Close()
		for {
			children, readErr := f.ReadDir(128)
			for _, child := range children {
				if strings.HasPrefix(child.Name(), ".") || child.Type()&os.ModeSymlink != 0 {
					continue
				}
				name := dir + "/" + child.Name()
				if child.IsDir() && len(strings.Split(name, "/")) <= 3 {
					if err := visit(name); err != nil {
						return err
					}
				}
				if child.Type().IsRegular() && managedObject(name, false) {
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
	return entries, nil
}
