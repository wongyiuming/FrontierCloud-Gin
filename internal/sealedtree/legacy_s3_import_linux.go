//go:build linux

package sealedtree

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path"
	"reflect"
	"strings"
	"unicode/utf8"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/sourceauth"
)

func (s *SQLStore) legacyS3Placement(ctx context.Context, tx treeQuery, id string) (string, string, S3Placement, error) {
	p := S3Placement{Version: 1, ObjectID: id}
	var name, kind, locator, objectID, key, etag, proof, namespaceKey string
	var size int64
	err := tx.QueryRowContext(ctx, `SELECT g.media_path,g.object_kind,g.path_locator,g.object_id,g.size_bytes,g.etag,g.created_at,g.updated_at,
		g.storage_member_id,o.object_key,o.proof_json,o.revision,m.endpoint,m.region,m.bucket,m.prefix,m.address_style,m.namespace_key
		FROM global_media_objects g
		JOIN s3_objects o ON o.media_id=g.media_id AND o.member_id=g.storage_member_id AND o.object_id=g.object_id
		JOIN cluster_storage_members c ON c.member_id=g.storage_member_id
		JOIN s3_members m ON m.member_id=c.member_id
		WHERE g.media_id=? AND g.state='active' AND o.state='active' AND c.member_kind='S3' AND c.transport='S3'
		AND c.relationship_id IS NULL AND length(CAST(o.proof_json AS BLOB))<=16384`, id).Scan(
		&name, &kind, &locator, &objectID, &size, &etag, &p.CreatedAt, &p.UpdatedAt,
		&p.MemberID, &key, &proof, &p.ObjectRevision, &p.Location.Endpoint, &p.Location.Region, &p.Location.Bucket, &p.Location.Prefix, &p.Location.AddressStyle, &namespaceKey)
	if err != nil || locator != localLegacyLocator(name) || !validLegacyS3Path(name, kind) || json.Unmarshal([]byte(proof), &p.Proof) != nil ||
		p.Proof.ObjectID != objectID || p.Proof.Key != key || p.Proof.Bytes != size || p.Proof.ETag != etag {
		return "", "", S3Placement{}, ErrConflict
	}
	p.Encryption, err = readLocalLegacyEncryption(ctx, tx, id)
	if err != nil || !validS3Placement(p) {
		return "", "", S3Placement{}, ErrConflict
	}
	namespace, err := p.Location.Namespace()
	if err != nil || namespaceKey != namespace.Origin+"\n"+namespace.Bucket {
		return "", "", S3Placement{}, ErrConflict
	}
	if p.Encryption != nil {
		tag, e := s.mediaFileTag("id", p.Encryption.FileID)
		if e != nil {
			return "", "", S3Placement{}, e
		}
		present, e := mediaTagPresent(ctx, tx, tag)
		if e != nil || !present {
			return "", "", S3Placement{}, ErrConflict
		}
	}
	return name, kind, p, nil
}

func validLegacyS3Path(name, kind string) bool {
	if path.Clean(name) != name || utf8.RuneCountInString(name) > 1024 || !validComponent(path.Base(name)) {
		return false
	}
	parts := strings.Split(name, "/")
	if len(parts) < 3 || len(parts) > 4 {
		return false
	}
	ext := strings.ToLower(path.Ext(name))
	return kind == "audio" && parts[0] == "music" && (ext == ".mp3" || ext == ".m4a" || ext == ".flac" || ext == ".wav") ||
		kind == "video" && parts[0] == "vido" && (ext == ".mp4" || ext == ".webm" || ext == ".mkv")
}

// migrateLegacyS3Held imports metadata under the existing offline batch scope.
// The same database supplies both the stable object identity and the provider
// proof. This leaves the provider, source rows and quota untouched. Provider
// availability, outstanding grants and complete accounting are cutover gates.
func migrateLegacyS3Held(scope *localMasterScope, id string) error {
	if scope == nil || scope.ctx == nil || scope.s == nil || scope.guard == nil || scope.mediaRoot == nil || !hexID(id) {
		return ErrInvalid
	}
	ctx, s := scope.ctx, scope.s
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = scope.guard(tx); err != nil {
		return err
	}
	if err = s.lockIndexedWriter(ctx, tx); err != nil {
		return err
	}
	name, kind, placement, err := s.legacyS3Placement(ctx, tx, id)
	if err != nil {
		return err
	}
	parent, err := s.ensureLegacyDirectoryPathTx(ctx, tx, path.Dir(name))
	if err != nil {
		return err
	}
	entry := Entry{ParentID: parent, ObjectID: id, Kind: kind, Name: path.Base(name)}
	facts, err := s.readLocalLegacyFacts(ctx, tx, entry, name, false)
	if err != nil {
		return err
	}
	var lyricCount int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM media_lyric_links WHERE media_id=?`, id).Scan(&lyricCount); err != nil || lyricCount > 1 || kind == "video" && lyricCount != 0 {
		return ErrConflict
	}
	var builtin *localLegacySource
	var builtinInfo os.FileInfo
	if facts.InternalDefaultLyric != nil {
		builtin, err = openLocalLegacySource(scope.mediaRoot, "lyrics/default.lrc")
		if err != nil {
			return err
		}
		defer builtin.Close()
		builtinInfo, err = builtin.File().Stat()
		if err != nil || !builtinInfo.Mode().IsRegular() || builtinInfo.Size() != int64(len(sourceauth.DefaultLyricContent)) {
			return ErrBlobIncomplete
		}
		data, err := io.ReadAll(io.LimitReader(&contextReader{ctx: ctx, r: builtin.File()}, int64(len(sourceauth.DefaultLyricContent))+1))
		if err != nil || !bytes.Equal(data, []byte(sourceauth.DefaultLyricContent)) {
			return ErrBlobIncomplete
		}
	}
	if kind == "audio" {
		resolution := &LyricResolutionFact{Origin: "local", State: "none", OperationID: s.listingMAC("legacy-s3-lyric-import", id)}
		if facts.Lyric != nil {
			resolution.State = "explicit"
		}
		if builtin != nil {
			resolution.State = "default"
		}
		facts.LyricResolution = resolution
		resolution.Evidence, err = s.localLyricEvidence(facts)
		if err != nil {
			return err
		}
	}
	record, existing, err := s.recordByID(ctx, tx, id)
	switch {
	case err == nil:
		if existing != entry || record.Revision != 1 || s.verifyLegacyS3Replay(ctx, tx, record.ObjectIndex, entry, facts, placement) != nil {
			return ErrConflict
		}
	case errors.Is(err, sql.ErrNoRows):
		if err = s.insertS3PlacementTx(ctx, tx, entry, facts, placement); err != nil {
			return err
		}
	default:
		return err
	}
	if builtin != nil {
		current, e := builtin.File().Stat()
		if e != nil || builtin.Check() != nil || !os.SameFile(builtinInfo, current) || current.Size() != builtinInfo.Size() || !current.ModTime().Equal(builtinInfo.ModTime()) {
			return ErrBlobIncomplete
		}
	}
	if err = scope.guard(tx); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLStore) verifyLegacyS3Replay(ctx context.Context, tx treeQuery, index string, entry Entry, facts Facts, expected S3Placement) error {
	actual, revision, err := s.factsFor(ctx, tx, entry, index)
	if err != nil || revision != 1 || !reflect.DeepEqual(actual, facts) {
		return ErrConflict
	}
	if ok, err := s.checkIndexedS3(ctx, tx, entry, index); err != nil || !ok {
		return ErrConflict
	}
	var slot string
	var sealed []byte
	if err = tx.QueryRowContext(ctx, `SELECT blob_index,revision,sealed FROM sealed_tree_placements WHERE object_index=?`, index).Scan(&slot, &revision, &sealed); err != nil || revision != 1 {
		return ErrConflict
	}
	placement, err := s.openIndexedS3Placement(ctx, tx, entry.ObjectID, slot, index, revision, sealed)
	if err != nil || !reflect.DeepEqual(placement, expected) {
		return ErrConflict
	}
	return nil
}
