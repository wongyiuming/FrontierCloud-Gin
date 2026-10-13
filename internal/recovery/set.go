package recovery

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/fsutil"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
)

const SetFile = "recovery-set.json"
const RestoredSetFile = ".fc-restored-set.json"
const MaxSetMembers = 33

type Relation struct {
	NodeID    string `json:"node_id"`
	Direction string `json:"direction"`
	State     string `json:"state"`
	Protocol  int    `json:"protocol"`
}
type SetMember struct {
	NodeID     string     `json:"node_id"`
	Role       string     `json:"role"`
	Database   string     `json:"database"`
	Revision   string     `json:"revision"`
	Generation int        `json:"schema_generation"`
	Archive    string     `json:"archive"`
	SHA256     string     `json:"sha256"`
	Bytes      int64      `json:"bytes"`
	Relations  []Relation `json:"relations"`
}
type SetManifest struct {
	Format      string      `json:"format"`
	Version     int         `json:"version"`
	ID          string      `json:"set_id"`
	MasterID    string      `json:"master_id"`
	CreatedAt   string      `json:"created_at"`
	Consistency string      `json:"consistency"`
	Members     []SetMember `json:"members"`
}
type SetReport struct {
	Manifest         SetManifest               `json:"manifest"`
	SHA256           string                    `json:"sha256"`
	Verified         bool                      `json:"integrity_verified"`
	CompleteCluster  bool                      `json:"complete_cluster"`
	BusinessVerified bool                      `json:"restored_business_verified"`
	CleanupWarnings  map[string]ScratchWarning `json:"cleanup_warnings,omitempty"`
}

type ScratchWarning struct {
	Warning         string `json:"warning"`
	RetainedScratch string `json:"retained_scratch"`
}

// ValidateSetGraph admits exactly one Master and its complete reciprocal set
// of active Storage identities. Offline health is expected under the freeze;
// pending/revoked/foreign relationships cannot be silently omitted.
func ValidateSetGraph(m SetManifest) error {
	if m.Format != "frontiercloud-recovery-set" || m.Version != 1 || !nodePattern.MatchString(m.ID) || !nodePattern.MatchString(m.MasterID) || m.Consistency != "all-listed-local-native-leases-held-and-deployment-writers-stopped" || len(m.Members) < 2 || len(m.Members) > MaxSetMembers {
		return ErrUnsafe
	}
	seen := map[string]SetMember{}
	for _, member := range m.Members {
		if !SupportedSchemaGeneration(member.Generation) || !nodePattern.MatchString(member.NodeID) || seen[member.NodeID].NodeID != "" || member.NodeID == m.MasterID && member.Role != "Master" || member.NodeID != m.MasterID && (member.Role != "Follower" || member.Database != "sqlite") {
			return ErrUnsafe
		}
		seen[member.NodeID] = member
	}
	master, ok := seen[m.MasterID]
	if !ok || len(master.Relations) != len(m.Members)-1 {
		return ErrUnsafe
	}
	peers := map[string]bool{}
	for _, relation := range master.Relations {
		peer, ok := seen[relation.NodeID]
		if !ok || peer.NodeID == m.MasterID || peers[peer.NodeID] || relation.Direction != "downstream" || relation.State != "active" || relation.Protocol != 2 || len(peer.Relations) != 1 {
			return ErrUnsafe
		}
		back := peer.Relations[0]
		if back.NodeID != m.MasterID || back.Direction != "upstream" || back.State != "active" || back.Protocol != 2 {
			return ErrUnsafe
		}
		peers[peer.NodeID] = true
	}
	return nil
}

func relationsEqual(a, b []Relation) bool {
	if len(a) != len(b) {
		return false
	}
	aa := append([]Relation(nil), a...)
	bb := append([]Relation(nil), b...)
	sort.Slice(aa, func(i, j int) bool { return aa[i].NodeID < aa[j].NodeID })
	sort.Slice(bb, func(i, j int) bool { return bb[i].NodeID < bb[j].NodeID })
	for i := range aa {
		if aa[i] != bb[i] {
			return false
		}
	}
	return true
}

func setMemberMatches(member SetMember, m Manifest, set string) bool {
	if m.RecoverySet != set || member.NodeID != m.NodeID || member.Role != m.Role || member.Database != m.Database || member.Revision != m.Revision || member.Generation != m.SchemaGeneration || member.Bytes != m.Bytes || !relationsEqual(member.Relations, m.Relations) || len(m.Missing) != len(m.Relations) {
		return false
	}
	missing := map[string]bool{}
	for _, relation := range m.Relations {
		missing["matching recovery state for related node "+relation.NodeID+" is not included"] = true
	}
	for _, item := range m.Missing {
		if !missing[item] {
			return false
		}
		delete(missing, item)
	}
	return len(missing) == 0
}

// PublishSet is called only by the coordinator while every native lifecycle
// lease remains held. Individual archives retain their incomplete-cluster fact.
func PublishSet(ctx context.Context, directory string, m SetManifest) (SetReport, error) {
	if ValidateSetGraph(m) != nil {
		return SetReport{}, ErrUnsafe
	}
	m.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	for _, member := range m.Members {
		if member.Archive != member.NodeID+".tar" || !hashPattern.MatchString(member.SHA256) {
			return SetReport{}, ErrUnsafe
		}
		r, e := Check(ctx, filepath.Join(directory, member.Archive), member.SHA256)
		if e != nil || !setMemberMatches(member, r.Manifest, m.ID) {
			return SetReport{}, ErrUnsafe
		}
	}
	raw, e := json.MarshalIndent(m, "", "  ")
	if e != nil {
		return SetReport{}, e
	}
	raw = append(raw, '\n')
	f, e := os.CreateTemp(directory, SetFile+".next-")
	if e != nil {
		return SetReport{}, e
	}
	temporary := f.Name()
	defer os.Remove(temporary)
	_, e = f.Write(raw)
	if e == nil {
		e = f.Sync()
	}
	e = errors.Join(e, f.Close())
	if e != nil {
		return SetReport{}, e
	}
	if e = os.Link(temporary, filepath.Join(directory, SetFile)); e != nil {
		return SetReport{}, e
	}
	root, e := os.OpenRoot(directory)
	if e != nil {
		return SetReport{}, e
	}
	defer root.Close()
	if e = fsutil.SyncDirectory(root, "."); e != nil {
		return SetReport{}, e
	}
	h := sha256.Sum256(raw)
	return SetReport{Manifest: m, SHA256: hex.EncodeToString(h[:]), Verified: true, CompleteCluster: true}, nil
}

// CheckSet streams every archive. Hash-valid archives from different freeze
// sets or an incomplete relationship roster cannot be combined into a restore.
func CheckSet(ctx context.Context, directory, expected string) (SetReport, error) {
	var result SetReport
	f, e := openArchive(filepath.Join(directory, SetFile))
	if e != nil {
		return result, e
	}
	defer f.Close()
	raw, e := io.ReadAll(io.LimitReader(f, 1<<20+1))
	if e != nil || len(raw) > 1<<20 {
		return result, ErrUnsafe
	}
	if _, e = protocol.ParseStrictJSON(raw, 1<<20); e != nil {
		return result, e
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&result.Manifest) != nil || ValidateSetGraph(result.Manifest) != nil {
		return result, ErrUnsafe
	}
	h := sha256.Sum256(raw)
	result.SHA256 = hex.EncodeToString(h[:])
	if expected != "" && (!hashPattern.MatchString(expected) || result.SHA256 != expected) {
		return result, ErrUnsafe
	}
	for _, member := range result.Manifest.Members {
		if member.Archive != member.NodeID+".tar" || !hashPattern.MatchString(member.SHA256) {
			return result, ErrUnsafe
		}
		r, e := Check(ctx, filepath.Join(directory, member.Archive), member.SHA256)
		if e != nil || !setMemberMatches(member, r.Manifest, result.Manifest.ID) {
			return result, ErrUnsafe
		}
	}
	result.Verified = true
	result.CompleteCluster = true
	return result, nil
}

// ApplySet extracts all identities into a single absent parent and leaves
// native offline gates intact. It creates no containers and makes no claim of
// business validation; activating related nodes requires coordinated recovery.
func ApplySet(ctx context.Context, directory, target, expected, master string) (SetReport, error) {
	result, e := CheckSet(ctx, directory, expected)
	if e != nil {
		return result, e
	}
	if !hashPattern.MatchString(expected) || result.Manifest.MasterID != master {
		return result, ErrUnsafe
	}
	if _, e = os.Lstat(target); !os.IsNotExist(e) {
		return result, errors.New("cluster restoration target must not exist")
	}
	stage, e := os.MkdirTemp(filepath.Dir(target), ".fc-set-restore-")
	if e != nil {
		return result, e
	}
	for _, member := range result.Manifest.Members {
		if _, e = applySetMember(ctx, filepath.Join(directory, member.Archive), filepath.Join(stage, member.NodeID), member.SHA256, member.NodeID, result.Manifest.ID); e != nil {
			return result, e
		}
	}
	// This marker prevents an individual member being opened as an independent
	// recovery. The subsequent set activation must retain the same full roster.
	raw, _ := json.Marshal(result)
	f, e := os.OpenFile(filepath.Join(stage, RestoredSetFile), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return result, e
	}
	_, e = f.Write(raw)
	if e == nil {
		e = f.Sync()
	}
	e = errors.Join(e, f.Close())
	if e != nil {
		return result, e
	}
	root, e := os.OpenRoot(stage)
	if e != nil {
		return result, e
	}
	for _, member := range result.Manifest.Members {
		path := member.NodeID + "/deployment/.fc-recovery-set.json"
		f, err := root.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			root.Close()
			return result, err
		}
		_, err = f.Write(raw)
		if err == nil {
			err = f.Sync()
		}
		err = errors.Join(err, f.Close())
		if err != nil {
			root.Close()
			return result, err
		}
		if err = fsutil.SyncDirectory(root, member.NodeID+"/deployment"); err != nil {
			root.Close()
			return result, err
		}
	}
	if e = fsutil.SyncDirectory(root, "."); e != nil {
		root.Close()
		return result, e
	}
	root.Close()
	if _, e = os.Lstat(target); !os.IsNotExist(e) {
		return result, ErrUnsafe
	}
	if e = os.Rename(stage, target); e != nil {
		return result, e
	}
	parent, e := os.OpenRoot(filepath.Dir(target))
	if e != nil {
		return result, e
	}
	defer parent.Close()
	return result, fsutil.SyncDirectory(parent, ".")
}
