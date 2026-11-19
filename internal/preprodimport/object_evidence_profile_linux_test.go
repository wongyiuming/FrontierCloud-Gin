//go:build linux && object_profile

package preprodimport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/snapshotcrypt"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type objectProfileLease struct {
	start    time.Time
	duration *atomic.Int64
}

func (l *objectProfileLease) Check(ctx context.Context) error { return ctx.Err() }
func (l *objectProfileLease) Release()                        { l.duration.Store(time.Since(l.start).Microseconds()) }
func objectProfileRSS() int64 {
	raw, e := os.ReadFile("/proc/self/status")
	if e != nil {
		return 0
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "VmRSS:") {
			f := strings.Fields(line)
			if len(f) > 1 {
				v, _ := strconv.ParseInt(f[1], 10, 64)
				return v * 1024
			}
		}
	}
	return 0
}
func TestObjectEvidence2631Profile(t *testing.T) {
	if os.Getenv("FC_OBJECT_PROFILE") != "1" {
		t.Skip("explicit isolated profile required")
	}
	ctx := context.Background()
	projection, _, _, _ := fixture(t)
	video := projection.Media[1]
	// Historical aggregate shape: 1792 media and 839 user lyrics. This is
	// synthetic, not a claim about current source rows or their exact sizes.
	for i := 0; i < 1790; i++ {
		m := video
		m.MediaID = fmt.Sprintf("%064x", i+1000)
		m.ObjectID = fmt.Sprintf("%064x", i+100000)
		m.SourceID = projection.Mappings[i%len(projection.Mappings)].SourceID
		if i < 838 {
			m.Kind = "audio"
			m.Path = fmt.Sprintf("music/album/track-%04d.mp3", i)
			lyric := Lyric{ID: fmt.Sprintf("%064x", i+200000), Path: fmt.Sprintf("lyrics/a/track-%04d.lrc", i), Size: 5, SHA256: digest([]byte("lyric"))}
			projection.Lyrics = append(projection.Lyrics, lyric)
			projection.Links = append(projection.Links, Link{MediaID: m.MediaID, LyricID: lyric.ID})
		} else {
			m.Path = fmt.Sprintf("vido/category/item-%04d.mp4", i)
		}
		projection.Media = append(projection.Media, m)
	}
	for i := range projection.Mappings {
		projection.Mappings[i].Capacity = 1024 * 1024 * 1024
	}
	complete := completeSourceFixture(projection)
	mediaPaths := map[string]string{}
	lyricPaths := map[string]string{}
	for _, m := range projection.Media {
		mediaPaths[m.MediaID] = m.Path
	}
	for _, l := range projection.Lyrics {
		lyricPaths[l.ID] = l.Path
	}
	for i := range complete.Facts.LyricLinks {
		link := &complete.Facts.LyricLinks[i]
		link.MediaPath = mediaPaths[link.MediaID]
		link.LyricPath = lyricPaths[link.LyricID]
	}
	generation, e := completeSnapshotDigest(complete)
	if e != nil {
		t.Fatal(e)
	}
	signer := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	receiver, e := receiverFromMasterSeed(bytes.Repeat([]byte{8}, 32))
	if e != nil {
		t.Fatal(e)
	}
	pin := sourceAuthorityPin{Version: 1, Purpose: "frontiercloud:preprod-source-authority:v1", AuthorityKind: "ssh-collector-v1", SourceSSHHostKeySHA256: strings.Repeat("a", 64), SourceTLSOrigin: "https://source.test", SourceTLSSPKISHA256: strings.Repeat("b", 64), SourceNode: projection.Mappings[0].SourceID, SourceKeyID: projection.PremasterKeyID, SourcePublic: signer.Public().(ed25519.PublicKey), TargetNode: projection.Mappings[0].TargetID, TargetMasterPublic: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, 32)).Public().(ed25519.PublicKey), TargetX25519: receiver.PublicKey().Bytes(), Generation: generation}
	pin.ImportScope = syntheticImportScope(projection)
	for _, m := range projection.Mappings {
		pin.SourceOwners = append(pin.SourceOwners, sourceOwnerPin{NodeID: m.SourceID, SSHHostKeySHA256: pin.SourceSSHHostKeySHA256})
	}
	source := syntheticSourceForComplete(complete)
	now := time.Now().UTC().Truncate(time.Second)
	challenge := strings.Repeat("9", 64)
	source.Version = 1
	source.AuthorityKind = pin.AuthorityKind
	source.SourceSSHHostKeySHA256 = pin.SourceSSHHostKeySHA256
	source.SourceNode = pin.SourceNode
	source.SourcePublic = protocol.Encode(pin.SourcePublic)
	source.TargetNode = pin.TargetNode
	source.TargetReceiver = pin.TargetX25519
	source.Challenge = challenge
	source.IssuedUnix = now.Unix()
	source.ExpiresUnix = now.Add(4 * time.Minute).Unix()
	raw, e := json.Marshal(source)
	if e != nil {
		t.Fatal(e)
	}
	h := sha256.Sum256(raw)
	sourceDigest := hex.EncodeToString(h[:])
	signature, e := protocol.Sign(protocol.Encode(signer.Seed()), map[string]any{"kind": "frontiercloud-preprod-media-source-v1", "sha256": sourceDigest, "source_node": source.SourceNode, "target_node": source.TargetNode, "challenge": challenge})
	if e != nil {
		t.Fatal(e)
	}
	envelope, e := snapshotcrypt.Seal(store.SignedMediaSourceSnapshot{Snapshot: source, Signature: signature}, receiver.PublicKey().Bytes())
	if e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	if e = os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	dbPath := filepath.Join(dir, "evidence.sqlite")
	initial, e := os.OpenFile(dbPath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if e != nil {
		t.Fatal(e)
	}
	if e = initial.Close(); e != nil {
		t.Fatal(e)
	}
	db, e := sql.Open("sqlite", dbPath)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	for _, q := range []string{"PRAGMA journal_mode=WAL", "PRAGMA synchronous=FULL", "CREATE TABLE preprod_source_evidence(evidence_tag TEXT PRIMARY KEY,salt BLOB NOT NULL UNIQUE,nonce BLOB NOT NULL,cipher BLOB NOT NULL,challenge_tag TEXT NOT NULL UNIQUE)", "CREATE TABLE preprod_object_evidence(evidence_tag TEXT PRIMARY KEY,salt BLOB NOT NULL UNIQUE,nonce BLOB NOT NULL,cipher BLOB NOT NULL,challenge_tag TEXT NOT NULL UNIQUE)", "CREATE TABLE legacy_key_vault_meta(singleton INTEGER PRIMARY KEY,verifier TEXT NOT NULL)", "CREATE TABLE profile_noise(id INTEGER PRIMARY KEY, data BLOB)"} {
		if _, e = db.Exec(q); e != nil {
			t.Fatal(e)
		}
	}
	if e = os.Chmod(dbPath, 0600); e != nil {
		t.Fatal(e)
	}
	root := bytes.Repeat([]byte{12}, 32)
	if _, e = db.Exec("INSERT INTO legacy_key_vault_meta VALUES(1,?)", legacyVaultTag(root, "verifier", pin.TargetNode)); e != nil {
		t.Fatal(e)
	}
	ref, e := saveSourceEvidence(ctx, db, root, receiver, pin, envelope, challenge, complete, time.Now(), func(c context.Context) error { return c.Err() })
	if e != nil {
		t.Fatal(e)
	}
	facts, e := sourceObjectFactsDigest(source, video)
	if e != nil {
		t.Fatal(e)
	}
	scope := objectProofScope{TargetOwnerID: projection.Mappings[1].TargetID, TargetBlobID: strings.Repeat("a", 64), TargetReadAlias: strings.Repeat("b", 64), Challenge: strings.Repeat("8", 64)}
	proof := sshObjectProof{Version: 1, SourceNode: pin.SourceNode, SourceOwnerID: video.SourceID, OwnerSSHHostKeySHA256: pin.SourceSSHHostKeySHA256, SourceSnapshotDigest: sourceDigest, BeforeFactsSHA256: facts, AfterFactsSHA256: facts, MediaID: video.MediaID, SourceObjectID: video.ObjectID, Path: video.Path, SHA256: video.SHA256, Size: video.Size, Device: 1, Inode: 2, MtimeNS: 3, CtimeNS: 4, TargetNode: pin.TargetNode, TargetOwnerID: scope.TargetOwnerID, TargetBlobID: scope.TargetBlobID, TargetReadAlias: scope.TargetReadAlias, Challenge: scope.Challenge, IssuedUnix: now.Unix(), ExpiresUnix: now.Add(3 * time.Minute).Unix()}
	b, e := json.Marshal(proof)
	if e != nil {
		t.Fatal(e)
	}
	ph := sha256.Sum256(b)
	ps, e := protocol.Sign(protocol.Encode(signer.Seed()), map[string]any{"kind": "frontiercloud-preprod-ssh-object-proof-v1", "sha256": hex.EncodeToString(ph[:])})
	if e != nil {
		t.Fatal(e)
	}
	b, e = json.Marshal(signedSSHObjectProof{Proof: proof, Signature: ps})
	if e != nil {
		t.Fatal(e)
	}
	proofEnvelope, e := snapshotcrypt.SealObjectProof(b, receiver.PublicKey().Bytes())
	if e != nil {
		t.Fatal(e)
	}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	rssBefore := objectProfileRSS()
	var peak atomic.Int64
	peak.Store(rssBefore)
	stop := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		tick := time.NewTicker(5 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
				v := objectProfileRSS()
				if v > peak.Load() {
					peak.Store(v)
				}
			}
		}
	}()
	copyStart := time.Now()
	row, e := copyObjectSourceRow(ctx, db, root, pin, ref)
	copyMS := time.Since(copyStart)
	if e != nil {
		t.Fatal(e)
	}
	// The source row was copied and its transaction closed. A separate WAL writer
	// can commit and checkpoint while source authentication is in progress.
	other, e := sql.Open("sqlite", dbPath)
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close()
	writerStarted := make(chan struct{})
	writerDone := make(chan error, 1)
	var walPeak atomic.Int64
	var checkpointBusy atomic.Int64
	go func() {
		close(writerStarted)
		for i := 0; i < 64; i++ {
			if _, e := other.Exec("INSERT INTO profile_noise(data) VALUES(zeroblob(8192))"); e != nil {
				writerDone <- e
				return
			}
			if st, e := os.Stat(dbPath + "-wal"); e == nil && st.Size() > walPeak.Load() {
				walPeak.Store(st.Size())
			}
		}
		var busy, log, done int64
		e := other.QueryRow("PRAGMA wal_checkpoint(PASSIVE)").Scan(&busy, &log, &done)
		checkpointBusy.Store(busy)
		writerDone <- e
	}()
	<-writerStarted
	verifyStart := time.Now()
	_, _, e = decodeObjectSourceRow(root, receiver, pin, row)
	verifyMS := time.Since(verifyStart)
	if e != nil {
		t.Fatal(e)
	}
	if e = <-writerDone; e != nil {
		t.Fatal(e)
	}
	if checkpointBusy.Load() != 0 {
		t.Fatal("short source read retained a WAL snapshot")
	}
	var guardMicros atomic.Int64
	acquire := func(context.Context) (objectEvidenceLease, error) {
		return &objectProfileLease{start: time.Now(), duration: &guardMicros}, nil
	}
	saveStart := time.Now()
	if _, e = saveObjectEvidence(ctx, db, root, receiver, pin, ref, video.MediaID, scope, proofEnvelope, objectEvidenceTestBudget(), acquire); e != nil {
		t.Fatal(e)
	}
	saveMS := time.Since(saveStart)
	close(stop)
	<-stopped
	rssAfter := objectProfileRSS()
	runtime.ReadMemStats(&after)
	t.Logf("object_evidence_profile media=%d lyrics=%d source_cipher_bytes=%d short_read_ms=%.3f verify_outside_ms=%.3f save_total_ms=%.3f guard_ms=%.3f total_alloc_bytes=%d rss_before_bytes=%d sampled_peak_rss_bytes=%d rss_after_bytes=%d concurrent_wal_peak_bytes=%d checkpoint_busy=%d setup_excluded=true", len(projection.Media), len(projection.Lyrics), len(row.cipher), float64(copyMS.Microseconds())/1000, float64(verifyMS.Microseconds())/1000, float64(saveMS.Microseconds())/1000, float64(guardMicros.Load())/1000, after.TotalAlloc-before.TotalAlloc, rssBefore, peak.Load(), rssAfter, walPeak.Load(), checkpointBusy.Load())
}
