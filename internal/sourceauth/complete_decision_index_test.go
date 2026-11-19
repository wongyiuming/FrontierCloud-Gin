package sourceauth

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestIndexedLyricDecisions(t *testing.T) {
	c := CompleteSnapshot{
		Projection: Snapshot{
			Media:  []Media{{MediaID: "none", Kind: "audio"}, {MediaID: "explicit", Kind: "audio"}, {MediaID: "default", Kind: "audio"}, {MediaID: "video", Kind: "video"}},
			Lyrics: []Lyric{{ID: "custom"}, {ID: "builtin", Builtin: true}},
		},
		Facts: SourceCompleteFacts{LyricLinks: []SourceLyricLinkFact{
			{MediaID: "explicit", LyricID: "custom", LyricPath: "lyrics/album/custom.lrc"},
			{MediaID: "default", LyricID: "builtin", LyricPath: "lyrics/default.lrc"},
		}},
	}
	index, err := indexLyricDecisions(c)
	if err != nil {
		t.Fatal(err)
	}
	v := &CompleteVerified{snapshot: &Verified{valid: true}, decisions: index}
	for _, tc := range []struct{ track, state, lyric string }{
		{"none", "none", ""}, {"explicit", "explicit", "custom"}, {"default", "default", "builtin"},
	} {
		state, lyric, err := v.Decision(tc.track)
		if err != nil || state != tc.state || lyric != tc.lyric {
			t.Fatalf("%s: got %q %q %v", tc.track, state, lyric, err)
		}
	}
	for _, track := range []string{"missing", "video"} {
		if _, _, err := v.Decision(track); !errors.Is(err, ErrInvalid) {
			t.Fatalf("accepted %q: %v", track, err)
		}
	}
	// The index is independent of mutable source slices after construction.
	c.Facts.LyricLinks[0].LyricID = "replaced"
	if _, lyric, err := v.Decision("explicit"); err != nil || lyric != "custom" {
		t.Fatal("index changed after source mutation", lyric, err)
	}
	if _, _, err := (&CompleteVerified{}).Decision("none"); !errors.Is(err, ErrInvalid) {
		t.Fatal("zero capability accepted")
	}
}

// This isolates the cost of re-reading the ciphertext at the boundary. It is
// not a full migration benchmark and does not validate a real source signer.
func BenchmarkCheckDecisionEnvelope(b *testing.B) {
	for _, size := range []int{64 * 1024, 1024 * 1024, 2500 * 1024} {
		b.Run(fmt.Sprintf("cipher_%d", size), func(b *testing.B) {
			envelope := store.EncryptedMediaSourceSnapshot{Version: 1, Ephemeral: make([]byte, 32), Nonce: make([]byte, 12), Cipher: make([]byte, size)}
			raw, err := json.Marshal(envelope)
			if err != nil {
				b.Fatal(err)
			}
			digest := sha256.Sum256(raw)
			pin := AuthorityPin{SourceNode: "source", TargetNode: "target", SourceKeyID: "key", SourceSSHHostKeySHA256: "host", AuthorityKind: "ssh-collector-v1", SourcePublic: []byte("public"), TargetX25519: []byte("receiver"), Generation: "generation"}
			verified := &Verified{valid: true, ciphertextDigest: hex.EncodeToString(digest[:]), generation: pin.Generation, challenge: "challenge", sourceNode: pin.SourceNode, targetNode: pin.TargetNode, sourceKeyID: pin.SourceKeyID, hostKeyDigest: pin.SourceSSHHostKeySHA256, authorityKind: pin.AuthorityKind, sourcePublic: pin.SourcePublic, targetReceiver: pin.TargetX25519, ciphertextVersion: 1, expiresAt: time.Now().Add(time.Hour).Unix()}
			capability := &CompleteVerified{snapshot: verified, pin: pin, decisions: map[string]lyricDecision{"track": {state: "none"}}, challenge: "challenge", version: 1}
			b.SetBytes(int64(size))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := capability.CheckDecision(pin, envelope, 1, "track", "none", ""); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// Both cases check the same 64 decisions over a 1 MiB synthetic ciphertext.
// The batch case includes preparation and a final commit-boundary recheck;
// the benchmark does not exercise database fences, disk I/O or real signing.
func BenchmarkDecision64Envelope1MiB(b *testing.B) {
	envelope := store.EncryptedMediaSourceSnapshot{Version: 1, Ephemeral: make([]byte, 32), Nonce: make([]byte, 12), Cipher: make([]byte, 1024*1024)}
	raw, err := json.Marshal(envelope)
	if err != nil {
		b.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	pin := AuthorityPin{SourceNode: "source", TargetNode: "target", SourceKeyID: "key", SourceSSHHostKeySHA256: "host", AuthorityKind: "ssh-collector-v1", SourcePublic: []byte("public"), TargetX25519: []byte("receiver"), Generation: "generation"}
	verified := &Verified{valid: true, ciphertextDigest: hex.EncodeToString(digest[:]), generation: pin.Generation, challenge: "challenge", sourceNode: pin.SourceNode, targetNode: pin.TargetNode, sourceKeyID: pin.SourceKeyID, hostKeyDigest: pin.SourceSSHHostKeySHA256, authorityKind: pin.AuthorityKind, sourcePublic: pin.SourcePublic, targetReceiver: pin.TargetX25519, ciphertextVersion: 1, expiresAt: time.Now().Add(time.Hour).Unix()}
	capability := &CompleteVerified{snapshot: verified, pin: pin, decisions: make(map[string]lyricDecision), challenge: "challenge", version: 1}
	ids := make([]string, 64)
	for i := range ids {
		ids[i] = fmt.Sprintf("%064x", i)
		capability.decisions[ids[i]] = lyricDecision{state: "none"}
	}
	b.Run("individual", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			for _, id := range ids {
				if err := capability.CheckDecision(pin, envelope, 1, id, "none", ""); err != nil {
					b.Fatal(err)
				}
			}
		}
	})
	b.Run("batch_and_commit_check", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			batch, err := capability.PrepareDecisionBatch(pin, envelope, 1, ids)
			if err != nil {
				b.Fatal(err)
			}
			for _, id := range ids {
				if _, _, err = batch.Decision(id); err != nil {
					b.Fatal(err)
				}
			}
			if err = batch.CheckForCommit(pin, envelope, 1); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func TestIndexedLyricDecisionsRejectAmbiguity(t *testing.T) {
	base := func() CompleteSnapshot {
		return CompleteSnapshot{Projection: Snapshot{Media: []Media{{MediaID: "track", Kind: "audio"}}, Lyrics: []Lyric{{ID: "builtin", Builtin: true}}}, Facts: SourceCompleteFacts{LyricLinks: []SourceLyricLinkFact{{MediaID: "track", LyricID: "builtin", LyricPath: "lyrics/default.lrc"}}}}
	}
	for name, mutate := range map[string]func(*CompleteSnapshot){
		"duplicate track":    func(c *CompleteSnapshot) { c.Projection.Media = append(c.Projection.Media, c.Projection.Media[0]) },
		"duplicate link":     func(c *CompleteSnapshot) { c.Facts.LyricLinks = append(c.Facts.LyricLinks, c.Facts.LyricLinks[0]) },
		"unknown track":      func(c *CompleteSnapshot) { c.Facts.LyricLinks[0].MediaID = "other" },
		"empty lyric":        func(c *CompleteSnapshot) { c.Facts.LyricLinks[0].LyricID = "" },
		"wrong default path": func(c *CompleteSnapshot) { c.Facts.LyricLinks[0].LyricPath = "lyrics/wrong.lrc" },
	} {
		t.Run(name, func(t *testing.T) {
			c := base()
			mutate(&c)
			if _, err := indexLyricDecisions(c); !errors.Is(err, ErrInvalid) {
				t.Fatal("ambiguous source decision accepted", err)
			}
		})
	}
}

func TestDecisionBatchDeadlineAndInvalidCapability(t *testing.T) {
	envelope := store.EncryptedMediaSourceSnapshot{Version: 1, Ephemeral: make([]byte, 32), Nonce: make([]byte, 12), Cipher: make([]byte, 16)}
	raw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	pin := AuthorityPin{SourceNode: "source", TargetNode: "target", SourceKeyID: "key", SourceSSHHostKeySHA256: "host", AuthorityKind: "ssh-collector-v1", SourcePublic: []byte("public"), TargetX25519: []byte("receiver"), Generation: "generation"}
	snapshot := &Verified{valid: true, ciphertextDigest: hex.EncodeToString(digest[:]), generation: pin.Generation, challenge: "challenge", sourceNode: pin.SourceNode, targetNode: pin.TargetNode, sourceKeyID: pin.SourceKeyID, hostKeyDigest: pin.SourceSSHHostKeySHA256, authorityKind: pin.AuthorityKind, sourcePublic: pin.SourcePublic, targetReceiver: pin.TargetX25519, ciphertextVersion: 1, expiresAt: time.Now().Add(time.Hour).Unix()}
	v := &CompleteVerified{snapshot: snapshot, pin: pin, decisions: map[string]lyricDecision{"track": {state: "none"}}, challenge: "challenge", version: 1}
	batch, err := v.PrepareDecisionBatch(pin, envelope, 1, []string{"track"})
	if err != nil {
		t.Fatal(err)
	}
	snapshot.expiresAt = time.Now().Unix()
	if batch.CheckForCommit(pin, envelope, 1) == nil {
		t.Fatal("expired batch accepted at commit")
	}
	if _, err = v.PrepareDecisionBatch(pin, envelope, 1, []string{"track"}); !errors.Is(err, ErrInvalid) {
		t.Fatal("expired source created a new batch", err)
	}
	if (&DecisionBatch{}).CheckForCommit(pin, envelope, 1) == nil {
		t.Fatal("zero batch accepted")
	}
	if _, _, err = (&DecisionBatch{}).Decision("track"); !errors.Is(err, ErrInvalid) {
		t.Fatal("zero batch returned decision", err)
	}
}

func BenchmarkIndexedLyricDecision2631(b *testing.B) {
	c := CompleteSnapshot{}
	for i := 0; i < 2631; i++ {
		id := fmt.Sprintf("%064x", i)
		c.Projection.Media = append(c.Projection.Media, Media{MediaID: id, Kind: "audio"})
	}
	index, err := indexLyricDecisions(c)
	if err != nil {
		b.Fatal(err)
	}
	v := &CompleteVerified{snapshot: &Verified{valid: true}, decisions: index}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, track := range c.Projection.Media {
			if _, _, err = v.Decision(track.MediaID); err != nil {
				b.Fatal(err)
			}
		}
	}
}
