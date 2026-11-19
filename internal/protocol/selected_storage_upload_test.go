package protocol

import (
	"bytes"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
)

func TestSelectedStorageUploadPolicyBoundCapability(t *testing.T) {
	credential := Encode(bytes.Repeat([]byte{7}, 48))
	const now int64 = 1700000000
	meta, err := mediacrypto.NewMetadata(1024)
	if err != nil {
		t.Fatal(err)
	}
	base := SelectedStorageUpload{
		Relationship: strings.Repeat("1", 32), Master: strings.Repeat("2", 32), Owner: strings.Repeat("3", 32),
		MediaID: strings.Repeat("4", 64), ObjectID: strings.Repeat("5", 64), UploadID: strings.Repeat("6", 32),
		OperationID: strings.Repeat("7", 64), ContentSHA256: strings.Repeat("8", 64),
		RelationshipBinding: strings.Repeat("9", 64), Generation: strings.Repeat("b", 64), StageID: strings.Repeat("c", 64), PublishChallenge: strings.Repeat("d", 64), CleanupChallenge: strings.Repeat("e", 64),
		Size: meta.CiphertextSize, Policy: "Direct", Revision: 7,
		ResourceOrigin: "https://storage.example", AdminOrigin: "https://master.example", AdminBinding: strings.Repeat("a", 64), ExpiresAt: now + 90, Encryption: &meta,
	}
	for _, policy := range []string{"Direct", "Relay"} {
		claim := base
		claim.Policy = policy
		if policy == "Relay" {
			claim.ResourceOrigin = ""
		}
		token, err := SignSelectedStorageUpload(credential, claim, now)
		if err != nil {
			t.Fatal(policy, err)
		}
		payload, err := Decode(strings.Split(token, ".")[0])
		if err != nil || bytes.Contains(payload, []byte(`"path"`)) || bytes.Contains(payload, []byte("song.mp3")) || bytes.Contains(payload, []byte("music/")) {
			t.Fatal("capability exposed a logical media path", err)
		}
		fields, err := verifyCapabilityToken(credential, token)
		if err != nil {
			t.Fatal(err)
		}
		fields["path"] = "music/测试/song.mp3"
		withPath, err := capabilityToken(credential, fields)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := VerifySelectedStorageUpload(credential, withPath, now+1); err == nil {
			t.Fatal("unexpected logical path accepted")
		}
		got, err := VerifySelectedStorageUpload(credential, token, now+1)
		if err != nil || got.Relationship != claim.Relationship || got.Owner != claim.Owner || got.UploadID != claim.UploadID || got.OperationID != claim.OperationID || got.RelationshipBinding != claim.RelationshipBinding || got.Generation != claim.Generation || got.StageID != claim.StageID || got.PublishChallenge != claim.PublishChallenge || got.CleanupChallenge != claim.CleanupChallenge || got.ContentSHA256 != claim.ContentSHA256 || got.Revision != claim.Revision || got.Policy != claim.Policy || got.ResourceOrigin != claim.ResourceOrigin || got.AdminOrigin != claim.AdminOrigin || got.AdminBinding != claim.AdminBinding || got.Encryption == nil || *got.Encryption != meta {
			t.Fatal("claim did not round-trip", policy, got, err)
		}
		if _, err := VerifyStorageToken(credential, token, now+1); err == nil {
			t.Fatal("legacy verifier accepted new policy-bound operation")
		}
		if _, err := VerifySelectedStorageUpload(credential, token, claim.ExpiresAt); err == nil {
			t.Fatal("expired capability accepted")
		}
		if _, err := VerifySelectedStorageUpload(Encode(bytes.Repeat([]byte{8}, 48)), token, now+1); err == nil {
			t.Fatal("different relationship credential accepted")
		}
		if _, err := VerifySelectedStorageUpload(credential, token+"x", now+1); err == nil {
			t.Fatal("tampered capability accepted")
		}
		cleanup, err := SignSelectedStorageCleanup(credential, claim, now)
		if err != nil {
			t.Fatal("cleanup capability", err)
		}
		if _, err = VerifySelectedStorageUpload(credential, cleanup, now+1); err == nil {
			t.Fatal("cleanup capability accepted for upload")
		}
		if _, err = VerifySelectedStorageCleanup(credential, token, now+1); err == nil {
			t.Fatal("upload capability accepted for cleanup")
		}
		cleaned, err := VerifySelectedStorageCleanup(credential, cleanup, now+1)
		if err != nil || cleaned.OperationID != claim.OperationID || cleaned.CleanupChallenge != claim.CleanupChallenge {
			t.Fatal("cleanup scope mismatch", err)
		}
	}

	for name, mutate := range map[string]func(*SelectedStorageUpload){
		"bad-owner":                 func(v *SelectedStorageUpload) { v.Owner = "https://storage.example" },
		"missing-revision":          func(v *SelectedStorageUpload) { v.Revision = 0 },
		"bad-session-binding":       func(v *SelectedStorageUpload) { v.AdminBinding = "" },
		"bad-admin-origin":          func(v *SelectedStorageUpload) { v.AdminOrigin = "https://master.example/path" },
		"missing-digest":            func(v *SelectedStorageUpload) { v.ContentSHA256 = "" },
		"missing-relation-binding":  func(v *SelectedStorageUpload) { v.RelationshipBinding = "" },
		"missing-generation":        func(v *SelectedStorageUpload) { v.Generation = "" },
		"missing-stage":             func(v *SelectedStorageUpload) { v.StageID = "" },
		"missing-publish-challenge": func(v *SelectedStorageUpload) { v.PublishChallenge = "" },
		"missing-cleanup-challenge": func(v *SelectedStorageUpload) { v.CleanupChallenge = "" },
		"reused-stage":              func(v *SelectedStorageUpload) { v.StageID = v.ObjectID },
		"reused-challenge":          func(v *SelectedStorageUpload) { v.CleanupChallenge = v.PublishChallenge },
		"reused-blob-id":            func(v *SelectedStorageUpload) { v.ObjectID = v.OperationID },
		"bad-direct-origin":         func(v *SelectedStorageUpload) { v.ResourceOrigin = "https://storage.example/path" },
		"bad-direct-port":           func(v *SelectedStorageUpload) { v.ResourceOrigin = "https://storage.example:8443" },
		"relay-with-origin":         func(v *SelectedStorageUpload) { v.Policy = "Relay" },
		"metadata-size":             func(v *SelectedStorageUpload) { v.Size++ },
		"too-long":                  func(v *SelectedStorageUpload) { v.ExpiresAt = now + TokenSeconds + 1 },
	} {
		t.Run(name, func(t *testing.T) {
			claim := base
			mutate(&claim)
			if _, err := SignSelectedStorageUpload(credential, claim, now); err == nil {
				t.Fatal("invalid claim signed")
			}
		})
	}

	t.Run("recording-domain", func(t *testing.T) {
		claim := base
		claim.RecordingIngressNode, claim.RecordingIngressGeneration = base.Master, 8
		recording, err := SignSelectedRecordingUpload(credential, claim, now)
		if err != nil {
			t.Fatal(err)
		}
		cleanup, err := SignSelectedRecordingCleanup(credential, claim, now)
		if err != nil {
			t.Fatal(err)
		}
		admin, err := SignSelectedStorageUpload(credential, base, now)
		if err != nil {
			t.Fatal(err)
		}
		got, err := VerifySelectedRecordingUpload(credential, recording, now)
		if err != nil || got.RecordingIngressNode != claim.RecordingIngressNode || got.RecordingIngressGeneration != claim.RecordingIngressGeneration || got.AdminOrigin != claim.AdminOrigin {
			t.Fatal("recording ingress binding did not round-trip", err)
		}
		if _, err = VerifySelectedRecordingCleanup(credential, cleanup, now); err != nil {
			t.Fatal("recording cleanup grant rejected", err)
		}
		for _, wrong := range []struct {
			token  string
			verify func(string, string, int64) (SelectedStorageUpload, error)
		}{
			{recording, VerifySelectedStorageUpload},
			{cleanup, VerifySelectedStorageCleanup},
			{recording, VerifySelectedRecordingCleanup},
			{cleanup, VerifySelectedRecordingUpload},
			{admin, VerifySelectedRecordingUpload},
		} {
			if _, err = wrong.verify(credential, wrong.token, now); err == nil {
				t.Fatal("cross-domain grant accepted")
			}
		}
		if _, err = SignSelectedStorageUpload(credential, claim, now); err == nil {
			t.Fatal("recording ingress fields accepted in Admin claim")
		}
		oversize, err := mediacrypto.NewMetadata(1 << 30)
		if err != nil {
			t.Fatal(err)
		}
		for name, mutate := range map[string]func(*SelectedStorageUpload){
			"no-node":    func(v *SelectedStorageUpload) { v.RecordingIngressNode = "" },
			"no-epoch":   func(v *SelectedStorageUpload) { v.RecordingIngressGeneration = 0 },
			"same-owner": func(v *SelectedStorageUpload) { v.Owner = v.Master },
			"relay":      func(v *SelectedStorageUpload) { v.Policy, v.ResourceOrigin = "Relay", "" },
			"cleartext":  func(v *SelectedStorageUpload) { v.Encryption = nil },
			"oversize":   func(v *SelectedStorageUpload) { v.Encryption, v.Size = &oversize, oversize.CiphertextSize },
		} {
			t.Run(name, func(t *testing.T) {
				invalid := claim
				mutate(&invalid)
				if _, err := SignSelectedRecordingUpload(credential, invalid, now); err == nil {
					t.Fatal("invalid recording claim signed")
				}
			})
		}
	})
}

func TestSelectedStorageAdminBindingIsRelationshipScoped(t *testing.T) {
	credential := Encode(bytes.Repeat([]byte{7}, 48))
	relationship, session := strings.Repeat("1", 32), strings.Repeat("a", 64)
	first, err := SelectedStorageAdminBinding(credential, relationship, session)
	if err != nil || !objectID.MatchString(first) || first == session {
		t.Fatal("invalid pseudonymous binding", err)
	}
	again, err := SelectedStorageAdminBinding(credential, relationship, session)
	if err != nil || again != first {
		t.Fatal("binding is not stable", err)
	}
	otherSession, err := SelectedStorageAdminBinding(credential, relationship, strings.Repeat("b", 64))
	if err != nil || otherSession == first {
		t.Fatal("different sessions were conflated", err)
	}
	otherRelation, err := SelectedStorageAdminBinding(credential, strings.Repeat("2", 32), session)
	if err != nil || otherRelation == first {
		t.Fatal("different relationships were conflated", err)
	}
	if _, err = SelectedStorageAdminBinding(credential, relationship, "session-cookie"); err == nil {
		t.Fatal("raw or malformed session accepted")
	}
}
