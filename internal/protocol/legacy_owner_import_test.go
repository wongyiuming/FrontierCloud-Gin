package protocol

import (
	"bytes"
	"strings"
	"testing"
)

func TestLegacyOwnerReceiptBindsExactSignedPlanWithoutPath(t *testing.T) {
	p := LegacyOwnerImportPlan{Kind: "legacy-owner-import-v1", MasterID: strings.Repeat("1", 32), OwnerID: strings.Repeat("2", 32), RelationshipID: strings.Repeat("3", 32), RelationshipBinding: strings.Repeat("4", 64), OwnerBinding: strings.Repeat("5", 64), FenceBinding: strings.Repeat("6", 64), Generation: strings.Repeat("7", 64), OperationID: strings.Repeat("8", 64), StageID: strings.Repeat("9", 64), BlobID: strings.Repeat("a", 64), SourceID: strings.Repeat("b", 64), SourcePath: "music/album/song.mp3", Digest: strings.Repeat("c", 64), Bytes: 20, Challenge: strings.Repeat("d", 64), ExpiresAt: 12345}
	receipt, err := p.PublishedReceipt()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := receipt["source_path"]; ok {
		t.Fatal("receipt exposes old path")
	}
	key := Encode(bytes.Repeat([]byte{7}, 32))
	public, err := PublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := Sign(key, receipt)
	if err != nil || Verify(public, receipt, sig) != nil {
		t.Fatal("signature", err)
	}
	for _, mutate := range []func(*LegacyOwnerImportPlan){func(v *LegacyOwnerImportPlan) { v.SourcePath = "music/album/other.mp3" }, func(v *LegacyOwnerImportPlan) { v.SourceID = strings.Repeat("e", 64) }, func(v *LegacyOwnerImportPlan) { v.FenceBinding = strings.Repeat("e", 64) }, func(v *LegacyOwnerImportPlan) { v.ExpiresAt++ }} {
		changed := p
		mutate(&changed)
		got, e := changed.PublishedReceipt()
		if e != nil || Verify(public, got, sig) == nil {
			t.Fatal("modified plan reused receipt", e)
		}
	}
	for _, bad := range []string{"music/../escape.mp3", "music/.hidden/song.mp3", "/music/a.mp3", "lyrics/song.lrc", "music\\a.mp3"} {
		changed := p
		changed.SourcePath = bad
		if _, err = changed.Payload(); err == nil {
			t.Fatal("unsafe path accepted", bad)
		}
	}
}
