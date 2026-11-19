package protocol

import (
	"strings"
	"testing"
)

func TestLegacyReadDrainReceiptBindsScopeAndChallenge(t *testing.T) {
	r := LegacyReadDrainReceipt{Kind: "legacy-media-drain-v1", OperationID: strings.Repeat("a", 32), Challenge: strings.Repeat("b", 64), ExpiresAt: 12345, MasterID: strings.Repeat("c", 32), OwnerID: strings.Repeat("d", 32), RelationshipID: strings.Repeat("e", 32), RelationshipBinding: strings.Repeat("f", 64), OwnerBinding: strings.Repeat("1", 64), FenceBinding: strings.Repeat("2", 64), State: "revoked"}
	if _, err := r.Payload(); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*LegacyReadDrainReceipt){
		func(v *LegacyReadDrainReceipt) { v.Kind = "opaque-alias-revoke-v1" },
		func(v *LegacyReadDrainReceipt) { v.State = "active" },
		func(v *LegacyReadDrainReceipt) { v.OperationID = "bad" },
		func(v *LegacyReadDrainReceipt) { v.Challenge = "" },
		func(v *LegacyReadDrainReceipt) { v.ExpiresAt = 0 },
		func(v *LegacyReadDrainReceipt) { v.RelationshipBinding = "" },
		func(v *LegacyReadDrainReceipt) { v.OwnerBinding = "" },
		func(v *LegacyReadDrainReceipt) { v.FenceBinding = "" },
	} {
		copy := r
		mutate(&copy)
		if _, err := copy.Payload(); err == nil {
			t.Fatal("invalid receipt accepted", copy)
		}
	}
}

func TestLegacyReadEnrollmentReceiptRequiresOwnerScope(t *testing.T) {
	r := LegacyReadEnrollmentReceipt{Kind: "legacy-media-enrollment-v1", Challenge: strings.Repeat("a", 64), MasterID: strings.Repeat("b", 32), OwnerID: strings.Repeat("c", 32), RelationshipID: strings.Repeat("d", 32), RelationshipBinding: strings.Repeat("e", 64), OwnerBinding: strings.Repeat("f", 64), FenceBinding: strings.Repeat("1", 64), State: "active"}
	if _, err := r.Payload(); err != nil {
		t.Fatal(err)
	}
	request := LegacyReadEnrollmentRequest{RelationshipID: r.RelationshipID, Challenge: r.Challenge}
	if !request.Valid() {
		t.Fatal("valid challenge rejected")
	}
	request.Challenge = "bad"
	if request.Valid() {
		t.Fatal("invalid challenge accepted")
	}
	r.OwnerBinding = ""
	if _, err := r.Payload(); err == nil {
		t.Fatal("missing owner binding accepted")
	}
}

func TestLegacyReadStatusRequiresFreshChallengeAndOriginalOperation(t *testing.T) {
	r := LegacyReadStatusRequest{Action: "status", RequestID: strings.Repeat("a", 32), Challenge: strings.Repeat("b", 64), OriginalOperationID: strings.Repeat("c", 32), OriginalChallenge: strings.Repeat("d", 64), OriginalExpiresAt: 12345, ExpiresAt: 23456, MasterID: strings.Repeat("e", 32), OwnerID: strings.Repeat("f", 32), RelationshipID: strings.Repeat("1", 32), RelationshipBinding: strings.Repeat("2", 64), OwnerBinding: strings.Repeat("3", 64), FenceBinding: strings.Repeat("4", 64)}
	for _, state := range []string{"draining", "revoked"} {
		if _, err := r.Receipt(state); err != nil {
			t.Fatal(state, err)
		}
	}
	if _, err := r.Receipt("active"); err == nil {
		t.Fatal("active status accepted")
	}
	status, err := r.Receipt("revoked")
	if err != nil {
		t.Fatal(err)
	}
	r.Action = "resume"
	resume, err := r.Receipt("revoked")
	if err != nil {
		t.Fatal(err)
	}
	statusPayload, _ := status.Payload()
	resumePayload, _ := resume.Payload()
	if statusPayload["action"] == resumePayload["action"] {
		t.Fatal("action not signed")
	}
	r.Action = "other"
	if _, err = r.Receipt("revoked"); err == nil {
		t.Fatal("invalid action accepted")
	}
	r.Action = "resume"
	r.Challenge = r.OriginalChallenge
	if _, err := r.Receipt("revoked"); err == nil {
		t.Fatal("old challenge accepted")
	}
}
