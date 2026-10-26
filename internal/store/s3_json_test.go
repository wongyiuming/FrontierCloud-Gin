package store

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestS3JSONCredentialsAndUnknownPhysicalFacts(t *testing.T) {
	v := S3Member{StorageMember: StorageMember{ID: "fixture", Kind: "S3", Transport: "S3", Allocation: MaxStorageAllocation, Used: 9007199254740993, Compute: map[string]any{"enabled": true}, Backup: map[string]any{"enabled": true}}, Name: "bucket", SealedCredentials: "DO-NOT-SERIALIZE", Revision: 3, CredentialRevision: 2, Location: S3Location{Bucket: "test"}}
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err = json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"physical_free_bytes", "physical_total_bytes", "compute", "backup"} {
		if string(fields[key]) != "null" {
			t.Fatal("invented provider fact", key, string(raw))
		}
	}
	if string(fields["physical_capacity_known"]) != "false" || string(fields["external_traffic_known"]) != "false" || string(fields["used_bytes"]) != "9007199254740993" || string(fields["revision"]) != "3" || string(fields["name"]) != `"bucket"` {
		t.Fatal("lost S3 fields or integer precision", string(raw))
	}
	if strings.Contains(string(raw), v.SealedCredentials) || strings.Contains(fmt.Sprintf("%+v %#v", v, v), v.SealedCredentials) {
		t.Fatal("sealed credentials escaped")
	}
	nativeValue := StorageMember{Kind: "MasterLocal", PhysicalFree: 9007199254740993}
	native, err := json.Marshal(nativeValue)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(native), `"physical_free_bytes":9007199254740993`) || strings.Contains(string(native), `"physical_capacity_known"`) {
		t.Fatal("native DTO regression", string(native))
	}
	type original StorageMember
	originalJSON, err := json.Marshal(original(nativeValue))
	if err != nil || !bytes.Equal(native, originalJSON) {
		t.Fatal("native migration manifest serialization bytes changed", string(native), string(originalJSON), err)
	}
}
