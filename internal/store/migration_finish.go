package store

import "sort"

type MigrationUnitFinishGrant struct {
	Header      MigrationPeerHeader `json:"header"`
	Unit        MigrationUnit       `json:"unit"`
	UnitVersion string              `json:"unit_version"`
	ObjectsSHA  string              `json:"objects_sha256"`
}
type MigrationUnitFinishReceipt struct {
	Grant    MigrationUnitFinishGrant `json:"grant"`
	MemberID string                   `json:"member_id"`
	Complete bool                     `json:"complete"`
}

// Both peers reconstruct this digest from their complete persisted roster;
// no long object list or caller-selected filesystem path is carried by the RPC.
func MigrationUnitObjectsSHA(objects []MigrationPeerObject) (string, error) {
	copyObjects := append([]MigrationPeerObject(nil), objects...)
	for i := range copyObjects {
		copyObjects[i].Header = MigrationPeerHeader{}
		copyObjects[i].State = ""
	}
	sort.Slice(copyObjects, func(i, j int) bool { return copyObjects[i].Object.ID < copyObjects[j].Object.ID })
	return MigrationDigest(copyObjects)
}
