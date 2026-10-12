package store

import "sort"

type MigrationDrainReceipt struct {
	TaskID   string `json:"task_id"`
	SourceID string `json:"source_id"`
	PlanSHA  string `json:"plan_sha256"`
	Released bool   `json:"released"`
}

type MigrationTaskFinishGrant struct {
	Outcome   string              `json:"outcome"`
	Header    MigrationPeerHeader `json:"header"`
	UnitsSHA  string              `json:"units_sha256"`
	UnitCount int64               `json:"unit_count"`
}
type MigrationTaskFinishReceipt struct {
	Grant    MigrationTaskFinishGrant `json:"grant"`
	MemberID string                   `json:"member_id"`
	Complete bool                     `json:"complete"`
}

func MigrationTaskUnitsSHA(units []MigrationUnitFinishGrant) (string, error) {
	copyUnits := append([]MigrationUnitFinishGrant(nil), units...)
	sort.Slice(copyUnits, func(i, j int) bool { return copyUnits[i].Unit.ID < copyUnits[j].Unit.ID })
	return MigrationDigest(copyUnits)
}

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
