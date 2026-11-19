package business

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/migrations"
	_ "modernc.org/sqlite"
)

type recoveryAccountingFixtureLease string

func (l recoveryAccountingFixtureLease) Check(ctx context.Context) error { return ctx.Err() }
func (l recoveryAccountingFixtureLease) Binding(context.Context) (string, error) {
	return string(l), nil
}
func (recoveryAccountingFixtureLease) Release() {}

func TestRecoveryAccountingRosterRejectsAmbiguousOrUnsettledOwners(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "pool.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	schema, err := migrations.Statements("sqlite")
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range schema {
		exec(stmt)
	}
	repo := New(db, "sqlite")
	master, direct, relay := strings.Repeat("1", 32), strings.Repeat("2", 32), strings.Repeat("3", 32)
	provider, retired := strings.Repeat("4", 32), strings.Repeat("5", 32)
	directRelation, relayRelation, retiredRelation := strings.Repeat("a", 32), strings.Repeat("b", 32), strings.Repeat("c", 32)
	lease := recoveryAccountingFixtureLease(strings.Repeat("f", 64))
	exec(`INSERT INTO sealed_tree_owner_fence VALUES(1,?)`, string(lease))
	exec(`INSERT INTO node_identity VALUES(1,?,'Master','https://master.test','fixture',1)`, master)
	exec(`INSERT INTO node_relationships VALUES(?,?,?,'fixture','fixture','downstream','Direct','active','offline',1,0,0,0,'fixture',2,'{}',1)`, directRelation, direct, "https://direct.test")
	exec(`INSERT INTO node_relationships VALUES(?,?,?,'fixture','fixture','downstream','Relay','active','offline',1,0,0,0,'fixture',2,'{}',1)`, relayRelation, relay, "https://relay.test")
	exec(`INSERT INTO node_relationships VALUES(?,?,?,'fixture','fixture','downstream','Relay','revoked','offline',1,0,0,0,'fixture',2,'{}',1)`, retiredRelation, retired, "https://retired.test")
	exec(`INSERT INTO cluster_storage_members VALUES(?,NULL,'MasterLocal','Local',1,1024,40,0,0,'online',1,1)`, master)
	exec(`INSERT INTO cluster_storage_members VALUES(?,?,'Follower','Direct',1,1024,50,0,0,'offline',0,1)`, direct, directRelation)
	exec(`INSERT INTO cluster_storage_members VALUES(?,?,'Follower','Relay',1,1024,30,0,0,'offline',0,1)`, relay, relayRelation)
	exec(`INSERT INTO cluster_storage_members VALUES(?,?,'Follower','Relay',0,1024,0,0,0,'offline',0,1)`, retired, retiredRelation)
	exec(`INSERT INTO cluster_storage_members VALUES(?,NULL,'S3','S3',1,1024,60,0,0,'online',1,1)`, provider)
	exec(`INSERT INTO s3_members(member_id,name,endpoint,region,bucket,prefix,address_style,namespace_key,sealed_credentials,credential_revision,revision,probe_revision,probe_state,created_at,updated_at) VALUES(?,'fixture','https://s3.test','fixture','fixture','managed','path','fixture','sealed',1,1,1,'ready',1,1)`, provider)
	owners, err := repo.recoveryAccountingRoster(ctx, lease)
	if err != nil || len(owners) != 4 || owners[0].ID != master || owners[1].ID != direct || owners[1].RelationshipID != directRelation || owners[2].ID != relay || owners[2].RelationshipID != relayRelation || owners[3].ID != provider {
		t.Fatalf("unexpected recovery roster: %+v, %v", owners, err)
	}
	if owners[0].add(40, false) != nil || owners[1].add(50, false) != nil || owners[2].add(30, false) != nil || owners[3].add(60, true) != nil || owners[0].Bytes != 40 || owners[3].Objects != 1 {
		t.Fatalf("exact charges rejected: %+v", owners)
	}
	if owners[3].add(1, false) == nil || owners[1].add(1, false) == nil || (*recoveryOwnerCharge)(nil).add(1, false) == nil {
		t.Fatal("charge accepted on the wrong, overcharged or absent owner")
	}
	for _, tc := range []struct {
		name, change, restore, id string
	}{
		{"reserved bytes", `UPDATE cluster_storage_members SET reserved_bytes=1 WHERE member_id=?`, `UPDATE cluster_storage_members SET reserved_bytes=0 WHERE member_id=?`, master},
		{"revoked owner still charged", `UPDATE cluster_storage_members SET used_bytes=1 WHERE member_id=?`, `UPDATE cluster_storage_members SET used_bytes=0 WHERE member_id=?`, retired},
		{"owner relationship mode differs", `UPDATE cluster_storage_members SET transport='Relay' WHERE member_id=?`, `UPDATE cluster_storage_members SET transport='Direct' WHERE member_id=?`, direct},
		{"active relationship missing its owner", `UPDATE cluster_storage_members SET relationship_id=NULL WHERE member_id=?`, `UPDATE cluster_storage_members SET relationship_id='` + directRelation + `' WHERE member_id=?`, direct},
	} {
		t.Run(tc.name, func(t *testing.T) {
			exec(tc.change, tc.id)
			defer exec(tc.restore, tc.id)
			if got, err := repo.recoveryAccountingRoster(ctx, lease); !errors.Is(err, errRecoveryAccounting) || got != nil {
				t.Fatalf("invalid roster accepted: %+v, %v", got, err)
			}
		})
	}
}
