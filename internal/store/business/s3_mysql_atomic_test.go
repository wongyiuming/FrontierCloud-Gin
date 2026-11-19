package business_test

import (
	"os"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// Verify InnoDB rollback with faults inside the two publication transactions.
func TestS3MySQLAtomicReservationAndPublicationFaults(t *testing.T) {
	if os.Getenv("FRONTIERCLOUD_TEST_MYSQL_HOST") == "" {
		t.Skip("requires isolated MySQL test database")
	}
	f := newS3SQL(t, true)
	member := f.add(t, "mysql-atomic", true)
	t.Cleanup(func() {
		_, _ = f.raw.Exec("DROP TRIGGER IF EXISTS fail_s3_mysql_reserve")
		_, _ = f.raw.Exec("DROP TRIGGER IF EXISTS fail_s3_mysql_publish")
	})
	if _, err := f.raw.Exec("CREATE TRIGGER fail_s3_mysql_reserve BEFORE INSERT ON s3_uploads FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'fixture reserve failure'"); err != nil {
		t.Fatal(err)
	}
	meta, err := mediacrypto.NewMetadata(11)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.pool.(store.EncryptionRepository).ReserveEncryptedUpload(f.ctx, "music/S3MySQLAtomic/a.mp3", "s3", meta.CiphertextSize, 0, store.AdminAudit{}, &meta); err == nil || !strings.Contains(err.Error(), "fixture reserve failure") {
		t.Fatalf("reservation did not reach injected failure: %v", err)
	}
	for _, table := range []string{"cluster_upload_sessions", "media_encryption", "s3_uploads"} {
		var count int
		if err = f.raw.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil || count != 0 {
			t.Fatal("reservation partially committed", table, count, err)
		}
	}
	member, err = f.repo.S3Member(f.ctx, member.ID)
	if err != nil || member.Reserved != 0 {
		t.Fatal("failed reservation leaked quota", member, err)
	}
	if _, err = f.raw.Exec("DROP TRIGGER fail_s3_mysql_reserve"); err != nil {
		t.Fatal(err)
	}
	u, proof := f.completing(t, f.reserve(t, "music/S3MySQLAtomic/a.mp3", meta.CiphertextSize, &meta))
	if _, err = f.raw.Exec("CREATE TRIGGER fail_s3_mysql_publish BEFORE INSERT ON s3_objects FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'fixture publication failure'"); err != nil {
		t.Fatal(err)
	}
	if _, err = f.repo.S3FinalizeUpload(f.ctx, u.Reservation.ID, u.Revision, proof, store.AdminAudit{}); err == nil || !strings.Contains(err.Error(), "fixture publication failure") {
		t.Fatalf("publication did not reach injected failure: %v", err)
	}
	member, err = f.repo.S3Member(f.ctx, member.ID)
	if err != nil || member.Used != 0 || member.Reserved != proof.Bytes {
		t.Fatal("publication partially changed quota", member, err)
	}
	var count int
	if err = f.raw.QueryRow("SELECT COUNT(*) FROM global_media_objects").Scan(&count); err != nil || count != 0 {
		t.Fatal("partial global catalog", count, err)
	}
	current, err := f.repo.S3Upload(f.ctx, u.Reservation.ID)
	if err != nil || current.State != "completing" || current.Reservation.State != "reserved" || current.Reservation.Encryption == nil {
		t.Fatal("completion rollback lost journal/crypto", current, err)
	}
	if _, err = f.raw.Exec("DROP TRIGGER fail_s3_mysql_publish"); err != nil {
		t.Fatal(err)
	}
	if _, err = f.repo.S3FinalizeUpload(f.ctx, u.Reservation.ID, u.Revision, proof, store.AdminAudit{}); err != nil {
		t.Fatal("same-proof retry after SQL fault", err)
	}
}
