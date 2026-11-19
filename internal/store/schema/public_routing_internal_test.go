package schema

import "testing"

func TestPublicRoutingMySQLConstraintNormalizationPreservesLiteralValues(t *testing.T) {
	canonical := "CHECK (configured_transport IN ('Direct','Relay'))"
	mysql := "check ((`configured_transport` in (_utf8mb4'Direct',_utf8mb4'Relay')))"
	if normalizedS3Check(canonical) != normalizedS3Check(mysql) {
		t.Fatal("MySQL's equivalent character-set introducer was not recognized")
	}
	mysqlEscaped := "check ((`configured_transport` in (_utf8mb4\\'Direct\\',_utf8mb4\\'Relay\\')))"
	if normalizedS3Check(canonical) != normalizedS3Check(mysqlEscaped) {
		t.Fatal("MySQL's escaped metadata literal was not recognized")
	}
	ddl := "CREATE TABLE native_transport_policy (configured_transport VARCHAR(16) NOT NULL, revision BIGINT NOT NULL, CHECK (configured_transport IN ('Direct','Relay')), CHECK (revision>0))"
	expected := s3Checks(ddl)
	actual := []string{
		normalizedS3Check("(`configured_transport` in (_utf8mb4\\'Direct\\',_utf8mb4\\'Relay\\'))"),
		normalizedS3Check("(`revision` > 0)"),
	}
	if len(expected) != 2 || expected[0] != actual[0] || expected[1] != actual[1] {
		t.Fatalf("MySQL clause mismatch: expected %q, got %q", expected, actual)
	}
	for _, foreign := range []string{
		"CHECK (configured_transport IN ('Direct_utf8mb4','Relay'))",
		"CHECK (configured_transport IN ('Direct','Direct'))",
		"CHECK (configured_transport IN ('DIRECT','Relay'))",
		"CHECK (configured_transport IN (_utf8mb4\\'Direct(extra)\\',_utf8mb4\\'Relay\\'))",
		"CHECK (configured_transport IN (_utf8mb4\\'Direct\\',_utf8mb4\\'Relay2\\'))",
	} {
		if normalizedS3Check(canonical) == normalizedS3Check(foreign) {
			t.Fatal("different literal values must remain different", foreign)
		}
	}
}

func TestSelectedUploadMySQLConstraintNormalizationPreservesStateValues(t *testing.T) {
	canonical := "CHECK (state IN ('pending','completed','cancelled'))"
	actual := "(`state` in (_utf8mb4\\'pending\\',_utf8mb4\\'completed\\',_utf8mb4\\'cancelled\\'))"
	expected := s3Checks(canonical)
	if len(expected) != 1 || expected[0] != normalizedS3Check(actual) {
		t.Fatal("MySQL 8.4 state constraint did not match canonical DDL")
	}
	for _, foreign := range []string{
		"(`state` in (_utf8mb4\\'pending2\\',_utf8mb4\\'completed\\',_utf8mb4\\'cancelled\\'))",
		"(`state` in (_utf8mb4\\'pending\\',_utf8mb4\\'completed\\',_utf8mb4\\'cancelled2\\'))",
		"(`state` in (_utf8mb4\\'PENDING\\',_utf8mb4\\'completed\\',_utf8mb4\\'cancelled\\'))",
		"(`state` in (_utf8mb4\\'pending\\',_utf8mb4\\'completed\\',_utf8mb4\\'pending\\'))",
	} {
		if expected[0] == normalizedS3Check(foreign) {
			t.Fatal("different state constraint accepted", foreign)
		}
	}
}
