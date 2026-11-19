package business

import (
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/migrations"
)

func TestLegacyBackupGuardCoversEveryCanonicalSealedTreeTable(t *testing.T) {
	for _, backend := range []string{"sqlite", "mysql"} {
		statements, err := migrations.SealedTreeStatements(backend)
		if err != nil {
			t.Fatal(err)
		}
		// The v2 export also cannot represent the independently versioned
		// legacy-read control intents. Omission can resurrect a revoked reader.
		intentStatements, err := migrations.LegacyReadIntentStatements(backend)
		if err != nil {
			t.Fatal(err)
		}
		statements = append(statements, intentStatements...)
		selectedStatements, err := migrations.SelectedUploadIntentStatements(backend)
		if err != nil {
			t.Fatal(err)
		}
		statements = append(statements, selectedStatements...)
		seen := make(map[string]bool)
		for _, statement := range statements {
			const prefix = "CREATE TABLE IF NOT EXISTS "
			if !strings.HasPrefix(statement, prefix) {
				continue
			}
			name := strings.Fields(strings.TrimPrefix(statement, prefix))[0]
			seen[name] = true
		}
		if len(seen) != len(unsupportedSealedTreeBackupTables) {
			t.Fatalf("%s sealed-tree backup guard count mismatch", backend)
		}
		for _, name := range unsupportedSealedTreeBackupTables {
			if !seen[name] {
				t.Fatalf("%s missing sealed-tree guard", backend)
			}
		}
	}
}
