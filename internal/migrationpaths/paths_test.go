package migrationpaths

import "testing"

func TestCloseDropsStoredPaths(t *testing.T) {
	var p MigrationPathPreflight
	if err := p.Add("synthetic/track", false); err != nil {
		t.Fatal(err)
	}
	p.Close()
	if len(p.paths) != 0 {
		t.Fatal("source path references retained")
	}
}
