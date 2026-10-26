package recovery_test

import (
	"context"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/recovery"
	"github.com/wongyiuming/FrontierCloud-Gin/migrations"
)

func TestArchiveKeepsExplicitSupportedSourceGeneration(t *testing.T) {
	if migrations.Generation != 8 {
		t.Skip("explicit generation-8 recovery boundary")
	}
	for _, generation := range []int{6, 7} {
		t.Run(string(rune('0'+generation)), func(t *testing.T) {
			_, archive, m, sources := fixture(t)
			m.SchemaGeneration = generation
			r, e := recovery.Create(context.Background(), archive, m, sources)
			if e != nil {
				t.Fatal(e)
			}
			if r.Manifest.SchemaGeneration != generation {
				t.Fatal("backup relabelled old database with operator generation")
			}
			checked, e := recovery.Check(context.Background(), archive, r.SHA256)
			if e != nil || checked.Manifest.SchemaGeneration != generation {
				t.Fatal(checked.Manifest.SchemaGeneration, e)
			}
		})
	}
}
func TestArchiveRejectsUndefinedOldAndFutureGeneration(t *testing.T) {
	for _, generation := range []int{5, migrations.Generation + 1} {
		t.Run(string(rune('0'+generation)), func(t *testing.T) {
			_, archive, m, sources := fixture(t)
			m.SchemaGeneration = generation
			if _, e := recovery.Create(context.Background(), archive, m, sources); e == nil {
				t.Fatal("undefined recovery compatibility accepted", generation)
			}
		})
	}
}
