package sealedtree

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestMigrationPathPreflightPreservesExactNamesAndRejectsAmbiguity(t *testing.T) {
	var p MigrationPathPreflight
	for _, value := range []struct {
		path string
		dir  bool
	}{
		{"音乐/专辑/晴天.mp3", false},
		{"音乐/专辑", true}, // previously implied parent
		{"音乐/专辑/A.mp3", false},
		{"音乐/专辑/a.mp3", false},
		{"音乐/专辑/é.mp3", false},
		{"音乐/专辑/e\u0301.mp3", false},
	} {
		if err := p.Add(value.path, value.dir); err != nil {
			t.Fatal(err)
		}
	}
	if n, err := p.Counts(); err != nil || n != 7 {
		t.Fatal("unexpected exact-path count", n, err)
	}
	if err := p.Add("音乐/专辑/A.mp3", false); !errors.Is(err, ErrMigrationPathConflict) {
		t.Fatal("duplicate explicit path accepted", err)
	}
	if n, err := p.Counts(); n != 0 || !errors.Is(err, ErrMigrationPathConflict) {
		t.Fatal("partial plan reported complete", n, err)
	}
}

func TestMigrationPathPreflightRefusesOversizedCatalog(t *testing.T) {
	var p MigrationPathPreflight
	for i := 0; i < migrationMaxEntries; i++ {
		if err := p.Add(fmt.Sprintf("object-%05d", i), false); err != nil {
			t.Fatal("within-budget source rejected", err)
		}
	}
	if err := p.Add("one-too-many", false); !errors.Is(err, ErrMigrationPathConflict) {
		t.Fatal("over-budget source accepted", err)
	}
	if _, err := p.Counts(); !errors.Is(err, ErrMigrationPathConflict) {
		t.Fatal("truncated source reported as complete", err)
	}
}

func TestMigrationPathPreflightCloseRefusesReuse(t *testing.T) {
	var p MigrationPathPreflight
	if err := p.Add("synthetic/track", false); err != nil {
		t.Fatal(err)
	}
	p.Close()
	if _, err := p.Counts(); !errors.Is(err, ErrMigrationPathConflict) {
		t.Fatal("closed preflight reported results", err)
	}
	if err := p.Add("another", false); !errors.Is(err, ErrMigrationPathConflict) {
		t.Fatal("closed preflight reused", err)
	}
}

func TestMigrationPathPreflightRefusesExcessivePathBytes(t *testing.T) {
	var p MigrationPathPreflight
	defer p.Close()
	suffix := strings.Repeat("x", 995)
	for i := 0; i < migrationMaxEntries; i++ {
		err := p.Add(fmt.Sprintf("%05d%s", i, suffix), false)
		if err != nil {
			if !errors.Is(err, ErrMigrationPathConflict) || i != migrationMaxPathBytes/1000 {
				t.Fatal("unexpected byte limit", i, err)
			}
			if _, err = p.Counts(); !errors.Is(err, ErrMigrationPathConflict) {
				t.Fatal("partial source reported complete", err)
			}
			return
		}
	}
	t.Fatal("excessive source path bytes accepted")
}

func TestMigrationPathPreflightRejectsFileParentsAndInvalidComponents(t *testing.T) {
	for _, values := range [][]struct {
		path string
		dir  bool
	}{
		{{"x", false}, {"x/y", false}},
		{{"x/y", false}, {"x", false}},
		{{"x//y", false}},
		{{"x/../y", false}},
		{{"x\\y", false}},
		{{strings.Repeat("x/", 128) + "y", false}},
	} {
		var p MigrationPathPreflight
		var err error
		for _, value := range values {
			err = p.Add(value.path, value.dir)
			if err != nil {
				break
			}
		}
		if !errors.Is(err, ErrMigrationPathConflict) {
			t.Fatal("ambiguous source accepted", err)
		}
	}
}
