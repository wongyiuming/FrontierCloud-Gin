package preprodimport

import (
	"strings"
	"testing"
)

func syntheticImportScope(s Snapshot) *sourceImportScope {
	return &sourceImportScope{Version: 1, Purpose: "frontiercloud:preprod-approved-scope:v1", Mappings: append([]Mapping(nil), s.Mappings...), ExcludedTencentSourceID: s.ExcludedSourceIDs[0]}
}

func TestApprovedScopeBindsOnlyTencentAndExactMappings(t *testing.T) {
	mappings := []Mapping{{SourceID: strings.Repeat("1", 32), TargetID: strings.Repeat("4", 32), Role: "master", Capacity: 1000}, {SourceID: strings.Repeat("2", 32), TargetID: strings.Repeat("5", 32), Role: "direct", Capacity: 1000}, {SourceID: strings.Repeat("3", 32), TargetID: strings.Repeat("6", 32), Role: "relay", Capacity: 1000}}
	excluded := strings.Repeat("7", 32)
	projection := Snapshot{Mappings: append([]Mapping(nil), mappings...), ExcludedSourceIDs: []string{excluded}}
	scope := &sourceImportScope{Version: 1, Purpose: "frontiercloud:preprod-approved-scope:v1", Mappings: append([]Mapping(nil), mappings...), ExcludedTencentSourceID: excluded}
	if !sourceScopeMatches(scope, projection) {
		t.Fatal("exact independently approved scope rejected")
	}
	t.Run("no approval", func(t *testing.T) {
		if sourceScopeMatches(nil, projection) {
			t.Fatal("missing approval accepted")
		}
	})
	t.Run("other exclusion", func(t *testing.T) {
		p := projection
		p.ExcludedSourceIDs = []string{strings.Repeat("8", 32)}
		if sourceScopeMatches(scope, p) {
			t.Fatal("other exclusion accepted")
		}
	})
	t.Run("additional exclusion", func(t *testing.T) {
		p := projection
		p.ExcludedSourceIDs = []string{excluded, strings.Repeat("8", 32)}
		if sourceScopeMatches(scope, p) {
			t.Fatal("extra excluded owner accepted")
		}
	})
	t.Run("target mapping", func(t *testing.T) {
		p := projection
		p.Mappings = append([]Mapping(nil), p.Mappings...)
		p.Mappings[1].TargetID = strings.Repeat("8", 32)
		if sourceScopeMatches(scope, p) {
			t.Fatal("unapproved target accepted")
		}
	})
	t.Run("capacity", func(t *testing.T) {
		p := projection
		p.Mappings = append([]Mapping(nil), p.Mappings...)
		p.Mappings[1].Capacity++
		if sourceScopeMatches(scope, p) {
			t.Fatal("unapproved capacity accepted")
		}
	})
	t.Run("duplicate", func(t *testing.T) {
		p := projection
		p.Mappings = append([]Mapping(nil), p.Mappings...)
		p.Mappings[1] = p.Mappings[0]
		if sourceScopeMatches(scope, p) {
			t.Fatal("duplicate accepted")
		}
	})
}
