package sourceauth

import (
	"reflect"
	"strings"
	"testing"
)

func TestSourceCapabilityPreflightsInputBeforeEncoding(t *testing.T) {
	small := CompleteSnapshot{Projection: Snapshot{Media: []Media{{Path: "music/small.mp3"}}}}
	budget := 4 * 1024 * 1024
	if !boundCapabilityInput(reflect.ValueOf(small), &budget, 0) {
		t.Fatal("small input rejected")
	}
	huge := CompleteSnapshot{Projection: Snapshot{Media: []Media{{Path: strings.Repeat("x", 1024*1024)}}}}
	budget = 4 * 1024 * 1024
	if boundCapabilityInput(reflect.ValueOf(huge), &budget, 0) {
		t.Fatal("oversized input reached JSON encoding")
	}
}
