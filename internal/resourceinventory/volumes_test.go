package resourceinventory

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVolumeSessionsPinnedExclusionsScopeAndSingleSlot(t *testing.T) {
	directory := t.TempDir()
	if e := os.Mkdir(filepath.Join(directory, "media"), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(directory, "media", "native.mp3"), []byte("native"), 0600); e != nil {
		t.Fatal(e)
	}
	data, e := os.OpenRoot(directory)
	if e != nil {
		t.Fatal(e)
	}
	defer data.Close()
	media, e := data.OpenRoot("media")
	if e != nil {
		t.Fatal(e)
	}
	defer media.Close()
	recording, e := os.OpenRoot(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer recording.Close()
	pin, e := media.Stat(".")
	if e != nil {
		t.Fatal(e)
	}
	sessions, e := NewVolumeSessions(data, media, recording, map[string]os.FileInfo{"media": pin}, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer sessions.Close()
	binding := Binding{MemberID: strings.Repeat("1", 32), MasterID: strings.Repeat("2", 32), RelationshipID: strings.Repeat("3", 32), Scope: "data"}
	opened, e := sessions.Open(context.Background(), strings.Repeat("4", 32), binding)
	if e != nil {
		t.Fatal(e)
	}
	native := binding
	native.Scope = "media"
	if _, e = sessions.Open(context.Background(), strings.Repeat("5", 32), native); !errors.Is(e, ErrBusy) {
		t.Fatal("scope bypassed slot", e)
	}
	page, e := sessions.Page(context.Background(), opened.ID, opened.Incarnation, binding, 0)
	if e != nil {
		t.Fatal(e)
	}
	if !page.Page.Complete || page.Page.LogicalBytes != 0 || len(page.Page.Entries) != 1 || page.Page.Entries[0].Path != "media" {
		t.Fatal("duplicate native descent", page)
	}
	if _, e = sessions.Page(context.Background(), opened.ID, opened.Incarnation, native, 0); !errors.Is(e, ErrSession) {
		t.Fatal("scope changed", e)
	}
	opened, e = sessions.Open(context.Background(), strings.Repeat("5", 32), native)
	if e != nil {
		t.Fatal(e)
	}
	page, e = sessions.Page(context.Background(), opened.ID, opened.Incarnation, native, 0)
	if e != nil || page.Page.LogicalBytes != 6 {
		t.Fatal(page, e)
	}
	if e = sessions.Cancel(opened.ID, opened.Incarnation, native); e != nil {
		t.Fatal(e)
	}
	if e = os.Rename(filepath.Join(directory, "media"), filepath.Join(directory, "old-media")); e != nil {
		t.Fatal(e)
	}
	if e = os.Mkdir(filepath.Join(directory, "media"), 0700); e != nil {
		t.Fatal(e)
	}
	if _, e = sessions.Open(context.Background(), strings.Repeat("6", 32), binding); !errors.Is(e, ErrChanged) {
		t.Fatal("replaced exclusion accepted", e)
	}
	legacy := NewSessions(data, nil)
	defer legacy.Close()
	if _, e = legacy.Open(context.Background(), strings.Repeat("7", 32), native); !errors.Is(e, ErrSession) {
		t.Fatal("legacy granted native root", e)
	}
}
