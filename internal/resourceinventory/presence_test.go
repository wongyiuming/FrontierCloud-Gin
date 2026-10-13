package resourceinventory

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestPresenceReportsMissingRegularAndUnsupportedAncestors(t *testing.T) {
	dir, root, _ := inventoryFixture(t)
	if e := root.MkdirAll("media/nested", 0700); e != nil {
		t.Fatal(e)
	}
	f, e := root.OpenFile("media/nested/real", os.O_CREATE|os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal(e)
	}
	f.Write([]byte("opaque"))
	f.Close()
	if e = os.Symlink("nested", filepath.Join(dir, "media/link")); e != nil {
		t.Fatal(e)
	}
	for _, test := range []struct{ name, state string }{{"media/nested/real", "present"}, {"media/nested/missing", "missing"}, {"recordings/missing/file", "missing"}, {"media/link/real", "unsupported"}, {"../outside", "invalid_path"}, {"media/nested", "unsupported"}} {
		observed, e := PresenceAt(context.Background(), root, test.name)
		if e != nil || observed.State != test.state {
			t.Fatal(test, observed, e)
		}
		if test.state == "present" && observed.LogicalBytes != 6 {
			t.Fatal(observed)
		}
	}
}
