package resourcemigration

import (
	"testing"
	"time"
)

func TestTargetCompletionAdmitsMaximumObjectOnSlowStorage(t *testing.T) {
	const bytes = int64(10 << 30)
	// At two MiB/s the supported maximum takes over 85 minutes to rehash.
	slowDigest := time.Duration(bytes/(2<<20)) * time.Second
	if targetCompletionTTL(bytes) <= slowDigest {
		t.Fatal("maximum object cannot finish target digest on slow storage")
	}
	if targetCompletionTTL(7) != 30*time.Minute || targetCompletionTTL(1<<62) > 24*time.Hour {
		t.Fatal("target deadline bounds")
	}
}
