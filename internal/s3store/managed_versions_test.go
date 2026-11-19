package s3store

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

func versionListFixture(f *fakeS3, handler http.HandlerFunc) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.versionList = handler
}

func versionListEntry(key, version string, latest bool) string {
	return fmt.Sprintf(`<Version><Key>%s</Key><VersionId>%s</VersionId><IsLatest>%t</IsLatest><ETag>"etag"</ETag><Size>23</Size></Version>`, xmlValue(key), xmlValue(version), latest)
}

func versionListResponse(w http.ResponseWriter, bucket, prefix, nextKey, nextVersion, entries string) {
	w.Header().Set("Content-Type", "application/xml")
	fmt.Fprintf(w, `<ListVersionsResult><Name>%s</Name><Prefix>%s</Prefix><IsTruncated>%t</IsTruncated>`, xmlValue(bucket), xmlValue(prefix), nextKey != "")
	if nextKey != "" {
		fmt.Fprintf(w, `<NextKeyMarker>%s</NextKeyMarker><NextVersionIdMarker>%s</NextVersionIdMarker>`, xmlValue(nextKey), xmlValue(nextVersion))
	}
	fmt.Fprint(w, entries, `</ListVersionsResult>`)
}

func TestManagedObjectVersionsUsesExactPrefixAndBothCursors(t *testing.T) {
	for _, style := range []string{"path", "virtual"} {
		t.Run(style, func(t *testing.T) {
			f := newFakeS3(t, style)
			prefix := f.client.config.Prefix + "/objects/"
			cursorKey, cursorVersion := prefix+"a", "v1"
			if style == "virtual" {
				cursorKey, cursorVersion = prefix+"b", "v2"
			}
			versionListFixture(f, func(w http.ResponseWriter, r *http.Request) {
				q := r.URL.Query()
				if q.Get("prefix") != prefix || q.Get("max-keys") != strconv.Itoa(managedVersionPageSize) || q.Has("delimiter") {
					t.Error("list request exceeded fixed managed scope")
					apiError(w, http.StatusBadRequest, "InvalidArgument")
					return
				}
				if q.Get("key-marker") == "" {
					versionListResponse(w, f.client.config.Bucket, prefix, cursorKey, cursorVersion, versionListEntry(prefix+"a", "v1", true))
					return
				}
				if q.Get("key-marker") != cursorKey || q.Get("version-id-marker") != cursorVersion {
					t.Error("version listing lost a cursor")
				}
				versionListResponse(w, f.client.config.Bucket, prefix, "", "", versionListEntry(prefix+"b", "v2", true))
			})
			checks := 0
			var result []ManagedObjectVersion
			err := f.client.VisitManagedObjectVersions(context.Background(), 2, func(context.Context) error { checks++; return nil }, func(v ManagedObjectVersion) error {
				result = append(result, v)
				return nil
			})
			if err != nil || len(result) != 2 || checks != 5 || result[0] != (ManagedObjectVersion{Key: "objects/a", VersionID: "v1", ETag: `"etag"`, Size: 23}) || result[1].Key != "objects/b" || result[1].VersionID != "v2" {
				t.Fatal("exact listing did not finish", err, checks)
			}
		})
	}
}

func TestManagedObjectVersionsRequiresLiveCheckBeforeVisiting(t *testing.T) {
	for _, allowedChecks := range []int{0, 1} {
		f := newFakeS3(t, "path")
		prefix := f.client.config.Prefix + "/objects/"
		versionListFixture(f, func(w http.ResponseWriter, _ *http.Request) {
			versionListResponse(w, f.client.config.Bucket, prefix, "", "", versionListEntry(prefix+"a", "v1", true))
		})
		checks := 0
		fenceLost := errors.New("writer fence lost")
		err := f.client.VisitManagedObjectVersions(context.Background(), 1, func(context.Context) error {
			checks++
			if checks > allowedChecks {
				return fenceLost
			}
			return nil
		}, func(ManagedObjectVersion) error {
			t.Error("stale proof reached visitor")
			return nil
		})
		f.mu.Lock()
		requests := f.requests[http.MethodGet]
		f.mu.Unlock()
		if err != fenceLost || requests != allowedChecks {
			t.Fatal("stale fence did not stop the scan", err, requests)
		}
	}
}

func TestManagedObjectVersionsRejectsIncompleteOrUnsafeResponses(t *testing.T) {
	for _, name := range []string{"wrong prefix", "wrong bucket", "outside prefix", "historical version", "null version", "missing version", "delete marker", "duplicate key", "empty", "empty final page", "bad cursor", "cursor skips version", "missing cursor row", "oversized page", "expected bound", "page bound", "denied"} {
		t.Run(name, func(t *testing.T) {
			f := newFakeS3(t, "path")
			bucket, prefix := f.client.config.Bucket, f.client.config.Prefix+"/objects/"
			versionListFixture(f, func(w http.ResponseWriter, r *http.Request) {
				key, version, nextKey, nextVersion := prefix+"a", "v1", "", ""
				responseBucket, responsePrefix := bucket, prefix
				latest := true
				extra := ""
				switch name {
				case "wrong prefix":
					responsePrefix = strings.TrimSuffix(prefix, "/")
				case "wrong bucket":
					responseBucket = "other-private"
				case "outside prefix":
					key = strings.TrimSuffix(prefix, "/") + "-neighbor/a"
				case "historical version":
					latest = false
				case "null version":
					version = "null"
				case "missing version":
					version = ""
				case "delete marker":
					extra = fmt.Sprintf(`<DeleteMarker><Key>%s</Key><VersionId>deleted</VersionId><IsLatest>true</IsLatest></DeleteMarker>`, xmlValue(key))
				case "duplicate key":
					extra = versionListEntry(key, "other", true)
				case "empty":
					versionListResponse(w, bucket, prefix, "", "", "")
					return
				case "empty final page":
					if r.URL.Query().Has("key-marker") {
						versionListResponse(w, bucket, prefix, "", "", "")
						return
					}
					nextKey, nextVersion = key, version
				case "bad cursor":
					nextKey, nextVersion = prefix+"0", "v2"
				case "cursor skips version":
					nextKey, nextVersion = key, "other"
				case "missing cursor row":
					if r.URL.Query().Has("key-marker") {
						key, version = prefix+"c", "v3"
					} else {
						nextKey, nextVersion = prefix+"b", "v2"
					}
				case "oversized page":
					extra = strings.Repeat(versionListEntry(prefix+"b", "v2", true), managedVersionPageSize)
				case "expected bound":
					nextKey, nextVersion = key, version
				case "page bound":
					key = fmt.Sprintf("%s%04d", prefix, f.requests[http.MethodGet])
					nextKey, nextVersion = key, version
				case "denied":
					apiError(w, http.StatusForbidden, "AccessDenied")
					return
				}
				versionListResponse(w, responseBucket, responsePrefix, nextKey, nextVersion, versionListEntry(key, version, latest)+extra)
			})
			limit, wantRequests, wantErr := MaxManagedObjectVersions, 1, ErrResponse
			switch name {
			case "empty final page", "missing cursor row":
				wantRequests = 2
			case "expected bound":
				limit, wantErr = 1, ErrIncomplete
			case "page bound":
				wantRequests, wantErr = managedVersionMaxPages, ErrIncomplete
			case "denied":
				wantErr = ErrDenied
			}
			err := f.client.VisitManagedObjectVersions(context.Background(), limit, func(context.Context) error { return nil }, func(ManagedObjectVersion) error { return nil })
			f.mu.Lock()
			defer f.mu.Unlock()
			if !errors.Is(err, wantErr) || f.requests[http.MethodGet] != wantRequests || len(f.requests) != 1 {
				t.Fatalf("response escaped bounds: GETs=%d err=%v", f.requests[http.MethodGet], err)
			}
		})
	}
}
