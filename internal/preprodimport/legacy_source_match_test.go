package preprodimport

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestLegacySourceMatchBindsNativeObjectDescriptorAndOwner(t *testing.T) {
	meta, err := mediacrypto.NewMetadata(4097)
	if err != nil { t.Fatal(err) }
	descriptor, _ := json.Marshal(meta)
	id, source, owner, object, digest := strings.Repeat("1",64), strings.Repeat("2",32), strings.Repeat("3",32), strings.Repeat("4",64), strings.Repeat("5",64)
	name, kind, state, etag, size := "music/专辑/歌曲.mp3", "audio", "active", "\""+digest+"\"", "4145"
	// The descriptor's encrypted size is authoritative.
	size = strconv.FormatInt(meta.CiphertextSize, 10)
	zero, created, updated, masterLocal, local := "0", "1", "2", "MasterLocal", "Local"
	fileID, encoded, mediaKind := meta.FileID, string(descriptor), "media"
	projection := Snapshot{Media: []Media{{MediaID:id, ObjectID:object, SourceID:source, Path:name, Kind:kind, Size:meta.CiphertextSize, SHA256:digest, Encryption:&meta}}, Mappings: []Mapping{{SourceID:source,TargetID:owner,Role:"master"}}}
	scope := keyScope{MediaID:id, SourceObjectID:object, TargetOwnerID:owner, ContentSHA256:digest, StoredBytes:meta.CiphertextSize, Descriptor:meta}
	snapshot := store.MediaSourceSnapshot{SourceNode:source, Sections: []store.MediaSourceSection{
		{Name:"placements", Rows:[][]*string{{&id,&source,&object,&name,&kind,&size,&etag,&state,&created,&updated}}},
		{Name:"members", Rows:[][]*string{{&source,nil,&masterLocal,&local,&zero,&zero,&zero,&zero,&zero,&state,&zero,&updated}}},
		{Name:"encryption", Rows:[][]*string{{&mediaKind,&id,&fileID,&encoded,&created}}},
	}}
	if _, _, err = matchLegacySourceObject(snapshot, projection, scope); err != nil { t.Fatal(err) }
	weak := "W/\"fixture\""
	snapshot.Sections[0].Rows[0][6] = &weak
	if _, gotETag, e := matchLegacySourceObject(snapshot, projection, scope); e != nil || gotETag != weak { t.Fatal("weak ETag not preserved") }
	snapshot.Sections[0].Rows[0][6] = &etag
	badObject := strings.Repeat("6",64)
	snapshot.Sections[0].Rows[0][2] = &badObject
	if _, _, err = matchLegacySourceObject(snapshot, projection, scope); err == nil { t.Fatal("changed source object accepted") }
	snapshot.Sections[0].Rows[0][2] = &object
	badFile := strings.Repeat("7",32)
	snapshot.Sections[2].Rows[0][2] = &badFile
	if _, _, err = matchLegacySourceObject(snapshot, projection, scope); err == nil { t.Fatal("changed FileID accepted") }
}
