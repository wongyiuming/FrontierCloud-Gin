package preprodimport

import (
	"encoding/json"
	"io"
	"strconv"
	"strings"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// This matcher is used only after signature, collector/SSH pin, recipient and
// challenge verification. It proves one native object's SQL facts match the
// authorized projection, not that all files or the whole cluster are atomic.
func matchLegacySourceObject(s store.MediaSourceSnapshot, projection Snapshot, scope keyScope) (Media, string, error) {
	var empty Media
	sections := map[string]store.MediaSourceSection{}
	for _, section := range s.Sections {
		if _, exists := sections[section.Name]; exists { return empty, "", invalid("legacy source section") }
		sections[section.Name] = section
	}
	var media Media
	found := false
	for _, candidate := range projection.Media {
		if candidate.MediaID == scope.MediaID {
			if found { return empty, "", invalid("legacy duplicate media") }
			media, found = candidate, true
		}
	}
	if !found || media.Encryption == nil || (media.Kind != "audio" && media.Kind != "video") || !validPath(media.Path, media.Kind) || media.ObjectID != scope.SourceObjectID || media.SHA256 != scope.ContentSHA256 || media.Size != scope.StoredBytes || *media.Encryption != scope.Descriptor {
		return empty, "", invalid("legacy source media")
	}
	mappingFound := false
	for _, mapping := range projection.Mappings {
		if mapping.SourceID == media.SourceID && mapping.TargetID == scope.TargetOwnerID {
			if mappingFound { return empty, "", invalid("legacy source mapping") }
			mappingFound = true
		}
	}
	if !mappingFound { return empty, "", invalid("legacy source mapping") }
	var placement []*string
	for _, row := range sections["placements"].Rows {
		if len(row) != 10 || row[0] == nil { return empty, "", invalid("legacy placement row") }
		if *row[0] == scope.MediaID {
			if placement != nil { return empty, "", invalid("legacy duplicate placement") }
			placement = row
		}
	}
	if placement == nil { return empty, "", invalid("legacy placement absent") }
	for _, cell := range placement { if cell == nil { return empty, "", invalid("legacy placement null") } }
	size, err := strconv.ParseInt(*placement[5], 10, 64)
	// The caller must authenticate a separate pinned SSH byte proof when the ETag is weak.
	if err != nil || *placement[1] != media.SourceID || *placement[2] != media.ObjectID || *placement[3] != media.Path || *placement[4] != media.Kind || size != media.Size || *placement[7] != "active" {
		return empty, "", invalid("legacy placement mismatch")
	}
	var member []*string
	for _, row := range sections["members"].Rows {
		if len(row) != 12 || row[0] == nil { return empty, "", invalid("legacy member row") }
		if *row[0] == media.SourceID {
			if member != nil { return empty, "", invalid("legacy duplicate member") }
			member = row
		}
	}
	if member == nil || member[2] == nil || member[3] == nil { return empty, "", invalid("legacy member absent") }
	if *member[2] == "MasterLocal" {
		if media.SourceID != s.SourceNode || member[1] != nil || *member[3] != "Local" { return empty, "", invalid("legacy local owner") }
	} else if *member[2] == "Follower" {
		if member[1] == nil || (*member[3] != "Direct" && *member[3] != "Relay") { return empty, "", invalid("legacy follower owner") }
		matched := false
		for _, row := range sections["relationships"].Rows {
			if len(row) != 8 || row[0] == nil || row[1] == nil || row[4] == nil || row[6] == nil { return empty, "", invalid("legacy relation row") }
			if *row[0] == *member[1] && *row[1] == media.SourceID && *row[4] == "downstream" && *row[6] == "active" { if matched { return empty, "", invalid("legacy relation duplicate") }; matched = true }
		}
		if !matched { return empty, "", invalid("legacy relation absent") }
	} else { return empty, "", invalid("legacy non-native owner") }
	var encryption []*string
	for _, row := range sections["encryption"].Rows {
		if len(row) != 5 || row[0] == nil || row[1] == nil { return empty, "", invalid("legacy encryption row") }
		if *row[0] == "media" && *row[1] == media.MediaID {
			if encryption != nil { return empty, "", invalid("legacy duplicate encryption") }
			encryption = row
		}
	}
	if encryption == nil || encryption[2] == nil || encryption[3] == nil || *encryption[2] != scope.Descriptor.FileID { return empty, "", invalid("legacy encryption absent") }
	decoder := json.NewDecoder(strings.NewReader(*encryption[3]))
	decoder.DisallowUnknownFields()
	var descriptor mediacrypto.Metadata
	var extra any
	if decoder.Decode(&descriptor) != nil || decoder.Decode(&extra) != io.EOF || descriptor != scope.Descriptor || descriptor.Validate() != nil { return empty, "", invalid("legacy descriptor mismatch") }
	return media, *placement[6], nil
}
