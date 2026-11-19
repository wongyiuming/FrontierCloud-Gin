package sourceauth

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"io"
	"net/url"
	"strconv"
	"strings"
)

func CompareCompleteSourceFacts(source store.MediaSourceSnapshot, complete CompleteSnapshot) error {
	if _, err := CompleteSnapshotDigest(complete); err != nil {
		return err
	}
	if len(source.Sections) != len(columns) {
		return invalid("complete source sections")
	}
	for i, expected := range columns {
		section := source.Sections[i]
		if section.Name != expected.name || len(section.Columns) != len(expected.fields) || section.Rows == nil {
			return invalid("complete source sections")
		}
		for j := range expected.fields {
			if section.Columns[j] != expected.fields[j] {
				return invalid("complete source columns")
			}
		}
	}
	rows := func(index int) ([][]string, error) {
		section := source.Sections[index]
		out := make([][]string, 0, len(section.Rows))
		for _, row := range section.Rows {
			if len(row) != len(section.Columns) {
				return nil, invalid("complete source row")
			}
			cells := make([]string, len(row))
			for i, value := range row {
				if value == nil {
					if section.Name != "encryption" || i != 3 {
						return nil, invalid("complete source null")
					}
					continue
				}
				cells[i] = *value
			}
			out = append(out, cells)
		}
		return out, nil
	}
	match := func(actual, expected [][]string) error {
		if len(actual) != len(expected) {
			return invalid("complete source coverage")
		}
		seen := make(map[string]bool, len(actual))
		for _, row := range actual {
			b, _ := json.Marshal(row)
			key := string(b)
			if seen[key] {
				return invalid("complete source duplicate")
			}
			seen[key] = true
		}
		for _, row := range expected {
			b, _ := json.Marshal(row)
			key := string(b)
			if !seen[key] {
				return invalid("complete source mismatch")
			}
			delete(seen, key)
		}
		if len(seen) != 0 {
			return invalid("complete source coverage")
		}
		return nil
	}
	all, err := rows(0)
	if err != nil {
		return err
	}
	actual := make([][]string, 0, len(all))
	for _, row := range all {
		sum := sha256.Sum256([]byte(row[2]))
		if row[3] != hex.EncodeToString(sum[:]) {
			return invalid("complete source object locator")
		}
		actual = append(actual, []string{row[0], row[1], row[2], row[4], row[5]})
	}
	expected := make([][]string, 0, len(complete.Facts.Objects))
	for _, f := range complete.Facts.Objects {
		expected = append(expected, []string{f.ID, f.Kind, f.Path, f.CreatedAt, f.UpdatedAt})
	}
	if err = match(actual, expected); err != nil {
		return err
	}
	objects := make(map[string]SourceObjectFact, len(complete.Facts.Objects))
	for _, f := range complete.Facts.Objects {
		objects[f.ID] = f
	}
	for _, lyric := range complete.Projection.Lyrics {
		f, ok := objects[lyric.ID]
		if !ok || f.Kind != "lyric" || f.Path != lyric.Path {
			return invalid("complete source lyric object")
		}
	}

	media := map[string]Media{}
	for _, m := range complete.Projection.Media {
		media[m.MediaID] = m
	}
	placements := map[string]SourcePlacementFact{}
	for _, f := range complete.Facts.Placements {
		placements[f.MediaID] = f
	}
	excluded := map[string]bool{}
	for _, id := range complete.Projection.ExcludedSourceIDs {
		excluded[id] = true
	}
	all, err = rows(1)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	allPlacementIDs := map[string]bool{}
	excludedMediaIDs := map[string]bool{}
	for _, r := range all {
		// An excluded owner cannot hide a duplicate of an included object ID.
		if !id64.MatchString(r[0]) || allPlacementIDs[r[0]] {
			return invalid("complete source duplicate placement")
		}
		allPlacementIDs[r[0]] = true
		if excluded[r[1]] {
			if _, exists := media[r[0]]; exists {
				return invalid("excluded source object collision")
			}
			excludedMediaIDs[r[0]] = true
			continue
		}
		m, ok := media[r[0]]
		f, has := placements[r[0]]
		if !ok || !has || seen[r[0]] || r[1] != m.SourceID || r[2] != m.ObjectID || r[3] != m.Path || r[4] != m.Kind || r[5] != strconv.FormatInt(m.Size, 10) || r[6] != f.ETag || r[7] != "active" || r[7] != f.State || r[8] != strconv.FormatInt(f.CreatedAt, 10) || r[9] != strconv.FormatInt(f.UpdatedAt, 10) {
			return invalid("complete source placement")
		}
		seen[r[0]] = true
	}
	if len(seen) != len(media) {
		return invalid("complete source placement coverage")
	}

	for _, section := range []struct {
		index    int
		expected [][]string
	}{
		{2, func() [][]string {
			var a [][]string
			for _, f := range complete.Facts.Visibility {
				a = append(a, []string{f.Path, strconv.FormatInt(f.Hidden, 10), f.UpdatedAt})
			}
			return a
		}()},
		{3, func() [][]string {
			var a [][]string
			for _, f := range complete.Facts.Playback {
				a = append(a, []string{f.MediaID, f.Path, strconv.Itoa(f.Preference), strconv.FormatInt(f.PlayScore, 10), f.CreatedAt, f.UpdatedAt})
			}
			return a
		}()},
		{4, func() [][]string {
			var a [][]string
			for _, f := range complete.Facts.LyricLinks {
				a = append(a, []string{f.MediaID, f.MediaPath, f.LyricID, f.LyricPath, f.CreatedAt, f.UpdatedAt})
			}
			return a
		}()},
	} {
		actual, err = rows(section.index)
		if err != nil {
			return err
		}
		// Playback and lyric-link rows are keyed by the media ID. Exclude
		// only rows whose owner was independently identified above; retain
		// path-based visibility rules and the complete objects section.
		if section.index == 3 || section.index == 4 {
			kept := actual[:0]
			excludedSeen := map[string]bool{}
			for _, row := range actual {
				if excludedMediaIDs[row[0]] {
					if excludedSeen[row[0]] {
						return invalid("excluded source duplicate fact")
					}
					excludedSeen[row[0]] = true
				} else {
					kept = append(kept, row)
				}
			}
			actual = kept
		}
		if err = match(actual, section.expected); err != nil {
			return err
		}
	}

	encryption := map[string]SourceEncryptionFact{}
	for _, f := range complete.Facts.Encryption {
		encryption[f.ObjectID] = f
	}
	all, err = rows(5)
	if err != nil {
		return err
	}
	seen = map[string]bool{}
	excludedEncryption := map[string]bool{}
	for i, r := range all {
		if excludedMediaIDs[r[1]] {
			if _, exists := encryption[r[1]]; exists || excludedEncryption[r[1]] {
				return invalid("excluded source encryption collision")
			}
			excludedEncryption[r[1]] = true
			// A user-excluded active object is not a retained tombstone.
			// Require an actual media descriptor so unrelated malformed or
			// deleted encryption rows are not silently reclassified.
			if r[0] != "media" || source.Sections[5].Rows[i][3] == nil || r[3] == "" {
				return invalid("excluded source encryption")
			}
			continue
		}
		f, ok := encryption[r[1]]
		if !ok || seen[r[1]] || r[0] != f.Kind || r[2] != f.FileID || r[4] != strconv.FormatInt(f.CreatedAt, 10) {
			return invalid("complete source encryption")
		}
		descriptor := source.Sections[5].Rows[i][3]
		if m, active := media[r[1]]; active {
			var meta mediacrypto.Metadata
			decoder := json.NewDecoder(strings.NewReader(r[3]))
			decoder.DisallowUnknownFields()
			var extra any
			if m.Encryption == nil || descriptor == nil || r[3] == "" || decoder.Decode(&meta) != nil || decoder.Decode(&extra) != io.EOF || meta != *m.Encryption {
				return invalid("complete source descriptor")
			}
		} else if descriptor != nil {
			return invalid("complete source tombstone")
		}
		seen[r[1]] = true
	}
	if len(seen) != len(encryption) {
		return invalid("complete source encryption coverage")
	}
	// Owner identities are independently pinned on the target; the signed
	// source snapshot must also connect each mapped owner to its actual active
	// downstream relationship. Unreferenced historical members are not imported.
	rels := map[string][]string{}
	all, err = rows(7)
	if err != nil {
		return err
	}
	for _, r := range all {
		if !id32.MatchString(r[0]) || rels[r[0]] != nil {
			return invalid("complete source relationship")
		}
		rels[r[0]] = r
	}
	owners := map[string][]*string{}
	for _, row := range source.Sections[6].Rows {
		if len(row) != 12 || row[0] == nil || owners[*row[0]] != nil {
			return invalid("complete source member")
		}
		owners[*row[0]] = row
	}
	for id := range excluded {
		row := owners[id]
		// An absent retired node is possible after an explicit tombstone;
		// if the source still identifies it, it must be a native follower.
		// An S3 member can never be silently classified as retired Tencent.
		if row != nil && (len(row) != 12 || row[2] == nil || *row[2] != "Follower") {
			return invalid("excluded source member kind")
		}
	}
	for _, mapping := range complete.Projection.Mappings {
		row := owners[mapping.SourceID]
		if len(row) != 12 || row[2] == nil || row[3] == nil {
			return invalid("complete source owner")
		}
		if mapping.Role == "master" {
			if *row[2] != "MasterLocal" || *row[3] != "Local" || row[1] != nil || mapping.SourceID != source.SourceNode {
				return invalid("complete source master owner")
			}
			continue
		}
		if *row[2] != "Follower" || (*row[3] != "Direct" && *row[3] != "Relay") || row[1] == nil {
			return invalid("complete source follower owner")
		}
		r := rels[*row[1]]
		if len(r) != 8 || r[1] != mapping.SourceID || r[4] != "downstream" || (r[5] != "Direct" && r[5] != "Relay") || r[6] != "active" {
			return invalid("complete source follower relationship")
		}
		u, err := url.Parse(r[2])
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
			return invalid("complete source endpoint")
		}
		pub, err := protocol.Decode(r[3])
		if err != nil || len(pub) != 32 || bytes.Equal(pub, make([]byte, 32)) {
			return invalid("complete source peer key")
		}
	}
	keys, err := rows(8)
	if err != nil || len(keys) != 1 || len(keys[0]) != 3 || keys[0][0] != "1" || keys[0][1] != complete.Projection.PremasterKeyID {
		return invalid("complete source key identity")
	}
	return nil
}
