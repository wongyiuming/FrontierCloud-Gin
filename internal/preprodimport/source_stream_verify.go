package preprodimport

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"unicode/utf8"
)

type sourceStreamFrame struct {
	Section string    `json:"section,omitempty"`
	Columns []string  `json:"columns,omitempty"`
	Row     []*string `json:"row,omitempty"`
	End     string    `json:"end,omitempty"`
	Rows    *int64    `json:"rows,omitempty"`
}

// verifySourceRowsV2 validates the complete decrypted frame sequence against
// the independently signed manifest. It does not publish any imported row.
// The caller must discard/roll back all provisional state on any error.
func verifySourceRowsV2(ctx context.Context, input io.Reader, size int64, sections []sourceSectionDigest, expectedKeyID string) error {
	return verifySourceRowsV2VisitIDs(ctx, input, size, sections, expectedKeyID, nil)
}

// An ID visitor is allowed only after the caller has independently verified
// the complete signed stream and pinned the same trusted stage descriptor.
// A failure after an emitted batch must leave the final completion gate shut.
func verifySourceRowsV2VisitIDs(ctx context.Context, input io.Reader, size int64, sections []sourceSectionDigest, expectedKeyID string, visit func(string) error) error {
	if ctx == nil || input == nil || size <= 0 || len(sections) != len(sourceRowSpecs) || !id64.MatchString(expectedKeyID) {
		return invalid("source stream frame input")
	}
	scanner := bufio.NewScanner(io.LimitReader(input, size+1))
	scanner.Buffer(make([]byte, 4096), (1<<20)+1)
	// ScanLines accepts an unterminated final line; frames are canonical only
	// when every record includes its final newline, including the last one.
	scanner.Split(func(data []byte, atEOF bool) (int, []byte, error) {
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			return i + 1, data[:i], nil
		}
		if atEOF && len(data) != 0 {
			return 0, nil, invalid("source stream unterminated frame")
		}
		return 0, nil, nil
	})
	var consumed int64
	read := func() (sourceStreamFrame, []byte, error) {
		var frame sourceStreamFrame
		if ctx.Err() != nil {
			return frame, nil, ctx.Err()
		}
		if !scanner.Scan() {
			return frame, nil, invalid("source stream frame truncated")
		}
		raw := append([]byte(nil), scanner.Bytes()...)
		raw = append(raw, '\n')
		consumed += int64(len(raw))
		if consumed < 0 || consumed > size {
			return frame, nil, invalid("source stream frame size")
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&frame); err != nil {
			return frame, nil, invalid("source stream frame json")
		}
		if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
			return frame, nil, invalid("source stream frame trailing")
		}
		return frame, raw, nil
	}
	for index, spec := range sourceRowSpecs {
		expected := sections[index]
		if expected.Name != spec.name || expected.Rows < 0 || !id64.MatchString(expected.SHA256) {
			return invalid("source stream section manifest")
		}
		hash := sha256.New()
		frame, raw, err := read()
		if err != nil {
			return err
		}
		_, _ = hash.Write(raw)
		if frame.Section != spec.name || !reflect.DeepEqual(frame.Columns, spec.columns) || frame.Row != nil || frame.End != "" || frame.Rows != nil {
			return invalid("source stream section header")
		}
		keyIndex := -1
		for i, col := range spec.columns {
			if col == spec.key {
				keyIndex = i
			}
		}
		if keyIndex < 0 {
			return invalid("source stream section key")
		}
		first := true
		last := ""
		var count int64
		for {
			frame, raw, err = read()
			if err != nil {
				return err
			}
			_, _ = hash.Write(raw)
			if frame.End != "" {
				if frame.End != spec.name || frame.Rows == nil || *frame.Rows != count || frame.Section != "" || frame.Columns != nil || frame.Row != nil || count != expected.Rows {
					return invalid("source stream section end")
				}
				break
			}
			if frame.Section != "" || frame.Columns != nil || frame.Rows != nil || len(frame.Row) != len(spec.columns) {
				return invalid("source stream row frame")
			}
			for i, cell := range frame.Row {
				if cell == nil {
					if !(spec.name == "encryption" && spec.columns[i] == "descriptor_json") && !(spec.name == "members" && spec.columns[i] == "relationship_id") {
						return invalid("source stream row null")
					}
					continue
				}
				if len(*cell) > 65536 || !utf8.ValidString(*cell) || strings.ContainsRune(*cell, 0) {
					return invalid("source stream row value")
				}
			}
			key := frame.Row[keyIndex]
			if key == nil || *key == "" || (!first && *key <= last) || (spec.name == "crypto_key_id" && *key != "1") {
				return invalid("source stream row key")
			}
			if spec.name == "encryption" && (frame.Row[0] == nil || *frame.Row[0] != "media") {
				return invalid("source stream encryption scope")
			}
			if spec.name == "crypto_key_id" && (len(frame.Row) < 2 || frame.Row[1] == nil || *frame.Row[1] != expectedKeyID) {
				return invalid("source stream media key identity")
			}
			if spec.name == "encryption_ids" && !id32.MatchString(*key) {
				return invalid("source stream encryption file ID")
			}
			if spec.name == "encryption_ids" && visit != nil {
				if err := visit(*key); err != nil {
					return err
				}
			}
			first = false
			last = *key
			count++
			if count < 0 {
				return invalid("source stream row count")
			}
		}
		expectedHash, err := hex.DecodeString(expected.SHA256)
		if spec.name == "crypto_key_id" && count != 1 {
			return invalid("source stream media key count")
		}
		if err != nil || subtle.ConstantTimeCompare(hash.Sum(nil), expectedHash) != 1 {
			return invalid("source stream section digest")
		}
	}
	if consumed != size || scanner.Scan() || scanner.Err() != nil {
		return invalid("source stream frame completeness")
	}
	return ctx.Err()
}
