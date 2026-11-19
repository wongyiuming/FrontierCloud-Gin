// Package preprodimport prepares a non-runnable, media-only SQLite projection.
package preprodimport

import (
	"fmt"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sourceauth"
	"regexp"
)

var ErrInvalid = sourceauth.ErrProjectionInvalid
var id32 = regexp.MustCompile(`^[a-f0-9]{32}$`)
var id64 = regexp.MustCompile(`^[a-f0-9]{64}$`)

type Mapping = sourceauth.Mapping
type Media = sourceauth.Media
type Lyric = sourceauth.Lyric
type Link = sourceauth.Link
type Directory = sourceauth.Directory
type Visibility = sourceauth.Visibility
type Preference = sourceauth.Preference
type NonceTombstone = sourceauth.NonceTombstone
type Snapshot = sourceauth.Snapshot
type Report = sourceauth.Report

func invalid(detail string) error      { return fmt.Errorf("%w: %s", ErrInvalid, detail) }
func validPath(name, kind string) bool { return sourceauth.ValidPath(name, kind) }
func validVisibility(name string) bool { return sourceauth.ValidVisibility(name) }
func validate(s Snapshot, key []byte) (map[string]Mapping, Report, error) {
	return sourceauth.Validate(s, key)
}
func validateSnapshotShape(s Snapshot) (map[string]Mapping, Report, error) {
	return sourceauth.ValidateSnapshotShape(s)
}
func validateWithKeyID(s Snapshot, verify func(string) bool) (map[string]Mapping, Report, error) {
	return sourceauth.ValidateWithKeyID(s, verify)
}
