// Package resourceinventory observes rooted filesystem metadata with bounded
// pages. Observations are not content proofs or an atomic retirement permit.
package resourceinventory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
	"io"
	"math"
	"os"
	"path"
	"strings"
	"sync"
	"unicode/utf8"
)

const PageEntries = 64
const PageBytes = 48 << 10

// Reserve bounded room for native SQL facts without doubling path strings.
const FactBytes = 400
const MaxDepth = 64
const MaxPathBytes = 4096

var ErrChanged = errors.New("inventory directory changed; restart observation")
var ErrSequence = errors.New("inventory page sequence conflicts with session")
var ErrLimit = errors.New("inventory path, depth or byte count exceeds bounds")

type Entry struct {
	Path         string `json:"path"`
	Kind         string `json:"kind"`
	LogicalBytes int64  `json:"logical_bytes"`
	ModifiedNS   int64  `json:"modified_ns"`
}
type Page struct {
	Sequence   uint64  `json:"sequence"`
	Entries    []Entry `json:"entries"`
	Complete   bool    `json:"complete"`
	EntryCount uint64  `json:"entry_count"`
	// Logical bytes count regular paths, including multiple hard links. They
	// are never physical allocated bytes, releasable space or a quota authority.
	LogicalBytes      int64  `json:"logical_bytes"`
	ObservationSHA256 string `json:"observation_sha256"`
}
type directory struct {
	name string
	file *os.File
	info os.FileInfo
}
type Scanner struct {
	mutex            sync.Mutex
	root             *os.Root
	stack            []directory
	pending          *Entry
	digest           hash.Hash
	next, count      uint64
	bytes            int64
	last             *Page
	complete, closed bool
	excluded         map[string]os.FileInfo
}

// New borrows the already-authorized root; it never creates or writes files.
// Close releases only the scanner's directory handles, not the borrowed root.
func New(root *os.Root) (*Scanner, error) {
	return NewExcluding(root, nil)
}

// NewExcluding omits descent only into two explicitly pinned native mounts.
// It still reports each directory entry and rejects replacement of the pin.
func NewExcluding(root *os.Root, excluded map[string]os.FileInfo) (*Scanner, error) {
	if root == nil {
		return nil, os.ErrInvalid
	}
	if len(excluded) > 2 {
		return nil, ErrLimit
	}
	s := &Scanner{root: root, digest: sha256.New()}
	s.excluded = make(map[string]os.FileInfo, len(excluded))
	for name, info := range excluded {
		if name != "media" && name != "recordings" || info == nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, ErrLimit
		}
		s.excluded[name] = info
	}
	if e := s.checkExcluded(); e != nil {
		return nil, e
	}
	if e := s.openDirectory("."); e != nil {
		return nil, e
	}
	return s, nil
}

func (s *Scanner) checkExcluded() error {
	for name, pin := range s.excluded {
		info, e := s.root.Lstat(name)
		if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !os.SameFile(pin, info) {
			return ErrChanged
		}
	}
	return nil
}
func (s *Scanner) openDirectory(name string) error {
	if len(s.stack) >= MaxDepth {
		return ErrLimit
	}
	before, e := s.root.Lstat(name)
	if e != nil {
		return e
	}
	if !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return ErrChanged
	}
	f, e := s.root.Open(name)
	if e != nil {
		return e
	}
	actual, e := f.Stat()
	if e != nil || !os.SameFile(before, actual) || !actual.IsDir() || !before.ModTime().Equal(actual.ModTime()) {
		f.Close()
		if e != nil {
			return e
		}
		return ErrChanged
	}
	s.stack = append(s.stack, directory{name, f, actual})
	return nil
}
func (s *Scanner) checkDirectories() error {
	for _, d := range s.stack {
		now, e := s.root.Lstat(d.name)
		if e != nil {
			return e
		}
		if !now.IsDir() || now.Mode()&os.ModeSymlink != 0 || !os.SameFile(now, d.info) || !now.ModTime().Equal(d.info.ModTime()) {
			return ErrChanged
		}
	}
	return nil
}
func (s *Scanner) closeHandles() error {
	var result error
	for i := len(s.stack) - 1; i >= 0; i-- {
		result = errors.Join(result, s.stack[i].file.Close())
	}
	s.stack = nil
	s.closed = true
	return result
}
func (s *Scanner) Close() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.closed {
		return nil
	}
	return s.closeHandles()
}
func clone(p Page) Page { p.Entries = append([]Entry{}, p.Entries...); return p }

// Next accepts only the next page or an exact replay of the most recent page.
// A failed/changed scan cannot resume or report complete. Callers must bind the
// session to identity, scope and expiry, and independently check SQL facts and
// concurrent writers before any migration start or retirement operation.
func (s *Scanner) Next(ctx context.Context, sequence uint64) (page Page, result error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if e := ctx.Err(); e != nil {
		return page, e
	}
	if s.last != nil && sequence == s.last.Sequence {
		return clone(*s.last), nil
	}
	if sequence != s.next || s.closed || s.complete {
		return page, ErrSequence
	}
	defer func() {
		if result != nil {
			s.last = nil
			result = errors.Join(result, s.closeHandles())
		}
	}()
	page = Page{Sequence: sequence, Entries: []Entry{}}
	if e := s.checkExcluded(); e != nil {
		return page, e
	}
	encodedBytes := 0
	if e := s.checkDirectories(); e != nil {
		return page, e
	}
	for len(page.Entries) < PageEntries {
		if e := ctx.Err(); e != nil {
			return page, e
		}
		var entry Entry
		if s.pending != nil {
			entry = *s.pending
			s.pending = nil
		} else {
			if len(s.stack) == 0 {
				page.Complete = true
				break
			}
			d := s.stack[len(s.stack)-1]
			names, e := d.file.ReadDir(1)
			if e != nil && e != io.EOF {
				return page, e
			}
			if len(names) == 0 {
				// Check this directory before closing; later changes to completed
				// subtrees require the caller's mutation/version admission, not this
				// bounded walker retaining every directory in memory.
				if e := s.checkDirectories(); e != nil {
					return page, e
				}
				if e := d.file.Close(); e != nil {
					return page, e
				}
				s.stack = s.stack[:len(s.stack)-1]
				continue
			}
			base := names[0].Name()
			if !utf8.ValidString(base) || strings.ContainsAny(base, "\\\x00:") || base == "." || base == ".." {
				return page, ErrLimit
			}
			name := path.Join(d.name, base)
			if len(name) > MaxPathBytes {
				return page, ErrLimit
			}
			info, e := s.root.Lstat(name)
			if e != nil {
				return page, e
			}
			pin := s.excluded[name]
			if pin != nil && (!info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !os.SameFile(pin, info)) {
				return page, ErrChanged
			}
			entry = Entry{Path: name, ModifiedNS: info.ModTime().UnixNano()}
			switch {
			case info.Mode()&os.ModeSymlink != 0:
				entry.Kind = "symlink"
			case info.IsDir():
				entry.Kind = "directory"
				if pin == nil {
					if e = s.openDirectory(name); e != nil {
						return page, e
					}
				}
			case info.Mode().IsRegular():
				entry.Kind = "regular"
				entry.LogicalBytes = info.Size()
			default:
				entry.Kind = "special"
			}
		}
		raw, e := json.Marshal(entry)
		if e != nil {
			return page, e
		}
		if len(raw) > PageBytes {
			return page, ErrLimit
		}
		if encodedBytes+len(raw)+FactBytes > PageBytes {
			s.pending = &entry
			break
		}
		encodedBytes += len(raw) + FactBytes
		if entry.LogicalBytes < 0 || entry.LogicalBytes > math.MaxInt64-s.bytes || s.count == math.MaxUint64 {
			return page, ErrLimit
		}
		s.bytes += entry.LogicalBytes
		s.count++
		s.digest.Write(raw)
		s.digest.Write([]byte{'\n'})
		page.Entries = append(page.Entries, entry)
	}
	if e := s.checkDirectories(); e != nil {
		return page, e
	}
	page.EntryCount = s.count
	if e := s.checkExcluded(); e != nil {
		return page, e
	}
	page.LogicalBytes = s.bytes
	page.ObservationSHA256 = hex.EncodeToString(s.digest.Sum(nil))
	s.next++
	s.complete = page.Complete
	saved := clone(page)
	s.last = &saved
	return page, nil
}
