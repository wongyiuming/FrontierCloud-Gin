package migrationpaths

import (
	"errors"
	"strings"
	"unicode/utf8"
)

// ErrMigrationPathConflict intentionally contains no source path or ID.
var ErrMigrationPathConflict = errors.New("sealed tree migration path conflict")

// MigrationPathPreflight detects ambiguous source trees in trusted Master
// memory. It does not read a database, reconcile replicated catalog rows,
// authenticate a source snapshot, persist a manifest or authorize migration.
// The caller must provide one already-reconciled, complete, fenced source view.
// No normalization or case folding is performed. Memory is bounded by both
// entries and bytes; discard the preflight if either bound is exceeded. It is
// not concurrency-safe. The caller must Close it on success and on failure.
type MigrationPathPreflight struct {
	paths map[string]migrationPathState
	bytes int
	count int
	bad   bool
}

type migrationPathState struct {
	directory bool
	explicit  bool
}

const MaxEntries = 25000
const MaxPathBytes = 16 * 1024 * 1024

// ValidComponent is shared with the tree's authenticated name codec.
func ValidComponent(s string) bool {
	return s != "" && len(s) <= 1024*utf8.UTFMax && utf8.ValidString(s) && utf8.RuneCountInString(s) <= 1024 && s != "." && s != ".." && !strings.ContainsAny(s, "/\\") && !strings.ContainsRune(s, '\x00')
}

// Add accepts a slash-separated logical path and whether it is a directory.
// An implied parent may subsequently be recorded explicitly once. Multiple
// explicit rows or a file used as a parent fail closed, even with identical
// text, until the caller reconciles the source's ownership and identity.
func (p *MigrationPathPreflight) Add(value string, directory bool) error {
	if p == nil || p.bad {
		return ErrMigrationPathConflict
	}
	if value == "" || len(value) > 4096 || !utf8.ValidString(value) || utf8.RuneCountInString(value) > 1024 || strings.HasPrefix(value, "/") {
		p.bad = true
		return ErrMigrationPathConflict
	}
	parts := strings.Split(value, "/")
	if len(parts) > 128 {
		p.bad = true
		return ErrMigrationPathConflict
	}
	if p.paths == nil {
		p.paths = make(map[string]migrationPathState)
	}
	end := 0
	for i, part := range parts {
		if !ValidComponent(part) {
			p.bad = true
			return ErrMigrationPathConflict
		}
		if i > 0 {
			end++ // slash
		}
		end += len(part)
		current := value[:end]
		isLast := i == len(parts)-1
		wantDirectory := !isLast || directory
		previous, exists := p.paths[current]
		if exists {
			if previous.directory != wantDirectory || (isLast && previous.explicit) {
				p.bad = true
				return ErrMigrationPathConflict
			}
			if isLast {
				previous.explicit = true
				p.paths[strings.Clone(current)] = previous
			}
			continue
		}
		if p.count >= MaxEntries || len(current) > MaxPathBytes-p.bytes {
			p.bad = true
			return ErrMigrationPathConflict
		}
		// Do not retain an arbitrarily larger caller-owned backing string through
		// a short substring; only the bounded prefix is kept by this index.
		p.paths[strings.Clone(current)] = migrationPathState{directory: wantDirectory, explicit: isLast}
		p.count++
		p.bytes += len(current)
	}
	return nil
}

// Counts returns only aggregate information, never names. A failed or partial
// preflight cannot be treated as success. It does not imply import readiness.
func (p *MigrationPathPreflight) Counts() (int, error) {
	if p == nil || p.bad {
		return 0, ErrMigrationPathConflict
	}
	return p.count, nil
}

// Close drops retained references and makes this instance unusable. Go does
// not guarantee that prior string contents are securely erased from memory.
func (p *MigrationPathPreflight) Close() {
	if p == nil {
		return
	}
	clear(p.paths)
	p.paths = nil
	p.bytes, p.count, p.bad = 0, 0, true
}
