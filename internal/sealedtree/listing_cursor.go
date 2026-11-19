package sealedtree

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"io"
)

// Cursor contents are encrypted and authenticated, bound to one keyed parent
// group revision and ancestor chain. They contain no business names, hidden
// lookup tags or raw IDs. Mutations outside this directory do not stale them.
func (s *SQLStore) sealListingCursor(group, lookup string, revision int64, anchor string) (string, error) {
	if !hexID(group) || !hexID(lookup) || lookup == listingSentinel || revision < 0 || !hexID(anchor) {
		return "", ErrInvalid
	}
	random := make([]byte, recordSaltBytes+nonceBytes)
	if _, err := io.ReadFull(rand.Reader, random); err != nil {
		return "", ErrInvalid
	}
	aead, err := s.tree.recordCipher(random[:recordSaltBytes], "cursor")
	if err != nil {
		return "", err
	}
	plain := make([]byte, 200)
	copy(plain, group)
	copy(plain[64:], lookup)
	binary.BigEndian.PutUint64(plain[128:], uint64(revision))
	copy(plain[136:], anchor)
	defer clear(plain)
	sealed := append([]byte{2}, random...)
	sealed = aead.Seal(sealed, random[recordSaltBytes:], plain, []byte("frontiercloud:sealed-tree:listing-cursor:v2"))
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}
func (s *SQLStore) openListingCursor(token, group string, revision int64, anchor string) (string, error) {
	if len(token) > 512 || !hexID(group) || revision < 0 || !hexID(anchor) {
		return "", ErrInvalid
	}
	sealed, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil || len(sealed) != 1+recordSaltBytes+nonceBytes+200+16 || sealed[0] != 2 {
		return "", ErrInvalid
	}
	aead, err := s.tree.recordCipher(sealed[1:1+recordSaltBytes], "cursor")
	if err != nil {
		return "", err
	}
	plain, err := aead.Open(nil, sealed[1+recordSaltBytes:1+recordSaltBytes+nonceBytes], sealed[1+recordSaltBytes+nonceBytes:], []byte("frontiercloud:sealed-tree:listing-cursor:v2"))
	if err != nil {
		return "", ErrInvalid
	}
	defer clear(plain)
	if string(plain[:64]) != group || binary.BigEndian.Uint64(plain[128:136]) != uint64(revision) || string(plain[136:]) != anchor {
		return "", ErrFenceChanged
	}
	lookup := string(plain[64:128])
	if !hexID(lookup) || lookup == listingSentinel {
		return "", ErrInvalid
	}
	return lookup, nil
}
