package sealedtree

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

type shortPreparedWriter struct{ accepted int }

func (w *shortPreparedWriter) Write(p []byte) (int, error) {
	n := len(p) / 2
	w.accepted += n
	return n, nil
}

func TestPreparedBlobShortWriteFailsClosed(t *testing.T) {
	data := bytes.Repeat([]byte("fixture"), 32)
	sum := sha256.Sum256(data)
	w := &shortPreparedWriter{}
	if err := copyPreparedBytes(context.Background(), w, bytes.NewReader(data), int64(len(data)), hex.EncodeToString(sum[:])); err == nil {
		t.Fatal("short write accepted")
	}
	if w.accepted >= len(data) {
		t.Fatal("fixture did not produce a short write")
	}
}
