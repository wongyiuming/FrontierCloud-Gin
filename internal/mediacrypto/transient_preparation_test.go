package mediacrypto

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestTransientPreparationExpiresAndRejectsRestartAndLegacy(t *testing.T) {
	master := bytes.Repeat([]byte{0x6a}, 32)
	first, err := New(master)
	if err != nil {
		t.Fatal(err)
	}
	second, err := New(master)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := NewMetadata(123)
	if err != nil {
		t.Fatal(err)
	}
	token, err := first.SignTransientPreparation("admin:one", metadata)
	if err != nil || first.VerifyTransientPreparation("admin:one", token, metadata) != nil {
		t.Fatal("current manager rejected its token", err)
	}
	if second.VerifyTransientPreparation("admin:one", token, metadata) == nil {
		t.Fatal("restored or restarted manager accepted old token")
	}
	if first.VerifyTransientPreparation("admin:other", token, metadata) == nil || first.VerifyPreparation("admin:one", token, metadata) == nil {
		t.Fatal("binding or protocol domain bypass")
	}
	legacy, err := first.SignPreparation("admin:one", metadata)
	if err != nil || first.VerifyTransientPreparation("admin:one", legacy, metadata) == nil || second.VerifyPreparation("admin:one", legacy, metadata) != nil {
		t.Fatal("legacy and transient tokens are not properly separated", err)
	}
	client, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	session, err := first.NewSession("admin:one", base64.StdEncoding.EncodeToString(client.PublicKey().Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = first.Wrap("admin:one", session.SessionID, metadata); err != nil {
		t.Fatal(err)
	}
	if err = first.ResetTransientPreparations(); err != nil {
		t.Fatal(err)
	}
	if first.VerifyTransientPreparation("admin:one", token, metadata) == nil {
		t.Fatal("reset accepted old token")
	}
	if _, err = first.Wrap("admin:one", session.SessionID, metadata); !errors.Is(err, ErrSession) {
		t.Fatal("reset retained old session", err)
	}
	if err = first.VerifyPreparation("admin:one", legacy, metadata); err != nil {
		t.Fatal("legacy token changed", err)
	}
	token, err = first.SignTransientPreparation("admin:one", metadata)
	if err != nil || first.VerifyTransientPreparation("admin:one", token, metadata) != nil {
		t.Fatal("new epoch failed", err)
	}
	first.now = func() time.Time { return time.Now().Add(SessionLifetime + time.Minute) }
	if first.VerifyTransientPreparation("admin:one", token, metadata) == nil {
		t.Fatal("expired transient token accepted")
	}
}

func TestTransientPreparationConcurrentReset(t *testing.T) {
	manager, err := New(bytes.Repeat([]byte{0x7b}, 32))
	if err != nil {
		t.Fatal(err)
	}
	meta, err := NewMetadata(91)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	failures := make(chan error, 4)
	for i := 0; i < cap(failures); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 64; j++ {
				token, e := manager.SignTransientPreparation("admin:test", meta)
				if e == nil {
					e = manager.VerifyTransientPreparation("admin:test", token, meta)
				}
				// A reset may legally occur between issuance and verification.
				if e != nil && !errors.Is(e, ErrSession) {
					failures <- e
					return
				}
			}
		}()
	}
	for i := 0; i < 64; i++ {
		if err = manager.ResetTransientPreparations(); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
	close(failures)
	for e := range failures {
		t.Fatalf("concurrent epoch operation: %v", e)
	}
}
