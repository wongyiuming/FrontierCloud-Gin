package preprodimport

import (
	"bytes"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
)

func TestLegacyEnvelopeUsesExactSourceSessionAndDescriptor(t *testing.T) {
	source, err := mediacrypto.New(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	receiver, public, err := newLegacyReceiver()
	if err != nil {
		t.Fatal(err)
	}
	grant, err := source.NewSession("admin:fixture", public)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := mediacrypto.NewMetadata(4097)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := source.Wrap("admin:fixture", grant.SessionID, metadata)
	if err != nil {
		t.Fatal(err)
	}
	got, err := receiver.open(grant, metadata, metadata, envelope, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer clear(got)
	want, err := source.FileKey(metadata)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(want)
	if !bytes.Equal(got, want) {
		t.Fatal("key differs from source")
	}

	other, _, err := newLegacyReceiver()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = other.open(grant, metadata, metadata, envelope, time.Now()); err == nil {
		t.Fatal("wrong target accepted")
	}
	changed := metadata
	changed.PlaintextSize++
	if _, err = receiver.open(grant, metadata, changed, envelope, time.Now()); err == nil {
		t.Fatal("changed descriptor accepted")
	}
	if _, err = receiver.open(grant, metadata, metadata, envelope, time.Unix(grant.ExpiresAt, 0)); err == nil {
		t.Fatal("expired grant accepted")
	}
	badEnvelope := envelope
	badEnvelope.WrappedKey = envelope.WrappedKey[:len(envelope.WrappedKey)-4] + "AAAA"
	if _, err = receiver.open(grant, metadata, metadata, badEnvelope, time.Now()); err == nil {
		t.Fatal("changed envelope accepted")
	}
	badGrant := grant
	badGrant.SessionID = "00000000000000000000000000000000"
	if _, err = receiver.open(badGrant, metadata, metadata, envelope, time.Now()); err == nil {
		t.Fatal("changed session accepted")
	}
	badEnvelope = envelope
	badEnvelope.ExpiresAt--
	if _, err = receiver.open(grant, metadata, metadata, badEnvelope, time.Now()); err == nil {
		t.Fatal("changed expiry accepted")
	}
}
