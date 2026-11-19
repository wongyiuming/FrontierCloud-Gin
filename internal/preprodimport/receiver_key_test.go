package preprodimport

import (
	"bytes"
	"testing"
)

func TestReceiverDerivationIsStableAndBoundToMaster(t *testing.T) {
	seed := bytes.Repeat([]byte{0x71}, 32)
	first, err := receiverFromMasterSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := receiverFromMasterSeed(append([]byte(nil), seed...))
	if err != nil || !bytes.Equal(first.PublicKey().Bytes(), restored.PublicKey().Bytes()) {
		t.Fatal("receiver did not survive identity restore")
	}
	other, err := receiverFromMasterSeed(bytes.Repeat([]byte{0x72}, 32))
	if err != nil || bytes.Equal(first.PublicKey().Bytes(), other.PublicKey().Bytes()) {
		t.Fatal("different master received the same receiver")
	}
	if _, err = receiverFromMasterSeed(make([]byte, 32)); err == nil {
		t.Fatal("zero seed accepted")
	}
	if _, err = receiverFromMasterSeed(seed[:31]); err == nil {
		t.Fatal("short seed accepted")
	}
}
