package sealedtree

import (
	"errors"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestPlacementPlainSizeCeilingDoesNotExpandEncryptedV1(t *testing.T) {
	if protocol.MaxOpaquePlainBytes != store.MaxStorageAllocation {
		t.Fatal("native size ceiling drift")
	}
	tree := fixture(t)
	p := fixturePlacement(t, strings.Repeat("b", 64))
	p.Bytes = protocol.MaxOpaquePlainBytes
	if _, err := tree.SealPlacement(p, 1); err != nil {
		t.Fatal("maximum plain size", err)
	}
	p.Bytes++
	if _, err := tree.SealPlacement(p, 1); !errors.Is(err, ErrInvalid) {
		t.Fatal("oversized object accepted", err)
	}
	meta, err := mediacrypto.NewMetadata(mediacrypto.MaxPlaintextSize)
	if err != nil {
		t.Fatal(err)
	}
	p.Bytes, p.Encryption = meta.CiphertextSize, &meta
	if _, err := tree.SealPlacement(p, 1); err != nil {
		t.Fatal("maximum valid v1 ciphertext", err)
	}
	p.Bytes = protocol.MaxOpaquePlainBytes
	if _, err := tree.SealPlacement(p, 1); !errors.Is(err, ErrInvalid) {
		t.Fatal("mismatched encrypted size accepted", err)
	}
	meta.PlaintextSize = mediacrypto.MaxPlaintextSize + 1
	if meta.Validate() == nil {
		t.Fatal("v1 encryption limit changed")
	}
}
