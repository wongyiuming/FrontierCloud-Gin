package preprodimport

import (
	"context"
	"crypto/ecdh"
	"encoding/hex"
	"io"
	"os"
	"time"
)

// validateCapturedSourceStreamV2 combines pinned-manifest authentication,
// target-key decryption and complete frame validation without persisting any
// plaintext. Success is still not an import or owner publication permit.
func validateCapturedSourceStreamV2(ctx context.Context, signed signedSourceStream, intent sourceCaptureIntent, sourcePublic string, receiver *ecdh.PrivateKey, stage *os.File, now time.Time) error {
	if ctx == nil || ctx.Err() != nil || receiver == nil || stage == nil {
		return invalid("source stream receive input")
	}
	if err := verifySourceStreamManifest(signed, intent, sourcePublic, receiver.PublicKey().Bytes(), now); err != nil {
		return err
	}
	plainRaw, err := hex.DecodeString(signed.Manifest.PlainSHA256)
	if err != nil || len(plainRaw) != 32 {
		return invalid("source stream plaintext digest")
	}
	cipherRaw, err := hex.DecodeString(signed.Manifest.CipherSHA256)
	if err != nil || len(cipherRaw) != 32 {
		return invalid("source stream ciphertext digest")
	}
	var plain, cipher [32]byte
	copy(plain[:], plainRaw)
	copy(cipher[:], cipherRaw)
	reader, writer := io.Pipe()
	done := make(chan error, 1)
	go func() {
		err := verifySourceRowsV2(ctx, reader, signed.Manifest.Header.PlainSize, signed.Manifest.Sections, intent.SourceKeyID)
		_ = reader.CloseWithError(err)
		done <- err
	}()
	err = openSourceStreamV2(ctx, signed.Manifest.Header, receiver, stage, writer, plain, cipher)
	if err != nil {
		_ = writer.CloseWithError(err)
	} else {
		_ = writer.Close()
	}
	verifyErr := <-done
	if err != nil {
		return err
	}
	if verifyErr != nil {
		return verifyErr
	}
	return ctx.Err()
}
