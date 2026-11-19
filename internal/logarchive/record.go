package logarchive

import (
	"encoding/hex"
	"encoding/json"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

// SealRecord protects the Master manifest as well as its wrapped per-block
// key. Persist this envelope, not a JSON serialization of Record.
func SealRecord(master *vault.Vault, record Record) (string, error) {
	if _, err := UnwrapForMaster(master, record); err != nil {
		return "", err
	}
	if !validCiphertextReference(record) {
		return "", ErrBlock
	}
	raw, err := json.Marshal(record)
	if err != nil {
		return "", ErrBlock
	}
	return master.Seal(string(raw))
}

func OpenRecord(master *vault.Vault, sealed string) (Record, error) {
	var record Record
	if master == nil || len(sealed) > 16384 {
		return record, ErrBlock
	}
	raw, err := master.Unseal(sealed)
	if err != nil || json.Unmarshal([]byte(raw), &record) != nil || !validCiphertextReference(record) {
		return Record{}, ErrBlock
	}
	if _, err = UnwrapForMaster(master, record); err != nil {
		return Record{}, err
	}
	return record, nil
}

func validCiphertextReference(record Record) bool {
	sha, err := hex.DecodeString(record.CiphertextSHA256)
	return err == nil && len(sha) == 32 && hex.EncodeToString(sha) == record.CiphertextSHA256 && record.CiphertextBytes > len(magic)+12+16 && record.CiphertextBytes <= MaxPlainBytes+len(magic)+12+16
}
