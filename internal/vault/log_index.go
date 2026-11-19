package vault

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// LogSecurityIndex supports bounded existing ban-window counts without keeping
// an IP address or event body in the archive's operational index.
func (v *Vault) LogSecurityIndex(ip string) string {
	mac := hmac.New(sha256.New, v.key[:])
	mac.Write([]byte("frontiercloud:log:security-window:v1\x00"))
	mac.Write([]byte(ip))
	return hex.EncodeToString(mac.Sum(nil))
}
