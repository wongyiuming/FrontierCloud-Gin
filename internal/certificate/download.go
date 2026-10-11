package certificate

// DownloadEnvelope carries no plaintext key. The selected node seals its own
// complete pair to a fresh browser key; a Master only forwards this ciphertext.
type DownloadEnvelope struct {
	Algorithm    string `json:"algorithm"`
	PublicKey    string `json:"public_key"`
	Salt         string `json:"salt"`
	IV           string `json:"iv"`
	Ciphertext   string `json:"ciphertext"`
	Hostname     string `json:"hostname"`
	Fingerprint  string `json:"fingerprint"`
	BrowserNonce string `json:"browser_nonce"`
}
