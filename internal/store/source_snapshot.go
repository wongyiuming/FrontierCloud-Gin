package store

// MediaSourceSnapshot is sensitive Master-only data. It contains business
// paths and encryption descriptors; callers must not log it or persist it
// outside the trusted target. Nil cells represent SQL NULL.
type MediaSourceSection struct {
	Name    string      `json:"name"`
	Columns []string    `json:"columns"`
	Rows    [][]*string `json:"rows"`
}

type MediaSourceSnapshot struct {
	Version        int                  `json:"version"`
	AuthorityKind  string               `json:"authority_kind"`
	SourceSSHHostKeySHA256 string       `json:"source_ssh_host_key_sha256"`
	SourceNode     string               `json:"source_node"`
	SourcePublic   string               `json:"source_public"`
	TargetNode     string               `json:"target_node"`
	TargetReceiver []byte               `json:"target_receiver"`
	Challenge      string               `json:"challenge"`
	IssuedUnix     int64                `json:"issued_unix"`
	ExpiresUnix    int64                `json:"expires_unix"`
	Sections       []MediaSourceSection `json:"sections"`
}

type SignedMediaSourceSnapshot struct {
	Snapshot  MediaSourceSnapshot `json:"snapshot"`
	Signature string              `json:"signature"`
}

// EncryptedMediaSourceSnapshot is the only transfer representation. The
// destination must authenticate the source signature after decryption.
type EncryptedMediaSourceSnapshot struct {
	Version   int    `json:"version"`
	Ephemeral []byte `json:"ephemeral"`
	Nonce     []byte `json:"nonce"`
	Cipher    []byte `json:"cipher"`
}
