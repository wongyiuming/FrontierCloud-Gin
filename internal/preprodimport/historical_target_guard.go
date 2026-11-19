package preprodimport

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"os"
	"path/filepath"
	"reflect"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

// historicalTargetGuard is specific to the isolated preproduction history
// import. The caller obtains expected identity/pin from trusted configuration
// and must hold maintenance.InspectSQLite for this exact path for its lifetime.
// It is not an Owner recovery proof or product activation capability.
type historicalTargetGuard struct {
	path        string
	identity    store.NodeIdentity
	pin         sourceAuthorityPin
	scopeDigest string
	vault       *vault.Vault
	check       func() error
}

func (g historicalTargetGuard) validate(ctx context.Context, tx *sql.Tx) error {
	if ctx == nil || tx == nil || g.check == nil || g.vault == nil || g.path == "" || !id64.MatchString(g.scopeDigest) || !validSourceAuthority(g.pin) || g.identity.Role != "Master" || g.identity.ID != g.pin.TargetNode || g.identity.PrivateKey == "" || g.identity.CreatedAt <= 0 || g.check() != nil {
		return invalid("historical target authority")
	}
	rows, err := tx.QueryContext(ctx, `PRAGMA database_list`)
	if err != nil {
		return invalid("historical target database")
	}
	var mainPath string
	for rows.Next() {
		var index int
		var name, path string
		if err = rows.Scan(&index, &name, &path); err != nil {
			rows.Close()
			return invalid("historical target database")
		}
		if name == "main" {
			mainPath = path
		}
	}
	rowsErr := rows.Err()
	closeErr := rows.Close()
	if rowsErr != nil || closeErr != nil || mainPath == "" {
		return invalid("historical target database")
	}
	expectedPath, err := filepath.Abs(g.path)
	if err != nil {
		return invalid("historical target database")
	}
	mainPath, err = filepath.Abs(mainPath)
	if err != nil || filepath.Clean(mainPath) != filepath.Clean(expectedPath) {
		return invalid("historical target database")
	}
	want, err := os.Lstat(expectedPath)
	if err != nil || !want.Mode().IsRegular() || want.Mode()&os.ModeSymlink != 0 {
		return invalid("historical target database")
	}
	got, err := os.Stat(mainPath)
	if err != nil || !os.SameFile(want, got) {
		return invalid("historical target database")
	}
	var actual store.NodeIdentity
	if err = tx.QueryRowContext(ctx, `SELECT node_id,role,endpoint,private_key,created_at FROM node_identity WHERE singleton=1`).Scan(&actual.ID, &actual.Role, &actual.Endpoint, &actual.PrivateKey, &actual.CreatedAt); err != nil || actual != g.identity {
		return invalid("historical target identity")
	}
	private, err := g.vault.Unseal(actual.PrivateKey)
	if err != nil {
		return invalid("historical target identity")
	}
	seed, err := protocol.Decode(private)
	if err != nil {
		return invalid("historical target identity")
	}
	defer clear(seed)
	public, err := protocol.PublicKey(private)
	if err != nil {
		return invalid("historical target identity")
	}
	publicBytes, err := protocol.Decode(public)
	if err != nil || subtle.ConstantTimeCompare(publicBytes, g.pin.TargetMasterPublic) != 1 {
		return invalid("historical target identity")
	}
	receiver, err := receiverFromMasterSeed(seed)
	if err != nil || subtle.ConstantTimeCompare(receiver.PublicKey().Bytes(), g.pin.TargetX25519) != 1 {
		return invalid("historical target receiver")
	}
	var raw []byte
	if err = tx.QueryRowContext(ctx, `SELECT sealed FROM sealed_tree_source_pin WHERE singleton=1`).Scan(&raw); err != nil || len(raw) == 0 || len(raw) > 8192 {
		return invalid("historical target source pin")
	}
	pin, err := decodeSourceAuthority(g.vault, string(raw))
	if err != nil || !reflect.DeepEqual(pin, g.pin) {
		return invalid("historical target source pin")
	}
	if g.check() != nil {
		return invalid("historical target maintenance")
	}
	return nil
}

// The source scope is independently pinned by the coordinator; the source
// stream cannot choose its own destination, key identity or signer.
func (g historicalTargetGuard) matchesSource(intent sourceCaptureIntent, public string, receiver []byte) bool {
	return validSourceAuthority(g.pin) && id64.MatchString(g.scopeDigest) && intent.SourceNode == g.pin.SourceNode && intent.TargetNode == g.pin.TargetNode && intent.SourceKeyID == g.pin.SourceKeyID && intent.ScopeDigest == g.scopeDigest && public == protocol.Encode(g.pin.SourcePublic) && subtle.ConstantTimeCompare(receiver, g.pin.TargetX25519) == 1
}
