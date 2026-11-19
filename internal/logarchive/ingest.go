package logarchive

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

type IngestPacket struct {
	ID        string `json:"id"`
	Master    string `json:"master"`
	Node      string `json:"node"`
	Ephemeral []byte `json:"ephemeral"`
	Nonce     []byte `json:"nonce"`
	Cipher    []byte `json:"cipher"`
}

func (p IngestPacket) aad() []byte {
	return []byte("frontiercloud:log-ingest:v1\x00" + p.Master + "\x00" + p.Node + "\x00" + p.ID)
}
func sealIngest(public []byte, master, node string, plain []byte) (IngestPacket, error) {
	var p IngestPacket
	if !identifier(master) || !identifier(node) || len(plain) > 16384 {
		return p, ErrPolicy
	}
	remote, e := ecdh.X25519().NewPublicKey(public)
	if e != nil {
		return p, e
	}
	private, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		return p, e
	}
	secret, e := private.ECDH(remote)
	if e != nil {
		return p, e
	}
	id := make([]byte, 16)
	if _, e = rand.Read(id); e != nil {
		return p, e
	}
	p = IngestPacket{ID: hex.EncodeToString(id), Master: master, Node: node, Ephemeral: private.PublicKey().Bytes()}
	key := sha256.Sum256(append(append([]byte("frontiercloud:log-ingest:key:v1\x00"), secret...), p.aad()...))
	clear(secret)
	block, e := aes.NewCipher(key[:])
	clear(key[:])
	if e != nil {
		return p, e
	}
	aead, e := cipher.NewGCM(block)
	if e != nil {
		return p, e
	}
	p.Nonce = make([]byte, aead.NonceSize())
	if _, e = rand.Read(p.Nonce); e != nil {
		return p, e
	}
	p.Cipher = aead.Seal(nil, p.Nonce, plain, p.aad())
	return p, nil
}
func openIngest(private []byte, p IngestPacket) ([]byte, error) {
	if !identifier(p.ID) || !identifier(p.Master) || !identifier(p.Node) || len(p.Cipher) > 16400 || len(p.Cipher) < 16 || len(p.Nonce) != 12 {
		return nil, ErrPolicy
	}
	local, e := ecdh.X25519().NewPrivateKey(private)
	if e != nil {
		return nil, e
	}
	remote, e := ecdh.X25519().NewPublicKey(p.Ephemeral)
	if e != nil {
		return nil, e
	}
	secret, e := local.ECDH(remote)
	if e != nil {
		return nil, e
	}
	key := sha256.Sum256(append(append([]byte("frontiercloud:log-ingest:key:v1\x00"), secret...), p.aad()...))
	clear(secret)
	block, e := aes.NewCipher(key[:])
	clear(key[:])
	if e != nil {
		return nil, e
	}
	aead, e := cipher.NewGCM(block)
	if e != nil {
		return nil, e
	}
	return aead.Open(nil, p.Nonce, p.Cipher, p.aad())
}

func (c *Catalog) IngestPublic(ctx context.Context) ([]byte, error) {
	key, e := c.ingestPrivate(ctx)
	if e != nil {
		return nil, e
	}
	defer clear(key)
	private, e := ecdh.X25519().NewPrivateKey(key)
	if e != nil {
		return nil, e
	}
	return private.PublicKey().Bytes(), nil
}
func (c *Catalog) ingestPrivate(ctx context.Context) ([]byte, error) {
	var sealed string
	e := c.db.QueryRowContext(ctx, "SELECT sealed FROM log_ingest_key WHERE id=1").Scan(&sealed)
	if errors.Is(e, sql.ErrNoRows) {
		private, e := ecdh.X25519().GenerateKey(rand.Reader)
		if e != nil {
			return nil, e
		}
		sealed, e = c.vault.Seal(base64.RawStdEncoding.EncodeToString(private.Bytes()))
		if e != nil {
			return nil, e
		}
		if _, e = c.db.ExecContext(ctx, "INSERT INTO log_ingest_key(id,sealed) VALUES(1,?) ON CONFLICT(id) DO NOTHING", sealed); e != nil {
			return nil, e
		}
		if e = c.db.QueryRowContext(ctx, "SELECT sealed FROM log_ingest_key WHERE id=1").Scan(&sealed); e != nil {
			return nil, e
		}
	} else if e != nil {
		return nil, e
	}
	plain, e := c.vault.Unseal(sealed)
	if e != nil {
		return nil, e
	}
	raw, e := base64.RawStdEncoding.DecodeString(plain)
	if e != nil || len(raw) != 32 {
		return nil, ErrBlock
	}
	return raw, nil
}
func (c *Catalog) Ingest(ctx context.Context, node string, p IngestPacket) error {
	if node != p.Node || p.Master != c.master {
		return ErrPolicy
	}
	key, e := c.ingestPrivate(ctx)
	if e != nil {
		return e
	}
	plain, e := openIngest(key, p)
	clear(key)
	if e != nil {
		return e
	}
	defer clear(plain)
	var event struct {
		Kind   Kind           `json:"kind"`
		Fields map[string]any `json:"fields"`
	}
	if json.Unmarshal(plain, &event) != nil || !validKind(event.Kind) || event.Fields == nil {
		return ErrPolicy
	}
	event.Fields["source_node"] = node
	tx, e := c.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var old string
	e = tx.QueryRowContext(ctx, "SELECT packet_id FROM log_ingest_receipts WHERE node_id=? AND packet_id=?", node, p.ID).Scan(&old)
	if errors.Is(e, sql.ErrNoRows) {
		handled, e := c.AppendTransaction(ctx, tx, event.Kind, event.Fields)
		if e != nil {
			return e
		}
		if !handled {
			return ErrPolicy
		}
	} else if e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, "INSERT INTO log_ingest_receipts(node_id,packet_id,received) VALUES(?,?,?) ON CONFLICT(node_id,packet_id) DO UPDATE SET received=excluded.received", node, p.ID, time.Now().UnixNano()); e != nil {
		return e
	}
	return tx.Commit()
}
func (c *Catalog) IngestReceipts(ctx context.Context, node string) ([]string, error) {
	rows, e := c.db.QueryContext(ctx, "SELECT packet_id FROM log_ingest_receipts WHERE node_id=? ORDER BY received DESC LIMIT 16", node)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	ids := []string{}
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			return nil, e
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}
