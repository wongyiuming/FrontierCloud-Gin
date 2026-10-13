package node

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/migrationdata"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

var ErrMigrationDirect = errors.New("migration requires direct storage connectivity")

func migrationDecode(payload any, out any) error {
	raw, e := json.Marshal(payload)
	if e != nil {
		return e
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if e = d.Decode(out); e != nil {
		return ErrCapability
	}
	var tail any
	if d.Decode(&tail) != io.EOF {
		return ErrCapability
	}
	return nil
}

func (s *Service) migrationSign(ctx context.Context, payload any) (migrationdata.Signed, error) {
	raw, e := json.Marshal(payload)
	if e != nil {
		return migrationdata.Signed{}, e
	}
	value, e := protocol.ParseStrictJSON(raw, MaxControlBytes)
	if e != nil {
		return migrationdata.Signed{}, e
	}
	row, e := s.repo.ReadIdentity(ctx)
	if e != nil {
		return migrationdata.Signed{}, e
	}
	payloadMap, ok := value.(map[string]any)
	if !ok {
		return migrationdata.Signed{}, ErrCapability
	}
	signed, e := s.identity.signed(row, payloadMap)
	return migrationdata.Signed{Payload: signed.Payload, Signature: signed.Signature}, e
}

func migrationGrantValid(g migrationdata.DirectGrant, now int64) bool {
	key, e := protocol.Decode(g.TargetPublicKey)
	return e == nil && len(key) == 32 && g.Format == migrationdata.DirectGrantFormat &&
		g.Spec.TaskID == g.Lease.TaskID && g.Spec.TaskID == g.Header.TaskID &&
		g.Spec.MasterID == g.Header.MasterID && g.Spec.SourceID == g.Header.SourceID &&
		g.Spec.TargetID == g.Header.TargetID && g.Spec.SourceID != g.Spec.TargetID &&
		g.ExpiresAt > now && g.ExpiresAt <= now+60 && g.ExpiresAt <= g.Lease.ExpiresAt
}

// MigrationDelegate signs an object/version/target-key grant after the HTTP
// caller has checked the source's persistent peer object. No bearer read route
// exists: the target must additionally prove possession of its private identity.
func (s *Service) MigrationDelegate(ctx context.Context, rel store.Relationship, v migrationdata.Request, h store.MigrationPeerHeader) (migrationdata.Signed, error) {
	if e := s.RequireFollower(ctx, rel); e != nil {
		return migrationdata.Signed{}, e
	}
	row, e := s.repo.ReadIdentity(ctx)
	if e != nil {
		return migrationdata.Signed{}, e
	}
	g := migrationdata.DirectGrant{Format: migrationdata.DirectGrantFormat, Header: h, Lease: v.Lease, Spec: v.Spec, SourceEndpoint: row.Endpoint, TargetPublicKey: v.TargetPublicKey, ExpiresAt: min(time.Now().Unix()+60, v.Lease.ExpiresAt)}
	if row.ID != h.SourceID || rel.ID != h.SourceRelationship || rel.PeerID != h.MasterID || !migrationGrantValid(g, time.Now().Unix()) {
		return migrationdata.Signed{}, ErrCapability
	}
	return s.migrationSign(ctx, g)
}

// AuthenticateMigrationRead accepts only a source-signed grant and a fresh
// target-signed, route/offset/length-bound request. Nonces share the persistent
// upstream ledger; revocation, retirement and credential replacement invalidate
// delegated reads even if their signatures have not expired.
func (s *Service) AuthenticateMigrationRead(ctx context.Context, signed migrationdata.Signed) (store.Relationship, migrationdata.Request, string, error) {
	var read migrationdata.DirectRead
	var grant migrationdata.DirectGrant
	var empty store.Relationship
	var req migrationdata.Request
	if migrationDecode(signed.Payload, &read) != nil || migrationDecode(read.Grant.Payload, &grant) != nil {
		return empty, req, "", ErrAuthentication
	}
	now := time.Now().Unix()
	row, e := s.repo.ReadIdentity(ctx)
	if e != nil {
		return empty, req, "", e
	}
	public, e := s.public(row)
	if e != nil {
		return empty, req, "", e
	}
	if !migrationGrantValid(grant, now) || row.ID != grant.Header.SourceID || read.Route != migrationdata.PeerReadRoute || !ValidIdentifier(read.Nonce) || read.Time < now-30 || read.Time > now+30 ||
		read.Length < 1 || read.Length > migrationdata.ChunkBytes || read.Offset < 0 || read.Offset%migrationdata.ChunkBytes != 0 || read.Offset > grant.Spec.Bytes-int64(read.Length) ||
		protocol.Verify(public, read.Grant.Payload, read.Grant.Signature) != nil || protocol.Verify(grant.TargetPublicKey, signed.Payload, signed.Signature) != nil {
		return empty, req, "", ErrAuthentication
	}
	rel, e := s.repo.Relationship(ctx, grant.Header.SourceRelationship)
	if e != nil || rel.PeerID != grant.Header.MasterID || s.RequireFollower(ctx, rel) != nil {
		return empty, req, "", ErrAuthentication
	}
	rel, e = s.repo.ReserveNodeNonce(ctx, rel.ID, read.Nonce, rel.Credential, now, false, false)
	if e != nil || s.RequireFollower(ctx, rel) != nil {
		return empty, req, "", ErrAuthentication
	}
	req = migrationdata.Request{Spec: grant.Spec, Lease: grant.Lease, Offset: read.Offset, Length: read.Length}
	return rel, req, read.Nonce, nil
}

func (s *Service) MigrationSignChunk(ctx context.Context, chunk migrationdata.DirectChunk) (migrationdata.Signed, error) {
	return s.migrationSign(ctx, chunk)
}

// MigrationPull reads one bounded chunk from the pinned source over verified
// HTTPS. The Master supplies only a signed grant and public routing facts.
// There is deliberately no Master fallback or arbitrary route/URL input.
func (s *Service) MigrationPull(ctx context.Context, rel store.Relationship, v migrationdata.Request, h store.MigrationPeerHeader) (migrationdata.DirectChunk, error) {
	var chunk migrationdata.DirectChunk
	if s.RequireFollower(ctx, rel) != nil || v.TransferGrant == nil || len(v.Data) != 0 || v.SHA != "" {
		return chunk, ErrCapability
	}
	var g migrationdata.DirectGrant
	if migrationDecode(v.TransferGrant.Payload, &g) != nil {
		return chunk, ErrCapability
	}
	row, e := s.repo.ReadIdentity(ctx)
	if e != nil {
		return chunk, e
	}
	public, e := s.public(row)
	if e != nil {
		return chunk, e
	}
	endpoint, e := Endpoint(v.SourceEndpoint)
	if e != nil || endpoint != v.SourceEndpoint || endpoint != g.SourceEndpoint || !migrationGrantValid(g, time.Now().Unix()) || !reflect.DeepEqual(g.Header, h) || !reflect.DeepEqual(g.Lease, v.Lease) || !reflect.DeepEqual(g.Spec, v.Spec) ||
		public != g.TargetPublicKey || row.ID != h.TargetID || rel.ID != h.TargetRelationship || rel.PeerID != h.MasterID ||
		v.Length < 1 || v.Length > migrationdata.ChunkBytes || v.Offset < 0 || v.Offset%migrationdata.ChunkBytes != 0 || v.Offset > v.Spec.Bytes-int64(v.Length) ||
		protocol.Verify(v.SourcePublicKey, v.TransferGrant.Payload, v.TransferGrant.Signature) != nil {
		return chunk, ErrCapability
	}
	nonce, e := randomNodeID()
	if e != nil {
		return chunk, e
	}
	read := migrationdata.DirectRead{Route: migrationdata.PeerReadRoute, Grant: *v.TransferGrant, Offset: v.Offset, Length: v.Length, Nonce: nonce, Time: time.Now().Unix()}
	signed, e := s.migrationSign(ctx, read)
	if e != nil {
		return chunk, e
	}
	// Fixed route, no relationship credential: authentication is the grant plus
	// target identity proof. Transport retains DNS/TLS/no-proxy/no-redirect rules.
	response, e := s.transport.Request(ctx, endpoint, migrationdata.PeerReadRoute, "POST", map[string]any{"payload": signed.Payload, "signature": signed.Signature}, "", "")
	if e != nil {
		return chunk, ErrMigrationDirect
	}
	var proof migrationdata.Signed
	if migrationDecode(response, &proof) != nil || protocol.Verify(v.SourcePublicKey, proof.Payload, proof.Signature) != nil || migrationDecode(proof.Payload, &chunk) != nil {
		return chunk, ErrCapability
	}
	if chunk.Waiting {
		if chunk.Nonce != nonce || chunk.Offset != v.Offset || chunk.Version != v.Spec.SourceVersion || len(chunk.Data) != 0 || chunk.Size != 0 || chunk.SHA != "" || chunk.Traffic == nil || chunk.Traffic.CanRun {
			return migrationdata.DirectChunk{}, ErrCapability
		}
		return chunk, nil
	}
	sum := sha256.Sum256(chunk.Data)
	if chunk.Nonce != nonce || chunk.Offset != v.Offset || chunk.Size != v.Length || len(chunk.Data) != v.Length || chunk.Version != v.Spec.SourceVersion || chunk.SHA != hex.EncodeToString(sum[:]) {
		return migrationdata.DirectChunk{}, ErrCapability
	}
	return chunk, nil
}
