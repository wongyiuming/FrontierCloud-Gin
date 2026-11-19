package node

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

var ErrFollowerRelayRange = errors.New("invalid or unsatisfiable relay range")

// FollowerRelayResponse contains only validated framing and the opaque body.
// No owner URL, bearer, placement headers or underlying network error escapes.
type FollowerRelayResponse struct {
	Body         io.ReadCloser
	Status       int
	Length       int64
	ContentRange string
}

type followerRelayReadClient interface {
	MediaRelayRead(context.Context, string, string, string, string, string, int64) (FollowerRelayResponse, error)
}

type opaqueFollowerRelayReadClient interface {
	MediaOpaqueRelayRead(context.Context, string, string, string, string, string, int64) (FollowerRelayResponse, error)
}

// OpenOpaqueFollowerRelayStream must follow a fresh tree visibility, owner and
// placement check under the context's still-held tree lease. The caller checks
// that lease once more before sending a response, then releases it before body
// drain. Neither the upstream URL nor owner bearer contains historical IDs.
func (s *Service) OpenOpaqueFollowerRelayStream(ctx context.Context, relayToken, alias, blob, revision, digest string, size int64, meta *mediacrypto.Metadata, sessions *mediacrypto.Manager, method, byteRange string) (FollowerRelayResponse, error) {
	var empty FollowerRelayResponse
	prerequisite, ok := store.IngressPrerequisiteFromContext(ctx)
	if !ok || prerequisite.Check(ctx) != nil || sessions == nil {
		return empty, ErrCapability
	}
	claim, err := s.VerifyOpaqueFollowerRelayCapability(ctx, relayToken, alias)
	descriptor, descErr := protocol.IngressMediaDescriptor(size, meta)
	placementRevision, revisionErr := protocol.OpaquePlacementRevision(alias, blob, digest, size, meta)
	if err != nil || descErr != nil || revisionErr != nil || claim.Revision != revision || revision != placementRevision || claim.Descriptor != descriptor || !sessions.CheckDirectSession(claim.SessionID) {
		return empty, ErrCapability
	}
	relation, err := s.repo.Relationship(ctx, claim.RelationshipID)
	if err != nil {
		return empty, ErrCapability
	}
	credential, err := s.identity.vault.Unseal(relation.Credential)
	if err != nil {
		return empty, ErrCapability
	}
	token, err := protocol.OpaqueIngressMediaToken(credential, relation.ID, claim.MasterID, claim.OwnerID, alias, claim.IngressID, claim.PublicOrigin, claim.SessionID, blob, claim.Generation, time.Now().Unix(), claim.ExpiresAt, size, digest, meta)
	if err != nil || prerequisite.Check(ctx) != nil || !sessions.CheckDirectSession(claim.SessionID) {
		return empty, ErrCapability
	}
	client, ok := s.transport.(opaqueFollowerRelayReadClient)
	if !ok {
		return empty, errors.New("verified opaque relay unavailable")
	}
	response, err := client.MediaOpaqueRelayRead(ctx, relation.Endpoint, alias, token, method, byteRange, size)
	if err != nil {
		return empty, err
	}
	if response.Body == nil {
		return empty, ErrCapability
	}
	confirmed, confirmErr := s.VerifyOpaqueFollowerRelayCapability(ctx, relayToken, alias)
	if confirmErr != nil || confirmed != claim || prerequisite.Check(ctx) != nil || !sessions.CheckDirectSession(claim.SessionID) {
		response.Body.Close()
		return empty, ErrCapability
	}
	return response, nil
}

// OpenFollowerRelayStream may follow only a visibility and revision check by
// the media layer. The derived owner bearer stays within this server call.
func (s *Service) OpenFollowerRelayStream(ctx context.Context, relayToken string, row store.GlobalMedia, meta *mediacrypto.Metadata, sessions *mediacrypto.Manager, method, byteRange string) (FollowerRelayResponse, error) {
	var empty FollowerRelayResponse
	claim, err := s.VerifyFollowerRelayCapability(ctx, relayToken, row.ID)
	if err != nil || row.RelationshipID == nil || *row.RelationshipID != claim.RelationshipID || row.MemberID != claim.OwnerID || row.ObjectID != claim.ObjectID || store.NativeResourceRevision(row) != claim.Revision {
		return empty, ErrCapability
	}
	var token string
	if meta == nil {
		if len(row.ETag) != 66 || row.ETag[0] != '"' || row.ETag[65] != '"' || !resourceIdentifier.MatchString(row.ETag[1:65]) {
			return empty, ErrCapability
		}
		token, err = s.followerRelayOwnerPlainCapability(ctx, relayToken, row.ID, row.Bytes, row.ETag[1:65], sessions)
	} else {
		token, err = s.FollowerRelayOwnerCapability(ctx, relayToken, row.ID, row.Bytes, meta, sessions)
	}
	if err != nil {
		return empty, err
	}
	relation, err := s.repo.Relationship(ctx, claim.RelationshipID)
	if err != nil {
		return empty, ErrCapability
	}
	client, ok := s.transport.(followerRelayReadClient)
	if !ok {
		return empty, errors.New("verified relay unavailable")
	}
	return client.MediaRelayRead(ctx, relation.Endpoint, row.ObjectID, token, method, byteRange, row.Bytes)
}

// followerRelayRange accepts the same bounded single-range shapes used by the
// public edge. It never permits multipart bodies or arithmetic overflow.
func followerRelayRange(value string, size int64) (int64, int64, error) {
	if size <= 0 || len(value) > 128 || !strings.HasPrefix(value, "bytes=") || strings.Contains(value, ",") {
		return 0, 0, ErrFollowerRelayRange
	}
	parts := strings.Split(strings.TrimPrefix(value, "bytes="), "-")
	if len(parts) != 2 || parts[0] == "" && parts[1] == "" {
		return 0, 0, ErrFollowerRelayRange
	}
	parse := func(v string) (int64, error) {
		if v == "" {
			return 0, ErrFollowerRelayRange
		}
		for _, c := range v {
			if c < '0' || c > '9' {
				return 0, ErrFollowerRelayRange
			}
		}
		return strconv.ParseInt(v, 10, 64)
	}
	if parts[0] == "" {
		suffix, err := parse(parts[1])
		if err != nil || suffix <= 0 {
			return 0, 0, ErrFollowerRelayRange
		}
		if suffix >= size {
			return 0, size - 1, nil
		}
		return size - suffix, size - 1, nil
	}
	start, err := parse(parts[0])
	if err != nil || start >= size {
		return 0, 0, ErrFollowerRelayRange
	}
	end := size - 1
	if parts[1] != "" {
		end, err = parse(parts[1])
		if err != nil || end < start {
			return 0, 0, ErrFollowerRelayRange
		}
		if end >= size {
			end = size - 1
		}
	}
	return start, end, nil
}

// MediaRelayRead performs only one verified HTTPS request to the paired owner,
// with a server-only header capability. The caller owns Body and cancellation.
// The transport's dedicated storage pool does not consume heartbeat slots.
func (t *Transport) MediaRelayRead(ctx context.Context, origin, objectID, token, method, byteRange string, size int64) (FollowerRelayResponse, error) {
	return t.mediaRelayRead(ctx, origin, objectID, token, method, byteRange, size, "/internal/v1/media/")
}

// MediaOpaqueRelayRead targets only the v5 owner route with a random alias.
func (t *Transport) MediaOpaqueRelayRead(ctx context.Context, origin, alias, token, method, byteRange string, size int64) (FollowerRelayResponse, error) {
	return t.mediaRelayRead(ctx, origin, alias, token, method, byteRange, size, "/internal/v1/opaque-media/")
}

func (t *Transport) mediaRelayRead(ctx context.Context, origin, objectID, token, method, byteRange string, size int64, route string) (FollowerRelayResponse, error) {
	var result FollowerRelayResponse
	origin, err := Endpoint(origin)
	if err != nil || !resourceIdentifier.MatchString(objectID) || token == "" || len(token) > 4096 || (method != http.MethodGet && method != http.MethodHead) || size < 0 {
		return result, ErrCapability
	}
	status, length, contentRange := http.StatusOK, size, ""
	if byteRange != "" {
		if size == 0 {
			// The original owner uses net/http.ServeContent: a start range on
			// an empty file is ignored, whereas a suffix gives an empty 206.
			if len(byteRange) > 128 || !strings.HasPrefix(byteRange, "bytes=") || strings.Contains(byteRange, ",") {
				return result, ErrFollowerRelayRange
			}
			parts := strings.Split(strings.TrimPrefix(byteRange, "bytes="), "-")
			if len(parts) != 2 || parts[0] == "" && parts[1] == "" {
				return result, ErrFollowerRelayRange
			}
			for _, part := range parts {
				if part == "" {
					continue
				}
				for _, c := range part {
					if c < '0' || c > '9' {
						return result, ErrFollowerRelayRange
					}
				}
				if _, e := strconv.ParseInt(part, 10, 64); e != nil {
					return result, ErrFollowerRelayRange
				}
			}
			if parts[0] == "" {
				status, contentRange = http.StatusPartialContent, "bytes 0--1/0"
			}
		} else {
			start, end, e := followerRelayRange(byteRange, size)
			if e != nil {
				return result, ErrFollowerRelayRange
			}
			status, length = http.StatusPartialContent, end-start+1
			contentRange = fmt.Sprintf("bytes %d-%d/%d", start, end, size)
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, origin+route+objectID, nil)
	if err != nil {
		return result, errors.New("verified relay unavailable")
	}
	req.Header.Set("X-Media-Capability", token)
	req.Header.Set("Accept-Encoding", "identity")
	if byteRange != "" {
		req.Header.Set("Range", byteRange)
	}
	resp, err := t.storage.Do(req)
	if err != nil {
		return result, errors.New("verified relay unavailable")
	}
	// An owner using the old Nginx X-Accel path returns 200 for an empty
	// suffix range; the Go-only path returns an empty 206. Both are bounded.
	if size == 0 && status == http.StatusPartialContent && resp.StatusCode == http.StatusOK {
		status, contentRange = http.StatusOK, ""
	}
	if resp.StatusCode != status || resp.ContentLength != length || resp.Header.Get("Content-Encoding") != "" && resp.Header.Get("Content-Encoding") != "identity" || len(resp.Header.Values("Content-Range")) > 1 || resp.Header.Get("Content-Range") != contentRange {
		resp.Body.Close()
		return result, errors.New("verified relay response mismatch")
	}
	return FollowerRelayResponse{Body: resp.Body, Status: status, Length: length, ContentRange: contentRange}, nil
}
