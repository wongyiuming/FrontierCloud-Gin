package node

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"sort"
	"strconv"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/certificate"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func (s *Service) ConfigureNetwork(port int, client certificate.Client, status func() certificate.View, audit store.AdminRepository) {
	s.SetSTUNPort(port)
	s.certificateClient = client
	s.certificateStatus = status
	s.certificateAudit = audit
}

// Zero is an explicit unavailable responder, not an old peer's absent field.
func (s *Service) SetSTUNPort(port int) { s.stunPort.Store(int64(port)) }
func certificateRequestValid(request certificate.Request) bool {
	if request.Enabled {
		return false
	}
	if request.Action == "status" {
		return request.BrowserPublicKey == "" && request.BrowserNonce == ""
	}
	return request.Action == "download" && len(request.BrowserPublicKey) > 0 && len(request.BrowserPublicKey) <= 90 && len(request.BrowserNonce) == 43
}
func viewMap(v certificate.View) (map[string]any, error) {
	raw, e := json.Marshal(v)
	if e != nil {
		return nil, e
	}
	var result map[string]any
	e = json.Unmarshal(raw, &result)
	return result, e
}
func (s *Service) Certificate(ctx context.Context, id string, request certificate.Request, audit store.NodeAudit) (map[string]any, error) {
	if !certificateRequestValid(request) {
		return nil, store.ErrNodeState
	}
	row, e := s.repo.ReadIdentity(ctx)
	if e != nil {
		return nil, e
	}
	local := row.ID == id && (row.Role == "Master" || row.Role == "Standalone")
	var relation store.Relationship
	if !local {
		relation, e = s.repo.Relationship(ctx, id)
		if e != nil {
			return nil, e
		}
		if row.Role != "Master" || relation.Direction != "downstream" || relation.State != "active" || relation.Protocol != protocol.Version {
			return nil, store.ErrNodeState
		}
	}
	if !s.certificateDispatch.TryLock() {
		return nil, errors.New("certificate request busy; retry after current request")
	}
	defer s.certificateDispatch.Unlock()
	if request.Action == "download" {
		if s.certificateAudit == nil {
			return nil, store.ErrNodeState
		}
		if e = s.certificateAudit.AppendAudit(ctx, store.AdminAudit{SessionHash: audit.Actor, Action: "node_certificate_download", TargetCount: 1, SourceSummary: id, Result: "requested", RequestID: audit.RequestID, TraceID: audit.TraceID}); e != nil {
			return nil, e
		}
	}
	if local {
		if s.certificateStatus == nil {
			return nil, store.ErrNodeState
		}
		if request.Action == "status" {
			return viewMap(s.certificateStatus())
		}
		if s.certificateClient == nil {
			return nil, store.ErrNodeState
		}
		v, e := s.certificateClient.Control(ctx, request)
		if e != nil {
			return nil, e
		}
		return viewMap(v)
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	payload := map[string]any{"action": request.Action}
	if request.Action == "download" {
		payload["browser_public_key"] = request.BrowserPublicKey
		payload["browser_nonce"] = request.BrowserNonce
	}
	return s.Call(ctx, relation, "/internal/v1/certificate", payload)
}
func (s *Service) ReceiveCertificate(ctx context.Context, r store.Relationship, request certificate.Request) (certificate.View, error) {
	if !certificateRequestValid(request) {
		return certificate.View{}, store.ErrNodeState
	}
	if e := s.RequireFollower(ctx, r); e != nil {
		return certificate.View{}, e
	}
	if s.certificateStatus == nil {
		return certificate.View{}, errors.New("node certificate status unavailable")
	}
	if request.Action == "status" {
		return s.certificateStatus(), nil
	}
	if s.certificateClient == nil {
		return certificate.View{}, errors.New("certificate controller unavailable")
	}
	return s.certificateClient.Control(ctx, request)
}

// Only established storage hostnames may become browser ICE endpoints. The port
// comes from signed heartbeat facts; older peers use the existing 3478 default.
func (s *Service) STUNURLs(ctx context.Context, master string, port int) ([]string, error) {
	result := []string{"stun:" + net.JoinHostPort(master, strconv.Itoa(port))}
	row, e := s.repo.ReadIdentity(ctx)
	if e != nil {
		return nil, e
	}
	if row.Role != "Master" {
		return result, nil
	}
	relations, e := s.repo.Relationships(ctx, false)
	if e != nil {
		return nil, e
	}
	sort.Slice(relations, func(i, j int) bool { return relations[i].PeerID < relations[j].PeerID })
	seen := map[string]bool{result[0]: true}
	for _, r := range relations {
		if r.Direction != "downstream" || r.State != "active" {
			continue
		}
		origin, e := Endpoint(r.Endpoint)
		if e != nil {
			continue
		}
		u, _ := url.Parse(origin)
		p := 3478
		if _, known := r.Summary["stun_port"]; known {
			n, ok := intField(r.Summary, "stun_port")
			if !ok || n <= 0 || n > 65535 {
				continue
			}
			p = int(n)
		}
		value := "stun:" + net.JoinHostPort(u.Hostname(), strconv.Itoa(p))
		if !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	return result, nil
}
