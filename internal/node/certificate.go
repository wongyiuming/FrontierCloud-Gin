package node

import (
	"context"
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
func (s *Service) Certificate(ctx context.Context, id string, request certificate.Request, audit store.NodeAudit) (map[string]any, error) {
	if request.Action != "status" && request.Action != "renew" && request.Action != "auto" {
		return nil, store.ErrNodeState
	}
	row, e := s.repo.ReadIdentity(ctx)
	if e != nil {
		return nil, e
	}
	r, e := s.repo.Relationship(ctx, id)
	if e != nil {
		return nil, e
	}
	if row.Role != "Master" || r.Direction != "downstream" || r.State != "active" || r.Protocol != protocol.Version {
		return nil, store.ErrNodeState
	}
	if !s.certificateDispatch.TryLock() {
		return nil, errors.New("certificate control busy; retry after current request")
	}
	defer s.certificateDispatch.Unlock()
	if request.Action != "status" {
		if s.certificateAudit == nil {
			return nil, store.ErrNodeState
		}
		if e = s.certificateAudit.AppendAudit(ctx, store.AdminAudit{SessionHash: audit.Actor, Action: "node_certificate_" + request.Action, TargetCount: 1, SourceSummary: r.ID, Result: "requested", RequestID: audit.RequestID, TraceID: audit.TraceID}); e != nil {
			return nil, e
		}
	}
	wire := map[string]any{"action": request.Action}
	if request.Action == "auto" {
		wire["enabled"] = request.Enabled
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	result, e := s.Call(ctx, r, "/internal/v1/certificate", wire)
	if e == nil && request.Action != "status" {
		s.Wake()
	}
	return result, e
}
func (s *Service) ReceiveCertificate(ctx context.Context, r store.Relationship, request certificate.Request) (certificate.View, error) {
	if e := s.RequireFollower(ctx, r); e != nil {
		return certificate.View{}, e
	}
	if s.certificateStatus == nil {
		return certificate.View{}, errors.New("storage certificate status unavailable")
	}
	v := s.certificateStatus()
	if request.Action == "status" && s.certificateClient == nil {
		return v, nil
	}
	if s.certificateClient == nil {
		return v, errors.New("certificate agent not configured")
	}
	if request.Action != "status" && request.Action != "renew" && request.Action != "auto" {
		return v, store.ErrNodeState
	}
	result, e := s.certificateClient.Control(ctx, request)
	if e != nil {
		if request.Action == "status" {
			v.Job.Code = "agent_unavailable"
			return v, nil
		}
		return v, e
	}
	// Show the actually served certificate, with the agent's durable renewal state.
	v.Managed = true
	v.AutoRenew = result.AutoRenew
	v.Validation = result.Validation
	v.Job = result.Job
	return v, nil
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
