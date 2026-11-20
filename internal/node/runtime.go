package node

import (
	"context"
	"errors"
	"log/slog"
	"math"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func heartbeatWindow(previous map[string]any, rtt int, now int64) map[string]any {
	var samples [][2]int64
	if old, ok := previous["heartbeat"].(map[string]any); ok {
		if values, ok := old["samples"].([]any); ok {
			for _, raw := range values {
				item, ok := raw.([]any)
				if !ok || len(item) != 2 {
					continue
				}
				stamp, ok1 := intField(map[string]any{"v": item[0]}, "v")
				latency, ok2 := intField(map[string]any{"v": item[1]}, "v")
				if ok1 && ok2 && stamp >= now-3600 && stamp <= now && latency >= 0 && latency <= math.MaxInt32 {
					samples = append(samples, [2]int64{stamp, latency})
				}
			}
		}
	}
	samples = append(samples, [2]int64{now, int64(max(0, rtt))})
	if len(samples) > 180 {
		samples = samples[len(samples)-180:]
	}
	minimum, maximum, total := samples[0][1], samples[0][1], int64(0)
	for _, sample := range samples {
		minimum = min(minimum, sample[1])
		maximum = max(maximum, sample[1])
		total += sample[1]
	}
	return map[string]any{"current_ms": samples[len(samples)-1][1], "min_ms": minimum, "avg_ms": int64(math.RoundToEven(float64(total) / float64(len(samples)))), "max_ms": maximum, "count": len(samples), "window_seconds": 3600, "samples": samples}
}

func (s *Service) Revoke(ctx context.Context, id string, a store.NodeAudit) error {
	relation, err := s.repo.Relationship(ctx, id)
	if err != nil {
		return err
	}
	if s.logArchiveProtect != nil && s.logArchiveProtect(ctx, relation.PeerID) {
		return ErrLogArchiveNodePinned
	}
	row, err := s.repo.ReadIdentity(ctx)
	if err != nil {
		return err
	}
	apply := func() error { return s.repo.RevokeRelationship(ctx, id, false, a) }
	if row.Role == "Follower" {
		if s.volume == nil {
			return errors.New("business volume is not configured")
		}
		err = s.withOwnerControlExclusive(ctx, func(ctx context.Context) error {
			return s.volume.WithPromotion(ctx, "Follower", func(store.NodePromotion) error {
				return s.emptyRecordings(ctx, func() error { return s.repo.RevokeRelationship(ctx, id, false, a) })
			})
		})
	} else {
		err = apply()
	}
	if err != nil {
		return err
	}
	// The durable tombstone is authoritative immediately; an unreachable peer is
	// retried by the control loop. No new pairing is allowed before its receipt.
	if err = s.NotifyRevocation(ctx, relation); err != nil {
		slog.Warn("peer revocation pending", "relationship_id", id)
	}
	return nil
}

func (s *Service) Tick(ctx context.Context, relation store.Relationship) error {
	if relation.State == "revoked" {
		return s.NotifyRevocation(ctx, relation)
	}
	if relation.State == "pending" {
		if time.Now().Unix()-relation.CreatedAt > 300 {
			return s.Revoke(ctx, relation.ID, store.NodeAudit{Actor: "pair-timeout"})
		}
		if relation.Direction != "downstream" {
			return nil
		}
		if _, err := s.Call(ctx, relation, "/internal/v1/confirm", map[string]any{}); err != nil {
			return err
		}
		if err := s.repo.ActivateRelationship(ctx, relation.ID, store.NodeAudit{Actor: "pair-recovery"}); err != nil {
			return err
		}
		var err error
		relation, err = s.repo.Relationship(ctx, relation.ID)
		if err != nil {
			return err
		}
	}
	if relation.State != "active" {
		return errors.New("invalid relationship state")
	}
	started := time.Now()
	var requested *store.NativeTransportPolicy
	var requestedOrigin string
	probe := func() (map[string]any, error) {
		if relation.Status != "online" {
			role := "Master"
			if relation.Direction == "downstream" {
				role = "Follower"
			}
			if _, err := s.transport.Identity(ctx, relation.Endpoint, relation.PeerID, relation.PublicKey, role); err != nil {
				return nil, err
			}
		}
		value := map[string]any{"capabilities": protocol.AdvertisedCapabilities()}
		if relation.Direction == "downstream" {
			if s.pool == nil {
				return nil, errors.New("resource pool is not configured")
			}
			config, err := s.pool.MemberConfiguration(ctx, relation.PeerID)
			if err != nil {
				return nil, err
			}
			value = map[string]any{"mode": relation.Mode, "resources": resourceWire(config), "capabilities": protocol.AdvertisedCapabilities()}
			if ingress, e := s.CurrentPublicIngress(ctx); e == nil {
				value["public_ingress"] = map[string]any{"node_id": ingress.NodeID, "public_origin": ingress.PublicOrigin, "generation": ingress.Generation}
			}
			if capabilities, e := protocol.ReadCapabilities(relation.Summary); e == nil && slices.Contains(capabilities, "native-transport-apply-v1") && s.nativeTransportReady != nil {
				if routing, ok := s.repo.(store.PublicRoutingRepository); ok {
					if s.initialNativeTransport {
						s.configureInitialTransport(ctx, routing, relation)
					}
					if p, e := routing.NativeTransport(ctx, relation.PeerID); e == nil && p.Revision > 0 && p.State != "applied" && p.State != "inactive" && p.State != "retained" && s.nativeTransportReady(ctx, relation, p.ConfiguredTransport) == nil {
						if p.ConfiguredTransport == "Relay" {
							requested = &p
							value["native_transport_request"] = map[string]any{"transport": "Relay", "revision": p.Revision}
						} else if p.ConfiguredTransport == "Direct" {
							if origin, e := s.VerifyFollowerResourceIdentity(ctx, relation.ID); e == nil {
								requested, requestedOrigin = &p, origin
								value["native_transport_request"] = map[string]any{"transport": "Direct", "revision": p.Revision, "origin": origin}
							}
						}
					}
				}
			}
		}
		if s.logHeartbeat != nil {
			s.logHeartbeat.Outgoing(ctx, relation, value)
		}
		summary, err := s.Call(ctx, relation, "/internal/v1/heartbeat", value)
		if err != nil {
			return nil, err
		}
		version, valid := intField(summary, "protocol")
		if !valid || version != protocol.Version {
			return nil, errors.New("heartbeat protocol mismatch")
		}
		capabilities, err := protocol.ReadCapabilities(summary)
		if err != nil {
			return nil, err
		}
		summary["capabilities"] = capabilities
		if s.logHeartbeat != nil {
			s.logHeartbeat.Incoming(ctx, relation, summary)
		}
		return summary, nil
	}
	summary, err := probe()
	now := time.Now().Unix()
	if err != nil {
		if errors.Is(ctx.Err(), context.Canceled) {
			return err
		}
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer cancel()
		if recordErr := s.repo.RecordHeartbeat(cleanup, relation.ID, false, 0, nil, now); recordErr != nil {
			return recordErr
		}
		return err
	}
	rtt := int(min(startedElapsed(started), math.MaxInt32))
	summary["heartbeat"] = heartbeatWindow(relation.Summary, rtt, now)
	if err := s.repo.RecordHeartbeat(ctx, relation.ID, true, rtt, summary, now); err != nil {
		return err
	}
	if requested != nil {
		if result, ok := summary["native_transport_result"].(map[string]any); ok {
			revision, valid := intField(result, "revision")
			capabilities, _ := protocol.ReadCapabilities(summary)
			if valid && revision == requested.Revision && textField(result, "transport") == requested.ConfiguredTransport && textField(result, "state") == "applied" && slices.Contains(capabilities, "native-transport-apply-v1") && s.nativeTransportReady(ctx, relation, requested.ConfiguredTransport) == nil {
				if requested.ConfiguredTransport == "Direct" && textField(result, "origin") == requestedOrigin {
					if origin, e := s.VerifyFollowerResourceIdentity(ctx, relation.ID); e == nil && origin == requestedOrigin {
						if repo, ok := s.repo.(nativeDirectApplicationRepository); ok {
							if err := repo.RecordNativeDirectApplication(ctx, relation.ID, revision, origin); err != nil {
								slog.Warn("native transport application not published", "relationship_id", relation.ID)
							}
						}
					}
				} else if requested.ConfiguredTransport == "Relay" {
					if repo, ok := s.repo.(nativeTransportApplicationRepository); ok {
						if err := repo.RecordNativeTransportApplication(ctx, relation.ID, revision, "Relay"); err != nil {
							slog.Warn("native transport application not published", "relationship_id", relation.ID)
						}
					}
				}
			}
		}
	}
	return nil
}

func (s *Service) configureInitialTransport(ctx context.Context, routing store.PublicRoutingRepository, relation store.Relationship) {
	profile := textField(relation.Summary, "storage_transport")
	if profile != strings.ToLower(relation.Mode) || (relation.Mode != "Direct" && relation.Mode != "Relay") {
		return
	}
	policy, err := routing.NativeTransport(ctx, relation.PeerID)
	if err != nil || policy.Revision != 0 || policy.ConfiguredTransport != relation.Mode ||
		s.nativeTransportReady(ctx, relation, relation.Mode) != nil {
		return
	}
	// CAS leaves any concurrent administrator selection authoritative.
	_, _ = s.ConfirmNativeTransport(ctx, relation.PeerID, relation.Mode, 0, store.NodeAudit{Actor: "paired-transport-bootstrap"})
}

func startedElapsed(started time.Time) int64 { return max(0, time.Since(started).Milliseconds()) }

// Run is joined during shutdown. Control probes have their own small connection
// pool, and no media body ever passes through this scheduler or control client.
func (s *Service) Run(ctx context.Context) {
	if s.volume == nil {
		slog.Error("node control volume is not configured")
		return
	}
	release, err := s.volume.ControlLease(ctx)
	if err != nil {
		if ctx.Err() == nil {
			slog.Error("node control lease unavailable")
		}
		return
	}
	defer release()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return
		}
		relations, err := s.repo.Relationships(ctx, true)
		if err != nil {
			slog.Warn("node control state unavailable")
		} else {
			slots := make(chan struct{}, 4)
			var workers sync.WaitGroup
			for _, relation := range relations {
				select {
				case slots <- struct{}{}:
				case <-ctx.Done():
					workers.Wait()
					return
				}
				workers.Go(func() {
					defer func() { <-slots }()
					probe, cancel := context.WithTimeout(ctx, 15*time.Second)
					defer cancel()
					if err := s.Tick(probe, relation); err != nil && ctx.Err() == nil {
						slog.Warn("node control probe failed", "relationship_id", relation.ID)
					}
				})
			}
			workers.Wait()
		}
		if s.masterResourceReady != nil {
			probe, cancel := context.WithTimeout(ctx, 8*time.Second)
			_ = s.PrepareMasterResourcePolicy(probe)
			cancel()
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-s.wakeup:
		}
	}
}
