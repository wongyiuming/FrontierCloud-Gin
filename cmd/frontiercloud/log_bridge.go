package main

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"os"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/logarchive"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// Bounded encrypted packets piggyback on the existing authenticated heartbeat.
// A log fault never fails a health probe or changes business reachability.
type projectLogBridge struct {
	master   *logarchive.Runtime
	producer *logarchive.Producer
}

func (b *projectLogBridge) Outgoing(ctx context.Context, rel store.Relationship, packet map[string]any) {
	ctx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	if b.master != nil && rel.Direction == "downstream" {
		if !b.master.Enabled() {
			packet["project_logs"] = map[string]any{"enabled": false}
			return
		}
		public, e := b.master.Catalog.IngestPublic(ctx)
		if e != nil {
			return
		}
		acks, e := b.master.Catalog.IngestReceipts(ctx, rel.PeerID)
		if e != nil {
			return
		}
		packet["project_logs"] = map[string]any{"enabled": true, "public_key": base64.RawStdEncoding.EncodeToString(public), "receipts": acks}
	} else if b.producer != nil && rel.Direction == "upstream" && b.producer.Enabled() {
		values, e := b.producer.Packets(ctx, rel.PeerID)
		if e != nil {
			return
		}
		wire, e := logarchive.ControlValue(values)
		if e != nil {
			return
		}
		packet["project_log_packets"] = wire
		packet["project_log_producer"] = b.producer.PublicWire()
	}
}
func (b *projectLogBridge) Incoming(ctx context.Context, rel store.Relationship, packet map[string]any) {
	ctx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	if b.master != nil && rel.Direction == "downstream" {
		raw, present := packet["project_log_packets"]
		delete(packet, "project_log_packets")
		if !present || !b.master.Enabled() {
			return
		}
		data, e := json.Marshal(raw)
		if e != nil || len(data) > 384<<10 {
			return
		}
		var values []logarchive.IngestPacket
		if json.Unmarshal(data, &values) != nil || len(values) > 16 {
			return
		}
		for _, v := range values {
			b.master.QueueIngest(rel.PeerID, v)
		}
	} else if b.producer != nil && rel.Direction == "upstream" {
		raw, present := packet["project_logs"]
		if !present {
			return
		}
		data, e := json.Marshal(raw)
		if e != nil || len(data) > 4096 {
			return
		}
		var value struct {
			Enabled  bool     `json:"enabled"`
			Public   string   `json:"public_key"`
			Receipts []string `json:"receipts"`
		}
		if json.Unmarshal(data, &value) != nil {
			return
		}
		if !value.Enabled {
			b.producer.ObserveInactive(ctx, rel.PeerID)
			return
		} // Active deployments do not expose a disable UI.
		public, e := base64.RawStdEncoding.DecodeString(value.Public)
		if e != nil {
			return
		}
		_ = b.producer.Configure(ctx, rel.PeerID, public, true, value.Receipts)
	}
}

func configureStorageProjectLogs(settings config.Config, s runtimeHTTP) func() error {
	noop := func() error { return nil }
	db, ok := s.Database.(interface{ Database() *sql.DB })
	if !ok || settings.DatabaseType != config.DatabaseSQLite {
		return noop
	}
	identity, e := s.Control.IdentityState(context.Background())
	if e != nil || identity.Role != "Follower" {
		return noop
	}
	producer, e := logarchive.OpenProducer(db.Database(), identity.ID)
	if e != nil {
		return noop
	}
	s.Control.ConfigureLogHeartbeat(&projectLogBridge{producer: producer})
	if repo, ok := s.Database.Pool().(interface{ ConfigureLogProducer(*logarchive.Producer) }); ok {
		repo.ConfigureLogProducer(producer)
	}
	old := slog.Default().Handler()
	handler := &logarchive.Handler{Runtime: producer, Fallback: old}
	slog.SetDefault(slog.New(handler))
	producer.Start(context.Background())
	closeCollector, e := logarchive.OpenCollector(producer, os.Stdout)
	if e != nil {
		closeCollector = func() error { return nil }
	}
	return func() error {
		e := closeCollector()
		producer.Close()
		if slog.Default().Handler() == handler {
			slog.SetDefault(slog.New(old))
		}
		return e
	}
}
