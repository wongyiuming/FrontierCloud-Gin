package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/logarchive"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
)

const logBlobPath = "/api/v1/media/log-archive/blob"

type logRemote struct {
	node     *node.Service
	audience string
}

func (r *logRemote) Store(ctx context.Context, t logarchive.Target, ref logarchive.Reference, p []byte, expires int64) error {
	_, e := r.node.LogArchiveCall(ctx, t, map[string]any{"action": "put", "reference": ref, "payload": p, "expires": expires})
	return e
}
func (r *logRemote) Pull(ctx context.Context, target, source logarchive.Target, ref logarchive.Reference, expires int64) error {
	grant, e := r.node.LogReadGrant(ctx, source, ref, target.Origin)
	if e != nil {
		return e
	}
	_, e = r.node.LogArchiveCall(ctx, target, map[string]any{"action": "pull", "reference": ref, "source_origin": source.Origin, "grant": grant, "expires": expires, "audience": target.Origin})
	return e
}
func (r *logRemote) Verify(ctx context.Context, t logarchive.Target, ref logarchive.Reference) error {
	_, e := r.node.LogArchiveCall(ctx, t, map[string]any{"action": "verify", "reference": ref})
	return e
}
func (r *logRemote) Release(ctx context.Context, t logarchive.Target, ref logarchive.Reference, expired bool) error {
	_, e := r.node.LogArchiveCall(ctx, t, map[string]any{"action": "release", "reference": ref, "expired": expired})
	return e
}

func fetchLogCiphertext(ctx context.Context, origin, audience string, grant node.Envelope, ref logarchive.Reference) ([]byte, error) {
	if node.MasterOriginInvalid(origin) || node.MasterOriginInvalid(audience) || !ref.Valid() {
		return nil, logarchive.ErrPolicy
	}
	raw, e := json.Marshal(grant)
	if e != nil {
		return nil, e
	}
	req, e := http.NewRequestWithContext(ctx, "POST", origin+logBlobPath, bytes.NewReader(raw))
	if e != nil {
		return nil, e
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", audience)
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	transport := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
		return dialer.DialContext(ctx, "tcp4", address)
	}, TLSHandshakeTimeout: 3 * time.Second, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, e := client.Do(req)
	if e != nil {
		return nil, e
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return nil, logarchive.ErrBlock
	}
	p, e := io.ReadAll(io.LimitReader(response.Body, int64(ref.Bytes)+1))
	if e != nil || len(p) != ref.Bytes {
		return nil, logarchive.ErrBlock
	}
	sum := sha256.Sum256(p)
	if hex.EncodeToString(sum[:]) != ref.SHA256 {
		return nil, logarchive.ErrBlock
	}
	return p, nil
}

// PullLogForMaster is used only by the explicit local operator read command.
// It returns ciphertext; the archive node receives no decryption key.
func PullLogForMaster(ctx context.Context, service *node.Service, target logarchive.Target, ref logarchive.Reference, audience string) ([]byte, error) {
	grant, e := service.LogReadGrant(ctx, target, ref, audience)
	if e != nil {
		return nil, e
	}
	return fetchLogCiphertext(ctx, target.Origin, audience, grant, ref)
}

// RegisterLogReplica adds only ciphertext storage to an existing resource node.
// Anonymous requests cannot initialize the namespace or obtain decrypt keys.
func RegisterLogReplica(router *gin.Engine, settings config.Config, resolver *network.Resolver, service *node.Service) func() error {
	var mu sync.Mutex
	var replica *logarchive.Replica
	ctx, stop := context.WithCancel(context.Background())
	var worker sync.WaitGroup
	worker.Add(1)
	go func() {
		defer worker.Done()
		timer := time.NewTicker(30 * time.Second)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				if !service.BusinessTraffic().CanRun {
					continue
				}
				mu.Lock()
				r := replica
				mu.Unlock()
				if r != nil {
					deadline, cancel := context.WithTimeout(ctx, time.Second)
					_ = r.Expire(deadline, time.Now())
					cancel()
				}
			}
		}
	}()
	get := func() (*logarchive.Replica, error) {
		mu.Lock()
		defer mu.Unlock()
		if replica != nil {
			return replica, nil
		}
		v, e := logarchive.OpenReplica(settings.DataRoot)
		if e == nil {
			replica = v
		}
		return v, e
	}
	service.ConfigureLogArchiveProtection(func(ctx context.Context, master string) bool {
		_, e := os.Lstat(filepath.Join(settings.DataRoot, ".log-archive", "replicas.sqlite"))
		if os.IsNotExist(e) {
			return false
		}
		if e != nil {
			return true
		}
		r, e := get()
		return e != nil || r.HasActive(ctx, master)
	})
	router.OPTIONS(logBlobPath, func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		if node.MasterOriginInvalid(origin) {
			c.Status(403)
			return
		}
		c.Header("Access-Control-Allow-Origin", origin)
		c.Header("Vary", "Origin")
		c.Header("Access-Control-Allow-Methods", "POST, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type")
		c.Header("Access-Control-Max-Age", "60")
		c.Status(204)
	})
	router.POST(logBlobPath, func(c *gin.Context) {
		if !nodeHTTPS(c, settings, resolver) {
			return
		}
		body, ok := nodeBody(c)
		if !ok {
			return
		}
		var grant node.Envelope
		if controlJSON(body, &grant) != nil {
			detail(c, 400, "Invalid log read grant")
			return
		}
		master, ref, e := service.VerifyLogReadGrant(c.Request.Context(), grant, c.GetHeader("Origin"))
		if e != nil {
			detail(c, 403, "Log read grant expired or unavailable")
			return
		}
		c.Header("Access-Control-Allow-Origin", c.GetHeader("Origin"))
		c.Header("Vary", "Origin")
		noStore(c)
		store, e := get()
		if e != nil {
			detail(c, 503, "Log archive storage unavailable")
			return
		}
		p, e := store.Read(c.Request.Context(), master, ref, time.Now())
		if e != nil {
			detail(c, 404, "Log archive block unavailable")
			return
		}
		c.Header("Access-Control-Allow-Origin", c.GetHeader("Origin"))
		c.Header("Vary", "Origin")
		noStore(c)
		c.Data(200, "application/octet-stream", p)
	})
	router.POST("/internal/v1/log-archive", func(c *gin.Context) {
		if !nodeHTTPS(c, settings, resolver) {
			return
		}
		body, ok := nodeBody(c)
		if !ok {
			return
		}
		rel, e := service.Authenticate(c.Request.Context(), c.Request.Header, "POST", "/internal/v1/log-archive", body, false, false)
		if e != nil || rel.Direction != "upstream" {
			detail(c, 403, "Invalid log archive authority")
			return
		}
		identity, e := service.IdentityState(c.Request.Context())
		if e != nil || identity.Role != "Follower" {
			detail(c, 403, "Log archive requires a resource node")
			return
		}
		var value struct {
			Action    string               `json:"action"`
			Reference logarchive.Reference `json:"reference"`
			Payload   []byte               `json:"payload"`
			Expires   int64                `json:"expires"`
			Source    string               `json:"source_origin"`
			Grant     node.Envelope        `json:"grant"`
			Audience  string               `json:"audience"`
			Expired   bool                 `json:"expired"`
		}
		decoder := json.NewDecoder(strings.NewReader(string(body)))
		decoder.UseNumber()
		decoder.DisallowUnknownFields()
		if decoder.Decode(&value) != nil || decoder.Decode(new(any)) != io.EOF {
			detail(c, 400, "Invalid log archive request")
			return
		}
		store, e := get()
		if e != nil {
			detail(c, 503, "Log archive storage unavailable")
			return
		}
		if value.Action == "probe" {
			c.JSON(200, gin.H{"node_id": identity.ID, "protocol": "log-archive-v1", "capture_ready": service.LogCaptureReady() && logarchive.CollectorReady()})
			return
		}
		if !value.Reference.Valid() {
			detail(c, 400, "Invalid log block identity")
			return
		}
		// Data work follows the node's existing traffic gate. Expiry/release is
		// also queued rather than forced through busy foreground traffic.
		if !service.BusinessTraffic().CanRun {
			detail(c, 409, "Log archive waits for idle traffic")
			return
		}
		switch value.Action {
		case "put":
			e = store.Put(c.Request.Context(), rel.PeerID, value.Reference, value.Payload, value.Expires, time.Now())
		case "pull":
			var p []byte
			p, e = fetchLogCiphertext(c.Request.Context(), value.Source, value.Audience, value.Grant, value.Reference)
			if e == nil {
				e = store.Put(c.Request.Context(), rel.PeerID, value.Reference, p, value.Expires, time.Now())
			}
		case "verify":
			_, e = store.Read(c.Request.Context(), rel.PeerID, value.Reference, time.Now())
		case "release":
			e = store.Release(c.Request.Context(), rel.PeerID, value.Reference, value.Expired, time.Now())
		default:
			e = errors.New("unsupported archive operation")
		}
		if e != nil {
			detail(c, 409, "Log archive operation incomplete; source retained")
			return
		}
		c.JSON(200, gin.H{"id": value.Reference.ID, "sha256": value.Reference.SHA256, "bytes": value.Reference.Bytes})
	})
	return func() error {
		stop()
		worker.Wait()
		mu.Lock()
		defer mu.Unlock()
		if replica != nil {
			return replica.Close()
		}
		return nil
	}
}
