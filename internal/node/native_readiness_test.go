package node

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type opaqueProbeFixtureLease struct{}

func (opaqueProbeFixtureLease) Check(ctx context.Context) error { return ctx.Err() }
func (opaqueProbeFixtureLease) Release()                        {}

func enableOpaqueProbeFixture(s *Service) {
	s.ConfigureOpaqueOwnerRequestReadiness(func(context.Context) (IngressPrerequisiteLease, error) {
		return opaqueProbeFixtureLease{}, nil
	})
}

func TestNativeMediaEndpointProbeRequiresVerifiedTLSAndAuthorization(t *testing.T) {
	var status atomic.Int32
	status.Store(http.StatusUnauthorized)
	server, roots := privateCA(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/internal/v1/media/"+"0000000000000000000000000000000000000000000000000000000000000000" || r.Header.Get("X-Media-Capability") != "" {
			t.Error("probe broadened request")
		}
		if status.Load() == http.StatusFound {
			http.Redirect(w, r, "https://untrusted.example/", http.StatusFound)
			return
		}
		w.WriteHeader(int(status.Load()))
		if status.Load() == http.StatusUnauthorized {
			_, _ = w.Write([]byte(`{"detail":"Media capability invalid or expired"}`))
		}
	}))
	trusted := testTransport(t, server, roots)
	if err := trusted.ProbeNativeMediaEndpoint(context.Background(), "https://node.test"); err != nil {
		t.Fatal(err)
	}
	status.Store(http.StatusOK)
	if err := trusted.ProbeNativeMediaEndpoint(context.Background(), "https://node.test"); err == nil {
		t.Fatal("unprotected endpoint accepted")
	}
	status.Store(http.StatusFound)
	if err := trusted.ProbeNativeMediaEndpoint(context.Background(), "https://node.test"); err == nil {
		t.Fatal("redirect accepted")
	}
	status.Store(http.StatusUnauthorized)
	untrusted := testTransport(t, server, x509.NewCertPool())
	if err := untrusted.ProbeNativeMediaEndpoint(context.Background(), "https://node.test"); err == nil {
		t.Fatal("untrusted certificate accepted")
	}
	if err := trusted.ProbeNativeMediaEndpoint(context.Background(), "https://wrong-name.test"); err == nil {
		t.Fatal("wrong hostname accepted")
	}
}

func TestFollowerPlainReadinessRequiresPairedV4ProofAndTLS(t *testing.T) {
	ctx := context.Background()
	transport := &localControl{nodes: map[string]*Service{}}
	master, masterDB := testNode(t, "Master", "https://master.test", transport)
	owner, ownerDB := testNode(t, "Follower", "https://follower.test", transport)
	master.ConfigureVolumes(masterDB.Pool(), &testVolume{}, recordingRoot(t))
	owner.ConfigureVolumes(ownerDB.Pool(), &testVolume{}, recordingRoot(t))
	transport.nodes["https://master.test"], transport.nodes["https://follower.test"] = master, owner
	pair, err := owner.CreatePair(ctx, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	relationID, err := master.ImportPair(ctx, pair, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	relation, err := master.repo.Relationship(ctx, relationID)
	if err != nil {
		t.Fatal(err)
	}
	var broken, redirect, genericIdentity, mediaRedirect, mediaGeneric atomic.Bool
	var reads atomic.Int32
	owner.ConfigurePlainReadProbe(func(context.Context) error {
		reads.Add(1)
		if broken.Load() {
			return errors.New("fixture reader failed")
		}
		return nil
	})
	var opaqueReads atomic.Int32
	owner.ConfigureOpaqueReadProbe(func(context.Context) error {
		opaqueReads.Add(1)
		if broken.Load() {
			return errors.New("fixture opaque reader failed")
		}
		return nil
	})
	enableOpaqueProbeFixture(owner)
	server, roots := privateCA(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/internal/v1/identity" {
			value, err := owner.SignedIdentity(r.Context(), r.URL.Query().Get("challenge"))
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			_ = json.NewEncoder(w).Encode(value)
			return
		}
		if (r.URL.Path == NativePlainMediaProbePath || r.URL.Path == NativeOpaqueMediaProbePath) && r.Method == http.MethodGet {
			if mediaRedirect.Load() {
				http.Redirect(w, r, "https://untrusted.test/", http.StatusFound)
				return
			}
			paired, err := owner.Authenticate(r.Context(), r.Header, r.Method, r.URL.Path, nil, false, false)
			challenge := r.Header.Get("X-Fc-Plain-Probe")
			if r.URL.Path == NativeOpaqueMediaProbePath {
				challenge = r.Header.Get("X-Fc-Opaque-Probe")
			}
			if err != nil || !ValidIdentifier(challenge) {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if mediaGeneric.Load() {
				signed, _ := owner.SignedIdentity(r.Context(), challenge)
				_ = json.NewEncoder(w).Encode(signed)
				return
			}
			var signed Envelope
			if r.URL.Path == NativeOpaqueMediaProbePath {
				signed, err = owner.VerifyOwnedOpaqueMediaProbe(r.Context(), paired, challenge, r.Header.Get("X-Media-Capability"))
			} else {
				signed, err = owner.VerifyOwnedPlainMediaProbe(r.Context(), paired, challenge, r.Header.Get("X-Media-Capability"))
			}
			if err != nil {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			_ = json.NewEncoder(w).Encode(signed)
			return
		}
		if r.URL.Path != NativePlainProbePath || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if redirect.Load() {
			http.Redirect(w, r, "https://untrusted.test/", http.StatusFound)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 4097))
		if err != nil || len(body) > 4096 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		paired, err := owner.Authenticate(r.Context(), r.Header, r.Method, r.URL.Path, body, false, false)
		var request struct{ Challenge, Token string }
		if err != nil || json.Unmarshal(body, &request) != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if genericIdentity.Load() {
			signed, _ := owner.SignedIdentity(r.Context(), request.Challenge)
			_ = json.NewEncoder(w).Encode(signed)
			return
		}
		signed, err := owner.VerifyOwnedPlainProbe(r.Context(), paired, request.Challenge, request.Token)
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(signed)
	}))
	master.transport = testTransport(t, server, roots)
	if err := master.VerifyFollowerPlainReadiness(ctx, relation, "https://node.test"); err != nil || reads.Load() != 2 {
		t.Fatal("paired v4 reader probe", err)
	}
	if err := master.VerifyFollowerOpaqueReadiness(ctx, relation, "https://node.test"); err != nil || opaqueReads.Load() != 1 {
		t.Fatal("paired v5 reader probe", err)
	}
	broken.Store(true)
	if err := master.VerifyFollowerPlainReadiness(ctx, relation, "https://node.test"); err == nil {
		t.Fatal("failed reader was marked ready")
	}
	if err := master.VerifyFollowerOpaqueReadiness(ctx, relation, "https://node.test"); err == nil {
		t.Fatal("failed opaque reader marked ready")
	}
	broken.Store(false)
	genericIdentity.Store(true)
	if err := master.VerifyFollowerPlainReadiness(ctx, relation, "https://node.test"); err == nil {
		t.Fatal("ordinary signed identity was accepted as a reader proof")
	}
	genericIdentity.Store(false)
	redirect.Store(true)
	if err := master.VerifyFollowerPlainReadiness(ctx, relation, "https://node.test"); err == nil {
		t.Fatal("redirected reader probe accepted")
	}
	redirect.Store(false)
	mediaRedirect.Store(true)
	if err := master.VerifyFollowerPlainReadiness(ctx, relation, "https://node.test"); err == nil {
		t.Fatal("redirected actual media path accepted")
	}
	if err := master.VerifyFollowerOpaqueReadiness(ctx, relation, "https://node.test"); err == nil {
		t.Fatal("redirected opaque reader accepted")
	}
	mediaRedirect.Store(false)
	mediaGeneric.Store(true)
	if err := master.VerifyFollowerPlainReadiness(ctx, relation, "https://node.test"); err == nil {
		t.Fatal("ordinary identity was accepted as actual media-path proof")
	}
	if err := master.VerifyFollowerOpaqueReadiness(ctx, relation, "https://node.test"); err == nil {
		t.Fatal("ordinary identity accepted as opaque proof")
	}
	mediaGeneric.Store(false)
	master.transport = testTransport(t, server, x509.NewCertPool())
	if err := master.VerifyFollowerOpaqueReadiness(ctx, relation, "https://node.test"); err == nil {
		t.Fatal("opaque probe accepted untrusted TLS")
	}
	if err := master.VerifyFollowerPlainReadiness(ctx, relation, "https://node.test"); err == nil {
		t.Fatal("untrusted TLS accepted")
	}
	owner.ConfigurePlainReadProbe(nil)
	master.transport = testTransport(t, server, roots)
	owner.ConfigureOpaqueReadProbe(nil)
	if err := master.VerifyFollowerOpaqueReadiness(ctx, relation, "https://node.test"); err == nil {
		t.Fatal("owner without opaque capability accepted")
	}
	if err := master.VerifyFollowerPlainReadiness(ctx, relation, "https://node.test"); err == nil {
		t.Fatal("old owner without v4 capability accepted")
	}
	credential, err := master.identity.vault.Unseal(relation.Credential)
	if err != nil {
		t.Fatal(err)
	}
	probeToken, err := protocol.PlainIngressProbeToken(credential, relation.ID, strings.Repeat("1", 32), relation.PeerID, strings.Repeat("2", 32), time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := owner.VerifyOwnedMedia(ctx, probeToken, strings.Repeat("0", 64)); err == nil {
		t.Fatal("readiness probe token authorized media")
	}
}
