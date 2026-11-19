package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/publicproxy"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type ingressEdgeControl interface {
	publicproxy.NodeAuthenticator
	publicproxy.CurrentIngress
	IdentityState(context.Context) (store.NodeIdentity, error)
}

// masterIngressProbeOnly is a bounded bootstrap handler for a future
// listen-before-recovery startup. It exposes only the existing authenticated
// candidate challenge; it cannot serve business or admit ingress requests.
// A caller must still gate the listener's transition to normal service on the
// complete Owner/tree and selected-ingress readiness checks.
func masterIngressProbeOnly(control ingressEdgeControl, resolver *network.Resolver) http.Handler {
	denied := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
	})
	edge := masterIngressEdge(denied, control, resolver)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL == nil || r.URL.Path != node.IngressCandidateEdgePath {
			denied.ServeHTTP(w, r)
			return
		}
		edge.ServeHTTP(w, r)
	})
}

// masterIngressEdge is outside the Gin business middleware: the verified
// logical request enters it exactly once, with its authenticated client IP.
func masterIngressEdge(next http.Handler, control ingressEdgeControl, resolver *network.Resolver) http.Handler {
	return masterIngressEdgeWithCatalogPreparer(next, control, resolver, nil)
}

// masterIngressEdgeWithCatalogPreparer installs the same authenticated catalog
// preparer as the Master public handlers. Supplying it does not enable peer
// ingress: the control still owns the selection and final admission fences.
func masterIngressEdgeWithCatalogPreparer(next http.Handler, control ingressEdgeControl, resolver *network.Resolver, preparer publicproxy.CatalogPreparer) http.Handler {
	return masterIngressEdgeWithControls(next, control, resolver, preparer, false)
}

func masterIngressEdgeWithControls(next http.Handler, control ingressEdgeControl, resolver *network.Resolver, preparer publicproxy.CatalogPreparer, recordingControlsReady bool) http.Handler {
	// Reserve independent capacity for key/session admission before touching
	// the node store, so large public responses cannot fill every edge slot.
	businessSlots := make(chan struct{}, 16)
	keySlots := make(chan struct{}, 8)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, publicproxy.EdgePrefix+"/") && r.URL.Path != publicproxy.EdgePrefix {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		if r.URL.RawPath != "" || control == nil || resolver == nil || (r.TLS == nil && (!resolver.Resolve(r).FromTrustedProxy || !resolver.SecureAdmin(r))) {
			publicproxy.LogMasterIngressEdgeRejection()
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		slots := businessSlots
		switch r.URL.Path {
		case publicproxy.EdgePrefix + "/api/v1/media/crypto/session", publicproxy.EdgePrefix + "/api/v1/media/crypto/key", publicproxy.EdgePrefix + "/api/v1/media/crypto/native/source", publicproxy.EdgePrefix + "/api/v1/media/crypto/revoke", publicproxy.EdgePrefix + "/api/v1/media/admin-handoff/authorize":
			slots = keySlots
		}
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
			return
		}
		identity, err := control.IdentityState(r.Context())
		if err != nil || identity.Role != "Master" {
			http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
			return
		}
		if r.URL.Path == node.IngressCandidateEdgePath {
			probe, ok := control.(interface {
				VerifyCandidateEdge(context.Context, http.Header, []byte) (node.Envelope, error)
			})
			if !ok || r.Method != http.MethodPost || r.URL.RawQuery != "" || r.URL.ForceQuery {
				http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
				return
			}
			body, readErr := io.ReadAll(io.LimitReader(r.Body, 1025))
			if readErr != nil || len(body) == 0 || len(body) > 1024 {
				http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
				return
			}
			result, probeErr := probe.VerifyCandidateEdge(r.Context(), r.Header, body)
			if probeErr != nil {
				http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(result)
			return
		}
		verifier, err := publicproxy.NewVerifier(publicproxy.VerifierConfig{MasterOrigin: identity.Endpoint, Authenticator: control, Current: control, EdgeResolver: resolver, CatalogPreparer: preparer, RecordingControlsReady: recordingControlsReady})
		if err != nil {
			http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
			return
		}
		http.StripPrefix(publicproxy.EdgePrefix, verifier.Wrap(next)).ServeHTTP(w, r)
	})
}
