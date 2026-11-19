package publicproxy

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type catalogFixturePrepare func(*http.Request) (PreparedCatalog, error)

func (f catalogFixturePrepare) PrepareCatalog(r *http.Request) (PreparedCatalog, error) {
	return f(r)
}

type catalogFixturePrereq struct{}

func (catalogFixturePrereq) Check(context.Context) error { return nil }

type catalogFixtureCurrent struct {
	*fixtureCurrent
	changeRelationship bool
}

func (c *catalogFixtureCurrent) AcquireCatalogIngress(ctx context.Context, rel store.Relationship, expected store.PublicIngress, check func(context.Context, store.IngressPrerequisite) error) (store.PublicIngress, store.PublicIngressLease, error) {
	if c.changeRelationship || rel.ID != testRelationship || check(ctx, catalogFixturePrereq{}) != nil {
		return store.PublicIngress{}, nil, errors.New("changed")
	}
	current, lease, err := c.AcquireCurrentIngress(ctx)
	if err != nil {
		return current, lease, err
	}
	if current != expected {
		lease.Release()
		return store.PublicIngress{}, nil, errors.New("generation")
	}
	return current, lease, nil
}

func TestPreparedCatalogRequiresOneProofAndFinalCommit(t *testing.T) {
	const master = "https://master.example"
	for _, tc := range []struct {
		name                                                                 string
		scopeFail, relationFail, commitFail, oversized, changedDuringPrepare bool
	}{
		{name: "success"}, {name: "scope", scopeFail: true}, {name: "relationship", relationFail: true}, {name: "commit", commitFail: true}, {name: "oversized", oversized: true}, {name: "changed-during-prepare", changedDuringPrepare: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, _, current := fixtureVerifier(t, master)
			if tc.commitFail {
				current.commitErr = errors.New("commit")
			}
			v.current = &catalogFixtureCurrent{fixtureCurrent: current, changeRelationship: tc.relationFail}
			calls := 0
			releases := 0
			v.catalogPreparer = catalogFixturePrepare(func(r *http.Request) (PreparedCatalog, error) {
				calls++
				if _, ok := network.AuthenticatedIngressFromContext(r.Context()); !ok || network.HasActivePublicAdmission(r.Context()) {
					t.Fatal("preparation context has wrong authority")
				}
				if tc.changedDuringPrepare {
					moved := active()
					moved.Generation++
					current.set(moved, nil)
				}
				body := []byte(`{"entries":["private-result"]}`)
				if tc.oversized {
					body = append([]byte(`{"entries":"`), []byte(strings.Repeat("x", maxBusinessResponse))...)
					body = append(body, []byte(`"}`)...)
				}
				return PreparedCatalog{Body: body, Release: func() { releases++ }, CheckScope: func(context.Context, store.IngressPrerequisite) error {
					if tc.scopeFail {
						return errors.New("changed")
					}
					return nil
				}}, nil
			})
			r := signedFixtureFor(t, master, http.MethodGet, "/api/v1/media/catalog/media?path=music")
			w := httptest.NewRecorder()
			v.Wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("ordinary handler reached") })).ServeHTTP(w, r)
			if releases != 1 {
				t.Fatal("prepared resource lease not released", releases)
			}
			if tc.name == "success" {
				if w.Code != 200 || !strings.Contains(w.Body.String(), "private-result") || w.Header().Get("Cache-Control") != "private, no-store" {
					t.Fatal("missing committed response", w.Code, w.Body.String())
				}
				// The same signed proof can never be prepared a second time.
				replay := httptest.NewRecorder()
				v.Wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("replay reached handler") })).ServeHTTP(replay, r)
				if replay.Code != http.StatusForbidden || calls != 1 {
					t.Fatal("nonce replay accepted", replay.Code, calls)
				}
			} else if w.Code == 200 || strings.Contains(w.Body.String(), "private-result") {
				t.Fatal("failed admission exposed result", w.Code, w.Body.String())
			}
		})
	}
}
