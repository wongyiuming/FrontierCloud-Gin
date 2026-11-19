package httpapi

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/admin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

const handoffCookieName = "__Host-frontiercloud-admin-flow"

func (a *Admin) handoffBinding(c *gin.Context) (admin.HandoffBinding, store.PublicIngressLease, bool) {
	if !a.settings.TLSEnabled || a.public == nil || a.public.control == nil || a.public.media == nil {
		detail(c, http.StatusServiceUnavailable, "认证交接不可用")
		return admin.HandoffBinding{}, nil, false
	}
	adminOrigin, err := node.Endpoint(a.settings.AdminOrigin)
	if err != nil || adminOrigin != a.settings.AdminOrigin {
		detail(c, http.StatusServiceUnavailable, "认证交接不可用")
		return admin.HandoffBinding{}, nil, false
	}
	identity, err := a.public.media.IdentityState(c.Request.Context())
	if err != nil || identity.Role != "Master" {
		detail(c, http.StatusServiceUnavailable, "认证交接不可用")
		return admin.HandoffBinding{}, nil, false
	}
	current, lease, err := a.public.control.AcquireCurrentIngress(c.Request.Context())
	if err != nil || lease == nil {
		if lease != nil {
			lease.Release()
		}
		detail(c, http.StatusServiceUnavailable, "认证交接不可用")
		return admin.HandoffBinding{}, nil, false
	}
	return admin.HandoffBinding{AdminOrigin: adminOrigin, PublicOrigin: current.PublicOrigin, IngressID: current.NodeID, Generation: current.Generation}, lease, true
}

func (a *Admin) directManagementOrigin(c *gin.Context) bool {
	if _, peer := network.AuthenticatedIngressFromContext(c.Request.Context()); peer {
		return false
	}
	u, err := url.Parse(a.settings.AdminOrigin)
	secure := c.Request.TLS != nil
	if !secure && a.handoffNetwork != nil {
		identity := a.handoffNetwork.Resolve(c.Request)
		secure = identity.FromTrustedProxy && a.handoffNetwork.SecureAdmin(c.Request)
	}
	return err == nil && u.Scheme == "https" && strings.EqualFold(c.Request.Host, u.Host) && secure
}

func sameOriginPost(c *gin.Context, expected string) bool {
	origins := c.Request.Header.Values("Origin")
	sites := c.Request.Header.Values("Sec-Fetch-Site")
	return len(origins) == 1 && origins[0] == expected && len(sites) <= 1 && (len(sites) == 0 || sites[0] == "same-origin")
}

// This page is opened directly on the configured Master management origin.
// Its cookie never leaves that origin; the random challenge is sent only to
// the origin selected by the Master, and the returned ticket is origin checked.
func (a *Admin) handoffStart(c *gin.Context) {
	noStore(c)
	c.Header("Referrer-Policy", "no-referrer")
	if !a.directManagementOrigin(c) {
		detail(c, http.StatusForbidden, "认证交接不可用")
		return
	}
	binding, lease, ok := a.handoffBinding(c)
	if !ok {
		return
	}
	defer lease.Release()
	cookie, challenge, err := a.auth.BeginHandoff(c.Request.Context(), binding, a.info(c))
	if err != nil {
		authError(c, err)
		return
	}
	if c.Request.Context().Err() != nil || lease.Commit() != nil || c.Request.Context().Err() != nil {
		a.auth.CancelHandoffFlow(challenge)
		detail(c, http.StatusServiceUnavailable, "认证交接不可用")
		return
	}
	http.SetCookie(c.Writer, &http.Cookie{Name: handoffCookieName, Value: cookie, Path: "/", MaxAge: 60, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	page := `<!doctype html><meta charset="utf-8"><title>管理身份验证</title><body><p id="status">正在等待认证结果…</p><script>
const publicOrigin = ` + jsonString(binding.PublicOrigin) + `;
const challenge = ` + jsonString(challenge) + `;
const statusEl = document.getElementById('status');
let busy = false;
if (!window.opener) { statusEl.textContent = '请从公共首页重新发起认证。'; }
else {
  window.addEventListener('message', async event => {
    if (busy || event.origin !== publicOrigin || event.source !== window.opener || !event.data || event.data.type !== 'frontiercloud-admin-ticket' || event.data.challenge !== challenge || typeof event.data.ticket !== 'string') return;
    busy = true;
    try {
      const result = await fetch('/api/v1/media/admin/handoff/redeem', {method:'POST', credentials:'same-origin', cache:'no-store', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ticket:event.data.ticket})});
      if (!result.ok) throw new Error('rejected');
      window.location.replace('/api/v1/media/admin');
    } catch (_) { statusEl.textContent = '认证交接失败，请从公共首页重新发起。'; }
  });
  window.opener.postMessage({type:'frontiercloud-admin-flow', challenge}, publicOrigin);
}
</script></body>`
	serveTrustedHTML(c, page, false)
}

// Authorize only accepts the authenticated current-ingress context installed
// by the peer verifier while it owns the authoritative lease.
func (a *Admin) handoffAuthorize(c *gin.Context) {
	noStore(c)
	assertion, ok := network.AuthenticatedIngressFromContext(c.Request.Context())
	if !ok || a.public == nil || a.public.media == nil || !a.settings.TLSEnabled || !sameOriginPost(c, assertion.PublicOrigin) {
		detail(c, http.StatusForbidden, "认证交接不可用")
		return
	}
	identity, err := a.public.media.IdentityState(c.Request.Context())
	adminOrigin, originErr := node.Endpoint(a.settings.AdminOrigin)
	if err != nil || identity.Role != "Master" || originErr != nil || adminOrigin != a.settings.AdminOrigin {
		detail(c, http.StatusServiceUnavailable, "认证交接不可用")
		return
	}
	var request struct {
		Challenge string `json:"challenge"`
		Key       string `json:"key"`
	}
	if !smallStrictJSON(c, &request) {
		detail(c, http.StatusBadRequest, "认证交接无效")
		return
	}
	binding := admin.HandoffBinding{AdminOrigin: adminOrigin, PublicOrigin: assertion.PublicOrigin, IngressID: assertion.NodeID, Generation: assertion.Generation}
	ticket, err := a.auth.AuthorizeHandoff(c.Request.Context(), binding, request.Challenge, request.Key, a.info(c))
	if err != nil {
		authError(c, err)
		return
	}
	present, registered := network.RegisterPublicAdmissionAbort(c.Request.Context(), func() { a.auth.CancelHandoff(ticket) })
	if !present || !registered {
		a.auth.CancelHandoff(ticket)
		detail(c, http.StatusServiceUnavailable, "认证交接不可用")
		return
	}
	c.JSON(http.StatusOK, gin.H{"ticket": ticket})
}

func (a *Admin) handoffRedeem(c *gin.Context) {
	noStore(c)
	if !a.directManagementOrigin(c) || !sameOriginPost(c, a.settings.AdminOrigin) {
		detail(c, http.StatusForbidden, "认证交接不可用")
		return
	}
	var request struct {
		Ticket string `json:"ticket"`
	}
	if !smallStrictJSON(c, &request) {
		detail(c, http.StatusBadRequest, "认证交接无效")
		return
	}
	var cookie string
	count := 0
	for _, item := range c.Request.Cookies() {
		if item.Name == handoffCookieName {
			cookie = item.Value
			count++
		}
	}
	if count != 1 {
		detail(c, http.StatusForbidden, "认证交接无效")
		return
	}
	binding, lease, ok := a.handoffBinding(c)
	if !ok {
		return
	}
	defer lease.Release()
	a.redeemHandoffWithLease(c, binding, lease, request.Ticket, cookie)
}

func (a *Admin) redeemHandoffWithLease(c *gin.Context, binding admin.HandoffBinding, lease store.PublicIngressLease, ticket, cookie string) {
	session, err := a.auth.RedeemHandoff(c.Request.Context(), binding, ticket, cookie)
	if err != nil {
		authError(c, err)
		return
	}
	// Consuming and validating the ticket happens while the selection fence is
	// still held. Commit is the admission point; a failed/ambiguous commit
	// revokes the unpublished session rather than emitting its cookie.
	if c.Request.Context().Err() != nil || lease.Commit() != nil || c.Request.Context().Err() != nil {
		a.auth.CancelRedeemedHandoff(session)
		detail(c, http.StatusServiceUnavailable, "认证交接不可用")
		return
	}
	a.cookies(c, session)
	http.SetCookie(c.Writer, &http.Cookie{Name: handoffCookieName, Path: "/", MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}
