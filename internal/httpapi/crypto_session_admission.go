package httpapi

import (
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
)

const cryptoSessionCreationWindow = time.Minute
const cryptoSessionIPCreations = 64
const cryptoSessionCookieCreations = 8
const cryptoSessionAdmissionEntries = 8192

type cryptoCreationWindow struct {
	count int
	until time.Time
}

// This is public-handshake admission only. Range/key requests consume no new
// window, and Admin handshakes do not use this public cache.
type cryptoSessionAdmission struct {
	mu      sync.Mutex
	windows map[string]cryptoCreationWindow
	now     func() time.Time
}

func (a *cryptoSessionAdmission) allow(ip, binding string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	if a.now != nil {
		now = a.now()
	}
	if a.windows == nil {
		a.windows = make(map[string]cryptoCreationWindow)
	}
	for key, window := range a.windows {
		if !window.until.After(now) {
			delete(a.windows, key)
		}
	}
	keys := [2]string{"ip:" + ip, "cookie:" + binding}
	limits := [2]int{cryptoSessionIPCreations, cryptoSessionCookieCreations}
	needed := 0
	for i, key := range keys {
		window, exists := a.windows[key]
		if exists && window.count >= limits[i] {
			return false
		}
		if !exists {
			needed++
		}
	}
	if len(a.windows)+needed > cryptoSessionAdmissionEntries {
		return false
	}
	for _, key := range keys {
		window, exists := a.windows[key]
		if !exists {
			window.until = now.Add(cryptoSessionCreationWindow)
		}
		window.count++
		a.windows[key] = window
	}
	return true
}

func (p *Public) allowPublicCryptoSession(c *gin.Context, binding string) bool {
	resolver, err := network.New(p.settings.TrustedProxyNetworks)
	if err != nil {
		internalError(c, err)
		return false
	}
	// Resolve uses forwarded addresses only for configured trusted proxies;
	// neither a raw client header nor an arbitrary cookie is an IP identity.
	ip := resolver.Resolve(c.Request).IP
	if ip == "" || binding == "" || !p.cryptoSessionLimit.allow(ip, binding) {
		noStore(c)
		c.Header("Retry-After", strconv.Itoa(int(cryptoSessionCreationWindow/time.Second)))
		detail(c, http.StatusTooManyRequests, "临时密钥会话创建过于频繁，请稍后重试")
		return false
	}
	return true
}
