package httpapi

import (
	"encoding/xml"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
)

func TestPublicStandardsUseConfiguredOriginWithPortNotRequestHost(t *testing.T) {
	for _, tls := range []bool{false, true} {
		scheme, portKey, port := "http", "HTTP_PORT", "9080"
		values := map[string]string{"SERVER_NAME": "example.test", "SECURITY_CONTACT": "https://reports.example.test/submit"}
		if tls {
			scheme, portKey, port = "https", "HTTPS_PORT", "8443"
			values["TLS_ENABLED"] = "true"
		}
		values[portKey] = port
		settings, err := config.LoadFrom(func(key string) string { return values[key] })
		if err != nil {
			t.Fatal(err)
		}
		p := &Public{settings: settings}
		router := gin.New()
		p.registerPublicStandards(router)
		origin := scheme + "://example.test:" + port
		for path, expected := range map[string]string{
			"/robots.txt":               origin + "/sitemap.xml",
			"/sitemap.xml":              origin + "/api/v1/media",
			"/.well-known/security.txt": "Canonical: " + origin + "/.well-known/security.txt",
		} {
			w := httptest.NewRecorder()
			r := httptest.NewRequest("GET", path, nil)
			r.Host = "attacker.test:6666"
			router.ServeHTTP(w, r)
			if w.Code != 200 || !strings.Contains(w.Body.String(), expected) || strings.Contains(w.Body.String(), "attacker.test") {
				t.Fatal(path, w.Code, w.Body.String())
			}
		}
	}
}

func TestPublicStandardsDoNotAdvertiseUnknownDynamicPorts(t *testing.T) {
	settings, err := config.LoadFrom(func(key string) string {
		if key == "HTTP_PORT" {
			return "0"
		}
		if key == "SECURITY_CONTACT" {
			return "https://reports.example.test/submit"
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	p := &Public{settings: settings}
	router := gin.New()
	p.registerPublicStandards(router)
	for _, path := range []string{"/robots.txt", "/sitemap.xml", "/.well-known/security.txt"} {
		if w := request(router, "GET", path, ""); w.Code != 503 || strings.Contains(w.Body.String(), "http://localhost") {
			t.Fatal("unknown public port advertised", path, w.Code, w.Body.String())
		}
	}
}

func TestPublicStandardsDoNotEnumeratePrivateResourcesOrTrustHost(t *testing.T) {
	router, _, _, public := publicFixture(t, false)
	public.settings.SecurityContact = "https://reports.example.test/submit"
	for _, target := range []string{"/robots.txt", "/sitemap.xml", "/.well-known/security.txt"} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", target, nil)
		r.Host = "attacker.test"
		router.ServeHTTP(w, r)
		if w.Code != 200 || strings.Contains(w.Body.String(), "attacker.test") || strings.Contains(w.Body.String(), "song.mp3") {
			t.Fatal(target, w.Code, w.Body.String())
		}
	}
	w := request(router, "GET", "/sitemap.xml", "")
	var body struct {
		URLs []struct {
			Location string `xml:"loc"`
		} `xml:"url"`
	}
	if err := xml.Unmarshal(w.Body.Bytes(), &body); err != nil || len(body.URLs) != 3 {
		t.Fatal("invalid public-only sitemap", err, w.Body.String())
	}
	for _, item := range body.URLs {
		if !strings.HasPrefix(item.Location, "http://localhost/api/v1/media") {
			t.Fatal("unexpected canonical URL", item.Location)
		}
	}
	w = request(router, "GET", "/robots.txt", "")
	for _, rule := range []string{"Disallow: /api/", "Disallow: /internal/", "Disallow: /static/media/", "Allow: /api/v1/media$"} {
		if !strings.Contains(w.Body.String(), rule) {
			t.Fatal("crawler privacy rule missing", rule)
		}
	}
	w = request(router, "GET", "/.well-known/security.txt", "")
	for _, line := range strings.Split(w.Body.String(), "\n") {
		if strings.HasPrefix(line, "Expires: ") {
			expires, err := time.Parse(time.RFC3339, strings.TrimPrefix(line, "Expires: "))
			if err != nil || !expires.After(time.Now()) || expires.After(time.Now().Add(31*24*time.Hour)) {
				t.Fatal("invalid RFC 9116 expiry", line)
			}
		}
	}
	if !strings.Contains(w.Body.String(), "Contact: https://reports.example.test/submit\n") || !strings.Contains(w.Header().Get("Cache-Control"), "no-store") {
		t.Fatal("invalid contact response")
	}
	public.settings.SecurityContact = ""
	if w := request(router, "GET", "/.well-known/security.txt", ""); w.Code != 404 {
		t.Fatal("fabricated reporting contact")
	}
}
