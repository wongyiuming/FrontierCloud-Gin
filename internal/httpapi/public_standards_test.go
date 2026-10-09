package httpapi

import (
	"encoding/xml"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

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
