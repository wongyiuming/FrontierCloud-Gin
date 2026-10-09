package httpapi

import (
	"encoding/xml"
	"net/url"
	"time"

	"github.com/gin-gonic/gin"
)

func (p *Public) registerPublicStandards(router *gin.Engine) {
	// Explicitly advertise landing pages only, never an inventory of media,
	// recordings, signed capabilities or administrative paths.
	public := []string{"/api/v1/media", "/api/v1/media/music", "/api/v1/media/video"}
	// LoadFrom validates this configured origin, including published ports.
	origin, _ := url.Parse(p.settings.PublicOrigin)
	readyOrigin := func(c *gin.Context) bool {
		if origin == nil || origin.Host == "" {
			detail(c, 503, "PUBLIC_ORIGIN is required after dynamic port allocation")
			return false
		}
		return true
	}
	router.GET("/robots.txt", func(c *gin.Context) {
		if !readyOrigin(c) {
			return
		}
		body := "User-agent: *\nDisallow: /api/\nDisallow: /internal/\nDisallow: /static/media/\nDisallow: /karaoke/\nDisallow: /docs\nDisallow: /redoc\nDisallow: /openapi.json\nDisallow: /metrics\nDisallow: /health\n"
		for _, path := range public {
			body += "Allow: " + path + "$\n"
		}
		canonical := *origin
		canonical.Path = "/sitemap.xml"
		body += "Sitemap: " + canonical.String() + "\n"
		c.Header("Cache-Control", "public, max-age=3600")
		c.Data(200, "text/plain; charset=utf-8", []byte(body))
	})
	router.GET("/sitemap.xml", func(c *gin.Context) {
		if !readyOrigin(c) {
			return
		}
		type entry struct {
			Location string `xml:"loc"`
		}
		body := struct {
			XMLName   xml.Name `xml:"urlset"`
			Namespace string   `xml:"xmlns,attr"`
			Entries   []entry  `xml:"url"`
		}{Namespace: "http://www.sitemaps.org/schemas/sitemap/0.9"}
		for _, path := range public {
			canonical := *origin
			canonical.Path = path
			body.Entries = append(body.Entries, entry{canonical.String()})
		}
		raw, err := xml.Marshal(body)
		if err != nil {
			internalError(c, err)
			return
		}
		c.Header("Cache-Control", "public, max-age=3600")
		c.Data(200, "application/xml; charset=utf-8", append([]byte(xml.Header), raw...))
	})
	router.GET("/.well-known/security.txt", func(c *gin.Context) {
		noStore(c)
		if p.settings.SecurityContact == "" {
			detail(c, 404, "Vulnerability reporting contact is not configured")
			return
		}
		if !readyOrigin(c) {
			return
		}
		canonical := *origin
		canonical.Path = "/.well-known/security.txt"
		body := "Contact: " + p.settings.SecurityContact + "\nExpires: " + time.Now().UTC().Add(30*24*time.Hour).Format(time.RFC3339) + "\nCanonical: " + canonical.String() + "\nPreferred-Languages: zh, en\n"
		c.Data(200, "text/plain; charset=utf-8", []byte(body))
	})
}
