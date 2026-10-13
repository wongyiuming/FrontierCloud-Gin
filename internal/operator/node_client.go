package operator

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/noderetirement"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"
)

var ErrNodeClient = errors.New("node administration request failed; check TLS, authentication and Master connectivity")
var ErrNodeAuthority = errors.New("expected one active downstream relationship for this member on the selected Master")

const nodeResponseBytes = 16 << 20

type NodeClient struct {
	client *http.Client
	origin *url.URL
	csrf   string
}

func NewNodeClient(master string) (*NodeClient, error) {
	origin, e := url.Parse(master)
	if e != nil || origin.Scheme != "https" || origin.Host == "" || origin.Hostname() == "" || origin.User != nil || origin.RawQuery != "" || origin.Fragment != "" || origin.Opaque != "" || (origin.Path != "" && origin.Path != "/") || origin.RawPath != "" {
		return nil, ErrNodeClient
	}
	jar, e := cookiejar.New(nil)
	if e != nil {
		return nil, ErrNodeClient
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxResponseHeaderBytes = 64 << 10
	transport.MaxIdleConns = 2
	transport.MaxIdleConnsPerHost = 1
	return &NodeClient{origin: origin, client: &http.Client{Jar: jar, Transport: transport, Timeout: 270 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func nodeClientID(value string) bool {
	decoded, e := hex.DecodeString(value)
	return e == nil && len(decoded) == 16 && value == strings.ToLower(value)
}
func (c *NodeClient) request(ctx context.Context, method, path, body, contentType string, target any) (int, error) {
	return c.requestQuery(ctx, method, path, "", body, contentType, target)
}
func (c *NodeClient) requestQuery(ctx context.Context, method, path, query, body, contentType string, target any) (int, error) {
	endpoint := *c.origin
	endpoint.Path = "/api/v1/media/admin" + path
	endpoint.RawQuery = query
	req, e := http.NewRequestWithContext(ctx, method, endpoint.String(), strings.NewReader(body))
	if e != nil {
		return 0, ErrNodeClient
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("X-Admin-Activity", "active")
	if c.csrf != "" {
		req.Header.Set("X-CSRF-Token", c.csrf)
	}
	response, e := c.client.Do(req)
	if e != nil {
		return 0, ErrNodeClient
	}
	defer response.Body.Close()
	if response.StatusCode != 200 && response.StatusCode != 409 {
		return response.StatusCode, ErrNodeClient
	}
	reader := io.LimitReader(response.Body, nodeResponseBytes+1)
	decoder := json.NewDecoder(reader)
	if e = decoder.Decode(target); e != nil {
		return response.StatusCode, ErrNodeClient
	}
	if e = decoder.Decode(new(any)); e != io.EOF || decoder.InputOffset() > nodeResponseBytes {
		return response.StatusCode, ErrNodeClient
	}
	return response.StatusCode, nil
}
func (c *NodeClient) Login(ctx context.Context, credential string) error {
	if len(credential) < 1 || len(credential) > 4096 || strings.ContainsAny(credential, "\r\n\x00") {
		return ErrNodeClient
	}
	var login struct {
		Status string `json:"status"`
	}
	status, e := c.request(ctx, "POST", "/elevate", url.Values{"token": {credential}}.Encode(), "application/x-www-form-urlencoded", &login)
	if e != nil || status != 200 || login.Status != "ok" {
		return ErrNodeClient
	}
	var session struct {
		Session bool   `json:"session"`
		CSRF    string `json:"csrf_cookie_name"`
	}
	status, e = c.request(ctx, "GET", "/status", "", "application/json", &session)
	if e != nil || status != 200 || !session.Session || session.CSRF == "" || len(session.CSRF) > 128 {
		return ErrNodeClient
	}
	for _, cookie := range c.client.Jar.Cookies(c.origin) {
		if cookie.Name == session.CSRF && len(cookie.Value) > 0 && len(cookie.Value) <= 4096 {
			c.csrf = cookie.Value
			return nil
		}
	}
	return ErrNodeClient
}
func (c *NodeClient) Close() {
	if c.csrf != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		var value any
		c.request(ctx, "POST", "/logout", "{}", "application/json", &value)
	}
	c.client.CloseIdleConnections()
}
func (c *NodeClient) RetirementCheck(ctx context.Context, member string) (noderetirement.Report, error) {
	var report noderetirement.Report
	if !nodeClientID(member) || c.csrf == "" {
		return report, ErrNodeAuthority
	}
	var nodes struct {
		Role          string `json:"role"`
		ID            string `json:"node_id"`
		Relationships []struct {
			ID        string `json:"relationship_id"`
			Peer      string `json:"peer_id"`
			Direction string `json:"direction"`
			State     string `json:"state"`
		} `json:"relationships"`
	}
	status, e := c.request(ctx, "GET", "/nodes", "", "application/json", &nodes)
	if e != nil || status != 200 {
		return report, ErrNodeClient
	}
	if nodes.Role != "Master" || nodes.ID == member || !nodeClientID(nodes.ID) {
		return report, ErrNodeAuthority
	}
	relationship := ""
	for _, rel := range nodes.Relationships {
		if rel.Peer == member && rel.Direction == "downstream" && rel.State == "active" {
			if relationship != "" || !nodeClientID(rel.ID) {
				return report, ErrNodeAuthority
			}
			relationship = rel.ID
		}
	}
	if relationship == "" {
		return report, ErrNodeAuthority
	}
	body, _ := json.Marshal(map[string]string{"member_id": member})
	var response json.RawMessage
	status, e = c.request(ctx, "POST", "/nodes/"+relationship+"/retire/check", string(body), "application/json", &response)
	if e != nil {
		return report, e
	}
	if status == 409 {
		var failed struct {
			Report noderetirement.Report `json:"report"`
		}
		if json.Unmarshal(response, &failed) != nil {
			return report, ErrNodeClient
		}
		report = failed.Report
		report.ObservationComplete = false
	} else {
		if json.Unmarshal(response, &report) != nil {
			return report, ErrNodeClient
		}
	}
	if report.MemberID != member || !report.PreflightOnly || len(report.Concerns) > noderetirement.MaxCategories {
		return noderetirement.Report{}, ErrNodeClient
	}
	if len(report.Volumes) > 3 || report.ObservationComplete && len(report.Volumes) != 3 {
		return noderetirement.Report{}, ErrNodeClient
	}
	var entries uint64
	var bytes int64
	for i, volume := range report.Volumes {
		if volume.Scope != []string{"data", "media", "recordings"}[i] || volume.FreeBytes < 0 || volume.TotalBytes < volume.FreeBytes || volume.LogicalBytes < 0 || volume.RetainedEntries > volume.Entries || volume.WritableVerified || i == 0 && volume.InDataRoot || volume.Entries > ^uint64(0)-entries || volume.LogicalBytes > int64(^uint64(0)>>1)-bytes {
			return noderetirement.Report{}, ErrNodeClient
		}
		entries += volume.Entries
		bytes += volume.LogicalBytes
		if report.ObservationComplete && (!clientHash(volume.ObservationSHA256)) {
			return noderetirement.Report{}, ErrNodeClient
		}
	}
	if report.ObservationComplete && (entries != report.PhysicalEntries || bytes != report.LogicalBytes) {
		return noderetirement.Report{}, ErrNodeClient
	}
	for _, concern := range report.Concerns {
		if concern.Count < 1 || len(concern.Code) > 80 || len(concern.Samples) > 8 {
			return noderetirement.Report{}, ErrNodeClient
		}
		for _, sample := range concern.Samples {
			if len(sample) > 4096 {
				return noderetirement.Report{}, ErrNodeClient
			}
		}
	}
	for _, ledger := range []store.RetirementLedger{report.Master, report.Peer} {
		if len(ledger.Blockers) > 32 {
			return noderetirement.Report{}, ErrNodeClient
		}
		for _, block := range ledger.Blockers {
			if block.Count < 1 || len(block.Code) > 80 || len(block.NextStep) > 128 || len(block.SampleIDs) > 8 {
				return noderetirement.Report{}, ErrNodeClient
			}
			for _, id := range block.SampleIDs {
				if len(id) > 128 {
					return noderetirement.Report{}, ErrNodeClient
				}
			}
		}
	}
	if report.ObservationComplete && (report.Master.MemberID != member || report.Peer.MemberID != member || report.Master.RelationshipID != relationship || report.Peer.RelationshipID != relationship || report.Master.Role != "Master" || report.Peer.Role != "Follower") {
		return noderetirement.Report{}, ErrNodeClient
	}
	if !report.ObservationComplete {
		return report, ErrNodeClient
	}
	return report, nil
}

// UseCA adds an explicitly supplied public CA to normal TLS verification.
// There is no insecure transport mode or automatic certificate acceptance.
func (c *NodeClient) UseCA(raw []byte) error {
	if c.csrf != "" || len(raw) == 0 || len(raw) > 1<<20 {
		return ErrNodeClient
	}
	roots, e := x509.SystemCertPool()
	if e != nil {
		roots = x509.NewCertPool()
	}
	if !roots.AppendCertsFromPEM(raw) {
		return ErrNodeClient
	}
	transport := c.client.Transport.(*http.Transport)
	transport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	return nil
}
