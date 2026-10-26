package s3store

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func (c *Client) doGrant(ctx context.Context, method string, grant Grant, payload []byte, headers http.Header) (*http.Response, error) {
	if len(payload) > 1024 {
		return nil, ErrConfig
	}
	request, err := http.NewRequestWithContext(ctx, method, grant.URL, bytes.NewReader(payload))
	if err != nil {
		return nil, ErrConfig
	}
	for name, value := range grant.Headers {
		if strings.EqualFold(name, "Content-Length") {
			if method == http.MethodPut && value != strconv.Itoa(len(payload)) {
				return nil, ErrConfig
			}
			continue // Go and browsers set this from the fixed payload length.
		}
		request.Header.Set(name, value)
	}
	for name, values := range headers {
		for _, value := range values {
			request.Header.Add(name, value)
		}
	}
	response, err := c.http.Do(request)
	if err != nil {
		return nil, ErrNetwork
	}
	return response, nil
}

func headerTokens(value string) map[string]bool {
	result := make(map[string]bool)
	for _, token := range strings.Split(value, ",") {
		result[strings.ToLower(strings.TrimSpace(token))] = true
	}
	return result
}

func originAllowed(header http.Header, origin string) bool {
	return header.Get("Access-Control-Allow-Origin") == origin || header.Get("Access-Control-Allow-Origin") == "*"
}

func headersExposed(header http.Header, names ...string) bool {
	exposed := headerTokens(header.Get("Access-Control-Expose-Headers"))
	for _, name := range names {
		if !exposed[name] && !exposed["*"] {
			return false
		}
	}
	return true
}

func (c *Client) preflight(ctx context.Context, raw, origin, method string, requested []string) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodOptions, raw, nil)
	if err != nil {
		return ErrCORS
	}
	request.Header.Set("Origin", origin)
	request.Header.Set("Access-Control-Request-Method", method)
	request.Header.Set("Access-Control-Request-Headers", strings.Join(requested, ","))
	response, err := c.http.Do(request)
	if err != nil {
		return ErrCORS
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 || !originAllowed(response.Header, origin) {
		return ErrCORS
	}
	methods, headers := headerTokens(response.Header.Get("Access-Control-Allow-Methods")), headerTokens(response.Header.Get("Access-Control-Allow-Headers"))
	if !methods[strings.ToLower(method)] {
		return ErrCORS
	}
	for _, name := range requested {
		if !headers[name] && !headers["*"] {
			return ErrCORS
		}
	}
	return nil
}

// Test performs actual signed small-object operations. A single-part multipart
// is intentional: the control plane probe is <=1KiB; the browser/provider gate
// separately proves real 8MiB multi-part uploads. It never reports HeadBucket
// or bucket CORS configuration alone as proof of these capabilities.
func (c *Client) Test(ctx context.Context, origin string) (report TestReport, result error) {
	report.NoMutation = true
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return report, ErrNetwork
	}
	return c.TestKey(ctx, origin, "probes/"+hex.EncodeToString(nonce))
}

// TestKey must follow a service-side durable probe intent. Metadata binds the
// object to that same planned key, so recovery does not need a lost in-memory
// nonce to distinguish its own probe from foreign material.
func (c *Client) TestKey(ctx context.Context, origin, relativeProbeKey string) (report TestReport, result error) {
	return c.testKey(ctx, origin, relativeProbeKey, nil)
}

// TestKeyWithCheckpoint is the production probe entry point. A nil journal
// callback is rejected before Create; TestKey remains a fixture convenience.
func (c *Client) TestKeyWithCheckpoint(ctx context.Context, origin, relativeProbeKey string, checkpoint func(string) error) (TestReport, error) {
	if checkpoint == nil {
		return TestReport{ProbeKey: relativeProbeKey, NoMutation: true}, ErrConfig
	}
	return c.testKey(ctx, origin, relativeProbeKey, checkpoint)
}

func (c *Client) testKey(ctx context.Context, origin, relativeProbeKey string, checkpoint func(string) error) (report TestReport, result error) {
	report.NoMutation = true
	report.ProbeKey = relativeProbeKey
	origin, err := normalizeEndpoint(origin)
	if err != nil {
		return report, ErrConfig
	}
	if !strings.HasPrefix(relativeProbeKey, "probes/") {
		return report, ErrConfig
	}
	if _, err = c.key(relativeProbeKey); err != nil {
		return report, err
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	metadata := map[string]string{"fc-probe": relativeProbeKey}
	report.NoMutation = false // Entering Create may mutate, including lost responses.
	report.UploadID, err = c.CreateMultipart(ctx, report.ProbeKey, metadata)
	if err != nil {
		report.Code = boundedCode(err)
		report.CleanupUncertain = IsUncertain(err)
		// Explicit rejections (for example AccessDenied) and local validation
		// failures prove Create did not succeed. Do not turn a wrong credential
		// into an unrecoverable unknown-create journal with no upload ID.
		report.NoMutation = !report.CleanupUncertain
		return report, err
	}
	completionAttempted, completed, deletionAttempted := false, false, false
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if completed {
			if !report.Delete && !deletionAttempted {
				deletionAttempted = true
				err := c.Delete(cleanup, report.ProbeKey, report.VersionID, report.ETag)
				if err != nil {
					report.CleanupUncertain = true
				} else {
					report.Delete = true
				}
			}
			if report.Delete {
				_, err := c.Head(cleanup, report.ProbeKey, report.VersionID)
				report.Cleanup = errors.Is(err, ErrNotFound)
			}
		} else {
			err := c.Abort(cleanup, report.ProbeKey, report.UploadID)
			if err == nil || errors.Is(err, ErrNotFound) {
				_, err = c.ListParts(cleanup, report.ProbeKey, report.UploadID)
				report.Cleanup = !completionAttempted && errors.Is(err, ErrNotFound)
			}
		}
		if !report.Cleanup {
			report.CleanupUncertain = true
			if result == nil {
				result = &OperationError{Code: ErrIncomplete, Uncertain: true}
			}
		}
		if result != nil {
			report.Code = boundedCode(result)
		}
	}()
	if checkpoint != nil && checkpoint(report.UploadID) != nil {
		// Do not retain an arbitrary journal error, which may contain private
		// storage diagnostics. The known UID and cleanup facts remain available.
		return report, ErrIncomplete
	}
	payload := bytes.Repeat([]byte("frontiercloud-s3-probe;"), 24) // 528 bytes.
	digest := sha256.Sum256(payload)
	checksum := base64.StdEncoding.EncodeToString(digest[:])
	grant, err := c.PresignPart(ctx, report.ProbeKey, report.UploadID, 1, int64(len(payload)), checksum, time.Minute)
	if err != nil {
		return report, err
	}
	requested := []string{"x-amz-checksum-sha256"}
	for name := range grant.Headers {
		name = strings.ToLower(name)
		if name != "content-length" && name != "x-amz-checksum-sha256" {
			requested = append(requested, name)
		}
	}
	if err = c.preflight(ctx, grant.URL, origin, http.MethodPut, requested); err != nil {
		return report, err
	}
	uploaded, err := c.doGrant(ctx, http.MethodPut, grant, payload, http.Header{"Origin": {origin}})
	if err != nil {
		return report, err
	}
	etag := uploaded.Header.Get("ETag")
	uploaded.Body.Close()
	if uploaded.StatusCode != http.StatusOK || !validETag(etag) || uploaded.Header.Get("X-Amz-Checksum-Sha256") != checksum || !originAllowed(uploaded.Header, origin) {
		return report, ErrResponse
	}
	if !headersExposed(uploaded.Header, "etag", "x-amz-checksum-sha256") {
		return report, ErrCORS
	}
	report.Write = true
	parts, err := c.ListParts(ctx, report.ProbeKey, report.UploadID)
	if err != nil || len(parts) != 1 || parts[0].ETag != etag || parts[0].Size != int64(len(payload)) || parts[0].SHA256 != checksum {
		if err == nil {
			err = ErrResponse
		}
		return report, err
	}
	completionAttempted = true
	proof, err := c.Complete(ctx, report.ProbeKey, report.UploadID, parts)
	if err != nil {
		return report, err
	}
	if len(proof.Metadata) != 1 || proof.Metadata["fc-probe"] != relativeProbeKey {
		return report, ErrResponse
	}
	completed = true
	report.VersionID, report.ETag = proof.VersionID, proof.ETag
	report.Multipart = true
	head, err := c.PresignHead(ctx, report.ProbeKey, proof.VersionID, proof.ETag, time.Minute)
	if err != nil {
		return report, err
	}
	headHeaders := make([]string, 0, len(head.Headers))
	for name := range head.Headers {
		if !strings.EqualFold(name, "Content-Length") {
			headHeaders = append(headHeaders, strings.ToLower(name))
		}
	}
	if err = c.preflight(ctx, head.URL, origin, http.MethodHead, headHeaders); err != nil {
		return report, err
	}
	headed, err := c.doGrant(ctx, http.MethodHead, head, nil, http.Header{"Origin": {origin}})
	if err != nil {
		return report, err
	}
	headed.Body.Close()
	if headed.StatusCode != http.StatusOK || headed.ContentLength != proof.Size || headed.Header.Get("ETag") != proof.ETag || headed.Header.Get("X-Amz-Checksum-Sha256") != proof.ChecksumSHA256 || !originAllowed(headed.Header, origin) {
		return report, ErrResponse
	}
	if !headersExposed(headed.Header, "etag", "x-amz-checksum-sha256", "x-amz-checksum-type") || proof.VersionID != "" && !headersExposed(headed.Header, "x-amz-version-id") {
		return report, ErrCORS
	}
	report.Head = true
	read, err := c.PresignGet(ctx, report.ProbeKey, proof.VersionID, proof.ETag, "", time.Minute)
	if err != nil {
		return report, err
	}
	if err = c.preflight(ctx, read.URL, origin, http.MethodGet, []string{"if-match", "range"}); err != nil {
		return report, err
	}
	response, err := c.doGrant(ctx, http.MethodGet, read, nil, http.Header{"Origin": {origin}, "Range": {"bytes=0-15"}})
	if err != nil {
		return report, err
	}
	body, readErr := io.ReadAll(response.Body)
	response.Body.Close()
	if readErr != nil || response.StatusCode != http.StatusPartialContent || response.Header.Get("Content-Range") != "bytes 0-15/"+strconv.Itoa(len(payload)) || !bytes.Equal(body, payload[:16]) {
		return report, ErrResponse
	}
	if !originAllowed(response.Header, origin) || !headersExposed(response.Header, "etag", "content-range") {
		return report, ErrCORS
	}
	report.Range = true
	response, err = c.doGrant(ctx, http.MethodGet, read, nil, http.Header{"Origin": {origin}})
	if err != nil {
		return report, err
	}
	body, readErr = io.ReadAll(response.Body)
	response.Body.Close()
	if readErr != nil || response.StatusCode != http.StatusOK || !bytes.Equal(body, payload) || !originAllowed(response.Header, origin) {
		return report, ErrResponse
	}
	report.Read = true
	if !headersExposed(response.Header, "etag", "x-amz-checksum-sha256", "x-amz-checksum-type", "content-range") || proof.VersionID != "" && !headersExposed(response.Header, "x-amz-version-id") {
		return report, ErrCORS
	}
	// A bucket that permits anonymous object reads fails the private-store
	// capability gate even if every signed request happened to work.
	unsigned, _ := url.Parse(read.URL)
	unsigned.RawQuery = ""
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, unsigned.String(), nil)
	response, err = c.http.Do(request)
	if err != nil {
		return report, ErrNetwork
	}
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden && response.StatusCode != http.StatusUnauthorized {
		return report, ErrDenied
	}
	report.CORS = true
	deletionAttempted = true
	if err = c.Delete(ctx, report.ProbeKey, proof.VersionID, proof.ETag); err != nil {
		return report, err
	}
	report.Delete = true
	return report, nil
}

func boundedCode(err error) string {
	for _, code := range []error{ErrConfig, ErrCredentials, ErrEndpoint, ErrNetwork, ErrNotFound, ErrDenied, ErrConflict, ErrResponse, ErrChecksum, ErrIncomplete, ErrCORS} {
		if errors.Is(err, code) {
			return code.Error()
		}
	}
	return ErrResponse.Error()
}
