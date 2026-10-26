package s3store

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeObject struct {
	payload        []byte
	metadata       map[string]string
	etag, checksum string
	size           int64
}
type fakeS3 struct {
	mu              sync.Mutex
	server          *httptest.Server
	objects         map[string]fakeObject
	uploads         map[string]fakeObject
	parts           map[string][]Part
	mode            string
	requests        map[string]int
	badSignatures   int
	resolved        int
	dials           []string
	createdKey      string
	createdMetadata map[string]string
	client          *Client
}

func hmac256(key []byte, value string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(value))
	return h.Sum(nil)
}

// Verify the real SDK's wire signatures independently with the documented
// SigV4 HMAC construction. The fixture never substitutes a mock S3 API client.
func validSignature(request *http.Request, payload []byte) bool {
	query := request.URL.Query()
	credential, signed, signature, stamp := query.Get("X-Amz-Credential"), query.Get("X-Amz-SignedHeaders"), query.Get("X-Amz-Signature"), query.Get("X-Amz-Date")
	presigned := signature != ""
	if !presigned {
		auth := request.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 ") {
			return false
		}
		for _, field := range strings.Split(strings.TrimPrefix(auth, "AWS4-HMAC-SHA256 "), ",") {
			name, value, _ := strings.Cut(strings.TrimSpace(field), "=")
			switch name {
			case "Credential":
				credential = value
			case "SignedHeaders":
				signed = value
			case "Signature":
				signature = value
			}
		}
		stamp = request.Header.Get("X-Amz-Date")
	}
	scope := strings.Split(credential, "/")
	if len(scope) != 5 || scope[0] != "EXAMPLEACCESSKEY" || scope[2] != "us-east-1" || scope[3] != "s3" || scope[4] != "aws4_request" || len(stamp) < 8 || scope[1] != stamp[:8] {
		return false
	}
	var canonical strings.Builder
	for _, name := range strings.Split(signed, ";") {
		value := request.Header.Get(name)
		if name == "host" {
			value = request.Host
		}
		if name == "content-length" {
			value = strconv.FormatInt(request.ContentLength, 10)
		}
		canonical.WriteString(name + ":" + strings.Join(strings.Fields(value), " ") + "\n")
	}
	query.Del("X-Amz-Signature")
	encoded := strings.ReplaceAll(query.Encode(), "+", "%20")
	digest := request.Header.Get("X-Amz-Content-Sha256")
	if presigned {
		digest = "UNSIGNED-PAYLOAD"
	}
	if digest == "" {
		sum := sha256.Sum256(payload)
		digest = hex.EncodeToString(sum[:])
	}
	uri := request.URL.EscapedPath()
	if uri == "" {
		uri = "/"
	}
	text := request.Method + "\n" + uri + "\n" + encoded + "\n" + canonical.String() + "\n" + signed + "\n" + digest
	hash := sha256.Sum256([]byte(text))
	stringToSign := "AWS4-HMAC-SHA256\n" + stamp + "\n" + strings.Join(scope[1:], "/") + "\n" + hex.EncodeToString(hash[:])
	key := hmac256([]byte("AWS4"+validCredentials().SecretKey), scope[1])
	key = hmac256(key, scope[2])
	key = hmac256(key, scope[3])
	key = hmac256(key, scope[4])
	return hmac.Equal([]byte(signature), []byte(hex.EncodeToString(hmac256(key, stringToSign))))
}

func newFakeS3(t *testing.T, style string) *fakeS3 {
	t.Helper()
	f := &fakeS3{objects: map[string]fakeObject{}, uploads: map[string]fakeObject{}, parts: map[string][]Part{}, requests: map[string]int{}}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "S3 fixture"}, DNSNames: []string{"s3.fixture.test", "frontiercloud-media.s3.fixture.test"}, IPAddresses: []net.IP{net.ParseIP("192.168.6.20"), net.ParseIP("fd01::20")}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	f.server = httptest.NewUnstartedServer(http.HandlerFunc(f.serve))
	f.server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}
	f.server.StartTLS()
	t.Cleanup(f.server.Close)
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	_, port, _ := net.SplitHostPort(f.server.Listener.Addr().String())
	config := baseConfig()
	config.Endpoint = "https://s3.fixture.test:" + port
	config.AddressStyle = style
	options := transportOptions{roots: roots, resolve: func(context.Context, string) ([]netip.Addr, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.resolved++
		return []netip.Addr{netip.MustParseAddr("192.168.6.20")}, nil
	}, dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		f.mu.Lock()
		f.dials = append(f.dials, address)
		f.mu.Unlock()
		return (&net.Dialer{}).DialContext(ctx, network, f.server.Listener.Addr().String())
	}}
	f.client, err = newClient(config, validCredentials(), options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.client.Close)
	return f
}

func xmlValue(value string) string {
	var b bytes.Buffer
	xml.EscapeText(&b, []byte(value))
	return b.String()
}
func apiError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	fmt.Fprintf(w, "<Error><Code>%s</Code><Message>https://secret.example/?credential=DO-NOT-REFLECT</Message></Error>", code)
}

func (f *fakeS3) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests[r.Method]++
	w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
	w.Header().Set("Access-Control-Expose-Headers", "ETag, X-Amz-Checksum-Sha256, X-Amz-Checksum-Type, X-Amz-Version-Id, Content-Range")
	if f.mode == "put-expose" && r.Method == http.MethodPut || f.mode == "head-expose" && r.Method == http.MethodHead || f.mode == "range-expose" && r.Header.Get("Range") != "" {
		w.Header().Del("Access-Control-Expose-Headers")
	}
	if f.mode == "cors" {
		w.Header().Del("Access-Control-Allow-Origin")
	}
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Methods", "GET, PUT, HEAD")
		w.Header().Set("Access-Control-Allow-Headers", "*")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, controlLimit+1))
	key := strings.TrimPrefix(r.URL.Path, "/"+f.client.config.Bucket+"/")
	if f.client.config.AddressStyle == "virtual" {
		key = strings.TrimPrefix(r.URL.Path, "/")
	}
	if !validSignature(r, body) {
		if f.mode == "public" && r.Method == http.MethodGet && r.Header.Get("Authorization") == "" && r.URL.Query().Get("X-Amz-Signature") == "" {
			if object, ok := f.objects[key]; ok {
				w.Write(object.payload)
				return
			}
		}
		if r.Header.Get("Authorization") != "" || r.URL.Query().Get("X-Amz-Signature") != "" {
			f.badSignatures++
		}
		apiError(w, http.StatusForbidden, "AccessDenied")
		return
	}
	if f.mode == "redirect" {
		w.Header().Set("Location", "https://unrelated.example/secret")
		w.WriteHeader(http.StatusTemporaryRedirect)
		return
	}
	if f.mode == "headers" {
		w.Header().Set("X-Unbounded", strings.Repeat("x", 17<<10))
	}
	if f.mode == "delay" {
		time.Sleep(150 * time.Millisecond)
	}
	query := r.URL.Query()
	upload := query.Get("uploadId")
	switch {
	case r.Method == http.MethodGet && query.Has("uploads"):
		prefix := query.Get("prefix")
		if prefix == "" || !strings.HasPrefix(prefix, f.client.config.Prefix+"/") || query.Get("max-uploads") != "128" {
			apiError(w, 403, "AccessDenied")
			return
		}
		truncated, nextID := "false", ""
		id := "upload-one"
		observedKey := prefix
		if f.mode == "upload-list-outside" {
			observedKey = "foreign/object"
		}
		if f.mode == "upload-list-pages" && query.Get("upload-id-marker") == "" {
			truncated, nextID = "true", "upload-one"
		}
		if f.mode == "upload-list-pages" && query.Get("upload-id-marker") != "" {
			id = "upload-two"
		}
		if f.mode == "upload-list-bound" || f.mode == "upload-list-cycle" {
			id = fmt.Sprintf("upload-%d", f.requests["GET"])
			truncated, nextID = "true", id
			if f.mode == "upload-list-cycle" {
				nextID = "fixed-cursor"
			}
		}
		fmt.Fprintf(w, "<ListMultipartUploadsResult><Bucket>%s</Bucket><Prefix>%s</Prefix><IsTruncated>%s</IsTruncated><NextKeyMarker>%s</NextKeyMarker><NextUploadIdMarker>%s</NextUploadIdMarker>", f.client.config.Bucket, xmlValue(prefix), truncated, xmlValue(prefix), xmlValue(nextID))
		if f.mode != "upload-list-empty" {
			fmt.Fprintf(w, "<Upload><Key>%s</Key><UploadId>%s</UploadId><Initiated>2026-10-25T00:00:00Z</Initiated></Upload>", xmlValue(observedKey), xmlValue(id))
			if f.mode == "upload-list-normal" {
				fmt.Fprintf(w, "<Upload><Key>%s-neighbor</Key><UploadId>DO-NOT-RETURN</UploadId><Initiated>2026-10-25T00:00:00Z</Initiated></Upload>", xmlValue(prefix))
			}
		}
		fmt.Fprint(w, "</ListMultipartUploadsResult>")
	case r.Method == http.MethodPost && query.Has("uploads"):
		if r.Header.Get("X-Amz-Checksum-Algorithm") != "SHA256" || r.Header.Get("X-Amz-Checksum-Type") != "COMPOSITE" {
			apiError(w, 400, "BadDigest")
			return
		}
		if f.mode == "create500" {
			apiError(w, 500, "InternalError")
			return
		}
		if strings.HasPrefix(f.mode, "create-rejected-") {
			apiError(w, http.StatusForbidden, strings.TrimPrefix(f.mode, "create-rejected-"))
			return
		}
		if f.mode == "large" {
			w.Write(bytes.Repeat([]byte("x"), int(controlLimit)+1))
			return
		}
		metadata := map[string]string{}
		for name, values := range r.Header {
			if strings.HasPrefix(strings.ToLower(name), "x-amz-meta-") {
				metadata[strings.TrimPrefix(strings.ToLower(name), "x-amz-meta-")] = values[0]
			}
		}
		f.uploads[key] = fakeObject{metadata: metadata}
		f.createdKey, f.createdMetadata = key, metadata
		f.parts[key] = nil
		w.Header().Set("Content-Type", "application/xml")
		fmt.Fprintf(w, "<InitiateMultipartUploadResult><Bucket>%s</Bucket><Key>%s</Key><UploadId>fixture-upload</UploadId></InitiateMultipartUploadResult>", f.client.config.Bucket, xmlValue(key))
	case r.Method == http.MethodPut && upload != "":
		object, ok := f.uploads[key]
		if !ok {
			apiError(w, 404, "NoSuchUpload")
			return
		}
		hash := sha256.Sum256(body)
		checksum := base64.StdEncoding.EncodeToString(hash[:])
		if r.Header.Get("X-Amz-Checksum-Sha256") != checksum {
			apiError(w, 400, "BadDigest")
			return
		}
		object.payload = append([]byte(nil), body...)
		f.uploads[key] = object
		number, _ := strconv.Atoi(query.Get("partNumber"))
		f.parts[key] = []Part{{Number: int32(number), Size: int64(len(body)), SHA256: checksum, ETag: `"opaque-part"`}}
		w.Header().Set("ETag", `"opaque-part"`)
		w.Header().Set("X-Amz-Checksum-Sha256", checksum)
	case r.Method == http.MethodGet && upload != "":
		if _, ok := f.uploads[key]; !ok {
			apiError(w, 404, "NoSuchUpload")
			return
		}
		truncated, next := "false", ""
		entries := f.parts[key]
		if f.mode == "pages" && query.Get("part-number-marker") == "" {
			entries = entries[:1]
			truncated, next = "true", "1"
		}
		if f.mode == "pages" && query.Get("part-number-marker") != "" {
			entries = entries[1:]
		}
		if f.mode == "bad-marker" {
			truncated, next = "true", "0"
		}
		fmt.Fprintf(w, "<ListPartsResult><Bucket>%s</Bucket><Key>%s</Key><UploadId>%s</UploadId><IsTruncated>%s</IsTruncated><NextPartNumberMarker>%s</NextPartNumberMarker><ChecksumAlgorithm>SHA256</ChecksumAlgorithm><ChecksumType>COMPOSITE</ChecksumType>", f.client.config.Bucket, xmlValue(key), xmlValue(upload), truncated, next)
		for _, part := range entries {
			fmt.Fprintf(w, "<Part><PartNumber>%d</PartNumber><Size>%d</Size><ETag>%s</ETag><ChecksumSHA256>%s</ChecksumSHA256></Part>", part.Number, part.Size, xmlValue(part.ETag), part.SHA256)
		}
		fmt.Fprint(w, "</ListPartsResult>")
	case r.Method == http.MethodPost && upload != "":
		if f.mode == "embedded-error" {
			apiError(w, 200, "InternalError")
			return
		}
		object, ok := f.uploads[key]
		if !ok {
			apiError(w, 404, "NoSuchUpload")
			return
		}
		if r.Header.Get("If-None-Match") != "*" {
			apiError(w, 403, "AccessDenied")
			return
		}
		if _, ok := f.objects[key]; ok {
			apiError(w, 412, "PreconditionFailed")
			return
		}
		size, checksum, err := partsProof(f.parts[key])
		if err != nil {
			apiError(w, 400, "InvalidPart")
			return
		}
		var completed struct {
			Parts []struct {
				Number int32  `xml:"PartNumber"`
				ETag   string `xml:"ETag"`
				SHA256 string `xml:"ChecksumSHA256"`
			} `xml:"Part"`
		}
		if xml.Unmarshal(body, &completed) != nil || len(completed.Parts) != len(f.parts[key]) || r.Header.Get("X-Amz-Checksum-Sha256") != checksum || r.Header.Get("X-Amz-Checksum-Type") != "COMPOSITE" || r.Header.Get("X-Amz-Mp-Object-Size") != strconv.FormatInt(size, 10) {
			apiError(w, 400, "BadDigest")
			return
		}
		for i, part := range completed.Parts {
			expected := f.parts[key][i]
			if part.Number != expected.Number || part.ETag != expected.ETag || part.SHA256 != expected.SHA256 {
				apiError(w, 400, "InvalidPart")
				return
			}
		}
		object.etag = `"opaque-object"`
		object.checksum = checksum
		object.size = size
		if f.mode == "metadata" {
			object.metadata = map[string]string{"fc-probe": "foreign"}
		}
		f.objects[key] = object
		delete(f.uploads, key)
		if f.mode == "checkpoint-complete-lost" {
			// Commit the object but lose the completion response before a final
			// report can carry its version/ETag to the service journal.
			apiError(w, 500, "InternalError")
			return
		}
		w.Header().Set("X-Amz-Version-Id", "fixture-version")
		w.Header().Set("X-Amz-Checksum-Type", "COMPOSITE")
		fmt.Fprintf(w, "<CompleteMultipartUploadResult><Bucket>%s</Bucket><Key>%s</Key><ETag>%s</ETag><ChecksumSHA256>%s</ChecksumSHA256><ChecksumType>COMPOSITE</ChecksumType></CompleteMultipartUploadResult>", f.client.config.Bucket, xmlValue(key), xmlValue(object.etag), checksum)
	case r.Method == http.MethodDelete && upload != "":
		delete(f.uploads, key)
		delete(f.parts, key)
		w.WriteHeader(204)
	case r.Method == http.MethodDelete:
		object, ok := f.objects[key]
		if !ok {
			w.WriteHeader(204)
			return
		}
		if r.Header.Get("If-Match") != object.etag || query.Get("versionId") != "fixture-version" {
			apiError(w, 412, "PreconditionFailed")
			return
		}
		delete(f.objects, key)
		if f.mode == "delete-lost" {
			apiError(w, 500, "InternalError")
			return
		}
		w.WriteHeader(204)
	case r.Method == http.MethodHead || r.Method == http.MethodGet:
		object, ok := f.objects[key]
		if !ok {
			apiError(w, 404, "NoSuchKey")
			return
		}
		if version := query.Get("versionId"); version != "" && version != "fixture-version" {
			apiError(w, 404, "NoSuchVersion")
			return
		}
		if match := r.Header.Get("If-Match"); match != "" && match != object.etag {
			apiError(w, 412, "PreconditionFailed")
			return
		}
		w.Header().Set("ETag", object.etag)
		w.Header().Set("X-Amz-Version-Id", "fixture-version")
		w.Header().Set("X-Amz-Checksum-Sha256", object.checksum)
		w.Header().Set("X-Amz-Checksum-Type", "COMPOSITE")
		for name, value := range object.metadata {
			w.Header().Set("X-Amz-Meta-"+name, value)
		}
		if r.Method == http.MethodHead {
			if r.Header.Get("X-Amz-Checksum-Mode") != "ENABLED" {
				apiError(w, 400, "InvalidRequest")
				return
			}
			w.Header().Set("Content-Length", strconv.FormatInt(object.size, 10))
			return
		}
		if r.Header.Get("Range") == "bytes=0-15" {
			w.Header().Set("Content-Range", "bytes 0-15/"+strconv.Itoa(len(object.payload)))
			w.WriteHeader(206)
			w.Write(object.payload[:16])
			return
		}
		w.Write(object.payload)
	default:
		apiError(w, 400, "InvalidRequest")
	}
}

func TestListPartsObservesHolesAndValidatesActualPagination(t *testing.T) {
	for _, mode := range []string{"holes", "pages", "duplicate", "unordered", "bad-marker", "bad-checksum", "too-many"} {
		t.Run(mode, func(t *testing.T) {
			f := newFakeS3(t, "path")
			f.mode = mode
			sum := sha256.Sum256([]byte("part"))
			checksum := base64.StdEncoding.EncodeToString(sum[:])
			first := Part{Number: 1, Size: PartSize, SHA256: checksum, ETag: `"opaque-1"`}
			third := Part{Number: 3, Size: 1, SHA256: checksum, ETag: `"opaque-3"`}
			entries := []Part{first, third}
			switch mode {
			case "duplicate":
				entries = []Part{first, first}
			case "unordered":
				entries = []Part{third, first}
			case "bad-checksum":
				entries[1].SHA256 = "invalid"
			case "too-many":
				entries[1].Number = 1281
			}
			key := "music/v1/objects/partial"
			f.uploads[key] = fakeObject{}
			f.parts[key] = entries
			parts, err := f.client.ListParts(context.Background(), "objects/partial", "fixture-upload")
			if mode == "holes" || mode == "pages" {
				if err != nil || len(parts) != 2 || parts[1].Number != 3 {
					t.Fatal("valid sparse recovery observation refused", err)
				}
				if _, _, err := partsProof(parts); !errors.Is(err, ErrConfig) {
					t.Fatal("incomplete observations became a completion proof")
				}
				if mode == "pages" {
					f.mu.Lock()
					count := f.requests["GET"]
					f.mu.Unlock()
					if count != 2 {
						t.Fatal("actual ListParts pagination did not advance", count)
					}
				}
			} else if !errors.Is(err, ErrResponse) {
				t.Fatal("unbounded or invalid provider listing accepted", err)
			}
		})
	}
}

func TestConditionalReadsDeletesAndNoOverwrite(t *testing.T) {
	f := newFakeS3(t, "path")
	sum := sha256.Sum256([]byte("fixture"))
	partChecksum := base64.StdEncoding.EncodeToString(sum[:])
	parts := []Part{{Number: 1, Size: 7, SHA256: partChecksum, ETag: `"part"`}}
	_, composite, _ := partsProof(parts)
	key := "music/v1/objects/immutable"
	f.objects[key] = fakeObject{payload: []byte("fixture"), size: 7, checksum: composite, etag: `"correct"`, metadata: map[string]string{"fc-owner": "fixture"}}
	if err := f.client.Delete(context.Background(), "objects/immutable", "fixture-version", `"wrong"`); !errors.Is(err, ErrConflict) || IsUncertain(err) {
		t.Fatal("conditional deletion lost its definite refusal", err)
	}
	if _, err := f.client.Head(context.Background(), "objects/immutable", "wrong-version"); !errors.Is(err, ErrNotFound) {
		t.Fatal("HEAD escaped requested generation", err)
	}
	grant, err := f.client.PresignGet(context.Background(), "objects/immutable", "fixture-version", `"wrong"`, "", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	response, err := f.client.doGrant(context.Background(), http.MethodGet, grant, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 412 {
		t.Fatal("signed GET did not enforce ETag")
	}
	if _, err = f.client.CreateMultipart(context.Background(), "objects/immutable", map[string]string{"fc-owner": "fixture"}); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.parts[key] = parts
	f.mu.Unlock()
	if _, err = f.client.Complete(context.Background(), "objects/immutable", "fixture-upload", parts); !errors.Is(err, ErrConflict) || IsUncertain(err) {
		t.Fatal("completion overwrote an existing immutable key", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.objects[key].etag != `"correct"` {
		t.Fatal("conditional refusal changed the prior object")
	}
}

func TestSignedSDKProbeCompleteCORSRangeAndCleanup(t *testing.T) {
	for _, style := range []string{"path", "virtual"} {
		t.Run(style, func(t *testing.T) {
			f := newFakeS3(t, style)
			report, err := f.client.Test(context.Background(), "https://browser.fixture.test")
			if err != nil || !report.Read || !report.Head || !report.Write || !report.Delete || !report.Multipart || !report.Range || !report.CORS || !report.Cleanup || report.CleanupUncertain {
				t.Fatalf("probe flags=%+v code=%v", report, err)
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if len(f.objects) != 0 || len(f.uploads) != 0 || f.badSignatures != 0 || f.requests["POST"] != 2 || f.requests["PUT"] != 1 || f.requests["DELETE"] != 1 {
				t.Fatal("probe did not execute the exact signed mutation/cleanup sequence", f.requests, f.badSignatures)
			}
		})
	}
}

func TestProbeFailureCleanupAndUnknownMutations(t *testing.T) {
	for _, tc := range []struct {
		mode               string
		code               error
		cleanup, uncertain bool
	}{
		{"cors", ErrCORS, true, false}, {"put-expose", ErrCORS, true, false}, {"head-expose", ErrCORS, true, false}, {"range-expose", ErrCORS, true, false}, {"public", ErrDenied, true, false}, {"embedded-error", ErrResponse, false, true},
		{"metadata", ErrResponse, false, true}, {"delete-lost", ErrResponse, false, true},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			f := newFakeS3(t, "path")
			f.mode = tc.mode
			report, err := f.client.Test(context.Background(), "https://browser.fixture.test")
			if !errors.Is(err, tc.code) || report.Cleanup != tc.cleanup || report.CleanupUncertain != tc.uncertain {
				t.Fatalf("unexpected bounded failure flags=%+v code=%v", report, err)
			}
			if strings.Contains(fmt.Sprint(err), "secret") || strings.Contains(fmt.Sprint(err), "credential") {
				t.Fatal("SDK error disclosed provider diagnostic")
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if tc.mode == "delete-lost" && f.requests["DELETE"] != 1 {
				t.Fatal("ambiguous deletion was retried")
			}
			if tc.mode == "metadata" && len(f.objects) != 1 {
				t.Fatal("cleanup deleted an object with unproved ownership")
			}
		})
	}
}

func TestMutatingErrorsAreBoundedAndNeverRetried(t *testing.T) {
	for _, mode := range []string{"create500", "large", "redirect", "headers"} {
		t.Run(mode, func(t *testing.T) {
			f := newFakeS3(t, "path")
			f.mode = mode
			_, err := f.client.CreateMultipart(context.Background(), "objects/immutable", map[string]string{"fc-owner": "id"})
			if err == nil || !IsUncertain(err) || len(err.Error()) > 32 || strings.Contains(err.Error(), "https") {
				t.Fatal("ambiguous mutation or error boundary lost", err)
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.requests["POST"] != 1 {
				t.Fatal("SDK retried a mutation", f.requests)
			}
		})
	}
}

func TestGrantBindsChecksumSizeETagVersionAndExpiry(t *testing.T) {
	f := newFakeS3(t, "path")
	sum := sha256.Sum256([]byte("part"))
	checksum := base64.StdEncoding.EncodeToString(sum[:])
	grant, err := f.client.PresignPart(context.Background(), "objects/immutable", "upload-id", 1, PartSize, checksum, 60*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(grant.URL)
	signed := u.Query().Get("X-Amz-SignedHeaders")
	if grant.Headers["X-Amz-Checksum-Sha256"] != checksum || !strings.Contains(signed, "x-amz-checksum-sha256") || !strings.Contains(signed, "content-length") || u.Query().Get("X-Amz-Expires") != "60" || grant.Headers["Content-Length"] != strconv.FormatInt(PartSize, 10) {
		t.Fatal("upload grant missing required signed constraints", signed, grant.Headers)
	}
	read, err := f.client.PresignGet(context.Background(), "objects/immutable", "version-id", `"opaque-etag"`, "歌曲.mp3", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	u, _ = url.Parse(read.URL)
	if u.Query().Get("versionId") != "version-id" || read.Headers["If-Match"] != `"opaque-etag"` || !strings.Contains(u.Query().Get("X-Amz-SignedHeaders"), "if-match") || !strings.HasPrefix(u.Query().Get("response-content-disposition"), "attachment; filename*=UTF-8''") {
		t.Fatal("download grant lost object generation")
	}
	if _, err = f.client.PresignPart(context.Background(), "objects/immutable", "upload-id", 1281, 1, checksum, time.Minute); !errors.Is(err, ErrConfig) {
		t.Fatal("oversized part count accepted")
	}
}

func TestPartsAreCompositeContiguousAndStrictlyBounded(t *testing.T) {
	sum := sha256.Sum256([]byte("part"))
	checksum := base64.StdEncoding.EncodeToString(sum[:])
	parts := []Part{{Number: 1, Size: PartSize, SHA256: checksum, ETag: `"etag-1"`}, {Number: 2, Size: 4, SHA256: checksum, ETag: `"etag-2"`}}
	size, composite, err := partsProof(parts)
	if err != nil || size != PartSize+4 || composite == checksum || !strings.HasSuffix(composite, "-2") || !validComposite(composite) {
		t.Fatal("composite/full checksum conflated")
	}
	for _, bad := range [][]Part{nil, {{Number: 0, Size: 1, SHA256: checksum, ETag: `"e"`}}, {{Number: 2, Size: 1, SHA256: checksum, ETag: `"e"`}}, {{Number: 1, Size: 1, SHA256: checksum, ETag: `"e"`}, {Number: 2, Size: 1, SHA256: checksum, ETag: `"e"`}}, {{Number: 1, Size: PartSize + 1, SHA256: checksum, ETag: `"e"`}}, {{Number: 1, Size: 1, SHA256: "bad", ETag: `"e"`}}, {{Number: 1, Size: 1, SHA256: checksum, ETag: "etag\r\n"}}} {
		if _, _, err := partsProof(bad); !errors.Is(err, ErrConfig) {
			t.Fatal("invalid completion accepted")
		}
	}
}

func TestPlannedProbeKeyAndDeterministicRecoveryMetadata(t *testing.T) {
	f := newFakeS3(t, "path")
	planned := "probes/member1/probe1"
	report, err := f.client.TestKey(context.Background(), "https://browser.fixture.test", planned)
	if err != nil || report.ProbeKey != planned || !report.Head || !report.Cleanup {
		t.Fatal("pre-recorded probe intent was not honored", err)
	}
	f.mu.Lock()
	key, metadata := f.createdKey, f.createdMetadata["fc-probe"]
	f.mu.Unlock()
	if key != "music/v1/"+planned || metadata != planned {
		t.Fatal("crash recovery requires a lost in-memory nonce")
	}
	for _, relative := range []string{"", "objects/immutable", "probes/../escape", "probes//escape"} {
		if _, err = f.client.TestKey(context.Background(), "https://browser.fixture.test", relative); err == nil {
			t.Fatal("probe escaped its planned probe namespace")
		}
	}
}

func TestJournaledProbeCheckpointsBeforeAnyPayload(t *testing.T) {
	for _, mode := range []string{"committed", "rejected", "missing-callback"} {
		t.Run(mode, func(t *testing.T) {
			f := newFakeS3(t, "path")
			var saved string
			calls := 0
			checkpoint := func(id string) error {
				f.mu.Lock()
				defer f.mu.Unlock()
				calls++
				if id != "fixture-upload" || f.requests["POST"] != 1 || f.requests["PUT"] != 0 || f.requests["OPTIONS"] != 0 || len(f.objects) != 0 {
					t.Fatal("probe performed payload/signature traffic before checkpoint", f.requests)
				}
				if mode == "rejected" {
					return errors.New("private journal diagnostic https://secret.example/DO-NOT-REFLECT")
				}
				saved = id
				return nil
			}
			if mode == "missing-callback" {
				checkpoint = nil
			}
			report, err := f.client.TestKeyWithCheckpoint(context.Background(), "https://browser.fixture.test", "probes/member1/probe1", checkpoint)
			f.mu.Lock()
			defer f.mu.Unlock()
			switch mode {
			case "committed":
				if err != nil || calls != 1 || saved != report.UploadID || !report.Cleanup || !report.Multipart || f.requests["PUT"] != 1 || f.requests["POST"] != 2 {
					t.Fatal("checkpointed signed probe did not complete", report, err, f.requests)
				}
			case "rejected":
				if !errors.Is(err, ErrIncomplete) || calls != 1 || report.NoMutation || report.UploadID != "fixture-upload" || !report.Cleanup || report.CleanupUncertain || f.requests["POST"] != 1 || f.requests["PUT"] != 0 || f.requests["OPTIONS"] != 0 || f.requests["DELETE"] != 1 || len(f.uploads) != 0 {
					t.Fatal("failed journal reached payload or leaked cleanup", report, err, f.requests)
				}
				if strings.Contains(err.Error(), "private") || strings.Contains(err.Error(), "https") {
					t.Fatal("checkpoint diagnostic escaped its closed error boundary")
				}
			case "missing-callback":
				if !errors.Is(err, ErrConfig) || !report.NoMutation || len(f.requests) != 0 || calls != 0 {
					t.Fatal("missing journal allowed creation", report, err, f.requests)
				}
			}
		})
	}
}

func TestCheckpointRetainsUIDAcrossLostCompletionAndRecovery(t *testing.T) {
	f := newFakeS3(t, "path")
	f.mode = "checkpoint-complete-lost"
	planned := "probes/member1/probe1"
	var saved string
	_, err := f.client.TestKeyWithCheckpoint(context.Background(), "https://browser.fixture.test", planned, func(id string) error {
		saved = id
		return nil
	})
	// Deliberately discard the final report, as a service process crash can.
	// Recovery uses only the UID checkpoint and the already planned key.
	if err == nil || saved != "fixture-upload" {
		t.Fatal("lost completion failed to retain a durable UID", err)
	}
	f.mu.Lock()
	objects, uploads, signatures := len(f.objects), len(f.uploads), f.badSignatures
	f.mu.Unlock()
	if objects != 1 || uploads != 0 || signatures != 0 {
		t.Fatal("fixture did not commit exactly one signed object before losing response")
	}
	if err = f.client.Abort(context.Background(), planned, saved); err != nil {
		t.Fatal(err)
	}
	if _, err = f.client.ListParts(context.Background(), planned, saved); !errors.Is(err, ErrNotFound) {
		t.Fatal("known multipart identity did not prove closure", err)
	}
	proof, err := f.client.Head(context.Background(), planned, "")
	if err != nil || len(proof.Metadata) != 1 || proof.Metadata["fc-probe"] != planned {
		t.Fatal("completed probe lost exact planned ownership", err)
	}
	if err = f.client.Delete(context.Background(), planned, proof.VersionID, proof.ETag); err != nil {
		t.Fatal("known UID recovery could not conditionally delete exact version", err)
	}
	if _, err = f.client.Head(context.Background(), planned, proof.VersionID); !errors.Is(err, ErrNotFound) {
		t.Fatal("recovery lacked independent absence proof", err)
	}
}

func TestPresignGetAcceptsManagedUnicodeFilenameBounds(t *testing.T) {
	f := newFakeS3(t, "path")
	for _, filename := range []string{
		strings.Repeat("a", 237) + ".mp3",
		strings.Repeat("a", 251) + ".mp3",
		strings.Repeat("歌", 100) + ".mp3",
		strings.Repeat("歌", 251) + ".mp3",
		strings.Repeat("🦉", 251) + ".mp3",
	} {
		grant, err := f.client.PresignGet(context.Background(), "objects/immutable", "fixture-version", `"opaque"`, filename, time.Minute)
		if err != nil {
			t.Fatal("accepted managed filename could not receive source grant", len(filename), err)
		}
		parsed, _ := url.Parse(grant.URL)
		disposition := strings.TrimPrefix(parsed.Query().Get("response-content-disposition"), "attachment; filename*=UTF-8''")
		decoded, err := url.PathUnescape(disposition)
		if err != nil || decoded != filename || grant.Headers["If-Match"] != `"opaque"` {
			t.Fatal("signed filename or object identity changed")
		}
		request, _ := http.NewRequest(http.MethodGet, grant.URL, nil)
		for name, value := range grant.Headers {
			request.Header.Set(name, value)
		}
		if !validSignature(request, nil) {
			t.Fatal("long UTF-8 display filename was not covered by real SDK signature")
		}
	}
	for _, filename := range []string{strings.Repeat("a", 256), strings.Repeat("🦉", 257), "bad\rname", "bad\nname", "bad\x00name", "bad\x7fname", "bad\u0085name", "bad/name", `bad\name`, string([]byte{0xff})} {
		if _, err := f.client.PresignGet(context.Background(), "objects/immutable", "fixture-version", `"opaque"`, filename, time.Minute); !errors.Is(err, ErrConfig) {
			t.Fatal("invalid display filename became a signed grant", err)
		}
	}
}

func TestExactUploadEnumerationIsPrefixBoundedAndConservative(t *testing.T) {
	for _, mode := range []string{"upload-list-normal", "upload-list-empty", "upload-list-pages", "upload-list-bound", "upload-list-cycle", "upload-list-outside"} {
		t.Run(mode, func(t *testing.T) {
			f := newFakeS3(t, "path")
			f.mode = mode
			listing, err := f.client.ListUploads(context.Background(), "probes/member1/probe1")
			switch mode {
			case "upload-list-cycle", "upload-list-outside":
				if !errors.Is(err, ErrResponse) {
					t.Fatal("malformed/cross-prefix enumeration admitted", err)
				}
			case "upload-list-bound":
				if err != nil || listing.Complete || len(listing.Uploads) != 10 {
					t.Fatal("bounded enumeration was presented as complete", err)
				}
			case "upload-list-empty":
				if err != nil || !listing.Complete || len(listing.Uploads) != 0 {
					t.Fatal("empty observation misrepresented", err)
				}
			case "upload-list-normal":
				if err != nil || !listing.Complete || len(listing.Uploads) != 1 || listing.Uploads[0].UploadID != "upload-one" {
					t.Fatal("enumeration returned another key's upload", err)
				}
			case "upload-list-pages":
				if err != nil || !listing.Complete || len(listing.Uploads) != 2 {
					t.Fatal("exact-key pagination did not finish", err)
				}
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.requests["POST"]+f.requests["PUT"]+f.requests["DELETE"] != 0 || f.requests["GET"] > 10 {
				t.Fatal("enumeration mutated provider state or exceeded its bound")
			}
		})
	}
}

func TestStaticExplicitCredentialsAndTemporaryGrantDeadline(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "WRONGAMBIENTKEY")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "wrong-ambient-secret")
	t.Setenv("AWS_SESSION_TOKEN", "wrong-ambient-token")
	t.Setenv("AWS_REGION", "wrong-region")
	t.Setenv("AWS_ENDPOINT_URL", "http://169.254.169.254")
	f := newFakeS3(t, "path")
	if _, err := f.client.CreateMultipart(context.Background(), "objects/explicit", map[string]string{"fc-owner": "fixture"}); err != nil {
		t.Fatal("ambient configuration replaced explicit authority", err)
	}
	temporary := validCredentials()
	temporary.SessionToken = "explicit-temporary-token"
	temporary.ExpiresAt = time.Now().Unix() + 120
	client, err := newClient(f.client.config, temporary, f.client.transport.options)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	sum := sha256.Sum256([]byte("part"))
	checksum := base64.StdEncoding.EncodeToString(sum[:])
	grant, err := client.PresignPart(context.Background(), "objects/temp", "upload", 1, 4, checksum, MaxGrantDuration)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(grant.URL)
	if u.Query().Get("X-Amz-Security-Token") != temporary.SessionToken || grant.ExpiresAt > temporary.ExpiresAt-30 {
		t.Fatal("temporary grant ignored explicit token/clock-skew deadline")
	}
}

func TestProbeNoMutationPreservesPreconditionsAndUnknownCreate(t *testing.T) {
	f := newFakeS3(t, "path")
	key := "probes/member/probe"
	for _, origin := range []string{"http://browser.fixture.test", "https://browser.fixture.test/path"} {
		report, err := f.client.TestKey(context.Background(), origin, key)
		if err == nil || !report.NoMutation || report.ProbeKey != key {
			t.Fatal("certain pre-network rejection lost its probe fact", err)
		}
	}
	report, err := f.client.TestKey(context.Background(), "https://browser.fixture.test", "objects/not-a-probe")
	if err == nil || !report.NoMutation {
		t.Fatal("planned-key validation was described as a mutation")
	}
	f.mode = "create500"
	report, err = f.client.TestKey(context.Background(), "https://browser.fixture.test", key)
	if err == nil || report.NoMutation || !report.CleanupUncertain || !IsUncertain(err) {
		t.Fatal("unknown Create was described as definitely absent", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.requests["POST"] != 1 {
		t.Fatal("precondition checks unexpectedly mutated provider")
	}
}

func TestProbeDefiniteCreateRejectionDoesNotRequireUnknownCleanup(t *testing.T) {
	for _, code := range []string{"AccessDenied", "InvalidAccessKeyId", "SignatureDoesNotMatch", "ExpiredToken", "PreconditionFailed", "BadDigest"} {
		t.Run(code, func(t *testing.T) {
			f := newFakeS3(t, "path")
			f.mode = "create-rejected-" + code
			key := "probes/member/rejected"
			report, err := f.client.TestKey(context.Background(), "https://browser.fixture.test", key)
			if err == nil || IsUncertain(err) || !report.NoMutation || report.CleanupUncertain || report.ProbeKey != key || report.UploadID != "" {
				t.Fatal("definite rejection became unknown provider state", code, err)
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.requests["POST"] != 1 || f.requests["DELETE"] != 0 || len(f.uploads) != 0 {
				t.Fatal("rejected probe was retried or deleted unrelated material", f.requests)
			}
		})
	}
}
