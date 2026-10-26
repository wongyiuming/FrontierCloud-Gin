package s3store

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/aws/smithy-go/logging"
)

const maxParts = int(MaxObjectSize / PartSize)

type Client struct {
	config      Config
	credentials Credentials
	sdk         *s3.Client
	signer      *s3.PresignClient
	http        *http.Client
	transport   *boundedTransport
}

var _ Provider = (*Client)(nil)
var _ KeyedProber = (*Client)(nil)
var _ ExactUploadLister = (*Client)(nil)
var _ HeadPresigner = (*Client)(nil)

func New(config Config, explicit Credentials) (*Client, error) {
	return newClient(config, explicit, transportOptions{})
}

func newClient(config Config, explicit Credentials, transport transportOptions) (*Client, error) {
	config, err := Normalize(config)
	if err != nil {
		return nil, err
	}
	if err = explicit.Validate(time.Now()); err != nil {
		return nil, err
	}
	endpoint, _ := url.Parse(config.Endpoint)
	if address, parseErr := netip.ParseAddr(endpoint.Hostname()); parseErr == nil && !allowedAddress(address) {
		return nil, ErrEndpoint
	}
	if config.AddressStyle == "virtual" && len(config.Bucket)+1+len(endpoint.Hostname()) > 253 {
		return nil, ErrEndpoint
	}
	httpClient, bounded := newBoundedHTTP(config, transport)
	// Never LoadDefaultConfig: no files, environment, metadata, ambient proxy,
	// endpoint discovery or role exchange can supply authority or credentials.
	awsConfig := aws.Config{Region: config.Region, HTTPClient: httpClient,
		Credentials:      credentials.NewStaticCredentialsProvider(explicit.AccessKey, explicit.SecretKey, explicit.SessionToken),
		RetryMaxAttempts: 1, Logger: logging.Nop{},
		RequestChecksumCalculation: aws.RequestChecksumCalculationWhenRequired,
		ResponseChecksumValidation: aws.ResponseChecksumValidationWhenRequired}
	client := s3.NewFromConfig(awsConfig, func(options *s3.Options) {
		options.BaseEndpoint = aws.String(config.Endpoint)
		options.UsePathStyle = config.AddressStyle == "path"
		options.DisableMultiRegionAccessPoints = true
		options.DisableS3ExpressSessionAuth = aws.Bool(true)
		options.UseARNRegion = false
	})
	return &Client{config: config, credentials: explicit, sdk: client,
		signer: s3.NewPresignClient(client, func(options *s3.PresignOptions) { options.Presigner = headerPresigner{} }),
		http:   httpClient, transport: bounded}, nil
}

// Close releases idle network resources. It does not revoke already granted
// bearer URLs or discard an application's durable upload recovery record.
func (c *Client) Close() { c.transport.inner.CloseIdleConnections() }

func (*Client) String() string   { return "S3 client [redacted]" }
func (*Client) GoString() string { return "s3store.Client{[redacted]}" }

// Keep the checksum as a signed browser header, not an unsigned application
// promise. All other SDK SigV4 S3 options (including URI escaping) are retained.
type headerPresigner struct{}

func (headerPresigner) PresignHTTP(ctx context.Context, credentials aws.Credentials, request *http.Request,
	payloadHash, service, region string, now time.Time, options ...func(*v4.SignerOptions)) (string, http.Header, error) {
	options = append(options, func(options *v4.SignerOptions) { options.DisableHeaderHoisting = true })
	return v4.NewSigner().PresignHTTP(ctx, credentials, request, payloadHash, service, region, now, options...)
}

func (c *Client) key(relative string) (string, error) {
	if err := c.credentials.Validate(time.Now()); err != nil {
		return "", err
	}
	return c.config.ProviderKey(relative)
}

func opaque(value string, max int) bool { return printableASCII(value, 1, max) }
func validETag(value string) bool {
	if len(value) < 3 || len(value) > 512 || value[0] != '"' || value[len(value)-1] != '"' {
		return false
	}
	for _, ch := range value[1 : len(value)-1] {
		if ch < 33 || ch > 126 || ch == '"' {
			return false
		}
	}
	return true
}
func validChecksum(value string) bool {
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && base64.StdEncoding.EncodeToString(decoded) == value
}
func metadataCopy(value map[string]string) (map[string]string, error) {
	if len(value) > 16 {
		return nil, ErrResponse
	}
	result := make(map[string]string, len(value))
	size := 0
	for key, entry := range value {
		if len(key) == 0 || len(key) > 64 || len(entry) > 1024 {
			return nil, ErrResponse
		}
		for _, ch := range key {
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
				return nil, ErrResponse
			}
		}
		for _, ch := range entry {
			if ch < 32 || ch > 126 {
				return nil, ErrResponse
			}
		}
		size += len(key) + len(entry)
		if size > 8192 {
			return nil, ErrResponse
		}
		result[key] = entry
	}
	return result, nil
}

func failure(err error, mutate bool) error {
	if err == nil {
		return nil
	}
	code := ErrNetwork
	unknown := mutate
	var api smithy.APIError
	if errors.As(err, &api) {
		switch api.ErrorCode() {
		case "NoSuchKey", "NoSuchVersion", "NoSuchUpload", "NotFound":
			code = ErrNotFound
		case "AccessDenied", "InvalidAccessKeyId", "SignatureDoesNotMatch", "ExpiredToken", "InvalidToken":
			code, unknown = ErrDenied, false
		case "PreconditionFailed", "ConditionalRequestConflict", "InvalidPart", "InvalidPartOrder", "EntityTooSmall":
			code, unknown = ErrConflict, false
		case "BadDigest", "InvalidDigest":
			code, unknown = ErrChecksum, false
		default:
			code = ErrResponse
		}
	}
	if errors.Is(err, ErrResponse) {
		code = ErrResponse
	}
	if errors.Is(err, ErrEndpoint) {
		code = ErrEndpoint
	}
	return &OperationError{Code: code, Uncertain: unknown}
}
func invalidResponse(mutate bool) error { return &OperationError{Code: ErrResponse, Uncertain: mutate} }

func (c *Client) CreateMultipart(ctx context.Context, relative string, metadata map[string]string) (string, error) {
	key, err := c.key(relative)
	if err != nil {
		return "", err
	}
	copy, err := metadataCopy(metadata)
	if err != nil || len(copy) == 0 {
		return "", ErrConfig
	}
	out, err := c.sdk.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{Bucket: aws.String(c.config.Bucket), Key: &key,
		Metadata: copy, ContentType: aws.String("application/octet-stream"),
		ChecksumAlgorithm: types.ChecksumAlgorithmSha256, ChecksumType: types.ChecksumTypeComposite})
	if err != nil {
		return "", failure(err, true)
	}
	if !opaque(aws.ToString(out.UploadId), 2048) || aws.ToString(out.Key) != key || aws.ToString(out.Bucket) != c.config.Bucket {
		return "", invalidResponse(true)
	}
	return *out.UploadId, nil
}

func (c *Client) grant(out *v4.PresignedHTTPRequest, expiry time.Duration) (Grant, error) {
	u, err := url.Parse(out.URL)
	if err != nil || len(out.URL) > 16384 || u.Scheme != "https" || u.Host != c.transport.authority || u.User != nil || u.Fragment != "" {
		return Grant{}, ErrEndpoint
	}
	issued, err := time.Parse("20060102T150405Z", u.Query().Get("X-Amz-Date"))
	seconds, parseErr := strconv.ParseInt(u.Query().Get("X-Amz-Expires"), 10, 64)
	if err != nil || parseErr != nil || seconds != int64(expiry/time.Second) || issued.After(time.Now().Add(30*time.Second)) {
		return Grant{}, ErrResponse
	}
	headers := make(map[string]string)
	for name, values := range out.SignedHeader {
		if strings.EqualFold(name, "Host") {
			continue
		} // Browser supplies URL authority.
		if len(values) != 1 || !opaque(values[0], 8192) {
			return Grant{}, ErrResponse
		}
		headers[http.CanonicalHeaderKey(name)] = values[0]
	}
	return Grant{URL: out.URL, Headers: headers, ExpiresAt: issued.Add(expiry).Unix()}, nil
}

func (c *Client) PresignPart(ctx context.Context, relative, upload string, number int32, size int64, checksum string, expiry time.Duration) (Grant, error) {
	ctx, cancel := context.WithTimeout(ctx, controlTimeout)
	defer cancel()
	key, err := c.key(relative)
	if err != nil {
		return Grant{}, err
	}
	if !opaque(upload, 2048) || number < 1 || number > int32(maxParts) || size < 1 || size > PartSize || !validChecksum(checksum) {
		return Grant{}, ErrConfig
	}
	if _, err = c.transport.pinned(ctx); err != nil {
		return Grant{}, failure(err, false)
	}
	expiry, err = c.credentials.GrantDuration(time.Now(), expiry)
	if err != nil {
		return Grant{}, err
	}
	out, err := c.signer.PresignUploadPart(ctx, &s3.UploadPartInput{Bucket: aws.String(c.config.Bucket), Key: &key, UploadId: &upload,
		PartNumber: &number, ContentLength: &size, ChecksumSHA256: &checksum, ChecksumAlgorithm: types.ChecksumAlgorithmSha256}, s3.WithPresignExpires(expiry))
	if err != nil {
		return Grant{}, failure(err, false)
	}
	return c.grant(out, expiry)
}

func (c *Client) ListParts(ctx context.Context, relative, upload string) ([]Part, error) {
	ctx, cancel := context.WithTimeout(ctx, controlTimeout)
	defer cancel()
	key, err := c.key(relative)
	if err != nil {
		return nil, err
	}
	if !opaque(upload, 2048) {
		return nil, ErrConfig
	}
	var result []Part
	var marker *string
	var lastNumber int32
	for page := 0; page < maxParts; page++ {
		out, err := c.sdk.ListParts(ctx, &s3.ListPartsInput{Bucket: aws.String(c.config.Bucket), Key: &key, UploadId: &upload,
			MaxParts: aws.Int32(128), PartNumberMarker: marker})
		if err != nil {
			return nil, failure(err, false)
		}
		if aws.ToString(out.Key) != key || aws.ToString(out.Bucket) != c.config.Bucket || aws.ToString(out.UploadId) != upload || out.ChecksumAlgorithm != types.ChecksumAlgorithmSha256 || out.ChecksumType != types.ChecksumTypeComposite {
			return nil, invalidResponse(false)
		}
		for _, entry := range out.Parts {
			part := Part{Number: aws.ToInt32(entry.PartNumber), Size: aws.ToInt64(entry.Size), ETag: aws.ToString(entry.ETag), SHA256: aws.ToString(entry.ChecksumSHA256)}
			if part.Number <= lastNumber || part.Number > int32(maxParts) || len(result) >= maxParts || part.Size < 1 || part.Size > PartSize || !validETag(part.ETag) || !validChecksum(part.SHA256) {
				return nil, invalidResponse(false)
			}
			result = append(result, part)
			lastNumber = part.Number
		}
		if !aws.ToBool(out.IsTruncated) {
			return result, nil
		}
		if len(out.Parts) == 0 || len(result) >= maxParts || aws.ToString(out.NextPartNumberMarker) != strconv.Itoa(int(lastNumber)) || aws.ToString(out.NextPartNumberMarker) == aws.ToString(marker) {
			return nil, invalidResponse(false)
		}
		marker = out.NextPartNumberMarker
	}
	return nil, ErrResponse
}

func partsProof(parts []Part) (int64, string, error) {
	if len(parts) < 1 || len(parts) > maxParts {
		return 0, "", ErrConfig
	}
	var size int64
	composite := sha256.New()
	for index, part := range parts {
		if part.Number != int32(index+1) || part.Size < 1 || part.Size > PartSize || (index != len(parts)-1 && part.Size != PartSize) || !validChecksum(part.SHA256) || !validETag(part.ETag) {
			return 0, "", ErrConfig
		}
		decoded, _ := base64.StdEncoding.DecodeString(part.SHA256)
		composite.Write(decoded)
		size += part.Size
	}
	if size > MaxObjectSize {
		return 0, "", ErrConfig
	}
	return size, base64.StdEncoding.EncodeToString(composite.Sum(nil)) + "-" + strconv.Itoa(len(parts)), nil
}

func (c *Client) Complete(ctx context.Context, relative, upload string, parts []Part) (Proof, error) {
	ctx, cancel := context.WithTimeout(ctx, controlTimeout)
	defer cancel()
	key, err := c.key(relative)
	if err != nil {
		return Proof{}, err
	}
	if !opaque(upload, 2048) {
		return Proof{}, ErrConfig
	}
	size, checksum, err := partsProof(parts)
	if err != nil {
		return Proof{}, err
	}
	completed := make([]types.CompletedPart, len(parts))
	for index, part := range parts {
		completed[index] = types.CompletedPart{PartNumber: aws.Int32(part.Number), ETag: aws.String(part.ETag), ChecksumSHA256: aws.String(part.SHA256)}
	}
	out, err := c.sdk.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{Bucket: aws.String(c.config.Bucket), Key: &key, UploadId: &upload,
		MultipartUpload: &types.CompletedMultipartUpload{Parts: completed}, IfNoneMatch: aws.String("*"),
		ChecksumType: types.ChecksumTypeComposite, ChecksumSHA256: &checksum, MpuObjectSize: &size})
	if err != nil {
		return Proof{}, failure(err, true)
	}
	if aws.ToString(out.Key) != key || aws.ToString(out.Bucket) != c.config.Bucket || !validETag(aws.ToString(out.ETag)) || aws.ToString(out.ChecksumSHA256) != checksum || out.ChecksumType != types.ChecksumTypeComposite || (aws.ToString(out.VersionId) != "" && !opaque(*out.VersionId, 1024)) {
		return Proof{}, invalidResponse(true)
	}
	proof, err := c.Head(ctx, relative, aws.ToString(out.VersionId))
	if err != nil {
		return Proof{}, &OperationError{Code: ErrIncomplete, Uncertain: true}
	}
	if proof.ETag != aws.ToString(out.ETag) || proof.Size != size || proof.ChecksumSHA256 != checksum || proof.ChecksumType != "COMPOSITE" {
		return Proof{}, &OperationError{Code: ErrChecksum, Uncertain: true}
	}
	return proof, nil
}

func (c *Client) Head(ctx context.Context, relative, version string) (Proof, error) {
	key, err := c.key(relative)
	if err != nil {
		return Proof{}, err
	}
	if version != "" && !opaque(version, 1024) {
		return Proof{}, ErrConfig
	}
	input := &s3.HeadObjectInput{Bucket: aws.String(c.config.Bucket), Key: &key, ChecksumMode: types.ChecksumModeEnabled}
	if version != "" {
		input.VersionId = &version
	}
	out, err := c.sdk.HeadObject(ctx, input)
	if err != nil {
		return Proof{}, failure(err, false)
	}
	proof := Proof{Size: aws.ToInt64(out.ContentLength), ETag: aws.ToString(out.ETag), VersionID: aws.ToString(out.VersionId), ChecksumSHA256: aws.ToString(out.ChecksumSHA256), ChecksumType: string(out.ChecksumType)}
	proof.Metadata, err = metadataCopy(out.Metadata)
	if err != nil || len(proof.Metadata) == 0 || out.ContentLength == nil || proof.Size < 1 || proof.Size > MaxObjectSize || !validETag(proof.ETag) || (version != "" && version != proof.VersionID) || (proof.VersionID != "" && !opaque(proof.VersionID, 1024)) || proof.ChecksumType != "COMPOSITE" || !validComposite(proof.ChecksumSHA256) {
		return Proof{}, invalidResponse(false)
	}
	_, count, _ := strings.Cut(proof.ChecksumSHA256, "-")
	partCount, _ := strconv.ParseInt(count, 10, 64)
	if proof.Size <= (partCount-1)*PartSize || proof.Size > partCount*PartSize {
		return Proof{}, invalidResponse(false)
	}
	return proof, nil
}

func validComposite(value string) bool {
	checksum, count, ok := strings.Cut(value, "-")
	number, err := strconv.Atoi(count)
	return ok && err == nil && number >= 1 && number <= maxParts && strconv.Itoa(number) == count && validChecksum(checksum)
}

func (c *Client) Abort(ctx context.Context, relative, upload string) error {
	key, err := c.key(relative)
	if err != nil {
		return err
	}
	if !opaque(upload, 2048) {
		return ErrConfig
	}
	_, err = c.sdk.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{Bucket: aws.String(c.config.Bucket), Key: &key, UploadId: &upload})
	return failure(err, true)
}

func (c *Client) ListUploads(ctx context.Context, relative string) (UploadListing, error) {
	ctx, cancel := context.WithTimeout(ctx, controlTimeout)
	defer cancel()
	key, err := c.key(relative)
	if err != nil {
		return UploadListing{}, err
	}
	result := UploadListing{Uploads: make([]MultipartUpload, 0)}
	var keyMarker, uploadMarker *string
	seenMarkers, seenUploads := map[string]bool{}, map[string]bool{}
	for page := 0; page < 10; page++ {
		out, err := c.sdk.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{Bucket: aws.String(c.config.Bucket), Prefix: &key,
			MaxUploads: aws.Int32(128), KeyMarker: keyMarker, UploadIdMarker: uploadMarker})
		if err != nil {
			return UploadListing{}, failure(err, false)
		}
		if aws.ToString(out.Bucket) != c.config.Bucket || aws.ToString(out.Prefix) != key || len(out.Uploads) > 128 || len(out.CommonPrefixes) != 0 {
			return UploadListing{}, invalidResponse(false)
		}
		for _, entry := range out.Uploads {
			observedKey := aws.ToString(entry.Key)
			if len(observedKey) > 1024 || !strings.HasPrefix(observedKey, key) {
				return UploadListing{}, invalidResponse(false)
			}
			if observedKey != key {
				continue
			} // Never return another key's IDs.
			id := aws.ToString(entry.UploadId)
			if !opaque(id, 2048) || entry.Initiated == nil || entry.Initiated.Unix() <= 0 || seenUploads[id] {
				return UploadListing{}, invalidResponse(false)
			}
			seenUploads[id] = true
			result.Uploads = append(result.Uploads, MultipartUpload{UploadID: id, InitiatedAt: entry.Initiated.Unix()})
		}
		if !aws.ToBool(out.IsTruncated) {
			result.Complete = true
			return result, nil
		}
		nextKey, nextUpload := aws.ToString(out.NextKeyMarker), aws.ToString(out.NextUploadIdMarker)
		cursor := nextKey + "\x00" + nextUpload
		if len(out.Uploads) == 0 || len(nextKey) > 1024 || !strings.HasPrefix(nextKey, key) || nextKey < aws.ToString(keyMarker) || !opaque(nextUpload, 2048) || seenMarkers[cursor] {
			return UploadListing{}, invalidResponse(false)
		}
		seenMarkers[cursor] = true
		keyMarker, uploadMarker = out.NextKeyMarker, out.NextUploadIdMarker
	}
	return result, nil // Reached the bound; Complete deliberately remains false.
}

func (c *Client) Delete(ctx context.Context, relative, version, etag string) error {
	key, err := c.key(relative)
	if err != nil {
		return err
	}
	if !validETag(etag) || (version != "" && !opaque(version, 1024)) {
		return ErrConfig
	}
	input := &s3.DeleteObjectInput{Bucket: aws.String(c.config.Bucket), Key: &key, IfMatch: &etag}
	if version != "" {
		input.VersionId = &version
	}
	_, err = c.sdk.DeleteObject(ctx, input)
	return failure(err, true)
}

func (c *Client) PresignGet(ctx context.Context, relative, version, etag, filename string, expiry time.Duration) (Grant, error) {
	ctx, cancel := context.WithTimeout(ctx, controlTimeout)
	defer cancel()
	key, err := c.key(relative)
	if err != nil {
		return Grant{}, err
	}
	if !validETag(etag) || (version != "" && !opaque(version, 1024)) || len(filename) > 1024 || !utf8.ValidString(filename) || utf8.RuneCountInString(filename) > 255 || strings.ContainsAny(filename, "\r\n/\\\x00") {
		return Grant{}, ErrConfig
	}
	for _, ch := range filename {
		if unicode.IsControl(ch) {
			return Grant{}, ErrConfig
		}
	}
	if _, err = c.transport.pinned(ctx); err != nil {
		return Grant{}, failure(err, false)
	}
	expiry, err = c.credentials.GrantDuration(time.Now(), expiry)
	if err != nil {
		return Grant{}, err
	}
	input := &s3.GetObjectInput{Bucket: aws.String(c.config.Bucket), Key: &key, IfMatch: &etag}
	if version != "" {
		input.VersionId = &version
	}
	if filename != "" {
		input.ResponseContentDisposition = aws.String(fmt.Sprintf("attachment; filename*=UTF-8''%s", strings.ReplaceAll(url.QueryEscape(filename), "+", "%20")))
	}
	out, err := c.signer.PresignGetObject(ctx, input, s3.WithPresignExpires(expiry))
	if err != nil {
		return Grant{}, failure(err, false)
	}
	return c.grant(out, expiry)
}

func (c *Client) PresignHead(ctx context.Context, relative, version, etag string, expiry time.Duration) (Grant, error) {
	ctx, cancel := context.WithTimeout(ctx, controlTimeout)
	defer cancel()
	key, err := c.key(relative)
	if err != nil {
		return Grant{}, err
	}
	if !validETag(etag) || (version != "" && !opaque(version, 1024)) {
		return Grant{}, ErrConfig
	}
	if _, err = c.transport.pinned(ctx); err != nil {
		return Grant{}, failure(err, false)
	}
	expiry, err = c.credentials.GrantDuration(time.Now(), expiry)
	if err != nil {
		return Grant{}, err
	}
	input := &s3.HeadObjectInput{Bucket: aws.String(c.config.Bucket), Key: &key, IfMatch: &etag, ChecksumMode: types.ChecksumModeEnabled}
	if version != "" {
		input.VersionId = &version
	}
	out, err := c.signer.PresignHeadObject(ctx, input, s3.WithPresignExpires(expiry))
	if err != nil {
		return Grant{}, failure(err, false)
	}
	return c.grant(out, expiry)
}
