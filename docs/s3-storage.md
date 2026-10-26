# Optional S3 storage

An S3 member is a private object-store adapter managed by the cluster's single
Master. It joins the logical storage pool without becoming a FrontierCloud node
or a second business authority. The Master retains media paths, permissions,
encryption descriptors, ownership, quota and audit records; ordinary media bytes
travel directly between the browser and the bucket.

This contract describes the source feature. A compatible-provider fixture does
not prove a real AWS account's IAM, billing, region or bucket policy, and a source
change is not evidence that a production cluster has been upgraded.

## Supported boundary

- Private AWS S3 general-purpose buckets, using an explicitly selected region,
  or compatible HTTPS endpoints that pass the same capability probe.
- Music and video, with the existing explicit plaintext/encrypted choice.
  Browser AES-GCM remains independent of provider-side encryption.
- Multipart upload, resume, cancellation, Range playback, managed download,
  visibility, priority, same-parent logical rename and recovery-aware deletion.
- At most 10 GiB of stored bytes per object, including encryption overhead;
  8 MiB parts, two unconfirmed part grants, a 30-minute idle deadline and a
  24-hour absolute upload deadline. Grants last at most five minutes and are
  additionally bounded by explicit credential expiry.

S3 members have no native pairing package, heartbeat, filesystem free-space
measurement, Compute or business-Backup resources. Provider physical capacity
and traffic remain unknown. Allocation is a FrontierCloud logical limit, not
the bucket's physical size or a provider billing limit.

This feature does not create accounts/buckets, import pre-existing bucket
objects, expose a bucket browser, make a bucket public, configure a CDN, manage
KMS keys, or act as a general object proxy. S3 Express/directory buckets, access
point/ARN routing, replication and cold-tier restore are outside this boundary.
Native recording, Storage-to-Storage migration and retirement jobs reject S3
members. Provider lifecycle or manual object deletion can make managed media
unavailable; they do not become supported catalog mutation methods.

## Configure a member

1. Prepare a private bucket and dedicated credential with the permissions below.
   Use a dedicated prefix that no other application writes to. Keep provider
   automatic deletion/archival rules away from managed completed objects.
2. Configure the bucket's browser CORS policy for the exact FrontierCloud HTTPS
   origin. Both Master and browser must reach and normally trust the endpoint.
3. In **Node management**, add an S3 member. Supply its name, bucket, region,
   optional endpoint, dedicated prefix, address style and logical allocation.
   Empty AWS endpoint derives the regional service endpoint; custom services
   generally use path style. The default style is normalized from the endpoint.
4. Enter the access key and secret, with session token and actual expiry when
   using temporary credentials. Credentials are explicit and write-only in the
   Admin interface. The Master seals them in its existing private vault.
5. Run the capability test, then enable allocation. The test creates and removes
   a small journaled probe; failure or uncertain cleanup keeps admission closed.
6. In Media management, explicitly select the S3 site type and storage mode.
   FrontierCloud selects a member; the user does not choose an individual member
   for each upload. Direct children of one parent retain their storage affinity.

Neither `.env`, shared AWS profiles, instance metadata nor host cloud identity
supplies these credentials. The application has no custom-CA/TLS-skip switch for
S3; an endpoint must be trusted through the runtime's normal trust mechanism.
Redirects and unsafe endpoint destinations are refused by the control client.
Browser requests use the browser's own network and certificate validation.

## Bucket permissions and browser CORS

Use a dedicated private bucket or carefully scoped IAM policy. Object access
requires `s3:PutObject`, `s3:GetObject`, `s3:DeleteObject`,
`s3:AbortMultipartUpload` and `s3:ListMultipartUploadParts`. The control plane
also needs bucket-level `s3:ListBucket` and `s3:ListBucketMultipartUploads` to
distinguish absence and reconcile an uncertain multipart creation. Versioned
objects require `s3:GetObjectVersion` and `s3:DeleteObjectVersion`. The runtime
does not need bucket creation, bucket deletion, public-policy writes or CORS
administration permissions. An administrator configures CORS separately.

In particular, AWS can return 403 for a missing object when `s3:ListBucket` is
absent. That response cannot serve as proof of absence for quota release.
See AWS's [permission mapping](https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-with-s3-policy-actions.html)
and [HeadObject behavior](https://docs.aws.amazon.com/AmazonS3/latest/API/API_HeadObject.html).
Additional bucket policies, KMS encryption and retention locks can require more
authority or prevent cleanup; the capability probe must pass the actual policy.

An example S3-console CORS rule follows. Replace the origin with this deployment's
exact HTTPS origin:

```json
[
  {
    "AllowedOrigins": ["https://media.example.com"],
    "AllowedMethods": ["GET", "HEAD", "PUT"],
    "AllowedHeaders": ["content-type", "if-match", "range", "x-amz-*"],
    "ExposeHeaders": [
      "ETag", "Content-Length", "Content-Range", "Accept-Ranges",
      "x-amz-checksum-sha256", "x-amz-checksum-type", "x-amz-version-id"
    ],
    "MaxAgeSeconds": 300
  }
]
```

CORS permits a browser to read an authorized response; it does not grant object
access. The actual probe checks preflight, upload, HEAD, Range reads, checksums
and cleanup. A generic “S3 compatible” label or an OPTIONS 200 alone is
insufficient. See AWS's [CORS elements](https://docs.aws.amazon.com/AmazonS3/latest/userguide/ManageCorsUsing.html).

## Object identity and failure recovery

Provider keys are generated immutable identifiers below the configured prefix.
Logical folder rename updates catalog metadata without copying bucket payload.
The Master journals intent before provider mutations, verifies server-observed
part size/checksum/ETag, and conditionally completes one object. Multipart ETags
and composite SHA256 checksums are not complete-file SHA256 values.
The existing catalog admits ETags up to 128 bytes. Recovery retains up to 512
bytes so an unsupported provider response can be conditionally cleaned rather
than stranding an unknown intent. The probe persists its Create upload ID before
issuing any part grant, payload request or completion request.

Reads bind the exact current catalog path/object ID and stored version/ETag.
Signed URLs and their required headers remain bearer authority until expiry;
they are never audit payloads or resumable-upload storage. Existing grants cannot
be recalled immediately by hiding an object or changing a credential field.
The client must preserve signed `If-Match` headers and request a fresh grant
after expiry. Provider content replacement must fail instead of playing a new
object under the previous identity.

An interrupted upload remains reserved until recovery proves its exact owned
multipart/object has been cleaned and all issued grants have settled. A timeout,
elapsed deadline, missing browser or empty multipart listing after an uncertain
Create cannot prove that no provider write occurred. Such an intent remains
visible and blocking rather than silently freeing quota. Known uploads are
aborted, their parts checked, and any owned completed object conditionally
deleted. Foreign metadata, changed versions, denied requests or unavailable
providers preserve the fence for a later bounded retry. The recovery loop scans
journals in bounded batches; it never scans/replays an entire bucket.

AWS notes that in-flight parts can require repeated abort/inspection. A successful
abort followed by an empty ListParts or a definitive missing upload is cleanup
evidence; an ambiguous abort with an empty still-open upload is not. See
[AbortMultipartUpload](https://docs.aws.amazon.com/AmazonS3/latest/API/API_AbortMultipartUpload.html).

Resume retains only small upload metadata and plaintext block hashes. Encrypted
resume may retain ciphertext in browser OPFS, without the file key. Selecting a
different file, expired authorization or a provider error must not silently
restart as plaintext or attach different bytes to the existing upload.

## Credential changes and backups

Location/prefix changes are refused while owned objects or unresolved intents
remain. For same-location credential replacement, first disable allocation and
settle outstanding old grants. Recovery credentials initially have cleanup-only
authority: clean pending intents, pass a fresh capability probe, then explicitly
enable allocation. Active objects retain their object IDs, provider keys,
versions, ETags, catalog ownership and used quota. Do not delete media merely to
rotate a key or renew temporary credentials.

Business-v2 backups include only stable S3 location/object metadata. They omit
sealed credentials and transient provider grants; restored members are disabled
and require new credentials and a fresh probe. Unresolved upload/probe/delete
intents or live grants block that snapshot. Full state backups retain the
database together with the existing private vault. Neither backup copies S3
media payload or replaces provider data retention.

This additive feature uses database generation 8. Upgrade an existing generation-7
store through the supported operator/maintenance path and retain its pre-upgrade
recovery archive and matching images. Generation-7 binaries must refuse the new
store. Changing an image tag alone is not a supported database downgrade.
