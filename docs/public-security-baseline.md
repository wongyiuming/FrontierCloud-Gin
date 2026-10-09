# Public website security baseline

The maintainer supplied a DNSPup website-check report dated 2026-10-08 for
`520mall.cc`, score 71. It is a public configuration scan, not a penetration
test or proof that application authorization and data integrity are secure.
The report URL did not load in the research tool; its pasted findings were
checked against source and read-only public responses/DNS on 2026-10-09.

## Findings and scope

| Finding | Treatment |
| --- | --- |
| Main media pages lacked CSP | Gin now issues a fresh 256-bit nonce per HTML response, marks trusted source before substitution, forbids inline event attributes and eval, and disables HTML caching. Nginx preserves one canonical policy. |
| Player used inline `onclick` | Delegated DOM listeners preserve selection after catalog refresh without relaxing script CSP. |
| Nginx version disclosed | `server_tokens off` suppresses the version, including errors. It does not conceal that Nginx exists and is not a substitute for patching. |
| HTTP/1.1-only ALPN | Enable HTTP/2 on TLS servers; explicitly share TLS 1.2/1.3 and AEAD cipher policy with the default TLS server. Retain HTTP/1.1 fallback. |
| Error pages lost headers | Add the complete edge headers on the maintenance location. Allow only hashes of its fixed trusted inline script/style, including upstream-generated 503 redirects. |
| Karaoke duplicated security headers in staging | A child `proxy_hide_header Cache-Control` replaced the parent's entire hide list. All local hide lists now include the shared security/audit response filter; real tests assert each security header occurs once, including karaoke. Recording relays also ignore upstream internal-redirect instructions, as media relays already did. |
| Admin canonical redirect lost a mapped HTTPS port | Found in the real loopback browser gate, not the third-party scan. Use a relative 308 so the actual public port survives; normal production port 443 is unaffected. The browser follows the original login destination rather than bypassing this hop. |
| Discovery URLs omitted non-default ports | GitHub automatic review caught this in the new implementation before merge. Canonical URLs now derive from configured HTTP_PORT/HTTPS_PORT, or a validated PUBLIC_ORIGIN matching SERVER_NAME for external proxies/dynamic ports; never from request Host. Real random-port TLS tests assert sitemap, robots and security.txt URLs. |
| HSTS scored as weak | Keep the existing one-year HTTPS-only policy. Do not add `includeSubDomains` or preload without auditing all current/future subdomains. |
| Missing discovery files | Publish robots rules and a sitemap of only three public landing pages, never media filenames, resource IDs, recordings or Admin URLs. These are crawler hints, not access controls. |
| Missing `security.txt` | Publish RFC 9116 contact/expiry/canonical fields only when `SECURITY_CONTACT` names a real monitored HTTPS form or mailbox. Without a supplied contact the endpoint intentionally returns 404, not a fabricated address. |
| No MX/SPF/DMARC | No email business, confirmed by the maintainer. Use the no-mail DNS policy below, not a mail server. |
| No CAA/DNSSEC/CDN/WAF | CAA/DNSSEC are DNS/operator tasks. CDN/WAF/Anycast are optional architecture choices, not automatic defects. No DNS, account or production configuration was changed in this source patch. |
| OCSP stapling absent | Let's Encrypt retired OCSP on 2025-08-06 and now publishes revocation through CRLs. Do not enable a broken responder to chase a score. |

The direct Go surface, including `only_stroge`, has restrictive CSP, nosniff,
frame denial and permissions headers even without Nginx. Karaoke alone grants
same-origin microphone use; camera and geolocation remain denied. No broad
script `unsafe-inline`/`unsafe-eval` exception is added.

Compatibility exceptions are deliberate: inline CSS supports dynamic player
sizing; HTTPS connect/media/image sources support operator-selected direct
storage endpoints; blob media supports buffered playback and recording preview.
Authenticated Swagger/ReDoc retain their existing third-party documentation
scripts as nonced trusted tags, with a documentation-only stylesheet origin.
This is not an assertion that the application has no XSS or supply-chain risk.

## Manual DNS and operator configuration

Read-only Google public DNS queries on 2026-10-09 returned the expected DMIT A
record and Cloudflare NS records, but no CAA, DS/DNSKEY, MX, SPF TXT or DMARC.
Repeat against authoritative DNS before editing; records may change later.
The maintainer performs production upgrades and DNS changes manually.

For a domain that **neither sends nor receives mail**, add exactly one Null MX,
one SPF TXT and one DMARC TXT (do not create duplicate SPF/DMARC records):

| Type | Name | Value |
| --- | --- | --- |
| MX | `@` | priority `0`, destination `.` |
| TXT | `@` | `v=spf1 -all` |
| TXT | `_dmarc` | `v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s` |

No report mailbox (`rua`/`ruf`) is invented. These policies must change before
introducing legitimate mail, including mail from any subdomain. If the DNS UI
rejects `.` as the MX destination, use its documented API/import support;
never replace Null MX with a nonexistent hostname or the website IP.

If Let's Encrypt remains the only CA, CAA can be restricted with `0 issue
"letsencrypt.org"`; optionally deny unused wildcard issuance with `0 issuewild
""`. First confirm every certificate automation and DNS-challenge provider.
Enable Cloudflare DNSSEC, then publish its exact supplied DS at NameSilo;
verify the chain before considering it complete. Do not invent DS keys, use
unverified AAAA, or switch on proxy/CDN without testing streams, Range, upload
sizes/timeouts and storage high ports.

Set `.env` `SECURITY_CONTACT` to a **real** monitored HTTPS report form or an
external monitored mailbox. It need not be an address at `520mall.cc`. Native
container replacement preserves existing environment; setting this optional
new value requires explicitly recreating the affected web service with the
current pinned image/config, not merely pressing the version upgrade button.

Discovery URLs use the configured TLS mode and published HTTP_PORT/HTTPS_PORT.
For an external proxy or dynamically allocated port, set PUBLIC_ORIGIN to the
real HTTP(S) origin matching SERVER_NAME. Unknown dynamic ports disable the
discovery documents with 503 until configured, rather than advertising a wrong
80/443 URL; other business routes remain available. Request Host is not trusted.

## Verification and promotion

Run full Go behavior tests, relevant race tests, SQLite/MySQL real Gin black-box
tests, the actual Nginx maintenance test, and `scripts/test-browser-security.sh`
on the bounded development host. The new browser gate uses a fresh loopback
Compose project, short-lived self-signed test certificate and synthetic WAVs;
it cannot target a live URL. It verifies real HTTP/2, TLS 1.2/1.3, rejection of
TLS 1.0/1.1, one CSP header, Range responses, valid playback selection,
Admin/Karaoke scripts, microphone scope, blocked injected inline JS/handlers,
and the actual maintenance document's script/style under CSP.

`scripts/test-nginx-response-headers.sh` additionally runs a real isolated
Nginx with a deliberately untrusted synthetic upstream, no published ports or
external network, and a 64 MiB / 0.5 CPU bound. It checks canonical single
headers, hidden audit IDs/cookies, and ignored storage internal redirects.

Then push the exact tested commit to `dev`, await its lightweight CI, await the
event-driven staging CD's complete state and matching live web/updater SHA,
and verify public staging behavior. **Only then open the dev-to-main PR** and
merge after its required checks. Production is a separate maintainer-run
upgrade, not part of staging CD. Do not fast-forward dev to a new merge SHA
before recording which staging SHA was actually accepted.

GitHub CI remains bounded to three minutes; the new browser/TLS and multi-node
acceptance are not CI jobs. Local source contracts are not substitutes for
real browser/TLS checks. A successful scan or score is not full penetration
testing, weak-mainland-network acceptance or a security certification.

## Primary references

- [CSP](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy)
- [Nginx HTTP/2](https://nginx.org/en/docs/http/ngx_http_v2_module.html)
- [RFC 9116 security.txt](https://www.rfc-editor.org/rfc/rfc9116)
- [Let's Encrypt OCSP retirement](https://letsencrypt.org/2025/08/06/ocsp-service-has-reached-end-of-life/)
- [RFC 7505 Null MX](https://www.rfc-editor.org/rfc/rfc7505.html)
- [Cloudflare DNSSEC](https://developers.cloudflare.com/dns/dnssec/)
- [Let's Encrypt CAA](https://letsencrypt.org/docs/caa/)
