# Server-Side Request Forgery (SSRF) Checklist

Deep-dive audit checklist for HTTP request dispatchers, webhook receivers, URL fetchers, and PDF/image generators. Load when reviewing or verifying any feature that issues network requests to user-supplied URLs or hosts.

## Core Invariant

**Never resolve or connect to a user-supplied network endpoint without enforcing strict scheme allowlisting, resolving the host to an IP address, validating that the resolved IP does not belong to private or reserved subnets, and pinning the connection to that validated IP.**

## 1. Cloud Metadata & Reserved IP Representations

Attackers use alternative IP representations to bypass naive string matching or regexes:

- [ ] **IPv4 link-local (Cloud IMDSv1/v2)**: `169.254.169.254` (AWS, GCP, Azure, OpenStack metadata).
- [ ] **Decimal IP format**: `http://2852039166/` (evaluates to `169.254.169.254`).
- [ ] **Hexadecimal IP format**: `http://0xa9fea9fe/` or `http://0xa9.0xfe.0xa9.0xfe/`.
- [ ] **Octal IP format**: `http://0251.0376.0251.0376/`.
- [ ] **IPv6 embedded IPv4**: `http://[::ffff:169.254.169.254]/` or `http://[::ffff:a9fe:a9fe]/`.
- [ ] **IPv6 loopback / unique local**: `http://[::1]/`, `http://[fe80::1]/` (link-local), `http://[fc00::]/` (private unique local).
- [ ] **Shortened / integer localhost**: `http://127.1/`, `http://0/`, `http://0.0.0.0/`.
- [ ] **RFC 1918 Private Ranges**:
  - `10.0.0.0/8`
  - `172.16.0.0/12`
  - `192.168.0.0/16`
  - `127.0.0.0/8` (Loopback)
  - `100.64.0.0/10` (Carrier-grade NAT)

## 2. DNS Rebinding & Time-of-Check to Time-of-Use (TOCTOU)

- [ ] **Separate check vs fetch**: Does the code resolve the DNS name, check if the IP is public, and then call `fetch(url)` or `http.get(url)`?
  - **This is fundamentally broken against DNS Rebinding.**
  - An attacker controls a domain with TTL=0. The first DNS lookup returns a benign public IP (`93.184.216.34`), passing the validation check. The HTTP client's internal DNS lookup moments later returns `169.254.169.254` or `127.0.0.1`.
- [ ] **Proper fix**: Use a custom transport / socket dialer that resolves the host once, validates the IP against a blocklist, and explicitly dials the verified IP while passing the original hostname in the `Host` header and TLS SNI extension.

## 3. Redirect Chains Following to Internal Subnets

- [ ] **HTTP redirect following**: Does the HTTP client automatically follow 301, 302, 307, or 308 redirects?
  - If a public URL (e.g., `https://attacker.com/redirect`) redirects to `http://169.254.169.254/latest/meta-data/` or `http://192.168.1.1/admin`, does the client follow it?
- [ ] **Redirect validation**: When redirects are enabled, is the target URL of *each hop* validated against the same IP and scheme constraints as the initial URL?
- [ ] **Redirect limits**: Is redirect following capped (e.g., max 3 hops) or disabled entirely?

## 4. Protocol Smuggling & Scheme Validation

- [ ] **Scheme restriction**: Does the client enforce `http` and `https` exclusively?
- [ ] **Smuggled schemes**: Can an attacker pass non-HTTP schemes?
  - `file:///etc/passwd` (Local file read via cURL / libcurl or webview / headless browser).
  - `gopher://127.0.0.1:6379/_...` (Arbitrary TCP packet smuggling to internal Redis, Memcached, or SMTP servers).
  - `dict://`, `ldap://`, `jar://`, `netdoc://`.
- [ ] **URL parser confusion**: Discrepancies between the URL parser used for validation and the URL parser used by the HTTP client:
  - Userinfo confusion: `http://expected.com@169.254.169.254/`
  - Whitespace / CRLF injection in URL path or headers: injecting raw `\r\n` to send arbitrary commands to internal plaintext services.

## 5. Dangerous Contexts & Secondary Sinks

- [ ] **Headless Browsers & PDF Generators**: Puppeteer, Playwright, wkhtmltopdf, PrinceXML:
  - If rendering HTML containing `<iframe src="http://169.254.169.254/latest/meta-data/">` or `<img src="http://127.0.0.1:8080/admin/delete">`.
  - Is network access disabled (`--disable-web-security` absent; network interception rules active; file schemes disabled)?
- [ ] **Image processing libraries**: ImageMagick (`MSL`, `MVG`, `SVG` files triggering external URL fetches or local file inclusions).
- [ ] **Webhooks**: Endpoints where users configure webhook URLs: are they verified against an internal IP blocklist at registration and at dispatch time?

## Verification Strategy for Verifier

1. Locate the HTTP client invocation (`axios`, `fetch`, `requests`, `http.Client`, `RestTemplate`).
2. Trace the target URL: is any part of the scheme, host, port, or path derived from user input?
3. Check whether IP validation occurs. If validation exists:
   - Does it prevent decimal/hex/IPv6 formats?
   - Does it connect to the validated IP directly or does it make a second DNS request (DNS rebinding)?
   - Does it disable redirects, or re-verify each redirect location?
4. If IMDSv2 is enforced on cloud infrastructure (requires session token header `X-aws-ec2-metadata-token`), state whether an attacker without header injection can steal credentials.
