# OAuth 2.0 & OpenID Connect (OIDC) Checklist

Deep-dive audit checklist for identity delegation, single sign-on (SSO), and token exchange flows. Load when reviewing or verifying OAuth 2.0 authorization servers, clients, or OIDC relying party implementations.

## Core Invariant

**Every authorization response must be cryptographically or statefully bound to the specific user session that initiated it, token signatures must be strictly validated against trusted keys and algorithms, and redirect URIs must match registered values exactly.**

## 1. State Parameter & CSRF Protection

- [ ] **State parameter presence**: Does the client generate a unique, cryptographically random `state` parameter (minimum 128 bits of entropy) before redirecting the user to the authorization server?
- [ ] **State binding to session**: Is the `state` value stored in the user's browser session (e.g. encrypted or HttpOnly session cookie) or cryptographically bound to the session ID?
- [ ] **State validation upon callback**: Does the `/callback` handler strictly verify that `request.query.state` matches the session's stored state before exchanging the code?
- [ ] **One-time use (replay prevention)**: Is the state value invalidated immediately upon verification to prevent replay attacks?
- [ ] **Attack impact**: Omission or improper validation of `state` allows Login CSRF — an attacker tricks a victim into linking the attacker's social/corporate account to the victim's session, intercepting data or permissions.

## 2. Proof Key for Code Exchange (PKCE - RFC 7636)

- [ ] **PKCE enforcement**: Is PKCE enforced for all public clients (Single Page Applications, Mobile Apps, Desktop/CLI)?
- [ ] **Transformation algorithm**: Does the client use `code_challenge_method=S256`?
  - The `plain` method must be rejected by the authorization server.
- [ ] **Code verifier secrecy**: Is the `code_verifier` stored securely in client memory or ephemeral storage and exchanged directly with the `/token` endpoint over TLS?
- [ ] **Server-side validation**: Does the token endpoint compute `SHA256(code_verifier)` and verify that it matches the stored `code_challenge` before returning access or ID tokens?

## 3. Redirect URI Validation

- [ ] **Strict exact matching**: Does the authorization server require exact string matching for `redirect_uri` against pre-registered client URIs?
- [ ] **Wildcard & regex pitfalls**:
  - Are wildcards (`*`) permitted in domain, subdomain, or path components (e.g., `https://*.example.com/callback`)?
  - Does the matching algorithm allow path traversal (e.g., `https://example.com/oauth/callback/../../open-redirect`)?
  - Does the matching allow parameter appending (e.g., `https://example.com/callback?extra=payload`)?
- [ ] **Localhost and custom URI schemes**: In native/mobile apps, are custom schemes (`myapp://callback`) or private-use URI schemes handled without allowing arbitrary third-party apps on the same OS to claim the scheme?

## 4. OIDC ID Token & Nonce Verification

- [ ] **Nonce parameter**: Does the client send a cryptographically random `nonce` in the authorization request for OpenID Connect flows?
- [ ] **Nonce validation in ID Token**: Does the client verify that the `nonce` claim in the returned JWT matches the session's stored nonce, mitigating token injection and replay?
- [ ] **Standard claim validations**:
  - `iss` (Issuer): Exactly matches the expected provider's issuer URL (including `https://` protocol and no trailing slash anomalies).
  - `aud` (Audience): Matches this client's `client_id` (rejecting tokens issued for other applications of the same provider).
  - `exp` (Expiration): Current time is strictly before `exp` (with acceptable clock skew of <= 60 seconds).
  - `nbf` / `iat`: Token is not used before its issuance / not-before time.

## 5. Token Exchange, Signature & Algorithm Spoofing

- [ ] **Algorithm confusion (`alg: none`)**: Does the JWT verification library explicitly reject tokens with `"alg": "none"`?
- [ ] **Symmetric vs Asymmetric Key Confusion (HMAC vs RSA)**:
  - If the provider signs tokens with RSA (RS256) or ECDSA (ES256), does the verification function ensure the token's algorithm is strictly asymmetric?
  - Flaw: Calling `jwt.verify(token, rsaPublicKey)` without restricting algorithms to `['RS256']`. An attacker signs a token using the server's public key as an HMAC secret with `alg: HS256`.
- [ ] **JWKS Header Injection (`jku` / `jwk`)**:
  - Does the verification parser trust the `jku` (JWK Set URL) or inline `jwk` header in the incoming token without verifying that the URL is an explicitly trusted domain?
  - An attacker hosts a malicious JWKS and sets `jku: https://attacker.com/jwks.json`.
- [ ] **Key ID (`kid`) SQL injection / directory traversal**:
  - Is the `kid` header used directly in database queries or file system paths (`/keys/${kid}.pem`) without sanitization?

## Verification Strategy for Verifier

1. Inspect the authorization redirect initiation: check for `state`, `code_challenge`, and `nonce`.
2. Inspect the callback route: verify whether `state` is compared with a session-stored value.
3. Inspect JWT verification calls:
   - Check if `algorithms` is explicitly specified (e.g., `algorithms: ['RS256']`).
   - Check if `issuer` and `audience` are verified.
4. If testing an authorization server implementation, verify whether `redirect_uri` allows wildcard subdomains, trailing parameters, or HTTP schemes on non-loopback IPs.
