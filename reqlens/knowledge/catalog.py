"""Catalog: check id -> title, OWASP mapping, explanation, manual test, lesson, references.

To add a check, add an entry here and emit it from a module in :mod:`reqlens.checks`.
Manual tests are single steps a human runs against a target and test accounts they are
authorized to use. They never describe automation, mass requests, or data extraction.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from reqlens.model import Concern, Confidence, Evidence, Finding

CATEGORIES: dict[str, str] = {
    "API1:2023": "Broken Object Level Authorization",
    "API2:2023": "Broken Authentication",
    "API3:2023": "Broken Object Property Level Authorization",
    "API4:2023": "Unrestricted Resource Consumption",
    "API5:2023": "Broken Function Level Authorization",
    "API7:2023": "Server Side Request Forgery",
    "API8:2023": "Security Misconfiguration",
    "API9:2023": "Improper Inventory Management",
}

WSTG_URL = "https://owasp.org/www-project-web-security-testing-guide/latest/"
_API = "https://owasp.org/API-Security/editions/2023/en/"
_CS = "https://cheatsheetseries.owasp.org/cheatsheets/"
_MDN = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/"
_PS = "https://portswigger.net/web-security/"

API1 = _API + "0xa1-broken-object-level-authorization/"
API2 = _API + "0xa2-broken-authentication/"
API3 = _API + "0xa3-broken-object-property-level-authorization/"
API5 = _API + "0xa5-broken-function-level-authorization/"
API8 = _API + "0xa8-security-misconfiguration/"
API9 = _API + "0xa9-improper-inventory-management/"
JWT_CS = _CS + "JSON_Web_Token_for_Java_Cheat_Sheet.html"
JWT_BCP = "https://www.rfc-editor.org/rfc/rfc8725"
PS_JWT = _PS + "jwt"


@dataclass(frozen=True)
class Entry:
    """Static knowledge about one kind of finding."""

    title: str
    category: str
    concern: Concern
    why: str
    manual_test: str
    learning: str
    wstg: tuple[str, ...] = ()
    references: tuple[str, ...] = field(default_factory=tuple)


def _e(title, category, concern, why, manual_test, learning, wstg=(), refs=()) -> Entry:
    return Entry(
        title, category, Concern(concern), why, manual_test, learning, tuple(wstg), tuple(refs)
    )


CATALOG: dict[str, Entry] = {
    # ---------------------------------------------------------------- headers
    "HDR-HSTS-MISSING": _e(
        "HSTS header missing",
        "API8:2023",
        "medium",
        "Without Strict-Transport-Security, a browser that follows an http:// link or a typed "
        "bare domain makes a plaintext request first. Someone on the same network can "
        "intercept it and keep the victim on HTTP (SSL stripping).",
        "Open http://<host>/ once in a browser with DevTools open. Note whether it redirects "
        "to HTTPS, then check whether any HTTPS response from this host sends "
        "Strict-Transport-Security.",
        "HSTS tells the browser: for the next max-age seconds, only ever use HTTPS for this "
        "host. It protects every visit after the first; HSTS preloading protects the first "
        "one too. A typical policy is max-age=31536000; includeSubDomains.",
        ["WSTG-CONF-07"],
        [
            _MDN + "Strict-Transport-Security",
            _CS + "HTTP_Strict_Transport_Security_Cheat_Sheet.html",
        ],
    ),
    "HDR-HSTS-WEAK": _e(
        "HSTS max-age is short",
        "API8:2023",
        "low",
        "A short max-age means the browser forgets the HTTPS-only rule quickly, reopening the "
        "first-request downgrade window.",
        "Read the Strict-Transport-Security header on an HTTPS response and compare max-age "
        "with the recommended minimum of 15552000 (180 days); one year is common.",
        "HSTS only protects for as long as max-age says. Very short values are often left "
        "over from a cautious rollout and never raised.",
        ["WSTG-CONF-07"],
        [_MDN + "Strict-Transport-Security"],
    ),
    "HDR-CSP-MISSING": _e(
        "Content-Security-Policy missing on HTML pages",
        "API8:2023",
        "medium",
        "CSP is the main browser-side defence that limits the damage of a cross-site "
        "scripting (XSS) bug. Without it, any injected script runs with full page access.",
        "Open one of the listed pages with DevTools > Network, select the document request, "
        "and confirm no Content-Security-Policy header (or <meta http-equiv> tag) is present.",
        "CSP is an allow-list the browser enforces: which origins may supply scripts, styles, "
        "frames and connections. A strong policy uses nonces or hashes for scripts and avoids "
        "'unsafe-inline'. It does not fix XSS, it contains it.",
        ["WSTG-CONF-12"],
        [_MDN + "Content-Security-Policy", _CS + "Content_Security_Policy_Cheat_Sheet.html"],
    ),
    "HDR-CSP-WEAK": _e(
        "Content-Security-Policy allows unsafe script sources",
        "API8:2023",
        "low",
        "Directives like 'unsafe-inline', 'unsafe-eval', or a wildcard script source let "
        "injected scripts run, which removes most of CSP's protection against XSS.",
        "Paste the policy from the evidence into Google's CSP Evaluator "
        "(csp-evaluator.withgoogle.com) and read which directives it marks as high risk.",
        "A CSP is only as strong as its script-src. 'unsafe-inline' allows any inline "
        "<script>; 'unsafe-eval' allows eval(); '*' or broad CDNs can host attacker code.",
        ["WSTG-CONF-12"],
        [_CS + "Content_Security_Policy_Cheat_Sheet.html"],
    ),
    "HDR-CSP-REPORT-ONLY": _e(
        "Content-Security-Policy is report-only",
        "API8:2023",
        "low",
        "Content-Security-Policy-Report-Only only reports violations; it blocks nothing.",
        "Confirm in DevTools that the page sends only the -Report-Only header, then check "
        "with the team whether enforcement was planned.",
        "Report-only mode is a rollout step: collect violations, fix them, then switch to "
        "the enforcing header. Staying in report-only leaves pages unprotected.",
        ["WSTG-CONF-12"],
        [_MDN + "Content-Security-Policy-Report-Only"],
    ),
    "HDR-FRAME-MISSING": _e(
        "Page can be framed (clickjacking protection missing)",
        "API8:2023",
        "medium",
        "Without X-Frame-Options or CSP frame-ancestors, another site can load this page in "
        "an invisible frame and trick a logged-in user into clicking buttons on it.",
        'Create a local HTML file containing <iframe src="<page URL>"></iframe>, open it in '
        "the browser where your test account is logged in, and see whether the page renders "
        "inside the frame.",
        "Clickjacking abuses the victim's own session: the attacker can't read the page, but "
        "can make the user click on it. CSP frame-ancestors 'none' (or 'self') is the modern "
        "fix; X-Frame-Options DENY/SAMEORIGIN is the older one.",
        ["WSTG-CLNT-09"],
        [_PS + "clickjacking", _CS + "Clickjacking_Defense_Cheat_Sheet.html"],
    ),
    "HDR-NOSNIFF-MISSING": _e(
        "X-Content-Type-Options: nosniff missing",
        "API8:2023",
        "low",
        "Without nosniff, browsers may guess a response's type. A file served as text could "
        "be run as script or style if an attacker can influence its content.",
        "Check the listed responses in DevTools for X-Content-Type-Options; if any endpoint "
        "serves user-uploaded files, note its Content-Type too.",
        "MIME sniffing was a convenience for misconfigured servers; today it's an attack "
        "surface. nosniff makes the browser trust the declared Content-Type.",
        ["WSTG-CONF-14"],
        [_MDN + "X-Content-Type-Options"],
    ),
    "HDR-REFERRER-MISSING": _e(
        "Referrer-Policy not set",
        "API8:2023",
        "info",
        "Without a policy, the browser default decides how much of the current URL is sent "
        "to other sites. Modern defaults are reasonable, but older browsers send full URLs.",
        "Look for Referrer-Policy on the listed pages; then check whether any of this app's "
        "URLs contain tokens or IDs that should not reach third parties.",
        "The Referer header leaks the page you came from. If URLs hold secrets (reset "
        "tokens, session IDs), that leak becomes an account-takeover path.",
        ["WSTG-CONF-14"],
        [_MDN + "Referrer-Policy"],
    ),
    "HDR-REFERRER-UNSAFE": _e(
        "Referrer-Policy sends full URLs to other sites",
        "API8:2023",
        "low",
        "unsafe-url (and no-referrer-when-downgrade) sends the full URL, including the query "
        "string, to every site a page links to or loads resources from.",
        "Find a page whose URL contains an identifier or token, click an external link from "
        "it in your test session, and inspect the Referer header in DevTools.",
        "Prefer strict-origin-when-cross-origin or stricter so other sites see at most your "
        "origin, never paths or query strings.",
        ["WSTG-CONF-14"],
        [_MDN + "Referrer-Policy"],
    ),
    "HDR-PERMISSIONS-MISSING": _e(
        "Permissions-Policy not set",
        "API8:2023",
        "info",
        "Permissions-Policy limits which powerful browser features (camera, geolocation, "
        "payment) pages and embedded frames may use. It's defence in depth.",
        "Check the listed pages for Permissions-Policy and list which browser features the "
        "app actually needs.",
        "Least privilege applied to the browser: turn off features you don't use so a "
        "compromised script or third-party frame can't use them either.",
        ["WSTG-CONF-14"],
        [_MDN + "Permissions-Policy"],
    ),
    "HDR-VERSION-DISCLOSURE": _e(
        "Software version disclosed in response headers",
        "API8:2023",
        "low",
        "Exact product versions let anyone look up known vulnerabilities (CVEs) for that "
        "version without probing further.",
        "Note the product and version from the evidence and look it up in a CVE database "
        "(e.g. nvd.nist.gov) to see whether it is still supported and patched.",
        "Version banners don't create vulnerabilities, but they remove guesswork for an "
        "attacker and often reveal unpatched software. Remove or genericise them.",
        ["WSTG-INFO-02"],
        [API8],
    ),
    # ---------------------------------------------------------------- cookies
    "CK-SECURE-MISSING": _e(
        "Cookie set without the Secure attribute",
        "API2:2023",
        "medium",
        "A cookie without Secure is also sent over plain HTTP. If the browser ever makes an "
        "HTTP request to this host, the cookie travels unencrypted.",
        "In DevTools > Application > Cookies, confirm the Secure column is unticked for this "
        "cookie on your test account.",
        "Secure keeps a cookie off unencrypted connections. Every session or auth cookie on "
        "an HTTPS site should have it; the __Host- prefix enforces it.",
        ["WSTG-SESS-02"],
        [_CS + "Session_Management_Cheat_Sheet.html", _MDN + "Set-Cookie"],
    ),
    "CK-HTTPONLY-MISSING": _e(
        "Session cookie readable by JavaScript (HttpOnly missing)",
        "API2:2023",
        "medium",
        "Without HttpOnly, any script on the page, including one injected through XSS, can "
        "read the session cookie and send it elsewhere.",
        "With your test account logged in, run document.cookie in the DevTools console and "
        "see whether this cookie's name appears.",
        "HttpOnly hides a cookie from JavaScript while still sending it with requests. It "
        "turns an XSS bug from 'steal the session' into the smaller 'act within the page'.",
        ["WSTG-SESS-02"],
        [_CS + "Session_Management_Cheat_Sheet.html"],
    ),
    "CK-SAMESITE-MISSING": _e(
        "Cookie set without SameSite",
        "API2:2023",
        "low",
        "Without an explicit SameSite, behaviour depends on the browser default (Lax in "
        "modern Chrome, not everywhere). Cross-site requests may carry the cookie, which "
        "enables cross-site request forgery (CSRF).",
        "Identify one state-changing request (e.g. updating a profile field on your test "
        "account) and check whether it needs a CSRF token in addition to the cookie.",
        "SameSite=Lax or Strict stops the browser from attaching the cookie to most "
        "cross-site requests. It is a strong CSRF defence, but should be explicit.",
        ["WSTG-SESS-02", "WSTG-SESS-05"],
        [_MDN + "Set-Cookie#samesitesamesite-value", _PS + "csrf/bypassing-samesite-restrictions"],
    ),
    "CK-SAMESITE-NONE-INSECURE": _e(
        "SameSite=None cookie without Secure",
        "API2:2023",
        "medium",
        "SameSite=None sends the cookie on every cross-site request. Browsers reject "
        "SameSite=None without Secure, so this cookie may silently fail or, in older "
        "browsers, be sent everywhere over HTTP.",
        "Check in DevTools > Application > Cookies whether the browser stored this cookie, "
        "and whether any cross-site flow (SSO, embedded widget) depends on it.",
        "SameSite=None is for cookies that must work cross-site; it requires Secure and "
        "usually a separate CSRF defence.",
        ["WSTG-SESS-02"],
        [_MDN + "Set-Cookie#samesitesamesite-value"],
    ),
    "CK-DOMAIN-BROAD": _e(
        "Cookie scoped to a parent domain",
        "API2:2023",
        "low",
        "A Domain attribute shares the cookie with every subdomain. Any other subdomain "
        "(including a forgotten or less secure one) receives the cookie and can overwrite it.",
        "List the subdomains of the cookie's domain that you know of and consider whether "
        "each one should receive this session cookie.",
        "Omitting Domain makes a host-only cookie, sent only to the exact host that set it. "
        "That is the safest default; the __Host- prefix enforces it.",
        ["WSTG-SESS-02"],
        [_MDN + "Set-Cookie#domaindomain-value"],
    ),
    "CK-SESSION-PERSISTENT": _e(
        "Long-lived session cookie",
        "API2:2023",
        "low",
        "A session cookie that persists for weeks survives browser restarts and stays valid "
        "on shared or lost devices.",
        "Log in with your test account, note the cookie's expiry in DevTools, close and "
        "reopen the browser, and see whether you are still logged in.",
        "Session lifetime is a trade-off between convenience and exposure. Pair long-lived "
        "'remember me' cookies with server-side idle and absolute timeouts, and rotate them.",
        ["WSTG-SESS-07"],
        [_CS + "Session_Management_Cheat_Sheet.html"],
    ),
    # ---------------------------------------------------------------- CORS
    "CORS-REFLECTED-ORIGIN": _e(
        "CORS reflects a foreign Origin",
        "API8:2023",
        "high",
        "The response allowed an Origin outside your scope. If the server echoes any Origin "
        "and also allows credentials, any website a logged-in user visits can read this "
        "endpoint's responses.",
        "Send this request once more (e.g. Burp Repeater) with the header Origin: "
        "https://reqlens-test.example and check whether Access-Control-Allow-Origin echoes "
        "it and Access-Control-Allow-Credentials is true.",
        "CORS relaxes the same-origin policy for origins the server trusts. Reflecting the "
        "Origin header blindly means trusting everyone. Use an explicit allow-list.",
        ["WSTG-CLNT-07"],
        [_PS + "cors", API8],
    ),
    "CORS-NULL-ORIGIN": _e(
        "CORS allows the 'null' origin",
        "API8:2023",
        "medium",
        "Sandboxed iframes and local files send Origin: null, so allowing 'null' is "
        "effectively allowing any attacker who uses a sandboxed frame.",
        "Send this request once with Origin: null and check the Access-Control-Allow-Origin "
        "and Access-Control-Allow-Credentials headers in the response.",
        "'null' is not a safe placeholder origin. Remove it from CORS allow-lists.",
        ["WSTG-CLNT-07"],
        [_PS + "cors"],
    ),
    "CORS-WILDCARD-CREDENTIALS": _e(
        "CORS wildcard combined with credentials",
        "API8:2023",
        "medium",
        "Access-Control-Allow-Origin: * with Allow-Credentials: true is rejected by browsers, "
        "but it shows the CORS policy is hand-built. Such servers often switch to reflecting "
        "the Origin to 'fix' the error.",
        "Send this request once with Origin: https://reqlens-test.example and check whether "
        "the server keeps '*' or echoes your origin.",
        "Credentials and wildcard can't be combined by design. If credentialed cross-origin "
        "access is needed, the server must name trusted origins explicitly.",
        ["WSTG-CLNT-07"],
        [_PS + "cors"],
    ),
    "CORS-WILDCARD-AUTHENTICATED": _e(
        "Authenticated endpoint allows any origin",
        "API8:2023",
        "low",
        "Any website may read this response cross-origin (without cookies). If the endpoint "
        "also accepts a bearer token or IP-based trust, data may be exposed.",
        "Check whether this endpoint returns user-specific data when called without cookies "
        "or Authorization (a plain request from a private browser window).",
        "Wildcard CORS is fine for public data, risky for anything authenticated by means "
        "other than cookies.",
        ["WSTG-CLNT-07"],
        [_PS + "cors"],
    ),
    # ---------------------------------------------------------------- JWT
    "JWT-ALG-NONE": _e(
        "JWT uses alg 'none' (unsigned token)",
        "API2:2023",
        "high",
        "An unsigned token can be edited by anyone who holds it: change a claim, keep "
        "alg: none, and nothing proves the change was not made by the server.",
        "Copy your own test-account token, change a harmless claim (e.g. a display name) in "
        "an offline JWT editor keeping alg none, send it once, and see whether the server "
        "accepts the change.",
        "A JWT's security comes entirely from its signature. alg 'none' exists in the spec "
        "for already-protected contexts and must never be accepted for authentication.",
        ["WSTG-SESS-10"],
        [PS_JWT, JWT_BCP, JWT_CS],
    ),
    "JWT-NONE-ACCEPTANCE": _e(
        "Test whether the server accepts unsigned JWTs (alg: none)",
        "API2:2023",
        "medium",
        "Some JWT libraries trust the alg named in the token header. If the server accepts "
        "alg 'none', anyone can forge tokens without any key.",
        "Copy your own test-account token into an offline JWT editor (jwt_tool, Burp JWT "
        "Editor), set alg to none (try 'none' and 'None'), remove the signature but keep the "
        "trailing dot, and send it once to an endpoint that needs authentication. A 401/403 "
        "is the expected, safe result.",
        "Servers must pin the expected algorithm in code instead of reading it from the "
        "token. This is one of the oldest JWT bugs and still appears in custom integrations.",
        ["WSTG-SESS-10"],
        [PS_JWT + "#accepting-tokens-with-no-signature", JWT_BCP],
    ),
    "JWT-SIGNATURE-CHECK": _e(
        "Test whether the JWT signature is verified at all",
        "API2:2023",
        "medium",
        "Some services decode the token without verifying its signature (e.g. calling "
        "decode() instead of verify()), so any edited token is trusted.",
        "Copy your own test-account token, change one character inside the signature (the "
        "third part), and send it once to an authenticated endpoint. Anything other than "
        "401/403 means the signature is not checked.",
        "Decoding a JWT only reads it; verifying checks the signature with the server's key. "
        "Every service that trusts the token, including internal ones, must verify.",
        ["WSTG-SESS-10"],
        [PS_JWT + "#accepting-arbitrary-signatures", JWT_CS],
    ),
    "JWT-ALG-CONFUSION": _e(
        "Algorithm confusion (asymmetric -> HS256) worth testing",
        "API2:2023",
        "medium",
        "With RS/ES/PS tokens the server verifies using a public key. If it also accepts "
        "HS256, an attacker can sign a forged token with HMAC using that public key (which is "
        "public) as the secret.",
        "Get the server's public key from its JWKS endpoint or certificate, then in an "
        "offline JWT editor (jwt_tool -X k, or Burp JWT Editor) re-sign a copy of your own "
        "token as HS256 with that key and send it once. Rejection (401/403) is the expected, "
        "safe result.",
        "Key confusion happens when verification code says 'verify with this key' without "
        "fixing the algorithm, and the library uses the RSA public key bytes as an HMAC "
        "secret. Fix: pin the algorithm (and key type) on the server side.",
        ["WSTG-SESS-10"],
        [PS_JWT + "/algorithm-confusion", JWT_BCP],
    ),
    "JWT-HMAC-WEAK-SECRET": _e(
        "HMAC-signed JWT: secret strength worth testing offline",
        "API2:2023",
        "medium",
        "HS256/384/512 tokens are signed with a shared secret. If that secret is short or a "
        "default (e.g. 'secret', a framework example), anyone with one token can forge others.",
        "Offline only, on your own captured token: run a wordlist check of known weak JWT "
        "secrets (e.g. hashcat -m 16500 or jwt_tool -C with a list such as jwt.secrets.list). "
        "Nothing is sent to the target.",
        "An HMAC secret must be long and random (at least as many bits as the hash, e.g. "
        "256 bits for HS256). Because anyone with one token can test guesses offline, weak "
        "secrets fail silently.",
        ["WSTG-SESS-10", "WSTG-CRYP-04"],
        [PS_JWT + "#brute-forcing-secret-keys", JWT_BCP],
    ),
    "JWT-KID-INJECTION": _e(
        "JWT 'kid' header present: key-lookup injection worth testing",
        "API2:2023",
        "medium",
        "The kid (key id) tells the server which key to verify with. If the server uses it "
        "in a file path, database query or command without validation, an attacker can "
        "point it at a key they control or know (e.g. an empty file).",
        "In an offline JWT editor, copy your own token, set kid to a path such as "
        "../../../../dev/null and sign it with an empty HMAC key, then send it once. Expect "
        "rejection; also note how the server responds to a kid that does not exist.",
        "kid should be an opaque identifier looked up in a fixed key set, never a path or "
        "query fragment. Treat every header field of an unverified token as attacker input.",
        ["WSTG-SESS-10"],
        [PS_JWT + "#injecting-self-signed-jwts-via-the-kid-parameter"],
    ),
    "JWT-JKU-X5U": _e(
        "JWT names a key URL (jku/x5u)",
        "API2:2023",
        "medium",
        "jku/x5u tell the server where to fetch the verification key. If it follows any URL, "
        "an attacker can host their own key and sign arbitrary tokens; it is also an SSRF "
        "vector.",
        "Copy your own token, change jku/x5u to a URL on a host you control (for example a "
        "request-catcher you own) and send it once. Check only whether your host receives a "
        "fetch; a fetch means the server trusts token-supplied key URLs.",
        "Key locations must come from server configuration or a strict allow-list, never "
        "from the token being verified.",
        ["WSTG-SESS-10"],
        [PS_JWT + "#injecting-self-signed-jwts-via-the-jku-parameter"],
    ),
    "JWT-EMBEDDED-JWK": _e(
        "JWT carries its own key (jwk/x5c header)",
        "API2:2023",
        "high",
        "A token that ships its own verification key is only safe if the server ignores it. "
        "If the server trusts the embedded key, anyone can sign tokens with their own key.",
        "In an offline JWT editor (Burp JWT Editor 'Embedded JWK' attack), sign a copy of "
        "your own token with a new key embedded in the header and send it once. Expect "
        "rejection.",
        "Verification keys must be configured on the server. CVE-2018-0114 is a classic "
        "example of a library trusting the embedded jwk.",
        ["WSTG-SESS-10"],
        [PS_JWT + "#injecting-self-signed-jwts-via-the-jwk-parameter"],
    ),
    "JWT-ECDSA-PSYCHIC": _e(
        "ECDSA JWT: check for invalid-signature acceptance",
        "API2:2023",
        "low",
        "Some ECDSA verifiers accepted signatures of all zeros ('psychic signatures', "
        "CVE-2022-21449 in Java 15-18).",
        "If the server is Java-based, copy your own token and replace the signature with an "
        "all-zero ECDSA signature in an offline JWT tool, then send it once. Expect rejection.",
        "ECDSA verification must reject r=0 or s=0. This is patched in current JDKs, so the "
        "test mainly confirms patch level.",
        ["WSTG-SESS-10"],
        ["https://nvd.nist.gov/vuln/detail/CVE-2022-21449"],
    ),
    "JWT-KEY-HYGIENE": _e(
        "Asymmetric JWT: review key strength and rotation",
        "API2:2023",
        "info",
        "Signature algorithms are only as strong as their keys. Short RSA keys (<2048 bits), "
        "keys that never rotate, and JWKS endpoints that still publish retired keys weaken "
        "every token.",
        "Fetch the issuer's JWKS (often /.well-known/jwks.json or the iss URL's openid "
        "configuration) and check each key's size, kid, and whether old keys are still "
        "listed.",
        "Keys need lifecycles: generation with adequate size, publication, rotation, and "
        "retirement. Tokens signed with a retired key should stop being accepted.",
        ["WSTG-SESS-10", "WSTG-CRYP-04"],
        [JWT_BCP],
    ),
    "JWT-EXP-MISSING": _e(
        "JWT has no expiry (exp claim missing)",
        "API2:2023",
        "medium",
        "Without exp, a leaked token stays valid until the signing key changes, which may be "
        "never.",
        "Keep a copy of a token from an old session of your test account and send it once "
        "after logging out (or a day later) to see whether it is still accepted.",
        "Bearer tokens are like cash: whoever holds them can spend them. Short lifetimes "
        "(minutes for access tokens) plus refresh tokens limit the damage of a leak.",
        ["WSTG-SESS-10", "WSTG-SESS-07"],
        [JWT_BCP, API2],
    ),
    "JWT-EXP-LONG": _e(
        "JWT lifetime is long",
        "API2:2023",
        "low",
        "A token valid for many hours or days gives a thief a long window, and JWTs usually "
        "cannot be revoked before they expire.",
        "Log out of your test account, then send a saved copy of its token once and see "
        "whether the server still accepts it (tests revocation as well as lifetime).",
        "Access tokens are typically short-lived (5-60 minutes). Long-lived sessions should "
        "use refresh tokens that the server can revoke.",
        ["WSTG-SESS-10", "WSTG-SESS-07"],
        [JWT_BCP],
    ),
    "JWT-SENSITIVE-CLAIMS": _e(
        "Personal or sensitive data inside a JWT",
        "API3:2023",
        "low",
        "JWT payloads are only base64-encoded, not encrypted. Anyone who sees the token "
        "(logs, browser storage, proxies) can read these claims.",
        "Decode a copy of your own token with a local tool such as jwt_tool (avoid pasting "
        "live tokens into websites) and "
        "list each claim the client really needs.",
        "Signing proves who issued data; it does not hide it. Keep tokens to identifiers and "
        "authorization facts, or use encrypted JWE if data must travel in the token.",
        ["WSTG-SESS-10"],
        [JWT_CS],
    ),
    "TOKEN-IN-URL": _e(
        "Secret token carried in the URL",
        "API2:2023",
        "medium",
        "URLs end up in browser history, server and proxy logs, analytics, and Referer "
        "headers sent to other sites. A token in the URL leaks through all of them.",
        "Open the listed URL's page in your test session, click an external link or load a "
        "third-party resource, and check in DevTools whether the token appears in the "
        "outgoing Referer header.",
        "Credentials belong in headers (Authorization) or cookies, not in query strings. "
        "Single-use, short-lived tokens (password reset links) reduce, but don't remove, "
        "the risk.",
        ["WSTG-SESS-04"],
        [API2],
    ),
    # ---------------------------------------------------------------- disclosure
    "DISC-STACKTRACE": _e(
        "Stack trace in a response",
        "API8:2023",
        "medium",
        "Stack traces reveal framework, file paths, library versions and code structure, "
        "and show that unexpected input reaches code that fails loudly.",
        "Repeat the listed request once with the same input on your test account and read "
        "the full error; note what internal detail it reveals.",
        "Production error handlers should log details server-side and return a generic "
        "message with a correlation id.",
        ["WSTG-ERRH-01", "WSTG-ERRH-02"],
        [_PS + "information-disclosure", API8],
    ),
    "DISC-SQL-ERROR": _e(
        "Database error message in a response",
        "API8:2023",
        "medium",
        "Raw database errors expose the database type and query structure, and often mean "
        "user input reaches SQL in a way that deserves a careful injection review.",
        "Look at which parameter the failing request carried, then (on your test account) "
        "send it once with a harmless value such as a single quote and compare the error.",
        "SQL injection happens when input is concatenated into queries. Parameterised "
        "queries prevent it; generic error pages stop the details leaking.",
        ["WSTG-ERRH-01", "WSTG-INPV-05"],
        [_PS + "sql-injection"],
    ),
    "DISC-DEBUG-PAGE": _e(
        "Framework debug page or verbose error page",
        "API8:2023",
        "medium",
        "Debug pages (Django DEBUG, Werkzeug, Laravel Whoops, ASP.NET yellow screen) can "
        "reveal settings, environment variables and source code; some allow code execution.",
        "Open the listed URL in your test session and read what the page exposes "
        "(settings, environment, source lines). Do not use any interactive console it offers.",
        "Debug mode is for development only. It is a common, high-impact misconfiguration.",
        ["WSTG-ERRH-01", "WSTG-CONF-02"],
        [_PS + "information-disclosure", API8],
    ),
    "DISC-INTERNAL-IP": _e(
        "Internal IP address disclosed",
        "API8:2023",
        "low",
        "Private addresses reveal internal network layout and are useful to an attacker "
        "planning SSRF or lateral movement.",
        "Find where the address appears in the listed response (header or field) and note "
        "which component (load balancer, upstream service) adds it.",
        "Responses should not mention internal hosts. Strip headers such as X-Backend-Server "
        "and avoid echoing upstream addresses in errors.",
        ["WSTG-INFO-05"],
        [_PS + "information-disclosure"],
    ),
    "DISC-INTERNAL-HOST": _e(
        "Internal hostname disclosed",
        "API8:2023",
        "low",
        "Internal hostnames (.internal, .local, .corp, localhost:port) reveal infrastructure "
        "and may be reachable through SSRF.",
        "Note where the hostname appears and which feature produced it; check whether any "
        "parameter of this app accepts URLs (a possible SSRF entry point).",
        "Internal names leak through redirects, error messages and config endpoints.",
        ["WSTG-INFO-05"],
        [_PS + "information-disclosure"],
    ),
    "DISC-FILE-PATH": _e(
        "Server file path disclosed",
        "API8:2023",
        "low",
        "Absolute paths reveal the operating system, deployment layout and user names, and "
        "help an attacker exploit path traversal or file inclusion bugs.",
        "Read the path in the evidence and note what it reveals (OS, framework, user).",
        "Paths usually leak through error messages and stack traces; fix the error handler.",
        ["WSTG-INFO-05", "WSTG-ERRH-01"],
        [_PS + "information-disclosure"],
    ),
    "DISC-VERSION-BODY": _e(
        "Software version disclosed in a response body",
        "API8:2023",
        "low",
        "Version strings in error pages or footers let anyone match known CVEs.",
        "Look up the product and version from the evidence in a CVE database.",
        "Default error pages of servers and frameworks often print their version; replace "
        "them with custom pages.",
        ["WSTG-INFO-02"],
        [API8],
    ),
    "DISC-PII-RESPONSE": _e(
        "Personal data in responses",
        "API3:2023",
        "info",
        "These responses return personal data. That may be expected (your own profile), but "
        "each one is worth checking for who else can retrieve it.",
        "Log in as a second test account and request the same endpoint (with the first "
        "account's identifier where one appears). The second account should not see the "
        "first account's personal data.",
        "Personal data exposure usually combines with an authorization flaw (BOLA). Map "
        "which endpoints return personal data, then test their access control.",
        ["WSTG-INFO-05", "WSTG-ATHZ-04"],
        [API3],
    ),
    "OBS-INSTRUCTION-TEXT": _e(
        "Instruction-like text in captured data",
        "API8:2023",
        "info",
        "Captured content contains text addressed to an AI or tool (e.g. 'ignore previous "
        "instructions'). reqlens treats it as data and never follows it, but its presence "
        "may indicate a prompt-injection attempt or test payload in the application.",
        "Find where the text comes from (user-generated content, a third-party feed) and "
        "consider whether any AI feature in the application reads that content.",
        "Prompt injection hides instructions in data an AI will read. Systems that feed "
        "user content to an AI must treat it as untrusted input.",
        ["WSTG-INPV"],
        ["https://genai.owasp.org/llmrisk/llm01-prompt-injection/"],
    ),
    # ---------------------------------------------------------------- access control
    "ACC-IDOR": _e(
        "Object identifier in request: test object-level authorization (BOLA/IDOR)",
        "API1:2023",
        "medium",
        "The request names an object by ID. If the server only checks that you are logged "
        "in, not that the object is yours, any user can read or change others' objects.",
        "Using two test accounts you control (A and B): copy this request from account A, "
        "replace the identifier with one that belongs to account B, and send it once with "
        "A's session. Seeing B's data or changing it means object-level authorization is "
        "missing.",
        "BOLA/IDOR is the most common serious API flaw. Sequential numeric IDs make it easy "
        "to find; random UUIDs make it harder but are not an access control.",
        ["WSTG-ATHZ-04"],
        [API1, _PS + "access-control/idor"],
    ),
    "ACC-EXCESSIVE-DATA": _e(
        "Response may expose more fields than needed",
        "API3:2023",
        "medium",
        "The response contains sensitive-looking fields. APIs often return whole database "
        "objects and rely on the front end to hide fields, but anyone can read the raw "
        "response.",
        "Compare the fields in this response with what the page actually displays for your "
        "test account; list any field the UI never shows.",
        "Excessive data exposure: filter responses on the server to the fields each client "
        "and role needs. Hiding them in the UI is not access control.",
        ["WSTG-INFO-05"],
        [API3],
    ),
    "ACC-MASS-ASSIGNMENT": _e(
        "Writable object with privileged-looking fields: test mass assignment",
        "API3:2023",
        "medium",
        "The object returned by the API has fields such as role or isAdmin that the client "
        "does not send when updating it. If the server binds every incoming field to the "
        "object, a user can set those fields themselves.",
        "On your test account, send this update request once with one extra field from the "
        'evidence added (e.g. "role": "admin" or "isAdmin": true), then reload the '
        "object to see whether the value changed.",
        "Mass assignment comes from frameworks that auto-bind request fields to models. Fix "
        "with an explicit allow-list of writable fields per role.",
        ["WSTG-INPV-20"],
        [API3, _CS + "Mass_Assignment_Cheat_Sheet.html"],
    ),
    "ACC-FUNCTION-LEVEL": _e(
        "Administrative or internal endpoint seen: test function-level authorization",
        "API5:2023",
        "low",
        "Endpoints named admin, internal, manage or debug often perform privileged actions. "
        "If they only check that a user is logged in, any user can call them.",
        "With a low-privilege test account, send the listed request once and check whether "
        "it is refused (401/403) or carried out.",
        "Function-level authorization means checking the caller's role for every privileged "
        "operation on the server, not just hiding the button.",
        ["WSTG-ATHZ-02"],
        [API5],
    ),
    # ---------------------------------------------------------------- caching
    "CACHE-AUTH-NO-STORE": _e(
        "Authenticated response may be cached",
        "API8:2023",
        "low",
        "Responses that require login but lack Cache-Control: no-store may be stored by the "
        "browser or shared caches, so personal data can survive logout on shared computers.",
        "Log in with your test account, view the listed page, log out, then press the "
        "browser Back button and see whether the authenticated content reappears.",
        "Use Cache-Control: no-store for authenticated responses that contain personal or "
        "sensitive data. 'private' only keeps shared caches out.",
        ["WSTG-ATHN-06"],
        [_MDN + "Cache-Control"],
    ),
    # ---------------------------------------------------------------- GraphQL
    "GQL-INTROSPECTION": _e(
        "GraphQL introspection enabled",
        "API9:2023",
        "medium",
        "Introspection returns the entire schema: every query, mutation and field, including "
        "ones the UI never uses (admin mutations, internal fields).",
        "Review the schema the response returned and list mutations or fields that the UI "
        "never calls; those are the first candidates for authorization tests.",
        "Introspection is a development convenience. In production it hands attackers a map; "
        "disable it or restrict it to trusted clients.",
        ["WSTG-APIT-01"],
        [_PS + "graphql", API9],
    ),
    "GQL-ENDPOINT": _e(
        "GraphQL endpoint in use",
        "API9:2023",
        "info",
        "GraphQL concentrates many operations behind one URL, so per-operation authorization, "
        "query depth limits and batching limits all need to be checked separately.",
        "For each operation in the evidence, note which test account roles should be able to "
        "call it; then test one operation at a time with a lower-privileged account.",
        "GraphQL's flexibility shifts security work from URLs to resolvers: each field and "
        "mutation needs its own authorization check.",
        ["WSTG-APIT-01"],
        [_PS + "graphql"],
    ),
    "GQL-FIELD-SUGGESTIONS": _e(
        "GraphQL field suggestions leak the schema",
        "API9:2023",
        "low",
        "'Did you mean ...?' errors reveal field names even when introspection is disabled.",
        "Send one query with a slightly misspelled field name on your test account and read "
        "whether the error suggests real field names.",
        "Disable suggestions in production along with introspection.",
        ["WSTG-APIT-01"],
        [_PS + "graphql"],
    ),
    # ---------------------------------------------------------------- hashes
    "HASH-PASSWORD-HASH-EXPOSED": _e(
        "Password hash returned by the API",
        "API3:2023",
        "high",
        "A value shaped like a password hash appears in a response. Password hashes should "
        "never leave the server; anyone who obtains them can attack them offline.",
        "Check which endpoint and field returns the value, and whether a second test account "
        "can retrieve the first account's hash (combine with the BOLA test).",
        "Even strong hashes (bcrypt, argon2) only slow attackers down. Exposing them turns an "
        "online guessing problem into an offline one.",
        ["WSTG-INFO-05", "WSTG-CRYP-04"],
        [API3],
    ),
    "HASH-DIGEST-EXPOSED": _e(
        "Hash-like value in a sensitive field",
        "API3:2023",
        "low",
        "A hex digest sits in a field whose name suggests a credential or secret. If it is a "
        "fast, unsalted hash of a password (MD5/SHA-1/SHA-256), it can be reversed offline.",
        "Identify what the field is for (ask the team or read the API docs) and whether it "
        "must be returned to clients at all.",
        "Fast hashes are for integrity, not passwords. Password storage needs a slow, salted "
        "algorithm such as argon2id or bcrypt.",
        ["WSTG-CRYP-04"],
        [_CS + "Password_Storage_Cheat_Sheet.html"],
    ),
    # ---------------------------------------------------------------- optional tools
    "EXT-JWT-TOOL": _e(
        "jwt_tool's offline reading of the captured JWT",
        "API2:2023",
        "info",
        "A second, independent tool decoded the same token structure. Agreement confirms the "
        "algorithm and header fields the JWT findings are based on; disagreement is worth a "
        "closer look before you test.",
        "Run jwt_tool yourself in decode mode on a copy of your own test-account token "
        "(python jwt_tool.py <token>, with no -t target and no -M/-X/-C mode) and compare.",
        "jwt_tool is a widely used JWT testing toolkit. reqlens uses only its decoder, on a "
        "token rebuilt from redacted parts, so it never sees your real token or contacts any "
        "server.",
        ["WSTG-SESS-10"],
        ["https://github.com/ticarpi/jwt_tool"],
    ),
    "EXT-HASHCAT-IDENTIFY": _e(
        "hashcat's hash-mode identification for a captured value's shape",
        "API3:2023",
        "info",
        "hashcat lists every hash mode whose structure matches the value's shape, which "
        "narrows down what the value could be (and how hard it would be to attack offline).",
        "Ask the team or the API documentation what the field contains, and whether clients "
        "need it at all.",
        "Hash identification is about structure: length, alphabet and prefix. Several "
        "algorithms share a shape (MD5, MD4 and NTLM are all 32 hex characters), so treat "
        "the list as candidates. reqlens gave hashcat a synthetic sample of the same shape, "
        "never the captured value, and used only --identify.",
        ["WSTG-CRYP-04"],
        ["https://hashcat.net/wiki/doku.php?id=example_hashes"],
    ),
}


def entry(check_id: str) -> Entry:
    """Look up a catalog entry; unknown ids are a programming error."""
    return CATALOG[check_id]


def make_finding(
    check_id: str,
    evidence: list[Evidence] | None = None,
    *,
    observed: str = "",
    concern: Concern | str | None = None,
    title: str | None = None,
    source: str = "rule",
    informational: bool = False,
) -> Finding:
    """Build a :class:`Finding` from the catalog entry for ``check_id``."""
    item = entry(check_id)
    level = Concern(concern) if concern is not None else item.concern
    return Finding(
        check_id=check_id,
        title=title or item.title,
        category=item.category,
        concern=level,
        why=item.why,
        manual_test=item.manual_test,
        learning=item.learning,
        confidence=Confidence.INFORMATIONAL
        if informational or level is Concern.INFO
        else Confidence.POSSIBLE,
        wstg=list(item.wstg),
        evidence=list(evidence or []),
        references=list(item.references),
        source=source,
        observed=observed,
        occurrences=len(evidence or []),
    )
