"""Exercise actual Keycloak PKCE login through HTTPS; no third-party packages.

This checks HTTP interoperability, not browser SameSite or JavaScript behavior.
"""
import html.parser
import http.cookiejar
import ssl
import urllib.error
import urllib.parse
import urllib.request

BASE = "https://localhost:8443"


class LocalhostCookiePolicy(http.cookiejar.DefaultCookiePolicy):
    def return_ok_secure(self, cookie, request):
        # Browsers treat localhost as trustworthy, including Keycloak's Secure
        # cookies on HTTP. Model that exception only for this local IdP, keeping
        # the console's Secure cookie restricted to HTTPS.
        url = urllib.parse.urlsplit(request.get_full_url())
        if (
            (url.scheme, url.netloc) == ("http", "localhost:8080")
            and cookie.path.startswith("/realms/mcp/")
        ):
            return True
        return super().return_ok_secure(cookie, request)


class LoginForm(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.action = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form" and attrs.get("id") == "kc-form-login":
            self.action = attrs["action"]


def check_user(user):
    jar = http.cookiejar.CookieJar(policy=LocalhostCookiePolicy())
    # Trust only this stack's generated certificate, rather than disabling TLS.
    context = ssl.create_default_context(cafile="/tls/localhost.crt")
    client = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar),
        urllib.request.HTTPSHandler(context=context),
    )
    with client.open(BASE + "/console/login", timeout=30) as response:
        form = LoginForm()
        form.feed(response.read().decode())
    assert form.action, "Keycloak did not return its login form"
    # Never submit even development credentials to an unexpected endpoint.
    target = urllib.parse.urlsplit(form.action)
    assert (target.scheme, target.netloc) == ("http", "localhost:8080")
    body = urllib.parse.urlencode({
        "username": user, "password": user + "-password", "credentialId": ""
    }).encode()
    with client.open(form.action, data=body, timeout=30) as response:
        landing = response.read().decode()
        assert response.url.startswith(BASE + "/console/callback"), "Unexpected callback"
        assert "Continue" in landing, "Console did not establish a session"
    assert any(c.name == "mcp_console_session" and c.secure for c in jar)
    for page in ("policy", "policy/edit", "activity", "access-review", "usage",
                 "sessions", "artifacts", "proposals", "health"):
        with client.open(BASE + "/console/" + page, timeout=30) as response:
            assert response.status == 200, (page, response.status)
            assert response.url == BASE + "/console/" + page, response.url
            assert response.headers.get("Content-Security-Policy")
            assert "admin_backend_unavailable" not in response.read().decode()
    # Cookie authentication must not bypass the console's Origin check.
    try:
        client.open(BASE + "/console/logout", data=b"", timeout=30)
    except urllib.error.HTTPError as error:
        assert error.code == 403, error.code
    else:
        raise AssertionError("Logout without Origin was accepted")
    request = urllib.request.Request(BASE + "/console/logout", data=b"",
                                     headers={"Origin": BASE})
    with client.open(request, timeout=30) as response:
        assert response.status == 200
    assert not any(c.name == "mcp_console_session" for c in jar)
    print(user + ": PKCE login, nine console pages, CSRF refusal and logout passed")


for username in ("alice", "bob"):
    check_user(username)
