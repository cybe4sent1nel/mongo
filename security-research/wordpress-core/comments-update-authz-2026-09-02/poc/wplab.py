#!/usr/bin/env python3
"""Small helper for driving the local WordPress 7.1 lab over real HTTP."""
import re
import sys
import requests

BASE = "http://127.0.0.1:8371"

CREDS = {
    "admin": "AdminPass123!",
    "editor": "Pass123!editor",
    "author": "Pass123!author",
    "contributor": "Pass123!contributor",
    "subscriber": "Pass123!subscriber",
}


class Session:
    def __init__(self, user):
        self.user = user
        self.s = requests.Session()
        self.s.headers["User-Agent"] = "wp71-audit"
        self.rest_nonce = None

    def login(self):
        r = self.s.post(
            BASE + "/wp-login.php",
            data={
                "log": self.user,
                "pwd": CREDS[self.user],
                "wp-submit": "Log In",
                "redirect_to": BASE + "/wp-admin/",
                "testcookie": "1",
            },
            allow_redirects=False,
        )
        assert any(c.startswith("wordpress_logged_in") for c in self.s.cookies.keys()), (
            f"login failed for {self.user}: {r.status_code}"
        )
        return self

    def fetch_rest_nonce(self):
        r = self.s.get(BASE + "/wp-admin/index.php")
        m = re.search(r'wpApiSettings.*?"nonce":"([a-f0-9]+)"', r.text)
        if not m:
            m = re.search(r'createNonceMiddleware\(\s*"([a-f0-9]+)"', r.text)
        if not m:
            m = re.search(r'"nonce":"([a-f0-9]{10})"', r.text)
        assert m, "no rest nonce found"
        self.rest_nonce = m.group(1)
        return self.rest_nonce

    def rest(self, method, route, **kw):
        if self.rest_nonce is None:
            self.fetch_rest_nonce()
        headers = kw.pop("headers", {})
        headers["X-WP-Nonce"] = self.rest_nonce
        url = BASE + "/index.php?rest_route=" + route
        return self.s.request(method, url, headers=headers, **kw)

    def get(self, path, **kw):
        return self.s.get(BASE + path, **kw)

    def admin_nonce(self, path, name):
        """Scrape a named nonce out of an admin page."""
        r = self.s.get(BASE + path)
        m = re.search(r'name="%s"\s+value="([a-zA-Z0-9]+)"' % re.escape(name), r.text)
        if not m:
            m = re.search(r'%s=([a-zA-Z0-9]+)' % re.escape(name), r.text)
        return m.group(1) if m else None


def sess(user):
    return Session(user).login()


if __name__ == "__main__":
    u = sys.argv[1] if len(sys.argv) > 1 else "admin"
    s = sess(u)
    print("logged in as", u, "rest nonce:", s.fetch_rest_nonce())
