"""Regression tests for the .ac.in scope bug and soft-404 suppression.

Bug: ``portal.svkm.ac.in`` was scoped to ``ac.in`` instead of ``svkm.ac.in``,
so the passive subdomain scanner enumerated (and the deep-scan chained)
EVERY ``.ac.in`` website — producing cross-domain findings like
``http://abie.ac.in/db.sql.gz`` in a scan of a single NMIMS portal host.

These tests pin the public-suffix-aware registrable-domain logic (shared by
the subdomain scanner and the base skill) and the http_probe soft-404 guard.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pipeline.domains import (  # noqa: E402
    MULTI_LABEL_SUFFIXES,
    is_under_domain,
    registrable_domain,
)
from pipeline.scanner import subdomains_httpx  # noqa: E402
from pipeline.scanner.http_probe import HttpProbeScanner  # noqa: E402


class _Resp:
    """Minimal stand-in for requests.Response (classify reads these fields)."""

    def __init__(self, status=200, content_type="text/html", text=""):
        self.status_code = status
        self.headers = {"content-type": content_type}
        self.text = text


class TestRegistrableDomain:
    def test_plain_two_labels(self):
        assert registrable_domain("example.com") == "example.com"

    def test_simple_subdomain(self):
        assert registrable_domain("a.b.example.com") == "example.com"

    def test_ac_in_is_not_a_registrable_domain(self):
        assert registrable_domain("portal.svkm.ac.in") == "svkm.ac.in"

    def test_ac_in_apex(self):
        assert registrable_domain("svkm.ac.in") == "svkm.ac.in"

    def test_deeply_nested_ac_in(self):
        assert registrable_domain("cdn.api.portal.svkm.ac.in") == "svkm.ac.in"

    def test_co_uk(self):
        assert registrable_domain("mail.example.co.uk") == "example.co.uk"

    def test_com_au(self):
        assert registrable_domain("shop.example.com.au") == "example.com.au"

    def test_suffix_table_present(self):
        assert "ac.in" in MULTI_LABEL_SUFFIXES
        assert "co.uk" in MULTI_LABEL_SUFFIXES


class TestUnderDomain:
    def test_apex_is_in_scope(self):
        assert is_under_domain("svkm.ac.in", "svkm.ac.in") is True

    def test_subdomain_is_in_scope(self):
        assert is_under_domain("portal.svkm.ac.in", "svkm.ac.in") is True
        assert is_under_domain("cdn.api.svkm.ac.in", "svkm.ac.in") is True

    def test_sibling_ac_in_site_is_OUT_of_scope(self):
        # The exact bug: unrelated .ac.in colleges must never match svkm.ac.in.
        assert is_under_domain("abie.ac.in", "svkm.ac.in") is False
        assert is_under_domain("aaacet.ac.in", "svkm.ac.in") is False
        assert is_under_domain("bvicam.ac.in", "svkm.ac.in") is False
        assert is_under_domain("charusat.ac.in", "svkm.ac.in") is False

    def test_lookalike_is_out_of_scope(self):
        assert is_under_domain("evilsvkm.ac.in", "svkm.ac.in") is False
        assert is_under_domain("svkm.ac.in.evil.com", "svkm.ac.in") is False


class TestScannerScopeHelpers:
    def test_scanner_module_uses_shared_helpers(self):
        assert subdomains_httpx._registrable("portal.svkm.ac.in") == "svkm.ac.in"
        assert subdomains_httpx._under_domain(
            "abie.ac.in", "svkm.ac.in") is False
        assert subdomains_httpx._under_domain(
            "portal.svkm.ac.in", "svkm.ac.in") is True

    def test_candidate_filter_keeps_only_in_scope(self):
        registrable = registrable_domain("portal.svkm.ac.in")
        candidates = {
            "portal.svkm.ac.in",      # the target itself
            "svkm.ac.in",             # the apex
            "usermgmt.svkm.ac.in",    # in scope
            "abie.ac.in",             # sibling college — must be dropped
            "bvicam.ac.in",           # sibling college — must be dropped
            "charusat.ac.in",         # sibling college — must be dropped
        }
        kept = {c for c in candidates if is_under_domain(c, registrable)}
        assert kept == {
            "portal.svkm.ac.in", "svkm.ac.in", "usermgmt.svkm.ac.in",
        }
        assert not any("ac.in" in c and not c.endswith("svkm.ac.in")
                       for c in kept)


class TestSoft404Suppression:
    def test_generic_html_body_is_suppressed(self):
        # dump.sql returning a generic HTML 200 is a soft-404, not a leak.
        resp = _Resp(status=200, content_type="text/html",
                     text="<!doctype html><html><head><title>Not Found</title>"
                          "</head><body>Object not found!</body></html>")
        assert HttpProbeScanner._classify_config("dump.sql", resp) is None
        assert HttpProbeScanner._classify_config("id_rsa", resp) is None

    def test_api_docs_generic_body_is_suppressed(self):
        resp = _Resp(status=200, content_type="text/html",
                     text="<html><body>welcome to our website</body></html>")
        assert HttpProbeScanner._classify_config("api-docs", resp) is None

    def test_real_file_body_still_reported(self):
        # A genuine SQL dump has no HTML structure — it must stay CRITICAL.
        resp = _Resp(status=200, content_type="application/octet-stream",
                     text="-- MySQL dump\nCREATE TABLE users (\n  id int,"
                          "\n  password varchar(255)\n);\nINSERT ...")
        result = HttpProbeScanner._classify_config("dump.sql", resp)
        assert result is not None
        assert result[0] == "critical"

    def test_cloudflare_challenge_body_is_suppressed(self):
        resp = _Resp(status=200, content_type="text/html",
                     text="<html><head><title>Just a moment...</title></head>"
                          "<body>Checking your browser before proceeding."
                          "cloudflare</body></html>")
        assert HttpProbeScanner._classify_config("dump.sql", resp) is None
        assert HttpProbeScanner._classify_config("access.log", resp) is None