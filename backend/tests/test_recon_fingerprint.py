"""Tests for technology fingerprinting module."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pipeline.recon.fingerprint import fingerprint


class TestFingerprint:
    def test_nginx_server(self):
        headers = {"server": "nginx/1.24.0"}
        result = fingerprint(headers)
        assert "nginx" in result.technologies
        assert result.categories["nginx"] == "server"

    def test_apache_with_php(self):
        headers = {"server": "Apache/2.4.57", "x-powered-by": "PHP/8.1.0"}
        result = fingerprint(headers)
        assert "apache" in result.technologies
        assert "php" in result.technologies

    def test_wordpress_in_body(self):
        headers = {"server": "nginx"}
        body = '<link rel="stylesheet" href="/wp-content/themes/style.css">'
        result = fingerprint(headers, body)
        assert "wordpress" in result.technologies

    def test_empty_input(self):
        result = fingerprint({}, "")
        assert result.technologies == []
        assert result.categories == {}

    def test_no_duplicates(self):
        headers = {"server": "nginx", "x-powered-by": "nginx"}
        result = fingerprint(headers)
        assert result.technologies.count("nginx") == 1

    def test_sorted_output(self):
        headers = {"server": "apache", "x-powered-by": "PHP/8.1"}
        result = fingerprint(headers)
        assert result.technologies == sorted(result.technologies)

    def test_fastapi_detected(self):
        headers = {"server": "uvicorn"}
        result = fingerprint(headers)
        assert "uvicorn" in result.technologies

    def test_to_dict(self):
        result = fingerprint({"server": "nginx"})
        d = result.to_dict()
        assert "technologies" in d
        assert "categories" in d
        assert isinstance(d["technologies"], list)
