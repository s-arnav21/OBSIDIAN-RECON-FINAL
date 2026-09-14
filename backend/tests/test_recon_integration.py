"""Integration tests for the recon pipeline."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pipeline.recon import run_recon, domain_of


class TestDomainOf:
    def test_bare_url(self):
        assert domain_of("https://example.com/path") == "example.com"

    def test_with_port(self):
        assert domain_of("http://localhost:8080") == "localhost"

    def test_bare_domain(self):
        assert domain_of("example.com") == "example.com"


class TestRunRecon:
    def test_unreachable_target(self):
        result = run_recon("http://127.0.0.1:1")
        assert result.live is not None
        assert result.live.reachable is False
        assert result.dns is not None
        assert result.fingerprint is not None
        assert result.total_assets == 1

    def test_result_structure(self):
        result = run_recon("http://127.0.0.1:1")
        d = result.to_dict()
        assert "target" in d
        assert "dns" in d
        assert "live" in d
        assert "fingerprint" in d
        assert "assets" in d
        assert "timestamp" in d
        assert len(d["assets"]) == 1

    def test_primary_asset_flagged(self):
        result = run_recon("http://127.0.0.1:1")
        assert result.primary_asset is not None
        assert result.primary_asset.is_primary is True
