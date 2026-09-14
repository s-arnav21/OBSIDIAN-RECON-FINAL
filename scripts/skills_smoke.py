"""Functional smoke test — run the same skill against a local fixture in both.

Start an ephemeral HTTP server with deliberately weak/missing security
headers, execute the `security-headers` skill via the Skill base/SkillContext
APIs, and print the resulting RawFindings as JSON. Running this from each
project and diffing the output proves end-to-end behavior is identical.

    cd <project>/backend && python <path>/skills_smoke.py
"""
from __future__ import annotations

import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.getcwd())


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        body = b"<html><head><title>fixture</title></head><body>ok</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Server", "fixture/1.0")
        # Deliberately NOT setting CSP / HSTS / X-Frame-Options / nosniff.
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # quiet
        pass


def main() -> None:
    from skills import load_all_skills, get_skill
    from skills.base import SkillContext

    load_all_skills()

    server = HTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        ctx = SkillContext(
            target_url=f"http://127.0.0.1:{port}/",
            host="127.0.0.1",
            port=port,
            scheme="http",
            authorized=True,
            scan_id="smoke-test",
            open_ports=[port],
        )
        skill = get_skill("security-headers")
        result = skill.run(ctx)
        rows = [{
            "skill": result.skill_name,
            "success": result.success,
            "findings": [
                {
                    "scanner_template_id": f.scanner_template_id,
                    "vulnerability_type": f.vulnerability_type,
                    "severity": f.severity,
                    "url": f.url,
                    "description": f.description,
                    "raw": f.raw,
                }
                for f in sorted(
                    result.findings,
                    key=lambda f: (f.scanner_template_id, f.description or ""),
                )
            ],
            "error": result.error,
        }]
        json.dump({"context": f"http://127.0.0.1:{port}/",
                   "runs": rows}, sys.stdout, indent=2, sort_keys=True)
        print()
    finally:
        server.shutdown()
        thread.join()


if __name__ == "__main__":
    main()