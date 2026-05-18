"""Capture real CLI output as crisp SVG 'screenshots' using rich's recorder.

Run:  python3 scripts/capture_cli.py
"""
from __future__ import annotations

import http.server
import json
import os
import socketserver
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rich.console import Console
from rich.terminal_theme import MONOKAI

import aegis.cli as cli
from aegis.config import AegisConfig
from aegis.orchestrator import Orchestrator

ASSETS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "assets")
os.makedirs(ASSETS, exist_ok=True)


class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        time.sleep(0.01)
        b = json.dumps({"status": "success"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)


def serve():
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 8867), H)
    srv.allow_reuse_address = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()


def save(rec: Console, name: str, title: str):
    rec.save_svg(os.path.join(ASSETS, name), title=title,
                 theme=MONOKAI, clear=True)
    print("saved", name)


def main():
    serve()

    # --- doctor (live Ollama probe) ---
    rec = Console(record=True, width=92)
    cli.con = rec
    try:
        cli.doctor(config=None)
    except SystemExit:
        pass
    save(rec, "cli-doctor.svg", "aegis doctor")

    # --- run + offensive scan (heuristic for a fast, deterministic capture) ---
    rec = Console(record=True, width=100)
    cli.con = rec
    cli._banner()
    cfg = AegisConfig.load()
    cfg.ollama.enabled = False
    cfg.safety.authorized = True
    orch = Orchestrator(cfg)
    rec.print("[cyan]$ aegis scan \"http://127.0.0.1:8867/api?id=1\" "
              "--offensive[/]")
    code = cli._execute(orch, raw="http://127.0.0.1:8867/api/orders?id=1",
                        input_type="auto", plan=None, goal="",
                        ai_plan=False, offensive=True, save=False,
                        formats="json")
    rec.print(f"[dim]exit code: {code}[/]")
    save(rec, "cli-scan.svg", "aegis scan  —  offensive + defensive")


if __name__ == "__main__":
    main()
