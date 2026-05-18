"""Drive the real AEGIS GUI under Xvfb and capture screenshots + a demo GIF.

Run:  xvfb-run -a -s "-screen 0 1360x920x24" python3 scripts/capture_gui.py
"""
from __future__ import annotations

import http.server
import json
import os
import socketserver
import subprocess
import sys
import threading
import time
import tkinter as tk

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Neutralise modal dialogs (they block the Xvfb event loop).
from tkinter import messagebox
messagebox.showinfo = lambda *a, **k: None
messagebox.showwarning = lambda *a, **k: None
messagebox.showerror = lambda *a, **k: print("DIALOG-ERROR:", a, k)

from aegis.config import AegisConfig
from aegis.gui import AegisGUI

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ASSETS = os.path.join(ROOT, "assets")
os.makedirs(ASSETS, exist_ok=True)


class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        time.sleep(0.015)
        b = json.dumps({"status": "success", "data": [1, 2, 3]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)
    do_POST = do_GET


def serve():
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 8866), H)
    srv.allow_reuse_address = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()


def shot(name):
    subprocess.run(["import", "-window", "root",
                     os.path.join(ASSETS, name)], check=False)
    print("shot", name, flush=True)


def main():
    serve()
    cfg = AegisConfig.load()
    cfg.safety.authorized = True
    cfg.ollama.enabled = False  # deterministic, fast, offline for the capture
    root = tk.Tk()
    app = AegisGUI(root, cfg)
    app.authorized.set(True)
    app.offensive.set(True)
    app.input.delete("1.0", "end")
    app.input.insert("1.0", "http://127.0.0.1:8866/api/v1/users?id=1")
    app.v_requests.set(140)
    app.v_concurrency.set(14)

    st = {"i": 0, "frames": [], "phase": "idle", "done_at": None}

    def tick():
        i = st["i"]
        st["i"] += 1
        ph = st["phase"]

        if ph == "idle":
            if i == 5:
                shot("gui-idle.png")
            if i == 8:
                app._start()
                st["phase"] = "running"
            root.after(220, tick)
            return

        if ph == "running":
            if i % 3 == 0 and len(st["frames"]) < 16:
                f = os.path.join(ASSETS, f"_f{i:03d}.png")
                subprocess.run(["import", "-window", "root", f], check=False)
                st["frames"].append(f)
            running = app.worker is not None and app.worker.is_alive()
            if not running and app.report is not None:
                st["phase"] = "settle"
                st["done_at"] = i
            root.after(200, tick)
            return

        if ph == "settle":
            # let donut sweep + charts render
            if i == st["done_at"] + 8:
                shot("gui-results.png")
            elif i == st["done_at"] + 12:
                app._show_tab(1)
            elif i == st["done_at"] + 18:
                shot("gui-endpoints.png")
                app._show_tab(2)
            elif i == st["done_at"] + 24:
                shot("gui-security.png")
                app._show_tab(3)
            elif i == st["done_at"] + 32:
                shot("gui-charts.png")
                _gif(st["frames"])
                root.quit()
                return
            root.after(220, tick)

    root.after(500, tick)
    root.after(60000, root.quit)
    root.mainloop()
    try:
        root.destroy()
    except tk.TclError:
        pass


def _gif(frames):
    frames = [f for f in frames if os.path.exists(f)]
    if len(frames) >= 3:
        subprocess.run(
            ["convert", "-delay", "20", "-loop", "0", "-resize", "900x",
             *frames, "-layers", "Optimize",
             os.path.join(ASSETS, "gui-demo.gif")], check=False)
        print("gif gui-demo.gif", flush=True)
    for f in frames:
        try:
            os.remove(f)
        except OSError:
            pass


if __name__ == "__main__":
    main()
