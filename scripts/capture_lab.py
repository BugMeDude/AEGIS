"""Capture a real WORKING LAB snapshot of the AEGIS GUI.

Uses the actual local config (aegis.yaml: lab_mode + gemma4:31b-cloud), so
the header shows the real LLM engine and the LAB MODE ribbon. Runs a small
authorised localhost test with offensive scan + HTTP/2 so every results tab
is populated, then screenshots idle / results / endpoints / security / charts
and builds the demo GIF.

Run:  xvfb-run -a -s "-screen 0 1600x940x24" python3 scripts/capture_lab.py
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

from tkinter import messagebox
messagebox.showinfo = lambda *a, **k: None
messagebox.showwarning = lambda *a, **k: None
messagebox.showerror = lambda *a, **k: print("DIALOG-ERROR:", a, k)

from aegis.config import AegisConfig
from aegis.gui import AegisGUI

ASSETS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "assets")
os.makedirs(ASSETS, exist_ok=True)


class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        time.sleep(0.012)
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
    cfg = AegisConfig.load()                 # REAL lab config (gemma + lab_mode)
    root = tk.Tk()
    app = AegisGUI(root, cfg)
    app.input.delete("1.0", "end")
    app.input.insert("1.0", "http://127.0.0.1:8866/api/v1/users?id=1")
    app.http2.set(True)
    app.offensive.set(True)
    app.v_requests.set(28)
    app.v_concurrency.set(8)
    app.v_timeout.set(8)

    st = {"i": 0, "frames": [], "phase": "idle", "done": None}

    def tick():
        i = st["i"]
        st["i"] += 1
        ph = st["phase"]
        if ph == "idle":
            if i == 4:
                app._set_mode("autopilot")     # show live mode selection
            if i == 7:
                shot("gui-idle.png")
            if i == 10:
                app._set_mode("manual")        # manual small run
                app._start()
                st["phase"] = "run"
            root.after(260, tick)
            return
        if ph == "run":
            if i % 3 == 0 and len(st["frames"]) < 16:
                f = os.path.join(ASSETS, f"_f{i:03d}.png")
                subprocess.run(["import", "-window", "root", f], check=False)
                st["frames"].append(f)
            alive = app.worker is not None and app.worker.is_alive()
            if not alive and app.report is not None:
                st["phase"] = "settle"
                st["done"] = i
            root.after(300, tick)
            return
        if ph == "settle":
            d = st["done"]
            if i == d + 6:
                shot("gui-results.png")
            elif i == d + 11:
                app._show_tab(1)
            elif i == d + 16:
                shot("gui-endpoints.png")
                app._show_tab(2)
            elif i == d + 21:
                shot("gui-security.png")
                app._show_tab(3)
            elif i == d + 28:
                shot("gui-charts.png")
                _gif(st["frames"])
                root.quit()
                return
            root.after(280, tick)

    root.after(500, tick)
    root.after(180000, root.quit)            # generous: real gemma calls
    root.mainloop()
    try:
        root.destroy()
    except tk.TclError:
        pass


def _gif(frames):
    frames = [f for f in frames if os.path.exists(f)]
    if len(frames) >= 3:
        subprocess.run(["convert", "-delay", "22", "-loop", "0",
                         "-resize", "900x", *frames, "-layers", "Optimize",
                         os.path.join(ASSETS, "gui-demo.gif")], check=False)
        print("gif gui-demo.gif", flush=True)
    for f in frames:
        try:
            os.remove(f)
        except OSError:
            pass


if __name__ == "__main__":
    main()
