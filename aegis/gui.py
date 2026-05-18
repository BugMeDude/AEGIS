"""AEGIS desktop GUI — calm frosted-glass edition, responsive.

A restrained, mostly-monochrome glass aesthetic (one accent) with generous
whitespace, inspired by modern glassmorphism references. The layout is fully
responsive: the left control column is fixed-width, the right results column
and the background fill the window, so maximise / full-screen genuinely use
the whole screen instead of sitting centred.

Still a thin shell over :class:`Orchestrator` (worker thread + queue +
``after`` pump) so the engine never blocks the UI.
"""

from __future__ import annotations

import math
import os
import queue
import threading
import tkinter as tk
from collections import deque
from tkinter import filedialog, messagebox, ttk

from . import __version__
from .config import AegisConfig
from .models import RunReport
from .orchestrator import Orchestrator
from .reporting import write_reports
from .safety import SafetyError

EDU_CAPTION_GUI = ("Educational & Research Edition  ·  Offensive + Defensive"
                   "  ·  authorised testing only")

try:
    from PIL import Image, ImageTk
    _HAS_PIL = True
except Exception:  # pragma: no cover
    _HAS_PIL = False

try:
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    from matplotlib.figure import Figure
    _HAS_MPL = True
except Exception:  # pragma: no cover
    _HAS_MPL = False

ASSETS = os.path.join(os.path.dirname(os.path.dirname(__file__)), "assets")

# Calm, near-monochrome palette — one accent.
C = dict(
    bg="#0e1217", bg2="#10151c",
    panel="#161b24", panel2="#1b212c", inset="#10141b",
    line="#272f3b", hi="#39424f",
    ink="#e8ecf3", mut="#8b93a3", faint="#5b6373",
    acc="#6b8afd", acc_d="#5677e6", acc_soft="#22305a",
    ok="#4cc3a3", warn="#d8a24a", danger="#df6b6b",
)
SEV = {"Critical": C["danger"], "High": "#e58f8f", "Medium": C["warn"],
       "Low": C["acc"], "Info": C["mut"]}


def _hx(c):
    c = c.lstrip("#")
    return tuple(int(c[i:i + 2], 16) for i in (0, 2, 4))


def _mix(a, b, t):
    a, b = _hx(a), _hx(b)
    return "#%02x%02x%02x" % tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3))


def _round(cv, x0, y0, x1, y1, r, **kw):
    pts = [x0 + r, y0, x1 - r, y0, x1, y0, x1, y0 + r, x1, y1 - r, x1, y1,
           x1 - r, y1, x0 + r, y1, x0, y1, x0, y1 - r, x0, y0 + r, x0, y0]
    return cv.create_polygon(pts, smooth=True, **kw)


# --------------------------------------------------------------------------- #
class Btn(tk.Canvas):
    """Rounded button. kind: primary | ghost | danger. Reliable click."""

    def __init__(self, master, text, command, *, w=140, h=42, kind="primary"):
        super().__init__(master, width=w, height=h, bg=C["panel"],
                          highlightthickness=0, bd=0, cursor="hand2")
        self.cmd, self.w, self.h, self.kind = command, w, h, kind
        self._txt = text
        self._hover = 0.0
        self._press = False
        self._enabled = True
        self._anim = None
        self.bind("<Enter>", lambda e: self._tw(1))
        self.bind("<Leave>", self._lv)
        self.bind("<ButtonPress-1>", self._dn)
        self.bind("<ButtonRelease-1>", self._up)
        self._draw()

    def set_bg(self, color):
        self.configure(bg=color)
        self._draw()

    def config_state(self, enabled):
        self._enabled = enabled
        self.configure(cursor="hand2" if enabled else "arrow")
        self._draw()

    def set_text(self, t):
        self._txt = t
        self._draw()

    def _lv(self, _e):
        self._press = False
        self._tw(0)

    def _dn(self, _e):
        if self._enabled:
            self._press = True
            self._draw()

    def _up(self, e):
        if not self._enabled:
            return
        was = self._press
        self._press = False
        self._draw()
        if was and 0 <= e.x <= self.w and 0 <= e.y <= self.h:
            self.after(10, self.cmd)

    def _tw(self, target):
        if self._anim:
            self.after_cancel(self._anim)
            self._anim = None

        def run():
            self._hover += (target - self._hover) * 0.3
            if abs(target - self._hover) < 0.04:
                self._hover = target
                self._draw()
                return
            self._draw()
            self._anim = self.after(16, run)
        run()

    def _draw(self):
        self.delete("all")
        ins = 2 if self._press else 0
        if self.kind == "primary":
            base = _mix(C["acc"], "#ffffff", 0.10 * self._hover)
            if self._press:
                base = C["acc_d"]
            _round(self, 2 + ins, 2 + ins, self.w - 2, self.h - 2, 11,
                    fill=base, outline="")
            fg = "#0b1020"
        elif self.kind == "danger":
            _round(self, 2 + ins, 2 + ins, self.w - 2, self.h - 2, 11,
                    fill=C["panel2"],
                    outline=_mix(C["danger"], C["ink"], self._hover * .3),
                    width=1)
            fg = C["danger"]
        else:  # ghost
            _round(self, 2 + ins, 2 + ins, self.w - 2, self.h - 2, 11,
                    fill=C["panel2"],
                    outline=_mix(C["line"], C["acc"], self._hover), width=1)
            fg = C["ink"] if self._enabled else C["faint"]
        if self.kind == "primary" and not self._enabled:
            _round(self, 2, 2, self.w - 2, self.h - 2, 11, fill=C["panel2"],
                    outline=C["line"], width=1)
            fg = C["faint"]
        self.create_text(self.w / 2, self.h / 2 + ins, text=self._txt,
                         fill=fg, font=("DejaVu Sans", 10, "bold"))


class Dropdown(tk.Canvas):
    """Reliable select (posts a tk.Menu — works on every WM)."""

    def __init__(self, master, values, default, *, w=128, h=30,
                 on_change=None):
        super().__init__(master, width=w, height=h, bg=C["panel"],
                          highlightthickness=0, bd=0, cursor="hand2")
        self.values, self._val = list(values), default
        self.w, self.h, self.on_change = w, h, on_change
        self._hover = False
        self.bind("<Button-1>", self._open)
        self.bind("<Enter>", lambda e: self._set_h(True))
        self.bind("<Leave>", lambda e: self._set_h(False))
        self._draw()

    def get(self):
        return self._val

    def set(self, v):
        if v in self.values:
            self._val = v
            self._draw()

    def _set_h(self, v):
        self._hover = v
        self._draw()

    def _draw(self):
        self.delete("all")
        _round(self, 1, 1, self.w - 1, self.h - 1, 8, fill=C["panel2"],
                outline=C["acc"] if self._hover else C["line"], width=1)
        self.create_text(12, self.h / 2, anchor="w", text=self._val,
                         fill=C["ink"], font=("DejaVu Sans", 10))
        self.create_text(self.w - 14, self.h / 2 - 1, text="▾",
                         fill=C["acc"], font=("DejaVu Sans", 10, "bold"))

    def _open(self, _e):
        m = tk.Menu(self, tearoff=0, bg=C["panel2"], fg=C["ink"],
                    activebackground=C["acc"], activeforeground="#0b1020",
                    bd=0, relief="flat", font=("DejaVu Sans", 10))
        for v in self.values:
            m.add_command(label=v, command=lambda x=v: self._pick(x))
        try:
            m.tk_popup(self.winfo_rootx(),
                       self.winfo_rooty() + self.h + 2)
        finally:
            m.grab_release()

    def _pick(self, v):
        self._val = v
        self._draw()
        if self.on_change:
            self.on_change(v)


class Toggle(tk.Canvas):
    def __init__(self, master, text, var: tk.BooleanVar, accent=None):
        super().__init__(master, width=470, height=28, bg=C["panel"],
                          highlightthickness=0, bd=0, cursor="hand2")
        self.var, self.accent, self.text = var, accent or C["acc"], text
        self._p = 1.0 if var.get() else 0.0
        self.bind("<Button-1>", self._click)
        self._draw()

    def _click(self, _e):
        self.var.set(not self.var.get())
        tgt = 1.0 if self.var.get() else 0.0

        def run():
            self._p += (tgt - self._p) * 0.35
            if abs(tgt - self._p) < 0.02:
                self._p = tgt
                self._draw()
                return
            self._draw()
            self.after(14, run)
        run()

    def _draw(self):
        self.delete("all")
        _round(self, 2, 5, 42, 23, 9,
                fill=_mix(C["line"], self.accent, self._p), outline="")
        kx = 6 + 26 * self._p
        self.create_oval(kx, 7, kx + 14, 21, fill="#f2f5fb", outline="")
        self.create_text(54, 14, anchor="w", text=self.text,
                         fill=C["ink"] if self.var.get() else C["mut"],
                         font=("DejaVu Sans", 10))


class Donut(tk.Canvas):
    def __init__(self, master, size=190):
        super().__init__(master, width=size, height=size, bg=C["panel"],
                          highlightthickness=0, bd=0)
        self.s = size
        self._t = self._c = 0.0
        self.letter, self.color = "—", C["mut"]
        self._draw()

    def set(self, frac, letter, color):
        self._t = max(0.0, min(1.0, frac))
        self.letter, self.color = letter, color

        def run():
            self._c += (self._t - self._c) * 0.14
            if abs(self._t - self._c) < 0.005:
                self._c = self._t
                self._draw()
                return
            self._draw()
            self.after(16, run)
        run()

    def _draw(self):
        self.delete("all")
        s = self.s
        self.create_oval(16, 16, s - 16, s - 16, outline=C["line"], width=10)
        if self._c > 0:
            self.create_arc(16, 16, s - 16, s - 16, start=90,
                            extent=-360 * self._c, style="arc", width=10,
                            outline=self.color)
        self.create_text(s / 2, s / 2 - 8, text=self.letter,
                         fill=self.color, font=("DejaVu Sans", 44, "bold"))
        self.create_text(s / 2, s / 2 + 28, text="GRADE", fill=C["mut"],
                         font=("DejaVu Sans", 10, "bold"))


class Sparkline(tk.Canvas):
    def __init__(self, master, w=600, h=64):
        super().__init__(master, bg=C["inset"], highlightthickness=0, bd=0)
        self.w, self.h = w, h
        self.data: deque[float] = deque(maxlen=120)

    def resize(self, w, h):
        self.w, self.h = w, h
        self.configure(width=w, height=h)
        self._draw()

    def push(self, v):
        self.data.append(v)
        self._draw()

    def reset(self):
        self.data.clear()
        self.delete("all")

    def _draw(self):
        self.delete("all")
        if len(self.data) < 2:
            return
        mx = max(self.data) or 1
        pts = []
        for i, v in enumerate(self.data):
            x = 8 + (self.w - 16) * i / (self.data.maxlen - 1)
            y = self.h - 8 - (self.h - 20) * (v / mx)
            pts += [x, y]
        self.create_line(*pts, fill=C["ok"], width=2, smooth=True,
                         capstyle="round")


# --------------------------------------------------------------------------- #
class AegisGUI:
    def __init__(self, root: tk.Tk, config: AegisConfig) -> None:
        self.root = root
        self.cfg = config
        self.orch = Orchestrator(config)
        self.events: queue.Queue = queue.Queue()
        self.worker: threading.Thread | None = None
        self.stop_flag = threading.Event()
        self.report: RunReport | None = None
        self._fs = False
        self._rz = None
        self._wh = (0, 0)
        self._glow = 0.0

        root.title("AEGIS — Autonomous API Stress & Security Intelligence")
        root.configure(bg=C["bg"])
        root.geometry("1480x900")
        root.minsize(1080, 720)
        root.bind("<F11>", lambda e: self._toggle_fs())
        root.bind("<Escape>", lambda e: self._set_fs(False))
        root.bind("<Control-q>", lambda e: root.quit())
        root.bind("<Configure>", self._on_resize)

        self.bg = tk.Canvas(root, highlightthickness=0, bd=0, bg=C["bg"])
        self.bg.place(x=0, y=0, relwidth=1, relheight=1)

        self._style()
        self._mkimg()
        self._build()
        self.root.after(60, self._first_layout)
        self.root.after(120, self._pump)
        self._animate()

    # ---- fullscreen ---------------------------------------------------- #
    def _toggle_fs(self):
        self._set_fs(not self._fs)

    def _set_fs(self, on):
        self._fs = on
        try:
            self.root.attributes("-fullscreen", on)
        except tk.TclError:
            self.root.state("zoomed" if on else "normal")
        self.fs_btn.set_text("Exit Full · Esc" if on else "Fullscreen · F11")
        self.root.after(80, self._relayout)

    # ---- style --------------------------------------------------------- #
    def _style(self):
        s = ttk.Style()
        try:
            s.theme_use("clam")
        except tk.TclError:
            pass
        s.configure(".", background=C["panel"], foreground=C["ink"],
                    fieldbackground=C["panel2"], bordercolor=C["line"],
                    font=("DejaVu Sans", 10))
        s.configure("A.TSpinbox", fieldbackground=C["panel2"],
                    foreground=C["ink"], arrowcolor=C["acc"],
                    bordercolor=C["line"], arrowsize=12, padding=5)
        s.map("A.TSpinbox", foreground=[("disabled", C["faint"])])
        s.configure("TScrollbar", background=C["panel2"],
                    troughcolor=C["bg2"], arrowcolor=C["mut"],
                    bordercolor=C["line"])
        s.configure("Treeview", background=C["panel2"],
                    fieldbackground=C["panel2"], foreground=C["ink"],
                    rowheight=27, borderwidth=0)
        s.configure("Treeview.Heading", background=C["bg2"],
                    foreground=C["mut"], font=("DejaVu Sans", 9, "bold"),
                    relief="flat")
        s.map("Treeview", background=[("selected", C["acc_soft"])],
              foreground=[("selected", C["ink"])])

    def _mkimg(self):
        self.imgs = {}
        p = os.path.join(ASSETS, "aegis_mark_128.png")
        if _HAS_PIL and os.path.exists(p):
            self.imgs["mark"] = ImageTk.PhotoImage(
                Image.open(p).resize((58, 58), Image.LANCZOS))

    # ---- build (create once) ------------------------------------------ #
    def _build(self):
        R = self.root
        self.lbl_brand = tk.Label(R, text="AEGIS", bg=C["bg"], fg=C["ink"],
                                  font=("DejaVu Sans", 26, "bold"))
        self.lbl_sub = tk.Label(
            R, text="Autonomous API Stress & Security Intelligence  ·  "
            f"v{__version__}", bg=C["bg"], fg=C["mut"],
            font=("DejaVu Sans", 10))
        self.lbl_eng = tk.Label(
            R, bg=C["bg"], fg=C["ok"], font=("DejaVu Sans", 10, "bold"),
            text=("LLM " + self.orch.brain.client.active_model
                  if self.orch.brain.client.available else "Heuristic engine"))
        self.fs_btn = Btn(R, "Fullscreen · F11", self._toggle_fs, w=150,
                          h=30, kind="ghost")
        self.fs_btn.set_bg(C["bg"])
        if "mark" in self.imgs:
            self.lbl_logo = tk.Label(R, image=self.imgs["mark"], bg=C["bg"])
        else:
            self.lbl_logo = tk.Label(R, text="◆", bg=C["bg"], fg=C["acc"],
                                     font=("DejaVu Sans", 30))
        lab = self.cfg.safety.lab_mode
        self.lbl_ribbon = tk.Label(
            R, bg=C["panel"], fg=C["warn"] if not lab else C["danger"],
            font=("DejaVu Sans", 9, "bold"), anchor="w", padx=16,
            text=("LAB MODE · full capability, no caps · "
                  if lab else "") + EDU_CAPTION_GUI)

        self._build_left()
        self._build_right()

    def _sec(self, text, y):
        return tk.Label(self.root, text=text, bg=C["panel"], fg=C["acc"],
                        font=("DejaVu Sans", 9, "bold"))

    def _hint(self, text):
        return tk.Label(self.root, text=text, bg=C["panel"], fg=C["mut"],
                         font=("DejaVu Sans", 8))

    def _build_left(self):
        R = self.root
        self.L = {}
        self.L["s_in"] = self._sec("TARGET INPUT", 0)
        self.L["h_in"] = self._hint("cURL · URL · IP · Postman · OpenAPI · HAR")
        self.input = tk.Text(R, bg=C["panel2"], fg=C["ink"],
                             insertbackground=C["acc"], relief="flat",
                             font=("DejaVu Sans Mono", 10), wrap="word",
                             padx=10, pady=8, undo=True,
                             highlightthickness=1,
                             highlightbackground=C["line"],
                             highlightcolor=C["acc"])
        self.input.insert("1.0", "https://example.com")
        self._menu(self.input)
        self.clear_btn = Btn(R, "✕ Clear", self._clear_input, w=78, h=24,
                             kind="ghost")
        self.L["s_type"] = self._sec("TYPE", 0)
        self.itype = Dropdown(R, ["auto", "curl", "url", "postman",
                                  "openapi", "har"], "auto", w=120, h=30)
        self.open_btn = Btn(R, "Open file…", self._open, w=120, h=30,
                            kind="primary")
        self.paste_btn = Btn(R, "Paste", self._paste, w=72, h=30,
                             kind="ghost")
        self.L["s_mode"] = self._sec("MODE", 0)
        self.mode = tk.StringVar(value="manual")
        self._mode_btns = {}
        for val in ("manual", "autopilot", "nlp"):
            b = tk.Canvas(R, width=132, height=32, bg=C["panel"],
                          highlightthickness=0, bd=0, cursor="hand2")
            b.bind("<Button-1>", lambda e, v=val: self._set_mode(v))
            self._mode_btns[val] = b
        self._render_modes()

        self._spins = {}
        for key, label, dflt in (("concurrency", "Concurrency", 10),
                                  ("duration", "Duration (s · 0 = count)", 0),
                                  ("requests", "Total requests", 200),
                                  ("timeout", "Timeout (s)", 15)):
            lb = tk.Label(R, text=label, bg=C["panel"], fg=C["mut"],
                          font=("DejaVu Sans", 10), anchor="w")
            var = tk.IntVar(value=dflt)
            setattr(self, f"v_{key}", var)
            sp = ttk.Spinbox(R, from_=0, to=100_000_000, textvariable=var,
                             width=9, style="A.TSpinbox")
            self._spins[key] = (lb, sp)

        self.L["s_goal"] = self._sec("GOAL  (autopilot / AI plan)", 0)
        self.goal = tk.Entry(R, bg=C["panel2"], fg=C["ink"],
                             insertbackground=C["acc"], relief="flat",
                             font=("DejaVu Sans", 10),
                             highlightthickness=1,
                             highlightbackground=C["line"],
                             highlightcolor=C["acc"])
        self.goal.insert(0, "baseline performance & security check")
        self._menu(self.goal)

        self.authorized = tk.BooleanVar(value=self.cfg.safety.authorized)
        self.lab = tk.BooleanVar(value=self.cfg.safety.lab_mode)
        self.offensive = tk.BooleanVar(value=False)
        self.tg_auth = Toggle(R, "I am authorised to test the target(s)",
                              self.authorized, C["ok"])
        self.tg_lab = Toggle(R, "Lab mode — no caps, full capability",
                             self.lab, C["danger"])
        self.tg_off = Toggle(R, "Offensive active scan  (education / research)",
                             self.offensive, C["acc"])
        self.L["h_dast"] = self._hint(
            "Active DAST · SQLi · XSS · traversal · cmd/SSTI · redirect · bypass")
        self.start_btn = Btn(R, "▶  START", self._start, w=250, h=44,
                             kind="primary")
        self.stop_btn = Btn(R, "■  STOP", self._stop, w=140, h=44,
                            kind="danger")
        self.stop_btn.config_state(False)
        self.prog = tk.Canvas(R, height=10, bg=C["inset"],
                              highlightthickness=0, bd=0)
        self._prog_val = 0.0
        self.status = tk.Label(R, text="Idle — configure and press Start.",
                               bg=C["panel"], fg=C["mut"], anchor="w",
                               font=("DejaVu Sans", 9))

    def _build_right(self):
        R = self.root
        self._tabs = ["Summary", "Endpoints", "Security", "Charts"]
        self._tab = 0
        self.tabbar = tk.Canvas(R, height=42, bg=C["panel"],
                                highlightthickness=0, bd=0, cursor="hand2")
        self.tabbar.bind("<Button-1>", self._tab_click)
        self._ind = -1.0
        self.content = tk.Frame(R, bg=C["panel"])

        self.sm = tk.Frame(self.content, bg=C["panel"])
        self.donut = Donut(self.sm, 188)
        self.metrics_lbl = tk.Label(self.sm, bg=C["panel"], fg=C["ink"],
                                    justify="left", anchor="nw",
                                    font=("DejaVu Sans", 11))
        self.spark_cap = tk.Label(self.sm, bg=C["panel"], fg=C["faint"],
                                  text="Live throughput (req/s)",
                                  font=("DejaVu Sans", 8), anchor="w")
        self.spark = Sparkline(self.sm)
        self.summary = tk.Text(self.sm, bg=C["panel2"], fg=C["ink"],
                               relief="flat", wrap="word",
                               font=("DejaVu Sans", 10), padx=14, pady=12,
                               highlightthickness=0)
        self.summary.tag_configure("h", foreground=C["acc"],
                                   font=("DejaVu Sans", 10, "bold"))
        self._menu(self.summary)

        self.ep = tk.Frame(self.content, bg=C["panel"])
        self.ep_tree = self._tree(
            self.ep, ("method", "url", "att", "ok", "avg", "p95", "p99",
                      "max"), (60, 320, 55, 55, 60, 60, 60, 60))
        self.se = tk.Frame(self.content, bg=C["panel"])
        self.sec_tree = self._tree(
            self.se, ("sev", "type", "endpoint", "remediation"),
            (84, 190, 230, 280))
        for k, col in SEV.items():
            self.sec_tree.tag_configure(k, foreground=col)
        self.ch = tk.Frame(self.content, bg=C["panel"])
        self.canvas = None
        if not _HAS_MPL:
            tk.Label(self.ch, bg=C["panel"], fg=C["mut"],
                     text="matplotlib not available").pack(pady=40)

        self._tabw = {"Summary": self.sm, "Endpoints": self.ep,
                      "Security": self.se, "Charts": self.ch}

        self.footer = tk.Frame(R, bg=C["panel"])
        self.save_btns = []
        for fmt, txt in (("html", "↓ HTML"), ("json", "↓ JSON"),
                         ("md", "↓ MD"), ("csv", "↓ CSV")):
            self.save_btns.append(
                Btn(R, txt, lambda f=fmt: self._save(f), w=116, h=38,
                    kind="ghost"))
        self.foot_note = tk.Label(R, bg=C["panel"], fg=C["faint"],
                                  font=("DejaVu Sans", 8), anchor="e",
                                  text="authorised testing · education & "
                                       "research")

    def _tree(self, parent, cols, widths):
        t = ttk.Treeview(parent, columns=cols, show="headings")
        sb = ttk.Scrollbar(parent, orient="vertical", command=t.yview)
        t.configure(yscrollcommand=sb.set)
        for c, w in zip(cols, widths):
            t.heading(c, text=c.upper())
            t.column(c, width=w, anchor="w" if c in ("url", "endpoint",
                     "remediation") else "center")
        t.tag_configure("odd", background=C["panel2"])
        t.tag_configure("even", background=C["inset"])
        sb.pack(side="right", fill="y")
        t.pack(side="left", fill="both", expand=True)
        return t

    # ---- responsive layout -------------------------------------------- #
    def _first_layout(self):
        self._relayout()

    def _on_resize(self, e):
        if e.widget is not self.root:
            return
        if (e.width, e.height) == self._wh:
            return
        self._wh = (e.width, e.height)
        if self._rz:
            self.root.after_cancel(self._rz)
        self._rz = self.root.after(50, self._relayout)

    def _relayout(self):
        W = self.root.winfo_width() or 1480
        H = self.root.winfo_height() or 900
        PAD, LW = 24, 452
        # background
        self.bg.delete("all")
        for i in range(70):
            self.bg.create_rectangle(
                0, H * i / 70, W, H * i / 70 + H / 70 + 1,
                fill=_mix(C["bg"], C["bg2"], abs(0.5 - i / 70) * 1.4),
                outline="")
        gx = 120 + 60 * math.sin(self._glow)
        for r in range(360, 0, -28):
            self.bg.create_oval(gx - r, -120 - r, gx + r, -120 + r,
                                fill=_mix(C["bg"], C["acc"],
                                          0.05 * (1 - r / 360)), outline="")
        hb = 78
        rib_y = hb + 6
        body = rib_y + 40
        lx0, lx1 = PAD, PAD + LW
        rx0, rx1 = lx1 + 18, W - PAD
        self._card(lx0, body, lx1, H - PAD)
        self._card(rx0, body, rx1, H - PAD - 70)
        self._card(rx0, H - PAD - 58, rx1, H - PAD)

        self.lbl_logo.place(x=PAD + 6, y=18, width=58, height=58)
        self.lbl_brand.place(x=PAD + 78, y=20)
        self.lbl_sub.place(x=PAD + 80, y=56)
        self.fs_btn.place(x=W - PAD - 154, y=24)
        self.lbl_eng.place(x=W - PAD - 320, y=28, width=160)
        self.lbl_eng.configure(anchor="e")
        self.lbl_ribbon.place(x=lx0, y=rib_y, width=rx1 - lx0, height=32)

        self._layout_left(lx0, body, H)
        self._layout_right(rx0, rx1, body, H, PAD)

    def _card(self, x0, y0, x1, y1):
        _round(self.bg, x0, y0 + 3, x1, y1 + 3, 18,
                fill=_mix(C["bg"], "#000000", .3), outline="")
        _round(self.bg, x0, y0, x1, y1, 18, fill=C["panel"],
                outline=C["line"], width=1)
        self.bg.create_line(x0 + 18, y0 + 1, x1 - 18, y0 + 1,
                            fill=C["hi"])

    def _layout_left(self, x0, y0, H):
        x = x0 + 26
        y = y0 + 22
        self.L["s_in"].place(x=x, y=y)
        self.L["h_in"].place(x=x, y=y + 18)
        self.clear_btn.place(x=x0 + 452 - 26 - 78 - 26, y=y - 4)
        self.input.place(x=x, y=y + 38, width=400, height=118)
        y += 174
        self.L["s_type"].place(x=x, y=y + 6)
        self.itype.place(x=x + 50, y=y)
        self.open_btn.place(x=x + 184, y=y)
        self.paste_btn.place(x=x + 312, y=y)
        y += 46
        self.L["s_mode"].place(x=x, y=y)
        for i, val in enumerate(("manual", "autopilot", "nlp")):
            self._mode_btns[val].place(x=x + i * 138, y=y + 18)
        y += 60
        for key in ("concurrency", "duration", "requests", "timeout"):
            lb, sp = self._spins[key]
            lb.place(x=x, y=y + 2, width=260, height=20)
            sp.place(x=x + 300, y=y, width=100, height=26)
            y += 34
        y += 6
        self.L["s_goal"].place(x=x, y=y)
        self.goal.place(x=x, y=y + 18, width=400, height=26)
        y += 56
        self.tg_auth.place(x=x, y=y)
        self.tg_lab.place(x=x, y=y + 30)
        self.tg_off.place(x=x, y=y + 60)
        self.L["h_dast"].place(x=x, y=y + 90)
        y += 116
        self.start_btn.place(x=x, y=y)
        self.stop_btn.place(x=x + 262, y=y)
        y += 56
        self.prog.place(x=x, y=y, width=400, height=10)
        self.status.place(x=x, y=y + 18, width=400, height=18)

    def _layout_right(self, x0, x1, y0, H, PAD):
        w = x1 - x0
        self.tabbar.place(x=x0 + 14, y=y0 + 14, width=w - 28, height=42)
        self._draw_tabs(w - 28)
        cy = y0 + 64
        ch = (H - PAD - 70) - cy - 14
        self.content.place(x=x0 + 14, y=cy, width=w - 28, height=ch)
        cw = w - 28
        # summary children
        self.metrics_lbl.place(x=210, y=14, width=cw - 230, height=180)
        self.donut.place(x=6, y=8)
        self.spark_cap.place(x=8, y=204)
        self.spark.place(x=8, y=220)
        self.spark.resize(cw - 16, 60)
        self.summary.place(x=8, y=290, width=cw - 16, height=ch - 300)
        # footer
        fy = H - PAD - 50
        for i, b in enumerate(self.save_btns):
            b.place(x=x0 + 16 + i * 126, y=fy)
        self.foot_note.place(x=x1 - 270, y=fy + 12, width=250)
        self._show_tab(self._tab, animate=False)

    # ---- tabs ---------------------------------------------------------- #
    def _draw_tabs(self, w):
        self.tabbar.delete("all")
        n = len(self._tabs)
        seg = w / n
        for i, name in enumerate(self._tabs):
            a = i == self._tab
            self.tabbar.create_text(seg * i + seg / 2, 18, text=name,
                                    fill=C["ink"] if a else C["mut"],
                                    font=("DejaVu Sans", 11,
                                          "bold" if a else "normal"))
        if self._ind < 0:
            self._ind = seg / 2
        cx = seg * self._tab + seg / 2
        self.tabbar.create_line(cx - 26, 36, cx + 26, 36, fill=C["acc"],
                                width=2, capstyle="round")
        self._seg = seg

    def _tab_click(self, e):
        seg = getattr(self, "_seg", 200)
        self._show_tab(int(max(0, min(3, e.x // seg))))

    def _show_tab(self, i, animate=True):
        self._tab = i
        for w in self._tabw.values():
            w.place_forget()
        self._tabw[self._tabs[i]].place(x=0, y=0, relwidth=1, relheight=1)
        if not hasattr(self, "_seg"):
            return
        tw = self._seg * len(self._tabs)
        target = self._seg * i + self._seg / 2
        if not animate:
            self._ind = target
            self._draw_tabs(tw)
            return

        def slide():
            self._ind += (target - self._ind) * 0.25
            self._draw_tabs(tw)
            if abs(target - self._ind) > 1:
                self.root.after(14, slide)
        slide()

    def _render_modes(self):
        names = {"manual": "Manual", "autopilot": "Autopilot",
                 "nlp": "Natural"}
        for val, b in self._mode_btns.items():
            b.delete("all")
            sel = self.mode.get() == val
            _round(b, 1, 1, 131, 31, 9,
                    fill=C["acc"] if sel else C["panel2"],
                    outline=C["acc"] if sel else C["line"], width=1)
            b.create_text(66, 16, text=names[val],
                          fill="#0b1020" if sel else C["mut"],
                          font=("DejaVu Sans", 10, "bold"))

    def _set_mode(self, v):
        self.mode.set(v)
        self._render_modes()

    # ---- editor / clipboard ------------------------------------------- #
    def _menu(self, w):
        is_t = isinstance(w, tk.Text)
        m = tk.Menu(w, tearoff=0, bg=C["panel2"], fg=C["ink"],
                    activebackground=C["acc"], activeforeground="#0b1020",
                    bd=0)
        m.add_command(label="Cut", command=lambda: w.event_generate("<<Cut>>"))
        m.add_command(label="Copy",
                      command=lambda: w.event_generate("<<Copy>>"))
        m.add_command(label="Paste",
                      command=lambda: w.event_generate("<<Paste>>"))
        m.add_separator()
        m.add_command(label="Select all",
                      command=lambda: self._sel_all(w, is_t))
        m.add_command(label="Clear",
                      command=lambda: (w.delete("1.0", "end") if is_t
                                       else w.delete(0, "end")))

        def pop(e):
            try:
                m.tk_popup(e.x_root, e.y_root)
            finally:
                m.grab_release()
        w.bind("<Button-3>", pop)
        w.bind("<Control-a>", lambda e: self._sel_all(w, is_t))
        w.bind("<Control-A>", lambda e: self._sel_all(w, is_t))

    @staticmethod
    def _sel_all(w, is_t):
        if is_t:
            w.tag_add("sel", "1.0", "end-1c")
        else:
            w.select_range(0, "end")
        return "break"

    def _clear_input(self):
        self.input.delete("1.0", "end")
        self.input.focus_set()

    def _paste(self):
        try:
            self.input.insert("insert", self.root.clipboard_get())
        except tk.TclError:
            pass

    # ---- animation ----------------------------------------------------- #
    def _animate(self):
        self._glow += 0.012
        if self.worker and self.worker.is_alive():
            self._draw_prog(moving=True)
        # gentle background glow drift (cheap: only the glow ovals)
        self.root.after(60, self._animate)

    def _draw_prog(self, moving=False):
        self.prog.delete("all")
        w = self.prog.winfo_width() or 400
        _round(self.prog, 0, 0, w, 10, 5, fill=C["inset"], outline="")
        fw = max(2, int(w * self._prog_val / 100))
        _round(self.prog, 0, 0, fw, 10, 5, fill=C["acc"], outline="")

    # ---- file ---------------------------------------------------------- #
    def _open(self):
        p = filedialog.askopenfilename(
            title="Load test input",
            filetypes=[("All supported",
                        "*.txt *.json *.har *.yaml *.yml *.curl *.sh "
                        "*.list *.log"),
                       ("JSON / Postman / OpenAPI / HAR", "*.json *.har"),
                       ("YAML / OpenAPI", "*.yaml *.yml"),
                       ("cURL / text / URL list", "*.txt *.curl *.sh"),
                       ("All files", "*.*")])
        if not p:
            return
        try:
            with open(p, encoding="utf-8", errors="replace") as fh:
                data = fh.read()
        except OSError as e:
            messagebox.showerror("AEGIS", f"Could not read file:\n{e}")
            return
        self.input.delete("1.0", "end")
        self.input.insert("1.0", data)
        ext = os.path.splitext(p)[1].lower()
        self.itype.set({".json": "postman", ".har": "har", ".yaml": "openapi",
                        ".yml": "openapi", ".curl": "curl",
                        ".sh": "curl"}.get(ext, "auto"))
        self.status.configure(
            text=f"Loaded {os.path.basename(p)} ({len(data)} bytes)")

    # ---- run ----------------------------------------------------------- #
    def _start(self):
        if self.worker and self.worker.is_alive():
            return
        raw = self.input.get("1.0", "end").strip()
        if not raw:
            messagebox.showwarning("AEGIS", "Provide target input first.")
            return
        self.cfg.safety.authorized = self.authorized.get()
        self.cfg.safety.lab_mode = self.lab.get()
        if self.lab.get():
            self.cfg.safety.authorized = True
        self.orch = Orchestrator(self.cfg)
        offensive = self.offensive.get()
        self.stop_flag.clear()
        self.start_btn.config_state(False)
        self.stop_btn.config_state(True)
        self._prog_val = 0.0
        self._draw_prog()
        self.spark.reset()
        self._clear()
        mode = self.mode.get()

        def job():
            try:
                cb = lambda e, d: self.events.put((e, d))
                stop = self.stop_flag.is_set
                if mode == "nlp":
                    rep = self.orch.from_nlp(raw, on_event=cb,
                                             should_stop=stop)
                elif mode == "autopilot":
                    rep = self.orch.autopilot(
                        raw, input_type=self.itype.get(),
                        goal=self.goal.get(), offensive=offensive,
                        on_event=cb, should_stop=stop)
                else:
                    from .models import TestPlan
                    specs = self.orch.parse(raw, input_type=self.itype.get())
                    plan = TestPlan(
                        concurrency=self.v_concurrency.get(),
                        duration_seconds=self.v_duration.get(),
                        total_requests=self.v_requests.get(),
                        timeout_seconds=float(self.v_timeout.get() or 15),
                        source="user", rationale="GUI manual plan.")
                    rep = self.orch.run(specs, plan=plan, offensive=offensive,
                                        on_event=cb, should_stop=stop)
                self.events.put(("report", {"report": rep}))
            except SafetyError as e:
                self.events.put(("error", {"t": "Refused", "m": str(e)}))
            except Exception as e:
                self.events.put(("error", {"t": type(e).__name__,
                                           "m": str(e)}))
        self.worker = threading.Thread(target=job, daemon=True)
        self.worker.start()

    def _stop(self):
        self.stop_flag.set()
        self.status.configure(text="Stopping…")

    # ---- pump ---------------------------------------------------------- #
    def _pump(self):
        try:
            while True:
                ev, d = self.events.get_nowait()
                self._handle(ev, d)
        except queue.Empty:
            pass
        self.root.after(110, self._pump)

    def _handle(self, ev, d):
        if ev == "phase":
            self.status.configure(text=f"● {d['name'].title()} …")
        elif ev == "plan":
            p = d["plan"]
            self.status.configure(
                text=f"Plan · {p['mode']} · conc={p['concurrency']}")
        elif ev == "safety":
            self.status.configure(text="⚠ " + ", ".join(d["notes"]))
        elif ev == "progress":
            self._prog_val = d.get("percent", 0)
            self._draw_prog()
            self.spark.push(d.get("rps", 0))
            self.status.configure(
                text=f"{d.get('total',0)} req · {d.get('rps',0):.0f} rps · "
                     f"avg {d.get('avg_ms',0):.0f} ms")
        elif ev == "report":
            self._finish(d["report"])
        elif ev == "error":
            self.start_btn.config_state(True)
            self.stop_btn.config_state(False)
            messagebox.showerror(f"AEGIS — {d['t']}", d["m"])
            self.status.configure(text="Failed.")

    def _clear(self):
        self.ep_tree.delete(*self.ep_tree.get_children())
        self.sec_tree.delete(*self.sec_tree.get_children())
        self.summary.delete("1.0", "end")
        self.metrics_lbl.config(text="")

    def _finish(self, rep: RunReport):
        self.report = rep
        self.start_btn.config_state(True)
        self.stop_btn.config_state(False)
        self._prog_val = 100
        self._draw_prog()
        d = rep.to_dict()
        s, ins = d["summary"], rep.insight
        gc = {"A": C["ok"], "B": C["ok"], "C": C["warn"],
              "D": C["danger"], "F": C["danger"]}.get(ins.grade, C["mut"])
        gv = {"A": .96, "B": .82, "C": .64, "D": .46, "F": .26}.get(
            ins.grade, .08)
        self.donut.set(gv, ins.grade or "—", gc)
        self.status.configure(text=f"✔ Done — grade {ins.grade} · "
                              f"{s['success_rate']}% ok")
        self.metrics_lbl.config(text=(
            f"Requests     {s['total_attempts']}   "
            f"(✓ {s['total_successes']}   ✗ {s['total_failures']})\n"
            f"Success       {s['success_rate']} %\n"
            f"Avg latency   {s['overall_avg_ms']} ms\n"
            f"Throughput    {s['throughput_rps']} rps\n"
            f"Top severity  {s['highest_severity']}\n"
            f"Engine        {ins.engine}"))
        self.summary.delete("1.0", "end")
        for head, body in (("SUMMARY", ins.summary),
                           ("BENCHMARK", ins.benchmark),
                           ("OPTIMIZATION", ins.optimization),
                           ("FORECAST", ins.prediction)):
            self.summary.insert("end", f"{head}\n", "h")
            self.summary.insert("end", f"{body}\n\n")
        if ins.assertions:
            self.summary.insert("end", "SUGGESTED ASSERTIONS\n", "h")
            for a in ins.assertions:
                self.summary.insert("end", f"  • {a}\n")
        for i, e in enumerate(rep.endpoints):
            self.ep_tree.insert(
                "", "end", tags=("even" if i % 2 else "odd",),
                values=(e.method, e.url, e.attempts, f"{e.success_rate:.0f}%",
                        f"{e.avg_ms:.0f}", f"{e.p95:.0f}", f"{e.p99:.0f}",
                        f"{e.max_ms:.0f}"))
        for v in rep.vulnerabilities:
            self.sec_tree.insert("", "end", tags=(v.severity.value,),
                                 values=(v.severity.value, v.type,
                                         v.endpoint, v.remediation))
        self._draw_charts(rep)
        self._show_tab(0, animate=False)

    def _draw_charts(self, rep):
        if not _HAS_MPL:
            return
        if self.canvas:
            self.canvas.get_tk_widget().destroy()
        fig = Figure(figsize=(7.6, 5.2), facecolor=C["panel"])
        fig.subplots_adjust(hspace=0.55, left=0.1, right=0.97, top=0.92,
                            bottom=0.13)
        a1, a2 = fig.add_subplot(211), fig.add_subplot(212)
        for ax in (a1, a2):
            ax.set_facecolor(C["panel2"])
            for sp in ax.spines.values():
                sp.set_color(C["line"])
            ax.tick_params(colors=C["mut"], labelsize=8)
        eps = rep.endpoints[:6]
        labels = [e.url.split("//")[-1][:18] for e in eps] or ["—"]
        xs = range(len(labels))
        a1.bar([i - .22 for i in xs], [e.p50 for e in eps], .22, label="p50",
               color=C["acc"])
        a1.bar(list(xs), [e.p95 for e in eps], .22, label="p95",
               color=C["ok"])
        a1.bar([i + .22 for i in xs], [e.p99 for e in eps], .22, label="p99",
               color=C["warn"])
        a1.set_xticks(list(xs))
        a1.set_xticklabels(labels, rotation=16, ha="right")
        a1.set_title("Latency percentiles (ms)", color=C["ink"], fontsize=10)
        a1.legend(facecolor=C["panel"], edgecolor=C["line"],
                  labelcolor=C["ink"], fontsize=8)
        sev = {}
        for v in rep.vulnerabilities:
            sev[v.severity.value] = sev.get(v.severity.value, 0) + 1
        names = [o for o in ("Critical", "High", "Medium", "Low", "Info")
                 if sev.get(o)]
        if names:
            a2.barh(names, [sev[n] for n in names],
                    color=[SEV[n] for n in names])
            a2.invert_yaxis()
        else:
            a2.text(.5, .5, "No security findings", ha="center",
                    color=C["ok"], transform=a2.transAxes)
        a2.set_title("Security findings by severity", color=C["ink"],
                     fontsize=10)
        self.canvas = FigureCanvasTkAgg(fig, master=self.ch)
        self.canvas.draw()
        self.canvas.get_tk_widget().pack(fill="both", expand=True)

    def _save(self, fmt):
        if not self.report:
            messagebox.showinfo("AEGIS", "Run a test first.")
            return
        w = write_reports(self.report, self.cfg.report_dir, [fmt])
        messagebox.showinfo("AEGIS", f"Saved:\n{list(w.values())[0]}")


def launch(config: AegisConfig | None = None) -> None:
    root = tk.Tk()
    AegisGUI(root, config or AegisConfig.load())
    root.mainloop()


if __name__ == "__main__":
    launch()
