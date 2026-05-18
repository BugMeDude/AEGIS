"""AEGIS desktop GUI — modern glassmorphic, animated, multi-colour edition.

Tkinter has no CSS, blur or true alpha, so "glassmorphism / 3D / motion" is
achieved with a custom Canvas engine: multi-stop gradients, faux glow blobs,
rounded glass panels, neon gradient buttons, sliding toggles, an animated
progress shimmer, a live RPS sparkline, an animated donut grade gauge, a
sliding tab indicator and embedded modern charts.

Everything sits on a fixed-size *stage* frame that is centred in the window,
so the app is fully resizable / full-screen while keeping its layout. The
whole thing stays a thin shell over :class:`Orchestrator` (worker thread +
queue + ``after`` pump) so the engine never blocks the UI.
"""

from __future__ import annotations

import math
import os
import queue
import threading
import tkinter as tk
from collections import deque
from tkinter import filedialog, messagebox, ttk

from . import EDU_NOTICE, __version__
from .config import AegisConfig
from .models import RunReport
from .orchestrator import Orchestrator
from .reporting import write_reports
from .safety import SafetyError

# DejaVu (the GUI font) has no colour-emoji glyphs.
EDU_CAPTION_GUI = ("EDUCATIONAL & RESEARCH EDITION  —  Offensive + Defensive"
                   "  ·  Authorised testing only")

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

C = dict(
    bg0="#070a14", bg1="#0c1124", bg2="#150c28",
    glass="#161d33", glass2="#1b2440", stroke="#33436f",
    ink="#eaf2ff", mut="#9aabd4",
    cyan="#22d3ee", violet="#8b5cf6", magenta="#e879f9",
    lime="#a3e635", amber="#f59e0b", red="#fb7185", green="#34d399",
)
GRAD = [C["cyan"], C["violet"], C["magenta"]]


def _hx(c):
    c = c.lstrip("#")
    return tuple(int(c[i:i + 2], 16) for i in (0, 2, 4))


def _mix(a, b, t):
    a, b = _hx(a), _hx(b)
    return "#%02x%02x%02x" % tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3))


def _grad(stops, t):
    if t <= 0:
        return stops[0]
    if t >= 1:
        return stops[-1]
    seg = t * (len(stops) - 1)
    i = int(seg)
    return _mix(stops[i], stops[i + 1], seg - i)


def _lum(hexc):
    r, g, b = _hx(hexc)
    return (0.299 * r + 0.587 * g + 0.114 * b) / 255.0


def _round(cv: tk.Canvas, x0, y0, x1, y1, r, **kw):
    pts = [
        x0 + r, y0, x1 - r, y0, x1, y0, x1, y0 + r, x1, y1 - r, x1, y1,
        x1 - r, y1, x0 + r, y1, x0, y1, x0, y1 - r, x0, y0 + r, x0, y0,
    ]
    return cv.create_polygon(pts, smooth=True, **kw)


# --------------------------------------------------------------------------- #
class NeonButton(tk.Canvas):
    """Rounded gradient button.

    Hover glow and press inset are *separate* state (a float and a bool) with a
    single cancel-safe animation, so a click is never swallowed by the hover
    tween — the bug that made the old button feel dead.
    """

    def __init__(self, master, text, command, *, w=150, h=44,
                 stops=None, fg=None):
        super().__init__(master, width=w, height=h, bg=C["glass"],
                          highlightthickness=0, bd=0, cursor="hand2")
        self.cmd, self.w, self.h = command, w, h
        self.stops = stops or [C["cyan"], C["violet"]]
        self._txt = text
        self._hover = 0.0
        self._press = False
        self._enabled = True
        self._anim = None
        self.fg = fg or ("#08101f" if _lum(_grad(self.stops, .5)) > .5
                         else "#eaf2ff")
        self.bind("<Enter>", lambda e: self._tween(1.0))
        self.bind("<Leave>", self._leave)
        self.bind("<ButtonPress-1>", self._on_press)
        self.bind("<ButtonRelease-1>", self._on_release)
        self._draw()

    def set_bg(self, color):
        self.configure(bg=color)
        self._draw()

    def config_state(self, enabled: bool):
        self._enabled = enabled
        self.configure(cursor="hand2" if enabled else "arrow")
        self._draw()

    def _leave(self, _e):
        self._press = False
        self._tween(0.0)

    def _on_press(self, _e):
        if self._enabled:
            self._press = True
            self._draw()

    def _on_release(self, e):
        if not self._enabled:
            return
        was = self._press
        self._press = False
        self._draw()
        if was and 0 <= e.x <= self.w and 0 <= e.y <= self.h:
            self.after(10, self.cmd)

    def _tween(self, target):
        if self._anim:
            self.after_cancel(self._anim)
            self._anim = None

        def run():
            self._hover += (target - self._hover) * 0.3
            if abs(target - self._hover) < 0.03:
                self._hover = target
                self._draw()
                return
            self._draw()
            self._anim = self.after(16, run)
        run()

    def _draw(self):
        self.delete("all")
        inset = 3 if self._press else 0
        x0, y0, x1, y1 = 5 + inset, 5 + inset, self.w - 5 - inset, self.h - 5 - inset
        n = 22
        for i in range(n):
            self._round_band(x0, y0 + i * (y1 - y0) / n, x1, y1,
                             _grad(self.stops, i / n))
        glow = _mix(self.stops[-1], "#ffffff", 0.18 + 0.45 * self._hover)
        _round(self, 3, 3, self.w - 3, self.h - 3, 15,
                outline=glow, width=1 + 2 * self._hover, fill="")
        if not self._enabled:
            _round(self, 4, 4, self.w - 4, self.h - 4, 15,
                    fill=C["bg1"], outline="", stipple="gray50")
        self.create_text(self.w / 2, self.h / 2,
                          text=self._txt,
                          fill=self.fg if self._enabled else C["mut"],
                          font=("DejaVu Sans", 11, "bold"))

    def _round_band(self, x0, y0, x1, y1, col):
        _round(self, x0, y0, x1, y1, 13, fill=col, outline="")


class Toggle(tk.Canvas):
    """Animated sliding switch."""

    def __init__(self, master, text, var: tk.BooleanVar, accent=None):
        super().__init__(master, width=460, height=30, bg=C["glass"],
                          highlightthickness=0, bd=0, cursor="hand2")
        self.var, self.accent, self.text = var, accent or C["cyan"], text
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
        _round(self, 2, 6, 44, 25, 9, fill=_mix(C["stroke"], self.accent,
               self._p), outline="")
        kx = 8 + 28 * self._p
        self.create_oval(kx, 8, kx + 15, 23, fill="#f4f8ff", outline="")
        self.create_text(58, 15, anchor="w", text=self.text,
                         fill=C["ink"] if self.var.get() else C["mut"],
                         font=("DejaVu Sans", 10))


class Donut(tk.Canvas):
    """Animated grade gauge."""

    def __init__(self, master, size=200):
        super().__init__(master, width=size, height=size, bg=C["glass"],
                          highlightthickness=0, bd=0)
        self.s = size
        self._target = 0.0
        self._cur = 0.0
        self.letter = "—"
        self.color = C["mut"]
        self._draw()

    def set(self, frac, letter, color):
        self._target = max(0.0, min(1.0, frac))
        self.letter, self.color = letter, color

        def run():
            self._cur += (self._target - self._cur) * 0.12
            if abs(self._target - self._cur) < 0.005:
                self._cur = self._target
                self._draw()
                return
            self._draw()
            self.after(16, run)
        run()

    def _draw(self):
        self.delete("all")
        s, cx = self.s, self.s / 2
        self.create_oval(18, 18, s - 18, s - 18, outline=C["stroke"], width=14)
        ext = -360 * self._cur
        steps = max(1, int(abs(ext) / 6))
        for i in range(steps):
            self.create_arc(18, 18, s - 18, s - 18,
                            start=90 + (ext / steps) * i,
                            extent=ext / steps - 0.5, style="arc", width=14,
                            outline=_grad(GRAD, i / steps))
        self.create_text(cx, cx - 8, text=self.letter, fill=self.color,
                         font=("DejaVu Sans", 46, "bold"))
        self.create_text(cx, cx + 30, text="GRADE", fill=C["mut"],
                         font=("DejaVu Sans", 11, "bold"))


class Sparkline(tk.Canvas):
    """Rolling live throughput line."""

    def __init__(self, master, w=760, h=70):
        super().__init__(master, width=w, height=h, bg=C["glass2"],
                          highlightthickness=0, bd=0)
        self.w, self.h = w, h
        self.data: deque[float] = deque(maxlen=90)
        _round(self, 0, 0, w, h, 12, fill=C["glass2"], outline="")

    def push(self, v):
        self.data.append(v)
        self._draw()

    def reset(self):
        self.data.clear()
        self.delete("ln")

    def _draw(self):
        self.delete("ln")
        if len(self.data) < 2:
            return
        mx = max(self.data) or 1
        pts = []
        for i, v in enumerate(self.data):
            x = 8 + (self.w - 16) * i / (self.data.maxlen - 1)
            y = self.h - 8 - (self.h - 22) * (v / mx)
            pts += [x, y]
        self.create_line(*pts, fill=C["cyan"], width=2, smooth=True,
                         tags="ln", capstyle="round")


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
        self._blobs = [[180, 240, 1], [1060, 200, -1], [560, 760, 1]]
        self._phase = 0.0
        self._fs = False

        self.W, self.H = 1340, 904
        root.title("AEGIS — Autonomous API Stress & Security Intelligence")
        root.configure(bg=C["bg0"])
        root.geometry(f"{self.W}x{self.H}")
        root.minsize(1100, 740)
        root.bind("<F11>", lambda e: self._toggle_fs())
        root.bind("<Escape>", lambda e: self._set_fs(False))
        root.bind("<Control-q>", lambda e: root.quit())

        # Centred fixed-size stage -> resizable / full-screen friendly.
        self.stage = tk.Frame(root, width=self.W, height=self.H, bg=C["bg0"])
        self.stage.place(relx=0.5, rely=0.5, anchor="center")
        self.stage.pack_propagate(False)

        self.bg = tk.Canvas(self.stage, width=self.W, height=self.H,
                            highlightthickness=0, bd=0)
        self.bg.place(x=0, y=0)

        self._style()
        self._paint_bg()
        self._logo()
        self._build()
        self._animate()
        self.root.after(120, self._pump)

    # ---- full screen --------------------------------------------------- #
    def _toggle_fs(self):
        self._set_fs(not self._fs)

    def _set_fs(self, on: bool):
        self._fs = on
        try:
            self.root.attributes("-fullscreen", on)
        except tk.TclError:
            self.root.state("zoomed" if on else "normal")
        self.fs_btn._txt = "Exit Full (Esc)" if on else "Fullscreen (F11)"
        self.fs_btn._draw()

    # ---- background ---------------------------------------------------- #
    def _paint_bg(self):
        self.bg.delete("bgfill")
        steps = 80
        for i in range(steps):
            self.bg.create_rectangle(
                0, self.H * i / steps, self.W,
                self.H * i / steps + self.H / steps + 1,
                fill=_grad([C["bg0"], C["bg1"], C["bg2"], C["bg0"]], i / steps),
                outline="", tags="bgfill")
        self._paint_blobs()
        self._panel(28, 178, 478, 872)
        self._panel(496, 178, 1312, 812)
        self._panel(496, 826, 1312, 892)

    def _paint_blobs(self):
        self.bg.delete("blob")
        for bx, by, _ in self._blobs:
            for r in range(170, 0, -16):
                col = _mix(C["bg1"],
                           C["violet"] if (bx + by) % 2 else C["cyan"],
                           0.09 * (1 - r / 170))
                self.bg.create_oval(bx - r, by - r, bx + r, by + r,
                                    fill=col, outline="", tags="blob")
        self.bg.tag_lower("blob")
        self.bg.tag_lower("bgfill")

    def _panel(self, x0, y0, x1, y1):
        _round(self.bg, x0 + 3, y0 + 4, x1 + 3, y1 + 4, 22, fill=C["bg0"],
                outline="", tags="pnl")
        _round(self.bg, x0, y0, x1, y1, 22, fill=C["glass"],
                outline=C["stroke"], width=1, tags="pnl")
        self.bg.create_line(x0 + 22, y0 + 1, x1 - 22, y0 + 1,
                            fill=_mix(C["stroke"], "#ffffff", .28), tags="pnl")

    # ---- style --------------------------------------------------------- #
    def _style(self):
        s = ttk.Style()
        try:
            s.theme_use("clam")
        except tk.TclError:
            pass
        s.configure(".", background=C["glass"], foreground=C["ink"],
                    fieldbackground=C["glass2"], bordercolor=C["stroke"],
                    font=("DejaVu Sans", 10))
        s.configure("TScrollbar", background=C["glass2"],
                    troughcolor=C["bg1"], bordercolor=C["stroke"],
                    arrowcolor=C["cyan"])
        # Combobox (the previously-invisible TYPE selector).
        s.configure("A.TCombobox", arrowsize=16, padding=5)
        s.map("A.TCombobox",
              fieldbackground=[("readonly", C["glass2"])],
              background=[("readonly", C["glass2"]),
                          ("active", C["glass2"])],
              foreground=[("readonly", C["ink"])],
              arrowcolor=[("readonly", C["cyan"])],
              bordercolor=[("readonly", C["cyan"])],
              selectbackground=[("readonly", C["glass2"])],
              selectforeground=[("readonly", C["ink"])])
        for opt, val in (("*TCombobox*Listbox.background", C["glass2"]),
                         ("*TCombobox*Listbox.foreground", C["ink"]),
                         ("*TCombobox*Listbox.selectBackground", C["violet"]),
                         ("*TCombobox*Listbox.selectForeground", "#ffffff"),
                         ("*TCombobox*Listbox.font", "DejaVu Sans 10")):
            self.root.option_add(opt, val)
        s.configure("A.TSpinbox", fieldbackground=C["glass2"],
                    foreground=C["ink"], arrowsize=13,
                    bordercolor=C["stroke"], arrowcolor=C["cyan"], padding=4)
        s.map("A.TSpinbox", foreground=[("disabled", C["mut"])],
              fieldbackground=[("readonly", C["glass2"])])
        s.configure("Treeview", background=C["glass2"],
                    fieldbackground=C["glass2"], foreground=C["ink"],
                    rowheight=27, borderwidth=0)
        s.configure("Treeview.Heading", background=C["bg1"],
                    foreground=C["cyan"], font=("DejaVu Sans", 9, "bold"),
                    relief="flat")
        s.map("Treeview", background=[("selected", C["violet"])],
              foreground=[("selected", "#ffffff")])

    def _logo(self):
        self.imgs = {}
        p = os.path.join(ASSETS, "aegis_mark_128.png")
        if _HAS_PIL and os.path.exists(p):
            im = Image.open(p).resize((78, 78), Image.LANCZOS)
            self.imgs["mark"] = ImageTk.PhotoImage(im)
            self.bg.create_image(58, 70, image=self.imgs["mark"], anchor="w")

    # ---- build --------------------------------------------------------- #
    def _build(self):
        self.bg.create_text(154, 50, anchor="w", text="AEGIS",
                            font=("DejaVu Sans", 32, "bold"), fill=C["ink"])
        self._sheen = self.bg.create_text(
            154, 50, anchor="w", text="AEGIS",
            font=("DejaVu Sans", 32, "bold"), fill=C["cyan"])
        self.bg.create_text(156, 86, anchor="w",
                            text="Autonomous API Stress & Security "
                                 f"Intelligence   ·   v{__version__}",
                            font=("DejaVu Sans", 11), fill=C["mut"])
        self.bg.create_text(
            1196, 36, anchor="e", font=("DejaVu Sans", 10, "bold"),
            fill=C["lime"], text=("LLM " + self.orch.brain.client.active_model
                                  if self.orch.brain.client.available
                                  else "Heuristic engine"))
        self.fs_btn = NeonButton(self.stage, "Fullscreen (F11)",
                                 self._toggle_fs, w=150, h=30,
                                 stops=[C["glass2"], C["stroke"]])
        self.fs_btn.set_bg(C["glass"])
        self.fs_btn.place(x=1158, y=58)

        _round(self.bg, 28, 128, 1312, 166, 12,
                fill=_mix(C["bg1"], C["amber"], 0.10),
                outline=_mix(C["stroke"], C["amber"], .4), width=1)
        self.bg.create_text(670, 147, text="★  " + EDU_CAPTION_GUI,
                            font=("DejaVu Sans", 10, "bold"), fill=C["amber"])

        self._build_left()
        self._build_right()
        self._build_footer()

    def _lbl(self, x, y, txt, color=None, size=10, bold=False, anchor="w"):
        return self.bg.create_text(x, y, anchor=anchor, text=txt,
                                   fill=color or C["mut"],
                                   font=("DejaVu Sans", size,
                                         "bold" if bold else "normal"))

    def _build_left(self):
        x = 50
        self._lbl(x, 204, "TARGET INPUT", C["cyan"], 10, True)
        self._lbl(x, 222, "cURL · URL · IP · Postman · OpenAPI · HAR",
                  C["mut"], 8)

        wrap = tk.Frame(self.stage, bg=C["stroke"])
        wrap.place(x=x, y=236, width=406, height=128)
        self.input = tk.Text(wrap, bg=C["glass2"], fg=C["ink"],
                             insertbackground=C["cyan"], relief="flat",
                             font=("DejaVu Sans Mono", 10), wrap="word",
                             padx=10, pady=8, undo=True)
        self.input.place(x=1, y=1, width=404, height=126)
        self.input.insert("1.0", "https://example.com")
        self._add_editor_menu(self.input)

        self.clear_btn = NeonButton(self.stage, "✕ Clear", self._clear_input,
                                    w=78, h=26, stops=[C["glass2"],
                                                       C["stroke"]])
        self.clear_btn.set_bg(C["glass"])
        self.clear_btn.place(x=x + 328, y=205)

        self._lbl(x, 384, "TYPE", C["cyan"], 9, True)
        self.itype = ttk.Combobox(self.stage, width=10, state="readonly",
                                  style="A.TCombobox",
                                  values=["auto", "curl", "url", "postman",
                                          "openapi", "har"])
        self.itype.set("auto")
        self.itype.place(x=x + 52, y=376, height=28)
        self.open_btn = NeonButton(self.stage, "Open file…", self._open,
                                   w=120, h=30,
                                   stops=[C["cyan"], C["violet"]])
        self.open_btn.place(x=x + 200, y=375)
        self.paste_btn = NeonButton(self.stage, "Paste", self._paste,
                                    w=78, h=30,
                                    stops=[C["glass2"], C["stroke"]])
        self.paste_btn.set_bg(C["glass"])
        self.paste_btn.place(x=x + 328, y=375)

        self._lbl(x, 420, "MODE", C["cyan"], 10, True)
        self.mode = tk.StringVar(value="manual")
        self._mode_btns = {}
        for i, (val, _t) in enumerate((("manual", 0), ("autopilot", 0),
                                       ("nlp", 0))):
            b = tk.Canvas(self.stage, width=128, height=34, bg=C["glass"],
                          highlightthickness=0, bd=0, cursor="hand2")
            b.place(x=x + i * 136, y=436)
            b.bind("<Button-1>", lambda e, v=val: self._set_mode(v))
            self._mode_btns[val] = b
        self._render_modes()

        self._spin("Concurrency", "concurrency", 10, 488)
        self._spin("Duration (s · 0 = count)", "duration", 0, 524)
        self._spin("Total requests", "requests", 200, 560)
        self._spin("Timeout (s)", "timeout", 15, 596)

        self._lbl(x, 636, "GOAL  (autopilot / AI plan)", C["mut"], 9, True)
        ge = tk.Frame(self.stage, bg=C["stroke"])
        ge.place(x=x, y=652, width=406, height=28)
        self.goal = tk.Entry(ge, bg=C["glass2"], fg=C["ink"],
                             insertbackground=C["cyan"], relief="flat",
                             font=("DejaVu Sans", 10))
        self.goal.place(x=1, y=1, width=404, height=26)
        self.goal.insert(0, "baseline performance & security check")
        self._add_editor_menu(self.goal)

        self.authorized = tk.BooleanVar(value=self.cfg.safety.authorized)
        self.offensive = tk.BooleanVar(value=False)
        Toggle(self.stage, "I am authorised to test the target(s)",
               self.authorized, C["green"]).place(x=x, y=690)
        Toggle(self.stage, "Offensive active scan  (education / research)",
               self.offensive, C["magenta"]).place(x=x, y=720)
        self._lbl(x, 752, "Active DAST · SQLi · XSS · traversal · cmd/SSTI · "
                  "redirect · header-bypass", C["mut"], 8)

        self.start_btn = NeonButton(self.stage, "▶  START", self._start,
                                    w=250, h=46,
                                    stops=[C["cyan"], C["violet"]])
        self.start_btn.place(x=x, y=770)
        self.stop_btn = NeonButton(self.stage, "■  STOP", self._stop,
                                   w=140, h=46,
                                   stops=[C["red"], C["magenta"]])
        self.stop_btn.config_state(False)
        self.stop_btn.place(x=x + 262, y=770)

        self.prog = tk.Canvas(self.stage, width=406, height=14,
                              bg=C["glass2"], highlightthickness=0, bd=0)
        self.prog.place(x=x, y=828)
        self._prog_val = 0.0
        self._shimmer = 0.0
        self._draw_prog()
        self.status = self._lbl(x, 854, "Idle — configure and press Start.",
                                C["mut"], 9)

    def _spin(self, label, attr, default, y):
        x = 50
        self._lbl(x, y, label, C["mut"], 9)
        v = tk.IntVar(value=default)
        setattr(self, f"v_{attr}", v)
        ttk.Spinbox(self.stage, from_=0, to=1_000_000, textvariable=v,
                    width=8, style="A.TSpinbox").place(x=x + 326, y=y - 7,
                                                       height=26)

    def _render_modes(self):
        names = {"manual": "● Manual", "autopilot": "◆ Autopilot",
                 "nlp": "▸ Natural"}
        for val, b in self._mode_btns.items():
            b.delete("all")
            sel = self.mode.get() == val
            stops = ([C["cyan"], C["violet"]] if sel
                     else [C["glass2"], C["glass2"]])
            for i in range(17):
                b.create_rectangle(0, i * 2, 128, i * 2 + 3,
                                   fill=_grad(stops, i / 17), outline="")
            _round(b, 1, 1, 127, 33, 10, fill="",
                    outline=C["cyan"] if sel else C["stroke"], width=1)
            b.create_text(64, 17, text=names[val],
                          fill="#08101f" if sel else C["mut"],
                          font=("DejaVu Sans", 10, "bold"))

    def _set_mode(self, v):
        self.mode.set(v)
        self._render_modes()

    # ---- input editor menu / clipboard -------------------------------- #
    def _add_editor_menu(self, widget):
        is_text = isinstance(widget, tk.Text)
        m = tk.Menu(widget, tearoff=0, bg=C["glass2"], fg=C["ink"],
                    activebackground=C["violet"], activeforeground="#fff",
                    bd=0)
        m.add_command(label="Cut",
                      command=lambda: widget.event_generate("<<Cut>>"))
        m.add_command(label="Copy",
                      command=lambda: widget.event_generate("<<Copy>>"))
        m.add_command(label="Paste",
                      command=lambda: widget.event_generate("<<Paste>>"))
        m.add_separator()
        m.add_command(label="Select all",
                      command=lambda: self._select_all(widget, is_text))
        m.add_command(label="Clear",
                      command=lambda: (widget.delete("1.0", "end")
                                       if is_text else widget.delete(0, "end")))

        def popup(e):
            try:
                m.tk_popup(e.x_root, e.y_root)
            finally:
                m.grab_release()
        widget.bind("<Button-3>", popup)
        widget.bind("<Control-a>",
                    lambda e: (self._select_all(widget, is_text), "break")[1])
        widget.bind("<Control-A>",
                    lambda e: (self._select_all(widget, is_text), "break")[1])

    @staticmethod
    def _select_all(widget, is_text):
        if is_text:
            widget.tag_add("sel", "1.0", "end-1c")
        else:
            widget.select_range(0, "end")
        return "break"

    def _clear_input(self):
        self.input.delete("1.0", "end")
        self.input.focus_set()

    def _paste(self):
        try:
            self.input.insert("insert", self.root.clipboard_get())
        except tk.TclError:
            pass

    # ---- right: tabs + content ---------------------------------------- #
    def _build_right(self):
        self._tabs = ["Summary", "Endpoints", "Security", "Charts"]
        self._tab = 0
        self._tabwidgets = {}
        self.tabbar = tk.Canvas(self.stage, width=800, height=44,
                                bg=C["glass"], highlightthickness=0, bd=0,
                                cursor="hand2")
        self.tabbar.place(x=512, y=192)
        self.tabbar.bind("<Button-1>", self._tab_click)
        self._ind = -1.0
        self._draw_tabs()

        self.content = tk.Frame(self.stage, bg=C["glass"])
        self.content.place(x=512, y=244, width=800, height=556)

        sm = tk.Frame(self.content, bg=C["glass"])
        self.donut = Donut(sm, 200)
        self.donut.place(x=0, y=8)
        self.metrics_lbl = tk.Label(sm, bg=C["glass"], fg=C["ink"],
                                    justify="left", anchor="nw",
                                    font=("DejaVu Sans", 11))
        self.metrics_lbl.place(x=220, y=14, width=560, height=190)
        tk.Label(sm, bg=C["glass"], fg=C["mut"],
                 text="Live throughput (req/s)",
                 font=("DejaVu Sans", 8)).place(x=14, y=210)
        self.spark = Sparkline(sm, 760, 66)
        self.spark.place(x=10, y=226)
        self.summary = tk.Text(sm, bg=C["glass2"], fg=C["ink"], relief="flat",
                               wrap="word", font=("DejaVu Sans", 10),
                               padx=12, pady=10, highlightthickness=0)
        self.summary.place(x=10, y=300, width=778, height=248)
        self.summary.tag_configure("h", foreground=C["cyan"],
                                   font=("DejaVu Sans", 10, "bold"))
        self._add_editor_menu(self.summary)
        self._tabwidgets["Summary"] = sm

        ep = tk.Frame(self.content, bg=C["glass"])
        self.ep_tree = self._tree(
            ep, ("method", "url", "att", "ok", "avg", "p95", "p99", "max"),
            (60, 320, 55, 55, 60, 60, 60, 60))
        self._tabwidgets["Endpoints"] = ep

        se = tk.Frame(self.content, bg=C["glass"])
        self.sec_tree = self._tree(
            se, ("sev", "type", "endpoint", "remediation"),
            (84, 190, 230, 280))
        for sv, col in (("Critical", C["red"]), ("High", "#ff9aa8"),
                        ("Medium", C["amber"]), ("Low", C["cyan"]),
                        ("Info", C["mut"])):
            self.sec_tree.tag_configure(sv, foreground=col)
        self._tabwidgets["Security"] = se

        ch = tk.Frame(self.content, bg=C["glass"])
        self.chart_holder = ch
        self.canvas = None
        if not _HAS_MPL:
            tk.Label(ch, bg=C["glass"], fg=C["mut"],
                     text="matplotlib not available").pack(pady=40)
        self._tabwidgets["Charts"] = ch
        self._show_tab(0)

    def _tree(self, parent, cols, widths):
        wrap = tk.Frame(parent, bg=C["glass"])
        wrap.pack(fill="both", expand=True, padx=6, pady=6)
        t = ttk.Treeview(wrap, columns=cols, show="headings")
        sb = ttk.Scrollbar(wrap, orient="vertical", command=t.yview)
        t.configure(yscrollcommand=sb.set)
        for c, w in zip(cols, widths):
            t.heading(c, text=c.upper())
            t.column(c, width=w, anchor="w" if c in ("url", "endpoint",
                     "remediation") else "center")
        t.tag_configure("odd", background=C["glass"])
        t.tag_configure("even", background=C["glass2"])
        sb.pack(side="right", fill="y")
        t.pack(side="left", fill="both", expand=True)
        return t

    def _draw_tabs(self):
        self.tabbar.delete("all")
        for i, name in enumerate(self._tabs):
            a = i == self._tab
            self.tabbar.create_text(20 + i * 130 + 50, 18, text=name,
                                    fill=C["ink"] if a else C["mut"],
                                    font=("DejaVu Sans", 11,
                                          "bold" if a else "normal"))
        if self._ind < 0:
            self._ind = 20.0
        for k in range(20):
            self.tabbar.create_rectangle(self._ind + k * 5, 38,
                                         self._ind + k * 5 + 6, 41,
                                         fill=_grad(GRAD, k / 20), outline="")

    def _tab_click(self, e):
        self._show_tab(int(max(0, min(3, (e.x - 20) // 130))))

    def _show_tab(self, i):
        self._tab = i
        for w in self._tabwidgets.values():
            w.place_forget()
        self._tabwidgets[self._tabs[i]].place(x=0, y=0, width=800, height=556)
        target = 20 + i * 130

        def slide():
            self._ind += (target - self._ind) * 0.25
            self._draw_tabs()
            if abs(target - self._ind) > 1:
                self.root.after(14, slide)
            else:
                self._ind = float(target)
                self._draw_tabs()
        slide()

    def _build_footer(self):
        x = 512
        for i, (fmt, txt) in enumerate((("html", "↓ HTML"), ("json", "↓ JSON"),
                                        ("md", "↓ MD"), ("csv", "↓ CSV"))):
            NeonButton(self.stage, txt, lambda f=fmt: self._save(f),
                       w=120, h=40,
                       stops=[C["violet"], C["magenta"]]).place(
                x=x + i * 132, y=842)
        self.bg.create_text(1300, 859, anchor="e",
                            text="Authorised testing only · "
                                 "education & research",
                            fill=C["mut"], font=("DejaVu Sans", 8))

    # ---- animation ----------------------------------------------------- #
    def _animate(self):
        self._phase += 0.04
        self.bg.itemconfig(self._sheen,
                           fill=_grad(GRAD, (math.sin(self._phase) + 1) / 2))
        for b in self._blobs:
            b[0] += b[2] * 0.6
            if b[0] > self.W + 120 or b[0] < -120:
                b[2] *= -1
        if int(self._phase * 25) % 3 == 0:
            self._paint_blobs()
        if self.worker and self.worker.is_alive():
            self._shimmer = (self._shimmer + 0.06) % 1.0
            self._draw_prog()
        self.root.after(40, self._animate)

    def _draw_prog(self):
        self.prog.delete("all")
        _round(self.prog, 0, 0, 406, 14, 7, fill=C["glass2"], outline="")
        w = max(2, int(406 * self._prog_val / 100))
        for i in range(w):
            self.prog.create_line(i, 1, i, 13,
                                  fill=_grad(GRAD,
                                             (i / 406 + self._shimmer) % 1.0))
        _round(self.prog, 0, 0, 406, 14, 7, outline=C["stroke"], width=1,
                fill="")

    # ---- file ---------------------------------------------------------- #
    def _open(self):
        p = filedialog.askopenfilename(
            title="Load test input (cURL / URL list / Postman / OpenAPI / HAR)",
            filetypes=[
                ("All supported", "*.txt *.json *.har *.yaml *.yml *.curl "
                                  "*.sh *.list *.csv *.log"),
                ("JSON / Postman / OpenAPI / HAR", "*.json *.har"),
                ("YAML / OpenAPI", "*.yaml *.yml"),
                ("cURL / text / URL list", "*.txt *.curl *.sh *.list"),
                ("All files", "*.*"),
            ])
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
        guess = {".json": "postman", ".har": "har", ".yaml": "openapi",
                 ".yml": "openapi", ".curl": "curl", ".sh": "curl"}.get(
                 ext, "auto")
        self.itype.set(guess)
        self.bg.itemconfig(self.status,
                           text=f"Loaded {os.path.basename(p)} "
                                f"({len(data)} bytes) · type={guess}")

    # ---- run ----------------------------------------------------------- #
    def _start(self):
        if self.worker and self.worker.is_alive():
            return
        raw = self.input.get("1.0", "end").strip()
        if not raw:
            messagebox.showwarning("AEGIS", "Provide target input first.")
            return
        self.cfg.safety.authorized = self.authorized.get()
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
        self.bg.itemconfig(self.status, text="Stopping…")

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
            self.bg.itemconfig(self.status, text=f"● {d['name'].title()} …")
        elif ev == "plan":
            p = d["plan"]
            self.bg.itemconfig(
                self.status, text=f"Plan: {p['mode']} · "
                f"conc={p['concurrency']} · {p.get('rationale','')[:60]}")
        elif ev == "safety":
            self.bg.itemconfig(self.status, text="⚠ " + ", ".join(d["notes"]))
        elif ev == "progress":
            self._prog_val = d.get("percent", 0)
            self._draw_prog()
            self.spark.push(d.get("rps", 0))
            self.bg.itemconfig(
                self.status,
                text=f"{d.get('total',0)} req · {d.get('rps',0):.0f} rps · "
                     f"avg {d.get('avg_ms',0):.0f} ms")
        elif ev == "report":
            self._finish(d["report"])
        elif ev == "error":
            self.start_btn.config_state(True)
            self.stop_btn.config_state(False)
            messagebox.showerror(f"AEGIS — {d['t']}", d["m"])
            self.bg.itemconfig(self.status, text="Failed.")

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
        gc = {"A": C["green"], "B": C["lime"], "C": C["amber"],
              "D": C["red"], "F": C["red"]}.get(ins.grade, C["mut"])
        gv = {"A": .96, "B": .82, "C": .66, "D": .48, "F": .28}.get(
            ins.grade, .1)
        self.donut.set(gv, ins.grade or "—", gc)
        self.bg.itemconfig(self.status,
                           text=f"✔ Done — grade {ins.grade} · "
                                f"{s['success_rate']}% ok")
        self.metrics_lbl.config(text=(
            f"Requests    {s['total_attempts']}   "
            f"(✓ {s['total_successes']}   ✗ {s['total_failures']})\n"
            f"Success      {s['success_rate']} %\n"
            f"Avg latency  {s['overall_avg_ms']} ms\n"
            f"Throughput   {s['throughput_rps']} rps\n"
            f"Top severity {s['highest_severity']}\n"
            f"Engine       {ins.engine}"))
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
        self._show_tab(0)

    def _draw_charts(self, rep: RunReport):
        if not _HAS_MPL:
            return
        if self.canvas:
            self.canvas.get_tk_widget().destroy()
        fig = Figure(figsize=(7.8, 5.3), facecolor=C["glass"])
        fig.subplots_adjust(hspace=0.55, left=0.1, right=0.97, top=0.93,
                            bottom=0.12)
        ax1, ax2 = fig.add_subplot(211), fig.add_subplot(212)
        for ax in (ax1, ax2):
            ax.set_facecolor(C["glass2"])
            for sp in ax.spines.values():
                sp.set_color(C["stroke"])
            ax.tick_params(colors=C["mut"], labelsize=8)
        eps = rep.endpoints[:6]
        labels = [e.url.split("//")[-1][:18] for e in eps] or ["—"]
        xs = range(len(labels))
        ax1.bar([i - .25 for i in xs], [e.p50 for e in eps], .25, label="p50",
                color=C["cyan"])
        ax1.bar(list(xs), [e.p95 for e in eps], .25, label="p95",
                color=C["violet"])
        ax1.bar([i + .25 for i in xs], [e.p99 for e in eps], .25, label="p99",
                color=C["magenta"])
        ax1.set_xticks(list(xs))
        ax1.set_xticklabels(labels, rotation=18, ha="right")
        ax1.set_title("Latency percentiles (ms)", color=C["ink"], fontsize=10)
        ax1.legend(facecolor=C["glass"], edgecolor=C["stroke"],
                   labelcolor=C["ink"], fontsize=8)
        sev = {}
        for v in rep.vulnerabilities:
            sev[v.severity.value] = sev.get(v.severity.value, 0) + 1
        cols = {"Critical": C["red"], "High": "#ff9aa8", "Medium": C["amber"],
                "Low": C["cyan"], "Info": C["mut"]}
        names = [o for o in ("Critical", "High", "Medium", "Low", "Info")
                 if sev.get(o)]
        if names:
            ax2.barh(names, [sev[n] for n in names],
                     color=[cols[n] for n in names])
            ax2.invert_yaxis()
        else:
            ax2.text(0.5, 0.5, "No security findings ✓", ha="center",
                     color=C["green"], transform=ax2.transAxes)
        ax2.set_title("Security findings by severity", color=C["ink"],
                      fontsize=10)
        self.canvas = FigureCanvasTkAgg(fig, master=self.chart_holder)
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
