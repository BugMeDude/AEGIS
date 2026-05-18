"""AEGIS desktop GUI — a clean, modern ttk rebuild of the old GuiManager.

Design goals that the original monolith missed:
  * UI is a thin shell over :class:`Orchestrator` (no business logic here).
  * The engine runs in a worker thread; the UI thread only consumes a queue
    via ``after()`` so it never freezes.
  * Cooperative stop, live percentiles, tabbed results, embedded chart.
"""

from __future__ import annotations

import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from . import EDU_CAPTION, EDU_NOTICE
from .config import AegisConfig
from .models import RunReport
from .orchestrator import Orchestrator
from .reporting import write_reports
from .safety import SafetyError

# Optional charting.
try:
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    from matplotlib.figure import Figure
    _HAS_MPL = True
except Exception:  # pragma: no cover
    _HAS_MPL = False

BG = "#0c0f17"
CARD = "#151a26"
INK = "#e6edf3"
MUT = "#8b97a8"
ACC = "#58a6ff"
OK = "#3fb950"
BAD = "#f85149"
WARN = "#d29922"


class AegisGUI:
    def __init__(self, root: tk.Tk, config: AegisConfig) -> None:
        self.root = root
        self.cfg = config
        self.orch = Orchestrator(config)
        self.events: queue.Queue = queue.Queue()
        self.worker: threading.Thread | None = None
        self.stop_flag = threading.Event()
        self.report: RunReport | None = None

        root.title("AEGIS — Autonomous API Stress & Security Intelligence")
        root.geometry("1280x860")
        root.configure(bg=BG)
        root.minsize(1040, 720)
        self._style()
        self._build()
        self.root.after(120, self._pump)

    # ------------------------------------------------------------------ #
    def _style(self) -> None:
        st = ttk.Style()
        try:
            st.theme_use("clam")
        except tk.TclError:
            pass
        st.configure(".", background=BG, foreground=INK, fieldbackground=CARD,
                     bordercolor="#232a3a", font=("Segoe UI", 10))
        st.configure("TFrame", background=BG)
        st.configure("Card.TFrame", background=CARD)
        st.configure("TLabel", background=BG, foreground=INK)
        st.configure("Muted.TLabel", background=BG, foreground=MUT)
        st.configure("Title.TLabel", background=BG, foreground=ACC,
                     font=("Segoe UI", 17, "bold"))
        st.configure("TButton", background="#1f6feb", foreground="white",
                     borderwidth=0, padding=8, font=("Segoe UI", 10, "bold"))
        st.map("TButton", background=[("active", "#388bfd"),
                                      ("disabled", "#30363d")])
        st.configure("Stop.TButton", background=BAD)
        st.map("Stop.TButton", background=[("active", "#ff7b72")])
        st.configure("TNotebook", background=BG, borderwidth=0)
        st.configure("TNotebook.Tab", background=CARD, foreground=MUT,
                     padding=(16, 8))
        st.map("TNotebook.Tab", background=[("selected", "#1f6feb")],
               foreground=[("selected", "white")])
        st.configure("Treeview", background=CARD, fieldbackground=CARD,
                     foreground=INK, rowheight=26, borderwidth=0)
        st.configure("Treeview.Heading", background="#1b2230",
                     foreground=MUT, font=("Segoe UI", 9, "bold"))
        st.configure("TEntry", fieldbackground=CARD, foreground=INK)
        st.configure("TCombobox", fieldbackground=CARD, foreground=INK)
        st.configure("Horizontal.TProgressbar", background=ACC,
                     troughcolor=CARD, borderwidth=0)
        st.configure("TCheckbutton", background=BG, foreground=INK)
        st.configure("TLabelframe", background=BG, foreground=MUT)
        st.configure("TLabelframe.Label", background=BG, foreground=MUT)

    # ------------------------------------------------------------------ #
    def _build(self) -> None:
        top = ttk.Frame(self.root, padding=14)
        top.pack(fill="x")
        ttk.Label(top, text="🛡  AEGIS", style="Title.TLabel").pack(side="left")
        ttk.Label(top, text="  Autonomous API Stress & Security Intelligence",
                  style="Muted.TLabel").pack(side="left", pady=(6, 0))
        eng = ("LLM: " + self.orch.brain.client.active_model
               if self.orch.brain.client.available else "Heuristic engine")
        ttk.Label(top, text=eng, style="Muted.TLabel").pack(side="right",
                                                            pady=(6, 0))

        cap = ttk.Frame(self.root, style="TFrame")
        cap.pack(fill="x", padx=14)
        lbl = tk.Label(cap, text="  " + EDU_CAPTION + "  ", bg="#3a2f0b",
                       fg="#f0c674", font=("Segoe UI", 9, "bold"),
                       anchor="w", padx=8, pady=3)
        lbl.pack(fill="x")

        body = ttk.Frame(self.root, padding=(14, 0, 14, 14))
        body.pack(fill="both", expand=True)
        body.columnconfigure(0, weight=1, minsize=420)
        body.columnconfigure(1, weight=2)
        body.rowconfigure(0, weight=1)

        self._build_left(body)
        self._build_right(body)

    def _build_left(self, parent: ttk.Frame) -> None:
        left = ttk.Frame(parent, style="Card.TFrame", padding=14)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 12))

        ttk.Label(left, text="Input  (cURL · URL · Postman · OpenAPI · HAR)",
                  background=CARD, foreground=MUT).pack(anchor="w")
        self.input = tk.Text(left, height=9, bg="#0d1117", fg=INK,
                             insertbackground=INK, relief="flat",
                             font=("JetBrains Mono", 10), wrap="word",
                             padx=8, pady=8)
        self.input.pack(fill="x", pady=(4, 10))
        self.input.insert("1.0", "https://example.com")

        row = ttk.Frame(left, style="Card.TFrame")
        row.pack(fill="x", pady=4)
        ttk.Label(row, text="Type", background=CARD).pack(side="left")
        self.itype = ttk.Combobox(row, width=10, state="readonly",
                                  values=["auto", "curl", "url", "postman",
                                          "openapi", "har"])
        self.itype.set("auto")
        self.itype.pack(side="left", padx=6)
        ttk.Button(row, text="Open file…", command=self._open
                   ).pack(side="right")

        mode = ttk.LabelFrame(left, text="Mode", padding=8)
        mode.pack(fill="x", pady=12)
        self.mode = tk.StringVar(value="manual")
        for txt, val in (("Manual plan", "manual"),
                         ("🤖 Autopilot (AI plans)", "autopilot"),
                         ("Natural language", "nlp")):
            ttk.Radiobutton(mode, text=txt, value=val, variable=self.mode,
                            command=self._mode_changed).pack(anchor="w")

        self.manual = ttk.Frame(left, style="Card.TFrame")
        self.manual.pack(fill="x")
        self._spin(self.manual, "Concurrency", "concurrency", 10, 0)
        self._spin(self.manual, "Duration (s, 0=count)", "duration", 0, 1)
        self._spin(self.manual, "Total requests", "requests", 200, 2)
        self._spin(self.manual, "Timeout (s)", "timeout", 15, 3)

        self.goal_row = ttk.Frame(left, style="Card.TFrame")
        ttk.Label(self.goal_row, text="Goal", background=CARD).pack(side="left")
        self.goal = ttk.Entry(self.goal_row)
        self.goal.pack(side="left", fill="x", expand=True, padx=6)
        self.goal.insert(0, "baseline performance & security check")

        self.authorized = tk.BooleanVar(value=self.cfg.safety.authorized)
        ttk.Checkbutton(
            left, variable=self.authorized,
            text="I am authorised to test the target system(s)").pack(
            anchor="w", pady=(14, 2))
        self.offensive = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            left, variable=self.offensive,
            text="⚔ Offensive active scan (education / research)").pack(
            anchor="w", pady=(0, 2))
        ttk.Label(left, text="Active DAST: SQLi · XSS · traversal · cmd/SSTI · "
                  "redirect · header bypass", style="Muted.TLabel",
                  background=CARD, font=("Segoe UI", 8)).pack(anchor="w")

        btns = ttk.Frame(left, style="Card.TFrame")
        btns.pack(fill="x", pady=8)
        self.start_btn = ttk.Button(btns, text="▶  Start", command=self._start)
        self.start_btn.pack(side="left", expand=True, fill="x", padx=(0, 4))
        self.stop_btn = ttk.Button(btns, text="■  Stop", style="Stop.TButton",
                                   command=self._stop, state="disabled")
        self.stop_btn.pack(side="left", expand=True, fill="x", padx=(4, 0))

        self.pbar = ttk.Progressbar(left, mode="determinate", maximum=100)
        self.pbar.pack(fill="x", pady=(10, 4))
        self.status = ttk.Label(left, text="Idle.", background=CARD,
                                foreground=MUT)
        self.status.pack(anchor="w")

    def _spin(self, parent, label, attr, default, r) -> None:
        parent.columnconfigure(1, weight=1)
        ttk.Label(parent, text=label, background=CARD).grid(
            row=r, column=0, sticky="w", pady=3)
        var = tk.IntVar(value=default)
        setattr(self, f"v_{attr}", var)
        ttk.Spinbox(parent, from_=0, to=1_000_000, textvariable=var,
                    width=10).grid(row=r, column=1, sticky="e", pady=3)

    def _build_right(self, parent: ttk.Frame) -> None:
        right = ttk.Frame(parent)
        right.grid(row=0, column=1, sticky="nsew")
        self.nb = ttk.Notebook(right)
        self.nb.pack(fill="both", expand=True)

        # Summary tab
        self.sum_tab = ttk.Frame(self.nb, style="Card.TFrame", padding=14)
        self.nb.add(self.sum_tab, text="Summary")
        self.summary = tk.Text(self.sum_tab, bg=CARD, fg=INK, relief="flat",
                               wrap="word", font=("Segoe UI", 11),
                               padx=10, pady=10, state="disabled")
        self.summary.pack(fill="both", expand=True)

        # Endpoints tab
        ep = ttk.Frame(self.nb, style="Card.TFrame")
        self.nb.add(ep, text="Endpoints")
        cols = ("method", "url", "att", "ok", "avg", "p95", "p99", "max")
        self.ep_tree = ttk.Treeview(ep, columns=cols, show="headings")
        for c, w in zip(cols, (60, 360, 60, 55, 60, 60, 60, 60)):
            self.ep_tree.heading(c, text=c.upper())
            self.ep_tree.column(c, width=w, anchor="w" if c == "url" else "center")
        self.ep_tree.pack(fill="both", expand=True, padx=6, pady=6)

        # Security tab
        se = ttk.Frame(self.nb, style="Card.TFrame")
        self.nb.add(se, text="Security")
        scols = ("sev", "type", "endpoint", "remediation")
        self.sec_tree = ttk.Treeview(se, columns=scols, show="headings")
        for c, w in zip(scols, (80, 200, 260, 360)):
            self.sec_tree.heading(c, text=c.upper())
            self.sec_tree.column(c, width=w, anchor="w")
        self.sec_tree.tag_configure("Critical", foreground=BAD)
        self.sec_tree.tag_configure("High", foreground="#ff7b72")
        self.sec_tree.tag_configure("Medium", foreground=WARN)
        self.sec_tree.tag_configure("Low", foreground=ACC)
        self.sec_tree.pack(fill="both", expand=True, padx=6, pady=6)

        # Chart tab
        if _HAS_MPL:
            self.chart_tab = ttk.Frame(self.nb, style="Card.TFrame")
            self.nb.add(self.chart_tab, text="Chart")
            self.canvas = None

        bar = ttk.Frame(right, padding=(0, 8, 0, 0))
        bar.pack(fill="x")
        for fmt in ("html", "json", "md", "csv"):
            ttk.Button(bar, text=f"Save {fmt.upper()}",
                       command=lambda f=fmt: self._save(f)).pack(
                side="left", padx=4)

    # ------------------------------------------------------------------ #
    def _mode_changed(self) -> None:
        m = self.mode.get()
        for w in (self.manual, self.goal_row):
            w.pack_forget()
        if m == "manual":
            self.manual.pack(fill="x")
        elif m == "autopilot":
            self.goal_row.pack(fill="x", pady=6)

    def _open(self) -> None:
        path = filedialog.askopenfilename(
            filetypes=[("Supported", "*.txt *.json *.har *.yaml *.yml"),
                       ("All", "*.*")])
        if path:
            with open(path, encoding="utf-8") as fh:
                self.input.delete("1.0", "end")
                self.input.insert("1.0", fh.read())

    # ------------------------------------------------------------------ #
    def _start(self) -> None:
        if self.worker and self.worker.is_alive():
            return
        raw = self.input.get("1.0", "end").strip()
        if not raw:
            messagebox.showwarning("AEGIS", "Provide input first.")
            return
        self.cfg.safety.authorized = self.authorized.get()
        self.orch = Orchestrator(self.cfg)
        offensive = self.offensive.get()
        self.stop_flag.clear()
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.pbar["value"] = 0
        self._clear_results()
        mode = self.mode.get()

        def job() -> None:
            try:
                cb = lambda e, d: self.events.put((e, d))
                stop = self.stop_flag.is_set
                if mode == "nlp":
                    rep = self.orch.from_nlp(raw, on_event=cb, should_stop=stop)
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
                self.events.put(("error", {"title": "Refused", "msg": str(e)}))
            except Exception as e:
                self.events.put(("error",
                                 {"title": type(e).__name__, "msg": str(e)}))

        self.worker = threading.Thread(target=job, daemon=True)
        self.worker.start()

    def _stop(self) -> None:
        self.stop_flag.set()
        self.status.config(text="Stopping…")

    # ------------------------------------------------------------------ #
    def _pump(self) -> None:
        try:
            while True:
                event, data = self.events.get_nowait()
                self._handle(event, data)
        except queue.Empty:
            pass
        self.root.after(120, self._pump)

    def _handle(self, event: str, data: dict) -> None:
        if event == "phase":
            self.status.config(text=f"{data['name'].title()}…")
        elif event == "plan":
            p = data["plan"]
            self.status.config(text=f"Plan: {p['mode']} conc={p['concurrency']}")
        elif event == "safety":
            self.status.config(text="Safety clamp: " + ", ".join(data["notes"]))
        elif event == "progress":
            self.pbar["value"] = data.get("percent", 0)
            self.status.config(
                text=f"{data.get('total',0)} reqs · "
                     f"{data.get('rps',0):.0f} rps · "
                     f"avg {data.get('avg_ms',0):.0f} ms")
        elif event == "report":
            self._finish(data["report"])
        elif event == "error":
            self._reset_buttons()
            messagebox.showerror(f"AEGIS — {data['title']}", data["msg"])
            self.status.config(text="Failed.")

    def _clear_results(self) -> None:
        self.ep_tree.delete(*self.ep_tree.get_children())
        self.sec_tree.delete(*self.sec_tree.get_children())
        self.summary.config(state="normal")
        self.summary.delete("1.0", "end")
        self.summary.config(state="disabled")

    def _reset_buttons(self) -> None:
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")

    def _finish(self, rep: RunReport) -> None:
        self.report = rep
        self._reset_buttons()
        self.pbar["value"] = 100
        d = rep.to_dict()
        s, ins = d["summary"], rep.insight
        self.status.config(text=f"Done — grade {ins.grade} · "
                                f"{s['success_rate']}% ok")

        txt = (
            f"GRADE  {ins.grade}\n"
            f"{'='*60}\n"
            f"Requests      {s['total_attempts']}  "
            f"(✓{s['total_successes']}  ✗{s['total_failures']})\n"
            f"Success rate  {s['success_rate']} %\n"
            f"Avg latency   {s['overall_avg_ms']} ms\n"
            f"Throughput    {s['throughput_rps']} rps\n"
            f"Top severity  {s['highest_severity']}\n"
            f"AI engine     {ins.engine}\n"
            f"{'='*60}\n\n"
            f"SUMMARY\n{ins.summary}\n\n"
            f"BENCHMARK\n{ins.benchmark}\n\n"
            f"OPTIMIZATION\n{ins.optimization}\n\n"
            f"FORECAST\n{ins.prediction}\n\n"
            f"SUGGESTED ASSERTIONS\n" +
            "\n".join(f"  • {a}" for a in ins.assertions)
        )
        self.summary.config(state="normal")
        self.summary.delete("1.0", "end")
        self.summary.insert("1.0", txt)
        self.summary.config(state="disabled")

        for e in rep.endpoints:
            self.ep_tree.insert("", "end", values=(
                e.method, e.url, e.attempts, f"{e.success_rate:.0f}%",
                f"{e.avg_ms:.0f}", f"{e.p95:.0f}", f"{e.p99:.0f}",
                f"{e.max_ms:.0f}"))
        for v in rep.vulnerabilities:
            self.sec_tree.insert("", "end",
                                 values=(v.severity.value, v.type,
                                         v.endpoint, v.remediation),
                                 tags=(v.severity.value,))
        self._draw_chart(rep)

    def _draw_chart(self, rep: RunReport) -> None:
        if not _HAS_MPL or not rep.endpoints:
            return
        if self.canvas:
            self.canvas.get_tk_widget().destroy()
        fig = Figure(figsize=(7, 4.6), facecolor=CARD)
        ax = fig.add_subplot(111)
        ax.set_facecolor(CARD)
        labels = [e.url.split("//")[-1][:24] for e in rep.endpoints]
        x = range(len(labels))
        ax.bar([i - 0.2 for i in x], [e.avg_ms for e in rep.endpoints],
               0.4, label="avg ms", color=ACC)
        ax.bar([i + 0.2 for i in x], [e.p95 for e in rep.endpoints],
               0.4, label="p95 ms", color=WARN)
        ax.set_xticks(list(x))
        ax.set_xticklabels(labels, rotation=20, ha="right", fontsize=8)
        for spine in ax.spines.values():
            spine.set_color("#232a3a")
        ax.tick_params(colors=MUT)
        ax.set_title("Latency by endpoint", color=INK)
        ax.legend(facecolor=CARD, labelcolor=INK)
        fig.tight_layout()
        self.canvas = FigureCanvasTkAgg(fig, master=self.chart_tab)
        self.canvas.draw()
        self.canvas.get_tk_widget().pack(fill="both", expand=True)

    def _save(self, fmt: str) -> None:
        if not self.report:
            messagebox.showinfo("AEGIS", "Run a test first.")
            return
        written = write_reports(self.report, self.cfg.report_dir, [fmt])
        messagebox.showinfo("AEGIS", f"Saved:\n{list(written.values())[0]}")


def launch(config: AegisConfig | None = None) -> None:
    root = tk.Tk()
    AegisGUI(root, config or AegisConfig.load())
    root.mainloop()


if __name__ == "__main__":
    launch()
