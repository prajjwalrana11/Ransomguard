"""RansomGuard desktop application - early-2000s "classic Windows" look.
Everything (protect, investigate, recover, demos, SQL, settings) is available from this window.
Threading rule: Tk is touched only by the main thread; background threads post text to a queue."""
import os
import queue
import sys
import threading
import time
import traceback
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import psutil

from . import lab
from .db import HIDDEN_CONFIG, format_report
from .engine import Engine
from .report_pdf import write_pdf

BG, NAVY, TEAL, WHITE, DARK = "#D4D0C8", "#0A246A", "#008080", "#FFFFFF", "#808080"
FONT, FONT_B, MONO = ("Tahoma", 9), ("Tahoma", 9, "bold"), ("Courier New", 9)
CANNED_FALLBACK = [("Incident history", "SELECT id, status, severity, risk_score FROM incidents ORDER BY created_ts DESC LIMIT 20")]


def parse_canned():
    path = os.path.join(lab.PKG_PARENT, "queries.sql")
    out, title, buf = [], None, []
    try:
        for line in open(path):
            if line.startswith("-- Q"):
                if title and buf:
                    out.append((title, " ".join(buf).strip()))
                title, buf = line[3:].strip(), []
            elif title and not line.startswith("--") and line.strip():
                buf.append(line.strip())
        if title and buf:
            out.append((title, " ".join(buf).strip()))
    except OSError:
        pass
    return out or CANNED_FALLBACK


class App:
    def __init__(self, data_dir, splash=True):
        self.eng = Engine(data_dir, on_log=lambda l, m: self.outq.put(("log", f"[{l}] {m}")))
        self.outq, self.busy, self.sigs, self.last_report = queue.Queue(), False, {}, None
        self._alert_win = None
        self.eng.on_incident = lambda iid: self.outq.put(("incident", iid))      # engine thread -> Tk main thread
        self.root = tk.Tk()
        self.root.withdraw()
        self.root.title("RansomGuard 1.0 - Real-time Ransomware Protection")
        self.root.geometry("1040x700")
        self.root.minsize(900, 600)
        self.root.configure(bg=BG)
        self.root.option_add("*Font", FONT)
        self._style()
        self._build()
        self.root.protocol("WM_DELETE_WINDOW", self.quit)
        if splash:
            self._splash()
        else:
            self._launch()

    # ------------------------------------------------------------------ look & feel
    def _style(self):
        st = ttk.Style()
        st.theme_use("classic")
        st.configure(".", background=BG, font=FONT)
        st.configure("Treeview", background=WHITE, fieldbackground=WHITE, rowheight=18, font=FONT, borderwidth=2, relief="sunken")
        st.configure("Treeview.Heading", background=BG, font=FONT_B, relief="raised", borderwidth=2)
        st.map("Treeview", background=[("selected", NAVY)], foreground=[("selected", WHITE)])
        st.configure("TNotebook", background=BG, borderwidth=2)
        st.configure("TNotebook.Tab", background=BG, padding=(12, 3), font=FONT)
        st.map("TNotebook.Tab", background=[("selected", BG)], expand=[("selected", (1, 1, 1, 0))])
        st.configure("TCombobox", font=FONT)
        st.configure("Horizontal.TProgressbar", background=NAVY, troughcolor=WHITE)

    def btn(self, parent, text, cmd, width=None):
        return tk.Button(parent, text=text, command=cmd, bg=BG, activebackground="#E4E0D8", relief="raised", bd=2,
                         padx=8, pady=1, width=width, font=FONT, highlightthickness=0)

    def group(self, parent, title):
        return tk.LabelFrame(parent, text=title, bg=BG, bd=2, relief="groove", font=FONT_B, padx=6, pady=4)

    def tree(self, parent, cols, height=10, expand=True):
        f = tk.Frame(parent, bg=BG)
        t = ttk.Treeview(f, columns=[c[0] for c in cols], show="headings", height=height)
        for name, w in cols:
            t.heading(name, text=name)
            t.column(name, width=w, anchor="w", stretch=(w >= 200))
        sb = ttk.Scrollbar(f, orient="vertical", command=t.yview)
        t.configure(yscrollcommand=sb.set)
        t.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        f.pack(fill="both" if expand else "x", expand=expand)
        return t

    def text(self, parent, dark=False, height=10):
        f = tk.Frame(parent, bg=BG, bd=2, relief="sunken")
        t = tk.Text(f, wrap="none", font=MONO, height=height, bd=0,
                    bg="black" if dark else WHITE, fg="#C0C0C0" if dark else "black", insertbackground="#C0C0C0")
        sy, sx = ttk.Scrollbar(f, command=t.yview), ttk.Scrollbar(f, orient="horizontal", command=t.xview)
        t.configure(yscrollcommand=sy.set, xscrollcommand=sx.set)
        sy.pack(side="right", fill="y")
        sx.pack(side="bottom", fill="x")
        t.pack(fill="both", expand=True)
        f.pack(fill="both", expand=True)
        return t

    def fill(self, t, rows, key=None):
        sig = hash(tuple(rows))
        if self.sigs.get(key or str(t)) == sig:
            return
        self.sigs[key or str(t)] = sig
        sel = set(t.selection())
        t.delete(*t.get_children())
        for r in rows:
            t.insert("", "end", iid=str(r[0]), values=r)
        keep = [i for i in sel if t.exists(i)]
        if keep:
            t.selection_set(keep)

    # ------------------------------------------------------------------ splash / launch
    def _splash(self):
        s = tk.Toplevel(self.root)
        s.overrideredirect(True)
        w, h = 420, 210
        s.geometry(f"{w}x{h}+{(s.winfo_screenwidth() - w) // 2}+{(s.winfo_screenheight() - h) // 2}")
        s.configure(bg=BG, bd=3, relief="raised")
        top = tk.Frame(s, bg=NAVY, height=70)
        top.pack(fill="x")
        tk.Label(top, text="RansomGuard", bg=NAVY, fg=WHITE, font=("Times New Roman", 26, "bold italic")).pack(pady=(8, 0))
        tk.Label(top, text="Real-time Ransomware Protection  -  Version 1.0", bg=NAVY, fg="#B0C4FF", font=FONT).pack()
        msg = tk.StringVar(value="Loading modules...")
        tk.Label(s, textvariable=msg, bg=BG, font=FONT).pack(pady=(18, 4))
        pb = ttk.Progressbar(s, length=340, maximum=100)
        pb.pack()
        tk.Label(s, text="Copyright (c) 2026  University CS Project  -  OS + DBMS Edition", bg=BG, fg=DARK, font=("Tahoma", 8)).pack(side="bottom", pady=6)
        steps = ["Initialising SQLite database...", "Loading detection rules...", "Starting filesystem watcher...", "Ready."]

        def tick(i=0):
            pb["value"] = (i + 1) * 25
            msg.set(steps[min(i, 3)])
            if i < 3:
                s.after(280, tick, i + 1)
            else:
                s.after(300, lambda: (s.destroy(), self._launch()))
        tick()

    def _launch(self):
        self.root.deiconify()
        self.eng.cfg = self.eng.db.get_config()
        if self.eng.db.one("SELECT COUNT(*) n FROM protected_folders WHERE active=1")["n"]:
            self.eng.start()
        self.refresh()
        self.pump()

    # ------------------------------------------------------------------ layout
    def _build(self):
        r = self.root
        self._menus()
        ban = tk.Frame(r, bg=NAVY, height=54)
        ban.pack(fill="x")
        tk.Label(ban, text="RansomGuard", bg=NAVY, fg=WHITE, font=("Times New Roman", 22, "bold italic")).pack(side="left", padx=10, pady=4)
        tk.Label(ban, text="Real-time Ransomware Protection", bg=NAVY, fg="#B0C4FF", font=FONT).pack(side="left", pady=(14, 0))
        self.led = tk.Canvas(ban, width=22, height=22, bg=NAVY, highlightthickness=0)
        self.led.pack(side="right", padx=(0, 12))
        self.led_id = self.led.create_oval(3, 3, 19, 19, fill="gray", outline=WHITE)
        self.banner_status = tk.StringVar()
        tk.Label(ban, textvariable=self.banner_status, bg=NAVY, fg=WHITE, font=FONT_B).pack(side="right", padx=6)

        tb = tk.Frame(r, bg=BG, bd=2, relief="groove")
        tb.pack(fill="x", padx=2, pady=2)
        for text, cmd in (("Start", self.start), ("Stop", self.stop), ("Add Folder...", self.add_folder),
                          ("Scan", self.scan_selected), ("|", None), ("Simulate Attack", lambda: self.bg(lab.start_attack)),
                          ("Run Demos", lambda: self.run_demos(range(1, len(lab.DEMOS) + 1))), ("SQL Console", lambda: self.nb.select(self.tab_db)),
                          ("|", None), ("Trusted Apps...", self.trusted_apps), ("Settings...", self.settings)):
            if cmd is None:
                tk.Frame(tb, width=2, bd=1, relief="sunken", bg=BG).pack(side="left", fill="y", padx=4, pady=2)
            else:
                self.btn(tb, text, cmd).pack(side="left", padx=2, pady=2)

        sbar = tk.Frame(r, bg=BG)
        sbar.pack(side="bottom", fill="x")
        self.sv = [tk.StringVar(value="Ready"), tk.StringVar(), tk.StringVar()]
        for i, (v, w) in enumerate(zip(self.sv, (0, 38, 24))):
            tk.Label(sbar, textvariable=v, bd=1, relief="sunken", anchor="w", bg=BG, width=w, font=FONT).pack(
                side="left", fill="x", expand=(i == 0), padx=1, pady=1)

        self.nb = ttk.Notebook(r)
        self.nb.pack(fill="both", expand=True, padx=4, pady=4)
        mk = lambda name: (lambda f: (self.nb.add(f, text=name), f)[1])(tk.Frame(self.nb, bg=BG, padx=6, pady=6))
        self.tab_prot, self.tab_ev, self.tab_inc = mk("Protection"), mk("Live Events"), mk("Incidents")
        self.tab_q, self.tab_proc, self.tab_db = mk("Quarantine"), mk("Processes"), mk("Database")
        self.tab_demo, self.tab_log = mk("Demonstrations"), mk("Event Log")
        self._tab_protection(); self._tab_events(); self._tab_incidents(); self._tab_quarantine()
        self._tab_processes(); self._tab_database(); self._tab_demos(); self._tab_log()

    def _menus(self):
        m = tk.Menu(self.root, bg=BG, font=FONT)
        def sub(label, items):
            mm = tk.Menu(m, tearoff=0, bg=BG, font=FONT)
            for it in items:
                mm.add_separator() if it is None else mm.add_command(label=it[0], command=it[1])
            m.add_cascade(label=label, menu=mm)
        sub("File", [("Add Protected Folder...", self.add_folder), ("Back Up Database...", self.backup_db), None, ("Exit", self.quit)])
        sub("Protection", [("Start Monitoring", self.start), ("Stop Monitoring", self.stop), None, ("Scan Selected Folder", self.scan_selected),
                           ("Trusted Apps...", self.trusted_apps), ("Settings...", self.settings)])
        sub("Tools", [("Create / Reset Test Lab", lambda: self.bg(lambda e, s: (lab.ensure_lab(e, s), s("lab ready: " + lab.lab_root(e))))),
                      ("Simulate Ransomware Attack", lambda: self.bg(lab.start_attack)), ("Kill Simulator", self._kill_sim), None,
                      ("Re-arm Decoy Files", lambda: self.sv[0].set(f"{self.eng.rearm_canaries()} decoy file(s) re-armed")), None,
                      ("Verify Audit Log", self.verify_audit), ("Prune Old Events...", self.prune),
                      ("Check Database Integrity", self.integrity), ("Show Database Schema", self.schema), None,
                      ("Run Adversarial Evaluation (several minutes)", lambda: self.bg(lambda e, s: s(__import__("ransomguard.evaluate", fromlist=["run"]).run(s))))])
        sub("Demonstrations", [(f"{n}. {t}", (lambda n=n: self.run_demos([n]))) for n, t, _, _ in lab.DEMOS] + [None, ("Run All", lambda: self.run_demos(range(1, len(lab.DEMOS) + 1)))])
        sub("Help", [("OS and DBMS Concepts...", self.concepts), ("About RansomGuard", self.about)])
        self.root.config(menu=m)

    # ------------------------------------------------------------------ tabs
    def _tab_protection(self):
        g = self.group(self.tab_prot, "Protected folders")
        g.pack(fill="both", expand=True)
        self.t_folders = self.tree(g, [("id", 40), ("path", 560), ("backups", 70), ("incidents", 70)], height=5)
        b = tk.Frame(g, bg=BG); b.pack(anchor="w", pady=4)
        for t, c in (("Add...", self.add_folder), ("Remove", self.remove_folder), ("Scan selected", self.scan_selected)):
            self.btn(b, t, c, 14).pack(side="left", padx=2)
        row = tk.Frame(self.tab_prot, bg=BG); row.pack(fill="x")
        g2 = self.group(row, "Engine status"); g2.pack(side="left", fill="both", expand=True, padx=(0, 4))
        self.stat = {}
        for i, k in enumerate(("Notification API", "Event queue", "Received / processed", "Duplicates collapsed", "Spooled to disk",
                               "Database errors", "Open incidents", "Decoy files", "Audit chain", "Database size")):
            tk.Label(g2, text=k + ":", bg=BG, anchor="w").grid(row=i, column=0, sticky="w")
            self.stat[k] = tk.Label(g2, text="-", bg=BG, anchor="w", font=FONT_B)
            self.stat[k].grid(row=i, column=1, sticky="w", padx=8)
        g3 = self.group(row, "Scan history"); g3.pack(side="left", fill="both", expand=True)
        self.t_scans = self.tree(g3, [("id", 30), ("status", 80), ("files", 60), ("flagged", 60)], height=5)
        self.t_scans.bind("<<TreeviewSelect>>", self._scan_pick)
        self.t_scanres = self.tree(g3, [("path", 300), ("reason", 160)], height=4)
        self.t_scanres.configure(show="headings")

    def _tab_events(self):
        self.paused = tk.BooleanVar()
        tk.Checkbutton(self.tab_ev, text="Pause updates", variable=self.paused, bg=BG, activebackground=BG).pack(anchor="w")
        self.t_ev = self.tree(self.tab_ev, [("id", 50), ("time", 80), ("type", 70), ("path", 380), ("renamed to", 200), ("entropy", 55), ("attribution", 80), ("pid", 55)], height=24)

    def _tab_incidents(self):
        self.t_inc = self.tree(self.tab_inc, [("id", 40), ("time", 80), ("severity", 70), ("risk", 50), ("status", 80), ("pid", 55), ("process", 120)], height=6, expand=False)
        self.t_inc.bind("<<TreeviewSelect>>", lambda e: self.show_incident())
        b = tk.Frame(self.tab_inc, bg=BG); b.pack(anchor="w", pady=4)
        for t, c in (("Recover from backup", self.recover), ("Mark false positive", self.false_pos), ("Resume process", lambda: self.proc_act(False)),
                     ("Terminate process", lambda: self.proc_act(True)), ("Export PDF report...", self.export_pdf)):
            self.btn(b, t, c).pack(side="left", padx=2)
        self.report = self.text(self.tab_inc)

    def _tab_quarantine(self):
        self.t_q = self.tree(self.tab_q, [("id", 40), ("incident", 60), ("status", 90), ("original path", 440), ("sha256", 150), ("integrity", 70)], height=18)
        b = tk.Frame(self.tab_q, bg=BG); b.pack(anchor="w", pady=4)
        self.btn(b, "Restore (hash-verified)", lambda: self.restore(False)).pack(side="left", padx=2)
        self.btn(b, "Restore to...", lambda: self.restore(True)).pack(side="left", padx=2)

    def _tab_processes(self):
        g = self.group(self.tab_proc, "Process lifecycle inside protected folders"); g.pack(fill="both", expand=True)
        self.t_pe = self.tree(g, [("id", 40), ("when", 90), ("event", 70), ("pid", 60), ("name", 120), ("exe", 380)], height=8)
        g = self.group(self.tab_proc, "Attribution observations (which process was seen touching a folder)"); g.pack(fill="both", expand=True)
        self.t_po = self.tree(g, [("id", 40), ("when", 90), ("pid", 60), ("name", 110), ("parent", 110), ("user", 80), ("method", 80), ("confidence", 80)], height=8)

    def _tab_database(self):
        top = tk.Frame(self.tab_db, bg=BG); top.pack(fill="x")
        tk.Label(top, text="Canned query:", bg=BG).pack(side="left")
        self.canned = parse_canned()
        self.cb = ttk.Combobox(top, values=[t for t, _ in self.canned], state="readonly", width=60)
        self.cb.pack(side="left", padx=4)
        self.cb.bind("<<ComboboxSelected>>", self._pick_canned)
        self.btn(top, "Run (F5)", self.run_sql).pack(side="left", padx=4)
        self.btn(top, "Integrity", self.integrity).pack(side="left", padx=2)
        self.btn(top, "Schema", self.schema).pack(side="left", padx=2)
        self.btn(top, "Backup...", self.backup_db).pack(side="left", padx=2)
        self.sql = self.text(self.tab_db, height=5)
        self.sql.insert("end", "SELECT name, weight, detail FROM incident_signals ORDER BY id DESC LIMIT 10")
        self.sql.bind("<F5>", lambda e: self.run_sql())
        self.sql_info = tk.StringVar(value="Read-only console (query_only connection). EXPLAIN QUERY PLAN works too.")
        tk.Label(self.tab_db, textvariable=self.sql_info, bg=BG, anchor="w").pack(fill="x")
        self.t_sql = self.tree(self.tab_db, [("result", 200)], height=12)

    def _tab_demos(self):
        left = self.group(self.tab_demo, "Academic demonstrations"); left.pack(side="left", fill="y", padx=(0, 6))
        for n, title, _, desc in lab.DEMOS:
            f = tk.Frame(left, bg=BG); f.pack(fill="x", pady=2)
            self.btn(f, f"{n}. {title}", (lambda n=n: self.run_demos([n])), 24).pack(anchor="w")
            tk.Label(f, text=desc, bg=BG, wraplength=210, justify="left", fg="#404040", font=("Tahoma", 8)).pack(anchor="w")
        self.btn(left, f"Run all 1-{len(lab.DEMOS)}", lambda: self.run_demos(range(1, len(lab.DEMOS) + 1)), 24).pack(pady=6)
        self.btn(left, "Clear console", lambda: self.console.delete("1.0", "end"), 24).pack()
        right = self.group(self.tab_demo, "Console"); right.pack(side="left", fill="both", expand=True)
        self.console = self.text(right, dark=True, height=30)
        self.console.insert("end", "RansomGuard demonstration console\nAll demos run on the LIVE engine and database in a disposable lab folder.\n\n")

    def _tab_log(self):
        self.t_log = self.tree(self.tab_log, [("id", 50), ("time", 90), ("level", 70), ("message", 700)], height=24)

    # ------------------------------------------------------------------ actions
    def say(self, s):
        self.outq.put(("say", s))

    def bg(self, fn):
        if self.busy:
            return self.sv[0].set("Busy - another operation is running")
        self.busy = True
        self.nb.select(self.tab_demo)

        def work():
            try:
                fn(self.eng, self.say)
            except Exception:  # noqa
                self.say("ERROR:\n" + traceback.format_exc())
            finally:
                self.outq.put(("done", "Ready"))     # ordered AFTER all console output; the pump clears busy
        threading.Thread(target=work, daemon=True, name="gui-task").start()

    def run_demos(self, which):
        which = list(which)

        def all_(e, say):
            for n in which:
                title, fn = lab.DEMOS[n - 1][1], lab.DEMOS[n - 1][2]
                say(f"\n{'=' * 70}\nDEMONSTRATION {n}: {title}\n{'=' * 70}")
                fn(e, say)
            say("\n--- finished ---")
        self.outq.put(("status", f"Running demonstration(s) {which}..."))
        self.bg(all_)

    def _kill_sim(self):
        lab.kill_sim()
        self.sv[0].set("Simulator terminated")

    def start(self):
        self.eng.start()
        self.sv[0].set("Monitoring started")

    def stop(self):
        self.eng.stop()
        self.sv[0].set("Monitoring stopped")

    def add_folder(self):
        d = filedialog.askdirectory(title="Choose a folder to protect")
        if d:
            try:
                self.eng.add_folder(d)
                if not self.eng.running:
                    self.eng.start()
            except ValueError as ex:
                messagebox.showerror("Cannot protect folder", str(ex))

    def remove_folder(self):
        for s in self.t_folders.selection():
            self.eng.remove_folder(int(s))

    def scan_selected(self):
        sel = self.t_folders.selection()
        if not sel:
            return messagebox.showinfo("Scan", "Select a protected folder on the Protection tab first.")
        for s in sel:
            self.eng.start_scan(int(s))
        self.nb.select(self.tab_prot)

    def _scan_pick(self, _=None):
        s = self.t_scans.selection()
        if s:
            self.fill(self.t_scanres, [(r["id"], r["path"], r["reason"]) for r in self.eng.db.query(
                "SELECT id,path,reason FROM scan_results WHERE session_id=? LIMIT 200", (int(s[0]),))], key="scanres")

    def sel_incident(self):
        s = self.t_inc.selection()
        return int(s[0]) if s else None

    def show_incident(self):
        i = self.sel_incident()
        if not i:
            return
        rep = self.eng.db.incident_report(i)
        key = (i, rep["incident"]["updated_ts"], len(rep["actions"]), len(rep["recoveries"]))
        if key == self.last_report:
            return
        self.last_report = key
        self.report.delete("1.0", "end")
        self.report.insert("end", format_report(rep))

    def recover(self):
        i = self.sel_incident()
        if i:
            g, b = self.eng.responder.recover_incident(i)
            messagebox.showinfo("Recovery", f"{g} file(s) recovered from backup (SHA-256 verified), {b} failed.")
            self.last_report = None
            self.show_incident()

    def false_pos(self):
        i = self.sel_incident()
        if i:
            self.eng.db.set_incident_status(i, "false_positive")

    def proc_act(self, kill):
        i = self.sel_incident()
        r = i and self.eng.db.one("SELECT p.pid,p.create_time,p.name FROM incidents i JOIN processes p ON p.id=i.process_id WHERE i.id=?", (i,))
        if not r:
            return messagebox.showinfo("No process", "This incident has no reliably attributed process.")
        try:
            p = psutil.Process(r["pid"])
            if abs(round(p.create_time(), 3) - r["create_time"]) > 0.01:
                return messagebox.showerror("PID reused", "That PID now belongs to a different process; refusing to act.")
            if kill:
                if messagebox.askyesno("Terminate process", f"Terminate {r['name']} (PID {r['pid']})?"):
                    p.kill()
                    self.sv[0].set(f"PID {r['pid']} terminated")
            else:
                p.resume()
                self.sv[0].set(f"PID {r['pid']} resumed")
        except psutil.Error as ex:
            messagebox.showerror("Operating system refused", str(ex))

    def restore(self, ask_dest):
        for s in self.t_q.selection():
            dest = None
            if ask_dest:
                dest = filedialog.asksaveasfilename(title="Restore file as")
                if not dest:
                    continue
            ok, msg = self.eng.responder.restore_quarantined(int(s), dest)
            messagebox.showinfo("Restore", msg) if ok else messagebox.showerror("Restore failed", msg)

    def integrity(self):
        res = self.eng.db.integrity_check()
        messagebox.showinfo("Database integrity", "PRAGMA integrity_check + foreign_key_check:\n\n" + "\n".join(res))

    def backup_db(self):
        d = filedialog.asksaveasfilename(title="Back up database", defaultextension=".db", initialfile="ransomguard_backup.db")
        if d:
            self.eng.db.backup_to(d)
            messagebox.showinfo("Backup", f"Consistent online backup written:\n{d}")

    def verify_audit(self):
        ok, n, bad, head = self.eng.db.verify_audit()
        (messagebox.showinfo if ok else messagebox.showerror)("Audit log", (
            f"Hash chain intact.\n{n} entries.\nHead hash:\n{head}\n\nNote the head hash somewhere safe: it anchors the log." if ok
            else f"TAMPERING DETECTED: chain breaks at entry {bad} (of {n} checked)."))

    def prune(self):
        from tkinter import simpledialog
        d = simpledialog.askinteger("Prune old events", "Delete raw events older than how many days?\n(events linked to incidents are always kept)", initialvalue=30, minvalue=1, parent=self.root)
        if d:
            self.sv[0].set(f"pruned {self.eng.db.prune(d)} event(s); VACUUM done; audited")

    def schema(self):
        w = tk.Toplevel(self.root); w.title("Database Schema"); w.geometry("700x560"); w.configure(bg=BG)
        t = self.text(w)
        db = self.eng.db
        for r in db.query("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"):
            n = db.one(f"SELECT COUNT(*) c FROM {r['name']}")["c"]
            t.insert("end", f"TABLE {r['name']}  ({n} rows)\n")
            for c in db.query(f"PRAGMA table_info({r['name']})"):
                t.insert("end", f"    {c['name']:<18} {c['type']:<8} {'PK' if c['pk'] else ''}{' NOT NULL' if c['notnull'] else ''}\n")
            for fk in db.query(f"PRAGMA foreign_key_list({r['name']})"):
                t.insert("end", f"    FK {fk['from']} -> {fk['table']}.{fk['to']}\n")
            t.insert("end", "\n")
        t.insert("end", "INDEXES\n")
        for r in db.query("SELECT name, tbl_name FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_%' ORDER BY tbl_name"):
            t.insert("end", f"    {r['name']}  on {r['tbl_name']}\n")

    def _pick_canned(self, _=None):
        self.sql.delete("1.0", "end")
        self.sql.insert("end", dict(self.canned)[self.cb.get()])
        self.run_sql()

    def run_sql(self):
        q = self.sql.get("1.0", "end").strip().rstrip(";")
        if not q.lower().startswith(("select", "explain", "with", "pragma table_info", "pragma index_list")) or ";" in q:
            return self.sql_info.set("Only a single read-only SELECT / EXPLAIN statement is allowed.")
        try:
            t0 = time.time()
            cur = self.eng.db.reader().execute(q)
            rows = cur.fetchmany(500)
            cols = [d[0] for d in cur.description]
        except Exception as ex:  # noqa
            return self.sql_info.set(f"SQL error: {ex}")
        self.t_sql.destroy()
        self.t_sql.master.destroy()
        self.t_sql = self.tree(self.tab_db, [(c, max(80, 700 // max(1, len(cols)))) for c in cols], height=12)
        for r in rows:
            self.t_sql.insert("", "end", values=[("" if v is None else v) for v in tuple(r)])
        self.sql_info.set(f"{len(rows)} row(s) in {(time.time() - t0) * 1000:.1f} ms" + ("  (first 500 shown)" if len(rows) == 500 else ""))

    # ------------------------------------------------------------------ alert popup / PDF / trusted apps
    def alert(self, iid):
        """Always-on-top desktop alert shown when the engine raises an incident (main thread only)."""
        if self.eng.cfg.get("alert_popup") != "1":
            return
        rep = self.eng.db.incident_report(iid)
        if not rep:
            return
        i = rep["incident"]
        frozen = any(a["action"] == "suspend_process" and a["success"] for a in rep["actions"])
        quar = sum(1 for q in rep["quarantine"] if q["status"] == "quarantined")
        who = f"{i['pname']} (PID {i['pid']})" if i["pid"] else "not identified"
        if self._alert_win is not None:
            try:
                self._alert_win.destroy()
            except tk.TclError:
                pass
        w = self._alert_win = tk.Toplevel(self.root)
        w.title("RansomGuard ALERT"); w.configure(bg=BG); w.resizable(False, False); w.attributes("-topmost", True)
        hd = tk.Frame(w, bg="#B00020"); hd.pack(fill="x")
        tk.Label(hd, text="  \u26A0  RANSOMWARE-LIKE ACTIVITY DETECTED", bg="#B00020", fg=WHITE, font=("Tahoma", 11, "bold"), pady=6).pack(anchor="w")
        body = (f"Incident #{iid}    risk {i['risk_score']}/100    severity {i['severity']}\n\n"
                f"Folder:    {os.path.basename(i['folder'].rstrip('/\\\\')) or i['folder']}\n"
                f"Process:   {who}\n"
                f"Response:  {'process FROZEN' if frozen else 'no process frozen'}, {quar} file(s) quarantined\n\n"
                "Open the Incidents tab to review and recover files.")
        tk.Label(w, text=body, bg=BG, justify="left", font=FONT, padx=14, pady=10).pack(anchor="w")
        bt = tk.Frame(w, bg=BG); bt.pack(pady=(0, 10))

        def close():
            self._alert_win = None
            w.destroy()

        def view():
            close()
            self.root.deiconify(); self.root.lift()
            self.nb.select(self.tab_inc); self.refresh()
            if self.t_inc.exists(str(iid)):
                self.t_inc.selection_set(str(iid)); self.t_inc.see(str(iid))
        self.btn(bt, "View incident", view, 14).pack(side="left", padx=4)
        self.btn(bt, "Dismiss", close, 10).pack(side="left", padx=4)
        w.update_idletasks()
        x, y = self.root.winfo_screenwidth() - w.winfo_width() - 24, self.root.winfo_screenheight() - w.winfo_height() - 70
        w.geometry(f"+{max(0, x)}+{max(0, y)}")
        w.protocol("WM_DELETE_WINDOW", close)
        w.after(20000, lambda: close() if self._alert_win is w else None)
        self.root.bell()

    def export_pdf(self):
        i = self.sel_incident()
        if not i:
            return messagebox.showinfo("Export PDF", "Select an incident in the list first.")
        rep = self.eng.db.incident_report(i)
        path = filedialog.asksaveasfilename(parent=self.root, defaultextension=".pdf", initialfile=f"RansomGuard_Incident_{i}.pdf",
                                            filetypes=[("PDF document", "*.pdf")])
        if not path:
            return
        ok, n, bad, _ = self.eng.db.verify_audit()
        body = format_report(rep, full=True) + f"\n  AUDIT LOG INTEGRITY: {'OK' if ok else 'BROKEN at entry %s' % bad} ({n} hash-chained entries)"
        try:
            write_pdf(path, f"RansomGuard - Incident Report #{i}", body)
        except OSError as ex:
            return messagebox.showerror("Export PDF", f"Could not write the file:\n{ex}")
        self.sv[0].set(f"report saved: {path}")
        if messagebox.askyesno("Export PDF", f"Report saved to\n{path}\n\nOpen it now?") and hasattr(os, "startfile"):
            os.startfile(path)                                   # Windows; elsewhere the path is shown in the status bar

    def trusted_apps(self):
        w = tk.Toplevel(self.root); w.title("Trusted Apps"); w.configure(bg=BG); w.transient(self.root); w.resizable(False, False)
        tk.Label(w, text=("Writes by a program on this list are still logged but are NOT scored as ransomware.\n"
                          "Use it for backup / sync / archive tools. Decoy files are never excused.\n"
                          "Tip: pick the .exe with Browse (full path is harder to impersonate than a bare name)."),
                 bg=BG, justify="left", font=FONT, padx=10, pady=8).pack(anchor="w")
        lb = tk.Listbox(w, width=78, height=8, relief="sunken", bd=2, font=FONT)
        lb.pack(padx=10)
        for a in self.eng.trusted_apps():
            lb.insert("end", a)

        def save():
            self.eng.db.set_config("trusted_apps", ",".join(lb.get(0, "end")))
            self.eng.reload_config()
            self.sv[0].set(f"{lb.size()} trusted app(s) saved")

        def add(value):
            value = value.strip()
            if not value or value in lb.get(0, "end"):
                return
            if "," in value:
                return messagebox.showerror("Trusted Apps", "Commas are not allowed in a name or path.", parent=w)
            if os.path.basename(value).lower() in ("python.exe", "pythonw.exe", "python", "python3", "py.exe") and not messagebox.askyesno(
                    "Trusted Apps", "Python also runs the attack simulator, so the demo attack would no longer be detected.\nAdd it anyway?", parent=w):
                return
            lb.insert("end", value); save(); ent.delete(0, "end")

        row = tk.Frame(w, bg=BG); row.pack(fill="x", padx=10, pady=6)
        ent = tk.Entry(row, width=40, relief="sunken", bd=2); ent.pack(side="left")
        self.btn(row, "Add", lambda: add(ent.get()), 8).pack(side="left", padx=4)
        self.btn(row, "Browse...", lambda: add(filedialog.askopenfilename(parent=w, filetypes=[("Programs", "*.exe"), ("All files", "*")]) or ""), 10).pack(side="left")
        self.btn(row, "Remove", lambda: ([lb.delete(s) for s in reversed(lb.curselection())], save()), 10).pack(side="left", padx=4)
        self.btn(w, "Close", w.destroy, 10).pack(pady=(0, 10))

    def settings(self):
        w = tk.Toplevel(self.root); w.title("RansomGuard Settings"); w.configure(bg=BG); w.transient(self.root); w.resizable(False, False)
        g = self.group(w, "Detection and response (stored in the config table)"); g.pack(padx=8, pady=8)
        cfg, ents = self.eng.db.get_config(), {}
        cfg = {k: v for k, v in cfg.items() if k not in HIDDEN_CONFIG}
        for i, k in enumerate(sorted(cfg)):
            tk.Label(g, text=k, bg=BG, anchor="w", width=24).grid(row=i, column=0, sticky="w")
            e = tk.Entry(g, width=14, relief="sunken", bd=2); e.insert(0, cfg[k]); e.grid(row=i, column=1, padx=6, pady=1)
            ents[k] = e

        def apply(close):
            try:
                for k, e in ents.items():
                    if e.get() != cfg[k]:
                        float(e.get())
                        self.eng.db.set_config(k, e.get())
                self.eng.reload_config()
                self.sv[0].set("Settings saved")
                close and w.destroy()
            except ValueError:
                messagebox.showerror("Invalid value", "All settings must be numeric.")
        b = tk.Frame(w, bg=BG); b.pack(pady=(0, 8))
        for t, c in (("OK", lambda: apply(True)), ("Cancel", w.destroy), ("Apply", lambda: apply(False))):
            self.btn(b, t, c, 10).pack(side="left", padx=4)

    def concepts(self):
        w = tk.Toplevel(self.root); w.title("OS and DBMS Concepts"); w.geometry("720x520"); w.configure(bg=BG)
        t = self.text(w)
        t.insert("end", (
            "OPERATING SYSTEMS\n  * Native FS notifications (inotify / ReadDirectoryChangesW / FSEvents)  engine.py\n"
            "  * Producer/consumer queue, worker thread, shutdown Events        engine.py\n"
            "  * PID / parent / create-time identity, attribution                procinfo.py\n"
            "  * Process suspend (SIGSTOP / NtSuspend), PID-reuse guard          response.py\n"
            "  * Permissions: 0700 data dirs, AccessDenied handling              response.py\n"
            "  * Reactive detection vs preventive enforcement                    README\n\n"
            "DBMS\n  * 16-table normalised schema, FK / CHECK / UNIQUE                db.py\n"
            "  * BEGIN IMMEDIATE transactions + rollback                          db.py\n"
            "  * Partial unique index (one open incident per folder)              db.py\n"
            "  * WAL + single serialised writer + per-thread readers              db.py\n"
            "  * Persisted baseline with poisoning safeguard                      detector.py\n"
            "  * Forensic report joins; integrity_check; online backup            db.py\n\nSee README.md for status of every claim (tested / implemented / partial / proposed).\n"))

    def about(self):
        messagebox.showinfo("About RansomGuard", "RansomGuard 1.0\nReal-time Ransomware Protection\n\nOS + DBMS edition (university project)\n"
                            f"Notification API: {self.eng.api_name or 'not started'}\nPython {sys.version.split()[0]}, SQLite {__import__('sqlite3').sqlite_version}")

    # ------------------------------------------------------------------ periodic work
    def pump(self):
        try:
            while True:
                kind, val = self.outq.get_nowait()
                try:
                    if kind == "say":
                        self.console.insert("end", val + "\n"); self.console.see("end")
                    elif kind in ("status", "done"):
                        self.sv[0].set(val)
                        if kind == "done":
                            self.busy = False
                    elif kind == "log":
                        self.sv[0].set(val[:90])
                    elif kind == "incident":
                        self.alert(val)
                except tk.TclError as ex:           # a bad message must never kill the pump
                    self.sv[0].set(f"display error: {ex}")
        except queue.Empty:
            pass
        self.root.after(100, self.pump)

    def _canary_txt(self):
        r = self.eng.db.one("SELECT COUNT(*) n, COUNT(tripped_ts) t FROM canaries")
        return f"{r['n'] - r['t']} armed, {r['t']} tripped"

    def _audit_txt(self):
        if time.time() - getattr(self, "_audit_ts", 0) > 10:      # O(n) re-hash: at most every 10 s
            self._audit_ts = time.time()
            ok, n, bad, _ = self.eng.db.verify_audit()
            self._audit_res = f"OK ({n} entries)" if ok else f"BROKEN at entry {bad}"
        return self._audit_res

    def refresh(self):
        e, db, ts = self.eng, self.eng.db, (lambda x: time.strftime("%H:%M:%S", time.localtime(x)))
        try:
            openinc = db.one("SELECT COUNT(*) n FROM incidents WHERE status='open'")["n"]
            if not e.running:
                state, color = "NOT MONITORING", "#C00000"
            elif openinc:
                state, color = "THREAT DETECTED", "#FF8000"
            else:
                state, color = "PROTECTED", "#00C000"
            self.banner_status.set(state); self.led.itemconfig(self.led_id, fill=color)
            size = os.path.getsize(db.path) / 1024
            for k, v in (("Notification API", e.api_name or "-"), ("Event queue", f"{e.q.qsize()} waiting"),
                         ("Received / processed", f"{e.stats['received']} / {e.stats['processed']}"),
                         ("Duplicates collapsed", e.stats["deduped"]), ("Spooled to disk", f"{e.stats['spooled']}  (replayed {e.stats['replayed']})"),
                         ("Database errors", e.stats["db_errors"]), ("Open incidents", openinc), ("Decoy files", self._canary_txt()),
                         ("Audit chain", self._audit_txt()), ("Database size", f"{size:.0f} KB")):
                if k in self.stat:
                    self.stat[k].config(text=str(v))
            self.sv[1].set(f"Events: {e.stats['processed']}   Queue: {e.q.qsize()}   Spool: {e.spool.size()} B")
            self.sv[2].set(time.strftime("%H:%M:%S"))
            self.fill(self.t_folders, [tuple(r) for r in db.query(
                "SELECT f.id,f.path,(SELECT COUNT(*) FROM backups b WHERE b.folder_id=f.id),(SELECT COUNT(*) FROM incidents i WHERE i.folder_id=f.id) FROM protected_folders f WHERE active=1")], "folders")
            self.fill(self.t_scans, [tuple(r) for r in db.query("SELECT id,status,files_scanned,flagged FROM scan_sessions ORDER BY id DESC LIMIT 8")], "scans")
            if not self.paused.get():
                self.fill(self.t_ev, [(r["id"], ts(r["ts"]), r["event_type"], r["path"], r["dest_path"] or "", f"{r['entropy']:.2f}" if r["entropy"] else "",
                                       r["attribution"], r["pid"] or "") for r in db.query(
                    """SELECT e.id,e.ts,e.event_type,e.path,e.dest_path,e.entropy,e.attribution,p.pid FROM fs_events e
                       LEFT JOIN process_observations o ON o.id=e.process_obs_id LEFT JOIN processes p ON p.id=o.process_id ORDER BY e.id DESC LIMIT 300""")], "ev")
            self.fill(self.t_inc, [(r["id"], ts(r["created_ts"]), r["severity"], r["risk_score"], r["status"], r["pid"] or "", r["name"] or "") for r in db.query(
                "SELECT i.*,p.pid,p.name FROM incidents i LEFT JOIN processes p ON p.id=i.process_id ORDER BY i.id DESC LIMIT 100")], "inc")
            self.show_incident()
            self.fill(self.t_q, [(r["id"], r["incident_id"], r["status"], r["original_path"], r["sha256"][:16], {None: "", 1: "verified", 0: "FAILED"}[r["integrity_ok"]])
                                 for r in db.query("SELECT * FROM quarantine ORDER BY id DESC LIMIT 300")], "q")
            self.fill(self.t_pe, [(r["id"], ts(r["ts"]), r["kind"], r["pid"], r["name"], r["exe"] or "") for r in db.query(
                "SELECT pe.id,pe.ts,pe.kind,p.pid,p.name,p.exe FROM process_events pe JOIN processes p ON p.id=pe.process_id ORDER BY pe.id DESC LIMIT 200")], "pe")
            self.fill(self.t_po, [(r["id"], ts(r["ts"]), r["pid"], r["name"], r["parent_name"] or "", r["username"] or "", r["method"], r["confidence"]) for r in db.query(
                "SELECT o.id,o.ts,p.pid,p.name,p.parent_name,p.username,o.method,o.confidence FROM process_observations o JOIN processes p ON p.id=o.process_id ORDER BY o.id DESC LIMIT 200")], "po")
            self.fill(self.t_log, [(r["id"], ts(r["ts"]), r["level"], r["message"]) for r in db.query("SELECT * FROM monitor_log ORDER BY id DESC LIMIT 200")], "log")
        except Exception as ex:  # noqa
            self.sv[0].set(f"refresh error: {ex}")
        self.root.after(1000, self.refresh)

    def quit(self):
        if self.busy and not messagebox.askyesno("Exit", "A task is still running. Exit anyway?"):
            return
        lab.kill_sim()
        self.eng.close()
        self.root.destroy()


def run(data_dir):
    App(data_dir).root.mainloop()
