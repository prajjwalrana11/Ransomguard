import argparse
import json
import os
import sys
import time

from .db import format_report

DEFAULT_DATA = os.path.join(os.path.expanduser("~"), ".ransomguard")


def _engine(a, **kw):
    from .engine import Engine
    return Engine(a.data_dir, **kw)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="ransomguard")
    ap.add_argument("--data-dir", default=DEFAULT_DATA, help="DB, backups, quarantine live here (owner-only)")
    sub = ap.add_subparsers(dest="cmd")   # no sub-command -> open the application window
    sub.add_parser("gui")
    m = sub.add_parser("monitor"); m.add_argument("folders", nargs="+")
    d = sub.add_parser("demo"); d.add_argument("--keep", action="store_true")
    sub.add_parser("incidents")
    for n in ("report", "recover"):
        s = sub.add_parser(n); s.add_argument("id", type=int)
    sub.add_parser("quarantine")
    r = sub.add_parser("restore"); r.add_argument("id", type=int); r.add_argument("--dest")
    ev = sub.add_parser("evaluate"); ev.add_argument("--out"); ev.add_argument("--only", help="comma list of scenario prefixes, e.g. A1,B2")
    sub.add_parser("verify-audit")
    xp = sub.add_parser("export-pdf"); xp.add_argument("id", type=int); xp.add_argument("--out")
    pr = sub.add_parser("prune"); pr.add_argument("days", type=int)
    sub.add_parser("check-db")
    b = sub.add_parser("backup-db"); b.add_argument("dest")
    q = sub.add_parser("sql"); q.add_argument("query")
    a = ap.parse_args(argv)
    a.cmd = a.cmd or "gui"

    if a.cmd == "demo":
        from .demo import main as demo
        return demo(a.keep)
    if a.cmd == "evaluate":
        from .evaluate import run as ev_run
        print(ev_run(print, a.only.split(",") if a.only else None, a.out))
        return
    if a.cmd == "gui":
        from .gui import run
        return run(a.data_dir)
    e = _engine(a, on_log=(lambda l, m: print(f"[{l}] {m}")) if a.cmd == "monitor" else None,
                on_incident=(lambda i: print(f"*** INCIDENT #{i} created - run: report {i}")) if a.cmd == "monitor" else None)
    try:
        if a.cmd == "monitor":
            for f in a.folders:
                e.add_folder(f)
            e.start()
            print("Monitoring. Ctrl+C to stop.")
            try:
                while True:
                    time.sleep(5)
                    print(f"[stats] {dict(e.stats)} queue={e.q.qsize()}")
            except KeyboardInterrupt:
                pass
        elif a.cmd == "incidents":
            for r in e.db.query("SELECT id,status,severity,risk_score,datetime(created_ts,'unixepoch','localtime') t FROM incidents ORDER BY created_ts DESC"):
                print(tuple(r))
        elif a.cmd == "report":
            print(format_report(e.db.incident_report(a.id)))
        elif a.cmd == "export-pdf":
            from .report_pdf import write_pdf
            rep = e.db.incident_report(a.id)
            if not rep:
                sys.exit("no such incident")
            out = a.out or f"RansomGuard_Incident_{a.id}.pdf"
            print("written", out, write_pdf(out, f"RansomGuard - Incident Report #{a.id}", format_report(rep, full=True)), "bytes")
        elif a.cmd == "recover":
            print("recovered, failed =", e.responder.recover_incident(a.id))
        elif a.cmd == "quarantine":
            for r in e.db.query("SELECT id,incident_id,status,original_path,sha256 FROM quarantine ORDER BY id"):
                print(tuple(r))
        elif a.cmd == "restore":
            print(e.responder.restore_quarantined(a.id, a.dest))
        elif a.cmd == "verify-audit":
            ok, n, bad, head = e.db.verify_audit()
            print(f"audit chain: {'OK' if ok else 'BROKEN at id ' + str(bad)}  entries={n}  head={head[:16]}...")
        elif a.cmd == "prune":
            print("deleted events:", e.db.prune(a.days))
        elif a.cmd == "check-db":
            print(e.db.integrity_check())
        elif a.cmd == "backup-db":
            print("written", e.db.backup_to(a.dest))
        elif a.cmd == "sql":
            if not a.query.lstrip().lower().startswith(("select", "explain", "pragma table_info")):
                sys.exit("read-only: SELECT/EXPLAIN only")
            for r in e.db.query(a.query):
                print(tuple(r))
    finally:
        e.close()
