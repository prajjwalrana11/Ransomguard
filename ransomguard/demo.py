"""Scripted, reproducible academic demonstration (Demonstrations 1-6). Run: python -m ransomguard demo"""
import os
import shutil
import subprocess
import sys
import tempfile
import time

import psutil

from . import pyexec, simulator
from .db import format_report
from .engine import Engine
from .response import sha256_file

PKG_PARENT = pyexec.base_dir()


def banner(t):
    print("\n" + "=" * 78 + f"\n{t}\n" + "=" * 78)


def table(db, sql, params=(), maxrows=12):
    rows = db.query(sql, params)
    print(f"SQL> {' '.join(sql.split())}")
    if not rows:
        print("   (no rows)")
    for r in rows[:maxrows]:
        print("   " + " | ".join(str(r[k])[:46] for k in r.keys()))
    if len(rows) > maxrows:
        print(f"   ... {len(rows) - maxrows} more rows")


def wait(cond, timeout=15):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.1)
    return False


def main(keep=False):
    base = tempfile.mkdtemp(prefix="ransomguard_demo_")
    basic, attack, data = (os.path.join(base, n) for n in ("basic", "attack", "data"))
    os.makedirs(basic)
    simulator.init_dir(attack, files=40)
    e = Engine(data)
    fb, fa = e.add_folder(basic), e.add_folder(attack)
    wait(lambda: e.db.one("SELECT COUNT(*) n FROM backups")["n"] >= 40)
    e.start()
    time.sleep(0.5)
    env = {**os.environ, "PYTHONPATH": PKG_PARENT}
    print(f"Demo workspace: {base}   (disposable; protected folders: basic/, attack/)")

    banner("DEMO 1 - OS event handling: create / modify / rename / delete")
    print(f"Notification API in use: {e.api_name}")
    p = os.path.join(basic, "report.txt")
    open(p, "w").write("quarterly numbers\n"); time.sleep(0.3)
    open(p, "a").write("more numbers\n"); time.sleep(0.3)
    os.rename(p, p + ".old"); time.sleep(0.3)
    os.remove(p + ".old")
    wait(lambda: e.db.one("SELECT COUNT(DISTINCT event_type) n FROM fs_events WHERE folder_id=?", (fb,))["n"] >= 4)
    table(e.db, "SELECT id, event_type, substr(path, -16) AS path, substr(dest_path,-20) AS dest, attribution FROM fs_events WHERE folder_id=? ORDER BY id", (fb,))
    print("NOTE: these are NOTIFICATIONS delivered AFTER the kernel completed the operation (reactive).")

    banner("DEMO 2 - Process identification (harmless writer process)")
    code = "import time,os\nfor i in range(6):\n    open(f'proc_{i}.txt','w').write('x'*100); time.sleep(0.25)\n"
    w = subprocess.Popen(pyexec.code_cmd(code), cwd=basic)
    wait(lambda: e.db.one("SELECT COUNT(*) n FROM process_events WHERE kind='exited'")["n"] >= 1)
    print(f"(writer PID was {w.pid}; our own PID is {os.getpid()} and is deliberately excluded)")
    table(e.db, """SELECT p.pid, p.name, p.ppid, p.parent_name AS parent, p.username AS user, o.method, o.confidence
                   FROM process_observations o JOIN processes p ON p.id=o.process_id ORDER BY o.id DESC LIMIT 3""")
    table(e.db, "SELECT pe.kind, p.pid, p.name, datetime(pe.ts,'unixepoch','localtime') AS at FROM process_events pe JOIN processes p ON p.id=pe.process_id ORDER BY pe.id")
    table(e.db, "SELECT e.event_type, substr(e.path,-12) AS file, e.attribution, p.pid FROM fs_events e LEFT JOIN process_observations o ON o.id=e.process_obs_id LEFT JOIN processes p ON p.id=o.process_id WHERE e.path LIKE '%proc_%' ORDER BY e.id LIMIT 6")
    print("Attribution is INFERRED (cwd/open-file scan), not reported by the OS event; rows with 'none' were short writes missed between scans.")

    banner("DEMO 3 - Concurrency: 600-file burst, UI/main thread stays responsive")
    import threading
    before = dict(e.stats)

    def burst():
        for i in range(600):
            open(os.path.join(basic, f"burst_{i:03d}.txt"), "w").write("data " * 40)
    t0 = time.time()
    threading.Thread(target=burst, name="burst-writer").start()
    worst = 0.0
    while time.time() - t0 < 15:                        # simulated UI loop: 10 ms ticks while monitoring runs
        a = time.time(); time.sleep(0.01); worst = max(worst, time.time() - a - 0.01)
        n = e.db.one("SELECT COUNT(DISTINCT path) n FROM fs_events WHERE path LIKE '%burst_%' AND event_type='created'")["n"]
        if n >= 600:
            break
    print(f"burst persisted: {n}/600 distinct files in {time.time()-t0:.2f}s; worst main-thread stall {worst*1000:.1f} ms")
    print(f"queue depth now {e.q.qsize()}, received={e.stats['received']-before['received']}, deduped={e.stats['deduped']-before['deduped']}, spooled={e.stats['spooled']}")
    print("threads:", sorted(t.name for t in __import__('threading').enumerate() if t.name in ('worker', 'health', 'procwatch')))
    print("False-positive check - incidents after benign burst:", e.db.one("SELECT COUNT(*) n FROM incidents")["n"])

    banner("DEMO 4 - Ransomware-like behaviour (harmless simulator on disposable files)")
    sim = subprocess.Popen(pyexec.module_cmd("ransomguard.simulator", attack, "--delay", "0.03"), cwd=attack, env=env)
    wait(lambda: e.db.one("SELECT COUNT(*) n FROM response_actions WHERE action='suspend_process'")["n"] >= 1)
    time.sleep(0.8)
    st = psutil.Process(sim.pid).status() if sim.poll() is None else "exited"
    print(f"Simulator PID {sim.pid} state after response: {st}")
    iid = e.db.one("SELECT id FROM incidents ORDER BY id LIMIT 1")["id"]
    print(format_report(e.db.incident_report(iid)))
    if sim.poll() is None:
        sim.kill(); sim.wait()

    banner("DEMO 5 - DBMS: relationships, rollback, indexes")
    table(e.db, """SELECT i.id AS inc, i.severity, i.risk_score AS risk, p.pid, p.name,
                   (SELECT COUNT(*) FROM incident_files f WHERE f.incident_id=i.id) AS files,
                   (SELECT COUNT(*) FROM incident_events ie WHERE ie.incident_id=i.id) AS events,
                   (SELECT COUNT(*) FROM response_actions a WHERE a.incident_id=i.id) AS actions
                   FROM incidents i LEFT JOIN processes p ON p.id=i.process_id""")
    table(e.db, "SELECT name, weight, detail FROM incident_signals WHERE incident_id=? ORDER BY weight DESC", (iid,))
    before_n = e.db.one("SELECT COUNT(*) n FROM incidents")["n"]
    try:
        with e.db.transaction() as c:
            c.execute("INSERT INTO incidents(folder_id,severity,risk_score,first_event_ts,created_ts,updated_ts) VALUES(?,?,?,?,?,?)", (fa, "high", 99, 0, 0, 0))
            c.execute("INSERT INTO response_actions(incident_id,ts,action,success) VALUES(last_insert_rowid(),0,'test',5)")  # violates CHECK
    except Exception as ex:
        print(f"Controlled failure -> {type(ex).__name__}: {ex}")
    print(f"Incidents before={before_n} after={e.db.one('SELECT COUNT(*) n FROM incidents')['n']}  (ROLLBACK left no partial record)")
    for q in ("SELECT * FROM incidents WHERE created_ts > 0 ORDER BY created_ts DESC LIMIT 10",
              "SELECT * FROM incidents WHERE severity='high' AND status='contained'",
              "SELECT * FROM fs_events WHERE path='/x'"):
        print("EXPLAIN QUERY PLAN>", q, "\n    ->", " / ".join(r[3] for r in e.db.query("EXPLAIN QUERY PLAN " + q)))
    print("Baseline windows (trusted=0 are suspicious windows that are NOT learned):")
    table(e.db, "SELECT trusted, COUNT(*) AS windows, MAX(write_count) AS max_writes FROM activity_baseline GROUP BY trusted")

    banner("DEMO 6 - Persistence, forensic history, restore + integrity")
    e.close()
    print("Engine closed. Reopening the same data directory as a fresh instance...")
    e2 = Engine(data)
    print("integrity_check:", e2.db.integrity_check())
    table(e2.db, "SELECT id, status, severity, risk_score FROM incidents")
    table(e2.db, "SELECT action, success, count(*) AS n FROM response_actions GROUP BY action, success")
    q = e2.db.one("SELECT * FROM quarantine WHERE status='quarantined' ORDER BY id LIMIT 1")
    dest = os.path.join(base, "restored_" + os.path.basename(q["original_path"]))
    ok, msg = e2.responder.restore_quarantined(q["id"], dest)
    print(f"restore quarantine #{q['id']} -> {dest}: {ok} ({msg}); recorded sha256={q['sha256'][:16]}.. actual={sha256_file(dest)[:16]}..")
    good, bad = e2.responder.recover_incident(iid)
    print(f"recover from pre-incident backups: {good} recovered, {bad} failed")
    r = e2.db.one("SELECT target_path, detail FROM recovery_records WHERE success=1 ORDER BY id LIMIT 1")
    if r:
        b = e2.db.one("SELECT sha256 FROM backups WHERE original_path=? ORDER BY id DESC LIMIT 1", (r["target_path"],))
        print(f"verify {os.path.basename(r['target_path'])}: backup sha={b['sha256'][:16]}.. file sha={sha256_file(r['target_path'])[:16]}.. match={b['sha256']==sha256_file(r['target_path'])}")
    table(e2.db, "SELECT action, substr(target,-22) AS target, success, detail FROM response_actions WHERE incident_id=? AND action IN ('restore_file','recover_file') ORDER BY id", (iid,), 5)
    e2.close()
    if not keep:
        shutil.rmtree(base, ignore_errors=True)
    print("\nDemo complete.")
