"""In-app demonstrations. Every demo runs against the LIVE engine/database (the same one the GUI
shows), inside a disposable lab folder next to the data directory. `say(text)` prints to the app console."""
import os
import subprocess
import sys
import threading
import time

import psutil

from . import pyexec, simulator
from .db import Database, format_report
from .response import sha256_file

PKG_PARENT = pyexec.base_dir()
_sim = {"proc": None}


def lab_root(e):
    return os.path.join(os.path.dirname(e.data_dir), "RansomGuardLab")


def wait(cond, timeout=15):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.1)
    return False


def tbl(db, sql, params=(), maxrows=12):
    rows = db.query(sql, params)
    out = ["SQL> " + " ".join(sql.split())]
    if not rows:
        out.append("   (no rows)")
    for r in rows[:maxrows]:
        out.append("   " + " | ".join(str(r[k])[:44] for k in r.keys()))
    if len(rows) > maxrows:
        out.append(f"   ... {len(rows) - maxrows} more rows")
    return "\n".join(out)


def ensure_lab(e, say):
    root = lab_root(e)
    basic, attack = os.path.join(root, "basic"), os.path.join(root, "attack")
    os.makedirs(basic, exist_ok=True)
    if not os.path.exists(os.path.join(attack, simulator.MARKER)):
        simulator.init_dir(attack, 40)
    ids = {}
    for name, p in (("basic", basic), ("attack", attack)):
        rp = os.path.realpath(p)
        row = e.db.one("SELECT id,active FROM protected_folders WHERE path=?", (rp,))
        if row is None or not row["active"] or row["id"] not in e.folders:
            ids[name] = e.add_folder(p)
            say(f"protected folder added: {rp}")
        else:
            ids[name] = row["id"]
    if not e.running:
        e.start()
        say("monitoring started")
        time.sleep(0.5)
    return basic, attack, ids


def kill_sim():
    p = _sim["proc"]
    if p and p.poll() is None:
        try:
            p.kill()
            p.wait(3)
        except Exception:  # noqa
            pass
    _sim["proc"] = None


def start_attack(e, say, canaries=True):
    """Reset the attack folder, snapshot backups, then launch the harmless simulator (cwd = attack folder)."""
    basic, attack, ids = ensure_lab(e, say)
    kill_sim()
    names = os.listdir(attack)
    t_ign, IGN_TTL = time.time(), 2.5
    e.ignore([os.path.join(attack, n) for n in names] +
             [os.path.join(attack, f"doc_{i:03d}.txt{x}") for i in range(40) for x in ("", ".locked")] +
             [os.path.join(attack, n) for n in (".sim_key", "README_HOW_TO_DECRYPT.txt", simulator.MARKER)], ttl=IGN_TTL)
    for n in names:
        p = os.path.join(attack, n)
        if os.path.isfile(p):
            os.remove(p)
    simulator.init_dir(attack, 40)
    if canaries and e.cfg.get("canary_enabled") == "1":
        e.ensure_canaries(ids["attack"], attack, rearm=True)      # fresh decoys, backed up before the snapshot
    n = e.responder.snapshot(ids["attack"], attack, e.cfg)
    say(f"attack folder reset; {n} files backed up before the 'attack'")
    # the suppression window (reset noise only) MUST expire before the simulator starts
    time.sleep(max(0.0, IGN_TTL - (time.time() - t_ign)) + 0.4)
    before = e.db.one("SELECT COALESCE(MAX(id),0) m FROM incidents")["m"]
    proc = subprocess.Popen(pyexec.module_cmd("ransomguard.simulator", attack, "--delay", "0.03"), cwd=attack,
                            env={**os.environ, "PYTHONPATH": PKG_PARENT}, stdout=subprocess.DEVNULL)
    _sim["proc"] = proc
    say(f"harmless simulator started: PID {proc.pid}, working directory = {attack}")
    return proc, before


def demo1(e, say):
    basic, _, ids = ensure_lab(e, say)
    say(f"Notification API in use: {e.api_name}")
    tag = f"d1_{int(time.time())}"
    p = os.path.join(basic, tag + ".txt")
    open(p, "w").write("quarterly numbers\n"); time.sleep(0.3)
    open(p, "a").write("more numbers\n"); time.sleep(0.3)
    os.rename(p, p + ".old"); time.sleep(0.3)
    os.remove(p + ".old")
    wait(lambda: e.db.one("SELECT COUNT(DISTINCT event_type) n FROM fs_events WHERE path LIKE ?", (f"%{tag}%",))["n"] >= 4)
    say(tbl(e.db, "SELECT id, event_type, substr(path,-24) AS path, substr(dest_path,-24) AS dest, attribution FROM fs_events WHERE path LIKE ? ORDER BY id", (f"%{tag}%",)))
    say("NOTE: events are NOTIFICATIONS delivered AFTER the kernel completed the operation (reactive, not preventive).\n"
        "Chain: Python open()/write()/rename()/unlink() -> system calls -> kernel VFS -> inotify event -> watchdog thread -> queue.")


def demo2(e, say):
    basic, _, ids = ensure_lab(e, say)
    last = e.db.one("SELECT COALESCE(MAX(id),0) m FROM process_events")["m"]
    code = "import time\nfor i in range(6):\n    open('proc_%d.txt' % i,'w').write('x'*100); time.sleep(0.25)\n"
    w = subprocess.Popen(pyexec.code_cmd(code), cwd=basic)
    say(f"harmless writer started: PID {w.pid} (the app's own PID {os.getpid()} is deliberately excluded)")
    wait(lambda: e.db.one("SELECT COUNT(*) n FROM process_events WHERE id>? AND kind='exited'", (last,))["n"] >= 1, 12)
    say(tbl(e.db, """SELECT p.pid, p.name, p.ppid, p.parent_name AS parent, p.username AS user, o.method, o.confidence
                     FROM process_observations o JOIN processes p ON p.id=o.process_id WHERE p.pid=? ORDER BY o.id DESC LIMIT 3""", (w.pid,)))
    say(tbl(e.db, "SELECT pe.kind, p.pid, p.name, datetime(pe.ts,'unixepoch','localtime') AS at FROM process_events pe JOIN processes p ON p.id=pe.process_id WHERE pe.id>? ORDER BY pe.id", (last,)))
    say(tbl(e.db, "SELECT e.event_type, substr(e.path,-12) AS file, e.attribution, p.pid FROM fs_events e LEFT JOIN process_observations o ON o.id=e.process_obs_id LEFT JOIN processes p ON p.id=o.process_id WHERE e.path LIKE '%/proc_%' ORDER BY e.id DESC LIMIT 6"))
    say("Attribution is INFERRED (cwd / open-file scan via psutil), not reported by the OS event itself.\n"
        "Rows with 'none' were short writes that finished between scans. Other users' processes need root/Administrator.")


def demo3(e, say):
    basic, _, ids = ensure_lab(e, say)
    before_inc = e.db.one("SELECT COUNT(*) n FROM incidents")["n"]
    before = dict(e.stats)
    tag = f"b{int(time.time()) % 100000}"

    def burst():
        for i in range(600):
            open(os.path.join(basic, f"{tag}_{i:03d}.txt"), "w").write("data " * 40)
    t0 = time.time()
    threading.Thread(target=burst, name="burst-writer", daemon=True).start()
    say("600-file burst started from a separate thread; the window stays live while the worker drains the queue...")
    wait(lambda: e.db.one("SELECT COUNT(DISTINCT path) n FROM fs_events WHERE path LIKE ? AND event_type='created'", (f"%{tag}_%",))["n"] >= 600, 30)
    n = e.db.one("SELECT COUNT(DISTINCT path) n FROM fs_events WHERE path LIKE ? AND event_type='created'", (f"%{tag}_%",))["n"]
    say(f"persisted {n}/600 distinct files in {time.time() - t0:.2f}s | queue depth now {e.q.qsize()} | "
        f"received +{e.stats['received'] - before['received']} deduped +{e.stats['deduped'] - before['deduped']} spooled {e.stats['spooled']}")
    say("threads: " + ", ".join(sorted(t.name for t in threading.enumerate() if t.name in ("worker", "health", "procwatch"))) + " (+ OS observer thread, + this GUI thread)")
    say(f"false-positive check: new incidents after benign burst = {e.db.one('SELECT COUNT(*) n FROM incidents')['n'] - before_inc}")


def demo4(e, say):
    saved = e.cfg.get("canary_enabled", "1")
    e.cfg["canary_enabled"] = "0"
    say("(decoy files are switched OFF for this demo so the BEHAVIOURAL rules are what you see; Demonstration 7 shows decoys)")
    try:
        proc, before = start_attack(e, say, canaries=False)
        if not wait(lambda: e.db.one("SELECT COUNT(*) n FROM incidents WHERE id>?", (before,))["n"] >= 1, 20):
            say("no incident was created within 20 s (check Event Log tab)")
            return
        time.sleep(1.0)
        iid = e.db.one("SELECT MAX(id) m FROM incidents")["m"]
        st = psutil.Process(proc.pid).status() if proc.poll() is None else "exited"
        say(f"simulator PID {proc.pid} state after automatic response: {st}")
        say(format_report(e.db.incident_report(iid)))
        say("The suspended simulator is left frozen so you can try Resume / Terminate on the Incidents tab (or Tools > Kill simulator).")
    finally:
        e.cfg["canary_enabled"] = saved


def demo5(e, say):
    _, _, ids = ensure_lab(e, say)
    iid = e.db.one("SELECT MAX(id) m FROM incidents")["m"]
    if not iid:
        say("No incident exists yet - run Demonstration 4 first.")
        return
    say(tbl(e.db, """SELECT i.id AS inc, i.severity, i.risk_score AS risk, p.pid, p.name,
                     (SELECT COUNT(*) FROM incident_files f WHERE f.incident_id=i.id) AS files,
                     (SELECT COUNT(*) FROM incident_events ie WHERE ie.incident_id=i.id) AS events,
                     (SELECT COUNT(*) FROM response_actions a WHERE a.incident_id=i.id) AS actions
                     FROM incidents i LEFT JOIN processes p ON p.id=i.process_id ORDER BY i.id DESC""", maxrows=5))
    say(tbl(e.db, "SELECT name, weight, detail FROM incident_signals WHERE incident_id=? ORDER BY weight DESC", (iid,)))
    n0 = e.db.one("SELECT COUNT(*) n FROM incidents")["n"]
    try:
        with e.db.transaction() as c:
            c.execute("INSERT INTO incidents(folder_id,severity,risk_score,first_event_ts,created_ts,updated_ts) VALUES(?,?,?,?,?,?)", (ids["attack"], "high", 99, 0, 0, 0))
            c.execute("INSERT INTO response_actions(incident_id,ts,action,success) VALUES(last_insert_rowid(),0,'test',5)")
    except Exception as ex:  # noqa
        say(f"Controlled failure inside a transaction -> {type(ex).__name__}: {ex}")
    say(f"Incidents before={n0} after={e.db.one('SELECT COUNT(*) n FROM incidents')['n']}  (ROLLBACK left no partial record)")
    for q in ("SELECT * FROM incidents WHERE created_ts > 0 ORDER BY created_ts DESC LIMIT 10",
              "SELECT * FROM incidents WHERE severity='high' AND status='contained'",
              "SELECT * FROM fs_events WHERE path='/x'"):
        say("EXPLAIN QUERY PLAN> " + q + "\n    -> " + " / ".join(r[3] for r in e.db.query("EXPLAIN QUERY PLAN " + q)))
    say("Baseline windows (trusted=0 are suspicious/bursty windows that are stored but NOT learned):")
    say(tbl(e.db, "SELECT trusted, COUNT(*) AS windows, MAX(write_count) AS max_writes FROM activity_baseline GROUP BY trusted"))


def demo6(e, say):
    ensure_lab(e, say)
    iid = e.db.one("SELECT MAX(id) m FROM incidents")["m"]
    if not iid:
        say("No incident exists yet - run Demonstration 4 first.")
        return
    say("Opening the database file through a brand-new, independent connection (as after an application restart)...")
    db2 = Database(e.db.path)
    say("integrity_check: " + str(db2.integrity_check()))
    say(tbl(db2, "SELECT id, status, severity, risk_score FROM incidents ORDER BY id DESC", maxrows=5))
    say(tbl(db2, "SELECT action, success, count(*) AS n FROM response_actions GROUP BY action, success"))
    q = db2.one("SELECT * FROM quarantine WHERE incident_id=? AND status='quarantined' ORDER BY id LIMIT 1", (iid,))
    if q:
        dest_dir = os.path.join(lab_root(e), "restored")
        os.makedirs(dest_dir, exist_ok=True)
        dest = os.path.join(dest_dir, f"q{q['id']}_" + os.path.basename(q["original_path"]))
        if os.path.exists(dest):
            os.remove(dest)
        ok, msg = e.responder.restore_quarantined(q["id"], dest)
        say(f"restore quarantine #{q['id']} -> {dest}: {ok} ({msg})")
        if ok:
            say(f"  recorded sha256={q['sha256'][:24]}...  actual={sha256_file(dest)[:24]}...")
    good, bad = e.responder.recover_incident(iid)
    say(f"recover from pre-incident backups: {good} recovered, {bad} failed")
    r = db2.one("SELECT target_path FROM recovery_records WHERE incident_id=? AND success=1 ORDER BY id LIMIT 1", (iid,))
    if r:
        b = db2.one("SELECT sha256 FROM backups WHERE original_path=? ORDER BY id DESC LIMIT 1", (r["target_path"],))
        say(f"verify {os.path.basename(r['target_path'])}: backup sha={b['sha256'][:24]}... file sha={sha256_file(r['target_path'])[:24]}... match={b['sha256'] == sha256_file(r['target_path'])}")
    db2.close()
    say("Tip: close and re-open this application - all incidents, actions and quarantine history are still listed.")


def demo7(e, say):
    basic, attack, ids = ensure_lab(e, say)
    if not e.db.one("SELECT 1 FROM canaries WHERE folder_id=? AND tripped_ts IS NULL", (ids["basic"],)):
        e.rearm_canaries()
    rows = e.db.query("SELECT path FROM canaries WHERE folder_id=? AND tripped_ts IS NULL ORDER BY id", (ids["basic"],))
    say(f"{len(rows)} decoy files are armed in {basic}:")
    for r in rows:
        say("   " + os.path.basename(r["path"]))
    target = rows[0]["path"]
    before = e.db.one("SELECT COALESCE(MAX(id),0) m FROM incidents")["m"]
    say(f"\nA harmless child process, started from a DIFFERENT directory, overwrites ONE decoy ({os.path.basename(target)}) with random bytes.\n"
        "No rate, entropy history or process attribution is needed: nothing legitimate ever touches a decoy.")
    subprocess.run(pyexec.code_cmd(f"import os;open({target!r},'wb').write(os.urandom(4000))"), cwd=lab_root(e))
    if not wait(lambda: e.db.one("SELECT COUNT(*) n FROM incidents WHERE id>?", (before,))["n"] >= 1, 10):
        say("no incident created (is canary_enabled set to 1 in Settings?)")
        return
    time.sleep(0.8)
    iid = e.db.one("SELECT MAX(id) m FROM incidents")["m"]
    say(format_report(e.db.incident_report(iid)))
    say(tbl(e.db, "SELECT id, kind, payload FROM audit_log WHERE kind LIKE 'canary%' OR kind='process_attributed' ORDER BY id DESC", (), 6))
    ok, n, bad, head = e.db.verify_audit()
    say(f"audit chain: {'OK' if ok else 'BROKEN at entry ' + str(bad)} ({n} hash-chained entries, head {head[:16]}...)")
    say(f"fresh decoys re-armed: {e.rearm_canaries()}")
    r = e.db.one("SELECT process_id FROM incidents WHERE id=?", (iid,))
    say("process: " + ("attributed (see report)" if r["process_id"] else
        "NOT attributed - the writer wrote too little and exited; the incident is still raised and the decoy quarantined, but nothing could be suspended."))
    say("Honest limit: a decoy only helps if the attacker reaches it early. Detection by rules (demo 4) is the first line; decoys are the cheap tripwire.")


DEMOS = [
    (1, "OS event handling", demo1, "Create / modify / rename / delete files in a protected folder and watch the real inotify/ReadDirectoryChangesW events arrive in the database."),
    (2, "Process identification", demo2, "A harmless child process writes files; see the PID, parent, user, and confidence RansomGuard can really obtain."),
    (3, "Concurrency", demo3, "600-file burst: producer thread, bounded queue, batching worker, transactional writes - while this window stays responsive."),
    (4, "Ransomware behaviour", demo4, "Harmless simulator 'encrypts' disposable files. Detection, risk score, process suspension and quarantine happen automatically."),
    (5, "DBMS relationships", demo5, "Incident joins, controlled transaction ROLLBACK, EXPLAIN QUERY PLAN index proof, baseline windows."),
    (6, "Persistence & restore", demo6, "Reopen the DB on a fresh connection, verify integrity, restore a quarantined file and recover from backups with SHA-256 checks."),
    (7, "Decoy files (canaries)", demo7, "Hidden decoys nothing legitimate touches: one overwritten decoy raises an incident by itself - no rates, entropy or attribution needed."),
]
