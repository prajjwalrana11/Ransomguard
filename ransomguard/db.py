"""SQLite persistence: schema, connection strategy, transactions, integrity, reports.

Connection strategy (see README "Transactions, Indexing, and Concurrency"):
  * ONE shared write connection, guarded by an RLock -> writers are serialised in
    user space, so SQLite's single-writer lock is almost never contended.
  * Every write is an explicit `BEGIN IMMEDIATE ... COMMIT/ROLLBACK` (transaction()).
  * One READ connection per thread (thread-local). WAL mode lets readers proceed
    while the writer commits (readers see the last committed snapshot).
  * busy_timeout handles contention with *other processes* (e.g. the CLI).
"""
import contextlib
import hashlib
import json
import os
import sqlite3
import threading
import time

SCHEMA_VERSION = 2

DEFAULT_CONFIG = {
    "window_sec": "10",          # sliding detection window
    "risk_threshold": "60",      # score >= threshold -> incident
    "min_write_burst": "15",     # writes per window before 'write_burst' fires
    "entropy_threshold": "7.5",  # Shannon bits/byte regarded as encrypted-looking
    "baseline_sigma": "3",       # std-devs above baseline mean
    "baseline_min_windows": "20",
    "baseline_history": "500",
    "auto_suspend": "1",
    "auto_quarantine": "1",
    "queue_max": "5000",
    "max_backup_bytes": str(5 * 1024 * 1024),
    "snapshot_max_files": "500",
    "canary_enabled": "1",       # decoy files that alert on first touch
    "canary_count": "6",         # decoys per protected folder (1-8)
    "long_window_sec": "300",    # slow-attack window
    "sustained_files": "10",     # distinct encrypted-looking files in the long window
    "versioned_backup": "1",     # back up benign new/changed files (not just the startup snapshot)
    "backup_versions": "5",
    "io_attribution": "1",       # fall back to write-volume attribution when cwd/open-file finds nothing
    "io_min_bytes": "16384",
    "io_dominance": "3",
    "late_attach_sec": "30",     # events after containment still join the incident
    "alert_popup": "1",          # desktop alert window when an incident is raised
    "canary_randomize": "1",     # per-install random decoy names (an attacker cannot hard-code a skip list)
    "canary_seed": "",           # generated on first use; hidden from the Settings dialog
    "trusted_apps": "",          # comma-separated exe names / full paths whose writes are not scored (decoys still trip)
}
HIDDEN_CONFIG = {"canary_seed", "trusted_apps"}   # text values: not editable in the numeric Settings dialog

SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_version(version INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS config(key TEXT PRIMARY KEY, value TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS protected_folders(
  id INTEGER PRIMARY KEY,
  path TEXT NOT NULL UNIQUE,
  added_ts REAL NOT NULL,
  active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)));

CREATE TABLE IF NOT EXISTS processes(
  id INTEGER PRIMARY KEY,
  pid INTEGER NOT NULL,
  create_time REAL NOT NULL,          -- (pid, create_time) identifies a process; PIDs get reused
  name TEXT, exe TEXT, cmdline TEXT, ppid INTEGER, parent_name TEXT, username TEXT,
  UNIQUE(pid, create_time));

CREATE TABLE IF NOT EXISTS process_observations(
  id INTEGER PRIMARY KEY,
  process_id INTEGER NOT NULL REFERENCES processes(id),
  ts REAL NOT NULL,
  method TEXT NOT NULL,               -- 'cwd' | 'open_file'
  confidence TEXT NOT NULL CHECK(confidence IN ('reliable','ambiguous')));

CREATE TABLE IF NOT EXISTS process_events(
  id INTEGER PRIMARY KEY,
  process_id INTEGER NOT NULL REFERENCES processes(id),
  folder_id INTEGER NOT NULL REFERENCES protected_folders(id),
  ts REAL NOT NULL,
  kind TEXT NOT NULL CHECK(kind IN ('started','exited')));

CREATE TABLE IF NOT EXISTS fs_events(
  id INTEGER PRIMARY KEY,
  folder_id INTEGER NOT NULL REFERENCES protected_folders(id),
  ts REAL NOT NULL,
  event_type TEXT NOT NULL CHECK(event_type IN ('created','modified','deleted','moved')),
  path TEXT NOT NULL,
  dest_path TEXT,
  size INTEGER,
  entropy REAL,
  process_obs_id INTEGER REFERENCES process_observations(id),
  attribution TEXT NOT NULL DEFAULT 'none' CHECK(attribution IN ('reliable','ambiguous','none')),
  replayed INTEGER NOT NULL DEFAULT 0);

CREATE TABLE IF NOT EXISTS incidents(
  id INTEGER PRIMARY KEY,
  folder_id INTEGER NOT NULL REFERENCES protected_folders(id),
  process_id INTEGER REFERENCES processes(id),
  status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','contained','resolved','false_positive')),
  severity TEXT NOT NULL CHECK(severity IN ('low','medium','high','critical')),
  risk_score INTEGER NOT NULL CHECK(risk_score BETWEEN 0 AND 100),
  first_event_ts REAL NOT NULL,
  created_ts REAL NOT NULL,
  updated_ts REAL NOT NULL);

CREATE TABLE IF NOT EXISTS incident_signals(
  id INTEGER PRIMARY KEY,
  incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  weight INTEGER NOT NULL,
  detail TEXT NOT NULL,               -- JSON: measured value, threshold, baseline mean/std...
  ts REAL NOT NULL,
  UNIQUE(incident_id, name));

CREATE TABLE IF NOT EXISTS incident_events(
  incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  event_id INTEGER NOT NULL REFERENCES fs_events(id),
  PRIMARY KEY(incident_id, event_id));

CREATE TABLE IF NOT EXISTS incident_files(
  incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  path TEXT NOT NULL,                 -- original path
  current_path TEXT,                  -- path after rename (NULL if deleted)
  last_event_type TEXT NOT NULL,
  entropy REAL,
  first_seen REAL NOT NULL,
  last_seen REAL NOT NULL,
  PRIMARY KEY(incident_id, path));

CREATE TABLE IF NOT EXISTS backups(
  id INTEGER PRIMARY KEY,
  folder_id INTEGER NOT NULL REFERENCES protected_folders(id),
  original_path TEXT NOT NULL,
  backup_path TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  size INTEGER NOT NULL,
  ts REAL NOT NULL,
  UNIQUE(folder_id, original_path, sha256));

CREATE TABLE IF NOT EXISTS quarantine(
  id INTEGER PRIMARY KEY,
  incident_id INTEGER NOT NULL REFERENCES incidents(id),
  original_path TEXT NOT NULL,
  quarantine_path TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  size INTEGER NOT NULL,
  ts REAL NOT NULL,
  status TEXT NOT NULL DEFAULT 'quarantined' CHECK(status IN ('quarantined','restored')),
  restored_ts REAL,
  restored_dest TEXT,
  integrity_ok INTEGER CHECK(integrity_ok IN (0,1)));

CREATE TABLE IF NOT EXISTS recovery_records(
  id INTEGER PRIMARY KEY,
  incident_id INTEGER NOT NULL REFERENCES incidents(id),
  backup_id INTEGER REFERENCES backups(id),
  quarantine_id INTEGER REFERENCES quarantine(id),
  ts REAL NOT NULL,
  target_path TEXT NOT NULL,
  success INTEGER NOT NULL CHECK(success IN (0,1)),
  detail TEXT);

CREATE TABLE IF NOT EXISTS response_actions(
  id INTEGER PRIMARY KEY,
  incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  ts REAL NOT NULL,
  action TEXT NOT NULL,               -- suspend_process | quarantine_file | restore_file | recover_file | ...
  target TEXT,
  success INTEGER NOT NULL CHECK(success IN (0,1)),
  detail TEXT);

CREATE TABLE IF NOT EXISTS scan_sessions(
  id INTEGER PRIMARY KEY,
  folder_id INTEGER NOT NULL REFERENCES protected_folders(id),
  started_ts REAL NOT NULL, finished_ts REAL,
  status TEXT NOT NULL DEFAULT 'running' CHECK(status IN ('running','finished','cancelled','error')),
  files_scanned INTEGER NOT NULL DEFAULT 0, flagged INTEGER NOT NULL DEFAULT 0);

CREATE TABLE IF NOT EXISTS scan_results(
  id INTEGER PRIMARY KEY,
  session_id INTEGER NOT NULL REFERENCES scan_sessions(id) ON DELETE CASCADE,
  path TEXT NOT NULL, verdict TEXT NOT NULL, reason TEXT, entropy REAL);

CREATE TABLE IF NOT EXISTS activity_baseline(
  id INTEGER PRIMARY KEY,
  folder_id INTEGER NOT NULL REFERENCES protected_folders(id),
  window_start REAL NOT NULL,
  write_count INTEGER NOT NULL,
  max_score INTEGER NOT NULL,
  trusted INTEGER NOT NULL CHECK(trusted IN (0,1)));   -- only trusted windows feed the baseline

CREATE TABLE IF NOT EXISTS monitor_log(
  id INTEGER PRIMARY KEY, ts REAL NOT NULL, level TEXT NOT NULL, message TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS canaries(
  id INTEGER PRIMARY KEY,
  folder_id INTEGER NOT NULL REFERENCES protected_folders(id),
  path TEXT NOT NULL UNIQUE,
  sha256 TEXT NOT NULL,
  created_ts REAL NOT NULL,
  tripped_ts REAL);

-- Tamper-evident hash chain: hash = sha256(prev_hash | ts | kind | payload). Append-only (triggers below).
CREATE TABLE IF NOT EXISTS audit_log(
  id INTEGER PRIMARY KEY,
  ts REAL NOT NULL,
  kind TEXT NOT NULL,
  payload TEXT NOT NULL,
  prev_hash TEXT NOT NULL,
  hash TEXT NOT NULL UNIQUE);

CREATE TRIGGER IF NOT EXISTS trg_audit_no_update BEFORE UPDATE ON audit_log
  BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS trg_audit_no_delete BEFORE DELETE ON audit_log
  BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS trg_actions_no_update BEFORE UPDATE ON response_actions
  BEGIN SELECT RAISE(ABORT, 'response_actions is append-only'); END;
CREATE TRIGGER IF NOT EXISTS trg_actions_no_delete BEFORE DELETE ON response_actions
  BEGIN SELECT RAISE(ABORT, 'response_actions is append-only'); END;
CREATE TRIGGER IF NOT EXISTS trg_events_no_update BEFORE UPDATE ON fs_events
  BEGIN SELECT RAISE(ABORT, 'fs_events is append-only'); END;
CREATE TRIGGER IF NOT EXISTS trg_events_no_delete BEFORE DELETE ON fs_events
  WHEN IFNULL((SELECT value FROM config WHERE key='allow_prune'), '0') <> '1'
  BEGIN SELECT RAISE(ABORT, 'fs_events is append-only (retention pruning only)'); END;

CREATE INDEX IF NOT EXISTS idx_audit_kind ON audit_log(kind, ts);
CREATE INDEX IF NOT EXISTS idx_canary_folder ON canaries(folder_id);
CREATE INDEX IF NOT EXISTS idx_events_ts          ON fs_events(ts);
CREATE INDEX IF NOT EXISTS idx_events_folder_ts   ON fs_events(folder_id, ts);
CREATE INDEX IF NOT EXISTS idx_events_path        ON fs_events(path);
CREATE INDEX IF NOT EXISTS idx_events_obs         ON fs_events(process_obs_id);
CREATE INDEX IF NOT EXISTS idx_proc_pid           ON processes(pid);
CREATE INDEX IF NOT EXISTS idx_obs_process        ON process_observations(process_id, ts);
CREATE INDEX IF NOT EXISTS idx_procevents_ts      ON process_events(ts);
CREATE INDEX IF NOT EXISTS idx_incidents_created  ON incidents(created_ts);
CREATE INDEX IF NOT EXISTS idx_incidents_sev_stat ON incidents(severity, status);
CREATE INDEX IF NOT EXISTS idx_incidents_process  ON incidents(process_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_one_open_incident_per_folder
       ON incidents(folder_id) WHERE status = 'open';
CREATE INDEX IF NOT EXISTS idx_incfiles_path      ON incident_files(path);
CREATE INDEX IF NOT EXISTS idx_increv_event       ON incident_events(event_id);
CREATE INDEX IF NOT EXISTS idx_actions_incident   ON response_actions(incident_id, ts);
CREATE INDEX IF NOT EXISTS idx_quar_incident      ON quarantine(incident_id, status);
CREATE INDEX IF NOT EXISTS idx_backups_path       ON backups(folder_id, original_path, id);
CREATE INDEX IF NOT EXISTS idx_baseline_lookup    ON activity_baseline(folder_id, trusted, window_start);
CREATE INDEX IF NOT EXISTS idx_scanres_session    ON scan_results(session_id);
"""


def severity_for(score: int) -> str:
    return "critical" if score >= 90 else "high" if score >= 75 else "medium" if score >= 60 else "low"


class Database:
    def __init__(self, path: str):
        self.path = path
        self._wlock = threading.RLock()
        self._local = threading.local()
        self.fail_writes = False  # fault-injection hook used by tests/demo ("database unavailable")
        self._w = self._connect()
        with self._wlock:
            self._w.executescript(SCHEMA)
            if not self._w.execute("SELECT 1 FROM schema_version").fetchone():
                self._w.execute("INSERT INTO schema_version VALUES(?)", (SCHEMA_VERSION,))
            else:   # additive migration: new tables/triggers above are CREATE IF NOT EXISTS
                self._w.execute("UPDATE schema_version SET version=? WHERE version<?", (SCHEMA_VERSION, SCHEMA_VERSION))
            for k, v in DEFAULT_CONFIG.items():
                self._w.execute("INSERT OR IGNORE INTO config(key,value) VALUES(?,?)", (k, v))

    def _connect(self, readonly=False):
        c = sqlite3.connect(self.path, timeout=5.0, isolation_level=None, check_same_thread=False)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA foreign_keys=ON")
        c.execute("PRAGMA busy_timeout=5000")
        c.execute("PRAGMA synchronous=NORMAL")
        if readonly:
            c.execute("PRAGMA query_only=ON")
        return c

    # ---- write path -------------------------------------------------------
    @contextlib.contextmanager
    def transaction(self):
        """Serialised, atomic write transaction. Rolls back on ANY exception."""
        with self._wlock:
            if self.fail_writes:
                raise sqlite3.OperationalError("database unavailable (injected fault)")
            c = self._w
            c.execute("BEGIN IMMEDIATE")
            try:
                yield c
                c.execute("COMMIT")
            except BaseException:
                c.execute("ROLLBACK")
                raise

    # ---- read path --------------------------------------------------------
    def reader(self):
        c = getattr(self._local, "conn", None)
        if c is None:
            c = self._local.conn = self._connect(readonly=True)
        return c

    def query(self, sql, params=()):
        return self.reader().execute(sql, params).fetchall()

    def one(self, sql, params=()):
        return self.reader().execute(sql, params).fetchone()

    # ---- audit chain / retention -----------------------------------------
    @staticmethod
    def _chain_hash(prev, ts, kind, body):
        return hashlib.sha256(f"{prev}|{ts!r}|{kind}|{body}".encode()).hexdigest()

    def audit(self, c, kind, payload):
        """Append to the hash chain INSIDE the caller's transaction (so it commits/rolls back with the evidence)."""
        row = c.execute("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
        prev, ts, body = (row[0] if row else "0" * 64), time.time(), json.dumps(payload, sort_keys=True, default=str)
        c.execute("INSERT INTO audit_log(ts,kind,payload,prev_hash,hash) VALUES(?,?,?,?,?)",
                  (ts, kind, body, prev, self._chain_hash(prev, ts, kind, body)))

    def verify_audit(self):
        """Recompute the whole chain. Returns (ok, entries, first_bad_id, head_hash)."""
        prev, n = "0" * 64, 0
        for r in self.reader().execute("SELECT id,ts,kind,payload,prev_hash,hash FROM audit_log ORDER BY id"):
            n += 1
            if r["prev_hash"] != prev or r["hash"] != self._chain_hash(prev, r["ts"], r["kind"], r["payload"]):
                return False, n, r["id"], prev
            prev = r["hash"]
        return True, n, None, prev

    def set_incident_status(self, iid, status):
        with self.transaction() as c:
            c.execute("UPDATE incidents SET status=?,updated_ts=? WHERE id=?", (status, time.time(), iid))
            self.audit(c, "incident_status", {"incident": iid, "status": status})

    def prune(self, days, vacuum=True):
        """Retention: delete raw events older than N days that no incident references. Audited."""
        cutoff = time.time() - days * 86400
        with self.transaction() as c:
            c.execute("INSERT OR REPLACE INTO config(key,value) VALUES('allow_prune','1')")
            n = c.execute("DELETE FROM fs_events WHERE ts<? AND id NOT IN (SELECT event_id FROM incident_events)", (cutoff,)).rowcount
            c.execute("INSERT OR REPLACE INTO config(key,value) VALUES('allow_prune','0')")
            self.audit(c, "prune_events", {"older_than_days": days, "deleted": n})
        if vacuum:
            with self._wlock:
                self._w.execute("VACUUM")
        return n

    # ---- config -----------------------------------------------------------
    def get_config(self):
        return {r["key"]: r["value"] for r in self.query("SELECT key,value FROM config")}

    def set_config(self, key, value):
        with self.transaction() as c:
            c.execute("INSERT INTO config(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                      (key, str(value)))

    def log(self, level, message):
        try:
            with self.transaction() as c:
                c.execute("INSERT INTO monitor_log(ts,level,message) VALUES(?,?,?)", (time.time(), level, message))
        except sqlite3.Error:
            pass

    # ---- baseline ---------------------------------------------------------
    @staticmethod
    def baseline_stats(conn, folder_id, history=500):
        rows = conn.execute(
            "SELECT write_count FROM activity_baseline WHERE folder_id=? AND trusted=1 "
            "ORDER BY window_start DESC LIMIT ?", (folder_id, history)).fetchall()
        n = len(rows)
        if n == 0:
            return {"n": 0, "mean": 0.0, "std": 0.0}
        vals = [r[0] for r in rows]
        mean = sum(vals) / n
        std = (sum((v - mean) ** 2 for v in vals) / n) ** 0.5
        return {"n": n, "mean": mean, "std": std}

    # ---- integrity / backup ----------------------------------------------
    def integrity_check(self):
        return [r[0] for r in self.reader().execute("PRAGMA integrity_check").fetchall()] + \
               [f"FK violation: {tuple(r)}" for r in self.reader().execute("PRAGMA foreign_key_check").fetchall()]

    def backup_to(self, dest_path):
        """Online consistent copy using SQLite's backup API (safe while monitoring runs)."""
        dst = sqlite3.connect(dest_path)
        try:
            with self._wlock:
                self._w.backup(dst)
        finally:
            dst.close()
        return dest_path

    def close(self):
        with self._wlock:
            try:
                self._w.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            except sqlite3.Error:
                pass
            self._w.close()

    # ---- forensic report --------------------------------------------------
    def incident_report(self, iid):
        q = self.query
        inc = self.one("""SELECT i.*, f.path AS folder, p.pid, p.name AS pname, p.exe, p.cmdline, p.ppid,
                                  p.parent_name, p.username, p.create_time
                           FROM incidents i JOIN protected_folders f ON f.id=i.folder_id
                           LEFT JOIN processes p ON p.id=i.process_id WHERE i.id=?""", (iid,))
        if inc is None:
            return None
        return {
            "incident": dict(inc),
            "signals": [dict(r) for r in q("SELECT name,weight,detail FROM incident_signals WHERE incident_id=? ORDER BY weight DESC", (iid,))],
            "timeline": [dict(r) for r in q("""SELECT e.id,e.ts,e.event_type,e.path,e.dest_path,e.entropy,e.attribution,
                                                      p.pid, p.name AS pname
                                               FROM incident_events ie JOIN fs_events e ON e.id=ie.event_id
                                               LEFT JOIN process_observations o ON o.id=e.process_obs_id
                                               LEFT JOIN processes p ON p.id=o.process_id
                                               WHERE ie.incident_id=? ORDER BY e.ts, e.id""", (iid,))],
            "files": [dict(r) for r in q("SELECT * FROM incident_files WHERE incident_id=? ORDER BY first_seen", (iid,))],
            "actions": [dict(r) for r in q("SELECT ts,action,target,success,detail FROM response_actions WHERE incident_id=? ORDER BY id", (iid,))],
            "quarantine": [dict(r) for r in q("SELECT * FROM quarantine WHERE incident_id=? ORDER BY id", (iid,))],
            "recoveries": [dict(r) for r in q("SELECT * FROM recovery_records WHERE incident_id=? ORDER BY id", (iid,))],
        }


def format_report(rep, full=False) -> str:
    if not rep:
        return "no such incident"
    i = rep["incident"]
    t = lambda ts: time.strftime("%H:%M:%S", time.localtime(ts)) + f".{int((ts % 1) * 1000):03d}"
    L = [f"INCIDENT #{i['id']}  status={i['status']}  severity={i['severity']}  risk={i['risk_score']}/100",
         f"  folder : {i['folder']}",
         f"  first event {t(i['first_event_ts'])}  detected {t(i['created_ts'])}  "
         f"(detection latency {i['created_ts'] - i['first_event_ts']:.2f}s)"]
    if i["pid"]:
        L.append(f"  process: pid={i['pid']} name={i['pname']} ppid={i['ppid']} ({i['parent_name']}) user={i['username']}")
        L.append(f"           exe={i['exe']}  started={t(i['create_time'])}")
    else:
        L.append("  process: not attributed (no single reliable candidate)")
    L.append("  SIGNALS (why the score is what it is):")
    for s in rep["signals"]:
        L.append(f"    +{s['weight']:>2} {s['name']:<20} {s['detail']}")
    n_tl = 80 if full else 15
    L.append(f"  TIMELINE ({len(rep['timeline'])} events, first {min(n_tl, len(rep['timeline']))} shown):")
    for e in rep["timeline"][:n_tl]:
        who = f"pid {e['pid']}" if e["pid"] else e["attribution"]
        ent = f" H={e['entropy']:.2f}" if e["entropy"] else ""
        dest = f" -> {os.path.basename(e['dest_path'])}" if e["dest_path"] else ""
        L.append(f"    {t(e['ts'])} {e['event_type']:<8} {os.path.basename(e['path'])}{dest}{ent} [{who}]")
    L.append(f"  AFFECTED FILES: {len(rep['files'])}")
    if full:
        for f in rep["files"][:60]:
            L.append(f"    {os.path.basename(f['path'])}" + (f"  ->  {os.path.basename(f['current_path'])}" if f["current_path"] and f["current_path"] != f["path"] else ""))
    L.append("  RESPONSE ACTIONS:")
    for a in rep["actions"]:
        L.append(f"    {t(a['ts'])} {a['action']:<16} {'OK  ' if a['success'] else 'FAIL'} {os.path.basename(a['target'] or '')} {a['detail'] or ''}")
    L.append(f"  QUARANTINED: {sum(1 for q in rep['quarantine'] if q['status']=='quarantined')}  "
             f"RESTORED: {sum(1 for q in rep['quarantine'] if q['status']=='restored')}  "
             f"RECOVERED-FROM-BACKUP: {sum(1 for r in rep['recoveries'] if r['success'])}")
    return "\n".join(L)
