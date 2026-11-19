"""Engine: OS events -> bounded queue -> worker (attribute, detect, persist) -> response.

Threads
  watchdog observer thread(s) : producers. Native OS notifications -> normalised tuple -> queue.
  worker thread               : the ONLY consumer; owns detector state; batches DB writes.
  health thread               : restarts a dead observer, logs it.
  procwatch thread            : records process start/exit inside protected folders.
  scan threads                : on-demand folder scans (cancellable).
Queue is bounded; on overflow or when the DB is unavailable, events go to an on-disk JSONL spool
(size-capped, loudly counted) and are replayed later: evidence is neither lost silently nor
accumulated unboundedly in memory.
"""
import json
import os
import queue
import sqlite3
import threading
import time
import uuid
from collections import defaultdict

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from . import canary, procinfo
from .db import Database, severity_for
from .detector import (COMPRESSED_EXT, NOTE_RE, SUSPICIOUS_EXT, WRITE_TYPES, Detector, file_entropy)
from .response import Responder, sha256_file

SPOOL_MAX_BYTES = 20 * 1024 * 1024


class Spool:
    def __init__(self, path):
        self.path, self.lock = path, threading.Lock()
        self.dropped = 0

    def append(self, item):
        with self.lock:
            if os.path.exists(self.path) and os.path.getsize(self.path) > SPOOL_MAX_BYTES:
                self.dropped += 1
                return False
            with open(self.path, "a") as f:
                f.write(json.dumps(list(item[:4]) + [True]) + "\n")
            return True

    def drain(self):
        with self.lock:
            if not os.path.exists(self.path) or os.path.getsize(self.path) == 0:
                return []
            with open(self.path) as f:
                items = [tuple(json.loads(l)) for l in f if l.strip()]
            open(self.path, "w").close()
            return items

    def size(self):
        try:
            return os.path.getsize(self.path)
        except OSError:
            return 0


class _Handler(FileSystemEventHandler):
    """Runs on the OS-notification thread: must be fast -> normalise + enqueue only."""
    def __init__(self, engine):
        self.e = engine

    def on_created(self, ev):
        not ev.is_directory and self.e._enqueue("created", ev.src_path)

    def on_modified(self, ev):
        not ev.is_directory and self.e._enqueue("modified", ev.src_path)

    def on_deleted(self, ev):
        not ev.is_directory and self.e._enqueue("deleted", ev.src_path)

    def on_moved(self, ev):
        not ev.is_directory and self.e._enqueue("moved", ev.src_path, ev.dest_path)


class Engine:
    def __init__(self, data_dir, on_log=None, on_incident=None):
        self.data_dir = os.path.realpath(data_dir)
        os.makedirs(self.data_dir, mode=0o700, exist_ok=True)
        self.db = Database(os.path.join(self.data_dir, "ransomguard.db"))
        self.cfg = self.db.get_config()
        self.q = queue.Queue(maxsize=int(self.cfg["queue_max"]))
        self.stop_evt = threading.Event()
        self.detector = Detector(self.cfg)
        self._ignore, self._ilock = {}, threading.Lock()
        self.responder = Responder(self.db, self.data_dir, self.ignore)
        self.spool = Spool(os.path.join(self.data_dir, "spool.jsonl"))
        self.folders = {}                       # id -> normalised path
        self.stats = defaultdict(int)
        self.observer = None
        self.canary, self._bk_last = {}, {}      # normalised canary path -> {id, sha256}; per-path backup debounce
        self.threads, self.scans = [], {}
        self._trusted_seen = set()
        self.on_log, self.on_incident = on_log, on_incident
        self.api_name = None
        self.running = False

    def reload_config(self):
        self.cfg = self.db.get_config()
        self.detector.configure(self.cfg)

    # ------------------------------------------------------------------ logging
    def log(self, level, msg):
        if self.on_log:
            self.on_log(level, msg)
        self.db.log(level, msg)

    # ------------------------------------------------------------------ folders
    def add_folder(self, path):
        path = os.path.realpath(path)
        if not os.path.isdir(path):
            raise ValueError(f"not a directory: {path}")
        if path == self.data_dir or path.startswith(self.data_dir + os.sep) or self.data_dir.startswith(path + os.sep):
            raise ValueError("protected folder must not contain (or be inside) the RansomGuard data directory")
        with self.db.transaction() as c:
            c.execute("INSERT INTO protected_folders(path,added_ts) VALUES(?,?) ON CONFLICT(path) DO UPDATE SET active=1",
                      (path, time.time()))
            fid = c.execute("SELECT id FROM protected_folders WHERE path=?", (path,)).fetchone()[0]
        self.folders[fid] = os.path.normcase(path)
        self.ensure_canaries(fid, path)
        if self.running and self.observer:
            self.observer.schedule(_Handler(self), path, recursive=True)
        threading.Thread(target=self._snapshot, args=(fid, path), daemon=True, name="snapshot").start()
        return fid

    def remove_folder(self, fid):
        with self.db.transaction() as c:
            c.execute("UPDATE protected_folders SET active=0 WHERE id=?", (fid,))
        self.folders.pop(fid, None)
        if self.running:
            self._restart_observer()

    def _folder_path(self, fid):
        return self.db.one("SELECT path FROM protected_folders WHERE id=?", (fid,))["path"]

    def _register_canary(self, p):
        r = self.db.one("SELECT id,sha256 FROM canaries WHERE path=?", (p,))
        if r:
            self.canary[os.path.normcase(p)] = {"id": r["id"], "sha256": r["sha256"]}

    def canary_names(self):
        """Decoy names for this install: random per-install (seed kept in config), or the legacy fixed list when an older
        database already has decoys planted under those names."""
        if self.cfg.get("canary_randomize") != "1":
            return canary.CANARY_NAMES
        seed = self.cfg.get("canary_seed", "")
        if not seed:
            if self.db.one("SELECT 1 FROM canaries LIMIT 1"):
                return canary.CANARY_NAMES          # existing install: keep its decoys valid
            seed = uuid.uuid4().hex[:12]
            self.db.set_config("canary_seed", seed)
            self.cfg = self.db.get_config()
        return canary.names_for(seed)

    def ensure_canaries(self, fid, path, rearm=False):
        """Plant decoy files in a protected folder (idempotent). Tripped decoys stay as evidence until re-armed."""
        if self.cfg.get("canary_enabled") != "1":
            return 0
        n = 0
        for name in self.canary_names()[:max(1, min(8, int(self.cfg.get("canary_count", 6))))]:
            p = os.path.join(path, name)
            row = self.db.one("SELECT tripped_ts FROM canaries WHERE path=?", (p,))
            if row and (not row["tripped_ts"] or not rearm) and (os.path.exists(p) or row["tripped_ts"]):
                self._register_canary(p)
                continue
            if row and row["tripped_ts"] and os.path.exists(p):
                continue                       # still present but modified: quarantine/restore it first
            # no event suppression here: our own writes carry the expected content hash, so _canary_check never trips on them
            p, sha = canary.plant(path, name)
            with self.db.transaction() as c:
                c.execute("""INSERT INTO canaries(folder_id,path,sha256,created_ts) VALUES(?,?,?,?)
                             ON CONFLICT(path) DO UPDATE SET sha256=excluded.sha256,created_ts=excluded.created_ts,tripped_ts=NULL""",
                          (fid, p, sha, time.time()))
                self.db.audit(c, "canary_armed", {"path": p})
            self._register_canary(p)
            self.responder.backup_file(fid, p, self.cfg)
            n += 1
        for r in self.db.query("SELECT path FROM canaries WHERE folder_id=?", (fid,)):
            self._register_canary(r["path"])
        return n

    def rearm_canaries(self):
        return sum(self.ensure_canaries(f, self._folder_path(f), rearm=True) for f in list(self.folders))

    def _canary_check(self, e):
        """Return the canary id if this event is a VERIFIED change to a decoy (content hash differs / renamed / deleted)."""
        if self.cfg.get("canary_enabled") != "1" or e["type"] == "created":
            return None
        for p in (e["path"], e["dest"]):
            info = p and self.canary.get(os.path.normcase(p))
            if not info:
                continue
            if e["type"] == "modified":
                try:
                    if sha256_file(p) == info["sha256"]:
                        return None            # metadata-only touch (atime/mtime): content unchanged
                except OSError:
                    pass
            return info["id"]
        return None

    def trusted_apps(self):
        return [x.strip() for x in self.cfg.get("trusted_apps", "").split(",") if x.strip()]

    def _is_trusted(self, conf, cands):
        """True only when ONE process is reliably attributed and it is on the allowlist. Entries containing a path separator
        match the full exe path (hard to spoof); plain names match the exe name (convenient, but a same-named malware could
        hide behind it, so the Trusted Apps window recommends full paths). Decoy files are never excused."""
        if conf != "reliable" or len(cands) != 1:
            return False
        allow = self.trusted_apps()
        if not allow:
            return False
        name, exe = (cands[0].get("name") or "").lower(), os.path.normcase(cands[0].get("exe") or "")
        for a in allow:
            if os.sep in a or "/" in a or ":" in a:
                if exe and os.path.normcase(os.path.realpath(a)) == os.path.normcase(os.path.realpath(exe)):
                    return True
            elif a.lower() == name:
                return True
        return False

    def _snapshot(self, fid, path):
        try:
            n = self.responder.snapshot(fid, path, self.cfg, self.stop_evt)
            self.log("info", f"backup snapshot of {path}: {n} files")
            self.stats["snapshot_done"] += 1
        except Exception as e:  # noqa
            self.log("error", f"snapshot failed: {e}")

    # ------------------------------------------------------------------ lifecycle
    def start(self):
        if self.running:
            return
        self.stop_evt.clear()
        self.cfg = self.db.get_config()
        self.detector.configure(self.cfg)
        for r in self.db.query("SELECT id,path FROM protected_folders WHERE active=1"):
            if os.path.isdir(r["path"]):
                self.folders[r["id"]] = os.path.normcase(r["path"])
        for fid in list(self.folders):
            self.ensure_canaries(fid, self._folder_path(fid))
        self._restart_observer()
        self.running = True
        for fn, name in ((self._worker, "worker"), (self._health, "health"), (self._procwatch, "procwatch")):
            t = threading.Thread(target=fn, daemon=True, name=name)
            t.start()
            self.threads.append(t)
        self.log("info", f"monitoring {len(self.folders)} folder(s) via {self.api_name}")

    def stop(self):
        if not self.running:
            return
        self.running = False
        if self.observer:
            self.observer.stop()
            self.observer.join(timeout=3)
        self.stop_evt.set()
        for s in self.scans.values():
            s["cancel"].set()
        for t in self.threads:
            t.join(timeout=5)
        self.threads.clear()
        self.log("info", "monitoring stopped")

    def close(self):
        self.stop()
        self.db.close()

    def _restart_observer(self):
        if self.observer:
            try:
                self.observer.stop()
                self.observer.join(timeout=2)
            except Exception:  # noqa
                pass
        self.observer = Observer()
        self.api_name = type(self.observer).__name__ + " (native OS notifications)"
        h = _Handler(self)
        for fid, p in self.folders.items():
            row = self.db.one("SELECT path FROM protected_folders WHERE id=?", (fid,))
            self.observer.schedule(h, row["path"], recursive=True)
        self.observer.start()

    def _health(self):
        while not self.stop_evt.wait(2.0):
            if self.observer is not None and not self.observer.is_alive() and self.running:
                self.stats["observer_restarts"] += 1
                self.log("error", "filesystem observer died; restarting")
                try:
                    self._restart_observer()
                except Exception as e:  # noqa
                    self.log("error", f"observer restart failed: {e}")

    # ------------------------------------------------------------------ producer side
    def ignore(self, paths, ttl=3.0):
        with self._ilock:
            for p in paths:
                self._ignore[os.path.normcase(p)] = time.time() + ttl

    def _ignored(self, path):
        p = os.path.normcase(path)
        if p.startswith(self.data_dir):
            return True
        with self._ilock:
            exp = self._ignore.get(p)
            return exp is not None and exp > time.time()

    def _enqueue(self, etype, src, dest=None):
        if self._ignored(src) or (dest and self._ignored(dest)):
            self.stats["self_events_ignored"] += 1
            return
        item = (time.time(), etype, src, dest, False)
        self.stats["received"] += 1
        try:
            self.q.put_nowait(item)
        except queue.Full:
            if self.spool.append(item):
                self.stats["spooled"] += 1
            else:
                self.stats["dropped_spool_full"] += 1

    # ------------------------------------------------------------------ consumer side
    def _folder_for(self, path):
        p, best = os.path.normcase(path), None
        for fid, root in self.folders.items():
            if (p == root or p.startswith(root + os.sep)) and (best is None or len(root) > len(self.folders[best])):
                best = fid
        return best

    def _collect(self):
        try:
            batch = [self.q.get(timeout=0.2)]
        except queue.Empty:
            return []
        while len(batch) < 500:
            try:
                batch.append(self.q.get_nowait())
            except queue.Empty:
                break
        return batch

    def _worker(self):
        backoff = 0
        while not self.stop_evt.is_set():
            batch = self._collect()
            if not batch:
                self._idle()
                continue
            try:
                self._process(batch)
                backoff = 0
            except sqlite3.Error as e:
                self.stats["db_errors"] += 1
                for it in batch:
                    if self.spool.append(it):
                        self.stats["spooled"] += 1
                self.log("error", f"DB write failed ({e}); {len(batch)} events spooled to disk")
                self.stop_evt.wait(min(5.0, 0.3 * 2 ** backoff))
                backoff += 1
        # final drain, then persist any still-open baseline windows
        for _ in range(100):
            batch = self._collect()
            if not batch:
                break
            try:
                self._process(batch)
            except sqlite3.Error:
                for it in batch:
                    self.spool.append(it)
                break
        self._idle(force=True)

    def _idle(self, force=False):
        done = self.detector.flush_idle(time.time() + (1e9 if force else 0))
        if done:
            try:
                with self.db.transaction() as c:
                    c.executemany("INSERT INTO activity_baseline(folder_id,window_start,write_count,max_score,trusted) VALUES(?,?,?,?,?)", done)
            except sqlite3.Error:
                pass
        if self.spool.size() and not force:
            items = self.spool.drain()
            for i in range(0, len(items), 500):
                try:
                    self._process(items[i:i + 500])
                    self.stats["replayed"] += len(items[i:i + 500])
                except sqlite3.Error:
                    for it in items[i:]:
                        self.spool.append(it)
                    break
        with self._ilock:
            now = time.time()
            for k in [k for k, v in self._ignore.items() if v < now]:
                del self._ignore[k]

    @staticmethod
    def _dedupe(batch):
        """Collapse duplicate notifications (e.g. several 'modified' per write) within 50 ms."""
        out, last = [], {}
        for it in batch:
            key = (it[1], it[2], it[3])
            if key in last and it[0] - last[key] < 0.05:
                continue
            last[key] = it[0]
            out.append(it)
        return out

    def _upsert_process(self, c, p):
        c.execute("""INSERT OR IGNORE INTO processes(pid,create_time,name,exe,cmdline,ppid,parent_name,username)
                     VALUES(?,?,?,?,?,?,?,?)""",
                  (p["pid"], p["create_time"], p["name"], p["exe"], p["cmdline"], p["ppid"], p["parent_name"], p["username"]))
        return c.execute("SELECT id FROM processes WHERE pid=? AND create_time=?", (p["pid"], p["create_time"])).fetchone()[0]

    def _process(self, batch):
        deduped = self._dedupe(batch)
        self.stats["deduped"] += len(batch) - len(deduped)
        groups = defaultdict(list)
        for ts, et, src, dest, rep in deduped:
            fid = self._folder_for(src)
            if fid is not None:
                groups[fid].append({"ts": ts, "type": et, "path": src, "dest": dest, "replayed": rep,
                                    "entropy": None, "size": None})
        if not groups:
            return
        live = any(not e["replayed"] for g in groups.values() for e in g)
        cfg = self.cfg
        conf, cands = procinfo.attribute([self.folders[f] for f in groups]) if live else ("none", [])
        trusted = live and self._is_trusted(conf, cands)
        budget = 100
        for g in groups.values():
            for e in g:
                tgt = e["dest"] if e["type"] == "moved" else e["path"]
                if e["type"] != "deleted":
                    try:
                        e["size"] = os.path.getsize(tgt)
                    except OSError:
                        pass
                    if budget > 0 and not e["replayed"]:
                        e["entropy"] = file_entropy(tgt)
                        budget -= 1
        for g in groups.values():
            for e in g:
                e["canary"] = None if e["replayed"] else self._canary_check(e)
        pending, scores = [], {}
        hist = int(self.cfg["baseline_history"])
        with self.db.transaction() as c:                      # ONE atomic unit per batch
            obs_id = proc_row = None
            for cand in cands:
                pr = self._upsert_process(c, cand)
                oid = c.execute("INSERT INTO process_observations(process_id,ts,method,confidence) VALUES(?,?,?,?)",
                                (pr, time.time(), cand["method"], conf)).lastrowid
                if conf == "reliable":
                    obs_id, proc_row = oid, pr
            for fid, evs in groups.items():
                for e in evs:
                    e["id"] = c.execute(
                        "INSERT INTO fs_events(folder_id,ts,event_type,path,dest_path,size,entropy,process_obs_id,attribution,replayed) "
                        "VALUES(?,?,?,?,?,?,?,?,?,?)",
                        (fid, e["ts"], e["type"], e["path"], e["dest"], e["size"], e["entropy"],
                         obs_id if not e["replayed"] else None, conf if not e["replayed"] else "none", int(e["replayed"]))).lastrowid
                for e in evs:
                    if e.get("canary") and c.execute("UPDATE canaries SET tripped_ts=? WHERE id=? AND tripped_ts IS NULL", (e["ts"], e["canary"])).rowcount:
                        self.db.audit(c, "canary_tripped", {"path": e["path"], "event": e["type"]})
                if trusted and not any(e.get("canary") for e in evs):
                    self.stats["trusted_skipped"] += len(evs)       # events stay in the forensic log but are not scored
                    if cands[0]["pid"] not in self._trusted_seen:
                        self._trusted_seen.add(cands[0]["pid"])
                        self.log("info", f"trusted app {cands[0]['name']} (pid {cands[0]['pid']}) is writing in a protected folder: not scored")
                    continue
                late = self._attach_late(c, fid, evs, proc_row)
                self.detector.add(fid, evs)
                score, signals, window = self.detector.evaluate(fid, self.db.baseline_stats(c, fid, hist))
                scores[fid] = score
                if late:
                    pending.append(late)
                for e in evs:
                    for row in self.detector.account(fid, e["ts"], e["type"] in WRITE_TYPES, score):
                        c.execute("INSERT INTO activity_baseline(folder_id,window_start,write_count,max_score,trusted) VALUES(?,?,?,?,?)", row)
                if score >= self.detector.threshold and not late:
                    pending.append(self._upsert_incident(c, fid, score, signals, window, proc_row))
        self.stats["processed"] += sum(len(g) for g in groups.values())
        if cfg.get("versioned_backup") == "1":
            hot = {p["fid"] for p in pending}
            self._version_backups(groups, {f for f in groups if f not in hot and scores.get(f, 0) < self.detector.threshold / 2})
        for info in pending:                                   # response AFTER commit; outcomes persisted separately
            self._respond(info)

    def _upsert_incident(self, c, fid, score, signals, window, proc_row):
        now = time.time()
        row = c.execute("SELECT id,risk_score,process_id FROM incidents WHERE folder_id=? AND status='open'", (fid,)).fetchone()
        susp = [x["ts"] for x in window if self.detector._suspicious(x)]
        t0 = min(susp) if susp else min(x["ts"] for x in window)       # incident starts at the first SUSPICIOUS event
        window = [x for x in window if x["ts"] >= t0 - 0.5]            # unrelated earlier activity is not evidence
        if row is None:
            iid = c.execute("INSERT INTO incidents(folder_id,process_id,severity,risk_score,first_event_ts,created_ts,updated_ts) VALUES(?,?,?,?,?,?,?)",
                            (fid, proc_row, severity_for(score), score, t0, now, now)).lastrowid
            new = True
        else:
            iid, new = row["id"], False
            best = max(score, row["risk_score"])
            c.execute("UPDATE incidents SET risk_score=?,severity=?,updated_ts=?,process_id=COALESCE(process_id,?) WHERE id=?",
                      (best, severity_for(best), now, proc_row, iid))
        for s in signals:
            c.execute("""INSERT INTO incident_signals(incident_id,name,weight,detail,ts) VALUES(?,?,?,?,?)
                         ON CONFLICT(incident_id,name) DO UPDATE SET weight=excluded.weight,detail=excluded.detail,ts=excluded.ts""",
                      (iid, s["name"], s["weight"], json.dumps(s["detail"]), now))
        self._link(c, iid, window)
        if new:
            self.db.audit(c, "incident_created", {"incident": iid, "folder": fid, "score": score,
                                                  "signals": [s["name"] for s in signals]})
        return {"id": iid, "fid": fid, "new": new, "score": score}

    def _link(self, c, iid, events):
        for e in events:
            if "id" not in e:
                continue
            c.execute("INSERT OR IGNORE INTO incident_events(incident_id,event_id) VALUES(?,?)", (iid, e["id"]))
            cur = None if e["type"] == "deleted" else (e["dest"] if e["type"] == "moved" else e["path"])
            c.execute("""INSERT INTO incident_files(incident_id,path,current_path,last_event_type,entropy,first_seen,last_seen)
                         VALUES(?,?,?,?,?,?,?)
                         ON CONFLICT(incident_id,path) DO UPDATE SET current_path=excluded.current_path,
                           last_event_type=excluded.last_event_type, entropy=COALESCE(excluded.entropy,entropy),
                           last_seen=excluded.last_seen""",
                      (iid, e["path"], cur, e["type"], e["entropy"], e["ts"], e["ts"]))

    def _attach_late(self, c, fid, evs, proc_row):
        """Damage between detection and containment: suspicious events arriving shortly after an incident was
        contained are attached to it (so they are quarantined and recoverable) instead of being forgotten."""
        row = c.execute("SELECT id,process_id FROM incidents WHERE folder_id=? AND status='contained' AND updated_ts>? "
                        "ORDER BY id DESC LIMIT 1", (fid, time.time() - float(self.cfg["late_attach_sec"]))).fetchone()
        if not row:
            return None
        take = [e for e in evs if self.detector._suspicious(e)]
        if take or (proc_row is not None and proc_row == row["process_id"]):
            # deletions that accompany encrypted-looking activity (copy-encrypt-delete attacks) belong to the attack
            take += [e for e in evs if e["type"] == "deleted"]
        if not take:
            return None
        c.execute("UPDATE incidents SET updated_ts=?,process_id=COALESCE(process_id,?) WHERE id=?", (time.time(), proc_row, row["id"]))
        self._link(c, row["id"], take)
        self.db.audit(c, "incident_late_events", {"incident": row["id"], "events": len(take)})
        return {"id": row["id"], "fid": fid, "new": False, "score": 0}

    def _version_backups(self, groups, quiet):
        """Back up benign new/changed files (never encrypted-looking ones) so they are recoverable too."""
        n, now = 0, time.time()
        for fid in quiet:
            for e in groups[fid]:
                if n >= 100:
                    return
                if e["replayed"] or e.get("canary") or e["type"] not in WRITE_TYPES:
                    continue
                tgt = e["dest"] if e["type"] == "moved" else e["path"]
                if (os.path.splitext(tgt)[1].lower() in SUSPICIOUS_EXT or (e["entropy"] or 0) >= self.detector.ent_thr
                        or self._bk_last.get(tgt, 0) > now - 3 or os.path.normcase(tgt) in self.canary):
                    continue
                self._bk_last[tgt] = now
                if os.path.isfile(tgt) and self.responder.backup_file(fid, tgt, self.cfg):
                    n += 1
        if len(self._bk_last) > 5000:
            self._bk_last.clear()

    # ------------------------------------------------------------------ response
    def _respond(self, info):
        iid, fid = info["id"], info["fid"]
        acted = suspended = False
        try:
            inc = self.db.one("SELECT process_id,first_event_ts FROM incidents WHERE id=?", (iid,))
            if not inc["process_id"] and self.cfg["io_attribution"] == "1":
                conf, cands = procinfo.attribute_io(inc["first_event_ts"] - 0.1, int(self.cfg["io_min_bytes"]), float(self.cfg["io_dominance"]))
                if conf == "reliable":
                    with self.db.transaction() as c:
                        pr = self._upsert_process(c, cands[0])
                        c.execute("INSERT INTO process_observations(process_id,ts,method,confidence) VALUES(?,?,?,?)", (pr, time.time(), "io_delta", "reliable"))
                        c.execute("UPDATE incidents SET process_id=? WHERE id=? AND process_id IS NULL", (pr, iid))
                        self.db.audit(c, "process_attributed", {"incident": iid, "pid": cands[0]["pid"], "method": "io_delta"})
                    inc = self.db.one("SELECT process_id,first_event_ts FROM incidents WHERE id=?", (iid,))
            if self.cfg["auto_suspend"] == "1" and inc["process_id"]:
                tried = self.db.one("SELECT 1 FROM response_actions WHERE incident_id=? AND action='suspend_process'", (iid,))
                if not tried:
                    p = self.db.one("SELECT pid,create_time,name FROM processes WHERE id=?", (inc["process_id"],))
                    suspended = self.responder.suspend_process(iid, dict(p))
                    acted |= suspended
            if self.cfg["auto_quarantine"] == "1":
                thr = float(self.cfg["entropy_threshold"])
                rows = self.db.query(
                    """SELECT path,current_path,entropy FROM incident_files f WHERE incident_id=? AND current_path IS NOT NULL
                       AND last_event_type!='deleted' AND NOT EXISTS
                       (SELECT 1 FROM quarantine q WHERE q.incident_id=f.incident_id AND q.original_path=f.path) LIMIT 500""", (iid,))
                for r in rows:
                    cur = r["current_path"]
                    if ((r["entropy"] or 0) >= thr or os.path.splitext(cur)[1].lower() in SUSPICIOUS_EXT) and os.path.exists(cur):
                        acted |= self.responder.quarantine_file(iid, r["path"], cur)
            if acted:
                with self.db.transaction() as c:
                    if c.execute("UPDATE incidents SET status='contained',updated_ts=? WHERE id=? AND status='open'", (time.time(), iid)).rowcount:
                        self.db.audit(c, "incident_status", {"incident": iid, "status": "contained"})
                self.detector.reset(fid)
            if suspended:
                self.rearm_canaries()          # threat frozen: put fresh decoys back
        except sqlite3.Error as e:
            self.log("error", f"response bookkeeping failed for incident {iid}: {e}")
        if info["new"] and self.on_incident:
            self.on_incident(iid)

    # ------------------------------------------------------------------ process watcher
    def _procwatch(self):
        prev = {}
        while not self.stop_evt.wait(0.5):
            roots = list(self.folders.values())
            if not roots:
                continue
            try:
                procinfo.sample_io()
            except Exception:  # noqa
                pass
            cur = procinfo.scan(roots, ttl=0)
            changes = [("started", cur[k]) for k in cur if k not in prev] + [("exited", prev[k]) for k in prev if k not in cur]
            prev = cur
            if not changes:
                continue
            try:
                with self.db.transaction() as c:
                    for kind, p in changes:
                        fid = next((f for f, r in self.folders.items() if r == p["root"]), None)
                        if fid is None:
                            continue
                        pr = self._upsert_process(c, p)
                        c.execute("INSERT INTO process_events(process_id,folder_id,ts,kind) VALUES(?,?,?,?)", (pr, fid, time.time(), kind))
            except sqlite3.Error:
                pass

    # ------------------------------------------------------------------ on-demand scan
    def start_scan(self, fid):
        folder = self.db.one("SELECT path FROM protected_folders WHERE id=?", (fid,))["path"]
        with self.db.transaction() as c:
            sid = c.execute("INSERT INTO scan_sessions(folder_id,started_ts) VALUES(?,?)", (fid, time.time())).lastrowid
        cancel = threading.Event()
        self.scans[sid] = {"cancel": cancel}
        threading.Thread(target=self._scan, args=(sid, folder, cancel), daemon=True, name=f"scan-{sid}").start()
        return sid

    def _scan(self, sid, folder, cancel):
        thr, scanned, flagged, rows, status = float(self.cfg["entropy_threshold"]), 0, 0, [], "finished"
        try:
            for root, _, files in os.walk(folder):
                for fn in files:
                    if cancel.is_set():
                        status = "cancelled"
                        raise StopIteration
                    p = os.path.join(root, fn)
                    scanned += 1
                    ext = os.path.splitext(fn)[1].lower()
                    ent = file_entropy(p)
                    reason = ("known ransomware extension" if ext in SUSPICIOUS_EXT else
                              "ransom-note filename" if NOTE_RE.search(fn) else
                              f"high entropy ({ent:.2f} bits/byte)" if ent and ent >= thr else None)
                    if reason:
                        flagged += 1
                        rows.append((sid, p, "suspicious", reason, ent))
                    if len(rows) >= 200:
                        self._flush_scan(sid, rows, scanned, flagged)
                        rows = []
        except StopIteration:
            pass
        except Exception as e:  # noqa
            status = "error"
            self.log("error", f"scan {sid}: {e}")
        self._flush_scan(sid, rows, scanned, flagged, status)

    def _flush_scan(self, sid, rows, scanned, flagged, status=None):
        with self.db.transaction() as c:
            c.executemany("INSERT INTO scan_results(session_id,path,verdict,reason,entropy) VALUES(?,?,?,?,?)", rows)
            c.execute("UPDATE scan_sessions SET files_scanned=?,flagged=? WHERE id=?", (scanned, flagged, sid))
            if status:
                c.execute("UPDATE scan_sessions SET status=?,finished_ts=? WHERE id=?", (status, time.time(), sid))
