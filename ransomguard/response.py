"""Controlled response: process suspension, quarantine, restore, backup recovery.
Every action's outcome (success/failure + detail) is persisted in response_actions."""
import hashlib
import os
import shutil
import sqlite3
import time

import psutil

PROTECTED_NAMES = {"systemd", "init", "launchd", "explorer.exe", "svchost.exe", "csrss.exe", "winlogon.exe",
                   "services.exe", "lsass.exe", "wininit.exe", "kernel_task", "sshd", "bash", "zsh", "sh"}


def sha256_file(path, chunk=1 << 20):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


class Responder:
    def __init__(self, db, data_dir, ignore):
        self.db, self.ignore = db, ignore          # ignore(paths): suppress self-caused FS events
        self.qdir = os.path.join(data_dir, "quarantine")
        self.bdir = os.path.join(data_dir, "backups")
        for d in (self.qdir, self.bdir):
            os.makedirs(d, mode=0o700, exist_ok=True)
            try:
                os.chmod(d, 0o700)    # owner-only. On Windows this is a no-op: rely on the NTFS ACL of the data dir.
            except OSError:
                pass

    def _action(self, c, iid, action, target, ok, detail):
        c.execute("INSERT INTO response_actions(incident_id,ts,action,target,success,detail) VALUES(?,?,?,?,?,?)",
                  (iid, time.time(), action, target, 1 if ok else 0, detail))
        self.db.audit(c, "response_action", {"incident": iid, "action": action, "target": target, "success": bool(ok), "detail": detail})

    def record(self, iid, action, target, ok, detail):
        with self.db.transaction() as c:
            self._action(c, iid, action, target, ok, detail)

    # ---- process control ----------------------------------------------------
    def suspend_process(self, iid, proc):
        """proc: dict(pid, create_time, name). Suspends only if identity re-verified."""
        pid, ct, name = proc["pid"], proc["create_time"], proc["name"] or "?"
        target = f"pid {pid} ({name})"
        try:
            if pid <= 1 or pid == os.getpid() or pid in {p.pid for p in psutil.Process().parents()}:
                raise PermissionError("refusing to suspend self/ancestor/init")
            if name.lower() in PROTECTED_NAMES:
                raise PermissionError(f"'{name}' is on the protected-process list")
            p = psutil.Process(pid)
            if abs(round(p.create_time(), 3) - ct) > 0.01:
                raise psutil.NoSuchProcess(pid, msg="PID reused by a different process")
            p.suspend()
            time.sleep(0.15)
            status = p.status()
            ok = status in (psutil.STATUS_STOPPED, "stopped")
            detail = f"state after SIGSTOP/NtSuspend = {status}"
        except psutil.NoSuchProcess as e:
            ok, detail = False, f"process gone or PID reused: {e}"
        except psutil.AccessDenied:
            ok, detail = False, "access denied (insufficient OS privileges; not elevating)"
        except PermissionError as e:
            ok, detail = False, str(e)
        self.record(iid, "suspend_process", target, ok, detail)
        return ok

    # ---- quarantine ------------------------------------------------------------
    def quarantine_file(self, iid, original, current):
        try:
            sha = sha256_file(current)
            size = os.path.getsize(current)
            qpath = os.path.join(self.qdir, f"{int(time.time()*1000)}_{sha[:12]}_{os.path.basename(current)}")
            self.ignore([current, qpath])
            shutil.move(current, qpath)
            try:
                os.chmod(qpath, 0o600)
            except OSError:
                pass
            with self.db.transaction() as c:       # row + action atomically
                c.execute("INSERT INTO quarantine(incident_id,original_path,quarantine_path,sha256,size,ts) VALUES(?,?,?,?,?,?)",
                          (iid, original, qpath, sha, size, time.time()))
                self._action(c, iid, "quarantine_file", current, True, f"sha256={sha[:16]}")
            return True
        except (OSError, sqlite3.Error) as e:
            try:
                self.record(iid, "quarantine_file", current, False, f"{type(e).__name__}: {e}")
            except sqlite3.Error:
                pass
            return False

    def restore_quarantined(self, qid, dest=None):
        r = self.db.one("SELECT * FROM quarantine WHERE id=?", (qid,))
        if r is None or r["status"] != "quarantined":
            return False, "not found / already restored"
        target = dest or r["original_path"]
        try:
            if sha256_file(r["quarantine_path"]) != r["sha256"]:
                raise ValueError("quarantined file hash does not match recorded hash (tampered?)")
            if os.path.exists(target):
                raise FileExistsError(f"{target} exists; refusing to overwrite")
            self.ignore([target])
            os.makedirs(os.path.dirname(target), exist_ok=True)
            shutil.copy2(r["quarantine_path"], target)
            ok = sha256_file(target) == r["sha256"]
            if ok:
                os.remove(r["quarantine_path"])
            with self.db.transaction() as c:
                c.execute("UPDATE quarantine SET status=?, restored_ts=?, restored_dest=?, integrity_ok=? WHERE id=?",
                          ("restored" if ok else "quarantined", time.time(), target, 1 if ok else 0, qid))
                self._action(c, r["incident_id"], "restore_file", target, ok,
                             "sha256 verified after restore" if ok else "hash mismatch after copy")
            return ok, "restored, sha256 verified" if ok else "hash mismatch"
        except (OSError, ValueError, sqlite3.Error) as e:
            try:
                self.record(r["incident_id"], "restore_file", target, False, f"{type(e).__name__}: {e}")
            except sqlite3.Error:
                pass
            return False, str(e)

    # ---- backups -----------------------------------------------------------------
    def snapshot(self, folder_id, folder, cfg, stop=None):
        """Content-addressed pre-incident copies (size/file-count capped). Returns files backed up."""
        maxb, maxf, n = int(cfg["max_backup_bytes"]), int(cfg["snapshot_max_files"]), 0
        rows = []
        for root, dirs, files in os.walk(folder):
            for fn in files:
                if stop is not None and stop.is_set():
                    break
                p = os.path.join(root, fn)
                try:
                    if os.path.islink(p) or os.path.getsize(p) > maxb:
                        continue
                    sha = sha256_file(p)
                    bp = os.path.join(self.bdir, sha)
                    if not os.path.exists(bp):
                        shutil.copyfile(p, bp)
                        os.chmod(bp, 0o600)
                    rows.append((folder_id, p, bp, sha, os.path.getsize(p), time.time()))
                except OSError:
                    continue
                n += 1
                if n >= maxf:
                    break
            if n >= maxf:
                break
        with self.db.transaction() as c:
            c.executemany("INSERT OR IGNORE INTO backups(folder_id,original_path,backup_path,sha256,size,ts) VALUES(?,?,?,?,?,?)", rows)
        return n

    def backup_file(self, folder_id, path, cfg):
        """Versioned backup of a benign new/changed file (content-addressed; keeps the newest N versions)."""
        try:
            if os.path.islink(path) or os.path.getsize(path) > int(cfg["max_backup_bytes"]):
                return False
            sha = sha256_file(path)
            bp = os.path.join(self.bdir, sha)
            if not os.path.exists(bp):
                shutil.copyfile(path, bp)
                os.chmod(bp, 0o600)
            keep = int(cfg["backup_versions"])
            with self.db.transaction() as c:
                c.execute("INSERT OR IGNORE INTO backups(folder_id,original_path,backup_path,sha256,size,ts) VALUES(?,?,?,?,?,?)",
                          (folder_id, path, bp, sha, os.path.getsize(path), time.time()))
                old = c.execute("""SELECT id,backup_path FROM backups WHERE folder_id=? AND original_path=?
                                   AND id NOT IN (SELECT backup_id FROM recovery_records WHERE backup_id IS NOT NULL)
                                   ORDER BY id DESC LIMIT -1 OFFSET ?""", (folder_id, path, keep)).fetchall()
                for r in old:
                    c.execute("DELETE FROM backups WHERE id=?", (r["id"],))
                    if not c.execute("SELECT 1 FROM backups WHERE backup_path=?", (r["backup_path"],)).fetchone():
                        try:
                            os.remove(r["backup_path"])
                        except OSError:
                            pass
            return True
        except (OSError, sqlite3.Error):
            return False

    def recover_incident(self, iid):
        """Restore every affected file that has a backup. Returns (recovered, failed)."""
        files = self.db.query("SELECT f.path, i.folder_id, i.first_event_ts FROM incident_files f JOIN incidents i ON i.id=f.incident_id WHERE f.incident_id=?", (iid,))
        good = bad = 0
        # Backups are trusted only if made BEFORE the first encrypted-looking event of this incident (a backup taken
        # mid-attack could itself be encrypted). Benign events in the same window (e.g. file creation) don't count.
        thr = float(self.db.get_config()["entropy_threshold"])
        t0 = self.db.one("SELECT MIN(e.ts) m FROM incident_events ie JOIN fs_events e ON e.id=ie.event_id "
                         "WHERE ie.incident_id=? AND e.entropy>=?", (iid, thr))["m"]
        for f in files:
            if self.db.one("SELECT 1 FROM canaries WHERE path=?", (f["path"],)):
                continue                  # decoys are replaced by fresh ones (re-arm), not "recovered"
            # only versions made BEFORE the first encrypted-looking event are trusted (see t0 above)
            b = self.db.one("SELECT * FROM backups WHERE folder_id=? AND original_path=? AND ts<=? ORDER BY id DESC LIMIT 1",
                            (f["folder_id"], f["path"], t0 if t0 is not None else f["first_event_ts"]))
            if b is None:
                continue
            ok, detail = True, "restored from backup, sha256 verified"
            try:
                if os.path.exists(f["path"]):
                    if sha256_file(f["path"]) == b["sha256"]:
                        continue                      # already intact
                    raise FileExistsError("a different file exists at the original path")
                self.ignore([f["path"]])
                shutil.copyfile(b["backup_path"], f["path"])
                ok = sha256_file(f["path"]) == b["sha256"]
                if not ok:
                    detail = "hash mismatch after restore"
            except OSError as e:
                ok, detail = False, f"{type(e).__name__}: {e}"
            with self.db.transaction() as c:
                c.execute("INSERT INTO recovery_records(incident_id,backup_id,ts,target_path,success,detail) VALUES(?,?,?,?,?,?)",
                          (iid, b["id"], time.time(), f["path"], 1 if ok else 0, detail))
                self._action(c, iid, "recover_file", f["path"], ok, detail)
            good, bad = good + ok, bad + (not ok)
        return good, bad
