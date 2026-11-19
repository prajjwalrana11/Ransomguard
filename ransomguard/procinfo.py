"""Best-effort process attribution using psutil (user-space, permission-limited).

Filesystem notification APIs (inotify / ReadDirectoryChangesW / FSEvents) do NOT say which
process caused an event. We therefore *infer*: a process is a candidate if its current working
directory or an open file handle lies inside a protected folder. Exactly one candidate =>
'reliable'; several => 'ambiguous' (evidence stored, but never acted on); none => 'none'.
Limits: short-lived writers that open+write+close between scans are missed; processes we lack
permission to inspect (other users, protected system processes) are invisible without admin/root.
"""
import os
import threading
import time
from collections import deque

import psutil

_lock = threading.Lock()
_cache = {"ts": 0.0, "key": None, "val": {}}


def _under(path, roots):
    """Return the matching protected root (or None)."""
    p = os.path.normcase(os.path.realpath(path))
    for r in roots:
        if p == r or p.startswith(r + os.sep):
            return r
    return None


def scan(roots, ttl=0.4):
    """Return {(pid, create_time): info} for processes touching any root."""
    roots = tuple(sorted(os.path.normcase(os.path.realpath(r)) for r in roots))
    with _lock:
        if _cache["key"] == roots and time.time() - _cache["ts"] < ttl:
            return _cache["val"]
        me = os.getpid()
        found = {}
        for p in psutil.process_iter():
            if p.pid == me:
                continue
            method = root = None
            try:
                cwd = p.cwd()
                root = _under(cwd, roots) if cwd else None
                if root:
                    method = "cwd"
                else:
                    for f in p.open_files():
                        root = _under(f.path, roots)
                        if root:
                            method = "open_file"
                            break
                if not method:
                    continue
                with p.oneshot():
                    parent = p.parent()
                    found[(p.pid, round(p.create_time(), 3))] = {
                        "pid": p.pid, "create_time": round(p.create_time(), 3), "name": p.name(),
                        "exe": _safe(p.exe), "cmdline": " ".join(_safe(p.cmdline, []) or [])[:500],
                        "ppid": p.ppid(), "parent_name": parent.name() if parent else None,
                        "username": _safe(p.username), "method": method, "root": root}
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
                continue
        _cache.update(ts=time.time(), key=roots, val=found)
        return found


def _safe(fn, default=None):
    try:
        return fn()
    except (psutil.Error, OSError):
        return default


# ---- write-volume ("io_delta") attribution ---------------------------------------------------
# Used when cwd/open-file inspection finds nothing (attacker started elsewhere, writes via absolute paths,
# keeps no handle open). We sample every process's cumulative bytes-written counter and attribute to the
# process that wrote by far the most recently. HEURISTIC: a legitimate heavy writer (backup tool, installer)
# running at the same moment can be mistaken for the attacker, so it needs a dominance margin and is only
# used once an incident has already fired; suspension is reversible (Resume button).
_io_lock = threading.Lock()
_io_prev, _io_hist = {}, {}


def sample_io():
    now, me, seen = time.time(), os.getpid(), set()
    with _io_lock:
        for p in psutil.process_iter():
            if p.pid == me:
                continue
            try:
                io, ct = p.io_counters(), round(p.create_time(), 3)
            except (psutil.Error, OSError, AttributeError):
                continue
            w = getattr(io, "write_chars", None)          # bytes passed to write() (Linux); includes page cache
            w = io.write_bytes if w is None else w
            key = (p.pid, ct)
            seen.add(key)
            prev = _io_prev.get(key)
            if prev is None and now - ct < 15:            # brand-new process: everything it wrote counts
                prev = 0
            if prev is not None and w > prev:
                _io_hist.setdefault(key, deque()).append((now, w - prev))
            _io_prev[key] = w
        for k in [k for k in _io_prev if k not in seen]:
            del _io_prev[k]
            _io_hist.pop(k, None)
        for dq in _io_hist.values():
            while dq and dq[0][0] < now - 15:
                dq.popleft()


def io_ranked(since, exclude=()):
    """Processes ranked by bytes written since `since` (an INCIDENT's first suspicious event, not 'the last N seconds':
    a process that wrote earlier - e.g. one already frozen - must not be blamed). Stopped processes are skipped."""
    with _io_lock:
        ranked = [(k, sum(b for t, b in dq if t > since)) for k, dq in _io_hist.items() if k[0] not in exclude]
    out = []
    for k, b in sorted([r for r in ranked if r[1] > 0], key=lambda r: -r[1]):
        try:
            if psutil.Process(k[0]).status() == psutil.STATUS_STOPPED:
                continue
        except psutil.Error:
            continue
        out.append((k, b))
    return out


def _describe(pid, create_time, method, root=None):
    try:
        p = psutil.Process(pid)
        if abs(round(p.create_time(), 3) - create_time) > 0.01:
            return None
        with p.oneshot():
            parent = p.parent()
            return {"pid": pid, "create_time": create_time, "name": p.name(), "exe": _safe(p.exe),
                    "cmdline": " ".join(_safe(p.cmdline, []) or [])[:500], "ppid": p.ppid(),
                    "parent_name": parent.name() if parent else None, "username": _safe(p.username),
                    "method": method, "root": root}
    except (psutil.Error, OSError):
        return None


def attribute(roots):
    """Per-batch attribution from cwd / open file handles. 1 candidate = reliable, several = ambiguous."""
    c = list(scan(roots, ttl=0).values())     # always a fresh scan: a stale cache would mis-attribute
    return ("reliable" if len(c) == 1 else "ambiguous" if len(c) > 1 else "none"), c


def attribute_io(since, min_bytes=16384, dominance=3.0):
    """Incident-time fallback: the process that wrote by far the most since the incident began."""
    sample_io()
    family = {os.getpid()} | {p.pid for p in psutil.Process().parents()}
    ranked = io_ranked(since, exclude=family)
    if ranked and ranked[0][1] >= min_bytes and (len(ranked) == 1 or ranked[0][1] >= dominance * ranked[1][1]):
        info = _describe(ranked[0][0][0], ranked[0][0][1], "io_delta")
        if info:
            return "reliable", [info]
    return "none", []
