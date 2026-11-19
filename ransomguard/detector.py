"""Behavioural detection: sliding-window rules + persisted-history baseline.

Pure logic (no I/O except reading file bytes for entropy) so it is unit-testable.
Every signal records *why* it fired (measured value, threshold, baseline stats) so
an evaluator can inspect how history influenced the alert.
"""
import math
import os
import re
from collections import defaultdict, deque

COMPRESSED_EXT = {".zip", ".gz", ".7z", ".rar", ".jpg", ".jpeg", ".png", ".gif", ".mp3", ".mp4",
                  ".mkv", ".pdf", ".docx", ".xlsx", ".pptx", ".bz2", ".xz", ".webp", ".iso"}
SUSPICIOUS_EXT = {".locked", ".encrypted", ".crypt", ".crypted", ".enc", ".ransom", ".rnsmwr",
                  ".wncry", ".cerber", ".locky", ".zepto", ".lockbit", ".rg_locked"}
NOTE_RE = re.compile(r"(decrypt|ransom|restore[_ -]?files|recover[_ -]?files|how[_ -]?to[_ -]?(recover|restore))", re.I)
WRITE_TYPES = ("created", "modified", "moved")


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts if c)


_ZIP = (b"PK\x03\x04", b"PK\x05\x06")
# extension -> (offset, accepted magic prefixes). Real media/containers are high-entropy BY NATURE, so their
# entropy is meaningless; but their HEADER must still be valid. Encrypted-in-place files lose it.
MAGIC = {".jpg": (0, (b"\xff\xd8\xff",)), ".jpeg": (0, (b"\xff\xd8\xff",)), ".png": (0, (b"\x89PNG",)),
         ".gif": (0, (b"GIF8",)), ".pdf": (0, (b"%PDF",)), ".zip": (0, _ZIP), ".docx": (0, _ZIP), ".xlsx": (0, _ZIP),
         ".pptx": (0, _ZIP), ".gz": (0, (b"\x1f\x8b",)), ".7z": (0, (b"7z\xbc\xaf",)), ".rar": (0, (b"Rar!",)),
         ".bz2": (0, (b"BZh",)), ".xz": (0, (b"\xfd7zXZ",)), ".webp": (0, (b"RIFF",)),
         ".mp3": (0, (b"ID3", b"\xff\xfb", b"\xff\xf3", b"\xff\xf2")), ".mp4": (4, (b"ftyp",)), ".mkv": (0, (b"\x1a\x45\xdf\xa3",))}


def magic_ok(ext, data):
    off, prefixes = MAGIC[ext]
    return any(data[off:off + len(p)] == p for p in prefixes)


def file_entropy(path, nbytes=8192, min_bytes=1024):
    """Entropy (bits/byte) of the first 8 KiB, or None when it carries no evidence.
    Known compressed/media types are only evaluated when their header is INVALID (content was overwritten)."""
    ext = os.path.splitext(path)[1].lower()
    try:
        with open(path, "rb") as f:
            data = f.read(nbytes)
    except OSError:
        return None
    if ext in COMPRESSED_EXT:
        if ext not in MAGIC or len(data) < 16 or magic_ok(ext, data):
            return None
        return shannon_entropy(data) if len(data) >= 256 else None   # header destroyed -> evidence
    return shannon_entropy(data) if len(data) >= min_bytes else None


class Detector:
    def __init__(self, cfg):
        self.configure(cfg)
        self.win = defaultdict(deque)   # folder_id -> deque of event dicts (sliding window)
        self.long = defaultdict(deque)  # folder_id -> deque of (ts, path) for SUSPICIOUS events only (slow attacks)
        self.buckets = {}               # folder_id -> open baseline bucket

    def configure(self, cfg):
        self.window = float(cfg["window_sec"])
        self.threshold = int(cfg["risk_threshold"])
        self.min_burst = int(cfg["min_write_burst"])
        self.ent_thr = float(cfg["entropy_threshold"])
        self.sigma = float(cfg["baseline_sigma"])
        self.base_min = int(cfg["baseline_min_windows"])
        self.long_window = float(cfg.get("long_window_sec", 300))
        self.sustained = int(cfg.get("sustained_files", 10))

    # -- window -------------------------------------------------------------
    def _suspicious(self, e):
        if e.get("canary"):
            return True
        ext = lambda p: os.path.splitext(p or "")[1].lower()
        if e["type"] in WRITE_TYPES and e.get("entropy") is not None and e["entropy"] >= self.ent_thr:
            return True
        return (e["type"] == "moved" and ext(e.get("dest")) in SUSPICIOUS_EXT) or \
               (e["type"] == "created" and ext(e["path"]) in SUSPICIOUS_EXT)

    def add(self, folder_id, events):
        dq = self.win[folder_id]
        dq.extend(events)
        if dq:
            horizon = max(e["ts"] for e in dq) - self.window
            while dq and dq[0]["ts"] < horizon:
                dq.popleft()
        lg = self.long[folder_id]
        lg.extend((e["ts"], e["path"]) for e in events if self._suspicious(e))
        if lg:
            horizon = max(t for t, _ in lg) - self.long_window
            while lg and lg[0][0] < horizon:
                lg.popleft()

    def reset(self, folder_id):
        self.win[folder_id].clear()
        self.long[folder_id].clear()

    # -- scoring ------------------------------------------------------------
    def evaluate(self, folder_id, baseline):
        w = list(self.win[folder_id])
        sig = []
        writes = [e for e in w if e["type"] in WRITE_TYPES]
        n = len(writes)
        distinct = len({e["path"] for e in w})
        if n >= self.min_burst:
            sig.append(("write_burst", 30, {"writes": n, "window_sec": self.window, "threshold": self.min_burst}))
        if baseline and baseline["n"] >= self.base_min:
            limit = baseline["mean"] + self.sigma * max(baseline["std"], 1.0)
            if n > limit and n >= 5:
                sig.append(("baseline_deviation", 15, {
                    "writes": n, "baseline_mean": round(baseline["mean"], 2), "baseline_std": round(baseline["std"], 2),
                    "limit": round(limit, 2), "baseline_windows": baseline["n"]}))
        elif n >= self.min_burst:
            sig[-1][2]["baseline"] = f"cold-start (only {baseline['n'] if baseline else 0} trusted windows)"
        ents = [e["entropy"] for e in writes if e.get("entropy") is not None]
        high = [x for x in ents if x >= self.ent_thr]
        if len(high) >= 3 and len(high) >= 0.6 * len(ents):
            sig.append(("high_entropy_writes", 35, {"high_entropy_files": len(high), "sampled": len(ents),
                                                    "threshold_bits": self.ent_thr, "max": round(max(high), 2)}))
        ren = [e for e in w if e["type"] == "moved" and e.get("dest")
               and os.path.splitext(e["dest"])[1].lower() != os.path.splitext(e["path"])[1].lower()]
        if len(ren) >= 5:
            sig.append(("mass_rename", 20, {"renames": len(ren)}))
        bad = [e for e in ren if os.path.splitext(e["dest"])[1].lower() in SUSPICIOUS_EXT] + \
              [e for e in w if e["type"] == "created" and os.path.splitext(e["path"])[1].lower() in SUSPICIOUS_EXT]
        if bad:
            sig.append(("suspicious_extension", 15, {"files": len(bad), "ext": os.path.splitext(bad[0].get("dest") or bad[0]["path"])[1]}))
        dels = sum(1 for e in w if e["type"] == "deleted")
        if dels >= 10:
            sig.append(("mass_delete", 10, {"deletes": dels}))
        notes = [e for e in w if e["type"] == "created" and NOTE_RE.search(os.path.basename(e["path"]))]
        if notes:
            sig.append(("ransom_note", 15, {"file": os.path.basename(notes[0]["path"])}))
        if distinct >= 20:
            sig.append(("many_distinct_files", 10, {"distinct": distinct}))
        can = [e for e in w if e.get("canary")]
        if can:   # a decoy no legitimate program touches was modified/renamed/deleted
            sig.append(("canary_tripped", 80, {"decoys": sorted({os.path.basename(e["path"]) for e in can}),
                                               "events": [e["type"] for e in can][:5]}))
        distinct_susp = len({p for _, p in self.long[folder_id]})
        if distinct_susp >= self.sustained:   # slow attack: below burst thresholds but steadily encrypting
            sig.append(("sustained_encryption", 60, {"distinct_files": distinct_susp, "window_sec": self.long_window,
                                                     "threshold": self.sustained}))
        score = min(100, sum(s[1] for s in sig))
        return score, [{"name": a, "weight": b, "detail": c} for a, b, c in sig], w

    # -- baseline accounting (poisoning safeguard lives in _close) -----------
    def account(self, folder_id, ts, is_write, score):
        b = int(ts // self.window)
        cur = self.buckets.get(folder_id)
        done = []
        if cur and cur["b"] != b:
            done.append(self._close(folder_id, cur))
            cur = None
        if cur is None:
            cur = self.buckets[folder_id] = {"b": b, "count": 0, "max": 0}
        cur["count"] += 1 if is_write else 0
        cur["max"] = max(cur["max"], score)
        return [d for d in done if d]

    def flush_idle(self, now):
        done = []
        for fid, cur in list(self.buckets.items()):
            if cur["b"] < int(now // self.window):
                d = self._close(fid, cur)
                del self.buckets[fid]
                if d:
                    done.append(d)
        return done

    def _close(self, folder_id, cur):
        if cur["count"] == 0:
            return None
        # SAFEGUARD: a window is "trusted" (eligible for the baseline) only if its peak risk
        # stayed below half the alert threshold. Suspicious bursts are stored but never learned.
        trusted = 1 if cur["max"] < self.threshold / 2 else 0
        return (folder_id, cur["b"] * self.window, cur["count"], cur["max"], trusted)
