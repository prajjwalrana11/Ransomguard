"""Adversarial evaluation harness: runs hostile and benign scenarios against a fresh engine each time and reports
what really happened. Run: python -m ransomguard evaluate [--out FILE] [--only N,N]"""
import gzip
import os
import shutil
import subprocess
import sys
import tempfile
import time

import psutil

from . import pyexec, simulator
from .engine import Engine
from .response import sha256_file

PKG_PARENT = pyexec.base_dir()

ATTACKS = [
    ("A1 classic in-place + .locked, sorted order, cwd=target", dict(mode="inplace", shuffle=False, chdir=True, delay=0.03)),
    ("A2 classic, shuffled order, started elsewhere", dict(mode="inplace", shuffle=True, chdir=False, delay=0.03)),
    ("A3 copy-encrypt-delete (.enc), shuffled, elsewhere", dict(mode="copydelete", shuffle=True, chdir=False, delay=0.03)),
    ("A4 stealth: keeps names/types, shuffled, elsewhere", dict(mode="stealth", shuffle=True, chdir=False, delay=0.03)),
    ("A5 slow stealth (0.5 s/file), shuffled, elsewhere", dict(mode="stealth", shuffle=True, chdir=False, delay=0.5)),
    ("A6 touches ONE decoy only (attack aborted early)", dict(mode="canary_only")),
]
BENIGN = [
    ("B1 copy 200 text files", "import os,shutil\nfor i in range(200):\n    open(os.path.join(T,f'n_{i}.txt'),'w').write('text '*100)"),
    ("B2 copy 60 JPEG/DOCX-like files (valid headers)", "import os\nfor i in range(60):\n    h=b'\\xff\\xd8\\xff\\xe0' if i%2 else b'PK\\x03\\x04'\n    open(os.path.join(T,f'm_{i}.'+('jpg' if i%2 else 'docx')),'wb').write(h+os.urandom(4000))"),
    ("B3 gzip 40 files (valid .gz)", "import os,gzip\nfor i in range(40):\n    with gzip.open(os.path.join(T,f'g_{i}.gz'),'wb') as f: f.write(os.urandom(2000)+b'a'*3000)"),
    ("B4 encrypt 20 files with gpg-style tool (.gpg, random)  [KNOWN false positive]", "import os\nfor i in range(20):\n    open(os.path.join(T,f'e_{i}.gpg'),'wb').write(os.urandom(4000))"),
]


def _wait(cond, timeout):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.1)
    return False


def _setup(canary):
    base = tempfile.mkdtemp(prefix="rg_eval_")
    target = os.path.join(base, "t")
    simulator.init_dir(target, 40, kinds="mixed")
    e = Engine(os.path.join(base, "data"))
    e.db.set_config("canary_enabled", "1" if canary else "0")
    e.reload_config()
    e.add_folder(target)
    _wait(lambda: e.stats["snapshot_done"] >= 1, 15)
    e.start()
    time.sleep(1.0)
    return base, target, e


def _user_files(target, decoys):
    skip = set(decoys) | simulator.SKIP
    return {f: sha256_file(os.path.join(target, f)) for f in os.listdir(target)
            if f not in skip and os.path.isfile(os.path.join(target, f))}


def run_attack(spec, canary):
    base, target, e = _setup(canary)
    try:
        orig = _user_files(target, e.canary_names())
        t0 = time.time()
        if spec["mode"] == "canary_only":
            c = os.path.join(target, e.canary_names()[0])
            proc = subprocess.Popen(pyexec.code_cmd(f"import os;open({c!r},'wb').write(os.urandom(4096))"), cwd=base)
        else:
            cmd = pyexec.module_cmd("ransomguard.simulator", target, "--mode", spec["mode"], "--delay", str(spec["delay"]))
            cmd += (["--shuffle"] if spec["shuffle"] else []) + ([] if spec["chdir"] else ["--no-chdir"])
            proc = subprocess.Popen(cmd, cwd=target if spec["chdir"] else base, env={**os.environ, "PYTHONPATH": PKG_PARENT},
                                    stdout=subprocess.DEVNULL)
        def done():
            try:
                return proc.poll() is not None or psutil.Process(proc.pid).status() == "stopped"
            except psutil.Error:
                return True
        _wait(done, 60)
        time.sleep(2.5)                                    # let the pipeline drain (late events, response)
        alive = proc.poll() is None
        state = "frozen" if alive and psutil.Process(proc.pid).status() == "stopped" else ("running!" if alive else "finished")
        inc = e.db.one("SELECT * FROM incidents ORDER BY id LIMIT 1")
        lost = sum(1 for f, h in orig.items() if not os.path.exists(os.path.join(target, f)) or sha256_file(os.path.join(target, f)) != h)
        res = {"detected": inc is not None, "latency": (inc["created_ts"] - t0) if inc else None, "lost": lost, "total": len(orig),
               "attacker": state, "signals": "", "attributed": False, "suspended": False, "recovered_lost": None}
        if inc:
            res["signals"] = ",".join(r["name"] for r in e.db.query("SELECT name FROM incident_signals WHERE incident_id=? ORDER BY weight DESC", (inc["id"],)))
            res["attributed"] = bool(e.db.one("SELECT 1 FROM incidents i JOIN processes p ON p.id=i.process_id WHERE p.pid=?", (proc.pid,)))
            res["suspended"] = bool(e.db.one("SELECT 1 FROM response_actions WHERE action='suspend_process' AND success=1"))
            if alive:
                proc.kill()
            for r in e.db.query("SELECT id FROM incidents ORDER BY id"):
                e.responder.recover_incident(r["id"])
            res["recovered_lost"] = sum(1 for f, h in orig.items() if not os.path.exists(os.path.join(target, f)) or sha256_file(os.path.join(target, f)) != h)
        return res
    finally:
        try:
            proc.kill()
        except Exception:  # noqa
            pass
        e.close()
        shutil.rmtree(base, ignore_errors=True)


def run_benign(code):
    base, target, e = _setup(True)
    try:
        src = f"T={target!r}\n" + code
        subprocess.run(pyexec.code_cmd(src), cwd=base, timeout=60)
        time.sleep(3.0)
        n = e.db.one("SELECT COUNT(*) n FROM incidents")["n"]
        sig = ",".join(r["name"] for r in e.db.query("SELECT DISTINCT name FROM incident_signals"))
        return {"incidents": n, "signals": sig}
    finally:
        e.close()
        shutil.rmtree(base, ignore_errors=True)


def run(say=print, only=None, out=None):
    rows = ["| Scenario | Canaries | Detected | Latency | Files lost at stop | Lost after recovery | Process found | Suspended | Attacker | Signals |",
            "|---|---|---|---|---|---|---|---|---|---|"]
    n = 0
    for name, spec in ATTACKS:
        for canary in (False, True):
            n += 1
            if only and not any(name.startswith(o) for o in only):
                continue
            say(f"running {name} (canaries {'ON' if canary else 'off'}) ...")
            r = run_attack(spec, canary)
            row = (f"| {name} | {'on' if canary else 'off'} | {'YES' if r['detected'] else '**NO**'} | "
                   f"{'%.2fs' % r['latency'] if r['latency'] is not None else '-'} | {r['lost']}/{r['total']} | "
                   f"{r['recovered_lost'] if r['recovered_lost'] is not None else '-'} | {'yes' if r['attributed'] else 'no'} | "
                   f"{'yes' if r['suspended'] else 'no'} | {r['attacker']} | {r['signals'] or '-'} |")
            rows.append(row)
            say(row)
    rows += ["", "| Benign workload (must NOT alert) | Alerts | Signals |", "|---|---|---|"]
    for name, code in BENIGN:
        if only and not any(name.startswith(o) for o in only):
            continue
        say(f"running {name} ...")
        r = run_benign(code)
        row = f"| {name} | {r['incidents']} | {r['signals'] or '-'} |"
        rows.append(row)
        say(row)
    text = "\n".join(rows)
    if out:
        open(out, "w").write(text + "\n")
    return text


if __name__ == "__main__":
    print(run())
