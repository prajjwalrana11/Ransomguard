"""HARMLESS ransomware simulator for demos/tests/evaluation.

Safety: refuses to run unless the target directory contains the marker file '.ransomguard_testdir'
(created with --init), never follows symlinks, never leaves the directory. "Encryption" is a reversible XOR
with a key saved in the same directory.

Behaviours (to test detection honestly, not just the easy case):
  --mode inplace      overwrite in place, then rename to .locked, drop a ransom note   (classic)
  --mode copydelete   write an encrypted NEW file (.enc) then delete the original       (no in-place writes)
  --mode stealth      overwrite in place, KEEP names and extensions, no note, no rename (quiet)
  --no-chdir          do not make the target the working directory (cwd-based attribution fails)
  --shuffle           random file order (canaries are not necessarily hit first)
  --delay S           seconds between files (slow attack)
"""
import argparse
import hashlib
import os
import random
import sys
import time

MARKER = ".ransomguard_testdir"
SKIP = {MARKER, ".sim_key", "README_HOW_TO_DECRYPT.txt"}


def keystream(key, n):
    out, ctr = bytearray(), 0
    while len(out) < n:
        out += hashlib.sha256(key + ctr.to_bytes(8, "big")).digest()
        ctr += 1
    return bytes(out[:n])


def init_dir(d, files=40, size=4096, kinds="text"):
    """kinds='text': doc_NNN.txt only. kinds='mixed': text + valid-header JPEG/DOCX-like files (high entropy bodies)."""
    os.makedirs(d, exist_ok=True)
    open(os.path.join(d, MARKER), "w").write("disposable test directory\n")
    for i in range(files):
        if kinds == "mixed" and i % 4 == 1:
            name, data = f"photo_{i:03d}.jpg", b"\xff\xd8\xff\xe0" + os.urandom(size)
        elif kinds == "mixed" and i % 4 == 3:
            name, data = f"report_{i:03d}.docx", b"PK\x03\x04" + os.urandom(size)
        else:
            name = f"doc_{i:03d}.txt"
            data = (f"document {i} " + "lorem ipsum dolor sit amet " * 400)[:size].encode()
        open(os.path.join(d, name), "wb").write(data)


def run(d, delay=0.02, ext=".locked", mode="inplace", chdir=True, shuffle=False, seed=7):
    d = os.path.realpath(d)
    if not os.path.exists(os.path.join(d, MARKER)):
        sys.exit(f"refusing: {d} has no {MARKER} marker (use --init on a disposable directory)")
    if chdir:
        os.chdir(d)
    key = os.urandom(32)
    open(os.path.join(d, ".sim_key"), "wb").write(key)
    targets = sorted(f for f in os.listdir(d) if f not in SKIP and os.path.isfile(os.path.join(d, f))
                     and not os.path.islink(os.path.join(d, f)) and not f.endswith((".locked", ".enc")))
    if shuffle:
        random.Random(seed).shuffle(targets)
    P = lambda f: os.path.join(d, f)
    enc = lambda data: bytes(a ^ b for a, b in zip(data, keystream(key, len(data))))
    for f in targets:
        data = open(P(f), "rb").read()
        if mode == "copydelete":
            open(P(f + ".enc"), "wb").write(enc(data))
            os.remove(P(f))
        else:
            with open(P(f), "wb") as fh:
                fh.write(enc(data))
        time.sleep(delay)
    if mode == "inplace":
        for f in targets:
            os.rename(P(f), P(f) + ext)
            time.sleep(delay)
    if mode != "stealth":
        open(P("README_HOW_TO_DECRYPT.txt"), "w").write("SIMULATION ONLY. Nothing is actually held for ransom.\n")
    print(f"simulated attack ({mode}) finished on {len(targets)} files")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("dir")
    ap.add_argument("--init", action="store_true", help="create disposable test directory with sample files")
    ap.add_argument("--mixed", action="store_true", help="with --init: include JPEG/DOCX-like files")
    ap.add_argument("--files", type=int, default=40)
    ap.add_argument("--delay", type=float, default=0.02)
    ap.add_argument("--mode", choices=("inplace", "copydelete", "stealth"), default="inplace")
    ap.add_argument("--no-chdir", action="store_true")
    ap.add_argument("--shuffle", action="store_true")
    a = ap.parse_args()
    if a.init:
        init_dir(a.dir, a.files, kinds="mixed" if a.mixed else "text")
    else:
        run(a.dir, a.delay, mode=a.mode, chdir=not a.no_chdir, shuffle=a.shuffle)
