"""Tests for the 'professional polish' features: random decoy names, trusted apps, PDF report, exe-safe child processes."""
import os, subprocess, sys, tempfile, time, unittest

from ransomguard import canary, pyexec, simulator
from ransomguard.db import format_report
from ransomguard.engine import Engine
from ransomguard.report_pdf import build_pdf, write_pdf
from tests.test_hardening import Env, ROOT, wait


class RandomDecoys(unittest.TestCase):
    def test_names_deterministic_unique_and_spread(self):
        a = canary.names_for("abc123")
        self.assertEqual(a, canary.names_for("abc123"))
        self.assertEqual(len(set(a)), 8)
        self.assertNotEqual(a, canary.names_for("zzz999"))
        self.assertEqual(canary.names_for(""), canary.CANARY_NAMES)
        self.assertGreaterEqual(len({n[:2] for n in a}), 6)       # still spread across the alphabet

    def test_engine_uses_random_names_and_keeps_them_after_restart(self):
        base = tempfile.mkdtemp()
        e = Engine(os.path.join(base, "d"))
        names = e.canary_names()
        self.assertNotEqual(names, canary.CANARY_NAMES)
        e.close()
        e2 = Engine(os.path.join(base, "d"))
        self.assertEqual(e2.canary_names(), names)
        e2.close()

    def test_two_installs_get_different_names(self):
        a, b = Engine(os.path.join(tempfile.mkdtemp(), "d")), Engine(os.path.join(tempfile.mkdtemp(), "d"))
        self.assertNotEqual(a.canary_names(), b.canary_names())
        a.close(); b.close()

    def test_randomize_off_gives_legacy_names(self):
        e = Engine(os.path.join(tempfile.mkdtemp(), "d"))
        e.db.set_config("canary_randomize", "0"); e.reload_config()
        self.assertEqual(e.canary_names(), canary.CANARY_NAMES)
        e.close()


class TrustedApps(Env):
    # 'encrypts' user files (never decoys). Slow enough, and alive long enough, that the engine can identify the process:
    # a writer that exits before attribution cannot be matched to the trusted list (documented limit).
    CODE = ("import os,time\nfor f in sorted(os.listdir('.')):\n"
            "    if f.startswith(('doc_', 'photo_', 'report_')):\n        open(f, 'wb').write(os.urandom(4096)); time.sleep(0.04)\ntime.sleep(2.5)\n")

    def _attack(self):
        return subprocess.Popen(pyexec.code_cmd(self.CODE), cwd=self.t)

    def test_is_trusted_rules(self):
        e = self.e
        cand = [{"name": "7zFM.exe", "exe": "/opt/7z/7zFM.exe", "pid": 1}]
        self.assertFalse(e._is_trusted("reliable", cand))                       # empty allowlist
        e.cfg["trusted_apps"] = "7zfm.exe"
        self.assertTrue(e._is_trusted("reliable", cand))                        # name match, case-insensitive
        self.assertFalse(e._is_trusted("ambiguous", cand))                      # never on uncertain attribution
        self.assertFalse(e._is_trusted("reliable", cand + cand))                # never when several candidates
        e.cfg["trusted_apps"] = "/opt/7z/7zFM.exe"
        self.assertTrue(e._is_trusted("reliable", cand))                        # full-path match
        self.assertFalse(e._is_trusted("reliable", [{"name": "7zFM.exe", "exe": "/tmp/evil/7zFM.exe", "pid": 2}]))   # spoofed name, wrong path

    def test_untrusted_writer_is_detected(self):                                # control for the test below
        p = self._attack()
        self.assertTrue(wait(lambda: self.n_inc() >= 1, 15))
        p.kill()

    def test_trusted_app_still_trips_a_decoy(self):
        self.e.db.set_config("trusted_apps", sys.executable); self.e.reload_config()
        d = self.e.canary_names()[0]
        p = subprocess.Popen(pyexec.code_cmd(f"import os,time;open({d!r},'wb').write(os.urandom(3000));time.sleep(30)"), cwd=self.t)   # trusted child, cwd inside the folder
        try:
            self.assertTrue(wait(lambda: self.n_inc() == 1, 10))                # decoys are never excused (the child gets frozen, so it never exits by itself)
        finally:
            p.kill()

    def test_trusted_writer_raises_no_incident_but_events_are_logged(self):
        self.e.db.set_config("trusted_apps", sys.executable); self.e.reload_config()
        p = self._attack()
        p.wait(timeout=60)
        time.sleep(3.0)
        self.assertEqual(self.n_inc(), 0)
        self.assertGreater(self.e.stats["trusted_skipped"], 20)                 # skipped for scoring ...
        self.assertGreater(self.e.db.one("SELECT COUNT(*) n FROM fs_events")["n"], 20)   # ... but still in the forensic log


class PdfReport(unittest.TestCase):
    def test_valid_pdf_structure_and_pagination(self):
        body = "\n".join(f"  line {i} " + "x" * 130 for i in range(150))
        d = build_pdf("RansomGuard - Incident Report #1", body)
        self.assertTrue(d.startswith(b"%PDF-1.4") and d.rstrip().endswith(b"%%EOF"))
        self.assertGreater(d.count(b"/Type /Page "), 3)
        self.assertIn(b"page 1 of", d)
        start = int(d.split(b"startxref\n")[1].split()[0])
        self.assertTrue(d[start:].startswith(b"xref"))                          # xref offset is correct

    def test_special_characters_are_escaped(self):
        d = build_pdf("t", "path C:\\dir\\(file).txt  unicode \u2192 \u20ac")
        self.assertIn(b"C:\\\\dir\\\\\\(file\\).txt", d)

    def test_real_incident_report_exports(self):
        class E(Env):
            def runTest(s): pass
        env = E(); env.setUp()
        try:
            open(os.path.join(env.t, env.e.canary_names()[0]), "wb").write(os.urandom(3000))
            self.assertTrue(wait(lambda: env.n_inc() == 1, 10))
            iid = env.e.db.one("SELECT id FROM incidents")["id"]
            out = os.path.join(env.base, "r.pdf")
            n = write_pdf(out, f"Report {iid}", format_report(env.e.db.incident_report(iid), full=True))
            self.assertGreater(n, 800)
            self.assertIn(b"canary_tripped", open(out, "rb").read())
        finally:
            env.tearDown()


class ExeSafeChildren(unittest.TestCase):
    def test_commands_from_source_and_frozen(self):
        self.assertEqual(pyexec.module_cmd("m", 1)[1:], ["-m", "m", "1"] if not pyexec.FROZEN else ["--rg-module", "m", "1"])
        old = pyexec.FROZEN
        try:
            pyexec.FROZEN = True
            self.assertEqual(pyexec.module_cmd("ransomguard.simulator", "x")[1:], ["--rg-module", "ransomguard.simulator", "x"])
            self.assertEqual(pyexec.code_cmd("print(1)")[1:], ["--rg-code", "print(1)"])
        finally:
            pyexec.FROZEN = old

    def test_launcher_dispatches_child_requests(self):
        launcher = os.path.join(ROOT, "RansomGuard.pyw")
        r = subprocess.run([sys.executable, launcher, "--rg-code", "print('child-ok', __name__)"], capture_output=True, text=True, timeout=30)
        self.assertEqual(r.stdout.strip(), "child-ok __main__")
        d = tempfile.mkdtemp()
        r = subprocess.run([sys.executable, launcher, "--rg-module", "ransomguard.simulator", d, "--help"], capture_output=True, text=True, timeout=30, cwd=ROOT)
        self.assertEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main()
