import os, sqlite3, subprocess, sys, tempfile, time, unittest
from ransomguard import simulator
from ransomguard.db import DEFAULT_CONFIG, Database
from ransomguard.detector import Detector, file_entropy
from ransomguard.engine import Engine
from ransomguard.response import sha256_file

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def wait(cond, timeout=10):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.1)
    return False


class Env(unittest.TestCase):
    def setUp(self, canary=True, kinds="mixed", files=40):
        self.base = tempfile.mkdtemp()
        self.t = os.path.join(self.base, "t")
        simulator.init_dir(self.t, files, kinds=kinds)
        self.e = Engine(os.path.join(self.base, "data"))
        self.e.db.set_config("canary_enabled", "1" if canary else "0")
        self.e.reload_config()
        self.fid = self.e.add_folder(self.t)
        wait(lambda: self.e.stats["snapshot_done"] >= 1)
        self.e.start()
        time.sleep(0.8)

    def tearDown(self):
        self.e.close()

    def n_inc(self):
        return self.e.db.one("SELECT COUNT(*) n FROM incidents")["n"]


class CanaryTests(Env):
    def test_decoys_planted_and_registered(self):
        n = int(DEFAULT_CONFIG["canary_count"])
        self.assertEqual(self.e.db.one("SELECT COUNT(*) n FROM canaries")["n"], n)
        for name in self.e.canary_names()[:n]:
            self.assertTrue(os.path.exists(os.path.join(self.t, name)))
        self.assertEqual(self.n_inc(), 0)                         # planting them did not raise an alert

    def test_single_modified_decoy_raises_incident(self):
        open(os.path.join(self.t, self.e.canary_names()[0]), "wb").write(os.urandom(3000))
        self.assertTrue(wait(lambda: self.n_inc() == 1, 8))
        self.assertTrue(self.e.db.one("SELECT 1 FROM incident_signals WHERE name='canary_tripped'"))
        self.assertIsNotNone(self.e.db.one("SELECT tripped_ts FROM canaries WHERE path LIKE ?", ("%" + self.e.canary_names()[0],))["tripped_ts"])

    def test_deleted_decoy_raises_incident(self):
        os.remove(os.path.join(self.t, self.e.canary_names()[1]))
        self.assertTrue(wait(lambda: self.n_inc() == 1, 8))

    def test_metadata_only_touch_is_not_an_alert(self):
        p = os.path.join(self.t, self.e.canary_names()[0])
        os.utime(p, (1, 1))
        time.sleep(2.0)
        self.assertEqual(self.n_inc(), 0)                         # content hash unchanged

    def test_rearm_after_trip(self):
        p = os.path.join(self.t, self.e.canary_names()[0])
        open(p, "wb").write(os.urandom(3000))
        self.assertTrue(wait(lambda: self.e.db.one("SELECT COUNT(*) n FROM quarantine")["n"] >= 1, 8))   # encrypted decoy quarantined
        self.assertGreaterEqual(self.e.rearm_canaries(), 1)
        self.assertTrue(os.path.exists(p))
        self.assertIsNone(self.e.db.one("SELECT tripped_ts FROM canaries WHERE path=?", (p,))["tripped_ts"])


class StealthPipelineTests(Env):
    def setUp(self):
        super().setUp(canary=False)                               # prove the OTHER defences work alone

    def test_stealth_attack_from_elsewhere_detected_attributed_and_recovered(self):
        orig = {f: sha256_file(os.path.join(self.t, f)) for f in os.listdir(self.t) if f not in simulator.SKIP and os.path.isfile(os.path.join(self.t, f))}
        p = subprocess.Popen([sys.executable, "-m", "ransomguard.simulator", self.t, "--mode", "stealth", "--shuffle", "--no-chdir", "--delay", "0.03"],
                             cwd=self.base, env={**os.environ, "PYTHONPATH": ROOT}, stdout=subprocess.DEVNULL)
        try:
            self.assertTrue(wait(lambda: self.n_inc() >= 1, 15), "stealth attack (names/extensions kept) was not detected")
            self.assertTrue(wait(lambda: self.e.db.one("SELECT COUNT(*) n FROM response_actions WHERE action='suspend_process' AND success=1")["n"] >= 1, 8),
                            "attacker started from another directory was not found by write-volume attribution")
            row = self.e.db.one("SELECT pr.pid, o.method FROM incidents i JOIN processes pr ON pr.id=i.process_id "
                                "JOIN process_observations o ON o.process_id=pr.id ORDER BY o.id DESC LIMIT 1")
            self.assertEqual(row["pid"], p.pid)
            self.assertIn(row["method"], ("io_delta", "open_file", "cwd"))   # which route found it is timing-dependent
        finally:
            p.kill(); p.wait()
        time.sleep(2.5)
        for r in self.e.db.query("SELECT id FROM incidents"):
            self.e.responder.recover_incident(r["id"])
        bad = [f for f, h in orig.items() if not os.path.exists(os.path.join(self.t, f)) or sha256_file(os.path.join(self.t, f)) != h]
        self.assertEqual(bad, [])                                 # late (post-detection) damage was captured and recovered

    def test_versioned_backup_of_new_benign_file_but_not_encrypted_one(self):
        good, bad = os.path.join(self.t, "new_notes.txt"), os.path.join(self.t, "blob.dat")
        open(good, "w").write("hello world " * 200)
        open(bad, "wb").write(os.urandom(4000))
        self.assertTrue(wait(lambda: self.e.db.one("SELECT COUNT(*) n FROM backups WHERE original_path=?", (good,))["n"] == 1, 8))
        self.assertEqual(self.e.db.one("SELECT COUNT(*) n FROM backups WHERE original_path=?", (bad,))["n"], 0)
        for i in range(8):                                        # versions are capped
            time.sleep(3.2)
            open(good, "w").write(f"version {i} " * 200)
            if i >= 6:
                break
        self.assertTrue(wait(lambda: self.e.db.one("SELECT COUNT(*) n FROM backups WHERE original_path=?", (good,))["n"] >= 3, 8))
        self.assertLessEqual(self.e.db.one("SELECT COUNT(*) n FROM backups WHERE original_path=?", (good,))["n"], int(DEFAULT_CONFIG["backup_versions"]))


class IoAttributionTests(unittest.TestCase):
    """Deterministic test of the write-volume fallback (independent of cwd / open handles)."""
    CODE = ("import time,os,tempfile\nf=open(os.path.join(tempfile.mkdtemp(),'w'),'wb')\n"
            "for i in range(300):\n    f.write(b'x'*1024); f.flush(); time.sleep(0.01)\ntime.sleep(5)\n")

    def test_dominant_writer_found_and_stopped_process_never_blamed(self):
        import psutil
        from ransomguard import procinfo
        procinfo.sample_io()
        t0 = time.time()
        p = subprocess.Popen([sys.executable, "-c", self.CODE], cwd=tempfile.gettempdir())
        try:
            time.sleep(1.5)
            conf, cands = procinfo.attribute_io(t0 - 0.1, min_bytes=16384, dominance=3.0)
            self.assertEqual(conf, "reliable")
            self.assertEqual((cands[0]["pid"], cands[0]["method"]), (p.pid, "io_delta"))
            self.assertEqual(procinfo.attribute_io(time.time() + 5, 16384, 3.0)[0], "none")    # nothing written after 'since'
            psutil.Process(p.pid).suspend()
            time.sleep(0.3)
            self.assertEqual(procinfo.attribute_io(t0 - 0.1, 16384, 3.0)[0], "none")             # frozen => cannot be the writer now
        finally:
            p.kill(); p.wait()


class DetectorHardening(unittest.TestCase):
    def test_header_check_closes_extension_evasion(self):
        d = tempfile.mkdtemp()
        ok, bad = os.path.join(d, "a.jpg"), os.path.join(d, "b.docx")
        open(ok, "wb").write(b"\xff\xd8\xff\xe0" + os.urandom(4000))
        open(bad, "wb").write(os.urandom(4000))                   # same extension, header destroyed
        self.assertIsNone(file_entropy(ok))
        self.assertGreater(file_entropy(bad), 7.5)

    def test_sustained_rule_catches_slow_attack_below_burst_rate(self):
        det = Detector(DEFAULT_CONFIG)
        ev = lambda i: {"ts": i * 8.0, "type": "modified", "path": f"/p/f{i}", "dest": None, "entropy": 7.9}
        for i in range(9):
            det.add(1, [ev(i)])
            score, sigs, _ = det.evaluate(1, None)
        self.assertLess(score, 60)                                # 9 files over 72 s: not yet
        det.add(1, [ev(9)]); det.add(1, [ev(10)])
        score, sigs, _ = det.evaluate(1, None)
        self.assertIn("sustained_encryption", {s["name"] for s in sigs})
        self.assertGreaterEqual(score, 60)
        self.assertNotIn("write_burst", {s["name"] for s in sigs})  # never exceeded the 10-second burst rate


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.db = Database(os.path.join(tempfile.mkdtemp(), "a.db"))
        with self.db.transaction() as c:
            c.execute("INSERT INTO protected_folders(path,added_ts) VALUES('/x',0)")
            self.db.audit(c, "one", {"a": 1}); self.db.audit(c, "two", {"b": 2})

    def test_chain_ok_and_append_only_triggers(self):
        self.assertTrue(self.db.verify_audit()[0])
        for sql in ("UPDATE audit_log SET kind='x'", "DELETE FROM audit_log"):
            with self.assertRaises(sqlite3.Error):
                with self.db.transaction() as c:
                    c.execute(sql)

    def test_tampering_with_triggers_dropped_is_still_detected(self):
        with self.db.transaction() as c:
            c.execute("DROP TRIGGER trg_audit_no_update")
            c.execute("UPDATE audit_log SET payload='{\"a\": 999}' WHERE id=1")
        ok, n, bad, _ = self.db.verify_audit()
        self.assertFalse(ok)
        self.assertEqual(bad, 1)

    def test_events_and_actions_are_append_only_but_prunable(self):
        with self.db.transaction() as c:
            c.execute("INSERT INTO fs_events(folder_id,ts,event_type,path) VALUES(1,1,'created','/x/a')")
            c.execute("INSERT INTO fs_events(folder_id,ts,event_type,path) VALUES(1,?,'created','/x/b')", (time.time(),))
        for sql in ("DELETE FROM fs_events", "UPDATE fs_events SET path='/y'"):
            with self.assertRaises(sqlite3.Error):
                with self.db.transaction() as c:
                    c.execute(sql)
        self.assertEqual(self.db.prune(30, vacuum=False), 1)       # only the old, unreferenced event
        self.assertEqual(self.db.one("SELECT COUNT(*) n FROM fs_events")["n"], 1)
        self.assertEqual(self.db.one("SELECT value FROM config WHERE key='allow_prune'")["value"], "0")
        self.assertTrue(self.db.verify_audit()[0])
        self.assertEqual(self.db.one("SELECT COUNT(*) n FROM audit_log WHERE kind='prune_events'")["n"], 1)


if __name__ == "__main__":
    unittest.main()
