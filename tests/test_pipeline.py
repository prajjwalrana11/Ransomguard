import hashlib, os, subprocess, sys, tempfile, time, unittest
import psutil
from ransomguard import simulator
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


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.base = tempfile.mkdtemp()
        self.test = os.path.join(self.base, "t")
        os.makedirs(self.test)
        self.e = Engine(os.path.join(self.base, "data"))
        self.fid = self.e.add_folder(self.test)
        time.sleep(0.3)
        self.e.start()
        time.sleep(0.3)

    def tearDown(self):
        self.e.close()

    def types(self):
        return {r[0] for r in self.e.db.query("SELECT DISTINCT event_type FROM fs_events")}

    def test_basic_events(self):
        p = os.path.join(self.test, "a.txt")
        open(p, "w").write("hello")
        time.sleep(0.2)
        open(p, "a").write(" world")
        time.sleep(0.2)
        os.rename(p, p + ".bak")
        time.sleep(0.2)
        os.remove(p + ".bak")
        self.assertTrue(wait(lambda: self.types() >= {"created", "modified", "moved", "deleted"}), self.types())

    def test_burst_is_not_lost_and_benign_no_incident(self):
        for i in range(300):
            open(os.path.join(self.test, f"b{i}.txt"), "w").write("text " * 50)
        self.assertTrue(wait(lambda: self.e.db.one("SELECT COUNT(DISTINCT path) n FROM fs_events WHERE event_type='created'")["n"] >= 300, 15))
        self.assertEqual(self.e.db.one("SELECT COUNT(*) n FROM incidents")["n"], 0)   # plain text copy != ransomware

    def test_ransomware_incident_suspend_and_recover(self):
        simulator.init_dir(self.test, files=40)
        orig = {f: hashlib.sha256(open(os.path.join(self.test, f), "rb").read()).hexdigest()
                for f in os.listdir(self.test) if f.startswith("doc_")}
        self.e.cfg["canary_enabled"] = "0"        # this test exercises the behavioural rules + recovery; decoys have their own tests
        self.e.responder.snapshot(self.fid, self.test, self.e.cfg)
        time.sleep(0.5)
        p = subprocess.Popen([sys.executable, "-m", "ransomguard.simulator", self.test, "--delay", "0.03"],
                             cwd=self.test, env={**os.environ, "PYTHONPATH": ROOT})
        try:
            self.assertTrue(wait(lambda: self.e.db.one("SELECT COUNT(*) n FROM response_actions WHERE action='suspend_process' AND success=1")["n"] >= 1, 15))
            inc = self.e.db.one("SELECT i.*, pr.pid FROM incidents i JOIN processes pr ON pr.id=i.process_id ORDER BY i.id LIMIT 1")
            self.assertEqual(inc["pid"], p.pid)
            self.assertGreaterEqual(inc["risk_score"], 60)
            self.assertEqual(psutil.Process(p.pid).status(), "stopped")
        finally:
            p.kill(); p.wait()
        time.sleep(0.5)
        iid = inc["id"]
        for r in self.e.db.query("SELECT id FROM quarantine WHERE incident_id=?", (iid,)):
            pass
        good, bad = self.e.responder.recover_incident(iid)
        self.assertGreater(good, 0)
        self.assertEqual(bad, 0)
        for r in self.e.db.query("SELECT path FROM incident_files WHERE incident_id=?", (iid,)):
            name = os.path.basename(r["path"])
            if name in orig and os.path.exists(r["path"]):
                self.assertEqual(sha256_file(r["path"]), orig[name])

    def test_quarantine_restore_verifies_hash(self):
        f = os.path.join(self.test, "q.bin")
        open(f, "wb").write(os.urandom(5000))
        sha = hashlib.sha256(open(f, "rb").read()).hexdigest()
        with self.e.db.transaction() as c:
            iid = c.execute("INSERT INTO incidents(folder_id,severity,risk_score,first_event_ts,created_ts,updated_ts) VALUES(?,?,?,?,?,?)",
                            (self.fid, "high", 80, 0, 0, 0)).lastrowid
        self.assertTrue(self.e.responder.quarantine_file(iid, f, f))
        self.assertFalse(os.path.exists(f))
        q = self.e.db.one("SELECT * FROM quarantine")
        ok, _ = self.e.responder.restore_quarantined(q["id"])
        self.assertTrue(ok)
        self.assertEqual(hashlib.sha256(open(f, "rb").read()).hexdigest(), sha)
        self.assertEqual(self.e.db.one("SELECT integrity_ok FROM quarantine")["integrity_ok"], 1)

    def test_db_outage_spools_then_replays(self):
        self.e.db.fail_writes = True
        for i in range(30):
            open(os.path.join(self.test, f"o{i}.txt"), "w").write("x")
        self.assertTrue(wait(lambda: self.e.stats["db_errors"] >= 1 and self.e.spool.size() > 0, 10))
        self.e.db.fail_writes = False
        self.assertTrue(wait(lambda: self.e.db.one("SELECT COUNT(DISTINCT path) n FROM fs_events WHERE event_type='created' AND path LIKE '%/o%'")["n"] >= 30, 20))
        self.assertGreater(self.e.db.one("SELECT COUNT(*) n FROM fs_events WHERE replayed=1")["n"], 0)

    def test_queue_overflow_spills_to_disk(self):
        self.e.stop()
        self.e.q.maxsize = 5                       # tiny queue, worker stopped -> must spill, not grow
        for i in range(50):
            self.e._enqueue("created", os.path.join(self.test, f"s{i}"))
        self.assertEqual(self.e.q.qsize(), 5)
        self.assertEqual(self.e.stats["spooled"], 45)

    def test_data_dir_cannot_be_protected(self):
        with self.assertRaises(ValueError):
            self.e.add_folder(self.e.data_dir)


if __name__ == "__main__":
    unittest.main()
