import os, sqlite3, tempfile, time, unittest
from ransomguard.db import Database


class DbTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.db = Database(os.path.join(self.d, "t.db"))
        with self.db.transaction() as c:
            c.execute("INSERT INTO protected_folders(path,added_ts) VALUES('/x',0)")

    def _inc(self, c, status="open", sev="high", score=80):
        return c.execute("INSERT INTO incidents(folder_id,severity,risk_score,status,first_event_ts,created_ts,updated_ts) "
                         "VALUES(1,?,?,?,0,0,0)", (sev, score, status)).lastrowid

    def test_rollback_leaves_no_partial_records(self):
        with self.assertRaises(sqlite3.IntegrityError):
            with self.db.transaction() as c:
                iid = self._inc(c)
                c.execute("INSERT INTO incident_files VALUES(?,?,?,?,?,?,?)", (iid, "/x/a", None, "modified", 7.9, 0, 0))
                c.execute("INSERT INTO response_actions(incident_id,ts,action,success) VALUES(?,?,?,?)", (iid, 0, "x", 7))  # CHECK fails
        self.assertEqual(self.db.one("SELECT COUNT(*) n FROM incidents")["n"], 0)
        self.assertEqual(self.db.one("SELECT COUNT(*) n FROM incident_files")["n"], 0)

    def test_constraints(self):
        with self.assertRaises(sqlite3.IntegrityError):
            with self.db.transaction() as c:
                self._inc(c, sev="catastrophic")
        with self.assertRaises(sqlite3.IntegrityError):          # FK: unknown incident
            with self.db.transaction() as c:
                c.execute("INSERT INTO response_actions(incident_id,ts,action,success) VALUES(999,0,'x',1)")

    def test_one_open_incident_per_folder(self):
        with self.db.transaction() as c:
            self._inc(c)
        with self.assertRaises(sqlite3.IntegrityError):
            with self.db.transaction() as c:
                self._inc(c)
        with self.db.transaction() as c:                          # a contained one is allowed
            self._inc(c, status="contained")

    def test_indexes_used(self):
        def plan(sql):
            return " ".join(r[3] for r in self.db.query("EXPLAIN QUERY PLAN " + sql))
        self.assertIn("idx_incidents_created", plan("SELECT * FROM incidents WHERE created_ts > 5"))
        self.assertIn("idx_incidents_sev_stat", plan("SELECT * FROM incidents WHERE severity='high' AND status='open'"))
        self.assertIn("idx_events_path", plan("SELECT * FROM fs_events WHERE path='/x/a'"))
        self.assertIn("idx_events_folder_ts", plan("SELECT * FROM fs_events WHERE folder_id=1 AND ts>5"))
        self.assertIn("idx_proc_pid", plan("SELECT * FROM processes WHERE pid=4"))

    def test_integrity_and_online_backup(self):
        self.assertEqual(self.db.integrity_check(), ["ok"])
        b = self.db.backup_to(os.path.join(self.d, "bk.db"))
        self.assertEqual(sqlite3.connect(b).execute("SELECT COUNT(*) FROM protected_folders").fetchone()[0], 1)

    def test_persistence_across_reopen(self):
        with self.db.transaction() as c:
            self._inc(c)
        self.db.close()
        db2 = Database(os.path.join(self.d, "t.db"))
        self.assertEqual(db2.one("SELECT COUNT(*) n FROM incidents")["n"], 1)

    def test_concurrent_writers_serialised(self):
        import threading
        errs = []
        def w(i):
            try:
                for j in range(50):
                    with self.db.transaction() as c:
                        c.execute("INSERT INTO monitor_log(ts,level,message) VALUES(?,?,?)", (time.time(), "t", f"{i}-{j}"))
            except Exception as e:
                errs.append(e)
        ts = [threading.Thread(target=w, args=(i,)) for i in range(6)]
        [t.start() for t in ts]; [t.join() for t in ts]
        self.assertEqual(errs, [])
        self.assertEqual(self.db.one("SELECT COUNT(*) n FROM monitor_log")["n"], 300)


if __name__ == "__main__":
    unittest.main()
