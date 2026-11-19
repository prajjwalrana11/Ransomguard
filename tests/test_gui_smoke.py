"""Headless GUI smoke test. Needs tkinter and a display: on a server run `xvfb-run -a python -m unittest ...`."""
import os, sys, tempfile, time, unittest
try:
    import tkinter  # noqa
    HAVE = bool(os.environ.get("DISPLAY") or sys.platform in ("win32", "darwin"))
except ImportError:
    HAVE = False


@unittest.skipUnless(HAVE, "needs tkinter + a display (use xvfb-run)")
class GuiSmoke(unittest.TestCase):
    def test_everything_through_the_app(self):
        from ransomguard import gui
        app = gui.App(os.path.join(tempfile.mkdtemp(), "data"), splash=True)
        r = app.root

        def pump(sec):
            end = time.time() + sec
            while time.time() < end:
                r.update(); time.sleep(0.03)
        pump(1.8)                                   # splash screen -> main window
        self.assertEqual(r.state(), "normal")
        app.run_demos([1, 4, 5, 6])
        pump(1)
        end = time.time() + 90
        while app.busy and time.time() < end:
            pump(0.2)
        self.assertFalse(app.busy)
        out = app.console.get("1.0", "end")
        for needle in ("InotifyObserver", "ROLLBACK left no partial record", "state after automatic response: stopped", "match=True"):
            if "Inotify" in needle and sys.platform != "linux":
                continue
            self.assertIn(needle, out)
        pump(1.5)                                   # let the 1 s refresh run
        self.assertEqual(len(app.t_inc.get_children()), 1)
        self.assertEqual(app.banner_status.get(), "PROTECTED")
        app.sql.delete("1.0", "end"); app.sql.insert("end", "SELECT name, weight FROM incident_signals")
        app.run_sql()
        self.assertIn("row(s)", app.sql_info.get())
        self.assertGreaterEqual(len(app.t_sql.get_children()), 2)
        app.quit()


if __name__ == "__main__":
    unittest.main()
