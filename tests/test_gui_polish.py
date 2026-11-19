"""Headless GUI test of the alert popup, PDF export and Trusted Apps window. Run with: xvfb-run -a python -m unittest tests.test_gui_polish"""
import os, subprocess, sys, tempfile, time, unittest
try:
    import tkinter  # noqa
    HAVE = bool(os.environ.get("DISPLAY") or sys.platform in ("win32", "darwin"))
except ImportError:
    HAVE = False


@unittest.skipUnless(HAVE, "needs tkinter + a display (use xvfb-run)")
class GuiPolish(unittest.TestCase):
    def test_alert_pdf_and_trusted_window(self):
        from ransomguard import gui, pyexec
        base = tempfile.mkdtemp()
        folder = os.path.join(base, "protected"); os.makedirs(folder)
        open(os.path.join(folder, "a.txt"), "w").write("hello")
        app = gui.App(os.path.join(base, "data"), splash=False)
        r = app.root

        def pump(sec):
            end = time.time() + sec
            while time.time() < end:
                r.update(); time.sleep(0.03)
        pump(0.5)
        app.eng.add_folder(folder); app.eng.start()
        pump(1.5)
        # trip a decoy from a child process -> incident -> popup on the Tk main thread
        d = app.eng.canary_names()[0]
        p = subprocess.Popen(pyexec.code_cmd(f"import os,time;open({d!r},'wb').write(os.urandom(3000));time.sleep(30)"), cwd=folder)
        try:
            end = time.time() + 15
            while app._alert_win is None and time.time() < end:
                pump(0.2)
            self.assertIsNotNone(app._alert_win, "alert popup did not appear")
            texts = [w.cget("text") for w in app._alert_win.winfo_children()[1:2]]
            self.assertIn("Incident #1", texts[0])
            # popup can be switched off in config
            app._alert_win.destroy(); app._alert_win = None
            app.eng.cfg["alert_popup"] = "0"; app.alert(1)
            self.assertIsNone(app._alert_win)
            app.eng.cfg["alert_popup"] = "1"
            # PDF export through the real button handler
            app.refresh(); pump(0.5)
            app.t_inc.selection_set(app.t_inc.get_children()[0]); pump(0.3)
            out = os.path.join(base, "report.pdf")
            gui.filedialog.asksaveasfilename = lambda **k: out
            gui.messagebox.askyesno = lambda *a, **k: False
            app.export_pdf()
            data = open(out, "rb").read()
            self.assertTrue(data.startswith(b"%PDF") and b"AUDIT LOG INTEGRITY: OK" in data)
            # Trusted Apps window opens and shows what is stored
            app.eng.db.set_config("trusted_apps", "backup.exe"); app.eng.reload_config()
            before = set(r.winfo_children())
            app.trusted_apps(); pump(0.3)
            win = [w for w in r.winfo_children() if w not in before][0]
            self.assertEqual(win.title(), "Trusted Apps")
            win.destroy()
            app.settings(); pump(0.3)                                  # hidden text keys must not break the numeric Settings dialog
            [w for w in r.winfo_children() if w.winfo_class() == "Toplevel"][-1].destroy()
        finally:
            p.kill()
            app.quit()
            app.__dict__.clear()          # drop Tk variables on the main thread so a later GUI test in the same process cannot abort
            import gc; gc.collect()


if __name__ == "__main__":
    unittest.main()
