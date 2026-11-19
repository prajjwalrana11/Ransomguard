import os, unittest
from ransomguard.db import DEFAULT_CONFIG
from ransomguard.detector import Detector, shannon_entropy


def ev(i, typ, name, t=0.0, ent=None, dest=None):
    return {"ts": t + i * 0.01, "type": typ, "path": f"/p/{name}", "dest": dest and f"/p/{dest}", "entropy": ent}


class DetectorTests(unittest.TestCase):
    def det(self):
        return Detector(DEFAULT_CONFIG)

    def test_entropy_bounds(self):
        self.assertLess(shannon_entropy(b"a" * 4096), 0.01)
        self.assertGreater(shannon_entropy(os.urandom(8192)), 7.9)

    def test_benign_bulk_copy_not_flagged(self):
        d = self.det()
        d.add(1, [ev(i, "created", f"f{i}.txt", ent=4.5) for i in range(40)])
        score, sigs, _ = d.evaluate(1, None)
        self.assertLess(score, 60, sigs)

    def test_ransomware_pattern_flagged(self):
        d = self.det()
        d.add(1, [ev(i, "modified", f"f{i}.txt", ent=7.95) for i in range(20)] +
                 [ev(30 + i, "moved", f"f{i}.txt", dest=f"f{i}.txt.locked") for i in range(20)] +
                 [ev(60, "created", "README_HOW_TO_DECRYPT.txt")])
        score, sigs, _ = d.evaluate(1, None)
        names = {s["name"] for s in sigs}
        self.assertGreaterEqual(score, 90)
        self.assertTrue({"write_burst", "high_entropy_writes", "mass_rename", "suspicious_extension", "ransom_note"} <= names)

    def test_baseline_influences_score(self):
        d = self.det()
        d.add(1, [ev(i, "modified", f"f{i}", ent=4.0) for i in range(10)])
        _, none_sigs, _ = d.evaluate(1, None)
        _, hist_sigs, _ = d.evaluate(1, {"n": 100, "mean": 2.0, "std": 1.0})
        self.assertNotIn("baseline_deviation", {s["name"] for s in none_sigs})
        dev = [s for s in hist_sigs if s["name"] == "baseline_deviation"]
        self.assertTrue(dev and dev[0]["detail"]["baseline_mean"] == 2.0)
        _, busy, _ = d.evaluate(1, {"n": 100, "mean": 12.0, "std": 3.0})   # normally busy folder
        self.assertNotIn("baseline_deviation", {s["name"] for s in busy})

    def test_poisoning_safeguard(self):
        d = self.det()
        out = d.account(1, 100.0, True, 80)        # suspicious window
        out += d.account(1, 100.1, True, 80)
        out += d.account(1, 150.0, True, 5)        # next bucket closes the first
        out += d.account(1, 250.0, True, 5)
        self.assertEqual(out[0][4], 0)             # suspicious window: trusted=0 (never learned)
        self.assertEqual(out[1][4], 1)             # quiet window: trusted=1


if __name__ == "__main__":
    unittest.main()
