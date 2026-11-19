# RansomGuard

A ransomware-defence tool built around **operating-system mechanisms** (native filesystem notifications,
process inspection/control, threads and queues, OS permissions) and a **relational forensic database** (SQLite:
transactions, constraints, indexes, WAL concurrency, persisted behavioural baselines).
Detection is driven by real OS events and persisted history; nothing in the pipeline is hard-coded or simulated
(only the *attacker* is simulated, by a harmless script).

```
pip install -r requirements.txt          # watchdog, psutil  (Python 3.9+; GUI needs tkinter)
python -m unittest discover -s tests -t .   # 32 core tests (~55 s) + 1 GUI smoke test (needs tkinter + display; `xvfb-run -a` on servers)
python -m ransomguard                    # OPEN THE APPLICATION (everything below is also available inside it)
                                         #   (or double-click RansomGuard.pyw)
python -m ransomguard demo               # command-line version of Demonstrations 1-6 (add --keep to keep the workspace)
python -m ransomguard monitor DIR [DIR]  # headless monitoring
python -m ransomguard incidents | report ID | recover ID | quarantine | restore ID | check-db | verify-audit | prune DAYS | evaluate | backup-db FILE | sql "SELECT ..."
```
## Using the application (early-2000s "classic Windows" UI)
`python -m ransomguard` opens a window with a splash screen, menu bar, toolbar and tabs. **No command line is needed:**

| Tab / menu | What you can do |
|---|---|
| **Protection** | add/remove protected folders, start/stop monitoring, scan a folder, live engine statistics (queue, spool, DB errors), scan history |
| **Live Events** | real-time filesystem events from the database with entropy and process attribution (pausable) |
| **Incidents** | list + full forensic report; **Recover from backup**, **Mark false positive**, **Resume** / **Terminate** the suspended process |
| **Quarantine** | hash-verified **Restore**, or **Restore to…** another path |
| **Processes** | process start/exit inside protected folders; attribution observations |
| **Database** | read-only SQL console, the 13 canned forensic queries, schema viewer, integrity check, online backup |
| **Demonstrations** | buttons for Demonstrations 1-7 (or *Run all*); output appears in a console window; every demo runs on the live engine, so the other tabs fill in as it runs |
| **Event Log** | monitor health messages (errors, restarts, spool events) |
| **Tools / Settings** | create/reset the test lab, simulate an attack, kill the simulator, edit detection thresholds (stored in the `config` table) |

The lab lives in a folder called `RansomGuardLab` next to the data directory (default `~/RansomGuardLab`). Monitoring starts automatically on launch when folders are already protected.

Data (DB, backups, quarantine) lives in `~/.ransomguard` (override with `--data-dir`), created owner-only (0700).

**Status vocabulary used below:** ✅ *tested* = covered by an automated test or verified in the scripted demo ·
🟡 *implemented* = code exists and was run, but has no automated test · 🟠 *partial* · 🔵 *proposed* = not built.
Verification was done on **Linux (inotify)** only.

---
## System Architecture and Event Flow

```
 OS kernel (inotify / ReadDirectoryChangesW / FSEvents)
        │ notifications (after the operation completed)
 ┌──────▼───────────┐  put_nowait   ┌──────────────┐   full / DB down    ┌─────────────┐
 │ watchdog observer │──────────────▶│ bounded Queue │───────────────────▶│ disk spool  │
 │ thread (producer) │  engine.py    │  (5000)       │◀── replay when idle │ (JSONL,20MB)│
 └──────────────────┘ _enqueue       └──────┬───────┘                     └─────────────┘
                                             │ get (batch ≤500)
                                    ┌────────▼─────────── worker thread (single consumer) ───────────┐
                                    │ 1 dedupe (50 ms)   2 folder lookup   3 process attribution (psutil)│
                                    │ 4 entropy of written files   5 ── BEGIN IMMEDIATE ──────────────┐ │
                                    │    insert processes/observations/fs_events                      │ │
                                    │    Detector.evaluate(window, baseline from DB) → score+signals  │ │
                                    │    upsert incident + signals + incident_events + incident_files │ │
                                    │    baseline windows (trusted / untrusted)  ── COMMIT ───────────┘ │
                                    │ 6 respond (after commit): suspend process → quarantine files →    │
                                    │   each outcome persisted (own transaction) → incident 'contained' │
                                    └───────────────────────────────────────────────────────────────────┘
 other threads: health (restart dead observer) · procwatch (process start/exit) · scan threads · GUI (reads DB only)
```
Flow mapped to your 11 steps: 1 OS reports (`engine._Handler`) → 2 normalise (`_enqueue`) → 3 process info (`procinfo.attribute`) →
4 thread-safe pipeline (`Engine.q`) → 5 detection with baseline (`detector.Detector.evaluate`, `Database.baseline_stats`) →
6 persist in a transaction (`Engine._process`) → 7 risk score → 8 incident with links (`Engine._upsert_incident`) →
9 controlled response (`Engine._respond`, `response.Responder`) → 10 outcome persisted (`Responder._action`) →
11 GUI/CLI read stored data (`Database.incident_report`, `gui.py`).

---
## Operating Systems Concepts Implemented

| # | Concept | Where | Status |
|---|---|---|---|
| 1 | Native FS notifications (create/modify/delete/rename), recursive. `watchdog` selects inotify (Linux), ReadDirectoryChangesW (Windows), FSEvents/kqueue (macOS). Engine reports which one is active (`InotifyObserver`). | `engine.py: _restart_observer, _Handler` | ✅ (Linux) · Windows/macOS 🔵 untested |
| 2 | Async processing, burst handling: producer thread → bounded queue → batching consumer; duplicate notifications collapsed | `engine.py: _enqueue, _collect, _dedupe` | ✅ burst (`test_burst_is_not_lost…`, demo 3); dedupe 🟡 |
| 3 | Event ≠ prevention: events arrive *after* the syscall finished; this is **reactive** detection | README + demo 1 output | ✅ (documented behaviour) |
| 4 | PIDs, exe path, parent, create time, username recorded; identity = `(pid, create_time)` to survive PID reuse | `procinfo.py`, table `processes` | ✅ (`test_ransomware_incident…`, demo 2) |
| 5 | Process creation/exit events inside protected folders | `engine._procwatch`, table `process_events` | 🟡 (demo 2) |
| 6 | Safe suspension (SIGSTOP / NtSuspendProcess via psutil) only when attribution is *reliable*; refuses self/ancestors/init/protected names; re-verifies create_time; records real resulting state | `response.py: suspend_process` | ✅ suspend; PID-reuse and protected-name refusal 🟡 |
| 7 | Threads & sync: worker is the only consumer and owns detector state; `Queue` is the synchronisation primitive; writes serialised by an `RLock`; `Event` for shutdown | `engine.py`, `db.py: transaction` | ✅ (`test_concurrent_writers_serialised`) |
| 8 | No duplicate incidents: single worker + DB partial unique index (below) | `db.py: uq_one_open_incident_per_folder` | ✅ (`test_one_open_incident_per_folder`) |
| 9 | Self-event suppression (our own quarantine/restore moves would otherwise be re-detected) | `engine.ignore/_ignored` | 🟡 |
| 10 | Permissions: data/quarantine/backup dirs `0700`, files `0600`; access-denied handled and recorded as a failed action; app never self-elevates | `response.py: __init__`, `suspend_process` | 🟠 chmod is a no-op on Windows (rely on NTFS ACL); AccessDenied branch 🟡 |
| 11 | Resource management: bounded queue, size-capped spool, observer stopped/joined, threads joined, WAL checkpoint on close | `engine.stop/close`, `Spool` | ✅ overflow (`test_queue_overflow_spills_to_disk`); clean shutdown 🟡 |
| 12 | Recovery from monitor failure: health thread restarts a dead observer | `engine._health` | 🟡 not fault-tested |
| 13 | Preventive enforcement (blocking a write *before* it happens: minifilter driver / fanotify-perm / EndpointSecurity) | — | 🔵 proposed (needs kernel/privileged component) |

**Process states & limits.** Suspension moves the target to *stopped* (Linux) / suspended (Windows); the demo shows
`state = stopped`. User space can only control processes the OS permits (same user, or root/Administrator).
Attribution is *inferred*: a process is a candidate if its cwd or an open file is inside a protected folder; exactly one
candidate ⇒ `reliable`, several ⇒ `ambiguous` (stored as evidence, never acted on). Short-lived writers that open/write/close
between scans are missed, and processes we cannot inspect are invisible. Real EDRs use kernel callbacks to avoid this.

---
## DBMS Concepts Implemented

| Concept | Where | Status |
|---|---|---|
| Normalised schema, PK/FK, CHECK, UNIQUE (18 tables) | `db.py: SCHEMA` | ✅ (`test_constraints`) |
| Atomic multi-table transactions with rollback | `Database.transaction`, used by `Engine._process` | ✅ (`test_rollback_leaves_no_partial_records`, demo 5) |
| Partial unique index (one open incident per folder) | `uq_one_open_incident_per_folder` | ✅ |
| Secondary indexes verified with `EXPLAIN QUERY PLAN` | `db.py` indexes | ✅ (`test_indexes_used`, demo 5) |
| Concurrency: WAL, 1 serialised writer connection, per-thread readers, `busy_timeout` | `Database._connect/transaction/reader` | ✅ |
| Behavioural baseline from persisted history, with poisoning safeguard | `Database.baseline_stats`, `Detector.account/_close`, table `activity_baseline` | ✅ unit-tested; 🟠 end-to-end influence only shown with injected stats (no long-running field data) |
| Forensic reconstruction (incident → events → process → signals → actions → quarantine → recovery) | `Database.incident_report`, `queries.sql` | ✅ |
| Integrity: `PRAGMA integrity_check` + `foreign_key_check`, online backup via SQLite backup API | `Database.integrity_check/backup_to` | ✅ |
| Append-only triggers + hash-chained audit log + audited retention pruning (`prune`) | `db.py` | ✅ (`AuditTests`) |
| Survives restart | — | ✅ (`test_persistence_across_reopen`, demo 6) |
| DB unavailable while monitoring continues: events spooled to disk, replayed (`replayed=1`) | `Engine._worker/_idle`, `Spool` | ✅ (`test_db_outage_spools_then_replays`) |

### Database Schema and Relationships
```
protected_folders 1─∞ fs_events ∞─1 process_observations ∞─1 processes 1─∞ process_events ∞─1 protected_folders
protected_folders 1─∞ incidents ∞─0..1 processes
incidents 1─∞ incident_signals        (UNIQUE incident,name; detail = JSON evidence incl. baseline stats)
incidents ∞─∞ fs_events               via incident_events (composite PK)
incidents 1─∞ incident_files          (PK incident,path; original path + post-rename path)
incidents 1─∞ response_actions        (action, success 0/1, detail)  ← "did the response actually work"
incidents 1─∞ quarantine ; backups ∞─1 protected_folders ; recovery_records → incidents, backups, quarantine
protected_folders 1─∞ scan_sessions 1─∞ scan_results ; protected_folders 1─∞ activity_baseline ; config ; monitor_log
```
*Justification.* `processes` is separate from `process_observations` (one process, many sightings; avoids repeating exe/cmdline per
event). `incident_events` is a true M:N because one event can support later incidents and an incident spans thousands of events.
`incident_files` is keyed by *original* path because ransomware renames; `current_path` tracks where it went. Evidence is separate from
interpretation: `fs_events` is append-only raw data; `incident_signals` holds the derived reasons. Backups are content-addressed
(file named by SHA-256) so identical content is stored once.

### Transactions, Indexing, and Concurrency
* **Transactions.** One worker batch (processes, observations, events, window evaluation, incident, signals, links, baseline rows) is one
  `BEGIN IMMEDIATE … COMMIT`; any exception → `ROLLBACK` (so no incident without its files/events). Response actions run *after* commit and
  each persists its own outcome atomically (e.g. `quarantine` row + `response_actions` row together), so a crash mid-response leaves a truthful record.
* **Isolation / locking.** SQLite is single-writer. `BEGIN IMMEDIATE` takes the write lock up front (no deadlock-prone lock upgrade);
  in WAL mode readers never block the writer and see the last committed snapshot (snapshot isolation per statement; SQLite as a whole is serialisable for writers).
  All in-process writers share one connection behind an `RLock`, so contention is resolved in user space; `busy_timeout=5000 ms` covers other
  processes (e.g. CLI while GUI runs).
* **Indexes.** timestamps (`idx_incidents_created`, `idx_events_ts`, `idx_events_folder_ts`), severity+status, process pid, event path,
  incident-file path, FK lookup columns. `EXPLAIN QUERY PLAN` output in demo 5 shows `SEARCH … USING INDEX` (no full scans).
* **Unavailable DB.** Worker catches `sqlite3.Error`, appends the batch to `spool.jsonl` (cap 20 MB; beyond it events are *counted* in `stats['dropped_spool_full']`
  and logged, not silently dropped), backs off exponentially, replays on recovery. Memory stays bounded (queue 5000).
* **Baseline.** Per folder, per 10-s window, the number of writes is stored. Baseline = mean/std of the last 500 **trusted** active windows; `baseline_deviation`
  fires when current writes exceed mean + 3·max(std,1) and needs ≥ 20 trusted windows (else "cold-start" is recorded in the signal detail).
  *Poisoning safeguards:* a window is trusted only if its peak risk stayed < half the threshold (suspicious ramp-ups are stored with `trusted=0`, never learned);
  the baseline never lowers the absolute `write_burst`/entropy rules; empty windows are not stored. *Limits:* a patient attacker staying below half-threshold for many
  windows can still shift it; a few hundred windows from one machine is a small sample; windows are only recorded while the monitor runs.

---
## OS–DBMS Integration
The OS supplies *events and process facts*; the DB supplies *memory and accountability*. Concretely: (1) every OS event is stored with the
process observation that explains it; (2) the detector reads the folder's historical baseline **from SQLite inside the same transaction** that stores the new evidence;
(3) the open-incident rule is enforced by the database, not by hope; (4) the OS-level response (SIGSTOP, file move) is recorded with its real result;
(5) restores re-verify SHA-256 against the DB record; (6) the GUI shows only what is stored. Detection latency in the demo: ≈0.26 s from first write to incident.
**Honest consequence:** this is reactive — in the demo ~10–13 of 40 files were already encrypted before containment; quarantine moved those aside and
`recover` restored all of them from pre-incident backups (hash-verified).

### Detection rules (all in `detector.py`; incident at score ≥ 60, configurable in `config`)
`canary_tripped`(80) · `sustained_encryption`(60, ≥10 distinct encrypted-looking files within 300 s - catches slow attacks) · `write_burst`(30, ≥15 writes/10 s) ·
`high_entropy_writes`(35, ≥3 files and ≥60 % of sampled writes ≥ 7.5 bits/byte) · `mass_rename`(20) · `suspicious_extension`(15, renamed *or newly created* `.locked/.enc/...`) ·
`ransom_note`(15) · `mass_delete`(10) · `many_distinct_files`(10) · `baseline_deviation`(15).
*Media/archives (jpg, png, pdf, zip, docx, mp4 ...) are naturally high-entropy, so entropy is ignored for them **unless their header is invalid** (`detector.MAGIC`):
a `.jpg` that no longer starts with a JPEG header was overwritten.*

---
## Hardening and Honest Evaluation
After an honest self-assessment, these were added and then attacked with a deliberately nastier simulator (`simulator.py --mode ... --no-chdir --shuffle --delay`):

| Feature | Where | Status |
|---|---|---|
| **Decoy (canary) files**: 6 per protected folder, names spread alphabetically; a verified change (content hash differs), rename or delete = incident. Metadata-only touches and our own writes never trip it. Decoys are re-armed after the attacker is frozen. | `canary.py`, `engine.ensure_canaries/_canary_check`, table `canaries` | ✅ tested (`CanaryTests`, evaluation A1/A6) |
| **Header check** for media/archive extensions (closes the "keep the .jpg/.docx extension" evasion) | `detector.file_entropy/MAGIC` | ✅ tested |
| **Slow-attack rule** (`sustained_encryption`, 300 s window) | `detector.Detector.long` | ✅ tested |
| **Attribution without cwd**: at incident time, rank processes by bytes written *since the incident's first suspicious event* (stopped processes skipped; needs ≥16 KB and 3× dominance). Heuristic: a legitimate heavy writer at the same moment could be blamed; suspension is reversible (Resume button). | `procinfo.attribute_io`, `engine._respond` | ✅ tested; 🟠 heuristic |
| **Damage between detection and containment** is attached to the incident (30 s) so it is quarantined and recoverable | `engine._attach_late` | ✅ tested (stealth test, A3) |
| **Versioned backups** of benign new/changed files (never encrypted-looking ones; newest 5 versions kept). Recovery only trusts versions made *before the first encrypted-looking event*. | `response.backup_file/recover_incident` | ✅ tested |
| **Tamper-evident audit log**: SHA-256 hash chain written *inside the same transaction* as each incident/response/status change; `verify-audit` re-computes it | `db.audit/verify_audit`, table `audit_log` | ✅ tested |
| **Append-only triggers** on `audit_log`, `response_actions`, `fs_events` (events deletable only through the audited `prune`) | `db.SCHEMA` triggers, `db.prune` | ✅ tested |
| `evaluate` command and *Tools → Run Adversarial Evaluation* | `evaluate.py` | ✅ |

**Evaluation results** (`python -m ransomguard evaluate`; Linux, 40 files per run, fresh engine per row, files "lost at stop" = originals missing/changed when the attacker stopped, before recovery):

| Scenario | Canaries | Detected | Latency | Files lost at stop | Lost after recovery | Process found | Suspended | Signals |
|---|---|---|---|---|---|---|---|---|
| A1 classic in-place, sorted, cwd=target | off | yes | 0.31 s | 10/40 | 0 | yes | yes | sustained, entropy, burst |
| A1 | on | yes | 0.03 s | **0/40** | 0 | yes | yes | canary |
| A2 classic, shuffled, started elsewhere | off | yes | 0.31 s | 10/40 | 0 | yes (io) | yes | sustained, entropy, burst |
| A2 | on | yes | 0.20 s | 5/40 | 0 | yes (io) | yes | canary, entropy |
| A3 copy-encrypt-delete `.enc`, shuffled, elsewhere | off | yes | 0.22 s | 7/40 | 0 | yes | yes | entropy, burst, suspicious ext |
| A3 | on | yes | 0.19 s | 5/40 | 0 | yes | yes | canary, entropy, ext |
| A4 stealth (names/types kept), shuffled, elsewhere | off | yes | 0.31 s | 10/40 | 0 | yes | yes | sustained, entropy, burst |
| A4 | on | yes | 0.19 s | 5/40 | 0 | yes | yes | canary, entropy |
| A5 slow stealth (0.5 s/file) | off | yes | 4.55 s | 10/40 | 0 | yes | yes | sustained, entropy |
| A5 | on | yes | 2.55 s | 5/40 | 0 | yes | yes | canary, entropy |
| A6 one decoy overwritten, attacker stops | off | **no** | - | 0/40 | - | - | - | - |
| A6 | on | yes | 0.02 s | 0/40 | 0 | no | no | canary |

| Benign workload (must not alert) | Alerts |
|---|---|
| B1 copy 200 text files / B2 copy 60 JPEG/DOCX-like files (valid headers) / B3 gzip 40 files | 0 / 0 / 0 |
| B4 encrypt 20 files with a gpg-style tool (`.gpg`, random bytes) | **1 - known false positive** (indistinguishable from ransomware by content) |

*How to read it honestly:* decoys only reduce damage when the attacker reaches one early (A1: all damage prevented; shuffled runs: damage halved with 6 decoys vs 3 decoys, which made no difference in an earlier run);
their other value is catching an attack that stops after touching one file (A6). Row A3/off recovered everything only after the late-deletion fix described above.

### Known evasions and limits (not fixed)
1. **Very slow attacker** (< 10 files per 5 minutes) that also avoids the decoys is below every rule.
2. **Decoy names are fixed in the source**: an attacker who knows them can skip them. 🔵 per-installation random names would fix it.
3. **Partial / intermittent encryption** that leaves the first 8 KiB and valid headers intact (entropy is sampled from the first 8 KiB only) is *not* detected by entropy. Untested. 🔵
4. **No self-protection**: an attacker running as the same user can kill RansomGuard, delete the DB/backups/quarantine folder, or drop the triggers. The hash chain makes *edits* detectable (`verify-audit`) but cannot detect deletion of the whole database; the head hash must be noted externally to anchor it.
5. **Attribution stays heuristic**: a quiet attacker (little written) is not identified (see Demonstration 7); a busy legitimate process could be blamed (needs 3× dominance, only used after an incident fires).
6. **False positives**: legitimate encryption tools that don't leave a recognised header (gpg, VeraCrypt volumes, some game/archive formats) look identical to ransomware.
7. **Evaluation limits**: the attacker is a simulator written by the same author, one fixed shuffle order per scenario, 40 files, one Linux machine, no background load, latencies from a fast local disk. It demonstrates mechanisms, not real-world detection rates.
8. Signals are scored over the 10-second window, so unrelated bursty activity in the same window can inflate a score (the incident's *timeline and affected files* are limited to events from its first suspicious event onward).

---
## Testing and Demonstration Guide
Automated: `python -m unittest discover -s tests -t . -v` → 19 tests: `test_db.py` (constraints, rollback, partial unique index, query plans, integrity, backup, restart, concurrent writers),
`test_detector.py` (entropy, benign vs ransomware, baseline influence, poisoning safeguard), `test_pipeline.py` (real inotify events, 300-file burst without false positive,
real simulator → incident → process suspended → recovery with hash check, quarantine/restore, DB outage spool/replay, queue overflow).

Scripted demo — one command, expected observations in brackets:
| Demo | How | Expected |
|---|---|---|
| 1 OS events | `python -m ransomguard demo` (section 1) | `InotifyObserver`; rows `created, modified, modified, moved, deleted` in `fs_events` |
| 2 Process | section 2: child python writes 6 files with cwd in the folder | `process_observations` confidence `reliable`, method `cwd`; `process_events` started→exited; events carry its PID |
| 3 Concurrency | section 3: 600 files from a thread while a 10-ms "UI loop" polls the DB | 600/600 persisted in well under 1 s, worst stall in single-digit ms, queue drains to 0, 0 incidents |
| 4 Detection | section 4: simulator on `attack/` | incident risk ≥ 60, signals `high_entropy_writes`+`write_burst`, simulator state `stopped`, quarantine actions OK |
| 5 DBMS | section 5 | join counts per incident; controlled `CHECK` failure → `Incidents before=1 after=1`; `SEARCH … USING INDEX` plans; `activity_baseline` shows untrusted windows |
| 6 Persistence | section 6: close, reopen new `Engine` | `integrity_check ['ok']`, incident + actions still there, quarantine restore `sha256 verified`, 9 recovered, `match=True` |
| 7 Decoys | *Demonstrations → 7* (GUI) | one overwritten decoy → incident in ~0.01 s with only 1 event in its timeline; honest note when the writer could not be identified; `audit_log` shows `canary_armed` / `canary_tripped` |

Manual replay of the same by hand (two terminals):
```
python -m ransomguard.simulator /tmp/lab --init                 # creates disposable dir + marker file
python -m ransomguard --data-dir /tmp/rg monitor /tmp/lab       # terminal 1 (or: gui)
cd /tmp/lab && python -m ransomguard.simulator /tmp/lab         # terminal 2 (needs PYTHONPATH=<project> or run from project dir with cwd set)
python -m ransomguard --data-dir /tmp/rg incidents ; ... report 1 ; ... recover 1 ; ... quarantine ; ... restore 1 --dest /tmp/x.txt
python -m ransomguard --data-dir /tmp/rg sql "SELECT name,weight,detail FROM incident_signals WHERE incident_id=1"
```
More SQL: `queries.sql` (17 forensic/reporting queries). The simulator refuses any directory without its `.ransomguard_testdir` marker, never follows symlinks and uses a reversible XOR.

---
## Professional additions (final polish)

| Feature | Where | Notes |
|---|---|---|
| Random decoy names | `canary.py`, `Engine.canary_names()` | Seed stored in the `config` table (`canary_seed`); each install gets different names. Older databases keep their existing decoys. `canary_randomize=0` restores the fixed list. |
| Trusted Apps | toolbar / Protection menu, `Engine._is_trusted()` | Writes by a listed program are logged but not scored. Decoy files are never excused. Full-path entries (Browse) are safer than bare names. Limit: a writer that exits before the engine identifies it cannot be matched. |
| Alert popup | `App.alert()`, setting `alert_popup` | Always-on-top window with risk, process, response and a View incident button. |
| PDF incident report | Incidents tab > Export PDF report..., CLI `export-pdf <id>` | Dependency-free writer (`report_pdf.py`); includes the audit-chain integrity line. |
| Windows .exe | `build_exe.bat` | PyInstaller one-folder build. Helper processes (attack simulator, demo writers) go through `pyexec.py` because a frozen exe cannot run `python -m`. Not tested on Windows by the author of this note: build it and test every button before presenting. |

Tests: `python -m unittest discover -s tests -t .` (add `xvfb-run -a` on a headless Linux box for the GUI tests).

## Limitations and Future Improvements
* **Reactive only** (🔵 preventive blocking needs a minifilter / fanotify-perm / EndpointSecurity component and elevated privileges).
* **Attribution is heuristic** (cwd / open handle, then write-volume at incident time); misses quiet writers and other users' processes without privileges; `open_files()` can be slow on Windows. See *Known evasions* above.
* **Platforms:** developed and tested on Linux. Windows/macOS use the same code paths via watchdog/psutil but are *untested*; `chmod` protections are weak on Windows.
* **GUI:** `gui.py` + `lab.py` were exercised headlessly on Linux under Xvfb (smoke test runs demos 1,4,5,6 through the app; demo 7 and the new Tools-menu items were exercised manually under Xvfb and checks incidents, banner status and SQL console; layout was checked from screenshots). Not tested: Windows/macOS rendering, native file dialogs, the Resume/Terminate/Restore-to/Settings buttons, Add-Folder dialog.
* Not covered by tests: observer-restart, access-denied branches, PID-reuse guard, scan sessions, process-watcher (GUI: see above). Not built: files over 5 MB are not backed up (cap; startup snapshot also capped at 500 files), scheduled DB backups (manual `backup-db` only), encryption-at-rest of backups, self-protection / watchdog service, per-install random decoy names.
* Detection is rule-based with a simple statistical baseline — no ML. Heavy legitimate encryption/compression of many unknown-type files can false-positive; tune `config`.
* Containment happens after some files are already damaged (≈0.3 s latency in the demo; depends on hardware and attacker speed).
