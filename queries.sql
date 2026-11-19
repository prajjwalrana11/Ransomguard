-- Forensic / reporting queries. Run:  python -m ransomguard --data-dir DIR sql "<query>"   (read-only)
-- Q1 incident history (uses idx_incidents_created)
SELECT id, status, severity, risk_score, datetime(created_ts,'unixepoch','localtime') FROM incidents ORDER BY created_ts DESC LIMIT 20;
-- Q2 filter by severity+status (idx_incidents_sev_stat)
SELECT id, risk_score FROM incidents WHERE severity='medium' AND status='contained';
-- Q3 who did it: incident -> process
SELECT i.id, p.pid, p.name, p.exe, p.ppid, p.parent_name, p.username FROM incidents i JOIN processes p ON p.id=i.process_id;
-- Q4 why: signals incl. baseline statistics that influenced the score
SELECT name, weight, detail FROM incident_signals WHERE incident_id=1 ORDER BY weight DESC;
-- Q5 trace: initial FS activity -> detection (timeline of linked events)
SELECT datetime(e.ts,'unixepoch','localtime') t, e.event_type, e.path, e.dest_path, e.entropy, e.attribution
FROM incident_events ie JOIN fs_events e ON e.id=ie.event_id WHERE ie.incident_id=1 ORDER BY e.ts, e.id;
-- Q6 response outcomes (did the response actually succeed?)
SELECT datetime(ts,'unixepoch','localtime') t, action, success, target, detail FROM response_actions WHERE incident_id=1 ORDER BY id;
-- Q7 every incident that touched a given file (idx_incfiles_path)
SELECT incident_id, path, current_path, last_event_type FROM incident_files WHERE path LIKE '%doc_000%';
-- Q8 quarantine + restoration history with integrity result
SELECT id, original_path, sha256, status, integrity_ok, restored_dest FROM quarantine;
-- Q9 backup/recovery chain
SELECT r.target_path, r.success, b.sha256 FROM recovery_records r JOIN backups b ON b.id=r.backup_id;
-- Q10 baseline: trusted windows feed it, untrusted (suspicious/bursty) windows are kept for audit but not learned
SELECT trusted, COUNT(*) windows, AVG(write_count) mean_writes, MAX(write_count) max_writes FROM activity_baseline GROUP BY trusted;
-- Q11 process lifecycle inside protected folders
SELECT pe.kind, p.pid, p.name, datetime(pe.ts,'unixepoch','localtime') FROM process_events pe JOIN processes p ON p.id=pe.process_id ORDER BY pe.id;
-- Q12 events lost to outages were replayed, not dropped
SELECT replayed, COUNT(*) FROM fs_events GROUP BY replayed;
-- Q13 monitor health log
SELECT datetime(ts,'unixepoch','localtime'), level, message FROM monitor_log ORDER BY id DESC LIMIT 20;
-- Q14 audit chain: every incident/response/canary event, hash-linked (verify with: python -m ransomguard verify-audit)
SELECT id, datetime(ts,'unixepoch','localtime') t, kind, substr(prev_hash,1,10) prev, substr(hash,1,10) hash, payload FROM audit_log ORDER BY id DESC LIMIT 30;
-- Q15 decoy files: armed vs tripped
SELECT id, path, datetime(created_ts,'unixepoch','localtime') armed, datetime(tripped_ts,'unixepoch','localtime') tripped FROM canaries;
-- Q16 how each process was identified (cwd / open_file / io_delta) and with what confidence
SELECT o.method, o.confidence, COUNT(*) n FROM process_observations o GROUP BY o.method, o.confidence;
-- Q17 backup versions per file (newest first)
SELECT original_path, COUNT(*) versions, MAX(datetime(ts,'unixepoch','localtime')) newest FROM backups GROUP BY original_path ORDER BY versions DESC LIMIT 20;
