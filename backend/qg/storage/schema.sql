-- QuantumGuard schema v1. Parameterised queries only; no ORM.
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS users (
  user_id TEXT PRIMARY KEY, name TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL, seeded INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS user_roles (
  user_id TEXT NOT NULL REFERENCES users(user_id), role TEXT NOT NULL, granted_at TEXT NOT NULL,
  change_id TEXT, source TEXT NOT NULL DEFAULT 'signed', PRIMARY KEY (user_id, role));
-- roles reported by the external identity source (sandbox adapter / signals), reconciled by QG-R005
CREATE TABLE IF NOT EXISTS observed_roles (
  user_id TEXT NOT NULL, role TEXT NOT NULL, observed_at TEXT NOT NULL, PRIMARY KEY (user_id, role));

CREATE TABLE IF NOT EXISTS devices (
  device_id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(user_id), name TEXT NOT NULL,
  kem_pk BLOB NOT NULL, sig_pk BLOB NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL, directory_epoch INTEGER NOT NULL, last_seen_at TEXT,
  revoked_at TEXT, revoked_epoch INTEGER, compromise_time TEXT, certificate TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS devices_user ON devices(user_id);

CREATE TABLE IF NOT EXISTS directory (
  epoch INTEGER PRIMARY KEY, doc TEXT NOT NULL, doc_hash BLOB NOT NULL, issued_at TEXT NOT NULL,
  superseded_at TEXT, revocation INTEGER NOT NULL DEFAULT 0, reason TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS invites (
  invite_id TEXT PRIMARY KEY, code_hash BLOB NOT NULL UNIQUE, user_id TEXT NOT NULL REFERENCES users(user_id),
  created_by TEXT, created_at TEXT NOT NULL, expires_at TEXT NOT NULL, status TEXT NOT NULL,
  bootstrap INTEGER NOT NULL DEFAULT 0, used_at TEXT, used_by_device TEXT, created_by_device TEXT);
CREATE TABLE IF NOT EXISTS enrol_holds (
  hold_id TEXT PRIMARY KEY, user_id TEXT NOT NULL, incident_id TEXT, created_at TEXT NOT NULL, lifted_at TEXT);

CREATE TABLE IF NOT EXISTS sessions (
  session_id TEXT PRIMARY KEY, device_id TEXT NOT NULL, user_id TEXT NOT NULL, last_seq INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL, last_used_at TEXT NOT NULL, hard_expires_at TEXT NOT NULL, fresh_required INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS sessions_device ON sessions(device_id);
CREATE TABLE IF NOT EXISTS ended_sessions (
  session_id TEXT PRIMARY KEY, device_id TEXT NOT NULL, user_id TEXT NOT NULL, ended_at TEXT NOT NULL, reason TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS files (
  file_id TEXT PRIMARY KEY, owner_user_id TEXT NOT NULL, name TEXT NOT NULL, classification TEXT NOT NULL,
  current_version INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
  is_decoy INTEGER NOT NULL DEFAULT 0, deleted INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS file_versions (
  file_id TEXT NOT NULL REFERENCES files(file_id), version INTEGER NOT NULL, status TEXT NOT NULL,
  reason TEXT NOT NULL, size_bytes INTEGER NOT NULL, chunk_count INTEGER NOT NULL, created_at TEXT NOT NULL,
  created_by_device TEXT NOT NULL, manifest TEXT, manifest_sig TEXT, ciphertext_sha256 TEXT,
  committed_at TEXT, committed_by_device TEXT, PRIMARY KEY (file_id, version));
CREATE TABLE IF NOT EXISTS slots (
  slot_id TEXT PRIMARY KEY, file_id TEXT NOT NULL, version INTEGER NOT NULL, device_id TEXT NOT NULL,
  sealed BLOB NOT NULL, seal_epoch INTEGER NOT NULL, wrap_epoch INTEGER NOT NULL, created_at TEXT NOT NULL,
  UNIQUE (file_id, version, device_id));
CREATE INDEX IF NOT EXISTS slots_device ON slots(device_id);
CREATE TABLE IF NOT EXISTS leases (
  lease_id TEXT PRIMARY KEY, session_id TEXT NOT NULL, device_id TEXT NOT NULL, file_id TEXT NOT NULL,
  version INTEGER NOT NULL, expires_at TEXT NOT NULL, cancelled INTEGER NOT NULL DEFAULT 0,
  kind TEXT NOT NULL DEFAULT 'slot');
CREATE INDEX IF NOT EXISTS leases_device ON leases(device_id);
CREATE TABLE IF NOT EXISTS releases (
  receipt_id TEXT PRIMARY KEY, file_id TEXT NOT NULL, version INTEGER NOT NULL, device_id TEXT NOT NULL, ts TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS releases_device ON releases(device_id);

CREATE TABLE IF NOT EXISTS receipts (
  leaf_index INTEGER PRIMARY KEY, id TEXT NOT NULL UNIQUE, ts TEXT NOT NULL, action TEXT NOT NULL,
  decision TEXT NOT NULL, reason_code TEXT NOT NULL, user_id TEXT, device_id TEXT, session_id TEXT,
  resource TEXT, leaf BLOB NOT NULL, leaf_hash BLOB NOT NULL);
CREATE INDEX IF NOT EXISTS receipts_device ON receipts(device_id);
CREATE INDEX IF NOT EXISTS receipts_user ON receipts(user_id);
CREATE INDEX IF NOT EXISTS receipts_resource ON receipts(resource);
CREATE TABLE IF NOT EXISTS checkpoints (
  tree_size INTEGER PRIMARY KEY, root_hash BLOB NOT NULL, ts TEXT NOT NULL, doc TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS incidents (
  id TEXT PRIMARY KEY, device_id TEXT NOT NULL UNIQUE, user_id TEXT NOT NULL, status TEXT NOT NULL,
  reported_at TEXT NOT NULL, reported_by TEXT NOT NULL, compromise_time TEXT NOT NULL, note TEXT NOT NULL DEFAULT '',
  time_to_enforce_ms INTEGER NOT NULL, directory_epoch INTEGER NOT NULL, revoke_receipt_id TEXT,
  checkpoint_tree_size INTEGER NOT NULL, closed_at TEXT);
CREATE TABLE IF NOT EXISTS incident_timeline (
  id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id TEXT NOT NULL, step TEXT NOT NULL, ts TEXT NOT NULL,
  receipt_id TEXT, detail TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS rekey_jobs (
  file_id TEXT NOT NULL, incident_id TEXT, reason TEXT NOT NULL, status TEXT NOT NULL,
  from_version INTEGER NOT NULL, new_version INTEGER, claimed_by TEXT, created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL, PRIMARY KEY (file_id, from_version));

CREATE TABLE IF NOT EXISTS alerts (
  id TEXT PRIMARY KEY, ts TEXT NOT NULL, rule_id TEXT NOT NULL, severity TEXT NOT NULL, status TEXT NOT NULL,
  user_id TEXT, device_id TEXT, session_id TEXT, summary TEXT NOT NULL, condition TEXT NOT NULL,
  receipt_ids TEXT NOT NULL, response_id TEXT, incident_id TEXT, acknowledged_by TEXT, extra TEXT);
CREATE TABLE IF NOT EXISTS responses (
  id TEXT PRIMARY KEY, alert_id TEXT NOT NULL, action TEXT NOT NULL, scope_kind TEXT NOT NULL, scope_id TEXT,
  created_at TEXT NOT NULL, expires_at TEXT, lifted_at TEXT, lifted_by TEXT, lift_reason TEXT);
CREATE INDEX IF NOT EXISTS responses_scope ON responses(scope_kind, scope_id);

CREATE TABLE IF NOT EXISTS changes (
  id TEXT PRIMARY KEY, type TEXT NOT NULL, target_user_id TEXT NOT NULL, role TEXT, file_id TEXT,
  reason TEXT NOT NULL, requested_by TEXT NOT NULL, requested_device TEXT NOT NULL, requested_at TEXT NOT NULL,
  status TEXT NOT NULL, approvals_required INTEGER NOT NULL, change_doc TEXT NOT NULL, signature TEXT NOT NULL,
  applied_at TEXT, reject_reason TEXT, invite_name TEXT);
CREATE TABLE IF NOT EXISTS change_approvals (
  change_id TEXT NOT NULL, user_id TEXT NOT NULL, device_id TEXT NOT NULL, at TEXT NOT NULL, signature TEXT NOT NULL,
  PRIMARY KEY (change_id, user_id));

CREATE TABLE IF NOT EXISTS signals (
  id TEXT PRIMARY KEY, jti TEXT NOT NULL UNIQUE, iss TEXT NOT NULL, event_type TEXT NOT NULL, subject_id TEXT NOT NULL,
  event_ts INTEGER NOT NULL, received_at TEXT NOT NULL, applied INTEGER NOT NULL, body TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS services (
  service_id TEXT PRIMARY KEY, name TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL, is_decoy INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS service_keys (
  key_id TEXT PRIMARY KEY, service_id TEXT NOT NULL, alg TEXT NOT NULL, public_key BLOB NOT NULL, status TEXT NOT NULL,
  created_at TEXT NOT NULL, retired_at TEXT);
CREATE TABLE IF NOT EXISTS keysets (epoch INTEGER PRIMARY KEY, doc TEXT NOT NULL, issued_at TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS messages (
  id TEXT PRIMARY KEY, from_device TEXT NOT NULL, from_user TEXT NOT NULL, to_user_id TEXT NOT NULL,
  created_at TEXT NOT NULL, signature TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS message_envelopes (
  message_id TEXT NOT NULL, device_id TEXT NOT NULL, xwing_ct TEXT NOT NULL, ciphertext TEXT NOT NULL,
  PRIMARY KEY (message_id, device_id));

CREATE TABLE IF NOT EXISTS incident_files (
  incident_id TEXT NOT NULL, file_id TEXT NOT NULL, from_version INTEGER NOT NULL, category TEXT NOT NULL,
  rekey TEXT NOT NULL, new_version INTEGER, PRIMARY KEY (incident_id, file_id));
