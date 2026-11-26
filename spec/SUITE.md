# Suite QG-1 (normative)

This document fixes every byte that two QuantumGuard implementations must agree on. A second
implementer (the TypeScript browser client) must be able to produce byte-identical results from
this file and `spec/vectors/` alone. Where this file and `spec/API.md` disagree on a route or field
name, `spec/API.md` wins; where they disagree on bytes, this file wins.

Words: MUST, MUST NOT, SHOULD as in RFC 2119. `||` is byte concatenation. `u32be(n)` is the
4-byte big-endian encoding of `n`. `ascii("x")` is the ASCII bytes of a literal. `utf8(s)` is the
UTF-8 encoding of a string. Every literal string in this file is ASCII.

## 1. Algorithms

| Use | Algorithm | Exact reference |
|---|---|---|
| Hybrid KEM | X-Wing | `draft-connolly-cfrg-xwing-kem-11` (23 September 2026). Seed-form 32-byte decapsulation key, 1216-byte encapsulation key, 1120-byte ciphertext, 32-byte shared secret. Combiner `SHA3-256(ss_M \|\| ss_X \|\| ct_X \|\| pk_X \|\| 5c2e2f2f5e5c)` (label last) |
| ML-KEM inside X-Wing | ML-KEM-768 | FIPS 203 |
| Device and server signatures | ML-DSA-65 | FIPS 204, pure (not HashML-DSA), hedged signing, always with a context string (section 4) |
| Second signature on trust records | Ed25519 | RFC 8032, pure Ed25519 (not Ed25519ph, not Ed25519ctx) |
| Bulk encryption, wrapping, sealing, keystore | AES-256-GCM | 12-byte nonce, 16-byte tag, tag appended to ciphertext |
| Key derivation | HKDF-SHA-384 | RFC 5869 |
| Key confirmation and request MAC | HMAC-SHA-384 | RFC 2104, full 48-byte tag, never truncated |
| Hashes of data and the log | SHA-256 | FIPS 180-4 |
| Log | Merkle tree | RFC 6962 section 2.1 (leaf prefix `0x00`, node prefix `0x01`) |
| Keystore passphrase | Argon2id | RFC 9106, version `0x13` |

There is no negotiation. Every signed, hashed or stored object carries `"suite": "QG-1"`. Any
other value MUST be rejected (`QG_BAD_SUITE`; server raises rule QG-R014). The server checks every `suite`
member at any depth of a request body (a manifest or share statement inside a commit included).

### 1.1 X-Wing in QG-1

- Key generation: `sk = random(32)`; `expanded = SHAKE256(sk, 96 bytes)`;
  ML-KEM-768 key from `d = expanded[0:32]`, `z = expanded[32:64]` (FIPS 203 `KeyGen_internal`;
  libraries that take a 64-byte seed take `d || z = expanded[0:64]`);
  `sk_X = expanded[64:96]`; `pk = pk_M (1184) || X25519(sk_X, 9) (32)`.
- Encapsulation and decapsulation exactly as the draft sections 5.4 and 5.5.
- A device's KEM private key is stored as the 32-byte seed `sk` only. The expanded key MUST NOT
  leave the process.
- Test vectors: `spec/vectors/xwing.json` (the three vectors from Appendix C of the draft, copied
  verbatim). Python checks key generation, decapsulation and the X25519 half of encapsulation
  (`cryptography` exposes no derandomized ML-KEM encapsulation); a client that has
  `EncapsulateDerand` MUST also check `ct` and `ss` from `eseed`.

### 1.2 ML-DSA-65 in QG-1

- Private keys are stored as the 32-byte seed `xi` (FIPS 204 `KeyGen_internal`). Public key 1952
  bytes, signature 3309 bytes.
- Signing is hedged (randomized). Signatures are therefore not reproducible; vectors list
  signatures that MUST verify and mutated ones that MUST NOT.

## 2. Encodings

### 2.1 Binary values

Every binary value in JSON is **base64url without padding** (RFC 4648 section 5, `=` omitted),
written `b64u`. Decoders MUST reject: `=` characters, characters outside `A-Z a-z 0-9 - _`,
a length whose remainder mod 4 is 1, and non-canonical encodings (the unused low bits of the last
character are not zero). Equivalently: decode, re-encode, and reject unless the result equals the
input. Hex appears in exactly one place (the request MAC body hash, section 6), lower case.

### 2.2 Canonical JSON

`canon(x)` is RFC 8785 (JCS) restricted as follows; both implementations MUST reject values outside
the restriction rather than try to encode them.

- Allowed values: object, array, string, `true`, `false`, `null`, and integers in
  `[-(2^53-1), 2^53-1]`. **No floating-point numbers** (a number with `.`, `e` or `E` is rejected),
  no `-0`.
- Object keys are ASCII strings, unique, sorted by byte value. Members are written `"key":value`
  separated by `,` with no whitespace anywhere.
- Strings: UTF-8, no lone surrogates. Escape `"` as `\"`, `\` as `\\`, U+0008 `\b`, U+0009 `\t`,
  U+000A `\n`, U+000C `\f`, U+000D `\r`, other code points below U+0020 as `\u00XX` with lower-case
  hex. Every other code point, including `/`, U+007F and non-ASCII, is written as raw UTF-8.
- Integers in shortest decimal form, `-` only for negatives, no leading zeros, no `+`.

Vectors: `spec/vectors/canonical_json.json` (`valid`: input value and exact output bytes;
`invalid`: inputs that MUST be rejected).

### 2.3 Identifiers and times

- Ids: prefix (`usr_ dev_ fil_ slt_ ses_ inv_ rcp_ inc_ alr_ rsp_ chg_ svc_ key_ msg_ sig_ enr_
  lse_ sst_`) followed by the 22-character b64u encoding of 16 random bytes. `sst_` names a pending
  session start. The recovery key's pseudo device id is the literal `recovery`.
- Times: RFC 3339 UTC with exactly three fractional digits and `Z`, e.g.
  `2026-11-26T12:00:00.000Z`. Times are strings in every signed object. Server time is
  authoritative.

## 3. Key derivation (every HKDF call)

All calls are HKDF-SHA-384. An "empty" salt is the zero-length string, which RFC 5869 makes
identical to 48 zero bytes.

| Name | IKM | Salt | Info (ASCII) | Length |
|---|---|---|---|---|
| Enrolment confirmation key `K_ec` | X-Wing `ss` from `/enroll/start` | `challenge` (32 bytes) | `QG/v1/enroll/confirm` | 48 |
| Session confirmation key `K_sc` | X-Wing `ss` from `/session/start` | `challenge` (32 bytes) | `QG/v1/session/confirm` | 48 |
| Session MAC key `K_mac` | same `ss` | `challenge` | `QG/v1/session/mac` | 48 |
| Wrap key `KEK` (DEK wrap, section 7.2) | X-Wing `ss` for that recipient | empty | `QG/v1/wrap` | 32 |
| Seal key for epoch `e` (server only) | 32-byte server seal master key | empty | `QG/v1/seal/` followed by decimal `e` | 32 |
| Message key (section 11) | X-Wing `ss` for that device | empty | `QG/v1/message` | 32 |

## 4. Signatures and contexts

Each signature has a purpose `p`. The context is `ctx = ascii("QG/v1/" + p)`.

| Purpose `p` | Signer | Signs |
|---|---|---|
| `enroll` | device ML-DSA | enrolment transcript (5.1) |
| `session` | device ML-DSA | session transcript (5.2) |
| `manifest` | device ML-DSA | upload manifest (7.4) |
| `share` | device ML-DSA | share statement (7.5) |
| `change` | device ML-DSA | change request and approval statements (10) |
| `message` | device ML-DSA | message statement (11) |
| `certificate` | server, dual | device certificate (8.2) |
| `directory` | server, dual | directory (8.3) |
| `checkpoint` | server, dual | log checkpoint (9.3) |
| `keyset` | server, dual | service key set (12) |
| `policy` | server, dual | policy bundle (13) |
| `report` | server, dual | proof bundle (9.5) |

Signing input `M` for an object is `canon(object)` where the object excludes its own signature
field (`signatures` for dual-signed objects; detached signatures are sent beside the object).

- ML-DSA-65: `sig = ML-DSA.Sign(sk, M, ctx)` (FIPS 204 Algorithm 2 with context string `ctx`).
- Ed25519: `sig = Ed25519.Sign(sk, ctx || 0x00 || M)`.

**Dual-signature rule.** A dual-signed object carries
`"signatures": {"ed25519": b64u, "mldsa": b64u}`. A verifier MUST verify **both** under the
server's `ed25519_pk` and `mldsa_pk` and MUST reject the object if either is missing, malformed
or invalid. There is no "either one is enough" mode and no other key in `signatures` is allowed.

Server public keys come from `GET /api/v1/meta` (`server_keys.ed25519_pk`, `server_keys.mldsa_pk`,
both b64u raw public keys: 32 and 1952 bytes). Offline verifiers take them from a pinned file and
SHOULD warn when they only have keys embedded in the bundle being verified.

## 5. Transcripts

### 5.1 Enrolment

1. Client: generate `sig` (ML-DSA-65) and `kem` (X-Wing) keys locally. `POST /enroll/start`
   `{suite, code, device_name, kem_pk, sig_pk}` (`kem_pk` 1216 bytes, `sig_pk` 1952 bytes, b64u).
2. Server: `challenge = random(32)`; `(ss, xwing_ct) = XWing.Encapsulate(kem_pk)`; reply
   `{enroll_id, challenge, xwing_ct, user:{user_id, name, roles[]}, directory_epoch, server_time}`.
3. Both sides build the transcript `T_e = canon(` 

   ```
   {"challenge": b64u, "device_name": str, "directory_epoch": int, "enroll_id": str,
    "kem_pk": b64u, "purpose": "enroll", "server_time": str, "sig_pk": b64u,
    "suite": "QG-1", "user_id": str, "xwing_ct": b64u}
   ```
   `)` using exactly the values sent and received (strings compared byte for byte).
4. Client: `ss = XWing.Decapsulate(xwing_ct, kem_sk)`; `K_ec` per section 3;
   `signature = ML-DSA.Sign(sig_sk, T_e, "QG/v1/enroll")`; `key_confirm = HMAC-SHA-384(K_ec, T_e)`.
   `POST /enroll/finish {enroll_id, signature, key_confirm}`.
5. Server verifies both (HMAC compared in constant time); either failing answers
   `QG_BAD_SIGNATURE` / `proof_failed`. This proves possession of both private keys. The enrol
   state is single use and expires with the invite.

### 5.2 Session

1. `POST /session/start {suite, device_id}` ->
   `{start_id, challenge, xwing_ct, directory_epoch, server_time}`. For an unknown or revoked
   device the server answers the same shape with random `xwing_ct` (1120 bytes).
2. `T_s = canon(`

   ```
   {"challenge": b64u, "device_id": str, "directory_epoch": int, "purpose": "session",
    "server_time": str, "start_id": str, "suite": "QG-1", "xwing_ct": b64u}
   ```
   `)`.
3. Client: decapsulate; derive `K_sc` and `K_mac`; `signature = ML-DSA.Sign(sig_sk, T_s,
   "QG/v1/session")`; `key_confirm = HMAC-SHA-384(K_sc, T_s)`. `POST /session/finish
   {start_id, signature, key_confirm}`.
4. Server checks the device against the current directory (active, not revoked, not expired),
   then both proofs. Revoked device: `QG_DENY_REVOKED` (QG-R001). Otherwise any failure:
   `QG_BAD_SIGNATURE`. A start is single use and lives 60 seconds.
5. Session: idle TTL 600 s, sliding, hard cap 3600 s from `session/finish`. The client keeps
   `K_mac` in memory only.

## 6. Request MAC

Every authenticated request carries `QG-Session`, `QG-Seq`, `QG-MAC`.

```
mac_input = utf8(METHOD) || 0x0a || utf8(PATH) || 0x0a || utf8(SEQ) || 0x0a || utf8(hex(SHA-256(body)))
QG-MAC    = b64u(HMAC-SHA-384(K_mac, mac_input))
```

- `METHOD`: upper case (`GET`, `POST`, `PUT`, `PATCH`, `DELETE`).
- `PATH`: the request target exactly as sent on the wire: path plus `?` plus query when a query is
  present, percent-encoding untouched, starting with `/api/v1/`. No scheme, no host, no fragment.
- `SEQ`: the `QG-Seq` header value, decimal, no sign, no leading zeros, `1 <= SEQ <= 2^53-1`.
- body hash: lower-case hex SHA-256 of the exact body bytes (the empty body hashes to
  `e3b0c442...b855`). No trailing newline after the hash.
- Server order of checks: session exists (`QG_NO_SESSION`), MAC (`QG_BAD_MAC`, QG-R012), sequence
  strictly greater than the last accepted (`QG_REPLAY`, QG-R002, session ended), device still
  active (`QG_DENY_REVOKED`, QG-R001). A request with a bad MAC does not advance the sequence.
- `request_hash` in receipts is `b64u(SHA-256(mac_input))`. For public routes the same layout is
  hashed with `SEQ = 0`.
- **Revoked sessions.** Revocation ends the device's sessions in its transaction, but the server keeps each
  ended session's `K_mac` in memory until that session's hard expiry. A later request on such a session is
  recorded as a denied attempt (receipt, incident timeline, QG-R001) only if its MAC verifies under that key
  with a sequence number above any seen before, at most 5 per session then one per 5 s. Any other request
  naming the session answers `QG_NO_SESSION` and writes nothing. Likewise `/session/finish` for a revoked
  device records an attempt only when the transcript signature verifies under that device's `sig_pk`;
  otherwise it answers `QG_BAD_SIGNATURE` and writes nothing about the device.
- **Failures that prove no key** (a bad request MAC, a failed handshake proof) are attributed to their
  *source*: the caller's network address together with the device (or, for enrolment, the person) they claim,
  never to that device or session itself. They feed QG-R012 through a per-address bucket (10, then one per
  second). Five in 60 s raise one alert whose response is `throttle` with scope `source` and id
  `<address>|<claim>`, for 300 s, liftable by an operator; repeats merge into that alert while it is active.
  While it is active, further *failed* proofs and bad MACs from that address for that claim answer
  `QG_RATE_LIMITED` / `source_throttled` (or `QG_BAD_MAC`) without being recorded again. A correct proof is
  always verified first and accepted, so nobody is refused because of someone else's failures, and other
  devices behind the same address are unaffected. Signature failures on an authenticated session (manifest,
  share, change, approval, message) throttle that session. No address range is ever blocked.
- **Client address behind a proxy.** The address is the TCP peer unless `QG_TRUSTED_PROXIES` (comma-separated
  addresses, default `127.0.0.1`) names the peer, in which case `X-Forwarded-For` is used. A deployment behind
  a reverse proxy (the TLS profile's Caddy, the Cloudflare Worker) must set it to the proxy's address and must
  have the proxy overwrite, not append to, client-supplied forwarding headers.

Vectors: `spec/vectors/request_mac.json`.

## 7. Files

### 7.1 Chunks

- A file version has a fresh random 32-byte DEK and a fresh random 8-byte nonce prefix `P`.
- Plaintext is split into chunks of exactly `chunk_bytes = 1048576` bytes; the last chunk holds
  the remainder (1 to 1048576 bytes). An empty file is one empty chunk. `chunk_count >= 1`.
- Chunk `i` (from 0): `nonce_i = P || u32be(i)`;
  `aad_i = canon({"chunk_index": i, "file_id": str, "is_last": bool, "suite": "QG-1", "version": int})`;
  stored blob `C_i = nonce_i || AES-256-GCM-Encrypt(DEK, nonce_i, chunk_i, aad_i)` (12 + len + 16).
- A reader MUST check `nonce_i[8:12] == u32be(i)`, that `P` is the same in every chunk, that the
  chunk marked `is_last` is chunk `chunk_count - 1`, and MUST stop at the first failure.
  Reordering, truncation and bit flips all fail authentication.
- `ciphertext_sha256 = b64u(SHA-256(C_0 || C_1 || ... || C_{n-1}))`.

### 7.2 DEK wrap (inner wrap)

For recipient device `D` with X-Wing key `kem_pk` (for the recovery wrap: `recovery_pk` and
`device_id = "recovery"`):

```
(ss, xwing_ct) = XWing.Encapsulate(kem_pk)
KEK          = HKDF-SHA-384(ikm=ss, salt=empty, info="QG/v1/wrap", L=32)
binding      = {"device_id": D, "directory_epoch": int, "file_id": str, "suite": "QG-1", "version": int}
aad          = canon(binding)
n            = random(12)
wrapped_dek  = n || AES-256-GCM-Encrypt(KEK, n, DEK, aad)          # 60 bytes
inner_wrap   = {"xwing_ct": b64u(xwing_ct), "wrapped_dek": b64u(wrapped_dek)}
```

`directory_epoch` in the binding is the manifest's `directory_epoch` for a wrap made at commit, and the
share statement's `directory_epoch` for a wrap added by `/share`. The server stores it with the slot and
returns it as `wrap_epoch` from `GET /files/{id}/slot`. A wrap moved to another file, version or device
fails to open because the AAD differs.

### 7.3 Outer seal (server side, documented for review)

The server never stores an inner wrap in the clear. For slot `slot_id`:
`seal_key_e` per section 3 (`e` = current seal epoch, an integer that increases when the seal
master key rotates), `aad = canon({"device_id", "file_id", "seal_epoch": e, "slot_id", "suite":
"QG-1", "version"})`, `sealed = n || AES-256-GCM-Encrypt(seal_key_e, n, canon(inner_wrap), aad)`
with `n = random(12)`. A sealed blob copied to another slot, file, version or device fails to
unseal. The seal master key lives in `QG_KEYS_DIR`, never in the database.

### 7.4 Manifest

```
manifest = {"chunk_count": int, "ciphertext_sha256": b64u, "classification": "internal"|"confidential"|"restricted",
            "directory_epoch": int, "file_id": str, "recipients": [device_id, ...],
            "suite": "QG-1", "version": int}
manifest_sig = b64u(ML-DSA.Sign(device_sig_sk, canon(manifest), "QG/v1/manifest"))
```

`recipients` is sorted ascending by byte value, unique, never contains `recovery`, and MUST equal
the set of `device_id` in the commit's `wraps`. Only the owner's devices create or commit versions after
the first (`reason: "update"` or `"rekey"`), because the server cannot check that re-encrypted content is
unchanged; any other holder gets `QG_DENY_POLICY` / `owner_required`. The recovery wrap therefore always comes
from the owner. A re-key committed while a job is pending MUST name exactly the active devices holding a slot
on the current version (`QG_DENY_POLICY` / `recipient_not_allowed`), so nobody is dropped and nobody removed
by an unshare or revocation is added back. `/rekey/pending` lists re-key jobs to the owner's devices only;
a job waits (and its incident stays `rekeying`) until an owner device runs it. The recovery wrap is always present and separate.
The server verifies the signature against the committing device's `sig_pk`, the hash and chunk
count against the stored chunks, every recipient against policy, and the epoch (section 8.4).

### 7.5 Share statement

```
share     = {"directory_epoch": int, "file_id": str, "recipients": [device_id, ...], "suite": "QG-1", "version": int}
share_sig = b64u(ML-DSA.Sign(device_sig_sk, canon(share), "QG/v1/share"))
```

`recipients` are only the devices being added (sorted, unique) and equal the `wraps` device ids.
`version` is the current committed version. The sharing device must hold a slot for that version.

### 7.6 Opening

The opener calls `GET /files/{id}/slot`, verifies `manifest_sig` under the signer's `sig_pk` from a
directory it trusts, decapsulates `xwing_ct`, derives `KEK`, opens `wrapped_dek` with the binding
`{device_id: self, directory_epoch: wrap_epoch, file_id, suite, version}` (`wrap_epoch` from the slot
response; it equals `manifest.directory_epoch` unless the wrap came from a share), then
downloads chunks with `QG-Lease`, checks `ciphertext_sha256` and decrypts per 7.1.

Vectors: `spec/vectors/envelope.json` (full file: DEK, `P`, plaintext, chunk blobs, hash; a wrap
with its `ss`, `KEK`, nonce and output; negative cases).

### 7.7 Recovery kit

The recovery kit is an X-Wing key pair whose private half the server never holds.
`python -m qg.admin recovery-kit init [--out PATH]` generates it, writes the private half (format
`qg-recovery-kit/1`: `{format, suite, created_at, kem_seed, recovery_pk, note}`) to its own stdout or to
`PATH` (refused inside the data or keys volume, mode 0600), and only then stores the public half in the
keys volume and publishes a directory epoch carrying `recovery_pk`. A second run is refused.

- Before a kit exists `recovery_pk` is `null` in `GET /meta` and the directory, and a commit must not carry
  `recovery_wrap`. Afterwards every commit must carry it (`QG_INVALID_INPUT` / `recovery_wrap_required`).
- `POST /files/{id}/recover {change_id}` (admin, applied `recovery_release` with two approvals) returns the
  unsealed recovery wrap with `wrap_epoch`, `version`, `manifest`, `manifest_sig`, `signer_device_id` and a
  recovery lease (`lease:{lease_id, expires_at}`) bound to the caller's session for chunk downloads. Each
  change releases once. The kit holder unwraps with binding `device_id = "recovery"`.
- A copy of the data and keys volumes can unseal the outer seal of a recovery slot but cannot open the inner
  wrap: the kit's private key is in neither volume.

## 8. Directory

### 8.1 Epochs

The directory has an integer `epoch` starting at 1 that increases by exactly 1 for every change
(enrolment, revocation, rename, role change, quarantine). `prev_hash` is
`b64u(SHA-256(canon(previous directory including its signatures)))`; epoch 1 has `prev_hash` of
32 zero bytes. Clients store the highest epoch seen and MUST refuse a lower one.

### 8.2 Device certificate

`certificate = {"created_at", "device_id", "directory_epoch", "expires_at", "kem_pk", "name",
"sig_pk", "suite": "QG-1", "user_id", "signatures": {...}}`, dual-signed with purpose
`certificate`. `directory_epoch` is the epoch that first published the device. `expires_at` is
365 days after `created_at`.

### 8.3 Directory object

As `spec/API.md` 3.1, with `recovery_pk` `null` until a recovery kit is issued (7.7). `users` sorted by
`user_id`, each `roles` sorted; `devices` (certificate
fields without signatures) sorted by `device_id`; `revoked` sorted by `device_id`. Dual-signed,
purpose `directory`, signing input `canon(directory without "signatures")`.

### 8.4 Epoch grace

An object that names a `directory_epoch` (manifest, share, change) is accepted when that epoch is
the current one, or an older one that was superseded less than 60 seconds ago **and** no device
revocation happened after it. Otherwise `QG_STALE_EPOCH` (QG-R003).

## 9. Evidence log

### 9.1 Receipts and leaves

A receipt is the object of `spec/API.md` 3.4 including `suite` and `leaf_index`. The leaf for index
`i` is `leaf_i = canon(receipt_i)`. Hashes:

```
leaf_hash(i)  = SHA-256(0x00 || leaf_i)
node(l, r)    = SHA-256(0x01 || l || r)
MTH({})       = SHA-256("")
MTH({d0})     = leaf_hash(d0)
MTH(D[0:n])   = node(MTH(D[0:k]), MTH(D[k:n]))   where k is the largest power of two < n
```

Receipt fields fixed by QG-1: `key_epoch` is the file version (key generation) the decision concerned, or
0 when the decision is not about a file. A refused request writes a `deny` receipt even though the request
fails; the receipt id is returned in the error body and in `QG-Receipt`. A request from a revoked device on a
route with no more specific action uses action `access`.

Inclusion proofs and consistency proofs are those of RFC 6962 section 2.1.1 and 2.1.2; verify with
RFC 9162 sections 2.1.3.2 and 2.1.4.2. All hashes are b64u in JSON.

### 9.2 Proof routes

`GET /log/proof/{index}?tree_size=n` -> `{leaf_index, tree_size, leaf_hash, audit_path: [b64u],
checkpoint}`; `audit_path` is ordered from the leaf upward. `GET /log/consistency?from=&to=` ->
`{from, to, proof: [b64u]}`.

### 9.3 Checkpoints

`checkpoint = {"root_hash": b64u, "suite": "QG-1", "tree_size": int, "ts": str, "signatures":
{...}}`, dual-signed with purpose `checkpoint`. The server emits one at most every second when
receipts are waiting, after 256 receipts, and immediately inside every revocation. Signatures are
made once per checkpoint, never per receipt.

### 9.4 Offline verification (`qg verify`)

Inputs: a proof bundle and pinned server public keys. Steps, stopping at the first failure:
1. bundle `format` and `suite`; 2. the checkpoint's dual signature; 3. each entry in `leaf_index` order:
recompute `leaf_hash` from `canon(receipt)`, compare with `entries[k].leaf_hash`, and walk `audit_path` to
`checkpoint.root_hash` at `checkpoint.tree_size`; 4. the bundle's own dual signature (purpose `report`);
5. the revocation checkpoint's signature and the consistency proof from it to `checkpoint`; 6. the
directory's dual signature. Entries are checked before the bundle signature so that a modified receipt is
reported with its index: the result names the first bad `leaf_index`.

### 9.5 Proof bundle

```
{"format": "qg-proof-bundle/1", "suite": "QG-1", "incident_id": str, "generated_at": str,
 "server_keys": {"ed25519_pk": b64u, "mldsa_pk": b64u},
 "checkpoint": Checkpoint,                    // the newest checkpoint at export
 "revocation_checkpoint": Checkpoint,         // the one forced by the revocation
 "consistency": [b64u],                       // from revocation_checkpoint.tree_size to checkpoint.tree_size
 "directory": Directory,                      // the epoch published by the revocation
 "exposure": Exposure,                        // spec/API.md section 7
 "entries": [{"leaf_index": int, "leaf_hash": b64u, "receipt": Receipt, "audit_path": [b64u]}],
 "signatures": {"ed25519": b64u, "mldsa": b64u}}   // purpose "report", over everything else
```

`entries` holds every receipt of the incident (the revoke, every slot release to the device,
every denied attempt and every re-key commit) sorted by `leaf_index`, each with its inclusion path
against `checkpoint`.

Vectors: `spec/vectors/merkle.json` (leaf hashes, roots for sizes 0 to 9, inclusion and
consistency proofs) and `spec/vectors/checkpoint.json` (a checkpoint and keys; mutations that
MUST fail).

## 10. Changes and approvals

```
change    = {"directory_epoch": int, "file_id": str|null, "reason": str, "role": str|null,
             "suite": "QG-1", "target_user_id": str, "type": "role_grant"|"role_revoke"|"recovery_release"}
signature = b64u(ML-DSA.Sign(device_sig_sk, canon(change), "QG/v1/change"))
approval  = {"change_hash": b64u(SHA-256(canon(change))), "change_id": str, "decision": "approve",
             "purpose": "approve", "suite": "QG-1"}
approve signature = b64u(ML-DSA.Sign(approver_device_sig_sk, canon(approval), "QG/v1/change"))
```

The `purpose` member keeps an approval from ever being parsed as a change. A `Change` returned by the
API carries `change` (the exact signed statement), `signature` and `change_hash`; an approver verifies
`signature` under the requester's certificate and recomputes `change_hash` before signing the approval
statement above. Changes created by the server on an admin's behalf (inviting a person with a
privileged role) carry `signature: ""` and are attributed to the admin's session receipt instead.

## 11. Messages

For each recipient device: `(ss, xwing_ct) = XWing.Encapsulate(kem_pk)`; key per section 3;
`ciphertext = n || AES-256-GCM-Encrypt(key, n, plaintext, canon({"device_id", "suite": "QG-1",
"to_user_id"}))`, `n = random(12)`.

The sender signs one digest per envelope, so any single recipient device can check the signature from its own
envelope and the digests, without seeing other devices' ciphertext:

```
envelope_digest(e) = b64u(SHA-256(canon({"ciphertext": e.ciphertext, "device_id": e.device_id,
                                          "xwing_ct": e.xwing_ct})))          # b64u strings exactly as sent
statement = canon({"envelope_digests": [{"device_id", "digest"} for every envelope, sorted by device_id],
                   "suite": "QG-1", "to_user_id": str})
signature = b64u(ML-DSA.Sign(sender_sig_sk, statement, "QG/v1/message"))
```

The server recomputes the digests from the envelopes it receives and refuses a signature that does not
verify (`QG_BAD_SIGNATURE`). `GET /messages` returns to each device only its own envelope plus
`envelope_digests` (every envelope's digest) and `to_user_id`. The recipient checks that the digest of its own
envelope is listed for its `device_id`, rebuilds `statement` from `envelope_digests` and its own `user_id`, and
verifies the signature under the sender device's `sig_pk` from the current directory before decrypting.

Vectors: `spec/vectors/messages.json`.

## 12. Service key set

`{"epoch": int, "keys": [{"alg": "ML-DSA-65", "key_id", "public_key": b64u, "service_id",
"status": "active"|"retiring"|"retired"}] sorted by key_id, "suite": "QG-1", "signatures"}`,
dual-signed with purpose `keyset`. `epoch` increases on every rotation.

A request to any authenticated route may attribute itself to a service key with the header
`QG-Service-Key: key_...` (checked by the gateway on every route). A key in
status `retiring` is accepted for 600 seconds after rotation, then becomes `retired`; a retired key answers
`QG_DENY_POLICY` / `key_retired` (QG-R010); a decoy key raises QG-R004. Emergency rotation retires every
earlier key at once.

## 12a. Revocation side effects and automatic responses

- The revocation transaction also cancels every pending enrolment code that is for the device's person, or
  was created by that person (on any device) or by that device, for anyone. The person mints a new code from
  a trusted device. Devices already enrolled with a code before the report are not revoked by it (limit:
  the operator reviews recent enrolments).
- An automatic response cannot be lifted by the person it contains (its session, one of their devices, or
  their identity): `QG_DENY_POLICY` / `self_lift`. An admin may lift a response that contains an operator.

## 13. Policy bundle

`rules.yaml` is parsed into the JSON document `{"rules": [...], "suite": "QG-1", "version": int}`.
`policy_bundle_hash = b64u(SHA-256(canon(document)))`. The server signs exactly `canon(document)` dual
with purpose `policy` at first start (`signed_at` is reported beside the signatures, not inside them).
`GET /policy` returns `document = b64u(canon(document))` so a client can recompute the hash and verify
the signatures over those bytes. If the loaded file does not match the stored signature the policy
engine is unavailable and every decision fails closed, except that a bundle whose integer `version` is
higher than the stored one (shipped with a newer build) is signed once at start and recorded as an upgrade
(`policy_bundle_upgraded`). A changed bundle with the same or a lower version is never accepted. Every receipt carries `policy_bundle_hash`.

## 14. Signals (SET shaped)

`POST /signals` takes the JSON claims of a Security Event Token (RFC 8417) without JWS framing; it
is authenticated by the session MAC of an operator or a service identity.

```
{"iss": str, "jti": str (1..128 chars), "iat": int (seconds), "aud": "quantumguard",
 "events": {<one event type>: {"subject": {"format": "opaque", "id": "dev_...|usr_..."},
                               "event_timestamp": int (seconds), ...event fields}}}
```

Exactly one event per token. Accepted event types:

| Event type URI | Extra fields | Effect |
|---|---|---|
| `https://schemas.openid.net/secevent/caep/event-type/session-revoked` | `reason_admin?` | End every session of the subject device or person |
| `https://schemas.openid.net/secevent/caep/event-type/credential-change` | `credential_type: "device"`, `change_type: "revoke"`, `reason_admin?` | Revoke the subject device (compromise time = `event_timestamp`) |
| `https://schemas.openid.net/secevent/caep/event-type/device-compliance-change` | `previous_status`, `current_status: "compliant"|"not-compliant"` | Quarantine or release the subject device |
| `urn:qg:event-type:privilege-observed` | `role` | Identity source reports a role for a person; with no applied signed change for it, QG-R005 fires |

`jti` is deduplicated (`duplicate: true`, no second effect). Events older than the newest already
applied for the same subject and type are recorded but not applied (out-of-order delivery).

## 15. Keystore file (`*.qgkeystore`, CLI and browser)

```
{"format": "qg-keystore/1", "suite": "QG-1",
 "kdf":  {"alg": "argon2id", "version": 19, "m_kib": 19456, "t": 2, "p": 1, "salt": b64u(16 bytes)},
 "aead": {"alg": "AES-256-GCM", "nonce": b64u(12 bytes)},
 "label": {"user_id": str|null, "device_id": str|null, "device_name": str, "server": str|null, "created_at": str},
 "ciphertext": b64u}
```

- `key = Argon2id(password = utf8(NFC(passphrase)), salt, t, m_kib, p, tag length 32)`, no secret,
  no associated data.
- `header = the object without "ciphertext"`; `aad = canon(header)`.
- `plaintext = canon({"kem_seed": b64u(32), "sig_seed": b64u(32)})`;
  `ciphertext = AES-256-GCM-Encrypt(key, nonce, plaintext, aad)`.
- Readers MUST reject parameters outside `19456 <= m_kib <= 1048576`, `2 <= t <= 10`,
  `1 <= p <= 4`, so a hostile file cannot exhaust memory. A wrong passphrase and a modified header
  fail the same way.
- Changing the label (for example after enrolment assigns `device_id`) re-encrypts with a fresh
  nonce.

Vectors: `spec/vectors/keystore.json`.

## 16. Leases, limits and first start

- `GET /files/{id}/slot` issues a lease (`lse_`) bound to session, device, file and version, valid
  60 s. `GET /files/{id}/chunks/{n}` requires `QG-Lease` and checks it on every chunk; revocation,
  quarantine and a new version cancel leases.
- Limits (also in `GET /meta`): `chunk_bytes` 1048576, `max_file_bytes` 104857600,
  `max_recipients` 32, `lease_seconds` 60, `session_ttl_seconds` 600,
  `session_hard_cap_seconds` 3600. JSON bodies at most 256 KiB and nesting depth 16.
- Invites: single use, 15 minutes, server stores `SHA-256(normalised code)` only. Codes are 16
  characters of Crockford base32 (`0-9 A-Z` without `I L O U`, 80 bits from 10 random bytes) shown in
  four groups, e.g. `K7QM-2XVD-9RTA-HB4N`. Before hashing the server normalises what it receives:
  trim, upper-case, drop hyphens and spaces, read `O` as `0` and `I` or `L` as `1` (`spec/API.md` 4.1).
- The server never prints or logs a code. Codes for the seeded people come only from the local command
  `python -m qg.admin invite --all --json` (or `--user-id`), printed to that command's own stdout.
- **Deviation:** those admin-issued codes for seeded people are single use but live **24 hours**, so an
  evaluator has time to use them; issuing a new one for a person cancels that person's previous one. Every
  invite created through the API lives 15 minutes.
- The recovery kit is issued once by `python -m qg.admin recovery-kit init` (section 7.7). Until then
  `recovery_pk` is `null` and commits carry no recovery wrap.

## 17. Vector files

| File | Contents | Source |
|---|---|---|
| `xwing.json` | 3 vectors: seed, pk, eseed, ct, ss | draft-connolly-cfrg-xwing-kem-11 Appendix C |
| `mlkem768.json` | key generation (d, z -> ek) and decapsulation (64-byte seed, c -> k, including implicit rejection and malformed lengths) | NIST ACVP `ML-KEM-keyGen-FIPS203`; C2SP Wycheproof `mlkem_768_test.json` |
| `mldsa65.json` | key generation (seed -> pk) and signature verification with context | NIST ACVP `ML-DSA-keyGen-FIPS204`, `ML-DSA-sigVer-FIPS204` |
| `canonical_json.json` | canonical JSON cases | QuantumGuard |
| `request_mac.json` | MAC inputs and tags | QuantumGuard |
| `transcripts.json` | enrol and session transcripts, derived keys, confirmations | QuantumGuard |
| `envelope.json` | chunks, wraps, manifest | QuantumGuard |
| `keystore.json` | keystore files with their passphrases | QuantumGuard |
| `merkle.json`, `checkpoint.json` | log hashing and signatures | QuantumGuard |
| `messages.json` | message envelopes, digests, signed statement | QuantumGuard |

All values in vector files are hex (lower case) unless the field name ends in `_b64u` or the value
is a JSON object defined by this file, in which case it is exactly as it appears on the wire.
