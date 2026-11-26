// Copy for the public page. Kept apart from layout so the wording can be checked
// against THREAT_MODEL.md and the build plan in one place.

export const LIMITS = [
  'Anything a device already decrypted before it was revoked. We list it; we cannot recall it.',
  'A person who is tricked into opening a file for an attacker, or malware on a device that is currently authorised and unlocked.',
  'A weak passphrase on a stolen device, beyond the cost that slow key derivation imposes and the time it buys to revoke.',
  'Hardware-level key protection. The prototype stores keys in software; a production version would use a secure element or hardware module.',
  'Metadata. The backend knows who opened which file and when; that is what makes the exposure report possible.',
  'Availability against a determined flood. We rate-limit and fail closed, which protects data, not uptime.',
  'Side-channel attacks on the cryptographic libraries, which we rely on the library authors to address.',
]

export const PROBLEMS = [
  {
    title: 'A lost device is still trusted',
    body: 'A session or a cached token keeps working after the laptop is gone. Changing a password does nothing for a key the device already holds.',
  },
  {
    title: 'Permission outlives the decision',
    body: 'Access is checked once and assumed afterwards. Nothing re-asks whether this device, this person and this policy are still good at the moment a key is used.',
  },
  {
    title: 'Recorded today, decrypted later',
    body: 'Traffic and backups captured now can be opened once a large quantum computer exists, if the key exchange was classical only.',
  },
  {
    title: 'Logs you have to take on faith',
    body: 'After an incident the only account of what happened is a log its own operator could have edited.',
  },
]

export const PRODUCT = [
  {
    group: 'Protect',
    items: [
      ['Encrypted on the device', 'Files are sealed in 1 MiB blocks with AES-256-GCM before anything is sent. The server stores ciphertext.'],
      ['Two locks, two holders', 'The file key is wrapped for one device, then sealed again by the server. Neither can open a file alone.'],
      ['Hybrid key exchange', 'X25519 and ML-KEM-768 together, following the X-Wing construction. An attacker has to break both.'],
    ],
  },
  {
    group: 'Control',
    items: [
      ['Decided at the moment of use', 'Every key release is a fresh policy decision against the current device list. Default is deny.'],
      ['Revocation in one transaction', 'Reporting a device lost deletes its key slots and sessions and publishes a new signed device list together.'],
      ['Two people for sensitive changes', 'Granting an admin or operator role, or releasing a recovery slot, needs someone other than the requester.'],
    ],
  },
  {
    group: 'Detect',
    items: [
      ['Fourteen explainable rules', 'Rules, simple statistics and a privilege graph. No machine learning. Every alert names its rule and the receipts that matched.'],
      ['Scoped automatic responses', 'A response touches one session, device or identity, has an end time, and an operator can lift it.'],
      ['Exposure, not guesswork', 'For a lost device: which files it opened after the loss time, which it held a key for, and which it never asked for.'],
    ],
  },
  {
    group: 'Prove',
    items: [
      ['A receipt for every decision', 'Allow or deny, who, which device, which rule, under which policy version.'],
      ['An append-only log, signed twice', 'Checkpoints carry an Ed25519 and an ML-DSA-65 signature. Both must verify.'],
      ['Verification without us', 'A proof bundle checks offline, in the browser or with the command-line tool, using public keys only.'],
    ],
  },
] as const

export const SUITE = [
  ['Key exchange', 'X-Wing: X25519 with ML-KEM-768', 'Hybrid. Safe unless both are broken.'],
  ['Device and server signatures', 'ML-DSA-65, with a context string per purpose', 'Post-quantum.'],
  ['Long-lived trust records', 'Ed25519 and ML-DSA-65, both required', 'Hybrid.'],
  ['File contents and sealing', 'AES-256-GCM', '256-bit symmetric keys keep a wide margin.'],
  ['Key derivation and request codes', 'HKDF-SHA-384, HMAC-SHA-384', 'Hash-based; a wide margin.'],
  ['Evidence log', 'SHA-256 Merkle tree (RFC 6962 domain separation)', 'Hash-based.'],
  ['Passphrase to keystore key', 'Argon2id', 'Not affected; protects a stolen keystore from fast guessing.'],
] as const

export const ZONES = [
  {
    id: 'device',
    title: 'The device',
    trust: 'Holds private keys. Does all encryption.',
    parts: [
      ['Client crypto', 'Encrypts and decrypts files, wraps file keys and signs, in the browser and in the command-line tool alike.'],
      ['Device keystore', 'Holds the private keys, locked under a key derived from the passphrase with Argon2id.'],
      ['Verifier', 'Checks receipts, proofs and both checkpoint signatures locally, with public keys only.'],
    ],
  },
  {
    id: 'edge',
    title: 'The edge',
    trust: 'Untrusted. Sees only ciphertext, wrapped keys and signed requests.',
    parts: [
      ['Static site', 'Serves this page and the console. No third-party origin is loaded at run time.'],
      ['API forwarder', 'Passes API calls to the backend on the same origin, so there is no cross-origin configuration to get wrong.'],
    ],
  },
  {
    id: 'backend',
    title: 'The backend',
    trust: 'Decides, releases sealed slots, records evidence. Cannot read files.',
    parts: [
      ['Gateway', 'Checks the session, the per-request code and the request counter before anything else runs. No valid proof, no processing.'],
      ['Policy engine', 'Answers allow or deny from identity, device, role, sensitivity and policy version. Unreachable means deny.'],
      ['Directory', 'The signed list of people, devices and public keys, with a version number that only increases.'],
      ['Key release', 'Stores sealed key slots and unseals one only after an allow decision made at that moment.'],
      ['Detection', 'Runs the rules over the event stream. If it fails, access is not granted: enforcement does not depend on it.'],
      ['Evidence log', 'An append-only record of every decision with dual-signed checkpoints.'],
      ['Blob store', 'Keeps encrypted file contents. Ciphertext only.'],
    ],
  },
] as const

export const QUESTIONS = [
  [
    'Is this ready for real data?',
    'No. It is a research prototype, it has not been audited, and it stores keys in software. The demo uses synthetic data only.',
  ],
  [
    'Why hybrid instead of post-quantum only?',
    'ML-KEM is new compared with X25519. Using both means a flaw found in either one alone does not expose a file. The cost is about a kilobyte per key exchange.',
  ],
  [
    'Did you write your own cryptography?',
    'No primitives. Algorithms come from vetted libraries; our code composes them following the published X-Wing construction and passes its official test vectors. The composition is protocol code and is labelled as such.',
  ],
  [
    'What can the server see?',
    'File names, sizes, who can open what, and every decision. It cannot see file contents or file keys: a copy of its database alone does not decrypt anything, and a test proves that.',
  ],
  [
    'What happens if I forget my passphrase?',
    'There is no reset. An admin gives you a new code and you enrol the device again. Files stay available from your other devices, and a recovery slot exists that needs two approvals to use.',
  ],
  [
    'Does it use AI to detect attacks?',
    'No. Detection is fourteen fixed rules, simple statistics and a privilege graph, so every alert can say exactly why it fired.',
  ],
] as const
