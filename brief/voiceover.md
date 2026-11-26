This is QuantumGuard. When a device goes missing, it cuts that device off in milliseconds, re-keys what it could read, and proves it, with post-quantum cryptography.

Aiko enrols her laptop with a one-time code. Her browser creates two key pairs: M L D S A sixty-five for signing, and X-Wing, which combines X twenty-five five-nineteen with M L KEM seven sixty-eight, for key exchange. The device proves it holds both private keys before the server certifies it, and the keys never leave the laptop.

She protects a confidential trial protocol. It is encrypted right here, in one-megabyte A E S G C M chunks. The file key is wrapped for each of her devices, then sealed again by the server, so neither side can open the file alone.

Opening the file asks the policy engine at that moment. An allow releases the key with a sixty-second lease, and every decision becomes a receipt in a tamper-evident log.

Her phone has its own wrapped key, so it opens the same file. Now imagine she leaves that phone on a train.

From her laptop, Aiko reports the phone lost, last safe an hour ago. One transaction revokes the device, deletes its key slots, ends its sessions, and publishes a new signed device list. The server measured it, in milliseconds.

Now we crash the server. A hard kill, no clean shutdown.

It comes back up. The heartbeat reconnects, and the signed device list and the evidence log are exactly as they were. Nothing was lost.

The lost phone now tries to sign in to the restarted server. The server refuses it, records the attempt, and raises an alert.

Aiko's laptop signs in again after the restart. The file the phone opened after the loss time was exposed, so it already has a new key, and the incident is contained.

Meanwhile, an attacker probed the server: guessing file ids, replaying a request, and opening a decoy file.

Every attempt was refused and alerted, with a response scoped to just that session or device. Each alert names the identity, the service, and the event, with the receipts behind it. No machine learning: fourteen fixed rules.

Priya exports the incident's proof bundle: every receipt with its Merkle proof, and checkpoints signed with both Ed twenty-five five-nineteen and M L D S A sixty-five. It verifies right here in the browser, using public keys only, with no network request.

Now change a single receipt. Verification fails, and points to the exact entry that was altered.

We state plainly what we do not protect, like files already decrypted, or malware on an unlocked device. And every number here is measured on this build.

QuantumGuard is open source on GitHub. Thank you for watching.
