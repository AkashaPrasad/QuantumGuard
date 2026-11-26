# QuantumGuard: demo video script (about 4:00)

The browser part is automated and timed: `bash scripts/demo-video.sh` starts a fresh demo stack on
`http://localhost:18080`, opens a visible Chromium window, enrols Aiko's phone and the operator off camera,
then counts down 8 seconds and plays the take. Everything happens in **one window** with three tabs: Aiko's
laptop (`laptop.localhost`), Aiko's phone (`phone.localhost`) and Priya the operator (`ops.localhost`); each tab
is its own device. Record just that window.

- Every cue is printed in the terminal the moment it starts, with its time. A small caption bar shows the
  same line on screen; turn it off with `QG_DEMO_CAPTIONS=0`.
- Window size: `QG_DEMO_SIZE=1440x900` (default). Lead-in before the take: `QG_DEMO_LEAD_IN=8` seconds.
- Remove the demo stack afterwards with `bash scripts/demo-video.sh --down`. The stack on port 8080 is never
  touched. Every name and file is synthetic.

## Timeline

The voice-over is in [voiceover.md](voiceover.md): one paragraph per row below, spelled for text-to-speech.
For the best sync, generate each paragraph as its own clip and place it at its time.

| # | Time | Tab | On screen |
|---|---|---|---|
| 1 | 0:00 | laptop | Public page: the claim, then **How it works** |
| 2 | 0:12 | laptop | **Launch console**, **Enrol**: code, device name, passphrase; the two key pairs animate |
| 3 | 0:40 | laptop | **Files**, **Protect**: a confidential trial protocol; chunks sealed; the receipt |
| 4 | 1:00 | laptop | The file opens: "Checked on this device" |
| 5 | 1:15 | phone | The phone opens the same file, then sits on the public **Status** page |
| 6 | 1:28 | laptop | **Devices**, **Report lost** on the phone (last safe an hour ago): "Access removed", enforced in milliseconds |
| 7 | 1:50 | phone | **Status** heartbeat: the server is killed with SIGKILL; the link breaks, "not answering" |
| 8 | ~1:57 | phone | The server restarts; the heartbeat reconnects: "state intact after restart" (device list epoch and log size compared) |
| 9 | 2:10 | phone | The phone signs in to the restarted server: refused, "Access removed from this device" |
| 10 | 2:22 | laptop | The laptop unlocks again after the restart; the file has its new key; the incident is **Contained** |
| 11 | 2:40 | operator | **Alerts**: QG-R001 (lost phone), QG-R002 (replay), QG-R004 (decoy), QG-R009 (enumeration) from an off-camera attacker |
| 12 | ~2:46 | operator | The QG-R001 alert: **Who, where, what**, why it fired, receipts, the scoped response |
| 13 | 3:04 | operator | The incident, **Export proof bundle**, **Verify**: "Verified on this device" |
| 14 | 3:27 | operator | A copy with one receipt changed: verification fails at that entry |
| 15 | 3:40 | operator | Public page: **What we do not protect**, then **Measured performance** |
| 16 | 3:53 | operator | Back to the top; the take ends about 4:00 |

Times marked ~ follow a real event (the restart, the alert list) and move by a second or two between takes.

## Before you record

- Close other windows over the top-left of the screen, or set `QG_DEMO_SIZE` to your screen.
- Do a silent take first if you like: the run is the same every time, with fresh data.
- Read the enforcement time from the screen (it is also printed in the terminal); do not quote a number that
  is not shown.
