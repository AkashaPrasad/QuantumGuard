# Flow: protect-file
Persona and goal: An employee wants a sensitive file stored so that only chosen people's devices can open it.
Entry points: "Protect a file" button on Files; dropping a file anywhere on Files; command palette "Protect a file".
Happy path:
1. Choose or drop a file. The dialog shows its name and size.
2. Pick a sensitivity (Internal, Confidential (default), Restricted) and who can open it (people from the directory; "You, on N devices" is always included and cannot be removed).
3. "Protect" -> encrypts on this device chunk by chunk, uploads ciphertext (`POST /files`, `PUT .../chunks/n`), wraps the key for each device, `POST .../commit`.
4. Result: the receipt slip with "Protected", the people who can open it, and "Done". The file is first in the list.
States: loading (progress with chunk count and per-device checklist) | error in the dialog with Retry that keeps the choices | offline before start disables Protect; offline midway pauses and offers Retry | session expired -> lock overlay, then resumes from the form.
Errors: `recipient_not_allowed` names the person and asks to remove them; `QG_STALE_EPOCH` retries once automatically, then explains; file over the size limit is refused before any work with the limit stated.
Cancel: available until commit; nothing is committed and pending chunks are discarded by the server.
Exit points and what is saved: ciphertext and key slots on the server; the plaintext never leaves the device.
Clicks to complete: 3 (button, pick file, Protect) or drop + 1.
Keyboard path: button -> file input -> radio group -> checkboxes -> Protect; Escape cancels and asks to confirm only if encryption has started.
Tour anchors: `files-protect`.
Animations: EncryptChunks -> `encrypting` progress; WrapBeams -> each `wrapping` event.
Playwright test ids: `files-protect`, `protect-drop`, `protect-file-input`, `protect-classification`, `protect-recipient-<user_id>`, `protect-submit`, `protect-cancel`, `protect-progress`, `protect-receipt`, `protect-done`.
