# Flow: share-file
Persona and goal: A file owner (or anyone who can open it) wants another person to be able to open it, or to stop them.
Entry points: file detail sheet -> "Who can open this"; row menu -> Share.
Happy path (share): 1. Open the people picker. 2. Tick a person, "Share" -> this device opens its slot, wraps the key for each of their devices, `POST /files/:id/share`. 3. The person appears in the list with their devices.
Happy path (stop sharing): 1. "Remove" next to a person. 2. Confirm ("Remove access for Daniel Mensah. The file gets a new key.") -> `POST /files/:id/unshare`; the file shows "New key pending" and the re-key banner handles it.
States: loading (per-person spinner text) | empty ("Only you can open this") | error in the sheet | offline | session expired.
Errors: `recipient_not_allowed`; `QG_DENY_POLICY` when the caller has no slot; `QG_STALE_EPOCH` auto-retry once.
Exit points and what is saved: new slots; an unshare deletes slots at once and queues a re-key.
Clicks to complete: 3. Keyboard path: sheet traps focus, Escape closes.
Tour anchors: none. Animations: WrapBeams on share.
Playwright test ids: `file-share-open`, `share-user-<user_id>`, `share-submit`, `unshare-<user_id>`, `unshare-confirm`.
