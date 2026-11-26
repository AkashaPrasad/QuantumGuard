# Reproduced security findings

Pass 2 adds a minimal regression test for each demonstrated flaw, using only this project's
in-process app or localhost stack. Do not add speculative failing tests before the feature
exists. Each finding is summarised in `THREAT_MODEL.md` (section 6) with its severity, source location,
test ID and fix. No product implementation belongs in this directory.
