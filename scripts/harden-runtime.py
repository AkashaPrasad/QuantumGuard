"""Remove build and shell tools from the final image; called during image build."""

import os
from pathlib import Path
import shutil


for directory in ("/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin"):
    root = Path(directory)
    if not root.exists():
        continue
    for entry in root.iterdir():
        if directory == "/usr/local/bin" and entry.name.startswith("python"):
            continue
        if entry.is_dir() and not entry.is_symlink():
            shutil.rmtree(entry)
        else:
            entry.unlink()

for directory in ("/var/lib/apt/lists", "/var/cache/apt", "/root/.cache", "/build"):
    shutil.rmtree(directory, ignore_errors=True)
for directory in ("/var/lib/quantumguard/data", "/var/lib/quantumguard/keys"):
    Path(directory).mkdir(parents=True, exist_ok=True)
    os.chown(directory, 10001, 10001)
    os.chmod(directory, 0o700)
