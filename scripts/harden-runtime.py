"""Remove build and shell tools from the final image; called during image build."""

import glob
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

# Nothing below is imported or executed by the server, client, entrypoint or healthcheck.
# /var/lib/dpkg and /usr/share/doc stay so image scanners and licence notices keep working.
UNUSED = (
    "/usr/lib/*/gconv",  # iconv converters; Python has its own codecs
    "/usr/lib/*/perl-base",
    "/usr/share/perl5",
    "/usr/lib/apt",
    "/usr/share/bash-completion",
    "/usr/share/man",
    "/usr/share/info",
    "/usr/share/lintian",
    "/usr/local/include",
    "/usr/local/share/man",
    "/usr/local/lib/python3.12/site-packages/pip",
    "/usr/local/lib/python3.12/site-packages/pip-*.dist-info",
    "/usr/local/lib/python3.12/site-packages/setuptools*",
    "/usr/local/lib/python3.12/site-packages/wheel*",
    "/usr/local/lib/python3.12/site-packages/_distutils_hack",
    "/usr/local/lib/python3.12/ensurepip",
    "/usr/local/lib/python3.12/idlelib",
    "/usr/local/lib/python3.12/tkinter",
    "/usr/local/lib/python3.12/turtledemo",
    "/usr/local/lib/python3.12/lib2to3",
    "/usr/local/lib/python3.12/pydoc_data",
    "/usr/local/lib/python3.12/test",
    "/usr/local/lib/python3.12/config-3.12-*",
    "/usr/local/lib/python3.12/lib-dynload/_tkinter*",
    "/usr/local/lib/python3.12/**/test",
    "/usr/local/lib/python3.12/**/tests",
)
for pattern in UNUSED:
    for match in glob.glob(pattern, recursive=True):
        path = Path(match)
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path)
        elif path.exists() or path.is_symlink():
            path.unlink()
for directory in ("/var/lib/quantumguard/data", "/var/lib/quantumguard/keys"):
    Path(directory).mkdir(parents=True, exist_ok=True)
    os.chown(directory, 10001, 10001)
    os.chmod(directory, 0o700)
