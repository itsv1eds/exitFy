#!/usr/bin/env python3
"""Signs a release manifest with the repository's P-256 core signing key.

The digest chain in a release only proves that the bytes match what the release
listing reported. A client that had to reach that listing through a mirror has
no way to tell whether the listing itself was genuine. A detached signature is
pinned to the key rather than to the transport, so it keeps its meaning over a
path this repository does not control.

The private key never reaches the tree: it arrives on stdin and is written to a
private temporary file for the single openssl invocation that consumes it.
"""

import argparse
import os
import pathlib
import stat
import subprocess
import sys
import tempfile

MAX_MANIFEST_BYTES = 1024 * 1024
MAX_SIGNATURE_BYTES = 1024


def fail(message: str) -> None:
    raise SystemExit(f"manifest signing failed: {message}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    arguments = parser.parse_args()

    manifest = arguments.manifest
    if not manifest.is_file() or manifest.is_symlink():
        fail("manifest is not a regular file")
    if not 0 < manifest.stat().st_size <= MAX_MANIFEST_BYTES:
        fail("manifest size is out of range")

    key = sys.stdin.buffer.read()
    if not key or b"PRIVATE KEY" not in key:
        fail("signing key is missing or not a PEM private key")

    with tempfile.TemporaryDirectory(prefix="exitfy-signing-") as temporary:
        key_path = pathlib.Path(temporary) / "signing.pem"
        descriptor = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(descriptor, key)
        finally:
            os.close(descriptor)
        if stat.S_IMODE(key_path.stat().st_mode) != 0o600:
            fail("signing key file mode is unsafe")
        result = subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", str(key_path),
             "-out", str(arguments.output), str(manifest)],
            check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
    if result.returncode != 0:
        fail("openssl rejected the signing request")

    signature = arguments.output
    if not signature.is_file() or not 0 < signature.stat().st_size <= MAX_SIGNATURE_BYTES:
        fail("produced signature size is out of range")
    print(f"signed {manifest.name} -> {signature.name}")


if __name__ == "__main__":
    main()
