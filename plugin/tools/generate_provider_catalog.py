#!/usr/bin/env python3
"""Generate the encrypted Java provider catalog from a private local JSON file."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import stat
import tempfile
from urllib.parse import urlsplit


SCHEMA = 1
FIXED_PROVIDERS = ("elix", "shrimp")
MAX_PRIVATE_FILE_BYTES = 32 * 1024
MAX_ENDPOINT_BYTES = 4096
PACKAGE = "com.extera.plugins.exitfy"


def _fail(message: str) -> SystemExit:
    return SystemExit(f"provider catalog generation failed: {message}")


def _read_config(path: Path) -> tuple[str | None, ...]:
    if not path.is_file() or path.is_symlink():
        raise _fail("providers.private.json must be a regular file")
    if os.name == "posix" and stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise _fail("providers.private.json must have mode 0600")
    raw = path.read_bytes()
    if len(raw) > MAX_PRIVATE_FILE_BYTES:
        raise _fail("providers.private.json exceeds 32 KiB")
    try:
        root = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise _fail(f"providers.private.json is invalid JSON ({error.__class__.__name__})")
    if not isinstance(root, dict) or set(root) != {"schema", "providers"}:
        raise _fail("root must contain exactly schema and providers")
    if type(root.get("schema")) is not int or root.get("schema") != SCHEMA:
        raise _fail(f"schema must be {SCHEMA}")
    providers = root.get("providers")
    if not isinstance(providers, dict):
        raise _fail("providers must be an object")
    unknown = set(providers) - set(FIXED_PROVIDERS)
    if unknown:
        raise _fail("providers contains an unknown id")

    result: list[str | None] = []
    for provider_id in FIXED_PROVIDERS:
        value = providers.get(provider_id)
        if value is None:
            result.append(None)
            continue
        if not isinstance(value, str) or not value:
            raise _fail(f"{provider_id} must be a non-empty HTTPS URL or null")
        if value != value.strip() or any(
            ord(character) < 0x21 or ord(character) > 0x7E for character in value
        ):
            raise _fail(f"{provider_id} URL must contain visible ASCII URI characters only")
        encoded = value.encode("utf-8")
        if len(encoded) > MAX_ENDPOINT_BYTES:
            raise _fail(f"{provider_id} URL exceeds {MAX_ENDPOINT_BYTES} UTF-8 bytes")
        try:
            parsed = urlsplit(value)
            parsed.port
        except ValueError:
            raise _fail(f"{provider_id} URL has an invalid authority or port")
        if (
            parsed.scheme.lower() != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
            or "\\" in value
        ):
            raise _fail(f"{provider_id} must be an absolute HTTPS URL without credentials or fragment")
        result.append(value)
    return tuple(result)


def _mixer(index: int) -> bytes:
    mask = (1 << 64) - 1
    state = 0x6A09E667F3BCC909 ^ (((index + 1) * 0x9E3779B97F4A7C15) & mask)
    output = bytearray(24)
    for position in range(len(output)):
        state ^= state >> 12
        state &= mask
        state ^= (state << 25) & mask
        state &= mask
        state ^= state >> 27
        state &= mask
        state = (state * 0x2545F4914F6CDD1D) & mask
        output[position] = (state >> ((position & 7) * 8)) & 0xFF
    return bytes(output)


def _derive(first: bytes, second: bytes, index: int) -> tuple[bytes, bytes]:
    root = hashlib.sha256(first + _mixer(index) + second).digest()
    stream_key = hmac.new(root, bytes((0x31, index, 0x5C)), hashlib.sha256).digest()
    check_key = hmac.new(root, bytes((0x72, index, 0xA6)), hashlib.sha256).digest()
    return stream_key, check_key


def _transform(value: bytes, nonce: bytes, key: bytes) -> bytes:
    output = bytearray(len(value))
    for offset in range(0, len(value), hashlib.sha256().digest_size):
        counter = offset // hashlib.sha256().digest_size
        block = hmac.new(key, nonce + counter.to_bytes(4, "big"), hashlib.sha256).digest()
        chunk = value[offset : offset + len(block)]
        for index, item in enumerate(chunk):
            output[offset + index] = item ^ block[index]
    return bytes(output)


def _encrypt(value: str | None, index: int) -> dict[str, bytes | bool]:
    first = secrets.token_bytes(32)
    second = secrets.token_bytes(32)
    nonce = secrets.token_bytes(16)
    if value is None:
        return {
            "enabled": False,
            "first": first,
            "second": second,
            "nonce": nonce,
            "payload": b"",
            "tag": secrets.token_bytes(16),
        }
    stream_key, check_key = _derive(first, second, index)
    payload = _transform(value.encode("utf-8"), nonce, stream_key)
    tag = hmac.new(check_key, bytes((index,)) + nonce + payload, hashlib.sha256).digest()[:16]
    return {
        "enabled": True,
        "first": first,
        "second": second,
        "nonce": nonce,
        "payload": payload,
        "tag": tag,
    }


def _int_rows(name: str, rows: list[bytes]) -> str:
    lines = [f"    private static final int[][] {name} = {{"]
    for row in rows:
        if not row:
            lines.append("            {},")
            continue
        lines.append("            {")
        for offset in range(0, len(row), 12):
            values = ", ".join(str(value) for value in row[offset : offset + 12])
            lines.append(f"                    {values},")
        lines.append("            },")
    lines.append("    };")
    return "\n".join(lines)


def _long_rows(rows: list[bytes]) -> str:
    lines = ["    private static final long[][] VALUES = {"]
    for row in rows:
        values = [int.from_bytes(row[offset : offset + 8], "big") for offset in range(0, len(row), 8)]
        lines.append("            {")
        for offset in range(0, len(values), 2):
            pair = ", ".join(f"0x{value:016x}L" for value in values[offset : offset + 2])
            lines.append(f"                    {pair},")
        lines.append("            },")
    lines.append("    };")
    return "\n".join(lines)


def _data_source(entries: list[dict[str, bytes | bool]], fingerprint: str) -> str:
    enabled = ", ".join("true" if entry["enabled"] else "false" for entry in entries)
    nonces = [entry["nonce"] for entry in entries]
    payloads = [entry["payload"] for entry in entries]
    tags = [entry["tag"] for entry in entries]
    return f"""package {PACKAGE};

// Generated by tools/generate_provider_catalog.py. Input fingerprint: {fingerprint}
final class ProviderCatalogData {{
    private static final boolean[] ENABLED = {{{enabled}}};
{_int_rows("NONCES", nonces)}
{_int_rows("PAYLOADS", payloads)}
{_int_rows("TAGS", tags)}

    private ProviderCatalogData() {{
    }}

    static int size() {{
        return ENABLED.length;
    }}

    static boolean enabled(int index) {{
        return ENABLED[index];
    }}

    static byte[] nonce(int index) {{
        return bytes(NONCES[index]);
    }}

    static byte[] payload(int index) {{
        return bytes(PAYLOADS[index]);
    }}

    static byte[] tag(int index) {{
        return bytes(TAGS[index]);
    }}

    private static byte[] bytes(int[] values) {{
        byte[] output = new byte[values.length];
        for (int index = 0; index < values.length; index++) output[index] = (byte) values[index];
        return output;
    }}
}}
"""


def _material_source(class_name: str, rows: list[bytes], fingerprint: str) -> str:
    return f"""package {PACKAGE};

// Generated by tools/generate_provider_catalog.py. Input fingerprint: {fingerprint}
final class {class_name} {{
{_long_rows(rows)}

    private {class_name}() {{
    }}

    static byte[] value(int index) {{
        return expand(VALUES[index]);
    }}

    private static byte[] expand(long[] values) {{
        byte[] output = new byte[values.length * 8];
        int offset = 0;
        for (long value : values) {{
            for (int shift = 56; shift >= 0; shift -= 8) {{
                output[offset++] = (byte) (value >>> shift);
            }}
        }}
        return output;
    }}
}}
"""


def _atomic_write(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as output:
            output.write(value)
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _fingerprint(values: tuple[str | None, ...]) -> str:
    script_digest = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    canonical = json.dumps(
        {"generator": script_digest, "providers": values},
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def generate(input_path: Path, output_dir: Path) -> None:
    values = _read_config(input_path)
    fingerprint = _fingerprint(values)
    targets = {
        "ProviderCatalogData.java": output_dir / "ProviderCatalogData.java",
        "CatalogMaterialA.java": output_dir / "CatalogMaterialA.java",
        "CatalogMaterialB.java": output_dir / "CatalogMaterialB.java",
    }
    marker = f"Input fingerprint: {fingerprint}"
    if all(path.is_file() and marker in path.read_text(encoding="utf-8") for path in targets.values()):
        print(f"Encrypted provider catalog is current ({sum(value is not None for value in values)} active)")
        return

    entries = [_encrypt(value, index) for index, value in enumerate(values)]
    sources = {
        "ProviderCatalogData.java": _data_source(entries, fingerprint),
        "CatalogMaterialA.java": _material_source(
            "CatalogMaterialA", [entry["first"] for entry in entries], fingerprint
        ),
        "CatalogMaterialB.java": _material_source(
            "CatalogMaterialB", [entry["second"] for entry in entries], fingerprint
        ),
    }
    for name, source in sources.items():
        _atomic_write(targets[name], source)
    print(f"Generated encrypted provider catalog ({sum(value is not None for value in values)} active)")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    arguments = parser.parse_args()
    generate(arguments.input.resolve(), arguments.output_dir.resolve())


if __name__ == "__main__":
    main()
