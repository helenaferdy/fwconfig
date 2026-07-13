"""File / upload helpers."""

from __future__ import annotations

import io
import tarfile
import zipfile
from pathlib import Path


TEXT_LIKE = {".conf", ".cfg", ".txt", ".xml", ".json", ".csv", ".log", ".cli"}


def decode_bytes(data: bytes) -> str:
    for enc in ("utf-8", "utf-8-sig", "latin-1", "cp1252"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def extract_text_from_upload(filename: str, data: bytes) -> str:
    """Return configuration text from raw upload bytes.

    Archives (.zip/.tar/.gz/.tgz) are expanded and the largest text-like
    member is selected as the primary configuration.
    """
    name = filename.lower()
    suffix = Path(name).suffix

    if suffix == ".zip" or name.endswith(".zip"):
        return _from_zip(data)
    if suffix in {".tgz", ".gz"} or name.endswith((".tar.gz", ".tgz", ".tar")):
        return _from_tar(data)
    return decode_bytes(data)


def _from_zip(data: bytes) -> str:
    best_name = ""
    best_data = b""
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            ext = Path(info.filename).suffix.lower()
            if ext not in TEXT_LIKE and ext != "":
                # still consider extensionless and common conf names
                if not any(info.filename.lower().endswith(e) for e in TEXT_LIKE):
                    continue
            raw = zf.read(info)
            if len(raw) > len(best_data):
                best_data = raw
                best_name = info.filename
    if not best_data:
        # fallback: largest file overall
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                raw = zf.read(info)
                if len(raw) > len(best_data):
                    best_data = raw
                    best_name = info.filename
    if not best_data:
        raise ValueError("ZIP archive contains no readable configuration files")
    return decode_bytes(best_data)


def _from_tar(data: bytes) -> str:
    best_data = b""
    mode = "r:*"
    with tarfile.open(fileobj=io.BytesIO(data), mode=mode) as tf:
        for member in tf.getmembers():
            if not member.isfile():
                continue
            f = tf.extractfile(member)
            if not f:
                continue
            raw = f.read()
            ext = Path(member.name).suffix.lower()
            if ext in TEXT_LIKE or len(raw) > len(best_data):
                if ext in TEXT_LIKE or not best_data:
                    if len(raw) > len(best_data) or ext in TEXT_LIKE:
                        # Prefer text-like; otherwise largest
                        if ext in TEXT_LIKE or not best_data:
                            best_data = raw
                        elif len(raw) > len(best_data):
                            best_data = raw
    if not best_data:
        raise ValueError("Archive contains no readable configuration files")
    return decode_bytes(best_data)
