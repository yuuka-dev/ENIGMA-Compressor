from __future__ import annotations

import struct
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path

MAGIC = b"ENGMPACK"
VERSION = 1


@dataclass
class PackedEntry:
    """Satu entri berkas di dalam arsip ENGMPACK."""

    path: str
    data: bytes


def _kumpulkan_berkas(paths: Iterable[str]) -> Iterator[tuple[str, Path]]:
    """
    Mengumpulkan berkas dari path; bila direktori, rekursif semua isinya.
    Mengembalikan (jalur_arsip, path_berkas) untuk tiap berkas.
    """
    for p in paths:
        path = Path(p).resolve()
        if path.is_file():
            yield (p, path)
        elif path.is_dir():
            for f in path.rglob("*"):
                if f.is_file():
                    rel = f.relative_to(path)
                    jalur_arsip = str(Path(path.name) / rel)
                    yield (jalur_arsip, f)


def pack_files(paths: Iterable[str], out_path: str) -> None:
    """
    Format arsip kustom yang sangat sederhana:

    MAGIC(8) | VERSION(1) | count(u32)
      diulang:
        path_len(u16) | path(bytes, UTF‑8) | size(u64) | data
    """
    entries: list[PackedEntry] = []
    for jalur_arsip, path_berkas in _kumpulkan_berkas(paths):
        entries.append(
            PackedEntry(path=jalur_arsip, data=path_berkas.read_bytes())
        )

    with open(out_path, "wb") as out:
        out.write(MAGIC)
        out.write(struct.pack("!B", VERSION))
        out.write(struct.pack("!I", len(entries)))
        for ent in entries:
            path_bytes = ent.path.encode("utf-8")
            if len(path_bytes) > 0xFFFF:
                raise ValueError("Jalur terlalu panjang untuk format arsip")
            out.write(struct.pack("!H", len(path_bytes)))
            out.write(path_bytes)
            out.write(struct.pack("!Q", len(ent.data)))
            out.write(ent.data)


def unpack_archive(archive_path: str, output_root: str = ".") -> None:
    with open(archive_path, "rb") as f:
        if f.read(len(MAGIC)) != MAGIC:
            raise ValueError("Magic arsip tidak valid")
        (version,) = struct.unpack("!B", f.read(1))
        if version != VERSION:
            raise ValueError(f"Versi arsip tidak didukung: {version}")
        (count,) = struct.unpack("!I", f.read(4))

        for _ in range(count):
            (path_len,) = struct.unpack("!H", f.read(2))
            path_bytes = f.read(path_len)
            (size,) = struct.unpack("!Q", f.read(8))
            data = f.read(size)

            rel_path = path_bytes.decode("utf-8")
            out_path = Path(output_root, rel_path)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            with open(out_path, "wb") as out:
                out.write(data)

