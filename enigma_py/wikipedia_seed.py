from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass

import requests

WIKIPEDIA_API_URL = "https://en.wikipedia.org/api/rest_v1/page/random/summary"


@dataclass
class BenihWikipedia:
    """Representasi benih 32‑byte yang diturunkan dari halaman Wikipedia acak."""

    seed_bytes: bytes
    deskripsi: str


def ambil_benih_wikipedia(timeout: float = 5.0) -> BenihWikipedia:
    """
    Mengambil halaman Wikipedia acak dan menurunkan benih 32‑byte
    dari judul dan ringkasannya.

    Implementasi ini tidak identik bit‑per‑bit dengan kode C,
    tetapi mempertahankan ide yang sama:
    menggunakan Wikipedia sebagai sumber entropi eksternal.
    """
    resp = requests.get(WIKIPEDIA_API_URL, timeout=timeout)
    resp.raise_for_status()
    data = resp.json()

    title = data.get("title", "")
    extract = data.get("extract", "")

    # Tambah garam acak supaya bila halaman yang sama terambil berkali‑kali,
    # distribusi benih tetap sulit diprediksi.
    salt = random.randbytes(16) if hasattr(random, "randbytes") else bytes(
        random.getrandbits(8) for _ in range(16)
    )
    h = hashlib.sha256()
    h.update(title.encode("utf-8", errors="ignore"))
    h.update(b"\n")
    h.update(extract.encode("utf-8", errors="ignore"))
    h.update(b"\n")
    h.update(salt)
    seed = h.digest()

    extract_preview = extract[:80].replace('\n', ' ')
    info = f"{title} | {extract_preview}..."
    return BenihWikipedia(seed_bytes=seed, deskripsi=info)


def get_seed_and_info() -> tuple[bytes, str]:
    """Fungsi pembantu untuk mendapatkan (benih, deskripsi) sekaligus."""
    s = ambil_benih_wikipedia()
    return s.seed_bytes, s.deskripsi

