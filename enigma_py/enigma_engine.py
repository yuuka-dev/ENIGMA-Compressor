from __future__ import annotations

import hashlib
from dataclasses import dataclass


@dataclass
class EnigmaMachine:
    """
    Cipher stream sederhana terinspirasi dari Enigma,
    tetapi diimplementasikan sebagai PRG modern.

    Implementasi ini tidak bit‑kompatibel dengan versi C;
    ia menghasilkan kunci aliran dari benih lalu melakukan XOR
    sebagai "kriptografi bergaya Enigma".
    """

    key: bytes

    @classmethod
    def from_seed(cls, seed: bytes) -> EnigmaMachine:
        # Menurunkan material kunci internal dari benih dengan SHA‑512
        key = hashlib.sha512(seed).digest()
        return cls(key=key)

    def keystream(self, n: int) -> bytes:
        out = bytearray()
        counter = 0
        while len(out) < n:
            h = hashlib.sha512(self.key + counter.to_bytes(8, "big")).digest()
            out.extend(h)
            counter += 1
        return bytes(out[:n])

    def transform_file(self, src: str, dst: str, chunk_size: int = 1024 * 1024) -> None:
        """
        Transformasi involutif: diterapkan dua kali dengan benih yang sama
        akan mengembalikan isi berkas ke bentuk asal.
        """
        with open(src, "rb") as f_in, open(dst, "wb") as f_out:
            while True:
                chunk = f_in.read(chunk_size)
                if not chunk:
                    break
                stream = self.keystream(len(chunk))
                out = bytes(a ^ b for a, b in zip(chunk, stream))
                f_out.write(out)

