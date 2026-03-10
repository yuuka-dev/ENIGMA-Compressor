from __future__ import annotations

import base64

import numpy as np
from PIL import Image


def _xor_bytes(data: bytes, key: str | None) -> bytes:
    if not key:
        return data
    key_bytes = key.encode("utf-8")
    key_arr = np.frombuffer(key_bytes, dtype=np.uint8)
    data_arr = np.frombuffer(data, dtype=np.uint8)
    # Repeat key to match data length
    key_rep = np.resize(key_arr, data_arr.shape)
    out = np.bitwise_xor(data_arr, key_rep)
    return out.tobytes()


def _embed_bits_into_image(img: Image.Image, bits: np.ndarray) -> Image.Image:
    """Menanam bit 0/1 ke bit paling rendah (LSB) dari kanal RGB gambar."""
    if img.mode != "RGB":
        img = img.convert("RGB")
    arr = np.array(img, dtype=np.uint8)
    flat = arr.reshape(-1, 3)  # abaikan alfa

    capacity = flat.size  # 3 * jumlah piksel
    if bits.size > capacity:
        raise ValueError("Kapasitas PNG terlalu kecil untuk menampung payload benih")

    flat_bytes = flat.reshape(-1)
    # Clear current LSB, then set from bits
    flat_bytes[: bits.size] = (flat_bytes[: bits.size] & 0xFE) | bits
    flat = flat_bytes.reshape(flat.shape)
    out = flat.reshape(arr.shape)
    return Image.fromarray(out, mode="RGB")


def _extract_bits_from_image(img: Image.Image, bit_count: int) -> np.ndarray:
    if img.mode != "RGB":
        img = img.convert("RGB")
    arr = np.array(img, dtype=np.uint8)
    flat_bytes = arr.reshape(-1, 3).reshape(-1)
    if bit_count > flat_bytes.size:
        raise ValueError("bit_count yang diminta melebihi kapasitas gambar")
    bits = flat_bytes[:bit_count] & 0x01
    return bits


def hide_seed_in_png(path: str, seed: bytes, password: str | None) -> None:
    """
    Menyembunyikan benih 32‑byte ke dalam PNG dengan steganografi LSB,
    ditambah XOR+Base64 opsional.
    """
    # Bentuk payload: XOR -> Base64 -> [panjang][data]
    xored = _xor_bytes(seed, password)
    b64 = base64.b64encode(xored)
    if len(b64) > 255:
        raise ValueError("Encoded seed too long")
    payload = bytes([len(b64)]) + b64

    # As bits MSB-first
    bits = np.unpackbits(np.frombuffer(payload, dtype=np.uint8))

    try:
        img = Image.open(path)
    except FileNotFoundError:
        # Jika PNG belum ada, buat gambar putih sederhana dengan kapasitas cukup.
        # Tiap piksel punya 3 kanal => 3 bit kapasitas.
        pixels_needed = int(np.ceil(bits.size / 3))
        side = int(np.ceil(np.sqrt(pixels_needed)))
        img = Image.new("RGB", (side, side), color=(255, 255, 255))

    out = _embed_bits_into_image(img, bits)
    out.save(path, format="PNG")


def extract_seed_from_png(path: str, password: str | None) -> bytes:
    img = Image.open(path)

    # First read 1 byte length => 8 bits
    len_bits = _extract_bits_from_image(img, 8)
    length = np.packbits(len_bits)[0]

    # Now read payload bytes
    payload_bits = _extract_bits_from_image(img, 8 * (1 + length))
    payload_bytes = np.packbits(payload_bits).tobytes()
    encoded = payload_bytes[1 : 1 + length]

    xored = base64.b64decode(encoded)
    seed = _xor_bytes(xored, password)
    return seed

