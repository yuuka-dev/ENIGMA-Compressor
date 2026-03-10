"""
log_samar.py

Biner -> penyamaran log / log -> pemulihan biner

Spesifikasi konversi (sama dengan log_samar.c):
  - Pisah biner masukan per 90MB
  - Konversi 8 byte per baris log (biner -> field desimal)
  - Nama field disamarkan seperti metrik pemantau server
  - Timestamp berdasarkan time(), +2ms per baris
  - pad= : jumlah byte nol di akhir (hanya baris terakhir)
  - chk= : jumlah 8 byte mod 256 (verifikasi integritas)
"""

from __future__ import annotations

import re
import time
from pathlib import Path

BYTE_PER_BARIS = 8
UKURAN_CHUNK = 90 * 1024 * 1024
PANJANG_BARIS = 256

NAMA_NODE = ("srv-node-01", "srv-node-02", "srv-node-03")
NAMA_FIELD = ("cpu", "mem", "dsk", "net", "lat", "req", "err", "tmp")
BULAN = (
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
)

# Pola regex untuk ekstraksi baris data
RE_FIELD = re.compile(r"(\w+)=(\d+)")


def _buat_waktu(basis: int, ms_lanjut: int) -> str:
    """Format timestamp: Mar 15 08:42:31.847"""
    ts = basis + (ms_lanjut // 1000)
    ms = ms_lanjut % 1000
    t = time.localtime(ts)
    return (
        f"{BULAN[t.tm_mon]} {t.tm_mday:2d} "
        f"{t.tm_hour:02d}:{t.tm_min:02d}:{t.tm_sec:02d}.{ms:03d}"
    )


def _buat_baris(
    data: bytes,
    pad: int,
    seq: int,
    pid: int,
    basis: int,
    ms: int,
) -> str:
    """
    Generate satu baris log.
    data[8]: 8 byte (bagian pad sudah nol)
    pad: jumlah byte nol di akhir (0 = baris penuh)
    """
    waktu = _buat_waktu(basis, ms)
    node = NAMA_NODE[seq % len(NAMA_NODE)]

    fields = " ".join(f"{NAMA_FIELD[i]}={data[i]:03d}" for i in range(8))
    chk = sum(data) & 0xFF

    return f"{waktu} {node} agentd[{pid}]: seq={seq:09d} {fields} pad={pad:03d} chk={chk:03d}\n"


def _normalisasi_awalan(awalan: str) -> str:
    """
    Jika user input "output_part001.log" -> normalisasi ke "output"
    """
    if len(awalan) >= 12:
        tail = awalan[-12:]
        if tail.startswith("_part") and tail[5:8].isdigit() and tail[8:] == ".log":
            return awalan[:-12]
    return awalan


def split_and_disguise(
    src_path: str,
    prefix: str,
    part_size: int = UKURAN_CHUNK,
) -> int:
    """
    Pisah biner masukan per part_size,
    tulis tiap chunk ke berkas prefix_partNNN.log
    Format sesuai spesifikasi C.
    """
    data = Path(src_path).read_bytes()
    total = len(data)
    basis = int(time.time())
    pid = 20000 + (basis & 0x7FFF)
    ms_clock = 0
    seq = 1
    part = 1
    cursor = 0

    while cursor < total:
        chunk_bytes = min(part_size, total - cursor)
        chunk_end = cursor + chunk_bytes

        part_name = f"{prefix}_part{part:03d}.log"
        with open(part_name, "w", encoding="utf-8", newline="\n") as fout:
            # Baris STARTUP di awal chunk
            waktu = _buat_waktu(basis, ms_clock)
            fout.write(
                f"{waktu} {NAMA_NODE[0]} agentd[{pid}]: STARTUP part={part:03d} "
                f"total_bytes={chunk_bytes} epoch={basis}\n"
            )
            ms_clock += 2

            # Proses 8 byte per iterasi
            while cursor < chunk_end:
                n = min(BYTE_PER_BARIS, chunk_end - cursor)
                pad = BYTE_PER_BARIS - n

                block = bytearray(8)
                block[:n] = data[cursor : cursor + n]
                # sisanya sudah 0

                baris = _buat_baris(
                    bytes(block), pad, seq, pid, basis, ms_clock
                )
                fout.write(baris)

                cursor += n
                seq += 1
                ms_clock += 2

        part += 1

    return part - 1


def _extrak_nilai(baris: str, kunci: str) -> int | None:
    """Ekstrak angka dari format key=NNN"""
    for m in RE_FIELD.finditer(baris):
        if m.group(1) == kunci:
            return int(m.group(2))
    return None


def restore_from_logs(prefix: str, out_path: str) -> int:
    """
    Baca prefix_part001.log, 002.log, ... secara urut,
    ekstrak 8 byte per baris log untuk memulihkan biner.
    """
    awalan = _normalisasi_awalan(prefix)
    total_keluar = 0

    with open(out_path, "wb") as fout:
        for part in range(1, 1000):
            part_name = f"{awalan}_part{part:03d}.log"
            if not Path(part_name).exists():
                break

            total_bytes_chunk = 0
            bytes_written_chunk = 0

            with open(part_name, encoding="utf-8") as fin:
                for baris in fin:
                    baris = baris.strip()

                    # Baris STARTUP
                    if "STARTUP" in baris:
                        p = baris.find("total_bytes=")
                        if p >= 0:
                            p += len("total_bytes=")
                            end = baris.find(" ", p)
                            if end < 0:
                                end = len(baris)
                            total_bytes_chunk = int(baris[p:end] or 0)
                        continue

                    # Baris data: ekstrak 8 field
                    val = []
                    for i in range(BYTE_PER_BARIS):
                        v = _extrak_nilai(baris, NAMA_FIELD[i])
                        if v is None:
                            break
                        val.append(v)
                    if len(val) != BYTE_PER_BARIS:
                        continue

                    pad_val = _extrak_nilai(baris, "pad")
                    chk_val = _extrak_nilai(baris, "chk")
                    if pad_val is None or chk_val is None:
                        continue

                    chk_calc = sum(val) & 0xFF
                    if chk_calc != chk_val:
                        continue

                    real_bytes = BYTE_PER_BARIS - pad_val
                    if total_bytes_chunk > 0:
                        sisa = total_bytes_chunk - bytes_written_chunk
                        if real_bytes > sisa:
                            real_bytes = sisa

                    data_out = bytes(val[i] for i in range(real_bytes))
                    fout.write(data_out)
                    bytes_written_chunk += real_bytes
                    total_keluar += real_bytes

    if total_keluar <= 0:
        Path(out_path).unlink(missing_ok=True)
        raise ValueError(
            f"Tidak ada data dipulihkan. Periksa awalan log "
            f"(mis. {awalan}_part001.log)."
        )

    return total_keluar
