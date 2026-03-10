from __future__ import annotations

import sys
from pathlib import Path

import click

# Coba impor absolut dulu; kalau gagal (dijalankan langsung dari repo),
# jatuh kembali ke impor relatif.
try:  # mode paket: python -m enigma_py.cli ...
    from enigma_py.enigma_engine import EnigmaMachine
    from enigma_py.log_samar import restore_from_logs, split_and_disguise
    from enigma_py.packer import pack_files, unpack_archive
    from enigma_py.png_lsb import extract_seed_from_png, hide_seed_in_png
    from enigma_py.wikipedia_seed import get_seed_and_info
except ModuleNotFoundError:  # mode skrip langsung: python enigma_py/cli.py ...
    from .enigma_engine import EnigmaMachine
    from .log_samar import restore_from_logs, split_and_disguise
    from .packer import pack_files, unpack_archive
    from .png_lsb import extract_seed_from_png, hide_seed_in_png
    from .wikipedia_seed import get_seed_and_info


@click.group()
def cli() -> None:
    """Kompresor / enkriptor gaya ENIGMA ditulis dengan Python."""


@cli.command()
@click.argument(
    "paths", type=click.Path(exists=True, dir_okay=True, file_okay=True), nargs=-1
)
@click.option(
    "--base-name", "-b", default="output", help="Nama dasar untuk berkas keluaran."
)
@click.option(
    "--key-png",
    "-k",
    default=None,
    help="Path to key PNG (default: BASE_NAME_key.png, created if missing).",
)
@click.option(
    "--password", "-p", default=None, hide_input=True, help="Optional XOR password."
)
def pack(
    paths: list[str], base_name: str, key_png: str | None, password: str | None
) -> None:
    """
    Pipa lengkap: benih Wikipedia -> PNG LSB -> enkripsi Enigma -> arsip -> log tersamarkan.
    """
    if not paths:
        click.echo("Tidak ada berkas masukan yang diberikan.", err=True)
        sys.exit(1)

    seed, info = get_seed_and_info()
    click.echo(f"[BENIH] {info}")

    key_png = key_png or f"{base_name}_key.png"
    click.echo(f"[LANGKAH 1/6] Menyembunyikan benih ke PNG LSB: {key_png}")
    hide_seed_in_png(key_png, seed, password)
    click.echo(f"[PNG]   Benih tersembunyi di: {key_png}")

    machine = EnigmaMachine.from_seed(seed)

    engm_path = f"{base_name}.engm"
    enc_path = f"{base_name}.enc"
    click.echo(f"[LANGKAH 2/6] Mengemas berkas -> {engm_path}")
    pack_files(paths, engm_path)

    click.echo(f"[LANGKAH 3/6] Mengenkripsi {engm_path} -> {enc_path}")
    machine.transform_file(engm_path, enc_path)
    Path(engm_path).unlink(missing_ok=True)

    click.echo(
        f"[LANGKAH 4/6] Memecah & menyamarkan {enc_path} -> {base_name}_partNNN.log"
    )
    parts = split_and_disguise(enc_path, base_name)
    Path(enc_path).unlink(missing_ok=True)

    click.echo("[LANGKAH 5/6] Selesai mengemas dan mengenkripsi.")
    click.echo(f"[LOG]  {parts} bagian log dibuat.")
    click.echo(f"[LANGKAH 6/6] Simpan berkas PNG kunci dengan aman: {key_png}")


@cli.command()
@click.option(
    "--prefix",
    "-x",
    required=True,
    help="Awalan berkas log tersamar (dasar dari *_partNNN.log).",
)
@click.option(
    "--archive-out",
    "-o",
    default="hasil.engm",
    help="Berkas arsip keluaran (akan dihapus setelah ekstraksi).",
)
@click.option(
    "--key-png",
    "-k",
    default=None,
    help="Jalur PNG kunci (baku: PREFIX_key.png).",
)
@click.option(
    "--password", "-p", default=None, hide_input=True, help="Optional XOR password."
)
def restore(
    prefix: str, archive_out: str, key_png: str | None, password: str | None
) -> None:
    """
    Pipa balik: PNG LSB -> benih -> dekripsi Enigma -> arsip -> ekstrak berkas.
    """
    key_png = key_png or f"{prefix}_key.png"
    tmp_enc = f"{prefix}.enc.tmp"

    click.echo(f"[LANGKAH 0/4] Mengekstrak benih dari PNG LSB: {key_png}")
    seed = extract_seed_from_png(key_png, password)

    click.echo(
        f"[LANGKAH 1/4] Memulihkan biner terenkripsi dari log: {prefix}_partNNN.log -> {tmp_enc}"
    )
    total = restore_from_logs(prefix, tmp_enc)
    if total <= 0:
        click.echo("[GALAT] Gagal memulihkan dari log.", err=True)
        sys.exit(1)

    machine = EnigmaMachine.from_seed(seed)

    click.echo(f"[LANGKAH 2/4] Mendekripsi {tmp_enc} -> {archive_out}")
    machine.transform_file(tmp_enc, archive_out)
    Path(tmp_enc).unlink(missing_ok=True)

    click.echo(f"[LANGKAH 3/4] Membuka arsip {archive_out}")
    unpack_archive(archive_out, ".")
    Path(archive_out).unlink(missing_ok=True)

    click.echo("[LANGKAH 4/4] Selesai. Berkas berhasil dipulihkan.")


@cli.command()
def interactive() -> None:
    """
    Shell interaktif minimal terinspirasi dari main.c versi C.
    """
    queue: list[str] = []
    click.echo("=== ROCKMAN.EXE Compressor ===")
    click.echo("Masukkan jalur berkas atau perintah:")
    click.echo("  [baris kosong] = jalankan pack dengan antrian saat ini")
    click.echo("  1              = tampilkan antrian")
    click.echo("  2              = kosongkan antrian")
    click.echo("  3              = mulai pemulihan")
    click.echo("  4              = keluar\n")

    while True:
        try:
            line = input("> ").strip()
        except EOFError:
            break

        if not line:
            if not queue:
                click.echo("  (antrian kosong)")
                continue
            base = input("Nama dasar keluaran (baku: output): ").strip() or "output"
            key_png = input(f"Jalur PNG kunci (baku: {base}_key.png): ").strip() or None
            password = input("Sandi XOR (kosong = tanpa sandi): ").strip() or None
            pack(queue, base_name=base, key_png=key_png, password=password)
            queue.clear()
            continue

        if '"' not in line:
            if line == "4":
                break
            if line == "2":
                queue.clear()
                click.echo("  Antrian dikosongkan.")
                continue
            if line == "1":
                if not queue:
                    click.echo("  (antrian kosong)")
                else:
                    for i, p in enumerate(queue, 1):
                        click.echo(f"  [{i}] {p}")
                continue
            if line == "3":
                prefix = input("Awalan log (mis. output): ").strip()
                archive_out = (
                    input("Berkas arsip keluaran (baku: hasil.engm): ").strip()
                    or "hasil.engm"
                )
                key_png = (
                    input(f"Jalur PNG kunci (baku: {prefix}_key.png): ").strip() or None
                )
                password = input("Sandi XOR (kosong = tanpa sandi): ").strip() or None
                restore(
                    prefix=prefix,
                    archive_out=archive_out,
                    key_png=key_png,
                    password=password,
                )
                continue

        # Kalau bukan perintah, anggap sebagai satu atau lebih jalur berkas.
        for token in line.split():
            queue.append(token)
            click.echo(f"  Ditambahkan: {token}")


def main() -> None:
    cli(prog_name="enigma-py")


if __name__ == "__main__":
    main()
