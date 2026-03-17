#include "packer.h"
#include "enigma_engine.h"
#include "define.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>

/*
 * packer.c — ENIGMA Archive packer / unpacker implementation
 *
 * [EN] Implements pak_berkas() and buka_arsip() as declared in packer.h.
 *      pak_berkas() writes a sequential stream: one HeaderArsip followed by
 *      (HeaderBerkas + path bytes + file data) blocks, transferring file data
 *      in UKURAN_CHUNK (4096-byte) pieces to avoid large stack allocations.
 *      buka_arsip() traverses the same layout zero-copy by advancing a cursor
 *      pointer through the caller-supplied buffer.
 *
 * [ID] Implementasi pak_berkas() dan buka_arsip(). Data ditransfer per chunk
 *      4096 byte. buka_arsip() zero-copy via pointer traversal.
 * [JA] pak_berkas() と buka_arsip() の実装。ファイルデータは4096バイトチャンクで転送。
 *      buka_arsip() はゼロコピーのポインタトラバーサルを使用する。
 */

/* Transfer chunk size: _N1024 × _N4 = 4096 bytes
 * [JA] 転送チャンクサイズ: 4096バイト */
#define UKURAN_CHUNK (_N1024 * _N4)

/*
 * buat_magic — Derive 4-byte dynamic magic from seed
 *
 * [EN] Computes the first 4 bytes of SHA-256(seed[32] || "MGCK").
 *      The "MGCK" domain label prevents cross-context collisions with other
 *      SHA-256 derivations from the same seed.  The magic is deterministic:
 *      the same seed always produces the same magic, but without the correct
 *      seed the value cannot be predicted or forged.
 * [ID] Turunkan magic 4 byte dari SHA-256(benih || "MGCK"). Deterministik.
 * [JA] SHA-256(seed || "MGCK") の先頭4バイトを動的マジックとして導出する。
 */
static void buat_magic(const uint8_t *benih, uint8_t *magic) {
    uint8_t tmp[_N32 + _N4];
    uint8_t h[_N32];

    memcpy(tmp, benih, _N32);
    tmp[_N32]          = 'M';
    tmp[_N32 + _N1]    = 'G';
    tmp[_N32 + _N2]    = 'C';
    tmp[_N32 + _N3]    = 'K';

    hitung_sha256(tmp, _N32 + _N4, h);

    /* Salin 4 byte pertama */
    *(uint32_t *)magic = *(const uint32_t *)h;
}

/* ================================================================
 * pak_berkas — Pack multiple files into one .engm archive
 *
 * [EN] Write order (sequential, no seeking):
 *        HeaderArsip
 *        for each file:
 *          HeaderBerkas  (pragma pack(1), no padding)
 *          path bytes    (direct fwrite)
 *          file data     (chunked transfer, UKURAN_CHUNK bytes at a time)
 *      Files that fail to open are recorded as 0-byte entries with a warning.
 * [ID] Tulis berurutan: HeaderArsip + loop (HeaderBerkas + jalur + data chunk).
 * [JA] 順次書き込み: HeaderArsip + ループ（HeaderBerkas + パス + チャンクデータ）。
 * ================================================================ */
int pak_berkas(const char * const *jalur, uint32_t jumlah,
               const char *jalur_keluar, const uint8_t benih[32]) {
    FILE     *keluar;
    HeaderArsip  ha;
    HeaderBerkas hb;
    const char  *jp;      /* pointer ke tiap jalur */
    uint16_t     pj;      /* panjang jalur */
    FILE        *masuk;
    uint8_t      chunk[UKURAN_CHUNK];
    uint64_t     sisa;
    size_t       dibaca;
    uint32_t     i;

    keluar = fopen(jalur_keluar, "wb");
    if (!keluar) return -1;

    /* --- Tulis header arsip (magic dari benih) --- */
    buat_magic(benih, ha.magic);
    ha.versi  = 0x01;
    ha.jumlah = jumlah;
    fwrite(&ha, sizeof(HeaderArsip), 1, keluar);

    /* --- Pak tiap berkas secara berurutan --- */
    for (i = 0; i < jumlah; i++) {
        jp = jalur[i];
        pj = (uint16_t)strlen(jp);

        masuk = fopen(jp, "rb");
        if (!masuk) {
            fprintf(stderr, "  [SKIP] %s\n", jp);
            /* Catat entri ukuran nol dan lanjutkan */
            hb.panjang_jalur = pj;
            hb.ukuran_data   = 0;
            fwrite(&hb,  sizeof(HeaderBerkas), 1,  keluar);
            fwrite(jp,   1,                    pj, keluar);
            continue;
        }

        /* Dapat ukuran berkas */
        fseek(masuk, 0, SEEK_END);
        hb.ukuran_data   = (uint64_t)ftell(masuk);
        hb.panjang_jalur = pj;
        fseek(masuk, 0, SEEK_SET);

        /* Tulis header + jalur */
        fwrite(&hb, sizeof(HeaderBerkas), 1,  keluar);
        fwrite(jp,  1,                    pj, keluar);

        /* Transfer data per chunk */
        sisa = hb.ukuran_data;
        while (sisa > 0) {
            dibaca = fread(chunk, 1,
                           sisa < UKURAN_CHUNK ? (size_t)sisa : UKURAN_CHUNK,
                           masuk);
            if (dibaca == 0) break;
            fwrite(chunk, 1, dibaca, keluar);
            sisa -= (uint64_t)dibaca;
        }

        printf("  [OK] %-60s  %llu byte\n", jp,
               (unsigned long long)hb.ukuran_data);
        fclose(masuk);
    }

    fclose(keluar);
    return 0;
}

/* ================================================================
 * buka_arsip — Parse an .engm archive buffer (zero-copy pointer traversal)
 *
 * [EN] Advances a single cursor pointer from the start to the end of buf[],
 *      filling hasil[] with direct pointers into the buffer — no malloc, no
 *      memcpy.  Cursor movement:
 *        cursor → HeaderArsip         (verify magic + version)
 *        cursor += sizeof(HeaderArsip)
 *        for each entry:
 *          cursor → HeaderBerkas
 *          cursor += sizeof(HeaderBerkas)
 *          InfoBerkas.jalur = cursor  (path, no null terminator)
 *          cursor += panjang_jalur
 *          InfoBerkas.data  = cursor  (raw file data)
 *          cursor += ukuran_data
 *      Returns -1 immediately on any bounds violation.
 * [ID] Traverse pointer zero-copy. Isi hasil[] dengan pointer ke buffer.
 * [JA] ゼロコピーのポインタトラバーサル。hasil[] にバッファへの直接ポインタを格納。
 * ================================================================ */
int buka_arsip(const uint8_t *buf, size_t ukuran,
               InfoBerkas *hasil, uint32_t *jumlah_keluar,
               const uint8_t benih[32]) {
    const uint8_t    *kursor = buf;
    const uint8_t    *batas  = buf + ukuran;
    const HeaderArsip *ha;
    const HeaderBerkas *hb;
    uint8_t  magic_expected[4];
    uint32_t i;

    /* Turunkan magic yang diharapkan dari benih dan cocokkan dengan header */
    buat_magic(benih, magic_expected);

    if (kursor + sizeof(HeaderArsip) > batas)              return -1;
    ha = (const HeaderArsip *)kursor;
    if (memcmp(ha->magic, magic_expected, _N4) != 0)        return -1;
    if (ha->versi != 0x01)                                  return -1;
    kursor += sizeof(HeaderArsip);

    *jumlah_keluar = ha->jumlah;

    /* Penelusuran pointer: parse tiap entri */
    for (i = 0; i < ha->jumlah; i++) {
        if (kursor + sizeof(HeaderBerkas) > batas)  return -1;
        hb = (const HeaderBerkas *)kursor;
        kursor += sizeof(HeaderBerkas);

        /* Jalur: lewati pointer langsung (zero-copy) */
        if (kursor + hb->panjang_jalur > batas)     return -1;
        hasil[i].jalur         = (const char *)kursor;
        hasil[i].panjang_jalur = hb->panjang_jalur;
        kursor += hb->panjang_jalur;

        /* Data: cukup pointer juga */
        if (kursor + (size_t)hb->ukuran_data > batas) return -1;
        hasil[i].data        = kursor;
        hasil[i].ukuran_data = hb->ukuran_data;
        kursor += (size_t)hb->ukuran_data;
    }

    return 0;
}
