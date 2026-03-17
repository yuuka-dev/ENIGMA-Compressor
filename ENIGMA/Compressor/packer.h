#ifndef PACKER_H
#define PACKER_H

#include <stdint.h>
#include <stddef.h>

/*
 * packer.h — ENIGMA Archive (.engm) format and packer/unpacker API
 *
 * [EN] Defines the binary layout of an .engm archive and the two public
 *      functions that create and parse it.
 *
 *      Binary layout:
 *        [HeaderArsip]
 *          magic[4]   — dynamic magic: first 4 bytes of SHA-256(seed || "MGCK").
 *                       Changes with every seed, so the header cannot be
 *                       identified without knowing the correct seed.
 *          versi      — format version, currently 0x01
 *          jumlah     — uint32_t count of stored files
 *
 *        [HeaderBerkas] × jumlah
 *          panjang_jalur  — uint16_t path length (no null terminator)
 *          ukuran_data    — uint64_t raw file size in bytes
 *          jalur[panjang_jalur]   — raw path bytes
 *          data[ukuran_data]      — raw file contents
 *
 *      Traversal: advance pointer by sizeof(HeaderBerkas) + path_len + data_len
 *      for each entry.  buka_arsip() does this zero-copy by handing out pointers
 *      directly into the caller-supplied buffer.
 *
 * [ID] Format biner arsip .engm: header dengan magic dinamis, diikuti entri
 *      berkas berurutan. buka_arsip() menggunakan zero-copy pointer traversal.
 * [JA] .engmアーカイブのバイナリ形式。動的マジックと連続ファイルエントリ。
 *      buka_arsip()はゼロコピーのポインタトラバーサルを使用する。
 */

#pragma pack(push, 1)

/*
 * HeaderArsip — Archive-level header (9 bytes, packed)
 *
 * [EN] Written once at the start of the .engm file.
 *      The magic is seed-dependent, making the file unreadable without the key.
 * [ID] Header arsip. Magic bergantung pada benih.
 * [JA] アーカイブ先頭ヘッダー。マジックはシード依存。
 */
typedef struct {
    uint8_t  magic[4];   /* dynamic magic (seed-dependent)   */
    uint8_t  versi;      /* format version = 0x01            */
    uint32_t jumlah;     /* number of stored files           */
} HeaderArsip;

/*
 * HeaderBerkas — Per-file header (10 bytes, packed)
 *
 * [EN] Immediately followed in memory by `panjang_jalur` path bytes and
 *      then `ukuran_data` data bytes.  No alignment padding (pragma pack 1).
 * [ID] Diikuti oleh byte jalur lalu byte data. Tanpa padding.
 * [JA] パスバイトとデータバイトが直後に続く。パディングなし（pack 1）。
 */
typedef struct {
    uint16_t panjang_jalur; /* path length (no null terminator) */
    uint64_t ukuran_data;   /* file size in bytes               */
    /* Memory layout after this struct:
     *   uint8_t jalur[panjang_jalur]
     *   uint8_t data [ukuran_data  ] */
} HeaderBerkas;

#pragma pack(pop)

/*
 * InfoBerkas — Unpacked file entry (zero-copy pointer into caller's buffer)
 *
 * [EN] buka_arsip() fills an array of these structs with pointers that refer
 *      directly into the buffer passed by the caller — no malloc, no memcpy.
 *      The caller must keep the original buffer alive for as long as InfoBerkas
 *      entries are in use.
 * [ID] Hasil unpack: pointer langsung ke buffer pemanggil (zero-copy).
 * [JA] ゼロコピーのアンパック結果。呼び出し元バッファへの直接ポインタ。
 */
typedef struct {
    const char    *jalur;         /* pointer to path start (not null-terminated) */
    uint16_t       panjang_jalur; /* path length in bytes                        */
    const uint8_t *data;          /* pointer to file data start                  */
    uint64_t       ukuran_data;   /* file size in bytes                          */
} InfoBerkas;

/* ================================================================
 * Public API
 * [ID] API publik | [JA] 公開API
 * ================================================================ */

/*
 * pak_berkas — Pack multiple files into one .engm archive
 *
 * [EN] Writes HeaderArsip (with seed-derived magic) followed by one
 *      HeaderBerkas + path + data block per input file.  Files that cannot
 *      be opened are recorded as zero-byte entries and skipped with a warning.
 *
 *      jalur[]     : array of file paths to pack
 *      jumlah      : number of paths
 *      jalur_keluar: output archive path (created or overwritten)
 *      benih       : 32-byte seed for dynamic magic derivation
 *      Returns: 0 = success / -1 = I/O error
 *
 * [ID] Pak banyak berkas ke satu arsip. Berkas tidak bisa dibuka dicatat nol byte.
 * [JA] 複数ファイルを1つのアーカイブにパックする。開けないファイルはゼロバイトとして記録。
 */
int pak_berkas(const char * const *jalur, uint32_t jumlah,
               const char *jalur_keluar, const uint8_t benih[32]);

/*
 * buka_arsip — Parse an .engm archive buffer (zero-copy)
 *
 * [EN] Validates the magic against the supplied seed, then traverses the
 *      buffer filling hasil[] with direct pointers into buf[].  No dynamic
 *      allocation is performed; the caller must ensure buf stays valid.
 *
 *      buf          : buffer containing the entire archive
 *      ukuran       : buffer size in bytes
 *      hasil        : caller-allocated InfoBerkas array (must hold ≥ file count)
 *      jumlah_keluar: receives the actual number of files
 *      benih        : 32-byte seed for magic verification
 *      Returns: 0 = success / -1 = invalid archive or wrong seed
 *
 * [ID] Parse buffer arsip tanpa alokasi (zero-copy). Verifikasi magic dengan benih.
 * [JA] アーカイブバッファをゼロコピーで解析する。マジックをシードで検証する。
 */
int buka_arsip(const uint8_t *buf, size_t ukuran,
               InfoBerkas *hasil, uint32_t *jumlah_keluar,
               const uint8_t benih[32]);

#endif /* PACKER_H */
