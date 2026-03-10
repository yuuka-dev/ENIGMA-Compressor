#ifndef PACKER_H
#define PACKER_H

#include <stdint.h>
#include <stddef.h>

/* ================================================================
 * Format biner ENIGMA Archive (.engm)
 *
 * [HeaderArsip]
 *   magic[4]           magic dinamis - 4 byte pertama SHA-256(benih || "MGCK")
 *                      magic berubah tiap benih berubah
 *   versi              0x01
 *   jumlah             uint32_t - jumlah berkas
 *
 * [HeaderBerkas] × jumlah
 *   panjang_jalur      uint16_t - panjang string jalur (tanpa null)
 *   ukuran_data        uint64_t - ukuran data berkas (byte)
 *   jalur[panjang_jalur]        - byte jalur (tanpa null terminator)
 *   data[ukuran_data]           - isi berkas mentah
 *
 * Traversal: geser pointer sebesar sizeof(Header) + panjang + ukuran
 * ================================================================ */

#pragma pack(push, 1)

/* Header: seluruh arsip */
typedef struct {
    uint8_t  magic[4];   /* magic dinamis (tergantung benih) */
    uint8_t  versi;      /* nomor versi = 0x01               */
    uint32_t jumlah;     /* jumlah berkas tersimpan           */
} HeaderArsip;

/* Header: tiap entri berkas */
typedef struct {
    uint16_t panjang_jalur; /* panjang jalur (tanpa null)    */
    uint64_t ukuran_data;   /* ukuran data (byte)           */
    /* Layout memori setelahnya:
     *   uint8_t jalur[panjang_jalur]
     *   uint8_t data [ukuran_data  ]  */
} HeaderBerkas;

#pragma pack(pop)

/* ================================================================
 * Hasil unpack: penelusuran pointer (zero-copy, langsung referensi buffer)
 * ================================================================ */
typedef struct {
    const char    *jalur;         /* pointer ke awal jalur (tanpa null)    */
    uint16_t       panjang_jalur; /* panjang jalur                         */
    const uint8_t *data;          /* pointer ke awal data                 */
    uint64_t       ukuran_data;   /* ukuran data                           */
} InfoBerkas;

/* ================================================================
 * API
 * ================================================================ */

/* Pak banyak berkas ke satu arsip
 *   jalur[]     : larik jalur berkas
 *   jumlah      : jumlah berkas
 *   jalur_keluar: jalur berkas keluaran
 *   benih       : benih 32 byte untuk turunan magic
 *   Nilai kembali: 0=sukses, -1=gagal */
int pak_berkas(const char * const *jalur, uint32_t jumlah,
               const char *jalur_keluar, const uint8_t benih[32]);

/* Unpack buffer memori dengan penelusuran pointer (zero-copy)
 *   buf          : buffer berisi seluruh arsip
 *   ukuran       : ukuran buffer
 *   hasil        : larik InfoBerkas (dialokasi pemanggil)
 *   jumlah_keluar: terima jumlah berkas riil
 *   benih        : benih 32 byte untuk verifikasi magic
 *   Nilai kembali: 0=sukses, -1=tidak valid */
int buka_arsip(const uint8_t *buf, size_t ukuran,
               InfoBerkas *hasil, uint32_t *jumlah_keluar,
               const uint8_t benih[32]);

#endif /* PACKER_H */
