#ifndef ENIGMA_ENGINE_H
#define ENIGMA_ENGINE_H

#include <stdint.h>
#include <string.h>

/* ================================================================
 * Struktur utama Mesin Enigma 256-bit
 * 3 rotor sebagai S-Box uint8_t[256] + reflector involusi
 * ================================================================ */

#define JUMLAH_ROTOR 3

typedef struct {
    uint8_t rotor[JUMLAH_ROTOR][256];       /* S-Box maju (kanan->kiri) */
    uint8_t rotor_balik[JUMLAH_ROTOR][256]; /* S-Box terbalik (involusi) */
    uint8_t reflektor[256];                 /* Reflektor - involusi tanpa titik tetap */
    uint8_t offset[JUMLAH_ROTOR];           /* Offset stepping saat ini */
} MesinEnigma;

/* Bangkitkan rotor secara dinamis dari benih mentah (seed) */
void    hasilkan_rotor_dari_benih(MesinEnigma *mesin,
                                  const uint8_t *benih, size_t panjang_benih);

/* Enkripsi/dekripsi satu byte (involusi: fungsi yang sama untuk keduanya) */
uint8_t enkripsi_byte(MesinEnigma *mesin, uint8_t b);

/* SHA-256 publik - dipakai modul pengambil Wikipedia */
void    hitung_sha256(const uint8_t *data, size_t panjang, uint8_t hasil[32]);

/* Transform Enigma seluruh berkas (involutif: enkripsi/dekripsi sama)
 * jalur_masuk  : jalur berkas masukan
 * jalur_keluar : jalur berkas keluaran
 * Nilai kembali: 0=sukses / -1=error */
int     enkripsi_berkas(MesinEnigma *mesin,
                        const char *jalur_masuk,
                        const char *jalur_keluar);

#endif /* ENIGMA_ENGINE_H */
