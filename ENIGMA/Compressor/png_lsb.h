#ifndef PNG_LSB_H
#define PNG_LSB_H

/*
 * png_lsb.h
 *
 * Sembunyikan/ekstrak benih 32 byte dengan steganografi PNG LSB.
 *
 * Alur sembunyikan:
 *   benih[32]
 *     -> XOR( SHA-256(sandi) )
 *     -> Base64 encode (44 karakter)
 *     -> embed ke LSB piksel PNG 64x64 RGB
 *
 * Alur ekstrak:
 *   Ekstrak LSB piksel PNG
 *     -> Base64 decode
 *     -> XOR( SHA-256(sandi) )
 *     -> benih[32]
 */

#include <stdint.h>
#include <stddef.h>

/* Sembunyikan benih ke PNG LSB
 *   jalur_keluar : jalur berkas PNG keluaran
 *   benih[32]    : benih 32 byte yang disembunyikan
 *   sandi        : sandi turunan XOR (kosong = tanpa XOR)
 *   Nilai kembali: 0=sukses / -1=error */
int sembunyikan_benih_png(const char  *jalur_keluar,
                           const uint8_t benih[32],
                           const char  *sandi);

/* Ekstrak benih dari PNG LSB
 *   jalur_masuk : jalur berkas PNG masukan
 *   benih[32]   : buffer terima benih yang dipulihkan
 *   sandi       : sandi turunan XOR (kosong = tanpa XOR)
 *   Nilai kembali: 0=sukses / -1=error */
int ekstrak_benih_png(const char *jalur_masuk,
                       uint8_t     benih[32],
                       const char *sandi);

#endif /* PNG_LSB_H */
