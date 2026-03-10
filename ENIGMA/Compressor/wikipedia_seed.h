#ifndef WIKIPEDIA_SEED_H
#define WIKIPEDIA_SEED_H

#include <stdint.h>
#include <stddef.h>

/*
 * wikipedia_seed.h
 *
 * Bangkitkan benih Enigma dari artikel acak Wikipedia + oldid.
 *
 * Alur:
 *   1. GET /w/api.php?action=query&list=random  -> ambil judul
 *   2. GET /w/api.php?action=query&prop=revisions -> ambil oldid
 *   3. GET /w/index.php?action=raw&oldid=REVID  -> ambil wikitext mentah
 *   4. SHA-256( revid || 0x0A || wikitext )     -> benih 32 byte
 *
 * Dependensi: enigma_engine.h (hitung_sha256)
 *             winhttp.lib (API sistem Windows)
 */

/* Ambil artikel acak Wikipedia dan bangkitkan benih
 *
 *   benih[32] : buffer keluaran benih SHA-256
 *   info      : buffer string "judul (oldid=nomor)" (boleh NULL)
 *   info_sz   : ukuran buffer info
 *
 *   Nilai kembali: 0 = sukses / -1 = gagal */
int ambil_benih_wikipedia(uint8_t benih[32], char *info, size_t info_sz);

#endif /* WIKIPEDIA_SEED_H */
