#ifndef WIKIPEDIA_SEED_H
#define WIKIPEDIA_SEED_H

#include <stdint.h>
#include <stddef.h>

/*
 * wikipedia_seed.h — Unique seed generation from a random Wikipedia article
 *
 * [EN] Generates an unpredictable 32-byte seed for each encryption session by
 *      fetching a random Wikipedia article over HTTPS and hashing its content.
 *      Because the article title, revision ID (oldid), and wikitext all change
 *      unpredictably over time, the seed cannot be reproduced without recording
 *      the exact article revision used — which is stored in the PNG key file.
 *
 *      Seed derivation pipeline:
 *        1. GET /w/api.php?action=query&list=random  → article title
 *        2. GET /w/api.php?action=query&prop=revisions&titles=TITLE → oldid
 *        3. GET /w/index.php?action=raw&oldid=REVID  → raw wikitext
 *        4. SHA-256( revid_string || 0x0A || wikitext ) → 32-byte seed
 *
 *      The revid is mixed in so that even two fetches of the same article at
 *      different revisions produce different seeds.
 *
 *      Dependencies: enigma_engine.h (hitung_sha256), winhttp.lib (Windows API)
 *      No external library required.
 *
 * [ID] Bangkitkan benih 32 byte dari artikel acak Wikipedia via HTTPS.
 *      SHA-256(revid || wikitext). Tanpa lib eksternal (winhttp.lib bawaan).
 * [JA] Wikipedia のランダム記事を HTTPS で取得し SHA-256 ハッシュを種として生成する。
 *      外部ライブラリ不要（Windows 標準 winhttp.lib を使用）。
 */

/*
 * ambil_benih_wikipedia — Fetch a random article and derive a 32-byte seed
 *
 * [EN] Executes the four-step pipeline described above.  On success, writes
 *      32 seed bytes to benih[] and a human-readable info string to info[].
 *      The info string has the form "Article Title (oldid=123456, 8192 byte)"
 *      and is intended for display to the user and storage in the key PNG so
 *      the seed origin can be identified later.
 *
 *      benih[32]: output buffer for the 32-byte seed
 *      info     : output buffer for the info string (may be NULL to skip)
 *      info_sz  : size of the info buffer in bytes
 *      Returns: 0 = success / -1 = network or parsing failure
 *
 * [ID] Ambil artikel acak Wikipedia dan bangkitkan benih 32 byte.
 *      info berisi "judul (oldid=..., ... byte)".
 * [JA] Wikipedia のランダム記事を取得して32バイト種を生成する。
 *      info には "タイトル (oldid=..., ... byte)" が格納される。
 */
int ambil_benih_wikipedia(uint8_t benih[32], char *info, size_t info_sz);

#endif /* WIKIPEDIA_SEED_H */
