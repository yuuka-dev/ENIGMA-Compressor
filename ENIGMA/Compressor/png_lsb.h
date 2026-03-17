#ifndef PNG_LSB_H
#define PNG_LSB_H

/*
 * png_lsb.h — Seed steganography via PNG LSB embedding
 *
 * [EN] Hides and recovers a 32-byte cryptographic seed inside the LSBs of a
 *      64×64 RGB PNG image without requiring any external library.
 *
 *      Hide pipeline:
 *        seed[32]
 *          → XOR with SHA-256(password)   (skipped when password is empty)
 *          → Base64 encode                (32 bytes → 44 ASCII chars)
 *          → prepend 1-byte length field  → 45-byte payload
 *          → embed into LSB of each pixel channel of a 64×64 RGB carrier
 *          → write PNG (self-generated, DEFLATE stored block, no zlib lib)
 *
 *      Recover pipeline (exact inverse):
 *        Read PNG → extract LSBs → Base64 decode → XOR → seed[32]
 *
 *      Carrier capacity: 64 × 64 × 3 = 12288 bits = 1536 bytes
 *      Payload size:     1 + 44 = 45 bytes = 360 bits  (well within capacity)
 *
 * [ID] Sembunyikan/ekstrak benih 32 byte di LSB piksel PNG 64×64 RGB.
 *      Tanpa lib eksternal. XOR opsional dengan SHA-256(sandi).
 * [JA] 64×64 RGB PNG のピクセル LSB に32バイト種を隠蔽・復元する。外部ライブラリ不要。
 */

#include <stdint.h>
#include <stddef.h>

/*
 * sembunyikan_benih_png — Hide a 32-byte seed inside a PNG file's LSBs
 *
 * [EN] Creates a new 64×64 RGB PNG at jalur_keluar with the seed embedded in
 *      pixel channel LSBs.  Carrier pixels are filled with deterministic
 *      SHA-256 CTR noise so the image looks like a valid photo thumbnail.
 *      If sandi is non-empty, the seed is XOR-encrypted with SHA-256(sandi)
 *      before embedding, making extraction impossible without the password.
 *
 *      jalur_keluar: output PNG file path (created or overwritten)
 *      benih[32]   : 32-byte seed to hide
 *      sandi       : XOR password string (empty string = no XOR)
 *      Returns: 0 = success / -1 = error
 *
 * [ID] Buat PNG 64×64 dengan benih tersembunyi di LSB piksel. XOR opsional.
 * [JA] 種を LSB に埋め込んだ 64×64 PNG を生成する。パスワード指定時は XOR 暗号化。
 */
int sembunyikan_benih_png(const char   *jalur_keluar,
                           const uint8_t benih[32],
                           const char   *sandi);

/*
 * ekstrak_benih_png — Recover a 32-byte seed from a PNG file's LSBs
 *
 * [EN] Reads jalur_masuk (must be a PNG produced by sembunyikan_benih_png),
 *      extracts the LSB payload, Base64-decodes it, and XOR-decrypts with
 *      SHA-256(sandi) if sandi is non-empty.  Returns -1 if the payload
 *      length field does not match the expected value (wrong file or corruption).
 *
 *      jalur_masuk: path to the PNG key file
 *      benih[32]  : output buffer for the recovered seed
 *      sandi      : XOR password (must match the one used during hiding)
 *      Returns: 0 = success / -1 = error or wrong password
 *
 * [ID] Ekstrak benih dari PNG LSB. Sandi harus cocok dengan saat penyembunyian.
 * [JA] PNG の LSB から種を復元する。パスワードは隠蔽時と一致が必要。
 */
int ekstrak_benih_png(const char *jalur_masuk,
                       uint8_t     benih[32],
                       const char *sandi);

#endif /* PNG_LSB_H */
