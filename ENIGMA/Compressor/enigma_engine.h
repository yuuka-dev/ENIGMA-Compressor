#ifndef ENIGMA_ENGINE_H
#define ENIGMA_ENGINE_H

#include <stdint.h>
#include <string.h>

/*
 * enigma_engine.h — Enigma cipher engine public API
 *
 * [EN] Defines the 256-symbol Enigma machine and its public interface.
 *      The cipher uses JUMLAH_ROTOR (3) rotors, each a bijective S-Box over
 *      uint8_t[256], plus a fixed-point-free reflector.  Encryption and
 *      decryption use the identical function (involution property), so a
 *      second call with the same key restores the original plaintext.
 *
 *      Rotors are generated deterministically from a 32-byte seed using a
 *      CTR-mode SHA-256 stream and Fisher-Yates shuffle, making each
 *      encryption session unique without storing the key explicitly.
 *
 *      SHA-256 is also exposed publicly so other modules (wikipedia_seed,
 *      png_lsb) can share the same implementation without a dependency on
 *      an external library.
 *
 * [ID] Definisi mesin Enigma 256-simbol dan antarmuka publiknya.
 *      Enkripsi dan dekripsi menggunakan fungsi yang sama (involutif).
 * [JA] 256シンボルのEnigmaマシン公開API。暗号化と復号は同一関数（対合性）。
 */

/* Number of rotors in the cipher machine
 * [ID] Jumlah rotor | [JA] ローター数 */
#define JUMLAH_ROTOR 3

/*
 * MesinEnigma — Enigma machine state
 *
 * [EN] Holds all mutable state for one encryption session.
 *      rotor[r]      : forward substitution table (right-to-left pass)
 *      rotor_balik[r]: inverse table (left-to-right return pass)
 *      reflektor     : involution with no fixed points (reflector)
 *      offset[r]     : current stepping position of each rotor
 *
 * [ID] Menyimpan seluruh status satu sesi enkripsi.
 * [JA] 1セッション分の暗号機状態を保持する。
 */
typedef struct {
    uint8_t rotor[JUMLAH_ROTOR][256];       /* forward S-Box (right→left)      */
    uint8_t rotor_balik[JUMLAH_ROTOR][256]; /* inverse S-Box (left→right)      */
    uint8_t reflektor[256];                 /* reflector — involution, no fixpt */
    uint8_t offset[JUMLAH_ROTOR];           /* current stepping offsets         */
} MesinEnigma;

/*
 * hasilkan_rotor_dari_benih — Initialise rotors from a raw seed
 *
 * [EN] Derives a deterministic CTR-mode SHA-256 byte stream from the seed,
 *      then uses Fisher-Yates shuffle to fill each rotor S-Box and builds its
 *      inverse table.  The reflector is generated last from the same stream.
 *      Calling this twice with identical seeds produces identical machines.
 *
 *      mesin        : machine struct to initialise (all fields overwritten)
 *      benih        : seed bytes (typically 32 bytes from Wikipedia SHA-256)
 *      panjang_benih: seed length in bytes
 *
 * [ID] Inisialisasi rotor secara deterministik dari benih menggunakan CTR-SHA256
 *      + Fisher-Yates. Benih sama selalu menghasilkan mesin sama.
 * [JA] CTR-SHA256ストリーム + Fisher-Yatesシャッフルでローターを初期化する。同じ種は同じ機械を生成。
 */
void hasilkan_rotor_dari_benih(MesinEnigma *mesin,
                                const uint8_t *benih, size_t panjang_benih);

/*
 * enkripsi_byte — Encrypt (or decrypt) a single byte
 *
 * [EN] Passes byte b through the full Enigma path:
 *        rotor[0] → rotor[1] → rotor[2] → reflector → rotor_balik[2]
 *        → rotor_balik[1] → rotor_balik[0]
 *      then advances the rotor stepping (odometer-style carry).
 *      Because the reflector is an involution and the path is symmetric,
 *      applying this function twice with the same key stream returns the
 *      original byte — hence "involutive".
 *
 *      mesin: machine whose state is advanced by one step after the call
 *      b    : input byte
 *      Returns: transformed byte
 *
 * [ID] Enkripsi/dekripsi satu byte (involutif: fungsi sama untuk keduanya).
 * [JA] 1バイトを暗号化/復号する（対合：同じ関数で暗号化・復号が可能）。
 */
uint8_t enkripsi_byte(MesinEnigma *mesin, uint8_t b);

/*
 * hitung_sha256 — Compute SHA-256 hash
 *
 * [EN] Standard SHA-256 over an arbitrary byte buffer.
 *      Exposed publicly so wikipedia_seed and png_lsb can share the
 *      implementation without pulling in an external crypto library.
 *
 *      data   : input buffer
 *      panjang: input length in bytes
 *      hasil  : 32-byte output buffer (must be at least 32 bytes)
 *
 * [ID] SHA-256 standar. Dibagikan ke modul lain agar tidak perlu lib eksternal.
 * [JA] 標準SHA-256。他モジュールと共有し外部ライブラリ依存を排除する。
 */
void hitung_sha256(const uint8_t *data, size_t panjang, uint8_t hasil[32]);

/*
 * enkripsi_berkas — Apply Enigma transform to an entire file
 *
 * [EN] Reads jalur_masuk in 4096-byte chunks, passes every byte through
 *      enkripsi_byte(), and writes the result to jalur_keluar.
 *      Because the transform is involutive, the same call encrypts and
 *      decrypts — calling it twice with the same rotor state recovers the
 *      original file.
 *
 *      mesin       : initialised machine (state is consumed during the call)
 *      jalur_masuk : path to input file
 *      jalur_keluar: path to output file (created or overwritten)
 *      Returns: 0 = success / -1 = I/O error
 *
 * [ID] Transform Enigma seluruh berkas (involutif). Sama untuk enkripsi/dekripsi.
 * [JA] ファイル全体にEnigma変換を適用する（対合：暗号化・復号で同じ関数を使用）。
 */
int enkripsi_berkas(MesinEnigma *mesin,
                    const char *jalur_masuk,
                    const char *jalur_keluar);

#endif /* ENIGMA_ENGINE_H */
