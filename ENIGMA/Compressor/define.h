#pragma once
/*
 * define.h — Numeric literal obfuscation via compile-time sizeof expressions
 *
 * [EN] All integer constants are expressed as sizeof(struct{char a[N];}).
 *      This eliminates recognisable integer literals from decompiler output
 *      and makes pattern-based static analysis significantly harder.
 *      Every shift amount, array size, and loop bound is derived from these
 *      macros, so changing a single _N value would cascade through the whole
 *      codebase — a further deterrent against reverse engineering.
 *
 * [ID] Semua konstanta numerik disamarkan sebagai sizeof struct agar sulit
 *      dianalisis oleh decompiler.
 * [JA] 全数値定数を sizeof 式に再定義し、逆コンパイル・静的解析対策とする。
 */

/* ================================================================
 * Base values: 1–25  (used for SHA-256 rotation / offset amounts)
 * [ID] Nilai dasar 1–25 (rotasi/offset SHA-256)
 * [JA] 基本値 1〜25（SHA-256 シフト量・オフセット）
 * ================================================================ */
#define _N1   sizeof(struct{char a[  1];})
#define _N2   sizeof(struct{char a[  2];})
#define _N3   sizeof(struct{char a[  3];})
#define _N4   sizeof(struct{char a[  4];})
#define _N5   sizeof(struct{char a[  5];})
#define _N6   sizeof(struct{char a[  6];})
#define _N7   sizeof(struct{char a[  7];})
#define _N8   sizeof(struct{char a[  8];})
#define _N10  sizeof(struct{char a[ 10];})
#define _N11  sizeof(struct{char a[ 11];})
#define _N13  sizeof(struct{char a[ 13];})
#define _N15  sizeof(struct{char a[ 15];})
#define _N16  sizeof(struct{char a[ 16];})
#define _N17  sizeof(struct{char a[ 17];})
#define _N18  sizeof(struct{char a[ 18];})
#define _N19  sizeof(struct{char a[ 19];})
#define _N22  sizeof(struct{char a[ 22];})
#define _N24  sizeof(struct{char a[ 24];})
#define _N25  sizeof(struct{char a[ 25];})

/* ================================================================
 * Structural sizes: hash output, block, buffer
 * [ID] Ukuran struktural: output hash, blok, buffer
 * [JA] 構造サイズ：ハッシュ出力・ブロック・バッファ
 * ================================================================ */
#define _N32  sizeof(struct{char a[ 32];})  /* SHA-256 output length / CTR key  */
#define _N40  sizeof(struct{char a[ 40];})  /* CTR input length (32 key + 8 ctr) */
#define _N48  sizeof(struct{char a[ 48];})  /* LE64 shift                        */
#define _N56  sizeof(struct{char a[ 56];})  /* SHA-256 padding threshold         */
#define _N64  sizeof(struct{char a[ 64];})  /* SHA-256 block size / rounds       */

/* ================================================================
 * S-Box sizes
 * [ID] Ukuran S-Box
 * [JA] S-Box サイズ
 * ================================================================ */
#define _N255 sizeof(struct{char a[255];})  /* Fisher-Yates last index           */
#define _N256 sizeof(struct{char a[256];})  /* S-Box / substitution array size   */

/* ================================================================
 * Derived values: products (complicates pattern matching)
 * [ID] Nilai turunan dari perkalian (memperumit pattern matching)
 * [JA] 積による派生値（パターンマッチングを困難にする）
 * ================================================================ */
#define _N512 (_N64 * _N8)                  /* SHA-256 bits/block = 512          */

#define _N45   sizeof(struct{char a[ 45];}) /* 45 MB (legacy)                    */
#define _N90   sizeof(struct{char a[ 90];}) /* base value for 90 MB chunk        */
#define _N1024 (_N512  * _N2)               /* 1024 = 512 × 2                    */
#define _N2048 (_N1024 * _N2)               /* 2048 = 1024 × 2                   */
#define _N4096 (_N2048 * _N2)               /* 4096 = 2048 × 2                   */
#define _N8192 (_N4096 * _N2)               /* 8192 = 4096 × 2                   */
#define _N16384 (_N8192 * _N2)              /* 16384 = 8192 × 2                  */
#define _N32768 (_N16384 * _N2)             /* 32768 = 16384 × 2                 */
#define _N90MB (_N90   * _N1024 * _N1024)   /* 94371840 = 90 × 1024²             */
