#pragma once
/* ================================================================
 * SS1  Redefinisi literal numerik
 *
 *     sizeof(struct{char a[N];}) ekspresi konstanta kompilasi,
 *     dipakai untuk ukuran larik, shift, batas loop.
 *     Menghilangkan pola literal dari output decompiler.
 * ================================================================ */

 /* Nilai dasar: 1 s/d 25 (rotasi/offset SHA-256) */
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

/* Ukuran struktural: output hash, blok, buffer */
#define _N32  sizeof(struct{char a[ 32];})  /* panjang output SHA-256 / key CTR */
#define _N40  sizeof(struct{char a[ 40];})  /* panjang input CTR (32+8)         */
#define _N48  sizeof(struct{char a[ 48];})  /* shift LE64                      */
#define _N56  sizeof(struct{char a[ 56];})  /* ambang padding SHA-256          */
#define _N64  sizeof(struct{char a[ 64];})  /* ukuran blok / ronde SHA-256     */

/* Ukuran S-Box */
#define _N255 sizeof(struct{char a[255];})  /* indeks akhir Fisher-Yates       */
#define _N256 sizeof(struct{char a[256];})  /* ukuran S-Box / larik substitusi */

/* Nilai turunan: perkalian (memperumit pattern matching) */
#define _N512 (_N64 * _N8)                  /* bit/blok SHA-256 = 512          */

#define _N45   sizeof(struct{char a[ 45];})  /* 45MB (lama)                     */
#define _N90   sizeof(struct{char a[ 90];})  /* nilai dasar chunk 90MB          */
#define _N1024 (_N512  * _N2)               /* 1024 = 512 × 2                  */
#define _N2048 (_N1024 * _N2)               /* 2048 = 1024 × 2                 */
#define _N90MB (_N90   * _N1024 * _N1024)   /* 94371840 = 90 × 1024²           */