/*
 * png_lsb.c
 *
 * Steganografi PNG LSB - modul penyembunyian/ekstraksi benih
 *
 * Tanpa lib eksternal. Bangkitkan PNG sendiri (64x64 RGB, DEFLATE stored block).
 *
 * Alur sembunyikan:
 *   benih -> XOR(SHA256(sandi)) -> Base64 -> LSB piksel -> tulis PNG
 *
 * Alur ekstrak:
 *   Baca PNG -> LSB piksel -> Base64 -> XOR(SHA256(sandi)) -> benih
 *
 * Kapasitas LSB: 64 x 64 x 3ch = 12,288 bit = 1,536 byte
 * Kebutuhan: [panjang:1byte] + [Base64:44byte] = 45byte = 360bit
 */

#include "png_lsb.h"
#include "enigma_engine.h"  /* hitung_sha256() */
#include "define.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

/* ================================================================
 * Konstanta internal
 * ================================================================ */

/* Ukuran gambar carrier (64x64 RGB) */
#define IMG_W    ((size_t)_N64)
#define IMG_H    ((size_t)_N64)
#define IMG_CH   ((size_t)_N3)
#define IMG_PIX  (IMG_W * IMG_H)             /* 4096 piksel        */
#define IMG_BYTES (IMG_PIX * IMG_CH)          /* 12288 channel      */

/* Byte per baris (termasuk filter byte) */
#define ROW_STRIDE  (_N1 + IMG_W * IMG_CH)   /* 193 bytes          */

/* Total byte data piksel mentah */
#define RAW_BYTES   (IMG_H * ROW_STRIDE)     /* 12352 bytes        */

/* Struktur payload: [len:1][base64:44] = 45 byte */
#define B64_LEN   (_N1 + _N1 + _N1 + _N1 +  \
                   _N1 + _N1 + _N1 + _N1 +  \
                   _N1 + _N1 + _N1 + _N1 +  \
                   _N1 + _N1 + _N1 + _N1 +  \
                   _N1 + _N1 + _N1 + _N1 +  \
                   _N1 + _N1 + _N1 + _N1 +  \
                   _N1 + _N1 + _N1 + _N1 +  \
                   _N1 + _N1 + _N1 + _N1 +  \
                   _N1 + _N1 + _N1 + _N1 +  \
                   _N1 + _N1 + _N1 + _N1 +  \
                   _N1 + _N1 + _N1 + _N1)   /* 44 */
#define PAYLOAD_LEN  (_N1 + B64_LEN)         /* 45 */

/* ================================================================
 * Adler-32 checksum (wajib untuk zlib)
 * ================================================================ */

static uint32_t adler32_hitung(const uint8_t *data, size_t n) {
    uint32_t s1 = 1u, s2 = 0u;
    const uint8_t *p   = data;
    const uint8_t *end = data + n;
    while (p < end) {
        s1 = (s1 + *p++) % 65521u;
        s2 = (s2 + s1)   % 65521u;
    }
    return (s2 << 16) | s1;
}

/* ================================================================
 * CRC-32 (untuk chunk PNG)
 * ================================================================ */

static uint32_t g_crc_table[256];
static int      g_crc_ready = 0;

static void crc_init(void) {
    uint32_t c;
    int n, k;
    if (g_crc_ready) return;
    for (n = 0; n < _N256; n++) {
        c = (uint32_t)n;
        for (k = 0; k < _N8; k++)
            c = (c & 1u) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        g_crc_table[n] = c;
    }
    g_crc_ready = 1;
}

static uint32_t crc32_buf(const uint8_t *buf, size_t len) {
    uint32_t crc = 0xFFFFFFFFu;
    const uint8_t *p   = buf;
    const uint8_t *end = buf + len;
    if (!g_crc_ready) crc_init();
    while (p < end)
        crc = g_crc_table[(crc ^ *p++) & 0xFFu] ^ (crc >> 8);
    return crc ^ 0xFFFFFFFFu;
}

/* ================================================================
 * Base64 encode / decode
 * ================================================================ */

static const char B64_TBL[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* data[n] -> string base64 out (null-terminated)
 * out perlu ukuran minimal ceil(n/3)*4+1 */
static void b64_encode(const uint8_t *data, size_t n, char *out) {
    const uint8_t *p = data;
    char          *q = out;
    while (n >= 3) {
        *q++ = B64_TBL[ p[0] >> 2];
        *q++ = B64_TBL[(p[0] & 0x03u) << 4 | p[1] >> 4];
        *q++ = B64_TBL[(p[1] & 0x0Fu) << 2 | p[2] >> 6];
        *q++ = B64_TBL[ p[2] & 0x3Fu];
        p += 3; n -= 3;
    }
    if (n == 1) {
        *q++ = B64_TBL[ p[0] >> 2];
        *q++ = B64_TBL[(p[0] & 0x03u) << 4];
        *q++ = '='; *q++ = '=';
    } else if (n == 2) {
        *q++ = B64_TBL[ p[0] >> 2];
        *q++ = B64_TBL[(p[0] & 0x03u) << 4 | p[1] >> 4];
        *q++ = B64_TBL[(p[1] & 0x0Fu) << 2];
        *q++ = '=';
    }
    *q = '\0';
}

/* Karakter base64 c -> nilai 6bit (-1 = invalid/padding) */
static int b64_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

/* String base64 src[src_len] -> out[]
 * Nilai kembali: byte didekode / -1=error */
static int b64_decode(const char *src, size_t src_len, uint8_t *out) {
    uint8_t *q = out;
    size_t   i;
    for (i = 0; i + 3 < src_len; i += 4) {
        int v0 = b64_val(src[i]);
        int v1 = b64_val(src[i+1]);
        int v2, v3;
        if (v0 < 0 || v1 < 0) return -1;
        *q++ = (uint8_t)((v0 << 2) | (v1 >> 4));
        if (src[i+2] == '=') break;
        v2 = b64_val(src[i+2]);
        if (v2 < 0) return -1;
        *q++ = (uint8_t)((v1 << 4) | (v2 >> 2));
        if (src[i+3] == '=') break;
        v3 = b64_val(src[i+3]);
        if (v3 < 0) return -1;
        *q++ = (uint8_t)((v2 << 6) | v3);
    }
    return (int)(q - out);
}

/* ================================================================
 * Bangkitkan piksel carrier (noise SHA-256 CTR)
 *
 * Benih tetap untuk noise pseudo-acak.
 * Ekstraksi bisa replika dengan benih sama, cukup baca LSB.
 * ================================================================ */

static void buat_piksel_dasar(uint8_t *ch, size_t n) {
    /* ASCII "ENIGMA_PNG_LSB_CARRIER" + padding = 32 byte */
    static const uint8_t BENIH_NOISE[32] = {
        0x45,0x4E,0x49,0x47, 0x4D,0x41,0x5F,0x50,
        0x4E,0x47,0x5F,0x4C, 0x53,0x42,0x5F,0x43,
        0x41,0x52,0x52,0x49, 0x45,0x52,0xDE,0xAD,
        0xBE,0xEF,0xCA,0xFE, 0xBA,0xBE,0x13,0x37
    };
    uint8_t  tmp[_N40], hash[_N32];
    uint64_t blok = 0;
    size_t   pos  = 0, i;

    while (pos < n) {
        /* SHA-256( BENIH_NOISE || blok_LE64 ) */
        memcpy(tmp, BENIH_NOISE, _N32);
        tmp[_N32+0] = (uint8_t)(blok);
        tmp[_N32+1] = (uint8_t)(blok >>  _N8);
        tmp[_N32+2] = (uint8_t)(blok >>  _N16);
        tmp[_N32+3] = (uint8_t)(blok >>  _N24);
        tmp[_N32+4] = (uint8_t)(blok >>  _N32);
        tmp[_N32+5] = (uint8_t)(blok >>  _N40);
        tmp[_N32+6] = (uint8_t)(blok >>  _N48);
        tmp[_N32+7] = (uint8_t)(blok >>  _N56);
        hitung_sha256(tmp, _N40, hash);
        blok++;
        for (i = 0; i < _N32 && pos < n; i++, pos++)
            ch[pos] = hash[i];
    }
}

/* ================================================================
 * §6  LSB 埋め込み / 抽出
 * ================================================================ */

/* channels[] の各バイト LSB に data[] のビット列を埋め込む
 * (ビッグエンディアン順: MSB first) */
static void lsb_umat(uint8_t *channels, size_t ch_count,
                     const uint8_t *data, size_t data_bits) {
    size_t bit;
    for (bit = 0; bit < data_bits && bit < ch_count; bit++) {
        uint8_t b = (data[bit >> 3] >> (7u - (bit & 7u))) & 1u;
        channels[bit] = (uint8_t)((channels[bit] & 0xFEu) | b);
    }
}

/* channels[] の各バイト LSB からビット列を抽出して data[] に復元 */
static void lsb_ambil(const uint8_t *channels, size_t ch_count,
                      uint8_t *data, size_t data_bits) {
    size_t bit;
    memset(data, 0, (data_bits + 7u) / 8u);
    for (bit = 0; bit < data_bits && bit < ch_count; bit++) {
        uint8_t b = channels[bit] & 1u;
        data[bit >> 3] |= (uint8_t)(b << (7u - (bit & 7u)));
    }
}

/* ================================================================
 * §7  PNG チャンク書き込みヘルパー
 * ================================================================ */

/* 4バイト big-endian 書き込み */
static void tulis_be32(FILE *f, uint32_t v) {
    uint8_t b[_N4];
    b[0] = (uint8_t)(v >> 24); b[1] = (uint8_t)(v >> 16);
    b[2] = (uint8_t)(v >>  8); b[3] = (uint8_t)(v);
    fwrite(b, 1, _N4, f);
}

/* チャンク書き出し: 長さ(4BE) + タイプ(4) + データ + CRC(4BE) */
static int tulis_chunk(FILE *f, const char type[_N4],
                        const uint8_t *data, uint32_t len) {
    uint32_t crc;
    tulis_be32(f, len);
    if (fwrite(type, 1, _N4, f) != _N4) return -1;
    if (len > 0 && fwrite(data, 1, len, f) != len) return -1;
    /* CRC はタイプ + データに対して計算 */
    crc = crc32_buf((const uint8_t *)type, _N4);
    {   /* CRC の続き: データ部 */
        uint32_t c2 = 0xFFFFFFFFu;
        const uint8_t *tp = (const uint8_t *)type;
        size_t i;
        c2 = 0xFFFFFFFFu;
        for (i = 0; i < _N4; i++)
            c2 = g_crc_table[(c2 ^ tp[i]) & 0xFFu] ^ (c2 >> 8);
        if (data && len > 0) {
            const uint8_t *dp = data;
            const uint8_t *de = data + len;
            while (dp < de)
                c2 = g_crc_table[(c2 ^ *dp++) & 0xFFu] ^ (c2 >> 8);
        }
        crc = c2 ^ 0xFFFFFFFFu;
    }
    tulis_be32(f, crc);
    (void)crc; /* digunakan di atas */
    return 0;
}

/* ================================================================
 * Tulis PNG (64x64 RGB, DEFLATE stored block)
 *
 * Struktur wrapper zlib:
 *   [CMF=0x78][FLG=0x01]           - header zlib
 *   [0x01][LEN_LO][LEN_HI]         - BFINAL=1, BTYPE=00 (stored)
 *   [NLEN_LO][NLEN_HI]             - ~LEN
 *   [RAW_BYTES byte]               - data mentah dengan filter
 *   [Adler-32 BE 4 byte]          - checksum zlib
 * ================================================================ */

static int tulis_png_64x64(FILE *f, const uint8_t *pixels) {
    static const uint8_t PNG_SIG[] = {137,80,78,71,13,10,26,10};
    /* 12352 = 0x3040  ~12352 & 0xFFFF = 0xCFBF */
    const uint16_t LEN  = (uint16_t)RAW_BYTES;
    const uint16_t NLEN = (uint16_t)(~LEN);

    uint8_t *raw  = NULL;  /* data mentah dengan filter     */
    uint8_t *idat = NULL;  /* data IDAT terbungkus zlib     */
    size_t   idat_sz;
    uint32_t adler;
    int      ret = -1;

    raw = (uint8_t *)malloc(RAW_BYTES);
    if (!raw) goto fin;

    /* Tiap baris: filter byte(0) + piksel RGB */
    {
        size_t   row;
        uint8_t *rp = raw;
        const uint8_t *pp = pixels;
        for (row = 0; row < IMG_H; row++) {
            *rp++ = 0x00;   /* filter: None */
            memcpy(rp, pp, IMG_W * IMG_CH);
            rp += IMG_W * IMG_CH;
            pp += IMG_W * IMG_CH;
        }
    }

    adler    = adler32_hitung(raw, RAW_BYTES);
    idat_sz  = _N2 + _N5 + RAW_BYTES + _N4;  /* zlib_hdr + stored_hdr + data + adler */
    idat     = (uint8_t *)malloc(idat_sz);
    if (!idat) goto fin;

    {
        uint8_t *p = idat;
        /* zlib ヘッダ */
        *p++ = 0x78; *p++ = 0x01;
        /* DEFLATE stored block ヘッダ */
        *p++ = 0x01;                           /* BFINAL=1, BTYPE=00 */
        *p++ = (uint8_t)(LEN  & 0xFFu);        /* LEN  低             */
        *p++ = (uint8_t)(LEN  >> 8);           /* LEN  高             */
        *p++ = (uint8_t)(NLEN & 0xFFu);        /* NLEN 低             */
        *p++ = (uint8_t)(NLEN >> 8);           /* NLEN 高             */
        /* 生データ */
        memcpy(p, raw, RAW_BYTES); p += RAW_BYTES;
        /* Adler-32 (big-endian) */
        *p++ = (uint8_t)(adler >> 24);
        *p++ = (uint8_t)(adler >> 16);
        *p++ = (uint8_t)(adler >>  8);
        *p++ = (uint8_t)(adler);
    }

    /* PNG シグネチャ */
    if (fwrite(PNG_SIG, 1, _N8, f) != _N8) goto fin;

    /* IHDR (width=64, height=64, depth=8, colortype=2/RGB) */
    {
        uint8_t ihdr[_N13] = {0,0,0,_N64, 0,0,0,_N64, _N8, _N2, 0, 0, 0};
        if (!g_crc_ready) crc_init();
        if (tulis_chunk(f, "IHDR", ihdr, _N13) != 0) goto fin;
    }

    /* IDAT */
    if (tulis_chunk(f, "IDAT", idat, (uint32_t)idat_sz) != 0) goto fin;

    /* IEND */
    if (tulis_chunk(f, "IEND", NULL, 0) != 0) goto fin;

    ret = 0;
fin:
    free(raw);
    free(idat);
    return ret;
}

/* ================================================================
 * §9  PNG 読み込み (自己生成フォーマット専用)
 *
 * IDAT を見つけ、zlib stored block ヘッダを読み飛ばして
 * 生ピクセルデータ (フィルタバイト込み) を pixels[] に展開する。
 * ================================================================ */

static int baca_png_64x64(FILE *f, uint8_t *pixels) {
    static const uint8_t PNG_SIG[] = {137,80,78,71,13,10,26,10};
    uint8_t  sig[_N8];
    uint8_t  hdr[_N8];    /* length(4) + type(4) */
    char     ctype[_N5];
    uint8_t *ibuf = NULL;
    uint32_t ilen;
    int      found = 0;
    int      ret   = -1;

    if (fread(sig, 1, _N8, f) != _N8) return -1;
    if (memcmp(sig, PNG_SIG, _N8) != 0) return -1;

    while (fread(hdr, 1, _N8, f) == _N8) {
        ilen = ((uint32_t)hdr[0] << 24) | ((uint32_t)hdr[1] << 16)
             | ((uint32_t)hdr[2] <<  8) |  (uint32_t)hdr[3];
        memcpy(ctype, hdr + _N4, _N4);
        ctype[_N4] = '\0';

        if (strcmp(ctype, "IHDR") == 0) {
            /* IHDR 13バイト + CRC 4バイト スキップ */
            if (fseek(f, _N13 + _N4, SEEK_CUR) != 0) goto fin;

        } else if (strcmp(ctype, "IDAT") == 0) {
            ibuf = (uint8_t *)malloc(ilen);
            if (!ibuf) goto fin;
            if (fread(ibuf, 1, ilen, f) != ilen) goto fin;
            if (fseek(f, _N4, SEEK_CUR) != 0) goto fin; /* CRC skip */

            /* 最低サイズ確認: zlib(2) + stored(5) + raw + adler(4) */
            if (ilen < _N2 + _N5 + RAW_BYTES + _N4) goto fin;

            /* zlib ヘッダ 2 バイト + stored ブロックヘッダ 5 バイト = 7 バイトスキップ */
            {
                const uint8_t *raw_start = ibuf + 7;
                size_t  row;
                const uint8_t *rp = raw_start;
                uint8_t       *pp = pixels;
                for (row = 0; row < IMG_H; row++) {
                    rp++;  /* filter byte スキップ */
                    memcpy(pp, rp, IMG_W * IMG_CH);
                    rp += IMG_W * IMG_CH;
                    pp += IMG_W * IMG_CH;
                }
            }
            found = 1;
            free(ibuf); ibuf = NULL;

        } else if (strcmp(ctype, "IEND") == 0) {
            fseek(f, _N4, SEEK_CUR); /* CRC skip */
            break;

        } else {
            /* 未知チャンク: データ + CRC スキップ */
            if (fseek(f, (long)(ilen + 4), SEEK_CUR) != 0) goto fin;
        }
    }

    ret = found ? 0 : -1;
fin:
    free(ibuf);
    return ret;
}

/* ================================================================
 * 公開 API
 * ================================================================ */

/*
 * sembunyikan_benih_png
 *
 * benih[32] を PNG LSB に隠蔽する。
 * sandi が空でなければ SHA-256(sandi) を XOR 鍵として使用。
 */
int sembunyikan_benih_png(const char  *jalur_keluar,
                           const uint8_t benih[32],
                           const char  *sandi) {
    uint8_t  xored[_N32];
    uint8_t  xor_key[_N32];
    char     b64[B64_LEN + 2];       /* null 終端用 +1, 余裕 +1 */
    uint8_t  payload[PAYLOAD_LEN];   /* [len:1][base64:44]       */
    uint8_t *pixels = NULL;
    FILE    *f      = NULL;
    int      ret    = -1;

    pixels = (uint8_t *)malloc(IMG_BYTES);
    if (!pixels) return -1;

    /* ---- XOR: sandi が空なら素通し ---- */
    if (sandi && sandi[0] != '\0') {
        hitung_sha256((const uint8_t *)sandi, strlen(sandi), xor_key);
        {
            int i;
            for (i = 0; i < _N32; i++)
                xored[i] = benih[i] ^ xor_key[i];
        }
    } else {
        memcpy(xored, benih, _N32);
    }

    /* ---- Base64 encode (32 byte -> 44 karakter) ---- */
    b64_encode(xored, _N32, b64);

    /* ---- ペイロード構築: [B64_LEN][b64データ] ---- */
    payload[0] = (uint8_t)B64_LEN;
    memcpy(payload + 1, b64, B64_LEN);

    /* ---- ノイズベースピクセル生成 ---- */
    buat_piksel_dasar(pixels, IMG_BYTES);

    /* ---- LSB に埋め込み ---- */
    lsb_umat(pixels, IMG_BYTES, payload, PAYLOAD_LEN * 8u);

    /* ---- PNG 書き出し ---- */
    f = fopen(jalur_keluar, "wb");
    if (!f) goto fin;
    ret = tulis_png_64x64(f, pixels);
    fclose(f);

fin:
    free(pixels);
    return ret;
}

/*
 * ekstrak_benih_png
 *
 * PNG LSB から benih[32] を抽出する。
 * sandi が空でなければ SHA-256(sandi) を XOR 鍵として使用。
 */
int ekstrak_benih_png(const char *jalur_masuk,
                       uint8_t     benih[32],
                       const char *sandi) {
    uint8_t  payload[PAYLOAD_LEN];
    uint8_t  xored[_N32];
    uint8_t  xor_key[_N32];
    char     b64[B64_LEN + 2];
    uint8_t *pixels = NULL;
    FILE    *f      = NULL;
    int      ret    = -1;

    pixels = (uint8_t *)malloc(IMG_BYTES);
    if (!pixels) return -1;

    /* ---- PNG 読み込み ---- */
    f = fopen(jalur_masuk, "rb");
    if (!f) goto fin;
    if (baca_png_64x64(f, pixels) != 0) goto fin;
    fclose(f); f = NULL;

    /* ---- LSB 抽出 ---- */
    lsb_ambil(pixels, IMG_BYTES, payload, PAYLOAD_LEN * 8u);
    free(pixels); pixels = NULL;

    /* ---- ペイロード検証 ---- */
    if (payload[0] != (uint8_t)B64_LEN) goto fin;   /* 長さ不一致 */
    memcpy(b64, payload + 1, B64_LEN);
    b64[B64_LEN] = '\0';

    /* ---- Base64 デコード ---- */
    if (b64_decode(b64, B64_LEN, xored) != _N32) goto fin;

    /* ---- XOR 復元 ---- */
    if (sandi && sandi[0] != '\0') {
        hitung_sha256((const uint8_t *)sandi, strlen(sandi), xor_key);
        {
            int i;
            for (i = 0; i < _N32; i++)
                benih[i] = xored[i] ^ xor_key[i];
        }
    } else {
        memcpy(benih, xored, _N32);
    }

    ret = 0;
fin:
    if (f)      fclose(f);
    free(pixels);
    return ret;
}
