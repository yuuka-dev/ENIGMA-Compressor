/*
 * enigma_engine.c - implementasi obfuskasi
 *
 * 依存ヘッダ: stdio.h  stdint.h  string.h のみ
 * 方針:
 *   - 重要ロジックは可能な限り #define に落とす
 *   - ヘルパー関数は FORCEINLINE でインライン強制
 *   - __asm__ によるジャンク命令を要所に混入
 *   - 常に True/False になる不透明な述語でフロー解析を妨害
 *   - すべての固定数値リテラルを sizeof(struct{char a[N];}) で再定義
 */

#include "enigma_engine.h"
#include "define.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>

/* ================================================================
 * §0  コンパイラ・アーキテクチャ互換マクロ
 * ================================================================ */

#if defined(__GNUC__) || defined(__clang__)
#  define FORCEINLINE  static __attribute__((always_inline)) inline
#elif defined(_MSC_VER)
#  define FORCEINLINE  static __forceinline
#else
#  define FORCEINLINE  static inline
#endif

#if (defined(__GNUC__) || defined(__clang__)) && \
    (defined(__i386__) || defined(__x86_64__))
#  define JUNK_ASM() \
     __asm__ volatile("nop\n\tnop\n\tnop\n\t" ::: "memory")
#  define JUNK_ASM_MUL(v) \
     do { int32_t _jv = (int32_t)(v); \
          __asm__ volatile( \
              "imull $0x6C62272E, %0, %0\n\t" \
              "xorl  %0, %0\n\t" \
              : "+r"(_jv) :: "cc"); \
          (void)_jv; } while(0)
#elif defined(_MSC_VER) && defined(_M_IX86)
#  define JUNK_ASM()       do { __asm nop __asm nop __asm nop } while(0)
#  define JUNK_ASM_MUL(v)  do { __asm mov eax, v \
                                __asm imul eax, 0x6C62272E \
                                __asm xor eax, eax } while(0)
#else
#  define JUNK_ASM()       ((void)0)
#  define JUNK_ASM_MUL(v)  ((void)(v))
#endif

/* ================================================================
 * §2  不透明な述語
 *     _N マクロを使うことで即値パターンも消える
 * ================================================================ */

#define OPAK_TRUE_BITS(x) \
    (((uint32_t)(x) | (~(uint32_t)(x))) == (uint32_t)(_N256 - _N1))

#define OPAK_TRUE_EVEN(n) \
    ((((uint64_t)(n) * ((uint64_t)(n) + _N1)) & _N1) == (uint64_t)0)

#define OPAK_FALSE_AND(x) \
    (((uint32_t)(x) & (~(uint32_t)(x))) != (uint32_t)0)

#define OPAK_FALSE_XOR(x) \
    (((uint32_t)(x) ^ (uint32_t)(x)) == _N1)

#define JUNK_DEAD(x) \
    do { if (OPAK_FALSE_XOR(x)) { \
           volatile uint32_t _dd = (uint32_t)(x) ^ 0xDEADBEEFU; \
           (void)_dd; JUNK_ASM(); } } while(0)

#define JUNK_CALC(seed) \
    do { volatile uint32_t _jc  = (uint32_t)(seed) * 0x9E3779B9U; \
         volatile uint32_t _jc2 = _jc ^ (_jc >> _N13); \
         _jc2 *= 0xC4CEB9FEU; _jc2 ^= (_jc2 >> _N16); \
         (void)_jc2; } while(0)

/* ================================================================
 * §3  SHA-256 演算マクロ群 (_N で全シフト量を再定義)
 * ================================================================ */

/* Rotasi 32bit kanan - turunkan jumlah kiri dari _N32 - n */
#define SHA_ROT(x,n)   (((uint32_t)(x)>>(n))|((uint32_t)(x)<<(_N32-(n))))

#define SHA_CH(e,f,g)  (((e)&(f))^(~(e)&(g)))
#define SHA_MAJ(a,b,c) (((a)&(b))^((a)&(c))^((b)&(c)))

/* Σ 関数: 大文字 (圧縮用) */
#define SHA_SB0(x) (SHA_ROT(x,_N2) ^SHA_ROT(x,_N13)^SHA_ROT(x,_N22))
#define SHA_SB1(x) (SHA_ROT(x,_N6) ^SHA_ROT(x,_N11)^SHA_ROT(x,_N25))

/* σ 関数: 小文字 (メッセージスケジュール用) */
#define SHA_SK0(x) (SHA_ROT(x,_N7) ^SHA_ROT(x,_N18)^((uint32_t)(x)>>_N3))
#define SHA_SK1(x) (SHA_ROT(x,_N17)^SHA_ROT(x,_N19)^((uint32_t)(x)>>_N10))

/* メッセージスケジュール展開: w[16] 〜 w[63] を算出 */
#define SHA_MSG_EXP(w,i) \
    ((w)[i] = SHA_SK1((w)[(i)-(int)_N2 ]) + (w)[(i)-(int)_N7 ] \
            + SHA_SK0((w)[(i)-(int)_N15]) + (w)[(i)-(int)_N16])

/* ビッグエンディアン 32bit ロード / ストア */
#define SHA_BE32_LOAD(p) \
    (((uint32_t)(p)[0]<<_N24)|((uint32_t)(p)[1]<<_N16)| \
     ((uint32_t)(p)[2]<<_N8 )| (uint32_t)(p)[3])

#define SHA_BE32_STORE(p,v) \
    do { (p)[0]=(uint8_t)((v)>>_N24); (p)[1]=(uint8_t)((v)>>_N16); \
         (p)[2]=(uint8_t)((v)>>_N8 ); (p)[3]=(uint8_t)((v)       ); } while(0)

/* 1ラウンド圧縮をすべてマクロ展開 */
#define SHA_ROUND(a,b,c,d,e,f,g,h,Ki,Wi) \
    do { uint32_t _T1 = (h)+SHA_SB1(e)+SHA_CH(e,f,g)+(Ki)+(Wi); \
         uint32_t _T2 = SHA_SB0(a)+SHA_MAJ(a,b,c); \
         (h)=(g); (g)=(f); (f)=(e); (e)=(d)+_T1; \
         (d)=(c); (c)=(b); (b)=(a); (a)=_T1+_T2; } while(0)

/* ハッシュ状態への 8語加算 */
#define SHA_ACCUM(st,a,b,c,d,e,f,g,h) \
    do { (st)[0]+=(a); (st)[1]+=(b); (st)[2]+=(c); (st)[3]+=(d); \
         (st)[4]+=(e); (st)[5]+=(f); (st)[6]+=(g); (st)[7]+=(h); } while(0)

/* ================================================================
 * §4  CTR ストリーム / エニグマ演算マクロ群 (_N で全オフセットを再定義)
 * ================================================================ */

/* CTR_LE64_PACK: buf[32..39] にカウンタ c をリトルエンディアン 64bit で書き込む */
#define CTR_LE64_PACK(buf, c) \
    do { uint8_t *_p = (uint8_t *)(buf) + _N32; uint64_t _c = (uint64_t)(c); \
         *_p++=(uint8_t)(_c        ); *_p++=(uint8_t)(_c>>_N8 ); \
         *_p++=(uint8_t)(_c>>_N16  ); *_p++=(uint8_t)(_c>>_N24); \
         *_p++=(uint8_t)(_c>>_N32  ); *_p++=(uint8_t)(_c>>_N40); \
         *_p++=(uint8_t)(_c>>_N48  ); *_p  =(uint8_t)(_c>>_N56); } while(0)

/* オフセット補正付き S-Box 1段通過 */
#define ROTOR_PASS(tbl, b, ofs) \
    ((uint8_t)(*((tbl) + (uint8_t)((uint8_t)(b)+(uint8_t)(ofs))) \
               - (uint8_t)(ofs)))

/* 2バイトのポインタ交換 */
#define TUKAR_BYTE(p, q) \
    do { uint8_t _tb = *(p); *(p) = *(q); *(q) = _tb; } while(0)

/* オドメーター式ローター送り (uint8_t オーバーフローを意図的に利用) */
#define STEPPING(o) \
    do { if (!++(o)[0]) if (!++(o)[1]) ++(o)[2]; } while(0)

/* 逆写像構築: balik[maju[n]] = n を 256 要素すべてに適用 */
#define INVERS_BUILD(maju, balik) \
    do { uint8_t _n = 0; \
         do { *((balik)+*((maju)+_n)) = _n; } while (++_n); } while(0)

/* 恒等置換 [0..255] を書き込む (uint8_t overflow で 256 回ループ) */
#define IDENTITY_FILL(larik) \
    do { uint8_t *_p = (larik); uint8_t _n = 0; \
         do { *_p++ = _n; } while (++_n); } while(0)

/* ================================================================
 * §5  SHA-256 定数テーブル (_N で配列サイズを再定義)
 * ================================================================ */

static const uint32_t K256[_N64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
    0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
    0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
    0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
    0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
    0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static const uint32_t IV256[_N8] = {
    0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
    0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
};

/* ================================================================
 * §6  型定義 (構造体メンバの配列長をすべて _N に置換)
 * ================================================================ */

typedef struct {
    uint32_t s   [_N8 ];    /* 中間ハッシュ値 h0..h7          */
    uint8_t  buf [_N64];    /* 入力バッファ (1 ブロック分)     */
    uint64_t bits;          /* 処理済みビット数                */
    uint32_t fill;          /* バッファ充填量 (byte)           */
} KonteksSHA256;

typedef struct {
    uint8_t  kunci[_N32];   /* CTR ベースキー                  */
    uint64_t cacah;         /* ブロックカウンタ                */
    uint8_t  blok [_N32];   /* 現在の出力ブロック              */
    uint8_t  pos;           /* blok 内の読み取り位置           */
} ArusByte;

/* ================================================================
 * §7  SHA-256 実装 (すべての数値リテラルを _N で再定義済み)
 * ================================================================ */

FORCEINLINE void proses_blok(KonteksSHA256 *ctx, const uint8_t *blok) {
    uint32_t    w[_N64];
    uint32_t    a,b,c,d,e,f,g,h;
    const uint8_t *p = blok;
    int i;

    /* ビッグエンディアン 32bit × _N16 語ロード */
    for (i = 0; i < (int)_N16; i++, p += _N4) w[i] = SHA_BE32_LOAD(p);

    /* Ekspansi message schedule (_N16 -> _N64) */
    for (i = (int)_N16; i < (int)_N64; i++) SHA_MSG_EXP(w, i);

    a=ctx->s[0]; b=ctx->s[1]; c=ctx->s[2]; d=ctx->s[3];
    e=ctx->s[4]; f=ctx->s[5]; g=ctx->s[6]; h=ctx->s[7];

    /* _N64 ラウンド圧縮 */
    for (i = 0; i < (int)_N64; i++) SHA_ROUND(a,b,c,d,e,f,g,h, K256[i], w[i]);

    SHA_ACCUM(ctx->s, a,b,c,d,e,f,g,h);
}

FORCEINLINE void mulai_sha256(KonteksSHA256 *ctx) {
    memcpy(ctx->s, IV256, _N32);
    ctx->bits = 0;
    ctx->fill = 0;
}

FORCEINLINE void masukkan_sha256(KonteksSHA256 *ctx,
                                  const uint8_t *data, size_t len) {
    const uint8_t *src = data;
    const uint8_t *end = data + len;
    while (src < end) {
        ctx->buf[ctx->fill++] = *src++;
        if (ctx->fill == (uint32_t)_N64) {
            proses_blok(ctx, ctx->buf);
            ctx->bits += _N512;   /* _N64 × _N8 = 512 bit */
            ctx->fill  = 0;
        }
    }
}

FORCEINLINE void akhiri_sha256(KonteksSHA256 *ctx, uint8_t *out) {
    uint64_t total = ctx->bits + (uint64_t)ctx->fill * _N8;
    uint8_t *p = ctx->buf + ctx->fill;
    int i;

    /* 0x80 パディング */
    *p++ = 0x80; ctx->fill++;
    if (ctx->fill > (uint32_t)_N56) {
        while (ctx->fill < (uint32_t)_N64) { *p++ = 0; ctx->fill++; }
        proses_blok(ctx, ctx->buf);
        ctx->fill = 0; p = ctx->buf;
    }
    while (ctx->fill < (uint32_t)_N56) { *p++ = 0; ctx->fill++; }

    /* ビット長をビッグエンディアン 64bit で byte _N56〜_N63 に書き込む */
    ctx->buf[_N56        ] = (uint8_t)(total >> _N56);
    ctx->buf[_N56 + _N1  ] = (uint8_t)(total >> _N48);
    ctx->buf[_N56 + _N2  ] = (uint8_t)(total >> _N40);
    ctx->buf[_N56 + _N3  ] = (uint8_t)(total >> _N32);
    ctx->buf[_N56 + _N4  ] = (uint8_t)(total >> _N24);
    ctx->buf[_N56 + _N4 + _N1] = (uint8_t)(total >> _N16);
    ctx->buf[_N56 + _N4 + _N2] = (uint8_t)(total >> _N8 );
    ctx->buf[_N56 + _N4 + _N3] = (uint8_t)(total        );
    proses_blok(ctx, ctx->buf);

    /* _N8 語をビッグエンディアンで出力: 各語 _N4 バイト */
    for (i = 0; i < (int)_N8; i++) SHA_BE32_STORE(out + i * (int)_N4, ctx->s[i]);
}

void hitung_sha256(const uint8_t *data, size_t panjang, uint8_t hasil[32]) {
    KonteksSHA256 ctx;
    mulai_sha256(&ctx);
    masukkan_sha256(&ctx, data, panjang);
    akhiri_sha256(&ctx, hasil);
}

/* ================================================================
 * §8  擬似乱数バイトストリーム (CTR-mode SHA-256)
 * ================================================================ */

FORCEINLINE void mulai_arus(ArusByte *arus,
                             const uint8_t *benih, size_t panjang) {
    hitung_sha256(benih, panjang, arus->kunci);
    arus->cacah = 0;
    arus->pos   = (uint8_t)_N32; /* 初回で強制ブロック生成 */
}

FORCEINLINE uint8_t ambil_byte(ArusByte *arus) {
    if (arus->pos >= (uint8_t)_N32) {
        JUNK_CALC(arus->cacah);
        JUNK_ASM();

        /* kunci(_N32 byte) || cacah_LE64(_N8 byte) = _N40 byte */
        uint8_t buf[_N40];
        memcpy(buf, arus->kunci, _N32);
        CTR_LE64_PACK(buf, arus->cacah);
        arus->cacah++;

        JUNK_ASM_MUL((uint32_t)arus->cacah);

        hitung_sha256(buf, _N40, arus->blok);
        arus->pos = 0;
    }
    return *(arus->blok + arus->pos++);
}

/* ================================================================
 * §9  ローター生成補助関数
 * ================================================================ */

FORCEINLINE void acak_fisher_yates(uint8_t *larik, ArusByte *arus) {
    /* 末尾要素へのポインタ: _N256 - _N1 = _N255 番目 */
    uint8_t *ujung = larik + _N255;
    uint8_t *acak;

    while (ujung > larik) {
        if (OPAK_TRUE_BITS((uint32_t)(ujung - larik))) {
            acak = larik + (uint32_t)(ambil_byte(arus)
                           % (uint32_t)(ujung - larik + _N1));
            TUKAR_BYTE(ujung, acak);
        }
        JUNK_DEAD((uint32_t)*ujung);
        --ujung;
    }
    JUNK_ASM();
}

FORCEINLINE void bangkitkan_reflektor(uint8_t *ref, ArusByte *arus) {
    uint8_t  perm[_N256];
    uint8_t *p;

    IDENTITY_FILL(perm);
    JUNK_CALC(perm[0]);
    JUNK_ASM();

    acak_fisher_yates(perm, arus);

    /* 隣接ペアで結合: ステップ幅 _N2 */
    for (p = perm; p < perm + _N256; p += _N2) {
        if (OPAK_TRUE_EVEN((uint64_t)(p - perm))) {
            ref[p[0]] = p[1];
            ref[p[1]] = p[0];
        }
    }
    JUNK_ASM_MUL(ref[0]);
}

/* ================================================================
 * §10  公開 API
 * ================================================================ */

void hasilkan_rotor_dari_benih(MesinEnigma *mesin,
                                const uint8_t *benih, size_t panjang_benih) {
    ArusByte arus;
    int      r;

    JUNK_CALC((uint32_t)panjang_benih);
    mulai_arus(&arus, benih, panjang_benih);

    for (r = 0; r < JUMLAH_ROTOR; r++) {
        IDENTITY_FILL(mesin->rotor[r]);
        JUNK_ASM();
        JUNK_DEAD((uint32_t)r);
        acak_fisher_yates(mesin->rotor[r], &arus);
        INVERS_BUILD(mesin->rotor[r], mesin->rotor_balik[r]);
        JUNK_CALC(mesin->rotor[r][r]);
    }

    bangkitkan_reflektor(mesin->reflektor, &arus);
    memset(mesin->offset, 0, JUMLAH_ROTOR);
    JUNK_ASM_MUL((uint32_t)mesin->offset[0]);
}

uint8_t enkripsi_byte(MesinEnigma *mesin, uint8_t b) {
    uint8_t (*rot )[_N256] = mesin->rotor;
    uint8_t (*roti)[_N256] = mesin->rotor_balik;
    uint8_t  *o            = mesin->offset;
    uint8_t  *op;
    int       i;

    JUNK_DEAD((uint32_t)b);
    JUNK_CALC((uint32_t)b);
    JUNK_ASM();

    /* Laluan maju: rotor[0] -> [1] -> [2] */
    if (OPAK_TRUE_BITS((uint32_t)b)) {
        for (i = 0, op = o; i < JUMLAH_ROTOR; i++, op++)
            b = ROTOR_PASS(*(rot + i), b, *op);
    }

    JUNK_ASM_MUL((uint32_t)b);

    /* リフレクター */
    b = *(mesin->reflektor + b);

    JUNK_ASM();
    JUNK_DEAD((uint32_t)b);

    /* Laluan balik: rotor_balik[2] -> [1] -> [0] */
    if (OPAK_TRUE_EVEN((uint64_t)b)) {
        for (i = JUMLAH_ROTOR-1, op = o + JUMLAH_ROTOR-1; i >= 0; i--, op--)
            b = ROTOR_PASS(*(roti + i), b, *op);
    }

    JUNK_CALC((uint32_t)b);
    JUNK_ASM();

    STEPPING(o);
    return b;
}

/* ================================================================
 * enkripsi_berkas
 *
 * Baca jalur_masuk per chunk 4096 byte,
 * transform tiap byte dengan enkripsi_byte(), tulis ke jalur_keluar.
 * Involutif: fungsi sama untuk enkripsi dan dekripsi.
 * Nilai kembali: 0=sukses / -1=error
 * ================================================================ */
int enkripsi_berkas(MesinEnigma *mesin,
                    const char *jalur_masuk,
                    const char *jalur_keluar) {
    /* Ukuran buffer: _N1024 x _N4 = 4096 byte */
    uint8_t  blok[_N1024 * _N4];
    uint8_t *kursor;
    FILE    *fin, *fout;
    size_t   dibaca, i;

    fin = fopen(jalur_masuk, "rb");
    if (!fin) return -1;

    fout = fopen(jalur_keluar, "wb");
    if (!fout) { fclose(fin); return -1; }

    while ((dibaca = fread(blok, 1, sizeof(blok), fin)) > 0) {
        JUNK_ASM();
        /* Telusuri langsung pakai pointer kursor */
        for (kursor = blok, i = 0; i < dibaca; i++, kursor++)
            *kursor = enkripsi_byte(mesin, *kursor);
        JUNK_ASM();
        if (fwrite(blok, 1, dibaca, fout) != dibaca) {
            fclose(fin); fclose(fout); return -1;
        }
    }

    fclose(fin);
    fclose(fout);
    return 0;
}
