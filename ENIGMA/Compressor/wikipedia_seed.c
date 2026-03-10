/*
 * wikipedia_seed.c
 *
 * Komunikasi HTTPS Wikipedia via WinHTTP (API Windows),
 * artikel acak + oldid di-SHA256 untuk benih.
 *
 * Tanpa lib eksternal - winhttp.lib bawaan Windows.
 */

#include "wikipedia_seed.h"
#include "enigma_engine.h"
#include "define.h"

#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* MSVC リンカ指示 (MinGW は -lwinhttp で対応) */
#ifdef _MSC_VER
#  pragma comment(lib, "winhttp.lib")
#endif

/* ================================================================
 * 内部定数
 * ================================================================ */

static const wchar_t WIKI_HOST[] = L"en.wikipedia.org";

/* Batas baca respons (isi artikel besar, 512KB) */
#define MAKS_RESPONS    (_N512 * _N1024)

#define MAKS_JUDUL      _N512          /* panjang max judul artikel */
#define MAKS_JUDUL_ENC  (MAKS_JUDUL * _N3)   /* setelah URL encode */
#define MAKS_REVID      _N32           /* panjang max string oldid */
#define MAKS_PATH_W     _N2048         /* panjang max path WinHTTP (wchar) */

/* ================================================================
 * Pembantu internal - konversi ASCII <-> wide char
 * ================================================================ */

/* Konversi string ASCII/Latin-1 ke wide (hanya BMP) */
static void c2w(const char *src, wchar_t *dst, size_t dst_wchars) {
    size_t i = 0;
    for (; i < dst_wchars - 1 && src[i]; i++)
        dst[i] = (wchar_t)(unsigned char)src[i];
    dst[i] = L'\0';
}

/* ================================================================
 * Pembantu internal - URL encode
 *
 * Karakter selain alfanumerik dan "-_.~" jadi %XX.
 * Spasi pakai %20, bukan + (kompatibilitas API Wikipedia).
 * ================================================================ */
static void url_encode(const char *src, char *dst, size_t dst_sz) {
    const char *p   = src;
    char       *q   = dst;
    char       *lim = dst + dst_sz - 4; /* %XX\0 の余裕 */

    while (*p && q < lim) {
        unsigned char c = (unsigned char)*p;
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') ||
            c == '-' || c == '_'   || c == '.' || c == '~') {
            *q++ = (char)c;
        } else {
            /* Spasi dan non-reserved jadi %XX */
            sprintf(q, "%%%02X", c);
            q += 3;
        }
        p++;
    }
    *q = '\0';
}

/* ================================================================
 * Pembantu internal - ekstraksi JSON sederhana (basis strstr)
 *
 * Respons API Wikipedia format stabil,
 * cukup pencarian strstr ringan.
 * ================================================================ */

/* "key":"VALUE" -> ekstrak VALUE ke out */
static int json_str(const char *json, const char *key,
                    char *out, size_t out_sz) {
    char        pat[256];
    const char *p, *s, *e;
    size_t      len;

    snprintf(pat, sizeof(pat), "\"%s\":\"", key);
    p = strstr(json, pat);
    if (!p) return -1;
    s = p + strlen(pat);
    /* Ekstraksi sederhana, tanpa pertimbangan escape backslash */
    e = strchr(s, '"');
    if (!e) return -1;
    len = (size_t)(e - s);
    if (len >= out_sz) len = out_sz - 1;
    memcpy(out, s, len);
    out[len] = '\0';
    return 0;
}

/* "key":NUMBER -> ekstrak string angka ke out */
static int json_num(const char *json, const char *key,
                    char *out, size_t out_sz) {
    char        pat[256];
    const char *p, *s;
    size_t      len = 0;

    snprintf(pat, sizeof(pat), "\"%s\":", key);
    p = strstr(json, pat);
    if (!p) return -1;
    s = p + strlen(pat);
    while (*s == ' ') s++;                    /* Lewati spasi */
    while (s[len] >= '0' && s[len] <= '9') len++;
    if (len == 0 || len >= out_sz) return -1;
    memcpy(out, s, len);
    out[len] = '\0';
    return 0;
}

/* ================================================================
 * Pembantu internal - WinHTTP GET
 *
 * Kirim HTTPS GET ke path, kembalikan body respons (dialokasi dinamis).
 * Pemanggil bertanggung jawab free(*out_buf).
 * ================================================================ */
static int http_get(const wchar_t *path,
                    uint8_t **out_buf, size_t *out_len) {
    HINTERNET hSes = NULL, hCon = NULL, hReq = NULL;
    uint8_t  *buf  = NULL;
    size_t    total = 0;
    DWORD     dwSz = 0, dwRead = 0;
    int       ret  = -1;

    /* Mulai sesi */
    hSes = WinHttpOpen(L"ENIGMA-Seed/1.0",
                       WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                       WINHTTP_NO_PROXY_NAME,
                       WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSes) goto fin;

    /* Koneksi host (HTTPS port 443) */
    hCon = WinHttpConnect(hSes, WIKI_HOST,
                          INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hCon) goto fin;

    /* Buka request (TLS wajib) */
    hReq = WinHttpOpenRequest(hCon, L"GET", path, NULL,
                              WINHTTP_NO_REFERER,
                              WINHTTP_DEFAULT_ACCEPT_TYPES,
                              WINHTTP_FLAG_SECURE);
    if (!hReq) goto fin;

    /* Kirim -> tunggu respons */
    if (!WinHttpSendRequest(hReq,
                            WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                            WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) goto fin;
    if (!WinHttpReceiveResponse(hReq, NULL)) goto fin;

    /* Baca body sampai MAKS_RESPONS */
    buf = (uint8_t *)malloc(MAKS_RESPONS + 1);
    if (!buf) goto fin;

    do {
        dwSz = 0;
        if (!WinHttpQueryDataAvailable(hReq, &dwSz) || dwSz == 0) break;
        if (total + (size_t)dwSz > MAKS_RESPONS)
            dwSz = (DWORD)(MAKS_RESPONS - total);
        if (!WinHttpReadData(hReq, buf + total, dwSz, &dwRead)) break;
        total += (size_t)dwRead;
    } while (dwRead > 0 && total < MAKS_RESPONS);

    buf[total] = '\0';  /* sentinel untuk operasi string */
    *out_buf   = buf;
    *out_len   = total;
    buf        = NULL;  /* transfer kepemilikan ke pemanggil */
    ret        = 0;

fin:
    free(buf);
    if (hReq) WinHttpCloseHandle(hReq);
    if (hCon) WinHttpCloseHandle(hCon);
    if (hSes) WinHttpCloseHandle(hSes);
    return ret;
}

/* ================================================================
 * 公開 API
 * ================================================================ */

/*
 * ambil_benih_wikipedia
 *
 * 1. Ambil judul artikel acak
 *       GET /w/api.php?action=query&list=random&rnnamespace=0&rnlimit=1&format=json
 *
 * 2. Ambil oldid (revision ID)
 *       GET /w/api.php?action=query&prop=revisions&titles=TITLE&rvprop=ids&rvlimit=1&format=json
 *
 * 3. Ambil wikitext mentah
 *       GET /w/index.php?action=raw&title=TITLE&oldid=REVID
 *
 * 4. SHA-256( revid || 0x0A || wikitext ) -> benih 32 byte
 */
int ambil_benih_wikipedia(uint8_t benih[32], char *info, size_t info_sz) {
    uint8_t *resp    = NULL; /* buffer respons HTTP */
    uint8_t *konten  = NULL; /* wikitext mentah      */
    uint8_t *masukan = NULL; /* buffer input SHA-256 */
    size_t   resp_len = 0, konten_len = 0;
    size_t   rev_len, total_len;
    int      ret = -1;

    char    judul    [MAKS_JUDUL];        /* judul artikel (UTF-8)  */
    char    judul_enc[MAKS_JUDUL_ENC];    /* judul setelah URL encode */
    char    revid    [MAKS_REVID];        /* string oldid            */
    wchar_t wpath    [MAKS_PATH_W];       /* path wide untuk WinHTTP */
    wchar_t w_enc    [MAKS_JUDUL_ENC];    /* ワイド版エンコードタイトル */
    wchar_t w_rev    [MAKS_REVID];        /* ワイド版 oldid          */

    /* ---- 1. Ambil judul artikel acak ---- */
    if (http_get(L"/w/api.php?action=query"
                 L"&list=random&rnnamespace=0&rnlimit=1&format=json",
                 &resp, &resp_len) != 0) {
        fprintf(stderr, "[WIKI] Gagal mengambil artikel acak\n");
        goto done;
    }
    if (json_str((char *)resp, "title", judul, sizeof(judul)) != 0) {
        fprintf(stderr, "[WIKI] Gagal parsing judul\n");
        goto done;
    }
    free(resp); resp = NULL;

    printf("[WIKI] Artikel : %s\n", judul);

    /* ---- 2. Ambil oldid ---- */
    url_encode(judul, judul_enc, sizeof(judul_enc));
    c2w(judul_enc, w_enc, MAKS_JUDUL_ENC);

    swprintf(wpath, MAKS_PATH_W,
             L"/w/api.php?action=query&prop=revisions"
             L"&titles=%ls&rvprop=ids&rvlimit=1&format=json",
             w_enc);

    if (http_get(wpath, &resp, &resp_len) != 0) {
        fprintf(stderr, "[WIKI] Gagal mengambil revid\n");
        goto done;
    }
    if (json_num((char *)resp, "revid", revid, sizeof(revid)) != 0) {
        fprintf(stderr, "[WIKI] Gagal parsing revid\n");
        goto done;
    }
    free(resp); resp = NULL;

    printf("[WIKI] oldid   : %s\n", revid);

    /* ---- 3. Ambil wikitext mentah ---- */
    c2w(revid, w_rev, MAKS_REVID);
    swprintf(wpath, MAKS_PATH_W,
             L"/w/index.php?action=raw&title=%ls&oldid=%ls",
             w_enc, w_rev);

    if (http_get(wpath, &konten, &konten_len) != 0) {
        fprintf(stderr, "[WIKI] Gagal mengambil konten\n");
        goto done;
    }

    printf("[WIKI] Konten  : %zu byte\n", konten_len);

    /* ---- 4. Bangkitkan benih SHA-256( revid || 0x0A || wikitext ) ----
     *
     * Campur oldid di depan agar benih unik per revisi.
     * 0x0A (newline) sebagai pemisah.
     * hitung_sha256 dari enigma_engine.h. */
    rev_len   = strlen(revid);
    total_len = rev_len + 1 + konten_len;

    masukan = (uint8_t *)malloc(total_len);
    if (!masukan) {
        fprintf(stderr, "[WIKI] Alokasi memori gagal\n");
        goto done;
    }

    memcpy(masukan,             revid,  rev_len);     /* revid          */
    masukan[rev_len] = '\n';                          /* 区切り 0x0A    */
    memcpy(masukan + rev_len + 1, konten, konten_len);/* wikitext 本文  */

    hitung_sha256(masukan, total_len, benih);

    /* 呼び出し元への情報文字列 (デバッグ・表示用) */
    if (info)
        snprintf(info, info_sz, "%s (oldid=%s, %zu byte)",
                 judul, revid, konten_len);

    ret = 0;

done:
    free(resp);
    free(konten);
    free(masukan);
    return ret;
}
