/*
 * wikipedia_seed.c — Wikipedia-based seed generation via WinHTTP
 *
 * [EN] Fetches a random Wikipedia article over HTTPS using the native Windows
 *      WinHTTP API and derives a 32-byte seed by hashing the article content.
 *
 *      No external library required — winhttp.lib ships with every Windows SDK.
 *
 *      Implementation notes:
 *        - All HTTPS connections target en.wikipedia.org port 443
 *        - JSON responses are parsed with simple strstr-based extraction
 *          (no JSON library), which is safe because the Wikipedia API response
 *          structure is stable and the fields of interest contain only ASCII
 *        - Article titles containing non-ASCII characters are URL-encoded
 *          using %XX encoding (spaces become %20, not +)
 *        - Wide-char (wchar_t) paths are used for WinHTTP path parameters
 *        - Response body is capped at MAKS_RESPONS (512 KB) to bound memory
 *
 * [ID] Ambil artikel acak Wikipedia via HTTPS WinHTTP. Tanpa lib eksternal.
 *      JSON di-parse dengan strstr sederhana. URL encode untuk judul non-ASCII.
 * [JA] WinHTTP を使って Wikipedia のランダム記事を HTTPS で取得し種を生成する。
 *      外部ライブラリ不要。JSON解析はstrstr、非ASCIIタイトルはURLエンコード。
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
 * Internal constants
 * [ID] Konstanta internal | [JA] 内部定数
 * ================================================================ */

static const wchar_t WIKI_HOST[] = L"en.wikipedia.org";

/* Batas baca respons (isi artikel besar, 512KB) */
#define MAKS_RESPONS    (_N512 * _N1024)

#define MAKS_JUDUL      _N512          /* panjang max judul artikel */
#define MAKS_JUDUL_ENC  (MAKS_JUDUL * _N3)   /* setelah URL encode */
#define MAKS_REVID      _N32           /* panjang max string oldid */
#define MAKS_PATH_W     _N2048         /* panjang max path WinHTTP (wchar) */

/* ================================================================
 * c2w — ASCII/Latin-1 string to wide-char conversion
 *
 * [EN] Converts a narrow string to wchar_t for WinHTTP path parameters.
 *      Handles only BMP code points (sufficient for URL-encoded ASCII output).
 * [ID] Konversi string ASCII ke wide char untuk parameter WinHTTP.
 * [JA] WinHTTPパスパラメータ用にASCII文字列をwchar_tに変換する。
 * ================================================================ */

/* Convert ASCII/Latin-1 string to wide-char (BMP only)
 * [JA] ASCII/Latin-1文字列をワイド文字に変換（BMP範囲のみ） */
static void c2w(const char *src, wchar_t *dst, size_t dst_wchars) {
    size_t i = 0;
    for (; i < dst_wchars - 1 && src[i]; i++)
        dst[i] = (wchar_t)(unsigned char)src[i];
    dst[i] = L'\0';
}

/* ================================================================
 * url_encode — Percent-encode a string for use in Wikipedia API URLs
 *
 * [EN] Encodes all characters except unreserved (A-Z a-z 0-9 - _ . ~) as
 *      %XX hexadecimal sequences.  Spaces become %20 (not +) for compatibility
 *      with the Wikipedia REST API path format.
 * [ID] Encode karakter non-alfanumerik menjadi %XX. Spasi jadi %20.
 * [JA] 英数字と "-_.~" 以外を %XX にエンコードする。スペースは %20。
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
 * Lightweight JSON field extraction (strstr-based)
 *
 * [EN] Wikipedia API responses have a stable, simple JSON structure.
 *      Rather than linking a full JSON library, two helpers cover the only
 *      two patterns needed:
 *        json_str : extracts the string value for  "key":"VALUE"
 *        json_num : extracts the numeric value for "key":NUMBER
 *      Neither handles escape sequences, but the fields of interest
 *      (article title, revid) contain only ASCII characters.
 * [ID] Ekstraksi field JSON sederhana dengan strstr. Cukup untuk respons Wikipedia.
 * [JA] strstrベースの軽量JSON抽出。Wikipedia APIの安定したレスポンス形式に対応。
 * ================================================================ */

/* "key":"VALUE" → extract VALUE into out
 * [JA] "key":"VALUE" 形式からVALUEを抽出 */
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

/* "key":NUMBER → extract numeric string into out
 * [JA] "key":NUMBER 形式から数値文字列を抽出 */
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
 * http_get — Send an HTTPS GET request and return the response body
 *
 * [EN] Opens a WinHTTP session, connects to WIKI_HOST on port 443, sends a
 *      GET request for path, and reads the response body in chunks up to
 *      MAKS_RESPONS (512 KB) bytes.  The returned buffer is heap-allocated
 *      and null-terminated; the caller must free(*out_buf).
 *      Returns 0 on success, -1 on any WinHTTP or allocation error.
 * [ID] HTTPS GET via WinHTTP. Buffer dialokasi dinamis, pemanggil harus free.
 * [JA] WinHTTPでHTTPS GETを送信し、レスポンスボディをヒープに格納して返す。
 *      呼び出し元が free(*out_buf) する責任を持つ。
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
 * Public API
 * [ID] API publik | [JA] 公開API
 * ================================================================ */

/*
 * ambil_benih_wikipedia — Fetch a random Wikipedia article and derive seed
 *
 * [EN] Executes the four-step seed derivation pipeline:
 *
 *      Step 1 — Random article title:
 *        GET /w/api.php?action=query&list=random&rnnamespace=0&rnlimit=1&format=json
 *
 *      Step 2 — Latest revision ID (oldid):
 *        GET /w/api.php?action=query&prop=revisions&titles=<TITLE>
 *                      &rvprop=ids&rvlimit=1&format=json
 *
 *      Step 3 — Raw wikitext at that revision:
 *        GET /w/index.php?action=raw&title=<TITLE>&oldid=<REVID>
 *
 *      Step 4 — Seed derivation:
 *        SHA-256( revid_string || 0x0A || wikitext ) → benih[32]
 *
 *      Mixing the revid ensures that two fetches of the same article at
 *      different revisions produce different seeds.  The 0x0A byte acts as
 *      a domain separator.  The info string is formatted as:
 *        "Article Title (oldid=123456, 8192 byte)"
 *      and is intended for display and storage in the PNG key file.
 *
 * [ID] Pipeline 4 langkah: ambil judul acak → oldid → wikitext → SHA-256.
 *      revid dicampur agar tiap revisi menghasilkan benih berbeda.
 * [JA] 4ステップのパイプライン: ランダム記事→oldid→wikitext→SHA-256。
 *      revidを混入することで同記事の異なるリビジョンでも異なる種を生成する。
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
