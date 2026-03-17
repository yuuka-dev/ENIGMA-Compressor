#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#if defined(_WIN32) || defined(_MSC_VER)
#  include <direct.h>
#  include <windows.h>
#  define MKDIR(p) _mkdir(p)
#else
#  include <sys/stat.h>
#  include <dirent.h>
#  include <sys/types.h>
#  define MKDIR(p) mkdir((p), 0755)
#endif
#include "packer.h"
#include "enigma_engine.h"
#include "wikipedia_seed.h"
#include "log_samar.h"
#include "png_lsb.h"
#include "define.h"
/*
 * main.c — ENIGMA Compressor console front-end
 *
 * [EN] Implements the interactive CLI loop.  The user drags files or folders
 *      onto the console window (which injects quoted paths as stdin lines),
 *      then presses Enter to trigger encryption, or types a numeric command:
 *        1 — restore  2 — show queue  3 — clear queue  4 — exit
 *
 *      Encryption pipeline (gabungkan_berkas):
 *        collect files → prompt for base name / key PNG / password
 *        → Wikipedia seed → PNG LSB hide → Enigma rotors → pack .engm
 *        → Enigma encrypt → split as _partNNN.log
 *
 *      Restoration pipeline (pulihkan_berkas):
 *        prompt for log prefix / output name / key PNG / password
 *        → extract seed from PNG LSB → restore .enc from logs
 *        → Enigma decrypt → unpack .engm → extract files
 *
 *      Directory inputs are expanded recursively on Windows via FindFirstFile.
 *
 * [ID] Loop CLI interaktif. Drop berkas → Enter untuk enkripsi.
 *      Perintah numerik 1–4 untuk restore/daftar/bersih/keluar.
 * [JA] インタラクティブなCLIループ。ファイルドロップ→Enterで暗号化。
 *      数字コマンド1〜4で復元/キュー表示/クリア/終了。
 */
#include "lang.h"       /* compile-time i18n: LANG_JA / LANG_ID / default EN */

#define PANJANG_JALUR_MAKS  _N1024
#define JUMLAH_JALUR_MAKS   _N32768

/* ================================================================
 * Internal helpers
 * [ID] Pembantu internal | [JA] 内部ヘルパー関数
 * ================================================================ */

/* buat_dir_orang_tua — Recursively create parent directories for a file path
 * [EN] Splits path at the last separator and calls MKDIR on each ancestor
 *      directory from the root down.  Silently ignores EEXIST errors.
 * [ID] Buat direktori induk secara rekursif (abaikan jika sudah ada).
 * [JA] ファイルパスの親ディレクトリを再帰的に作成する（既存は無視）。 */
static void buat_dir_orang_tua(const char *jalur_berkas) {
    char buf[PANJANG_JALUR_MAKS];
    char *p;
    size_t len;

    strncpy(buf, jalur_berkas, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    len = strlen(buf);
    /* Hapus trailing \ atau / agar jadi jalur direktori */
    while (len > 0 && (buf[len - 1] == '/' || buf[len - 1] == '\\')) {
        buf[--len] = '\0';
    }
    /* Hapus setelah pemisah terakhir -> dapat jalur direktori induk */
    for (p = buf + len; p > buf; p--) {
        if (*p == '/' || *p == '\\') {
            *p = '\0';
            break;
        }
    }
    if (p <= buf) return; /* Tidak ada pemisah = tidak ada induk */

    /* Buat direktori tiap pemisah (dari akar ke dalam) */
    for (p = buf; *p; p++) {
        if (*p == '/' || *p == '\\') {
            char c = *p;
            *p = '\0';
            if (buf[0] != '\0' && strlen(buf) > 2) {
                MKDIR(buf);
                (void)errno; /* Abaikan jika sudah ada */
            }
            *p = c;
        }
    }
    if (buf[0] != '\0') MKDIR(buf);
}

/* tambah_jalur_dari_baris — Parse one input line and append paths to queue
 * [EN] Handles both quoted ("C:\path\file") and unquoted (single-token) paths
 *      on the same line.  Windows drag-and-drop injects quoted paths separated
 *      by spaces, so multiple files can appear on one line.
 *      Returns the new total queue size.
 * [ID] Parse baris berisi satu atau lebih jalur (kutip/tanpa kutip).
 * [JA] 引用符あり・なしの両形式のパスを1行から解析してキューに追加する。 */
static int tambah_jalur_dari_baris(const char *baris,
                                    char tujuan[][PANJANG_JALUR_MAKS],
                                    int sudah, int maks) {
    int n = sudah;
    const char *p = baris;
    while (*p && n < maks) {
        /* Lewati spasi di depan */
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '\0') break;

        if (*p == '"') {
            /* Jalur dalam kutip */
            const char *awal = ++p;
            while (*p && *p != '"') p++;
            size_t len = (size_t)(p - awal);
            if (len > 0 && len < PANJANG_JALUR_MAKS) {
                memcpy(tujuan[n], awal, len);
                tujuan[n][len] = '\0';
                n++;
            }
            if (*p == '"') p++;
        } else {
            /* Tanpa kutip: ambil token sampai spasi */
            const char *awal = p;
            while (*p && *p != ' ' && *p != '\t') p++;
            size_t len = (size_t)(p - awal);
            if (len > 0 && len < PANJANG_JALUR_MAKS) {
                memcpy(tujuan[n], awal, len);
                tujuan[n][len] = '\0';
                n++;
            }
        }
    }
    return n; /* Total baru */
}

/* potong_spasi — Trim leading and trailing whitespace (including \r\n) in place
 * [ID] Hapus spasi/tab/CR/LF di awal dan akhir string.
 * [JA] 文字列の前後の空白（\r\nを含む）をインプレースで除去する。 */
static void potong_spasi(char *s) {
    int panjang = (int)strlen(s);
    while (panjang > 0 && (s[panjang-1] == ' '  ||
                            s[panjang-1] == '\t' ||
                            s[panjang-1] == '\r' ||
                            s[panjang-1] == '\n'))
        s[--panjang] = '\0';
    char *awal = s;
    while (*awal == ' ' || *awal == '\t') awal++;
    if (awal != s) memmove(s, awal, strlen(awal) + 1);
}

/* tampilkan_daftar — Print the current file queue to stdout
 * [ID] Tampilkan isi antrian ke stdout.
 * [JA] 現在のキュー内容を標準出力に表示する。 */
static void tampilkan_daftar(char (*jalur)[PANJANG_JALUR_MAKS], int jumlah) {
    if (jumlah == 0) { printf(MSG_QUEUE_EMPTY); return; }
    for (int i = 0; i < jumlah; i++)
        printf(MSG_QUEUE_ENTRY, i + 1, jalur[i]);
}

/* ================================================================
 * kumpulkan_berkas_dari_path — Expand a mixed file/directory list into files
 *
 * [EN] Iterates over masukan[]: files are appended directly; directories are
 *      expanded recursively using FindFirstFile/FindNextFile on Windows or
 *      opendir/readdir elsewhere.  Subdirectories encountered during recursion
 *      are processed via a single-element masukan array to reuse the function.
 *      Returns the total number of files placed in keluaran[].
 * [ID] Ekspansi daftar berkas/direktori menjadi daftar berkas akhir (rekursif).
 * [JA] ファイル/ディレクトリの混在リストをファイルリストに再帰展開する。
 * ================================================================ */
static int kumpulkan_berkas_dari_path(
    char (*masukan)[PANJANG_JALUR_MAKS], int jumlah_masukan,
    char (*keluaran)[PANJANG_JALUR_MAKS], int maks_keluar
) {
    int n = 0;
    for (int i = 0; i < jumlah_masukan && n < maks_keluar; i++) {
        const char *path = masukan[i];
#if defined(_WIN32) || defined(_MSC_VER)
        DWORD attr = GetFileAttributesA(path);
        if (attr == INVALID_FILE_ATTRIBUTES) {
            /* Jalur tidak valid -> lewati saja */
            continue;
        }
        if (attr & FILE_ATTRIBUTE_DIRECTORY) {
            /* Telusuri rekursif direktori */
            char pola[PANJANG_JALUR_MAKS];
            WIN32_FIND_DATAA fd;
            HANDLE h;

            snprintf(pola, sizeof(pola), "%s\\*",
                     path[0] ? path : ".");
            h = FindFirstFileA(pola, &fd);
            if (h == INVALID_HANDLE_VALUE) continue;
            do {
                if (strcmp(fd.cFileName, ".") == 0 ||
                    strcmp(fd.cFileName, "..") == 0) continue;
                char full[PANJANG_JALUR_MAKS];
                snprintf(full, sizeof(full), "%s\\%s", path, fd.cFileName);
                if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    /* Subdirektori: panggil diri sendiri via masukan sementara */
                    char sub_in[1][PANJANG_JALUR_MAKS];
                    strncpy(sub_in[0], full, PANJANG_JALUR_MAKS - 1);
                    sub_in[0][PANJANG_JALUR_MAKS - 1] = '\0';
                    n += kumpulkan_berkas_dari_path(
                        sub_in, 1, keluaran + n, maks_keluar - n);
                } else {
                    if (n >= maks_keluar) break;
                    strncpy(keluaran[n], full, PANJANG_JALUR_MAKS - 1);
                    keluaran[n][PANJANG_JALUR_MAKS - 1] = '\0';
                    n++;
                }
            } while (FindNextFileA(h, &fd));
            FindClose(h);
        } else {
            strncpy(keluaran[n], path, PANJANG_JALUR_MAKS - 1);
            keluaran[n][PANJANG_JALUR_MAKS - 1] = '\0';
            n++;
        }
#else
        struct stat st;
        if (stat(path, &st) != 0) continue;
        if (S_ISDIR(st.st_mode)) {
            DIR *dir = opendir(path);
            if (!dir) continue;
            struct dirent *ent;
            while ((ent = readdir(dir)) != NULL && n < maks_keluar) {
                if (strcmp(ent->d_name, ".") == 0 ||
                    strcmp(ent->d_name, "..") == 0) continue;
                char full[PANJANG_JALUR_MAKS];
                snprintf(full, sizeof(full), "%s/%s", path, ent->d_name);
                struct stat st2;
                if (stat(full, &st2) != 0) continue;
                if (S_ISDIR(st2.st_mode)) {
                    char sub_in[1][PANJANG_JALUR_MAKS];
                    strncpy(sub_in[0], full, PANJANG_JALUR_MAKS - 1);
                    sub_in[0][PANJANG_JALUR_MAKS - 1] = '\0';
                    n += kumpulkan_berkas_dari_path(
                        sub_in, 1, keluaran + n, maks_keluar - n);
                } else if (S_ISREG(st2.st_mode)) {
                    strncpy(keluaran[n], full, PANJANG_JALUR_MAKS - 1);
                    keluaran[n][PANJANG_JALUR_MAKS - 1] = '\0';
                    n++;
                }
            }
            closedir(dir);
        } else if (S_ISREG(st.st_mode)) {
            strncpy(keluaran[n], path, PANJANG_JALUR_MAKS - 1);
            keluaran[n][PANJANG_JALUR_MAKS - 1] = '\0';
            n++;
        }
#endif
    }
    return n;
}

/* ================================================================
 * gabungkan_berkas — Full encryption pipeline
 *
 * [EN] Prompts for output base name, key PNG path, and XOR password, then
 *      executes the six-step encryption pipeline:
 *        STEP 1: Wikipedia API → 32-byte SHA-256 seed
 *        STEP 2: seed → hide in PNG LSB (optional XOR + Base64)
 *        STEP 3: seed → initialise Enigma rotors
 *        STEP 4: files → .engm binary archive (pak_berkas)
 *        STEP 5: .engm → .enc encrypted file (enkripsi_berkas)
 *        STEP 6: .enc → _partNNN.log disguised parts (pisahkan_dan_samarkan)
 *      Temporary files (.engm, .enc) are removed after each step succeeds.
 * [ID] Enkripsi lengkap 6 langkah: seed Wikipedia → PNG → rotor → .engm
 *      → .enc → log. Berkas sementara dihapus setelah tiap langkah.
 * [JA] 6ステップの完全暗号化パイプライン。Wikipedia種→PNG→ローター→
 *      .engm→.enc→ログ。中間ファイルは各ステップ後に削除する。
 * ================================================================ */
static void gabungkan_berkas(char (*jalur)[PANJANG_JALUR_MAKS], int jumlah) {
    char       (*jalur_final)[PANJANG_JALUR_MAKS];
    const char *ptr_jalur[JUMLAH_JALUR_MAKS];
    char        nama_engm [PANJANG_JALUR_MAKS]; /* berkas pak sementara      */
    char        nama_enc  [PANJANG_JALUR_MAKS]; /* berkas terenkripsi sementara */
    char        awalan_log[PANJANG_JALUR_MAKS]; /* awalan keluaran log        */
    char        nama_png  [PANJANG_JALUR_MAKS]; /* jalur PNG kunci           */
    char        sandi     [256];                /* sandi turunan XOR         */
    char        dasar     [PANJANG_JALUR_MAKS]; /* nama dasar masukan user   */
    char        info_wiki [256];
    uint8_t     benih[32];
    MesinEnigma mesin;
    char       *p;
    int         i, hasil, bagian;

    if (jumlah == 0) { printf(MSG_QUEUE_EMPTY); return; }

    jalur_final = (char (*)[PANJANG_JALUR_MAKS])malloc(
        (size_t)JUMLAH_JALUR_MAKS * PANJANG_JALUR_MAKS);
    if (!jalur_final) {
        fprintf(stderr, ERR_ALLOC_FILES);
        return;
    }

    /* Kumpulkan berkas akhir (rekursif untuk direktori) */
    int jumlah_akhir = kumpulkan_berkas_dari_path(
        jalur, jumlah, jalur_final, JUMLAH_JALUR_MAKS);
    if (jumlah_akhir == 0) {
        printf(MSG_NO_VALID_FILES);
        free(jalur_final);
        return;
    }

    /* Bangun larik pointer */
    for (i = 0; i < jumlah_akhir; i++) ptr_jalur[i] = jalur_final[i];

    /* ---- Masukan nama dasar keluaran ---- */
    printf(MSG_PROMPT_BASENAME);
    fflush(stdout);
    if (!fgets(dasar, sizeof(dasar), stdin)) return;
    p = dasar + strlen(dasar);
    while (p > dasar && (p[-1]=='\n'||p[-1]=='\r'||p[-1]==' ')) *--p = '\0';
    if (dasar[0] == '\0') strncpy(dasar, "output", sizeof(dasar) - 1);

    /* ---- Masukan jalur PNG kunci ---- */
    printf(MSG_PROMPT_PNG_ENC, dasar);
    fflush(stdout);
    if (!fgets(nama_png, sizeof(nama_png), stdin)) return;
    p = nama_png + strlen(nama_png);
    while (p > nama_png && (p[-1]=='\n'||p[-1]=='\r'||p[-1]==' ')) *--p = '\0';
    if (nama_png[0] == '\0')
        snprintf(nama_png, sizeof(nama_png), "%s_key.png", dasar);

    /* ---- Masukan sandi XOR (kosong = tanpa XOR) ---- */
    printf(MSG_PROMPT_PASSWORD);
    fflush(stdout);
    if (!fgets(sandi, sizeof(sandi), stdin)) return;
    p = sandi + strlen(sandi);
    while (p > sandi && (p[-1]=='\n'||p[-1]=='\r'||p[-1]==' ')) *--p = '\0';

    /* Rakit nama berkas */
    snprintf(nama_engm,  sizeof(nama_engm),  "%s.engm", dasar);
    snprintf(nama_enc,   sizeof(nama_enc),   "%s.enc",  dasar);
    snprintf(awalan_log, sizeof(awalan_log), "%s",      dasar);

    /* ---- STEP 1: Ambil benih Wikipedia ---- */
    printf(MSG_STEP1);
    if (ambil_benih_wikipedia(benih, info_wiki, sizeof(info_wiki)) != 0) {
        fprintf(stderr, ERR_SEED);
        return;
    }
    printf(MSG_SEED, info_wiki);

    /* ---- STEP 2: Benih -> sembunyikan PNG LSB (XOR + Base64) ---- */
    printf(MSG_STEP2, nama_png);
    if (sembunyikan_benih_png(nama_png, benih, sandi) != 0) {
        fprintf(stderr, ERR_PNG_SAVE);
        return;
    }
    printf(MSG_PNG_OK, nama_png);

    /* ---- STEP 3: Inisialisasi rotor Enigma ---- */
    printf(MSG_STEP3);
    hasilkan_rotor_dari_benih(&mesin, benih, 32);
    printf(MSG_ENIGMA_READY);

    /* ---- STEP 4: Pak ke arsip biner ---- */
    printf(MSG_STEP4, jumlah_akhir, nama_engm);
    hasil = pak_berkas((const char * const *)ptr_jalur,
                       (uint32_t)jumlah_akhir, nama_engm, benih);
    if (hasil != 0) {
        fprintf(stderr, ERR_PACK);
        return;
    }
    printf(MSG_PACK_DONE, nama_engm);

    free(jalur_final);

    /* ---- STEP 5: Enkripsi Enigma ---- */
    printf(MSG_STEP5, nama_engm, nama_enc);
    if (enkripsi_berkas(&mesin, nama_engm, nama_enc) != 0) {
        fprintf(stderr, ERR_ENC);
        remove(nama_engm);
        return;
    }
    remove(nama_engm);
    printf(MSG_ENC_DONE, nama_enc);

    /* ---- STEP 6: Pemisahan 90MB + penyamaran log ---- */
    printf(MSG_STEP6, nama_enc, awalan_log);
    bagian = pisahkan_dan_samarkan(nama_enc, awalan_log);
    if (bagian < 0) {
        fprintf(stderr, ERR_LOG);
        remove(nama_enc);
        return;
    }
    remove(nama_enc);
    printf(MSG_LOG_DONE, bagian);

    printf(MSG_DONE_TITLE);
    printf(MSG_DONE_LOG, dasar, bagian);
    printf(MSG_DONE_KEY, nama_png);
}

/* ================================================================
 * pulihkan_berkas — Full restoration pipeline
 *
 * [EN] Prompts for log prefix, output archive name, key PNG path, and password,
 *      then executes the restoration pipeline:
 *        STEP 0: PNG LSB → extract seed (Base64 decode → optional XOR)
 *        STEP 1: _partNNN.log → .enc.tmp (pulihkan_dari_log)
 *        STEP 2: seed → reinitialise Enigma rotors
 *        STEP 3: .enc.tmp → .engm decrypt (enkripsi_berkas, involutive)
 *        STEP 4: .engm → extract all files to their original paths
 *      The temporary .enc.tmp file is removed after decryption succeeds.
 *      The .engm archive is also removed after extraction.
 * [ID] Pemulihan 4 langkah: ekstrak benih PNG → gabung log → dekripsi →
 *      ekstrak arsip. Berkas sementara dihapus setelah tiap langkah.
 * [JA] 4ステップの完全復元パイプライン。PNG種抽出→ログ結合→復号→
 *      アーカイブ展開。中間ファイルは各ステップ後に削除する。
 * ================================================================ */
static void pulihkan_berkas(void) {
    char        awalan    [PANJANG_JALUR_MAKS]; /* awalan log                  */
    char        nama_keluar[PANJANG_JALUR_MAKS]; /* berkas arsip setelah pemulihan */
    char        nama_enc  [PANJANG_JALUR_MAKS]; /* berkas terenkripsi sementara */
    char        nama_png  [PANJANG_JALUR_MAKS]; /* jalur PNG kunci             */
    char        sandi     [256];                /* XOR 鍵導出パスワード        */
    uint8_t     benih[32];
    MesinEnigma mesin;
    long long   total;
    char       *p;

    printf(MSG_PROMPT_LOG_PREFIX);
    fflush(stdout);
    if (!fgets(awalan, sizeof(awalan), stdin)) return;
    p = awalan + strlen(awalan);
    while (p > awalan && (p[-1]=='\n'||p[-1]=='\r'||p[-1]==' ')) *--p = '\0';

    printf(MSG_PROMPT_OUT_ARCHIVE);
    fflush(stdout);
    if (!fgets(nama_keluar, sizeof(nama_keluar), stdin)) return;
    p = nama_keluar + strlen(nama_keluar);
    while (p > nama_keluar && (p[-1]=='\n'||p[-1]=='\r'||p[-1]==' ')) *--p = '\0';
    if (nama_keluar[0] == '\0')
        strncpy(nama_keluar, "hasil.engm", sizeof(nama_keluar) - 1);

    /* ---- Masukan jalur PNG kunci ---- */
    printf(MSG_PROMPT_PNG_DEC, awalan);
    fflush(stdout);
    if (!fgets(nama_png, sizeof(nama_png), stdin)) return;
    p = nama_png + strlen(nama_png);
    while (p > nama_png && (p[-1]=='\n'||p[-1]=='\r'||p[-1]==' ')) *--p = '\0';
    if (nama_png[0] == '\0')
        snprintf(nama_png, sizeof(nama_png), "%s_key.png", awalan);

    /* ---- Masukan sandi ---- */
    printf(MSG_PROMPT_PASSWORD);
    fflush(stdout);
    if (!fgets(sandi, sizeof(sandi), stdin)) return;
    p = sandi + strlen(sandi);
    while (p > sandi && (p[-1]=='\n'||p[-1]=='\r'||p[-1]==' ')) *--p = '\0';

    snprintf(nama_enc, sizeof(nama_enc), "%s.enc.tmp", awalan);

    /* ---- STEP 0: Ekstrak benih dari PNG LSB ---- */
    printf(MSG_RESTORE_STEP0, nama_png);
    if (ekstrak_benih_png(nama_png, benih, sandi) != 0) {
        fprintf(stderr, ERR_PNG_EXTRACT);
        return;
    }
    printf(MSG_RESTORE_PNG_OK);

    /* ---- STEP 1: Pulihkan biner terenkripsi dari log ---- */
    printf(MSG_RESTORE_STEP1, awalan, nama_enc);
    total = pulihkan_dari_log(awalan, nama_enc);
    if (total < 0) {
        fprintf(stderr, ERR_LOG_RESTORE);
        return;
    }
    printf(MSG_RESTORE_LOG_OK, total);

    /* ---- STEP 2: Inisialisasi rotor ---- */
    printf(MSG_RESTORE_STEP2);
    hasilkan_rotor_dari_benih(&mesin, benih, 32);
    printf(MSG_ENIGMA_READY);

    /* ---- STEP 3: Dekripsi (sama dengan enkripsi, involutif) ---- */
    printf(MSG_RESTORE_STEP3, nama_enc, nama_keluar);
    if (enkripsi_berkas(&mesin, nama_enc, nama_keluar) != 0) {
        fprintf(stderr, ERR_DEC);
        remove(nama_enc);
        return;
    }
    remove(nama_enc);
    printf(MSG_RESTORE_DEC_OK, nama_keluar);

    /* ---- STEP 4: Buka arsip .engm -> ekstrak berkas ---- */
    printf(MSG_RESTORE_STEP4, nama_keluar);
    {
        FILE       *fengm;
        uint8_t    *buf;
        size_t      buf_sz;
        InfoBerkas *entri;
        uint32_t    jumlah_entri = 0;
        uint32_t    i;
        char        jalur_tmp[PANJANG_JALUR_MAKS];

        fengm = fopen(nama_keluar, "rb");
        if (!fengm) { fprintf(stderr, ERR_OPEN_ARCHIVE); return; }
        fseek(fengm, 0, SEEK_END);
        buf_sz = (size_t)ftell(fengm);
        fseek(fengm, 0, SEEK_SET);
        buf = (uint8_t *)malloc(buf_sz);
        if (!buf) { fclose(fengm); fprintf(stderr, ERR_ALLOC_BUF); return; }
        if (fread(buf, 1, buf_sz, fengm) != buf_sz) {
            free(buf); fclose(fengm);
            fprintf(stderr, ERR_READ_ARCHIVE); return;
        }
        fclose(fengm);

        entri = (InfoBerkas *)malloc(sizeof(InfoBerkas) * JUMLAH_JALUR_MAKS);
        if (!entri) {
            free(buf);
            fprintf(stderr, ERR_ALLOC_ENTRY);
            return;
        }

        if (buka_arsip(buf, buf_sz, entri, &jumlah_entri, benih) != 0) {
            free(buf);
            free(entri);
            fprintf(stderr, ERR_INVALID_ARCHIVE); return;
        }

        printf(MSG_RESTORE_ARCHIVE_COUNT, jumlah_entri);
        for (i = 0; i < jumlah_entri; i++) {
            FILE    *ftulis;
            uint16_t pj = entri[i].panjang_jalur;
            if (pj >= PANJANG_JALUR_MAKS) pj = (uint16_t)(PANJANG_JALUR_MAKS - 1);
            memcpy(jalur_tmp, entri[i].jalur, pj);
            jalur_tmp[pj] = '\0';

            buat_dir_orang_tua(jalur_tmp);
            ftulis = fopen(jalur_tmp, "wb");
            if (!ftulis) {
                fprintf(stderr, ERR_SKIP_FILE, jalur_tmp);
                continue;
            }
            if (entri[i].ukuran_data > 0)
                fwrite(entri[i].data, 1, (size_t)entri[i].ukuran_data, ftulis);
            fclose(ftulis);
            printf(MSG_RESTORE_FILE_OK, jalur_tmp,
                   (unsigned long long)entri[i].ukuran_data);
        }
        free(buf);
        free(entri);
        remove(nama_keluar); /* Hapus arsip sementara setelah ekstraksi */

        printf(MSG_RESTORE_DONE_TITLE);
        printf(MSG_RESTORE_DONE, jumlah_entri);
    }
}

/* ================================================================
 * main — Console input / command loop
 *
 * [EN] Reads lines from stdin in a loop.  Each line is either:
 *        - A quoted or unquoted file/directory path → appended to queue
 *        - A numeric command ("1"–"4") → triggers the corresponding action
 *        - Empty (Enter pressed) → runs the encryption pipeline
 *      UTF-8 console output is enabled on Windows via SetConsoleOutputCP(65001).
 * [ID] Loop baca stdin: jalur berkas → tambah ke antrian, perintah numerik →
 *      aksi, Enter kosong → enkripsi.
 * [JA] stdinをループ読み込み: パス→キュー追加、数字コマンド→アクション実行、
 *      空Enter→暗号化実行。UTF-8コンソール出力を有効化する。
 * ================================================================ */
int main(void) {
#if defined(_WIN32) || defined(_MSC_VER)
    SetConsoleOutputCP(65001);
    SetConsoleCP(65001);
#endif
    char (*antrian_jalur)[PANJANG_JALUR_MAKS];
    int  jumlah_jalur = 0;
    char masukan[PANJANG_JALUR_MAKS];

    antrian_jalur = (char (*)[PANJANG_JALUR_MAKS])malloc(
        (size_t)JUMLAH_JALUR_MAKS * PANJANG_JALUR_MAKS);
    if (!antrian_jalur) {
        fprintf(stderr, ERR_ALLOC_QUEUE);
        return 1;
    }

    printf(MSG_TITLE);
    printf(MSG_HELP_DROP);
    printf(MSG_HELP_ENTER);
    printf(MSG_HELP_RESTORE);
    printf(MSG_HELP_LIST);
    printf(MSG_HELP_CLEAR);
    printf(MSG_HELP_EXIT);

    while (fgets(masukan, sizeof(masukan), stdin)) {
        potong_spasi(masukan); /* Hapus \r\n dan spasi */

        /* ---- Deteksi perintah (baris tanpa kutip) ---- */
        if (strchr(masukan, '"') == NULL) {
            if (strcmp(masukan, "4") == 0)  { break; }
            if (strcmp(masukan, "3") == 0)  { jumlah_jalur = 0; printf(MSG_QUEUE_CLEARED); printf(MSG_PROMPT_CMD); continue; }
            if (strcmp(masukan, "2") == 0)  { tampilkan_daftar(antrian_jalur, jumlah_jalur); printf(MSG_PROMPT_CMD); continue; }
            if (strcmp(masukan, "1") == 0)  { pulihkan_berkas(); printf(MSG_PROMPT_CMD); continue; }
            if (masukan[0] == '\0')         { gabungkan_berkas(antrian_jalur, jumlah_jalur); jumlah_jalur = 0; printf(MSG_PROMPT_CMD); continue; }
        }

        /* ---- Baris jalur: tambah banyak jalur sekaligus ---- */
        if (jumlah_jalur >= JUMLAH_JALUR_MAKS) {
            fprintf(stderr, ERR_QUEUE_FULL, JUMLAH_JALUR_MAKS);
            continue;
        }
        {
            int sebelum = jumlah_jalur;
            jumlah_jalur = tambah_jalur_dari_baris(
                masukan, antrian_jalur, jumlah_jalur, JUMLAH_JALUR_MAKS);
            for (int i = sebelum; i < jumlah_jalur; i++)
                printf(MSG_ADDED, i + 1, antrian_jalur[i]);
        }
    }

    free(antrian_jalur);
    return 0;
}
