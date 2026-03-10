#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#if defined(_WIN32) || defined(_MSC_VER)
#  include <direct.h>
#  define MKDIR(p) _mkdir(p)
#else
#  include <sys/stat.h>
#  define MKDIR(p) mkdir((p), 0755)
#endif
#include "packer.h"
#include "enigma_engine.h"
#include "wikipedia_seed.h"
#include "log_samar.h"
#include "png_lsb.h"
#include "define.h"

#define PANJANG_JALUR_MAKS  _N1024
#define JUMLAH_JALUR_MAKS   _N256

/* ================================================================
 * Pembantu internal
 * ================================================================ */

/* Buat direktori induk secara rekursif untuk jalur berkas (jika belum ada) */
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

/* Pecah dan tambahkan jalur dari baris (kutip atau satu token tanpa kutip).
 * Nilai kembali: jumlah jalur yang ditambahkan */
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

/* Hapus spasi di awal dan akhir string */
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

/* Tampilkan isi antrian */
static void tampilkan_daftar(char jalur[][PANJANG_JALUR_MAKS], int jumlah) {
    if (jumlah == 0) { printf("  (antrian kosong)\n"); return; }
    for (int i = 0; i < jumlah; i++)
        printf("  [%d] %s\n", i + 1, jalur[i]);
}

/* ================================================================
 * gabungkan_berkas - Pipet enkripsi lengkap
 *
 * STEP 1: Wikipedia -> benih SHA-256
 * STEP 2: benih -> sembunyikan PNG LSB (XOR + Base64)
 * STEP 3: benih -> inisialisasi rotor Enigma
 * STEP 4: berkas -> arsip .engm (pak_berkas)
 * STEP 5: .engm -> .enc enkripsi (enkripsi_berkas)
 * STEP 6: .enc -> _partNNN.log penyamaran (pisahkan_dan_samarkan)
 * ================================================================ */
static void gabungkan_berkas(char jalur[][PANJANG_JALUR_MAKS], int jumlah) {
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

    if (jumlah == 0) { printf("  (antrian kosong)\n"); return; }

    /* Bangun larik pointer */
    for (i = 0; i < jumlah; i++) ptr_jalur[i] = jalur[i];

    /* ---- Masukan nama dasar keluaran ---- */
    printf("Nama dasar keluaran (kosong = output): ");
    fflush(stdout);
    if (!fgets(dasar, sizeof(dasar), stdin)) return;
    p = dasar + strlen(dasar);
    while (p > dasar && (p[-1]=='\n'||p[-1]=='\r'||p[-1]==' ')) *--p = '\0';
    if (dasar[0] == '\0') strncpy(dasar, "output", sizeof(dasar) - 1);

    /* ---- Masukan jalur PNG kunci ---- */
    printf("Nama berkas PNG kunci (kosong = %s_key.png): ", dasar);
    fflush(stdout);
    if (!fgets(nama_png, sizeof(nama_png), stdin)) return;
    p = nama_png + strlen(nama_png);
    while (p > nama_png && (p[-1]=='\n'||p[-1]=='\r'||p[-1]==' ')) *--p = '\0';
    if (nama_png[0] == '\0')
        snprintf(nama_png, sizeof(nama_png), "%s_key.png", dasar);

    /* ---- Masukan sandi XOR (kosong = tanpa XOR) ---- */
    printf("Sandi XOR (kosong = tanpa XOR): ");
    fflush(stdout);
    if (!fgets(sandi, sizeof(sandi), stdin)) return;
    p = sandi + strlen(sandi);
    while (p > sandi && (p[-1]=='\n'||p[-1]=='\r'||p[-1]==' ')) *--p = '\0';

    /* Rakit nama berkas */
    snprintf(nama_engm,  sizeof(nama_engm),  "%s.engm", dasar);
    snprintf(nama_enc,   sizeof(nama_enc),   "%s.enc",  dasar);
    snprintf(awalan_log, sizeof(awalan_log), "%s",      dasar);

    /* ---- STEP 1: Ambil benih Wikipedia ---- */
    printf("\n[STEP 1/6] Sedang memproses benih...\n");
    if (ambil_benih_wikipedia(benih, info_wiki, sizeof(info_wiki)) != 0) {
        fprintf(stderr, "  [GAGAL] Tidak dapat mengambil benih dari Wikipedia.\n\n");
        return;
    }
    printf("[SEED] %s\n\n", info_wiki);

    /* ---- STEP 2: Benih -> sembunyikan PNG LSB (XOR + Base64) ---- */
    printf("[STEP 2/6] Menyembunyikan benih ke PNG LSB: %s\n", nama_png);
    if (sembunyikan_benih_png(nama_png, benih, sandi) != 0) {
        fprintf(stderr, "  [GAGAL] Gagal menyimpan benih ke PNG.\n\n");
        return;
    }
    printf("[PNG]   Benih tersembunyi di: %s\n\n", nama_png);

    /* ---- STEP 3: Inisialisasi rotor Enigma ---- */
    printf("[STEP 3/6] Inisialisasi rotor Enigma...\n");
    hasilkan_rotor_dari_benih(&mesin, benih, 32);
    printf("[ENIGMA] Rotor siap.\n\n");

    /* ---- STEP 4: Pak ke arsip biner ---- */
    printf("[STEP 4/6] Mengemas %d berkas -> %s\n", jumlah, nama_engm);
    hasil = pak_berkas((const char * const *)ptr_jalur,
                       (uint32_t)jumlah, nama_engm, benih);
    if (hasil != 0) {
        fprintf(stderr, "  [GAGAL] Pengemasan gagal.\n\n");
        return;
    }
    printf("[PACK]  Selesai: %s\n\n", nama_engm);

    /* ---- STEP 5: Enkripsi Enigma ---- */
    printf("[STEP 5/6] Enkripsi: %s -> %s\n", nama_engm, nama_enc);
    if (enkripsi_berkas(&mesin, nama_engm, nama_enc) != 0) {
        fprintf(stderr, "  [GAGAL] Enkripsi gagal.\n\n");
        remove(nama_engm);
        return;
    }
    remove(nama_engm);
    printf("[ENC]   Selesai: %s\n\n", nama_enc);

    /* ---- STEP 6: Pemisahan 90MB + penyamaran log ---- */
    printf("[STEP 6/6] Menyamarkan: %s -> %s_partNNN.log\n", nama_enc, awalan_log);
    bagian = pisahkan_dan_samarkan(nama_enc, awalan_log);
    if (bagian < 0) {
        fprintf(stderr, "  [GAGAL] Penyamaran log gagal.\n\n");
        remove(nama_enc);
        return;
    }
    remove(nama_enc);
    printf("[LOG]   Selesai: %d bagian.\n\n", bagian);

    printf("=== SELESAI ===\n");
    printf("  Log  : %s_part001.log ... _part%03d.log\n", dasar, bagian);
    printf("  Kunci: %s  (simpan baik-baik!)\n\n", nama_png);
}

/* ================================================================
 * pulihkan_berkas - Pipet pemulihan lengkap
 *
 * STEP 0: PNG LSB -> ekstrak benih (Base64 -> XOR)
 * STEP 1: _partNNN.log -> .enc (pulihkan_dari_log)
 * STEP 2: benih -> inisialisasi rotor Enigma
 * STEP 3: .enc -> .engm dekripsi (enkripsi_berkas, involutif)
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

    printf("Awalan log masukan (mis. output): ");
    fflush(stdout);
    if (!fgets(awalan, sizeof(awalan), stdin)) return;
    p = awalan + strlen(awalan);
    while (p > awalan && (p[-1]=='\n'||p[-1]=='\r'||p[-1]==' ')) *--p = '\0';

    printf("Berkas keluaran arsip (kosong = hasil.engm): ");
    fflush(stdout);
    if (!fgets(nama_keluar, sizeof(nama_keluar), stdin)) return;
    p = nama_keluar + strlen(nama_keluar);
    while (p > nama_keluar && (p[-1]=='\n'||p[-1]=='\r'||p[-1]==' ')) *--p = '\0';
    if (nama_keluar[0] == '\0')
        strncpy(nama_keluar, "hasil.engm", sizeof(nama_keluar) - 1);

    /* ---- Masukan jalur PNG kunci ---- */
    printf("Berkas PNG kunci (kosong = %s_key.png): ", awalan);
    fflush(stdout);
    if (!fgets(nama_png, sizeof(nama_png), stdin)) return;
    p = nama_png + strlen(nama_png);
    while (p > nama_png && (p[-1]=='\n'||p[-1]=='\r'||p[-1]==' ')) *--p = '\0';
    if (nama_png[0] == '\0')
        snprintf(nama_png, sizeof(nama_png), "%s_key.png", awalan);

    /* ---- Masukan sandi ---- */
    printf("Sandi XOR (kosong = tanpa XOR): ");
    fflush(stdout);
    if (!fgets(sandi, sizeof(sandi), stdin)) return;
    p = sandi + strlen(sandi);
    while (p > sandi && (p[-1]=='\n'||p[-1]=='\r'||p[-1]==' ')) *--p = '\0';

    snprintf(nama_enc, sizeof(nama_enc), "%s.enc.tmp", awalan);

    /* ---- STEP 0: Ekstrak benih dari PNG LSB ---- */
    printf("\n[STEP 0/3] Mengekstrak benih dari PNG LSB: %s\n", nama_png);
    if (ekstrak_benih_png(nama_png, benih, sandi) != 0) {
        fprintf(stderr, "  [GAGAL] Gagal mengekstrak benih dari PNG.\n\n");
        return;
    }
    printf("[PNG]  Benih berhasil diekstrak.\n\n");

    /* ---- STEP 1: Pulihkan biner terenkripsi dari log ---- */
    printf("[STEP 1/3] Memulihkan dari log: %s_partNNN.log ke %s\n", awalan, nama_enc);
    total = pulihkan_dari_log(awalan, nama_enc);
    if (total < 0) {
        fprintf(stderr, "  [GAGAL] Pemulihan log gagal.\n\n");
        return;
    }
    printf("[LOG]  %lld byte dipulihkan.\n\n", total);

    /* ---- STEP 2: Inisialisasi rotor ---- */
    printf("[STEP 2/3] Inisialisasi rotor Enigma...\n");
    hasilkan_rotor_dari_benih(&mesin, benih, 32);
    printf("[ENIGMA] Rotor siap.\n\n");

    /* ---- STEP 3: Dekripsi (sama dengan enkripsi, involutif) ---- */
    printf("[STEP 3/3] Dekripsi: %s -> %s\n", nama_enc, nama_keluar);
    if (enkripsi_berkas(&mesin, nama_enc, nama_keluar) != 0) {
        fprintf(stderr, "  [GAGAL] Dekripsi gagal.\n\n");
        remove(nama_enc);
        return;
    }
    remove(nama_enc);
    printf("[DEC]  Selesai: %s\n\n", nama_keluar);

    /* ---- STEP 4: Buka arsip .engm -> ekstrak berkas ---- */
    printf("[STEP 4/4] Membuka arsip: %s\n", nama_keluar);
    {
        FILE       *fengm;
        uint8_t    *buf;
        size_t      buf_sz;
        InfoBerkas  entri[JUMLAH_JALUR_MAKS];
        uint32_t    jumlah_entri = 0;
        uint32_t    i;
        char        jalur_tmp[PANJANG_JALUR_MAKS];

        fengm = fopen(nama_keluar, "rb");
        if (!fengm) { fprintf(stderr, "  [GAGAL] Tidak dapat membuka arsip.\n\n"); return; }
        fseek(fengm, 0, SEEK_END);
        buf_sz = (size_t)ftell(fengm);
        fseek(fengm, 0, SEEK_SET);
        buf = (uint8_t *)malloc(buf_sz);
        if (!buf) { fclose(fengm); fprintf(stderr, "  [GAGAL] Alokasi memori gagal.\n\n"); return; }
        if (fread(buf, 1, buf_sz, fengm) != buf_sz) {
            free(buf); fclose(fengm);
            fprintf(stderr, "  [GAGAL] Gagal membaca arsip.\n\n"); return;
        }
        fclose(fengm);

        if (buka_arsip(buf, buf_sz, entri, &jumlah_entri, benih) != 0) {
            free(buf);
            fprintf(stderr, "  [GAGAL] Arsip tidak valid atau benih salah.\n\n"); return;
        }

        printf("[ARSIP] %u berkas ditemukan.\n", jumlah_entri);
        for (i = 0; i < jumlah_entri; i++) {
            FILE    *ftulis;
            uint16_t pj = entri[i].panjang_jalur;
            if (pj >= PANJANG_JALUR_MAKS) pj = (uint16_t)(PANJANG_JALUR_MAKS - 1);
            memcpy(jalur_tmp, entri[i].jalur, pj);
            jalur_tmp[pj] = '\0';

            buat_dir_orang_tua(jalur_tmp);
            ftulis = fopen(jalur_tmp, "wb");
            if (!ftulis) {
                fprintf(stderr, "  [SKIP] %s (gagal membuka untuk menulis)\n", jalur_tmp);
                continue;
            }
            if (entri[i].ukuran_data > 0)
                fwrite(entri[i].data, 1, (size_t)entri[i].ukuran_data, ftulis);
            fclose(ftulis);
            printf("  [OK]  %-60s  %llu byte\n", jalur_tmp,
                   (unsigned long long)entri[i].ukuran_data);
        }
        free(buf);
        remove(nama_keluar); /* Hapus arsip sementara setelah ekstraksi */

        printf("\n=== SELESAI ===\n");
        printf("  %u berkas dipulihkan.\n\n", jumlah_entri);
    }
}

/* ================================================================
 * main - Loop utama input drop konsol
 * ================================================================ */
int main(void) {
    char antrian_jalur[JUMLAH_JALUR_MAKS][PANJANG_JALUR_MAKS];
    int  jumlah_jalur = 0;
    char masukan[PANJANG_JALUR_MAKS];

    printf("=== ENIGMA Compressor ===\n");
    printf("Seret berkas ke jendela ini atau ketik jalur secara manual.\n");
    printf("  [Enter]   = jalankan enkripsi + penyamaran log\n");
    printf("  daftar    = tampilkan antrian\n");
    printf("  bersih    = kosongkan antrian\n");
    printf("  pulihkan  = pulihkan berkas dari log tersamar\n");
    printf("  keluar    = tutup program\n\n");

    while (fgets(masukan, sizeof(masukan), stdin)) {
        potong_spasi(masukan); /* Hapus \r\n dan spasi */

        /* ---- Deteksi perintah (baris tanpa kutip) ---- */
        if (strchr(masukan, '"') == NULL) {
            if (strcmp(masukan, "keluar") == 0)    { break; }
            if (strcmp(masukan, "bersih") == 0)    { jumlah_jalur = 0; printf("  Antrian dikosongkan.\n"); continue; }
            if (strcmp(masukan, "daftar") == 0)    { tampilkan_daftar(antrian_jalur, jumlah_jalur); continue; }
            if (strcmp(masukan, "pulihkan") == 0)  { pulihkan_berkas(); continue; }
            if (masukan[0] == '\0')                { gabungkan_berkas(antrian_jalur, jumlah_jalur); jumlah_jalur = 0; continue; }
        }

        /* ---- Baris jalur: tambah banyak jalur sekaligus ---- */
        if (jumlah_jalur >= JUMLAH_JALUR_MAKS) {
            fprintf(stderr, "  [GAGAL] Antrian penuh (maks %d).\n", JUMLAH_JALUR_MAKS);
            continue;
        }
        {
            int sebelum = jumlah_jalur;
            jumlah_jalur = tambah_jalur_dari_baris(
                masukan, antrian_jalur, jumlah_jalur, JUMLAH_JALUR_MAKS);
            for (int i = sebelum; i < jumlah_jalur; i++)
                printf("  Ditambahkan [%d]: %s\n", i + 1, antrian_jalur[i]);
        }
    }

    return 0;
}
