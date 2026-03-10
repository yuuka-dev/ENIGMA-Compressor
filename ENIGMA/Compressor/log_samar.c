/*
 * log_samar.c
 *
 * Biner -> penyamaran log / log -> pemulihan biner
 *
 * Spesifikasi konversi:
 *   - Pisah biner masukan per _N90MB (90MB)
 *   - Konversi 8 byte per baris log (HEX->DEC)
 *   - Nama field disamarkan seperti metrik pemantau server
 *   - Timestamp berdasarkan time(), +2ms per baris
 *   - pad= : jumlah byte nol di akhir (hanya baris terakhir)
 *   - chk= : jumlah 8 byte mod 256 (verifikasi integritas)
 */

#include "log_samar.h"
#include "define.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

/* ================================================================
 * Konstanta internal
 * ================================================================ */

/* Jumlah byte per baris log */
#define BYTE_PER_BARIS   8u

/* Ukuran maksimal tiap chunk = 90 x 1024 x 1024 */
#define UKURAN_CHUNK     ((size_t)_N90MB)

/* Panjang maksimal baris log */
#define PANJANG_BARIS    256u

/* Rotasi nama host (pilih seq % JUMLAH_NODE) */
static const char *NAMA_NODE[] = {
    "srv-node-01", "srv-node-02", "srv-node-03"
};
#define JUMLAH_NODE 3

/* Nama field (8 field = 8 byte) */
static const char *NAMA_FIELD[BYTE_PER_BARIS] = {
    "cpu", "mem", "dsk", "net", "lat", "req", "err", "tmp"
};

/* ================================================================
 * Pembantu internal - Generate timestamp
 *
 * basis   : detik dasar dari time()
 * ms_lanjut: milidetik dari basis
 * out     : format "Mar 15 08:42:31.847"
 * ================================================================ */
static void buat_waktu(time_t basis, uint64_t ms_lanjut,
                        char *out, size_t n) {
    static const char *BULAN[] = {
        "Jan","Feb","Mar","Apr","May","Jun",
        "Jul","Aug","Sep","Oct","Nov","Dec"
    };
    time_t   ts = basis + (time_t)(ms_lanjut / 1000u);
    struct tm *t = localtime(&ts);
    unsigned  ms = (unsigned)(ms_lanjut % 1000u);

    snprintf(out, n, "%s %2d %02d:%02d:%02d.%03u",
             BULAN[t->tm_mon], t->tm_mday,
             t->tm_hour, t->tm_min, t->tm_sec, ms);
}

/* ================================================================
 * Pembantu internal - Generate satu baris log
 *
 * data[8] : data byte (bagian pad sudah nol)
 * pad     : jumlah byte nol (0 = baris penuh)
 * seq     : nomor urut
 * pid     : ID proses palsu
 * out     : buffer keluaran
 * ================================================================ */
static void buat_baris(const uint8_t *data, uint8_t pad,
                        uint64_t seq, unsigned pid,
                        time_t basis, uint64_t ms,
                        char *out, size_t n) {
    char    waktu[_N32];
    char    fields[128];
    char   *fp = fields;
    uint32_t chk = 0;
    unsigned i;

    buat_waktu(basis, ms, waktu, sizeof(waktu));

    /* Rakit field "cpu=042 mem=187 ..." */
    for (i = 0; i < BYTE_PER_BARIS; i++) {
        fp += sprintf(fp, "%s=%03u ", NAMA_FIELD[i], data[i]);
        chk += data[i];
    }

    snprintf(out, n,
             "%s %s agentd[%u]: "
             "seq=%09llu %s"
             "pad=%03u chk=%03u\n",
             waktu,
             NAMA_NODE[seq % JUMLAH_NODE],
             pid,
             (unsigned long long)seq,
             fields,
             (unsigned)pad,
             (unsigned)(chk & 0xFFu));
}

/* ================================================================
 * Pembantu internal - Ambil nilai field dari baris log
 *
 * Ekstrak angka dari format "key=NNN "
 * ================================================================ */
static int extrak_nilai(const char* baris, const char* kunci, uint32_t* nilai) {
    const char* p = strstr(baris, kunci);
    if (!p) return -1;

    p += strlen(kunci);

    /* Jika kunci tidak termasuk "=", lewati satu karakter */
    if (*p == '=') {
        p++;
    }

    *nilai = (uint32_t)strtoul(p, NULL, 10);
    return 0;
}

/* ================================================================
 * pisahkan_dan_samarkan
 *
 * Pisah biner masukan per UKURAN_CHUNK,
 * tulis tiap chunk ke berkas *_partNNN.log
 * ================================================================ */
int pisahkan_dan_samarkan(const char *berkas_masuk,
                           const char *awalan_keluar) {
    FILE    *fin;
    uint8_t *fbuf;         /* buffer seluruh berkas */
    size_t   ftotal;
    uint8_t *kursor;       /* pointer posisi baca */
    uint8_t *batas;        /* batas buffer */

    char     nama_out[_N1024];
    FILE    *fout;
    char     baris[PANJANG_BARIS];
    uint8_t  data[BYTE_PER_BARIS];

    time_t   basis;        /* dasar timestamp */
    uint64_t ms_clock;     /* penghitung milidetik */
    uint64_t seq;          /* nomor urut baris */
    unsigned pid;          /* PID palsu */

    int      part;
    size_t   chunk_bytes;
    uint8_t  pad;
    unsigned i;

    /* ---- Baca seluruh berkas ---- */
    fin = fopen(berkas_masuk, "rb");
    if (!fin) return -1;

    fseek(fin, 0, SEEK_END);
    ftotal = (size_t)ftell(fin);
    fseek(fin, 0, SEEK_SET);

    fbuf = (uint8_t *)malloc(ftotal);
    if (!fbuf) { fclose(fin); return -1; }

    if (fread(fbuf, 1, ftotal, fin) != ftotal) {
        free(fbuf); fclose(fin); return -1;
    }
    fclose(fin);

    /* ---- Inisialisasi penunjuk ---- */
    kursor = fbuf;
    batas = fbuf + ftotal;
    basis = time(NULL);
    ms_clock = 0;
    seq = 1;
    pid = 20000u + (unsigned)(basis & 0x7FFFu); /* PID pseudo-acak */
    part = 1;
    fout = NULL;

    while (kursor < batas) {
        /* ---- Mulai chunk baru: buka berkas keluaran ---- */
        chunk_bytes = (size_t)(batas - kursor);
        if (chunk_bytes > UKURAN_CHUNK) chunk_bytes = UKURAN_CHUNK;

        snprintf(nama_out, sizeof(nama_out),
            "%s_part%03d.log", awalan_keluar, part);

        fout = fopen(nama_out, "w");
        if (!fout) { free(fbuf); return -1; }

        /* Baris STARTUP di awal chunk (total_bytes sebagai metadata) */
        {
            char waktu[32];
            buat_waktu(basis, ms_clock, waktu, sizeof(waktu));
            fprintf(fout,
                "%s %s agentd[%u]: STARTUP part=%03d "
                "total_bytes=%zu epoch=%llu\n",
                waktu,
                NAMA_NODE[0],
                pid, part,
                chunk_bytes,
                (unsigned long long)basis);
            ms_clock += 2u;
        }

        /* ---- Proses 8 byte per iterasi di dalam chunk ---- */
        uint8_t* chunk_end = kursor + chunk_bytes;

        while (kursor < chunk_end) {
            size_t n = (size_t)(chunk_end - kursor);
            if (n > BYTE_PER_BARIS) n = BYTE_PER_BARIS;

            pad = (uint8_t)(BYTE_PER_BARIS - n);

            /* Salin 8 byte; sisanya nol */
            memcpy(data, kursor, n);
            if (pad > 0) memset(data + n, 0, pad);

            buat_baris(data, pad, seq, pid, basis, ms_clock,
                baris, sizeof(baris));
            fputs(baris, fout);

            /* Majukan pointer sesuai data */
            kursor += n;
            seq++;
            ms_clock += 2u;
        }

        fclose(fout); fout = NULL;
        printf("  [LOG] Part %03d -> %s  (%zu byte)\n",
            part, nama_out, chunk_bytes);
        part++;
    }

    free(fbuf);
    return part - 1; /* Jumlah part yang dibuat */
}

/* ================================================================
 * pulihkan_dari_log
 *
 * Baca awalan_masuk_part001.log, 002.log, ... secara urut,
 * ekstrak 8 byte per baris log untuk memulihkan biner.
 * total_bytes di baris STARTUP mengatur ukuran chunk.
 * ================================================================ */
long long pulihkan_dari_log(const char* awalan_masuk,
    const char* berkas_keluar) {
    FILE* fout;
    FILE* fin;
    char     awalan_kerja[_N1024]; /* nama dasar dinormalisasi */
    char     nama_in[_N1024];
    char     baris[PANJANG_BARIS];
    uint8_t  data[BYTE_PER_BARIS];

    uint32_t val[BYTE_PER_BARIS], pad_val, chk_val;
    size_t   total_bytes_chunk;
    size_t   bytes_written_chunk;
    long long total_keluar = 0;
    size_t   len;
    int      part;
    unsigned i;
    int      ok;

    /* Jika user input "output_part001.log" -> normalisasi ke "output"
     * _partNNN.log = 5+3+4 = 12 karakter */
    strncpy(awalan_kerja, awalan_masuk, sizeof(awalan_kerja) - 1);
    awalan_kerja[sizeof(awalan_kerja) - 1] = '\0';
    len = strlen(awalan_kerja);
    if (len >= 12) {
        const char *tail = awalan_kerja + len - 12;
        if (strncmp(tail, "_part", 5) == 0 &&
            tail[5] >= '0' && tail[5] <= '9' &&
            tail[6] >= '0' && tail[6] <= '9' &&
            tail[7] >= '0' && tail[7] <= '9' &&
            strcmp(tail + 8, ".log") == 0) {
            awalan_kerja[len - 12] = '\0';
        }
    }

    fout = fopen(berkas_keluar, "wb");
    if (!fout) return -1;

    /* Coba part=001, 002, ... sampai tidak ditemukan */
    for (part = 1; part <= 999; part++) {
        snprintf(nama_in, sizeof(nama_in),
                 "%s_part%03d.log", awalan_kerja, part);

        fin = fopen(nama_in, "r");
        if (!fin) break; /* Part berikutnya tidak ada -> selesai */

        total_bytes_chunk  = 0;
        bytes_written_chunk = 0;

        while (fgets(baris, sizeof(baris), fin)) {
            /* Baris STARTUP: baca total_bytes untuk ukuran chunk */
            if (strstr(baris, "STARTUP")) {
                const char* p = strstr(baris, "total_bytes=");
                if (p) {
                    p += strlen("total_bytes=");
                    total_bytes_chunk = (size_t)strtoul(p, NULL, 10);
                }
                continue;
            }

            /* Baris data: ekstrak 8 field */
            ok = 1;
            for (i = 0; i < BYTE_PER_BARIS && ok; i++)
                ok = (extrak_nilai(baris, NAMA_FIELD[i], &val[i]) == 0);

            if (!ok) continue;
            if (extrak_nilai(baris, "pad=", &pad_val) != 0) continue;
            if (extrak_nilai(baris, "chk=", &chk_val) != 0) continue;

            /* Verifikasi checksum */
            uint32_t chk_calc = 0;
            for (i = 0; i < BYTE_PER_BARIS; i++) chk_calc += val[i];
            if ((chk_calc & 0xFFu) != chk_val) {
                fprintf(stderr, "  [ERR] Checksum tidak cocok: %s", baris);
                continue;
            }

            /* Jumlah byte riil = 8 - pad */
            uint8_t real_bytes = (uint8_t)(BYTE_PER_BARIS - pad_val);

            /* Jangan melebihi total_bytes jika sudah diketahui */
            if (total_bytes_chunk > 0) {
                size_t sisa = total_bytes_chunk - bytes_written_chunk;
                if ((size_t)real_bytes > sisa)
                    real_bytes = (uint8_t)sisa;
            }

            /* Konversi uint32_t -> uint8_t dan tulis */
            for (i = 0; i < real_bytes; i++)
                data[i] = (uint8_t)val[i];

            fwrite(data, 1, real_bytes, fout);
            bytes_written_chunk += real_bytes;
            total_keluar        += real_bytes;
        }

        fclose(fin);
        printf("  [LOG] Part %03d -> %lld byte dipulihkan\n",
               part, (long long)bytes_written_chunk);
    }

    fclose(fout);
    /* 0 byte = log tidak ditemukan atau awalan salah -> gagal */
    if (total_keluar <= 0) {
        remove(berkas_keluar);
        fprintf(stderr, "  [ERR] Tidak ada data dipulihkan. Periksa awalan log (mis. nama harus cocok: %s_part001.log).\n", awalan_kerja);
        return -1;
    }
    return total_keluar;
}
