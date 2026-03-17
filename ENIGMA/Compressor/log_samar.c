/*
 * log_samar.c — Binary-to-log disguise and log-to-binary recovery
 *
 * [EN] Implements the two-way conversion between an encrypted binary and a
 *      collection of fake server monitoring log files.
 *
 *      Encoding specification:
 *        - Input binary is split into 90 MB chunks (_N90MB)
 *        - Each chunk becomes one *_partNNN.log file
 *        - 8 bytes are encoded per log line as decimal field values (000–255)
 *          using field names that mimic real server metrics:
 *            cpu mem dsk net lat req err tmp
 *        - Timestamps increment by 2 ms per line from a base of time()
 *        - pad= field records the number of zero-padding bytes appended to
 *          fill the last 8-byte group (0 for all complete lines)
 *        - chk= field holds (sum of all 8 values) mod 256 for integrity
 *        - First line of each chunk is a STARTUP line recording chunk size
 *          so restoration knows exactly how many bytes to expect
 *
 * [ID] Enkripsi biner <-> log server palsu. 8 byte per baris, pisah 90MB/part.
 *      Timestamp, checksum, dan STARTUP line untuk integritas dan ukuran chunk.
 * [JA] 暗号化バイナリ⟺偽サーバーログの双方向変換。1行8バイト、90MB/パート。
 *      タイムスタンプ・チェックサム・STARTUPラインでチャンクサイズと整合性を管理。
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
 * buat_waktu — Generate a fake log timestamp string
 *
 * [EN] Formats a syslog-style timestamp "Mar 15 08:42:31.847" from a base
 *      Unix time and a running millisecond offset.  Used to make consecutive
 *      log lines look like they arrived 2 ms apart.
 *      basis    : base Unix timestamp (seconds) from time()
 *      ms_lanjut: accumulated millisecond offset from basis
 *      out / n  : output buffer and its size
 * [ID] Format timestamp syslog dari detik dasar + offset milidetik.
 * [JA] syslogスタイルのタイムスタンプを生成する。基準秒+ミリ秒オフセット。
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
 * buat_baris — Compose one fake log line from 8 data bytes
 *
 * [EN] Assembles a complete log line in the format:
 *        <timestamp> <node> agentd[<pid>]: seq=<N> cpu=<v0> mem=<v1> ...
 *          lat=<v4> req=<v5> err=<v6> tmp=<v7> pad=<pad> chk=<checksum>
 *      data[8]: payload bytes (zero-padded to 8 if last line)
 *      pad    : number of zero bytes appended (0 = full line)
 *      seq    : line sequence number (1-based, global across all parts)
 *      pid    : pseudo-random fake process ID
 *      out/n  : output buffer and its size
 * [ID] Rakit satu baris log palsu dari 8 byte data.
 * [JA] 8バイトのデータから偽ログ1行を組み立てる。
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
 * extrak_nilai — Extract a decimal field value from a log line
 *
 * [EN] Finds the first occurrence of kunci in baris, then reads the decimal
 *      integer that follows the "=" sign.  Used during restoration to read
 *      all eight payload fields as well as the pad= and chk= control fields.
 *      Returns 0 on success, -1 if the key is not found.
 * [ID] Cari kunci dalam baris, baca integer desimal setelah "=".
 * [JA] ログ行から "key=NNN" 形式の数値フィールドを抽出する。
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
 * pisahkan_dan_samarkan — Disguise encrypted binary as log files
 *
 * [EN] Reads the entire input file into memory, then iterates over it in
 *      UKURAN_CHUNK (90 MB) slices.  For each slice a new *_partNNN.log is
 *      opened, a STARTUP line is written, then the slice bytes are encoded
 *      8 per line until the chunk is exhausted.  The last line of each chunk
 *      uses pad= to record any zero-padding needed to fill the final 8-byte
 *      group.
 * [ID] Baca seluruh biner, pisah per 90MB, tulis tiap chunk ke *_partNNN.log.
 * [JA] バイナリ全体を読み込み、90MBチャンクに分割して各*_partNNN.logに書き出す。
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
 * pulihkan_dari_log — Recover encrypted binary from log files
 *
 * [EN] Opens awalan_part001.log, _part002.log, … in order until a file is
 *      not found.  For each file:
 *        - The STARTUP line is parsed for total_bytes (chunk size limit)
 *        - Each data line is parsed for the 8 payload field values
 *        - The chk= checksum is verified; mismatched lines are skipped
 *        - The pad= field determines how many bytes of the last group to write
 *      If the user supplies a full filename like "output_part001.log" the
 *      suffix is stripped automatically to derive the base prefix.
 *      Returns total bytes written, or -1 if no data was found.
 * [ID] Baca partNNN.log secara urut, verifikasi checksum, pulihkan biner.
 * [JA] partNNNログを順に読み込み、チェックサム検証後にバイナリを復元する。
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
