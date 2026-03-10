#ifndef LOG_SAMAR_H
#define LOG_SAMAR_H

/*
 * log_samar.h
 *
 * Biner terenkripsi Enigma dipisah 90MB,
 * tiap byte dikonversi HEX->DEC disamarkan sebagai log pemantau server.
 *
 * Format keluaran (1 baris = 8 byte):
 *   Mar 15 08:42:31.847 srv-node-01 agentd[23847]: \
 *     seq=000000001 cpu=042 mem=187 dsk=023 net=234 \
 *     lat=089 req=201 err=156 tmp=077 pad=000 chk=044
 *
 *   pad: jumlah byte nol di akhir (hanya baris terakhir)
 *   chk: jumlah 8 byte mod 256 (verifikasi integritas)
 */

/* Biner terenkripsi -> pisah 90MB + penyamaran log
 *   berkas_masuk   : jalur biner masukan
 *   awalan_keluar  : nama dasar log keluaran
 *                    -> awalan_keluar_part001.log, _part002.log, ...
 *   Nilai kembali  : jumlah part / -1 = error */
int pisahkan_dan_samarkan(const char *berkas_masuk,
                           const char *awalan_keluar);

/* Kumpulan log -> pemulihan biner
 *   awalan_masuk  : nama dasar log (cari awalan_masuk_partNNN.log)
 *   berkas_keluar : jalur biner keluaran
 *   Nilai kembali : byte dipulihkan / -1 = error */
long long pulihkan_dari_log(const char *awalan_masuk,
                             const char *berkas_keluar);

#endif /* LOG_SAMAR_H */
