#ifndef LOG_SAMAR_H
#define LOG_SAMAR_H

/*
 * log_samar.h — Encrypted binary disguise as server monitoring logs
 *
 * [EN] Provides two inverse operations for hiding and recovering an encrypted
 *      binary inside plausible-looking server log files.
 *
 *      Disguise format (one log line = 8 data bytes):
 *        Mar 15 08:42:31.847 srv-node-01 agentd[23847]:
 *          seq=000000001 cpu=042 mem=187 dsk=023 net=234
 *          lat=089 req=201 err=156 tmp=077 pad=000 chk=044
 *
 *        Fields:  cpu mem dsk net lat req err tmp — carry the 8 payload bytes
 *                 pad — number of zero-padding bytes appended to the last line
 *                 chk — sum of all 8 field values mod 256 (integrity check)
 *
 *      Splitting: input is split into 90 MB chunks; each chunk becomes one
 *      *_partNNN.log file.  The first line of every chunk is a STARTUP line
 *      recording the chunk byte count for accurate restoration.
 *
 * [ID] Sembunyikan biner terenkripsi sebagai log server. 8 byte per baris.
 *      Pisah per 90MB menjadi _partNNN.log.
 * [JA] 暗号化バイナリをサーバーログに偽装する。1行=8バイト、90MBごとに分割。
 */

/*
 * pisahkan_dan_samarkan — Disguise encrypted binary as log files
 *
 * [EN] Reads the entire input file, splits it into 90 MB chunks, and writes
 *      each chunk as a *_partNNN.log file containing fake server log lines.
 *      Each data byte is encoded as a decimal field value (000–255) in one of
 *      the eight named fields per line.
 *
 *      berkas_masuk : path to the encrypted binary to disguise
 *      awalan_keluar: output base name; files are named awalan_part001.log, ...
 *      Returns: number of part files created / -1 = error
 *
 * [ID] Biner terenkripsi -> pisah 90MB + tulis sebagai log server palsu.
 * [JA] 暗号化バイナリ→90MB分割→偽サーバーログとして書き出す。
 */
int pisahkan_dan_samarkan(const char *berkas_masuk,
                           const char *awalan_keluar);

/*
 * pulihkan_dari_log — Recover encrypted binary from log files
 *
 * [EN] Reads awalan_part001.log, _part002.log, … in order, extracts the eight
 *      field values from each data line, verifies the chk checksum, strips the
 *      pad zero-padding from the last line of each chunk, and writes the
 *      recovered bytes to berkas_keluar.
 *
 *      awalan_masuk : base name of the log files to read
 *      berkas_keluar: path to write the recovered binary
 *      Returns: total bytes written / -1 = error (no data found or wrong prefix)
 *
 * [ID] Baca log partNNN, ekstrak 8 byte per baris, pulihkan ke berkas biner.
 * [JA] partNNNログを順に読み込み、1行8バイトを抽出してバイナリを復元する。
 */
long long pulihkan_dari_log(const char *awalan_masuk,
                             const char *berkas_keluar);

#endif /* LOG_SAMAR_H */
