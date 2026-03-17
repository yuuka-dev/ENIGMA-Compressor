# ENIGMA Compressor

A Windows CLI tool that encrypts files and disguises them as `.log` files.

ファイルを暗号化して `.log` ファイルに偽装するWindows用CLIツール。

Alat CLI Windows untuk mengenkripsi file dan menyamarkannya sebagai file `.log`.

---

## Download / ダウンロード / Unduh

Download the latest exe from [Releases](../../releases).

| File | Language |
|---|---|
| `Enigma.exe` | English |
| `Enigma_ja.exe` | 日本語 |
| `Enigma_id.exe` | Bahasa Indonesia |

---

## English

### Features

- **Enigma encryption** — Original cipher engine based on the Enigma machine (8 rotors)
- **Wikipedia seed** — Generates a unique seed from a random Wikipedia article each time
- **PNG LSB steganography** — Hides key data in the LSB of a PNG image
- **Log disguise** — Splits encrypted output into `_part001.log` files
- **Multi-language** — English / Japanese / Indonesian (compile-time switch)

### Usage

#### Encrypt

1. Launch `Enigma.exe`
2. Drag and drop files or folders onto the window (multiple items supported)
3. Press `Enter`
4. Enter the output base name, key PNG path, and password

```
Output base name (blank = output): myfiles
Key PNG file (blank = myfiles_key.png):
XOR password (blank = no XOR):
```

Output:
- `myfiles_part001.log` ... `_partNNN.log` — encrypted split files
- `myfiles_key.png` — key file required for restore (**keep it safe**)

#### Restore

1. Launch `Enigma.exe`
2. Type `pulihkan` and press `Enter`
3. Enter the log prefix, key PNG path, and password

```
Input log prefix (e.g. output): myfiles
Output archive file (blank = hasil.engm):
Key PNG file (blank = myfiles_key.png):
XOR password (blank = no XOR):
```

### Commands

| Command | Action |
|---|---|
| *(drop files, then)* Enter | Run encryption |
| `1` | Restore mode |
| `2` | Show queue |
| `3` | Clear queue |
| `4` | Exit |

### Notes

- **If you lose the key PNG, restoration is impossible.** Always keep a backup.
- The password used for encryption must match the one used for restoration.
- Windows 10 version 1903 or later recommended.

---

## 日本語

### 特徴

- **Enigma暗号化** — Enigmaマシンをベースにした独自暗号エンジン（8ロータ）
- **Wikipediaシード** — 暗号化のたびにランダムなWikipedia記事からシードを生成
- **PNG LSBステガノグラフィ** — 鍵情報をPNG画像のLSBに隠蔽
- **ログ偽装** — 暗号化済みバイナリを `_part001.log` 等に分割偽装
- **多言語対応** — 英語 / 日本語 / インドネシア語（コンパイル時切り替え）

### 使い方

#### 暗号化

1. `Enigma_ja.exe` を起動
2. 暗号化したいファイルやフォルダをウィンドウにドラッグ＆ドロップ（複数可）
3. `Enter` を押す
4. 出力ベース名・鍵PNGパス・パスワードを入力

```
出力ベース名 (空白 = output): myfiles
鍵PNGファイル (空白 = myfiles_key.png):
XORパスワード (空白 = XORなし):
```

出力:
- `myfiles_part001.log` ... `_partNNN.log` — 暗号化済み分割ファイル
- `myfiles_key.png` — 復元に必要な鍵ファイル（**大切に保管**）

#### 復元

1. `Enigma_ja.exe` を起動
2. `pulihkan` と入力して `Enter`
3. ログ接頭辞・鍵PNG・パスワードを入力

```
ログの接頭辞を入力 (例: output): myfiles
出力アーカイブ名 (空白 = hasil.engm):
鍵PNGファイル (空白 = myfiles_key.png):
XORパスワード (空白 = XORなし):
```

### コマンド一覧

| コマンド | 動作 |
|---|---|
| *(ファイルドロップ後)* Enter | 暗号化実行 |
| `1` | 復元モード |
| `2` | キュー表示 |
| `3` | キュークリア |
| `4` | 終了 |

### 注意事項

- **鍵PNGを紛失すると復元不可能**です。必ずバックアップを取ってください。
- 暗号化時と復元時のパスワードが一致していないと復元できません。
- Windows 10 バージョン 1903 以降を推奨（日本語表示のため）。

---

## Bahasa Indonesia

### Fitur

- **Enkripsi Enigma** — Mesin cipher berbasis mesin Enigma (8 rotor)
- **Benih Wikipedia** — Menghasilkan benih unik dari artikel Wikipedia acak setiap kali
- **Steganografi PNG LSB** — Menyembunyikan data kunci di LSB gambar PNG
- **Penyamaran log** — Membagi output terenkripsi menjadi file `_part001.log`
- **Multibahasa** — Inggris / Jepang / Indonesia (pilihan waktu kompilasi)

### Cara Penggunaan

#### Enkripsi

1. Jalankan `Enigma_id.exe`
2. Seret file atau folder ke jendela (beberapa item didukung)
3. Tekan `Enter`
4. Masukkan nama dasar output, jalur PNG kunci, dan sandi

```
Nama dasar keluaran (kosong = output): myfiles
Nama berkas PNG kunci (kosong = myfiles_key.png):
Sandi XOR (kosong = tanpa XOR):
```

Output:
- `myfiles_part001.log` ... `_partNNN.log` — file terenkripsi terbagi
- `myfiles_key.png` — file kunci untuk pemulihan (**simpan baik-baik**)

#### Pemulihan

1. Jalankan `Enigma_id.exe`
2. Ketik `pulihkan` dan tekan `Enter`
3. Masukkan awalan log, PNG kunci, dan sandi

```
Awalan log masukan (mis. output): myfiles
Berkas keluaran arsip (kosong = hasil.engm):
Berkas PNG kunci (kosong = myfiles_key.png):
Sandi XOR (kosong = tanpa XOR):
```

### Daftar Perintah

| Perintah | Fungsi |
|---|---|
| *(setelah drop file)* Enter | Jalankan enkripsi |
| `1` | Mode pemulihan |
| `2` | Tampilkan antrian |
| `3` | Kosongkan antrian |
| `4` | Tutup program |

### Catatan

- **Jika PNG kunci hilang, pemulihan tidak mungkin dilakukan.** Selalu buat cadangan.
- Sandi saat enkripsi harus sama dengan sandi saat pemulihan.

---

## Build

Requires Visual Studio 2022 (v145 / C17).

```
git clone https://github.com/yuuka-dev/ENIGMA-Compressor.git
```

Open `ENIGMA/ENIGMA.slnx` in Visual Studio and build.

To change language: Project Properties → C/C++ → Preprocessor → add `LANG_JA` or `LANG_ID`.
