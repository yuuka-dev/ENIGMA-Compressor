# ENIGMA Compressor

ファイルを暗号化して `.log` ファイルに偽装するWindows用CLIツール。

---

## 特徴

- **Enigma暗号化** — Enigmaマシンをベースにした独自暗号エンジン（8ロータ）
- **Wikipediaシード** — 暗号化のたびにランダムなWikipedia記事からシードを生成
- **PNG LSBステガノグラフィ** — 鍵情報をPNG画像のLSBに隠蔽
- **ログ偽装** — 暗号化済みバイナリを `_part001.log` 等のログファイルに分割偽装
- **多言語対応** — 英語 / 日本語 / インドネシア語（コンパイル時切り替え）

---

## ダウンロード

[Releases](../../releases) から最新版の exe をダウンロードしてください。

| ファイル | 言語 |
|---|---|
| `Enigma.exe` | English |
| `Enigma_ja.exe` | 日本語 |
| `Enigma_id.exe` | Bahasa Indonesia |

---

## 使い方

### 暗号化

1. `Enigma.exe` を起動
2. 暗号化したいファイルやフォルダをウィンドウにドラッグ＆ドロップ（複数可）
3. `Enter` を押す
4. 出力ベース名・鍵PNGパス・パスワードを入力

```
Output base name (blank = output): myfiles
Key PNG file (blank = myfiles_key.png):
XOR password (blank = no XOR):
```

出力:
- `myfiles_part001.log` ... `_partNNN.log` — 暗号化済み分割ファイル
- `myfiles_key.png` — 復元に必要な鍵ファイル（**大切に保管**）

### 復元

1. `Enigma.exe` を起動
2. `pulihkan` と入力して Enter
3. ログファイルの接頭辞・鍵PNG・パスワードを入力

```
Input log prefix (e.g. output): myfiles
Output archive file (blank = hasil.engm):
Key PNG file (blank = myfiles_key.png):
XOR password (blank = no XOR):
```

### コマンド一覧

| コマンド | 動作 |
|---|---|
| *(ファイルをドロップ後) Enter* | 暗号化実行 |
| `pulihkan` | 復元モード |
| `daftar` | キュー表示 |
| `bersih` | キュークリア |
| `keluar` | 終了 |

---

## ビルド

Visual Studio 2022 (v145 / C17) が必要です。

```
git clone https://github.com/yuuka-dev/ENIGMA-Compressor.git
```

`ENIGMA/ENIGMA.slnx` をVisual Studioで開いてビルド。

### 言語を切り替えてビルドする

プロジェクトプロパティ → C/C++ → プリプロセッサ → **プリプロセッサの定義** に追記：

| 追加する定義 | ビルドされる言語 |
|---|---|
| *(なし)* | English（デフォルト） |
| `LANG_JA` | 日本語 |
| `LANG_ID` | Bahasa Indonesia |

---

## 注意事項

- **鍵PNGを紛失すると復元不可能**です。必ずバックアップを取ってください。
- 暗号化・復元時のパスワードが異なると復元できません。
- Windows 10 バージョン 1903 以降を推奨（日本語表示のため）。
