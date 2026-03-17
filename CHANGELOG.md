# Changelog

---

## [v1.0.1] - 2026-03-17

### English

#### Changed
- Replaced Indonesian-word commands (`pulihkan`, `daftar`, `bersih`, `keluar`) with numeric keys `1`–`4` for language-neutral operation.
  - `1` — Restore files from disguised log
  - `2` — Show queue
  - `3` — Clear queue
  - `4` — Exit
- After each operation completes (encryption, restore, list, clear), the command menu is now reprinted so the user always knows what to type next.

#### Fixed
- **GitHub Actions — MSBuild semicolon error:** Overriding `PreprocessorDefinitions` from the command line caused MSBuild to split the value on semicolons, treating `_CONSOLE` as an unknown switch. Fixed by adding a `$(LangDefine)` property to the vcxproj and passing only the single language token from the workflow.
- **GitHub Actions — wrong toolset:** The project targets Platform Toolset v145 (VS 2026) which is not available on `windows-latest` runners. Fixed by passing `/p:PlatformToolset=v143` in the workflow so the local project file is unchanged.
- **GitHub Actions — wrong output path:** The exe was looked up at `ENIGMA/x64/Release/` but MSBuild's default output directory for a project without an explicit `OutDir` is `$(ProjectDir)x64\Release\`. Fixed the rename and upload paths to `ENIGMA/Compressor/x64/Release/`.

---

### 日本語

#### 変更
- コマンドをインドネシア語単語からキー番号 (1〜4) に変更。言語に関係なく同じ操作感で使えるようになりました。
- 各処理（暗号化・復元・キュー表示・クリア）の完了後にコマンド一覧を再表示。

#### 修正
- GitHub Actions ビルドの MSBuild セミコロン問題を修正。
- GitHub Actions の PlatformToolset を v143 (VS2022) に上書きするよう修正。
- GitHub Actions の exe 出力パスを修正。

---

### Bahasa Indonesia

#### Diubah
- Perintah diubah dari kata-kata bahasa Indonesia menjadi angka 1–4.
- Setelah setiap proses selesai, daftar perintah ditampilkan kembali.

#### Diperbaiki
- Masalah titik koma MSBuild di GitHub Actions diperbaiki.
- PlatformToolset di-override ke v143 (VS2022) di GitHub Actions.
- Jalur output exe di GitHub Actions diperbaiki.

---

## [v1.0.0] - 2026-03-17

### English

#### Added
- Initial release.
- Enigma cipher engine (8 rotors) — original implementation inspired by the Enigma machine.
- Wikipedia seed — derives a unique 256-bit seed from a random Wikipedia article on every run.
- PNG LSB steganography — hides the seed inside the LSB of a user-supplied PNG image.
- Log disguise — splits the encrypted binary into `_part001.log` … `_partNNN.log` files.
- Multi-language support — English / Japanese / Indonesian, selected at compile time (`LANG_JA` / `LANG_ID`).
- GitHub Actions release workflow — builds all three language variants and publishes them as a GitHub Release on tag push.

---

### 日本語

#### 追加
- 初回リリース。
- Enigma暗号化エンジン（8ロータ）。
- Wikipedia seedによる毎回異なる256ビット鍵生成。
- PNG LSBへの鍵埋め込み。
- .log偽装分割出力。
- 多言語対応（英語・日本語・インドネシア語）。
- GitHub Actions リリースワークフロー。

---

### Bahasa Indonesia

#### Ditambahkan
- Rilis pertama.
- Mesin cipher Enigma (8 rotor).
- Pembangkit benih Wikipedia.
- Steganografi LSB PNG.
- Output log tersamar.
- Dukungan multibahasa (Inggris / Jepang / Indonesia).
- Alur rilis GitHub Actions.
