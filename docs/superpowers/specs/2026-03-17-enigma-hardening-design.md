# ENIGMA Compressor 復号難易度強化 設計書

**日付:** 2026-03-17
**対象ブランチ:** main
**後方互換性:** なし（新仕様で全面更新）

---

## 概要

既存のENIGMA Compressorの暗号化パイプラインを強化し、総当たり攻撃・暗号解析・リバースエンジニアリングへの耐性を大幅に向上させる。log/csv偽装機能は維持する。

---

## 現在のパイプライン

```
Wikipedia → SHA-256 → seed(32B)
seed XOR SHA-256(password) → PNG LSB(Base64)
seed → Enigma初期化(3ロータ)
files → .engm → Enigma×1暗号化 → .enc → _partNNN.log分割
```

**主な弱点:**
- パスワードKDFがSHA-256一発（ストレッチングなし）
- Enigmaロータ3本のみ・単一パス
- 改ざん検知なし（HMAC不在）
- セッション毎のソルトなし（固定的な鍵導出）
- 一時ファイルが平文削除（フォレンジック復元可能）

---

## 新パイプライン

### 暗号化フロー

```
[STEP 1] Wikipedia → seed(32B)
[STEP 2] BCryptGenRandom → salt(32B)
[STEP 3] PBKDF2-SHA256(password, salt, 100000回) → kdf_out(128B)
           kdf_out[0:32]   = prot_key   (PNG保護用XOR鍵)
           kdf_out[32:64]  = eng_key1   (Enigmaパス2のrotor seed)
           kdf_out[64:96]  = eng_key2   (Enigmaパス3のrotor seed)
           kdf_out[96:128] = hmac_key   (HMAC-SHA256認証鍵)
[STEP 4] PNG LSBに保存: salt(32B) || (seed XOR prot_key)(32B) = 64B合計
          ※ sandIパラメータは新実装では無視する（後述）
[STEP 5] files → .engm (既存pak処理、変更なし)
[STEP 6] Enigmaパス1: hasilkan_rotor_dari_benih(seed,8ロータ) → enkripsi_berkas(.engm → .enc1)
[STEP 7] Enigmaパス2: hasilkan_rotor_dari_benih(eng_key1,8ロータ) → enkripsi_berkas(.enc1 → .enc2)
[STEP 8] Enigmaパス3: hasilkan_rotor_dari_benih(eng_key2,8ロータ) → enkripsi_berkas(.enc2 → .enc3)
[STEP 9] HMAC-SHA256(hmac_key, .enc3の全内容) = tag(32B)
          .enc3の先頭にtag(32B)を付加 → .enc (合計サイズ = .enc3サイズ + 32)
[STEP 10] .enc → _partNNN.log分割 (既存log_samar処理、変更なし)
各一時ファイル(.engm, .enc1, .enc2, .enc3)はhapus_aman()でゼロフィル後にremove
```

### 復号フロー

```
[STEP 0] PNG LSBからsalt(32B) と seed_enc(32B)を抽出
          ※ sandi引数は無視する（暗号化時も無視したため）
[STEP 1] PBKDF2-SHA256(password, salt, 100000回) → kdf_out(128B)
[STEP 2] seed = seed_enc XOR prot_key
[STEP 3] _partNNN.log → .enc (既存pulihkan_dari_log、変更なし)
[STEP 4] HMACタグ検証:
          tag = .encの先頭32B
          ciphertext = .encの残り(.enc3相当)
          HMAC-SHA256(hmac_key, ciphertext) と tag を比較
          不一致の場合 → エラー出力後、.encをhapus_amanして即座に中断
[STEP 5] ciphertext部分を.enc3として保存（先頭32Bスキップ）
[STEP 6] Enigmaパス3逆: hasilkan_rotor_dari_benih(eng_key2) → enkripsi_berkas(.enc3 → .enc2)
          ※ enkripsi_berfasは対合(involutive)関数のため、復号も同じ関数を使う
[STEP 7] Enigmaパス2逆: hasilkan_rotor_dari_benih(eng_key1) → enkripsi_berkas(.enc2 → .enc1)
[STEP 8] Enigmaパス1逆: hasilkan_rotor_dari_benih(seed)    → enkripsi_berkas(.enc1 → .engm)
[STEP 9] .engm → ファイル展開 (既存buka_arsip、変更なし)
各一時ファイルはhapus_aman()でゼロフィル後にremove
```

**対合性(Involutive)の説明:**
既存の`enkripsi_berkas`は暗号化と復号が同一関数（同じrotor初期化・同じ処理順序）で実現される対合関数。多段の場合、復号は暗号化の逆順（パス3→パス2→パス1）で各パスを同じ`enkripsi_berkas`で実行すれば元のデータが得られる。別途復号専用関数は不要。

---

## モジュール変更詳細

### 1. `pbkdf2.h`（新規作成）

PBKDF2-SHA256とHMAC-SHA256を純C（外部ライブラリなし）で実装。
依存: `enigma_engine.h`の`hitung_sha256`のみ。

```c
/* HMAC-SHA256
 * 実装上の注意: hitung_sha256はシングルコール型のため、
 * innerhash = SHA256( (key_padded XOR ipad) || data ) を計算する際は
 * (64 + data_len) バイトの中間バッファを動的確保して一度にハッシュ計算する。
 * outer hashも同様に (64 + 32) = 96バイトバッファを使用。
 */
void hmac_sha256(const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len,
                 uint8_t out[32]);

/* PBKDF2-SHA256
 * password / pw_len : パスワードとその長さ
 * salt / salt_len   : ソルトとその長さ (通常32B)
 * iterations        : イテレーション回数 (100000)
 * out               : 出力バッファ
 * out_len           : 出力バイト数 (128B)
 */
void pbkdf2_sha256(const uint8_t *password, size_t pw_len,
                   const uint8_t *salt,     size_t salt_len,
                   uint32_t iterations,
                   uint8_t *out, size_t out_len);
```

### 2. `enigma_engine.h`（変更）

- `JUMLAH_ROTOR`: 3 → 8
- `MesinEnigma`構造体に`langkah[JUMLAH_ROTOR]`（各ロータの可変ステップ量）を追加

```c
typedef struct {
    uint8_t rotor[JUMLAH_ROTOR][256];
    uint8_t rotor_balik[JUMLAH_ROTOR][256];
    uint8_t reflektor[256];
    uint8_t offset[JUMLAH_ROTOR];
    uint8_t langkah[JUMLAH_ROTOR];  // ← 追加: seed由来の1〜7の可変ステップ量
} MesinEnigma;
```

**ABI破壊について:** `MesinEnigma`をスタックに確保している箇所（`main.c`内の`gabungkan_berkas`・`pulihkan_berkas`両関数）はヘッダ変更後の再コンパイルで自動対応される。既存バイナリとの互換性はない。

### 3. `enigma_engine.c`（変更）

- ロータ8本生成に対応（Fisher-Yatesを8回実行）
- `hasilkan_rotor_dari_benih`でlangkah配列を初期化
  - `langkah[i] = (seed_derived_byte % 7) + 1` （1〜7の値、0を排除）
- ステッピング処理: 各バイト暗号化後に各ロータを`langkah[i]`ずつ進める
  - ロータiは`langkah[i-1]`で定義されたキャリーが発生した場合に限り進む（オドメータ方式の拡張）

### 4. `png_lsb.h/c`（変更）

**保存データ構造の変更:**
- 旧: seed(32B) XOR SHA-256(sandi) をBase64(44文字) でLSB埋め込み
- 新: [salt(32B) || seed_enc(32B)] をBase64(88文字+パディング`==`含む) でLSB埋め込み
  - Base64(64B) = 88文字（末尾`==`パディング2文字含む、合計88文字）
  - 必要LSBビット数: 88 × 8 = 704ビット
  - 利用可能LSBビット数: 64×64×3 = 12,288ビット（十分）

**sandi引数の扱い:**
新実装では`sandi`引数を受け取っても**無視する**。
旧実装の`seed XOR SHA-256(sandi)`による保護は廃止し、PBKDF2由来の`prot_key`のみで保護する。
関数シグネチャは既存呼び出し元との互換性のため引数を残すが、内部では参照しない。

```c
// jalur_keluar: PNG出力パス
// salt[32]:     ランダムソルト
// seed_enc[32]: seed XOR prot_key (暗号化済みseed)
// sandi:        無視（後方互換用シグネチャ保持）
int sembunyikan_benih_png(const char   *jalur_keluar,
                           const uint8_t salt[32],
                           const uint8_t seed_enc[32],
                           const char   *sandi);

int ekstrak_benih_png(const char *jalur_masuk,
                       uint8_t    salt[32],
                       uint8_t    seed_enc[32],
                       const char *sandi);
```

### 5. `main.c`（変更）

**新規関数 `hapus_aman(const char *jalur)`:**

```
// 実装手順（順序厳守）:
// 1. fopen(jalur, "r+b")  ← 書き込みモード・トランケートなし
// 2. fseek(f, 0, SEEK_END) / ftell() でサイズ取得
// 3. fseek(f, 0, SEEK_SET)
// 4. ゼロバッファ(4096B)で全体をfwrite(0x00)
// 5. fflush(f) → FlushFileBuffers((HANDLE)_get_osfhandle(_fileno(f))) でOSバッファを確実にフラッシュ
// 6. fclose(f)
// 7. remove(jalur)
// ※ fwriteの戻り値を確認し、失敗時もremoveまで続行する（部分的なゼロフィルでも削除を優先）
static void hapus_aman(const char *jalur);
```

**`gabungkan_berkas`の更新:**
- BCryptGenRandom でsalt(32B)生成
- パスワードを`uint8_t`キャストしてPBKDF2呼び出し → kdf_out(128B)
- Enigma 3パス化（各パスに独立したMesinEnigma変数を使用）
- HMAC付加処理（先頭32B）
- 全一時ファイルを`hapus_aman`で削除（旧`remove`呼び出しを全て置換）

**`pulihkan_berkas`の更新:**
- PNG抽出でsalt + seed_enc取得（新シグネチャ対応）
- PBKDF2復元 → seed, hmac_key等を導出
- HMAC検証（失敗時はhapus_amanして即時return）
- HMACヘッダ(32B)スキップしてciphertext部を.enc3へ書き出し
- Enigma 3パス逆順復号
- 全一時ファイルを`hapus_aman`で削除

---

## セキュリティ評価

| 脅威 | 現在 | 強化後 |
|---|---|---|
| パスワード総当たり | SHA-256(1回) ≒ 即座 | PBKDF2(100000回) ≒ 非常に遅い |
| 暗号文解析 | 単一Enigmaパス | 3パス独立鍵・相互依存 |
| 改ざん検知 | なし | HMAC-SHA256 |
| セッション固有性 | なし | ソルト毎回ランダム |
| フォレンジック復元 | 平文削除 | ゼロフィル後削除 |
| ロータ強度 | 3本・固定ステップ | 8本・可変ステップ(1〜7) |
| PNGファイル改ざん | 検知不可 | **設計上の境界**: PNGはHMAC対象外。PNGとlogファイルをセットで秘密管理することがセキュリティ前提。PNG単体の完全性はユーザー責任。 |

**PNGの整合性について:** HMACはciphertext（`.enc3`相当）のみを保護し、PNG内のsaltは保護対象外。攻撃者がPNGを改ざんしてsaltを差し替えた場合、PBKDF2から別の`hmac_key`が導出されHMAC検証が失敗するため、改ざん検知はある程度機能する。ただしPNGとlogを両方制御できる攻撃者に対しては無効なため、PNG自体の物理的・アクセス制御的な保護が前提となる。

---

## ファイル変更サマリー

| ファイル | 種別 | 変更内容 |
|---|---|---|
| `pbkdf2.h` | 新規 | HMAC-SHA256 + PBKDF2-SHA256実装 |
| `enigma_engine.h` | 変更 | JUMLAH_ROTOR 3→8、MesinEnigmaにlangkah[]追加（ABI破壊あり） |
| `enigma_engine.c` | 変更 | 8ロータ対応・可変ステッピング実装 |
| `png_lsb.h` | 変更 | 関数シグネチャ変更（salt+seed_enc分離、sandi無視） |
| `png_lsb.c` | 変更 | 64B(88文字Base64)対応、sandi処理削除 |
| `main.c` | 変更 | パイプライン全面更新、hapus_aman追加、PBKDF2/HMAC統合 |
| `packer.h/c` | 変更なし | 既存処理そのまま |
| `log_samar.h/c` | 変更なし | log/csv偽装機能そのまま維持 |
| `wikipedia_seed.h/c` | 変更なし | Wikipedia seed取得そのまま |

---

## 制約・注意事項

- 後方互換性なし（既存の.log/.pngファイルは復号不可）
- log/csv偽装機能（`log_samar`）はそのまま維持
- 外部ライブラリ追加なし（純C・WindowsAPIのみ）
- PBKDF2の100000イテレーションにより暗号化時間が数秒増加（許容済み）
- PNG LSBの64×64 RGBサイズは64Bのデータに対して十分な容量（704/12288ビット使用）