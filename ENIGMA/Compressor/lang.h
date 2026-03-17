#pragma once
/*
 * lang.h — Compile-time language dispatcher
 *
 * [EN] Selects the appropriate string header at compile time.
 *      Define LANG_JA for Japanese or LANG_ID for Indonesian before building.
 *        MSBuild : /p:LangDefine=LANG_JA  (see Compressor.vcxproj)
 *        cl.exe  : /DLANG_JA
 *        IDE     : add LANG_JA to Preprocessor Definitions
 *      Defaults to English when neither macro is defined.
 *      All UI strings are exposed as MSG_* / ERR_* macros so the rest of the
 *      codebase stays language-agnostic.
 *
 * [ID] Pilih header bahasa saat kompilasi. LANG_JA = Jepang, LANG_ID = Indonesia.
 *      Default: bahasa Inggris.
 * [JA] コンパイル時に言語ヘッダーを選択する。LANG_JA/LANG_ID で切り替え、未定義は英語。
 */
#if defined(LANG_JA)
#  include "lang_ja.h"
#elif defined(LANG_ID)
#  include "lang_id.h"
#else
#  include "lang_en.h"
#endif
