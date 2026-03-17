#pragma once
/* ================================================================
 * lang.h  -  コンパイル時言語切り替え
 *
 * ビルド時に LANG_JA または LANG_ID を定義する。
 *   cl.exe:   /DLANG_JA
 *   MSBuild:  /p:PreprocessorDefinitions="LANG_JA;%(PreprocessorDefinitions)"
 *   IDE:      プリプロセッサの定義に LANG_JA を追記
 * 未定義の場合は英語（デフォルト）。
 * ================================================================ */
#if defined(LANG_JA)
#  include "lang_ja.h"
#elif defined(LANG_ID)
#  include "lang_id.h"
#else
#  include "lang_en.h"
#endif
