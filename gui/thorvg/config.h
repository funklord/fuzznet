/*
 * ThorVG's config.h, which its own meson configure step would generate and
 * this build does not run: fuzznet sec 1151, as fuzzypickles' gui/thorvg.
 * Empty -- what ThorVG reads from it is passed as defines from the Makefile
 * (THORVG_SW_RASTER_SUPPORT, THORVG_LOTTIE_LOADER_SUPPORT, TVG_STATIC,
 * THORVG_VERSION_STRING). It is first on ThorVG's include path, so no other
 * config.h in the tree is found by accident -- the way fuzzypickles' build
 * broke on 2026-11-10 when such a file went.
 */
#ifndef FZN_THORVG_CONFIG_H
#define FZN_THORVG_CONFIG_H
#endif
