/* pack_test -- closed log segments packed with zstd and chained by their
 * trailers. sec 459.
 *
 * THE HASH IS A TOY, a 32-byte FNV variant: what is under test is the chain
 * and the packing, not the primitive, and the library takes the hash as an
 * interface. The chain is recomputed here by a loop of this file's own, so
 * the packer is not checked against itself.
 *
 * In a scratch directory of its own that it leaves empty. */

#define _POSIX_C_SOURCE 200809L

#include "../pack.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <zstd.h>

static int checks, failures;

#define CHECK(cond, what)                                                                      \
	do {                                                                                   \
		checks++;                                                                      \
		if (!(cond)) {                                                                 \
			failures++;                                                            \
			fprintf(stderr, "  FAIL pack_test.c:%d: %s\n", __LINE__, what);        \
		}                                                                              \
	} while (0)

static int toy(void *ctx, uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len)
{
	size_t w, i;

	(void)ctx;
	for (w = 0; w < out_len; w++) {
		uint32_t h = 2166136261u ^ (uint32_t)(w * 0x9e3779b9u);

		for (i = 0; i < in_len; i++)
			h = (h ^ in[i]) * 16777619u;
		out[w] = (uint8_t)(h ^ (h >> 13) ^ (h >> 24));
	}
	return 1; /* nonzero is success, as the seam says */
}

static const fzn_hash_ops_t HASH = { toy, NULL };

static int refusing(void *ctx, uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len)
{
	(void)ctx;
	(void)in;
	(void)in_len;
	memset(out, 0, out_len);
	return 0;
}

static const fzn_hash_ops_t REFUSING = { refusing, NULL };
static char top[64];
static uint8_t seg[300000], back[400000];

/* The chain over `n` bytes from `prev`, by this test's own loop. */
static void chain(const uint8_t *b, size_t n, const uint8_t prev[32], uint8_t out[32])
{
	static uint8_t buf[32u + FZN_LOG_PACK_CHUNK];
	size_t at = 0;

	memcpy(out, prev, 32u);
	while (at < n) {
		size_t c = n - at < FZN_LOG_PACK_CHUNK ? n - at : FZN_LOG_PACK_CHUNK;

		memcpy(buf, out, 32u);
		memcpy(buf + 32, b + at, c);
		(void)toy(NULL, out, 32u, buf, 32u + c);
		at += c;
	}
}

/* A segment of `n` bytes of whole lines. */
static size_t make_segment(const char *path, size_t n)
{
	FILE *f = fopen(path, "wb");
	size_t i;

	for (i = 0; i < n; i++)
		seg[i] = (i + 1u) % 97u == 0u ? '\n' : (uint8_t)('a' + (i % 26u));
	if (n)
		seg[n - 1u] = '\n';
	if (!f || fwrite(seg, 1u, n, f) != n || fclose(f) != 0)
		return 0;
	return n;
}

static size_t unzstd(const char *path, uint8_t *out, size_t cap)
{
	static uint8_t z[400000];
	FILE *f = fopen(path, "rb");
	size_t n, r;

	if (!f)
		return 0;
	n = fread(z, 1u, sizeof(z), f);
	(void)fclose(f);
	r = ZSTD_decompress(out, cap, z, n);
	return ZSTD_isError(r) ? 0u : r;
}

static int flip(const char *path, long at)
{
	FILE *f = fopen(path, "r+b");
	int c, ok;

	if (!f)
		return 0;
	ok = fseek(f, at, SEEK_SET) == 0 && (c = fgetc(f)) != EOF && fseek(f, at, SEEK_SET) == 0
	     && fputc(c ^ 0x20, f) != EOF;
	return (fclose(f) == 0) && ok;
}

static int exists(const char *p)
{
	struct stat st;

	return stat(p, &st) == 0;
}

static void test_one_segment(void)
{
	static const size_t SIZES[] = { 1u, 97u, FZN_LOG_PACK_CHUNK, 2u * FZN_LOG_PACK_CHUNK,
		                        (2u * FZN_LOG_PACK_CHUNK) + 5000u };
	uint8_t zero[32] = { 0 }, prev[32], h[32], want[32], other[32];
	char log[160], zst[160], expect_tr[200];
	size_t i, n, got;

	memset(prev, 0x77, sizeof(prev));
	snprintf(log, sizeof(log), "%s/one.log", top);
	snprintf(zst, sizeof(zst), "%s/one.log.zst", top);
	for (i = 0; i < sizeof(SIZES) / sizeof(SIZES[0]); i++) {
		n = make_segment(log, SIZES[i]);
		chain(seg, n, prev, want);
		CHECK(n && fzn_log_pack_segment(log, zst, prev, &HASH, h) == FZN_LOG_PACK_OK
		              && memcmp(h, want, 32u) == 0,
		      "a segment packs, and its hash is the chain this test computes");
		CHECK(fzn_log_pack_verify(zst, prev, &HASH, h) == FZN_LOG_PACK_OK
		              && memcmp(h, want, 32u) == 0,
		      "and verifies, at one byte, a line, one chunk, two chunks and past them");
	}
	/* WHAT zstdcat WOULD SHOW: the segment, then the trailer line. */
	got = unzstd(zst, back, sizeof(back));
	{
		char ph[65], hh[65];
		size_t k;

		for (k = 0; k < 32u; k++) {
			snprintf(ph + (k * 2u), 3u, "%02x", prev[k]);
			snprintf(hh + (k * 2u), 3u, "%02x", want[k]);
		}
		snprintf(expect_tr, sizeof(expect_tr), "#fuzznet-log-trailer 1 prev=%s hash=%s\n", ph, hh);
	}
	CHECK(got == n + strlen(expect_tr) && memcmp(back, seg, n) == 0
	              && memcmp(back + n, expect_tr, strlen(expect_tr)) == 0,
	      "decompressed, it is the segment's bytes and then the trailer, as the header says");
	CHECK(fzn_log_pack_verify(zst, zero, &HASH, other) == FZN_LOG_PACK_ERR_CHAIN,
	      "verified from another prev, the chain does not hold");
	CHECK(flip(zst, 40L) && fzn_log_pack_verify(zst, prev, &HASH, other) != FZN_LOG_PACK_OK,
	      "a byte flipped in the packed file is found");
	/* A TRAILER WITH THE RIGHT PREV AND A WRONG HASH, made by hand: only
	 * the hash comparison can refuse it. */
	{
		static uint8_t plain[1000], z[2000];
		char line[200], ph[65];
		size_t k, zn;
		FILE *f;

		for (k = 0; k < 32u; k++)
			snprintf(ph + (k * 2u), 3u, "%02x", prev[k]);
		memcpy(plain, "a line\n", 7u);
		snprintf(line, sizeof(line), "#fuzznet-log-trailer 1 prev=%s hash=%064x\n", ph, 0);
		memcpy(plain + 7, line, strlen(line));
		zn = ZSTD_compress(z, sizeof(z), plain, 7u + strlen(line), 3);
		f = fopen(zst, "wb");
		CHECK(!ZSTD_isError(zn) && f && fwrite(z, 1u, zn, f) == zn && fclose(f) == 0,
		      "fixture: a packed file whose trailer has the right prev and a wrong hash");
		CHECK(fzn_log_pack_verify(zst, prev, &HASH, other) == FZN_LOG_PACK_ERR_CHAIN,
		      "a trailer whose hash is not the chain over the bytes is refused");
	}
	/* A HASH THAT REFUSES packs nothing and verifies nothing: the seam's
	 * zero is failure. */
	n = make_segment(log, 97u);
	CHECK(n && fzn_log_pack_segment(log, zst, prev, &REFUSING, h) == FZN_LOG_PACK_ERR_CHAIN,
	      "a hash that refuses packs nothing");
	CHECK(fzn_log_pack_segment(log, zst, prev, &HASH, h) == FZN_LOG_PACK_OK
	              && fzn_log_pack_verify(zst, prev, &REFUSING, other) == FZN_LOG_PACK_ERR_CHAIN,
	      "and verifies nothing");
	(void)remove(log);
	(void)remove(zst);
}

static void test_a_directory(void)
{
	static const uint64_t SETTLE = 10u * 1000000u;
	char a[160], b[160], cur[160], late[160], chain_path[160], z[200], text[80];
	uint8_t zero[32] = { 0 }, h1[32], h2[32], h3[32], ch[32];
	size_t packed = 9;
	FILE *f;

	snprintf(a, sizeof(a), "%s/netcfgd.1000000.10.log", top);
	snprintf(b, sizeof(b), "%s/netcfgd.2000000.11.log", top);
	snprintf(late, sizeof(late), "%s/netcfgd.9000000.12.log", top);
	snprintf(cur, sizeof(cur), "%s/netcfgd.log", top);
	snprintf(chain_path, sizeof(chain_path), "%s/netcfgd.chain", top);
	CHECK(make_segment(b, 3000u) && make_segment(a, 5000u) && make_segment(late, 100u)
	              && make_segment(cur, 200u),
	      "fixture: two settled segments, one just closed, and the current file");
	CHECK(fzn_log_pack_dir(top, "netcfgd", &HASH, 2000000u + SETTLE, SETTLE, &packed)
	                      == FZN_LOG_PACK_OK
	              && packed == 2u,
	      "the two settled segments are packed, and the just-closed one is not");
	CHECK(!exists(a) && !exists(b) && exists(late) && exists(cur),
	      "the packed segments are removed; the unsettled one and the current file stay");
	snprintf(z, sizeof(z), "%s.zst", a);
	CHECK(fzn_log_pack_verify(z, zero, &HASH, h1) == FZN_LOG_PACK_OK,
	      "the older is first in the chain, from zero");
	snprintf(z, sizeof(z), "%s.zst", b);
	CHECK(fzn_log_pack_verify(z, h1, &HASH, h2) == FZN_LOG_PACK_OK,
	      "the newer chains from the older");
	f = fopen(chain_path, "r");
	CHECK(f && fgets(text, sizeof(text), f) && strlen(text) == 65u, "the chain file holds a hash");
	if (f)
		(void)fclose(f);
	{
		size_t k;

		for (k = 0; k < 32u; k++) {
			unsigned v = 0;

			(void)sscanf(text + (k * 2u), "%2x", &v);
			ch[k] = (uint8_t)v;
		}
	}
	CHECK(memcmp(ch, h2, 32u) == 0, "and it is the newest segment's");
	CHECK(fzn_log_pack_dir(top, "netcfgd", &HASH, 2000000u + SETTLE, SETTLE, &packed)
	                      == FZN_LOG_PACK_OK
	              && packed == 0u,
	      "a second pass at the same time packs nothing");
	CHECK(fzn_log_pack_dir(top, "netcfgd", &HASH, 9000000u + SETTLE, SETTLE, &packed)
	                      == FZN_LOG_PACK_OK
	              && packed == 1u && !exists(late),
	      "once settled, the late one is packed");
	snprintf(z, sizeof(z), "%s.zst", late);
	CHECK(fzn_log_pack_verify(z, h2, &HASH, h3) == FZN_LOG_PACK_OK,
	      "and continues the chain across passes, from the hash the chain file kept");

	/* A CLOCK SET BACK, sec 470: a segment closed while the clock read
	 * years later is settled, not left until the clock reaches it; one a
	 * few seconds ahead -- skew -- still waits. */
	{
		char ahead[160], skew[160];
		uint8_t h4[32];

		snprintf(ahead, sizeof(ahead), "%s/netcfgd.900000000000.14.log", top);
		snprintf(skew, sizeof(skew), "%s/netcfgd.22000000.15.log", top);
		CHECK(make_segment(ahead, 300u) && make_segment(skew, 200u),
		      "fixture: a segment stamped years ahead, and one three seconds ahead");
		CHECK(fzn_log_pack_dir(top, "netcfgd", &HASH, 9000000u + SETTLE, SETTLE, &packed)
		                      == FZN_LOG_PACK_OK
		              && packed == 1u && !exists(ahead) && exists(skew),
		      "the one years ahead is packed, and the one within the settle period waits");
		snprintf(z, sizeof(z), "%s.zst", ahead);
		CHECK(fzn_log_pack_verify(z, h3, &HASH, h4) == FZN_LOG_PACK_OK,
		      "and it continues the chain");
		(void)remove(z);
		(void)remove(ahead);
		(void)remove(skew);
		/* AND ITS PACKED FORM, which only a broken settle check makes. */
		snprintf(z, sizeof(z), "%s.zst", skew);
		(void)remove(z);
	}
	CHECK(fzn_log_pack_dir(top, "a/b", &HASH, 0u, 0u, &packed) == FZN_LOG_PACK_ERR_MALFORMED,
	      "a program with a slash is refused");
	snprintf(z, sizeof(z), "%s.zst", a);
	(void)remove(z);
	snprintf(z, sizeof(z), "%s.zst", b);
	(void)remove(z);
	snprintf(z, sizeof(z), "%s.zst", late);
	(void)remove(z);
	/* EACH SEGMENT TOO, packed or not, so a failed pass leaves nothing. */
	(void)remove(a);
	(void)remove(b);
	(void)remove(late);
	(void)remove(cur);
	(void)remove(chain_path);
}

int main(void)
{
	(void)snprintf(top, sizeof(top), "/tmp/fzn-pack-test-XXXXXX");
	if (!mkdtemp(top)) {
		fprintf(stderr, "  FAIL pack_test.c: no scratch directory\n");
		return 1;
	}
	test_one_segment();
	test_a_directory();
	CHECK(rmdir(top) == 0, "the scratch directory is empty, and goes");

	if (failures) {
		fprintf(stderr, "pack_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("pack_test: all %d checks passed\n", checks);
	return 0;
}
