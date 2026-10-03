/* pack_test -- closed log segments packed with zstd and chained by their
 * trailers. sec 459. The prune and keep rules over entries, repacking a
 * segment without some of its lines, sec 474.
 *
 * THE HASH IS A TOY, a 32-byte FNV variant: what is under test is the chain
 * and the packing, not the primitive, and the library takes the hash as an
 * interface. The chain is recomputed here by a loop of this file's own, so
 * the packer is not checked against itself.
 *
 * In a scratch directory of its own that it leaves empty. */

#define _POSIX_C_SOURCE 200809L

#include "../pack.h"
#include "../entry.h"

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

/* ---- the rules over entries, sec 474 ------------------------------------ */

#define DAY (86400ull * 1000000ull)

struct line_spec {
	fzn_entry_level_t level;
	const char *subsystem;
	const char *text;
	uint64_t time_us;
};

/* A segment of a header and classic lines. */
static int write_classic(const char *path, const struct line_spec *l, size_t n, uint64_t pos)
{
	static char line[FZN_ENTRY_LINE_MAX];
	FILE *f = fopen(path, "w");
	size_t i;
	int ok;

	if (!f)
		return 0;
	ok = fputs("#fuzznet-log 1 machine=00000000000000000000000000000000 host=h\n", f) >= 0;
	for (i = 0; i < n && ok; i++) {
		fzn_entry_t e;
		size_t len = 0;

		memset(&e, 0, sizeof(e));
		strcpy(e.name.user, "root");
		strcpy(e.name.program, "netcfgd");
		e.name.pid = 7u;
		e.name.start_ms = 1u;
		e.name.position = pos + i;
		e.time_us = l[i].time_us;
		e.level = l[i].level;
		strcpy(e.subsystem, l[i].subsystem);
		e.text = (const uint8_t *)l[i].text;
		e.text_len = strlen(l[i].text);
		ok = fzn_entry_classic(&e, "h", line, sizeof(line), &len) == FZN_ENTRY_OK
		     && fwrite(line, 1u, len, f) == len;
	}
	return (fclose(f) == 0) && ok;
}

/* What the packed segment `path` holds, NUL-terminated in `back`. */
static const char *packed_text(const char *path)
{
	size_t n = unzstd(path, back, sizeof(back) - 1u);

	back[n] = '\0';
	return (const char *)back;
}

static int retain(const char *const *lines, size_t n, uint64_t now, size_t *removed,
                  size_t *repacked)
{
	fzn_retain_rule_t rules[4];
	size_t i;

	for (i = 0; i < n; i++)
		if (fzn_retain_parse(lines[i], strlen(lines[i]), &rules[i]) != FZN_RETAIN_OK)
			return 0;
	return fzn_log_pack_retain(top, "netcfgd", rules, n, &HASH, now, removed, repacked)
	       == FZN_LOG_PACK_OK;
}

static void test_entry_rules(void)
{
	const uint64_t now = 100u * DAY;
	const struct line_spec old_lines[] = {
		{ FZN_ENTRY_INFO, "apply", "old info", now - (41u * DAY) },
		{ FZN_ENTRY_DEBUG, "apply", "old debug", now - (41u * DAY) },
		{ FZN_ENTRY_ERROR, "apply", "old error", now - (41u * DAY) },
	};
	const struct line_spec new_lines[] = {
		{ FZN_ENTRY_DEBUG, "apply", "new debug", now - DAY - 1000u },
		{ FZN_ENTRY_INFO, "notes/sync", "new info", now - DAY - 1000u },
	};
	char a[160], b[160], c[160], za[200], zb[200], chain_path[160], want[100];
	uint8_t zero[32] = { 0 }, ha[32], hb[32], carry[32];
	size_t packed = 0, removed = 9, repacked = 9, k;

	snprintf(a, sizeof(a), "%s/netcfgd.%llu.20.log", top, (unsigned long long)(now - 40u * DAY));
	snprintf(b, sizeof(b), "%s/netcfgd.%llu.21.log", top, (unsigned long long)(now - DAY));
	snprintf(c, sizeof(c), "%s/netcfgd.%llu.22.log", top, (unsigned long long)(now - 1000u));
	snprintf(za, sizeof(za), "%s.zst", a);
	snprintf(zb, sizeof(zb), "%s.zst", b);
	snprintf(chain_path, sizeof(chain_path), "%s/netcfgd.chain", top);
	CHECK(write_classic(a, old_lines, 3u, 0u) && write_classic(b, new_lines, 2u, 3u)
	              && fzn_log_pack_dir(top, "netcfgd", &HASH, now - 10000u, 1000u, &packed)
	                         == FZN_LOG_PACK_OK
	              && packed == 2u && fzn_log_pack_verify(za, zero, &HASH, ha) == FZN_LOG_PACK_OK
	              && fzn_log_pack_verify(zb, ha, &HASH, hb) == FZN_LOG_PACK_OK,
	      "fixture: a segment forty days old and one a day old, packed and chained");
	for (k = 0; k < 32u; k++)
		snprintf(want + (k * 2u), 3u, "%02x", ha[k]);

	{
		const char *const r[] = { "prune netcfgd level=DT age 2d" };

		CHECK(retain(r, 1u, now, &removed, &repacked) && removed == 0u && repacked == 1u,
		      "debug older than two days: the old segment is repacked, nothing removed");
	}
	CHECK(strstr(packed_text(za), "old info") && strstr((char *)back, "old error")
	              && !strstr((char *)back, "old debug")
	              && strstr((char *)back, "#fuzznet-log-trailer 2 prev=")
	              && strstr((char *)back, "dropped=1\n") && strstr((char *)back, want)
	              && strstr((char *)back, "#fuzznet-log 1 machine="),
	      "the old debug line is gone, the rest and the header stay, under a version-2 "
	      "trailer naming the old hash and one line dropped");
	CHECK(fzn_log_pack_verify(za, zero, &HASH, carry) == FZN_LOG_PACK_OK
	              && memcmp(carry, ha, 32u) == 0
	              && fzn_log_pack_verify(zb, ha, &HASH, hb) == FZN_LOG_PACK_OK
	              && strstr(packed_text(zb), "new debug"),
	      "it verifies and carries its first hash, so the next still chains; the new debug "
	      "line, a day old, stays");

	{
		const char *const r[] = { "prune netcfgd age 30d", "keep netcfgd level=E age 90d" };

		CHECK(retain(r, 2u, now, &removed, &repacked) && removed == 0u && repacked == 1u
		              && !strstr(packed_text(za), "old info") && strstr((char *)back, "old error")
		              && strstr((char *)back, "dropped=2\n") && strstr((char *)back, want),
		      "a segment rule prunes the old segment and an entry rule keeps its error line, "
		      "so it is repacked again, two dropped in all, the first hash still named");
	}
	CHECK(fzn_log_pack_verify(za, zero, &HASH, carry) == FZN_LOG_PACK_OK
	              && memcmp(carry, ha, 32u) == 0,
	      "and still carries the hash it was first packed with");

	{
		const char *const r[] = { "prune netcfgd subsystem=notes count 0" };

		CHECK(retain(r, 1u, now, &removed, &repacked) && repacked == 1u
		              && !strstr(packed_text(zb), "new info") && strstr((char *)back, "new debug")
		              && fzn_log_pack_verify(zb, ha, &HASH, carry) == FZN_LOG_PACK_OK
		              && memcmp(carry, hb, 32u) == 0,
		      "a count over a subsystem drops the newer segment's notes line, which still "
		      "chains from the older");
	}

	/* A PACKED SEGMENT THAT DOES NOT VERIFY is kept whole, unread. */
	{
		const struct line_spec probe[] = {
			{ FZN_ENTRY_DEBUG, "probe", "a probe", now - DAY },
		};
		static uint8_t plain[1000], z[2000];
		char bad[160], line[200], hex[65];
		size_t zn, len = 0;
		struct stat before, after;
		FILE *f;

		snprintf(bad, sizeof(bad), "%s/netcfgd.%llu.23.log.zst", top,
		         (unsigned long long)(now - 50u * DAY));
		CHECK(write_classic(c, probe, 1u, 9u), "fixture: a debug line of its own subsystem");
		f = fopen(c, "rb");
		len = f ? fread(plain, 1u, 500u, f) : 0u;
		if (f)
			(void)fclose(f);
		memset(hex, '0', 64u);
		hex[64] = '\0';
		snprintf(line, sizeof(line), "#fuzznet-log-trailer 1 prev=%s hash=%s\n", hex, hex);
		memcpy(plain + len, line, strlen(line));
		zn = ZSTD_compress(z, sizeof(z), plain, len + strlen(line), 3);
		f = fopen(bad, "wb");
		CHECK(!ZSTD_isError(zn) && f && fwrite(z, 1u, zn, f) == zn && fclose(f) == 0
		              && stat(bad, &before) == 0,
		      "fixture: a packed segment whose trailer's hash is wrong");
		{
			const char *const r[] = { "prune netcfgd subsystem=probe age 0" };

			CHECK(retain(r, 1u, now, &removed, &repacked) && stat(bad, &after) == 0
			              && after.st_size == before.st_size && !exists(c),
			      "it is neither repacked nor removed; and the unpacked segment, its only "
			      "entry dropped, is removed");
		}
		(void)remove(bad);
	}
	CHECK(!exists(c), "the unpacked segment whose every entry went is gone");

	/* PART OF AN UNPACKED SEGMENT waits for its packing. */
	{
		const struct line_spec two[] = {
			{ FZN_ENTRY_DEBUG, "apply", "a debug", now - (5u * DAY) },
			{ FZN_ENTRY_INFO, "apply", "an info", now - (5u * DAY) },
		};
		/* Three days: the five-day-old debug line, not the newer segment's. */
		const char *const r[] = { "prune netcfgd level=D age 3d" };
		struct stat before, after;

		CHECK(write_classic(c, two, 2u, 10u) && stat(c, &before) == 0
		              && retain(r, 1u, now, &removed, &repacked) && stat(c, &after) == 0
		              && after.st_size == before.st_size,
		      "an unpacked segment some of whose lines go is left whole until it is packed");
	}

	/* EVERY ENTRY GONE: the segment is removed, and the newer still verifies. */
	{
		const char *const r[] = { "prune netcfgd level=E age 2d" };

		CHECK(retain(r, 1u, now, &removed, &repacked) && removed == 1u && !exists(za)
		              && fzn_log_pack_verify(zb, ha, &HASH, carry) == FZN_LOG_PACK_OK,
		      "the old segment, its last entry pruned, is removed; the newer verifies from "
		      "the prev it names");
	}
	/* NO ENTRY RULE: segments go whole, unread. */
	{
		const char *const r[] = { "prune netcfgd count 0" };

		CHECK(retain(r, 1u, now, &removed, &repacked) && removed == 2u && repacked == 0u
		              && !exists(zb) && !exists(c),
		      "with no entry rule, a segment rule removes whole segments");
	}
	CHECK(fzn_log_pack_retain(top, "a/b", NULL, 0u, &HASH, now, &removed, &repacked)
	              == FZN_LOG_PACK_ERR_MALFORMED,
	      "a program with a slash is refused");
	(void)remove(za);
	(void)remove(zb);
	(void)remove(c);
	(void)remove(a);
	(void)remove(b);
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
	test_entry_rules();
	CHECK(rmdir(top) == 0, "the scratch directory is empty, and goes");

	if (failures) {
		fprintf(stderr, "pack_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("pack_test: all %d checks passed\n", checks);
	return 0;
}
