/* copy_test -- copies of another host's packed log: listed, fetched in
 * parts, verified against the chain and the source's signature, and kept
 * only then. sec 483.
 *
 * THE HASH AND THE SIGNER ARE TOYS, as in pack_test: what is under test is
 * the carriage and the checking. The "host" is `fzn_log_copy_answer` over a
 * source directory, asked directly, with a small reply so a segment takes
 * many parts.
 *
 * In a scratch directory of its own that it leaves empty. */

#define _POSIX_C_SOURCE 200809L

#include "../copy.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int checks, failures;

#define CHECK(cond, what)                                                                      \
	do {                                                                                   \
		checks++;                                                                      \
		if (!(cond)) {                                                                 \
			failures++;                                                            \
			fprintf(stderr, "  FAIL copy_test.c:%d: %s\n", __LINE__, what);        \
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
	return 1;
}

static const fzn_hash_ops_t HASH = { toy, NULL };

static int toy_sig(const uint8_t *key, const uint8_t *msg, size_t n, uint8_t sig[FZN_SIG_LEN])
{
	static uint8_t buf[32u + 1024u];

	if (n > 1024u)
		return 0;
	memcpy(buf, key, 32u);
	memcpy(buf + 32, msg, n);
	return toy(NULL, sig, FZN_SIG_LEN, buf, 32u + n);
}

static int toy_sign(void *ctx, uint8_t sig[FZN_SIG_LEN], const uint8_t *msg, size_t n)
{
	return toy_sig((const uint8_t *)ctx, msg, n, sig);
}

static int toy_verify(void *ctx, const uint8_t pub[FZN_PUBKEY_LEN], const uint8_t *msg, size_t n,
                      const uint8_t sig[FZN_SIG_LEN])
{
	uint8_t want[FZN_SIG_LEN];

	(void)ctx;
	return toy_sig(pub, msg, n, want) && memcmp(want, sig, FZN_SIG_LEN) == 0;
}

static uint8_t host_key[32];
static fzn_sign_ops_t SIGN = { toy_verify, toy_sign, host_key };

static char top[64], src[128], dst[160];

/* THE HOST, asked directly: its answer from `src`, in replies of `cap`, a
 * byte of every part flipped when `flip` is set. */
struct host {
	size_t cap;
	int flip;
	size_t asked;
};

static int ask(void *ctx, const uint8_t *request, size_t request_len, uint8_t *reply,
               size_t reply_cap, size_t *reply_len)
{
	struct host *h = ctx;
	size_t cap = h->cap < reply_cap ? h->cap : reply_cap;

	h->asked++;
	*reply_len = fzn_log_copy_answer(src, request, request_len, reply, cap);
	if (*reply_len && h->flip && reply[1] == FZN_LOG_COPY_PART && *reply_len > 30u)
		reply[*reply_len - 3u] ^= 1u;
	return *reply_len > 0u;
}

/* A closed segment of `n` bytes of whole lines, at closing time `t`. */
static uint32_t seed = 1u;

static int make_segment(uint64_t t, size_t n)
{
	char path[200];
	FILE *f;
	size_t i;

	snprintf(path, sizeof(path), "%s/netcfgd.%llu.7.log", src, (unsigned long long)t);
	f = fopen(path, "w");
	if (!f)
		return 0;
	/* LETTERS THAT DO NOT REPEAT, so zstd leaves the segment large and a
	 * copy takes many parts. */
	for (i = 0; i < n; i++) {
		seed = (seed * 1103515245u) + 12345u;
		(void)fputc((i + 1u) % 61u == 0u || i + 1u == n ? '\n' : 'a' + (int)((seed >> 16) % 26u),
		            f);
	}
	return fclose(f) == 0;
}

static size_t count_in(const char *dir, const char *suffix)
{
	DIR *d = opendir(dir);
	struct dirent *e;
	size_t n = 0, sl = strlen(suffix);

	if (!d)
		return 0;
	while ((e = readdir(d)) != NULL) {
		size_t l = strlen(e->d_name);

		if (l > sl && strcmp(e->d_name + l - sl, suffix) == 0)
			n++;
	}
	(void)closedir(d);
	return n;
}

/* Every file in `dir`, then `dir`. */
static void wipe(const char *dir)
{
	DIR *d = opendir(dir);
	struct dirent *e;
	char path[300];

	if (!d)
		return;
	while ((e = readdir(d)) != NULL) {
		if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
			continue;
		snprintf(path, sizeof(path), "%s/%s", dir, e->d_name);
		(void)remove(path);
	}
	(void)closedir(d);
	(void)rmdir(dir);
}

int main(void)
{
	static const uint64_t SETTLE = 10u * 1000000u;
	fzn_log_pack_signer_t signer;
	fzn_log_copy_tally_t tally;
	struct host h = { 700u, 0, 0 };
	uint8_t other[32];
	char copies[200];
	size_t packed = 0;

	snprintf(top, sizeof(top), "/tmp/fzn-copy-test-XXXXXX");
	if (!mkdtemp(top)) {
		fprintf(stderr, "  FAIL copy_test.c: no scratch directory\n");
		return 1;
	}
	snprintf(src, sizeof(src), "%s/src", top);
	snprintf(copies, sizeof(copies), "%s/copy", top);
	memset(host_key, 0x5a, sizeof(host_key));
	memset(other, 0x6b, sizeof(other));
	memcpy(signer.key, host_key, 32u);
	signer.sign = &SIGN;
	CHECK(fzn_log_copy_dir(top, host_key, dst, sizeof(dst))
	              && strstr(dst, "/copy/5a5a5a5a") != NULL,
	      "a copy directory is named by its host's key");
	CHECK(mkdir(src, 0700) == 0 && make_segment(1000000u, 5000u) && make_segment(2000000u, 3000u)
	              && fzn_log_pack_dir(src, "netcfgd", &HASH, &signer, 2000000u + SETTLE, SETTLE,
	                                  &packed) == FZN_LOG_PACK_OK
	              && packed == 2u,
	      "fixture: the host's two signed packed segments");

	CHECK(fzn_log_copy_pull(ask, &h, "netcfgd", host_key, dst, &HASH, &SIGN, &tally)
	                      == FZN_LOG_COPY_OK
	              && tally.copied == 2u && count_in(dst, ".log.zst") == 2u
	              && count_in(dst, ".chain") == 1u && h.asked > 4u,
	      "both segments are copied, in many parts, with the chain's head");
	{
		fzn_log_pack_report_t report;

		CHECK(fzn_log_pack_check(dst, "netcfgd", &HASH, &SIGN, &report) == FZN_LOG_PACK_OK
		              && report.segments == 2u && report.signed_count == 2u
		              && memcmp(report.signer, host_key, 32u) == 0,
		      "the copy checks as the host's chain, signed by the host");
	}
	CHECK(fzn_log_copy_pull(ask, &h, "netcfgd", host_key, dst, &HASH, &SIGN, &tally)
	                      == FZN_LOG_COPY_OK
	              && tally.copied == 0u,
	      "a second pull copies nothing it holds");
	CHECK(make_segment(3000000u, 2000u)
	              && fzn_log_pack_dir(src, "netcfgd", &HASH, &signer, 3000000u + SETTLE, SETTLE,
	                                  &packed) == FZN_LOG_PACK_OK
	              && fzn_log_copy_pull(ask, &h, "netcfgd", host_key, dst, &HASH, &SIGN, &tally)
	                         == FZN_LOG_COPY_OK
	              && tally.copied == 1u && count_in(dst, ".log.zst") == 3u,
	      "a segment packed since is copied, chaining from the last kept");

	/* REFUSED: another host's key, a flipped byte, an unsigned segment. */
	wipe(dst);
	CHECK(fzn_log_copy_pull(ask, &h, "netcfgd", other, dst, &HASH, &SIGN, &tally)
	                      == FZN_LOG_COPY_ERR_VERIFY
	              && strstr(tally.refused, "netcfgd.1000000") && count_in(dst, ".log.zst") == 0u
	              && count_in(dst, ".new") == 0u,
	      "segments signed by another key than the host asked are refused, none kept");
	wipe(dst);
	h.flip = 1;
	CHECK(fzn_log_copy_pull(ask, &h, "netcfgd", host_key, dst, &HASH, &SIGN, &tally)
	                      == FZN_LOG_COPY_ERR_VERIFY
	              && count_in(dst, ".log.zst") == 0u && count_in(dst, ".new") == 0u,
	      "a segment changed in transit is refused, and nothing half-kept");
	h.flip = 0;
	wipe(dst);
	CHECK(make_segment(4000000u, 1500u)
	              && fzn_log_pack_dir(src, "netcfgd", &HASH, NULL, 4000000u + SETTLE, SETTLE,
	                                  &packed) == FZN_LOG_PACK_OK
	              && fzn_log_copy_pull(ask, &h, "netcfgd", host_key, dst, &HASH, &SIGN, &tally)
	                         == FZN_LOG_COPY_ERR_VERIFY
	              && tally.copied == 3u && strstr(tally.refused, "netcfgd.4000000")
	              && count_in(dst, ".log.zst") == 3u,
	      "an unsigned segment is refused after the signed ones before it are kept");

	/* THE HOST SERVES ONLY ITS PACKED SEGMENTS, by their own names. */
	{
		static const char *const NAMES[] = { "netcfgd.chain", "../x.1.2.log.zst",
			                             "netcfgd.4000000.7.log", "netcfgd.log" };
		uint8_t q[300], reply[700];
		size_t i, nl;
		int none = 1;

		for (i = 0; i < sizeof(NAMES) / sizeof(NAMES[0]); i++) {
			nl = strlen(NAMES[i]);
			q[0] = FZN_GATHER_VERSION;
			q[1] = FZN_LOG_COPY_PART_QUERY;
			q[2] = (uint8_t)nl;
			memcpy(q + 3, NAMES[i], nl);
			memset(q + 3 + nl, 0, 8u);
			none = none && fzn_log_copy_answer(src, q, 3u + nl + 8u, reply, sizeof(reply)) == 0u;
		}
		CHECK(none, "the chain's head, a path, an unpacked segment and the current file are "
		            "not served");
	}
	CHECK(fzn_log_copy_pull(ask, &h, "a/b", host_key, dst, &HASH, &SIGN, &tally)
	              == FZN_LOG_COPY_ERR_MALFORMED,
	      "a program with a slash is refused");

	wipe(dst);
	(void)rmdir(copies);
	wipe(src);
	CHECK(rmdir(top) == 0, "the scratch directory is empty, and goes");
	if (failures) {
		fprintf(stderr, "copy_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("copy_test: all %d checks passed\n", checks);
	return 0;
}
