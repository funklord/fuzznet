/* log_buckets_test -- a host's packed log segments as bucket items, sec
 * 571: scanned in, served and pulled through the exchange, pushed, kept as
 * copies only signed by their host, and fetched only where the rules would
 * hold them.
 *
 * TWO HOSTS IN ONE PROCESS, A and B, each a log directory and an in-memory
 * store, the exchange asked directly. THE HASH AND THE SIGNER ARE TOYS, as
 * in copy_test: what is under test is the carriage and the checking.
 *
 * HOW IT TERMINATES: no forks, fixed loops. Its scratch directory is its
 * own, made by mkdtemp, and every file in it is removed by name -- the
 * entries of directories this process made -- then each directory.
 */

#define _POSIX_C_SOURCE 200809L

#include "../log_buckets.h"
#include "../../log/copy.h"
#include "../../log/pack.h"
#include "../../messages/line.h"

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
			fprintf(stderr, "  FAIL log_buckets_test.c:%d: %s\n", __LINE__, what); \
		}                                                                              \
	} while (0)

/* ---- toys, as copy_test's ------------------------------------------------- */

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

static uint8_t key_a[32], key_b[32], key_x[32];
static fzn_sign_ops_t SIGN_A = { toy_verify, toy_sign, key_a };
static fzn_sign_ops_t SIGN_X = { toy_verify, toy_sign, key_x };

/* ---- a store per host --------------------------------------------------- */

#define ROWS 512

struct row {
	int used;
	fzn_persist_slot_t slot;
	uint8_t subject[FZN_PUBKEY_LEN];
	uint8_t bytes[FZN_BUCKETS_ITEM_MAX + 64u];
	size_t len;
};

struct mem {
	struct row rows[ROWS];
};

static struct row *row_of(struct mem *m, fzn_persist_slot_t slot, const uint8_t *subject, int make)
{
	int i, free_one = -1;

	for (i = 0; i < ROWS; i++) {
		if (!m->rows[i].used) {
			if (free_one < 0)
				free_one = i;
			continue;
		}
		if (m->rows[i].slot == slot && memcmp(m->rows[i].subject, subject, FZN_PUBKEY_LEN) == 0)
			return &m->rows[i];
	}
	if (!make || free_one < 0)
		return NULL;
	m->rows[free_one].used = 1;
	m->rows[free_one].slot = slot;
	memcpy(m->rows[free_one].subject, subject, FZN_PUBKEY_LEN);
	return &m->rows[free_one];
}

static int mem_load(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject, uint8_t *out,
                    size_t cap, size_t *len)
{
	struct row *r = row_of((struct mem *)ctx, slot, subject, 0);

	if (!r || r->len > cap)
		return 0;
	memcpy(out, r->bytes, r->len);
	*len = r->len;
	return 1;
}

static int mem_save(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject,
                    const uint8_t *bytes, size_t len)
{
	struct row *r = row_of((struct mem *)ctx, slot, subject, 1);

	if (!r || len > sizeof(r->bytes))
		return 0;
	memcpy(r->bytes, bytes, len);
	r->len = len;
	return 1;
}

static int mem_list(void *ctx, fzn_persist_slot_t slot, uint8_t *out, size_t max, size_t *count)
{
	struct mem *m = (struct mem *)ctx;
	size_t n = 0;
	int i;

	for (i = 0; i < ROWS; i++)
		if (m->rows[i].used && m->rows[i].slot == slot) {
			if (n >= max)
				return 0;
			memcpy(out + n * FZN_PUBKEY_LEN, m->rows[i].subject, FZN_PUBKEY_LEN);
			n++;
		}
	*count = n;
	return 1;
}

static int mem_remove(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject)
{
	struct row *r = row_of((struct mem *)ctx, slot, subject, 0);

	if (r)
		memset(r, 0, sizeof(*r));
	return 1;
}

static struct mem mem_a, mem_b;
static fzn_persist_ops_t store_a = { mem_load, mem_save, mem_list, mem_remove, &mem_a };
static fzn_persist_ops_t store_b = { mem_load, mem_save, mem_list, mem_remove, &mem_b };
static const fzn_buckets_t A = { &store_a, &HASH };
static const fzn_buckets_t B = { &store_b, &HASH };
static fzn_log_buckets_t lb_a, lb_b;
static fzn_reconcile_filer_t filer_a, filer_b;

/* ---- scratch ------------------------------------------------------------- */

static char top[64], dir_a[128], dir_b[128];

/* A packed segment of `n` bytes of lines in `dir`, closed at `t` (us),
 * chained from `prev` and signed by `signer` (NULL: unsigned). */
static uint32_t seed = 7u;

static int make_packed(const char *dir, uint64_t t, size_t n, uint8_t prev[32],
                       const fzn_sign_ops_t *sign, const uint8_t *key)
{
	char log[300], zst[310];
	fzn_log_pack_signer_t signer;
	uint8_t next[32];
	size_t i;
	FILE *f;

	snprintf(log, sizeof(log), "%s/netcfgd.%llu.42.log", dir, (unsigned long long)t);
	snprintf(zst, sizeof(zst), "%s.zst", log);
	f = fopen(log, "w");
	if (!f)
		return 0;
	for (i = 0; i < n; i++) {
		seed = (seed * 1103515245u) + 12345u;
		(void)fputc((i + 1u) % 61u == 0u || i + 1u == n ? '\n' : 'a' + (int)((seed >> 16) % 26u),
		            f);
	}
	if (fclose(f) != 0)
		return 0;
	if (sign) {
		memcpy(signer.key, key, 32u);
		signer.sign = sign;
	}
	if (fzn_log_pack_segment(log, zst, prev, &HASH, sign ? &signer : NULL, next)
	    != FZN_LOG_PACK_OK)
		return 0;
	memcpy(prev, next, 32u);
	return remove(log) == 0;
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

/* Every entry of `dir`, which this process made, then `dir`. */
static void wipe(const char *dir)
{
	DIR *d = opendir(dir);
	struct dirent *e;
	char path[400];

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

static void copy_dir_of(const char *dir, const uint8_t host[32], char *out, size_t cap)
{
	(void)fzn_log_copy_dir(dir, host, out, cap);
}

/* Each host afresh: its store empty, its directory emptied and made, its
 * kind pointed at both. */
static void fresh(void)
{
	char copies[300];

	copy_dir_of(dir_b, key_a, copies, sizeof(copies));
	wipe(copies);
	copy_dir_of(dir_a, key_b, copies, sizeof(copies));
	wipe(copies);
	snprintf(copies, sizeof(copies), "%s/copy", dir_a);
	(void)rmdir(copies);
	snprintf(copies, sizeof(copies), "%s/copy", dir_b);
	(void)rmdir(copies);
	wipe(dir_a);
	wipe(dir_b);
	(void)mkdir(dir_a, 0700);
	(void)mkdir(dir_b, 0700);
	memset(&mem_a, 0, sizeof(mem_a));
	memset(&mem_b, 0, sizeof(mem_b));
	fzn_log_buckets_close(&lb_a);
	fzn_log_buckets_close(&lb_b);
	(void)fzn_log_buckets_init(&lb_a, &A, dir_a, &HASH, &SIGN_A, key_a);
	(void)fzn_log_buckets_init(&lb_b, &B, dir_b, &HASH, &SIGN_A, key_b);
	lb_a.now_us = lb_b.now_us = 1790000000ull * 1000000ull;
	fzn_log_buckets_filer(&lb_a, &filer_a);
	fzn_log_buckets_filer(&lb_b, &filer_b);
}

/* ---- the exchange, asked directly ---------------------------------------- */

static uint8_t answer_buf[8192];
static size_t reply_cap = FZN_RECONCILE_REPLY_MIN;
/* 1: change the first byte of a segment's name in every first piece A
 * serves -- a byte no signature covers. */
static int rename_in_flight;

/* A ANSWERING B. */
static int to_a(void *ctx, const uint8_t *request, size_t request_len, uint8_t *reply,
                size_t cap, size_t *reply_len)
{
	fzn_reconcile_server_t srv;
	size_t n;

	(void)ctx;
	memset(&srv, 0, sizeof(srv));
	srv.store = &store_a;
	srv.hash = &HASH;
	srv.takers[FZN_BUCKETS_LOGS] = &filer_a;
	srv.sender = key_b;
	n = fzn_reconcile_serve(&srv, request, request_len, answer_buf,
	                        cap < reply_cap ? cap : reply_cap);
	if (!n)
		return 0;
	if (rename_in_flight && answer_buf[1] == FZN_RECONCILE_ITEM
	    && n > FZN_RECONCILE_ITEM_HEAD_LEN + 1u && answer_buf[39] == 0u && answer_buf[40] == 0u
	    && answer_buf[41] == 0u && answer_buf[42] == 0u)
		answer_buf[FZN_RECONCILE_ITEM_HEAD_LEN + 1u] ^= 0x20u;
	memcpy(reply, answer_buf, n);
	*reply_len = n;
	return 1;
}

/* B ANSWERING A, taking what A pushes. */
static int to_b(void *ctx, const uint8_t *request, size_t request_len, uint8_t *reply,
                size_t cap, size_t *reply_len)
{
	fzn_reconcile_server_t srv;
	size_t n;

	(void)ctx;
	memset(&srv, 0, sizeof(srv));
	srv.store = &store_b;
	srv.hash = &HASH;
	srv.takers[FZN_BUCKETS_LOGS] = &filer_b;
	srv.sender = key_a;
	n = fzn_reconcile_serve(&srv, request, request_len, reply, cap);
	if (!n)
		return 0;
	*reply_len = n;
	return 1;
}

static fzn_reconcile_err_t pull_b(fzn_reconcile_bucket_tally_t *t)
{
	static uint8_t reply[8192];

	return fzn_reconcile_buckets(&B, FZN_BUCKETS_LOGS, &filer_b, to_a, NULL, reply,
	                             sizeof(reply), t);
}

static int same_logs(void)
{
	static fzn_bucket_t a[16], b[16];
	size_t na = 0, nb = 0, i;

	if (fzn_buckets_list(&A, FZN_BUCKETS_LOGS, a, 16u, &na) != FZN_BUCKETS_OK
	    || fzn_buckets_list(&B, FZN_BUCKETS_LOGS, b, 16u, &nb) != FZN_BUCKETS_OK || na != nb
	    || na == 0u)
		return 0;
	for (i = 0; i < na; i++)
		if (a[i].count != b[i].count || memcmp(a[i].digest, b[i].digest, FZN_BUCKETS_ID_LEN) != 0)
			return 0;
	return 1;
}

/* July, August and September 2026, in us, the tenth of each. */
#define JULY_2026 (1783641600ull * 1000000ull)
#define AUGUST_2026 (1786320000ull * 1000000ull)
#define SEPTEMBER_2026 (1788998400ull * 1000000ull)

/* A's log: a large segment and a small one in July, a large one in
 * September, chained and signed by A. */
static int a_logs(void)
{
	uint8_t prev[32];

	memset(prev, 0, sizeof(prev));
	return make_packed(dir_a, JULY_2026, 20000u, prev, &SIGN_A, key_a)
	       && make_packed(dir_a, JULY_2026 + 1000u, 300u, prev, &SIGN_A, key_a)
	       && make_packed(dir_a, SEPTEMBER_2026, 20000u, prev, &SIGN_A, key_a);
}

static void test_a_scan_takes_its_own(void)
{
	size_t taken = 9;
	fzn_bucket_t k[4];
	size_t n = 0;

	fresh();
	CHECK(a_logs(), "fixture: A's three packed segments");
	CHECK(fzn_log_buckets_scan(&lb_a, &taken, NULL) && taken == 3u,
	      "a scan did not take A's three segments");
	{
		char path[300];
		struct stat st;

		/* THE LARGE PATH IS TAKEN: a 20,000-byte segment packs past a row. */
		snprintf(path, sizeof(path), "%s/netcfgd.%llu.42.log.zst", dir_a,
		         (unsigned long long)JULY_2026);
		CHECK(stat(path, &st) == 0 && (uint64_t)st.st_size > FZN_BUCKETS_ITEM_MAX,
		      "fixture: the large segment packed into no more than a row");
	}
	CHECK(fzn_buckets_list(&A, FZN_BUCKETS_LOGS, k, 4u, &n) == FZN_BUCKETS_OK && n == 2u
	              && memcmp(k[0].subject, key_a, 32u) == 0
	              && k[0].month == fzn_message_epoch_of(JULY_2026 / 1000u) && k[0].count == 2u
	              && k[1].month == fzn_message_epoch_of(SEPTEMBER_2026 / 1000u),
	      "A's segments are not A's, by the month each closed in");
	CHECK(fzn_log_buckets_scan(&lb_a, &taken, NULL) && taken == 0u,
	      "a second scan took a segment again");
}

static void test_pulled_and_kept_as_copies(void)
{
	char copies[300];
	fzn_log_pack_report_t report;
	fzn_reconcile_bucket_tally_t t;
	fzn_reconcile_err_t err;
	size_t taken;

	fresh();
	CHECK(a_logs() && fzn_log_buckets_scan(&lb_a, &taken, NULL), "fixture: A's log, scanned");
	err = pull_b(&t);
	if (err != FZN_RECONCILE_OK || t.applied != 3u)
		fprintf(stderr, "    %s: %zu lacked, %zu applied, %zu refused, %zu passed\n",
		        fzn_reconcile_err_str(err), t.lacked, t.applied, t.refused, t.passed);
	CHECK(err == FZN_RECONCILE_OK && t.applied == 3u && t.refused == 0u && same_logs(),
	      "B did not pull A's three segments, over the smallest reply");
	copy_dir_of(dir_b, key_a, copies, sizeof(copies));
	CHECK(count_in(copies, ".log.zst") == 3u
	              && fzn_log_pack_check(copies, "netcfgd", &HASH, &SIGN_A, &report)
	                         == FZN_LOG_PACK_OK
	              && report.segments == 3u && report.signed_count == 3u
	              && memcmp(report.signer, key_a, 32u) == 0,
	      "B's copies are not A's three segments, chained and signed by A");
	CHECK(count_in(copies, ".new") == 0u, "a staged file was left beside the copies");
	CHECK(pull_b(&t) == FZN_RECONCILE_OK && t.lacked == 0u, "a second pull found something");
}

/* KEPT ONLY SIGNED BY ITS SUBJECT: a segment of A's signed by X, or not
 * signed at all, is refused. */
static void test_signed_by_its_subject_only(void)
{
	char copies[300];
	fzn_reconcile_bucket_tally_t t;
	uint8_t prev[32];
	size_t taken;

	fresh();
	memset(prev, 0, sizeof(prev));
	CHECK(make_packed(dir_a, JULY_2026, 20000u, prev, &SIGN_X, key_x)
	              && make_packed(dir_a, JULY_2026 + 1000u, 300u, prev, NULL, NULL)
	              && fzn_log_buckets_scan(&lb_a, &taken, NULL) && taken == 2u,
	      "fixture: one of A's segments signed by X, one unsigned");
	copy_dir_of(dir_b, key_a, copies, sizeof(copies));
	CHECK(pull_b(&t) == FZN_RECONCILE_OK && t.refused == 2u && t.applied == 0u
	              && count_in(copies, ".log.zst") == 0u && count_in(copies, ".new") == 0u,
	      "a segment not signed by its host was kept, or left half written");
}

/* FETCHED ONLY WHERE THE RULES WOULD HOLD IT. */
static void test_wanted_by_the_rules(void)
{
	fzn_retain_rule_t rules[2];
	fzn_reconcile_bucket_tally_t t;
	size_t taken;

	fresh();
	CHECK(a_logs() && fzn_log_buckets_scan(&lb_a, &taken, NULL), "fixture: A's log, scanned");
	if (fzn_retain_parse("policy log drop", 15u, &rules[0]) != FZN_RETAIN_OK
	    || fzn_retain_parse("keep * copy age 40d", 19u, &rules[1]) != FZN_RETAIN_OK)
		CHECK(0, "fixture: the rules");
	lb_b.copy_rules = rules;
	lb_b.n_copy = 1u;
	CHECK(pull_b(&t) == FZN_RECONCILE_OK && t.passed == 2u && t.applied == 0u,
	      "under a drop policy alone a month was fetched");
	/* 1790000000 is 2026-09-21: September has not ended, and July ended
	 * 51 days before. */
	lb_b.n_copy = 2u;
	CHECK(pull_b(&t) == FZN_RECONCILE_OK && t.passed == 1u && t.applied == 1u,
	      "under drop with a 40-day keep, not September alone fetched");
	lb_b.copy_rules = NULL;
	lb_b.n_copy = 0u;
}

static void test_pushed(void)
{
	static uint8_t reply[FZN_RECONCILE_REPLY_MIN];
	char copies[300];
	fzn_reconcile_bucket_tally_t t;
	size_t taken;

	fresh();
	CHECK(a_logs() && fzn_log_buckets_scan(&lb_a, &taken, NULL), "fixture: A's log, scanned");
	CHECK(fzn_reconcile_push(&A, FZN_BUCKETS_LOGS, NULL, &filer_a, NULL, to_b, NULL, reply,
	                         sizeof(reply), &t)
	                      == FZN_RECONCILE_OK
	              && t.sent == 3u && t.refused == 0u && same_logs(),
	      "A did not push its three segments to B");
	copy_dir_of(dir_b, key_a, copies, sizeof(copies));
	CHECK(count_in(copies, ".log.zst") == 3u, "B does not hold A's three segments as copies");
}

/* A SEGMENT IS ITS ID'S, AND ITS MONTH'S: a name changed in flight -- which
 * no signature covers -- is refused by its id, and one offered under
 * another month than it closed in is refused by its name. */
static void test_its_id_and_its_month(void)
{
	static uint8_t item[512];
	char copies[300];
	fzn_reconcile_bucket_tally_t t;
	uint8_t subject[32], ref[FZN_BUCKETS_REF_MAX], ids[4][FZN_BUCKETS_ID_LEN];
	fzn_bucket_t k[2];
	size_t taken, n = 0, ref_len = 0, got = 0;
	uint64_t size = 0, total = 0;

	fresh();
	CHECK(a_logs() && fzn_log_buckets_scan(&lb_a, &taken, NULL), "fixture: A's log, scanned");
	rename_in_flight = 1;
	copy_dir_of(dir_b, key_a, copies, sizeof(copies));
	CHECK(pull_b(&t) == FZN_RECONCILE_OK && t.refused == 3u && t.applied == 0u
	              && count_in(copies, ".log.zst") == 0u,
	      "a segment whose name changed in flight was kept");
	rename_in_flight = 0;
	/* THE SMALL SEGMENT, offered under August though it closed in July. */
	memcpy(subject, key_a, 32u);
	CHECK(fzn_buckets_list(&A, FZN_BUCKETS_LOGS, k, 2u, &n) == FZN_BUCKETS_OK && n == 2u
	              && fzn_buckets_ids(&A, FZN_BUCKETS_LOGS, subject, k[0].month, 0u, ids, 4u, &got,
	                                 &total)
	                         == FZN_BUCKETS_OK
	              && got == 2u,
	      "fixture: July's two ids at A");
	{
		size_t i, small = 9u;

		for (i = 0; i < got; i++)
			if (fzn_buckets_ref(&A, FZN_BUCKETS_LOGS, ids[i], ref, &ref_len, &size)
			            == FZN_BUCKETS_OK
			    && size <= sizeof(item))
				small = i;
		CHECK(small < got && filer_a.read(filer_a.ctx, ref, ref_len, 0u, item, (size_t)size)
		              && filer_b.file(filer_b.ctx, subject, k[0].month + 1u, item, (size_t)size)
		                         == FZN_NODE_APPLY_REFUSED
		              && filer_b.file(filer_b.ctx, subject, k[0].month, item, (size_t)size)
		                         == FZN_NODE_APPLY_APPLIED,
		      "a segment offered under another month than it closed in was kept, or one "
		      "under its own was not");
	}
}

/* LET GO BY THE SCAN, sec 572: a segment of A's own removed from disk, a
 * segment repacked under its name, and a copy B's rules removed. Each
 * id stays counted; what is gone is served as not held and never taken
 * back. */
static void test_removed_and_repacked(void)
{
	char path[400], repacked[300], copies[300], spare[160];
	fzn_reconcile_bucket_tally_t t;
	fzn_bucket_t k[4];
	uint8_t prev[32];
	size_t taken = 0, let_go = 0, n = 0;

	fresh();
	CHECK(a_logs() && fzn_log_buckets_scan(&lb_a, &taken, NULL) && taken == 3u,
	      "fixture: A's log, scanned");
	/* THE SMALL JULY SEGMENT GONE, by A's own rules. */
	snprintf(path, sizeof(path), "%s/netcfgd.%llu.42.log.zst", dir_a,
	         (unsigned long long)(JULY_2026 + 1000u));
	CHECK(remove(path) == 0 && fzn_log_buckets_scan(&lb_a, &taken, &let_go) && taken == 0u
	              && let_go == 1u,
	      "a segment removed from disk was not let go");
	CHECK(fzn_buckets_list(&A, FZN_BUCKETS_LOGS, k, 4u, &n) == FZN_BUCKETS_OK && n == 2u
	              && k[0].count == 2u,
	      "the segment let go left July's count");
	/* SEPTEMBER'S REPACKED: another segment of another length under its
	 * name, made aside and moved over it. */
	snprintf(spare, sizeof(spare), "%s/spare", top);
	(void)mkdir(spare, 0700);
	memset(prev, 0, sizeof(prev));
	snprintf(path, sizeof(path), "%s/netcfgd.%llu.42.log.zst", dir_a,
	         (unsigned long long)SEPTEMBER_2026);
	snprintf(repacked, sizeof(repacked), "%s/netcfgd.%llu.42.log.zst", spare,
	         (unsigned long long)SEPTEMBER_2026);
	CHECK(make_packed(spare, SEPTEMBER_2026, 9000u, prev, &SIGN_A, key_a)
	              && rename(repacked, path) == 0,
	      "fixture: September's segment repacked under its name");
	(void)rmdir(spare);
	CHECK(fzn_log_buckets_scan(&lb_a, &taken, &let_go) && taken == 1u && let_go == 1u,
	      "a repacked segment's old id was not let go, or its new not taken");
	CHECK(fzn_buckets_list(&A, FZN_BUCKETS_LOGS, k, 4u, &n) == FZN_BUCKETS_OK && n == 2u
	              && k[1].count == 2u,
	      "September does not count its old id and its new");
	/* B TAKES WHAT A HOLDS, and nothing let go. */
	copy_dir_of(dir_b, key_a, copies, sizeof(copies));
	CHECK(pull_b(&t) == FZN_RECONCILE_OK && t.lacked == 4u && t.applied == 2u
	              && t.refused == 0u && count_in(copies, ".log.zst") == 2u,
	      "B did not take A's two segments held, or took one let go");
	/* A FILE AWAY AND BACK -- a log directory moved and moved back -- is
	 * let go while it is away and restored when it returns. */
	snprintf(path, sizeof(path), "%s/netcfgd.%llu.42.log.zst", dir_a,
	         (unsigned long long)JULY_2026);
	snprintf(repacked, sizeof(repacked), "%s/away", top);
	CHECK(rename(path, repacked) == 0 && fzn_log_buckets_scan(&lb_a, &taken, &let_go)
	              && let_go == 1u && rename(repacked, path) == 0
	              && fzn_log_buckets_scan(&lb_a, &taken, &let_go) && taken == 1u && let_go == 0u,
	      "a segment away and back was not let go, or not restored");
	{
		char ref[300];
		uint8_t id[FZN_BUCKETS_ID_LEN], named[FZN_BUCKETS_REF_MAX];
		size_t named_len = 0;
		uint64_t held = 0, size = 0;

		snprintf(ref, sizeof(ref), "o/netcfgd.%llu.42.log.zst", (unsigned long long)JULY_2026);
		CHECK(fzn_buckets_by_ref(&A, FZN_BUCKETS_LOGS, (const uint8_t *)ref, strlen(ref), id,
		                         &held)
		                      == FZN_BUCKETS_OK
		              && fzn_buckets_ref(&A, FZN_BUCKETS_LOGS, id, named, &named_len, &size)
		                         == FZN_BUCKETS_OK
		              && named_len == strlen(ref) && memcmp(named, ref, named_len) == 0,
		      "the segment back does not name its file again");
	}
	/* A COPY B'S RULES REMOVED is let go at B, and not taken again. */
	snprintf(path, sizeof(path), "%s/netcfgd.%llu.42.log.zst", copies,
	         (unsigned long long)JULY_2026);
	CHECK(remove(path) == 0 && fzn_log_buckets_scan(&lb_b, NULL, &let_go) && let_go == 1u,
	      "a copy removed at B was not let go");
	CHECK(pull_b(&t) == FZN_RECONCILE_OK && t.applied == 0u
	              && count_in(copies, ".log.zst") == 1u,
	      "a copy B let go was taken back");
}

/* A PACKED SEGMENT'S NAME, read for its closing time: the one name a copy
 * has, and the one this module keeps, serves or takes. */
static void test_a_segment_s_name(void)
{
	CHECK(fzn_log_copy_packed_time("netcfgd.1783641600000000.42.log.zst") == 1783641600000000ull,
	      "a segment's name did not read as its closing time");
	/* A SUFFIX OF THE RIGHT LENGTH AND THE WRONG BYTES: the one name only the
	 * suffix's own check refuses, the pid's place passing it. */
	CHECK(fzn_log_copy_packed_time("netcfgd.17.42.log.zzz") == 0u,
	      "a name ending in another eight bytes read as a packed segment's");
	CHECK(fzn_log_copy_packed_time("netcfgd.17.42.log") == 0u
	              && fzn_log_copy_packed_time("a/b.17.42.log.zst") == 0u
	              && fzn_log_copy_packed_time("netcfgd.1x.42.log.zst") == 0u
	              && fzn_log_copy_packed_time("netcfgd.17.4z.log.zst") == 0u
	              && fzn_log_copy_packed_time("netcfgd..42.log.zst") == 0u
	              && fzn_log_copy_packed_time(".17.42.log.zst") == 0u
	              && fzn_log_copy_packed_time(NULL) == 0u,
	      "a name that is no packed segment's read as one");
}

int main(void)
{
	snprintf(top, sizeof(top), "/tmp/fzn-log-buckets-test-XXXXXX");
	if (!mkdtemp(top)) {
		fprintf(stderr, "  FAIL log_buckets_test.c: no scratch directory\n");
		return 1;
	}
	snprintf(dir_a, sizeof(dir_a), "%s/a", top);
	snprintf(dir_b, sizeof(dir_b), "%s/b", top);
	memset(key_a, 0xa1, sizeof(key_a));
	memset(key_b, 0xb2, sizeof(key_b));
	memset(key_x, 0x5c, sizeof(key_x));

	test_a_segment_s_name();
	test_a_scan_takes_its_own();
	test_pulled_and_kept_as_copies();
	test_signed_by_its_subject_only();
	test_wanted_by_the_rules();
	test_pushed();
	test_its_id_and_its_month();
	test_removed_and_repacked();

	fresh();
	fzn_log_buckets_close(&lb_a);
	fzn_log_buckets_close(&lb_b);
	wipe(dir_a);
	wipe(dir_b);
	CHECK(rmdir(top) == 0, "the scratch directory would not go: something in it was not named");
	printf("log_buckets_test: %d checks, %d failure(s)\n", checks, failures);
	return failures ? 1 : 0;
}
