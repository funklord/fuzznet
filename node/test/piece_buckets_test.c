/* piece_buckets_test -- erasure-coded pieces as bucket items, sec 597:
 * ranked over the hosts, placed one to a host, pulled and pushed only to
 * the host each was placed on, and kept only in a piece's shape.
 *
 * TWO HOSTS IN ONE PROCESS, A and B, each a pieces directory and an
 * in-memory store, the exchange asked directly. THE HASH IS A TOY, as in
 * log_buckets_test: what is under test is the placing and the carriage.
 *
 * HOW IT TERMINATES: no forks, fixed loops. Its scratch is
 * /tmp/fzn-piece-buckets-test-PID, and every file in it is removed by name
 * -- the entries of the directories this process made -- then each
 * directory.
 */

#define _POSIX_C_SOURCE 200809L

#include "../piece_buckets.h"
#include "../pieces.h"
#include "../../chunk/erasure.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int checks, failures;

#define CHECK(cond, what)                                                                        \
	do {                                                                                     \
		checks++;                                                                        \
		if (!(cond)) {                                                                   \
			failures++;                                                              \
			fprintf(stderr, "  FAIL piece_buckets_test.c:%d: %s\n", __LINE__, what); \
		}                                                                                \
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

/* ---- a store per host --------------------------------------------------- */

#define ROWS 256

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
static fzn_persist_ops_t store_a = { mem_load, mem_save, mem_list, mem_remove, &mem_a, NULL };
static fzn_persist_ops_t store_b = { mem_load, mem_save, mem_list, mem_remove, &mem_b, NULL };
static const fzn_buckets_t A = { &store_a, &HASH };
static const fzn_buckets_t B = { &store_b, &HASH };
static fzn_piece_buckets_t pb_a, pb_b;
static fzn_reconcile_filer_t filer_a, filer_b;
static uint8_t key_a[32], key_b[32];

/* A TOY SIGNER, as log_buckets_test's: a signature is the toy hash of the
 * key and the message, so it verifies under the key it was made with. */
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

static fzn_sign_ops_t SIGN_A = { toy_verify, toy_sign, key_a };
static fzn_sign_ops_t SIGN_B = { toy_verify, toy_sign, key_b };

/* ---- scratch ------------------------------------------------------------- */

static char top[64], dir_a[128], dir_b[128];

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

static size_t pieces_in(const char *dir)
{
	DIR *d = opendir(dir);
	struct dirent *e;
	size_t n = 0;

	if (!d)
		return 0;
	while ((e = readdir(d)) != NULL) {
		size_t l = strlen(e->d_name);

		if (l > 6u && strcmp(e->d_name + l - 6u, ".piece") == 0)
			n++;
	}
	(void)closedir(d);
	return n;
}

static void fresh(void)
{
	wipe(dir_a);
	wipe(dir_b);
	memset(&mem_a, 0, sizeof(mem_a));
	memset(&mem_b, 0, sizeof(mem_b));
	fzn_piece_buckets_close(&pb_a);
	fzn_piece_buckets_close(&pb_b);
	(void)fzn_piece_buckets_init(&pb_a, &A, dir_a, &HASH, &SIGN_A, key_a);
	(void)fzn_piece_buckets_init(&pb_b, &B, dir_b, &HASH, &SIGN_B, key_b);
	fzn_piece_buckets_filer(&pb_a, &filer_a);
	fzn_piece_buckets_filer(&pb_b, &filer_b);
}

/* ---- the exchange, asked directly ---------------------------------------- */

/* A's view of what B may hold: the pieces placed on B. */
static int serves_b(void *ctx, fzn_buckets_kind_t kind, const uint8_t subject[FZN_PUBKEY_LEN])
{
	(void)ctx;
	return kind == FZN_BUCKETS_PIECES && memcmp(subject, key_b, 32u) == 0;
}

static fzn_reconcile_gate_t gate_b = { serves_b, NULL, NULL };

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
	srv.gate = &gate_b;
	srv.takers[FZN_BUCKETS_PIECES] = &filer_a;
	srv.sender = key_b;
	n = fzn_reconcile_serve(&srv, request, request_len, reply, cap);
	if (!n)
		return 0;
	*reply_len = n;
	return 1;
}

/* B's view of what A may hold: the pieces placed on A, and -- with
 * `by_item` -- any piece asked by id whose item is A's (sec 599). */
static int serves_a(void *ctx, fzn_buckets_kind_t kind, const uint8_t subject[FZN_PUBKEY_LEN])
{
	(void)ctx;
	return kind == FZN_BUCKETS_PIECES && memcmp(subject, key_a, 32u) == 0;
}

static int piece_of_a(void *ctx, fzn_buckets_kind_t kind, const uint8_t subject[FZN_PUBKEY_LEN],
                      const uint8_t id[FZN_BUCKETS_ID_LEN])
{
	uint8_t host[32];

	(void)ctx;
	(void)subject;
	return kind == FZN_BUCKETS_PIECES && fzn_piece_buckets_host(&pb_b, id, host)
	       && memcmp(host, key_a, 32u) == 0;
}

static int by_item = 1;
/* 1: B serves every bucket, so only whether it can read an item decides
 * what it answers. */
static int serve_all;

/* B ANSWERING A, taking what A pushes. */
static int to_b(void *ctx, const uint8_t *request, size_t request_len, uint8_t *reply,
                size_t cap, size_t *reply_len)
{
	fzn_reconcile_gate_t gate = { serves_a, NULL, NULL };
	fzn_reconcile_server_t srv;
	size_t n;

	(void)ctx;
	gate.serves_item = by_item ? piece_of_a : NULL;
	memset(&srv, 0, sizeof(srv));
	srv.store = &store_b;
	srv.hash = &HASH;
	srv.gate = serve_all ? NULL : &gate;
	srv.takers[FZN_BUCKETS_PIECES] = &filer_b;
	srv.sender = key_a;
	n = fzn_reconcile_serve(&srv, request, request_len, reply, cap);
	if (!n)
		return 0;
	*reply_len = n;
	return 1;
}

/* ---- the item ------------------------------------------------------------ */

#define ITEM_LEN 20000u
#define MONTH 680u

static uint8_t item[ITEM_LEN], item_id[FZN_BUCKETS_ID_LEN];

/* A cuts the item 1 + 1 and places piece i on `keepers[i]`. */
static int a_cuts(const uint8_t (*keepers)[32], size_t *placed)
{
	size_t written = 0;

	return fzn_pieces_cut(dir_a, 1u, item_id, key_a, keepers, item, ITEM_LEN, 1u, 1u, &written)
	               == FZN_PIECES_OK
	       && written == 2u
	       && fzn_piece_buckets_place(&pb_a, item_id, MONTH, 1u, 1u, keepers, placed);
}

static uint64_t count_of(const fzn_buckets_t *b, const uint8_t subject[32])
{
	fzn_bucket_t k;

	if (fzn_buckets_bucket(b, FZN_BUCKETS_PIECES, subject, MONTH, &k) != FZN_BUCKETS_OK)
		return 99u;
	return k.count;
}

/* ---- tests ---------------------------------------------------------------- */

static void test_rank(void)
{
	uint8_t hosts[6][32], back[6][32];
	size_t order[6], order_back[6], i, j, seen;
	uint8_t other[FZN_BUCKETS_ID_LEN];
	size_t order_other[6];
	int differs = 0;

	for (i = 0; i < 6u; i++) {
		memset(hosts[i], (int)(0x10u + i), 32u);
		memcpy(back[5u - i], hosts[i], 32u);
	}
	CHECK(fzn_piece_buckets_rank(&HASH, item_id, (const uint8_t (*)[32])hosts, 6u, order)
	          && fzn_piece_buckets_rank(&HASH, item_id, (const uint8_t (*)[32])back, 6u,
	                                    order_back),
	      "six hosts would not rank");
	for (i = 0, seen = 0; i < 6u; i++)
		for (j = 0; j < 6u; j++)
			seen += order[j] == i;
	CHECK(seen == 6u, "the order is not every host once");
	/* THE SAME HOST FOR EACH PIECE, whatever order the hosts came in. */
	for (i = 0; i < 6u; i++)
		CHECK(memcmp(hosts[order[i]], back[order_back[i]], 32u) == 0,
		      "the placement moved with the order the hosts were listed in");
	/* AND ANOTHER ITEM, ANOTHER ORDER: the pieces of many items spread. */
	memcpy(other, item_id, sizeof(other));
	other[0] ^= 1u;
	CHECK(fzn_piece_buckets_rank(&HASH, other, (const uint8_t (*)[32])hosts, 6u, order_other),
	      "another item would not rank");
	for (i = 0; i < 6u; i++)
		differs |= order_other[i] != order[i];
	CHECK(differs, "two items ranked the hosts alike: every first piece on one host");
}

static void test_place_pull_push(void)
{
	uint8_t keepers[2][32];
	fzn_reconcile_bucket_tally_t t;
	static uint8_t reply[8192];
	uint8_t out[ITEM_LEN];
	size_t placed = 0, len = 0;
	uint32_t used = 0;

	fresh();
	memcpy(keepers[0], key_a, 32u);
	memcpy(keepers[1], key_b, 32u);
	CHECK(a_cuts((const uint8_t (*)[32])keepers, &placed) && placed == 2u,
	      "A did not place both pieces");
	CHECK(count_of(&A, key_a) == 1u && count_of(&A, key_b) == 1u,
	      "A's buckets are not one piece for A and one for B");
	{
		uint8_t got[FZN_ERASURE_PIECES_MAX][32];
		unsigned k = 0, m = 0;

		CHECK(fzn_piece_buckets_cut_of(&pb_a, item_id, &k, &m, got) && k == 1u && m == 1u
		              && memcmp(got[0], key_a, 32u) == 0 && memcmp(got[1], key_b, 32u) == 0,
		      "A's record of the placement does not read back as placed");
		CHECK(!fzn_piece_buckets_cut_of(&pb_b, item_id, &k, &m, got),
		      "B has a record of a placement it did not make");
	}

	/* PULLED: B takes the piece placed on it, and not A's. */
	memset(&t, 0, sizeof(t));
	CHECK(fzn_reconcile_buckets(&B, FZN_BUCKETS_PIECES, &filer_b, to_a, NULL, reply,
	                            sizeof(reply), &t)
	                  == FZN_RECONCILE_OK
	          && t.applied == 1u,
	      "B did not pull its piece");
	CHECK(count_of(&B, key_b) == 1u && count_of(&B, key_a) == 0u && pieces_in(dir_b) == 1u,
	      "B holds other than the one piece placed on it");
	/* AND IT IS A PIECE OF THE ITEM: one of 1 + 1 rebuilds it alone. */
	CHECK(fzn_pieces_rebuild(dir_b, 1u, item_id, &HASH, out, sizeof(out), &len, &used)
	                  == FZN_PIECES_OK
	          && len == ITEM_LEN && memcmp(out, item, ITEM_LEN) == 0 && used == 2u,
	      "B's piece did not rebuild the item");

	/* PUSHED through A's gate: B is given its own piece only. */
	fresh();
	CHECK(a_cuts((const uint8_t (*)[32])keepers, &placed), "fixture: A cuts again");
	memset(&t, 0, sizeof(t));
	CHECK(fzn_reconcile_push(&A, FZN_BUCKETS_PIECES, &gate_b, &filer_a, NULL, to_b, NULL,
	                         reply, sizeof(reply), &t)
	                  == FZN_RECONCILE_OK
	          && t.sent == 1u,
	      "A did not push B its piece");
	CHECK(count_of(&B, key_b) == 1u && count_of(&B, key_a) == 0u && pieces_in(dir_b) == 1u,
	      "B was pushed other than its own piece");

	/* PUSHED UNGATED: B keeps none placed on another host. */
	fresh();
	CHECK(a_cuts((const uint8_t (*)[32])keepers, &placed), "fixture: A cuts a third time");
	memset(&t, 0, sizeof(t));
	CHECK(fzn_reconcile_push(&A, FZN_BUCKETS_PIECES, NULL, &filer_a, NULL, to_b, NULL, reply,
	                         sizeof(reply), &t)
	                  == FZN_RECONCILE_OK
	          && t.sent == 1u && t.passed == 1u && t.refused == 0u,
	      "a piece placed on A was sent to B at all, rather than passed over unwanted");
	CHECK(count_of(&B, key_a) == 0u && pieces_in(dir_b) == 1u,
	      "B keeps a piece placed on A");
}

/* COUNTED AND LET GO, sec 599: A asks B for the piece placed on B by its
 * id, which B serves A since the item is A's, and then lets go of its own
 * copy of it. */
static void test_counted_and_let_go(void)
{
	uint8_t keepers[2][32], piece_id[FZN_BUCKETS_ID_LEN], host[32];
	fzn_reconcile_bucket_tally_t t;
	static uint8_t reply[8192];
	size_t placed = 0, served = 0;
	uint32_t here = 0;
	int has = 0;

	fresh();
	memcpy(keepers[0], key_a, 32u);
	memcpy(keepers[1], key_b, 32u);
	CHECK(a_cuts((const uint8_t (*)[32])keepers, &placed)
	          && fzn_reconcile_push(&A, FZN_BUCKETS_PIECES, &gate_b, &filer_a, NULL, to_b, NULL,
	                                reply, sizeof(reply), &t)
	                     == FZN_RECONCILE_OK
	          && t.sent == 1u,
	      "fixture: A cuts and pushes B its piece");
	CHECK(fzn_piece_buckets_piece_id(&pb_a, item_id, 1u, piece_id, NULL)
	          && fzn_buckets_has(&B, FZN_BUCKETS_PIECES, piece_id),
	      "the id A placed piece 1 under is not the one B holds");
	CHECK(fzn_piece_buckets_host(&pb_b, piece_id, host) && memcmp(host, key_a, 32u) == 0,
	      "B's piece does not say it is of A's item");
	/* ASKED BY ID: served to A for its item, though the bucket is B's. */
	by_item = 0;
	CHECK(fzn_reconcile_peer_holds(FZN_BUCKETS_PIECES, piece_id, to_b, NULL, reply, sizeof(reply),
	                               &has)
	                  == FZN_RECONCILE_OK
	          && !has,
	      "fixture: without the item gate B's piece is not A's to see");
	by_item = 1;
	CHECK(fzn_reconcile_peer_holds(FZN_BUCKETS_PIECES, piece_id, to_b, NULL, reply, sizeof(reply),
	                               &has)
	                  == FZN_RECONCILE_OK
	          && has,
	      "B would not tell A it holds a piece of A's item");
	/* AND A'S OWN COPY OF IT GOES, its id remembered -- still had, so not
	 * fetched back, and served as not held. */
	CHECK(fzn_piece_buckets_let_go(&pb_a, item_id, 1u)
	          && fzn_pieces_held(dir_a, item_id, &here) == FZN_PIECES_OK && here == 1u
	          && fzn_buckets_has(&A, FZN_BUCKETS_PIECES, piece_id)
	          && fzn_buckets_item(&A, FZN_BUCKETS_PIECES, piece_id, reply, sizeof(reply),
	                              &served, NULL, NULL)
	                     == FZN_BUCKETS_ABSENT,
	      "A's copy of B's piece was not let go");
	CHECK(fzn_piece_buckets_piece_id(&pb_a, item_id, 1u, host, NULL)
	          && memcmp(host, piece_id, 32u) == 0,
	      "letting a piece go forgot its id");
	CHECK(fzn_piece_buckets_let_go(&pb_a, item_id, 1u), "letting a piece go twice failed");
}

/* LOST AND PUT BACK, sec 600: B's file of its piece goes while its row
 * stays; B then answers it does not hold it, A fetches nothing from it,
 * and pushed it again by id B takes it back rather than calling it held. */
static void test_lost_and_put_back(void)
{
	uint8_t keepers[2][32], piece_id[FZN_BUCKETS_ID_LEN], hex[65];
	fzn_reconcile_bucket_tally_t t;
	static uint8_t reply[8192], got[ITEM_LEN + 200u];
	char path[300];
	size_t placed = 0, len = 9, i, item_len = 0;
	uint64_t size = 0;
	int has = 1;

	fresh();
	memcpy(keepers[0], key_a, 32u);
	memcpy(keepers[1], key_b, 32u);
	CHECK(a_cuts((const uint8_t (*)[32])keepers, &placed)
	          && fzn_reconcile_push(&A, FZN_BUCKETS_PIECES, &gate_b, &filer_a, NULL, to_b, NULL,
	                                reply, sizeof(reply), &t)
	                     == FZN_RECONCILE_OK
	          && t.sent == 1u
	          && fzn_piece_buckets_piece_id(&pb_a, item_id, 1u, piece_id, &size)
	          && size == FZN_PIECE_HEAD_LEN + ITEM_LEN,
	      "fixture: A cuts and pushes B its piece");
	CHECK(fzn_pieces_item_len(dir_a, item_id, &item_len) == FZN_PIECES_OK && item_len == ITEM_LEN,
	      "a piece's head did not give its item's length");
	/* FETCHED BY ID while B holds it: the piece's bytes, whole. */
	CHECK(fzn_reconcile_fetch_one(FZN_BUCKETS_PIECES, piece_id, &HASH, got, sizeof(got), &len,
	                              to_b, NULL, reply, sizeof(reply))
	                  == FZN_RECONCILE_OK
	          && len == size,
	      "A could not fetch B's piece by its id");
	CHECK(fzn_reconcile_fetch_one(FZN_BUCKETS_PIECES, piece_id, &HASH, got, (size_t)size - 1u,
	                              &len, to_b, NULL, reply, sizeof(reply))
	          == FZN_RECONCILE_ERR_SHAPE,
	      "a piece longer than the room for it was fetched");
	for (i = 0; i < 32u; i++)
		snprintf((char *)hex + 2u * i, 3u, "%02x", item_id[i]);
	snprintf(path, sizeof(path), "%s/%s.1.piece", dir_b, (const char *)hex);
	/* CHANGED IN A BYTE AT B: not its id's bytes, so not fetched. */
	{
		FILE *f = fopen(path, "r+b");
		int c;

		CHECK(f && fseek(f, 100L, SEEK_SET) == 0 && (c = fgetc(f)) != EOF
		              && fseek(f, 100L, SEEK_SET) == 0 && fputc(c ^ 1, f) != EOF,
		      "fixture: a byte of B's piece changed");
		if (f)
			(void)fclose(f);
	}
	CHECK(fzn_reconcile_fetch_one(FZN_BUCKETS_PIECES, piece_id, &HASH, got, sizeof(got), &len,
	                              to_b, NULL, reply, sizeof(reply))
	          == FZN_RECONCILE_ERR_SHAPE,
	      "a piece not its id's bytes was fetched");
	/* ITS FILE GONE, ITS ROW KEPT. */
	CHECK(remove(path) == 0, "fixture: B's piece file removed");
	CHECK(fzn_reconcile_peer_holds(FZN_BUCKETS_PIECES, piece_id, to_b, NULL, reply, sizeof(reply),
	                               &has)
	                  == FZN_RECONCILE_OK
	          && !has,
	      "B said it holds a piece whose file is gone");
	/* AND WITH NO GATE TO SAY SO -- its bucket served outright, as a whole
	 * segment's is -- its row alone does not make it held. */
	serve_all = 1;
	has = 1;
	CHECK(fzn_reconcile_peer_holds(FZN_BUCKETS_PIECES, piece_id, to_b, NULL, reply, sizeof(reply),
	                               &has)
	                  == FZN_RECONCILE_OK
	          && !has,
	      "B's row alone made a piece whose file is gone held");
	serve_all = 0;
	CHECK(fzn_reconcile_fetch_one(FZN_BUCKETS_PIECES, piece_id, &HASH, got, sizeof(got), &len,
	                              to_b, NULL, reply, sizeof(reply))
	                  == FZN_RECONCILE_OK
	          && len == 0u,
	      "a piece whose file is gone was fetched");
	CHECK(fzn_reconcile_push_one(&A, FZN_BUCKETS_PIECES, key_b, MONTH, piece_id, &filer_a, to_b,
	                             NULL, reply, sizeof(reply), &t)
	                  == FZN_RECONCILE_OK
	          && t.sent == 1u && t.held == 0u && pieces_in(dir_b) == 1u,
	      "pushed by id, B did not take back the piece it lost");
	CHECK(fzn_reconcile_peer_holds(FZN_BUCKETS_PIECES, piece_id, to_b, NULL, reply, sizeof(reply),
	                               &has)
	                  == FZN_RECONCILE_OK
	          && has,
	      "B does not hold the piece put back");
}

/* A RELEASE, made here by hand from `chunk/piece.situ` rather than by the
 * module, so the layout has a second witness: piece `index` of `id`, the
 * piece `piece_id`, of `host`'s item, signed with `signer`. */
static void release_of(uint8_t rec[FZN_PIECE_RELEASE_LEN], const uint8_t host[32],
                       unsigned index, const uint8_t piece_id[FZN_BUCKETS_ID_LEN],
                       const fzn_sign_ops_t *signer)
{
	static const char label[] = "fuzznet.piece.release";
	uint8_t msg[sizeof(label) + 99u];

	rec[0] = 1u;
	rec[1] = 255u;
	memcpy(rec + 2, item_id, 32u);
	memcpy(rec + 34, host, 32u);
	rec[66] = (uint8_t)index;
	memcpy(rec + 67, piece_id, 32u);
	memcpy(msg, label, sizeof(label));
	memcpy(msg + sizeof(label), rec, 99u);
	(void)signer->sign(signer->ctx, rec + 99, msg, sizeof(msg));
}

/* RELEASED, sec 602: A releases the piece it placed on B; B lets it go and
 * keeps the release. A release not signed by the item's host, or signed by
 * a host the piece is not of, lets nothing go. */
static void test_released(void)
{
	uint8_t keepers[2][32], piece_id[FZN_BUCKETS_ID_LEN], rec[FZN_PIECE_RELEASE_LEN];
	fzn_reconcile_bucket_tally_t t;
	static uint8_t reply[8192];
	size_t placed = 0, len = 0;

	fresh();
	memcpy(keepers[0], key_a, 32u);
	memcpy(keepers[1], key_b, 32u);
	CHECK(a_cuts((const uint8_t (*)[32])keepers, &placed)
	          && fzn_reconcile_push(&A, FZN_BUCKETS_PIECES, &gate_b, &filer_a, NULL, to_b, NULL,
	                                reply, sizeof(reply), &t)
	                     == FZN_RECONCILE_OK
	          && t.sent == 1u && pieces_in(dir_b) == 1u
	          && fzn_piece_buckets_piece_id(&pb_a, item_id, 1u, piece_id, NULL),
	      "fixture: A cuts and pushes B its piece");
	/* FORGED: signed with B's key, naming A. */
	release_of(rec, key_a, 1u, piece_id, &SIGN_B);
	CHECK(filer_b.file(filer_b.ctx, key_b, MONTH, rec, sizeof(rec)) == FZN_NODE_APPLY_REFUSED
	          && pieces_in(dir_b) == 1u,
	      "a release not signed by the host it names was taken");
	/* SIGNED BY B, AS B: a piece of A's item is not B's to release. */
	release_of(rec, key_b, 1u, piece_id, &SIGN_B);
	CHECK(filer_b.file(filer_b.ctx, key_b, MONTH, rec, sizeof(rec)) == FZN_NODE_APPLY_APPLIED
	          && pieces_in(dir_b) == 1u,
	      "a release by a host the piece is not of let it go");
	/* PLACED ON A: not B's to take. */
	release_of(rec, key_a, 1u, piece_id, &SIGN_A);
	CHECK(filer_b.file(filer_b.ctx, key_a, MONTH, rec, sizeof(rec)) == FZN_NODE_APPLY_REFUSED,
	      "B took a release placed on A");
	/* A'S OWN, made by the module and pushed: B lets its piece go. */
	CHECK(fzn_piece_buckets_release(&pb_a, &SIGN_A, key_a, item_id, 1u, piece_id, key_b, MONTH)
	          && fzn_reconcile_push(&A, FZN_BUCKETS_PIECES, &gate_b, &filer_a, NULL, to_b, NULL,
	                                reply, sizeof(reply), &t)
	                     == FZN_RECONCILE_OK
	          && t.sent == 1u,
	      "A's release of B's piece was not pushed to B");
	CHECK(pieces_in(dir_b) == 0u
	          && fzn_buckets_item(&B, FZN_BUCKETS_PIECES, piece_id, reply, sizeof(reply), &len,
	                              NULL, NULL)
	                     == FZN_BUCKETS_ABSENT,
	      "B kept the piece A released");
	/* THE MODULE'S BYTES ARE THE HAND-MADE ONES: the bucket B holds is
	 * A's, item for item. */
	release_of(rec, key_a, 1u, piece_id, &SIGN_A);
	{
		uint8_t rid[FZN_BUCKETS_ID_LEN];

		CHECK(fzn_buckets_id(&HASH, rec, sizeof(rec), rid)
		          && fzn_buckets_has(&A, FZN_BUCKETS_PIECES, rid)
		          && fzn_buckets_has(&B, FZN_BUCKETS_PIECES, rid),
		      "the module's release is not the layout's");
	}
}

static void test_shape_refused(void)
{
	uint8_t bytes[FZN_PIECE_HEAD_LEN + 8u];
	char path[300];
	size_t i;

	fresh();
	/* A PIECE'S HEAD WITH A PIECE THE WRONG LENGTH. */
	memset(bytes, 0, sizeof(bytes));
	bytes[0] = 1u;
	bytes[1] = 1u;
	bytes[73] = 16u; /* item length 16 */
	bytes[74] = 1u;  /* k */
	bytes[75] = 1u;  /* m */
	memcpy(bytes + 77, key_b, 32u); /* placed on B */
	bytes[112] = 8u; /* piece_len 8, where 16 / 1 is 16 */
	CHECK(filer_b.file(filer_b.ctx, key_b, MONTH, bytes, sizeof(bytes)) == FZN_NODE_APPLY_REFUSED,
	      "a piece whose length is not its item's over k was kept");
	bytes[73] = 8u;
	CHECK(filer_b.file(filer_b.ctx, key_b, MONTH, bytes, sizeof(bytes)) == FZN_NODE_APPLY_APPLIED,
	      "a well-formed piece was not kept");
	bytes[76] = 2u; /* index past k + m */
	CHECK(filer_b.file(filer_b.ctx, key_b, MONTH, bytes, sizeof(bytes)) == FZN_NODE_APPLY_REFUSED,
	      "a piece indexed past k + m was kept");
	bytes[76] = 1u;
	CHECK(filer_b.file(filer_b.ctx, key_b, MONTH, bytes, sizeof(bytes) - 1u)
	          == FZN_NODE_APPLY_REFUSED,
	      "a piece cut short was kept");
	CHECK(filer_b.file(filer_b.ctx, key_a, MONTH, bytes, sizeof(bytes)) == FZN_NODE_APPLY_REFUSED,
	      "B kept a piece placed on A");
	memcpy(bytes + 77, key_a, 32u);
	CHECK(filer_b.file(filer_b.ctx, key_b, MONTH, bytes, sizeof(bytes)) == FZN_NODE_APPLY_REFUSED,
	      "B kept a piece whose head names A its keeper, its bucket B's");
	memcpy(bytes + 77, key_b, 32u);
	CHECK(pieces_in(dir_b) == 1u, "a refused piece left a file");
	/* REFS THE KIND DOES NOT NAME ARE NOT READ. */
	snprintf(path, sizeof(path), "p/%064u.0", 0u);
	CHECK(filer_b.read(filer_b.ctx, (const uint8_t *)path, strlen(path), 0u, bytes, 1u),
	      "the kept piece's ref did not read");
	for (i = 0; i < 4u; i++) {
		static const char *const bad[] = { "p/../../etc/passwd", "o/x", "p/0.0",
		                                   "p/0000000000000000000000000000000000000000000000000000"
		                                   "000000000000.00" };

		CHECK(!filer_b.read(filer_b.ctx, (const uint8_t *)bad[i], strlen(bad[i]), 0u, bytes, 1u),
		      "a ref not a piece's was read");
	}
}

int main(void)
{
	size_t i;
	uint32_t s = 99u;

	snprintf(top, sizeof(top), "/tmp/fzn-piece-buckets-test-%ld", (long)getpid());
	snprintf(dir_a, sizeof(dir_a), "%s/a", top);
	snprintf(dir_b, sizeof(dir_b), "%s/b", top);
	if (mkdir(top, 0700) != 0) {
		fprintf(stderr, "piece_buckets_test: cannot make %s\n", top);
		return 1;
	}
	memset(key_a, 0xaa, sizeof(key_a));
	memset(key_b, 0xbb, sizeof(key_b));
	for (i = 0; i < ITEM_LEN; i++) {
		s = s * 1103515245u + 12345u;
		item[i] = (uint8_t)(s >> 16);
	}
	(void)fzn_buckets_id(&HASH, item, ITEM_LEN, item_id);

	test_rank();
	test_place_pull_push();
	test_counted_and_let_go();
	test_lost_and_put_back();
	test_released();
	test_shape_refused();

	fzn_piece_buckets_close(&pb_a);
	fzn_piece_buckets_close(&pb_b);
	wipe(dir_a);
	wipe(dir_b);
	(void)rmdir(top);
	if (failures) {
		fprintf(stderr, "piece_buckets_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("piece_buckets_test: all %d checks passed\n", checks);
	return 0;
}
