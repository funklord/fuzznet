/* Tests for node/apply.c: a node's journal applied to its subsystems.
 * sec 503.
 *
 * ONE NODE'S JOURNAL, filled by hand, in a scratch directory of its own under
 * /tmp, made and removed by name. The signer is a keyed mixing function keyed
 * by the first byte of the public key, as roster_test's is: an object verifies
 * under the key it was signed as and no other.
 */

#include "../apply.h"
#include "../roster.h"
#include "../succession.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int failures;
static int checks;

#define CHECK(cond, what)                                                                      \
	do {                                                                                   \
		checks++;                                                                      \
		if (!(cond)) {                                                                 \
			failures++;                                                            \
			fprintf(stderr, "  FAIL apply_test.c:%d: %s\n", __LINE__, what);        \
		}                                                                              \
	} while (0)

static void mac(uint8_t out[FZN_SIG_LEN], uint8_t key, const uint8_t *msg, size_t len)
{
	uint64_t h = 0xcbf29ce484222325ull ^ key;
	size_t i;

	for (i = 0; i < len; i++)
		h = (h ^ msg[i]) * 0x100000001b3ull;
	for (i = 0; i < FZN_SIG_LEN; i++) {
		h = (h ^ (uint64_t)i) * 0x100000001b3ull;
		out[i] = (uint8_t)(h >> 56);
	}
}

static uint8_t signing_as;

static int stub_sign(void *ctx, uint8_t sig[FZN_SIG_LEN], const uint8_t *msg, size_t len)
{
	(void)ctx;
	mac(sig, signing_as, msg, len);
	return 1;
}

static int stub_verify(void *ctx, const uint8_t pk[FZN_PUBKEY_LEN], const uint8_t *msg, size_t len,
                       const uint8_t sig[FZN_SIG_LEN])
{
	uint8_t want[FZN_SIG_LEN];

	(void)ctx;
	mac(want, pk[0], msg, len);
	return memcmp(want, sig, FZN_SIG_LEN) == 0;
}

static int mix_hash(void *ctx, uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len)
{
	uint64_t h = 0x84222325cbf29ce4ull;
	size_t i;

	(void)ctx;
	for (i = 0; i < in_len; i++)
		h = (h ^ in[i]) * 0x100000001b3ull;
	for (i = 0; i < out_len; i++) {
		h = (h ^ (uint64_t)i) * 0x100000001b3ull;
		out[i] = (uint8_t)(h >> 40);
	}
	return 1;
}

static const fzn_sign_ops_t SIGN = { stub_verify, stub_sign, NULL };
static const fzn_hash_ops_t HASH = { mix_hash, NULL };

/* ---- an in-memory persist store ---------------------------------------- */

#define ROWS 64

static struct row {
	int used;
	fzn_persist_slot_t slot;
	uint8_t subject[FZN_PUBKEY_LEN];
	uint8_t bytes[2048];
	size_t len;
} rows[ROWS];

static struct row *row_of(fzn_persist_slot_t slot, const uint8_t *subject, int make)
{
	int i, free_one = -1;

	for (i = 0; i < ROWS; i++) {
		if (!rows[i].used) {
			if (free_one < 0)
				free_one = i;
			continue;
		}
		if (rows[i].slot == slot && memcmp(rows[i].subject, subject, FZN_PUBKEY_LEN) == 0)
			return &rows[i];
	}
	if (!make || free_one < 0)
		return NULL;
	rows[free_one].used = 1;
	rows[free_one].slot = slot;
	memcpy(rows[free_one].subject, subject, FZN_PUBKEY_LEN);
	return &rows[free_one];
}

static int mem_load(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject, uint8_t *out,
                    size_t cap, size_t *len)
{
	struct row *r = row_of(slot, subject, 0);

	(void)ctx;
	if (!r || r->len > cap)
		return 0;
	memcpy(out, r->bytes, r->len);
	*len = r->len;
	return 1;
}

static int mem_save(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject,
                    const uint8_t *bytes, size_t len)
{
	struct row *r;

	(void)ctx;
	if (len > sizeof(r->bytes))
		return 0;
	r = row_of(slot, subject, 1);
	if (!r)
		return 0;
	memcpy(r->bytes, bytes, len);
	r->len = len;
	return 1;
}

static int mem_list(void *ctx, fzn_persist_slot_t slot, uint8_t *out, size_t max, size_t *count)
{
	int i;

	(void)ctx;
	*count = 0;
	for (i = 0; i < ROWS && *count < max; i++)
		if (rows[i].used && rows[i].slot == slot)
			memcpy(out + (*count)++ * FZN_PUBKEY_LEN, rows[i].subject, FZN_PUBKEY_LEN);
	return 1;
}

/* ---- fixtures ---------------------------------------------------------- */

static void key(uint8_t out[FZN_PUBKEY_LEN], uint8_t seed)
{
	size_t i;

	for (i = 0; i < FZN_PUBKEY_LEN; i++)
		out[i] = (uint8_t)(seed + i * 3u);
	out[0] = seed;
}

static char dir[128];
static uint8_t used_writers[8];
static size_t n_used;

/* `writer` appends `object` to its estate stream in `nj`. */
static int put(fzn_node_journal_t *nj, uint8_t writer, const uint8_t *object, size_t len)
{
	uint8_t k[FZN_PUBKEY_LEN];
	size_t i;

	for (i = 0; i < n_used && used_writers[i] != writer; i++)
		;
	if (i == n_used)
		used_writers[n_used++] = writer;
	key(k, writer);
	signing_as = writer;
	return fzn_node_journal_append_object(nj, k, &SIGN, object, len, 1u, NULL)
	       == FZN_NODE_JOURNAL_OK;
}

static void test_the_journal_applied(void)
{
	static fzn_node_journal_t nj;
	static fzn_node_roster_t roster;
	static fzn_node_successions_t ns;
	static fzn_revocation_t rev_entries[8];
	static fzn_node_apply_t ap;
	fzn_revocation_store_t revs;
	fzn_persist_ops_t store = { 0 };
	fzn_node_apply_tally_t t;
	fzn_cap_id_t cap;
	uint8_t r[FZN_PUBKEY_LEN], m[FZN_PUBKEY_LEN], s[FZN_PUBKEY_LEN], alice[FZN_PUBKEY_LEN];
	uint8_t bob[FZN_PUBKEY_LEN], d[FZN_PUBKEY_LEN], d2[FZN_PUBKEY_LEN], now[FZN_PUBKEY_LEN];
	uint8_t hop[FZN_HOP_LEN], obj[FZN_ROSTER_MAX_LEN], inc[FZN_ROSTER_INCARNATION_LEN];
	uint8_t succ[FZN_SUCCESSION_LEN];
	size_t len = 0;

	store.load = mem_load;
	store.save = mem_save;
	store.list = mem_list;
	memset(&cap, 0x61, sizeof(cap));
	key(r, 0x10);
	key(m, 0x20);
	key(s, 0x30);
	key(alice, 0x40);
	key(bob, 0x50);
	key(d, 0x60);
	key(d2, 0x70);
	memset(inc, 0x0e, sizeof(inc));
	CHECK(fzn_node_journal_init(&nj, dir, &SIGN, &HASH) == FZN_NODE_JOURNAL_OK
	              && fzn_revocation_store_init(&revs, rev_entries, 8) == FZN_CHAIN_OK
	              && fzn_node_roster_init(&roster, r, &cap, &SIGN, NULL, &HASH)
	                         == FZN_NODE_ROSTER_OK
	              && fzn_node_successions_init(&ns, &HASH) == FZN_NODE_REVOKE_OK,
	      "fixture: the journal and the subsystems");
	memset(&ap, 0, sizeof(ap));
	ap.journal = &nj;
	ap.revocations = &revs;
	ap.roster = &roster;
	ap.successions = &ns;
	ap.store = &store;
	ap.root = r;
	ap.capability = &cap;
	ap.sign = &SIGN;
	ap.hash = &HASH;

	/* M's STREAM FIRST, so its roster record meets no grant on the first
	 * pass: M adds alice. Then R's: the grant to M, and a succession. */
	signing_as = 0x20;
	CHECK(fzn_roster_issue_add(m, alice, inc, 1u, &SIGN, obj, sizeof(obj), &len)
	              == FZN_ROSTER_OK
	              && put(&nj, 0x20, obj, len),
	      "fixture: M's roster record in M's stream");
	signing_as = 0x10;
	CHECK(fzn_chain_mint(r, m, &cap, 100u, FZN_NO_EXPIRY, 0, &SIGN, hop) == FZN_CHAIN_OK
	              && put(&nj, 0x10, hop, sizeof(hop)),
	      "fixture: R's grant to M in R's stream");
	signing_as = 0x10;
	CHECK(fzn_succession_issue(r, d, d2, NULL, &SIGN, succ) == FZN_CHAIN_OK
	              && put(&nj, 0x10, succ, sizeof(succ)),
	      "fixture: R's succession of D in R's stream");

	CHECK(fzn_node_apply_round(&ap, &t) == FZN_NODE_PULL_OK && t.grants == 1u
	              && t.applied == 2u && t.refused == 0u && t.waiting == 0u,
	      "one round did not apply R's grant and then M's record that waited on it");
	CHECK(fzn_node_roster_standing(&roster, alice, &revs, 2u) == FZN_ROSTER_ACTIVE,
	      "M's contact, applied from the journal, is not active");
	CHECK(fzn_node_successions_resolve(&ns, &revs, r, d, now)
	              && memcmp(now, d2, FZN_PUBKEY_LEN) == 0,
	      "R's succession, applied from the journal, does not read D through");
	{
		uint8_t hops[FZN_CHAIN_MAX_HOPS][FZN_HOP_LEN];
		size_t n = 9;

		CHECK(fzn_node_apply_chain(&ap, m, &cap, hops, &n) && n == 1u
		              && memcmp(hops[0], hop, FZN_HOP_LEN) == 0
		              && fzn_node_apply_chain(&ap, r, &cap, hops, &n) && n == 0u
		              && !fzn_node_apply_chain(&ap, s, &cap, hops, &n),
		      "the index did not rebuild M's chain, a root's empty one, and no stranger's");
	}

	/* A STRANGER'S RECORD, with no chain anywhere: it waits. */
	signing_as = 0x30;
	CHECK(fzn_roster_issue_add(s, bob, inc, 2u, &SIGN, obj, sizeof(obj), &len) == FZN_ROSTER_OK
	              && put(&nj, 0x30, obj, len)
	              && fzn_node_apply_round(&ap, &t) == FZN_NODE_PULL_OK && t.waiting == 1u
	              && t.applied == 0u
	              && fzn_node_roster_standing(&roster, bob, &revs, 2u) == FZN_ROSTER_ABSENT,
	      "a record with no chain did not wait, or counted");

	/* A KIND THE BODY DOES NOT CARRY: refused, and the stream goes on. */
	{
		uint8_t subject[FZN_SUBJECT_LEN];

		memset(subject, 0x11, sizeof(subject));
		signing_as = 0x20;
		CHECK(fzn_node_journal_append(&nj, m, &SIGN, (uint32_t)FZN_OBJECT_SUCCESSION, subject,
		                              hop, sizeof(hop), 1u, NULL) == FZN_NODE_JOURNAL_OK
		              && fzn_node_apply_round(&ap, &t) == FZN_NODE_PULL_OK && t.refused == 1u,
		      "a record whose kind its body's tag denies was not refused");
	}

	/* AND AGAIN: nothing new is applied. */
	CHECK(fzn_node_apply_round(&ap, &t) == FZN_NODE_PULL_OK && t.applied == 0u
	              && t.grants == 0u && t.refused == 0u,
	      "a second round applied something again");
	fzn_node_journal_close(&nj);
}

int main(void)
{
	char path[512];
	size_t i;

	snprintf(dir, sizeof(dir), "/tmp/fzn-apply-test-%ld", (long)getpid());
	if (mkdir(dir, 0700) != 0) {
		fprintf(stderr, "apply_test: could not make %s\n", dir);
		return 1;
	}
	test_the_journal_applied();
	/* EVERY STREAM FILE, BY NAME, then the directory. */
	for (i = 0; i < n_used; i++) {
		static const char DIGITS[] = "0123456789abcdef";
		uint8_t k[FZN_PUBKEY_LEN];
		char hex[FZN_PUBKEY_LEN * 2u + 1u];
		size_t j;

		key(k, used_writers[i]);
		for (j = 0; j < FZN_PUBKEY_LEN; j++) {
			hex[j * 2u] = DIGITS[k[j] >> 4];
			hex[j * 2u + 1u] = DIGITS[k[j] & 0x0fu];
		}
		hex[FZN_PUBKEY_LEN * 2u] = '\0';
		snprintf(path, sizeof(path), "%s/%s-%08lx.rec", dir, hex,
		         (unsigned long)FZN_NODE_JOURNAL_STREAM);
		(void)unlink(path);
	}
	CHECK(rmdir(dir) == 0, "the scratch directory would not go: a file the suite did not name");
	if (failures) {
		fprintf(stderr, "apply_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("apply_test: all %d checks passed\n", checks);
	return 0;
}
