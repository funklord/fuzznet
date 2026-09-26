/* node/identity.h: a node loads its identity or generates one, and refuses a
 * store holding part of one. sec 375.
 *
 * STUB CRYPTO, SO THIS RUNS IN EVERY BUILD. The seat derives a public key from
 * the seed by a fixed transform and the signer signs over the key AND the
 * message, so a verdict depends on the bytes -- `chain.h` records that a stub
 * ignoring its message cannot see a signed-range bug, and every stub here
 * answers over the message. The real Monocypher seat is covered in
 * `chain/test/sign_monocypher_test.c`; what is tested here is the policy.
 *
 * THE STORE COUNTS WRITES, because the refusals that matter most are the ones
 * that must leave a store untouched, and "returned an error" says nothing
 * about whether it wrote first.
 */

#include "../identity.h"

#include <stdio.h>
#include <string.h>

#ifdef FZN_FLOG_ON
#include "flog.h"
#endif

static int failures;
static int checks;

static void check_at(int ok, int line, const char *what)
{
	checks++;
	if (!ok) {
		failures++;
		printf("  FAIL identity_test.c:%d: %s\n", line, what);
	}
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, (what))

/* ---- stub signer and seat, sharing one state ------------------------- */

struct stub_signer {
	uint8_t pubkey[FZN_PUBKEY_LEN];
	int armed;
};

static void derive_pub(const uint8_t seed[FZN_SIGN_SEED_LEN], uint8_t pub[FZN_PUBKEY_LEN])
{
	unsigned i;

	for (i = 0; i < FZN_PUBKEY_LEN; i++)
		pub[i] = (uint8_t)(seed[i] ^ 0x5cu ^ (uint8_t)i);
}

static void tag_of(const uint8_t pub[FZN_PUBKEY_LEN], const uint8_t *msg, size_t len,
                   uint8_t sig[FZN_SIG_LEN])
{
	uint32_t h = 2166136261u;
	size_t i;

	for (i = 0; i < FZN_PUBKEY_LEN; i++)
		h = (h ^ pub[i]) * 16777619u;
	for (i = 0; i < len; i++)
		h = (h ^ msg[i]) * 16777619u;
	for (i = 0; i < FZN_SIG_LEN; i++) {
		h = (h ^ (uint32_t)i) * 16777619u;
		sig[i] = (uint8_t)(h >> 24);
	}
}

static int stub_install(void *ctx, const uint8_t seed[FZN_SIGN_SEED_LEN],
                        uint8_t pubkey_out[FZN_PUBKEY_LEN])
{
	struct stub_signer *s = (struct stub_signer *)ctx;

	if (!s || !seed || !pubkey_out)
		return 0;
	derive_pub(seed, s->pubkey);
	memcpy(pubkey_out, s->pubkey, FZN_PUBKEY_LEN);
	s->armed = 1;
	return 1;
}

static int stub_sign(void *ctx, uint8_t sig[FZN_SIG_LEN], const uint8_t *msg, size_t len)
{
	struct stub_signer *s = (struct stub_signer *)ctx;

	if (!s || !s->armed)
		return 0;
	tag_of(s->pubkey, msg, len, sig);
	return 1;
}

static int stub_verify(void *ctx, const uint8_t pubkey[FZN_PUBKEY_LEN], const uint8_t *msg,
                       size_t len, const uint8_t sig[FZN_SIG_LEN])
{
	uint8_t want[FZN_SIG_LEN];

	(void)ctx;
	tag_of(pubkey, msg, len, want);
	return memcmp(want, sig, FZN_SIG_LEN) == 0;
}

/* ---- stub agree: public = secret ^ 0x33, persist_test's shape ------- */

static int stub_public(void *ctx, uint8_t out[FZN_AGREE_PUBLIC_LEN],
                       const uint8_t secret[FZN_AGREE_SECRET_LEN])
{
	unsigned i;

	(void)ctx;
	for (i = 0; i < FZN_AGREE_PUBLIC_LEN; i++)
		out[i] = (uint8_t)(secret[i] ^ 0x33u);
	return 1;
}

static int stub_agree(void *ctx, uint8_t out[FZN_AGREE_SHARED_LEN],
                      const uint8_t secret[FZN_AGREE_SECRET_LEN],
                      const uint8_t peer[FZN_AGREE_PUBLIC_LEN])
{
	unsigned i;

	(void)ctx;
	for (i = 0; i < FZN_AGREE_SHARED_LEN; i++)
		out[i] = (uint8_t)(secret[i] ^ peer[i]);
	return 1;
}

static const fzn_agree_ops_t AGREE = { stub_public, stub_agree, NULL };
static const fzn_hash_ops_t HASH; /* carried, never called by this module */

/* ---- stub random: a counter, or zeroes, or a refusal ----------------- */

struct stub_rng {
	uint8_t next;
	int zeroes;
	int refuse;
};

static int stub_fill(void *ctx, uint8_t *out, size_t len)
{
	struct stub_rng *r = (struct stub_rng *)ctx;
	size_t i;

	if (r->refuse)
		return 0;
	for (i = 0; i < len; i++)
		out[i] = r->zeroes ? 0u : (uint8_t)(++r->next | 1u);
	return 1;
}

/* ---- an in-memory store over the three whole-host slots -------------- */

struct mem_store {
	uint8_t blob[8][FZN_PERSIST_MAX];
	size_t len[8];
	int held[8];
	unsigned saves;
	int fail_save_slot;
	int fail_load_slot;
};

static int mem_load(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject, uint8_t *out,
                    size_t cap, size_t *len)
{
	struct mem_store *m = (struct mem_store *)ctx;

	(void)subject;
	if ((unsigned)slot >= 8u || (int)slot == m->fail_load_slot || !m->held[slot]
	    || m->len[slot] > cap)
		return 0;
	memcpy(out, m->blob[slot], m->len[slot]);
	*len = m->len[slot];
	return 1;
}

static int mem_save(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject,
                    const uint8_t *bytes, size_t len)
{
	struct mem_store *m = (struct mem_store *)ctx;

	(void)subject;
	if ((unsigned)slot >= 8u || (int)slot == m->fail_save_slot || len > FZN_PERSIST_MAX)
		return 0;
	memcpy(m->blob[slot], bytes, len);
	m->len[slot] = len;
	m->held[slot] = 1;
	m->saves++;
	return 1;
}

static void mem_init(struct mem_store *m)
{
	memset(m, 0, sizeof(*m));
	m->fail_save_slot = -1;
	m->fail_load_slot = -1;
}

static fzn_persist_err_t held(const struct mem_store *m, fzn_persist_slot_t slot)
{
	return m->held[slot] ? FZN_PERSIST_OK : FZN_PERSIST_ERR_ABSENT;
}

static fzn_node_identity_found_t found_in(const struct mem_store *m)
{
	fzn_node_identity_found_t f;

	f.seed = held(m, FZN_PERSIST_OWN_IDENTITY);
	f.prekey = held(m, FZN_PERSIST_OWN_PREKEY);
	f.trust = held(m, FZN_PERSIST_TRUST);
	return f;
}

/* ---- one node's worth of wiring --------------------------------------- */

struct rig {
	struct mem_store *store;
	fzn_persist_ops_t store_ops;
	struct stub_rng rng;
	fzn_random_ops_t rng_ops;
	struct stub_signer signer;
	fzn_sign_seat_t seat;
	fzn_sign_ops_t sign;
	fzn_node_identity_env_t env;
};

static void rig_init(struct rig *r, struct mem_store *store)
{
	memset(r, 0, sizeof(*r));
	r->store = store;
	r->store_ops.load = mem_load;
	r->store_ops.save = mem_save;
	r->store_ops.list = NULL;
	r->store_ops.ctx = store;
	r->rng_ops.fill = stub_fill;
	r->rng_ops.ctx = &r->rng;
	r->seat.install = stub_install;
	r->seat.ctx = &r->signer;
	r->sign.sign = stub_sign;
	r->sign.verify = stub_verify;
	r->sign.ctx = &r->signer;
	r->env.store = &r->store_ops;
	r->env.rng = &r->rng_ops;
	r->env.seat = &r->seat;
	r->env.sign = &r->sign;
	r->env.hash = &HASH;
	r->env.agree = &AGREE;
}

/* ---- the cases -------------------------------------------------------- */

static void test_a_first_boot_creates_a_self_rooted_node(struct mem_store *store,
                                                         uint8_t pub_out[FZN_PUBKEY_LEN],
                                                         uint8_t prekey_pub_out[FZN_AGREE_PUBLIC_LEN])
{
	struct rig r;
	fzn_agree_secret_t sk;
	fzn_trust_t trust;
	fzn_node_identity_t id;
	fzn_node_identity_found_t found;
	fzn_prekey_record_t record;
	int created = -1;

	mem_init(store);
	rig_init(&r, store);
	memset(&sk, 0, sizeof(sk));
	fzn_trust_init(&trust);
	memset(&id, 0, sizeof(id));
	found = found_in(store);

	CHECK(fzn_node_identity_boot(&r.env, &found, 1000u, &sk, &trust, &id, &created)
	              == FZN_NODE_IDENTITY_OK,
	      "an empty store did not boot");
	CHECK(created == 1, "an empty store booted without saying it created a node");
	CHECK(store->saves == 3u && store->held[FZN_PERSIST_OWN_IDENTITY]
	              && store->held[FZN_PERSIST_OWN_PREKEY] && store->held[FZN_PERSIST_TRUST],
	      "a first boot did not store all three parts");

	/* THE ANCHOR NAMES THIS NODE, AND SAYS IT IS A SELF-ROOT. */
	CHECK(fzn_trust_source_of(&trust) == FZN_TRUST_SELF,
	      "a new node is not self-rooted, so joining an estate is an attack");
	CHECK(fzn_trust_root(&trust) != NULL
	              && memcmp(fzn_trust_root(&trust), id.pubkey, FZN_PUBKEY_LEN) == 0,
	      "a new node's self-root is not its own key");
	CHECK(memcmp(id.pubkey, r.signer.pubkey, FZN_PUBKEY_LEN) == 0,
	      "the identity reports a key the signer does not sign as");

	/* ITS PREKEY RECORD IS SIGNED BY IT AND CARRIES ITS AGREE KEY. */
	CHECK(fzn_prekey_open(id.prekey_record, FZN_PREKEY_LEN_TOTAL, &record) == FZN_PREKEY_OK
	              && fzn_prekey_verify(record, &r.sign) == FZN_PREKEY_OK,
	      "the new node's prekey record does not verify");
	CHECK(memcmp(record.host, id.pubkey, FZN_PUBKEY_LEN) == 0
	              && memcmp(record.prekey, fzn_agree_secret_public(&sk),
	                        FZN_AGREE_PUBLIC_LEN) == 0
	              && record.created_at == 1000u,
	      "the prekey record names another host, another key, or another time");
	CHECK(id.agree_secret == &sk && id.sign == &r.sign && id.hash == &HASH
	              && id.agree == &AGREE,
	      "the identity does not point at the caller's secret and the env's ops");

	memcpy(pub_out, id.pubkey, FZN_PUBKEY_LEN);
	memcpy(prekey_pub_out, fzn_agree_secret_public(&sk), FZN_AGREE_PUBLIC_LEN);
	fzn_agree_secret_wipe(&sk);
}

static void test_a_second_boot_is_the_same_node(struct mem_store *store,
                                                const uint8_t pub[FZN_PUBKEY_LEN],
                                                const uint8_t prekey_pub[FZN_AGREE_PUBLIC_LEN])
{
	struct rig r;
	fzn_agree_secret_t sk;
	fzn_trust_t trust;
	fzn_node_identity_t id;
	fzn_node_identity_found_t found;
	int created = -1;
	unsigned saves = store->saves;

	/* A FRESH RIG: a new process, a signer holding nothing, a random
	 * source that would produce a different node if it were asked. */
	rig_init(&r, store);
	r.rng.next = 0x90u;
	memset(&sk, 0, sizeof(sk));
	fzn_trust_init(&trust);
	found = found_in(store);

	CHECK(fzn_node_identity_boot(&r.env, &found, 2000u, &sk, &trust, &id, &created)
	              == FZN_NODE_IDENTITY_OK,
	      "a complete store did not boot");
	CHECK(created == 0, "a complete store was reported as a new node");
	CHECK(store->saves == saves, "loading an identity wrote to the store");
	CHECK(memcmp(id.pubkey, pub, FZN_PUBKEY_LEN) == 0,
	      "the restarted node has a different identity");
	CHECK(memcmp(fzn_agree_secret_public(&sk), prekey_pub, FZN_AGREE_PUBLIC_LEN) == 0,
	      "the restarted node has a different prekey, so queued traffic is lost");
	CHECK(fzn_trust_source_of(&trust) == FZN_TRUST_SELF,
	      "the self-root came back as something else");
	fzn_agree_secret_wipe(&sk);
}

static void test_a_partial_store_is_refused_untouched(const struct mem_store *complete)
{
	static const fzn_persist_slot_t SLOTS[3] = { FZN_PERSIST_OWN_IDENTITY,
		                                     FZN_PERSIST_OWN_PREKEY,
		                                     FZN_PERSIST_TRUST };
	unsigned i;

	/* EACH PART MISSING IN TURN, and the one that matters is the anchor:
	 * self-rooting a node that had joined an estate would drop it out
	 * silently. */
	for (i = 0; i < 3u; i++) {
		struct mem_store store;
		struct rig r;
		fzn_agree_secret_t sk;
		fzn_trust_t trust;
		fzn_node_identity_t id;
		fzn_node_identity_found_t found;
		int created = -1;

		store = *complete;
		store.saves = 0;
		store.held[SLOTS[i]] = 0;
		rig_init(&r, &store);
		memset(&sk, 0, sizeof(sk));
		fzn_trust_init(&trust);
		found = found_in(&store);
		CHECK(fzn_node_identity_boot(&r.env, &found, 3000u, &sk, &trust, &id, &created)
		              == FZN_NODE_IDENTITY_PARTIAL,
		      "a store missing one part was not refused as partial");
		CHECK(store.saves == 0u, "a partial store was written to");
		CHECK(created == 0, "a refused boot reported a new node");
	}
}

static void test_could_not_tell_is_not_a_first_run(void)
{
	struct mem_store store;
	struct rig r;
	fzn_agree_secret_t sk;
	fzn_trust_t trust;
	fzn_node_identity_t id;
	fzn_node_identity_found_t found;
	int created = -1;

	/* The store is EMPTY, so a boot that took BACKEND for ABSENT would
	 * create -- and on a real disk that briefly could not be read, would
	 * create over a live identity. */
	mem_init(&store);
	rig_init(&r, &store);
	memset(&sk, 0, sizeof(sk));
	fzn_trust_init(&trust);
	found = found_in(&store);
	found.prekey = FZN_PERSIST_ERR_BACKEND;
	CHECK(fzn_node_identity_boot(&r.env, &found, 1u, &sk, &trust, &id, &created)
	              == FZN_NODE_IDENTITY_STORE,
	      "a part the store could not answer for was taken as absent");
	CHECK(store.saves == 0u, "a store that could not answer was written to");
}

static void test_a_self_root_for_another_key_is_refused(const struct mem_store *complete)
{
	struct mem_store store = *complete;
	struct rig r;
	fzn_agree_secret_t sk, sk_before;
	fzn_trust_t trust, other, trust_before;
	fzn_node_identity_t id;
	uint8_t someone[FZN_PUBKEY_LEN];
	size_t len = 0;

	memset(someone, 0x77, sizeof(someone));
	fzn_trust_init(&other);
	CHECK(fzn_trust_self(&other, someone) == FZN_TRUST_OK, "fixture");
	CHECK(fzn_persist_trust_pack(&other, store.blob[FZN_PERSIST_TRUST], FZN_PERSIST_MAX, &len)
	              == FZN_PERSIST_OK,
	      "fixture");
	store.len[FZN_PERSIST_TRUST] = len;

	rig_init(&r, &store);
	/* SENTINELS, so "a refused load leaves the caller's structs alone" is
	 * asserted rather than assumed. */
	memset(&sk, 0xa5, sizeof(sk));
	memset(&trust, 0x5a, sizeof(trust));
	sk_before = sk;
	trust_before = trust;
	CHECK(fzn_node_identity_load(&r.env, 1u, &sk, &trust, &id) == FZN_NODE_IDENTITY_MISMATCH,
	      "a store self-rooted to somebody else's key loaded as this node");
	CHECK(memcmp(&sk, &sk_before, sizeof(sk)) == 0
	              && memcmp(&trust, &trust_before, sizeof(trust)) == 0,
	      "a refused load wrote the caller's secret or anchor");

	/* A JOINED NODE IS NOT A MISMATCH: a pinned root is somebody else's
	 * by design. */
	fzn_trust_init(&other);
	CHECK(fzn_trust_pin(&other, someone) == FZN_TRUST_OK, "fixture");
	CHECK(fzn_persist_trust_pack(&other, store.blob[FZN_PERSIST_TRUST], FZN_PERSIST_MAX, &len)
	              == FZN_PERSIST_OK,
	      "fixture");
	memset(&sk, 0, sizeof(sk));
	fzn_trust_init(&trust);
	CHECK(fzn_node_identity_load(&r.env, 1u, &sk, &trust, &id) == FZN_NODE_IDENTITY_OK,
	      "a node pinned into an estate would not load");
	CHECK(fzn_trust_source_of(&trust) == FZN_TRUST_PINNED
	              && memcmp(fzn_trust_root(&trust), someone, FZN_PUBKEY_LEN) == 0,
	      "the estate's root did not come back as the anchor");
	fzn_agree_secret_wipe(&sk);
}

static void test_a_signer_that_is_not_the_seated_one_is_refused(const struct mem_store *complete)
{
	struct mem_store store = *complete;
	struct rig r;
	struct stub_signer stranger;
	fzn_agree_secret_t sk;
	fzn_trust_t trust;
	fzn_node_identity_t id;
	uint8_t seed[FZN_SIGN_SEED_LEN];

	/* `sign` pointed at an ARMED signer that is not the one `seat` arms:
	 * the record would name one key and carry another's signature. */
	rig_init(&r, &store);
	memset(seed, 0x42, sizeof(seed));
	memset(&stranger, 0, sizeof(stranger));
	(void)stub_install(&stranger, seed, stranger.pubkey);
	r.sign.ctx = &stranger;
	memset(&sk, 0, sizeof(sk));
	fzn_trust_init(&trust);
	CHECK(fzn_node_identity_load(&r.env, 1u, &sk, &trust, &id) == FZN_NODE_IDENTITY_CRYPTO,
	      "an identity whose signer is not its seated key was accepted");
}

static void test_creation_writes_nothing_until_it_can_write_everything(void)
{
	struct mem_store store;
	struct rig r;
	fzn_agree_secret_t sk;
	fzn_trust_t trust;
	fzn_node_identity_t id;
	fzn_node_identity_found_t found;
	int created = -1;

	/* A RANDOM SOURCE OF ZEROES yields the key everybody holds, which the
	 * seed's pack refuses -- so nothing may be on disk afterwards. */
	mem_init(&store);
	rig_init(&r, &store);
	r.rng.zeroes = 1;
	memset(&sk, 0, sizeof(sk));
	fzn_trust_init(&trust);
	CHECK(fzn_node_identity_create(&r.env, 1u, &sk, &trust, &id) == FZN_NODE_IDENTITY_CRYPTO,
	      "a node was created from an all-zero seed");
	CHECK(store.saves == 0u, "a refused creation wrote part of an identity");

	mem_init(&store);
	rig_init(&r, &store);
	r.rng.refuse = 1;
	CHECK(fzn_node_identity_create(&r.env, 1u, &sk, &trust, &id) == FZN_NODE_IDENTITY_CRYPTO
	              && store.saves == 0u,
	      "a refusing random source created something");

	/* A SAVE THAT FAILS PART WAY leaves a partial store, and the next boot
	 * must refuse it by name rather than repair it. The anchor is saved
	 * last, so this is the identity-without-anchor case. */
	mem_init(&store);
	rig_init(&r, &store);
	store.fail_save_slot = (int)FZN_PERSIST_TRUST;
	CHECK(fzn_node_identity_create(&r.env, 1u, &sk, &trust, &id) == FZN_NODE_IDENTITY_STORE,
	      "a failed save was reported as a created node");
	CHECK(store.held[FZN_PERSIST_OWN_IDENTITY] && !store.held[FZN_PERSIST_TRUST],
	      "the seed was not saved before the anchor");
	store.fail_save_slot = -1;
	found = found_in(&store);
	CHECK(fzn_node_identity_boot(&r.env, &found, 2u, &sk, &trust, &id, &created)
	              == FZN_NODE_IDENTITY_PARTIAL,
	      "the store a failed creation left was not refused as partial");
}

static void test_a_stored_part_that_will_not_open(const struct mem_store *complete)
{
	struct mem_store store = *complete;
	struct rig r;
	fzn_agree_secret_t sk;
	fzn_trust_t trust;
	fzn_node_identity_t id;

	rig_init(&r, &store);
	memset(&sk, 0, sizeof(sk));
	fzn_trust_init(&trust);
	memset(store.blob[FZN_PERSIST_OWN_IDENTITY] + 2, 0, FZN_SIGN_SEED_LEN);
	CHECK(fzn_node_identity_load(&r.env, 1u, &sk, &trust, &id) == FZN_NODE_IDENTITY_SHAPE,
	      "a stored all-zero seed loaded");

	store = *complete;
	store.fail_load_slot = (int)FZN_PERSIST_OWN_PREKEY;
	CHECK(fzn_node_identity_load(&r.env, 1u, &sk, &trust, &id) == FZN_NODE_IDENTITY_STORE,
	      "a load the store refused was not reported as the store's");
}

static void test_the_guards(void)
{
	struct mem_store store;
	struct rig r;
	fzn_agree_secret_t sk;
	fzn_trust_t trust;
	fzn_node_identity_t id;
	fzn_node_identity_found_t found;
	int created = 0;

	mem_init(&store);
	rig_init(&r, &store);
	found = found_in(&store);
	CHECK(fzn_node_identity_load(NULL, 1u, &sk, &trust, &id) == FZN_NODE_IDENTITY_MALFORMED
	              && fzn_node_identity_create(&r.env, 1u, NULL, &trust, &id)
	                         == FZN_NODE_IDENTITY_MALFORMED
	              && fzn_node_identity_boot(&r.env, NULL, 1u, &sk, &trust, &id, &created)
	                         == FZN_NODE_IDENTITY_MALFORMED
	              && fzn_node_identity_boot(&r.env, &found, 1u, &sk, &trust, &id, NULL)
	                         == FZN_NODE_IDENTITY_MALFORMED,
	      "a null argument was accepted");
	r.env.seat = NULL;
	CHECK(fzn_node_identity_create(&r.env, 1u, &sk, &trust, &id) == FZN_NODE_IDENTITY_MALFORMED
	              && store.saves == 0u,
	      "an env with no seat was accepted -- a key that cannot be seated is a "
	      "caller's to report, not this module's to work around");
	CHECK(strcmp(fzn_node_identity_err_str(FZN_NODE_IDENTITY_PARTIAL),
	             fzn_node_identity_err_str(FZN_NODE_IDENTITY_STORE)) != 0,
	      "two refusals share a sentence");
}

#ifdef FZN_FLOG_ON
static struct {
	int calls;
	int type;
	char subsystem[64];
} seen;

static int capture(flog_t *p, const flog_msg_t *m)
{
	(void)p;
	seen.calls++;
	seen.type = m->type;
	seen.subsystem[0] = '\0';
	if (m->subsystem)
		snprintf(seen.subsystem, sizeof(seen.subsystem), "%s", m->subsystem);
	return 0;
}

/* A NEW IDENTITY IS REPORTED, AND SO IS A REFUSED ONE. The creation is a
 * note, not an error -- every first run makes one -- and the refusal is an
 * error, because a node that will not start needs to say why. */
static void test_creation_and_refusal_are_reported(void)
{
	struct mem_store store;
	struct rig r;
	fzn_agree_secret_t sk;
	fzn_trust_t trust;
	fzn_node_identity_t id;
	fzn_node_identity_found_t found;
	flog_t diag;
	int created = 0;

	init_flog_t(&diag);
	diag.name = NULL;
	diag.accepted_msg_type = FLOG_ACCEPT_ALL;
	diag.output_func = capture;

	mem_init(&store);
	rig_init(&r, &store);
	r.env.log = &diag;
	memset(&sk, 0, sizeof(sk));
	fzn_trust_init(&trust);
	memset(&seen, 0, sizeof(seen));
	found = found_in(&store);
	CHECK(fzn_node_identity_boot(&r.env, &found, 1u, &sk, &trust, &id, &created)
	              == FZN_NODE_IDENTITY_OK,
	      "fixture: an empty store did not boot");
	CHECK(seen.calls == 1 && seen.type == FLOG_NOTE
	              && strcmp(seen.subsystem, "node/identity") == 0,
	      "creating a new identity was not reported as a note under node/identity");

	store.held[FZN_PERSIST_TRUST] = 0;
	memset(&seen, 0, sizeof(seen));
	found = found_in(&store);
	CHECK(fzn_node_identity_boot(&r.env, &found, 2u, &sk, &trust, &id, &created)
	              == FZN_NODE_IDENTITY_PARTIAL,
	      "fixture: a partial store booted");
	CHECK(seen.calls == 1 && seen.type == FLOG_ERR
	              && strcmp(seen.subsystem, "node/identity") == 0,
	      "a partial store was refused without an error under node/identity");
	fzn_agree_secret_wipe(&sk);
}
#endif

int main(void)
{
	static struct mem_store complete;
	uint8_t pub[FZN_PUBKEY_LEN], prekey_pub[FZN_AGREE_PUBLIC_LEN];

	test_a_first_boot_creates_a_self_rooted_node(&complete, pub, prekey_pub);
	test_a_second_boot_is_the_same_node(&complete, pub, prekey_pub);
	test_a_partial_store_is_refused_untouched(&complete);
	test_could_not_tell_is_not_a_first_run();
	test_a_self_root_for_another_key_is_refused(&complete);
	test_a_signer_that_is_not_the_seated_one_is_refused(&complete);
	test_creation_writes_nothing_until_it_can_write_everything();
	test_a_stored_part_that_will_not_open(&complete);
	test_the_guards();
#ifdef FZN_FLOG_ON
	test_creation_and_refusal_are_reported();
#endif

	printf("identity_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
