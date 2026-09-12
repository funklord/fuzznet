/*
 * A fuzz harness for session/session.c: one root per pair, from either side.
 *
 * WHAT session.h CLAIMS, read as three sentences. The base root is a function
 * of the UNORDERED pair {(identity, prekey), (identity, prekey)} -- "the
 * OUTPUT does not depend on which is which; that is the property". The
 * ephemeral root is a function of the ORDERED pair plus the ephemeral, so
 * swapping the roles changes it. And the two chain keys are DIRECTED: A's
 * send chain is B's receive chain, and neither is the other.
 *
 * THE ORACLE IS A BIJECTION, held as a table. Every derivation is filed
 * under a descriptor -- version, the two hosts in canonical order for v1 or
 * in role order for v2, and the ephemeral public key where there is one --
 * and the table is checked both ways. Two descriptors with one key are two
 * sessions become one, which is a peer reading traffic sealed for another.
 * One descriptor with two keys is a side that cannot talk to the other. The
 * descriptor is the header's statement of what the root depends on; it is
 * not the transcript's layout, which `session_kat_test` pins.
 *
 * THE IDENTITIES SHARE PREFIXES, deliberately. The canonical order is a
 * memcmp over thirty-two bytes, and `session_test` sorts identities that
 * differ in their first byte. A sort that read only the first few bytes
 * would tie on identities that agree that far, resolve the tie by which host
 * is asking, and derive two roots for one pair -- and no fixed fixture with
 * distinct first bytes can reach that. Here the two identities in a pair
 * agree for a random number of leading bytes, up to thirty-one.
 *
 * WHAT A BIJECTION CANNOT SEE, measured by sabotage so nobody quotes this
 * file for it: a field the transcript carries REDUNDANTLY. Drop a host's
 * prekey public from the base transcript and the root still changes with
 * every rotation, because the shared secret changed; drop the ephemeral
 * shared secret from v2 and the ephemeral public still separates sessions.
 * Both survived here and both are caught by `session_test`, which checks
 * that every input byte reaches the transcript, and by `session_kat_test`,
 * which pins the layout. A field being in the hash and a field being the
 * only thing that distinguishes two sessions are different properties, and
 * this harness holds the second.
 *
 * REFUSALS ARE PART OF THE MODEL. A session with yourself, an agreement that
 * refuses on the first or the second exchange, a hash that refuses: each
 * must leave the caller's buffers holding what they held, because a wiped
 * buffer looks like a key and an untouched one does not. The chains are the
 * exception and the header says so: a refused chain is wiped, and one
 * chain without the other is wiped too.
 */

#include "../session.h"
#include "../../constant_time/constant_time.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FUZZ_DEFAULT_CASES 20000u
#define FUZZ_MIN_CASES 1000u

#define HOSTS 4u
#define STEPS 12u
#define TABLE 64u
#define DESC_MAX (1u + (2u * (FZN_SESSION_IDENTITY_LEN + FZN_AGREE_PUBLIC_LEN)) \
                  + FZN_AGREE_PUBLIC_LEN)

static int stub_hash(void *ctx, uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len)
{
	uint64_t h = 0xcbf29ce484222325ull;
	size_t i;

	(void)ctx;
	h ^= (uint64_t)out_len;
	h *= 0x100000001b3ull;
	for (i = 0; i < in_len; i++) {
		h ^= in[i];
		h *= 0x100000001b3ull;
	}
	for (i = 0; i < out_len; i++) {
		h ^= (uint64_t)i + 0x9e3779b97f4a7c15ull;
		h *= 0x100000001b3ull;
		out[i] = (uint8_t)(h >> 32);
	}
	return 1;
}

/* Commutative toy agreement, as session_test's: the shared secret is the
 * XOR of the two secrets, so both sides reach it and the transcript is what
 * is on trial rather than X25519. */
static int stub_public_of(void *ctx, uint8_t out[FZN_AGREE_PUBLIC_LEN],
                          const uint8_t secret[FZN_AGREE_SECRET_LEN])
{
	unsigned i;

	(void)ctx;
	for (i = 0; i < FZN_AGREE_PUBLIC_LEN; i++)
		out[i] = (uint8_t)(secret[i] ^ 0x3cu);
	return 1;
}

static int stub_agree(void *ctx, uint8_t out[FZN_AGREE_SHARED_LEN],
                      const uint8_t secret[FZN_AGREE_SECRET_LEN],
                      const uint8_t peer[FZN_AGREE_PUBLIC_LEN])
{
	unsigned i;

	(void)ctx;
	for (i = 0; i < FZN_AGREE_SHARED_LEN; i++)
		out[i] = (uint8_t)(secret[i] ^ (peer[i] ^ 0x3cu));
	return 1;
}

/* THE REFUSING SEAMS WRITE BEFORE THEY REFUSE, as session_test argues a real
 * binding does: a stub that refuses without writing leaves nothing for the
 * code under test to have to not hand back. `fail_on` is 1-based over calls
 * since the counter was armed; zero never refuses. */
static unsigned agree_calls, agree_fail_on;
static unsigned hash_calls, hash_fail_on;

static int counted_agree(void *ctx, uint8_t out[FZN_AGREE_SHARED_LEN],
                         const uint8_t secret[FZN_AGREE_SECRET_LEN],
                         const uint8_t peer[FZN_AGREE_PUBLIC_LEN])
{
	agree_calls++;
	(void)stub_agree(ctx, out, secret, peer);
	if (agree_fail_on != 0u && agree_calls == agree_fail_on) {
		memset(out, 0x5e, FZN_AGREE_SHARED_LEN);
		return 0;
	}
	return 1;
}

static int counted_hash(void *ctx, uint8_t *out, size_t out_len, const uint8_t *in,
                        size_t in_len)
{
	hash_calls++;
	(void)stub_hash(ctx, out, out_len, in, in_len);
	if (hash_fail_on != 0u && hash_calls == hash_fail_on)
		return 0;
	return 1;
}

static const fzn_hash_ops_t HASH = { counted_hash, NULL };
static const fzn_agree_ops_t AGREE = { stub_public_of, counted_agree, NULL };

static void arm(unsigned agree_on, unsigned hash_on)
{
	agree_calls = 0u;
	agree_fail_on = agree_on;
	hash_calls = 0u;
	hash_fail_on = hash_on;
}

struct host {
	uint8_t identity[FZN_SESSION_IDENTITY_LEN];
	fzn_agree_secret_t prekey;
};

struct seen {
	uint8_t key[FZN_AEAD_KEY_LEN];
	uint8_t ck[FZN_COMMITMENT_KEY_LEN];
	uint8_t desc[DESC_MAX];
	size_t desc_len;
};

struct chain_seen {
	uint8_t chain[FZN_CHAIN_KEY_LEN];
	uint8_t from[FZN_SESSION_IDENTITY_LEN];
	uint8_t to[FZN_SESSION_IDENTITY_LEN];
	uint8_t key[FZN_AEAD_KEY_LEN];
};

struct coverage {
	unsigned long base;
	unsigned long base_deep_order; /* identities agreeing on 16+ leading bytes */
	unsigned long ephemeral;
	unsigned long roles_swapped;
	unsigned long rotated;
	unsigned long revisited; /* a descriptor already in the table */
	unsigned long chains;
	unsigned long refused_self;
	unsigned long refused_agree_first;
	unsigned long refused_agree_second;
	unsigned long refused_hash;
	unsigned long refused_chain_first;
	unsigned long refused_chain_second;
};

static uint32_t next(uint32_t *state)
{
	*state ^= *state << 13;
	*state ^= *state >> 17;
	*state ^= *state << 5;
	return *state;
}

static void fill(uint32_t *rng, uint8_t *p, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		p[i] = (uint8_t)next(rng);
}

static int rotate(uint32_t *rng, struct host *h)
{
	uint8_t secret[FZN_AGREE_SECRET_LEN];

	fill(rng, secret, sizeof(secret));
	return fzn_agree_secret_install(&h->prekey, &AGREE, secret) == FZN_AGREE_OK;
}

/* Identities that agree on `share` leading bytes and differ at the next,
 * so that the canonical order has to read that far. */
static void mint_hosts(uint32_t *rng, struct host *hosts, unsigned share)
{
	uint8_t common[FZN_SESSION_IDENTITY_LEN];
	unsigned h;

	fill(rng, common, sizeof(common));
	for (h = 0; h < HOSTS; h++) {
		memcpy(hosts[h].identity, common, share);
		hosts[h].identity[share] = (uint8_t)(common[share] + 1u + h);
		fill(rng, hosts[h].identity + share + 1u,
		     FZN_SESSION_IDENTITY_LEN - share - 1u);
		memset(&hosts[h].prekey, 0, sizeof(hosts[h].prekey));
	}
}

static const uint8_t *pub(const struct host *h)
{
	return fzn_agree_secret_public(&h->prekey);
}

/* Files a (descriptor, key) pair and checks the table both ways. */
static int file_root(struct seen *table, unsigned *used, const uint8_t *desc, size_t desc_len,
                     const uint8_t *key, const uint8_t *ck, const char *what,
                     struct coverage *cov)
{
	unsigned i;

	for (i = 0; i < *used; i++) {
		int same_desc = table[i].desc_len == desc_len
		                && memcmp(table[i].desc, desc, desc_len) == 0;
		int same_key = memcmp(table[i].key, key, FZN_AEAD_KEY_LEN) == 0
		               && memcmp(table[i].ck, ck, FZN_COMMITMENT_KEY_LEN) == 0;

		if (same_desc && same_key) {
			cov->revisited++;
			return 0;
		}
		if (same_desc) {
			printf("  MODEL: %s derived two different roots for one session\n", what);
			return 1;
		}
		if (same_key) {
			printf("  MODEL: %s derived one root for two different sessions\n", what);
			return 1;
		}
		if (memcmp(table[i].key, key, FZN_AEAD_KEY_LEN) == 0
		    || memcmp(table[i].ck, ck, FZN_COMMITMENT_KEY_LEN) == 0) {
			printf("  MODEL: %s shares half a root with another session\n", what);
			return 1;
		}
	}
	if (*used < TABLE) {
		memcpy(table[*used].key, key, FZN_AEAD_KEY_LEN);
		memcpy(table[*used].ck, ck, FZN_COMMITMENT_KEY_LEN);
		memcpy(table[*used].desc, desc, desc_len);
		table[*used].desc_len = desc_len;
		(*used)++;
	}
	return 0;
}

static size_t describe_base(uint8_t *desc, const struct host *a, const struct host *b)
{
	const struct host *lo = a;
	const struct host *hi = b;
	size_t at = 0;

	if (memcmp(a->identity, b->identity, FZN_SESSION_IDENTITY_LEN) > 0) {
		lo = b;
		hi = a;
	}
	desc[at++] = 1u;
	memcpy(desc + at, lo->identity, FZN_SESSION_IDENTITY_LEN);
	at += FZN_SESSION_IDENTITY_LEN;
	memcpy(desc + at, pub(lo), FZN_AGREE_PUBLIC_LEN);
	at += FZN_AGREE_PUBLIC_LEN;
	memcpy(desc + at, hi->identity, FZN_SESSION_IDENTITY_LEN);
	at += FZN_SESSION_IDENTITY_LEN;
	memcpy(desc + at, pub(hi), FZN_AGREE_PUBLIC_LEN);
	at += FZN_AGREE_PUBLIC_LEN;
	return at;
}

static size_t describe_v2(uint8_t *desc, const struct host *init, const struct host *resp,
                          const uint8_t *eph_pub)
{
	size_t at = 0;

	desc[at++] = 2u;
	memcpy(desc + at, init->identity, FZN_SESSION_IDENTITY_LEN);
	at += FZN_SESSION_IDENTITY_LEN;
	memcpy(desc + at, pub(init), FZN_AGREE_PUBLIC_LEN);
	at += FZN_AGREE_PUBLIC_LEN;
	memcpy(desc + at, resp->identity, FZN_SESSION_IDENTITY_LEN);
	at += FZN_SESSION_IDENTITY_LEN;
	memcpy(desc + at, pub(resp), FZN_AGREE_PUBLIC_LEN);
	at += FZN_AGREE_PUBLIC_LEN;
	memcpy(desc + at, eph_pub, FZN_AGREE_PUBLIC_LEN);
	at += FZN_AGREE_PUBLIC_LEN;
	return at;
}

static int untouched(const uint8_t *buf, const uint8_t *before, size_t n, const char *what)
{
	if (memcmp(buf, before, n) != 0) {
		printf("  MODEL: %s wrote into the caller's buffer on refusal\n", what);
		return 0;
	}
	return 1;
}

static int is_zero(const uint8_t *buf, size_t n)
{
	size_t i;
	uint8_t acc = 0;

	for (i = 0; i < n; i++)
		acc |= buf[i];
	return acc == 0u;
}

/* Both directions from both sides, against the chain table. */
static int check_chains(uint32_t *rng, struct chain_seen *ctable, unsigned *cused,
                        const struct host *a, const struct host *b, const uint8_t *key,
                        struct coverage *cov)
{
	uint8_t a_send[FZN_CHAIN_KEY_LEN], a_recv[FZN_CHAIN_KEY_LEN];
	uint8_t b_send[FZN_CHAIN_KEY_LEN], b_recv[FZN_CHAIN_KEY_LEN];
	uint8_t before_send[FZN_CHAIN_KEY_LEN], before_recv[FZN_CHAIN_KEY_LEN];
	unsigned fail = next(rng) % 8u; /* 1 or 2 refuse; the rest derive */
	unsigned i;

	if (fail == 1u || fail == 2u) {
		fill(rng, before_send, sizeof(before_send));
		fill(rng, before_recv, sizeof(before_recv));
		memcpy(a_send, before_send, sizeof(a_send));
		memcpy(a_recv, before_recv, sizeof(a_recv));
		arm(0u, fail);
		if (fzn_session_chains(&HASH, key, a->identity, b->identity, a_send, a_recv)
		    != FZN_SESSION_ERR_HASH) {
			printf("  MODEL: a refused chain derivation did not say HASH\n");
			return 1;
		}
		if (!is_zero(a_send, sizeof(a_send))) {
			printf("  MODEL: a refused chain derivation handed back a send chain\n");
			return 1;
		}
		if (fail == 1u) {
			if (!untouched(a_recv, before_recv, sizeof(a_recv), "chains (first refused)"))
				return 1;
			cov->refused_chain_first++;
		} else {
			if (!is_zero(a_recv, sizeof(a_recv))) {
				printf("  MODEL: a refused second chain was handed back\n");
				return 1;
			}
			cov->refused_chain_second++;
		}
		return 0;
	}

	arm(0u, 0u);
	if (fzn_session_chains(&HASH, key, a->identity, b->identity, a_send, a_recv)
	    != FZN_SESSION_OK
	    || fzn_session_chains(&HASH, key, b->identity, a->identity, b_send, b_recv)
	    != FZN_SESSION_OK) {
		printf("  MODEL: a chain derivation refused with nothing refusing\n");
		return 1;
	}
	if (memcmp(a_send, b_recv, FZN_CHAIN_KEY_LEN) != 0
	    || memcmp(a_recv, b_send, FZN_CHAIN_KEY_LEN) != 0) {
		printf("  MODEL: the two sides disagree about a direction's chain\n");
		return 1;
	}
	if (memcmp(a_send, a_recv, FZN_CHAIN_KEY_LEN) == 0) {
		printf("  MODEL: the two directions share a chain -- a replay decrypts\n");
		return 1;
	}
	if (memcmp(a_send, key, FZN_CHAIN_KEY_LEN) == 0
	    || memcmp(a_recv, key, FZN_CHAIN_KEY_LEN) == 0) {
		printf("  MODEL: a chain key is the session key\n");
		return 1;
	}
	for (i = 0; i < *cused; i++) {
		int same_chain = memcmp(ctable[i].chain, a_send, FZN_CHAIN_KEY_LEN) == 0;
		int same_desc = memcmp(ctable[i].from, a->identity, FZN_SESSION_IDENTITY_LEN) == 0
		                && memcmp(ctable[i].to, b->identity, FZN_SESSION_IDENTITY_LEN) == 0
		                && memcmp(ctable[i].key, key, FZN_AEAD_KEY_LEN) == 0;

		if (same_chain != same_desc) {
			printf("  MODEL: a chain key %s\n",
			       same_chain ? "is shared by two directions or two sessions"
			                  : "changed for the same direction and session");
			return 1;
		}
	}
	if (*cused < TABLE) {
		memcpy(ctable[*cused].chain, a_send, FZN_CHAIN_KEY_LEN);
		memcpy(ctable[*cused].from, a->identity, FZN_SESSION_IDENTITY_LEN);
		memcpy(ctable[*cused].to, b->identity, FZN_SESSION_IDENTITY_LEN);
		memcpy(ctable[*cused].key, key, FZN_AEAD_KEY_LEN);
		(*cused)++;
	}
	cov->chains++;
	return 0;
}

static int base_session(uint32_t *rng, struct seen *table, unsigned *used,
                        struct chain_seen *ctable, unsigned *cused, const struct host *a,
                        const struct host *b, unsigned share, struct coverage *cov)
{
	uint8_t ka[FZN_AEAD_KEY_LEN], cka[FZN_COMMITMENT_KEY_LEN];
	uint8_t kb[FZN_AEAD_KEY_LEN], ckb[FZN_COMMITMENT_KEY_LEN];
	uint8_t before_k[FZN_AEAD_KEY_LEN], before_ck[FZN_COMMITMENT_KEY_LEN];
	uint8_t desc[DESC_MAX];
	size_t desc_len;
	unsigned refuse = next(rng) % 10u;
	fzn_session_err_t err;

	if (refuse < 2u) {
		fill(rng, before_k, sizeof(before_k));
		fill(rng, before_ck, sizeof(before_ck));
		memcpy(ka, before_k, sizeof(ka));
		memcpy(cka, before_ck, sizeof(cka));
		arm(refuse == 0u ? 1u : 0u, refuse == 1u ? 1u : 0u);
		err = fzn_session_establish(&a->prekey, &AGREE, &HASH, a->identity, b->identity,
		                            pub(b), ka, cka);
		if (err != (refuse == 0u ? FZN_SESSION_ERR_AGREE : FZN_SESSION_ERR_HASH)) {
			printf("  MODEL: a refused base session answered %s\n",
			       fzn_session_err_str(err));
			return 1;
		}
		if (!untouched(ka, before_k, sizeof(ka), "base establish")
		    || !untouched(cka, before_ck, sizeof(cka), "base establish"))
			return 1;
		if (refuse == 0u)
			cov->refused_agree_first++;
		else
			cov->refused_hash++;
		return 0;
	}

	arm(0u, 0u);
	if (fzn_session_establish(&a->prekey, &AGREE, &HASH, a->identity, b->identity, pub(b),
	                          ka, cka) != FZN_SESSION_OK
	    || fzn_session_establish(&b->prekey, &AGREE, &HASH, b->identity, a->identity,
	                             pub(a), kb, ckb) != FZN_SESSION_OK) {
		printf("  MODEL: a base session refused with nothing refusing\n");
		return 1;
	}
	if (memcmp(ka, kb, sizeof(ka)) != 0 || memcmp(cka, ckb, sizeof(cka)) != 0) {
		printf("  MODEL: the two sides of a base session derived different roots "
		       "(identities agree on %u leading bytes)\n", share);
		return 1;
	}
	desc_len = describe_base(desc, a, b);
	if (file_root(table, used, desc, desc_len, ka, cka, "the base session", cov))
		return 1;
	cov->base++;
	if (share >= 16u)
		cov->base_deep_order++;
	return check_chains(rng, ctable, cused, a, b, ka, cov);
}

static int ephemeral_session(uint32_t *rng, struct seen *table, unsigned *used,
                             struct chain_seen *ctable, unsigned *cused, const struct host *init,
                             const struct host *resp, struct coverage *cov)
{
	fzn_agree_secret_t eph;
	uint8_t secret[FZN_AGREE_SECRET_LEN];
	uint8_t ki[FZN_AEAD_KEY_LEN], cki[FZN_COMMITMENT_KEY_LEN];
	uint8_t kr[FZN_AEAD_KEY_LEN], ckr[FZN_COMMITMENT_KEY_LEN];
	uint8_t ks[FZN_AEAD_KEY_LEN], cks[FZN_COMMITMENT_KEY_LEN];
	uint8_t before_k[FZN_AEAD_KEY_LEN], before_ck[FZN_COMMITMENT_KEY_LEN];
	uint8_t desc[DESC_MAX];
	size_t desc_len;
	unsigned refuse = next(rng) % 12u;
	fzn_session_err_t err;

	memset(&eph, 0, sizeof(eph));
	fill(rng, secret, sizeof(secret));
	if (fzn_agree_secret_install(&eph, &AGREE, secret) != FZN_AGREE_OK) {
		printf("  MODEL: the ephemeral would not install\n");
		return 1;
	}

	if (refuse < 3u) {
		/* 0: the prekey agreement refuses; 1: the ephemeral one does;
		 * 2: the hash does. Tried from the initiator's side and the
		 * responder's alternately, because both have two agreements. */
		int as_responder = (int)(next(rng) & 1u);

		fill(rng, before_k, sizeof(before_k));
		fill(rng, before_ck, sizeof(before_ck));
		memcpy(ki, before_k, sizeof(ki));
		memcpy(cki, before_ck, sizeof(cki));
		arm(refuse == 2u ? 0u : refuse + 1u, refuse == 2u ? 1u : 0u);
		if (as_responder)
			err = fzn_session_establish_responder(&resp->prekey, &AGREE, &HASH,
			                                      resp->identity, init->identity,
			                                      pub(init), fzn_agree_secret_public(&eph), ki, cki);
		else
			err = fzn_session_establish_initiator(&init->prekey, &eph, &AGREE, &HASH,
			                                      init->identity, resp->identity,
			                                      pub(resp), ki, cki);
		if (err != (refuse == 2u ? FZN_SESSION_ERR_HASH : FZN_SESSION_ERR_AGREE)) {
			printf("  MODEL: a refused ephemeral session answered %s\n",
			       fzn_session_err_str(err));
			return 1;
		}
		if (!untouched(ki, before_k, sizeof(ki), "ephemeral establish")
		    || !untouched(cki, before_ck, sizeof(cki), "ephemeral establish"))
			return 1;
		if (refuse == 0u)
			cov->refused_agree_first++;
		else if (refuse == 1u)
			cov->refused_agree_second++;
		else
			cov->refused_hash++;
		fzn_agree_secret_wipe(&eph);
		return 0;
	}

	arm(0u, 0u);
	if (fzn_session_establish_initiator(&init->prekey, &eph, &AGREE, &HASH, init->identity,
	                                    resp->identity, pub(resp), ki, cki) != FZN_SESSION_OK
	    || fzn_session_establish_responder(&resp->prekey, &AGREE, &HASH, resp->identity,
	                                       init->identity, pub(init), fzn_agree_secret_public(&eph), kr, ckr)
	       != FZN_SESSION_OK) {
		printf("  MODEL: an ephemeral session refused with nothing refusing\n");
		return 1;
	}
	if (memcmp(ki, kr, sizeof(ki)) != 0 || memcmp(cki, ckr, sizeof(cki)) != 0) {
		printf("  MODEL: initiator and responder derived different roots\n");
		return 1;
	}
	desc_len = describe_v2(desc, init, resp, fzn_agree_secret_public(&eph));
	if (file_root(table, used, desc, desc_len, ki, cki, "the ephemeral session", cov))
		return 1;
	cov->ephemeral++;

	/* THE ROLES SWAPPED WITH THE SAME EPHEMERAL is a different session: the
	 * header orders v2 by role on purpose. Filed under its own descriptor,
	 * so a role-blind derivation collides in the table. */
	if ((next(rng) & 3u) == 0u) {
		if (fzn_session_establish_initiator(&resp->prekey, &eph, &AGREE, &HASH,
		                                    resp->identity, init->identity, pub(init),
		                                    ks, cks) != FZN_SESSION_OK) {
			printf("  MODEL: the swapped ephemeral session refused\n");
			return 1;
		}
		desc_len = describe_v2(desc, resp, init, fzn_agree_secret_public(&eph));
		if (file_root(table, used, desc, desc_len, ks, cks, "the swapped ephemeral session",
		              cov))
			return 1;
		cov->roles_swapped++;
	}
	fzn_agree_secret_wipe(&eph);
	return check_chains(rng, ctable, cused, init, resp, ki, cov);
}

static int self_session(uint32_t *rng, const struct host *a, struct coverage *cov)
{
	uint8_t k[FZN_AEAD_KEY_LEN], ck[FZN_COMMITMENT_KEY_LEN];
	uint8_t before_k[FZN_AEAD_KEY_LEN], before_ck[FZN_COMMITMENT_KEY_LEN];
	uint8_t send[FZN_CHAIN_KEY_LEN], recv[FZN_CHAIN_KEY_LEN];
	uint8_t peer_id[FZN_SESSION_IDENTITY_LEN];

	/* The peer presents this host's own identity with a prekey that may or
	 * may not be its own: the refusal is about the identity. */
	memcpy(peer_id, a->identity, sizeof(peer_id));
	fill(rng, before_k, sizeof(before_k));
	fill(rng, before_ck, sizeof(before_ck));
	memcpy(k, before_k, sizeof(k));
	memcpy(ck, before_ck, sizeof(ck));
	arm(0u, 0u);
	if (fzn_session_establish(&a->prekey, &AGREE, &HASH, a->identity, peer_id, pub(a), k, ck)
	    != FZN_SESSION_ERR_SELF) {
		printf("  MODEL: a session with yourself was not refused as SELF\n");
		return 1;
	}
	if (!untouched(k, before_k, sizeof(k), "self establish")
	    || !untouched(ck, before_ck, sizeof(ck), "self establish"))
		return 1;
	memcpy(send, before_k, sizeof(send));
	memcpy(recv, before_ck, sizeof(recv));
	if (fzn_session_chains(&HASH, before_k, a->identity, peer_id, send, recv)
	    != FZN_SESSION_ERR_SELF) {
		printf("  MODEL: chains between a host and itself were not refused as SELF\n");
		return 1;
	}
	if (!untouched(send, before_k, sizeof(send), "self chains")
	    || !untouched(recv, before_ck, sizeof(recv), "self chains"))
		return 1;
	cov->refused_self++;
	return 0;
}

static int fuzz_one(uint32_t seed, struct coverage *cov)
{
	uint32_t rng = seed;
	struct host hosts[HOSTS];
	struct seen table[TABLE];
	struct chain_seen ctable[TABLE];
	unsigned used = 0, cused = 0;
	unsigned share = next(&rng) % FZN_SESSION_IDENTITY_LEN; /* 0..31 */
	unsigned h, s;

	(void)next(&rng);
	mint_hosts(&rng, hosts, share);
	for (h = 0; h < HOSTS; h++)
		if (!rotate(&rng, &hosts[h])) {
			printf("  MODEL: a prekey would not install\n");
			return 1;
		}

	for (s = 0; s < STEPS; s++) {
		unsigned a = next(&rng) % HOSTS;
		unsigned b = next(&rng) % HOSTS;
		unsigned op = next(&rng) % 16u;

		if (op == 0u) {
			if (!rotate(&rng, &hosts[a])) {
				printf("  MODEL: a rotation would not install\n");
				return 1;
			}
			cov->rotated++;
			continue;
		}
		if (op == 1u || a == b) {
			if (self_session(&rng, &hosts[a], cov))
				return 1;
			continue;
		}
		if (op < 9u) {
			if (base_session(&rng, table, &used, ctable, &cused, &hosts[a], &hosts[b],
			                 share, cov))
				return 1;
		} else {
			if (ephemeral_session(&rng, table, &used, ctable, &cused, &hosts[a],
			                      &hosts[b], cov))
				return 1;
		}
	}
	return 0;
}

#ifdef FZN_LIBFUZZER
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	uint32_t seed = 1u;
	size_t i;
	struct coverage cov;

	memset(&cov, 0, sizeof(cov));
	for (i = 0; i < size; i++)
		seed = (seed * 31u) + data[i];
	if (seed == 0u)
		seed = 1u;
	(void)fuzz_one(seed, &cov);
	return 0;
}
#else

static unsigned long floor_of(unsigned long cases, unsigned long per)
{
	unsigned long f = cases / per;

	return f == 0u ? 1u : f;
}

int main(int argc, char **argv)
{
	unsigned long cases = FUZZ_DEFAULT_CASES;
	struct coverage cov;
	unsigned long c;

	memset(&cov, 0, sizeof(cov));
	if (argc > 1) {
		cases = strtoul(argv[1], NULL, 10);
		if (cases == 0)
			cases = FUZZ_DEFAULT_CASES;
	}
	if (cases < FUZZ_MIN_CASES) {
		printf("session_fuzz: %lu cases is below FUZZ_MIN_CASES (%u).\n", cases,
		       (unsigned)FUZZ_MIN_CASES);
		return 1;
	}

	for (c = 0; c < cases; c++) {
		if (fuzz_one((uint32_t)c + 1u, &cov)) {
			printf("session_fuzz: FAILED on case %lu (seed %lu)\n", c, c + 1u);
			return 1;
		}
	}

	/* `base_deep_order` IS THE FLOOR THAT MATTERS: without pairs whose
	 * identities agree deep into the key, a canonical order that reads
	 * only a prefix is never asked to break a tie, and its two roots for
	 * one pair are never derived. `revisited` is the other: a descriptor
	 * met twice is the only case where "one descriptor, one root" can
	 * fail, and `roles_swapped` is the only case where a role-blind v2
	 * can. */
	if (cov.base < floor_of(cases, 1u) || cov.base_deep_order < floor_of(cases, 4u)
	    || cov.ephemeral < floor_of(cases, 2u) || cov.roles_swapped < floor_of(cases, 8u)
	    || cov.rotated < floor_of(cases, 4u) || cov.revisited < floor_of(cases, 4u)
	    || cov.chains < floor_of(cases, 1u) || cov.refused_self < floor_of(cases, 2u)
	    || cov.refused_agree_first < floor_of(cases, 8u)
	    || cov.refused_agree_second < floor_of(cases, 16u)
	    || cov.refused_hash < floor_of(cases, 8u)
	    || cov.refused_chain_first < floor_of(cases, 8u)
	    || cov.refused_chain_second < floor_of(cases, 8u)) {
		printf("session_fuzz: REACHED TOO LITTLE -- %lu base (%lu deep), %lu ephemeral, "
		       "%lu swapped, %lu rotations, %lu revisited, %lu chains, %lu self, "
		       "%lu/%lu/%lu agree/agree/hash refused, %lu/%lu chain refused, in %lu "
		       "cases.\n",
		       cov.base, cov.base_deep_order, cov.ephemeral, cov.roles_swapped,
		       cov.rotated, cov.revisited, cov.chains, cov.refused_self,
		       cov.refused_agree_first, cov.refused_agree_second, cov.refused_hash,
		       cov.refused_chain_first, cov.refused_chain_second, cases);
		return 1;
	}

	printf("session_fuzz: %lu cases, %lu base sessions (%lu with identities agreeing on "
	       "16+ bytes), %lu ephemeral (%lu with roles swapped), %lu rotations, %lu "
	       "sessions revisited, %lu chain pairs, %lu self refused, %lu/%lu/%lu refused "
	       "by the first agreement/the second/the hash, %lu/%lu chains refused, and "
	       "every root and chain was one-to-one with its session\n",
	       cases, cov.base, cov.base_deep_order, cov.ephemeral, cov.roles_swapped,
	       cov.rotated, cov.revisited, cov.chains, cov.refused_self, cov.refused_agree_first,
	       cov.refused_agree_second, cov.refused_hash, cov.refused_chain_first,
	       cov.refused_chain_second);
	return 0;
}
#endif
