/* A fuzz harness for the manifest admission path.
 *
 * WHY THIS MODULE, AND IT IS NOT BREADTH FOR ITS OWN SAKE. Three separate
 * findings landed in `chain/manifest.c` on 2026-08-31, recorded in project.md
 * secs 36 and 40: a refusing-signer case its sibling `chain/chain.c` had and
 * it did not, a maximum-length constant held by nothing, and -- the reason
 * both survived -- eleven fuzz harnesses in this tree and none here. Three
 * independent findings in one module is a fact about the module.
 *
 * MODEL-BASED RATHER THAN INVARIANT-BASED, for the reason
 * `chain/test/revocation_fuzz.c` gives. A manifest bug is not an overrun. It
 * is a host that reports itself COMPLETE while pairs it was told about are
 * missing -- the fail-open sec 13d exists to close -- or a deficit table
 * holding a pair no issuer named. Neither breaks a spot invariant; both break
 * a shadow that decides for itself what each manifest ought to do.
 *
 * WHAT THE SHADOW HAS TO GET RIGHT is `fzn_manifest_admit`'s tail, which is
 * where the rules interact:
 *
 *   - a pair the store already covers is skipped, and so is one the deficit
 *     table already holds;
 *   - a pair that will not fit sets the issuer's OVERFLOW flag and the walk
 *     CONTINUES, so one unrecordable pair cannot suppress the rest;
 *   - the flag clears only when nothing was dropped AND the manifest is at
 *     least as large as the largest that issuer has shown. A replayed older
 *     manifest names a subset, drops nothing, and would otherwise clear a
 *     flag while the pairs that overflowed are still missing.
 *
 * That last one is the case worth the harness on its own. It is a rollback
 * that looks exactly like an honest quiet day, and `cov.rollback` below is
 * floored so a run that never produced one cannot report success.
 *
 * TWO FOLLOWED ISSUERS, NOT ONE, which is revocation_fuzz's lesson taken
 * rather than rediscovered. With a single followed key every deficit entry
 * carries it, and the issuer term in `deficit_holds` is decided by nothing --
 * that harness proved the equivalent by deleting its comparison and getting
 * byte-identical output. Here two issuers are followed and a third is not, so
 * the same (capability, grantee) under two keys is an ordinary state.
 *
 * REAL BYTES, NOT FILLED STRUCTS, which is the same harness's other lesson.
 * Every manifest is built with `fzn_manifest_encode`, signed over the bytes
 * `fzn_manifest_signed_bytes` names, and opened again before it is admitted.
 * A harness that pointed a record at fields it had set by hand would agree
 * with itself about a layout the module never reads.
 *
 * Bounded and seeded like the others: a fixed case count from a seeded
 * generator, so a failing case is reproducible from this file alone.
 */

#include "../manifest.h"
#include "../revocation.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FUZZ_DEFAULT_CASES 20000u

/* Small on purpose. The deficit table has to FILL for the overflow rules to
 * be reachable at all, and a table a case cannot fill is a set of rules this
 * harness would report on without having entered. */
#define DEFICIT_CAP 3u
#define FOLLOWED 2u
#define KEYS 3u
#define CAPS 3u
#define GRANTEES 3u
#define MAX_PAIRS 2u
#define ROUNDS 8u

#define CANARY 16u

static void expand(uint8_t *out, size_t len, uint8_t seed)
{
	for (size_t i = 0; i < len; i++)
		out[i] = (uint8_t)(seed + (uint8_t)(i * 7u));
}

/* The stub's signature depends on the identity AND on every byte it covers,
 * so a manifest signed as one issuer does not verify as another and a single
 * flipped body byte does not verify at all. A constant would make every
 * refusal below untestable. */
static void mac(uint8_t out[FZN_SIG_LEN], uint8_t identity, const uint8_t *msg, size_t len)
{
	uint64_t h = 0xcbf29ce484222325ull;

	h ^= (uint64_t)identity;
	h *= 0x100000001b3ull;
	for (size_t i = 0; i < len; i++) {
		h ^= (uint64_t)msg[i];
		h *= 0x100000001b3ull;
	}
	for (size_t i = 0; i < FZN_SIG_LEN; i++) {
		h ^= (uint64_t)i + 1u;
		h *= 0x100000001b3ull;
		out[i] = (uint8_t)(h >> 56);
	}
}

/* Record identity for admission -- the same FNV expansion as the signer's,
 * over the whole record. */
static int stub_hash(void *ctx, uint8_t *out, size_t out_len, const uint8_t *in,
                     size_t in_len)
{
	uint64_t h = 0xcbf29ce484222325ull;
	size_t i;

	(void)ctx;
	if (!out || !in || out_len == 0)
		return 0;
	for (i = 0; i < in_len; i++) {
		h ^= (uint64_t)in[i];
		h *= 0x100000001b3ull;
	}
	for (i = 0; i < out_len; i++) {
		h ^= (uint64_t)i + 1u;
		h *= 0x100000001b3ull;
		out[i] = (uint8_t)(h >> 56);
	}
	return 1;
}

static const fzn_hash_ops_t HASH_OPS = { stub_hash, NULL };

static int stub_verify(void *ctx, const uint8_t pubkey[FZN_PUBKEY_LEN], const uint8_t *msg,
                       size_t msg_len, const uint8_t sig[FZN_SIG_LEN])
{
	uint8_t want[FZN_SIG_LEN];

	(void)ctx;
	mac(want, pubkey[0], msg, msg_len);
	return memcmp(want, sig, FZN_SIG_LEN) == 0;
}

static int stub_sign(void *ctx, uint8_t sig[FZN_SIG_LEN], const uint8_t *msg, size_t msg_len)
{
	const uint8_t *identity = ctx;

	mac(sig, *identity, msg, msg_len);
	return 1;
}

/* The arena the module writes into, with canaries either side of both arrays.
 * `fzn_manifest_admit` indexes the deficit table against a count it takes
 * from a record, so "did it stay inside what it was given" is a question this
 * harness must be able to answer without a sanitizer. */
struct arena {
	uint8_t front[CANARY];
	fzn_manifest_issuer_t issuers[FOLLOWED];
	uint8_t middle[CANARY];
	fzn_manifest_deficit_t deficit[DEFICIT_CAP];
	uint8_t back[CANARY];
};

/* The shadow. A second implementation of admit's rules, deliberately, for the
 * reason chain_fuzz states: a model that asked the module what it did would
 * agree with it always, including when both are wrong. */
struct model {
	uint8_t issuer[DEFICIT_CAP][FZN_PUBKEY_LEN];
	fzn_cap_id_t capability[DEFICIT_CAP];
	uint8_t grantee[DEFICIT_CAP][FZN_PUBKEY_LEN];
	size_t used;

	size_t pairs_seen[FOLLOWED];
	int overflowed[FOLLOWED];
};

/* What the store holds, kept beside it so `covers` can be predicted rather
 * than asked. */
/* WHAT THE STORE HOLDS, TRACKED INDEPENDENTLY, and it grew an id and a
 * state when a manifest entry did. The model must decide "am I behind about
 * this pair" from its OWN bookkeeping; asking the library would make this a
 * second copy of the code under test rather than a witness against it. */
struct held {
	fzn_cap_id_t capability[8];
	uint8_t grantee[8][FZN_PUBKEY_LEN];
	uint8_t issuer[8][FZN_PUBKEY_LEN];
	uint8_t id[8][FZN_REVOCATION_ID_LEN];
	int withdrawn[8];
	size_t used;
};

struct coverage {
	unsigned long admitted;
	unsigned long unknown_issuer;
	unsigned long bad_signature;
	unsigned long covered_skip;
	unsigned long duplicate_skip;
	unsigned long filled;
	unsigned long cleared;
	unsigned long rollback;
	unsigned long satisfied;
};

static int model_holds(const struct model *m, const uint8_t *issuer, const fzn_cap_id_t *cap,
                       const uint8_t *grantee)
{
	for (size_t i = 0; i < m->used; i++) {
		if (memcmp(m->issuer[i], issuer, FZN_PUBKEY_LEN) == 0 &&
		    memcmp(m->capability[i].b, cap, FZN_CAP_ID_LEN) == 0 &&
		    memcmp(m->grantee[i], grantee, FZN_PUBKEY_LEN) == 0)
			return 1;
	}
	return 0;
}

static size_t held_at(const struct held *h, const uint8_t *issuer, const fzn_cap_id_t *cap,
                      const uint8_t *grantee)
{
	size_t i;

	for (i = 0; i < h->used; i++) {
		if (memcmp(h->issuer[i], issuer, FZN_PUBKEY_LEN) == 0 &&
		    memcmp(h->capability[i].b, cap, FZN_CAP_ID_LEN) == 0 &&
		    memcmp(h->grantee[i], grantee, FZN_PUBKEY_LEN) == 0)
			break;
	}
	return i;
}

static int store_holds(const struct held *h, const uint8_t *issuer, const fzn_cap_id_t *cap,
                       const uint8_t *grantee)
{
	return held_at(h, issuer, cap, grantee) < h->used;
}

/* THE RULE, RESTATED FROM THE DESIGN RATHER THAN FROM THE CODE. A host is
 * behind an issuer about a pair unless it holds the same record and is not
 * the one missing a withdrawal:
 *
 *   holds nothing            -- behind
 *   same record, same state  -- agreed
 *   same record, they cleared and this host has not  -- behind
 *   same record, this host cleared  -- ahead
 *   different records        -- cannot tell from hashes, so behind (ask)
 */
static int model_behind(const struct held *h, const uint8_t *issuer,
                        const fzn_cap_id_t *cap, const uint8_t *grantee,
                        const uint8_t *their_id, int their_withdrawn)
{
	size_t at = held_at(h, issuer, cap, grantee);

	if (at == h->used)
		return 1;
	if (memcmp(h->id[at], their_id, FZN_REVOCATION_ID_LEN) != 0)
		return 1;
	return their_withdrawn && !h->withdrawn[at];
}

static size_t model_pending(const struct model *m, const uint8_t *issuer)
{
	size_t n = 0;

	for (size_t i = 0; i < m->used; i++) {
		if (memcmp(m->issuer[i], issuer, FZN_PUBKEY_LEN) == 0)
			n++;
	}
	return n;
}

static int pair_gt(const fzn_manifest_pair_t *a, const fzn_manifest_pair_t *b)
{
	int cmp = memcmp(a->capability.b, b->capability.b, FZN_CAP_ID_LEN);

	if (cmp != 0)
		return cmp > 0;
	return memcmp(a->grantee, b->grantee, FZN_PUBKEY_LEN) > 0;
}

/* Both directions, over every key including the one nobody follows.
 *
 * `fzn_manifest_pending` answers 0 for an unfollowed issuer and
 * `fzn_manifest_overflowed` answers 1, and those are not the same fact with
 * different signs -- manifest.h argues the asymmetry at length: an absent
 * answer must not read as a sound one. Asking about the third key on every
 * round is what holds that. */
static const char *agree(const fzn_manifest_state_t *state, const struct model *m,
                         uint8_t keys[KEYS][FZN_PUBKEY_LEN])
{
	for (size_t k = 0; k < KEYS; k++) {
		size_t want_pending = k < FOLLOWED ? model_pending(m, keys[k]) : 0u;
		int want_over = k < FOLLOWED ? m->overflowed[k] : 1;

		if (fzn_manifest_pending(state, keys[k]) != want_pending)
			return "pending disagrees with the model";
		if (fzn_manifest_overflowed(state, keys[k]) != want_over)
			return "overflowed disagrees with the model";
	}
	return NULL;
}

static const char *fuzz_one(const uint8_t *data, size_t len, struct coverage *cov)
{
	struct arena arena;
	fzn_manifest_state_t state;
	fzn_revocation_store_t store;
	fzn_revocation_t entries[8];
	struct model m;
	struct held held;
	uint8_t keys[KEYS][FZN_PUBKEY_LEN];
	fzn_cap_id_t caps[CAPS];
	uint8_t grantees[GRANTEES][FZN_PUBKEY_LEN];
	uint8_t identity = 0;
	fzn_sign_ops_t sign;
	size_t at = 0;
	unsigned pre;

#define TAKE() ((unsigned)(at < len ? data[at++] : 0u))

	memset(&m, 0, sizeof(m));
	memset(&held, 0, sizeof(held));
	sign.verify = stub_verify;
	sign.sign = stub_sign;
	sign.ctx = &identity;

	for (size_t i = 0; i < KEYS; i++)
		expand(keys[i], FZN_PUBKEY_LEN, (uint8_t)(0x10u + i));
	for (size_t i = 0; i < CAPS; i++)
		expand(caps[i].b, FZN_CAP_ID_LEN, (uint8_t)(0x40u + i));
	for (size_t i = 0; i < GRANTEES; i++)
		expand(grantees[i], FZN_PUBKEY_LEN, (uint8_t)(0x70u + i));

	if (fzn_manifest_init(&state, arena.issuers, FOLLOWED, arena.deficit, DEFICIT_CAP) !=
	    FZN_MANIFEST_OK)
		return "the fixture's state would not initialise";
	if (fzn_revocation_store_init(&store, entries, 8u) != FZN_CHAIN_OK)
		return "the fixture's store would not initialise";
	for (size_t i = 0; i < FOLLOWED; i++) {
		if (fzn_manifest_follow(&state, keys[i]) != FZN_MANIFEST_OK)
			return "the fixture could not follow an issuer";
	}

	/* Written AFTER init, so they measure what the rounds do rather than
	 * what initialising did. */
	memset(arena.front, 0x5a, CANARY);
	memset(arena.middle, 0x5a, CANARY);
	memset(arena.back, 0x5a, CANARY);

	/* Some revocations this host already holds, so the "already covered"
	 * skip is reachable. Without them every pair is a deficit and the first
	 * of admit's two skips is never taken. */
	pre = TAKE() % 3u;
	for (unsigned p = 0; p < pre; p++) {
		size_t ki = TAKE() % FOLLOWED;
		size_t ci = TAKE() % CAPS;
		size_t gi = TAKE() % GRANTEES;
		uint8_t rbytes[FZN_REVOCATION_LEN];
		fzn_revocation_record_t rrec;

		identity = keys[ki][0];
		if (fzn_revocation_issue(keys[ki], &caps[ci], grantees[gi], 1000u, &sign, rbytes) !=
		    FZN_CHAIN_OK)
			return "the fixture could not issue a revocation";
		if (fzn_revocation_open(rbytes, FZN_REVOCATION_LEN, &rrec) != FZN_CHAIN_OK)
			return "the fixture issued a revocation that will not open";
		if (fzn_revocation_admit(&store, fzn_revocation_offer_root(rrec), keys[ki], &sign,
		                         &HASH_OPS, NULL) != FZN_CHAIN_OK)
			continue;
		if (!store_holds(&held, keys[ki], &caps[ci], grantees[gi]) && held.used < 8u) {
			memcpy(held.issuer[held.used], keys[ki], FZN_PUBKEY_LEN);
			memcpy(held.capability[held.used].b, caps[ci].b, FZN_CAP_ID_LEN);
			memcpy(held.grantee[held.used], grantees[gi], FZN_PUBKEY_LEN);
			/* The record's identity, computed here with the same
			 * seam the store was given -- not read back out of the
			 * store, which would be the model asking the code
			 * under test what it should expect. */
			if (!stub_hash(NULL, held.id[held.used], FZN_REVOCATION_ID_LEN,
			               rbytes, FZN_REVOCATION_LEN))
				return "the fixture could not hash a revocation";
			held.withdrawn[held.used] = 0;
			held.used++;
		}
	}

	/* SEVERAL MANIFESTS PER CASE, because the rules that matter are about
	 * what a SECOND one does to the state a first one left. One admit per
	 * case could never reach a cleared flag or a rollback. */
	for (unsigned round = 0; round < ROUNDS; round++) {
		fzn_manifest_pair_t pairs[MAX_PAIRS];
		/* The encoder takes entries now. The generator below is about
		 * ordering and duplicates, which are properties of the KEY, so
		 * it goes on producing pairs and they are adapted here -- with
		 * the id derived from the index so no two entries collide, and
		 * the state alternating so both values reach `open`'s
		 * canonicality check. */
		fzn_manifest_entry_t entries[MAX_PAIRS];
		uint8_t buf[FZN_MANIFEST_LEN(MAX_PAIRS)];
		fzn_manifest_record_t rec;
		const uint8_t *msg;
		size_t msg_len;
		size_t npairs = 0;
		size_t out_len = 0;
		size_t ki = TAKE() % KEYS;
		unsigned n = TAKE() % (MAX_PAIRS + 1u);
		int corrupt = (TAKE() & 7u) == 0u;
		int dropped = 0;
		fzn_manifest_err_t got, want;
		const char *why;

		for (unsigned i = 0; i < n; i++) {
			fzn_manifest_pair_t p;
			int seen = 0;

			memcpy(p.capability.b, caps[TAKE() % CAPS].b, FZN_CAP_ID_LEN);
			memcpy(p.grantee, grantees[TAKE() % GRANTEES], FZN_PUBKEY_LEN);
			for (size_t j = 0; j < npairs; j++) {
				if (memcmp(pairs[j].capability.b, p.capability.b, FZN_CAP_ID_LEN) == 0 &&
				    memcmp(pairs[j].grantee, p.grantee, FZN_PUBKEY_LEN) == 0)
					seen = 1;
			}
			if (!seen)
				pairs[npairs++] = p;
		}
		for (size_t i = 1; i < npairs; i++) {
			fzn_manifest_pair_t hold = pairs[i];
			size_t j = i;

			while (j > 0 && pair_gt(&pairs[j - 1u], &hold)) {
				pairs[j] = pairs[j - 1u];
				j--;
			}
			pairs[j] = hold;
		}

		/* SOMETIMES HAND A PAIR BACK, which is what a host does when it
		 * finally receives the revocation a manifest told it about.
		 *
		 * Without this the harness could never watch the overflow flag
		 * CLEAR: nothing else frees a deficit slot, so once the table
		 * filled it stayed full and every later manifest dropped
		 * something. Measured before it was added -- 4 clearings in
		 * 20000 cases, against a floor of 100 -- which is the coverage
		 * counter doing its job on the harness rather than on the
		 * module. */
		if ((TAKE() & 1u) == 0u) {
			size_t si = TAKE() % FOLLOWED;
			const fzn_cap_id_t *sc = &caps[TAKE() % CAPS];
			const uint8_t *sg = grantees[TAKE() % GRANTEES];
			size_t removed = fzn_manifest_satisfy(&state, keys[si], sc, sg);
			size_t expect = 0;

			for (size_t i = 0; i < m.used;) {
				if (memcmp(m.issuer[i], keys[si], FZN_PUBKEY_LEN) == 0 &&
				    memcmp(m.capability[i].b, sc, FZN_CAP_ID_LEN) == 0 &&
				    memcmp(m.grantee[i], sg, FZN_PUBKEY_LEN) == 0) {
					m.used--;
					memmove(&m.issuer[i], &m.issuer[i + 1u],
					        (m.used - i) * FZN_PUBKEY_LEN);
					memmove(&m.capability[i], &m.capability[i + 1u],
					        (m.used - i) * FZN_CAP_ID_LEN);
					memmove(&m.grantee[i], &m.grantee[i + 1u],
					        (m.used - i) * FZN_PUBKEY_LEN);
					expect++;
					continue;
				}
				i++;
			}
			if (removed != expect)
				return "satisfy removed a different number than the model";
			cov->satisfied += removed;
		}

		identity = keys[ki][0];
		/* THE ID MATCHES THE STORE'S WHERE THE STORE HAS THE PAIR, and
		 * that is what keeps the interesting rows reachable. With
		 * synthetic ids everywhere, every entry would differ from
		 * everything held and the generator would only ever exercise
		 * "cannot tell, so ask" -- the three rows that say agreed,
		 * behind and ahead would never be built. */
		for (size_t e = 0; e < npairs; e++) {
			size_t at = held_at(&held, keys[ki], &pairs[e].capability,
			                    pairs[e].grantee);

			entries[e].pair = pairs[e];
			if (at < held.used) {
				memcpy(entries[e].id, held.id[at], FZN_REVOCATION_ID_LEN);
			} else {
				memset(entries[e].id, 0, sizeof(entries[e].id));
				entries[e].id[0] = (uint8_t)(e + 1u);
			}
			entries[e].state = (e & 1u) ? (uint8_t)FZN_MANIFEST_WITHDRAWN
			                            : (uint8_t)FZN_MANIFEST_REVOKED;
		}
		if (fzn_manifest_encode(buf, sizeof(buf), keys[ki], entries, npairs,
		                        &out_len) != FZN_MANIFEST_OK)
			return "the fixture could not encode a manifest";
		if (fzn_manifest_open(buf, out_len, &rec) != FZN_MANIFEST_OK)
			return "the fixture encoded a manifest that will not open";

		/* Signed over exactly what the module will verify, then reopened,
		 * so nothing here depends on the record still describing bytes
		 * that have since changed. */
		fzn_manifest_signed_bytes(rec, &msg, &msg_len);
		mac(buf + msg_len, keys[ki][0], msg, msg_len);
		if (corrupt)
			buf[msg_len] = (uint8_t)(buf[msg_len] ^ 0x01u);
		if (fzn_manifest_open(buf, out_len, &rec) != FZN_MANIFEST_OK)
			return "signing made a manifest that will not open";

		got = fzn_manifest_admit(&state, &store, rec, &sign);

		if (ki >= FOLLOWED) {
			want = FZN_MANIFEST_ERR_UNKNOWN_ISSUER;
			cov->unknown_issuer++;
		} else if (corrupt) {
			want = FZN_MANIFEST_ERR_SIGNATURE;
			cov->bad_signature++;
		} else {
			for (size_t i = 0; i < npairs; i++) {
				if (!model_behind(&held, keys[ki], &pairs[i].capability,
				                  pairs[i].grantee, entries[i].id,
				                  entries[i].state ==
				                          (uint8_t)FZN_MANIFEST_WITHDRAWN)) {
					cov->covered_skip++;
					continue;
				}
				if (model_holds(&m, keys[ki], &pairs[i].capability,
				                pairs[i].grantee)) {
					cov->duplicate_skip++;
					continue;
				}
				if (m.used >= DEFICIT_CAP) {
					m.overflowed[ki] = 1;
					dropped = 1;
					continue;
				}
				memcpy(m.issuer[m.used], keys[ki], FZN_PUBKEY_LEN);
				memcpy(m.capability[m.used].b, pairs[i].capability.b, FZN_CAP_ID_LEN);
				memcpy(m.grantee[m.used], pairs[i].grantee, FZN_PUBKEY_LEN);
				m.used++;
			}
			if (npairs >= m.pairs_seen[ki]) {
				m.pairs_seen[ki] = npairs;
				if (!dropped) {
					if (m.overflowed[ki])
						cov->cleared++;
					m.overflowed[ki] = 0;
				}
			} else if (m.overflowed[ki] && !dropped) {
				/* sec 13d's replayed-older-manifest: it drops
				 * nothing and must still not clear the flag. */
				cov->rollback++;
			}
			if (dropped)
				cov->filled++;
			else
				cov->admitted++;
			want = dropped ? FZN_MANIFEST_ERR_DEFICIT_FULL : FZN_MANIFEST_OK;
		}

		if (got != want)
			return "admit disagreed with the model";
		why = agree(&state, &m, keys);
		if (why != NULL)
			return why;
	}

	for (size_t i = 0; i < CANARY; i++) {
		if (arena.front[i] != 0x5a || arena.middle[i] != 0x5a || arena.back[i] != 0x5a)
			return "wrote outside the arrays it was given";
	}
	return NULL;
#undef TAKE
}

#ifdef FZN_LIBFUZZER
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct coverage cov = { 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	const char *why = fuzz_one(data, size, &cov);

	if (why != NULL) {
		printf("  INVARIANT: %s\n", why);
		abort();
	}
	return 0;
}
#else

static uint32_t next(uint32_t *state)
{
	*state = (*state * 1103515245u) + 12345u;
	return (*state >> 16) & 0xffffu;
}

/* Never zero, for the reason revocation_fuzz records at length: integer
 * division makes `cases / 200` zero for any run under 200 cases, and an
 * unsigned counter is never less than zero -- so every floor switches itself
 * off silently at exactly the case counts a sanitized run uses. */
static unsigned long floor_of(unsigned long cases, unsigned long per)
{
	unsigned long n = cases / per;

	return n != 0ul ? n : 1ul;
}

int main(int argc, char **argv)
{
	unsigned long cases = FUZZ_DEFAULT_CASES;
	struct coverage cov = { 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	uint32_t state = 0x9e3779b9u;

	if (argc > 1) {
		char *end = NULL;
		unsigned long n = strtoul(argv[1], &end, 10);

		if (end == argv[1] || *end != '\0' || n == 0ul) {
			printf("manifest_fuzz: usage: manifest_fuzz [cases]\n");
			return 1;
		}
		cases = n;
	}

	for (unsigned long c = 0; c < cases; c++) {
		uint8_t buf[112];
		const char *why;

		for (size_t i = 0; i < sizeof(buf); i++)
			buf[i] = (uint8_t)next(&state);
		why = fuzz_one(buf, sizeof(buf), &cov);
		if (why != NULL) {
			printf("manifest_fuzz: INVARIANT at case %lu: %s\n", c, why);
			return 1;
		}
	}

	/* EVERY ONE OF THESE IS A STATE THE RULES ARE ABOUT, and a run that
	 * reached none of them would report success having tested the parser
	 * and nothing else.
	 *
	 * `rollback` is the one worth the harness. It is sec 13d's replayed
	 * older manifest: smaller than the largest this issuer has shown, so it
	 * drops nothing and must STILL not clear the overflow flag. A run
	 * without one has not entered the case the high-water mark exists for,
	 * and that case is a host declaring its deficit sound while the pairs
	 * that overflowed are still missing. `cleared` is its honest twin --
	 * without both, a rule that never cleared anything and a rule that
	 * always did would look the same from here. */
	if (cov.admitted < floor_of(cases, 200u) || cov.unknown_issuer < floor_of(cases, 200u) ||
	    cov.bad_signature < floor_of(cases, 200u) || cov.covered_skip < floor_of(cases, 200u) ||
	    cov.duplicate_skip < floor_of(cases, 200u) || cov.filled < floor_of(cases, 200u) ||
	    cov.cleared < floor_of(cases, 200u) || cov.rollback == 0ul || cov.satisfied < floor_of(cases, 200u)) {
		printf("manifest_fuzz: REACHED TOO LITTLE -- %lu admitted, %lu unknown issuer, "
		       "%lu bad signature, %lu covered, %lu duplicate, %lu full, %lu cleared, "
		       "%lu rollbacks, %lu satisfied in %lu cases.\n",
		       cov.admitted, cov.unknown_issuer, cov.bad_signature, cov.covered_skip,
		       cov.duplicate_skip, cov.filled, cov.cleared, cov.rollback, cov.satisfied, cases);
		return 1;
	}

	printf("manifest_fuzz: %lu cases, %lu admitted, %lu unknown issuer, %lu bad signature, "
	       "%lu covered, %lu duplicate, %lu full, %lu cleared, %lu rollbacks refused, "
	       "%lu satisfied, model agreed throughout\n",
	       cases, cov.admitted, cov.unknown_issuer, cov.bad_signature, cov.covered_skip,
	       cov.duplicate_skip, cov.filled, cov.cleared, cov.rollback, cov.satisfied);
	return 0;
}
#endif
