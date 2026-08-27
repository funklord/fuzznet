/* The ORDER a receiver runs its checks in -- project.md sec 4.7, executed.
 *
 * That section is a seven-step sequence with a reason given for each step
 * preceding the next, and until this file existed **nothing ran it**. It said
 * so itself: a consumer had to derive the order from five headers and "would
 * be inventing a security property". A sequence recorded only in prose is the
 * weakest form of the strongest kind of claim, which is the shape this tree
 * has been finding all week.
 *
 * WHAT IS AND IS NOT HERE. Steps 4 and 5 -- the key commitment and the tag --
 * live in `wire/seal.c` and need situ's generated layout, so they are covered
 * by `wire/test/seal_test.c` and skipped here. This harness drives the five
 * that take decoded fields: freshness, replay, the capability chain against a
 * revocation store, and reassembly, in the documented order, over input a
 * stranger chose.
 *
 * WHAT IT ASSERTS is what no single-module harness can. Each module's own
 * fuzzer checks that module's rules; none of them can see the property the
 * ordering exists for:
 *
 *   - **A frame refused at any step costs nothing at a later one.** No slot
 *     is taken, no partial message advances, and no signature is verified
 *     after a refusal. This is the whole point of sec 4.7's ordering: the
 *     memory bound in chunk/reassembly.c protects a table that any stranger
 *     could otherwise fill with unauthenticated chunks.
 *   - **A replayed nonce never reaches reassembly twice.** The window is
 *     what stands between a repeated datagram and a repeated configuration
 *     change (sec 4.4a).
 *   - **A revoked or unrooted capability never advances a message.** Chain
 *     verification precedes reassembly, so a refusal there must leave the
 *     table exactly as it was.
 *   - **Signature verification is never spent on a stale frame.** Freshness
 *     precedes the chain for that reason and no other; if the order were
 *     reversed a receiver would pay for cryptography on frames already dead.
 *
 * Bounded and seeded as the other harnesses are, and it counts what it
 * reached: a run in which nothing was ever admitted would satisfy every
 * invariant above and prove none of them.
 */

#include "../freshness.h"

#include "../../chain/chain.h"
#include "../../chain/revocation.h"
#include "../../chunk/reassembly.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* How long a half-finished message may hold a slot. Generous, because what
 * these cases test is the bound EXISTING -- a zero expiry no longer means
 * for ever -- rather than any particular value of it. */
#define REASM_MAX_HOLD 1000000u

#define FUZZ_DEFAULT_CASES 20000u

/* THE FLOOR BELOW WHICH THIS HARNESS REFUSES TO REPORT SUCCESS AT ALL.
 *
 * `floor_of` below was fixed to never return zero, which closed CASES=1: a run
 * that demanded nothing could no longer pass by demanding nothing. It did not
 * close the case above it. A floor of ONE is cleared by luck -- the rarest
 * branch these harnesses reach occurs about once in 130 cases, so a 199-case
 * run hits it once and every counter then reports a real, honest, meaningless
 * number. Measured before this: `receive_fuzz 199` and `peer_fuzz 199` both
 * exited 0 with plausible counts.
 *
 * So this is a bound on the RUN rather than on the counters, and it lives in
 * the harness rather than in the Makefile deliberately. The Makefile is not
 * what somebody runs when they are chasing a crash under a sanitizer -- they
 * run this binary directly, with a small number, and read the exit code. A
 * bound that exists only in the thing that invokes the binary is not a bound
 * on the binary.
 *
 * 1000 is chosen against the floors themselves, which ask for one occurrence
 * per 200 cases: below that, every floor in this file collapses to the single
 * hit luck supplies. A run under it is not a shorter version of the campaign,
 * it is a different and much weaker claim, so it is refused rather than
 * reported. */
#define FUZZ_MIN_CASES 1000u
#define WINDOW_ENTRIES 8
/* The replay horizon this receiver is sized for. Expiries below run to
 * `now + 40`, so 64 leaves every path this harness measures exactly where it
 * was: nothing here is refused FZN_FRESH_ERR_HORIZON, and the `stale` counter
 * keeps counting what it counted. The horizon's own rules are
 * `frame/test/freshness_test.c`'s subject; this file's is the ORDER. */
#define WINDOW_MAX_AHEAD 64
#define SLOTS 4
#define SLOT_BYTES 512
#define REVS 4

/* THE VERDICT IS A FUNCTION OF THE KEY, NOT A GLOBAL YES OR NO.
 *
 * This stub opened `(void)pubkey;` and returned one `answer` whatever key it
 * was handed. The hop below is granted BY the pinned root TO 0x09, so the
 * root's signature is the only one that can authorise it -- but a stub blind
 * to the key answers the same to both, and chain.c verifying under
 * `hop->grantee` instead of `hop->grantor` accepted every unsigned hop this
 * harness generated without changing one counter.
 *
 * `good` is the set of identities whose signature verifies, indexed by the
 * low five bits of the key. Every identity here is a key of repeated bytes,
 * so those bits ARE the identity. */
struct signer {
	int calls;
	uint32_t good;
};

static int stub_verify(void *ctx, const uint8_t pubkey[FZN_PUBKEY_LEN], const uint8_t *msg,
                       size_t msg_len, const uint8_t sig[FZN_SIG_LEN])
{
	struct signer *s = (struct signer *)ctx;

	(void)msg;
	(void)msg_len;
	(void)sig;
	s->calls++;
	return (int)((s->good >> (pubkey[0] & 31u)) & 1u);
}

/* The signing half. `stub_verify`'s verdict is a function of the KEY, so the
 * signature's content is not read -- but a signer must exist, because
 * `fzn_chain_mint` cannot produce a hop without one. Filling it from the
 * message keeps it honest rather than constant. */
static int stub_sign(void *ctx, uint8_t sig[FZN_SIG_LEN], const uint8_t *msg, size_t msg_len)
{
	uint32_t acc = 0x9e3779b9u;
	size_t i;

	(void)ctx;
	for (i = 0; i < msg_len; i++)
		acc = (acc * 31u) + msg[i];
	for (i = 0; i < FZN_SIG_LEN; i++)
		sig[i] = (uint8_t)(acc >> ((i % 4u) * 8u));
	return 1;
}

struct coverage {
	unsigned long admitted;      /* reached reassembly */
	unsigned long stale;         /* refused at freshness */
	unsigned long replayed;      /* refused at the replay window */
	unsigned long unauthorised;  /* refused at the chain */
	unsigned long completed;     /* a whole message came back */
};

/* THE RECEIVER PERSISTS, and that is the whole reason this harness is worth
 * more than four separate ones.
 *
 * The first version built a fresh window for every case, and its `replayed`
 * counter could not increment: a first presentation of a nonce to an empty
 * window is never a replay. A counter that cannot move is a coverage claim
 * nobody can check, which is the failure these harnesses were written to
 * avoid rather than to reproduce.
 *
 * It is also the wrong shape. A receiver is not new for each datagram; its
 * window, its revocation store and its partial messages are exactly the state
 * that makes a replay meaningful, a table fillable, and a quota bite. So one
 * receiver takes the whole run, and the cost is that reproducing case N means
 * replaying the cases before it -- which is stated here rather than discovered
 * by somebody bisecting.
 */
struct receiver {
	fzn_replay_entry_t entries[WINDOW_ENTRIES];
	fzn_replay_window_t window;
	fzn_revocation_t revs[REVS];
	fzn_revocation_store_t store;
	fzn_partial_t slots[SLOTS];
	uint8_t storage[SLOTS][SLOT_BYTES];
	fzn_reasm_t table;
};

static int receiver_init(struct receiver *r)
{
	if (fzn_replay_init(&r->window, r->entries, WINDOW_ENTRIES, WINDOW_MAX_AHEAD) != FZN_FRESH_OK)
		return 0;
	if (fzn_revocation_store_init(&r->store, r->revs, REVS) != FZN_CHAIN_OK)
		return 0;
	for (size_t i = 0; i < SLOTS; i++) {
		if (fzn_reasm_slot_init(&r->slots[i], r->storage[i], SLOT_BYTES) != FZN_REASM_OK)
			return 0;
	}
	return fzn_reasm_init(&r->table, r->slots, SLOTS, SLOTS, REASM_MAX_HOLD) == FZN_REASM_OK;
}

/* One datagram, in sec 4.7's order. Returns non-zero on a broken invariant. */
static int receive_one(struct receiver *r, uint64_t now, const uint8_t *data, size_t len,
                       struct coverage *cov)
{
	fzn_partial_t *done = NULL;
	fzn_chain_hop_t hop;
	fzn_chain_t chain;
	struct signer signer = { 0, 0xffffffffu };
	fzn_sign_ops_t sign = { stub_verify, stub_sign, &signer };
	uint8_t hop_bytes[FZN_HOP_LEN];
	uint8_t root[FZN_PUBKEY_LEN], cap[FZN_CAP_ID_LEN], sender[FZN_SENDER_LEN];
	uint8_t nonce[FZN_NONCE_LEN], payload[64];
	uint64_t expires_at;
	uint32_t msg;
	uint16_t index, chunks;
	size_t payload_len;
	size_t live_before, live_after;
	int calls_before;
	int root_signed;
	fzn_fresh_err_t fresh;
	fzn_chain_err_t authorised;
	fzn_reasm_err_t admitted;

	if (len < 12)
		return 0;

	/* Everything a stranger chooses, drawn from the input. */
	memset(sender, data[0], sizeof(sender));
	/* A NARROW NONCE SPACE, deliberately. A full byte gives 256 values
	 * against an eight-entry window, so a nonce almost never recurs while
	 * its entry is still live and the replay counter stayed at zero -- a
	 * branch the harness claimed to cover and never reached. Sixteen values
	 * make re-presentation ordinary, which is what a receiver facing a
	 * stranger with a recording actually sees. */
	memset(nonce, (int)(data[1] % 16u), sizeof(nonce));
	memset(cap, data[2], sizeof(cap));
	memset(root, 0x01, sizeof(root));
	msg = data[3];
	chunks = (uint16_t)(1u + (data[4] % 4u));
	index = (uint16_t)(data[5] % chunks);
	payload_len = 1u + (data[6] % 32u);
	/* THE CLOCK ADVANCES, which the first persistent version of this did
	 * not do and which made the harness useless: a window that never
	 * expires anything fills after eight datagrams and refuses everything
	 * after that. Three admitted in twenty thousand cases. A receiver whose
	 * clock stands still is not a receiver, and the run was measuring that
	 * rather than the order.
	 *
	 * Expiries are relative to it: zero a third of the time, which means
	 * "no expiry" and is refused for a command, and otherwise ahead of now
	 * by a margin that lets entries age out of the window as `now` moves. */
	expires_at = (data[7] % 3u) == 0u ? 0u : now + 1u + (uint64_t)(data[8] % 40u);
	/* Sometimes the chain does not verify -- and it is THE ROOT'S signature
	 * that is missing, because the root is the only party whose signature
	 * on this hop means anything. Every other identity, the grantee
	 * included, keeps a good one, so a verifier that asks the wrong party
	 * gets a yes where the rules say no. */
	root_signed = (data[9] % 4u) != 0u;
	signer.good = 0xffffffffu;
	if (!root_signed)
		signer.good &= ~(1u << (0x01u & 31u)); /* the root's key, memset below */
	memset(payload, data[10], sizeof(payload));

	/* A REAL HOP, ENCODED AND SIGNED. This used to fill a struct and point
	 * `signed_region` at a fixed literal, so the fields and the bytes the
	 * signature covered had no relationship -- which is precisely the
	 * defect the binding closed. A harness cannot demonstrate a property
	 * the library does not have, and this one could not have. */
	{
		uint8_t grantee[FZN_PUBKEY_LEN];

		memset(grantee, 0x09, sizeof(grantee));
		if (fzn_chain_mint(root, grantee, cap, 100, FZN_NO_EXPIRY, 0, &sign,
		                   hop_bytes) != FZN_CHAIN_OK) {
			printf("  ORDER: the harness could not mint a hop\n");
			return 1;
		}
		if (fzn_hop_open(hop_bytes, FZN_HOP_LEN, &hop) != FZN_CHAIN_OK) {
			printf("  ORDER: the harness could not open the hop it minted\n");
			return 1;
		}
	}

	live_before = 0;
	for (size_t i = 0; i < SLOTS; i++)
		live_before += r->slots[i].live ? 1u : 0u;
	calls_before = signer.calls;

	/* STEPS 2 and 3: freshness, then replay, in one call. */
	fresh = fzn_replay_admit(&r->window, nonce, expires_at, FZN_EXPIRY_REQUIRED, now);
	if (fresh != FZN_FRESH_OK) {
		if (fresh == FZN_FRESH_ERR_REPLAY)
			cov->replayed++;
		else
			cov->stale++;

		/* Nothing after this may have run. */
		if (signer.calls != calls_before) {
			printf("  ORDER: a signature was verified on a frame refused for "
			       "freshness\n");
			return 1;
		}
		live_after = 0;
		for (size_t i = 0; i < SLOTS; i++)
			live_after += r->slots[i].live ? 1u : 0u;
		if (live_after != live_before) {
			printf("  ORDER: a slot was taken by a frame refused for freshness\n");
			return 1;
		}
		return 0;
	}

	/* A second presentation of the same nonce must be refused, which is
	 * the property the window exists for and is checked here rather than
	 * left to the freshness harness, because here it is the SECOND step of
	 * a sequence rather than a call on its own. */
	if (fzn_replay_admit(&r->window, nonce, expires_at, FZN_EXPIRY_REQUIRED, now) !=
	    FZN_FRESH_ERR_REPLAY) {
		printf("  ORDER: the same nonce was admitted twice in one exchange\n");
		return 1;
	}

	/* STEP 6: the capability chain, against the pinned root. */
	authorised = fzn_chain_verify(&hop, 1, root, cap, now, &sign, &r->store, &chain);

	/* AND UNDER WHOSE KEY. The hop is well formed, unexpiring, carries the
	 * capability asked for and matches no revocation -- the store is never
	 * written to -- so the ONLY thing that can refuse it is a missing
	 * signature, and the only signature that counts is the grantor's.
	 * The outcome must therefore track `root_signed` exactly. Verifying
	 * under `hop->grantee` reads 0x09's signature, which is always good,
	 * and admits a hop the root never granted. */
	if ((authorised == FZN_CHAIN_OK) != (root_signed != 0)) {
		printf("  AUTH: the chain %s while the root's signature was %s -- the hop "
		       "was verified under somebody else's key\n",
		       authorised == FZN_CHAIN_OK ? "verified" : "was refused",
		       root_signed ? "good" : "bad");
		return 1;
	}

	if (authorised != FZN_CHAIN_OK) {
		cov->unauthorised++;
		live_after = 0;
		for (size_t i = 0; i < SLOTS; i++)
			live_after += r->slots[i].live ? 1u : 0u;
		if (live_after != live_before) {
			printf("  ORDER: a slot was taken by an unauthorised frame\n");
			return 1;
		}
		return 0;
	}
	if (signer.calls - calls_before > 1) {
		printf("  ORDER: %d signature checks for a one-hop chain\n",
		       signer.calls - calls_before);
		return 1;
	}

	/* STEP 7: reassembly, last. */
	/* A DEADLINE ON THE PARTIAL MESSAGE, for the same reason the clock
	 * advances. Passing zero here means "never expires", and a four-slot
	 * table of partial messages that never expire fills as permanently as a
	 * replay window that never drains -- four admitted in twenty thousand
	 * cases, and the run measuring slot exhaustion rather than the order.
	 *
	 * Half the length of the replay window's horizon, so that a partial
	 * message gives up before the nonce that started it could be replayed. */
	admitted = fzn_reasm_accept(&r->table, sender, msg, index, chunks, payload, payload_len,
	                            now + 20u, now, &done);
	if (admitted == FZN_REASM_OK) {
		cov->admitted++;
		if (done) {
			cov->completed++;
			if (done->bytes == 0) {
				printf("  ORDER: a completed message holds no bytes\n");
				return 1;
			}
			/* AND HAND THE SLOT BACK, which this harness did not do.
			 *
			 * A completed slot is the caller's until it releases it,
			 * so it is no longer reclaimed by expiry -- otherwise a
			 * sweep takes it out from under a caller still reading
			 * it. This harness completed messages and never
			 * released, so once the table filled nothing was ever
			 * admitted again: 12 admitted in 20000 cases against
			 * about 1880 before, which the coverage floor caught.
			 *
			 * The floor doing that is the floor working. A harness
			 * that stops reaching the code it drives is exactly what
			 * it exists to refuse, and the fault was the harness's
			 * rather than the module's. */
			fzn_reasm_release(done);
		}
	}

	return 0;
}

static uint32_t next(uint32_t *state)
{
	*state = (*state * 1103515245u) + 12345u;
	return (*state >> 16) & 0xffffu;
}


/* THE FLOOR A COUNTER MUST CLEAR, AND IT IS NEVER ZERO.
 *
 * These floors were written as `floor_of(cases, 200u)` directly. Integer division
 * makes that ZERO for any run under 200 cases, and `unsigned < 0` is never
 * true -- so every coverage floor in this file switched itself off silently,
 * exactly when somebody lowered CASES. Which is precisely what one does when
 * running under a sanitizer, the case the Makefile advertises.
 *
 * Measured before this: `make fuzz CASES=199` exited 0 with chain_fuzz
 * reporting "0 delegated", the counter whose own comment says a run without
 * it "proves less than it says". At CASES=1 it reported 0 accepted and 0
 * delegated and still passed.
 *
 * One is the weakest honest floor: a harness that reached the interesting
 * path zero times out of one case has still reached it zero times. */
static unsigned long floor_of(unsigned long cases, unsigned long per)
{
	unsigned long n = cases / per;

	return n != 0ul ? n : 1ul;
}

int main(int argc, char **argv)
{
	unsigned long cases = FUZZ_DEFAULT_CASES;
	struct coverage cov = { 0, 0, 0, 0, 0 };
	static struct receiver r;
	uint8_t buf[32];

	if (argc > 1) {
		cases = strtoul(argv[1], NULL, 10);
		if (cases == 0)
			cases = FUZZ_DEFAULT_CASES;
	}

	if (cases < FUZZ_MIN_CASES) {
		printf("receive_fuzz: %lu cases is below FUZZ_MIN_CASES (%u), so this run will "
		       "not report success -- every coverage floor below that is "
		       "cleared by a single lucky hit. Re-run with %u or more.\n",
		       cases, (unsigned)FUZZ_MIN_CASES, (unsigned)FUZZ_MIN_CASES);
		return 1;
	}

	if (!receiver_init(&r)) {
		printf("receive_fuzz: the receiver would not initialise\n");
		return 1;
	}

	for (unsigned long c = 0; c < cases; c++) {
		uint32_t state = (uint32_t)c + 1u;
		size_t len = (size_t)(next(&state) % (sizeof(buf) + 1u));

		for (size_t i = 0; i < len; i++)
			buf[i] = (uint8_t)next(&state);

		if (receive_one(&r, 1000u + (uint64_t)c, buf, len, &cov)) {
			printf("receive_fuzz: FAILED on case %lu (seed %lu)\n", c, c + 1u);
			return 1;
		}
	}

	/* Every branch of the sequence must occur. A run that never got past
	 * freshness would satisfy every invariant above by never reaching the
	 * steps they are about. */
	if (cov.admitted < floor_of(cases, 200u) || cov.stale < floor_of(cases, 200u) ||
	    cov.unauthorised < floor_of(cases, 200u) || cov.replayed < floor_of(cases, 200u)) {
		printf("receive_fuzz: REACHED TOO LITTLE -- %lu admitted, %lu stale, "
		       "%lu unauthorised, %lu replayed in %lu cases.\n",
		       cov.admitted, cov.stale, cov.unauthorised, cov.replayed, cases);
		return 1;
	}

	printf("receive_fuzz: %lu cases, %lu admitted, %lu stale, %lu replayed, "
	       "%lu unauthorised, %lu completed, order held throughout\n",
	       cases, cov.admitted, cov.stale, cov.replayed, cov.unauthorised, cov.completed);
	return 0;
}
