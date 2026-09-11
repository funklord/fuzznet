/*
 * A fuzz harness for spool/transfer.c: no two live assignments overlap.
 *
 * WHY THAT PROPERTY AND WHY A HARNESS. `transfer.h` records the reason
 * itself, in the note explaining why `from` belongs to the caller: an
 * internal cursor was the obvious optimisation and it was **a second
 * mechanism producing disjoint ranges**, so the two-peer test passed with
 * the pending record removed -- the cursor accounting for disjointness on
 * its own. The header's conclusion is the one this file exists to serve:
 * *a property with two mechanisms where only one is load-bearing is a
 * property no test can hold.*
 *
 * With `from` in the caller's hands the pending record is the only mechanism
 * left, and a harness that drives `from` ADVERSARIALLY -- back to zero, into
 * the middle of a live assignment, past the end -- is what holds it. Two
 * hand-written peers cannot: they walk forward, and walking forward is the
 * thing the cursor was doing.
 *
 * WHAT IT CANNOT SEE, pinned so nobody quotes it for this. Making `overlaps`
 * treat TOUCHING ranges as overlapping survives every case here, and rightly
 * -- it is a conservative change, so it never produces an overlap, it only
 * refuses assignments it could have made. Nothing in this file measures a
 * missed opportunity, and nothing could: `transfer.h` says the search is
 * over "a bounded number of candidate ranges" and may answer
 * FZN_TRANSFER_NONE with free leaves elsewhere, so a refusal that was wrong
 * and a refusal that was allowed are the same observation from out here.
 *
 * THE MODEL IS THE PENDING SET, kept here as a plain array. Every range
 * `next_want` returns must overlap nothing in it. That is an oracle in sec
 * 270's sense: the answer is checked against a structure this file builds
 * from the operations it issued, not against a second reading of the module.
 *
 * THE WINDOW HAS TO BE ABLE TO OPEN, and the first draft of this file is the
 * reason that is said out loud. It stubbed the store, placed no bytes, and
 * therefore never completed a delivery -- so the window stayed at its floor
 * of 1, at most ONE assignment was ever live, and the overlap check compared
 * each new range against nothing. Every assertion passed and the headline
 * property was not being tested at all. The fixture below places real bytes
 * so deliveries succeed, the window opens, and several assignments are live
 * at once, which is the only arrangement in which "no two overlap" says
 * anything.
 *
 * WHAT IT DOES NOT DO IS DELIVER. `fzn_transfer_delivered` verifies against
 * the store -- "the store is right there, one bit per leaf" -- so claiming
 * delivery needs real bytes, real proofs and a real placement, which is
 * `transfer_test.c`'s fixture and not this one's subject. Here the delivery
 * path appears only as the refusal it owes: a claim for leaves the bitmap
 * does not hold must answer FZN_TRANSFER_ERR_UNKNOWN, and the harness asks
 * for that on every case.
 */

#include "../transfer.h"

#include "../../blob/blob.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FUZZ_DEFAULT_CASES 20000u
#define FUZZ_MIN_CASES 1000u

#define LEAVES 32u
#define MAX_SLOTS 8u
#define STEPS 24u

/* A REAL STORE, BUILT ONCE. The first version of this harness stubbed the
 * seams and never placed a byte, and it could not hold its own headline
 * property: the window opens only on a delivery the store supports, so it
 * stayed at its floor of 1, at most one assignment was ever live, and "no
 * two live assignments overlap" degenerated to a comparison against nothing.
 * The fixture below is deterministic, so it is built once and every case
 * reopens a fresh spool over the same root with an empty bitmap. */
static int stub_hash(void *ctx, uint8_t *out, size_t out_len, const uint8_t *in,
                     size_t in_len)
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

static const fzn_hash_ops_t HASH = { stub_hash, NULL };

static uint8_t sealed[LEAVES][FZN_BLOB_SEALED_MAX];
static size_t sealed_len[LEAVES];
static uint8_t leaf_hash[LEAVES][FZN_BLOB_HASH_LEN];
static uint8_t proof[LEAVES][FZN_BLOB_MAX_DEPTH * FZN_BLOB_HASH_LEN];
static unsigned proof_len[LEAVES];
static uint8_t the_root[FZN_BLOB_HASH_LEN];
static uint8_t disk[LEAVES * FZN_BLOB_SEALED_MAX];

static int disk_read(void *c, uint64_t o, uint8_t *b, size_t n)
{
	(void)c;
	if (o + n > sizeof(disk))
		return 0;
	memcpy(b, disk + o, n);
	return 1;
}

static int disk_write(void *c, uint64_t o, const uint8_t *b, size_t n)
{
	(void)c;
	if (o + n > sizeof(disk))
		return 0;
	memcpy(disk + o, b, n);
	return 1;
}

static const fzn_spool_ops_t OPS = { disk_read, disk_write, NULL, NULL };

static int build_fixture(void)
{
	fzn_blob_tree_t tree;
	unsigned i;

	fzn_blob_tree_init(&tree);
	for (i = 0; i < LEAVES; i++) {
		size_t j;

		sealed_len[i] = 48u + i * 3u;
		for (j = 0; j < sealed_len[i]; j++)
			sealed[i][j] = (uint8_t)((i * 37u) + j + 1u);
		if (fzn_blob_leaf_hash(&HASH, sealed[i], sealed_len[i], leaf_hash[i])
		    != FZN_BLOB_OK)
			return 0;
		if (fzn_blob_tree_push(&HASH, &tree, leaf_hash[i]) != FZN_BLOB_OK)
			return 0;
	}
	if (fzn_blob_tree_root(&HASH, &tree, the_root) != FZN_BLOB_OK)
		return 0;
	for (i = 0; i < LEAVES; i++) {
		if (fzn_blob_proof_build(&HASH, leaf_hash[0], LEAVES, i, proof[i],
		                         sizeof(proof[i]), &proof_len[i]) != FZN_BLOB_OK)
			return 0;
	}
	return 1;
}

struct live {
	uint64_t first;
	uint64_t count;
	uint64_t deadline;
	uint32_t peer;
};

struct coverage {
	unsigned long assigned;
	unsigned long refused_none;
	unsigned long refused_window;
	unsigned long failed_one;
	unsigned long expired_some;
	unsigned long expired_many;
	unsigned long delivered;
	unsigned long delivery_refused;
	unsigned long window_halved;
};

static uint32_t next(uint32_t *state)
{
	*state ^= *state << 13;
	*state ^= *state >> 17;
	*state ^= *state << 5;
	return *state;
}

static int overlaps(const struct live *a, uint64_t first, uint64_t count)
{
	return first < a->first + a->count && a->first < first + count;
}

static int fuzz_one(uint32_t seed, struct coverage *cov)
{
	uint32_t state = seed;
	fzn_spool_t spool;
	fzn_transfer_t transfer;
	fzn_transfer_assign_t assigns[MAX_SLOTS];
	struct live live[MAX_SLOTS];
	uint8_t map[FZN_SPOOL_BITMAP_LEN(LEAVES)];
	unsigned cap, n_live = 0, step, i, j;
	uint64_t now = 1000u;

	memset(map, 0, sizeof(map));
	cap = 1u + (next(&state) % MAX_SLOTS);
	memset(disk, 0, sizeof(disk));
	if (fzn_spool_open(&spool, the_root, LEAVES, map, sizeof(map), &OPS) != FZN_SPOOL_OK)
		return 1;
	if (fzn_transfer_open(&transfer, &spool, assigns, cap) != FZN_TRANSFER_OK)
		return 1;

	for (step = 0; step < STEPS; step++) {
		unsigned pick = next(&state) % 10u;

		if (pick < 5u) {
			/* ASK, WITH AN ADVERSARIAL `from`. A caller walking
			 * forward is the case a cursor would also satisfy; the
			 * interesting ones are a `from` inside a live range and
			 * a `from` that has gone backwards. */
			fzn_spool_range_t out;
			uint64_t from = next(&state) % LEAVES;
			uint64_t per = 1u + (next(&state) % 4u);
			uint32_t peer = next(&state) % 3u;
			uint64_t deadline = now + 10u + (next(&state) % 40u);
			fzn_transfer_err_t err;

			memset(&out, 0, sizeof(out));
			err = fzn_transfer_next_want(&transfer, peer, from, per, deadline,
			                             &out);
			if (err == FZN_TRANSFER_OK) {
				if (out.count == 0u || out.first + out.count > LEAVES) {
					printf("  MODEL: assigned [%llu,%llu) outside the %u "
					       "leaves\n", (unsigned long long)out.first,
					       (unsigned long long)(out.first + out.count),
					       LEAVES);
					return 1;
				}
				if (out.count > per) {
					printf("  MODEL: asked for at most %llu leaves and "
					       "was given %llu\n", (unsigned long long)per,
					       (unsigned long long)out.count);
					return 1;
				}
				for (i = 0; i < n_live; i++) {
					if (overlaps(&live[i], out.first, out.count)) {
						printf("  MODEL: [%llu,%llu) overlaps the live "
						       "assignment [%llu,%llu) -- two peers "
						       "were sent for the same bytes\n",
						       (unsigned long long)out.first,
						       (unsigned long long)(out.first + out.count),
						       (unsigned long long)live[i].first,
						       (unsigned long long)(live[i].first +
						                            live[i].count));
						return 1;
					}
				}
				if (n_live >= cap) {
					printf("  MODEL: %u assignments live with a cap of "
					       "%u\n", n_live + 1u, cap);
					return 1;
				}
				live[n_live].first = out.first;
				live[n_live].count = out.count;
				live[n_live].peer = peer;
				live[n_live].deadline = deadline;
				n_live++;
				cov->assigned++;
			} else if (err == FZN_TRANSFER_NONE) {
				cov->refused_none++;
			} else if (err == FZN_TRANSFER_FULL) {
				cov->refused_window++;
			} else {
				printf("  MODEL: next_want answered %s\n",
				       fzn_transfer_err_str(err));
				return 1;
			}
		} else if (pick < 7u && n_live > 0u) {
			/* A BATCH THAT DID NOT ARRIVE. Frees the slot, halves
			 * the window, and returns nothing to a want-list
			 * because nothing was removed from one. */
			unsigned k = next(&state) % n_live;
			unsigned before = fzn_transfer_window(&transfer);
			unsigned after;

			if (fzn_transfer_failed(&transfer, live[k].peer, live[k].first,
			                        live[k].count) != FZN_TRANSFER_OK) {
				printf("  MODEL: a live assignment could not be failed\n");
				return 1;
			}
			after = fzn_transfer_window(&transfer);
			if (after > before) {
				printf("  MODEL: a failure widened the window from %u to "
				       "%u\n", before, after);
				return 1;
			}
			if (after < before)
				cov->window_halved++;
			live[k] = live[n_live - 1u];
			n_live--;
			cov->failed_one++;
		} else if (pick < 9u && n_live > 0u) {
			/* A BATCH THAT ARRIVED. The bytes are placed for real
			 * first, because `delivered` verifies against the store
			 * rather than taking a caller's word -- so a claim only
			 * succeeds if the placement did. */
			unsigned k = next(&state) % n_live;
			uint64_t leaf;
			int placed = 1;
			fzn_transfer_err_t err;

			for (leaf = 0; leaf < live[k].count; leaf++) {
				uint64_t at = live[k].first + leaf;

				if (fzn_spool_place(&spool, &HASH, at, sealed[at],
				                    sealed_len[at], proof[at],
				                    proof_len[at]) != FZN_SPOOL_OK) {
					placed = 0;
					break;
				}
			}
			if (!placed) {
				printf("  MODEL: the fixture could not place leaves "
				       "[%llu,%llu)\n", (unsigned long long)live[k].first,
				       (unsigned long long)(live[k].first + live[k].count));
				return 1;
			}
			err = fzn_transfer_delivered(&transfer, live[k].peer, live[k].first,
			                             live[k].count);
			if (err != FZN_TRANSFER_OK) {
				printf("  MODEL: a delivery the store can support answered "
				       "%s\n", fzn_transfer_err_str(err));
				return 1;
			}
			live[k] = live[n_live - 1u];
			n_live--;
			cov->delivered++;
		} else if (pick < 9u) {
			/* A CLAIM THE STORE CANNOT SUPPORT. `delivered` is
			 * verified against the bitmap, "one bit per leaf", so a
			 * claim for a leaf nothing placed must be refused --
			 * otherwise congestion control opens on work that did
			 * not happen. */
			uint64_t at = next(&state) % LEAVES;

			if (!fzn_spool_has(&spool, at)) {
				fzn_transfer_err_t err =
				        fzn_transfer_delivered(&transfer, 0, at, 1);

				if (err != FZN_TRANSFER_ERR_UNKNOWN) {
					printf("  MODEL: a delivery of bytes the store does "
					       "not hold answered %s rather than refusing\n",
					       fzn_transfer_err_str(err));
					return 1;
				}
				cov->delivery_refused++;
			}
		} else {
			/* TIME PASSES. One decrease per loss event, however
			 * many assignments the event drops. */
			unsigned before = fzn_transfer_window(&transfer);
			unsigned after;
			size_t dropped;

			now += 20u;
			dropped = fzn_transfer_expire(&transfer, now);
			after = fzn_transfer_window(&transfer);
			/* THE MODEL KNOWS WHICH, because it chose every
			 * deadline it passed. An earlier draft could not: it
			 * zeroed the live set after any expire rather than
			 * tracking deadlines, so the module went on holding
			 * assignments the model had forgotten and the next
			 * expire reported dropping more than the model knew of.
			 * Resyncing a count is not a model. */
			{
				unsigned expected = 0;

				for (i = 0; i < n_live;) {
					if (live[i].deadline <= now) {
						live[i] = live[n_live - 1u];
						n_live--;
						expected++;
						continue;
					}
					i++;
				}
				if (dropped != expected) {
					printf("  MODEL: expire dropped %zu assignments and "
					       "%u had passed their deadline\n",
					       dropped, expected);
					return 1;
				}
			}
			if (dropped > 0u) {
				cov->expired_some++;
				if (dropped > 1u)
					cov->expired_many++;
				/* ONE HALVING, NOT ONE PER ASSIGNMENT. A stalled
				 * peer holding four batches is one failure, and
				 * charging four would collapse the window to its
				 * floor for a single event. */
				if (before > 1u && after < before / 2u) {
					printf("  MODEL: expiring %zu assignments took the "
					       "window from %u to %u -- more than one "
					       "decrease for one loss event\n",
					       dropped, before, after);
					return 1;
				}
			} else if (after != before) {
				printf("  MODEL: expiring nothing moved the window from %u "
				       "to %u\n", before, after);
				return 1;
			}
			if (fzn_transfer_in_flight(&transfer) != n_live) {
				printf("  MODEL: %zu in flight and the model holds %u\n",
				       fzn_transfer_in_flight(&transfer), n_live);
				return 1;
			}
		}

		/* THE WINDOW NEVER REACHES ZERO -- transfer.h calls that a
		 * property rather than a detail, because a transfer that cannot
		 * ask for anything can never learn the path recovered. */
		if (fzn_transfer_window(&transfer) == 0u) {
			printf("  MODEL: the window reached zero, so this transfer can "
			       "never ask for anything again\n");
			return 1;
		}
		if (fzn_transfer_in_flight(&transfer) > cap) {
			printf("  MODEL: %zu in flight with a cap of %u\n",
			       fzn_transfer_in_flight(&transfer), cap);
			return 1;
		}
	}

	(void)j;
	return 0;
}

#ifdef FZN_LIBFUZZER
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	uint32_t seed = 1u;
	size_t i;
	struct coverage cov = { 0, 0, 0, 0, 0, 0, 0, 0, 0 };

	for (i = 0; i < size; i++)
		seed = (seed * 31u) + data[i];
	if (seed == 0u)
		seed = 1u;
	if (!build_fixture())
		return 0;
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
	struct coverage cov = { 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	unsigned long c;

	if (argc > 1) {
		cases = strtoul(argv[1], NULL, 10);
		if (cases == 0)
			cases = FUZZ_DEFAULT_CASES;
	}
	if (cases < FUZZ_MIN_CASES) {
		printf("transfer_fuzz: %lu cases is below FUZZ_MIN_CASES (%u).\n", cases,
		       (unsigned)FUZZ_MIN_CASES);
		return 1;
	}

	/* THE STORE IS DETERMINISTIC, so it is built once and every case
	 * reopens a fresh spool over the same root. A failure here is the
	 * fixture and not the subject, and it says so. */
	if (!build_fixture()) {
		printf("transfer_fuzz: the fixture could not build its leaves, so no case "
		       "below would have meant anything.\n");
		return 1;
	}

	for (c = 0; c < cases; c++) {
		if (fuzz_one((uint32_t)c + 1u, &cov)) {
			printf("transfer_fuzz: FAILED on case %lu (seed %lu)\n", c, c + 1u);
			return 1;
		}
	}

	if (cov.assigned < floor_of(cases, 2u) || cov.refused_window < floor_of(cases, 20u)
	    || cov.failed_one < floor_of(cases, 4u) || cov.expired_some < floor_of(cases, 20u)
	    || cov.delivery_refused < floor_of(cases, 4u)
	    || cov.delivered < floor_of(cases, 4u)
	    || cov.expired_many < floor_of(cases, 100u)
	    || cov.window_halved < floor_of(cases, 20u)) {
		printf("transfer_fuzz: REACHED TOO LITTLE -- %lu assigned, %lu none, %lu "
		       "window full, %lu failed, %lu expired, %lu multi-expiries, %lu "
		       "delivered, %lu refused, %lu halvings, in %lu cases.\n",
		       cov.assigned, cov.refused_none, cov.refused_window, cov.failed_one,
		       cov.expired_some, cov.expired_many, cov.delivered,
		       cov.delivery_refused, cov.window_halved, cases);
		return 1;
	}

	printf("transfer_fuzz: %lu cases, %lu assigned and none overlapped, %lu found "
	       "nothing free, %lu found the window closed, %lu failed, %lu expiries "
	       "(%lu dropping more than one), %lu delivered, %lu refused, %lu "
	       "halvings\n",
	       cases, cov.assigned, cov.refused_none, cov.refused_window, cov.failed_one,
	       cov.expired_some, cov.expired_many, cov.delivered, cov.delivery_refused,
	       cov.window_halved);
	return 0;
}
#endif
