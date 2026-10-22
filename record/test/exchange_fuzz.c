/*
 * A fuzz harness for the journal exchange, `record/exchange.h`: sec 689's
 * first journey, the estate, whose every setting, grant and roster change
 * travels this way between hosts.
 *
 * WHY THIS ONE. A pull reads a peer's digest pages and its RECORDS
 * messages, and a push's taker reads a PUSH: every byte of each chosen by
 * the peer, a member of the estate or something that has its session. The
 * records inside are signed and the journal chains them, so the claim to
 * test is that no answer, however bent, gets a record held that its
 * issuer did not sign as the next of its stream.
 *
 * THE PEER LIES BY MUTATION. The server here is honest and holds only
 * genuine records, so any record the follower ends up holding that is not
 * byte for byte one of them was let in by a bent message. Each answer the
 * server gives -- and each PUSH the pusher sends -- is bent with even odds:
 * bits flipped, cut short, grown, a length field set to its extremes, a
 * slice repeated or two swapped.
 *
 * THE PROPERTIES:
 *   1. GENUINE ONLY. Every record the follower holds is the genuine record
 *      for its issuer, stream and sequence.
 *   2. NO GAPS, NOTHING AHEAD. A stream's records are held from 1 up to
 *      what its journal says it has received, and none beyond.
 *   3. NEVER MORE THAN THERE IS. A tally learns no more than the server
 *      holds of the streams followed.
 *   4. THE SERVER'S ANSWER IS BOUNDED AND A FUNCTION. Asked a bent request
 *      at a random cap, it writes at most the cap and answers the same
 *      bytes twice.
 *
 * FLOORS ON WHAT WAS REACHED, as `sync_fuzz` keeps them: a run that never
 * learned through a bent message, never refused one, never took a push or
 * never had a bent request answered has not tested what it claims, and
 * fails rather than reporting success.
 */

#include "../exchange.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FUZZ_DEFAULT_CASES 4000u
#define FUZZ_MIN_CASES 1000u

/* ---- the signer and hash, as exchange_test's: keyed by the key's first
 * byte, so a record verifies under the key it was signed as and no other --- */

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

/* ---- the generator ------------------------------------------------------ */

static uint32_t rng;

static uint32_t next(void)
{
	rng ^= rng << 13;
	rng ^= rng >> 17;
	rng ^= rng << 5;
	return rng;
}

static uint32_t below(uint32_t n)
{
	return n ? next() % n : 0u;
}

/* ---- two hosts in one process ------------------------------------------- */

#define SLOTS 64

struct slot {
	uint8_t issuer[FZN_PUBKEY_LEN];
	uint32_t stream;
	uint64_t seq;
	uint8_t bytes[FZN_RECORD_MAX_LEN];
	size_t len;
	int used;
};

struct host {
	struct slot slots[SLOTS];
	fzn_record_store_ops_t ops;
	fzn_record_store_t store;
	fzn_journal_entry_t entries[8];
	fzn_journal_t journal;
};

static int mem_put(void *ctx, const uint8_t issuer[FZN_PUBKEY_LEN], uint32_t stream, uint64_t seq,
                   const uint8_t *bytes, size_t len)
{
	struct host *h = ctx;
	int i, free_one = -1;

	if (len > FZN_RECORD_MAX_LEN)
		return 0;
	for (i = 0; i < SLOTS; i++) {
		if (!h->slots[i].used) {
			if (free_one < 0)
				free_one = i;
			continue;
		}
		if (h->slots[i].stream == stream && h->slots[i].seq == seq
		    && memcmp(h->slots[i].issuer, issuer, FZN_PUBKEY_LEN) == 0) {
			free_one = i;
			break;
		}
	}
	if (free_one < 0)
		return 0;
	memcpy(h->slots[free_one].issuer, issuer, FZN_PUBKEY_LEN);
	h->slots[free_one].stream = stream;
	h->slots[free_one].seq = seq;
	memcpy(h->slots[free_one].bytes, bytes, len);
	h->slots[free_one].len = len;
	h->slots[free_one].used = 1;
	return 1;
}

static int mem_get(void *ctx, const uint8_t issuer[FZN_PUBKEY_LEN], uint32_t stream, uint64_t seq,
                   uint8_t *out, size_t cap, size_t *len_out, int *found_out)
{
	struct host *h = ctx;
	int i;

	*found_out = 0;
	for (i = 0; i < SLOTS; i++)
		if (h->slots[i].used && h->slots[i].stream == stream && h->slots[i].seq == seq
		    && memcmp(h->slots[i].issuer, issuer, FZN_PUBKEY_LEN) == 0) {
			*found_out = 1;
			if (h->slots[i].len > cap)
				return 0;
			memcpy(out, h->slots[i].bytes, h->slots[i].len);
			*len_out = h->slots[i].len;
			return 1;
		}
	return 0;
}

static void host_init(struct host *h)
{
	memset(h, 0, sizeof(*h));
	h->ops.put = mem_put;
	h->ops.get = mem_get;
	h->ops.ctx = h;
	h->store.ops = &h->ops;
	h->store.log = NULL;
	(void)fzn_journal_init(&h->journal, h->entries, 8);
}

/* ---- the genuine records -------------------------------------------------- */

#define WRITERS 2
#define MAX_SEQ 6
static const uint8_t WRITER[WRITERS] = { 0x11, 0x22 };
static const uint64_t LENGTH[WRITERS] = { 6u, 3u };

static uint8_t genuine[WRITERS][MAX_SEQ][FZN_RECORD_MAX_LEN];
static size_t genuine_len[WRITERS][MAX_SEQ];
static uint8_t genuine_id[WRITERS][MAX_SEQ][FZN_RECORD_ID_LEN];

static void key(uint8_t out[FZN_PUBKEY_LEN], uint8_t seed)
{
	size_t i;

	for (i = 0; i < FZN_PUBKEY_LEN; i++)
		out[i] = (uint8_t)(seed + i * 7u);
	out[0] = seed;
}

static int make_genuine(void)
{
	uint8_t issuer[FZN_PUBKEY_LEN], subject[FZN_SUBJECT_LEN], body[40];
	size_t w;
	uint64_t s;

	memset(subject, 0x5b, sizeof(subject));
	for (w = 0; w < WRITERS; w++) {
		key(issuer, WRITER[w]);
		for (s = 1; s <= LENGTH[w]; s++) {
			memset(body, (int)(s + w * 16u), sizeof(body));
			signing_as = WRITER[w];
			if (fzn_record_sign(issuer, subject, 1u, 9u, s,
			                    s == 1u ? NULL : genuine_id[w][s - 2u], 100u + s, body,
			                    sizeof(body), &SIGN, genuine[w][s - 1u], FZN_RECORD_MAX_LEN,
			                    &genuine_len[w][s - 1u]) != FZN_RECORD_OK
			    || !mix_hash(NULL, genuine_id[w][s - 1u], FZN_RECORD_ID_LEN, genuine[w][s - 1u],
			                 genuine_len[w][s - 1u]))
				return 0;
		}
	}
	return 1;
}

/* `h` holds writer `w`'s first `n`: followed, admitted and stored. */
static int hold(struct host *h, size_t w, uint64_t n)
{
	uint8_t issuer[FZN_PUBKEY_LEN];
	fzn_record_t r;
	uint64_t s;

	key(issuer, WRITER[w]);
	if (fzn_journal_anchor(&h->journal, issuer, 1u, 0) != FZN_JOURNAL_OK)
		return 0;
	for (s = 1; s <= n; s++)
		if (fzn_record_open(genuine[w][s - 1u], genuine_len[w][s - 1u], &r) != FZN_RECORD_OK
		    || fzn_journal_admit_chained(&h->journal, issuer, 1u, s, fzn_record_prev(r),
		                                 genuine_id[w][s - 1u]) != FZN_JOURNAL_OK
		    || fzn_record_store_put(&h->store, r) != FZN_RECORD_STORE_OK)
			return 0;
	return 1;
}

/* ---- the lie ---------------------------------------------------------------- */

static size_t bend(uint8_t *buf, size_t len, size_t cap)
{
	size_t i, at, n, b;

	switch (below(6u)) {
	case 0: /* bits flipped */
		for (i = 1u + below(4u); i > 0 && len; i--)
			buf[below((uint32_t)len)] ^= (uint8_t)(1u << below(8u));
		return len;
	case 1: /* cut short */
		return len ? below((uint32_t)len) : 0u;
	case 2: /* grown */
		n = below(64u);
		for (i = 0; i < n && len < cap; i++)
			buf[len++] = (uint8_t)next();
		return len;
	case 3: /* a two-byte field at its extremes */
		if (len >= 2u) {
			at = below((uint32_t)(len - 1u));
			b = below(2u) ? 0xffu : 0x00u;
			buf[at] = (uint8_t)b;
			buf[at + 1u] = (uint8_t)b;
		}
		return len;
	case 4: /* a slice repeated */
		if (len >= 2u) {
			at = below((uint32_t)len);
			n = 1u + below((uint32_t)(len - at));
			if (len + n <= cap) {
				memmove(buf + at + n, buf + at, len - at);
				len += n;
			}
		}
		return len;
	default: /* two bytes swapped */
		if (len >= 2u) {
			uint8_t t;

			at = below((uint32_t)len);
			b = below((uint32_t)len);
			t = buf[at];
			buf[at] = buf[b];
			buf[b] = t;
		}
		return len;
	}
}

static struct host server, follower;
static uint8_t reply[8192];

struct coverage {
	unsigned long bent, learned_bent, refused, pushed_taken, answered_bent, cases;
};
static struct coverage cov;
static int bent_this;

/* THE LYING SERVER: the honest answer, bent with even odds. */
static int lying_ask(void *ctx, const uint8_t *request, size_t request_len, uint8_t *out,
                     size_t out_cap, size_t *out_len)
{
	(void)ctx;
	*out_len = fzn_exchange_answer(&server.journal, &server.store, request, request_len, out,
	                               out_cap);
	if (*out_len && below(2u)) {
		*out_len = bend(out, *out_len, out_cap);
		cov.bent++;
		bent_this = 1;
	}
	return *out_len != 0u;
}

/* THE LYING PUSHER: each message bent with even odds before the taker reads
 * it; a digest asked is answered by the follower, honestly. */
static int lying_push_ask(void *ctx, const uint8_t *request, size_t request_len, uint8_t *out,
                          size_t out_cap, size_t *out_len)
{
	static uint8_t bent[8192];
	size_t n = request_len < sizeof(bent) ? request_len : sizeof(bent);

	(void)ctx;
	memcpy(bent, request, n);
	if (below(2u)) {
		n = bend(bent, n, sizeof(bent));
		cov.bent++;
		bent_this = 1;
	}
	*out_len = fzn_exchange_take_push(&follower.journal, &follower.store, &SIGN, &HASH, bent, n,
	                                  out, out_cap);
	if (*out_len)
		return 1;
	*out_len = fzn_exchange_answer(&follower.journal, &follower.store, bent, n, out, out_cap);
	return *out_len != 0u;
}

/* ---- the properties ------------------------------------------------------- */

static int follower_holds_only_genuine(unsigned long c)
{
	uint8_t issuer[FZN_PUBKEY_LEN];
	size_t i, w;

	for (i = 0; i < SLOTS; i++) {
		const struct slot *sl = &follower.slots[i];
		int found = 0;

		if (!sl->used)
			continue;
		for (w = 0; w < WRITERS; w++) {
			uint64_t got;

			key(issuer, WRITER[w]);
			if (memcmp(sl->issuer, issuer, FZN_PUBKEY_LEN) != 0)
				continue;
			got = fzn_journal_next(&follower.journal, issuer, 1u) - 1u;
			/* 1 and 2: genuine, and within what the journal received. */
			if (sl->stream != 1u || sl->seq == 0u || sl->seq > LENGTH[w] || sl->seq > got
			    || sl->len != genuine_len[w][sl->seq - 1u]
			    || memcmp(sl->bytes, genuine[w][sl->seq - 1u], sl->len) != 0) {
				printf("exchange_fuzz: case %lu: writer %02x holds a record at %llu that "
				       "is not its genuine one, or is past what was received (%llu)\n",
				       c, WRITER[w], (unsigned long long)sl->seq, (unsigned long long)got);
				return 0;
			}
			found = 1;
		}
		if (!found) {
			printf("exchange_fuzz: case %lu: a record of an issuer nobody wrote is held\n", c);
			return 0;
		}
	}
	/* 2: no gaps -- every sequence up to what was received is held. */
	for (w = 0; w < WRITERS; w++) {
		uint64_t got, s;
		int found;

		key(issuer, WRITER[w]);
		got = fzn_journal_next(&follower.journal, issuer, 1u) - 1u;
		for (s = 1; s <= got; s++) {
			found = 0;
			for (i = 0; i < SLOTS && !found; i++)
				found = follower.slots[i].used && follower.slots[i].seq == s
				        && memcmp(follower.slots[i].issuer, issuer, FZN_PUBKEY_LEN) == 0;
			if (!found) {
				printf("exchange_fuzz: case %lu: writer %02x received %llu with %llu "
				       "missing\n", c, WRITER[w], (unsigned long long)got,
				       (unsigned long long)s);
				return 0;
			}
		}
	}
	return 1;
}

static int fuzz_one(unsigned long c)
{
	static uint8_t pool[16][FZN_EXCHANGE_RECORDS_QUERY_LEN + 64u];
	static size_t pool_len[16], pooled;
	size_t w, cap, a, b;
	uint64_t had[WRITERS], held_total = 0;
	int mode = (int)below(3u);

	rng = (uint32_t)(c * 2654435761u) ^ 0x5bd1e995u;
	if (!rng)
		rng = 1u;
	bent_this = 0;
	host_init(&server);
	host_init(&follower);
	for (w = 0; w < WRITERS; w++) {
		if (!hold(&server, w, LENGTH[w]))
			return 0;
		/* THE FOLLOWER holds a prefix of each, perhaps none. */
		had[w] = below((uint32_t)LENGTH[w] + 1u);
		if (!hold(&follower, w, had[w]))
			return 0;
		held_total += LENGTH[w] - had[w];
	}
	if (mode == 0) {
		fzn_exchange_tally_t t;

		memset(&t, 0, sizeof(t));
		(void)fzn_exchange_pull(&follower.journal, &follower.store, &SIGN, &HASH,
		                        1u + below(4u), lying_ask, NULL, reply, sizeof(reply), &t);
		/* 3: no more learned than there was to learn. */
		if (t.learned > held_total) {
			printf("exchange_fuzz: case %lu: learned %zu of %llu\n", c, t.learned,
			       (unsigned long long)held_total);
			return 0;
		}
		if (bent_this && t.learned)
			cov.learned_bent++;
		if (t.refused)
			cov.refused++;
	} else if (mode == 1) {
		fzn_exchange_push_tally_t t;

		memset(&t, 0, sizeof(t));
		(void)fzn_exchange_push(&server.journal, &server.store, lying_push_ask, NULL, reply,
		                        sizeof(reply), &t);
		if (t.taken > held_total) {
			printf("exchange_fuzz: case %lu: a push was taken %zu of %llu\n", c, t.taken,
			       (unsigned long long)held_total);
			return 0;
		}
		if (bent_this && t.taken)
			cov.pushed_taken++;
	} else {
		/* 4: a bent request, at a random cap, bounded and the same twice. */
		static uint8_t first[8192], second[8192], req[FZN_EXCHANGE_RECORDS_QUERY_LEN + 64u];
		fzn_exchange_tally_t t;
		size_t n, len1, len2;

		if (pooled < 16u) {
			/* SEED THE POOL from an honest pull's own requests. */
			struct {
				fzn_exchange_pulling_t p;
			} *s = calloc(1, sizeof(*s));
			int done = 0;

			if (!s)
				return 0;
			memset(&t, 0, sizeof(t));
			if (fzn_exchange_pull_begin(&s->p, &follower.journal, &follower.store, &SIGN, &HASH,
			                            2u, req, sizeof(req), &n) == FZN_EXCHANGE_OK) {
				while (!done && pooled < 16u) {
					memcpy(pool[pooled], req, n);
					pool_len[pooled++] = n;
					len1 = fzn_exchange_answer(&server.journal, &server.store, req, n, first,
					                           sizeof(first));
					if (fzn_exchange_pull_step(&s->p, len1 ? first : NULL, len1, req,
					                           sizeof(req), &n, &done) != FZN_EXCHANGE_OK)
						break;
				}
			}
			free(s);
		}
		if (!pooled)
			return 1;
		a = below((uint32_t)pooled);
		n = pool_len[a];
		memcpy(req, pool[a], n);
		n = bend(req, n, sizeof(req));
		cap = 1u + below(sizeof(first) - 1u);
		len1 = fzn_exchange_answer(&server.journal, &server.store, req, n, first, cap);
		len2 = fzn_exchange_answer(&server.journal, &server.store, req, n, second, cap);
		if (len1 > cap || len1 != len2 || memcmp(first, second, len1) != 0) {
			printf("exchange_fuzz: case %lu: an answer of %zu at a cap of %zu, or not the "
			       "same twice (%zu)\n", c, len1, cap, len2);
			return 0;
		}
		if (len1)
			cov.answered_bent++;
		cov.cases++;
		return 1;
	}
	cov.cases++;
	(void)b;
	return follower_holds_only_genuine(c);
}

static unsigned long floor_of(unsigned long cases, unsigned long per)
{
	unsigned long f = cases / per;

	return f ? f : 1u;
}

int main(int argc, char **argv)
{
	unsigned long cases = FUZZ_DEFAULT_CASES, c;

	if (argc > 1) {
		cases = strtoul(argv[1], NULL, 10);
		if (cases == 0)
			cases = FUZZ_DEFAULT_CASES;
	}
	if (cases < FUZZ_MIN_CASES) {
		printf("exchange_fuzz: %lu cases is below FUZZ_MIN_CASES (%u), so this run will not "
		       "report success. Re-run with %u or more.\n", cases, (unsigned)FUZZ_MIN_CASES,
		       (unsigned)FUZZ_MIN_CASES);
		return 1;
	}
	if (!make_genuine()) {
		printf("exchange_fuzz: the genuine records would not sign\n");
		return 1;
	}
	for (c = 0; c < cases; c++)
		if (!fuzz_one(c + 1u)) {
			printf("exchange_fuzz: FAILED on case %lu\n", c + 1u);
			return 1;
		}
	/* FLOORS: what a run must have reached to have tested anything. */
	if (cov.learned_bent < floor_of(cases, 40u) || cov.refused < floor_of(cases, 40u)
	    || cov.pushed_taken < floor_of(cases, 40u) || cov.answered_bent < floor_of(cases, 40u)) {
		printf("exchange_fuzz: REACHED TOO LITTLE -- %lu bent, %lu learned through a bent "
		       "message, %lu refused, %lu pushes taken bent, %lu bent requests answered, in "
		       "%lu cases\n", cov.bent, cov.learned_bent, cov.refused, cov.pushed_taken,
		       cov.answered_bent, cases);
		return 1;
	}
	printf("exchange_fuzz: %lu cases, %lu bent messages, %lu learned through one, %lu "
	       "refused, %lu pushes taken bent, %lu bent requests answered; every record held "
	       "genuine\n", cases, cov.bent, cov.learned_bent, cov.refused, cov.pushed_taken,
	       cov.answered_bent);
	return 0;
}
