/* A fuzz harness for `record/`'s byte-level parser, its encoder, and the
 * binding between them.
 *
 * WHY THIS EXISTS. `record.h` became a VIEW OVER ITS OWN BYTES, which added
 * the newest attacker-facing parser in the tree: `fzn_record_open` reads a
 * length, a version byte, an object byte and an embedded `body_len` out of a
 * buffer a stranger chose, and `fzn_record_is_open` is the guard `state/` and
 * `log/` use as their entry gate. Both were swept once by hand under
 * AddressSanitizer and found clean. A sweep is a snapshot; this is what makes
 * it continuous.
 *
 * IT IS NOT record_guided.c AGAIN. That harness drives `record/`, `state/`
 * and `log/` TOGETHER against a model of ORDER -- journal positions, cell
 * precedence, log retention -- and its signer is a constant, because nothing
 * in it calls `fzn_record_verify`. It never varies a byte of an encoding: it
 * mints every record through `fzn_record_sign` and opens it immediately. So
 * the parser sees exactly one shape, and authenticity is not on trial there
 * at all. This file is the other half: one module, hostile bytes, and a
 * signer whose answer depends on every byte it is handed.
 *
 * WHAT IT ASSERTS. Five properties, each a claim `record.h` makes:
 *
 *   1. ROUND TRIP. Whatever `fzn_record_sign` produces, `fzn_record_open`
 *      accepts, `fzn_record_verify` confirms, and every accessor returns what
 *      was signed. Driven at the edges -- sequence 1 and UINT64_MAX,
 *      `body_len` 0 and FZN_RECORD_BODY_MAX, all-zero and all-ones keys --
 *      rather than only at whatever the middle of the range happens to be.
 *
 *   2. CANONICALITY, in both directions. The same fields encode to the same
 *      bytes twice; an OPENED record re-encodes, from its accessors alone, to
 *      the identical bytes; and across every length from 0 to four past the
 *      record, EXACTLY ONE opens. That last one is the injectivity claim
 *      stated as something a harness can count: two different byte strings
 *      must not open to one logical record, and a buffer differing only in
 *      how much of it the caller claims is the cheapest such pair to build.
 *
 *   3. THE BINDING. Mutate any single byte of a signed record and either the
 *      parse refuses or the signature does -- never both accept. This is the
 *      defect the rewrite of `record.h` closed: before it, a genuine record
 *      verified with its subject rewritten, its stream moved, its kind
 *      changed, its body swapped and its `body_len` grown from 4 to 64. It is
 *      the one property here worth watching forever, and it is checked over
 *      arbitrary offsets rather than the seven `record_test.c` names by hand.
 *
 *   4. REFUSAL COSTS NOTHING. A refused `fzn_record_open` leaves the caller's
 *      view byte-identical to what it was, so a rejected buffer cannot be
 *      half-read. A refused `fzn_record_sign` leaves `*out_len` untouched --
 *      and, where the SIGNER is what refused, must not leave the previous
 *      record's signature sitting under the new record's header. That case is
 *      built to bite: the second sign asks for the SAME fields as the first,
 *      so a stale signature would produce a buffer that opens and verifies.
 *
 *   5. `fzn_record_is_open` AGREES WITH `fzn_record_open`. It was found
 *      accepting a view whose embedded `body_len` disagreed with its buffer,
 *      and the overflow that followed landed in consumer code where no reader
 *      would blame this library. It has been fixed; keeping the two in step
 *      is what this counts, on every buffer either of them sees.
 *
 *      THEY DO NOT AGREE COMPLETELY, and the harness says so rather than
 *      hiding it. `fzn_record_open` refuses sequence zero; `fzn_record_is_open`
 *      does not test the sequence at all. Measured: a 156-byte buffer with a
 *      good version byte, a good object byte, `body_len` 0 and an all-zero
 *      sequence gives FZN_RECORD_ERR_SEQ_ZERO from `open` and 1 from
 *      `is_open`. That is not a memory-safety gap -- the sequence is inside
 *      the buffer either guard admits -- but `record.h` says `is_open`
 *      "REPEATS THE STRUCTURAL PART of `fzn_record_open`" and names only the
 *      signature as what it leaves out. So the divergence is COUNTED, in
 *      `guard_gap` below, and any disagreement that is NOT sequence zero
 *      fails the run. The counter has no floor, deliberately: a floor on it
 *      would make the harness fail the day somebody closes the gap.
 *
 * HOSTILE INPUT, NOT ONLY MUTATED-GOOD INPUT. Every case feeds four
 * families: truncations at every length and four past the end; a record with
 * one FIELD rewritten to an edge value -- wrong version, wrong object,
 * `body_len` of 0, of the maximum, of one past it, of a random sixteen bits,
 * sequence zero, sequence all-ones; a single flipped byte anywhere; and a
 * buffer of random bytes, sometimes with the two tag bytes and the length
 * fixed up so that it gets past the front door and the accessors run over
 * garbage. The last is what a sanitizer needs in order to have something to
 * say.
 *
 * THE ORACLE IS WRITTEN FROM THE HEADER'S TABLE, IN LITERALS. `open_ought`
 * below spells 92, 156, 512, 64, 74, 90, 1 and 3 rather than including the
 * constants, because an oracle that asks the module for the offsets agrees
 * with the module however the module is wrong -- `evidence.md`'s independence
 * rule. The literals are tied back with `_Static_assert`, so a DELIBERATE
 * layout change stops the build here and names the line to edit, instead of
 * producing a runtime disagreement somebody has to diagnose.
 *
 * TERMINATION, because it runs unattended. `main` performs a fixed number of
 * cases -- argv[1] or FUZZ_DEFAULT_CASES -- from a seeded generator with no
 * entropy in it, so the run is bounded, reproducible from the source alone,
 * and prints the failing case's seed. It allocates nothing, opens nothing and
 * spawns nothing.
 *
 * It also compiles as a libFuzzer target under -DFZN_LIBFUZZER, the same way
 * chunk/test/reassembly_fuzz.c and chain/test/chain_fuzz.c do, so a longer
 * campaign with coverage feedback needs no second harness to drift from this
 * one.
 */

#include "../record.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

/* THE LAYOUT AS THE HEADER'S TABLE STATES IT, NOT AS THE HEADER'S MACROS
 * COMPUTE IT. See the note at the top: an oracle that indexes with
 * FZN_RECORD_OFF_* would move wherever the module moved and agree with it
 * silently. These are the numbers a reader checks the table against, and
 * `record.c` already asserts the same eight against the running sum -- so
 * this is a third witness to the same fact rather than a copy of either.
 *
 * The asserts below are what makes that affordable. A deliberate layout
 * change fails the build here, at the line that needs editing. */
#define WANT_VERSION      1u
#define WANT_OBJECT       130u
#define WANT_OFF_SEQ      74u
#define WANT_OFF_BODY_LEN 90u
#define WANT_HEADER_LEN   92u
#define WANT_BODY_MAX     512u
#define WANT_SIG_LEN      64u
#define WANT_MIN_LEN      156u
#define WANT_MAX_LEN      668u

_Static_assert(WANT_VERSION == (unsigned)FZN_SIGNED_VERSION, "oracle: the version byte moved");
_Static_assert(WANT_OBJECT == (unsigned)FZN_OBJECT_RECORD, "oracle: the object byte moved");
_Static_assert(WANT_OFF_SEQ == FZN_RECORD_OFF_SEQ, "oracle: seq moved");
_Static_assert(WANT_OFF_BODY_LEN == FZN_RECORD_OFF_BODY_LEN, "oracle: body_len moved");
_Static_assert(WANT_HEADER_LEN == FZN_RECORD_HEADER_LEN, "oracle: the header is not 92 bytes");
_Static_assert(WANT_BODY_MAX == FZN_RECORD_BODY_MAX, "oracle: the body bound moved");
_Static_assert(WANT_SIG_LEN == FZN_SIG_LEN, "oracle: the signature length moved");
_Static_assert(WANT_MIN_LEN == FZN_RECORD_MIN_LEN, "oracle: an empty record is not 156 bytes");
_Static_assert(WANT_MAX_LEN == FZN_RECORD_MAX_LEN, "oracle: a full record is not 668 bytes");

/* Four past the longest record, so that a length ABOVE the one the bytes
 * claim is an ordinary case rather than one nobody can construct. The slack
 * is real storage: `fzn_record_signature` on a view four bytes too long
 * reads four bytes past the record, and it must land inside the harness's
 * own buffer rather than past it. */
#define OVERSHOOT 4u
#define PROBE_CAP (FZN_RECORD_MAX_LEN + OVERSHOOT)

/* WHERE THE ACCESSORS' RESULTS GO. Reading a field and throwing it away is
 * something the optimiser may delete outright, and a read the compiler
 * deleted is one AddressSanitizer never sees. Everything an accessor returns
 * is folded in here, so the loads happen. */
static volatile uint64_t sink;

struct stub {
	unsigned long verifies;
	unsigned long signs;
	/* THE SIGNER SAYS NO. Not an error path a caller can reach by passing
	 * a bad argument -- this is a signer in another process, or in
	 * hardware, declining. It is the only way to reach the branch in
	 * `fzn_record_sign` that must not leave a stale signature behind. */
	int refuse;
	uint8_t key[FZN_PUBKEY_LEN];
};

/* A STAND-IN THAT DEPENDS ON EVERY BYTE IT IS HANDED, and on who signed. Not
 * cryptography: FNV-1a over the key and then the message, smeared across 64
 * bytes. What matters is only that flipping any single bit of either input
 * changes the result, because that is what makes property 3 measurable at
 * all. A stub that ignored its message is exactly what let the defect this
 * harness watches for live in the tree unseen. */
static void tag(uint8_t out[FZN_SIG_LEN], const uint8_t key[FZN_PUBKEY_LEN], const uint8_t *msg,
                size_t msg_len)
{
	uint64_t h = 14695981039346656037u;
	size_t i;

	for (i = 0; i < FZN_PUBKEY_LEN; i++) {
		h ^= key[i];
		h *= 1099511628211u;
	}
	for (i = 0; i < msg_len; i++) {
		h ^= msg[i];
		h *= 1099511628211u;
	}
	for (i = 0; i < FZN_SIG_LEN; i++) {
		h ^= (uint64_t)i + 1u;
		h *= 1099511628211u;
		out[i] = (uint8_t)(h >> 56);
	}
}

/* Verifies under the key it is GIVEN, which is the record's issuer. A stub
 * that verified under a fixed key could not tell a verifier reading the
 * issuer from one reading the subject -- the party a statement is about
 * rather than the party asserting it. */
static int stub_verify(void *ctx, const uint8_t pubkey[FZN_PUBKEY_LEN], const uint8_t *msg,
                       size_t msg_len, const uint8_t sig[FZN_SIG_LEN])
{
	struct stub *s = (struct stub *)ctx;
	uint8_t want[FZN_SIG_LEN];

	s->verifies++;
	if (!msg || msg_len == 0)
		return 0;
	tag(want, pubkey, msg, msg_len);
	return memcmp(want, sig, FZN_SIG_LEN) == 0;
}

static int stub_sign(void *ctx, uint8_t sig[FZN_SIG_LEN], const uint8_t *msg, size_t msg_len)
{
	struct stub *s = (struct stub *)ctx;

	s->signs++;
	if (s->refuse)
		return 0;
	if (!msg || msg_len == 0)
		return 0;
	tag(sig, s->key, msg, msg_len);
	return 1;
}

/* How much of the module a run actually reached. Counted rather than
 * assumed, because a harness that reaches nothing reports "no invariant
 * broken" exactly as loudly as one that reached everything. */
struct coverage {
	unsigned long minted;        /* records `fzn_record_sign` produced */
	unsigned long body_zero;     /* ... of those, with an empty body */
	unsigned long body_max;      /* ... with FZN_RECORD_BODY_MAX bytes */
	unsigned long seq_edge;      /* ... at sequence 1 or UINT64_MAX */
	unsigned long sign_refused;  /* signs the module or the signer refused */
	unsigned long probe_open;    /* probe buffers `fzn_record_open` accepted */
	unsigned long probe_shape;   /* ... refused as SHAPE */
	unsigned long probe_body;    /* ... refused as BODY_TOO_LARGE */
	unsigned long probe_seq;     /* ... refused as SEQ_ZERO */
	unsigned long tamper_parse;  /* single-byte mutations the parser caught */
	unsigned long tamper_verify; /* ... and those the signature caught */
	/* THE ONE DIVERGENCE, counted rather than asserted away. See the note
	 * at the top of this file: `fzn_record_is_open` does not test the
	 * sequence and `fzn_record_open` does. No floor -- closing the gap
	 * must not fail the run. */
	unsigned long guard_gap;
};

/* The fields a record carries, so that a case can be drawn once and then
 * signed, re-signed and compared without a twelve-argument call at each
 * step. `fzn_record_sign`'s argument order is the layout order and is also
 * its hazard -- `issuer` and `subject` are both 32 bytes and `stream` and
 * `kind` are both uint32, so a swap at a call site says nothing. Naming them
 * once is what keeps this harness from making that mistake in three places. */
struct fields {
	uint8_t issuer[FZN_PUBKEY_LEN];
	uint8_t subject[FZN_SUBJECT_LEN];
	uint32_t stream;
	uint32_t kind;
	uint64_t seq;
	uint64_t issued_at;
	const uint8_t *body;
	size_t body_len;
};

/* WHAT `fzn_record_open` MUST ANSWER, derived from the header's table and
 * from nothing else. A second implementation, deliberately: a check that
 * asked the parser whether the parser was right would agree with it always,
 * including when both are wrong.
 *
 * It answers the exact error CODE rather than accept-or-refuse, because the
 * taxonomy is a promise too -- BODY_TOO_LARGE is a sizing decision a consumer
 * can act on and SHAPE is not, and the header says the bound is tested before
 * the length agreement so that an oversized body is reported as the former. A
 * model that only counted refusals could not see those two swap. */
static fzn_record_err_t open_ought(const uint8_t *bytes, size_t len)
{
	size_t body_len;
	uint64_t seq = 0;
	size_t i;

	if (!bytes)
		return FZN_RECORD_ERR_MALFORMED;
	if (len < WANT_MIN_LEN)
		return FZN_RECORD_ERR_SHAPE;
	if (bytes[0] != WANT_VERSION)
		return FZN_RECORD_ERR_SHAPE;
	if (bytes[1] != WANT_OBJECT)
		return FZN_RECORD_ERR_SHAPE;

	body_len = ((size_t)bytes[WANT_OFF_BODY_LEN] << 8) | (size_t)bytes[WANT_OFF_BODY_LEN + 1u];
	if (body_len > WANT_BODY_MAX)
		return FZN_RECORD_ERR_BODY_TOO_LARGE;
	if (len != WANT_HEADER_LEN + body_len + WANT_SIG_LEN)
		return FZN_RECORD_ERR_SHAPE;

	for (i = 0; i < 8u; i++)
		seq = (seq << 8) | (uint64_t)bytes[WANT_OFF_SEQ + i];
	if (seq == 0)
		return FZN_RECORD_ERR_SEQ_ZERO;

	return FZN_RECORD_OK;
}

/* Write the embedded `body_len` field, big-endian, by hand. `fzn_put_be16`
 * would do it -- and would make every buffer this file corrupts agree with
 * the module about byte order, which is the one thing a corruption is
 * supposed to be able to disagree about. */
static void put_body_len(uint8_t *bytes, uint16_t body_len)
{
	bytes[WANT_OFF_BODY_LEN] = (uint8_t)(body_len >> 8);
	bytes[WANT_OFF_BODY_LEN + 1u] = (uint8_t)(body_len & 0xffu);
}

/* THE LENGTH A BUFFER'S OWN DECLARATION IMPLIES: what `len` would have to be
 * for the two to agree. Read by hand for the same reason `put_body_len`
 * writes by hand.
 *
 * It can exceed anything this harness will allocate -- the field is sixteen
 * bits, so the largest it implies is 65691 -- and the caller is what bounds
 * it. */
static size_t implied_len(const uint8_t *bytes)
{
	size_t body_len;

	body_len = ((size_t)bytes[WANT_OFF_BODY_LEN] << 8) | (size_t)bytes[WANT_OFF_BODY_LEN + 1u];

	return (size_t)WANT_HEADER_LEN + body_len + WANT_SIG_LEN;
}

/* And what `fzn_record_sign` must answer, in the order the header states the
 * refusals: a caller's bug, then the two fields with a bound, then the
 * capacity. Written out for the same reason `open_ought` is. */
static fzn_record_err_t sign_ought(const struct fields *f, size_t out_cap)
{
	if (!f->body && f->body_len != 0)
		return FZN_RECORD_ERR_MALFORMED;
	if (f->body_len > WANT_BODY_MAX)
		return FZN_RECORD_ERR_BODY_TOO_LARGE;
	if (f->seq == 0)
		return FZN_RECORD_ERR_SEQ_ZERO;
	if (out_cap < WANT_HEADER_LEN + f->body_len + WANT_SIG_LEN)
		return FZN_RECORD_ERR_MALFORMED;

	return FZN_RECORD_OK;
}

/* Encode `f` through the module. Returns what the module returned; the
 * caller holds it against `sign_ought`. */
static fzn_record_err_t mint(const struct fields *f, const fzn_sign_ops_t *ops, uint8_t *out,
                             size_t out_cap, size_t *out_len)
{
	return fzn_record_sign(f->issuer, f->subject, f->stream, f->kind, f->seq, f->issued_at,
	                       f->body, f->body_len, ops, out, out_cap, out_len);
}

/* Every accessor, over a view that opened, with the results folded into a
 * volatile so that none of the loads can be optimised away. This is where a
 * `body_len` that disagreed with its buffer would produce a read past the
 * end -- which is the fault `fzn_record_is_open` was fixed for, and the one
 * a sanitizer is here to catch. */
static void touch_accessors(fzn_record_t r)
{
	const uint8_t *at = NULL;
	size_t signed_len = 0, i;
	uint64_t acc = 0;

	acc += (uint64_t)fzn_record_stream(r);
	acc += (uint64_t)fzn_record_kind(r);
	acc += fzn_record_seq(r);
	acc += fzn_record_issued_at(r);
	acc += (uint64_t)fzn_record_body_len(r);

	for (i = 0; i < FZN_PUBKEY_LEN; i++)
		acc += fzn_record_issuer(r)[i];
	for (i = 0; i < FZN_SUBJECT_LEN; i++)
		acc += fzn_record_subject(r)[i];
	for (i = 0; i < fzn_record_body_len(r); i++)
		acc += fzn_record_body(r)[i];
	for (i = 0; i < FZN_SIG_LEN; i++)
		acc += fzn_record_signature(r)[i];

	fzn_record_signed_bytes(r, &at, &signed_len);
	for (i = 0; i < signed_len; i++)
		acc += at[i];

	sink += acc;
}

/* ONE BUFFER, THROUGH BOTH GATES AND THE ORACLE. This is properties 4 and 5
 * and half of 2, and it is the function every hostile buffer in this file
 * passes through -- truncations, field corruptions, single-byte mutations and
 * random bytes alike, so that none of those families can be tested to a
 * weaker standard than the others by accident.
 *
 * `accepted` receives 1 when `fzn_record_open` took the buffer. Returns 0, or
 * prints and returns 1 when something broke. */
static int probe(const uint8_t *bytes, size_t len, struct coverage *cov, int *accepted)
{
	fzn_record_t view, before;
	fzn_record_err_t got, want;
	int guard, guard_want;

	/* A POISON PATTERN THE MODULE CANNOT HAVE WRITTEN, kept so that "the
	 * view was left untouched" is a comparison rather than a hope. */
	memset(&view, 0xab, sizeof(view));
	before = view;

	got = fzn_record_open(bytes, len, &view);
	want = open_ought(bytes, len);
	*accepted = got == FZN_RECORD_OK;

	if (got != want) {
		printf("  INVARIANT: open answered \"%s\" where the layout says \"%s\", "
		       "at len %zu\n",
		       fzn_record_err_str(got), fzn_record_err_str(want), len);
		return 1;
	}

	if (got != FZN_RECORD_OK) {
		cov->probe_shape += got == FZN_RECORD_ERR_SHAPE;
		cov->probe_body += got == FZN_RECORD_ERR_BODY_TOO_LARGE;
		cov->probe_seq += got == FZN_RECORD_ERR_SEQ_ZERO;

		/* PROPERTY 4, the cheap half: a refusal must not have written
		 * anything into the caller's view. Otherwise a caller that
		 * ignored the return code -- which is the caller this guard
		 * exists for -- would be holding a half-read rejection. */
		if (memcmp(&before, &view, sizeof(before)) != 0) {
			printf("  INVARIANT: a refused open wrote into the caller's view "
			       "(at len %zu, \"%s\")\n",
			       len, fzn_record_err_str(got));
			return 1;
		}
	} else {
		cov->probe_open++;

		if (view.base != bytes || view.len != len) {
			printf("  INVARIANT: an opened view does not address its own bytes\n");
			return 1;
		}
		touch_accessors(view);
	}

	/* PROPERTY 5. The view is built by hand rather than taken from `open`,
	 * because that is precisely the boundary case `fzn_record_is_open`
	 * exists for: a caller handing `state/` or `log/` a record it got from
	 * somewhere neither of them can see. */
	view.base = bytes;
	view.len = len;
	guard = fzn_record_is_open(view);
	/* THE TWO GUARDS NOW AGREE ON EVERY INPUT, so the oracle is simply
	 * `open` accepted it.
	 *
	 * This read `want == OK || want == SEQ_ZERO` when the harness was
	 * written, because `fzn_record_is_open` did not test the sequence --
	 * the one input class on which the two disagreed. That was 10561 of
	 * 20000 cases, and this harness is what found it: it compares them on
	 * every input it generates rather than on the cases somebody thought
	 * to enumerate.
	 *
	 * The gap mattered because `fzn_record_verify` gates on `is_open`, so
	 * a hand-built view carrying sequence zero was verified and `state/`
	 * and `log/` would admit it through a gate `open` would have closed.
	 * The guard covers the sequence now, so the exception is gone. */
	guard_want = want == FZN_RECORD_OK;

	/* AND THE ACCESSORS RUN ON WHATEVER THE GUARD APPROVED, before anything
	 * below decides whether approving it was right. This is what a consumer
	 * does -- `state/` and `log/` call `fzn_record_is_open` and then read --
	 * and it is the difference between reporting that the guard is wrong and
	 * demonstrating what being wrong costs. A guard that admits a view whose
	 * `body_len` disagrees with its buffer produces the read past the end
	 * here, in this library, under a sanitizer, instead of in consumer code
	 * where the original one landed and where no reader would have blamed
	 * `record/`.
	 *
	 * Safe on a correct library by construction: `is_open` approves only a
	 * `body_len` inside the bound and a length that agrees with it exactly,
	 * so every read is inside `len`, and every caller here passes a buffer of
	 * at least PROBE_CAP bytes. */
	if (guard)
		touch_accessors(view);

	if (guard != guard_want) {
		printf("  INVARIANT: is_open answered %d and the layout says %d, at len %zu "
		       "(open said \"%s\")\n",
		       guard, guard_want, len, fzn_record_err_str(want));
		return 1;
	}
	if (guard != *accepted) {
		/* NO KNOWN DIVERGENCE REMAINS. There was exactly one -- sequence
		 * zero -- and it is closed, so any disagreement here is the two
		 * guards drifting apart again, which is what let an ASan-proven
		 * overflow reach consumer code the first time. */
		printf("  INVARIANT: is_open and open disagree at len %zu (\"%s\")\n", len,
		       fzn_record_err_str(want));
		return 1;
	}
	(void)cov;

	return 0;
}

/* PROPERTY 1 and the second half of PROPERTY 2, over a record that was just
 * minted: every accessor returns what was signed, the signature checks out,
 * the same fields encode to the same bytes twice, and the OPENED record
 * re-encodes from its accessors alone to those same bytes.
 *
 * The re-encode is the part `record_test.c` does once and this does over
 * every drawn combination. It is what makes "a record is a view over its own
 * bytes" a checkable statement rather than a description: if any accessor
 * read the wrong offset, the bytes it produces differ. */
static int check_round_trip(const struct fields *f, const uint8_t *bytes, size_t len,
                            const fzn_sign_ops_t *ops)
{
	uint8_t again[FZN_RECORD_MAX_LEN];
	fzn_record_t r;
	struct fields back;
	size_t again_len = 0;

	if (fzn_record_open(bytes, len, &r) != FZN_RECORD_OK) {
		printf("  INVARIANT: a record this module signed would not open\n");
		return 1;
	}
	if (len != FZN_RECORD_HEADER_LEN + f->body_len + FZN_SIG_LEN) {
		printf("  INVARIANT: a signed record is %zu bytes, wanted %zu\n", len,
		       (size_t)FZN_RECORD_HEADER_LEN + f->body_len + FZN_SIG_LEN);
		return 1;
	}
	if (fzn_record_verify(r, ops) != FZN_RECORD_OK) {
		printf("  INVARIANT: a record this module signed does not verify\n");
		return 1;
	}

	if (memcmp(fzn_record_issuer(r), f->issuer, FZN_PUBKEY_LEN) != 0 ||
	    memcmp(fzn_record_subject(r), f->subject, FZN_SUBJECT_LEN) != 0 ||
	    fzn_record_stream(r) != f->stream || fzn_record_kind(r) != f->kind ||
	    fzn_record_seq(r) != f->seq || fzn_record_issued_at(r) != f->issued_at ||
	    fzn_record_body_len(r) != f->body_len) {
		printf("  INVARIANT: a field did not survive the round trip\n");
		return 1;
	}
	if (f->body_len != 0 && memcmp(fzn_record_body(r), f->body, f->body_len) != 0) {
		printf("  INVARIANT: the body did not survive the round trip\n");
		return 1;
	}
	/* NEVER NULL, including for an empty body, where it points at the
	 * first byte of the signature. `record.h` promises exactly that, and
	 * it is the promise that made a null-pointer-with-a-length state
	 * unrepresentable for every consumer. */
	if (fzn_record_body(r) == NULL) {
		printf("  INVARIANT: an empty body has nowhere to point\n");
		return 1;
	}

	/* Determinism: the same fields, the same bytes. A buffer prefilled
	 * with something the encoder cannot have written, so that a field it
	 * failed to write shows up as a difference rather than as a zero that
	 * happened to match. */
	memset(again, 0xc7, sizeof(again));
	if (mint(f, ops, again, sizeof(again), &again_len) != FZN_RECORD_OK ||
	    again_len != len || memcmp(again, bytes, len) != 0) {
		printf("  INVARIANT: the same fields encoded to different bytes\n");
		return 1;
	}

	/* And from the accessors alone, which is the direction that catches a
	 * reader and a writer disagreeing about an offset. */
	memcpy(back.issuer, fzn_record_issuer(r), FZN_PUBKEY_LEN);
	memcpy(back.subject, fzn_record_subject(r), FZN_SUBJECT_LEN);
	back.stream = fzn_record_stream(r);
	back.kind = fzn_record_kind(r);
	back.seq = fzn_record_seq(r);
	back.issued_at = fzn_record_issued_at(r);
	back.body = fzn_record_body(r);
	back.body_len = fzn_record_body_len(r);

	memset(again, 0xc7, sizeof(again));
	again_len = 0;
	if (mint(&back, ops, again, sizeof(again), &again_len) != FZN_RECORD_OK ||
	    again_len != len || memcmp(again, bytes, len) != 0) {
		printf("  INVARIANT: an opened record does not re-encode to itself\n");
		return 1;
	}

	return 0;
}

/* PROPERTY 2's injectivity claim, and "truncated buffers at every length" in
 * one sweep. Across 0 to OVERSHOOT past the record, exactly one length may
 * open -- the record's own. Anything else means the same bytes are readable
 * as two different records, which is the hole `record.c` calls "the half of
 * the binding that the signature cannot supply on its own". */
static int sweep_lengths(const uint8_t *bytes, size_t rec_len, struct coverage *cov)
{
	size_t opened = 0, l;

	for (l = 0; l <= rec_len + OVERSHOOT; l++) {
		int accepted = 0;

		if (probe(bytes, l, cov, &accepted))
			return 1;
		if (accepted) {
			opened++;
			if (l != rec_len) {
				printf("  INVARIANT: a %zu-byte record also opened at %zu\n",
				       rec_len, l);
				return 1;
			}
		}
	}

	if (opened != 1) {
		printf("  INVARIANT: %zu of %zu lengths opened, wanted exactly one\n", opened,
		       rec_len + OVERSHOOT + 1u);
		return 1;
	}

	return 0;
}

/* ONE FIELD REWRITTEN TO AN EDGE VALUE, eight ways, on a copy of a genuine
 * record. Random bytes essentially never form this shape, so a harness that
 * fed only those would report a parser refusing everything as correct; a
 * harness that fed only single-byte flips would reach `body_len` of exactly
 * 512 or a sequence of exactly zero about never. These are the values the
 * refusals are written against, so they are produced on purpose.
 *
 * EACH BUFFER IS PROBED TWICE: at the record's own length, and at the length
 * its rewritten declaration implies. The second is the half that was missing,
 * and its absence hid a live hole.
 *
 * Case 4 writes `body_len = 513` and this file probed only at `rec_len`, where
 * the declaration and the buffer disagree -- so `fzn_record_is_open` refused it
 * on the length rule and the body bound above that rule was never the thing
 * doing the refusing. `sweep_lengths` varies the length and never touches
 * `body_len`. Both halves of the case existed; nothing applied them to the same
 * buffer, and `body_len > FZN_RECORD_BODY_MAX` could be deleted from
 * `fzn_record_is_open` with all 47 binaries in this suite still green.
 *
 * Combining them reaches it: a 669-byte buffer declaring a 513-byte body is
 * refused by `fzn_record_open` as BODY_TOO_LARGE and, without that bound in the
 * guard, satisfies every other test `fzn_record_is_open` makes -- so the two
 * disagree and property 5 goes red. `fzn_record_verify` gates on `is_open`,
 * which is what makes that divergence a record past the bound being verified
 * and admitted by `state/` and `log/` through a gate `fzn_record_open` closes.
 *
 * This costs no more room. The implied length is bounded by PROBE_CAP, which
 * already has three bytes to spare over the 669 the case needs, and cases that
 * leave `body_len` alone imply `rec_len` and are not probed twice. */
static int corrupt_fields(const uint8_t *bytes, size_t rec_len, uint16_t draw,
                          struct coverage *cov)
{
	uint8_t probe_buf[PROBE_CAP];
	int which;

	for (which = 0; which < 8; which++) {
		int accepted = 0;
		size_t implied;

		/* THE TAIL IS FILLED, NOT LEFT OVER. A probe at a length past
		 * `rec_len` reads bytes `memcpy` never wrote, and a buffer whose
		 * contents depend on what the last case left there is a case
		 * nobody can reproduce from its inputs. */
		memset(probe_buf, 0x5c, sizeof(probe_buf));
		memcpy(probe_buf, bytes, rec_len);
		switch (which) {
		case 0: /* a version this build does not speak */
			probe_buf[0] = (uint8_t)(draw & 0xffu);
			break;
		case 1: /* a record presented as some other signed object */
			probe_buf[1] = (uint8_t)(draw >> 8);
			break;
		case 2: /* the length now disagrees, unless it was empty */
			put_body_len(probe_buf, 0);
			break;
		case 3: /* the bound itself */
			put_body_len(probe_buf, (uint16_t)WANT_BODY_MAX);
			break;
		case 4: /* one past it: BODY_TOO_LARGE, not SHAPE */
			put_body_len(probe_buf, (uint16_t)(WANT_BODY_MAX + 1u));
			break;
		case 5: /* whatever sixteen bits the case drew */
			put_body_len(probe_buf, draw);
			break;
		case 6: /* the reserved sequence */
			memset(probe_buf + WANT_OFF_SEQ, 0, 8);
			break;
		default: /* and the far end of it */
			memset(probe_buf + WANT_OFF_SEQ, 0xff, 8);
			break;
		}

		if (probe(probe_buf, rec_len, cov, &accepted))
			return 1;

		/* AND AT THE LENGTH THE REWRITTEN DECLARATION ASKS FOR, when
		 * that is a different length and one this buffer holds. A
		 * sixteen-bit field implies up to 65691 bytes, which is the
		 * caller's to refuse rather than the harness's to allocate. */
		implied = implied_len(probe_buf);
		if (implied != rec_len && implied <= PROBE_CAP) {
			if (probe(probe_buf, implied, cov, &accepted))
				return 1;
		}
	}

	return 0;
}

/* PROPERTY 3, THE BINDING, and the reason this file exists. One byte of a
 * genuine record rewritten, anywhere in it -- header, body or signature --
 * and the pair of gates must not both let it through.
 *
 * There is no third outcome to allow for. Every byte but the signature is
 * inside the range the signature covers, and the signature itself is what
 * `fzn_record_verify` recomputes, so a mutation that survived both would mean
 * a field had escaped the signed range. That is exactly the defect the
 * rewrite of `record.h` closed, and exactly what a later refactor could
 * reopen without any test noticing. */
static int check_binding(const uint8_t *bytes, size_t rec_len, uint16_t draw,
                         const fzn_sign_ops_t *ops, struct coverage *cov)
{
	uint8_t probe_buf[PROBE_CAP];
	fzn_record_t r;
	size_t off = (size_t)draw % rec_len;
	int accepted = 0;

	memcpy(probe_buf, bytes, rec_len);
	/* Never zero, so the mutation is always a mutation. A flip that
	 * changed nothing would leave a genuine record and count as a pass. */
	probe_buf[off] = (uint8_t)(probe_buf[off] ^ (uint8_t)((draw >> 8) | 1u));

	if (probe(probe_buf, rec_len, cov, &accepted))
		return 1;

	if (!accepted) {
		cov->tamper_parse++;
		return 0;
	}

	if (fzn_record_open(probe_buf, rec_len, &r) != FZN_RECORD_OK) {
		printf("  INVARIANT: open is not deterministic\n");
		return 1;
	}
	if (fzn_record_verify(r, ops) == FZN_RECORD_OK) {
		printf("  INVARIANT: a record with byte %zu rewritten both parsed and "
		       "verified\n",
		       off);
		return 1;
	}
	cov->tamper_verify++;

	return 0;
}

/* PROPERTY 4's expensive half: the signer refuses, and the buffer already
 * holds a record.
 *
 * BUILT TO BITE. The second sign asks for the SAME fields as the first, so
 * the header and body it writes are byte-identical to what is already there.
 * If the signature area were left alone, the buffer would be the first record
 * again -- it would open, and it would verify, and nothing about it would
 * look like the failure it is. `record.c` zeroes that area for exactly this
 * reason and names the sibling modules that learned it first. This is what
 * would notice the memset going away. */
static int check_stale_signature(const struct fields *f, const fzn_sign_ops_t *ops,
                                 struct stub *stub, uint8_t *buf, size_t rec_len)
{
	fzn_record_t r;
	size_t sentinel = (size_t)-1;
	fzn_record_err_t err;

	stub->refuse = 1;
	err = mint(f, ops, buf, FZN_RECORD_MAX_LEN, &sentinel);
	stub->refuse = 0;

	if (err != FZN_RECORD_ERR_UNSIGNED) {
		printf("  INVARIANT: a refusing signer gave \"%s\", wanted \"%s\"\n",
		       fzn_record_err_str(err),
		       fzn_record_err_str(FZN_RECORD_ERR_UNSIGNED));
		return 1;
	}
	if (sentinel != (size_t)-1) {
		printf("  INVARIANT: a failed sign reported a length\n");
		return 1;
	}
	if (fzn_record_open(buf, rec_len, &r) == FZN_RECORD_OK &&
	    fzn_record_verify(r, ops) == FZN_RECORD_OK) {
		printf("  INVARIANT: a refused sign left a record that still verifies\n");
		return 1;
	}

	return 0;
}

/* A buffer of whatever the case drew, sometimes fixed up at the front so that
 * it gets past the version and object bytes and the length agreement -- at
 * which point every accessor runs over a stranger's bytes, which is the state
 * a sanitizer is here to have an opinion about.
 *
 * Unfixed, it is the ordinary case: 668 random bytes are not this shape, and
 * a parser is entitled to say so. Both are wanted. A run of only the first
 * kind proves the parser refuses things; a run of only the second proves it
 * accepts them. */
static int random_bytes_probe(const uint8_t *data, size_t len, uint16_t draw,
                              struct coverage *cov)
{
	uint8_t probe_buf[PROBE_CAP];
	size_t body_len = (size_t)draw % (WANT_BODY_MAX + 1u);
	size_t probe_len;
	size_t i;
	int accepted = 0;

	for (i = 0; i < sizeof(probe_buf); i++)
		probe_buf[i] = len != 0 ? data[(i * 7u + (size_t)draw) % len] : (uint8_t)i;

	if ((draw & 3u) != 0) {
		/* Past the front door: the two tag bytes and a `body_len` that
		 * agrees with the length this is about to be offered at. */
		probe_buf[0] = (uint8_t)WANT_VERSION;
		probe_buf[1] = (uint8_t)WANT_OBJECT;
		put_body_len(probe_buf, (uint16_t)body_len);
		probe_len = WANT_HEADER_LEN + body_len + WANT_SIG_LEN;
	} else {
		probe_len = (size_t)draw % (PROBE_CAP + 1u);
	}

	return probe(probe_buf, probe_len, cov, &accepted);
}

/* A cursor over the case's bytes. Past the end it answers zero, so a short
 * input is a case with tamer values rather than a rejected one -- the same
 * shape record_guided.c uses, and it is what keeps a libFuzzer corpus of
 * two-byte inputs from being wasted. */
struct cursor {
	const uint8_t *p;
	size_t n, i;
};

static uint8_t take8(struct cursor *c)
{
	return c->i < c->n ? c->p[c->i++] : 0u;
}

static uint16_t take16(struct cursor *c)
{
	uint16_t hi = take8(c);

	return (uint16_t)((uint16_t)(hi << 8) | take8(c));
}

/* WHY THE FIELDS ARE DRAWN FROM SMALL BIASED SETS RATHER THAN UNIFORMLY.
 *
 * A uniform 64-bit sequence is never 1 and never UINT64_MAX; a uniform
 * `body_len` is past the bound in 99.2% of draws and is exactly 0 or exactly
 * 512 in neither. Those are the values every bound in this module is written
 * against, so a generator that cannot produce them cannot test any of them --
 * the failure `chunk/test/reassembly_fuzz.c` was rebuilt to escape, where
 * three of four planted bugs survived 200000 cases because almost every offer
 * was refused at the front door. The wild values still occur; they have just
 * stopped being the only thing that occurs. */
static void draw_fields(struct cursor *c, struct fields *f, const uint8_t *body,
                        struct coverage *cov)
{
	uint8_t mode = take8(c);
	uint8_t key_pick = take8(c);
	uint8_t subj_pick = take8(c);

	memset(f->issuer, (key_pick & 1u) ? 0x00 : ((key_pick & 2u) ? 0xff : key_pick),
	       FZN_PUBKEY_LEN);
	memset(f->subject, (subj_pick & 1u) ? 0x00 : ((subj_pick & 2u) ? 0xff : subj_pick),
	       FZN_SUBJECT_LEN);

	switch (take8(c) & 3u) {
	case 0:
		f->stream = 0u;
		break;
	case 1:
		f->stream = FZN_STREAM_RESERVED - 1u;
		break;
	case 2:
		f->stream = FZN_STREAM_RESERVED;
		break;
	default:
		f->stream = 0xffffffffu;
		break;
	}
	f->kind = (uint32_t)take16(c);

	switch (mode & 3u) {
	case 0:
		f->seq = 1u;
		break;
	case 1:
		f->seq = 0xffffffffffffffffu;
		break;
	case 2:
		/* The value `fzn_record_open` and `fzn_record_sign` both
		 * refuse, so the refusal is reached rather than described. */
		f->seq = 0u;
		break;
	default:
		f->seq = 1u + (uint64_t)take16(c);
		break;
	}
	f->issued_at = (uint64_t)take16(c) << 32;

	switch ((mode >> 2) & 3u) {
	case 0:
		f->body_len = 0u;
		break;
	case 1:
		f->body_len = FZN_RECORD_BODY_MAX;
		break;
	case 2:
		/* Past the bound, so BODY_TOO_LARGE is a code the run has
		 * actually seen come back rather than one it assumes. */
		f->body_len = FZN_RECORD_BODY_MAX + 1u + ((size_t)take8(c) & 0x3fu);
		break;
	default:
		f->body_len = (size_t)take16(c) % (FZN_RECORD_BODY_MAX + 1u);
		break;
	}
	f->body = ((mode >> 4) & 1u) && f->body_len == 0 ? NULL : body;

	cov->body_zero += f->body_len == 0;
	cov->body_max += f->body_len == FZN_RECORD_BODY_MAX;
	cov->seq_edge += f->seq == 1u || f->seq == 0xffffffffffffffffu;
}

/* One case. Returns 0, or prints and returns 1 when an invariant broke. */
static int fuzz_one(const uint8_t *data, size_t len, struct coverage *cov)
{
	static uint8_t body[FZN_RECORD_BODY_MAX];
	/* PROBE_CAP rather than FZN_RECORD_MAX_LEN, so that the sweep's
	 * OVERSHOOT lengths address storage this harness owns. `fzn_record_sign`
	 * is still given FZN_RECORD_MAX_LEN as its capacity, so nothing the
	 * module writes reaches the slack -- it exists only to be read past the
	 * record by a view that claims to be longer than one. */
	uint8_t buf[PROBE_CAP];
	struct cursor c = { data, len, 0 };
	struct stub stub;
	fzn_sign_ops_t ops;
	struct fields f;
	size_t rec_len = (size_t)-1;
	size_t out_cap;
	uint16_t draw;
	fzn_record_err_t got, want;
	size_t i;

	memset(&stub, 0, sizeof(stub));
	ops.verify = stub_verify;
	ops.sign = stub_sign;
	ops.ctx = &stub;

	for (i = 0; i < sizeof(body); i++)
		body[i] = (uint8_t)(i * 31u + 7u + (len != 0 ? data[i % len] : 0u));

	memset(&f, 0, sizeof(f));
	draw_fields(&c, &f, body, cov);
	/* THE SIGNER IS THE ISSUER, so a record this harness mints verifies
	 * under the key that is inside it. A stub signing as somebody else
	 * would make every round trip fail and would say nothing about the
	 * module. */
	memcpy(stub.key, f.issuer, FZN_PUBKEY_LEN);

	/* Sometimes exactly enough, sometimes one byte short. The short case
	 * is the caller's bug `record.h` distinguishes from a bad datagram,
	 * and it must be refused before anything is signed. */
	out_cap = FZN_RECORD_MAX_LEN;
	if ((take8(&c) & 7u) == 0 && f.body_len <= FZN_RECORD_BODY_MAX) {
		out_cap = FZN_RECORD_HEADER_LEN + f.body_len + FZN_SIG_LEN;
		if ((take8(&c) & 1u) != 0)
			out_cap--;
	}

	draw = take16(&c);

	got = mint(&f, &ops, buf, out_cap, &rec_len);
	want = sign_ought(&f, out_cap);

	if (got != want) {
		printf("  INVARIANT: sign answered \"%s\", the rules say \"%s\" "
		       "(body_len %zu, seq %llu, cap %zu)\n",
		       fzn_record_err_str(got), fzn_record_err_str(want), f.body_len,
		       (unsigned long long)f.seq, out_cap);
		return 1;
	}

	if (got != FZN_RECORD_OK) {
		cov->sign_refused++;
		/* The one thing `record.h` promises about a failed sign: the
		 * length is untouched. It says nothing about the buffer, which
		 * "MAY HOLD PARTIAL BYTES", so nothing here asserts otherwise. */
		if (rec_len != (size_t)-1) {
			printf("  INVARIANT: a refused sign reported a length\n");
			return 1;
		}
		/* No record to probe, so give the parser the random family and
		 * end the case. */
		return random_bytes_probe(data, len, draw, cov);
	}

	cov->minted++;

	if (check_round_trip(&f, buf, rec_len, &ops))
		return 1;
	if (sweep_lengths(buf, rec_len, cov))
		return 1;
	if (corrupt_fields(buf, rec_len, draw, cov))
		return 1;
	if (check_binding(buf, rec_len, draw, &ops, cov))
		return 1;
	if (check_stale_signature(&f, &ops, &stub, buf, rec_len))
		return 1;
	if (random_bytes_probe(data, len, draw, cov))
		return 1;

	return 0;
}

#ifdef FZN_LIBFUZZER
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct coverage cov;

	memset(&cov, 0, sizeof(cov));
	if (fuzz_one(data, size, &cov))
		__builtin_trap();
	return 0;
}
#else

/* A seeded generator, so a run is reproducible from the source alone. Not a
 * good PRNG and not meant to be -- what it has to be is the SAME one every
 * time, on every machine, so that a case that fails here fails for whoever
 * reads the report. */
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
	struct coverage cov;
	uint8_t buf[64];

	memset(&cov, 0, sizeof(cov));

	if (argc > 1) {
		cases = strtoul(argv[1], NULL, 10);
		if (cases == 0)
			cases = FUZZ_DEFAULT_CASES;
	}

	if (cases < FUZZ_MIN_CASES) {
		printf("record_fuzz: %lu cases is below FUZZ_MIN_CASES (%u), so this run will "
		       "not report success -- every coverage floor below that is "
		       "cleared by a single lucky hit. Re-run with %u or more.\n",
		       cases, (unsigned)FUZZ_MIN_CASES, (unsigned)FUZZ_MIN_CASES);
		return 1;
	}

	/* NEVER SHORTER THAN A CASE NEEDS. `take8` answers zero past the end,
	 * which is right for a libFuzzer corpus -- a two-byte input should be a
	 * tame case rather than a rejected one -- but it makes a SEEDED run
	 * waste itself. Drawing the length from 0 upward, as the sibling
	 * harnesses do, gave 18% of cases fewer bytes than `fuzz_one` reads,
	 * and every one of those was the same all-zero case: measured, 5961 of
	 * 20000 draws came out with an empty body where a quarter, near 5000,
	 * is what the generator asks for. The floor is what `fuzz_one` consumes
	 * with room to spare, so a case is distinct from its neighbours. */
	for (unsigned long c = 0; c < cases; c++) {
		uint32_t state = (uint32_t)c + 1u;
		size_t len = 24u + (size_t)(next(&state) % (sizeof(buf) - 23u));

		for (size_t i = 0; i < len; i++)
			buf[i] = (uint8_t)next(&state);

		if (fuzz_one(buf, len, &cov)) {
			printf("record_fuzz: FAILED on case %lu (seed %lu)\n", c, c + 1u);
			return 1;
		}
	}

	/* EVERY DIRECTION MUST HAVE OCCURRED, or the run proves only the
	 * directions that did. A harness that never minted a record would
	 * report success against an encoder that refused everything; one that
	 * never saw a parse refused would report success against a parser that
	 * accepted everything; one that never saw a mutation caught by the
	 * SIGNATURE rather than by the parser would report success against a
	 * verifier that had stopped hashing.
	 *
	 * `tamper_verify` is the rarest of them and is floored lower. It needs
	 * a mutation that lands somewhere the parser cannot see -- the
	 * signature, the body, or a header field with no bound -- which is most
	 * offsets, so the rate is high; the low floor is against drift rather
	 * than against noise, exactly as chain_fuzz reasons about delegation.
	 *
	 * `guard_gap` is NOT floored. It counts the one place
	 * `fzn_record_is_open` and `fzn_record_open` are known to differ, and a
	 * floor on it would fail the run the day that difference is closed. */
	if (cov.minted < floor_of(cases, 200u) || cov.body_zero < floor_of(cases, 200u) ||
	    cov.body_max < floor_of(cases, 200u) || cov.seq_edge < floor_of(cases, 200u) ||
	    cov.sign_refused < floor_of(cases, 200u) ||
	    cov.probe_open < floor_of(cases, 200u) || cov.probe_shape < floor_of(cases, 200u) ||
	    cov.probe_body < floor_of(cases, 200u) || cov.probe_seq < floor_of(cases, 200u) ||
	    cov.tamper_parse < floor_of(cases, 1000u) ||
	    cov.tamper_verify < floor_of(cases, 1000u)) {
		printf("record_fuzz: REACHED TOO LITTLE -- %lu minted (%lu empty, %lu full, "
		       "%lu edge seq), %lu signs refused, %lu opened, %lu shape, %lu body, "
		       "%lu seq refused, %lu mutations caught by the parser, %lu by the "
		       "signature, in %lu cases. All must happen or this run proves less "
		       "than it says.\n",
		       cov.minted, cov.body_zero, cov.body_max, cov.seq_edge, cov.sign_refused,
		       cov.probe_open, cov.probe_shape, cov.probe_body, cov.probe_seq,
		       cov.tamper_parse, cov.tamper_verify, cases);
		return 1;
	}

	printf("record_fuzz: %lu cases, %lu minted (%lu empty, %lu full, %lu edge seq), "
	       "%lu signs refused, %lu opened, %lu shape, %lu body, %lu seq refused, "
	       "%lu mutations caught by the parser, %lu by the signature, "
	       "%lu is_open/open gaps (sequence zero), no invariant broken\n",
	       cases, cov.minted, cov.body_zero, cov.body_max, cov.seq_edge, cov.sign_refused,
	       cov.probe_open, cov.probe_shape, cov.probe_body, cov.probe_seq, cov.tamper_parse,
	       cov.tamper_verify, cov.guard_gap);
	return 0;
}
#endif
