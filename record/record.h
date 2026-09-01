/* A signed, sequenced statement -- the thing every dynamic permission system
 * here turns out to be moving.
 *
 * project.md sec 5 records the invariant the three consumers share: encrypted
 * networks, with keys for hosts and keys for users, carrying **permissions
 * that change at runtime**. Everything about the SHAPE of those permissions
 * differs per project and is configuration rather than design. What does not
 * differ is that somebody signs a statement, it reaches other hosts, they
 * decide whether it is authorised, and they end up agreeing about what is
 * currently true.
 *
 * That is what this file is. A grant, a revocation, a rule, a configuration
 * setting and a log line are all the same object here, and this module knows
 * what none of them mean.
 *
 * WHY OPAQUE, AND WHERE THE LINE IS. `kind` and `subject` and `body` are the
 * consumer's, exactly as a capability is 32 opaque bytes in `chain/chain.h`
 * and a verb is opaque bytes in `local/vocabulary.h`. A library that knew a
 * `kind` meant "revoke" would have chosen one project's permission taxonomy
 * and called it the model, which sec 5 says is the corner to avoid. What this
 * module owns is authenticity and ORDER; what a statement means is above it.
 *
 * A RECORD IS A VIEW OVER ITS OWN BYTES, AND THAT IS THE WHOLE DESIGN. There
 * is one buffer, the signature covers all of it but the signature, and every
 * field below is an accessor that reads out of that buffer. Nothing is
 * decoded into a parallel copy, so nothing can disagree with what was signed.
 *
 * WHAT THIS REPLACED, AND WHY THE OLD REASON EXPIRED. This struct used to
 * carry an opaque `signed_region` plus a set of decoded fields beside it, and
 * `fzn_record_verify` checked the signature over the region while comparing
 * no field against it. The header declined to encode, on `chain.h`'s
 * reasoning, because recomputing the bytes "would put a SECOND encoder in the
 * tree for the schema to disagree with later".
 *
 * **There was no first encoder.** Measured before this file was rewritten: no
 * record encoder or decoder existed anywhere in this tree, and
 * `wire/frame.situ` does not describe a record -- its `fzn_hop` is the
 * forwarder header, a different object sharing a word. The design avoided a
 * second encoder by having zero, and with zero the correspondence had no
 * producer and therefore no guarantee.
 *
 * What that cost, measured against a verifier that actually hashes what it is
 * given: a genuine record verified, and so did the same record with its
 * subject rewritten, its stream moved, its kind changed, its `issued_at`
 * moved, its body swapped for another buffer, its `body_len` grown from 4 to
 * 64 or shrunk to 0, and its sequence bumped from 5 to 1<<40. Only `issuer`
 * was refused, and only because it is the verification key rather than
 * because anything bound it. Both halves of the classic break were present at
 * once: the body POINTER and the body LENGTH were independently editable on a
 * record that still verified.
 *
 * And it landed above this module rather than staying theoretical.
 * `fzn_state_apply` orders by sequence, so replaying an issuer's own signed
 * grant with the sequence bumped brings a revoked permission back -- nothing
 * forged, one genuine record re-presented. `state/` also derives writer
 * identity from `stream`, so moving a genuine record between streams wedges a
 * cell at FZN_STATE_ERR_CROSS_STREAM permanently, and the revocation that
 * would have cleared it never lands.
 *
 * THE LAYOUT. Big-endian throughout, matching `frame.situ`'s `endian big`,
 * fixed width, no padding, fixed fields first and the one variable field
 * last. Offsets are stated as constants below so that a reader and the code
 * cannot disagree about them either.
 *
 *      off  size  field
 *        0     1  version    (FZN_SIGNED_VERSION)
 *        1     1  object     (FZN_OBJECT_RECORD)
 *        2    32  issuer
 *       34    32  subject
 *       66     4  stream
 *       70     4  kind
 *       74     8  seq
 *       82     8  issued_at
 *       90     2  body_len
 *       92     n  body       (n = body_len, 0..FZN_RECORD_BODY_MAX)
 *     92+n    64  signature
 *
 * So a record is 156 bytes plus its body, and at most 668. That fits
 * `frame.situ`'s `u16 length [max = 1024]` payload ceiling with 356 bytes to
 * spare even at a full body, which is checked rather than assumed in
 * `record/test/record_test.c`.
 *
 * THE VERSION AND OBJECT BYTES ARE INSIDE THE SIGNED RANGE, which is the
 * point of them; `wire/bytes.h` carries the argument and names the sibling
 * project that paid for it. Neither can be added later without invalidating
 * every signature already issued.
 *
 * PARSE CHECKS LAYOUT, VERIFY CHECKS SEMANTICS. `fzn_record_open` answers
 * whether a buffer is shaped like a record -- length, version, object,
 * `body_len` against the buffer it sits in -- and never touches a key.
 * `fzn_record_verify` answers whether the issuer signed it. Splitting them is
 * what keeps the cheap refusals cheap: a buffer refused for its shape or its
 * sequence has not cost a public-key operation, which is sec 4.7's ordering
 * argument applied here and is stronger than it was, because the refusal now
 * happens in a function that has no signer to spend.
 *
 * WHAT IS DELIBERATELY NOT HERE:
 *
 *   - **Authorisation.** Whether an issuer may say this is a capability
 *     question, answered by `fzn_chain_verify` against a capability the
 *     consumer maps from `kind`. Keeping it out is what lets one project
 *     authorise by chain, another by local uid, and a third by both.
 *   - **Transport.** A record does not know how it travelled. `wire/seal.h`
 *     carries bytes; this is what some of those bytes mean.
 *   - **Allocation.** Nothing here allocates, per sec 2. A body is bounded,
 *     the caller owns the buffer a record is a view of, and **that buffer
 *     must outlive every view of it and everything those views are stored
 *     in** -- see `state/state.h`, whose entries point into it.
 */

#ifndef FZN_RECORD_H
#define FZN_RECORD_H

#include "../chain/chain.h"
#include "../wire/bytes.h"

#include <stddef.h>
#include <stdint.h>

/* What a statement is ABOUT. Opaque, and 32 bytes so that it can hold a
 * public key -- the common case is a statement about a host or a user -- or
 * a hash of something longer. A consumer that wants a short name hashes it. */
#define FZN_SUBJECT_LEN 32

/* The largest body this will carry. Bounded because nothing here allocates,
 * and small because a record is a statement rather than a payload: a
 * configuration value, a rule, a grant. Anything larger is a message, and
 * `chunk/` already carries messages.
 *
 * AND IT IS NOT A NUMBER TO RAISE WHEN SOMETHING DOES NOT FIT, which is
 * worth saying here because a consumer arrived fifteen bytes over and
 * fifteen bytes reads like a rounding problem. Theirs was a delegation
 * chain carried inside a record. A chain is `FZN_CHAIN_HEADER_LEN` plus
 * `FZN_HOP_LEN` per hop -- 181 bytes at one hop, 360 at two, 539 at three
 * before any content at all, and 1434 at the eight this library allows,
 * which exceeds even a frame's whole payload.
 *
 * So the overage is the first value of a function of the delegation depth
 * of whoever is speaking, sampled where it happens to be closest. Raising
 * this to 544 buys exactly one hop and fails at the next, and each hop
 * after costs another 179 whatever the bound is. **The sender does not
 * control that depth and no bound here can.**
 *
 * WHICH MAKES THE SEPARATION BELOW LOAD-BEARING RATHER THAN A PREFERENCE.
 * This module puts authorisation outside the record -- whether a signer was
 * allowed to say a thing is `fzn_chain_verify` against a capability, and the
 * record carries the issuer's key and no chain. That reads as layering
 * taste until the arithmetic above, which is the reason: a record that
 * carried its chain would work at one hop, work at two, and stop. */
#define FZN_RECORD_BODY_MAX 512u

/* Stream numbers below this are fuzznet's to assign a meaning to; at or above
 * it, an issuer assigns its own and this library will never claim one.
 *
 * Reserved rather than assigned: nothing below 256 has a meaning today. The
 * boundary exists so a consumer choosing stream numbers now cannot be
 * overtaken later, which is the cheap half of the problem `fzn_kind` has the
 * expensive half of -- there, a consumer taking a spare value can make two
 * networks refuse each other's traffic, and assignment goes through fuzznet.
 * Here it cannot, because a stream is scoped to its issuer. */
#define FZN_STREAM_RESERVED 256u

/* WHERE EACH FIELD SITS. Written as a running sum of the field widths rather
 * than as literals, so that changing a width cannot leave an offset behind:
 * the arithmetic is the layout. `record.c` asserts the total against the 92
 * the header comment states, which is the one place a literal appears and the
 * one place a reader checks it against the table. */
#define FZN_RECORD_OFF_VERSION   0u
#define FZN_RECORD_OFF_OBJECT    (FZN_RECORD_OFF_VERSION + 1u)
#define FZN_RECORD_OFF_ISSUER    (FZN_RECORD_OFF_OBJECT + 1u)
#define FZN_RECORD_OFF_SUBJECT   (FZN_RECORD_OFF_ISSUER + FZN_PUBKEY_LEN)
#define FZN_RECORD_OFF_STREAM    (FZN_RECORD_OFF_SUBJECT + FZN_SUBJECT_LEN)
#define FZN_RECORD_OFF_KIND      (FZN_RECORD_OFF_STREAM + 4u)
#define FZN_RECORD_OFF_SEQ       (FZN_RECORD_OFF_KIND + 4u)
#define FZN_RECORD_OFF_ISSUED_AT (FZN_RECORD_OFF_SEQ + 8u)
#define FZN_RECORD_OFF_BODY_LEN  (FZN_RECORD_OFF_ISSUED_AT + 8u)
#define FZN_RECORD_OFF_BODY      (FZN_RECORD_OFF_BODY_LEN + 2u)

/* Everything the signature covers except the body: the fixed part. */
#define FZN_RECORD_HEADER_LEN FZN_RECORD_OFF_BODY

/* A record with no body, and a record with the largest one. Both are exact,
 * so a caller sizing a buffer for `fzn_record_sign` has a number to use and
 * `fzn_record_open` has one to refuse against. */
#define FZN_RECORD_MIN_LEN ((size_t)FZN_RECORD_HEADER_LEN + FZN_SIG_LEN)
#define FZN_RECORD_MAX_LEN ((size_t)FZN_RECORD_HEADER_LEN + FZN_RECORD_BODY_MAX + FZN_SIG_LEN)

typedef enum fzn_record_err {
	FZN_RECORD_OK = 0,
	/* THE CALLER HAS A BUG: a null pointer, a signer with no operation, an
	 * output buffer too small for a record that would fit in one. Kept
	 * distinct from SHAPE, which is about bytes that arrived from
	 * somewhere and is an ordinary thing to see on a network. */
	FZN_RECORD_ERR_MALFORMED = -1,
	/* The signature does not check out against the issuer -- or, from
	 * `fzn_record_sign`, the signer refused to produce one. */
	FZN_RECORD_ERR_UNSIGNED = -2,
	/* The body is larger than this module will carry. Its own error rather
	 * than MALFORMED, because it is a sizing decision a consumer can act on
	 * -- split the statement, or raise the bound deliberately -- and not a
	 * caller's bug. */
	FZN_RECORD_ERR_BODY_TOO_LARGE = -3,
	/* Sequence zero. Reserved to mean "no record yet", so that a journal
	 * entry can start empty without a separate flag.
	 *
	 * REFUSED BY `fzn_record_open` RATHER THAN BY `fzn_record_verify`,
	 * which is where it used to live. The ordering claim survives and gets
	 * cheaper: a record refused for its sequence must not cost a signature
	 * verification, and now it is refused by a function that has no key to
	 * verify with. */
	FZN_RECORD_ERR_SEQ_ZERO = -4,
	/* THESE BYTES ARE NOT A RECORD: too short, a version or object byte
	 * this build does not speak, or a `body_len` that disagrees with the
	 * buffer it was read out of. Its own code because it is the answer a
	 * receiver gives to a stranger, and folding it into MALFORMED would
	 * make a caller's bug and a bad datagram indistinguishable in a log. */
	FZN_RECORD_ERR_SHAPE = -5,
} fzn_record_err_t;

/* One statement, as a view over the bytes that carry it.
 *
 * `base` points at the first byte of the encoding and `len` is the whole of
 * it, signature included. The buffer is the caller's and is not copied: **it
 * must outlive the view and anything the view was stored into.**
 *
 * ONLY `fzn_record_open` MAY FILL ONE. Every accessor below reads at a fixed
 * offset and takes the length on trust, because `open` has already checked
 * it; calling one on a view that `open` did not fill is undefined, exactly as
 * reading through an uninitialised pointer is. `fzn_record_is_open` is the
 * cheap guard for a boundary that cannot be sure. */
typedef struct fzn_record {
	const uint8_t *base;
	size_t len;
} fzn_record_t;

/* Is this buffer a record?
 *
 * Answers SHAPE and nothing else -- the length agrees with the `body_len` it
 * carries, the version and object bytes are the ones this build signs, and
 * the sequence is not the reserved zero. No key is consulted and no signature
 * is checked; that is `fzn_record_verify`, deliberately separate so that a
 * malformed buffer costs no public-key arithmetic.
 *
 * `bytes` is borrowed, not copied. On any failure `*out` is left untouched,
 * so a caller cannot half-read a rejected buffer. */
fzn_record_err_t fzn_record_open(const uint8_t *bytes, size_t len, fzn_record_t *out);

/* Is this view one an accessor may be called on?
 *
 * For a boundary that takes a record from somewhere it cannot see -- a public
 * entry point in `state/` or `log/`, which must answer an error rather than
 * read through whatever a caller passed.
 *
 * IT REPEATS THE STRUCTURAL PART OF `fzn_record_open`, and the repetition is
 * the point rather than an oversight. It used to test only `base != NULL &&
 * len >= FZN_RECORD_MIN_LEN`, and that is not enough to make any accessor
 * safe: `fzn_record_body_len` reads `body_len` from the bytes, so a view whose
 * embedded length disagrees with its buffer hands a caller a pointer and a
 * size that do not belong together.
 *
 * Measured. Take a genuine 157-byte record and patch `body_len` to 512.
 * `fzn_record_open` refuses it -- "not the shape of a record", which is the
 * check whose comment says canonical is what makes it signable. The old
 * `is_open` returned 1, `fzn_state_apply` returned OK, and the consumer was
 * handed an entry claiming 512 bytes over a 157-byte buffer. ASan reports the
 * overflow in the CONSUMER, past anything this library can be blamed for by
 * a reader looking at the crash.
 *
 * A shorter variant faulted inside `state/`'s own `seq == 0` test -- a check
 * vacuous for every legal input, whose only live input class is the one where
 * evaluating it is itself the out-of-bounds read.
 *
 * So the guard has to be a real one. It is a handful of loads and no hashing,
 * which is what "cheap" was always supposed to mean here. What it does NOT
 * repeat is the signature -- authenticity is `fzn_record_verify`'s, and a
 * caller that admits an unverified record has skipped a step this module
 * cannot see. */
static inline int fzn_record_is_open(fzn_record_t r)
{
	size_t body_len;

	if (r.base == NULL || r.len < FZN_RECORD_MIN_LEN)
		return 0;
	if (r.base[FZN_RECORD_OFF_VERSION] != (uint8_t)FZN_SIGNED_VERSION)
		return 0;
	if (r.base[FZN_RECORD_OFF_OBJECT] != (uint8_t)FZN_OBJECT_RECORD)
		return 0;

	body_len = (size_t)fzn_get_be16(r.base + FZN_RECORD_OFF_BODY_LEN);
	if (body_len > FZN_RECORD_BODY_MAX)
		return 0;

	/* SEQUENCE ZERO, which this omitted and the paragraph above claimed it
	 * covered. `fzn_record_open` refuses it by name and journal.h reserves
	 * it for "nothing received yet", so it is as structural as the version
	 * byte -- and the sentence above says only the SIGNATURE is left out.
	 *
	 * It is not a memory-safety gap: the sequence lives inside a buffer
	 * either guard admits. What it costs is that `fzn_record_verify` gates
	 * on this function, so a hand-built view carrying sequence zero was
	 * VERIFIED, and `state/` and `log/` would then admit it through a gate
	 * `fzn_record_open` would have closed.
	 *
	 * Found by `record/test/record_fuzz.c`, which compares the two
	 * functions on every input it generates rather than on the cases
	 * somebody thought to enumerate. The disagreement was 10561 of 20000
	 * cases and every one of them was this. */
	if (fzn_get_be64(r.base + FZN_RECORD_OFF_SEQ) == 0u)
		return 0;

	/* EXACT, not "at least". A buffer longer than the record it holds is a
	 * different fault from a short one and neither is a record. */
	return r.len == (size_t)FZN_RECORD_HEADER_LEN + body_len + FZN_SIG_LEN;
}

/* WHO IS ASSERTING THIS. 32 bytes, and the key the signature is checked
 * against. Points into the record's own bytes. */
static inline const uint8_t *fzn_record_issuer(fzn_record_t r)
{
	return r.base + FZN_RECORD_OFF_ISSUER;
}

/* WHAT IT IS ABOUT. See FZN_SUBJECT_LEN. Points into the record's own
 * bytes. */
static inline const uint8_t *fzn_record_subject(fzn_record_t r)
{
	return r.base + FZN_RECORD_OFF_SUBJECT;
}

/* WHICH SEQUENCE THIS BELONGS TO. An issuer numbers each stream from 1
 * independently, so `fzn_record_seq` is unique within (issuer, stream) and
 * not within issuer.
 *
 * IT EXISTS BECAUSE OF PARTIAL ENTITLEMENT, and one sequence per issuer
 * cannot express it. If a recipient is not allowed to see some of an issuer's
 * records, its position develops holes it is not permitted to fill -- and
 * `fzn_journal_admit` refuses a gap, correctly, so that recipient asks for
 * ever for a record nobody will ever send it. Measured before this field
 * existed: admitting sequence 1 then 3 answers "ahead of what is held", and
 * the journal wants 2 permanently.
 *
 * So fidelity is a STREAM. A coarse track and a precise one are two streams,
 * each contiguous for whoever is entitled to it, and entitlement is an
 * ordinary capability question answered by `chain/`.
 *
 * WHO ASSIGNS THESE. A stream number is scoped to its issuer -- a position is
 * (issuer, stream) -- so two issuers using 7 for different purposes never
 * collide, and a stream needs agreement only between an issuer and whoever
 * follows it. That is a real structural difference from `fzn_kind`, which
 * every host must agree about before it can parse a frame at all, and it is
 * why this namespace does not need the central assignment that one does.
 *
 * One case does need agreement, and FZN_STREAM_RESERVED is the range kept for
 * it: a WELL-KNOWN stream means the same thing for every issuer, so that a
 * host anchoring a root can follow something without being told its number
 * out of band. An issuer's revocations are the obvious candidate. **None is
 * assigned yet**, deliberately -- naming one before anything follows it would
 * be inventing a mechanism ahead of its need. The range exists so that a
 * consumer can assign freely TODAY without a future well-known stream
 * colliding with what it chose.
 *
 * DELIBERATELY NOT `kind`, though the two are often the same value in
 * practice. Permissions need CROSS-KIND ORDERING -- a grant and a revocation
 * are different kinds and must be totally ordered against each other -- so a
 * consumer puts them in one stream and its telemetry in another. Collapsing
 * stream into kind would make that unsayable. */
static inline uint32_t fzn_record_stream(fzn_record_t r)
{
	return fzn_get_be32(r.base + FZN_RECORD_OFF_STREAM);
}

/* WHAT KIND OF STATEMENT. The consumer's own taxonomy; see the header. */
static inline uint32_t fzn_record_kind(fzn_record_t r)
{
	return fzn_get_be32(r.base + FZN_RECORD_OFF_KIND);
}

/* THE POSITION, per (issuer, stream), strictly increasing and never zero.
 *
 * Per-issuer rather than global because a global sequence needs consensus and
 * this design has none: two hosts that never speak must still be able to
 * issue. It is what makes a gap detectable -- see `record/journal.h` -- and it
 * is why replaying an old record is refused rather than merely useless.
 *
 * `fzn_record_open` refuses zero, so a record that exists has a usable one. */
static inline uint64_t fzn_record_seq(fzn_record_t r)
{
	return fzn_get_be64(r.base + FZN_RECORD_OFF_SEQ);
}

/* THE ISSUER'S CLOCK, AND NOT TRUSTED FOR ORDERING. Clocks disagree;
 * sequences do not. It is here because a consumer displaying a rule wants to
 * say when, and because an expiry policy needs something to compare. Ordering
 * decisions use `fzn_record_seq`. */
static inline uint64_t fzn_record_issued_at(fzn_record_t r)
{
	return fzn_get_be64(r.base + FZN_RECORD_OFF_ISSUED_AT);
}

/* HOW MANY BODY BYTES. At most FZN_RECORD_BODY_MAX, and `fzn_record_open` has
 * already checked it against the buffer, so this and `fzn_record_body` cannot
 * disagree. */
static inline size_t fzn_record_body_len(fzn_record_t r)
{
	return fzn_get_be16(r.base + FZN_RECORD_OFF_BODY_LEN);
}

/* THE CONSUMER'S OWN BYTES.
 *
 * NEVER NULL, including for an empty body, where it points one past the
 * header at the first byte of the signature and must not be dereferenced.
 * That is worth saying because the struct this replaced carried a body
 * pointer a caller set by hand, so a null pointer with a non-zero length was
 * a state every consumer had to test for. It is now unrepresentable. */
static inline const uint8_t *fzn_record_body(fzn_record_t r)
{
	return r.base + FZN_RECORD_OFF_BODY;
}

/* THE SIGNATURE, the last FZN_SIG_LEN bytes. */
static inline const uint8_t *fzn_record_signature(fzn_record_t r)
{
	return r.base + (r.len - FZN_SIG_LEN);
}

/* WHAT THE SIGNATURE COVERS: everything but the signature, which is the
 * version byte, the object byte, every field and the body.
 *
 * Exposed because a consumer that keeps its own transcript, or that wants to
 * re-verify without this module, must be able to name the same range this
 * module names -- and because a range somebody derives by hand is the defect
 * this file was rewritten to remove. */
static inline void fzn_record_signed_bytes(fzn_record_t r, const uint8_t **at, size_t *len)
{
	*at = r.base;
	*len = r.len - FZN_SIG_LEN;
}

/* Is this record what its issuer signed?
 *
 * Answers authenticity and nothing else. It does not ask whether the issuer
 * was ALLOWED to say it -- that is `fzn_chain_verify` against a capability the
 * consumer chooses for this `kind` -- and it does not ask whether the record
 * is current, which is the journal's question.
 *
 * Separated on purpose: a consumer that authorises by capability chain and one
 * that authorises by local uid both need this, and neither needs the other's
 * answer.
 *
 * Every field is inside the range checked, so there is no field to tamper with
 * that leaves this answering OK. That is the whole reason a record is a view
 * rather than a struct. */
fzn_record_err_t fzn_record_verify(fzn_record_t record, const fzn_sign_ops_t *sign);

/* Encode these fields and sign them, producing the bytes a record is.
 *
 * THE ONLY WAY TO PRODUCE A RECORD, and it has to exist: without it a
 * consumer cannot make one at all, and the locally-authored case -- a host
 * applying its own configuration, which is `state/`'s ordinary use -- has no
 * other answer. The predecessor of this file took the encoded bytes as an
 * INPUT to signing, which meant a caller had to have encoded a record before
 * it could make one, and there was nothing in the tree that could.
 *
 * A LOCALLY BUILT RECORD IS ENCODED AND THEN READ BACK. This writes bytes; it
 * does not hand back a view. The caller passes `out` to `fzn_record_open` and
 * uses the accessors, exactly as it would for a record that arrived from the
 * network, so there is one representation everywhere and a locally authored
 * statement travels through the same code as a received one. A field that
 * survives that round trip is a field the signature covers, which is the
 * property `record/test/record_test.c` checks by making it fail.
 *
 * The argument order IS the layout order, and that is the mnemonic. It is
 * also the hazard: `issuer` and `subject` are both 32-byte arrays and
 * `stream` and `kind` are both uint32, so either pair swaps at a call site
 * with nothing to say so. A swap produces a record that verifies and says
 * something else, so this is the call to read twice -- the same shape
 * `fzn_state_clear` was changed to take a record to avoid.
 *
 * `out_cap` must be at least FZN_RECORD_HEADER_LEN + `body_len` + FZN_SIG_LEN,
 * and FZN_RECORD_MAX_LEN is always enough. On success `*out_len` is the
 * number of bytes written. ON FAILURE `*out_len` IS UNTOUCHED AND `out` MAY
 * HOLD PARTIAL BYTES: a buffer from a failed sign is not a record and must
 * not be opened.
 *
 * FZN_RECORD_ERR_MALFORMED for a missing argument, an absent signer, a null
 * body of non-zero length, or an `out_cap` that cannot hold the result;
 * FZN_RECORD_ERR_BODY_TOO_LARGE and FZN_RECORD_ERR_SEQ_ZERO for the two
 * fields with a bound; FZN_RECORD_ERR_UNSIGNED if the signer refuses. */
fzn_record_err_t fzn_record_sign(const uint8_t issuer[FZN_PUBKEY_LEN],
                                 const uint8_t subject[FZN_SUBJECT_LEN], uint32_t stream,
                                 uint32_t kind, uint64_t seq, uint64_t issued_at,
                                 const uint8_t *body, size_t body_len,
                                 const fzn_sign_ops_t *sign, uint8_t *out, size_t out_cap,
                                 size_t *out_len);

/* A short name for `fzn_record_err_t`, for a log line or a message to a user.
 *
 * NEVER NULL, including for a value that is not one of the enumerators, so
 * that a caller may pass the result straight to a printf without a check. */
const char *fzn_record_err_str(fzn_record_err_t err);

#endif /* FZN_RECORD_H */
