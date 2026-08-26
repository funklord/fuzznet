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
 * WHY NO ENCODER HERE. `signed_region` is the bytes the signature covers and
 * is taken as opaque, for the reason `chain.h` gives at length: recomputing
 * them would put a second encoder in the tree for the schema to disagree with
 * later. The fields below are a DECODED VIEW of that same region and the
 * caller is responsible for their agreeing.
 *
 * WHAT IS DELIBERATELY NOT HERE:
 *
 *   - **Authorisation.** Whether an issuer may say this is a capability
 *     question, answered by `fzn_chain_verify` against a capability the
 *     consumer maps from `kind`. Keeping it out is what lets one project
 *     authorise by chain, another by local uid, and a third by both.
 *   - **Transport.** A record does not know how it travelled. `wire/seal.h`
 *     carries bytes; this is what some of those bytes mean.
 *   - **Allocation.** Nothing here allocates, per sec 2. A body is bounded and
 *     the caller owns it.
 */

#ifndef FZN_RECORD_H
#define FZN_RECORD_H

#include "../chain/chain.h"

#include <stddef.h>
#include <stdint.h>

/* What a statement is ABOUT. Opaque, and 32 bytes so that it can hold a
 * public key -- the common case is a statement about a host or a user -- or
 * a hash of something longer. A consumer that wants a short name hashes it. */
#define FZN_SUBJECT_LEN 32

/* The largest body this will carry. Bounded because nothing here allocates,
 * and small because a record is a statement rather than a payload: a
 * configuration value, a rule, a grant. Anything larger is a message, and
 * `chunk/` already carries messages. */
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

typedef enum fzn_record_err {
	FZN_RECORD_OK = 0,
	FZN_RECORD_ERR_MALFORMED = -1,
	/* The signature does not check out against the issuer. */
	FZN_RECORD_ERR_UNSIGNED = -2,
	/* The body is larger than this module will carry. Its own error rather
	 * than MALFORMED, because it is a sizing decision a consumer can act on
	 * -- split the statement, or raise the bound deliberately -- and not a
	 * caller's bug. */
	FZN_RECORD_ERR_BODY_TOO_LARGE = -3,
	/* Sequence zero. Reserved to mean "no record yet", so that a journal
	 * entry can start empty without a separate flag. */
	FZN_RECORD_ERR_SEQ_ZERO = -4,
} fzn_record_err_t;

/* One statement.
 *
 * `seq` is per ISSUER and strictly increasing. Per-issuer rather than global
 * because a global sequence needs consensus and this design has none: two
 * hosts that never speak must still be able to issue. It is what makes a gap
 * detectable -- see `record/journal.h` -- and it is why replaying an old
 * record is refused rather than merely useless.
 *
 * `issued_at` is the issuer's clock and is NOT trusted for ordering. Clocks
 * disagree; sequences do not. It is here because a consumer displaying a rule
 * wants to say when, and because an expiry policy needs something to compare.
 * Ordering decisions use `seq`. */
typedef struct fzn_record {
	uint8_t issuer[FZN_PUBKEY_LEN];
	uint8_t subject[FZN_SUBJECT_LEN];
	/* WHICH SEQUENCE THIS BELONGS TO. An issuer numbers each stream from 1
	 * independently, so `seq` is unique within (issuer, stream) and not
	 * within issuer.
	 *
	 * IT EXISTS BECAUSE OF PARTIAL ENTITLEMENT, and one sequence per issuer
	 * cannot express it. If a recipient is not allowed to see some of an
	 * issuer's records, its position develops holes it is not permitted to
	 * fill -- and `fzn_journal_admit` refuses a gap, correctly, so that
	 * recipient asks for ever for a record nobody will ever send it.
	 * Measured before this field existed: admitting sequence 1 then 3
	 * answers "ahead of what is held", and the journal wants 2 permanently.
	 *
	 * So fidelity is a STREAM. A coarse track and a precise one are two
	 * streams, each contiguous for whoever is entitled to it, and
	 * entitlement is an ordinary capability question answered by `chain/`.
	 *
	 * WHO ASSIGNS THESE. A stream number is scoped to its issuer -- a
	 * position is (issuer, stream) -- so two issuers using 7 for different
	 * purposes never collide, and a stream needs agreement only between an
	 * issuer and whoever follows it. That is a real structural difference
	 * from `fzn_kind`, which every host must agree about before it can
	 * parse a frame at all, and it is why this namespace does not need the
	 * central assignment that one does.
	 *
	 * One case does need agreement, and the range below is reserved for it:
	 * a WELL-KNOWN stream means the same thing for every issuer, so that a
	 * host anchoring a root can follow something without being told its
	 * number out of band. An issuer's revocations are the obvious
	 * candidate. **None is assigned yet**, deliberately -- naming one
	 * before anything follows it would be inventing a mechanism ahead of
	 * its need. The range exists so that a consumer can assign freely
	 * TODAY without a future well-known stream colliding with what it
	 * chose.
	 *
	 * DELIBERATELY NOT `kind`, though the two are often the same value in
	 * practice. Permissions need CROSS-KIND ORDERING -- a grant and a
	 * revocation are different kinds and must be totally ordered against
	 * each other -- so a consumer puts them in one stream and its telemetry
	 * in another. Collapsing stream into kind would make that unsayable. */
	uint32_t stream;
	uint32_t kind;
	uint64_t seq;
	uint64_t issued_at;
	const uint8_t *body;
	size_t body_len;
	uint8_t signature[FZN_SIG_LEN];
	const uint8_t *signed_region;
	size_t signed_region_len;
} fzn_record_t;

/* Is this record what its issuer signed?
 *
 * Answers authenticity and nothing else. It does not ask whether the issuer
 * was ALLOWED to say it -- that is `fzn_chain_verify` against a capability the
 * consumer chooses for this `kind` -- and it does not ask whether the record
 * is current, which is the journal's question.
 *
 * Separated on purpose: a consumer that authorises by capability chain and one
 * that authorises by local uid both need this, and neither needs the other's
 * answer. */
fzn_record_err_t fzn_record_verify(const fzn_record_t *record, const fzn_sign_ops_t *sign);

/* A short name for `fzn_record_err_t`, for a log line or a message to a user.
 *
 * NEVER NULL, including for a value that is not one of the enumerators, so
 * that a caller may pass the result straight to a printf without a check. */
const char *fzn_record_err_str(fzn_record_err_t err);

#endif /* FZN_RECORD_H */
