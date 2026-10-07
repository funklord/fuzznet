/* Revocation: the record, the store, and what it takes to put something in
 * it.
 *
 * project.md sec 4.2 is half built without this. It says a capability chain
 * is "verified against a pinned root rather than adopted, WITH REVOCATION
 * CARRIED ON CONTACT", and netcfgd's brief calls that the part it most
 * wants, as a requirement rather than a preference: a stolen device is a
 * capability to revoke, not a password to change. chain.c consults a list of
 * revocations; nothing until now produced one.
 *
 * A REVOCATION IS SIGNED, AND AN EARLIER COMMENT IN chain.h SAID OTHERWISE.
 * That comment argued a revocation needs no signature of its own because it
 * "arrives inside an authenticated datagram and is already attributable",
 * and that making it self-authenticating "would duplicate the envelope's
 * job". It is wrong, and the word that makes it wrong is CONTACT.
 *
 * An authenticated datagram attributes its contents to the peer that sent
 * it, and to nobody further back. Carried on contact means a revocation
 * travels peer to peer -- sec 5 records that relays are the next thing
 * likely to move in, and sec 13 that a frame may be handed over by a relay
 * hours late. So the carrier is not the issuer, and a revocation trusted
 * because of who handed it over is one any carrier can invent. That is not
 * a small hole: inventing revocations is a denial of service against
 * exactly the hosts an attacker wants disconnected, and it needs no key.
 *
 * So a revocation carries its issuer's signature, verified against the same
 * pinned root a chain is, through the same seam. Then it can cross a
 * stranger and still mean something, which is the property "on contact"
 * actually requires.
 *
 * A RECORD IS A VIEW OVER BYTES (2026-08-27), and it had the same defect a
 * hop did, one layer worse. This struct used to carry `capability`,
 * `grantee`, `issuer` and `issued_at` as decoded fields beside an opaque
 * `signed_region` nothing compared them against, and `fzn_revocation_admit`
 * pinned the issuer, verified the signature over the region, and then stored
 * the FIELDS. So one genuine root-signed revocation could be replayed with
 * `grantee` rewritten to any host an attacker cared to name -- a permanent
 * forged revocation, since revocation entries are never evicted and nothing
 * expires them. chain.h's design note carries the reproduction and the
 * reasoning; this file is the same change.
 *
 * VERIFIED ONCE, ON ADMISSION. The store keeps only what has already been
 * checked, so the query on the hot path is a comparison rather than a
 * signature check, and the store itself is what `fzn_chain_verify` is
 * handed.
 */

#ifndef FZN_REVOCATION_H
#define FZN_REVOCATION_H

#include "chain.h"

/* For `fzn_hash_ops_t`: admission must compute a record's identity, and
 * `blob/blob.h` already reaches for the same seam from outside session/. */
#include "../session/commitment.h"

/* THE REVOCATION LAYOUT. Big-endian, fixed width, no padding, fixed fields
 * first -- the same rules as the hop, for the same reason.
 *
 *     offset  size  field
 *          0     1  version    (= FZN_SIGNED_VERSION)
 *          1     1  object     (= FZN_OBJECT_REVOCATION)
 *          2    32  capability
 *         34    32  grantee
 *         66    32  issuer
 *         98     8  issued_at
 *        106    32  supersedes (the id of a revocation this replaces)
 *        138     8  epoch      (the k-of-n cycle this vote belongs to)
 *        146    32  cut        (the last act of the grantee's still trusted)
 *        178    64  signature
 *
 * The signature covers bytes 0 through 177. The epoch arrived in sec 400 and
 * the cut in sec 496; a record of either older layout (202 or 210 bytes)
 * does not open, by its length. The object byte is what stops a
 * signature made over a hop being presented as a revocation, and vice versa;
 * wire/bytes.h records what it cost fuzzypickles to learn that two record
 * types of the same length can have ONE SIGNATURE THAT VERIFIES AS BOTH. */
#define FZN_REVOCATION_BODY_LEN 178u
#define FZN_REVOCATION_LEN (FZN_REVOCATION_BODY_LEN + (size_t)FZN_SIG_LEN)

#define FZN_REV_OFF_VERSION 0u
#define FZN_REV_OFF_OBJECT 1u
#define FZN_REV_OFF_CAPABILITY 2u
#define FZN_REV_OFF_GRANTEE 34u
#define FZN_REV_OFF_ISSUER 66u
#define FZN_REV_OFF_ISSUED_AT 98u
/* The record this one answers, by hash, or all-zero for none.
 *
 * ON A REVOCATION it is the PREVIOUS revocation of the same (issuer,
 * capability, grantee), and all-zero for the first. It exists to make a
 * re-revocation a different record: without it, revoking a pair, withdrawing
 * it and revoking it again produces bytes identical to the first revocation
 * -- same fields, same `issued_at` at one-second resolution, and a
 * deterministic signer -- which therefore hashes to the record the
 * withdrawal names, and is refused as the stale copy it is not. The pair
 * would be revocable once, withdrawable once, and never revocable again.
 *
 * ON A WITHDRAWAL it is the revocation being undone, and must not be zero.
 *
 * WHAT THE STORE ENFORCES IS WEAKER THAN WHAT THIS FIELD MEANS, deliberately
 * and since sec 359. A re-revocation offered over a WITHDRAWN entry must NAME
 * a predecessor -- a non-zero `supersedes` -- and need not name the one the
 * store holds. Requiring the exact id made the only admissible record the one
 * immediately after the held withdrawal, so a host that missed a single
 * propagation round refused every later revocation of the pair and read it as
 * unrevoked. It could not recover: this store keeps a hash and a flag, never a
 * record, so the bridging record is one NOTHING RETAINS and no peer can be
 * asked for it. Erring revoked is the cheaper error -- a stale re-revocation
 * denies a grantee until the root withdraws again, where a refused genuine one
 * authorises a grantee the root revoked, silently and for ever.
 *
 * IT IS AN IDENTITY AND NEVER AN ORDER. `issued_at` above carries a NEVER
 * BECOME AN ORDERING KEY argument, and a per-pair counter here would be that
 * argument again under another name: a clock that cannot be bounded and a
 * counter that cannot be bounded are the same hazard. A hash is compared for
 * equality and never for magnitude, which is what makes it safe. */
#define FZN_REV_OFF_SUPERSEDES 106u
/* WHICH K-OF-N CYCLE A VOTE BELONGS TO. sec 400.
 *
 * A withdrawal carries the epoch of the revocation it undoes. A revocation
 * carries the lowest epoch its issuer's store holds open for the pair
 * (`fzn_revocation_current_epoch`), so once k have withdrawn an epoch, a
 * revocation cast afterwards opens the next one and counts from one again.
 * Without it the latch could not tell a withdrawal that completed an undo
 * from one cast before any quorum existed, and one vote re-revoked a device
 * k had restored (sec 399).
 *
 * A NUMBER COMPARED FOR MAGNITUDE, which `supersedes` below and `issued_at`
 * refuse to be, and the reason it is safe is where it is read. An epoch
 * moves nothing by itself: a live revocation counts whatever its epoch, so
 * an epoch can only decide whether WITHDRAWN votes still hold a latch shut,
 * and closing an epoch takes k distinct entitled issuers. One issuer
 * signing epoch UINT64_MAX is one of the k and nothing more. */
#define FZN_REV_OFF_EPOCH 138u
/* WHAT OF THE REVOKED KEY'S OWN WORK STILL STANDS. sec 496.
 *
 * A revoked key did things before it was revoked: wrote roster records,
 * granted devices, cast votes. Some of that was its owner's and some, after
 * a theft, may be a thief's. A record carries no time anybody can trust to
 * tell the two apart, so the line is drawn by ancestry, as a removed root's
 * is (sec 404): every act a key signs is logged in a chain of entries, and
 * a vote names the CUT -- the id of the last entry of the grantee's log the
 * voter still trusts. An act of a revoked key counts only while it stands
 * under the cut of every vote that revokes it; the tightest cut holds.
 *
 * ALL-ZERO TRUSTS NOTHING, which is what a revocation meant before the field
 * existed: a revoked writer counted for nothing. A WITHDRAWAL CARRIES ZERO,
 * refused otherwise at `open`, since undoing a vote restores everything and
 * has no line to draw; a store keeps the cut of the vote it undid.
 *
 * JUDGED WHEN READ, never applied: nothing is deleted when a key is revoked,
 * so an undo -- a device found that never left its owner's hands -- brings
 * every act back. */
#define FZN_REV_OFF_CUT 146u
#define FZN_REV_OFF_SIGNATURE FZN_REVOCATION_BODY_LEN

/* A revocation as it travels: what is withdrawn, who says so, and the proof.
 *
 * A VIEW, exactly as `fzn_chain_hop_t` is. `base` addresses
 * FZN_REVOCATION_LEN bytes the caller owns, and every field is read from the
 * bytes the signature covers. */
typedef struct fzn_revocation_record {
	const uint8_t *base;
} fzn_revocation_record_t;

/* Take a view over `len` bytes.
 *
 * Refuses a wrong length, a version byte that is not ours, and an object
 * byte that is not FZN_OBJECT_REVOCATION -- all FZN_CHAIN_ERR_SHAPE. Null
 * arguments are FZN_CHAIN_ERR_MALFORMED, which is the caller's bug rather
 * than a peer's bytes.
 *
 * There is no `delegable` here, so this has one canonicality check fewer
 * than `fzn_hop_open`: every remaining field is a fixed-width opaque value
 * or an integer, and each of those has exactly one encoding already. */
fzn_chain_err_t fzn_revocation_open(const uint8_t *bytes, size_t len,
                                    fzn_revocation_record_t *out);

/* Lay out a revocation, unsigned. `out` receives FZN_REVOCATION_LEN bytes
 * with the signature zeroed. The only encoder for this object, on the same
 * argument `fzn_hop_encode` carries. */
/* `object` is FZN_OBJECT_REVOCATION or FZN_OBJECT_WITHDRAWAL; `supersedes`
 * is the record this one answers, or NULL for none, which writes zeros.
 *
 * BOTH ARE ARGUMENTS RATHER THAN A SECOND FUNCTION OR A DEFAULTED FIELD.
 * chain/authz.h records the reasoning at length for its own `origins`: a
 * field added to a struct leaves every existing call site compiling while
 * getting whatever the default was, and a default here is either "this is a
 * revocation" -- which silently mints the wrong object for a caller meaning
 * to withdraw -- or "supersedes nothing", which silently mints the
 * un-chained re-revocation the field exists to prevent. An added argument
 * makes every call site fail to compile, which is the loud failure. */
fzn_chain_err_t fzn_revocation_encode(uint8_t *out, uint8_t object,
                                      const uint8_t issuer[FZN_PUBKEY_LEN],
                                      const fzn_cap_id_t *capability,
                                      const uint8_t grantee[FZN_PUBKEY_LEN],
                                      uint64_t issued_at, uint64_t epoch,
                                      const uint8_t supersedes[FZN_REVOCATION_ID_LEN],
                                      const uint8_t cut[FZN_REVOCATION_ID_LEN]);

/* Encode and sign a revocation: `issuer` withdraws `capability` from
 * `grantee`, still trusting the grantee's acts up to `cut` (NULL for
 * none, sec 496). `out` receives FZN_REVOCATION_LEN bytes.
 *
 * The counterpart to `fzn_chain_mint`, and it exists for the same reason:
 * without it, the root has no way to produce a revocation and every consumer
 * -- and every test -- writes its own encoder, which is what the whole
 * change of 2026-08-27 was about removing.
 *
 * `issuer` is a PUBLIC key, used to fill the record's issuer field; whether
 * the signer actually holds the matching secret is not a question this can
 * ask, exactly as in `fzn_chain_mint`. */
fzn_chain_err_t fzn_revocation_issue(const uint8_t issuer[FZN_PUBKEY_LEN],
                                     const fzn_cap_id_t *capability,
                                     const uint8_t grantee[FZN_PUBKEY_LEN], uint64_t issued_at,
                                     uint64_t epoch, const uint8_t cut[FZN_REVOCATION_ID_LEN],
                                     const fzn_sign_ops_t *sign, uint8_t *out);

/* THE THREE MINTING CALLS, and the split is the whole of how the chaining
 * rule is enforced rather than documented.
 *
 * `fzn_revocation_issue` above mints a FIRST revocation: `supersedes` is
 * zero. `fzn_revocation_reissue` mints one that supersedes a named earlier
 * revocation of the same triple. `fzn_revocation_issue_withdrawal` mints the
 * record that undoes one.
 *
 * A caller cannot get this wrong by omission, because a caller cannot omit
 * anything: re-revoking with `issue` produces a zero `supersedes`, and
 * `fzn_revocation_admit` REFUSES that against a store already holding a
 * withdrawal for the pair. The rule is a refusal at admission and not a
 * sentence in a header -- see the admission notes below.
 *
 * `target` for a withdrawal is the hash of the FZN_REVOCATION_LEN bytes of
 * the record being undone, and must be non-zero. Hashing the whole record
 * rather than its signed range is deliberate: what a peer holds and relays
 * is the whole record, so its identity is the thing that travelled.
 *
 * MINTING A WITHDRAWAL IS STRICT AND INSTALLING ONE IS NOT, and the two
 * rules must stay apart. Here the target may not be zero: a withdrawal
 * naming nothing could never be matched against anything later, so it would
 * pre-authorise the next revocation anybody issues for that pair -- a blank
 * cheque. At `fzn_revocation_admit` the opposite holds: a withdrawal for a
 * triple the store has never held is STORED, because it names ONE record by
 * hash and can only ever refuse that one. Tolerating any arrival order is
 * the whole point of it, and on a mesh a withdrawal overtaking its
 * revocation is ordinary rather than exceptional.
 *
 * Written as two rules because they look like one and somebody will
 * otherwise simplify them into "a withdrawal must name something real",
 * which is true of minting and wrong of installing. */
fzn_chain_err_t fzn_revocation_reissue(const uint8_t issuer[FZN_PUBKEY_LEN],
                                       const fzn_cap_id_t *capability,
                                       const uint8_t grantee[FZN_PUBKEY_LEN],
                                       uint64_t issued_at, uint64_t epoch,
                                       const uint8_t supersedes[FZN_REVOCATION_ID_LEN],
                                       const uint8_t cut[FZN_REVOCATION_ID_LEN],
                                       const fzn_sign_ops_t *sign, uint8_t *out);

fzn_chain_err_t fzn_revocation_issue_withdrawal(const uint8_t issuer[FZN_PUBKEY_LEN],
                                                const fzn_cap_id_t *capability,
                                                const uint8_t grantee[FZN_PUBKEY_LEN],
                                                uint64_t issued_at, uint64_t epoch,
                                                const uint8_t target[FZN_REVOCATION_ID_LEN],
                                                const fzn_sign_ops_t *sign, uint8_t *out);

/*
 * ---- A WITHDRAWAL HAS NO DISTRIBUTION PATH IN THIS LIBRARY -------------
 *
 * STATED BECAUSE ITS ABSENCE READS AS AN OVERSIGHT. Everything above works
 * on the host that performs the withdrawal -- the record is minted, admitted
 * and stored, `fzn_revocation_covers` answers no, and a stale copy of the
 * withdrawn revocation is refused. None of that reaches another host by
 * itself, and nothing here tells another host it should ask.
 *
 * Two hosts, and the trace is the whole of it:
 *
 *   A revokes P and B learns it. Both hold P revoked.
 *   A withdraws P. A's entry says withdrawn; B's still says revoked.
 *   A's manifest OMITS P -- `fzn_manifest_issue` skips withdrawn entries,
 *     correctly, since a manifest states what IS revoked and publishing P
 *     would tell every receiver to revoke a pair A has restored, under A's
 *     own signature.
 *   B's manifest NAMES P. A admits it and answers `fzn_revocation_known`,
 *     so A records no deficit, asks for nothing, and says nothing.
 *   B stays revoked. So does every host but A.
 *
 * The deficit machinery is the wrong shape for this and not merely missing a
 * case: it computes what THIS host lacks from a peer's manifest, and a
 * withdrawal is a thing this host HAS that the peer lacks. There is no
 * "here is what you are holding that I have since undone" anywhere in
 * `chain/manifest.h`, and a manifest cannot carry one without becoming a
 * statement about two kinds of thing.
 *
 * WHAT A CONSUMER MUST DO TODAY: hand the withdrawal record to
 * `fzn_revocation_admit` on every host that needs it, by whatever path it
 * already uses to move records. Admission is idempotent, so re-delivery is
 * free, and a host that never held the revocation stores the withdrawal as
 * a tombstone naming it (below, since 2026-09-03), so the revocation
 * arriving later is refused as the stale copy it is. What a consumer CANNOT
 * do is rely on the manifest exchange to converge it. fuzznet's own node is
 * one such path: a member pulls its root's records, withdrawals included,
 * with `get revocation` (`node/revoke.h`, secs 384 and 386).
 *
 * THE DESIGN QUESTION IS OPEN and is not this header's to settle: whether a
 * manifest gains a second section, whether withdrawals get a manifest of
 * their own, or whether a pair's entry becomes a state rather than a set
 * membership. Each changes what a manifest means, so it is the copyright
 * holder's. Recorded here rather than left for the next reader to derive
 * from an absence -- which is how `record/sync.h`'s append-only
 * precondition came to cost a consumer a day.
 */

/* The accessors, over an OPENED record -- see chain.h's equivalent note. */
/* Typed, like `fzn_manifest_capability`: the cast that makes a wire view
 * carry its type lives in the accessor so that no caller writes one. */
static inline const fzn_cap_id_t *fzn_revocation_capability(fzn_revocation_record_t rec)
{
	return (const fzn_cap_id_t *)(rec.base + FZN_REV_OFF_CAPABILITY);
}

static inline const uint8_t *fzn_revocation_grantee(fzn_revocation_record_t rec)
{
	return rec.base + FZN_REV_OFF_GRANTEE;
}

static inline const uint8_t *fzn_revocation_supersedes(fzn_revocation_record_t rec)
{
	return rec.base + FZN_REV_OFF_SUPERSEDES;
}

/* WHICH OF THE TWO THIS IS, read from the signed tag rather than inferred.
 *
 * A withdrawal and a revocation are the same length and differ in one byte
 * and one field, so nothing about a record's shape distinguishes them. Every
 * reader that acts on a record must ask -- and in particular a store must
 * not treat the PRESENCE of an entry as the answer to "is this revoked",
 * because after a withdrawal the entry is still there and says the
 * opposite. */
static inline int fzn_revocation_is_withdrawal(fzn_revocation_record_t rec)
{
	return rec.base[FZN_REV_OFF_OBJECT] == (uint8_t)FZN_OBJECT_WITHDRAWAL;
}

/* Who issued it. The root, or a grantor withdrawing from its own descendant.
 *
 * IT ARRIVED (2026-08-28), and this comment used to describe it as planned.
 * project.md sec 13b records the copyright holder's answer of 2026-08-27 --
 * grantor-revokes-descendant is coming, on the reasoning that it is a denial
 * of service inside one user's estate rather than an escalation across users
 * -- and sec 13c is the design that was built from it.
 *
 * THE ENTITLED ISSUERS ARE NOT A WIDER PARAMETER BUT A NARROWER ONE. For a
 * hop, they are the root and that hop's ancestors IN THE CHAIN BEING
 * VERIFIED, which `fzn_chain_verify` already walks with every grantor in
 * hand -- see `fzn_revocation_covers_chain` below. It cannot be told the
 * wrong set because it is not told. */
static inline const uint8_t *fzn_revocation_issuer(fzn_revocation_record_t rec)
{
	return rec.base + FZN_REV_OFF_ISSUER;
}

/* When the issuer says it revoked. DISPLAY AND POLICY ONLY, and it MUST
 * NEVER BECOME AN ORDERING KEY.
 *
 * It is inside the signed range, so it cannot be rewritten in flight -- and
 * that is exactly what makes it tempting. NO LIBRARY CODE READS IT: the
 * only callers in the tree are three lines of revocation_test.c, and
 * `fzn_revocation_admit` stores the issuer, capability and grantee and not
 * this. A field that is signed, free to read and load-bearing nowhere is
 * one somebody makes load-bearing.
 *
 * project.md sec 13a rejects that move for `state/` and the reasoning is
 * worse here: nothing bounds a clock, so `issued_at = UINT64_MAX` can never
 * be superseded by anything the issuer publishes afterwards -- which would
 * freeze a REVOCATION out, unrecoverably, which is the one direction this
 * module must never fail in. sec 4.7b measured the same shape live, where
 * 4096 frames at `expires_at = UINT64_MAX` pinned a replay window
 * permanently and needed no key to do it. */
static inline uint64_t fzn_revocation_issued_at(fzn_revocation_record_t rec)
{
	return fzn_get_be64(rec.base + FZN_REV_OFF_ISSUED_AT);
}

/* The epoch this vote belongs to. See FZN_REV_OFF_EPOCH. */
static inline uint64_t fzn_revocation_epoch(fzn_revocation_record_t rec)
{
	return fzn_get_be64(rec.base + FZN_REV_OFF_EPOCH);
}

/* The cut, sec 496: all-zero when the vote trusts nothing of the grantee's,
 * and always on a withdrawal. */
static inline const uint8_t *fzn_revocation_cut(fzn_revocation_record_t rec)
{
	return rec.base + FZN_REV_OFF_CUT;
}

static inline const uint8_t *fzn_revocation_signature(fzn_revocation_record_t rec)
{
	return rec.base + FZN_REV_OFF_SIGNATURE;
}

static inline void fzn_revocation_signed_bytes(fzn_revocation_record_t rec, const uint8_t **at,
                                               size_t *len)
{
	*at = rec.base;
	*len = FZN_REVOCATION_BODY_LEN;
}

/* A bounded set of verified revocations, over caller-owned storage.
 *
 * The signature is checked at admission and not at query, which is what
 * makes this a set of decided facts rather than of evidence: a chain
 * verification walks the whole set per hop, and re-checking a signature per
 * hop per revocation would make revocation cost grow with the square of
 * nothing useful.
 *
 * A CALLER PASSES THE STORE, AND THIS COMMENT USED TO SAY OTHERWISE. It said
 * "`entries` is exactly what fzn_chain_verify takes, so a caller passes
 * `store.entries, store.used` straight into it", and that pattern is what
 * every consumer and every suite in the tree followed. `used` is a count of
 * live entries and `capacity` is the length of the array; splitting them at
 * the call boundary handed the verifier the count and kept the bound behind,
 * and it read one entry past the array for any store where the two had
 * diverged -- a heap overflow on the authorization path, reproduced under
 * AddressSanitizer. chain.h carries the report. `fzn_chain_verify` takes a
 * `const fzn_revocation_store_t *` now, and the three fields travel
 * together because they only mean anything together. */
/* Declared, not included, and repeated per header on purpose: a forward
 * declaration is legal any number of times, and every header here is
 * self-contained rather than relying on what its neighbours pulled in. */
struct flog_t;

/* AN ADMIN AS THE STORE REMEMBERS IT: a key that showed a chain for the
 * store's admin capability, kept as each hop's grantor and grantee so the
 * store can ask later whether that chain has itself been revoked. sec 397. */
typedef struct fzn_revocation_admin {
	uint8_t key[FZN_PUBKEY_LEN];
	size_t hop_count;
	uint8_t grantor[FZN_CHAIN_MAX_HOPS][FZN_PUBKEY_LEN];
	uint8_t grantee[FZN_CHAIN_MAX_HOPS][FZN_PUBKEY_LEN];
	/* Each hop's hash, what a confirmation names: zero when the store
	 * keeps no confirmations. sec 414. */
	uint8_t hop_id[FZN_CHAIN_MAX_HOPS][FZN_REVOCATION_ID_LEN];
	/* The first hop's hash, the act its root logged: what a root set asks
	 * about once that root is removed. sec 417. */
	uint8_t first_act[FZN_REVOCATION_ID_LEN];
} fzn_revocation_admin_t;

/* A CONFIRMATION AS THE STORE KEEPS IT: who confirmed which admin grant, and
 * the record's own hash -- the act a root that confirms logs, which a root
 * set asks about once that root is removed. sec 414. */
typedef struct fzn_revocation_confirm {
	uint8_t confirmer[FZN_PUBKEY_LEN];
	uint8_t grant[FZN_REVOCATION_ID_LEN];
	uint8_t act[FZN_REVOCATION_ID_LEN];
} fzn_revocation_confirm_t;

/* THE ROOT SET, AS A STORE ASKS IT. sec 406. `member` is 1 for a key that is
 * a root, removed or not; `counts` is 1 when the record whose hash is `act`,
 * signed by root `root`, still counts -- always for a standing root, and for
 * a removed one only when its log shows the record before the removal's cut.
 * `chain/root_log.h` fills these from a settled view; a consumer may bring
 * its own. A vtable rather than the module, so that nothing linking the
 * store has to link the set. */
/* A KEY'S LOG OF ITS ACTS, as a store asks it. sec 496. `stands` is 1 when
 * the act whose hash is `act`, signed by `key`, is logged at or before the
 * entry `cut` in that key's chain of entries. `chain/root_log.h` fills it
 * from a log, the same log a root's acts are kept in: the entry's shape
 * names a key, and nothing in it needs the key to be a root. */
typedef struct fzn_act_log_ops {
	int (*stands)(void *ctx, const uint8_t key[FZN_PUBKEY_LEN],
	              const uint8_t cut[FZN_REVOCATION_ID_LEN],
	              const uint8_t act[FZN_REVOCATION_ID_LEN]);
	void *ctx;
} fzn_act_log_ops_t;

typedef struct fzn_root_ops {
	int (*member)(void *ctx, const uint8_t key[FZN_PUBKEY_LEN]);
	int (*counts)(void *ctx, const uint8_t root[FZN_PUBKEY_LEN],
	              const uint8_t act[FZN_REVOCATION_ID_LEN]);
	void *ctx;
} fzn_root_ops_t;

struct fzn_revocation_store {
	fzn_revocation_t *entries;
	size_t capacity;
	size_t used;
	/* Where this store says what happened, or NULL for silence. sec 211. */
	struct flog_t *log;
	/* Bumped whenever this store's ANSWERS could change, so a cache built
	 * on them can tell. Read it with `fzn_revocation_generation` rather
	 * than reaching in. sec 354. */
	uint64_t generation;
	/* HOW MANY DISTINCT ENTITLED ISSUERS A REVOCATION NEEDS, and how many
	 * withdrawals undo one: sec 394's k-of-n, in the core since sec 397.
	 * `fzn_revocation_store_set_quorum` raises it and names the admin
	 * capability whose holders may vote besides a hop's ancestors.
	 *
	 * LAST IN THE STRUCT, AND 0 READS AS 1, so a store a consumer
	 * initialised positionally before these fields existed -- `{ entries,
	 * capacity, used, NULL, 0 }`, which three suites here still use --
	 * keeps every answer it gave before.
	 *
	 * A STORE MUST START ZEROED OR FROM `fzn_revocation_store_init`. One
	 * declared on the stack and filled field by field holds whatever the
	 * stack held in these fields, and `admins_used` read as garbage is a
	 * read past an array. 29 declarations in this tree's suites did that
	 * and were harmless until sec 397 gave the store fields they never set;
	 * `chain_test` crashed on the first. */
	size_t quorum;
	int has_admin;
	fzn_cap_id_t admin_capability;
	fzn_revocation_admin_t *admins;
	size_t admin_capacity;
	size_t admins_used;
	/* THE ROOT SET, when the estate has more than one root: NULL for the
	 * single pinned root every call names. `root_hash` hashes a hop so
	 * `fzn_chain_verify` can ask whether a removed root's grant counts.
	 * Set with `fzn_revocation_store_set_roots`; sec 406. */
	const fzn_root_ops_t *roots;
	const fzn_hash_ops_t *root_hash;
	/* ADMIN GRANT CONFIRMATIONS, sec 414: NULL for none kept, in which case
	 * every admin grant counts as it did before. Set with
	 * `fzn_revocation_store_set_confirmations`. */
	fzn_revocation_confirm_t *confirms;
	size_t confirm_capacity;
	size_t confirms_used;
	const fzn_hash_ops_t *confirm_hash;
	/* THE LOG OF EVERY KEY'S ACTS, sec 496: NULL when none is kept, and
	 * then nothing a revoked key did stands -- what a revocation meant
	 * before votes carried a cut. Set with `fzn_revocation_store_set_acts`. */
	const fzn_act_log_ops_t *acts;
};

fzn_chain_err_t fzn_revocation_store_init(fzn_revocation_store_t *store, fzn_revocation_t *entries,
                                     size_t capacity);

/*
 * k-OF-n REVOCATION. project.md secs 394 and 397, the holder's decisions of
 * 2026-09-29: every revocation needs `quorum` distinct entitled issuers, and
 * undoing one needs as many.
 *
 * WHO IS ENTITLED: the root and a hop's ancestors in the chain, as always,
 * and -- when `admin_capability` is given -- any key that shows a chain for
 * that capability, whoever granted the device. Admins' records are admitted
 * with their admin chain in the offer; `admins` is where the store keeps
 * them, `admin_capacity` of them.
 *
 * THE RULE, per hop, over the distinct entitled issuers holding an entry for
 * it: revoked while `quorum` of them are live, and -- the latch -- once
 * `quorum` have revoked, until `quorum` have withdrawn. So one issuer can
 * neither revoke alone nor, having revoked with others, undo alone.
 *
 * EXCEPT THE ROOT, sec 403: a root acts for the estate alone. Its live
 * revocation revokes by itself and holds whatever others withdraw; its
 * withdrawal in epoch E undoes the decision in E, so no other vote cast in E
 * or earlier counts and the next opens E + 1. The root of a hop is the
 * judged chain's first grantor. At a quorum of 1 this overrides one thing
 * the old rule did not: a member's live vote in an epoch the root undid.
 *
 * ADMINS IN TWO STRATA, because admins revoking each other has no stable
 * answer under one rule. First the store decides which admins' own chains are
 * revoked, counting every admin's vote; then it drops the votes of those and
 * decides everything else. Mutual revocation cancels both admins, failing
 * toward revocation; the root restores whoever was right.
 *
 * Judged when asked, from the set held, so the answer does not depend on the
 * order anything arrived in. `fzn_revocation_store_set_quorum` refuses a
 * `quorum` of 0; a store that holds 0 in the field reads it as 1. With a
 * quorum of 1 and no admin capability every answer is what it was before
 * sec 397.
 */
/*
 * SEVERAL ROOTS. sec 406. With `roots` set, a store and `fzn_chain_verify`
 * over it take the estate's root set rather than the one root each call
 * names:
 *
 *   - a chain verifies from any root the set names, as long as its first
 *     hop counts -- always for a standing root, and for a removed one only
 *     when that hop is logged before the removal's cut;
 *   - a revocation signed by a root is admitted from any member root, and
 *     counts when read only while the set says its record does;
 *   - every root that counts acts alone, as sec 403 gives the one root.
 *
 * NULL `roots` is the single-root store every call site had before. `hash`
 * must be given with `roots`. MALFORMED otherwise.
 */
fzn_chain_err_t fzn_revocation_store_set_roots(fzn_revocation_store_t *store,
                                               const fzn_root_ops_t *roots,
                                               const fzn_hash_ops_t *hash);

/* Change the quorum alone, keeping the admins and confirmations held: what a
 * node calls when the estate's k changes under it (sec 418). MALFORMED for 0. */
fzn_chain_err_t fzn_revocation_store_set_k(fzn_revocation_store_t *store, size_t quorum);

fzn_chain_err_t fzn_revocation_store_set_quorum(fzn_revocation_store_t *store, size_t quorum,
                                                const fzn_cap_id_t *admin_capability,
                                                fzn_revocation_admin_t *admins,
                                                size_t admin_capacity);

/*
 * A GRANT OF ADMIN TAKES A GRANT PLUS CONFIRMATIONS. sec 414, the holder's
 * decision of 2026-09-29 (sec 397). One admin mints the grant as ever; it
 * counts once k - 1 OTHER admins have signed a confirmation naming it -- the
 * hop, by its hash. `k` is the store's quorum, so at k = 1 nothing needs one.
 *
 * A ROOT'S WORD SETTLES IT, as sec 403 gives a root the estate's authority: a
 * hop a root granted needs no confirmation, and one confirmation from a root
 * that counts is enough for any hop. A root is the chain's first grantor, or
 * with a root set any member whose confirmation the set says counts.
 *
 * WHO CONFIRMS: an admin the store holds whose own chain is confirmed, and
 * who is not the hop's grantor -- a grantor confirming itself is the one vote
 * the rule exists to stop being enough. The hop's grantee cannot help itself
 * either, with no rule needed: it must stand to confirm, and it stands only
 * once this hop has. Which admins
 * are confirmed is settled as the least set closed under that rule, so the
 * answer does not depend on arrival order, and no two admins can confirm
 * each other into existence. It is settled again after the revocation strata,
 * counting only confirmers left standing, which fails toward revocation.
 *
 * An unconfirmed admin's votes count for nothing, in either stratum.
 *
 * SET THE TABLE BEFORE ADMITTING ANY ADMIN, since an admin's hop ids are
 * taken on admission: MALFORMED once one is held, and for a table of 0 or a
 * missing hash.
 *
 * THE RECORD, big-endian, signed over the first 66 bytes:
 *
 *     off  len  field
 *       0    1  version     FZN_SIGNED_VERSION, 1
 *       1    1  object      FZN_OBJECT_ADMIN_CONFIRM
 *       2   32  confirmer
 *      34   32  grant       the hash of the hop confirmed
 *      66   64  signature   by the confirmer
 */
#define FZN_ADMIN_CONFIRM_OFF_CONFIRMER 2u
#define FZN_ADMIN_CONFIRM_OFF_GRANT 34u
#define FZN_ADMIN_CONFIRM_BODY_LEN 66u
#define FZN_ADMIN_CONFIRM_LEN (FZN_ADMIN_CONFIRM_BODY_LEN + (size_t)FZN_SIG_LEN)

fzn_chain_err_t fzn_revocation_store_set_confirmations(fzn_revocation_store_t *store,
                                                       fzn_revocation_confirm_t *table,
                                                       size_t capacity,
                                                       const fzn_hash_ops_t *hash);

/* Sign a confirmation of the hop whose hash is `grant`. `out` receives
 * FZN_ADMIN_CONFIRM_LEN bytes. */
fzn_chain_err_t fzn_admin_confirm_issue(const uint8_t confirmer[FZN_PUBKEY_LEN],
                                        const uint8_t grant[FZN_REVOCATION_ID_LEN],
                                        const fzn_sign_ops_t *sign, uint8_t *out);

/* Admit a confirmation: its shape and signature, and its confirmer's standing
 * -- a root with `hop_count` 0 (`root`, or a member of the store's set), or an
 * admin showing its admin chain in `hops`, kept in the admin table as a vote
 * would keep it. Whether it counts is judged when the store is read. OK when
 * already held. */
fzn_chain_err_t fzn_revocation_confirm_admit(fzn_revocation_store_t *store,
                                             const uint8_t *bytes, size_t len,
                                             const fzn_chain_hop_t *hops, size_t hop_count,
                                             const uint8_t root[FZN_PUBKEY_LEN],
                                             const fzn_sign_ops_t *sign);

/* WHETHER `key` STANDS AS AN ADMIN: held in the admin table, its grant
 * confirmed, its chain rooted in a root that counts, and not revoked by the
 * admins standing -- the admins whose votes count. What a setting by an
 * admin is judged by (sec 479). 0 for a store that cannot be read. */
int fzn_revocation_admin_stands(const fzn_revocation_store_t *store,
                                const uint8_t key[FZN_PUBKEY_LEN]);

/* WHETHER A RECORD SIGNED BY `issuer` IS CONFIRMED, by the rule an admin
 * grant is (sec 414): `issuer` a root whose record `act` counts -- the pinned
 * `root`, or a member of the set -- or an admin who stands, with k - 1
 * confirmations naming `act` from other admins who stand, or one from a root.
 * With no confirmations kept, or k = 1, an admin who stands acts alone. For
 * a record that is a grant in all but name: a succession (sec 498). 0 for a
 * store that cannot be read. */
int fzn_revocation_confirmed(const fzn_revocation_store_t *store,
                             const uint8_t issuer[FZN_PUBKEY_LEN],
                             const uint8_t act[FZN_REVOCATION_ID_LEN],
                             const uint8_t root[FZN_PUBKEY_LEN]);

/* ADMIT AN ADMIN'S CHAIN WITHOUT A VOTE: `hops` must grant the store's admin
 * capability to `key`, from `root` or a member root, and the admin is kept
 * as a vote's chain would keep it. For an admin known by something other
 * than a vote -- a retention setting, sec 479. OK when already held. */
fzn_chain_err_t fzn_revocation_admin_admit(fzn_revocation_store_t *store,
                                           const uint8_t key[FZN_PUBKEY_LEN],
                                           const fzn_chain_hop_t *hops, size_t hop_count,
                                           const uint8_t root[FZN_PUBKEY_LEN],
                                           const fzn_sign_ops_t *sign);

/* WHICH LINKS OF A CHAIN ARE REVOKED, given as each hop's grantor and grantee
 * rather than as opened hops -- for a caller that kept a chain's shape and
 * not its bytes, as the roster does. The same rule as
 * `fzn_revocation_covers_chain`, which is this applied to a chain's hops:
 * one implementation, so the two cannot disagree. */
/*
 * WHAT A REVOKED KEY DID THAT STILL STANDS. sec 496, the holder's direction of
 * 2026-10-07: a device stolen and later found is either restored -- its votes
 * withdrawn, and then everything it did counts again, since nothing here is
 * ever deleted -- or re-keyed, and then what it did after it left its owner's
 * hands has to be removable while what it did before stays.
 *
 * `fzn_revocation_act_stands` answers for hop `i` of a chain given by its
 * links, as `fzn_revocation_covers_links` takes one: 1 when that hop is not
 * revoked, or when it is and the act whose hash is `act`, signed by
 * `grantees[i]`, stands in the store's act log under the cut of every vote
 * that holds the revocation. 0 with no act log, for an all-zero cut, for a
 * corrupt store, and for a question with no subject.
 *
 * `fzn_revocation_store_set_acts` sets the log, or NULL for none; MALFORMED
 * for one with no `stands`.
 */
fzn_chain_err_t fzn_revocation_store_set_acts(fzn_revocation_store_t *store,
                                              const fzn_act_log_ops_t *acts);

int fzn_revocation_act_stands(const fzn_revocation_store_t *store,
                              const uint8_t (*grantors)[FZN_PUBKEY_LEN],
                              const uint8_t (*grantees)[FZN_PUBKEY_LEN], size_t hop_count,
                              const fzn_cap_id_t *capability, size_t i,
                              const uint8_t act[FZN_REVOCATION_ID_LEN]);

void fzn_revocation_covers_links(const fzn_revocation_store_t *store,
                                 const uint8_t (*grantors)[FZN_PUBKEY_LEN],
                                 const uint8_t (*grantees)[FZN_PUBKEY_LEN], size_t hop_count,
                                 const fzn_cap_id_t *capability,
                                 uint8_t revoked[FZN_CHAIN_MAX_HOPS]);

/* THE EPOCH A NEW VOTE ON (capability, grantee) BELONGS IN: the lowest this
 * store holds open, counting every issuer it has admitted for the pair and
 * its own quorum, and past any epoch `root` has undone (sec 403; NULL for no
 * root). 0 for a pair it holds nothing on. A withdrawal does not ask this --
 * it carries the epoch of the revocation it undoes. sec 400. */
uint64_t fzn_revocation_current_epoch(const fzn_revocation_store_t *store,
                                      const uint8_t root[FZN_PUBKEY_LEN],
                                      const fzn_cap_id_t *capability,
                                      const uint8_t grantee[FZN_PUBKEY_LEN]);

/*
 * Give this store somewhere to say what happened, or NULL to silence it.
 *
 * sec 211. What it knows and no return value carries: that it is FULL, which
 * here is worse than anywhere else in the library because this store never
 * evicts -- a revocation does not expire, so no slot is ever reclaimable and
 * a full store refuses every withdrawal from then on. A caller reading
 * FZN_CHAIN_ERR_STORE_FULL learns that one admission failed; what it needs to
 * know is that the host has stopped being able to learn about revocations at
 * all.
 *
 * Subsystem `chain/revocation`. The log is borrowed and must outlive the
 * store.
 */
void fzn_revocation_store_set_log(fzn_revocation_store_t *store, struct flog_t *log);

/* The manifest state, DECLARED here and DEFINED in manifest.h.
 *
 * Admitting a revocation settles a deficit: what a manifest said this host
 * was missing, it now holds. So `fzn_revocation_admit` needs the NAME of that
 * table -- and nothing more than the name, because the only thing it does
 * with one is hand it to `fzn_manifest_satisfy`.
 *
 * The same arrangement `chain.h` uses for `fzn_revocation_store_t`, and the
 * incomplete type is the point rather than a compromise: a module that cannot
 * see a table's fields cannot grow a second copy of the rule for finding an
 * entry in it, which is what `chain.h` records a heap overflow for. */
typedef struct fzn_manifest_state fzn_manifest_state_t;

/* A REVOCATION AS IT IS OFFERED TO A STORE: the record, plus the standing of
 * whoever signed it.
 *
 * The root needs no standing -- it is the pin, and `hop_count == 0` says so.
 * Anybody else has to show the chain that makes them an ancestor of what
 * they are withdrawing, and `hops` is that chain, OPENED, exactly as
 * `fzn_chain_verify` takes one.
 *
 * WHY A STRUCT RATHER THAN TWO MORE PARAMETERS. `fzn_revocation_merge`
 * absorbs a BATCH, which is what "carried on contact" looks like, and a
 * batch whose members may each carry a different chain cannot be an array of
 * records with one chain beside it. The two halves travel together because
 * they only mean anything together -- the same argument that made
 * `fzn_chain_verify` take a store rather than an array and a count.
 *
 * `hop_count == 0` IS ROOT-ISSUED AND REPRODUCES THE OLD BEHAVIOUR EXACTLY:
 * the issuer is compared against the pinned root and nothing else is
 * consulted, which is every admission this library performed before
 * 2026-08-28. `hops` is then ignored and NULL is the honest spelling. */
typedef struct fzn_revocation_offer {
	fzn_revocation_record_t record;
	const fzn_chain_hop_t *hops;
	size_t hop_count;
} fzn_revocation_offer_t;

/* The two spellings of an offer, so that no caller assembles one field by
 * field and leaves the other holding whatever its stack held. An offer with
 * a stale `hops` and a zero `hop_count` is harmless; the reverse is a read
 * through a pointer nobody set. */
static inline fzn_revocation_offer_t fzn_revocation_offer_root(fzn_revocation_record_t record)
{
	fzn_revocation_offer_t offer;

	offer.record = record;
	offer.hops = NULL;
	offer.hop_count = 0;
	return offer;
}

static inline fzn_revocation_offer_t fzn_revocation_offer_chain(fzn_revocation_record_t record,
                                                                const fzn_chain_hop_t *hops,
                                                                size_t hop_count)
{
	fzn_revocation_offer_t offer;

	offer.record = record;
	offer.hops = hops;
	offer.hop_count = hop_count;
	return offer;
}

/* Verify a revocation and record it. Returns FZN_CHAIN_OK if it is now in the
 * store, including when it was already there -- admitting the same
 * revocation twice is what happens every time two peers both tell you, and
 * it is not an error.
 *
 * WHO MAY SPEND THE STORE, AND IT IS NOT AN AUTHORISATION DECISION.
 * project.md sec 13c is the design and its reframing is what decides the
 * shape: the old root check did two jobs, and only one of them was
 * authorisation. What is honoured is decided by `fzn_revocation_covers_chain`
 * at verification time; the worst a wrongly-admitted entry can do is occupy
 * 96 bytes of a table that never evicts and never expires. So this is an
 * ADMISSION BOUND, it is allowed to be coarse, and it must not try to be
 * verify.
 *
 * The bound: a non-root revocation is admitted exactly when its issuer
 * presents a chain that verifies against the pinned root FOR THE CAPABILITY
 * BEING WITHDRAWN, whose last hop's grantee is that issuer, and whose last
 * hop is `delegable`. Put sharply -- admit a revocation from a key if and
 * only if `fzn_chain_delegate` would let that key GRANT the thing it is
 * withdrawing. Revoking a descendant is the inverse of granting one and
 * takes the same standing.
 *
 * `delegable` IS NOT DECORATION. A key can only be an ancestor if it appears
 * as some hop's grantor, and `fzn_chain_verify` refuses any such hop whose
 * predecessor was not `delegable`. So a non-delegable holder can never be an
 * ancestor, its revocations can never be honoured, and admitting them is
 * pure waste -- which excludes every leaf in an estate, most keys, from
 * spending the store. The depth ceiling is the same argument: a chain
 * already at FZN_CHAIN_MAX_HOPS has no room for the hop that would make its
 * grantee somebody's ancestor, which is exactly why `fzn_chain_delegate`
 * refuses to extend one.
 *
 * THREE INVARIANTS, EACH CHEAP TO BREAK BY ACCIDENT AND INVISIBLE WHEN
 * BROKEN. All three exist to keep this a CRDT -- project.md sec 13b records
 * that a standalone revocation carries no sequence, that revocation is
 * monotone, and that merge is set union, so any number of holders of one
 * replicated key may emit concurrently and every host converges. Order
 * dependence anywhere in admission destroys that.
 *
 *   - ADMISSION IS REVOCATION-BLIND. The issuer's chain is verified with no
 *     revocations at all. Otherwise admitting the root's withdrawal from H1
 *     first would make H1's own earlier revocation inadmissible, and what a
 *     store ends up holding would depend on the order two peers happened to
 *     tell you things.
 *   - ADMISSION IS CLOCK-BLIND. There is no `now` parameter to pass wrongly.
 *     Refusing a revocation because the REVOKER'S OWN grant had lapsed would
 *     silently re-connect a revoked device, which is the one direction this
 *     module must never fail in.
 *   - THE STORE IS NOT A CACHE. "This issuer already has an entry, so skip
 *     the chain check" looks free and makes the outcome order-dependent.
 *     Every non-root admission carries its chain, every time, including one
 *     that turns out to be a duplicate.
 *
 * AND ONE SEMANTIC, SETTLED IN SEC 13C RATHER THAN DECIDED HERE: when the
 * revoking grantor is itself later revoked, ITS REVOCATION STANDS. If it
 * fell, adding an entry to a store would REMOVE a derivable fact, and an
 * attacker could arrange it -- steal a host, delegate onward, get caught,
 * and the root's clean-up revocation of the parent would RESCUE the stolen
 * descendant. A grant's validity is continuously re-evaluated; a revocation
 * is a withdrawal already performed, by a party entitled at the time, and
 * nothing re-evaluates it. Recovery is by re-granting AROUND the revoker --
 * the entry bites only chains in which that grantor appears -- and never by
 * un-revoking.
 *
 * WHAT IS STORED COMES OUT OF THE BYTES THE SIGNATURE COVERED, which is the
 * 2026-08-27 change stated as a property. The previous version verified a
 * region and then stored fields that had never been compared with it, so a
 * genuine root-signed record could be replayed naming any grantee an
 * attacker liked -- permanently, since nothing here evicts or expires.
 *
 * A FULL STORE IS THE DANGEROUS CASE, AND IT IS THE OPPOSITE OF THE REPLAY
 * WINDOW'S. frame/freshness.h refuses when full and that FAILS CLOSED: the
 * worst outcome is a legitimate frame rejected. Here, failing to record a
 * revocation FAILS OPEN -- the host goes on accepting a capability that was
 * withdrawn, which is precisely the stolen device sec 4.2 exists to shut
 * out, and it does so silently unless somebody is watching.
 *
 * Three consequences, and they are the whole reason this comment is long:
 *
 *   - FZN_CHAIN_ERR_STORE_FULL is not a condition to retry or ignore. A consumer
 *     that logs it at debug level has built the failure it was avoiding.
 *   - Revocations are NOT expired or evicted to make room. A revocation
 *     that lapses un-revokes a device; there is no safe eviction policy,
 *     because every entry is protecting against something.
 *   - The store therefore has to be sized for the whole revocation history
 *     a deployment will ever have, not for a working set. That is a real
 *     cost and it is stated here rather than discovered: revocations only
 *     accumulate, so this is the one bound in the library that a long-lived
 *     deployment can grow into. project.md sec 14 carries it as open.
 *
 * `manifest` IS OPTIONAL AND NULL PRESERVES THE OLD BEHAVIOUR EXACTLY. When
 * one is passed, a revocation that lands in the store also drops the matching
 * pair from that state's deficit table -- the host was told it was missing
 * this and now is not. Without it the deficit never drains, so every consumer
 * that follows a manifest wants to pass one; the parameter is optional rather
 * than required because `chain/manifest.h` is stage 1 of project.md sec 13d
 * and a consumer that has not adopted it must not be forced to.
 *
 * DRAINING HAPPENS ON THE ALREADY-HELD PATH TOO. Admitting a revocation a
 * second time returns FZN_CHAIN_OK without storing anything, which is what
 * "carried on contact" looks like every time it works -- and if only the
 * storing path drained, a host that received the revocation before the
 * manifest would keep reporting it as missing for ever, having held it all
 * along. The two orders must converge, because a set is what this is. */
/* `hash` computes a record's IDENTITY -- FZN_REVOCATION_ID_LEN bytes over
 * the whole FZN_REVOCATION_LEN record -- and admission cannot work without
 * it, which is why it is an argument rather than something a caller may
 * leave out. Three questions need it and all three are equality tests on 32
 * bytes: what a withdrawal targets, what a re-revocation supersedes, and
 * which arriving record is the stale copy of one already withdrawn.
 *
 * THE WHOLE RECORD RATHER THAN ITS SIGNED RANGE. What a peer holds and
 * relays is the whole record, so the identity that travels is the whole
 * record's -- and a peer cannot make two records with one identity by
 * varying only the signature, because the signature is deterministic over
 * bytes the rest of the identity already covers.
 *
 * ADMISSION IS WHERE THE CHAINING RULE IS ENFORCED and not in the minting
 * calls, which is the point of the split in `fzn_revocation_reissue`: a
 * caller that re-revokes with `fzn_revocation_issue` mints a zero
 * `supersedes`, and against a store holding a withdrawal for that triple
 * this refuses it with FZN_CHAIN_ERR_UNKNOWN_TARGET. The rule is a refusal
 * a consumer meets rather than a sentence it has to have read. */
fzn_chain_err_t fzn_revocation_admit(fzn_revocation_store_t *store,
                                fzn_revocation_offer_t offer,
                                const uint8_t root[FZN_PUBKEY_LEN],
                                const fzn_sign_ops_t *sign,
                                const fzn_hash_ops_t *hash,
                                fzn_manifest_state_t *manifest);

/* Absorb a batch, which is what "on contact" looks like. Returns the number
 * admitted and reports the first failure through *err, so a caller can tell
 * "your peer sent one bad record" from "my store is full" -- the first is
 * routine on a hostile network and the second is an alarm.
 *
 * Keeps going after a bad record rather than stopping: one forged entry in
 * a batch must not stop a host learning the genuine ones travelling with
 * it, which would make forging a record a way to suppress revocation.
 *
 * `manifest` is passed through to `fzn_revocation_admit` unchanged, and NULL
 * means what it means there. It is here rather than only on the single
 * admission because THIS is the call a batch arrives through: a merge that
 * could not settle a deficit would leave the drain wired to the path
 * consumers use least.
 *
 * IT TAKES OFFERS RATHER THAN RECORDS (2026-08-28), because each member of a
 * batch may be issued by a different key and so may need a different chain.
 * A batch of records with one chain beside it could only ever have carried
 * one issuer's, which is the old root-only world with extra parameters. */
size_t fzn_revocation_merge(fzn_revocation_store_t *store,
                             const fzn_revocation_offer_t *offers, size_t count,
                             const uint8_t root[FZN_PUBKEY_LEN], const fzn_sign_ops_t *sign,
                             const fzn_hash_ops_t *hash,
                             fzn_chain_err_t *err, fzn_manifest_state_t *manifest);

/* Whether `issuer` has withdrawn this capability from this key.
 *
 * IT ASKS WHO, AND IT DID NOT USED TO. This took no issuer and no root at
 * all, while `fzn_revocation_admit` verified a record's issuer and then
 * discarded it, so a store holding root B's revocation answered "revoked"
 * about root A's realm -- and `fzn_chain_verify` takes `root` and the
 * entries array as independent parameters with nothing comparing them.
 * Confirmed by running it: B signs a revocation, it is admitted against B's
 * own root, and the query returned 1 with no root in it. Nothing said a
 * store belonged to one root and the old signature actively invited the
 * mistake by not asking. chain.h records why the issuer is kept per entry
 * rather than the store being bound to a root.
 *
 * THREE ANSWERS, AND THE ORDER THEY ARE DECIDED IN IS PART OF THE CONTRACT:
 *
 *   - A NULL store answers 0. It means "this host knows of no revocations",
 *     which is what `fzn_chain_verify` relies on when a consumer holding no
 *     store passes NULL.
 *   - A CORRUPT store answers 1 -- `used` past `capacity`, or a nonzero
 *     `used` with no array. Entries that cannot be scanned may hold the
 *     answer, and denying is the safe reply to an authorization question.
 *     Decided BEFORE anything else, so nothing gets a "no" out of a store
 *     that cannot be read.
 *   - A missing issuer, capability or grantee answers 0, because the
 *     question has no subject rather than because the answer is permissive.
 *     revocation.c argues that at length and records the alternative.
 *
 * This is a QUERY and not a verification: everything in the store was
 * checked on admission.
 *
 * IT ANSWERS ABOUT ONE GRANTEE, AND A CHAIN IS NOT ONE GRANTEE.
 * `fzn_revocation_covers_chain` below takes the hops and writes a verdict
 * PER HOP, which is the question a caller holding a chain is actually
 * asking. Reaching for this one on a chain's final grantee tests the last
 * hop and misses a revoked intermediate -- and it returns a confident 0
 * while doing it, because the grantee it was asked about really is not
 * revoked.
 *
 * `fzn_chain_verify` uses the per-hop form, so a consumer that verifies
 * through it is already right. This matters for a consumer doing its own
 * walk, which is the case that has no compiler to help it.
 *
 * The pointer used to run only the other way -- the sibling names this
 * function and this one did not name the sibling -- which is the wrong
 * direction for the pair: **the weaker call is the one a reader arrives at
 * first and the one that has to say what it does not cover.** Found by
 * sweeping every public function here whose name is a prefix of another's,
 * after the same shape turned up twice in one day elsewhere. */
/* Whether this store holds ANY record for this triple, revocation or
 * withdrawal. The replication question, as against
 * `fzn_revocation_covers`'s authorization one -- see revocation.c for why
 * they must not be confused and what confusing them costs. */
/* What this store holds about a triple: 1 and the outputs filled if it holds
 * anything, 0 otherwise.
 *
 * THE THIRD PREDICATE, and it exists because comparing two hosts' views of a
 * pair needs more than a yes. `fzn_revocation_covers` answers authorization,
 * `fzn_revocation_known` answers "must I still fetch this", and this one
 * answers "what exactly do I have", which is what a manifest comparison
 * requires: same record and same state is agreement, same record and a
 * withdrawal on their side means I am behind, and a different record means
 * neither of us can tell who is ahead from the hashes alone.
 *
 * All three go through one matching rule -- see revocation.c -- so there is
 * still one definition of "same triple". A store it cannot scan answers 0
 * and fills nothing; a caller comparing views must judge that separately,
 * which `chain/manifest.c` does through `store_sound` before it asks. */
int fzn_revocation_lookup(const fzn_revocation_store_t *store,
                           const uint8_t issuer[FZN_PUBKEY_LEN],
                           const fzn_cap_id_t *capability,
                           const uint8_t grantee[FZN_PUBKEY_LEN],
                           uint8_t id_out[FZN_REVOCATION_ID_LEN], int *withdrawn_out);

int fzn_revocation_known(const fzn_revocation_store_t *store,
                          const uint8_t issuer[FZN_PUBKEY_LEN],
                          const fzn_cap_id_t *capability,
                          const uint8_t grantee[FZN_PUBKEY_LEN]);

/* Whether this store can be scanned at all. Non-zero when it can.
 *
 * ASKED BY CONSUMERS, WHO HAD NO WAY TO ASK. project.md sec 183. Every
 * predicate here fails CLOSED on a store it cannot read -- which is right,
 * and which means none of them can be used to identify one: a caller cannot
 * tell "this store is corrupt" from the answer it would have got anyway.
 * `gui/revocation_view` had to open-code the test
 * to bound their own walks, which is a third and fourth copy of a rule this
 * library already held twice.
 *
 * WHAT IT MEANS: `used` does not exceed the array, and there is an array when
 * `used` says there are entries. That is the same condition the internal
 * guards have always used, and they call this now.
 *
 * A NULL STORE IS SOUND, and that is `chain/manifest.c`'s long-standing
 * answer rather than a new choice -- "no store means no revocations known,
 * which is an answer". A caller that wants to tell an ABSENT store from an
 * UNREADABLE one checks the pointer, which it already holds; collapsing those
 * two is the fail-open reading and this predicate does not invite it.
 *
 * IT IS NOT A NULL CHECK. Walking a store this returns non-zero for is safe
 * only if the pointer is not NULL, so the order is: pointer, then this, then
 * the walk. */
int fzn_revocation_store_sound(const fzn_revocation_store_t *store);

/*
 * This store's generation: a number that CHANGES whenever an answer might.
 *
 * It exists for `chain/memo.h`, which caches a chain verdict and must be able
 * to tell that a revocation has landed since. A cache cannot watch a store,
 * and asking "has anything changed" of a structure with no version is the
 * question that has no cheap answer -- so the store counts its own writes and
 * a cache compares two numbers.
 *
 * IT IS BUMPED ON WRITES, NOT ON CALLS. An `admit` that refuses a duplicate
 * changes nothing a lookup can see, and bumping there would throw a cache
 * away for every retransmission on a lossy link -- which is the traffic the
 * cache exists to survive. What bumps it is a slot being appended or an entry
 * being marked withdrawn.
 *
 * IT STARTS AT ONE, so that a memo entry left zero by `memset` can never
 * match a live generation. A cache whose "never recorded" and "recorded at
 * generation 0" are the same value is a cache that answers from a slot nobody
 * wrote.
 *
 * It never wraps in any life this library will see: one bump per write, and a
 * store that accepted one revocation per nanosecond for six hundred years
 * would still be short of 2^64.
 */
uint64_t fzn_revocation_generation(const fzn_revocation_store_t *store);

int fzn_revocation_covers(const fzn_revocation_store_t *store,
                           const uint8_t issuer[FZN_PUBKEY_LEN],
                           const fzn_cap_id_t *capability,
                           const uint8_t grantee[FZN_PUBKEY_LEN]);

/* WHICH HOPS OF THIS CHAIN ARE REVOKED, by an issuer entitled to revoke
 * them. `revoked` receives FZN_CHAIN_MAX_HOPS bytes, one per hop position,
 * 1 where that hop's grant has been withdrawn and 0 where it has not;
 * positions at or past `hop_count` are always 0.
 *
 * THE ENTITLED SET IS DERIVED, NOT ACCEPTED, and that is the whole reason
 * this takes a chain rather than an issuer. The issuers entitled to revoke
 * hop `i` are the root and hop `i`'s ancestors IN THIS CHAIN -- exactly
 * `{fzn_hop_grantor(hops[j]) : j <= i}`, which includes the root because
 * `fzn_chain_verify` has pinned `hops[0]`'s grantor to it. There is no
 * parameter through which a caller could name a wrong set, because there is
 * no parameter: project.md sec 13b calls this derive-don't-accept applied to
 * the thing that actually varies.
 *
 * IT IS WRITTEN HOISTED, and the naive form is the obvious one. Asking, per
 * hop, about every ancestor of that hop is O(hops^2) queries and each query
 * scans the store, which is O(hops^2 * R) for a table project.md sec 14
 * says only grows. Turned inside out it is O(R * hops): each entry names one
 * issuer, so find the SMALLEST `j` whose grantor is that issuer and the
 * entry applies to every hop from `j` onward. One pass over the store, two
 * bounded walks of the chain inside it -- the same cost the single-issuer
 * loop already paid.
 *
 * THE THREE ANSWERS ARE `fzn_revocation_covers`' THREE ANSWERS, decided in
 * the same order and for the same reasons, because it is the same store
 * being read for the same kind of question:
 *
 *   - A NULL store revokes nothing. It means "this host knows of no
 *     revocations", which is what `fzn_chain_verify` relies on when a
 *     consumer holding no store passes NULL.
 *   - A CORRUPT store revokes EVERY hop -- `used` past `capacity`, or a
 *     nonzero `used` with no array. Entries that cannot be scanned may hold
 *     the answer, and denying is the safe reply to an authorization
 *     question. Decided before anything else.
 *   - A missing `hops` or `capability`, a zero `hop_count`, or one past
 *     FZN_CHAIN_MAX_HOPS revokes nothing, because the question has no
 *     subject rather than because the answer is permissive. `revocation.c`
 *     argues that at length for the sibling function.
 *
 * A NULL `revoked` is the one argument with nothing to say: there is
 * nowhere to write an answer, so it writes none. */
void fzn_revocation_covers_chain(const fzn_revocation_store_t *store,
                                  const fzn_chain_hop_t *hops, size_t hop_count,
                                  const fzn_cap_id_t *capability,
                                  uint8_t revoked[FZN_CHAIN_MAX_HOPS]);

#endif /* FZN_REVOCATION_H */
