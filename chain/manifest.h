/* The revocation manifest: what an issuer says it has withdrawn, and what
 * this host is therefore missing.
 *
 * project.md sec 13b states the defect. A revocation stops a chain only at a
 * host that HAS it -- `fzn_revocation_covers` consults a local array and
 * nothing else, and `fzn_chain_verify` accepts an empty store as readily as a
 * full one. So a host that joined fresh, was offline, or was partitioned
 * verifies a chain the rest of the network revoked last week, and CANNOT TELL
 * THAT IT MIGHT BE WRONG. sec 4.2 already had half the sentence: a full store
 * "says you may be missing revocations YOU WERE TOLD ABOUT". There was no
 * notion of one that exists and was never handed over.
 *
 * THIS IS STAGE 1 OF TWO, AND IT IS NOT A GATE. sec 13d splits the work
 * deliberately: stage 1 is the object, follow/admit, the deficit table and the
 * reporting calls, and `fzn_chain_verify` is untouched. Nothing here refuses a
 * chain, there is no UNKNOWN verdict, and no new refusal path exists. What it
 * delivers is the half of sec 13b's defect statement that needs no policy
 * decision: a host can finally SAY what it is missing. Stage 2 -- the gate
 * inside `fzn_chain_verify` -- waits on a question with the copyright holder
 * about which reading of sec 4.4a was meant, and sec 13d says so.
 *
 * A CONSUMER MUST THEREFORE NOT READ SILENCE AS SAFETY. A zero deficit from
 * this module means "nothing the manifests I hold names is missing", never
 * "up to date": the union grows only when somebody hands you a LARGER
 * manifest, and a peer handing you last year's leaves you complete against a
 * stale set for ever. sec 13d names that weakness rather than dressing it up,
 * and the naming is the whole defence -- the verdict is *complete against the
 * manifests held*.
 *
 * IT NAMES THE PAIR, AND THAT IS THE SETTLED CORRECTION (2026-08-27). sec 13b
 * first specified a hash of the (issuer, capability, grantee) triple as the
 * id, and sec 13d refuted it once the condition it turned on was answered:
 * manifests never cross an estate boundary, so the hash bought nothing and
 * cost a dependency edge in a module that includes `constant_time.h` and
 * `wire/bytes.h` and nothing else. Three things follow from naming the pair,
 * and they are why it is the better object rather than merely the cheaper
 * one:
 *
 *   - The completeness predicate IS `fzn_revocation_covers`, which is already
 *     written, already constant-time, already refuses a corrupt store, and is
 *     already mutation-tested. `chain.h` records this tree's own lesson --
 *     bought with a heap overflow on the authorization path -- that the
 *     repair is to stop having two predicates.
 *   - A deficit is readable by a human. "I lack I's withdrawal of C from G"
 *     is a thing somebody can act on; an opaque id is fetchable only if every
 *     peer indexes its revocations by id.
 *   - No hashing seam enters `chain/`.
 *
 * The cost is real and is stated rather than buried: a pair is 64 bytes where
 * a hash was 32, so the per-frame capacity HALVES. Fourteen pairs is 996
 * bytes and fits one frame; fifteen is 1060 and must go through `chunk/`.
 * The hash form fitted twenty-eight.
 *
 * THE CONDITION THAT WOULD REVERSE IT, recorded as the hinge rather than the
 * answer. fuzzypickles gave the answer that settled it -- a peer holds none
 * of their capabilities, so a contact is never a grantee and there is nothing
 * a revocation could withdraw from one. If they ever grant a capability to
 * another user's host, contacts become grantees and manifests cross. That is
 * a design decision at their end and not a property of this wire format, so
 * it is theirs to signal and ours to watch for.
 */

#ifndef FZN_MANIFEST_H
#define FZN_MANIFEST_H

#include "revocation.h"

/* THE MANIFEST LAYOUT. Big-endian, fixed width, no padding, fixed fields
 * first -- the same rules as the hop and the revocation, for the same reason.
 *
 *     offset  size  field
 *          0     1  version    (= FZN_SIGNED_VERSION)
 *          1     1  object     (= FZN_OBJECT_MANIFEST)
 *          2    32  issuer
 *         34     2  count      (n, pairs that follow)
 *         36  64*n  pairs      (capability[32] then grantee[32], each)
 *   36 + 64n    64  signature
 *
 * The signature covers bytes 0 through 35 + 64n -- the whole body, version
 * and object byte included. `wire/bytes.h` says why those two are inside the
 * signed range and why neither could be added later, and the manifest is the
 * object that makes its argument concrete: a one-pair manifest is 164 bytes
 * and so is a record with an 8-byte body.
 *
 * THERE IS NO `issued_at`, AND THE ABSENCE IS DELIBERATE. `revocation.h`
 * carries the reasoning at length for the field it does have: a value that is
 * signed, free to read and load-bearing nowhere is one somebody makes
 * load-bearing, and nothing bounds a clock, so `UINT64_MAX` can never be
 * superseded by anything the issuer publishes afterwards. sec 13b found the
 * same shape independently and applied it here unprompted.
 *
 * Leaving it out also BUYS something, which is the rarer half. Without a
 * timestamp an issuer's manifest over a given set is a unique deterministic
 * byte string, so two replicated holders of one key -- which sec 13b's first
 * answer says is the normal case -- produce identical bytes from the same
 * view, and neither has to be told what the other did. */
#define FZN_MANIFEST_PAIR_LEN ((size_t)FZN_CAP_ID_LEN + (size_t)FZN_PUBKEY_LEN)
#define FZN_MANIFEST_HEADER_LEN 36u

#define FZN_MANIFEST_OFF_VERSION 0u
#define FZN_MANIFEST_OFF_OBJECT 1u
#define FZN_MANIFEST_OFF_ISSUER 2u
#define FZN_MANIFEST_OFF_COUNT 34u
#define FZN_MANIFEST_OFF_PAIRS FZN_MANIFEST_HEADER_LEN

/* What the signature covers, and the whole encoding, for `n` pairs. */
#define FZN_MANIFEST_BODY_LEN(pairs) \
	((size_t)FZN_MANIFEST_HEADER_LEN + FZN_MANIFEST_PAIR_LEN * (size_t)(pairs))
#define FZN_MANIFEST_LEN(pairs) (FZN_MANIFEST_BODY_LEN(pairs) + (size_t)FZN_SIG_LEN)

/* The shortest manifest there is, which is a real statement rather than a
 * degenerate one: `count = 0` is what a key that has revoked nothing must be
 * able to say, and a mechanism in which that is inexpressible cannot
 * distinguish "I have revoked nothing" from "I am not talking to you". */
#define FZN_MANIFEST_MIN_LEN FZN_MANIFEST_LEN(0)

/* THE MOST PAIRS ONE MANIFEST MAY NAME, and it is arithmetic rather than
 * policy: a manifest that cannot be delivered whole cannot be verified at
 * all, since the signature covers every pair.
 *
 * The ceiling is the largest message this library will reassemble --
 * `chunk/split.h`'s FZN_SPLIT_MAX_PAYLOAD times `chunk/reassembly.h`'s
 * FZN_REASM_MAX_CHUNKS, which is 1024 * 256 = 262144 bytes. Fixed overhead is
 * 100 bytes, so (262144 - 100) / 64 = 4094 pairs, and 4095 would be 262180.
 *
 * THE NUMBER IS REPEATED HERE RATHER THAN INCLUDED, and the tether is a test.
 * `chain/` includes `constant_time.h` and `wire/bytes.h` and nothing else --
 * that independence is the reason sec 13d chose the pair over a hash in the
 * first place, and taking a `chunk/` include to spell one constant would
 * spend it. `chain/test/manifest_test.c` static-asserts this against both
 * `chunk/` constants, which is the same arrangement `chunk/split.h` uses for
 * FZN_SPLIT_MAX_PAYLOAD against the generated schema and
 * `record/test/record_test.c` for FZN_RECORD_MAX_LEN against the payload
 * ceiling. So the tether is `make test`, not `make`; if either `chunk/`
 * number moves, that assertion is what refuses the half-done change.
 *
 * A SINGLE FRAME HOLDS FOURTEEN, which is the number a consumer actually
 * feels. 100 + 64 * 14 = 996 and fits FZN_SPLIT_MAX_PAYLOAD; fifteen is 1060
 * and goes through `chunk/`. Since a manifest is a full-set statement re-sent
 * whole on every change -- sec 13d's "O(history) republication is forced, not
 * chosen", both escapes having died on the key being replicated -- an estate
 * past fourteen revocations is a chunked send per new revocation per
 * follower. That is the design's price and it is known, not discovered. */
#define FZN_MANIFEST_MAX_PAIRS 4094u
#define FZN_MANIFEST_MAX_LEN FZN_MANIFEST_LEN(FZN_MANIFEST_MAX_PAIRS)

/* ITS OWN ERROR TYPE, WHICH IS THE ONE PLACE THIS FILE DOES NOT MIRROR
 * `revocation.h`.
 *
 * A revocation returns `fzn_chain_err_t` because its failures are chain
 * failures: a revocation that will not admit is a fact `fzn_chain_verify`
 * would otherwise have honoured. A manifest's are not. Nothing here can
 * return WRONG_ROOT, EXPIRED, REVOKED or NOT_DELEGABLE, and two of the
 * conditions below -- an issuer nobody chose to follow, and a deficit table
 * with no room -- have no spelling in that enum at all. Adding them would
 * grow every consumer's switch over chain errors by codes chain verification
 * can never produce, which is the direction `chain.h` was renamed away from
 * when `fzn_err_t` became `fzn_chain_err_t`.
 *
 * Every other module in the tree carries its own; this is the convention
 * rather than an exception to it. */
typedef enum fzn_manifest_err {
	FZN_MANIFEST_OK = 0,
	/* The caller handed us something structurally impossible: a null
	 * pointer, a view that was never opened, a state or a store whose own
	 * fields disagree. Distinct from SHAPE because it means the caller has
	 * a bug, not that a peer sent something bad. */
	FZN_MANIFEST_ERR_MALFORMED = -1,
	/* These bytes are not a manifest: a wrong length, a version or object
	 * byte that is not ours, a count past FZN_MANIFEST_MAX_PAIRS, or pairs
	 * that are not strictly ascending. Ordinary hostile input, and a
	 * receiver that logged it as its own defect would be looking in the
	 * wrong place. */
	FZN_MANIFEST_ERR_SHAPE = -2,
	/* The signature does not verify under the issuer the record names --
	 * or, from `fzn_manifest_issue`, the signer refused to produce one. */
	FZN_MANIFEST_ERR_SIGNATURE = -3,
	/* A manifest from an issuer this host does not follow.
	 *
	 * Following is a decision, exactly as `fzn_journal_anchor` is, and for
	 * the reason `record/journal.h` gives: a stranger's first statement
	 * accepted implicitly lets one authorised key fill a table with
	 * issuers nobody chose, permanently, since there is no forget. */
	FZN_MANIFEST_ERR_UNKNOWN_ISSUER = -4,
	/* No room to follow another issuer. Refused rather than evicted, for
	 * the reason `record/journal.h` refuses a full journal: dropping an
	 * issuer forgets its deficit, and a forgotten deficit is a host that
	 * looks complete. */
	FZN_MANIFEST_ERR_FULL = -5,
	/* At least one pair could not be recorded because the deficit table is
	 * full. The rest of the manifest was still admitted, and the issuer's
	 * OVERFLOW FLAG IS NOW SET -- see `fzn_manifest_overflowed`, which is
	 * the durable half of this answer and the one that matters.
	 *
	 * Its own code because it is the refusal in this file that fails OPEN,
	 * which is the same distinction `FZN_CHAIN_ERR_STORE_FULL` carries in
	 * `chain.h`. A dropped pair does not make this host report a fault; it
	 * makes it report a SMALLER deficit than it has, which is to say it
	 * looks MORE complete than it is. */
	FZN_MANIFEST_ERR_DEFICIT_FULL = -6,
} fzn_manifest_err_t;

/* One (capability, grantee) pair: the authority an issuer says it withdrew.
 *
 * It names the AUTHORITY rather than the paper, which is sec 13c's finding
 * and is why no grant id appears: a hop-id revocation is escaped by
 * re-issuing the same grant, so one signature brings a stolen device back.
 * The coarse pair cannot be escaped that way. */
typedef struct fzn_manifest_pair {
	fzn_cap_id_t capability;
	uint8_t grantee[FZN_PUBKEY_LEN];
} fzn_manifest_pair_t;

/* A manifest as it travels.
 *
 * A VIEW over bytes the caller owns, exactly as `fzn_revocation_record_t` and
 * `fzn_chain_hop_t` are, and `len` travels with `base` for the reason
 * `fzn_record_t` carries one: a manifest is variable length, so a pointer
 * alone does not say where the signature is. `len` is what
 * `fzn_manifest_open` measured and agreed with the embedded count; it is not
 * a second copy of the count for the bytes to disagree with, because every
 * accessor reads the count from the bytes and open has already insisted the
 * two describe one buffer. */
typedef struct fzn_manifest_record {
	const uint8_t *base;
	size_t len;
} fzn_manifest_record_t;

/* Take a view over `len` bytes.
 *
 * Refuses, with FZN_MANIFEST_ERR_SHAPE: a length below FZN_MANIFEST_MIN_LEN,
 * a version byte that is not ours, an object byte that is not
 * FZN_OBJECT_MANIFEST, a count past FZN_MANIFEST_MAX_PAIRS, a length that is
 * not exactly FZN_MANIFEST_LEN(count), and pairs that are not STRICTLY
 * ASCENDING as 64-byte strings. Null arguments are
 * FZN_MANIFEST_ERR_MALFORMED, which is the caller's bug rather than a peer's
 * bytes.
 *
 * THE ORDER IS CANONICALITY, NOT TIDINESS, and it earns its place three
 * times over:
 *
 *   - ONE SET MUST HAVE ONE ENCODING or the determinism above evaporates.
 *     Two replicated holders of one key producing identical bytes is the
 *     property that makes concurrent publication free, and n! orderings of a
 *     set destroy it as thoroughly as a timestamp would.
 *   - A MANIFEST PADDED TO INFLATE ITS TRANSFER IS REFUSED. Duplicates are
 *     what a strict ordering excludes, and without it an issuer could name
 *     one pair four thousand times: a signed, well-formed, maximally
 *     expensive statement carrying one fact.
 *   - MERGING TWO MANIFESTS IS A MERGE-SORT rather than a quadratic scan,
 *     which is what makes the union sec 13b needs affordable.
 *
 * It does NOT verify anything. `fzn_manifest_admit` is the only thing that
 * checks a signature, and keeping them apart is what leaves the issuer a
 * property of the record rather than an argument of a parser. */
fzn_manifest_err_t fzn_manifest_open(const uint8_t *bytes, size_t len,
                                     fzn_manifest_record_t *out);

/* The accessors, over an OPENED record -- see chain.h's equivalent note. Each
 * reads the bytes the signature covers, so there is nothing for a decision to
 * be taken from except what was signed. */
static inline const uint8_t *fzn_manifest_issuer(fzn_manifest_record_t rec)
{
	return rec.base + FZN_MANIFEST_OFF_ISSUER;
}

static inline size_t fzn_manifest_count(fzn_manifest_record_t rec)
{
	return (size_t)fzn_get_be16(rec.base + FZN_MANIFEST_OFF_COUNT);
}

/* The `i`th pair's two halves. `i` must be below `fzn_manifest_count`, which
 * `fzn_manifest_open` has already related to the buffer's length. */
/* THE CAST THAT MAKES THE VIEW TYPED LIVES HERE, and this is the only kind
 * of place it appears. A capability on the wire is thirty-two bytes inside a
 * frame nobody may copy, so the accessor hands back a pointer to them under
 * the type they are -- alignment 1, so the cast is sound, and every caller is
 * then type-checked without ever writing one itself. */
static inline const fzn_cap_id_t *fzn_manifest_capability(fzn_manifest_record_t rec, size_t i)
{
	return (const fzn_cap_id_t *)(rec.base + FZN_MANIFEST_OFF_PAIRS +
	                              FZN_MANIFEST_PAIR_LEN * i);
}

/* Computed from the base rather than by offsetting the capability above:
 * that pointer is a `fzn_cap_id_t *` now, and adding a byte count to it
 * would need casting back out of the type this exists to keep. */
static inline const uint8_t *fzn_manifest_grantee(fzn_manifest_record_t rec, size_t i)
{
	return rec.base + FZN_MANIFEST_OFF_PAIRS + FZN_MANIFEST_PAIR_LEN * i +
	       FZN_CAP_ID_LEN;
}

static inline const uint8_t *fzn_manifest_signature(fzn_manifest_record_t rec)
{
	return rec.base + FZN_MANIFEST_BODY_LEN(fzn_manifest_count(rec));
}

/* The bytes this manifest's signature covers: the body, from the first byte.
 *
 * A function rather than two constants each caller applies for itself,
 * because the range is the one thing every field's integrity rests on and it
 * is worth stating exactly once. */
static inline void fzn_manifest_signed_bytes(fzn_manifest_record_t rec, const uint8_t **at,
                                             size_t *len)
{
	*at = rec.base;
	*len = FZN_MANIFEST_BODY_LEN(fzn_manifest_count(rec));
}

/* Lay out a manifest, unsigned. `out` receives FZN_MANIFEST_LEN(count) bytes
 * with the signature zeroed, and `*out_len` says how many. The only encoder
 * for this object, on the same argument `fzn_hop_encode` carries.
 *
 * IT REFUSES A PAIR SET THAT IS NOT STRICTLY ASCENDING, which is the encoder
 * half of the canonicality `fzn_manifest_open` insists on. An encoder that
 * would emit bytes its own parser refuses is a second encoding waiting to be
 * discovered by somebody else's decoder.
 *
 * FZN_MANIFEST_ERR_MALFORMED for a missing argument or an `out_cap` too
 * small; FZN_MANIFEST_ERR_SHAPE for a count past FZN_MANIFEST_MAX_PAIRS or
 * pairs out of order. On failure `*out_len` is untouched and `out` may hold
 * partial bytes. */
fzn_manifest_err_t fzn_manifest_encode(uint8_t *out, size_t out_cap,
                                       const uint8_t issuer[FZN_PUBKEY_LEN],
                                       const fzn_manifest_pair_t *pairs, size_t count,
                                       size_t *out_len);

/* Encode and sign this issuer's manifest, DERIVED FROM ITS OWN STORE.
 *
 * Every entry in `store` whose issuer is `issuer` becomes one pair, sorted
 * ascending; nothing else does. `store` may be NULL, which means this issuer
 * has revoked nothing and yields a `count = 0` manifest -- the statement a
 * key with a clean record must be able to make.
 *
 * THE STORE IS THE SOURCE, AND THAT IS THE POINT OF THE FUNCTION rather than
 * a convenience. sec 13d states the attack it closes: an entitled issuer can
 * name pairs it cannot satisfy and, once stage 2's gate exists, wedge every
 * chain it is entitled for -- permanently, and MORE CHEAPLY THAN REVOKING,
 * since naming a pair needs no valid revocation and revoking needs one. The
 * mitigation is exactly this signature: deriving the set from the issuer's
 * own store means an honest implementation cannot name a pair it does not
 * hold, so the attack costs a modified library rather than a call.
 *
 * A dishonest one still can, and nothing here pretends otherwise -- the pairs
 * are what the issuer signs, and a key that lies about its own withdrawals is
 * outside what any verifier can check. What this removes is the accident and
 * the cheap deliberate case.
 *
 * `issuer` is a PUBLIC key, used to fill the record's issuer field and to
 * select entries; whether the signer holds the matching secret is not a
 * question this can ask, exactly as in `fzn_chain_mint`.
 *
 * A CORRUPT STORE IS REFUSED WITH MALFORMED rather than treated as empty. An
 * unreadable store yields no pairs, and no pairs is a signed statement that
 * this key has revoked nothing -- the fail-open answer, published under the
 * issuer's own signature and indistinguishable from the truth at every
 * receiver.
 *
 * FZN_MANIFEST_ERR_SHAPE for a store holding more than FZN_MANIFEST_MAX_PAIRS
 * entries for THIS issuer, and FZN_MANIFEST_ERR_MALFORMED for an `out_cap`
 * that cannot hold them -- both judged against the store, which is a
 * different question from the one `fzn_manifest_open` answers about what a
 * peer sent. Neither is a number the caller passed, so a caller that sized
 * `out` for the estate as it was reaches the second by growing rather than by
 * mistake. On both, `*out_len` is untouched and `out` may hold partial
 * bytes. */
fzn_manifest_err_t fzn_manifest_issue(const uint8_t issuer[FZN_PUBKEY_LEN],
                                      const fzn_revocation_store_t *store,
                                      const fzn_sign_ops_t *sign, uint8_t *out, size_t out_cap,
                                      size_t *out_len);

/* One followed issuer, and what this host knows about its manifests. */
typedef struct fzn_manifest_issuer {
	uint8_t issuer[FZN_PUBKEY_LEN];
	/* The largest count any manifest admitted from this issuer has
	 * carried. See `fzn_manifest_admit` for what it defends. */
	size_t pairs_seen;
	/* Sticky: a pair this issuer named could not be recorded. Never
	 * cleared except by an admission that drops nothing and is not a
	 * rollback. */
	int overflowed;
} fzn_manifest_issuer_t;

/* One thing this host knows it is missing: a revocation an issuer says it
 * made and that the revocation store does not hold.
 *
 * The same three fields as `fzn_revocation_t`, and deliberately NOT that
 * type. They are opposite verdicts over one shape -- `fzn_revocation_t` is
 * something this host has decided to believe, and this is something it has
 * decided it lacks -- and a table of one handed to a function expecting the
 * other would compile, run, and answer every question backwards. */
typedef struct fzn_manifest_deficit {
	uint8_t issuer[FZN_PUBKEY_LEN];
	fzn_cap_id_t capability;
	uint8_t grantee[FZN_PUBKEY_LEN];
} fzn_manifest_deficit_t;

/* What this host has been told, over caller-owned storage.
 *
 * TWO TABLES, SIZED SEPARATELY, because they grow with different things. The
 * issuer table grows with how many keys this host has decided to follow,
 * which is a number a consumer chooses. The deficit table grows with the
 * DEFICIT rather than with the revocation history -- pairs already satisfied
 * are never recorded -- so it peaks at a fresh join and drains to zero as the
 * revocations arrive. sec 13b's worry that a manifest makes sec 14's
 * unbounded growth permanent applies to the design that stores the UNION, and
 * this one does not store it.
 *
 * The same shape as `fzn_revocation_store_t` and `fzn_journal_t`:
 * caller-owned arrays, a capacity and a count, no allocation, no I/O, no
 * clock.
 *
 * DECLARED IN `revocation.h` AND DEFINED HERE, which is the arrangement
 * `chain.h` already uses for the revocation store and for its reason. A
 * revocation admission may drop a pair from a deficit table, so
 * `fzn_revocation_admit` needs the NAME; nothing in that file may reach into
 * one, so it does not get the fields. The incomplete type is the point rather
 * than a compromise. */
struct fzn_manifest_state {
	fzn_manifest_issuer_t *issuers;
	size_t issuer_capacity;
	size_t issuer_used;
	fzn_manifest_deficit_t *deficit;
	size_t deficit_capacity;
	size_t deficit_used;
};

/* Point a state at caller-owned storage. Both arrays are required and both
 * capacities must be nonzero, for the reason `fzn_revocation_store_init`
 * refuses a zero capacity: a table that can hold nothing records nothing and
 * reports success while doing it. */
fzn_manifest_err_t fzn_manifest_init(fzn_manifest_state_t *state,
                                     fzn_manifest_issuer_t *issuers, size_t issuer_capacity,
                                     fzn_manifest_deficit_t *deficit, size_t deficit_capacity);

/* Start following an issuer's manifests, deliberately.
 *
 * MIRRORS `fzn_journal_anchor`, AND FOR ITS REASON. A new issuer's first
 * statement is a decision rather than a fact: adopting whoever signs
 * something lets one authorised key -- or anybody at all, since generating a
 * keypair is free -- fill this table with issuers nobody chose, and there is
 * no forget here either. `record/sync.h` makes the same refusal one layer up
 * and says why the two halves have to agree: it declined to ASK a stranger
 * for anything while a PUSHED record was adopted regardless, and the door it
 * guarded had a second one standing open beside it.
 *
 * FOLLOWING TWICE IS NOT AN ERROR and changes nothing -- notably not the
 * overflow flag, which a re-follow must never clear. A consumer that
 * re-follows on every reconnect is behaving correctly, and turning that into
 * a way to erase a fail-open marker would be the whole mechanism defeated by
 * its own housekeeping.
 *
 * FZN_MANIFEST_ERR_FULL when there is no room. sec 13d observes that this is
 * where `FZN_CHAIN_ERR_STORE_FULL`'s fail-open becomes something a consumer
 * can act on: the manifest is the number nobody had, and it arrives BEFORE
 * the revocations do, so a host can learn it is about to be under-sized while
 * it can still say so. */
fzn_manifest_err_t fzn_manifest_follow(fzn_manifest_state_t *state,
                                       const uint8_t issuer[FZN_PUBKEY_LEN]);

/* Verify a manifest and record what it says this host is missing.
 *
 * VERIFIED UNDER THE RECORD'S OWN ISSUER FIELD, never a caller-supplied key,
 * which is the property `revocation_test.c` had to record a verifier's key to
 * observe. A manifest is a key's statement about itself; verified under
 * anything else it stops being one.
 *
 * `store` is this host's revocation store and may be NULL, meaning "this host
 * knows of no revocations" -- the same contract `fzn_revocation_covers` and
 * `fzn_chain_verify` keep for NULL, and the fresh-joiner case, where every
 * pair named becomes a deficit.
 *
 * A CORRUPT STORE IS REFUSED HERE AND NOT BORROWED FROM
 * `fzn_revocation_covers`, which is `revocation.c`'s own lesson arriving a
 * second time. That function answers "is this revoked?" and says YES for a
 * store it cannot scan, deliberately, because denying is the safe reply to an
 * authorization question. Read as "we already hold this", the same 1 makes
 * every pair in every manifest look satisfied, the deficit table stays empty,
 * and the host reports itself complete -- the fail-open answer, produced by
 * the more conservative-looking check being asked the wrong question. A
 * conservative answer to one question is a wrong answer to another, and the
 * two have to check separately.
 *
 * The order, cheap refusals before the expensive one:
 *
 *   1. arguments, and the state's own integrity
 *   2. the issuer is followed -- refused whatever it is signed with, so a
 *      stranger cannot spend a verification
 *   3. the store's integrity, before its answers are believed
 *   4. the signature
 *   5. each pair: skip if `fzn_revocation_covers` says the store already
 *      holds it, skip if the deficit table already names it, else append
 *
 * IT KEEPS GOING PAST A PAIR IT CANNOT RECORD, on `fzn_revocation_merge`'s
 * rule: one unrecordable entry must not stop the others, or filling a table
 * becomes a way to suppress everything behind the pair that filled it. What
 * it does instead is set that issuer's OVERFLOW FLAG, and
 * FZN_MANIFEST_ERR_DEFICIT_FULL is returned once the whole manifest has been
 * walked.
 *
 * THE FLAG IS NOT OPTIONAL, and sec 13d says so twice. Without it a dropped
 * pair makes a host look MORE complete than it is -- a second silent
 * fail-open on top of the one this whole exercise exists to close, and the
 * design would then make storage strictly worse than it found it.
 *
 * CLEARING IT TAKES MORE THAN A QUIET ADMISSION, and this is where the
 * specification in sec 13d is incomplete rather than wrong. "Clears only when
 * every pair lands" is right as far as it goes and a REPLAYED OLDER MANIFEST
 * satisfies it: a manifest is monotone, so last year's names a subset, every
 * pair of that subset is already held or already in the table, nothing is
 * dropped, and the flag clears while the pairs that overflowed are still
 * missing. So clearing also requires the manifest to be at least as large as
 * the largest this issuer has presented -- `pairs_seen`, one word per
 * followed issuer. An honest issuer's count never shrinks, because
 * revocations only accumulate; a rollback is exactly a count that did. */
fzn_manifest_err_t fzn_manifest_admit(fzn_manifest_state_t *state,
                                      const fzn_revocation_store_t *store,
                                      fzn_manifest_record_t record,
                                      const fzn_sign_ops_t *sign);

/* Drop a pair from the deficit table: this host has now stored the
 * revocation, so it is no longer missing it.
 *
 * Called by `fzn_revocation_admit` when it records something, which is what
 * makes the table drain. It is here rather than reached into from there for
 * the reason `chain.h` gives about the store's incomplete type: nothing
 * outside this module may walk these tables, because reaching in is what lets
 * two copies of one rule drift apart.
 *
 * Returns the number of entries removed, which is 0 or 1 for a well-formed
 * table and is returned rather than ignored so a caller -- or a test -- can
 * tell "it was missing and now is not" from "it was never listed". A NULL
 * state or a missing operand removes nothing. */
size_t fzn_manifest_satisfy(fzn_manifest_state_t *state, const uint8_t issuer[FZN_PUBKEY_LEN],
                            const fzn_cap_id_t *capability,
                            const uint8_t grantee[FZN_PUBKEY_LEN]);

/* How many revocations this issuer says it made that this host does not hold.
 *
 * Zero for an issuer that is not followed, and THAT IS NOT A CLAIM OF
 * COMPLETENESS -- it is the absence of a question. Ask
 * `fzn_manifest_overflowed` before reading a zero as good news; sec 13d's
 * "UNKNOWN must gate or the design does not close its own defect" is about
 * exactly this asymmetry, and it is stage 2's to enforce. A union has a
 * property a sequence head does not: no manifest is an empty union is a zero
 * deficit, so a fresh joiner is COMPLETE by vacuity. A number's absence is
 * distinguishable from zero; a set's is not. */
size_t fzn_manifest_pending(const fzn_manifest_state_t *state,
                            const uint8_t issuer[FZN_PUBKEY_LEN]);

/* Is what this state says about `issuer` under-reported?
 *
 * Answers 1 when a pair from that issuer was dropped for want of room, and
 * ALSO for a NULL state, a state whose own fields disagree, and an issuer
 * that is not followed -- all of which are the same fact in different
 * clothes: this host cannot say what it is missing from that key.
 *
 * IT ANSWERS THE OPPOSITE WAY ROUND FROM `fzn_revocation_covers`, whose NULL
 * store answers 0, and the difference is which direction is safe. There, NULL
 * means "this host knows of no revocations", which is a true and complete
 * answer about a real thing. Here, an absent state means the deficit is
 * entirely unmeasured, and reporting an unmeasured deficit as sound is the
 * fail-open this module exists to remove. Nothing in stage 1 refuses anything
 * on this answer, so the conservative reply costs nothing today and is the
 * one stage 2 must be able to build on. */
int fzn_manifest_overflowed(const fzn_manifest_state_t *state,
                            const uint8_t issuer[FZN_PUBKEY_LEN]);

/* Copy out what this host is missing from `issuer`. Returns how many pairs
 * were written, and never more than `out_cap`.
 *
 * `dropped` receives the number that did not fit, and is REQUIRED -- passing
 * NULL writes nothing and returns 0. `record/sync.h` argues it for
 * `fzn_sync_digest` and the argument is the same one: an optional
 * out-parameter is one every caller ignores, and a deficit report that
 * quietly does not fit is a range nobody asks for again. The scan runs in
 * table order, so a host that overflows drops the same pairs every round and
 * never asks for them at all.
 *
 * **AND THAT IS WHY `fzn_manifest_deficit_from` EXISTS, WHICH THIS COMMENT
 * DESCRIBED THE HAZARD OF AND DID NOT NAME.** A deficit larger than `out_cap`
 * -- a frame holds about ten pairs and a returning host's is a year of them
 * -- comes back as the same prefix for ever, so the tail is never requested
 * and the host stalls on it. The resumable form below takes a cursor and
 * wraps; use it for anything that fetches. This call is the `from = 0` case
 * and is right for a report a human reads.
 *
 * Stating the hazard and not the remedy is the same shape as
 * `fzn_session_establish` not naming the ephemeral pair, found the same day
 * and one file over: **the obvious name describes its own inadequacy and
 * leaves the reader to discover that the fix is adjacent.**
 *
 * The order is the table's, which is the order the pairs were admitted in.
 * That is a fact about this host's history and not about the issuer's
 * manifest, and NOTHING SHOULD DEPEND ON IT -- the manifest's own order is
 * canonical and this one is not. It is stable within a run, which is what a
 * test needs. */
size_t fzn_manifest_deficit(const fzn_manifest_state_t *state,
                            const uint8_t issuer[FZN_PUBKEY_LEN], fzn_manifest_pair_t *out,
                            size_t out_cap, size_t *dropped);

/* The same report, RESUMABLE, which is what turns it into a fetch path.
 *
 * WHY THE PLAIN CALL IS NOT ENOUGH, and its own comment says so: "the scan
 * runs in table order, so a host that overflows drops the same pairs every
 * round and never asks for them at all". With a deficit larger than `out_cap`
 * -- a frame holds ten pairs, and a returning host's deficit is a year of
 * them -- the same prefix comes back for ever and the tail is never
 * requested. The host converges on the part it could already see and stalls
 * on the rest, which is project.md sec 47's shattered-estate case arriving
 * through the one function meant to answer it.
 *
 * `from` is a position in THIS issuer's run of the table, reduced modulo the
 * run's length, and the window wraps. `next` receives where to resume, so a
 * caller that passes back what it was given last time sweeps the whole
 * deficit in `ceil(total / out_cap)` calls and then repeats. That is the
 * property `record/sync.h` gets for free from a journal position advancing;
 * a deficit does not advance, it drains, so the cursor has to be explicit.
 *
 * THE CURSOR IS A HINT AND NOT A GUARANTEE. Entries leave the table as
 * revocations arrive, so positions shift under it, and a call after a drain
 * may repeat a pair or step over one. Both are harmless -- asking twice is
 * idempotent and the wrap catches what was stepped over on the next lap --
 * and saying so is cheaper than a stability promise this table cannot keep.
 * A caller wanting determinism passes `from = 0`, which is the plain call.
 *
 * `dropped` now reports every pair NOT written rather than only those past
 * the end of the scan, since with a wrap there is no end: it is the deficit
 * that did not fit this request, which is the number a caller sizing its next
 * one wants. For `from = 0` and a table that fits, both readings are zero.
 *
 * `next` may be NULL for a caller that does not resume. `dropped` may not,
 * for the reason above. */
size_t fzn_manifest_deficit_from(const fzn_manifest_state_t *state,
                                const uint8_t issuer[FZN_PUBKEY_LEN], size_t from,
                                fzn_manifest_pair_t *out, size_t out_cap, size_t *dropped,
                                size_t *next);

/* What a peer's request cost this host to answer, and what it could not.
 *
 * The same shape `record/sync.h` and `spool/plan.h` return, and for their
 * reason: a caller sizing its next message needs to know whether this one was
 * the whole answer. */
typedef struct fzn_manifest_offer {
	/* Wants this host holds a revocation for and can therefore serve. */
	size_t held;
	/* Wants actually looked at. Less than `want_count` when the ceiling
	 * clipped the request. */
	size_t examined;
	/* Set when the peer named more than `holds_cap` could answer. The
	 * unexamined tail is NOT reported as "not held", because that is a
	 * different answer and a peer would act on it. */
	int truncated;
} fzn_manifest_offer_t;

/* Which of a peer's missing revocations this host can serve.
 *
 * THE OTHER HALF OF `fzn_manifest_deficit_from`. That call turns this host's
 * deficit into a request; this one turns a peer's request into an answer, and
 * between them they are the fetch path project.md sec 47 names as the thing
 * both stage-2 options need and neither commits to. `record/` has had this
 * pair since it was written -- `fzn_sync_plan_fetch` and
 * `fzn_sync_plan_offer` -- and revocations had the first without the second.
 *
 * WHAT IT DOES NOT DO IS PRODUCE THE RECORDS, and it cannot. This store keeps
 * `{capability, grantee, issuer}` and discards the signed bytes on admission,
 * so a host holds the FACT of a revocation and not the evidence. The signed
 * record is the consumer's storage, exactly as `record/` leaves the records
 * to a consumer and plans only the ranges. So `holds[i]` says "look this one
 * up and send it", not "here it is".
 *
 * `holds` receives one byte per want examined: 1 where this host holds a
 * matching revocation, 0 where it does not. Parallel to `wants`, which is
 * `fzn_revocation_covers_chain`'s idiom for a per-item verdict rather than a
 * filtered copy -- a caller that wanted the triples already has them.
 *
 * THE THREE RULES `record/sync.h` ARGUES ARE KEPT, because a serve path is
 * where a stranger chooses the number:
 *
 *   - **A request naming nothing gets nothing.** `want_count` of zero is OK
 *     and answers zero, rather than being read as "send everything".
 *   - **A ceiling, because the peer picks `want_count`.** More wants than
 *     `holds_cap` are clipped to what fits and `truncated` says so.
 *   - **Zero is refused rather than meaning unlimited.** A `holds_cap` of
 *     zero is MALFORMED, not an invitation.
 *
 * AN UNSOUND STORE IS REFUSED RATHER THAN ANSWERED, on the argument
 * `store_sound` already makes in this module: `fzn_revocation_covers` answers
 * 1 for a store it cannot scan because denying is safe for an AUTHORIZATION
 * question, and that same 1 here would make this host promise to serve every
 * pair a peer named. The question is "do we hold this", so the polarity is
 * this module's and not `chain/`'s. */
fzn_manifest_err_t fzn_manifest_plan_offer(const fzn_revocation_store_t *store,
                                           const fzn_manifest_deficit_t *wants,
                                           size_t want_count, uint8_t *holds,
                                           size_t holds_cap,
                                           fzn_manifest_offer_t *plan);

/* A short name for `fzn_manifest_err_t`, for a log line or a message to a
 * user.
 *
 * NEVER NULL, including for a value that is not one of the enumerators, so
 * that a caller may pass the result straight to a printf without a check. An
 * unrecognised value renders as "unknown", which is deliberately not any real
 * code's text. */
const char *fzn_manifest_err_str(fzn_manifest_err_t err);

#endif /* FZN_MANIFEST_H */
