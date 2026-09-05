#ifndef FZN_LEDGER_H
#define FZN_LEDGER_H

/*
 * What each peer has confirmed holding, per subject.
 *
 * The mirror of `record/journal.h` and the third question in that file's
 * pair. It keeps "what I received" and "what I applied" apart because every
 * distributed configuration bug lives in the gap between them; this is the
 * one it does not ask -- WHAT SOMEBODY ELSE HAS. A journal is indexed by who
 * WROTE a record. A ledger is indexed by who has ACKNOWLEDGED one.
 *
 * WHY IT IS HERE, and the provenance is the argument. fuzzypickles built this
 * twice -- once in a manifest path and once in a config-sync path -- and
 * `core/src/delivery_internal.h` records that they were extracted into one
 * only "once both had been built and shipped, rather than designed up front",
 * because "the two independent implementations agreed on more than expected,
 * which is what makes this worth sharing rather than a coincidence being
 * enshrined". It serves four scopes there now. That is what
 * `harmonization.md` asks for before anything is shared: real use across
 * several consumers rather than one bespoke thing designed on speculation.
 *
 * IT IS NOT THEIR CODE AND IT IS NOT A LIFT. Theirs takes a storage vtable
 * and addresses rows by a formatted string key; every table in this library
 * is a caller-owned array of fixed-width structs, and `persist/` is a
 * separate concern reached deliberately rather than a parameter every call
 * carries. What travelled is the shape and the argument, which is the half
 * that was worth travelling. project.md sec 98 has the measurement.
 *
 * WHAT STAYS WITH THE CONSUMER, because fuzzypickles found these differ
 * between two consumers in one tree and this library has no better claim:
 *
 *   - What a SUBJECT is. Thirty-two opaque bytes here, never interpreted. A
 *     consumer with one document per peer uses all-zero and one version says
 *     everything; a consumer with many settings hashes the setting name, and
 *     a host may be current on one and behind on another. Collapsing that
 *     into one number per peer "would be a lie in whichever direction was
 *     convenient" -- their words, and the reason `subject` is not optional.
 *   - The recipient set. Who is owed a copy is policy, and policy is not
 *     this library's.
 *   - What a VERSION counts, and what confirming means. A sequence, a
 *     generation, a document revision; this compares them and never
 *     produces one.
 *
 * NOTHING HERE SENDS OR ASKS. It is a table with an answer, in the shape of
 * `fzn_state_t` and `fzn_journal_t`. The planning calls elsewhere --
 * `fzn_sync_plan_offer`, `fzn_manifest_plan_offer` -- decide what to do
 * about a peer that is behind, and a consumer transmits.
 */

#include "record.h"

#include <stddef.h>
#include <stdint.h>

typedef enum fzn_ledger_err {
	FZN_LEDGER_OK = 0,
	FZN_LEDGER_ERR_MALFORMED = -1,
	FZN_LEDGER_ERR_FULL = -2,
	/* A confirmation that moves backwards. Reported rather than absorbed:
	 * see `fzn_ledger_confirm`, where the reordering it means is a fact
	 * about the network a caller may want. */
	FZN_LEDGER_ERR_STALE = -3,
} fzn_ledger_err_t;

typedef struct fzn_ledger_entry {
	uint8_t peer[FZN_PUBKEY_LEN];
	uint8_t subject[FZN_SUBJECT_LEN];
	/* The consumer's namespace, so two of them sharing one table cannot
	 * collide -- `record/record.h`'s FZN_STREAM_RESERVED divides this
	 * library's half from a consumer's and the same discipline applies.
	 * fuzzypickles spells it as a scope string; here it is an integer for
	 * the reason every key in this library is. */
	uint32_t kind;
	uint64_t version;
} fzn_ledger_entry_t;

typedef struct fzn_ledger {
	fzn_ledger_entry_t *entries;
	size_t capacity;
	size_t used;
} fzn_ledger_t;

/* Point `ledger` at caller-owned entries, and zero them.
 *
 * A zero capacity is refused rather than accepted as an empty ledger, which
 * is `fzn_journal_init`'s rule: a table that can hold nothing records
 * nothing and reports success while doing it. The array is zeroed, which
 * project.md sec 39 settled for this family. */
fzn_ledger_err_t fzn_ledger_init(fzn_ledger_t *ledger, fzn_ledger_entry_t *entries,
                                 size_t capacity);

/*
 * Record that `peer` has confirmed holding `version` of this subject.
 *
 * A CONFIRMATION NEVER MOVES BACKWARDS, and the argument is not caution. An
 * acknowledgement that arrives late is reordering rather than retraction:
 * both numbers were real confirmations when they were sent, so the higher
 * one is the better evidence and keeping it is not over-claiming. A ledger
 * that took the latest arrival instead would forget a delivery because a
 * datagram overtook another.
 *
 * The stale one is REPORTED rather than silently dropped. A caller that
 * wanted to know its acknowledgements are arriving out of order can, and one
 * that does not may ignore FZN_LEDGER_ERR_STALE -- the table is identical
 * either way. `record/journal.h` reports FZN_JOURNAL_ERR_GAP for the same
 * reason: a condition a distribution layer acts on is not an error to
 * paper over.
 *
 * A version of zero is refused. Zero is what an absent row answers, so
 * storing it would make "confirmed nothing" and "never heard of" the same
 * state, and the second must stay distinguishable.
 */
fzn_ledger_err_t fzn_ledger_confirm(fzn_ledger_t *ledger, const uint8_t peer[FZN_PUBKEY_LEN],
                                    const uint8_t subject[FZN_SUBJECT_LEN], uint32_t kind,
                                    uint64_t version);

/* The highest version this peer has confirmed for this subject, or zero.
 *
 * ZERO FOR AN UNKNOWN PEER, AND THAT IS THE SAFE DIRECTION. Under-claiming
 * costs a retransmission; over-claiming skips something a peer needs and is
 * indistinguishable from delivery. A ledger that cannot be scanned answers
 * zero for the same reason -- see `fzn_ledger_behind`. */
uint64_t fzn_ledger_confirmed(const fzn_ledger_t *ledger, const uint8_t peer[FZN_PUBKEY_LEN],
                              const uint8_t subject[FZN_SUBJECT_LEN], uint32_t kind);

/* Whether this peer is behind `current` for this subject.
 *
 * Non-zero when it is, which includes a peer never heard from, a subject
 * never sent, and a ledger too corrupt to scan. Every one of those resolves
 * to "send it again", which is the answer that costs bytes rather than
 * correctness -- the opposite polarity to `fzn_revocation_covers`, and for
 * the opposite reason: there an unreadable store must not silently
 * authorise, here it must not silently withhold. */
int fzn_ledger_behind(const fzn_ledger_t *ledger, const uint8_t peer[FZN_PUBKEY_LEN],
                      const uint8_t subject[FZN_SUBJECT_LEN], uint32_t kind, uint64_t current);

/* How many rows are held. Zero for a ledger that cannot be scanned, which is
 * `fzn_state_count`'s answer and for its reason: a count from a corrupt
 * table is invented rather than measured. */
size_t fzn_ledger_count(const fzn_ledger_t *ledger);

/* A short name for `fzn_ledger_err_t`. Never NULL. */
const char *fzn_ledger_err_str(fzn_ledger_err_t err);

#endif /* FZN_LEDGER_H */
