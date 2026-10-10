/* Where a host keeps its notes, and who may write them. sec 425, phase 3 of
 * the notes move.
 *
 * Ported from fuzzypickles' `notes_store` and `notes_admit` at b419405, with
 * their rules intact and their backend replaced: what was a key-value store
 * with load, store and exists is `persist/`'s seam here, which can also LIST
 * and REMOVE. That retires the hand-maintained index fuzzypickles' store
 * needed only because its backend could not enumerate -- an 8 KB blob read and
 * rewritten whole on every put, and one more thing a crash could leave
 * disagreeing with the records it named.
 *
 * WHAT IS STORED IS THE SIGNED RECORD, NOT THE DECODED NOTE. A host must
 * re-publish a node it cannot read: an older host meeting a content type a
 * newer one wrote carries it unchanged, or it deletes a newer host's notes on
 * every sync (`notes/note.h`). Re-encoding from a parsed struct cannot do
 * that, and the signature would not survive it. So this is a byte store, and
 * `notes/note.h` interprets a body once it has been read.
 *
 * KEYED BY CLAIM: (note id, writer). One writer's record about one note is a
 * claim, and `tree/tree.h` spells out why the key must be the pair: a store
 * keyed by note alone lets the second writer's claim overwrite the first,
 * which resolves by arrival order the reparenting conflict `tree/` refuses to
 * resolve. fuzzypickles shipped that, found it and fixed it, and this keeps
 * their fix. `persist/` keys by 32 bytes, so the pair is hashed to one under
 * a label of its own; `fzn_notes_get` then checks that what came back IS that
 * claim, since a hash is a promise about inputs and not about a backend.
 *
 * THE ADDRESS IS READ OUT OF THE RECORD, never taken beside it. fuzzypickles'
 * put took an id and an issuer alongside the bytes and had to refuse a caller
 * whose pair disagreed with the record -- two denials for a caller's bug.
 * Here there is no argument to disagree with, which is `record/store.h`'s
 * rule: a record cannot be filed under an address that is not its own.
 *
 * SUPERSESSION IS BY SEQUENCE WITHIN ONE CLAIM. A newer record from the same
 * writer replaces the one held; an older one, or the same one again, is
 * accepted and nothing is written -- a sender that is behind is not wrong,
 * and a retry landing on a host already current must be answerable or it
 * never terminates (fuzzypickles' config_sync paid for treating those two
 * alike). One writer, one sequence and two different records is
 * EQUIVOCATION and is refused: an honest writer cannot have signed both.
 *
 * ONE SEQUENCE PER HOST, NOT PER NOTE, on stream FZN_NOTE_STREAM. `record.h`
 * numbers a writer's records per stream, so a per-note version used as `seq`
 * would collide across notes in one stream. Since sec 517 a host's note
 * records are its journal's stream 0, chained, and the journal numbers them
 * (`notes/author.h`); the counter this kept is retired with its slot.
 *
 * SO THIS IS AN INDEX: each claim's latest record, which a view reads. The
 * note's history is the stream, and every record superseded here is still
 * there.
 */

#ifndef FZN_NOTES_STORE_H
#define FZN_NOTES_STORE_H

#include <stddef.h>
#include <stdint.h>

#include "note.h"
#include "../chain/chain.h"
#include "../persist/persist.h"
#include "../record/record.h"
#include "../session/commitment.h"

/* THE KIND A NOTE RECORD CARRIES: fuzzypickles' FZP_CMD_NOTES, kept. Their
 * hosts' notes are records already signed with it, and a different value here
 * would make every note a user holds today a record of some other kind to the
 * module that is replacing theirs. `record.h` leaves `kind` to whoever owns
 * the records; notes are fuzznet's now, so the value is too. */
#define FZN_NOTE_KIND 0x36u

/* THE STREAM every note record is on, for the reason above: one counter
 * across a host's notes, and a note's whole history on one stream, since
 * `record.h` records that moving a record between streams wedges the
 * receiving cell. Below FZN_STREAM_RESERVED, which is fuzznet's to assign,
 * and fuzzypickles' value. */
#define FZN_NOTE_STREAM 0u

/* THE KIND A PURGE RECORD CARRIES on the same stream, sec 519: "this note is
 * purged", about the note's id, written by the host that marked it. Above a
 * byte on purpose: fuzzypickles' command values double as record kinds and
 * fill 0x20 onward, and a kind no byte can spell meets none of them. */
#define FZN_NOTE_PURGE_KIND 0x136u

/* Claims one host may hold: a node nobody has fought over costs one, a
 * contested node one per writer. A bound rather than a promise, and the
 * failure is FZN_NOTES_ERR_FULL rather than a silent drop. */
#define FZN_NOTES_MAX 256u

typedef enum fzn_notes_err {
	FZN_NOTES_OK = 0,
	FZN_NOTES_ERR_MALFORMED = -1,    /* a null, or bytes that are not a record */
	FZN_NOTES_ERR_DENIED = -2,       /* the policy did not admit it; see the denial */
	FZN_NOTES_ERR_FULL = -3,         /* FZN_NOTES_MAX claims are held */
	FZN_NOTES_ERR_EQUIVOCATION = -4, /* one writer, one sequence, two records */
	FZN_NOTES_ERR_BACKEND = -5,      /* the backend refused, or cannot list */
	FZN_NOTES_ERR_ABSENT = -6,       /* this host holds no such claim */
	FZN_NOTES_ERR_SHAPE = -7,        /* what came back is not that claim's record */
	FZN_NOTES_ERR_UNSUPPORTED = -8,  /* the backend cannot remove */
	FZN_NOTES_ERR_PENDING = -9,      /* a note's content is not here yet, sec 514 */
	FZN_NOTES_ERR_PURGED = -10       /* the note was purged here, sec 518 */
} fzn_notes_err_t;

const char *fzn_notes_err_str(fzn_notes_err_t err);

/* ---- who may write ------------------------------------------------------ */

typedef struct fzn_notes_writer {
	uint8_t key[FZN_PUBKEY_LEN];
} fzn_notes_writer_t;

/*
 * Who may write, SPELLED rather than defaulted -- `chain/authz.h`'s
 * discipline, copied by fuzzypickles and kept: a memset, an uninitialised read
 * and a forgotten assignment all produce zero, and every one of them must
 * land on "no". An empty admitted set denies too: a host that has not loaded
 * its siblings knows of no writers, and that must not read as "any will do".
 */
typedef struct fzn_notes_policy {
	int spelled;
	const fzn_notes_writer_t *admitted;
	size_t admitted_count;
} fzn_notes_policy_t;

/* The only constructor, so a policy appears in a grep. For a user's own
 * notes, `admitted` is this host and its siblings; for a sharer's tree, the
 * sharing hosts. Which set is the caller's question, answered before this. */
static inline fzn_notes_policy_t fzn_notes_policy_writers(const fzn_notes_writer_t *admitted,
                                                          size_t count)
{
	fzn_notes_policy_t p;

	p.spelled = 1;
	p.admitted = admitted;
	p.admitted_count = admitted ? count : 0u;
	return p;
}

/* A verdict, and ZERO IS DENIAL, so reading it as a truth value is correct. */
typedef enum fzn_notes_verdict {
	FZN_NOTES_DENIED = 0,
	FZN_NOTES_ADMITTED = 1
} fzn_notes_verdict_t;

/* Why, for a log and never for a decision: kept out of the verdict so a
 * refusal can never be a nonzero enumerator. */
typedef enum fzn_notes_denial {
	FZN_NOTES_DENIAL_NONE = 0,
	FZN_NOTES_DENIAL_POLICY_UNSPELLED,
	FZN_NOTES_DENIAL_MALFORMED,
	FZN_NOTES_DENIAL_KIND,
	FZN_NOTES_DENIAL_SIGNATURE,
	FZN_NOTES_DENIAL_NOT_ADMITTED
} fzn_notes_denial_t;

/*
 * May this record be a note here? An unspelled policy is refused before the
 * record is looked at; then it must open, be of FZN_NOTE_KIND on
 * FZN_NOTE_STREAM, verify under its own issuer, and that issuer must be
 * admitted. AUTHENTICITY BEFORE ADMISSION: until the signature checks, the
 * issuer field is bytes somebody sent. `why` may be NULL.
 *
 * THE KIND IS NEW HERE. fuzzypickles' admission never read it, so a record a
 * sibling signed for any other purpose, with a body that happened to parse as
 * a node, was a note. A host's siblings sign other records under the same key.
 */
fzn_notes_verdict_t fzn_notes_admit(fzn_notes_policy_t policy, const uint8_t *record,
                                    size_t record_len, const fzn_sign_ops_t *sign,
                                    fzn_notes_denial_t *why);

const char *fzn_notes_denial_str(fzn_notes_denial_t why);

/* ---- the store ----------------------------------------------------------- */

/* A store over a `persist/` backend that can load, save and list; `remove`
 * is needed only by `fzn_notes_erase`. `hash` derives claim keys. */
typedef struct fzn_notes_store {
	const fzn_persist_ops_t *ops;
	const fzn_hash_ops_t *hash;
	/* Told once, when a note is first marked purged here, so the mark can
	 * travel (sec 519): the node appends a purge record to its notes
	 * stream. NULL after `fzn_notes_store_init`, and for a sharer's tree. */
	void (*purged)(void *ctx, const uint8_t id[FZN_SUBJECT_LEN]);
	void *purged_ctx;
	/* KEEP WHAT A NEWER RECORD SUPERSEDES, sec 581, as the note's history.
	 * 0 after `fzn_notes_store_init`, and for a sharer's tree. */
	int history;
} fzn_notes_store_t;

fzn_notes_err_t fzn_notes_store_init(fzn_notes_store_t *store, const fzn_persist_ops_t *ops,
                                     const fzn_hash_ops_t *hash);

/*
 * NOTE HISTORY, sec 581. A store with `history` set keeps each record a
 * newer one by the same writer supersedes, as it was signed, in persist slot
 * FZN_PERSIST_NOTE_HISTORY, one row per record keyed by a hash of its bytes:
 * the old meta and the wrapped content key with it, so an old version's text
 * opens as the current one's does. The retention rules decide how long a
 * version stays (`log/retain.h`, kind `history`, kept by default -- the
 * holder's of 2026-10-10); a purge takes a note's history with it.
 *
 * AT MOST FZN_NOTES_HISTORY_MAX versions in all. Past it the oldest version
 * is let go to keep the newest, so a store with no rules stays bounded.
 */
#define FZN_NOTES_HISTORY_MAX 4096u

/* One kept version: its row and its record, valid during the call. */
typedef void (*fzn_notes_history_fn)(void *ctx, const uint8_t row[FZN_PUBKEY_LEN],
                                     fzn_record_t record);

/* Every kept version, to `fn`. A row that will not open is passed over.
 * BACKEND when the store cannot list. */
fzn_notes_err_t fzn_notes_history_each(const fzn_notes_store_t *store,
                                       fzn_notes_history_fn fn, void *ctx);

/* One kept version's record, as signed, into `out` (at most `cap`):
 * ABSENT when no such row is kept, SHAPE when it will not open. */
fzn_notes_err_t fzn_notes_history_get(const fzn_notes_store_t *store,
                                      const uint8_t row[FZN_PUBKEY_LEN], uint8_t *out,
                                      size_t cap, size_t *out_len);

/* Let one version go. */
fzn_notes_err_t fzn_notes_history_remove(const fzn_notes_store_t *store,
                                         const uint8_t row[FZN_PUBKEY_LEN]);

/* Let every version of the note `id` go: what a purge does. */
fzn_notes_err_t fzn_notes_history_forget(const fzn_notes_store_t *store,
                                         const uint8_t id[FZN_SUBJECT_LEN]);

/* The 32-byte persist subject a claim is filed under. */
fzn_notes_err_t fzn_notes_claim_key(const fzn_notes_store_t *store,
                                    const uint8_t id[FZN_SUBJECT_LEN],
                                    const uint8_t issuer[FZN_PUBKEY_LEN],
                                    uint8_t out[FZN_PUBKEY_LEN]);

/*
 * THE PURGE MARK, sec 518. A note's records stay in its writers' journal
 * streams for good, so erasing its claims is not enough: the next time the
 * index is fed from a stream, every record of the note would be filed
 * again. A purged note's id is marked, in core persist, before its claims
 * are erased, and nothing of it is filed here again. Ids are random, so a
 * mark never stands in the way of a note written since.
 */
fzn_notes_err_t fzn_notes_mark_purged(const fzn_notes_store_t *store,
                                      const uint8_t id[FZN_SUBJECT_LEN]);

/* Whether `id` is marked purged. A mark that will not read counts as one: a
 * deletion is not undone because a row could not be read. */
int fzn_notes_purged(const fzn_notes_store_t *store, const uint8_t id[FZN_SUBJECT_LEN]);

/*
 * A NOTE'S WRAP KEY, sec 520: what its records' content keys are wrapped
 * under (`notes/note.h`), kept here and never in the journal. The note's
 * creator draws it; members and contacts it is shared with are given it
 * over their sessions; a purge destroys it.
 *
 * THE FIRST ONE HELD STANDS: a note has one creator and so one wrap key,
 * and a different one offered later is refused as EQUIVOCATION rather than
 * written over the key every record here unwraps under. A purged note takes
 * none, as PURGED.
 */
fzn_notes_err_t fzn_notes_wrap_get(const fzn_notes_store_t *store,
                                   const uint8_t id[FZN_SUBJECT_LEN],
                                   uint8_t out[FZN_NOTE_WRAP_KEY_LEN]);
fzn_notes_err_t fzn_notes_wrap_put(const fzn_notes_store_t *store,
                                   const uint8_t id[FZN_SUBJECT_LEN],
                                   const uint8_t key[FZN_NOTE_WRAP_KEY_LEN]);
/* ABSENT is not a failure here: a key never held is a key destroyed. */
fzn_notes_err_t fzn_notes_wrap_erase(const fzn_notes_store_t *store,
                                     const uint8_t id[FZN_SUBJECT_LEN]);

/*
 * File a record under the claim it carries, ADMITTING IT FIRST, INSIDE: a
 * check beside the write is one somebody forgets. DENIED with `*why` set when
 * the policy refuses; PURGED for a record of a note marked purged. `*wrote` (may be NULL) says whether anything changed:
 * an older record, or the same one again, is OK and writes nothing.
 * Capacity is checked before anything is written, so a refused put leaves
 * nothing behind. A held record that will not open is damage and is replaced
 * rather than allowed to freeze its note.
 */
fzn_notes_err_t fzn_notes_put(const fzn_notes_store_t *store, const uint8_t *record,
                              size_t record_len, fzn_notes_policy_t policy,
                              const fzn_sign_ops_t *sign, int *wrote, fzn_notes_denial_t *why);

/* Read one claim's record into `out` (FZN_RECORD_MAX_LEN fits any). SHAPE
 * when what came back is not a record or is another claim's. The caller does
 * not owe a verify for a record it put here; one read from a backend it does
 * not trust it does. */
fzn_notes_err_t fzn_notes_get(const fzn_notes_store_t *store, const uint8_t id[FZN_SUBJECT_LEN],
                              const uint8_t issuer[FZN_PUBKEY_LEN], uint8_t *out, size_t cap,
                              size_t *out_len);

/* Every claim key held, `cap` of them at most; BACKEND when there are more,
 * since a short list read as a whole one is notes that silently vanish. */
fzn_notes_err_t fzn_notes_claims(const fzn_notes_store_t *store,
                                 uint8_t (*keys)[FZN_PUBKEY_LEN], size_t cap, size_t *count);

/* Read the record filed under one claim key, as `fzn_notes_get` does for an
 * (id, writer) -- for a caller walking `fzn_notes_claims`. */
fzn_notes_err_t fzn_notes_get_key(const fzn_notes_store_t *store,
                                  const uint8_t key[FZN_PUBKEY_LEN], uint8_t *out, size_t cap,
                                  size_t *out_len);

/* Forget one claim, for a purge that has reached consensus. UNSUPPORTED when
 * the backend cannot remove: a refusal, not a silent skip. Nothing else here
 * deletes -- a trashed note is a flag (`notes/note.h`). */
fzn_notes_err_t fzn_notes_erase(const fzn_notes_store_t *store,
                                const uint8_t id[FZN_SUBJECT_LEN],
                                const uint8_t issuer[FZN_PUBKEY_LEN]);

#endif /* FZN_NOTES_STORE_H */
