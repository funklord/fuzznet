/* A node's operation journal: every write to its persistent state, kept so
 * the state can be replayed as it stood at any entry. project.md secs 523
 * and 524, sec 496's tier 2, as the holder decided it in sec 511 (5b).
 *
 * A DECORATOR OVER THE PERSIST OPS. `fzn_opjournal_ops` fills ops that pass
 * every load and list through and, after each save or remove the wrapped
 * ops took, write an entry: the op, the slot, the row, and the hash and
 * length of the bytes saved. Nothing writes to persistent state except
 * through these ops, so nothing escapes it. It is switchable: a node that
 * does not wrap its ops keeps none.
 *
 * THE JOURNAL'S OWN FORMAT, sec 498: each entry is the body of a record on
 * this node's own stream FZN_OPJOURNAL_STREAM, signed and chained, in a
 * `fzn_node_journal_t` of its own that nothing serves. It is never carried.
 *
 * IN GENERATIONS, sec 524. A record store never forgets a record, so the
 * entries cannot shrink in place. Each generation is a journal of its own,
 * numbered from 1, and the oldest is dropped whole once more than `keep`
 * are held. EVERY GENERATION OPENS WITH A SNAPSHOT: a save entry for every
 * row of every slot that keeps its bytes, as the wrapped store holds it,
 * then an OPENED entry counting them. So a generation replays alone, from
 * nothing, and the first covers what was written before the journal was
 * turned on. A generation with no OPENED entry is a snapshot a crash cut
 * short, and `fzn_opjournal_start` drops it and takes the snapshot again.
 *
 * BY HASH, AND PURGE-AWARE (the holder's 5b). An entry names the bytes it
 * saved by hash, and they are kept beside it, in persist slot
 * FZN_PERSIST_OP_BYTES of the wrapped ops, ONE COPY PER ENTRY under the
 * entry's place (generation and sequence), so a snapshot shares nothing
 * with the entries before it and erasing one entry's bytes never takes
 * another's. Erasing deletes the content while the entry, which says only
 * that a write happened, stays. A REMOVE ERASES THE ROW'S HISTORY: every
 * byte any entry of any generation kept for that row goes with it, so a
 * purged note, a removed contact or a forgotten share leaves nothing
 * readable here.
 *
 * SOME SLOTS KEEP NO BYTES AT ALL: the secrets and the sessions, whose old
 * states must not outlive them -- forward secrecy is a ratchet's old keys
 * being gone -- and notes' wrap keys, which a purge destroys (sec 520).
 * Their entries say a write happened, with no hash, and no snapshot takes
 * them. `fzn_opjournal_keeps` names the slots that do keep bytes, and they
 * are exactly the slots replay rebuilds: a slot is a pure function of its
 * entries when every one of its writes is kept.
 *
 * WRITE FIRST, ENTRY AFTER: a crash between leaves a write the journal does
 * not show, never an entry for a write that did not happen. A write whose
 * entry would not take is counted in `unrecorded` rather than refused --
 * the journal is a record of the state, not a gate on it.
 */

#ifndef FZN_NODE_OPJOURNAL_H
#define FZN_NODE_OPJOURNAL_H

#include <stddef.h>
#include <stdint.h>

#include "journal.h"
#include "../persist/persist.h"

/* Its own stream, in fuzznet's reserved range, on a journal of its own. */
#define FZN_OPJOURNAL_STREAM 2u
#define FZN_OPJOURNAL_KIND 0x201u

/* `node/opjournal.situ`. */
#define FZN_OPJOURNAL_VERSION 1u
#define FZN_OPJOURNAL_OP_SAVE 1u
#define FZN_OPJOURNAL_OP_REMOVE 2u
/* The snapshot is whole: `length` counts its entries, which precede it. */
#define FZN_OPJOURNAL_OP_OPENED 3u
#define FZN_OPJOURNAL_HAS_SUBJECT 0x01u
#define FZN_OPJOURNAL_BYTES_KEPT 0x02u
#define FZN_OPJOURNAL_OFF_VERSION 0u
#define FZN_OPJOURNAL_OFF_OP 1u
#define FZN_OPJOURNAL_OFF_SLOT 2u
#define FZN_OPJOURNAL_OFF_FLAGS 3u
#define FZN_OPJOURNAL_OFF_SUBJECT 4u
#define FZN_OPJOURNAL_OFF_HASH 36u
#define FZN_OPJOURNAL_OFF_LENGTH 68u
#define FZN_OPJOURNAL_ENTRY_LEN 72u

/* The most bytes one entry keeps. A larger write is entered by hash, its
 * bytes not kept, and counted: no slot here writes one today. */
#define FZN_OPJOURNAL_BYTES_MAX (16u * 1024u)

/* The most generations open at once. `keep` is at most one fewer, so a
 * rotation has a place to open the next before the oldest is dropped. */
#define FZN_OPJOURNAL_GENERATIONS_MAX 4u

/* The most rows of one slot a snapshot takes. A slot holding more cannot be
 * listed whole, and the rotation is put off rather than open a generation
 * that does not replay to the state. */
#define FZN_OPJOURNAL_SNAPSHOT_ROWS 4096u

typedef struct fzn_opjournal_entry {
	uint8_t op;
	uint8_t slot;
	uint8_t flags;
	uint8_t subject[FZN_PUBKEY_LEN];
	uint8_t hash[32];
	uint32_t length;
} fzn_opjournal_entry_t;

/* The codec. Nonzero on success; open refuses what the schema refuses. */
int fzn_opjournal_entry_write(const fzn_opjournal_entry_t *e,
                              uint8_t out[FZN_OPJOURNAL_ENTRY_LEN]);
int fzn_opjournal_entry_open(const uint8_t *body, size_t len, fzn_opjournal_entry_t *out);

/* Whether `slot` keeps its bytes, and so replays. See the header. */
int fzn_opjournal_keeps(fzn_persist_slot_t slot);

/*
 * WHERE GENERATIONS LIVE, which is the caller's to decide: a directory each
 * for a daemon, a store in memory for a suite.
 *
 * `open` gives generation `generation`'s journal, made empty if it does not
 * exist, following this node's FZN_OPJOURNAL_STREAM and having replayed
 * what it holds; NULL when it cannot. `drop` closes it and deletes it
 * whole, and the journal is not used after it.
 */
typedef struct fzn_opjournal_generations {
	fzn_node_journal_t *(*open)(void *ctx, uint64_t generation);
	void (*drop)(void *ctx, uint64_t generation);
	void *ctx;
} fzn_opjournal_generations_t;

typedef struct fzn_opjournal {
	fzn_opjournal_generations_t generations;
	/* The generations held, `first` to `last`, both 0 when none is. The
	 * caller sets them from what exists before `fzn_opjournal_start`;
	 * after it, they are this module's. */
	uint64_t first;
	uint64_t last;
	/* How many to hold, 1 to FZN_OPJOURNAL_GENERATIONS_MAX - 1, and the
	 * writes a generation enters after its snapshot before the next opens;
	 * 0 never rotates. Counted after the snapshot, so a state larger than
	 * a generation does not rotate on every write. */
	uint64_t keep;
	uint64_t rotate_at;
	/* The ops it wraps; bytes are kept in their FZN_PERSIST_OP_BYTES. */
	const fzn_persist_ops_t *base;
	/* This node's key, which signs each entry. */
	const uint8_t *issuer;
	const fzn_sign_ops_t *sign;
	const fzn_hash_ops_t *hash;
	/* The wall clock, in milliseconds. */
	uint64_t (*now)(void);
	/* Writes made that no entry records, bytes not kept for want of room or
	 * a store that refused them, and rotations put off because a whole
	 * snapshot could not be taken. */
	size_t unrecorded;
	size_t unkept;
	size_t unrotated;
	/* RETENTION: the most kept bytes, the oldest erased first past it; 0
	 * is no bound. Their entries stay, so a replay counts those writes
	 * missing rather than guessing them. `kept` is the running total, and
	 * `oldest_generation` and `oldest` the first entry whose bytes may
	 * still be kept, set by `fzn_opjournal_start`. */
	uint64_t budget;
	uint64_t kept;
	uint64_t oldest_generation;
	uint64_t oldest;
	/* The open journals, by generation modulo the maximum; the newest's
	 * OPENED entry; and the writes after it at which a put-off rotation is
	 * tried again. This module's. */
	fzn_node_journal_t *journals[FZN_OPJOURNAL_GENERATIONS_MAX];
	uint64_t opened_at;
	uint64_t retry_at;
} fzn_opjournal_t;

/*
 * OPEN WHAT EXISTS, and count it, so the budget is kept across a restart:
 * every entry walked once. A last generation with no OPENED entry is
 * dropped and its snapshot taken again; with none held, generation 1 opens
 * with one. More than `keep` held drops the oldest. Nonzero unless a
 * generation will not open, an entry will not read, or a snapshot cannot be
 * taken.
 */
int fzn_opjournal_start(fzn_opjournal_t *oj);

/* How many entries generation `generation` (0 for the newest) holds; 0 for
 * one not held. */
uint64_t fzn_opjournal_entries(const fzn_opjournal_t *oj, uint64_t generation);

/* Fill `ops` so every write through them is journalled in `oj`, which must
 * outlive them. */
void fzn_opjournal_ops(fzn_opjournal_t *oj, fzn_persist_ops_t *ops);

typedef struct fzn_opjournal_replay_tally {
	size_t saved;   /* rows written into the target */
	size_t removed; /* rows removed from it */
	size_t missing; /* saves whose bytes were erased, or will not match */
	size_t skipped; /* entries of slots that keep no bytes */
} fzn_opjournal_replay_tally_t;

/*
 * THE STATE AS IT STOOD after entry `upto` of `generation` (0 for the
 * newest; `upto` past the last for all of them): the slots
 * `fzn_opjournal_keeps` names, rebuilt into `into` -- an empty store, in
 * practice -- from the generation's snapshot onward, in order. Bytes are
 * read back from `oj`'s base and checked against the entry's hash. A save
 * whose bytes are gone is counted, not guessed at. This is also how a
 * captured journal becomes a test fixture. Nonzero unless the generation is
 * not held or not whole, or an entry or the target refused.
 */
int fzn_opjournal_replay(fzn_opjournal_t *oj, uint64_t generation, uint64_t upto,
                         const fzn_persist_ops_t *into, fzn_opjournal_replay_tally_t *tally);

#endif /* FZN_NODE_OPJOURNAL_H */
