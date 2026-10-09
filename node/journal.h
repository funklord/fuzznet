/* A node's journal: every key's estate stream, kept, served and pulled.
 * project.md sec 501, stage 2 of sec 500.
 *
 * `record/` is the journal and `record/exchange.h` the sync between two
 * hosts. This is where a node holds them: a record store on disk, one stream
 * per key the estate admits (FZN_NODE_JOURNAL_STREAM), the keys it follows,
 * and the records it writes for itself.
 *
 * FOLLOWING IS DELIBERATE. `fzn_node_journal_follow` anchors a key's stream
 * from the beginning and replays what the store already holds of it; a pull
 * fetches only streams followed, so a stranger's stream is never taken. The
 * daemon follows its own keys, the estate's roots and its members.
 *
 * WHAT IS WRITTEN: every act the node logs (`fzn_node_roots_log_act`), as a
 * record whose body is the act's own signed object, whole -- a vote, a roster
 * record, a confirmation, a root change, a setting, a succession, or a grant's
 * hop -- whose kind is that object's tag (`wire/bytes.h`, 128 and up), and
 * whose subject is the object's hash, the act the act log names. sec 502:
 * the journal carries the objects themselves, so a host that holds a key's
 * stream holds everything that key signed for its estate. The object keeps
 * its own signature inside the record's; flattening each into native fields
 * is a later step that changes no carriage.
 *
 * THE STORE IS NOT TRUSTED, here as in `record/store.h`: a stream is replayed
 * through the signature check and the chain on every start, so a file edited
 * underneath stops the stream at the edit rather than being believed.
 */

#ifndef FZN_NODE_JOURNAL_H
#define FZN_NODE_JOURNAL_H

#include <stddef.h>
#include <stdint.h>

#include "../persist/persist.h"
#include "../record/exchange.h"
#include "../chain/revocation.h"
#ifdef FZN_RECORD_STORE_FILE_ON
#include "../record/store_file.h"
#endif

/* The estate stream: every act a key signs for its estate, one chain per key.
 * Inside fuzznet's reserved range (record.h), and not notes' stream 0. */
#define FZN_NODE_JOURNAL_STREAM 1u

/* The most streams a node follows: its own keys, the roots, the members. */
#define FZN_NODE_JOURNAL_STREAMS_MAX 256u

/* The most records one request asks for: a window the next round extends. */
#define FZN_NODE_JOURNAL_WINDOW 64u


typedef enum fzn_node_journal_err {
	FZN_NODE_JOURNAL_OK = 0,
	FZN_NODE_JOURNAL_MALFORMED = -1,
	/* The store would not open, read or write. */
	FZN_NODE_JOURNAL_STORE = -2,
	/* No room to follow another stream. */
	FZN_NODE_JOURNAL_FULL = -3,
	/* A record would not be signed or admitted -- a fork of this node's own
	 * stream among them, which is a key used in two places. */
	FZN_NODE_JOURNAL_REFUSED = -4
} fzn_node_journal_err_t;

const char *fzn_node_journal_err_str(fzn_node_journal_err_t err);

typedef struct fzn_node_journal {
	fzn_journal_t journal;
	fzn_journal_entry_t entries[FZN_NODE_JOURNAL_STREAMS_MAX];
#ifdef FZN_RECORD_STORE_FILE_ON
	fzn_record_store_file_t file;
	int has_file;
#endif
	fzn_record_store_t store;
	const fzn_sign_ops_t *sign;
	const fzn_hash_ops_t *hash;
	/* WHAT A CUT KEEPS: the spine, where an estate act's id, predecessor
	 * and subject go when its record is cut (sec 546), and each stream's
	 * base (sec 547). NULL keeps neither: an act behind a cut record does
	 * not stand, and every stream is read from 1. */
	const fzn_persist_ops_t *keep;
} fzn_node_journal_t;

/* OVER ANY RECORD STORE, `ops`, which must outlive it: memory for a suite,
 * the file store for a daemon. sec 504: a journal needs a store, not a disk.
 * `sign` verifies what is replayed and pulled; `hash` names records. */
fzn_node_journal_err_t fzn_node_journal_init_store(fzn_node_journal_t *nj,
                                                   const fzn_record_store_ops_t *ops,
                                                   const fzn_sign_ops_t *sign,
                                                   const fzn_hash_ops_t *hash);

#ifdef FZN_RECORD_STORE_FILE_ON
/* Over the file store in `dir`, which must exist. */
fzn_node_journal_err_t fzn_node_journal_init(fzn_node_journal_t *nj, const char *dir,
                                             const fzn_sign_ops_t *sign,
                                             const fzn_hash_ops_t *hash);
#endif

void fzn_node_journal_close(fzn_node_journal_t *nj);

/* FOLLOW `key`'s estate stream, from its base, and replay what the store
 * holds of it: each record opened, verified and admitted in order, until the
 * first the store does not hold or the chain does not take. `replayed` (may
 * be NULL) is how many. Following a stream already followed replays nothing
 * and is OK.
 *
 * FROM ITS BASE, sec 547: a stream cut below its base is anchored just under
 * it, with the id the base row keeps as its head, so the first record held
 * must name it, and everything below counted applied -- it was, or it would
 * not have been cut. */
fzn_node_journal_err_t fzn_node_journal_follow(fzn_node_journal_t *nj,
                                               const uint8_t key[FZN_PUBKEY_LEN],
                                               size_t *replayed);

/* FOLLOW `key`'s `stream`, as `fzn_node_journal_follow` follows its estate
 * stream: a key's notes are its stream 0 (`notes/store.h`), its acts its
 * estate stream. sec 512. */
fzn_node_journal_err_t fzn_node_journal_follow_stream(fzn_node_journal_t *nj,
                                                      const uint8_t key[FZN_PUBKEY_LEN],
                                                      uint32_t stream, size_t *replayed);

/* How far this journal holds `key`'s `stream`: the highest sequence of an
 * unbroken run from its base, which the store holds and the chain admitted.
 * 0 when the stream is not followed or holds nothing. */
uint64_t fzn_node_journal_received(const fzn_node_journal_t *nj,
                                   const uint8_t key[FZN_PUBKEY_LEN], uint32_t stream);

/* WRITE ONE: the next record of `issuer`'s estate stream, signed by `sign`
 * (which holds `issuer`'s secret), naming the stream's head, admitted and
 * stored. The stream is followed first if it was not. Its id lands in `id`
 * (may be NULL). `now`, here and for every writer below, is milliseconds
 * since the epoch, as `fzn_record_issued_at` says. sec 561. */
fzn_node_journal_err_t fzn_node_journal_append(fzn_node_journal_t *nj,
                                               const uint8_t issuer[FZN_PUBKEY_LEN],
                                               const fzn_sign_ops_t *sign, uint32_t kind,
                                               const uint8_t subject[FZN_SUBJECT_LEN],
                                               const uint8_t *body, size_t body_len,
                                               uint64_t now, uint8_t id[FZN_RECORD_ID_LEN]);

/* `fzn_node_journal_append` on any `stream`. sec 512. */
fzn_node_journal_err_t fzn_node_journal_append_on(fzn_node_journal_t *nj,
                                                  const uint8_t issuer[FZN_PUBKEY_LEN],
                                                  uint32_t stream, const fzn_sign_ops_t *sign,
                                                  uint32_t kind,
                                                  const uint8_t subject[FZN_SUBJECT_LEN],
                                                  const uint8_t *body, size_t body_len,
                                                  uint64_t now,
                                                  uint8_t id_out[FZN_RECORD_ID_LEN]);

/* `fzn_node_journal_append_on`, and the record it signed into `out`, `cap`
 * bytes (FZN_RECORD_MAX_LEN fits any), `*out_len` of them: for a caller that
 * files the record somewhere besides the journal, as notes' claims index
 * does with each note record (sec 517). MALFORMED for a short `out`. */
fzn_node_journal_err_t fzn_node_journal_write(fzn_node_journal_t *nj,
                                              const uint8_t issuer[FZN_PUBKEY_LEN],
                                              uint32_t stream, const fzn_sign_ops_t *sign,
                                              uint32_t kind,
                                              const uint8_t subject[FZN_SUBJECT_LEN],
                                              const uint8_t *body, size_t body_len, uint64_t now,
                                              uint8_t *out, size_t cap, size_t *out_len,
                                              uint8_t id_out[FZN_RECORD_ID_LEN]);

/* WRITE AN OBJECT: `fzn_node_journal_append` with the object's tag (its
 * second byte) as the kind, its hash as the subject, and its bytes, `len` of
 * them, as the body. MALFORMED for something that is not a signed object of
 * this library's -- a tag below 128 -- or does not fit a record's body. */
fzn_node_journal_err_t fzn_node_journal_append_object(fzn_node_journal_t *nj,
                                                      const uint8_t issuer[FZN_PUBKEY_LEN],
                                                      const fzn_sign_ops_t *sign,
                                                      const uint8_t *object, size_t len,
                                                      uint64_t now,
                                                      uint8_t id[FZN_RECORD_ID_LEN]);

/*
 * THE ACT LOG, sec 506. Each key's estate stream is that key's acts in the
 * order it signed them, chained by `prev`: the per-key log sec 496 kept
 * beside the journal as root-log entries. So a cut -- the last act of a key
 * a revocation or a root's removal keeps -- is the id of a record in the
 * key's stream, and asking whether an act stands under it is a walk down
 * that stream. A follower holds every key it follows, so a host judges a
 * cut as the one that drew it does.
 */

/* The id of the last record of `key`'s stream this journal holds, into `id`:
 * the default cut. 0 for a key not followed, a stream with nothing in it, or
 * one marked forked -- the key signed in two places, and neither branch is
 * its last word. */
int fzn_node_journal_head(const fzn_node_journal_t *nj, const uint8_t key[FZN_PUBKEY_LEN],
                          uint8_t id[FZN_RECORD_ID_LEN]);

/* Whether a fork of `key`'s stream has been seen here. */
int fzn_node_journal_forked(const fzn_node_journal_t *nj, const uint8_t key[FZN_PUBKEY_LEN]);

/* DOES THIS ACT STAND UNDER THIS CUT? 1 when `key`'s stream holds the record
 * whose id is `cut` and, at or below it, a record whose subject is `act` --
 * the hash of the act's object. Walked down from the head this journal
 * admitted, each record checked against the `prev` above it, so a store
 * edited underneath answers 0. 0 for a cut not on the held branch. Bounded
 * by the stream's length: one read and one hash a record. A record absent
 * from the store is read from the spine (sec 546), where it was kept when it
 * was cut, and checked against the `prev` above it as a record is. */
int fzn_node_journal_stands(fzn_node_journal_t *nj, const uint8_t key[FZN_PUBKEY_LEN],
                            const uint8_t cut[FZN_RECORD_ID_LEN],
                            const uint8_t act[FZN_SUBJECT_LEN]);

/* A spine entry: a record's id, its predecessor's, and its subject. */
#define FZN_NODE_JOURNAL_SPINE_ENTRY (FZN_RECORD_ID_LEN + FZN_RECORD_ID_LEN + FZN_SUBJECT_LEN)

/* KEEP ESTATE ACT `seq` OF `key`'S STREAM IN THE SPINE, sec 546: its id,
 * predecessor and subject, read from the record, which must be held and
 * chain to what is held above it as `fzn_node_journal_stands` would check.
 * Called before a record is cut. MALFORMED with no `keep`. */
fzn_node_journal_err_t fzn_node_journal_spine_keep(fzn_node_journal_t *nj,
                                                   const uint8_t key[FZN_PUBKEY_LEN],
                                                   uint64_t seq);

/* ESTATE ACT `seq` OF `key`'S STREAM AS A SPINE ENTRY, sec 552: from the
 * record where it is held, from the spine where it was cut. 0 for neither. */
int fzn_node_journal_spine_entry(fzn_node_journal_t *nj, const uint8_t key[FZN_PUBKEY_LEN],
                                 uint64_t seq, uint8_t entry[FZN_NODE_JOURNAL_SPINE_ENTRY]);

/* THE FIRST SEQUENCE OF `key`'S `stream` THIS JOURNAL STILL HOLDS, sec 547:
 * 1 for a stream never cut, or with no `keep`. Where a reader of the stream
 * starts. */
uint64_t fzn_node_journal_base(const fzn_node_journal_t *nj, const uint8_t key[FZN_PUBKEY_LEN],
                               uint32_t stream);

/* MOVE `key`'S `stream`'S BASE UP TO `base`, before the records below it are
 * cut: kept with the id of the record at `base` - 1, which must be held.
 * Whether the stream's reader is past it is the caller's to know -- the
 * estate stream's apply, the notes index, the messages store each keep their
 * own place. A base never moves down. MALFORMED for no `keep`, a stream not
 * followed, a base at or below the current one, or one above what is
 * received; STORE for a record not held or a row that will not keep. */
fzn_node_journal_err_t fzn_node_journal_base_set(fzn_node_journal_t *nj,
                                                 const uint8_t key[FZN_PUBKEY_LEN],
                                                 uint32_t stream, uint64_t base);

/* The base, as `fzn_node_journal_base`, and the id below it into `below`
 * (all zero for a stream never cut): what a peer is sent, sec 552. */
uint64_t fzn_node_journal_base_below(const fzn_node_journal_t *nj,
                                     const uint8_t key[FZN_PUBKEY_LEN], uint32_t stream,
                                     uint8_t below[FZN_RECORD_ID_LEN]);

/*
 * TAKE A PEER'S BASE FOR A STREAM THIS JOURNAL IS BEHIND, sec 552: the peer
 * cut what lay between this journal's head and its base, so no pull brings
 * it, and reconciliation (sec 551) has brought the state it carried. The
 * journal moves up: `base`'s predecessor becomes its head, under the id
 * `below` the peer's next record must name, everything under it applied,
 * and the records this journal held of the stream go below its own new
 * base as a cut takes them.
 *
 * THE ESTATE STREAM BRINGS ITS SPINE across the gap: `entries`, one per
 * sequence from this journal's received + 1 to `base` - 1, ascending,
 * chained -- each naming the one before as its predecessor, the first
 * naming this journal's head, the last's id `below`. Checked at both ends
 * and refused (REFUSED) otherwise; the subjects between are the peer's
 * word, the one thing a bridge of ids cannot check. Another stream takes
 * none. OK and nothing done for a base this journal is not behind;
 * MALFORMED for no `keep`, a stream not followed or forked.
 */
fzn_node_journal_err_t fzn_node_journal_rebase(fzn_node_journal_t *nj,
                                               const uint8_t key[FZN_PUBKEY_LEN], uint32_t stream,
                                               uint64_t base, const uint8_t below[FZN_RECORD_ID_LEN],
                                               const uint8_t (*entries)[FZN_NODE_JOURNAL_SPINE_ENTRY],
                                               size_t n_entries);

/* WHERE A CUT OF `key`'S `stream` COULD END, sec 548: the first sequence from
 * the base that is past `limit`, not held, or issued at or after
 * `older_than_ms` -- milliseconds, compared with `fzn_record_issued_ms`, so a
 * record stamped in seconds before sec 561 is judged by the same clock.
 * Records [base, the answer) are each held and older. The base itself when
 * none is. `limit` is how far the stream's reader has got: nothing it has
 * not taken in is cut. */
uint64_t fzn_node_journal_cut_point(fzn_node_journal_t *nj, const uint8_t key[FZN_PUBKEY_LEN],
                                    uint32_t stream, uint64_t limit, uint64_t older_than_ms);

/* CUT `key`'S `stream` BELOW `below`, sec 548: the estate stream's records
 * kept in the spine first, the base moved up to `below`, then the records
 * let go -- that order, so a crash at any point leaves a stream whose base
 * says where it starts and whose standing is still judged. `*cut` (may be
 * NULL) is how many went. OK with nothing cut for a `below` at or under the
 * base. MALFORMED for no `keep`, a stream not followed, or a `below` past
 * what is received; STORE for a record not held, a row that will not keep,
 * or a store that cannot cut. */
fzn_node_journal_err_t fzn_node_journal_cut(fzn_node_journal_t *nj,
                                            const uint8_t key[FZN_PUBKEY_LEN], uint32_t stream,
                                            uint64_t below, size_t *cut);

/* Fill `ops` so a revocation store or a root set asks this journal. `nj`
 * must outlive them. */
void fzn_node_journal_acts(fzn_node_journal_t *nj, fzn_act_log_ops_t *ops);

/* THE PUSHER: one round of `fzn_exchange_push` against one peer, every
 * stream the peer follows that this node holds further. sec 512. */
fzn_exchange_err_t fzn_node_journal_push(fzn_node_journal_t *nj, fzn_exchange_ask_t ask,
                                         void *ask_ctx, uint8_t *reply, size_t reply_cap,
                                         fzn_exchange_push_tally_t *tally);

/* THE SERVER: `fzn_exchange_answer` over this node's journal and store, and a
 * PUSH taken through `fzn_exchange_take_push`. 0 for
 * a message that is not the journal's. */
size_t fzn_node_journal_answer(fzn_node_journal_t *nj, const uint8_t *request,
                               size_t request_len, uint8_t *reply, size_t reply_cap);

/* THE CLIENT: one round against one peer, `fzn_exchange_pull` with
 * FZN_NODE_JOURNAL_WINDOW. */
fzn_exchange_err_t fzn_node_journal_pull(fzn_node_journal_t *nj, fzn_exchange_ask_t ask,
                                         void *ask_ctx, uint8_t *reply, size_t reply_cap,
                                         fzn_exchange_tally_t *tally);

#endif /* FZN_NODE_JOURNAL_H */
