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
 * WHAT IS WRITTEN, IN THIS STAGE: a record of kind FZN_NODE_JOURNAL_KIND_ACT
 * for every act the node logs (`fzn_node_roots_log_act`), its subject the
 * act's hash and its body the act's kind. It mirrors the act log, so the
 * journal carries real chains end to end before sec 500's stage 3 moves each
 * kind of act onto records of its own and stage 4 retires the act log.
 *
 * THE STORE IS NOT TRUSTED, here as in `record/store.h`: a stream is replayed
 * through the signature check and the chain on every start, so a file edited
 * underneath stops the stream at the edit rather than being believed.
 */

#ifndef FZN_NODE_JOURNAL_H
#define FZN_NODE_JOURNAL_H

#include <stddef.h>
#include <stdint.h>

#include "../record/exchange.h"
#include "../record/store_file.h"

/* The estate stream: every act a key signs for its estate, one chain per key.
 * Inside fuzznet's reserved range (record.h), and not notes' stream 0. */
#define FZN_NODE_JOURNAL_STREAM 1u

/* The most streams a node follows: its own keys, the roots, the members. */
#define FZN_NODE_JOURNAL_STREAMS_MAX 256u

/* The most records one request asks for: a window the next round extends. */
#define FZN_NODE_JOURNAL_WINDOW 64u

/* The kinds of record on the estate stream. Zero is no kind. */
typedef enum fzn_node_journal_kind {
	/* An act the node logged, mirrored: subject the act's hash, body the
	 * act log's kind byte. Until sec 500's stage 4. */
	FZN_NODE_JOURNAL_KIND_ACT = 1
} fzn_node_journal_kind_t;

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
	fzn_record_store_file_t file;
	fzn_record_store_t store;
	const fzn_sign_ops_t *sign;
	const fzn_hash_ops_t *hash;
} fzn_node_journal_t;

/* Over the record store in `dir`, which must exist. `sign` verifies what is
 * replayed and pulled; `hash` names records. Both must outlive it. */
fzn_node_journal_err_t fzn_node_journal_init(fzn_node_journal_t *nj, const char *dir,
                                             const fzn_sign_ops_t *sign,
                                             const fzn_hash_ops_t *hash);

void fzn_node_journal_close(fzn_node_journal_t *nj);

/* FOLLOW `key`'s estate stream, from the beginning, and replay what the store
 * holds of it: each record opened, verified and admitted in order, until the
 * first the store does not hold or the chain does not take. `replayed` (may
 * be NULL) is how many. Following a stream already followed replays nothing
 * and is OK. */
fzn_node_journal_err_t fzn_node_journal_follow(fzn_node_journal_t *nj,
                                               const uint8_t key[FZN_PUBKEY_LEN],
                                               size_t *replayed);

/* WRITE ONE: the next record of `issuer`'s estate stream, signed by `sign`
 * (which holds `issuer`'s secret), naming the stream's head, admitted and
 * stored. The stream is followed first if it was not. Its id lands in `id`
 * (may be NULL). */
fzn_node_journal_err_t fzn_node_journal_append(fzn_node_journal_t *nj,
                                               const uint8_t issuer[FZN_PUBKEY_LEN],
                                               const fzn_sign_ops_t *sign, uint32_t kind,
                                               const uint8_t subject[FZN_SUBJECT_LEN],
                                               const uint8_t *body, size_t body_len,
                                               uint64_t now, uint8_t id[FZN_RECORD_ID_LEN]);

/* THE SERVER: `fzn_exchange_answer` over this node's journal and store. 0 for
 * a message that is not the journal's. */
size_t fzn_node_journal_answer(fzn_node_journal_t *nj, const uint8_t *request,
                               size_t request_len, uint8_t *reply, size_t reply_cap);

/* THE CLIENT: one round against one peer, `fzn_exchange_pull` with
 * FZN_NODE_JOURNAL_WINDOW. */
fzn_exchange_err_t fzn_node_journal_pull(fzn_node_journal_t *nj, fzn_exchange_ask_t ask,
                                         void *ask_ctx, uint8_t *reply, size_t reply_cap,
                                         fzn_exchange_tally_t *tally);

#endif /* FZN_NODE_JOURNAL_H */
