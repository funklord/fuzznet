/* The journal between two hosts: what one asks for, what the other answers.
 * project.md sec 501.
 *
 * `record/sync.h` decides WHAT to ask for, from two sets of positions, and
 * says it does not send, encode or schedule. This is the encoding and the
 * asking, so that every consumer of the journal does not write its own -- the
 * shape `get vote` and `get root` each grew, paging and deduplicating and
 * ordering on their own, which sec 500 retires.
 *
 * SIX MESSAGES, BINARY, stated in `record/exchange.situ`:
 *
 *     DIGEST_QUERY   "your positions, from this one"
 *     DIGEST         "these, of this many"
 *     RECORDS_QUERY  "this stream's records, from this sequence, at most n"
 *     RECORDS        "these"
 *     PUSH           "take these", unasked (sec 512)
 *     PUSHED         "taken, held, refused, forked"
 *
 * Binary because a record is up to 700 bytes and a reply line of hex is
 * bounded at 1024 characters. The first byte is the version, 5, below any
 * verb's first letter, so a node dispatching on it falls through to its
 * verbs when the message is not one of these.
 *
 * WHAT A PULL ADMITS. Only streams this host already follows -- the plan
 * comes from `fzn_sync_plan_fetch`, which never asks about a stranger -- and
 * of those, only a record that is exactly the next one asked for, signed by
 * its issuer, and extending the chain this host holds
 * (`fzn_journal_admit_chained`). A fork stops that stream for the round and
 * is counted; the record is not kept.
 *
 * A PUSH IS ADMITTED AS A PULL IS, and only on a stream the taker follows:
 * a hub pulls from nobody it is not paired to, so without a push a member's
 * records reached nobody but the members that pull it (sec 446's reason for
 * notes' push, met again). The pusher reads the taker's digest and sends
 * only what each listed stream lacks, so a stream the taker does not follow
 * is never offered, and one sent anyway is refused by the journal, which
 * adopts no issuer it was not told to follow.
 *
 * ADMITTED, THEN STORED. A record the journal refuses is never written, so a
 * fork at the head cannot overwrite the honest record at its sequence. A store
 * that refuses a write after admission leaves the journal ahead of the store
 * until the next start, when a consumer rebuilds its positions from what the
 * store holds; the pull says so with STORE.
 */

#ifndef FZN_EXCHANGE_H
#define FZN_EXCHANGE_H

#include <stddef.h>
#include <stdint.h>

#include "journal.h"
#include "store.h"
#include "sync.h"
#include "../session/commitment.h"

#define FZN_EXCHANGE_VERSION 5u

typedef enum fzn_exchange_type {
	FZN_EXCHANGE_DIGEST_QUERY = 1,
	FZN_EXCHANGE_DIGEST = 2,
	FZN_EXCHANGE_RECORDS_QUERY = 3,
	FZN_EXCHANGE_RECORDS = 4,
	FZN_EXCHANGE_PUSH = 5,
	FZN_EXCHANGE_PUSHED = 6
} fzn_exchange_type_t;

#define FZN_EXCHANGE_DIGEST_QUERY_LEN 4u
#define FZN_EXCHANGE_POSITION_LEN 44u
#define FZN_EXCHANGE_DIGEST_HEAD_LEN 8u
#define FZN_EXCHANGE_RECORDS_QUERY_LEN 48u
#define FZN_EXCHANGE_RECORDS_HEAD_LEN 4u
/* A PUSH is laid out as RECORDS is; PUSHED is its four counts. */
#define FZN_EXCHANGE_PUSH_HEAD_LEN 4u
#define FZN_EXCHANGE_PUSHED_LEN 10u

/* The smallest reply buffer either side may use: one whole record and its
 * length in a RECORDS message. A smaller one could never carry the largest
 * record a stream may hold. */
#define FZN_EXCHANGE_REPLY_MIN (FZN_EXCHANGE_RECORDS_HEAD_LEN + 2u + FZN_RECORD_MAX_LEN)

typedef enum fzn_exchange_err {
	FZN_EXCHANGE_OK = 0,
	/* A null argument, or a reply buffer under FZN_EXCHANGE_REPLY_MIN. */
	FZN_EXCHANGE_ERR_MALFORMED = -1,
	/* The peer did not answer. */
	FZN_EXCHANGE_ERR_NO_ANSWER = -2,
	/* The peer answered something that is not one of these messages. */
	FZN_EXCHANGE_ERR_SHAPE = -3,
	/* A record was admitted and the store would not keep it. */
	FZN_EXCHANGE_ERR_STORE = -4
} fzn_exchange_err_t;

const char *fzn_exchange_err_str(fzn_exchange_err_t err);

/* THE SERVER: answer one message from what `journal` holds and `store`
 * keeps. A DIGEST page as large as `reply_cap` takes; RECORDS of the stream
 * asked about, as many as fit, up to what the journal has received. 0 when
 * `request` is not one of these messages -- not version 5, or a query that
 * does not parse -- so a caller dispatching on the first byte falls through. */
size_t fzn_exchange_answer(const fzn_journal_t *journal, fzn_record_store_t *store,
                           const uint8_t *request, size_t request_len, uint8_t *reply,
                           size_t reply_cap);

/* How a puller reaches its peer: send `request`, fill `reply`, 1 for an
 * answer. The shape every pull here already takes. */
typedef int (*fzn_exchange_ask_t)(void *ctx, const uint8_t *request, size_t request_len,
                                  uint8_t *reply, size_t reply_cap, size_t *reply_len);

/* How many missing streams a tally names; past it they are counted only. */
#define FZN_EXCHANGE_MISSED_MAX 8u

typedef struct fzn_exchange_tally {
	size_t positions;   /* the peer's, read */
	size_t requested;   /* ranges planned */
	size_t learned;     /* records admitted and kept */
	size_t refused;     /* records not the next one, or not signed */
	size_t forks;       /* streams stopped at a fork */
	/* RANGES THE PEER CLAIMS AND SENT NOTHING OF: its position is past
	 * what this host holds and it no longer holds the next record --
	 * cut below its base (project.md sec 547), or a store that lost it.
	 * Either way no pull from this peer brings the stream on; it wants
	 * a state transfer. */
	size_t missing;
	/* WHICH: the first FZN_EXCHANGE_MISSED_MAX of them, so a caller can
	 * ask the peer where each starts now (`node/reconcile.h`, sec 552). */
	struct {
		uint8_t issuer[FZN_PUBKEY_LEN];
		uint32_t stream;
	} missed[FZN_EXCHANGE_MISSED_MAX];
} fzn_exchange_tally_t;

/* THE TAKER: one PUSH, admitted record by record exactly as a pull admits
 * them -- each opened, verified by its issuer, the next of a stream this
 * journal follows, and extending its chain -- and stored once admitted. A
 * record already held is counted held; the first that is refused or forks
 * stops the rest of the message, since every record after it in one stream
 * would be refused the same way. PUSHED into `reply`, its length, or 0 when
 * `request` is not a PUSH. A store that will not keep an admitted record
 * stops the message and counts it refused. */
size_t fzn_exchange_take_push(fzn_journal_t *journal, fzn_record_store_t *store,
                              const fzn_sign_ops_t *sign, const fzn_hash_ops_t *hash,
                              const uint8_t *request, size_t request_len, uint8_t *reply,
                              size_t reply_cap);

typedef struct fzn_exchange_push_tally {
	size_t positions;   /* the peer's, read */
	size_t offered;     /* records sent */
	size_t taken;       /* of those, admitted and kept there */
	size_t held;        /* already held there */
	size_t refused;     /* refused there */
	size_t forks;       /* stopped there at a fork */
} fzn_exchange_push_tally_t;

/* THE PUSHER: read the peer's digest, and for every stream it lists that
 * this journal holds further, send the records it lacks, as many to a
 * message as fit in `reply_cap`, the stream stopping at the first message
 * that is not wholly taken. `reply` is the caller's, at least
 * FZN_EXCHANGE_REPLY_MIN, and carries both each PUSH and its answer. */
fzn_exchange_err_t fzn_exchange_push(fzn_journal_t *journal, fzn_record_store_t *store,
                                     fzn_exchange_ask_t ask, void *ask_ctx, uint8_t *reply,
                                     size_t reply_cap, fzn_exchange_push_tally_t *tally);

/* THE CLIENT: one round against one peer. Pages the peer's digest, plans with
 * `fzn_sync_plan_fetch` at `max_per_request`, and asks for each range until
 * it is filled or the peer has no more. `reply` is the caller's, at least
 * FZN_EXCHANGE_REPLY_MIN. */
fzn_exchange_err_t fzn_exchange_pull(fzn_journal_t *journal, fzn_record_store_t *store,
                                     const fzn_sign_ops_t *sign, const fzn_hash_ops_t *hash,
                                     uint64_t max_per_request, fzn_exchange_ask_t ask,
                                     void *ask_ctx, uint8_t *reply, size_t reply_cap,
                                     fzn_exchange_tally_t *tally);

#endif /* FZN_EXCHANGE_H */
