/* Conversations: the lines a user's devices sent and received, kept in the
 * journal. project.md secs 526 to 528, the move of fuzzypickles' message
 * storage into this tree; `messages/line.h` is the format.
 *
 * WHERE LINES LIVE. Each device writes the lines it sent or received as
 * records of its own FZN_MESSAGE_STREAM, so the user's other devices hold
 * them by the journal sync every other act already rides, direction and
 * all. A line is shown once however many devices wrote it.
 *
 * NOTHING IS DELETED BY DEFAULT, and nothing bounds storage: the holder,
 * 2026-10-08, "custom rules delete/trim data. Definitely no default deletion
 * of messages." Text is sealed under a key per conversation, month and
 * writing device -- per device, so two never claim one key's row when keys
 * travel between them -- kept in persist slot FZN_PERSIST_CONVERSATION_KEY
 * and never in the journal, so a rule can trim by destroying a month's keys
 * (`fzn_messages_forget_epoch`) and leave the records as shells, listed and
 * unreadable. No rule is built, so nothing calls it but a test. Keys travel
 * between a user's devices through `node/messages.h` (sec 527); another
 * device's lines are shells here until its key arrives.
 *
 * A LINE'S STATE is the latest mark on it -- delivered, settled, handed
 * over, not delivered -- which may be written later and by another device.
 * AN OUT LINE WITH NO MARK IS STILL BEING SENT: 0 from `fzn_messages_state`
 * is "sending" for a line this user wrote, and NOT_DELIVERED is the one
 * state that says it never will be. FZN_PERSIST_MESSAGE_STATE holds the
 * latest per line, so a reader need not find the marks.
 *
 * WHAT IS DERIVED, sec 528, in FZN_PERSIST_MESSAGE_INDEX: each
 * conversation's lines in the order this store learned of them, so one
 * conversation pages, is searched and counts unread without reading any
 * other; each conversation's read position; and how far each device's
 * stream has been taken in. `fzn_messages_absorb` keeps them, a write
 * here keeps them for its own line at once, and `fzn_messages_reindex`
 * rebuilds them all from the journal.
 *
 * READ STATE TRAVELS (the holder, 2026-10-08): a conversation's read
 * position is a record too, the newest wins wherever it was written, so
 * reading on one device clears unread on every other.
 *
 * SEC 521, a hand-off given up on: the device that hands a message to
 * another of the user's devices writes it as its own OUT line and marks it
 * HANDED_OVER; when no device could send it, it marks it NOT_DELIVERED. The
 * text stays in the conversation either way.
 */

#ifndef FZN_MESSAGES_H
#define FZN_MESSAGES_H

#include <stddef.h>
#include <stdint.h>

#include "line.h"
#include "../node/journal.h"
#include "../persist/persist.h"
#include "../session/random.h"

/* The most devices a listing merges: this one and the user's others. */
#define FZN_MESSAGES_DEVICES_MAX 32u
/* The most lines a page holds, and the deepest a listing walks: offset and
 * page together. A deeper page is refused, not cut short. */
#define FZN_MESSAGES_PAGE_MAX 20u
#define FZN_MESSAGES_WALK_MAX 4096u
/* A conversation's index is kept this many lines to a row. */
#define FZN_MESSAGES_INDEX_CHUNK 16u

typedef enum fzn_messages_err {
	FZN_MESSAGES_OK = 0,
	FZN_MESSAGES_ERR_MALFORMED = -1, /* a null, or a direction or state out of range */
	FZN_MESSAGES_ERR_TEXT = -2,      /* longer than FZN_MESSAGE_TEXT_MAX */
	FZN_MESSAGES_ERR_JOURNAL = -3,   /* a record would not chain, or will not read */
	FZN_MESSAGES_ERR_BACKEND = -4,   /* the store refused, or cannot list */
	FZN_MESSAGES_ERR_SEAL = -5,      /* the randomness or the seal refused */
	FZN_MESSAGES_ERR_DEEP = -6,      /* past FZN_MESSAGES_WALK_MAX */
	FZN_MESSAGES_ERR_EQUIVOCATION = -7 /* another key is held for that row */
} fzn_messages_err_t;

const char *fzn_messages_err_str(fzn_messages_err_t err);

/* Everything the store needs. All borrowed. */
typedef struct fzn_messages {
	/* Conversation keys, line states, and the index. */
	const fzn_persist_ops_t *store;
	/* Where lines are chained, and read: it must follow FZN_MESSAGE_STREAM
	 * of every device below. */
	fzn_node_journal_t *journal;
	/* This device's key, which signs its lines. */
	const uint8_t *issuer;
	const fzn_sign_ops_t *sign;
	const fzn_random_ops_t *rng;
	const fzn_aead_ops_t *aead;
	const fzn_hash_ops_t *hash;
	uint64_t (*now)(void);
	/* The devices whose lines a listing merges, this one among them. */
	const uint8_t (*devices)[FZN_PUBKEY_LEN];
	size_t device_count;
} fzn_messages_t;

/* One line as a listing gives it. */
typedef struct fzn_message {
	uint8_t contact[FZN_PUBKEY_LEN];
	/* The device that wrote it. */
	uint8_t device[FZN_PUBKEY_LEN];
	uint8_t id[FZN_MESSAGE_ID_LEN];
	uint8_t direction;
	/* The latest mark, 0 for none: for an OUT line, still being sent. */
	uint8_t state;
	/* The sender's time, and when the device wrote it. */
	uint64_t stime;
	uint64_t written_at;
	/* 0 when its month's key is gone or not here: a shell, `text` empty. */
	int readable;
	char text[FZN_MESSAGE_TEXT_MAX + 1u];
	size_t text_len;
} fzn_message_t;

/*
 * WRITE A LINE: `text` (`len` bytes, at most FZN_MESSAGE_TEXT_MAX) to or
 * from `contact`, with the caller's `id` and the sender's time, as this
 * device's record or records. A month's key is drawn when its first line is
 * written. A text of two parts is two records; a write that fails between
 * them leaves the first, which no listing shows.
 */
fzn_messages_err_t fzn_messages_write(const fzn_messages_t *m,
                                      const uint8_t contact[FZN_PUBKEY_LEN], uint8_t direction,
                                      const uint8_t id[FZN_MESSAGE_ID_LEN], uint64_t stime,
                                      const char *text, size_t len);

/*
 * IMPORT A LINE held before the move: written as `fzn_messages_write`
 * writes, unless `contact`'s conversation already holds (`direction`,
 * `id`) -- written by any device -- when nothing is written. `*written`
 * says which. What was absorbed is what is checked, so absorb first.
 */
fzn_messages_err_t fzn_messages_import(const fzn_messages_t *m,
                                       const uint8_t contact[FZN_PUBKEY_LEN], uint8_t direction,
                                       const uint8_t id[FZN_MESSAGE_ID_LEN], uint64_t stime,
                                       const char *text, size_t len, int *written);

/* Whether `contact`'s conversation holds (`direction`, `id`), as absorbed. */
int fzn_messages_held(const fzn_messages_t *m, const uint8_t contact[FZN_PUBKEY_LEN],
                      uint8_t direction, const uint8_t id[FZN_MESSAGE_ID_LEN]);

/* MARK the line (`contact`, `direction`, `id`) with `state`, as a record,
 * and make it the line's state here. */
fzn_messages_err_t fzn_messages_mark(const fzn_messages_t *m,
                                     const uint8_t contact[FZN_PUBKEY_LEN], uint8_t direction,
                                     const uint8_t id[FZN_MESSAGE_ID_LEN], uint8_t state);

/* A line's state: its latest mark, or 0. */
uint8_t fzn_messages_state(const fzn_messages_t *m, const uint8_t contact[FZN_PUBKEY_LEN],
                           uint8_t direction, const uint8_t id[FZN_MESSAGE_ID_LEN]);

/* READ `contact`'s conversation up to the line `id`, as a record, and make
 * it the read position here. */
fzn_messages_err_t fzn_messages_read_up_to(const fzn_messages_t *m,
                                           const uint8_t contact[FZN_PUBKEY_LEN],
                                           const uint8_t id[FZN_MESSAGE_ID_LEN]);

/* The read position: nonzero, and the line's id, when there is one. */
int fzn_messages_read_position(const fzn_messages_t *m, const uint8_t contact[FZN_PUBKEY_LEN],
                               uint8_t id[FZN_MESSAGE_ID_LEN]);

/* HOW MANY IN LINES are newer than the read position -- all of them when
 * there is none -- counted down to FZN_MESSAGES_WALK_MAX lines, past which
 * `*more` is set and the count is a floor. */
fzn_messages_err_t fzn_messages_unread(const fzn_messages_t *m,
                                       const uint8_t contact[FZN_PUBKEY_LEN], size_t *count,
                                       int *more);

/*
 * A PAGE, newest first: lines with `contact`, from that conversation's index
 * alone, in the order this store learned of them; or with anyone for NULL,
 * every device's stream merged by when each was written. Past the first
 * `offset`, at most `cap` (FZN_MESSAGES_PAGE_MAX), `*count` of them, `*more`
 * nonzero when another follows. DEEP when `offset` and `cap` together pass
 * FZN_MESSAGES_WALK_MAX.
 */
fzn_messages_err_t fzn_messages_page(const fzn_messages_t *m,
                                     const uint8_t *contact, size_t offset, fzn_message_t *out,
                                     size_t cap, size_t *count, int *more);

/* `device`'s key for `contact` and `epoch`, held here: nonzero when it is. */
int fzn_messages_key_get(const fzn_messages_t *m, const uint8_t contact[FZN_PUBKEY_LEN],
                         uint32_t epoch, const uint8_t device[FZN_PUBKEY_LEN],
                         uint8_t key[FZN_CONVERSATION_KEY_LEN]);

/* KEEP `device`'s key for `contact` and `epoch`, carried from another of
 * the user's devices. THE FIRST HELD STANDS: the same key again is OK, and a
 * different one EQUIVOCATION, so a gift can neither replace a key nor bring
 * back one a rule destroyed and then dressed differently. */
fzn_messages_err_t fzn_messages_key_take(const fzn_messages_t *m,
                                         const uint8_t contact[FZN_PUBKEY_LEN], uint32_t epoch,
                                         const uint8_t device[FZN_PUBKEY_LEN],
                                         const uint8_t key[FZN_CONVERSATION_KEY_LEN]);

/* A line's key, seen by `fzn_messages_absorb`: `held` nonzero when this
 * store holds it. */
typedef void (*fzn_messages_seen_fn)(void *ctx, const uint8_t contact[FZN_PUBKEY_LEN],
                                     uint32_t epoch, const uint8_t device[FZN_PUBKEY_LEN],
                                     int held);

/*
 * ABSORB what every device's stream gained since `at` -- one entry per
 * device, parallel to `devices`, 0 to read from the beginning -- merged
 * oldest first by when each record was written. Every line's key is
 * reported to `seen` (may be NULL), held or not, so a caller learns which
 * keys to ask for and which of its own to give. Past how far the store had
 * already taken each stream in, a line joins its conversation's index, a
 * mark becomes its line's state when it is the newest, and a read position
 * becomes the conversation's when it is. `at` moves past every record
 * read; `*marks` (may be NULL) counts the marks taken in.
 */
fzn_messages_err_t fzn_messages_absorb(const fzn_messages_t *m, uint64_t *at,
                                       fzn_messages_seen_fn seen, void *ctx, size_t *marks);

/* REBUILD everything derived -- indexes, line states, read positions, how
 * far each stream was taken in -- from what the journal holds, every
 * device's records merged in the order they were written. What a lost or
 * doubted index is replaced with. `*marks` (may be NULL) counts marks. */
fzn_messages_err_t fzn_messages_reindex(const fzn_messages_t *m, size_t *marks);

/* DESTROY `contact`'s keys for `epoch`, this device's and every listed
 * device's, so that month's lines are shells here. For a trimming rule,
 * which is not built: nothing calls this by default. */
fzn_messages_err_t fzn_messages_forget_epoch(const fzn_messages_t *m,
                                             const uint8_t contact[FZN_PUBKEY_LEN],
                                             uint32_t epoch);

#endif /* FZN_MESSAGES_H */
