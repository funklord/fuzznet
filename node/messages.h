/* A node's conversations: `messages/messages.h` behind the daemon's verbs,
 * its devices' streams followed, and conversation keys carried between the
 * user's devices. project.md sec 527, phase 2 of the message move.
 *
 * THE DEVICES are this node and the estate's other nodes -- the user's
 * devices -- whose FZN_MESSAGE_STREAM the journal follows here, so the
 * journal's own pull and push carry their lines and marks both ways. A
 * listing merges them.
 *
 * WHAT A PULL BRINGS IS ABSORBED (`fzn_node_messages_absorb`) from where the
 * last absorb left each device's stream, from the beginning at start: marks
 * become line states, and each line's key is noted -- a key this node lacks
 * is asked for, and one this node drew is given.
 *
 * KEYS TRAVEL MEMBER TO MEMBER, over the authenticated remote hop, in the
 * four messages of `messages/keys.situ`: GIVE (a device's own keys, which is
 * how a hub that pulls from nobody comes by them), GIVEN, WANT (keys for
 * lines this node holds and cannot open) and KEYS. A key given is taken only
 * as the giver's own; the first key held stands. A contact's request never
 * reaches here.
 *
 * NOTHING IS DELETED BY DEFAULT, as sec 526 records the holder deciding:
 * there is no verb that removes a line, and only a retention rule the user
 * set trims one (sec 531).
 *
 * HOSTING IT IN-PROCESS, without fuzznetd (sec 530), is this order, and
 * `node/test/messages_test`'s two-host case runs it end to end over two
 * stores joined only by the exchange:
 *
 *   start   fzn_node_journal_init over the host's store; fzn_node_messages_init;
 *           fzn_node_messages_devices with the user's other devices; then
 *           `fzn_messages_upgrade` on `.m`, once, which keeps a store from
 *           before sec 536 in rows.
 *   serve   a member's request to `fzn_node_journal_answer` first, then to
 *           `fzn_node_messages_remote`; after an answered PUSH, absorb
 *           (`fzn_node_messages_absorb`), or a hub never sees what its
 *           members push.
 *   round   with each device it pulls from: `fzn_node_journal_pull`,
 *           `fzn_node_journal_push`, `fzn_node_messages_absorb`, then
 *           `fzn_node_messages_round`. Run one straight after a write to
 *           send it at once; fuzznetd does on `fresh`.
 *
 * The transport is the host's: `ask` is whatever carries a request to the
 * other device and its answer back.
 */

#ifndef FZN_NODE_MESSAGES_H
#define FZN_NODE_MESSAGES_H

#include <stddef.h>
#include <stdint.h>

#include "../chain/authz.h"
#include "../local/vocabulary.h"
#include "../messages/messages.h"
#include "buckets.h"

/* `messages/keys.situ`: notes-sync's version byte, types after notes' 22. */
#define FZN_NODE_MESSAGES_VERSION 2u
#define FZN_NODE_MESSAGES_GIVE 23u
#define FZN_NODE_MESSAGES_GIVEN 24u
#define FZN_NODE_MESSAGES_WANT 25u
#define FZN_NODE_MESSAGES_KEYS 26u
/* DELIVERY TO A CONTACT, sec 613, `messages/deliver.situ`: DELIVER carries
 * one line, DELIVERED answers it HELD or REFUSED. */
#define FZN_NODE_MESSAGES_DELIVER 27u
#define FZN_NODE_MESSAGES_DELIVERED 28u
#define FZN_NODE_MESSAGES_DELIVER_HEAD_LEN (2u + FZN_MESSAGE_ID_LEN + 8u + 2u)
#define FZN_NODE_MESSAGES_DELIVER_MAX (FZN_NODE_MESSAGES_DELIVER_HEAD_LEN + FZN_MESSAGE_TEXT_MAX)
#define FZN_NODE_MESSAGES_DELIVERED_LEN (2u + FZN_MESSAGE_ID_LEN + 1u)
#define FZN_NODE_MESSAGES_REFUSED 0u
#define FZN_NODE_MESSAGES_HELD 1u
/* HELD, and by every device of the recipient that keeps messages, sec
 * 615: the line is settled. */
#define FZN_NODE_MESSAGES_SETTLED 2u
/* SETTLEMENT BETWEEN MEMBERS, sec 615, `messages/deliver.situ`: HOLDS asks
 * a member whether it holds a line's item; HOLDING answers LACKS, HOLDS
 * or DECLINES -- it keeps none of that conversation's lines. */
#define FZN_NODE_MESSAGES_HOLDS 33u
#define FZN_NODE_MESSAGES_HOLDING 34u
#define FZN_NODE_MESSAGES_HOLDS_LEN (2u + FZN_PUBKEY_LEN + FZN_BUCKETS_ID_LEN)
#define FZN_NODE_MESSAGES_HOLDING_LEN (2u + FZN_BUCKETS_ID_LEN + 1u)
#define FZN_NODE_MESSAGES_LACKS 0u
#define FZN_NODE_MESSAGES_HOLDS_IT 1u
#define FZN_NODE_MESSAGES_DECLINES 2u
#define FZN_NODE_MESSAGES_PER 8u
#define FZN_NODE_MESSAGES_HEAD_LEN 3u
#define FZN_NODE_MESSAGES_GIVEN_LEN 4u
#define FZN_NODE_MESSAGES_ENTRY_LEN (FZN_PUBKEY_LEN + 4u + FZN_PUBKEY_LEN)
#define FZN_NODE_MESSAGES_HELD_LEN (FZN_NODE_MESSAGES_ENTRY_LEN + FZN_CONVERSATION_KEY_LEN)
#define FZN_NODE_MESSAGES_REQUEST_MAX                                                          \
	(FZN_NODE_MESSAGES_HEAD_LEN + FZN_NODE_MESSAGES_PER * FZN_NODE_MESSAGES_ENTRY_LEN)
#define FZN_NODE_MESSAGES_REPLY_MAX                                                            \
	(FZN_NODE_MESSAGES_HEAD_LEN + FZN_NODE_MESSAGES_PER * FZN_NODE_MESSAGES_HELD_LEN)

/* THE KEYS REMEMBERED BETWEEN ABSORBS, lacked and this node's own to give:
 * the struct's own room until the caller gives more
 * (`fzn_node_messages_use_keys`), told by `keys_wanted`. Past it they were
 * learned again only at the next start, and a line whose key was dropped
 * stayed unreadable until then. sec 704. Also the most a keys round asks
 * for at once: the rest are asked in the rounds after. */
#define FZN_NODE_MESSAGES_KEYS_MAX 64u

/* One conversation key's place: whose lines, which month, which device. */
typedef struct fzn_node_message_key {
	uint8_t contact[FZN_PUBKEY_LEN];
	uint32_t epoch;
	uint8_t device[FZN_PUBKEY_LEN];
} fzn_node_message_key_t;

/* Where a device's stream was last absorbed to. */
typedef struct fzn_node_message_cursor {
	uint8_t key[FZN_PUBKEY_LEN];
	uint64_t at;
} fzn_node_message_cursor_t;

/* A MONTH HELD BACK, sec 792: a conversation's month a peer holds that
 * this node's retention rules declined to fetch, and how many lines the
 * peer holds of it. */
typedef struct fzn_node_message_held_back {
	uint8_t contact[FZN_PUBKEY_LEN];
	uint32_t month;
	uint64_t lines;
} fzn_node_message_held_back_t;

typedef struct fzn_node_messages {
	fzn_messages_t m;
	/* THE DEVICES, sec 704: this node and the user's others, each with a
	 * cursor, an absorb's position and the core's working room -- four
	 * tables of `devices_cap`, the struct's own until the caller gives
	 * more (`fzn_node_messages_use_devices`). `devices_wanted` is how many
	 * a listing or a cursor found no room for, 0 when none did. They were
	 * 32, and the 33rd device was left out of every listing unsaid. */
	uint8_t (*devices)[FZN_PUBKEY_LEN];
	fzn_node_message_cursor_t *cursors;
	uint64_t *at;
	fzn_messages_work_t *work;
	size_t devices_cap, n_cursors, devices_wanted;
	/* THE KEYS, lacked and to give: `keys_cap` each. */
	fzn_node_message_key_t *lacks, *gives;
	size_t keys_cap, n_lacks, n_gives, keys_wanted;
	/* Keys noted past the room above. */
	size_t dropped;
	/* SET BY A WRITE THROUGH THE VERBS, sec 528, so the daemon pushes it
	 * now rather than at its next round; the daemon clears it. */
	int fresh;
	/* EACH LINE'S ITEM, by conversation and month (sec 564): kept as lines
	 * are taken, so a device away past the journal's window is handed them
	 * by `fzn_reconcile_buckets`. `m.items` points here. */
	fzn_buckets_t buckets;
	fzn_messages_items_t items;
	/* WHETHER THIS HOST KEEPS `contact`'S LINES, sec 615, by its own rules
	 * -- asked when a member asks whether it holds a line, since only this
	 * host knows the rules that reach it. NULL keeps every conversation. */
	int (*keeps)(void *ctx, const uint8_t contact[FZN_PUBKEY_LEN]);
	void *keeps_ctx;
	/* WHETHER THIS DEVICE SENDS A LINE ANOTHER DEVICE WROTE, sec 616: its
	 * writer is gone, and this device is the one of the user's devices
	 * left to take over. The caller holds the roster and when each device
	 * was last heard from. NULL: every device sends only its own. */
	int (*takes_over)(void *ctx, const uint8_t writer[FZN_PUBKEY_LEN],
	                  const uint8_t id[FZN_MESSAGE_ID_LEN]);
	void *takes_over_ctx;
	/* THE MONTHS HELD BACK at the last conversations pass, sec 792, the
	 * caller's table: `get message held-back` reads them, so a client can
	 * say how much older history the rules kept off this device and offer
	 * to change them. NULL and 0 for none. */
	const fzn_node_message_held_back_t *held_back;
	size_t n_held_back;
	/* THE OWN ROOM the tables above start on. */
	uint8_t own_devices[FZN_MESSAGES_DEVICES_MAX][FZN_PUBKEY_LEN];
	fzn_node_message_cursor_t own_cursors[FZN_MESSAGES_DEVICES_MAX];
	uint64_t own_at[FZN_MESSAGES_DEVICES_MAX];
	fzn_messages_work_t own_work[FZN_MESSAGES_DEVICES_MAX];
	fzn_node_message_key_t own_lacks[FZN_NODE_MESSAGES_KEYS_MAX];
	fzn_node_message_key_t own_gives[FZN_NODE_MESSAGES_KEYS_MAX];
} fzn_node_messages_t;

typedef struct fzn_node_messages_tally {
	size_t marks;    /* marks absorbed */
	size_t given;    /* keys a peer took */
	size_t refused;  /* keys a peer refused, another being held there */
	size_t taken;    /* keys taken from a peer */
	size_t lacking;  /* keys still lacked */
	size_t read;     /* devices whose stream gained records this absorb (sec 609) */
} fzn_node_messages_tally_t;

/* Point `nm` at its store, journal and this node's key. All borrowed. */
fzn_messages_err_t fzn_node_messages_init(fzn_node_messages_t *nm,
                                          const fzn_persist_ops_t *store,
                                          fzn_node_journal_t *journal, const uint8_t *issuer,
                                          const fzn_sign_ops_t *sign,
                                          const fzn_random_ops_t *rng,
                                          const fzn_aead_ops_t *aead,
                                          const fzn_hash_ops_t *hash, uint64_t (*now)(void));

/* LARGER TABLES OF THE CALLER'S, sec 704, what is held copied over; each
 * must outlive `nm`. For the devices: `devices`, `cursors`, `at` and `work`,
 * `cap` of each. For the keys: `lacks` and `gives`, `cap` of each. 0 for
 * room smaller than what is held. */
int fzn_node_messages_use_devices(fzn_node_messages_t *nm, uint8_t (*devices)[FZN_PUBKEY_LEN],
                                  fzn_node_message_cursor_t *cursors, uint64_t *at,
                                  fzn_messages_work_t *work, size_t cap);
int fzn_node_messages_use_keys(fzn_node_messages_t *nm, fzn_node_message_key_t *lacks,
                               fzn_node_message_key_t *gives, size_t cap);

/* THE DEVICES: this node first, then `keys` (`n` of them) not already
 * listed, each one's FZN_MESSAGE_STREAM followed in the journal. How many
 * are listed; one past `devices_cap` is left out and `devices_wanted` set,
 * and one the journal has no room to follow is left out. */
size_t fzn_node_messages_devices(fzn_node_messages_t *nm, const uint8_t (*keys)[FZN_PUBKEY_LEN],
                                 size_t n);

/* ABSORB every device's stream from where it was last absorbed. */
fzn_messages_err_t fzn_node_messages_absorb(fzn_node_messages_t *nm,
                                            fzn_node_messages_tally_t *tally);

/* A LINE GIVEN UP ON, secs 607 and 616: every OUT line still HANDED_OVER
 * in the conversation of a contact that no longer stands, and every one
 * still being sent -- no mark -- to a contact that was REMOVED -- `stands`
 * and `removed` say, for the caller holds the contact list and the roster;
 * a key that was never a contact is not removed, and its lines wait --
 * marked NOT_DELIVERED, so every device of the user
 * reads, through the journal, that no device will send it (fuzzypickles'
 * sec 196, recorded in sec 510). The one way a line stops short of being
 * delivered: the delivery itself never gives up (sec 610). Conversations
 * are found by their buckets, so one whose contact was removed is among
 * them. Every line is reached, however deep, by `fzn_messages_owed`.
 * `*marked` counts. */
fzn_messages_err_t fzn_node_messages_give_up(fzn_node_messages_t *nm,
                                             int (*stands)(void *ctx,
                                                           const uint8_t contact[FZN_PUBKEY_LEN]),
                                             int (*removed)(void *ctx,
                                                            const uint8_t contact[FZN_PUBKEY_LEN]),
                                             void *ctx, size_t *marked);

/* PAST A GAP: `device`'s stream moved up to `to` under a peer's base
 * (sec 552), so its cursor is moved there too, never back. */
void fzn_node_messages_skip(fzn_node_messages_t *nm, const uint8_t device[FZN_PUBKEY_LEN],
                            uint64_t to);

/* WHERE `device`'S CONVERSATIONS STREAM MAY BE CUT, sec 548: below the first
 * record issued at or after `older_than_ms`, no further than this run has
 * absorbed, and never between a line's parts -- a line's first part is read
 * back from the journal when its last is taken in. The stream's base when
 * nothing may go. */
uint64_t fzn_node_messages_cut_point(fzn_node_messages_t *nm, const uint8_t device[FZN_PUBKEY_LEN],
                                     uint64_t older_than_ms);

/* A LINE RECONCILED, sec 564: an item of conversation `contact`'s month
 * `epoch`, filed by `fzn_messages_file`. REFUSED for one that belongs to
 * another bucket than it came from. A line whose key is not here sets
 * `*waiting` (may be NULL), and its key is lacked and asked for. */
fzn_messages_err_t fzn_node_messages_file(fzn_node_messages_t *nm,
                                          const uint8_t contact[FZN_PUBKEY_LEN], uint32_t epoch,
                                          const uint8_t *item, size_t len, int *waiting);

/* A LINE THIS NODE PUSHED, sec 569, and the peer kept: an item as
 * `fzn_messages_file` reads it. When this device wrote it, its month's key
 * is noted to give at the next round -- the peer holds no stream of this
 * node's to learn the line from, and so no want of its own to ask with. A
 * line another device wrote is that device's key to give. */
void fzn_node_messages_pushed(fzn_node_messages_t *nm, const uint8_t contact[FZN_PUBKEY_LEN],
                              uint32_t epoch, const uint8_t *item, size_t len);

/* How a node asks a member: send `request`, fill `reply`. Nonzero on an
 * answer. */
typedef int (*fzn_node_messages_ask_t)(void *ctx, const uint8_t *request, size_t request_len,
                                       uint8_t *reply, size_t reply_cap, size_t *reply_len);

/* ONE ROUND WITH A MEMBER: give it this node's keys, and ask it for those
 * lacked. A key it takes or refuses is given no more; one it supplies is
 * lacked no more. 0 when it would not answer. */
int fzn_node_messages_round(fzn_node_messages_t *nm, fzn_node_messages_ask_t ask, void *ctx,
                            fzn_node_messages_tally_t *tally);

/* THE SAME ROUND WITH ONE MEMBER AS STEPS, sec 636: begin writes the first
 * request, or sets `*done` with nothing to give or ask; each step takes its
 * answer -- NULL for none -- and writes the next, or sets `*done`. 0 from
 * either when the member would not answer, which ends it, as above.
 * `request` is the caller's, at least FZN_NODE_MESSAGES_REQUEST_MAX, held
 * between steps: a give's keys are written into it and wiped by the step
 * its answer comes to. An answer's keys are the caller's to wipe once the
 * step has taken them. The tally is the struct's. */
typedef struct fzn_node_messages_rounding {
	fzn_node_messages_t *nm;
	int phase;
	size_t n, sent;  /* the batch asked, and a give's length */
	size_t asks;     /* requests made, bounded */
	size_t i, total; /* the wants, from a copy of what is lacked */
	fzn_node_message_key_t asked[FZN_NODE_MESSAGES_KEYS_MAX];
	fzn_node_messages_tally_t tally;
} fzn_node_messages_rounding_t;

int fzn_node_messages_round_begin(fzn_node_messages_rounding_t *r, fzn_node_messages_t *nm,
                                  uint8_t *request, size_t cap, size_t *request_len, int *done);

int fzn_node_messages_round_step(fzn_node_messages_rounding_t *r, const uint8_t *reply,
                                 size_t reply_len, uint8_t *request, size_t cap,
                                 size_t *request_len, int *done);

/* A MEMBER'S GIVE or WANT, answered; 0 for anything else, so a caller
 * dispatching on the first bytes falls through. `sender` is the member. */
size_t fzn_node_messages_remote(void *ctx, const uint8_t *sender, const uint8_t *request,
                                size_t request_len, uint8_t *reply, size_t reply_cap);

/* HOW A DELIVERY WENT, sec 613. */
typedef struct fzn_node_messages_delivery {
	size_t sent;      /* lines offered */
	size_t delivered; /* answered held, and marked delivered here */
	size_t settled;   /* answered settled, and marked settled here (sec 615) */
	size_t refused;   /* the host keeps no messages: the rest wait for another */
	size_t unanswered;
} fzn_node_messages_delivery_t;

/*
 * DELIVER TO `contact`, sec 613: every OUT line of that conversation still
 * being sent -- no mark -- that THIS device wrote, or takes over from a
 * writer gone (`takes_over`, sec 616), and can read, offered one
 * at a time through `ask`, the contact's host; with `settle`, also every
 * one DELIVERED and not yet settled (sec 615). A line answered HELD is
 * marked DELIVERED, one answered SETTLED is marked SETTLED, which the
 * user's other devices learn by the journal.
 * Stops at the first line refused, since the host refuses for every line
 * alike, and at the first unanswered, since a host that does not answer
 * one will not answer the next. Every line still owed is reached, oldest
 * first, however deep (`fzn_messages_owed`, sec 613).
 */
fzn_messages_err_t fzn_node_messages_deliver(fzn_node_messages_t *nm,
                                             const uint8_t contact[FZN_PUBKEY_LEN], int settle,
                                             fzn_node_messages_ask_t ask, void *ctx,
                                             fzn_node_messages_delivery_t *tally);

/* THE SAME DELIVERY AS STEPS, sec 636: begin writes the first line's offer,
 * or sets `*done` with none to offer; each step takes its answer -- NULL for
 * none -- and writes the next offer, or sets `*done` once a line is refused
 * or unanswered, or none is left. `request` is the caller's, at least
 * FZN_NODE_MESSAGES_DELIVER_MAX. Its place is held between steps and its
 * page read again each step, so it keeps no page of lines. The tally is the
 * struct's. */
typedef struct fzn_node_messages_delivering {
	fzn_node_messages_t *nm;
	uint8_t contact[FZN_PUBKEY_LEN];
	int settle, live;
	uint64_t at;                   /* the index place to look from */
	uint8_t id[FZN_MESSAGE_ID_LEN]; /* the line offered, and its state then */
	uint8_t state;
	fzn_node_messages_delivery_t tally;
} fzn_node_messages_delivering_t;

fzn_messages_err_t fzn_node_messages_deliver_begin(fzn_node_messages_delivering_t *d,
                                                   fzn_node_messages_t *nm,
                                                   const uint8_t contact[FZN_PUBKEY_LEN],
                                                   int settle, uint8_t *request, size_t cap,
                                                   size_t *request_len, int *done);

fzn_messages_err_t fzn_node_messages_deliver_step(fzn_node_messages_delivering_t *d,
                                                  const uint8_t *reply, size_t reply_len,
                                                  uint8_t *request, size_t cap,
                                                  size_t *request_len, int *done);

/*
 * A CONTACT'S DELIVERY, answered, sec 613; 0 for anything else. `contact`
 * is the conversation the line is filed under -- the sender, as the
 * caller resolved it -- and `keeps` whether this host keeps that
 * conversation's lines (`fzn_messages_keeps`). Kept: filed as an IN line
 * unless held already, and answered HELD either way -- SETTLED once the
 * line is marked settled here (sec 615) -- so a re-offer is idempotent on
 * the line's id. Not kept: answered REFUSED, nothing filed.
 */
size_t fzn_node_messages_contact(fzn_node_messages_t *nm, const uint8_t contact[FZN_PUBKEY_LEN],
                                 int keeps, const uint8_t *request, size_t request_len,
                                 uint8_t *reply, size_t reply_cap);

/* ONE MEMBER A SETTLEMENT ASKS, sec 615: its key, and how to reach it --
 * `ask` NULL for a member this node cannot reach, which never answers. */
typedef struct fzn_node_messages_member {
	const uint8_t *key;
	fzn_node_messages_ask_t ask;
	void *ctx;
} fzn_node_messages_member_t;

typedef struct fzn_node_messages_settlement {
	size_t weighed;  /* lines this node filed IN and not yet settled */
	size_t settled;  /* marked settled this pass */
	size_t waiting;  /* a member lacks it, or did not answer */
} fzn_node_messages_settlement_t;

/*
 * SETTLE, sec 615: every IN line THIS node wrote -- a contact's line it
 * filed -- and not yet marked settled, at most `cap` of them a pass: its
 * item asked of each of `members` (the estate's other devices), and marked
 * SETTLED once every one answers that it holds it or keeps none of that
 * conversation. A member that lacks it or does not answer leaves it for a
 * later pass. The mark reaches the user's other devices by the journal,
 * and any of them answers a re-offer SETTLED from then.
 */
fzn_messages_err_t fzn_node_messages_settle(fzn_node_messages_t *nm,
                                            const fzn_node_messages_member_t *members,
                                            size_t n_members, size_t cap,
                                            fzn_node_messages_settlement_t *tally);

/*
 * THE VERBS, for this node's own user only; 0 for what is not one. WHO is a
 * contact's name or its key in hex, ID 32 hex digits, the text the rest of
 * the line with %XX undone (so a newline is %0a) or `file PATH`:
 *
 *   add message WHO out|in ID [at MS] TEXT | file PATH
 *       TEXT one escaped word, a space as %20; PATH absolute (sec 651)
 *   set message WHO out|in ID delivered|settled|handed-over|not-delivered
 *   set message WHO read ID
 *   get message WHO unread
 *   get message owed            `ok HELD DELIVERED MORE`, this host's lines to
 *                               contacts not yet delivered, and delivered
 *                               and not settled (sec 661)
 *   get message [WHO] held-back `ok MONTHS LINES NEWEST`, the months of
 *                               older history this node's retention rules
 *                               declined to fetch at the last conversations
 *                               pass -- every conversation's, or WHO's --
 *                               the lines a peer holds of them, and the
 *                               newest of those months (months since 1970,
 *                               `fzn_message_epoch_of`), 0 for none (sec 792)
 *   list message [WHO] [FROM]
 *
 * `get message WHO unread` answers `ok COUNT MORE`, MORE 1 when the count
 * is a floor. A listing answers `ok FROM SHOWN MORE` then each line as
 * KEY,NAME,ID,DIRECTION,STATE,STIME,WRITTEN,READABLE,TEXT -- NAME `-` for a
 * key no contact holds, STATE `-` for none, TEXT escaped -- as many as fit;
 * the next page is asked FROM + SHOWN. In a listing a word of digits
 * alone is FROM, unless it is a whole key's 64 hex digits, which is WHO.
 */
size_t fzn_node_messages_local(void *ctx, fzn_origin_t origin, const fzn_request_t *request,
                               char *reply, size_t reply_cap);

#endif /* FZN_NODE_MESSAGES_H */
