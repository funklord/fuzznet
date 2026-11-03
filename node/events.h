/*
 * EVENTS PUSHED TO LOCAL SUBSCRIBERS, project.md sec 609: step 1 of the
 * move sec 608 lays out, since every UI needs to hear that something
 * changed rather than poll for it.
 *
 * A SUBSCRIBER is a local connection that asked `get events` and was
 * answered `ok events` (`node/local.h`); the node keeps it open and writes
 * it one line per change:
 *
 *     event SUBJECT NAME
 *
 * SUBJECT is the vocabulary's word for what changed -- `message`, `note`,
 * `file`, `setting` -- and NAME the item when it is known (a contact's
 * key, a note's id, a file's root, in hex), or `-` when the whole subject
 * should be read again. THIN ON PURPOSE, as fzpd's events are: an event
 * says what to fetch, and the fetch is the authority. A subscriber that
 * misses one loses nothing it cannot read again.
 *
 * NEVER BLOCKS THE NODE. A subscriber's socket is non-blocking, and one
 * that cannot take a whole line at once -- its buffer full, or gone -- is
 * dropped and closed. It reconnects and reads everything again, which is
 * what it must do after any gap anyway. A subscriber that writes anything,
 * or hangs up, is dropped too: after `ok events` the connection is the
 * node's to write and the client's to read.
 *
 * FZN_NODE_EVENTS_MAX subscribers at once, fzpd's own bound; past it a
 * `get events` is not taken.
 */
#ifndef FZN_NODE_EVENTS_H
#define FZN_NODE_EVENTS_H

#include <stddef.h>
#include <stdint.h>

#define FZN_NODE_EVENTS_MAX 8u
/* The longest SUBJECT and NAME: a word, and a 64-hex-digit key. */
#define FZN_NODE_EVENTS_SUBJECT_MAX 16u
#define FZN_NODE_EVENTS_NAME_MAX 64u

/* THE EVENTS KEPT, sec 866: the last this many published, each numbered,
 * so a reader that cannot hold a subscription -- an estate member asking
 * across the round -- asks what happened since its cursor and is told
 * when it fell behind. */
#define FZN_NODE_EVENTS_KEPT 256u

typedef struct fzn_node_event_kept {
	uint64_t seq;
	char subject[FZN_NODE_EVENTS_SUBJECT_MAX + 1u];
	char name[FZN_NODE_EVENTS_NAME_MAX + 1u];
} fzn_node_event_kept_t;

typedef struct fzn_node_events {
	int fds[FZN_NODE_EVENTS_MAX];
	size_t n;
	/* NUMBERED FROM 1, the next to be published's; the kept a ring. */
	uint64_t next;
	fzn_node_event_kept_t kept[FZN_NODE_EVENTS_KEPT];
	/* Subscribers dropped for a full buffer or a closed socket, and lines
	 * written, since init: for a status line and a test. */
	size_t dropped;
	size_t sent;
} fzn_node_events_t;

void fzn_node_events_init(fzn_node_events_t *ev);

/* Whether another subscriber would be taken. */
int fzn_node_events_room(const fzn_node_events_t *ev);

/* TAKE `fd` AS A SUBSCRIBER: owned from here, made non-blocking. 0 when
 * there is no room or the descriptor will not be made non-blocking, and
 * then `fd` is still the caller's. */
int fzn_node_events_add(fzn_node_events_t *ev, int fd);

/* PUBLISH `event SUBJECT NAME` to every subscriber. SUBJECT a lowercase
 * word, NAME lowercase hex or `-` (NULL for `-`); anything else is not
 * written, so no subscriber ever reads a line it cannot split. How many
 * subscribers took it. */
size_t fzn_node_events_publish(fzn_node_events_t *ev, const char *subject, const char *name);

/* WHAT HAPPENED SINCE `from`, sec 866, into `out` (`cap` bytes) as
 *
 *     NEXT FIRST [SUBJECT NAME]...
 *
 * NEXT the number to ask from next time, FIRST the oldest still kept: a
 * reader whose `from` is below FIRST missed some, and one whose `from` is
 * past NEXT is asking a node that started again -- either reads its state
 * again, as a dropped subscriber does. The events at or past `from`,
 * oldest first, as many as keep the page's `%XX`-escaped size within
 * `escaped_cap` (`local/escape.h`: a space costs three). Its length, or 0
 * when not even NEXT FIRST fits. */
size_t fzn_node_events_since(const fzn_node_events_t *ev, uint64_t from, char *out, size_t cap,
                             size_t escaped_cap);

/* SUBSCRIBER `fd` WAS READY TO READ: it hung up or spoke, and is dropped.
 * 0 when `fd` is not one of them. */
int fzn_node_events_ready(fzn_node_events_t *ev, int fd);

/* Every subscriber closed. */
void fzn_node_events_close(fzn_node_events_t *ev);

#endif /* FZN_NODE_EVENTS_H */
