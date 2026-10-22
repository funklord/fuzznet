/*
 * WHAT CROSSES THE REMOTE HOP, BY WHAT AND WITH WHOM, sec 685: fuzzypickles'
 * traffic meter (`daemon/traffic_meter.h`, read at their 3fbcdc2) moved into
 * fuzznet, as sec 672 orders, counted by the family a payload belongs to
 * rather than by fzpd's frame command byte.
 *
 * A FAMILY is what a payload's head says it is, by `node/types.h`'s
 * registry: notes, members, messages, contact devices, the relay, the
 * introductions, groups, streams, file references, files (spool's
 * messages), the journal, reconciliation, logs, an extension's types, and
 * a verb line. A cause envelope (`log/cause.h`) is looked through. A FILE's
 * request names its root, which is the row's key, as fzpd keyed a blob's
 * transfer; every other family has none, its peer being the answer.
 *
 * ONE TABLE A FAMILY, fzpd's reason: a busy file transfer must not evict
 * the rows of a conversation somebody is reading. A full table evicts its
 * least recently active row and adds its bytes to the family's evicted
 * totals, so a family's sums stay whole. Telemetry, in memory only: a
 * restart begins again.
 *
 * BYTES ARE PAYLOAD, NOT FRAMES: what was asked and answered, before sealing
 * and after opening, where fzpd counted frame bytes. The difference is the
 * seal's overhead, which says nothing about what moved.
 *
 * A RATE is bytes a second over the last sampling window of
 * FZN_METER_WINDOW_S, the window closed by the first count past it.
 */
#ifndef FZN_NODE_METER_H
#define FZN_NODE_METER_H

#include <stddef.h>
#include <stdint.h>

#include "../local/vocabulary.h"
#include "../chain/authz.h"

typedef enum fzn_meter_family {
	FZN_METER_VERBS = 0,
	FZN_METER_NOTES,
	FZN_METER_MEMBERS,
	FZN_METER_MESSAGES,
	FZN_METER_CONTACT_DEVICES,
	FZN_METER_RELAY,
	FZN_METER_INTRODUCE,
	FZN_METER_GROUPS,
	FZN_METER_STREAMS,
	FZN_METER_FILE_REFS,
	FZN_METER_FILES,
	FZN_METER_JOURNAL,
	FZN_METER_RECONCILE,
	FZN_METER_LOGS,
	FZN_METER_EXTENSION,
	FZN_METER_OTHER,
	FZN_METER_FAMILIES
} fzn_meter_family_t;

#define FZN_METER_ROWS_MAX 64u
#define FZN_METER_PEER_MAX 64u
#define FZN_METER_KEY_MAX 32u
#define FZN_METER_WINDOW_S 5u

/* The family's name as `list transfer` says it. */
const char *fzn_meter_family_name(fzn_meter_family_t family);

/* WHAT `payload` IS: its family, and into `key` its root when it is a
 * file's request, `*key_len` 32, else 0. A cause envelope is looked
 * through; what reads as none of the families is OTHER. */
fzn_meter_family_t fzn_meter_family_of(const uint8_t *payload, size_t len,
                                       uint8_t key[FZN_METER_KEY_MAX], size_t *key_len);

typedef struct fzn_meter_row {
	char peer[FZN_METER_PEER_MAX + 1u];
	uint8_t key[FZN_METER_KEY_MAX];
	size_t key_len;
	uint64_t up, down;		/* bytes, since the row appeared */
	uint64_t first_seen, last_seen;	/* seconds */
	uint64_t rate_up, rate_down;	/* bytes a second, the last window */
	uint64_t window_start, window_up, window_down;
} fzn_meter_row_t;

typedef struct fzn_meter {
	fzn_meter_row_t rows[FZN_METER_FAMILIES][FZN_METER_ROWS_MAX];
	size_t n[FZN_METER_FAMILIES];
	uint64_t evicted_up[FZN_METER_FAMILIES], evicted_down[FZN_METER_FAMILIES];
} fzn_meter_t;

/* COUNT `up` bytes sent and `down` received of `family` with `peer` (text,
 * cut at FZN_METER_PEER_MAX) under `key`, at `now`, seconds. A new row
 * past the bound takes the least recently active one's place. */
void fzn_meter_count(fzn_meter_t *m, fzn_meter_family_t family, const char *peer,
                     const uint8_t *key, size_t key_len, uint64_t up, uint64_t down,
                     uint64_t now);

/* THE VERBS, this node's own user's:
 *
 *   get transfer            each family that has moved anything: `ok
 *                           FAMILY,UP,DOWN ...`, bytes since the start,
 *                           evicted rows' included.
 *   list transfer [FROM]    the rows, family by family: `ok TOTAL FROM
 *                           FAMILY,PEER,KEY,UP,DOWN,RATE_UP,RATE_DOWN,
 *                           FIRST,LAST ...`, as many as fit one reply from
 *                           the FROMth, KEY 64 hex or empty, RATE bytes a
 *                           second, FIRST and LAST seconds.
 *
 * 0 for a request that is not one. */
size_t fzn_meter_local(const fzn_meter_t *m, fzn_origin_t origin, const fzn_request_t *request,
                       char *reply, size_t cap);

#endif /* FZN_NODE_METER_H */
