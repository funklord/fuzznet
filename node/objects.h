/*
 * NAMED OBJECTS, project.md sec 948: `living_room_lamp` = on or off. One host
 * sets it and another reads it, hears of the change, or polls it. The holder's,
 * for embedded, 2026-11-07.
 *
 * AN OBJECT IS TWO MEMBERS OF RESERVED LISTS (sec 854): `object` holds what it
 * may be and `object-value` what it is. So it is carried between the estate's
 * hosts as records are, resolves newest first and the same on every host, keeps
 * who set it and when, survives a host being away, and its deciding record is
 * never trimmed. Nothing here is a second store.
 *
 * WHO MAY: the gate is at the host that signs, as for any verb and call. Local
 * callers go by `local/permit/object`, other hosts and devices by
 * `remote/permit/object` (sec 921). An estate is one user's (its members are
 * trusted alike), so a host does not second-guess another's record.
 *
 * A DEVICE HAS ONLY `call` (sec 912): the procedure `object`, with `get NAME`
 * or `set NAME VALUE`, answered with the value alone, as airtime is the limit.
 * Its gateway signs for it and names it, so a value says who set it.
 */
#ifndef FZN_NODE_OBJECTS_H
#define FZN_NODE_OBJECTS_H

#include <stddef.h>
#include <stdint.h>

#include "rate.h"
#include "records.h"

#define FZN_NODE_OBJECT_LIST "object"
#define FZN_NODE_OBJECT_VALUE_LIST "object-value"

/* A NAME, a-z 0-9 and `_`: its hex is an event's name, at most 64 bytes. */
#define FZN_NODE_OBJECT_NAME_MAX 32u
/* A VALUE, one word of A-Z a-z 0-9 `_` `.` `-`, and never `-` alone, which is
 * how a listing says none has been set. */
#define FZN_NODE_OBJECT_VALUE_MAX 64u

typedef struct fzn_node_objects {
	const fzn_node_records_t *records;
	/* TOLD OF A CHANGE MADE HERE. May be NULL. One filed from a peer the
	 * caller learns of by `fzn_node_object_of_key`. */
	void (*changed)(const uint8_t *name, size_t name_len);
	/* HOW OFTEN A VALUE IS WRITTEN, sec 1034, when set: a set within its object's
	 * window is held, the newest standing, and written by `fzn_node_objects_due`
	 * once the window has passed -- a button pressed a thousand times a second
	 * is written once a window, and carried as often. `held` told the first time
	 * an object is held after passing freely, for one line to be said. */
	fzn_rate_t *rate;
	void (*held)(const uint8_t *name, size_t name_len);
} fzn_node_objects_t;

/* AN OBJECT'S WINDOW: the rate gate's floor, until the schema declares one per
 * object (sec 1034). */
#define FZN_NODE_OBJECT_EVERY_MS 1000u

typedef struct fzn_node_object {
	char name[FZN_NODE_OBJECT_NAME_MAX + 1u];
	size_t name_len;
	char value[FZN_NODE_OBJECT_VALUE_MAX + 1u]; /* "" while none was set */
	size_t value_len;
	uint64_t at;                                /* when it was set, ms; 0 if never */
	uint8_t by[FZN_PUBKEY_LEN];                 /* who set it */
	uint8_t allowed[FZN_SETTING_VALUE_MAX];     /* `on|off`, or `*` for any word */
	size_t allowed_len;
} fzn_node_object_t;

typedef enum fzn_node_object_err {
	FZN_NODE_OBJECT_OK = 0,
	FZN_NODE_OBJECT_MALFORMED = -1, /* a name or value out of shape */
	FZN_NODE_OBJECT_ABSENT = -2,    /* no such object */
	FZN_NODE_OBJECT_REFUSED = -3,   /* a value it may not have */
	FZN_NODE_OBJECT_EXISTS = -4,    /* made already, with other values */
	FZN_NODE_OBJECT_BACKEND = -5,   /* not read, or not kept */
	FZN_NODE_OBJECT_HELD = 1        /* taken, and held to its window (sec 1034) */
} fzn_node_object_err_t;

/* MAKE ONE: `allowed` as the object holds it. The same object again is OK and
 * writes nothing, so a host may say so at each start. */
fzn_node_object_err_t fzn_node_object_add(const fzn_node_objects_t *o, const uint8_t *name,
                                          size_t name_len, const uint8_t *allowed,
                                          size_t allowed_len);

/* SET ONE, for `by` (a device its gateway speaks for), NULL for this host.
 *
 * PAST THE NEWEST VALUE HELD, whatever this host's clock says: lists resolve by
 * version, so a host whose clock is behind would otherwise never change what
 * every host reads (sec 722's fault). A set made after reading always takes. */
fzn_node_object_err_t fzn_node_object_set(const fzn_node_objects_t *o, const uint8_t *name,
                                          size_t name_len, const uint8_t *value, size_t value_len,
                                          const uint8_t *by);

fzn_node_object_err_t fzn_node_object_get(const fzn_node_objects_t *o, const uint8_t *name,
                                          size_t name_len, fzn_node_object_t *out);

/* THE HELD VALUES WHOSE WINDOW HAS PASSED at `now_ms`, written: how many, sec 1034.
 * The daemon calls it each pass. */
size_t fzn_node_objects_due(const fzn_node_objects_t *o, uint64_t now_ms);

fzn_node_object_err_t fzn_node_object_remove(const fzn_node_objects_t *o, const uint8_t *name,
                                             size_t name_len);

/* THE OBJECT A RECORD'S KEY IS OF: its name's length, into `name`, or 0 for a key
 * that is no object's. */
size_t fzn_node_object_of_key(const uint8_t *key, size_t key_len,
                              char name[FZN_NODE_OBJECT_NAME_MAX + 1u]);

/* The verbs, as a local handler, `ctx` a `fzn_node_objects_t`; 0 for a request
 * that is not one:
 *
 *     add object NAME [VALUE...]  allowed values, none for any word
 *     set object NAME VALUE
 *     get object NAME             ok VALUE AT BY ALLOWED, or ok absent
 *     list object [FROM]          ok FROM SHOWN MORE, then NAME,VALUE,AT,BY,ALLOWED
 *     remove object NAME
 *
 * VALUE and BY are `-` while none was set. */
/* EVERY OBJECT, in the order `list object` gives them, each handed to `each`
 * with its value: a page at a time, as that verb reads them. 0 when the lists
 * could not be read; 1 otherwise, none included. */
int fzn_node_objects_each(const fzn_node_objects_t *o,
                          void (*each)(void *ctx, const fzn_node_object_t *x), void *ctx);
size_t fzn_node_objects_local(void *ctx, fzn_origin_t origin, const fzn_request_t *request,
                              char *reply, size_t reply_cap);

/* The procedure `object`: `get NAME` or `set NAME VALUE`, for `caller`, NULL for
 * a local one. The value's length in `answer`, 0 for one refused. */
size_t fzn_node_object_call(const fzn_node_objects_t *o, const uint8_t *caller,
                            const uint8_t *args, size_t args_len, uint8_t *answer, size_t cap);

#endif /* FZN_NODE_OBJECTS_H */
