/*
 * A STATUS, project.md sec 1076, in wire/ since sec 1078 so any layer reads
 * one -- a log's gatherer as well as the node: a host's answer to another that carries no
 * data -- ok, or why not -- in binary, where it was a text line the asker read
 * by its first letter (sec 455) and parsed (`ok`, `denied WHY`). The holder's,
 * sec 1061: no control between hosts rests on parsing text.
 *
 *     2 | FZN_TYPE_STATUS | CODE | WHY_LEN | WHY
 *
 * DESCRIBED BY wire/status.situ, whose generated reader and builder these
 * call; the codes here are the schema's, held equal to it where status.c is
 * compiled. CODE is what the asker decides on. WHY is for a person reading a
 * log and is never parsed: a host with no reason to give sends none.
 */
#ifndef FZN_NODE_STATUS_H
#define FZN_NODE_STATUS_H

#include "cmd.h"
#include <stddef.h>
#include <stdint.h>

/* ITS TYPE in version 2, allocated in node/types.h's registry as
 * FZN_TYPE_STATUS. */
#define FZN_STATUS_TYPE 65u
#define FZN_STATUS_HEAD_LEN 4u
#define FZN_STATUS_WHY_MAX 200u
#define FZN_STATUS_LEN_MAX (FZN_STATUS_HEAD_LEN + FZN_STATUS_WHY_MAX)

typedef enum fzn_status {
	FZN_STATUS_OK = 0,
	FZN_STATUS_DENIED = 1,      /* not this asker's to ask */
	FZN_STATUS_MALFORMED = 2,   /* the request was not one */
	FZN_STATUS_ERROR = 3,       /* this host could not */
	FZN_STATUS_UNSUPPORTED = 4, /* this host does no such thing */
	FZN_STATUS_SHEDDING = 5,    /* this host is loaded and sheds this kind now */
	FZN_STATUS_BUSY = 6         /* this host is taking turns: ask again */
} fzn_status_t;

/* A STATUS WRITTEN into `out`: its length, 0 when `cap` is short or `code` is
 * none of the above. `why` may be NULL; past FZN_STATUS_WHY_MAX it is cut. */
size_t fzn_status_write(uint8_t *out, size_t cap, fzn_status_t code, const char *why);

/* `in` READ AS A STATUS: 1 with its code, and its reason pointing into `in`,
 * `*why_len` long; 0 when it is no status or its shape is wrong. `why` and
 * `why_len` may be NULL. */
int fzn_status_read(const uint8_t *in, size_t len, fzn_status_t *code, const uint8_t **why,
                    size_t *why_len);

/* The code's name, as a log says it -- `ok`, `denied`, ... -- "unknown" for none. */
const char *fzn_status_name(fzn_status_t code);

#endif /* FZN_NODE_STATUS_H */
