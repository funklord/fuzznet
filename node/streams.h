/*
 * APP STREAMS, project.md sec 632: step 6c of sec 608, fuzzypickles'
 * location frames (their 0x25/0x26) as the first consumer of a general
 * shape -- an opaque, named stream each host writes, read by its user's own
 * hosts and by whoever it grants.
 *
 * A STREAM is a name the application chooses, `location` say, and each
 * host's records in it, numbered from 1. A record is OPAQUE: fuzznet never
 * learns what its bytes mean, the fix's encoding staying the application's
 * (sec 608's C list).
 *
 * RENDITIONS, NOT A TRANSFORM. fuzzypickles degrades a fix per contact --
 * exact, about 1 km, about 10 km -- when it answers. A daemon cannot call an
 * application's function, so the application writes each record AT EVERY
 * LEVEL it offers, level 0 the most exact, and a grant names the level a
 * recipient is given: the same choice, made where the encoding lives.
 *
 * WHO READS: this user's own hosts every level; a contact or a group's
 * members only as granted -- `grant stream NAME WHO LEVEL`, default deny --
 * and the coarsest rendition the record has when it has fewer levels than
 * the grant names. A host answers ONLY ABOUT ITS OWN STREAM, never another
 * host's it holds, fuzzypickles' rule: a contact may ask where you are, not
 * where your other contacts are.
 *
 * NOT SIGNED, and so not the journal: a record a contact holds is no proof
 * of where anybody was, as fuzzypickles' fixes never were. Carried in the
 * session that asked for it.
 *
 * BOUNDED: the newest FZN_STREAM_KEEP records of each (stream, host) are
 * kept, a ring, the oldest overwritten -- fuzzypickles' 1024 fixes, about
 * eight hours at thirty seconds.
 */
#ifndef FZN_NODE_STREAMS_H
#define FZN_NODE_STREAMS_H

#include <stddef.h>
#include <stdint.h>

#include "../persist/persist.h"
#include "../session/commitment.h" /* fzn_hash_ops_t */

#define FZN_STREAM_NAME_MAX 32u
#define FZN_STREAM_LEVELS_MAX 4u
#define FZN_STREAM_RENDITION_MAX 64u
#define FZN_STREAM_KEEP 1024u

typedef enum fzn_streams_err {
	FZN_STREAMS_OK = 0,
	FZN_STREAMS_ERR_MALFORMED = -1, /* a null, a name or record out of range */
	FZN_STREAMS_ERR_ABSENT = -2,    /* no such record or grant */
	FZN_STREAMS_ERR_DENIED = -3,    /* no grant for that reader */
	FZN_STREAMS_ERR_FULL = -4,      /* no longer answered, sec 704; kept for its value */
	FZN_STREAMS_ERR_BACKEND = -5,   /* the store refused, or cannot list */
	FZN_STREAMS_ERR_ROOM = -6       /* more than `cap`: `*count` says how many */
} fzn_streams_err_t;

const char *fzn_streams_err_str(fzn_streams_err_t err);

typedef struct fzn_stream_record {
	uint64_t seq;
	uint64_t at; /* seconds, when the host wrote it */
	size_t levels;
	uint8_t rendition[FZN_STREAM_LEVELS_MAX][FZN_STREAM_RENDITION_MAX];
	size_t rendition_len[FZN_STREAM_LEVELS_MAX];
} fzn_stream_record_t;

typedef struct fzn_streams {
	const fzn_persist_ops_t *store;
	const fzn_hash_ops_t *hash;
} fzn_streams_t;

/* A name a stream may have: 1 to FZN_STREAM_NAME_MAX of [a-z0-9_]. */
int fzn_stream_name_ok(const char *name, size_t len);

/* KEEP `r` as `origin`'s record in stream `name`, when it is newer than the
 * last kept -- one held already is OK and changes nothing -- the record
 * FZN_STREAM_KEEP before it going. A host appending its own passes the next
 * seq (`fzn_streams_last` + 1). */
fzn_streams_err_t fzn_streams_keep(const fzn_streams_t *s, const char *name, size_t name_len,
                                   const uint8_t origin[32], const fzn_stream_record_t *r);

/* The last record kept of `origin`'s in `name`, 0 for none. */
uint64_t fzn_streams_last(const fzn_streams_t *s, const char *name, size_t name_len,
                          const uint8_t origin[32]);

/* Every host whose records of `name` are held here, walked into `cap`:
 * ROOM with `*count` the number held when there are more. sec 704. */
fzn_streams_err_t fzn_streams_origins(const fzn_streams_t *s, const char *name, size_t name_len,
                                      uint8_t (*out)[32], size_t cap, size_t *count);

/* `origin`'s record `seq` in `name`. ABSENT when it is not kept, never
 * kept, or overwritten. */
fzn_streams_err_t fzn_streams_get(const fzn_streams_t *s, const char *name, size_t name_len,
                                  const uint8_t origin[32], uint64_t seq,
                                  fzn_stream_record_t *out);

/* GRANT `grantee` -- a contact's root or a group's id -- level `level` of
 * stream `name`, or with `level` negative take the grant away. */
fzn_streams_err_t fzn_streams_grant(const fzn_streams_t *s, const char *name, size_t name_len,
                                    const uint8_t grantee[32], int level);

/* The level `grantee` was granted of `name`; DENIED when none. */
fzn_streams_err_t fzn_streams_granted(const fzn_streams_t *s, const char *name, size_t name_len,
                                      const uint8_t grantee[32], unsigned *level);

/* `r` as a reader granted `level` is given it: that rendition alone, or the
 * coarsest the record has when it has fewer, as the record's only level. */
void fzn_streams_render(const fzn_stream_record_t *r, unsigned level, fzn_stream_record_t *out);

#endif /* FZN_NODE_STREAMS_H */
