/* Causes on the wire: a request carrying the names of the log entries it
 * was made for. sec 462, step 4 of sec 456's order, which the holder asked
 * for with the format rather than later.
 *
 * WHY: across an estate the wall clocks disagree, so ordering lines by time
 * alone lies about which answered which (sec 428). A host asking another
 * names the entry it logged for the work -- its CAUSE -- and the entry where
 * that work began -- its ORIGIN -- and the answering host logs what it did
 * with those names. One grep for the instance field of the origin then
 * reads the work from both ends.
 *
 * THE ENVELOPE, `log/cause.situ`: version 3, the two names in the log
 * record's own form, then the request as it would have gone bare. Version 3
 * is the dispatch, beside notes sync's 2 and the spool's 1.
 *
 * A WIRE BREAK, recorded rather than negotiated (sec 462): a host built
 * before this answers an envelope as a request it does not know. The only
 * consumers are in this workspace, which is why the holder had it go in now.
 */

#ifndef FZN_LOG_CAUSE_H
#define FZN_LOG_CAUSE_H

#include <stddef.h>
#include <stdint.h>

#include "entry.h"

#define FZN_CAUSE_VERSION 3u
/* An envelope's overhead at most: the version, two names, the length. */
#define FZN_CAUSE_OVERHEAD_MAX (1u + (2u * FZN_ENTRY_NAME_RECORD_MAX) + 2u)

/* Counting down from OK as every status here does; NONE is no failure but
 * the answer for a bare request, which is handled as it is. */
typedef enum fzn_cause_err {
	FZN_CAUSE_OK = 0,
	FZN_CAUSE_NONE = -1,            /* the payload is not an envelope */
	FZN_CAUSE_ERR_MALFORMED = -2,   /* a null, or an envelope that does not read */
	FZN_CAUSE_ERR_ROOM = -3         /* the envelope does not fit `cap` */
} fzn_cause_err_t;

const char *fzn_cause_err_str(fzn_cause_err_t err);

/* `inner` wrapped with `cause` and `origin` into `out`; its length in
 * `*len`. An empty request, or one past a u16, is MALFORMED. */
fzn_cause_err_t fzn_cause_wrap(const fzn_entry_name_t *cause, const fzn_entry_name_t *origin,
                               const uint8_t *inner, size_t inner_len, uint8_t *out, size_t cap,
                               size_t *len);

/* THE ENVELOPE TAKEN OFF: NONE, with nothing written, for a payload whose
 * first byte is not the version -- a bare request, to be handled as it is;
 * OK with the two names and the request inside, which points into
 * `payload`; MALFORMED for an envelope that does not read, every byte of
 * it accounted for. */
fzn_cause_err_t fzn_cause_unwrap(const uint8_t *payload, size_t len, fzn_entry_name_t *cause,
                                 fzn_entry_name_t *origin, const uint8_t **inner,
                                 size_t *inner_len);

#endif /* FZN_LOG_CAUSE_H */
