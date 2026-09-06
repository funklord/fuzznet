/*
 * Where a record's bytes live between arriving and being applied.
 *
 * project.md sec 132 and sec 133. The journal holds POSITIONS -- how far each
 * (issuer, stream) has got -- and deliberately holds no bytes, so until this
 * file nothing in the library said where a record waits between
 * `fzn_journal_admit` and `fzn_state_apply`. Every consumer would have
 * invented one, which is the shape that put `chain/authz.h` here.
 *
 * IT IS A SEAM BECAUSE THE ANSWER IS NOT ONE THING. A single process wants a
 * few hundred bytes per record in memory; a host resuming after a restart
 * wants them on disk; and sec 132's arrangement wants several processes of
 * one identity reading a store exactly one of them writes. Those are the same
 * two calls over different storage, which is what `spool/spool.h` is to
 * `spool/spool_file.c` and is modelled on it.
 *
 * THE STORE IS NOT TRUSTED, AND THAT IS THE WHOLE REASON SHARING IT IS SAFE.
 * A record carries its own signature, so a reader verifies what it reads and
 * a hostile writer can insert only records that fail verification. sec 132
 * turns on this: a shared cache is not a shared trust domain, and it is what
 * lets several processes cooperate without trusting each other.
 *
 * SO THIS MODULE DOES NOT VERIFY, AND A CALLER MUST. `fzn_record_store_get`
 * checks SHAPE and PLACEMENT and stops there; the signature is
 * `fzn_record_verify`'s and needs a `fzn_sign_ops_t` and a decision about
 * whose key, neither of which belongs to storage. A caller that reads from
 * here and applies without verifying has a shared store for an attacker.
 *
 * WHAT IT DOES CHECK IS THE ADDRESS, IN BOTH DIRECTIONS, AND THAT COSTS
 * NOTHING. `put` reads (issuer, stream, seq) OUT OF THE RECORD rather than
 * taking it beside the bytes, so a record cannot be filed under an address
 * that is not its own -- `chain/revocation.c` states the same rule for the
 * same reason, computing a record's identity "from the bytes that were signed
 * and not from anything a caller supplied beside them". And `get` compares
 * what came back against what was asked for, so a store that returns the
 * wrong record answers FZN_RECORD_STORE_ERR_MISPLACED rather than handing a
 * caller somebody else's bytes under the name it asked for.
 *
 * Three integer comparisons catch a whole class -- a buggy backend, an index
 * off by one, a writer filing under the wrong stream -- before any signature
 * is checked, which matters because the misplaced record may be perfectly
 * well signed. A signature says who wrote a record. It does not say the store
 * gave you the one you asked for.
 */
#ifndef FZN_RECORD_STORE_H
#define FZN_RECORD_STORE_H

#include "record.h"

#include <stddef.h>
#include <stdint.h>

typedef enum fzn_record_store_err {
	FZN_RECORD_STORE_OK = 0,
	/* A null argument, a record that was never opened, a buffer that
	 * cannot hold a record: the caller's bug. */
	FZN_RECORD_STORE_ERR_MALFORMED = -1,
	/* This store does not hold that record. AN ANSWER RATHER THAN A FAULT:
	 * it is what a reader gets for everything the owner has not fetched
	 * yet, which on a busy host is most of what it asks for. */
	FZN_RECORD_STORE_ERR_ABSENT = -2,
	/* The backend could not answer -- a file that would not open, a read
	 * that failed. Kept apart from ABSENT because "not held" is normal and
	 * "the store is broken" is not, and a caller that treated a broken
	 * store as an empty one would refetch the world. */
	FZN_RECORD_STORE_ERR_BACKEND = -3,
	/* What came back is not a record. A store fed a truncated write, or a
	 * file somebody edited. */
	FZN_RECORD_STORE_ERR_SHAPE = -4,
	/* What came back IS a record and is not the one that was asked for.
	 * Its own header names another (issuer, stream, seq). See the note
	 * above on why this is checked before any signature. */
	FZN_RECORD_STORE_ERR_MISPLACED = -5,
} fzn_record_store_err_t;

const char *fzn_record_store_err_str(fzn_record_store_err_t err);

/*
 * The backend, following this library's convention that NONZERO is success.
 *
 * `get` reports "not held" apart from "could not look" through `found_out`,
 * for the reason the two error values are kept apart: a reader asks for
 * records the owner has not fetched as a matter of course, and a backend that
 * collapsed the two would make an empty store and a broken one identical.
 *
 * `len_out` receives the length written into `out`. A backend that finds a
 * record too large for `cap` reports failure with `found_out` set, so a
 * caller can tell a short buffer from an absent record.
 */
typedef struct fzn_record_store_ops {
	int (*put)(void *ctx, const uint8_t issuer[FZN_PUBKEY_LEN], uint32_t stream,
	           uint64_t seq, const uint8_t *bytes, size_t len);
	int (*get)(void *ctx, const uint8_t issuer[FZN_PUBKEY_LEN], uint32_t stream,
	           uint64_t seq, uint8_t *out, size_t cap, size_t *len_out, int *found_out);
	void *ctx;
} fzn_record_store_ops_t;

typedef struct fzn_record_store {
	const fzn_record_store_ops_t *ops;
} fzn_record_store_t;

/* Point a store at a backend. */
fzn_record_store_err_t fzn_record_store_init(fzn_record_store_t *store,
                                             const fzn_record_store_ops_t *ops);

/*
 * File a record under the address it carries.
 *
 * Takes an OPENED record rather than bytes and a length, which is what makes
 * the address unforgeable by a caller: there is no argument to pass a wrong
 * issuer, stream or sequence in. `fzn_record_open` has already refused a
 * sequence of zero, so no caller can file one at a position the journal
 * cannot express.
 *
 * DOES NOT VERIFY, and the header says at length why. A caller stores what it
 * has verified, or accepts that every reader must.
 *
 * Storing a record twice at one address is the backend's to define: an
 * append-only log may hold both and return the first, and a map may replace.
 * Either is safe because a reader checks the address of what it gets and
 * verifies the signature, so the worst a duplicate can do is waste space.
 */
fzn_record_store_err_t fzn_record_store_put(fzn_record_store_t *store, fzn_record_t record);

/*
 * Read the record at an address into `out`, and hand back a view of it.
 *
 * `out` is the caller's, as everything in this library is, and must hold
 * FZN_RECORD_MAX_LEN to be sure of fitting any record.
 *
 * `record_out` receives a view over `out` -- so it is valid exactly as long
 * as `out` is, and a caller that returns a view over a buffer on its own
 * stack has made the mistake this sentence exists to prevent.
 *
 * Checks shape, then placement, then stops. THE CALLER STILL OWES
 * `fzn_record_verify`.
 */
fzn_record_store_err_t fzn_record_store_get(fzn_record_store_t *store,
                                            const uint8_t issuer[FZN_PUBKEY_LEN],
                                            uint32_t stream, uint64_t seq,
                                            uint8_t *out, size_t cap,
                                            fzn_record_t *record_out);

#endif
