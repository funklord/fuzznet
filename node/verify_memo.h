/*
 * A SIGNATURE CHECKED ONCE, project.md sec 931. Fuzzypickles' 20261106T1825Z: past about
 * 1700 contacts a round held the loop past a client's timeout, and rounds grew with what
 * was held. Settings are verified whenever they are read, so walking them cost an Ed25519
 * check a row, about 150 us, several times a round.
 *
 * `fzn_sign_ops_t` OVER ANOTHER, with the same answers. A signature that verified is
 * remembered by a hash of its key, message and signature, so the same bytes cost a hash
 * after that. Only a success is kept, and the whole digest is compared, so a different
 * message, key or signature is checked as if none had been. Nothing here says a key is
 * still trusted: a check has always been of the bytes, and revocation is asked apart.
 *
 * In sets of four, grown as it fills (sec 1007): a way taken by another is only a check
 * done again. No memory means no memo, and every check made.
 *
 * KEPT ACROSS A START, sec 938: a host verifies all it holds before it serves, 1 ms a
 * contact, so a restart at 20000 contacts answered nothing for 20 s. So the memo is
 * saved, SIGNED BY THIS HOST'S OWN KEY over a hash of it: one check takes it all back,
 * and no one without that key can add a forgery to it. A file that does not read or
 * does not verify is passed over, and every check made, so it can only be slower.
 * What it remembers is still only that these bytes verified.
 */
#ifndef FZN_NODE_VERIFY_MEMO_H
#define FZN_NODE_VERIFY_MEMO_H

#include <stddef.h>
#include <stdint.h>

#include "../chain/chain.h"
#include "../session/commitment.h"

/* THE SLOTS AT FIRST, grown twice over as three quarters are taken (sec 1007), in sets
 * of FZN_VERIFY_MEMO_WAYS. A multiple of the ways. */
#ifndef FZN_VERIFY_MEMO_SLOTS
#define FZN_VERIFY_MEMO_SLOTS 262144u
#endif
#define FZN_VERIFY_MEMO_WAYS 4u
/* A FILE claiming more than this is not read: a bound on what a corrupt count asks for,
 * 2 GB of digests, and not on what a host may hold. */
#define FZN_VERIFY_MEMO_HELD_MAX (1u << 26)
#define FZN_VERIFY_MEMO_DIGEST 32u

typedef struct fzn_verify_memo {
	const fzn_sign_ops_t *inner;
	const fzn_hash_ops_t *hash;
	uint8_t (*table)[FZN_VERIFY_MEMO_DIGEST]; /* made at the first check */
	size_t room, filled;                      /* its slots, and how many are taken */
	int no_room;
	unsigned long hits, checks;
	/* THIS HOST'S KEY, once known: what it signs needs no checking when read back,
	 * so its own records cost nothing at the first start after they were written. */
	const uint8_t *own;
	unsigned long added, added_saved; /* digests taken in, and at the last save */
} fzn_verify_memo_t;

/* `ops`, which verify through `m` and sign through `inner`. `inner` and `hash` must
 * outlive them. */
void fzn_verify_memo_init(fzn_verify_memo_t *m, const fzn_sign_ops_t *inner,
                          const fzn_hash_ops_t *hash, fzn_sign_ops_t *ops);

void fzn_verify_memo_free(fzn_verify_memo_t *m);

/* THE MEMO, signed, written whole over `path`, by the `inner` it was given. 1, or 0
 * with whatever was there left alone. */
int fzn_verify_memo_save(fzn_verify_memo_t *m, const char *path);

/* WHAT `path` REMEMBERS, signed by `own`, taken in: how many digests, 0 when it is
 * absent, or any of it is not as it was saved. */
size_t fzn_verify_memo_load(fzn_verify_memo_t *m, const char *path,
                            const uint8_t own[FZN_PUBKEY_LEN]);

#endif /* FZN_NODE_VERIFY_MEMO_H */
