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
 * Direct-mapped: a slot taken by another is only a check done again. No memory means no
 * memo, and every check made.
 */
#ifndef FZN_NODE_VERIFY_MEMO_H
#define FZN_NODE_VERIFY_MEMO_H

#include <stddef.h>
#include <stdint.h>

#include "../chain/chain.h"
#include "../session/commitment.h"

#ifndef FZN_VERIFY_MEMO_SLOTS
#define FZN_VERIFY_MEMO_SLOTS 262144u
#endif
#define FZN_VERIFY_MEMO_DIGEST 32u

typedef struct fzn_verify_memo {
	const fzn_sign_ops_t *inner;
	const fzn_hash_ops_t *hash;
	uint8_t (*table)[FZN_VERIFY_MEMO_DIGEST]; /* made at the first check */
	int no_room;
	unsigned long hits, checks;
} fzn_verify_memo_t;

/* `ops`, which verify through `m` and sign through `inner`. `inner` and `hash` must
 * outlive them. */
void fzn_verify_memo_init(fzn_verify_memo_t *m, const fzn_sign_ops_t *inner,
                          const fzn_hash_ops_t *hash, fzn_sign_ops_t *ops);

void fzn_verify_memo_free(fzn_verify_memo_t *m);

#endif /* FZN_NODE_VERIFY_MEMO_H */
