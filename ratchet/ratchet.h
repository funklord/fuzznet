#ifndef FZN_RATCHET_H
#define FZN_RATCHET_H

/*
 * A symmetric key chain: one KDF step, and a bounded fast-forward over it.
 *
 * THIS IS NOT CALLED `group`, DELIBERATELY. It is the generic half of
 * fuzzypickles' `group_ratchet.c`, and `group` is a word this workspace has
 * already found means two things -- a POSIX gid in `local/`, a set of people
 * in a chat. project.md sec 15d recorded that clash before either tree moved;
 * naming the module for the mechanism rather than for the one application
 * that wanted it is what spending that finding looks like. The roster, the
 * membership and the name of a group stay with the consumer, which is where
 * they mean something.
 *
 * THE SEAM WAS DRAWN FROM INSIDE THEIR TREE, at their offer, rather than
 * guessed from outside it. What is generic is the derivation and the bound;
 * what is theirs is storage, a group identified by a NAME STRING, and
 * rotation policy -- when to rotate is application policy and not ratchet
 * mechanism. Their own file already reaches into chat naming for
 * `fzp_is_valid_peer_name`, which is why the file boundary was never the
 * seam.
 *
 * AND IT IS NOT A PORT. Their ratchet is storage-backed throughout: it
 * loads, advances and persists inside one call. Nothing here does I/O, so
 * this is state-in, state-out, caller-owned, the way `record/journal.h`
 * already is -- the same algorithm with the persistence turned inside out,
 * which most of their 280 lines do not survive. They said so before this was
 * written, having just watched a transplanted test cost this tree an
 * afternoon.
 */

#include <stddef.h>
#include <stdint.h>

#include "../session/commitment.h" /* fzn_hash_ops_t */

#define FZN_CHAIN_KEY_LEN 32u
#define FZN_MESSAGE_KEY_LEN 32u

/*
 * The ceiling on a single fast-forward, adopted from fuzzypickles'
 * FZP_GROUP_RATCHET_MAX_ADVANCE at 100000.
 *
 * IT IS A SAFETY VALVE AND NOT A TUNING KNOB. A receiver that missed
 * messages re-derives forward WITHOUT needing the intermediates to have
 * arrived, which is the property that makes a chain usable over a transport
 * that loses things -- and it is the same property that hands a stranger an
 * unbounded loop, because the number of derivations is whatever sequence
 * number they wrote in a header. Take the bound with the feature or you have
 * taken half of it.
 *
 * WHAT THE BOUND STILL COSTS IS MEASURED RATHER THAN ASSUMED, and it is
 * two measurements with different standing. `ratchet_test.c` counts the
 * DERIVATIONS -- 100001 for a jump to the bound, asserted, so the count
 * cannot drift. The wall-clock figure is a separate measurement on this
 * machine against the Monocypher BLAKE2b binding and is not asserted
 * anywhere, because a timing pinned by a test is a test that fails on
 * somebody else's laptop: **62 ms**, at about 620 ns a step.
 *
 * SIXTY-TWO MILLISECONDS FOR ONE MESSAGE IS NOT NOTHING. It is bounded,
 * which is the whole point and is the difference between a defence and
 * none -- but a ~40-byte header naming a far-future sequence buys that,
 * and project.md sec 13c did this arithmetic for the manifest and did not
 * like the answer.
 *
 * WHETHER IT MATTERS DEPENDS ON WHAT IS ABOVE THIS, which is a layering
 * question rather than a ratchet one. Reached only after a frame's own AEAD
 * has opened, the cost is an insider's and the attacker is already a member;
 * reached from a sequence number a stranger can write, it is a stranger's.
 * This module cannot tell which, so it refuses rather than clamps --
 * FZN_RATCHET_ERR_TOO_FAR hands a caller the size of the jump it declined,
 * and a caller under load can refuse far earlier than the bound.
 */
#define FZN_RATCHET_MAX_ADVANCE 100000u

typedef enum fzn_ratchet_err {
	FZN_RATCHET_OK = 0,
	/* A null, or a buffer too small. The caller's bug. */
	FZN_RATCHET_ERR_MALFORMED,
	/* The hash vtable refused or was absent. */
	FZN_RATCHET_ERR_HASH,
	/*
	 * The target is BEHIND the chain's position.
	 *
	 * HARMLESS AND EXPECTED, not an attack, and it has its own code for
	 * that reason: a chain only moves forward, so this is what a
	 * duplicate or a replay looks like from here. A caller that logs it
	 * as an intrusion will be logging ordinary network weather.
	 */
	FZN_RATCHET_ERR_BEHIND,
	/* The jump is larger than FZN_RATCHET_MAX_ADVANCE. A stranger's
	 * sequence number, or a chain that has genuinely fallen that far
	 * behind and needs re-keying rather than re-deriving. */
	FZN_RATCHET_ERR_TOO_FAR,
	/*
	 * `to` and `from` are the same chain.
	 *
	 * ITS OWN CODE BECAUSE IT IS ITS OWN MISTAKE, and the error string
	 * spells out the whole hazard. Advancing a live chain in one step is
	 * the spelling that destroys a peer's delivery when a forged frame
	 * moves it -- see `fzn_ratchet_advance`, which refuses it rather than
	 * documenting against it.
	 */
	FZN_RATCHET_ERR_IN_PLACE,
} fzn_ratchet_err_t;

const char *fzn_ratchet_err_str(fzn_ratchet_err_t err);

/*
 * One step: from a chain key, the message key it yields and the chain key
 * that follows it.
 *
 * ONE HASH PRODUCING BOTH HALVES, which is `session/commitment.h`'s
 * construction again. Knowing a message key must not give the next chain
 * key -- that is the whole of what a chain is for -- and it does not, both
 * being outputs of a one-way function of the current chain key. Two separate
 * derivations would cost two hashes per step, which on a 100000-step
 * fast-forward is a doubling of the one operation that has a bound on it.
 *
 * ALIAS-SAFE, ON PURPOSE. `derive(k, mk, k)` is a valid in-place advance and
 * so is `derive(k, k, next)`. In a library whose state is caller-owned,
 * somebody WILL write the in-place form -- it is the natural way to spell
 * "advance this chain" -- and a function that silently corrupted its input
 * would fail as a decryption error a long way from here. Both outputs are
 * computed before either is written.
 */
fzn_ratchet_err_t fzn_ratchet_derive(const fzn_hash_ops_t *hash,
                                      const uint8_t chain_key[FZN_CHAIN_KEY_LEN],
                                      uint8_t message_key_out[FZN_MESSAGE_KEY_LEN],
                                      uint8_t next_chain_key_out[FZN_CHAIN_KEY_LEN]);

/*
 * A chain's position, owned by the caller.
 *
 * `seq` is the sequence number `key` will produce -- not the last one it
 * produced. The distinction is worth the sentence because both conventions
 * are common and the off-by-one between them is silent: two peers
 * disagreeing about it derive different keys and see authentication
 * failures, which reads as a transport fault.
 */
typedef struct fzn_ratchet_chain {
	uint8_t key[FZN_CHAIN_KEY_LEN];
	uint64_t seq;
} fzn_ratchet_chain_t;

void fzn_ratchet_init(fzn_ratchet_chain_t *chain, const uint8_t key[FZN_CHAIN_KEY_LEN],
                      uint64_t seq);

/*
 * Derives the message key for `target_seq` from `from`, and writes the chain
 * position that follows it into `to`.
 *
 * `to` MUST NOT BE `from`, AND PASSING THE SAME CHAIN IS REFUSED. That is the
 * whole design of this function and it is worth the paragraphs, because the
 * obvious signature -- advance a chain in place and hand back a key -- is the
 * one that has already cost a sibling project a defect.
 *
 * WHAT GOES WRONG WHEN A CHAIN ADVANCES BEFORE A FRAME IS VERIFIED. A
 * receiver reads a sequence number out of an arriving frame, fast-forwards to
 * it, derives the key, and only then tries to open the ciphertext. If the
 * chain has already moved, a frame that FAILS to open has still advanced it.
 * A ratchet moves one way, so every later genuine message from that sender is
 * now behind the position and is refused as a duplicate -- and its keys are
 * gone, because the chain key they came from has been overwritten.
 *
 * One forged datagram from anyone who has seen a real one therefore ENDS that
 * sender's delivery to that receiver, permanently, with no key material, and
 * reports itself as an ordinary duplicate. Irreversible, silent, and cheaper
 * than the denial-of-service the bound below is about: a flood stops when the
 * packets stop and this does not.
 *
 * Traced by fuzzypickles in their own live path at a311c7f, after this
 * library asked them a question about CPU cost. The answer was not about CPU.
 *
 * SO THE ORDER IS FORCED HERE RATHER THAN WRITTEN DOWN:
 *
 *     fzn_ratchet_chain_t next;
 *
 *     err = fzn_ratchet_advance(hash, &chain, seq, mk, &next, ...);
 *     if (err != FZN_RATCHET_OK) ...
 *     if (frame_opens_under(mk))
 *             chain = next;          <- committed only now
 *
 * A genuine gap still fast-forwards, because a genuine frame opens. A forged
 * one costs the derivations and changes nothing. The commit is a plain
 * assignment the caller makes after verifying, which is the one moment it can
 * be made safely -- and there is no way to spell the unsafe version, because
 * `to == from` returns FZN_RATCHET_ERR_IN_PLACE.
 *
 * THAT REFUSAL IS THE POINT AND NOT A CONVENIENCE. A rule saying "verify
 * before you commit" holds until somebody writes the caller that does not,
 * fails silently when they do, and lives in a module that cannot detect it.
 * fuzzypickles made this library that argument about a blob's leaf count a
 * day earlier and it was right then too.
 *
 * SKIPPED KEYS ARE OFFERED RATHER THAN DISCARDED. The keys for the sequence
 * numbers jumped over are written to `skipped_out` if it is given, oldest
 * first, and `*skipped_count` says how many. A caller that does not want them
 * passes NULL and they are lost.
 *
 * A chain moves one way, so a message that arrives after the chain has passed
 * it can never be opened again -- and on a datagram transport, late is not
 * exceptional. Treating a behind-position target as a duplicate covers a
 * REPLAY and not a genuinely late first delivery, which was never decrypted
 * and so is in nobody's history. Rather than decide that for a consumer, this
 * returns the material and lets them choose; retaining a skipped key is a
 * real cost, since it stays decryptable until dropped.
 *
 * `*skipped_count` is capped at `skipped_cap` and `*dropped` reports how many
 * did not fit, following `fzn_manifest_deficit`'s shape: a caller that asked
 * for less than there was must be told rather than left to infer it from a
 * count that stopped short.
 *
 * `to` IS NOT WRITTEN AT ALL UNLESS THE CALL SUCCEEDS, so a refusal part-way
 * through cannot leave a caller holding a position that is neither the old
 * one nor a usable new one.
 */
fzn_ratchet_err_t fzn_ratchet_advance(const fzn_hash_ops_t *hash,
                                       const fzn_ratchet_chain_t *from, uint64_t target_seq,
                                       uint8_t message_key_out[FZN_MESSAGE_KEY_LEN],
                                       fzn_ratchet_chain_t *to, uint8_t *skipped_out,
                                       size_t skipped_cap, size_t *skipped_count,
                                       size_t *dropped);

/* Erases a chain's key. A caller-owned secret needs a way to be forgotten,
 * and `constant_time.h`'s wipe is not something a consumer should have to
 * find for itself. */
void fzn_ratchet_wipe(fzn_ratchet_chain_t *chain);

#endif /* FZN_RATCHET_H */
