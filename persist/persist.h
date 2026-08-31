#ifndef FZN_PERSIST_H
#define FZN_PERSIST_H

/*
 * What must survive a restart, and the seam that makes it survive.
 *
 * WHY THIS EXISTS. Nine types in this library are caller-owned and live only
 * in memory. Until this file, nothing said which of them MUST outlive the
 * process -- and getting that wrong is silent. A consumer that does not
 * persist `fzn_trust_t` restarts with no anchor and adopts whatever root it
 * is next told about, which is the whole of trust-on-first-use gone, with no
 * error anywhere. That is `chain/authz.h`'s hazard one layer up: absence
 * reading as not-required, where the absent thing is a file.
 *
 * The gap existed because storage was out of scope, so nobody owned the
 * contract. Scope is not the same as silence: a library may decline to WRITE
 * a file and still owe a statement of what belongs in one.
 *
 * THE CORE STILL DOES NOT ALLOCATE OR WRITE. This module is a seam and a
 * serialisation; `persist/persist_file.c` is a default backend beside it,
 * separately compiled and separately disableable. A target with no
 * filesystem drops the backend and keeps everything else. A target with no
 * heap is unaffected either way -- nothing here allocates.
 *
 * AND A CONSUMER SHOULD NOT HAVE TO INVENT THE FORMAT. Two consumers
 * persisting `fzn_trust_t` by copying the struct would be two consumers
 * writing a memory layout to disk, which breaks on the first compiler that
 * pads differently. The pack and open functions below are the format, and
 * they are the library's for the same reason `fzn_chain_pack` is: a reader
 * with no writer is a writer everybody invents.
 */

#include <stddef.h>
#include <stdint.h>

#include "../prekey/prekey.h"
#include "../ratchet/ratchet.h"
#include "../session/agree.h"
#include "../trust/trust.h"

/*
 * WHAT LOSS COSTS, PER TYPE. This table is the reason the file exists and is
 * ordered by what happens when a consumer gets it wrong.
 *
 *   fzn_trust_t          MUST. Losing the anchor means the next root offered
 *                        is adopted. Silent, and it is the whole TOFU
 *                        protection.
 *   fzn_agree_secret_t   MUST, for a host that publishes a prekey. Losing it
 *                        loses every message sealed to that prekey while the
 *                        host was away -- which is the reboot survivability
 *                        the whole session design was chosen for.
 *   fzn_prekey_peer_t    MUST, per pinned peer. Losing it re-pins on first
 *                        use, silently accepting a key the host had already
 *                        committed against.
 *   fzn_ratchet_chain_t  MUST, per direction per peer, and SEE THE ORDERING
 *                        BELOW -- this is the one where persisting at the
 *                        wrong moment is worse than not persisting at all.
 *
 * Recoverable rather than required, and deliberately not served here:
 *
 *   fzn_state_t          rebuilt by replaying records. Persisting it is a
 *   fzn_journal_t        cache, and the journal decides what to re-fetch.
 *   fzn_revocation_store_t  refilled from manifests; sec 13d is the design.
 *   fzn_reasm_t          in-flight message fragments. Losing them costs a
 *                        retransmission and nothing else.
 *   fzn_replay_window_t  losing it widens the window a replay can use until
 *                        it refills. A consumer that cares persists it; the
 *                        failure is bounded and loud rather than silent.
 */

/*
 * THE ORDERING RULE FOR RATCHET CHAINS, WHICH IS ASYMMETRIC AND IS THE MOST
 * DANGEROUS THING IN THIS FILE.
 *
 * A chain moves one way and a message key must never be used twice. What a
 * crash costs therefore depends on which side of the use the save happened,
 * and the safe order is OPPOSITE for the two directions:
 *
 *   SEND:    save the advanced chain BEFORE sealing anything under the key.
 *            Crash after saving and before sending: a key is skipped, the
 *            peer fast-forwards, nothing is lost. Crash after sending and
 *            before saving: the same key is derived again and used for a
 *            SECOND message -- key and nonce reuse, which is the failure the
 *            whole AEAD rests on not happening.
 *
 *   RECEIVE: save the advanced chain AFTER opening the message. Crash after
 *            saving and before opening: that message can never be opened,
 *            because the chain has passed it. Crash after opening and before
 *            saving: the same key is derived again for a message already
 *            handled, which the replay window refuses.
 *
 * So: SEND SAVES EARLY, RECEIVE SAVES LATE. Both errors are silent in the
 * moment. The send one is a compromise; the receive one is a lost message.
 *
 * `fzn_persist_chain_slot` names the direction so a caller cannot hold one
 * and mean the other, which is the same reason `fzn_session_chains` returns
 * two buffers rather than one and a flag.
 */

#define FZN_PERSIST_VERSION 1u

/* Longest blob any pack function below produces, so a caller can size one
 * buffer and stop thinking about it. Asserted against each in persist.c. */
#define FZN_PERSIST_MAX 96u

typedef enum fzn_persist_slot {
	/* Whole-host, no subject. */
	FZN_PERSIST_TRUST = 1u,
	FZN_PERSIST_OWN_PREKEY = 2u,
	/* Per peer, keyed by that peer's identity. */
	FZN_PERSIST_PEER = 3u,
	FZN_PERSIST_SEND_CHAIN = 4u,
	FZN_PERSIST_RECV_CHAIN = 5u,
} fzn_persist_slot_t;

typedef enum fzn_persist_err {
	FZN_PERSIST_OK = 0,
	FZN_PERSIST_ERR_MALFORMED,
	/* The stored bytes are not this shape or not this version. A peer
	 * cannot reach these bytes, so this is a corrupt or foreign file
	 * rather than an attack -- but it is refused rather than repaired,
	 * because a half-read anchor is worse than none. */
	FZN_PERSIST_ERR_SHAPE,
	/* The backend refused or was absent. */
	FZN_PERSIST_ERR_BACKEND,
	/* Nothing stored under that slot. An ordinary state on first run, and
	 * its own code so a caller can tell it from a backend failure --
	 * which is the distinction that decides whether to mint a fresh
	 * prekey or to stop and shout. */
	FZN_PERSIST_ERR_ABSENT,
} fzn_persist_err_t;

const char *fzn_persist_err_str(fzn_persist_err_t err);

/*
 * The backend seam.
 *
 * KEYED BY (slot, subject) RATHER THAN BY A STRING, so this module neither
 * formats nor parses names and a backend cannot be handed a path. A
 * filesystem backend derives a filename; a key-value backend concatenates;
 * an embedded backend indexes a table. `subject` is NULL for the two
 * whole-host slots.
 *
 * `load` reports the length through `*len` and must not write past `cap`.
 * Returning zero means absent OR failed, and the two are distinguished by
 * the backend setting `*len` only on success -- which is why `load` takes a
 * length pointer rather than returning one.
 */
typedef struct fzn_persist_ops {
	int (*load)(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject, uint8_t *out,
	            size_t cap, size_t *len);
	int (*save)(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject,
	            const uint8_t *bytes, size_t len);
	void *ctx;
} fzn_persist_ops_t;

/* ---- the format ------------------------------------------------------- */

/*
 * Pack and open, per type. The bytes are the library's format, versioned,
 * and no struct's memory layout ever reaches a backend.
 *
 * A SECRET IS PACKED IN THE CLEAR and this module does not encrypt it. What
 * protects a stored prekey secret is the backend -- file permissions, a
 * keystore, an enclave -- and pretending otherwise by encrypting under a key
 * that would have to be stored beside it is the kind of ritual
 * `constant_time.h` argues against. `persist/persist_file.c` says what it
 * does about permissions; a consumer wanting more supplies its own backend,
 * which is what the seam is for.
 */
fzn_persist_err_t fzn_persist_trust_pack(const fzn_trust_t *trust, uint8_t *out, size_t cap,
                                          size_t *len);
fzn_persist_err_t fzn_persist_trust_open(const uint8_t *bytes, size_t len, fzn_trust_t *out);

fzn_persist_err_t fzn_persist_secret_pack(const fzn_agree_secret_t *secret, uint8_t *out,
                                           size_t cap, size_t *len);

/*
 * A REFUSED OPEN LEAVES `out` AS IT FOUND IT, on every path -- a null
 * argument, a header this is not, and a binding that will not derive.
 *
 * Stated because it was not, and because the absence let the three refusals
 * drift apart: two preserved the caller's secret and the third cleared it
 * before calling `fzn_agree_secret_install`, which is the one function in
 * the pair that promises not to. agree.h has that promise and the cost of
 * breaking it -- a host that cannot decrypt its own queued traffic because a
 * key derivation failed -- and this is the same guarantee one layer out.
 *
 * WHAT IT LETS A CALLER DO is retry. A host restoring from a backup while
 * running, or making a second attempt after a first was refused, may pass a
 * LIVE secret here and still hold it afterwards if the restore does not
 * happen. Without this, the safe way to call it was to restore into a
 * scratch struct and copy on success, which is a discipline no signature
 * asked for and none of the other `_open` functions here need.
 *
 * On success `out` is written in full and the stored generation is restored
 * over the one installing would have derived -- see the note in persist.c
 * about why the generation is put back rather than left at zero.
 */
fzn_persist_err_t fzn_persist_secret_open(const uint8_t *bytes, size_t len,
                                           const fzn_agree_ops_t *agree,
                                           fzn_agree_secret_t *out);

fzn_persist_err_t fzn_persist_peer_pack(const fzn_prekey_peer_t *peer, uint8_t *out, size_t cap,
                                         size_t *len);
fzn_persist_err_t fzn_persist_peer_open(const uint8_t *bytes, size_t len,
                                         fzn_prekey_peer_t *out);

fzn_persist_err_t fzn_persist_chain_pack(const fzn_ratchet_chain_t *chain, uint8_t *out,
                                          size_t cap, size_t *len);
fzn_persist_err_t fzn_persist_chain_open(const uint8_t *bytes, size_t len,
                                          fzn_ratchet_chain_t *out);

#endif /* FZN_PERSIST_H */
