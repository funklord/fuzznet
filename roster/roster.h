/* A user's roster, replicated across the user's own hosts.
 *
 * WHAT IT IS FOR. A contact belongs to its USER, not to the one device that
 * added it: removed on any of the user's hosts, it is removed on all of them
 * and stays removed. fuzzypickles found the failure this closes, with three
 * daemons: the vault removed alice, the phone later changed alice's location
 * share, the vault received the newer record, found alice absent, and
 * recreated her -- already allowed to ask where the user is. The holder
 * decided 2026-09-28 that removal is the user's act and that carrying it is
 * fuzznet's. project.md sec 388.
 *
 * THE INCARNATION IS THE WHOLE DESIGN. Adding a subject mints an
 * incarnation, 16 random bytes fixed at the add. Every later record about the
 * subject names the incarnation it concerns, and removal is a tombstone for
 * one incarnation, kept for good. A record naming a removed incarnation
 * changes nothing, however high its `seq` -- so a stale update cannot bring a
 * subject back under ANY concurrency, because nothing here orders by clock or
 * sequence to decide it. A deliberate re-add mints a new incarnation and is a
 * fresh subject, even for the same key.
 *
 * TWO LIVE INCARNATIONS OF ONE SUBJECT happen when it is added independently
 * on two hosts. The active one is the add with the greatest `(seq, writer)`:
 * `seq` compared as a number, `writer` as bytes. Settings belong to an
 * incarnation, so the losing one's settings are lost with it. That is
 * accepted rather than merged, at fuzzypickles' request that it be stated.
 *
 * THE SUBJECT IS 32 BYTES and this module does not say what of. For
 * fuzzypickles it is the contact's host public key.
 *
 * THE SETTING RECORD'S LAYOUT IS HERE; ITS RESOLUTION IS NOT YET. A setting
 * is written on an incarnation and carries an opaque body of up to
 * FZN_ROSTER_BODY_MAX bytes -- sized for fuzzypickles' synced config values
 * (FZP_CONFIG_VALUE_MAX, 192), not just the two-byte location share. How two
 * settings resolve is open: last-writer-wins, or the safe direction
 * fuzzypickles' configuration.md declares per setting. So `fzn_roster_admit`
 * refuses a setting as UNSUPPORTED until that is decided, rather than
 * resolving it one way now and another later.
 *
 * WHO MAY WRITE. The estate root, or a host that shows a chain from the root
 * for the roster's capability -- a consumer's, like fuzzypickles'
 * CAP_PEER_MANAGE -- naming it as the last grantee. The receiver checks it,
 * as revoking checks standing (`chain/revocation.h`).
 *
 * A REVOKED WRITER WRITES NOTHING, removals included. Both an add and a
 * removal are checked against the revocations this host holds. A removal was
 * first admitted revocation-blind, so none could be lost; fuzzypickles showed
 * the cost -- a stolen phone, queued offline, could remove every contact in
 * the estate for good, since a tombstone is permanent -- and the holder
 * decided 2026-09-28 to refuse it (sec 388). What that gives up: a genuine
 * removal made on a device just before it was revoked, and not yet carried,
 * is lost and must be made again from another host. Carriage runs through
 * the root, which decides for every host, so the refusal is the same
 * everywhere rather than depending on arrival order.
 *
 * THE CLOCK IS A DIFFERENT QUESTION. A removal carries no time of its own,
 * so it is checked at the moment its writer's newest hop was issued: one made
 * while the grant held is not lost to the grant expiring before it arrived.
 * An add can grant access and is checked against the clock as well.
 *
 * ONLY THE USER'S OWN HOSTS. The subject is never told it was removed. That
 * is fuzzypickles' rule for un-pairing, and this does not change it: the
 * tombstone lives among the user's hosts and goes nowhere else.
 *
 * The same shape as `fzn_revocation_store_t`: caller-owned entries, a
 * capacity, no allocation, no I/O, no clock of its own.
 *
 * THE RECORD, big-endian, signed over everything before the signature:
 *
 *     off  len  field
 *       0    1  version       FZN_SIGNED_VERSION, 1
 *       1    1  object        FZN_OBJECT_ROSTER_ADD, _REMOVE or _SET
 *       2   32  writer        the host that signed it
 *      34   32  subject
 *      66   16  incarnation
 *      82    8  seq           the writer's Lamport sequence
 *      90    2  setting       0 for an add or a remove
 *      92    1  body_len      0 for an add or a remove; at most 192
 *      93    n  body          opaque
 *    93+n   64  signature
 */

#ifndef FZN_ROSTER_H
#define FZN_ROSTER_H

#include <stddef.h>
#include <stdint.h>

#include "../chain/chain.h"
#include "../wire/bytes.h"

#define FZN_ROSTER_INCARNATION_LEN 16u
#define FZN_ROSTER_BODY_MAX 192u

#define FZN_ROSTER_OFF_VERSION 0u
#define FZN_ROSTER_OFF_OBJECT 1u
#define FZN_ROSTER_OFF_WRITER 2u
#define FZN_ROSTER_OFF_SUBJECT (FZN_ROSTER_OFF_WRITER + (size_t)FZN_PUBKEY_LEN)
#define FZN_ROSTER_OFF_INCARNATION (FZN_ROSTER_OFF_SUBJECT + (size_t)FZN_PUBKEY_LEN)
#define FZN_ROSTER_OFF_SEQ (FZN_ROSTER_OFF_INCARNATION + FZN_ROSTER_INCARNATION_LEN)
#define FZN_ROSTER_OFF_SETTING (FZN_ROSTER_OFF_SEQ + 8u)
#define FZN_ROSTER_OFF_BODY_LEN (FZN_ROSTER_OFF_SETTING + 2u)
#define FZN_ROSTER_HEADER_LEN (FZN_ROSTER_OFF_BODY_LEN + 1u)
#define FZN_ROSTER_LEN(body) ((size_t)FZN_ROSTER_HEADER_LEN + (size_t)(body) + (size_t)FZN_SIG_LEN)
#define FZN_ROSTER_MIN_LEN FZN_ROSTER_LEN(0)
#define FZN_ROSTER_MAX_LEN FZN_ROSTER_LEN(FZN_ROSTER_BODY_MAX)

FZN_STATIC_ASSERT(FZN_ROSTER_HEADER_LEN == 93u, "the roster record's header moved");

typedef enum fzn_roster_err {
	FZN_ROSTER_OK = 0,
	FZN_ROSTER_ERR_MALFORMED = -1,
	/* The bytes are not a roster record: a length, version, object or a
	 * field an add or a remove must leave zero. */
	FZN_ROSTER_ERR_SHAPE = -2,
	/* The signature does not verify under the record's own writer. */
	FZN_ROSTER_ERR_SIGNATURE = -3,
	/* The writer is not the root and shows no chain entitling it. */
	FZN_ROSTER_ERR_STANDING = -4,
	/* A second, different add for an incarnation already added. An
	 * incarnation is minted once, so two adds of one are one writer's
	 * statement contradicting another's, and neither is taken. */
	FZN_ROSTER_ERR_CONFLICT = -5,
	/* No room. A refused removal is a contact left in place, so this is
	 * the fail-open the store's size decides; see project.md sec 388. */
	FZN_ROSTER_ERR_FULL = -6,
	/* A setting record: laid out, not yet resolved. See the header. */
	FZN_ROSTER_ERR_UNSUPPORTED = -7
} fzn_roster_err_t;

const char *fzn_roster_err_str(fzn_roster_err_t err);

/* A record as it arrived: a view over caller-owned bytes, opened. */
typedef struct fzn_roster_record {
	const uint8_t *base;
	size_t len;
} fzn_roster_record_t;

/* Check the shape and give a view. Not the signature; `fzn_roster_admit`
 * verifies. */
fzn_roster_err_t fzn_roster_open(const uint8_t *bytes, size_t len, fzn_roster_record_t *out);

static inline uint8_t fzn_roster_object(fzn_roster_record_t rec)
{
	return rec.base[FZN_ROSTER_OFF_OBJECT];
}

static inline const uint8_t *fzn_roster_writer(fzn_roster_record_t rec)
{
	return rec.base + FZN_ROSTER_OFF_WRITER;
}

static inline const uint8_t *fzn_roster_subject(fzn_roster_record_t rec)
{
	return rec.base + FZN_ROSTER_OFF_SUBJECT;
}

static inline const uint8_t *fzn_roster_incarnation(fzn_roster_record_t rec)
{
	return rec.base + FZN_ROSTER_OFF_INCARNATION;
}

static inline uint64_t fzn_roster_seq(fzn_roster_record_t rec)
{
	return fzn_get_be64(rec.base + FZN_ROSTER_OFF_SEQ);
}

/* Mint an add, a remove or a setting, signed. `out` receives
 * FZN_ROSTER_LEN(body_len) bytes and `*out_len` says so. `writer` is the
 * signer's public key; whether the signer holds its secret is not a question
 * this can ask, as in `fzn_chain_mint`. An incarnation that is all zero is
 * refused: it would be the one every careless caller mints. */
fzn_roster_err_t fzn_roster_issue_add(const uint8_t writer[FZN_PUBKEY_LEN],
                                      const uint8_t subject[FZN_PUBKEY_LEN],
                                      const uint8_t incarnation[FZN_ROSTER_INCARNATION_LEN],
                                      uint64_t seq, const fzn_sign_ops_t *sign, uint8_t *out,
                                      size_t out_cap, size_t *out_len);

fzn_roster_err_t fzn_roster_issue_remove(const uint8_t writer[FZN_PUBKEY_LEN],
                                         const uint8_t subject[FZN_PUBKEY_LEN],
                                         const uint8_t incarnation[FZN_ROSTER_INCARNATION_LEN],
                                         uint64_t seq, const fzn_sign_ops_t *sign,
                                         uint8_t *out, size_t out_cap, size_t *out_len);

fzn_roster_err_t fzn_roster_issue_set(const uint8_t writer[FZN_PUBKEY_LEN],
                                      const uint8_t subject[FZN_PUBKEY_LEN],
                                      const uint8_t incarnation[FZN_ROSTER_INCARNATION_LEN],
                                      uint64_t seq, uint16_t setting, const uint8_t *body,
                                      size_t body_len, const fzn_sign_ops_t *sign, uint8_t *out,
                                      size_t out_cap, size_t *out_len);

/* One incarnation, as this host knows it. An entry can exist with only its
 * tombstone: a removal that overtook its add is stored, so the add arriving
 * later lands on it removed. The same arrival-order argument
 * `chain/revocation.h` makes for a withdrawal's tombstone. */
typedef struct fzn_roster_entry {
	uint8_t subject[FZN_PUBKEY_LEN];
	uint8_t incarnation[FZN_ROSTER_INCARNATION_LEN];
	int added;
	uint64_t add_seq;
	uint8_t add_writer[FZN_PUBKEY_LEN];
	int removed;
} fzn_roster_entry_t;

typedef struct fzn_roster {
	fzn_roster_entry_t *entries;
	size_t capacity;
	size_t used;
	/* The greatest `seq` any admitted record carried, so a writer here can
	 * number its next record past everything it has seen. */
	uint64_t seq_seen;
} fzn_roster_t;

fzn_roster_err_t fzn_roster_init(fzn_roster_t *roster, fzn_roster_entry_t *entries,
                                 size_t capacity);

/* What admission is checked against: the pinned root, the capability a
 * writer's chain must carry, and -- for an add -- the clock and the
 * revocations this host holds. */
typedef struct fzn_roster_authority {
	const uint8_t *root;
	const fzn_cap_id_t *capability;
	const fzn_sign_ops_t *sign;
	uint64_t now;
	const fzn_revocation_store_t *revocations;
} fzn_roster_authority_t;

/* Verify a record and apply it. `hops` is the writer's chain from the root,
 * opened, and `hop_count` 0 when the writer is the root. OK when the record is
 * now reflected, including when it already was. */
fzn_roster_err_t fzn_roster_admit(fzn_roster_t *roster, fzn_roster_record_t record,
                                  const fzn_chain_hop_t *hops, size_t hop_count,
                                  const fzn_roster_authority_t *authority);

/* RE-ADMIT A RECORD THIS HOST ADMITTED BEFORE, from its own store, at start.
 *
 * The signature and the chain are verified as `fzn_roster_admit` verifies
 * them, and the clock and the revocations are NOT consulted: this host
 * already decided this record, and a restart must reproduce that decision
 * rather than take a new one. Without that, a removal admitted a minute
 * before its writer was revoked would be refused at the next start and the
 * contact it removed would come back -- the roster changing because a process
 * restarted. `authority->now` and `->revocations` are ignored.
 *
 * NEVER FOR BYTES FROM ANOTHER HOST. Everything that arrives is admitted with
 * `fzn_roster_admit`; this is only the host's own record of what it admitted
 * already, read back. */
fzn_roster_err_t fzn_roster_restore(fzn_roster_t *roster, fzn_roster_record_t record,
                                    const fzn_chain_hop_t *hops, size_t hop_count,
                                    const fzn_roster_authority_t *authority);

/*
 * A BUNDLE: a record and its writer's chain, as they travel together.
 *
 * A receiver checks standing itself, so the chain has to arrive with the
 * record -- the record names its writer and nothing else. Neither part needs
 * a signature of its own here: the record is signed by its writer and every
 * hop by its grantor, so the bundle is two self-authenticating things side by
 * side, and a bundle whose chain was swapped for somebody else's is refused
 * at admission for standing, not accepted.
 *
 *     off  len  field
 *       0    1  hop_count     0 when the writer is the root; at most 8
 *       1    2  record_len    FZN_ROSTER_MIN_LEN .. FZN_ROSTER_MAX_LEN
 *       3    n  record
 *     3+n  179  hops, hop_count of them
 */
#define FZN_ROSTER_BUNDLE_HEAD_LEN 3u
#define FZN_ROSTER_BUNDLE_LEN(record_len, hop_count) \
	((size_t)FZN_ROSTER_BUNDLE_HEAD_LEN + (size_t)(record_len) \
	 + (size_t)(hop_count) * (size_t)FZN_HOP_LEN)
#define FZN_ROSTER_BUNDLE_MAX_LEN FZN_ROSTER_BUNDLE_LEN(FZN_ROSTER_MAX_LEN, FZN_CHAIN_MAX_HOPS)

typedef struct fzn_roster_bundle {
	fzn_roster_record_t record;
	fzn_chain_hop_t hops[FZN_CHAIN_MAX_HOPS];
	size_t hop_count;
} fzn_roster_bundle_t;

/* Pack `record` with the writer's chain, `hops` as the encoded hops. */
fzn_roster_err_t fzn_roster_bundle_pack(const uint8_t *record, size_t record_len,
                                        const uint8_t (*hops)[FZN_HOP_LEN], size_t hop_count,
                                        uint8_t *out, size_t out_cap, size_t *out_len);

/* Open a bundle: the record's shape and every hop's, not their signatures --
 * `fzn_roster_admit` verifies. The views point into `bytes`. */
fzn_roster_err_t fzn_roster_bundle_open(const uint8_t *bytes, size_t len,
                                        fzn_roster_bundle_t *out);

/* The subject's active incarnation into `incarnation`: the live one -- added
 * and not removed -- whose add has the greatest `(seq, writer)`. 1 when there
 * is one, 0 when the subject is absent or every incarnation of it is removed. */
int fzn_roster_active(const fzn_roster_t *roster, const uint8_t subject[FZN_PUBKEY_LEN],
                      uint8_t incarnation[FZN_ROSTER_INCARNATION_LEN]);

/* Whether this incarnation of the subject has been removed. */
int fzn_roster_removed(const fzn_roster_t *roster, const uint8_t subject[FZN_PUBKEY_LEN],
                       const uint8_t incarnation[FZN_ROSTER_INCARNATION_LEN]);

#endif /* FZN_ROSTER_H */
