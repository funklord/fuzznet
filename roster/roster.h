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
 * subject names the incarnation it concerns, and a removal is about one
 * incarnation. A record naming a removed incarnation changes nothing, however
 * high its `seq` -- so a stale update cannot bring a subject back under ANY
 * concurrency, because nothing here orders by clock or sequence to decide
 * it. A deliberate re-add mints a new incarnation and is a fresh subject,
 * even for the same key.
 *
 * A REMOVAL SUSPENDS, AND k OF THEM RETIRE. sec 394, the holder's decisions
 * of 2026-09-29. A removal from one writer SUSPENDS the incarnation at once:
 * nothing is shared with it and nothing deleted, and it is reversible in the
 * one way that matters -- if its writer turns out revoked, the suspension is
 * void. Removals of the same incarnation from `k` DISTINCT writers RETIRE it:
 * that is the agreement an irreversible act waits for, and a second device
 * confirming is simply that device removing the same incarnation, so there is
 * no separate confirm record. `k` is the estate's (default
 * FZN_ROSTER_K_DEFAULT); the root counts as one writer like any other.
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
 * EVERYTHING IS JUDGED WHEN THE ROSTER IS READ, AND NOTHING WHEN IT ARRIVES,
 * beyond a record's own signature and its writer's chain's structure. Which
 * writers count is decided by the revocations the READER passes in: a
 * writer any of whose hops is revoked counts for nothing, its adds, its
 * suspensions and its share of a retirement alike. So two hosts holding the
 * same records and the same revocations give the same answer whatever order
 * any of it arrived in, and a revocation learned late corrects the answer on
 * the next read. The first version refused a revoked writer's removal on
 * arrival (d83ac2c); under peer-to-peer carriage that depended on which a
 * host heard first, the removal or the revocation, and did not converge.
 *
 * THE CLOCK IS NOT CONSULTED. A record carries no time anybody can trust, so
 * a writer's chain is checked as of its newest hop's issue: a grant expiring
 * later does not undo what was written while it held. Only a revocation
 * withdraws, which is the library's rule since sec 345.
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
	/* No room for the entry or its writer. A refused removal is a contact
	 * left in place, so this is the fail-open the tables' sizes decide; see
	 * project.md sec 388. */
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
/* The default number of distinct writers whose removals retire an
 * incarnation. The estate's to set; 2 so that one stolen device cannot. */
#define FZN_ROSTER_K_DEFAULT 2u
/* The most distinct removers an entry keeps: enough for any k an estate
 * sets, since a retirement needs only k of them. */
#define FZN_ROSTER_REMOVERS_MAX 4u

/* A WRITER AS THE ROSTER REMEMBERS IT: its key, and just enough of its chain
 * to ask later whether any hop has been revoked -- each hop's grantor and
 * grantee, and the capability they carry. Held once in a small table and
 * pointed at by entries, since a user's writers are few and their records
 * many. `hop_count` 0 is the root, which no revocation reaches. */
typedef struct fzn_roster_writer {
	uint8_t key[FZN_PUBKEY_LEN];
	fzn_cap_id_t capability;
	size_t hop_count;
	uint8_t grantor[FZN_CHAIN_MAX_HOPS][FZN_PUBKEY_LEN];
	uint8_t grantee[FZN_CHAIN_MAX_HOPS][FZN_PUBKEY_LEN];
} fzn_roster_writer_t;

/* One incarnation, as this host holds it. Writers are indices into the
 * roster's writer table. An entry can exist with only removals: a removal
 * that overtook its add is stored, so the add arriving later lands on it. */
typedef struct fzn_roster_entry {
	uint8_t subject[FZN_PUBKEY_LEN];
	uint8_t incarnation[FZN_ROSTER_INCARNATION_LEN];
	int added;
	uint64_t add_seq;
	size_t add_writer;
	size_t remover_count;
	size_t remover[FZN_ROSTER_REMOVERS_MAX];
} fzn_roster_entry_t;

typedef struct fzn_roster {
	fzn_roster_entry_t *entries;
	size_t capacity;
	size_t used;
	fzn_roster_writer_t *writers;
	size_t writer_capacity;
	size_t writers_used;
	/* The greatest `seq` any admitted record carried, so a writer here can
	 * number its next record past everything it has seen. */
	uint64_t seq_seen;
} fzn_roster_t;

fzn_roster_err_t fzn_roster_init(fzn_roster_t *roster, fzn_roster_entry_t *entries,
                                 size_t capacity, fzn_roster_writer_t *writers,
                                 size_t writer_capacity);

/* What a record is checked against as it arrives: the pinned root, the
 * capability a writer's chain must carry, and the verifier. No clock and no
 * revocations -- those are the reader's (see the header). */
typedef struct fzn_roster_authority {
	const uint8_t *root;
	const fzn_cap_id_t *capability;
	const fzn_sign_ops_t *sign;
} fzn_roster_authority_t;

/* Verify a record and apply it. `hops` is the writer's chain from the root,
 * opened, and `hop_count` 0 when the writer is the root. OK when the record is
 * now reflected, including when it already was. */
fzn_roster_err_t fzn_roster_admit(fzn_roster_t *roster, fzn_roster_record_t record,
                                  const fzn_chain_hop_t *hops, size_t hop_count,
                                  const fzn_roster_authority_t *authority);

/* RE-ADMIT A RECORD THIS HOST ADMITTED BEFORE, from its own store, at start.
 *
 * The same as `fzn_roster_admit` since sec 394, when admission stopped
 * consulting the clock and the revocations and both became the reader's: a
 * restart reproduces exactly what was admitted, because nothing admission
 * decides could have changed. Kept so callers that read their store back say
 * so. */
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

/* WHAT A HOST SEES FOR ONE INCARNATION, judged against `revocations` -- the
 * ones this host holds, or NULL for none -- with `k` the estate's number of
 * distinct writers a retirement needs (0 means FZN_ROSTER_K_DEFAULT). */
typedef enum fzn_roster_state {
	/* Nothing held, or only records whose writers are revoked. */
	FZN_ROSTER_ABSENT = 0,
	/* Added by an unrevoked writer, and nobody unrevoked has removed it. */
	FZN_ROSTER_ACTIVE = 1,
	/* At least one unrevoked writer removed it: share nothing with it. */
	FZN_ROSTER_SUSPENDED = 2,
	/* `k` distinct unrevoked writers removed it: permanent, and what
	 * deleting the subject's data waits for. */
	FZN_ROSTER_RETIRED = 3
} fzn_roster_state_t;

fzn_roster_state_t fzn_roster_state(const fzn_roster_t *roster,
                                    const uint8_t subject[FZN_PUBKEY_LEN],
                                    const uint8_t incarnation[FZN_ROSTER_INCARNATION_LEN],
                                    const fzn_revocation_store_t *revocations, size_t k);

/* The subject's active incarnation into `incarnation`: of those ACTIVE under
 * `revocations` and `k`, the one whose add has the greatest `(seq, writer)`.
 * 1 when there is one, 0 when the subject is absent, suspended or retired in
 * every incarnation. */
int fzn_roster_active(const fzn_roster_t *roster, const uint8_t subject[FZN_PUBKEY_LEN],
                      const fzn_revocation_store_t *revocations, size_t k,
                      uint8_t incarnation[FZN_ROSTER_INCARNATION_LEN]);

#endif /* FZN_ROSTER_H */
