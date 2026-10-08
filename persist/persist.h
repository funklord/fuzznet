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
 *   the identity seed    MUST. It IS the host: the key every capability
 *                        this host minted chains to, and the key its peers
 *                        pinned. Losing it makes a different host with the
 *                        same name, and nothing re-derives it. It was in
 *                        neither list here -- `chain.h` kept secrets out of
 *                        this library by design and the inventory followed,
 *                        until sec 136 had a node generate its identity and
 *                        something had to store what it generated. sec 375.
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
 *   fzn_node_peer_t      MUST, per remote peer a node serves. Losing it
 *                        leaves `fuzznetd` bound and serving NOBODY -- the
 *                        session keys and the capability chain came from an
 *                        out-of-band pairing card, so nothing re-derives
 *                        them and every device must be paired again. It was
 *                        absent from BOTH lists here until sec 366, which is
 *                        this file's own hazard in this file: absence
 *                        reading as not-required. Packed by
 *                        `node/peer_persist.h` rather than below, because
 *                        the type lives behind the generated schema and
 *                        this header does not.
 *   fzn_node_pairing_t   MUST, per node a DEVICE is paired to -- the same
 *                        pairing seen from the other side. Losing it leaves
 *                        the device holding no session keys for a node that
 *                        still holds its peer, so the node answers a device
 *                        that can no longer ask. Absent from both lists until
 *                        sec 377, the third time this inventory has missed a
 *                        pairing half. Packed by `node/pair.h`.
 *   issued revocations   MUST, per grantee a node has revoked. The store
 *                        below says revocations are refilled from
 *                        manifests, which is true of those LEARNED; one a
 *                        node ISSUED exists only here, and losing it
 *                        re-admits the device on the next start. Kept as the
 *                        signed record, since the store keeps no record to
 *                        save. `node/revoke.h`, sec 380.
 *   learned revocations  RETIRED with slot 10, sec 509: a root's vote
 *                        arrives in the journal like any other and is kept
 *                        with the learned votes in slot 11.
 *
 * Recoverable rather than required, and deliberately not served here:
 *
 *   fzn_state_t          rebuilt by replaying records. Persisting it is a
 *   fzn_journal_t        cache, and the journal decides what to re-fetch.
 *   fzn_revocation_store_t  refilled from manifests; sec 13d is the design.
 *                        A node refills it from the records in slots 9 and
 *                        11 instead, secs 380 and 399.
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

/* Longest blob any pack function BELOW produces, so a caller can size one
 * buffer and stop thinking about it. Asserted against each in persist.c.
 *
 * IT DOES NOT COVER `FZN_PERSIST_NODE_PEER`, which is the one variable-length
 * slot and is bounded by `FZN_NODE_PEER_BLOB_MAX` in `node/peer_persist.h`.
 * A node peer carries up to FZN_CHAIN_MAX_HOPS signed hops, so folding it in
 * would take this from 96 bytes to about 1.5 KB -- and a host that persists
 * a trust anchor and a prekey and serves no remote peers would carry that
 * buffer for nothing. sec 313 asked whether this library fits an ESP8266,
 * which is why 96 against 1.5 KB is a real difference rather than a tidy
 * one. A caller that serves remote peers sizes for both; one that does not
 * is unaffected. */
#define FZN_PERSIST_MAX 96u


typedef enum fzn_persist_slot {
	/* Whole-host, no subject. */
	FZN_PERSIST_TRUST = 1u,
	FZN_PERSIST_OWN_PREKEY = 2u,
	/* Per peer, keyed by that peer's identity. */
	FZN_PERSIST_PEER = 3u,
	FZN_PERSIST_SEND_CHAIN = 4u,
	FZN_PERSIST_RECV_CHAIN = 5u,
	/* Per remote peer the NODE serves, keyed by that peer's identity.
	 * `node/peer_persist.h` packs it; see the inventory above for why the
	 * functions are not in this file. */
	FZN_PERSIST_NODE_PEER = 6u,
	/* Whole-host, no subject: the seed this host's signing key derives
	 * from. `node/identity.h` loads or generates it. sec 375. */
	FZN_PERSIST_OWN_IDENTITY = 7u,
	/* Per node this host is paired TO, keyed by that node's root.
	 * `node/pair.h` packs it. sec 377. */
	FZN_PERSIST_PAIRED_NODE = 8u,
	/* Per grantee, the latest revocation THIS node issued for it.
	 * `node/revoke.h` packs it. sec 380. The file backend names slots in
	 * variable-width decimal up to FZN_PERSIST_FILE_SLOT_MAX, so slot 10
	 * is `10-...` beside every existing name unchanged (sec 382). */
	FZN_PERSIST_ISSUED_REVOCATION = 9u,
	/* 10 IS RETIRED, sec 509, and not to be reused: it held a revocation
	 * a member pulled from its root with `get revocation` (sec 384). A
	 * root's vote arrives in the journal like any other and lands in 11. */
	/* Per (issuer, capability, grantee), keyed by a hash of the three: a
	 * vote this node LEARNED from any peer, with the chain that entitles
	 * its issuer. `node/revoke.h` keeps it. sec 399. */
	FZN_PERSIST_VOTE = 11u,
	/* 12 IS RETIRED, sec 509, and not to be reused: it held the root
	 * log's entries (sec 407). A key's acts are its journal stream now. */
	/* Per record id: a root-add, a root-remove or a root's setting of k
	 * (sec 418) this node holds. `node/roots.h` keeps it. sec 407. */
	FZN_PERSIST_ROOT_CHANGE = 13u,
	/* Whole-host, no subject: the seed of the root key this node holds
	 * beside its identity, if any. `node/roots.h` keeps it. sec 409. */
	FZN_PERSIST_OWN_ROOT = 14u,
	/* Per record id: an admin's confirmation of another's admin grant,
	 * with the confirmer's admin chain. `node/revoke.h` keeps it. sec 415. */
	FZN_PERSIST_ADMIN_CONFIRM = 15u,
	/* Whole-host, no subject: this node's own admin chain, from a root to
	 * its identity for the admin capability. `node/revoke.h` keeps it.
	 * sec 416. */
	FZN_PERSIST_OWN_ADMIN = 16u,
	/* Per claim key: one writer's latest signed record about one note,
	 * the key derived from (note id, writer) by `notes/store.h`, which
	 * keeps it. sec 425. */
	FZN_PERSIST_NOTE = 17u,
	/* 18 IS RETIRED, sec 517, and not to be reused: it held the last
	 * sequence this host signed a note record at (sec 425). A host's note
	 * records are its journal stream 0 now, which numbers them. */
	/* Per note id: a purge awaiting consensus -- the hosts pinned to sign
	 * it off and which have. `notes/purge.h` keeps it. sec 427. */
	FZN_PERSIST_NOTE_PURGE = 19u,
	/* Per node key: a node that pulls notes from this one, and so holds
	 * copies a purge must ask about. `notes/sync.h` keeps it. sec 433. */
	FZN_PERSIST_NOTE_PARTNER = 20u,
	/* Per key: a contact, a key outside the estate this node knows by a
	 * name. `contact/contact.h` keeps it. sec 435. */
	FZN_PERSIST_CONTACT = 21u,
	/* Per share key: a subtree of notes shared with a contact -- what the
	 * node checks a contact's capability against. `notes/share.h` keeps
	 * it. sec 436. */
	FZN_PERSIST_NOTE_SHARE = 22u,
	/* Per row: a note a contact shared with this node, filed in that
	 * sharer's tree. `notes/received.h` keeps it. sec 437. */
	FZN_PERSIST_SHARED_NOTE = 23u,
	/* Per sharer: a share this node accepted, and the address its
	 * sharer's node is pulled from. `node/received.h` keeps it. sec 437. */
	FZN_PERSIST_RECEIVED_SHARE = 24u,
	/* Per group id: a group of contacts, its name and its members' keys.
	 * `contact/group.h` keeps it. sec 471. */
	FZN_PERSIST_CONTACT_GROUP = 25u,
	/* Per rule: a retention rule set while the node runs, filed under a
	 * hash of its canonical text. `log/rules.h` keeps it. sec 475. */
	FZN_PERSIST_LOG_RULE = 26u,
	/* Per record: an estate retention rule an ADMIN set, with the admin
	 * chain that entitles it. `node/roots.h` keeps it. sec 479. */
	FZN_PERSIST_ADMIN_RETENTION = 27u,
	/* Per record id: a roster record about a contact -- an add or a
	 * removal, signed by an estate member -- with its writer's chain.
	 * `node/roster.h` keeps it. sec 489. */
	FZN_PERSIST_ROSTER = 28u,
	/* Per row: a file shared -- its root and a contact's key, a group's
	 * id, or every contact. `node/files.h` keeps it. sec 493. */
	FZN_PERSIST_FILE_SHARE = 29u,
	/* Per record id: a succession -- one key succeeded by another -- with
	 * its issuer's admin chain. `node/succession.h` keeps it. sec 499. */
	FZN_PERSIST_SUCCESSION = 30u,
	/* Per note id: the note was purged, and a record of it is never filed
	 * again, from the journal or from anybody. `notes/purge.h` keeps it.
	 * sec 518. */
	FZN_PERSIST_NOTE_PURGED = 31u,
	/* Per note id: the key the note's content keys are wrapped under, kept
	 * here and never in the journal, so a purge can destroy it. sec 520. */
	FZN_PERSIST_NOTE_WRAP = 32u,
	/* Per hash: the bytes an operation-journal entry saved, as they were
	 * written to another slot, kept so the state can be replayed; erased
	 * when that row is removed. `node/opjournal.h` keeps it. sec 523. */
	FZN_PERSIST_OP_BYTES = 33u,
	/* Per (contact, month, device), keyed by a hash of the three: the key
	 * one device's lines in a conversation that month are sealed under,
	 * kept here and
	 * never in the journal, so a trimming rule can destroy it.
	 * `messages/messages.h` keeps it. sec 526. */
	FZN_PERSIST_CONVERSATION_KEY = 34u,
	/* Per line, keyed by a hash of its contact, direction and id: its
	 * latest mark, rebuilt from the journal when lost. NOT CORE: it is
	 * derived. `messages/messages.h` keeps it. sec 526. */
	FZN_PERSIST_MESSAGE_STATE = 35u,
	/* Keyed by hashes of what each row is: each conversation's index of
	 * lines, its read position, and how far each device's stream was taken
	 * in. NOT CORE: it is derived, and `fzn_messages_reindex` rebuilds it
	 * from the journal. `messages/messages.h` keeps it. sec 528. */
	FZN_PERSIST_MESSAGE_INDEX = 36u,
	/* Per line its index names, keyed by a hash of the writing device and
	 * the last part's sequence: the line as the store keeps it, opened once
	 * its key has been here (sec 539), so it outlives the journal's window.
	 * NOT DERIVED once the journal is cut. `messages/messages.h` keeps it.
	 * sec 536. */
	FZN_PERSIST_MESSAGE_LINE = 37u,
} fzn_persist_slot_t;

/* ONE PAST THE HIGHEST SLOT, for a caller that walks every slot: the
 * operation journal's snapshot (sec 524) lists each in turn. A slot added
 * above moves it, and persist_test holds it to the highest slot its core
 * and store lists name. */
#define FZN_PERSIST_SLOT_END 38u

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

/* The head every blob here carries: a version byte and a tag byte.
 *
 * PUBLIC SO A SECOND MODULE CAN WRITE ONE. `node/peer_persist.c` packs a type
 * this header cannot see -- `fzn_node_peer_t` lives behind `wire/seal.h`,
 * the one module that depends on generated code, and pulling that in here
 * would cost persist the independence its own opening paragraph claims. So
 * the head is stated once and shared, rather than a second module deriving
 * the same two bytes and drifting. */
#define FZN_PERSIST_HEAD_LEN 2u
#define FZN_PERSIST_BLOB_NODE_PEER 5u
#define FZN_PERSIST_BLOB_PAIRING 7u
#define FZN_PERSIST_BLOB_REVOCATION 8u
#define FZN_PERSIST_BLOB_VOTE 9u
/* 10 is retired with the root log's entries, sec 509, and not reused. */
#define FZN_PERSIST_BLOB_ROOT_ADD 11u
#define FZN_PERSIST_BLOB_ROOT_REMOVE 12u
#define FZN_PERSIST_BLOB_OWN_ROOT 13u
#define FZN_PERSIST_BLOB_ADMIN_CONFIRM 14u
#define FZN_PERSIST_BLOB_OWN_ADMIN 15u
#define FZN_PERSIST_BLOB_QUORUM_SET 16u
#define FZN_PERSIST_BLOB_NOTE 17u
/* 18 is retired with the notes' counter, sec 517, and not reused. */
#define FZN_PERSIST_BLOB_NOTE_PURGE 19u
#define FZN_PERSIST_BLOB_NOTE_PARTNER 20u
#define FZN_PERSIST_BLOB_CONTACT 21u
#define FZN_PERSIST_BLOB_NOTE_SHARE 22u
#define FZN_PERSIST_BLOB_SHARED_NOTE 23u
#define FZN_PERSIST_BLOB_RECEIVED_SHARE 24u
#define FZN_PERSIST_BLOB_CONTACT_GROUP 25u
#define FZN_PERSIST_BLOB_LOG_RULE 26u
/* A root's setting of one estate retention rule, in slot 13 beside the root
 * changes and the settings of k. `node/roots.c` keeps it. sec 476. */
#define FZN_PERSIST_BLOB_RETENTION_SET 27u
#define FZN_PERSIST_BLOB_ADMIN_RETENTION 28u
/* A roster record and its writer's chain, in slot 28. `node/roster.c`
 * keeps it. sec 489. */
#define FZN_PERSIST_BLOB_ROSTER 29u
/* A file's share row, in slot 29. `node/files.c` keeps it. sec 493. */
#define FZN_PERSIST_BLOB_FILE_SHARE 30u
/* A succession and its issuer's chain, in slot 30. `node/succession.c`
 * keeps it. sec 499. */
#define FZN_PERSIST_BLOB_SUCCESSION 31u
/* A note's purge mark, in slot 31: a version byte, the mark being the row.
 * `notes/purge.c` keeps it. sec 518. */
#define FZN_PERSIST_BLOB_NOTE_PURGED 32u
/* A note's wrap key, in slot 32: 32 bytes. `notes/store.c` keeps it.
 * sec 520. */
#define FZN_PERSIST_BLOB_NOTE_WRAP 33u

/* Write a blob head, or refuse when `cap` cannot hold head and body. */
fzn_persist_err_t fzn_persist_head_write(uint8_t *out, size_t cap, size_t body,
                                          uint8_t tag);

/* Check one, EXACTLY: `len` must be head plus body and no more. A trailing
 * byte is a second encoding of one blob, and this module refuses one for the
 * reason every decoder here does -- "ignore what you do not understand" is
 * how one format becomes several. */
fzn_persist_err_t fzn_persist_head_check(const uint8_t *bytes, size_t len,
                                          size_t body, uint8_t tag);

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
	/* WHICH SUBJECTS THIS BACKEND HOLDS FOR `slot`, written into `out` as
	 * `*count` subjects of FZN_PUBKEY_LEN bytes each, capped at `max`.
	 * Returns 1 on success and 0 on failure.
	 *
	 * OPTIONAL, AND NULL IS AN HONEST ANSWER. `load` and `save` need a
	 * subject the caller already has; a node starting up has none -- it is
	 * asking WHICH peers it was told about, and until this existed the
	 * answer could only come from somewhere outside this library. A
	 * backend that cannot enumerate (a keystore addressed only by name, an
	 * enclave) leaves it NULL, and a caller that needs it reports that
	 * rather than guessing.
	 *
	 * TRUNCATION IS A FAILURE, not a short answer. A backend holding more
	 * than `max` returns 0: a caller that took the first `max` would
	 * silently serve some of its peers, which is worse than serving none
	 * because nothing anywhere says which are missing. */
	int (*list)(void *ctx, fzn_persist_slot_t slot, uint8_t *out, size_t max,
	            size_t *count);
	/* FORGET WHAT `save` STORED under (slot, subject). Returns 1 when it is
	 * gone afterwards -- INCLUDING when it was never there, because the
	 * caller's question is "is it gone", and a second removal answering
	 * failure would make a retry after a lost reply look like a fault --
	 * and 0 when the backend could not remove it.
	 *
	 * OPTIONAL, like `list`, and NULL is an honest "this backend cannot
	 * forget" -- an append-only log, a write-once keystore. A caller that
	 * needs removal reports its absence rather than working round it.
	 *
	 * Added so a node can un-pair a device (sec 379). Until then nothing in
	 * this library could forget anything it had stored, so a device once
	 * paired was served until somebody deleted a file by hand and restarted
	 * the node. */
	int (*remove)(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject);
	void *ctx;
} fzn_persist_ops_t;

/* ---- which slots are core, and a store that routes by it ------------- */

/*
 * WHETHER A SLOT HOLDS WHAT KEEPS AN ATTACKER OUT. project.md sec 389,
 * decision 7b, in the holder's words: "anything that is needed to avoid
 * putting us in the arms of an attacker needs to be in the core dir",
 * whatever its size. Everything else -- what costs availability when lost,
 * not safety -- may live elsewhere, somewhere bigger and less guarded.
 *
 * CORE, and what losing or rolling back each would buy an attacker:
 *
 *   TRUST                the anchor: lost, the next root offered is pinned
 *   OWN_PREKEY           this host's key-agreement secret
 *   PEER                 prekeys this host pinned: lost, the next contact
 *                        re-pins whatever key it is shown (sec 392 records
 *                        this one as a judgement, the holder's to overrule)
 *   SEND_/RECV_CHAIN     ratchet positions: rolled back, keys are reused
 *   OWN_IDENTITY         the signing seed
 *   ISSUED_REVOCATION    lost, a revoked device is admitted again
 *   VOTE                 lost, a revocation short of its quorum again
 *   ROOT_CHANGE          lost, a removed root counts again
 *   OWN_ROOT             the seed of a root key: the estate's authority
 *   ADMIN_CONFIRM        lost, an admin grant falls short of its k - 1
 *   OWN_ADMIN            lost, this node votes and confirms as nobody
 *
 * NOT CORE: NODE_PEER and PAIRED_NODE, the sessions a node serves and a
 * device holds. Lost, a device re-pairs; nothing is admitted that was not.
 *
 * NOT CORE EITHER: NOTE, NOTE_PURGE and NOTE_PARTNER (secs 425, 427, 433).
 * A note is the user's data, signed, and a sibling holds the same records:
 * lost, it is fetched again, and rolled back, the signature still says who
 * wrote what. A lost purge leaves a trashed note held until it is emptied again,
 * and a lost partner one held by a node a purge forgot to ask: space and
 * convergence, not a door.
 *
 * NOT CORE: OP_BYTES (sec 523). The operation journal's kept bytes are a
 * record of states already written elsewhere; lost, the history is shorter,
 * and rolled back it holds bytes a later removal erased, which a removal of
 * that row erases again.
 *
 * NOT CORE: CONTACT (sec 435). A contact entry is a name for a key and
 * grants nothing; what a contact may do is the chains issued to it, revoked
 * as any chain is. Lost, a name is forgotten; rolled back, a removed name
 * returns, still granting nothing.
 *
 * CORE: NOTE_SHARE (sec 436), named rather than left to the default. A
 * share row is what a contact's capability is checked against, so a row
 * rolled back is a contact reading a subtree after it was unshared -- a
 * door, which is the holder's test for core.
 *
 * NOT CORE: SHARED_NOTE (sec 437). A copy of a note somebody else wrote
 * and signed, pulled from their node: lost, it is pulled again; rolled back,
 * an older copy is superseded on the next pull. Neither is a door.
 *
 * NOT CORE: RECEIVED_SHARE (sec 437). Lost, a share stops being pulled until
 * it is accepted again; rolled back, a share this node dropped is pulled
 * again, into the sharer's own tree.
 *
 * NOT CORE: LOG_RULE (sec 475). Lost, a rule stops applying and this
 * host's logs are kept longer; rolled back, a removed rule prunes again.
 * Retention decides how long a host keeps its own logs, not who reads them.
 *
 * NOT CORE: ADMIN_RETENTION (sec 479), as LOG_RULE is: it decides how long
 * logs stay, not who reads them. A root's retention records live in
 * ROOT_CHANGE, which is core for the root set's sake, not theirs.
 *
 * CORE: FILE_SHARE (sec 493), named rather than left to the default, as
 * NOTE_SHARE is: a row rolled back is a contact fetching a file after it
 * was unshared, or a private file served to every contact.
 *
 * CORE: SUCCESSION (sec 499), named rather than left to the default. One
 * rolled back moves a re-keyed device's references back to its revoked key:
 * a loss rather than a door, and the guarded place is where a loss costs
 * least to notice.
 *
 * CORE: ROSTER (sec 489), named rather than left to the default. A
 * removal rolled back is a removed contact served again -- a door.
 *
 * CORE: NOTE_WRAP (sec 520), named rather than left to the default. A wrap
 * key rolled back is one a purge destroyed come back, and with it every copy
 * of the note's content that escaped the purge readable again.
 *
 * CORE: NOTE_PURGED (sec 518), named rather than left to the default, for
 * the roster's reason. A note's records stay in its writers' journal
 * streams for good, so a mark rolled back is a purged note filed again from
 * history the next time the index is fed: a deletion undone.
 *
 * CORE: CONTACT_GROUP (sec 471), named rather than left to the default.
 * Membership decides which contacts a group share reaches, so a group
 * rolled back re-admits a member removed from it -- a door, as a share row
 * is.
 *
 * A SLOT THIS DOES NOT NAME IS CORE. A slot added later without a decision
 * about it lands where losing it costs the least, which is the guarded
 * place. 1 for core, 0 otherwise. */
int fzn_persist_slot_is_core(fzn_persist_slot_t slot);

/* WHETHER A SLOT HOLDS ONE ROW FOR THE WHOLE HOST, under a NULL subject,
 * rather than one per subject. `list` cannot enumerate these, since they
 * have no subject to list, so a caller walking every row loads them
 * instead. 1 for whole-host, 0 otherwise.
 *
 * INLINE, because it is the slots' vocabulary rather than code: the
 * operation journal asks it, and linking persist.c for it would bring the
 * trust, prekey and ratchet packers into every binary that journals. */
static inline int fzn_persist_slot_whole_host(fzn_persist_slot_t slot)
{
	switch (slot) {
	case FZN_PERSIST_TRUST:
	case FZN_PERSIST_OWN_PREKEY:
	case FZN_PERSIST_OWN_IDENTITY:
	case FZN_PERSIST_OWN_ROOT:
	case FZN_PERSIST_OWN_ADMIN:
		return 1;
	default:
		return 0;
	}
}

/* TWO BACKENDS AS ONE: every call for a core slot goes to `core`, every
 * other to `store`. `fzn_persist_route_ops` fills `ops` with dispatchers over
 * the route, which must outlive them. `list` and `remove` answer 0 when the
 * backend a slot routes to lacks them, as a single backend lacking them would.
 * `store` may be the same ops as `core`, which is one directory holding both,
 * as before sec 392. */
typedef struct fzn_persist_route {
	const fzn_persist_ops_t *core;
	const fzn_persist_ops_t *store;
} fzn_persist_route_t;

void fzn_persist_route_ops(fzn_persist_route_t *route, fzn_persist_ops_t *ops);

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
 * The host's identity seed: FZN_SIGN_SEED_LEN bytes, stored as they are and
 * restored by `fzn_sign_seat_t` rather than here, so this format knows no
 * signature scheme and the seed is the one copy.
 *
 * AN ALL-ZERO SEED IS REFUSED BOTH WAYS. It derives a real key that anybody
 * can compute, so a host signing with it is signing for everyone -- and a
 * file of zeroes is far likelier a truncated or never-written one than a key
 * somebody chose. The comparison is constant-time, since the bytes are a
 * secret whatever they turn out to be.
 *
 * A refused open leaves `seed_out` as it found it, as `secret_open` does.
 */
fzn_persist_err_t fzn_persist_identity_pack(const uint8_t seed[FZN_SIGN_SEED_LEN], uint8_t *out,
                                             size_t cap, size_t *len);
fzn_persist_err_t fzn_persist_identity_open(const uint8_t *bytes, size_t len,
                                             uint8_t seed_out[FZN_SIGN_SEED_LEN]);

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
