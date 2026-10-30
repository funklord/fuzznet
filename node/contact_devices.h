/*
 * A CONTACT'S DEVICES, as this node reaches them and is reached by them,
 * project.md sec 614: step 2b-ii of sec 610, laid out as
 * `node/contact_devices.situ`.
 *
 * A pairing is one device to one host (`node/pair.h`), so delivering
 * between two users -- any device of the sender, any listed host of the
 * recipient, as the holder decided -- needs a session for every such pair.
 * None of them needs a card. A session is the device's agreement key
 * against the host's prekey, which X25519 makes the same from either end
 * (`node/provision.c`), so each side builds its own half from the other
 * side's PUBLIC prekey record: the host pairs the device as a sponsor
 * does (`fzn_node_pair`), the device builds its pairing from the host's
 * prekey. What has to cross is only who the keys are.
 *
 * AN ENTRY says: this prekey record's host is a device of the user whose
 * root is `owner`. It is that user's root itself, with no chain; or a key
 * the root's chain grants the estate's MEMBER capability -- the one the
 * remote hop checks, derived from the service and product and so the same
 * in every estate of the product -- and not any capability, since a user
 * grants its contacts capabilities too, and a contact is not a device.
 * A host's entry also carries where it is reached, as its own estate's
 * `net/address` says; a device that is only a sender carries none.
 *
 * WHAT IS NOT SIGNED: where a host is reached. The record is the device's
 * signature and the chain its owner's, but the address and port beside
 * them are signed by nobody (sec 764): they are vouched for by whoever
 * offered the entry -- the contact's own host, its owner checked, or a
 * member of this estate passing on one it kept. One moved misdirects
 * frames sealed for the device, which it alone can open: a delivery lost,
 * not one read.
 *
 * REVOCATIONS IN THE OTHER ESTATE, sec 776: its ROOT'S, carried here by
 * the messages at the end of this file and judged by
 * `fzn_contact_device_revoked`. A root acts for its estate alone at every
 * k (sec 403), so what it signed is the estate's decision whatever else this
 * node cannot see; votes of its members and admins, and of its other roots,
 * are not carried. The contact relation itself (`node/roster`) is what
 * stops a removed contact.
 *
 * Kept in persist slot FZN_PERSIST_CONTACT_DEVICE, one row per device keyed
 * by its key, as encoded. CORE: it decides whom this node pairs.
 */
#ifndef FZN_NODE_CONTACT_DEVICES_H
#define FZN_NODE_CONTACT_DEVICES_H

#include <stddef.h>
#include <stdint.h>

#include "../chain/chain.h"
#include "../chain/revocation.h"
#include "../persist/persist.h"
#include "../prekey/prekey.h"

#define FZN_CONTACT_DEVICE_VERSION 1u
#define FZN_CONTACT_DEVICE_ADDRESS_MAX 253u
/* THE ROOM A CALLER MAY START WITH, not a limit, sec 704: every contact's
 * devices together, thousands for a user with hundreds of contacts. Past
 * 128 the listing once failed, and delivery to every contact stopped with
 * nothing said. */
#define FZN_CONTACT_DEVICES_MAX 128u
#define FZN_CONTACT_DEVICE_HEAD_LEN (1u + FZN_PUBKEY_LEN + FZN_PREKEY_LEN_TOTAL)
#define FZN_CONTACT_DEVICE_MAX                                                                \
	(FZN_CONTACT_DEVICE_HEAD_LEN + 1u + FZN_CONTACT_DEVICE_ADDRESS_MAX + 2u + 1u            \
	 + FZN_CHAIN_MAX_HOPS * FZN_HOP_LEN)

typedef enum fzn_contact_device_err {
	FZN_CONTACT_DEVICE_OK = 0,
	FZN_CONTACT_DEVICE_ERR_MALFORMED = -1, /* a null, or a field out of range */
	FZN_CONTACT_DEVICE_ERR_SHAPE = -2,     /* bytes that are not an entry */
	FZN_CONTACT_DEVICE_ERR_REFUSED = -3,   /* its record or chain does not hold */
	FZN_CONTACT_DEVICE_ERR_STALE = -4,     /* the one kept has a newer record */
	FZN_CONTACT_DEVICE_ERR_ABSENT = -5,    /* none kept for that device */
	FZN_CONTACT_DEVICE_ERR_BACKEND = -6,   /* the store refused, or cannot list */
	FZN_CONTACT_DEVICE_ERR_ROOM = -7       /* more kept than the caller's room */
} fzn_contact_device_err_t;

const char *fzn_contact_device_err_str(fzn_contact_device_err_t err);

typedef struct fzn_contact_device {
	uint8_t owner[FZN_PUBKEY_LEN];
	/* The device's prekey record, as its device signed it. */
	uint8_t record[FZN_PREKEY_LEN_TOTAL];
	/* Where it is reached; `port` 0 and no address for a device that is
	 * not one. */
	char address[FZN_CONTACT_DEVICE_ADDRESS_MAX + 1u];
	size_t address_len;
	uint16_t port;
	/* The owner's chain to it for the member capability; none when it is
	 * the owner. */
	uint8_t hops[FZN_CHAIN_MAX_HOPS][FZN_HOP_LEN];
	size_t hop_count;
} fzn_contact_device_t;

/* The device's key: its prekey record's host. */
const uint8_t *fzn_contact_device_key(const fzn_contact_device_t *d);

fzn_contact_device_err_t fzn_contact_device_encode(const fzn_contact_device_t *d, uint8_t *out,
                                                   size_t cap, size_t *len);
fzn_contact_device_err_t fzn_contact_device_decode(const uint8_t *bytes, size_t len,
                                                   fzn_contact_device_t *out);

/* WHETHER `d` HOLDS: its record is signed by its host, and its host is its
 * owner with no chain, or the grantee of a chain from the owner for
 * `member` (the member capability) valid at `now`. REFUSED otherwise. */
fzn_contact_device_err_t fzn_contact_device_verify(const fzn_contact_device_t *d,
                                                   const fzn_sign_ops_t *sign,
                                                   const fzn_cap_id_t *member, uint64_t now);

/* KEEP `d`, verified by the caller: STALE when the record kept for that
 * device is newer; otherwise it replaces it, so an address or a chain
 * renewed under the same record is taken. */
fzn_contact_device_err_t fzn_contact_device_keep(const fzn_persist_ops_t *store,
                                                 const fzn_contact_device_t *d);

fzn_contact_device_err_t fzn_contact_device_get(const fzn_persist_ops_t *store,
                                                const uint8_t key[FZN_PUBKEY_LEN],
                                                fzn_contact_device_t *out);

/* Every device kept, in the store's order, walked (`fzn_persist_each`) into
 * `cap`: ROOM with `*count` the number kept when that is more, so the
 * caller can give room and list again, sec 704. BACKEND when the store will
 * not walk. */
fzn_contact_device_err_t fzn_contact_device_list(const fzn_persist_ops_t *store,
                                                 fzn_contact_device_t *out, size_t cap,
                                                 size_t *count);

/* Forget a device. ABSENT when none was kept. */
fzn_contact_device_err_t fzn_contact_device_remove(const fzn_persist_ops_t *store,
                                                   const uint8_t key[FZN_PUBKEY_LEN]);

/* ---- the messages, `node/contact_devices.situ` ---------------------------
 *
 * Notes-sync's version byte and type space, after delivery's 28:
 *
 *   OFFER  29  one entry: a device of the asker's user, offered to a
 *              contact's host, which pairs it (a contact asks)
 *   TAKEN  30  whether it was taken
 *   QUERY  31  `from`, and whose: HOSTS, the answerer's estate's hosts (a
 *              contact asks); KEPT, the contact devices it keeps (a member
 *              asks, so what one member learned reaches the rest)
 *   LIST   32  `from`, how many, whether more follow, then each entry
 *              after a 16-bit length
 */
#define FZN_CONTACT_DEVICES_VERSION 2u
#define FZN_CONTACT_DEVICES_OFFER 29u
#define FZN_CONTACT_DEVICES_TAKEN 30u
#define FZN_CONTACT_DEVICES_QUERY 31u
#define FZN_CONTACT_DEVICES_LIST 32u
#define FZN_CONTACT_DEVICES_HOSTS 0u
#define FZN_CONTACT_DEVICES_KEPT 1u
#define FZN_CONTACT_DEVICES_QUERY_LEN 4u
#define FZN_CONTACT_DEVICES_LIST_HEAD_LEN 5u
#define FZN_CONTACT_DEVICES_TAKEN_LEN 3u
/* The largest answer a listing writes, and the reply an asker reads into:
 * two of the largest entries at least. */
#define FZN_CONTACT_DEVICES_REPLY_MAX 4096u

/* How a node asks another: send `request`, fill `reply`. Nonzero on an
 * answer. */
typedef int (*fzn_contact_devices_ask_t)(void *ctx, const uint8_t *request, size_t request_len,
                                         uint8_t *reply, size_t reply_cap, size_t *reply_len);

/* OFFER `d` through `ask`: 1 taken, 0 refused, -1 no answer. */
int fzn_contact_devices_offer(const fzn_contact_device_t *d, fzn_contact_devices_ask_t ask,
                              void *ctx);

/* THE OFFER'S TWO HALVES, for a caller that awaits the answer itself (sec
 * 636): the request, in a buffer of FZN_CONTACT_DEVICES_OFFER_MAX, and its
 * answer read as the offer above reads it. */
#define FZN_CONTACT_DEVICES_OFFER_MAX (2u + FZN_CONTACT_DEVICE_MAX)

int fzn_contact_devices_offer_request(const fzn_contact_device_t *d, uint8_t *request,
                                      size_t cap, size_t *request_len);

int fzn_contact_devices_offer_reply(const uint8_t *reply, size_t reply_len);

/* AN OFFER, answered: `take` is handed the entry decoded -- not verified,
 * which is its to do -- and says whether it took it. 0 for anything that is
 * not an OFFER, so a caller dispatching on the first bytes falls through. */
size_t fzn_contact_devices_offer_answer(const uint8_t *request, size_t request_len,
                                        int (*take)(void *ctx, const fzn_contact_device_t *d),
                                        void *ctx, uint8_t *reply, size_t reply_cap);

/* ASK FOR `whose` (HOSTS or KEPT) through `ask`, page by page, handing each
 * entry decoded to `take` -- unverified, its to do. How many were handed
 * over, in `*count`; 0 when an answer did not come or did not read. */
int fzn_contact_devices_query(int whose, fzn_contact_devices_ask_t ask, void *ctx,
                              void (*take)(void *ctx, const fzn_contact_device_t *d),
                              void *take_ctx, size_t *count);

/* THE SAME QUERY AS STEPS, sec 636: begin writes the first page's request;
 * each step takes its answer -- NULL for none -- handing each device to
 * `take`, and writes the next page's or sets `*done`. 0 from a step on no
 * answer or nonsense, which ends it, as above. `count` is the struct's. A
 * reply may be FZN_CONTACT_DEVICES_REPLY_MAX bytes. */
typedef struct fzn_contact_devices_querying {
	int whose, live;
	void (*take)(void *ctx, const fzn_contact_device_t *d);
	void *take_ctx;
	size_t from, count;
} fzn_contact_devices_querying_t;

int fzn_contact_devices_query_begin(fzn_contact_devices_querying_t *q, int whose,
                                    void (*take)(void *ctx, const fzn_contact_device_t *d),
                                    void *take_ctx, uint8_t *request, size_t cap,
                                    size_t *request_len);

int fzn_contact_devices_query_step(fzn_contact_devices_querying_t *q, const uint8_t *reply,
                                   size_t reply_len, uint8_t *request, size_t cap,
                                   size_t *request_len, int *done);

/* A QUERY, answered: `entry_at` fills the `i`th entry of what `whose`
 * asks for, 0 past the last. As many as fit from `from`, and whether more
 * follow. 0 for anything that is not a QUERY, or `whose` this answerer will
 * not answer -- `entry_at` is NULL for it. */
size_t fzn_contact_devices_query_answer(const uint8_t *request, size_t request_len,
                                        int (*hosts_at)(void *ctx, size_t i,
                                                        fzn_contact_device_t *out),
                                        int (*kept_at)(void *ctx, size_t i,
                                                       fzn_contact_device_t *out),
                                        void *ctx, uint8_t *reply, size_t reply_cap);

/* ---- a contact's revocations, sec 776 -----------------------------------
 *
 * A DEVICE THE CONTACT REVOKED WAS STILL ONE LINES WENT TO: an entry was
 * never forgotten while its owner stood, so a stolen phone its owner cut
 * off kept receiving this user's lines, and kept speaking for the contact.
 *
 * WHAT CROSSES is the contact's ROOT'S signed records for the member
 * capability -- revocations and withdrawals, 242 bytes each and
 * self-authenticating -- asked of one of its hosts each round. A record is
 * taken only when its issuer is the contact asked about and its capability
 * the member one; it is admitted into a store of this node's for contacts'
 * records, whose admission handles stale copies, supersession and
 * withdrawals in any order (`chain/revocation.h`), and saved in slot
 * FZN_PERSIST_CONTACT_REVOCATION when the store holds exactly it.
 *
 * ONLY THE ROOT'S, because only the root's word is the estate's whatever
 * this node cannot see: at k above 1 a member's or an admin's vote counts
 * only with others, and another root's only while the contact's root set
 * names it, and neither the votes nor the set crosses. So nothing judged
 * here is a revocation the contact's estate did not make; what it may miss
 * is one the root did not sign.
 *
 * THE JUDGMENT, `fzn_contact_device_revoked`: a device falls when the
 * owner's live revocation names it, or names a key its chain passes through
 * with no line drawn -- a vote whose cut is zero trusts none of that key's
 * acts, its grants among them, so the device falls in its own estate too.
 * Under a cut, whether the grant lies before the line is the contact's act
 * log's to say, which does not cross, so that device is not judged here:
 * failing open there is what this node did before, and failing shut would
 * cut a device its own estate keeps.
 *
 *   REVOKED  33  `from` (32 bits): the root's records, from the `from`th
 *   RECORDS  34  `from` echoed, how many, whether more follow, then each
 *                record, FZN_REVOCATION_LEN bytes
 */
#define FZN_CONTACT_DEVICES_REVOKED 33u
#define FZN_CONTACT_DEVICES_RECORDS 34u
#define FZN_CONTACT_DEVICES_REVOKED_LEN 6u
#define FZN_CONTACT_DEVICES_RECORDS_HEAD_LEN 8u

/* THE QUERY AS STEPS, as the devices query is: begin writes the first
 * page's request; each step takes its answer, handing each record to
 * `take` -- not opened, nor checked, which is the taker's -- and writes the
 * next page's or sets `*done`. 0 from a step on no answer or nonsense. */
typedef struct fzn_contact_revoked_querying {
	int live;
	void (*take)(void *ctx, const uint8_t record[FZN_REVOCATION_LEN]);
	void *take_ctx;
	uint32_t from;
	size_t count;
} fzn_contact_revoked_querying_t;

int fzn_contact_revoked_query_begin(fzn_contact_revoked_querying_t *q,
                                    void (*take)(void *ctx,
                                                 const uint8_t record[FZN_REVOCATION_LEN]),
                                    void *take_ctx, uint8_t *request, size_t cap,
                                    size_t *request_len);

int fzn_contact_revoked_query_step(fzn_contact_revoked_querying_t *q, const uint8_t *reply,
                                   size_t reply_len, uint8_t *request, size_t cap,
                                   size_t *request_len, int *done);

/* A REVOKED QUERY, answered: `record_at` fills the `i`th record, 0 past the
 * last. As many as fit FZN_CONTACT_DEVICES_REPLY_MAX from `from`, and
 * whether more follow. 0 for anything that is not a REVOKED query. */
size_t fzn_contact_revoked_answer(const uint8_t *request, size_t request_len,
                                  int (*record_at)(void *ctx, size_t i,
                                                   uint8_t out[FZN_REVOCATION_LEN]),
                                  void *ctx, uint8_t *reply, size_t reply_cap);

/* TAKE ONE OF `owner`'s RECORDS into `revocations` -- this node's store for
 * contacts' records, single-rooted, quorum 1 -- and save it in `store`:
 * OK when the store now holds exactly it, saved, or holds a newer record for
 * its triple, so it was a stale copy; REFUSED when its issuer is not
 * `owner`, its capability not `member`, or it will not admit; ROOM when the
 * revocation store is full -- give it room (`fzn_revocation_store_use`) and
 * take it again; BACKEND when it is held and not saved. */
fzn_contact_device_err_t fzn_contact_revocation_take(fzn_revocation_store_t *revocations,
                                                     const fzn_persist_ops_t *store,
                                                     const uint8_t owner[FZN_PUBKEY_LEN],
                                                     const fzn_cap_id_t *member,
                                                     const uint8_t record[FZN_REVOCATION_LEN],
                                                     const fzn_sign_ops_t *sign,
                                                     const fzn_hash_ops_t *hash);

/* At start: every record saved, admitted again as its issuer's, into
 * `revocations`; how many in `*count`. ROOM when the store filled -- give it
 * room and load again, admission being idempotent. A row that will not
 * read or admit is passed over and counted in `*skipped`: these are other
 * estates' records, and one bad row must not keep this node from starting. */
fzn_contact_device_err_t fzn_contact_revocations_load(fzn_revocation_store_t *revocations,
                                                      const fzn_persist_ops_t *store,
                                                      const fzn_sign_ops_t *sign,
                                                      const fzn_hash_ops_t *hash, size_t *count,
                                                      size_t *skipped);

/* WHETHER `d` FALLS by its owner's revocations in `revocations`, as the
 * section above judges. 0 for a device that is its owner, and for a store
 * that holds nothing of the owner's. */
int fzn_contact_device_revoked(const fzn_contact_device_t *d,
                               const fzn_revocation_store_t *revocations,
                               const fzn_cap_id_t *member);

#endif /* FZN_NODE_CONTACT_DEVICES_H */
