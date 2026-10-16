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
 * WHAT IS NOT CHECKED: revocations in the other estate. Its revocation
 * store is not this node's, so a device the contact revoked is still taken
 * here until the contact's roster or a later entry says otherwise; the
 * contact relation itself (`node/roster`) is what stops a removed contact.
 *
 * Kept in persist slot FZN_PERSIST_CONTACT_DEVICE, one row per device keyed
 * by its key, as encoded. CORE: it decides whom this node pairs.
 */
#ifndef FZN_NODE_CONTACT_DEVICES_H
#define FZN_NODE_CONTACT_DEVICES_H

#include <stddef.h>
#include <stdint.h>

#include "../chain/chain.h"
#include "../persist/persist.h"
#include "../prekey/prekey.h"

#define FZN_CONTACT_DEVICE_VERSION 1u
#define FZN_CONTACT_DEVICE_ADDRESS_MAX 253u
/* How many a listing reads at once: a contact's devices, every contact. */
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
	FZN_CONTACT_DEVICE_ERR_BACKEND = -6    /* the store refused, or cannot list */
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

/* Every device kept, `cap` of them, in the store's order. BACKEND when the store
 * will not list or holds more than `cap`. */
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

#endif /* FZN_NODE_CONTACT_DEVICES_H */
