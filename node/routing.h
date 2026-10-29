/*
 * A USER'S ROUTING MANIFEST, project.md sec 611: fuzzypickles' host manifest
 * (its sec 10, blob v3) brought into fuzznet as step 2a of sec 610, laid out
 * as `node/routing.situ`. "Routing" rather than "manifest" because
 * `chain/manifest.h` is a revocation manifest, a different thing.
 *
 * WHAT IT SAYS: published reachability, not membership -- the addresses at
 * which a user's hosts may be reached, `address : port : transport :
 * metric`, lowest metric preferred. An entry names no key and confers no
 * authority; a host that wants no exposure is not listed and sits behind one
 * that is. A sender to the user tries the entries in order, and a host that
 * cannot take what it is sent says so.
 *
 * SIGNED OVER ITS STATEMENT: version, derivation version, generation, when,
 * the content hash and the signer -- 82 bytes, under "fuzznet.routing" and a
 * NUL. The document is bound by the hash, so a user's own hosts, each
 * deriving the document from the estate's settings, check the statement
 * alone, and a relay can edit nothing. The signer is the estate's root, or a
 * holder of its admin capability whose chain travels with the manifest.
 *
 * NEWEST BY (generation, signer), never by the clock: the timestamp is a
 * property of the statement and not of the content.
 */
#ifndef FZN_NODE_ROUTING_H
#define FZN_NODE_ROUTING_H

#include <stddef.h>
#include <stdint.h>

#include "../chain/chain.h"
#include "../persist/persist.h"
#include "../session/commitment.h"

#define FZN_ROUTING_ENTRIES_MAX 16u
#define FZN_ROUTING_ADDRESS_MAX 253u
#define FZN_ROUTING_STATEMENT_LEN 82u
#define FZN_ROUTING_HASH_LEN 32u
#define FZN_ROUTING_TRANSPORT_UDP 1u
/* The longest encoding: statement, document, chain and signature. */
#define FZN_ROUTING_MAX                                                                         \
	(FZN_ROUTING_STATEMENT_LEN + 2u + FZN_ROUTING_ENTRIES_MAX * (1u + FZN_ROUTING_ADDRESS_MAX \
	                                                            + 4u)                         \
	 + 1u + FZN_CHAIN_MAX_HOPS * FZN_HOP_LEN + FZN_SIG_LEN)

typedef enum fzn_routing_err {
	FZN_ROUTING_OK = 0,
	FZN_ROUTING_ERR_MALFORMED = -1, /* a null, or more entries than fit */
	FZN_ROUTING_ERR_SHAPE = -2,     /* bytes that are not a routing manifest */
	FZN_ROUTING_ERR_REFUSED = -3,   /* its hash, chain or signature does not hold */
	FZN_ROUTING_ERR_STALE = -4,     /* no newer than the one kept */
	FZN_ROUTING_ERR_ABSENT = -5,    /* none kept for that user */
	FZN_ROUTING_ERR_BACKEND = -6,   /* the store refused */
	FZN_ROUTING_ERR_FULL = -7       /* full, of entries no worse than this one */
} fzn_routing_err_t;

const char *fzn_routing_err_str(fzn_routing_err_t err);

typedef struct fzn_routing_entry {
	char address[FZN_ROUTING_ADDRESS_MAX + 1u];
	size_t address_len;
	uint16_t port;
	uint8_t transport;
	uint8_t metric;
} fzn_routing_entry_t;

typedef struct fzn_routing {
	uint64_t generation;
	uint64_t timestamp_ms;
	uint8_t content_hash[FZN_ROUTING_HASH_LEN];
	uint8_t signer[FZN_PUBKEY_LEN];
	int public_relay;
	fzn_routing_entry_t entries[FZN_ROUTING_ENTRIES_MAX];
	size_t n;
	uint8_t hops[FZN_CHAIN_MAX_HOPS][FZN_HOP_LEN];
	size_t hop_count;
	uint8_t sig[FZN_SIG_LEN];
} fzn_routing_t;

/* ADD AN ENTRY to the document, kept in canonical order -- metric ascending,
 * then address bytes, then port. MALFORMED for an address not of 1 to 253
 * bytes of letters, digits and `.-:`, a port of 0, the same address and
 * port twice, or past FZN_ROUTING_ENTRIES_MAX. */
fzn_routing_err_t fzn_routing_add(fzn_routing_t *r, const char *address, size_t address_len,
                                  uint16_t port, uint8_t transport, uint8_t metric);

/* OFFER AN ENTRY, sec 765: as `fzn_routing_add` while there is room; when
 * the document holds FZN_ROUTING_ENTRIES_MAX already, the entry takes the
 * place of the worst -- the last in canonical order, the highest metric --
 * when it comes before it, and is refused FULL when it does not. So a user
 * with more reachable hosts than a manifest holds publishes its best
 * rather than the first it happened to list. MALFORMED as `add`. */
fzn_routing_err_t fzn_routing_offer(fzn_routing_t *r, const char *address, size_t address_len,
                                    uint16_t port, uint8_t transport, uint8_t metric);

/* THE DOCUMENT'S HASH, from `public_relay` to the last entry, into `out`. */
int fzn_routing_content_hash(const fzn_routing_t *r, const fzn_hash_ops_t *hash,
                             uint8_t out[FZN_ROUTING_HASH_LEN]);

/* SIGN `r` as `signer` -- its secret behind `sign` -- at `generation` and
 * `now_ms`, carrying `hops` (`hop_count` of them, FZN_HOP_LEN each; none
 * for the root), which must be the signer's admin chain. */
fzn_routing_err_t fzn_routing_sign(fzn_routing_t *r, const fzn_hash_ops_t *hash,
                                   const fzn_sign_ops_t *sign,
                                   const uint8_t signer[FZN_PUBKEY_LEN],
                                   const uint8_t (*hops)[FZN_HOP_LEN], size_t hop_count,
                                   uint64_t generation, uint64_t now_ms);

/* THE MANIFEST OF THE USER WHOSE ROOT IS `root`: its document's hash holds,
 * and its signer is `root` with no chain, or the last grantee of a chain
 * from `root` for `admin` (may be NULL: then the root alone may sign), and
 * the statement's signature is the signer's. REFUSED otherwise. */
fzn_routing_err_t fzn_routing_verify(const fzn_routing_t *r, const fzn_hash_ops_t *hash,
                                     const fzn_sign_ops_t *sign,
                                     const uint8_t root[FZN_PUBKEY_LEN],
                                     const fzn_cap_id_t *admin, uint64_t now);

/* Whether `a` is newer than `b`: generation, then signer bytes. */
int fzn_routing_newer(const fzn_routing_t *a, const fzn_routing_t *b);

fzn_routing_err_t fzn_routing_encode(const fzn_routing_t *r, uint8_t *out, size_t cap,
                                     size_t *len);
fzn_routing_err_t fzn_routing_decode(const uint8_t *bytes, size_t len, fzn_routing_t *out);

/* KEEP `r`, verified by the caller, as the manifest of the user whose root
 * is `root`, in persist slot FZN_PERSIST_ROUTING: STALE when the one kept is
 * as new or newer. */
fzn_routing_err_t fzn_routing_keep(const fzn_persist_ops_t *store,
                                   const uint8_t root[FZN_PUBKEY_LEN], const fzn_routing_t *r);

/* THE MANIFEST KEPT for that user, as kept: ABSENT when none. */
fzn_routing_err_t fzn_routing_load(const fzn_persist_ops_t *store,
                                   const uint8_t root[FZN_PUBKEY_LEN], fzn_routing_t *out);

#endif /* FZN_NODE_ROUTING_H */
