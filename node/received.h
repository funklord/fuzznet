/* Shares this node has accepted, and where to pull each from. sec 437.
 *
 * A contact's node grants this one a share (`grant share` there) and hands
 * over a card; `add received` here takes the card as a pairing -- the session
 * this node asks under -- and records the sharer with the address it is
 * reached at, since a pairing carries none (sec 377). The daemon pulls each
 * row's sharer into that sharer's tree (`notes/received.h`).
 *
 * KEYED BY THE SHARER'S NODE KEY, which is the contact's key: one contact,
 * one row, one pairing. A sharer's address changing is a second `add received`.
 *
 * NOT CORE. Lost, a share stops being pulled until it is accepted again;
 * rolled back, one this node dropped is pulled again -- notes the sharer
 * chose to send, into a tree of their own. Neither opens a door.
 */

#ifndef FZN_NODE_RECEIVED_H
#define FZN_NODE_RECEIVED_H

#include <stddef.h>
#include <stdint.h>

#include "../persist/persist.h"

/* Sharers, matching `notes/received.h`'s room for eight trees. */
#define FZN_NODE_RECEIVED_MAX 8u
/* A host name or address: 1 to 253 bytes, none of them a space or control,
 * so a row reads back as one word. */
#define FZN_NODE_RECEIVED_HOST_MAX 253u

typedef enum fzn_node_received_err {
	FZN_NODE_RECEIVED_OK = 0,
	FZN_NODE_RECEIVED_ERR_MALFORMED = -1, /* a null, a host that is not one, port 0 */
	FZN_NODE_RECEIVED_ERR_FULL = -2,      /* FZN_NODE_RECEIVED_MAX are held */
	FZN_NODE_RECEIVED_ERR_ABSENT = -3,    /* nothing accepted from that sharer */
	FZN_NODE_RECEIVED_ERR_BACKEND = -4,   /* the store refused, or cannot list */
	FZN_NODE_RECEIVED_ERR_SHAPE = -5      /* a held row will not read */
} fzn_node_received_err_t;

const char *fzn_node_received_err_str(fzn_node_received_err_t err);

typedef struct fzn_node_received {
	uint8_t sharer[FZN_PUBKEY_LEN];
	char host[FZN_NODE_RECEIVED_HOST_MAX + 1u];
	size_t host_len;
	uint16_t port;
	uint64_t accepted_at_ms;
} fzn_node_received_t;

/* Whether `host` is one: 1 to 253 bytes from 0x21 to 0x7e. */
int fzn_node_received_host_ok(const char *host, size_t len);

/* Record a share from `sharer`, replacing its address when it is held.
 * FULL past FZN_NODE_RECEIVED_MAX. */
fzn_node_received_err_t fzn_node_received_add(const fzn_persist_ops_t *store,
                                        const uint8_t sharer[FZN_PUBKEY_LEN], const char *host,
                                        size_t host_len, uint16_t port, uint64_t now_ms);

fzn_node_received_err_t fzn_node_received_get(const fzn_persist_ops_t *store,
                                        const uint8_t sharer[FZN_PUBKEY_LEN],
                                        fzn_node_received_t *out);

/* Every share accepted, `cap` of them. */
fzn_node_received_err_t fzn_node_received_list(const fzn_persist_ops_t *store,
                                         fzn_node_received_t *out, size_t cap, size_t *count);

/* Stop pulling `sharer`. ABSENT when nothing was accepted from it. What was
 * pulled stays until `notes/received.h`'s forget. */
fzn_node_received_err_t fzn_node_received_remove(const fzn_persist_ops_t *store,
                                           const uint8_t sharer[FZN_PUBKEY_LEN]);

#endif /* FZN_NODE_RECEIVED_H */
