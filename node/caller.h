/* The caller's side of the remote hop: ask a node something and read what it
 * answers, however many datagrams that takes.
 *
 * WHY THIS IS HERE. `node/remote.h` is the side that SERVES, and sec 362 gave
 * it the ability to answer with a reply larger than one frame. Nothing helped
 * the other side. A consumer wanting to ask a node a question writes: build
 * an `fzn_send_t`, seal it, send it, receive datagrams, open each with the
 * session key, feed them to `fzn_reasm_accept`, and stop when the message
 * completes -- and it writes that again for every program it ships.
 * `node/test/provision_test.c` contains exactly that sequence by hand,
 * because there was nowhere else for it.
 *
 * `local/client.h` is the same idea for the local socket. This is its
 * counterpart, and the two are deliberately separate: a local caller is
 * authenticated by the kernel and sends a text line, a remote caller is
 * authenticated by a capability and sends a sealed frame. One function
 * covering both would be two functions with a flag.
 *
 * WHAT IT DOES NOT DO. It does not interpret a reply -- those are bytes, as
 * they are everywhere else here -- and it does not chunk a REQUEST. The node
 * opens one frame per datagram on the remote path and reassembles nothing, so
 * a request larger than a frame cannot be served however it is sent: this
 * refuses it rather than sending something that will be dropped. That mirror
 * piece is named in project.md sec 369 and is the node's to build first.
 */

#ifndef FZN_NODE_CALLER_H
#define FZN_NODE_CALLER_H

#include <stddef.h>
#include <stdint.h>

#include "remote.h"
#include "../chunk/reassembly.h"
#include "../chunk/split.h"
#include "../net/udp.h"
#include "../session/random.h"

typedef enum fzn_caller_err {
	FZN_CALLER_OK = 0,
	/* A null argument, no ops, or no reassembly table. */
	FZN_CALLER_ERR_MALFORMED = -1,
	/* The request is larger than a frame carries. Refused rather than
	 * sent: the node reassembles nothing on this path, so it would be
	 * dropped at the far end and read here as a timeout. */
	FZN_CALLER_ERR_REQUEST_TOO_LONG = -2,
	/* The frame would not seal. */
	FZN_CALLER_ERR_SEAL = -3,
	/* The datagram would not send. */
	FZN_CALLER_ERR_SEND = -4,
	/* Nothing arrived in time, or the pieces stopped arriving before the
	 * message completed. Distinct from SEND because it says the node has
	 * the question and did not finish answering, which is a different
	 * thing to report than a socket that refused. */
	FZN_CALLER_ERR_TIMEOUT = -5,
	/* A datagram arrived and would not open under the session key. This is
	 * NOT reported per stray frame -- see the note at `fzn_caller_ask` on
	 * why a frame that does not open is skipped rather than fatal. It is
	 * the error for a reply that opened and then failed reassembly. */
	FZN_CALLER_ERR_REASSEMBLY = -6,
	/* The completed reply is larger than the caller's buffer. The bytes are
	 * not returned: a prefix of a reply is a different reply. */
	FZN_CALLER_ERR_REPLY_TOO_LONG = -7
} fzn_caller_err_t;

const char *fzn_caller_err_str(fzn_caller_err_t err);

/* Everything one caller needs to talk to one node. Caller-owned, as
 * everything here is; `reasm` in particular is the caller's table and its
 * slots, so this allocates nothing. */
typedef struct fzn_caller {
	int fd;                  /* a bound UDP socket */
	fzn_udp_addr_t node;     /* where the node is */
	uint8_t sender[FZN_PUBKEY_LEN];   /* this caller's identity */
	fzn_cap_id_t capability; /* what it is exercising */
	/* The session it seals to the node with. Symmetric, so the same key
	 * opens the node's replies -- which is why one pair serves both
	 * directions and `node/remote.h` seals its answers under it. */
	uint8_t send_key[FZN_AEAD_KEY_LEN];
	uint8_t send_ckey[FZN_COMMITMENT_KEY_LEN];
	const fzn_hash_ops_t *hash;
	const fzn_aead_ops_t *aead;
	const fzn_random_ops_t *rng;
	fzn_reasm_t *reasm;
	/* The next message id. Incremented per ask, so a late reply to an
	 * earlier question is recognised and skipped rather than returned as
	 * the answer to this one. */
	uint32_t next_msg;
	/* The hop budget a request states, as `fzn_send_t.hops`. */
	uint8_t hops;
} fzn_caller_t;

/* Send one request, reporting the `msg` it went out under.
 *
 * SPLIT FROM `ask` BECAUSE A BLOCKING CALL IS NOT USABLE BY EVERYBODY, and
 * the test found it before a consumer did. A program with its own poll loop
 * wants to send, return to the loop, and read the reply when the socket says
 * there is one -- `ask` would have it block inside the library instead. The
 * split also makes the pair drivable by a single-process test against a node
 * whose loop that same test turns by hand, which `ask` alone is not: it
 * would wait for a reply from a node that has not been given a turn.
 *
 * The `msg` is the caller's handle on the answer. `recv` takes it so a late
 * reply to an earlier question is skipped rather than returned as this
 * one's. */
fzn_caller_err_t fzn_caller_send(fzn_caller_t *caller, const uint8_t *payload,
                                 size_t payload_len, uint64_t expires_at,
                                 uint32_t *msg);

/* Read the whole answer to `msg`, however many datagrams it takes. */
fzn_caller_err_t fzn_caller_recv(fzn_caller_t *caller, uint32_t msg,
                                 uint8_t *reply, size_t reply_cap,
                                 size_t *reply_len, unsigned timeout_ms);

/* Both, for a caller with no loop of its own.
 *
 * Seals `payload` as one frame, sends it, and receives until the reply
 * completes or `timeout_ms` passes with nothing arriving. A reply of one
 * frame and a reply of twenty are the same call.
 *
 * A FRAME THAT DOES NOT OPEN, OR CARRIES ANOTHER `msg`, IS SKIPPED RATHER
 * THAN FATAL. This socket may receive a late reply to a previous question, a
 * retransmission, or a stranger's datagram -- none of which says anything
 * about the answer being waited for. Returning an error on the first one
 * would let anybody who can send a packet to this port turn every request
 * into a failure. The timeout is what bounds the wait.
 *
 * `*reply_len` is set only on OK. */
fzn_caller_err_t fzn_caller_ask(fzn_caller_t *caller, const uint8_t *payload,
                                size_t payload_len, uint64_t expires_at,
                                uint8_t *reply, size_t reply_cap,
                                size_t *reply_len, unsigned timeout_ms);

#endif /* FZN_NODE_CALLER_H */
