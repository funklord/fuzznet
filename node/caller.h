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
 * they are everywhere else here. It DOES chunk a request, since sec 370 gave
 * the node step 8; before that it refused one, because the node reassembled
 * nothing and an over-large request was dropped at the far end and came back
 * as a timeout. A node with no reassembly table still drops one, which is
 * why `FZN_CALLER_ERR_TIMEOUT` remains the answer a caller may get for a
 * request the far end will not take.
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
	/* The request is larger than a RECEIVER will reassemble --
	 * FZN_REASM_MAX_CHUNKS pieces of FZN_SPLIT_MAX_PAYLOAD. Refused rather
	 * than sent, because `fzn_split_plan` will not plan it and a request
	 * that cannot be planned is one that cannot arrive. */
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
/* HOW MANY SETTLED MESSAGES A CALLER REMEMBERS, sec 737 -- given up on or
 * answered: a piece of one of them arriving late is dropped before
 * reassembly rather than taking a slot. One older than these is left to
 * the table's hold. 64, since a round sends several messages a peer and a
 * kept reply's pieces come back for a few seconds after. */
#define FZN_CALLER_FORGOTTEN 64u

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
	/* THE NODE'S CLOCK LESS THIS ONE'S, in milliseconds, sec 719 stage 3:
	 * every expiry this caller seals is stamped in the node's terms, so a
	 * request lives its whole life by the clock that judges it, whichever
	 * of the two is wrong. 0, the default, stamps by this caller's clock.
	 * Measured by the time probe (`node/clocks.h`) and set by whoever owns
	 * the caller; the node's own claim about its own clock, used only to
	 * reach that node. */
	int64_t clock_offset_ms;
	/* EVERY PAYLOAD THROUGH THIS FIRST, sec 465, when set: `wrap` writes
	 * the payload to send into `out` and returns its length, or 0 to send
	 * it as it is. It is how a daemon puts its log causes round requests
	 * the library sends on its behalf -- roots, votes -- which it never sees
	 * (`log/cause.h`); the caller knows nothing of what is put round them. */
	size_t (*wrap)(void *ctx, const uint8_t *in, size_t in_len, uint8_t *out, size_t out_cap);
	void *wrap_ctx;
	/* WHAT CROSSES, sec 685, when set: `sent` with each request as it went
	 * out, after the wrap, and the `msg` it went under -- by
	 * `fzn_caller_send` once it is sent and `fzn_caller_seal` once it is
	 * sealed; `answered` with each whole answer read, its `msg` and its
	 * length. How a daemon meters its traffic by what it was
	 * (`node/meter.h`); the caller counts nothing itself. */
	void (*sent)(void *ctx, const struct fzn_caller *caller, uint32_t msg,
	             const uint8_t *payload, size_t len);
	void (*answered)(void *ctx, const struct fzn_caller *caller, uint32_t msg, size_t len);
	void *traffic_ctx;
	/* WHO ANSWERS UNDER THIS SESSION, sec 708: the sender of the last frame
	 * that opened under its keys, set by the caller as it reads. What
	 * `fzn_caller_forget` needs to name a reply's partial in a reassembly
	 * table that may be shared. */
	uint8_t answerer[FZN_SENDER_LEN];
	int answerer_known;
	/* WHAT THIS CALLER SENT AND HEARD, counted up and never reset, sec
	 * 737: requests sent (a resend is one more), datagrams read, those
	 * that did not open under this session, those that opened as no answer
	 * (a hello, or the peer's own request), those that opened as another
	 * question's answer while one was awaited, the pieces taken into
	 * reassembly, those reassembly refused, with the last refusal's code,
	 * and the pieces of a message given up on, dropped before it. A daemon
	 * says the difference across a wait that failed; nothing here reads
	 * them. */
	unsigned long sends, heard, unopened, unasked, elsewhere, pieces, refused, late;
	int refused_err;
	/* AND THE LAST PIECE REFUSED: its message, index, count and length. */
	uint32_t refused_msg;
	uint16_t refused_index, refused_chunks;
	size_t refused_len;
	/* THE MESSAGES SETTLED, sec 737, the last FZN_CALLER_FORGOTTEN of them:
	 * given up on, by `fzn_caller_forget`, or answered, as a reply
	 * completes. A piece of one arriving after is dropped, so a reply's
	 * half that comes late -- its partner lost, or the answer already
	 * taken -- never holds a slot no ask will release. Sending a message
	 * again, or waiting for it again, takes it off. */
	uint32_t forgotten[FZN_CALLER_FORGOTTEN];
	unsigned forgotten_used, forgotten_next;
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

/* SEAL ONE REQUEST WITHOUT SENDING IT, sec 622: what `fzn_caller_send`
 * would send, wrapped as it would be, as one frame into `out` (`cap`
 * bytes), `*out_len` long, under the `msg` it reports -- for a relay to
 * carry, so the request must fit one frame: REQUEST_TOO_LONG otherwise.
 * The answer is read as any other, with `fzn_caller_recv`. */
fzn_caller_err_t fzn_caller_seal(fzn_caller_t *caller, const uint8_t *payload, size_t payload_len,
                                 uint64_t expires_at, uint32_t *msg, uint8_t *out, size_t cap,
                                 size_t *out_len);

/* A NOP, sealed and sent to the node from `fd` rather than the caller's own
 * socket, sec 622: a host behind a NAT saying where it is from the socket
 * it serves on, which keeps that socket's mapping open and tells the node
 * where to send what it relays. Nothing answers it. */
fzn_caller_err_t fzn_caller_hello(fzn_caller_t *caller, int fd, uint64_t expires_at);

/* Read the whole answer to `msg`, however many datagrams it takes. */
fzn_caller_err_t fzn_caller_recv(fzn_caller_t *caller, uint32_t msg,
                                 uint8_t *reply, size_t reply_cap,
                                 size_t *reply_len, unsigned timeout_ms);

/* FORGET THE ANSWER TO `msg`, given up on, sec 708: a reply held part way in
 * this caller's reassembly table, one piece lost, is dropped rather than
 * left to hold its slot until the table expires it. And remembered, sec
 * 737, so a piece of it arriving later is dropped before reassembly too.
 * `fzn_caller_recv` does this itself when it times out; a caller that waits
 * by other means -- the daemon's ask table -- calls it when it stops
 * waiting. */
void fzn_caller_forget(fzn_caller_t *caller, uint32_t msg);

/* CARRY A CALLER'S NUMBERING ONTO ONE BUILT AGAIN, sec 737: `to`'s next
 * message number and the messages given up on, from `from`, a caller on
 * the same session. Built again from its pairing, a caller numbers from 0,
 * and under the same keys a late piece of an old reply opens and lands on
 * the new message of its number -- refused where the plans differ, and
 * taken as the answer to a different request where they match. Carried,
 * no number repeats on the session and a late piece is dropped as late.
 * Nothing else is carried: keys, socket and counts are `to`'s own. */
void fzn_caller_carry(fzn_caller_t *to, const fzn_caller_t *from);

/* Both, for a caller with no loop of its own.
 *
 * Seals `payload` as one frame, sends it, and receives until the reply
 * completes or `timeout_ms` passes with no piece of it arriving; a
 * datagram that is not one moves nothing (sec 726). A reply of one
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
/* THE REPLY TO WHICHEVER OF THIS CALLER'S REQUESTS COMPLETES FIRST, and in
 * `*msg` which one it answers. sec 494. A caller with several requests out
 * -- a file fetched a window of spans at a time -- takes them as they come
 * rather than in the order it asked. The reassembly table must have a slot
 * for each request out at once; a reply finding none is refused there. */
fzn_caller_err_t fzn_caller_recv_any(fzn_caller_t *caller, uint32_t *msg, uint8_t *reply,
                                     size_t reply_cap, size_t *reply_len, unsigned timeout_ms);

/* SEND MESSAGE `msg` AGAIN, sec 737: the same request, sealed under a fresh
 * nonce, for a caller waiting on it in slices of its own. */
fzn_caller_err_t fzn_caller_resend(fzn_caller_t *caller, const uint8_t *payload,
                                   size_t payload_len, uint64_t expires_at, uint32_t msg);

/* WAIT FOR `msg` AS `fzn_caller_recv` does, but keep what has arrived of it
 * on a timeout: a caller resending waits in slices, and a reply's pieces
 * from before a resend complete it as well as those after. The caller that
 * gives up calls `fzn_caller_forget`. */
fzn_caller_err_t fzn_caller_recv_for(fzn_caller_t *caller, uint32_t msg, uint8_t *reply,
                                     size_t reply_cap, size_t *reply_len, unsigned timeout_ms);

/* THE REQUEST AND ITS REPLY, sent and waited for -- RESENT, sec 737, when
 * FZN_CALLER_RESEND_MS pass with no piece of the reply, at most
 * FZN_CALLER_RESENDS times and never past `timeout_ms`. Each resend is the
 * same message under a fresh nonce; a node keeping its replies answers it
 * without running it twice. A `timeout_ms` of 0 waits once, as
 * `fzn_caller_recv` does. */
#define FZN_CALLER_RESEND_MS 600u
#define FZN_CALLER_RESENDS 3u

fzn_caller_err_t fzn_caller_ask(fzn_caller_t *caller, const uint8_t *payload,
                                size_t payload_len, uint64_t expires_at,
                                uint8_t *reply, size_t reply_cap,
                                size_t *reply_len, unsigned timeout_ms);

#endif /* FZN_NODE_CALLER_H */
