/* See admin.h. */

#include "admin.h"

#include "peer_persist.h"
#include "roots.h"
#include "../provision/provision.h"

#include <stdio.h>
#include <string.h>

/* `ok ` and the whole card text must fit one reply line, or `add peer` is a
 * verb this node cannot answer. Pinned at TWO hops -- a card from the root,
 * and one from a member the root granted -- which is every card this node
 * makes unless it joined through a member of a member. A deeper card is
 * refused at the verb with an error saying so; `fuzznetd --pair` prints any
 * length. sec 391. */
#define ADMIN_CARD_HOPS 2u
/* A root by identity pairs with one hop and a proof: one add fits a reply
 * line and two do not. sec 419. */
#define ADMIN_CARD_PROOF 1u
_Static_assert(3u + FZN_PROVISION_TEXT_PREFIX_LEN
                       + FZN_PROVISION_TEXT_BODY_LEN(FZN_PROVISION_LEN(1, ADMIN_CARD_PROOF))
                   <= FZN_REPLY_MAX,
               "a one-hop card with ADMIN_CARD_PROOF adds does not fit one reply line");
_Static_assert(3u + FZN_PROVISION_TEXT_PREFIX_LEN
                       + FZN_PROVISION_TEXT_BODY_LEN(FZN_PROVISION_LEN(1, ADMIN_CARD_PROOF + 1u))
                   > FZN_REPLY_MAX,
               "ADMIN_CARD_PROOF is smaller than a reply line allows");
/* `grant admin` answers the grantee's whole chain as `h` items: two fit one
 * reply line and three do not. sec 416. */
#define ADMIN_CHAIN_HOPS 2u
_Static_assert(3u + (ADMIN_CHAIN_HOPS * (2u + (FZN_HOP_LEN * 2u))) <= FZN_REPLY_MAX,
               "an admin chain of ADMIN_CHAIN_HOPS does not fit one reply line");
_Static_assert(3u + FZN_PROVISION_TEXT_PREFIX_LEN
                       + FZN_PROVISION_TEXT_BODY_LEN(FZN_PROVISION_LEN(ADMIN_CARD_HOPS, 0))
                   <= FZN_REPLY_MAX,
               "a two-hop pairing card does not fit one reply line");
_Static_assert(FZN_NODE_LOCAL_REPLY_MAX >= FZN_REPLY_MAX + 1u,
               "the node's local reply buffer cannot hold a whole reply line");

static const uint8_t SUBJECT_PEER[] = "peer ";
static const uint8_t SUBJECT_PEERS[] = "peer";

static size_t answer(char *reply, size_t cap, fzn_reply_t kind, const char *detail,
                     size_t detail_len)
{
	size_t len = 0;

	if (fzn_reply_compose((uint8_t *)reply, cap, &len, kind, (const uint8_t *)detail,
	                      detail_len) != FZN_COMPOSE_OK)
		return 0;
	return len;
}

static size_t answer_text(char *reply, size_t cap, fzn_reply_t kind, const char *detail)
{
	return answer(reply, cap, kind, detail, detail ? strlen(detail) : 0u);
}

/* Hex to bytes, exactly `len` of them from exactly `2 * len` characters. The
 * fifth hand-rolled table in this tree (sec 368 counted four); the shared
 * helper is still a signal rather than something to extract in passing. */
static int unhex(const uint8_t *text, size_t text_len, uint8_t *out, size_t len)
{
	size_t i;

	if (text_len != len * 2u)
		return 0;
	for (i = 0; i < text_len; i++) {
		uint8_t c = text[i];
		unsigned v;

		if (c >= '0' && c <= '9')
			v = (unsigned)(c - '0');
		else if (c >= 'a' && c <= 'f')
			v = 10u + (unsigned)(c - 'a');
		else if (c >= 'A' && c <= 'F')
			v = 10u + (unsigned)(c - 'A');
		else
			return 0;
		if (i % 2u == 0u)
			out[i / 2u] = (uint8_t)(v << 4);
		else
			out[i / 2u] = (uint8_t)(out[i / 2u] | v);
	}
	return 1;
}

static size_t add_peer(fzn_node_admin_t *admin, const uint8_t *hex, size_t hex_len,
                       char *reply, size_t cap)
{
	uint8_t record_bytes[FZN_PREKEY_LEN_TOTAL];
	uint8_t card[FZN_PROVISION_MAX_LEN];
	char text[FZN_PROVISION_TEXT_MAX_LEN];
	fzn_prekey_record_t record;
	fzn_node_pair_err_t perr;
	size_t card_len = 0, loaded = 0;
	uint64_t now;
	static uint8_t proof[FZN_PROVISION_PROOF_MAX][FZN_PROVISION_PROOF_ITEM_LEN];
	static fzn_node_authority_t by_identity;
	const fzn_node_authority_t *authority = admin->authority;

	if (!unhex(hex, hex_len, record_bytes, sizeof(record_bytes))
	    || fzn_prekey_open(record_bytes, sizeof(record_bytes), &record) != FZN_PREKEY_OK)
		return answer_text(reply, cap, FZN_REPLY_MALFORMED, "not a prekey record");

	/* AS A ROOT BY IDENTITY, sec 419, when this node's identity stands as a
	 * root other than the genesis and the card -- one hop and the proof --
	 * fits one reply line: a shorter card than a joined chain gives. */
	if (admin->roots
	    && memcmp(admin->state->config.root, admin->id->pubkey, FZN_PUBKEY_LEN) != 0
	    && fzn_node_roots_identity_root(admin->roots, admin->store, admin->id->pubkey, proof,
	                                    &by_identity) == FZN_NODE_ROOTS_OK
	    && by_identity.proof_count <= ADMIN_CARD_PROOF)
		authority = &by_identity;

	/* A CARD THAT WILL NOT FIT THE REPLY IS REFUSED BEFORE ANYTHING IS
	 * PAIRED: afterwards the device would be saved and its card lost. */
	/* THROUGH A ROOT KEY, sec 411, the card is two hops and a proof: past
	 * one reply line by construction, so said here rather than found by a
	 * pairing that cannot answer. */
	if (!authority
	    && memcmp(admin->state->config.root, admin->id->pubkey, FZN_PUBKEY_LEN) != 0
	    && admin->roots && admin->roots->key_held
	    && fzn_root_view_stands(&admin->roots->view, admin->roots->key))
		return answer_text(reply, cap, FZN_REPLY_ERROR,
		                   "this node pairs through its root key, and that card is too "
		                   "long for one reply line; pair with fuzznetd --pair");
	if (authority && authority->hop_count + 1u > ADMIN_CARD_HOPS)
		return answer_text(reply, cap, FZN_REPLY_ERROR,
		                   "this node's chain is too deep for a card on one reply line; "
		                   "pair with fuzznetd --pair");
	now = admin->state->clock ? admin->state->clock() : 0u;
	perr = fzn_node_pair(admin->id, admin->state->config.root,
	                     &admin->state->config.remote_capability, authority, 0,
	                     admin->store, record, now,
	                     now + admin->card_lifetime, card, sizeof(card), &card_len);
	if (perr != FZN_NODE_PAIR_OK)
		return answer_text(reply, cap, FZN_REPLY_ERROR, fzn_node_pair_err_str(perr));

	/* THE LIVE SET, FROM THE STORE. A reload that fails leaves the node
	 * serving the set it had, and says so: the device is paired and saved,
	 * and serves from the next successful reload or restart, which is
	 * worse than now and better than a half-updated table. */
	if (fzn_node_peers_load(admin->store, admin->peers, admin->peers_cap, &loaded)
	    != FZN_PERSIST_OK)
		return answer_text(reply, cap, FZN_REPLY_ERROR,
		                   "paired and saved, and the running peer set did not reload");
	admin->state->peers = admin->peers;
	admin->state->peer_count = loaded;

	if (fzn_provision_text(card, card_len, text, sizeof(text)) != FZN_PROVISION_OK)
		return answer_text(reply, cap, FZN_REPLY_ERROR,
		                   "paired and saved, and the card would not encode");
	return answer(reply, cap, FZN_REPLY_OK, text, strlen(text));
}

/* Is `arg` the subject `peer`, alone or followed by a space and more? Sets
 * `rest` to what follows the space, or to nothing for `peer` alone. */
static int subject_peer(const fzn_request_t *request, const uint8_t **rest, size_t *rest_len)
{
	*rest = NULL;
	*rest_len = 0;
	if (!request->arg)
		return 0;
	if (request->arg_len == sizeof(SUBJECT_PEERS) - 1u
	    && memcmp(request->arg, SUBJECT_PEERS, request->arg_len) == 0)
		return 1;
	if (request->arg_len > sizeof(SUBJECT_PEER) - 1u
	    && memcmp(request->arg, SUBJECT_PEER, sizeof(SUBJECT_PEER) - 1u) == 0) {
		*rest = request->arg + (sizeof(SUBJECT_PEER) - 1u);
		*rest_len = request->arg_len - (sizeof(SUBJECT_PEER) - 1u);
		return 1;
	}
	return 0;
}

static void put_hex(char *out, const uint8_t *in, size_t len)
{
	static const char H[] = "0123456789abcdef";
	size_t i;

	for (i = 0; i < len; i++) {
		out[i * 2u] = H[in[i] >> 4];
		out[(i * 2u) + 1u] = H[in[i] & 0x0fu];
	}
}

/* `list peer [FROM]`: `ok TOTAL FROM KEY KEY ...`, as many keys as fit one
 * reply line from FROM onward.
 *
 * PAGED, NOT TRUNCATED. Sixty-four peers at sixty-five characters each will
 * not fit a line, and a list that silently stopped at the fifteenth would be
 * the short answer `persist.h` refuses for `list` -- a node that appears to
 * hold fewer devices than it does. The total is stated, so a caller knows
 * whether to ask again and from where. */
static size_t list_peers(fzn_node_admin_t *admin, const uint8_t *from_text, size_t from_len,
                         char *reply, size_t cap)
{
	char detail[FZN_REPLY_MAX];
	size_t from = 0, total = admin->state->peer_count, at, i;
	/* THE PAGE FOLLOWS THE BUFFER IT IS WRITTEN INTO, not only the line
	 * bound: the remote path's default reply buffer is FZN_NODE_REPLY_MAX,
	 * half the grammar's, and a page sized for the grammar would fail to
	 * compose there and the caller would hear nothing. Less the newline. */
	size_t limit = (cap > 0u && cap - 1u < FZN_REPLY_MAX) ? cap - 1u : FZN_REPLY_MAX;
	int n;

	for (i = 0; i < from_len; i++) {
		if (from_text[i] < '0' || from_text[i] > '9' || from > FZN_NODE_PEERS_MAX)
			return answer_text(reply, cap, FZN_REPLY_MALFORMED, "not a peer index");
		from = (from * 10u) + (size_t)(from_text[i] - '0');
	}
	if (from > total)
		return answer_text(reply, cap, FZN_REPLY_MALFORMED, "past the last peer");
	n = snprintf(detail, sizeof(detail), "%zu %zu", total, from);
	if (n < 0 || (size_t)n >= sizeof(detail))
		return 0;
	at = (size_t)n;
	/* One space and 64 hex characters per key, under the reply's bound
	 * less the `ok ` in front of the detail. */
	for (i = from; i < total; i++) {
		if (at + 1u + (FZN_PUBKEY_LEN * 2u) + 3u > limit)
			break;
		detail[at++] = ' ';
		put_hex(detail + at, admin->state->peers[i].sender, FZN_PUBKEY_LEN);
		at += FZN_PUBKEY_LEN * 2u;
	}
	return answer(reply, cap, FZN_REPLY_OK, detail, at);
}

/* `get revocation [FROM]`: the revocations this node ISSUED, as the signed
 * records, paged as `list peer` is -- `ok TOTAL FROM RECORD ...`, each record
 * 420 hex characters. What a member node pulls from its root (sec 384).
 * Non-mutating, so a remote caller holding the node's grant may ask. */
static size_t get_revocations(fzn_node_admin_t *admin, const uint8_t *from_text,
                              size_t from_len, char *reply, size_t cap)
{
	static uint8_t subjects[FZN_NODE_REVOCATIONS_MAX * FZN_PUBKEY_LEN];
	static char detail[FZN_REPLY_MAX];
	size_t limit = (cap > 0u && cap - 1u < FZN_REPLY_MAX) ? cap - 1u : FZN_REPLY_MAX;
	size_t from = 0, total = 0, at, i;
	int n;

	if (!admin->store->list
	    || !admin->store->list(admin->store->ctx, FZN_PERSIST_ISSUED_REVOCATION, subjects,
	                           FZN_NODE_REVOCATIONS_MAX, &total))
		return answer_text(reply, cap, FZN_REPLY_ERROR, "this store cannot list revocations");
	for (i = 0; i < from_len; i++) {
		if (from_text[i] < '0' || from_text[i] > '9' || from > FZN_NODE_REVOCATIONS_MAX)
			return answer_text(reply, cap, FZN_REPLY_MALFORMED, "not a revocation index");
		from = (from * 10u) + (size_t)(from_text[i] - '0');
	}
	if (from > total)
		return answer_text(reply, cap, FZN_REPLY_MALFORMED, "past the last revocation");
	n = snprintf(detail, sizeof(detail), "%zu %zu", total, from);
	if (n < 0 || (size_t)n >= sizeof(detail))
		return 0;
	at = (size_t)n;
	for (i = from; i < total; i++) {
		uint8_t record[FZN_REVOCATION_LEN];

		if (at + 1u + (FZN_REVOCATION_LEN * 2u) + 3u > limit)
			break;
		if (!fzn_node_issued_revocation(admin->store, subjects + (i * (size_t)FZN_PUBKEY_LEN),
		                                record))
			return answer_text(reply, cap, FZN_REPLY_ERROR, "a stored revocation did not read");
		detail[at++] = ' ';
		put_hex(detail + at, record, FZN_REVOCATION_LEN);
		at += FZN_REVOCATION_LEN * 2u;
	}
	return answer(reply, cap, FZN_REPLY_OK, detail, at);
}

/* `get vote [FROM]`: every vote this node holds, its own and learned, each
 * with its issuer's chain, as the item stream `node/revoke.h` describes --
 * `ok TOTAL FROM ITEM ...`. What a node pulls from any estate peer (sec 399).
 * Non-mutating, so a remote caller holding the node's grant may ask. */
static size_t get_votes(fzn_node_admin_t *admin, const uint8_t *from_text, size_t from_len,
                        char *reply, size_t cap)
{
	static char detail[FZN_REPLY_MAX];
	size_t limit = (cap > 0u && cap - 1u < FZN_REPLY_MAX) ? cap - 1u : FZN_REPLY_MAX;
	size_t from = 0, total = 0, len = 0, i;
	int n;

	for (i = 0; i < from_len; i++) {
		if (from_text[i] < '0' || from_text[i] > '9' || from > FZN_NODE_VOTES_MAX * 16u)
			return answer_text(reply, cap, FZN_REPLY_MALFORMED, "not a vote index");
		from = (from * 10u) + (size_t)(from_text[i] - '0');
	}
	/* The head is written after the walk, which is what knows the total;
	 * its room is reserved here at the widest a total and an index print. */
	if (limit < 3u + 24u
	    || !fzn_node_votes_page(admin->store, admin->authority,
	                            fzn_node_admin_chain_view(admin->admin_chain), from, detail + 24u,
	                            limit - 3u - 24u, &len, &total))
		return answer_text(reply, cap, FZN_REPLY_ERROR, "the votes did not read");
	if (from > total)
		return answer_text(reply, cap, FZN_REPLY_MALFORMED, "past the last vote");
	n = snprintf(detail, 24u, "%zu %zu", total, from);
	if (n < 0 || (size_t)n >= 24u)
		return 0;
	memmove(detail + n, detail + 24u, len);
	return answer(reply, cap, FZN_REPLY_OK, detail, (size_t)n + len);
}

/* `get root [FROM]`: every root record this node holds, as the item stream
 * `node/roots.h` describes -- `ok TOTAL FROM ITEM ...`. What a node pulls
 * from any peer before its votes (sec 408). Non-mutating, so a remote caller
 * holding the node's grant may ask. */
static size_t get_roots(fzn_node_admin_t *admin, const uint8_t *from_text, size_t from_len,
                        char *reply, size_t cap)
{
	static char detail[FZN_REPLY_MAX];
	size_t limit = (cap > 0u && cap - 1u < FZN_REPLY_MAX) ? cap - 1u : FZN_REPLY_MAX;
	size_t from = 0, total = 0, len = 0, i;
	int n;

	for (i = 0; i < from_len; i++) {
		if (from_text[i] < '0' || from_text[i] > '9' || from > FZN_NODE_ROOT_LOG_MAX * 32u)
			return answer_text(reply, cap, FZN_REPLY_MALFORMED, "not a root record index");
		from = (from * 10u) + (size_t)(from_text[i] - '0');
	}
	if (limit < 3u + 24u
	    || !fzn_node_roots_page(admin->store, from, detail + 24u, limit - 3u - 24u, &len,
	                            &total))
		return answer_text(reply, cap, FZN_REPLY_ERROR, "the root records did not read");
	if (from > total)
		return answer_text(reply, cap, FZN_REPLY_MALFORMED, "past the last root record");
	n = snprintf(detail, 24u, "%zu %zu", total, from);
	if (n < 0 || (size_t)n >= 24u)
		return 0;
	memmove(detail + n, detail + 24u, len);
	return answer(reply, cap, FZN_REPLY_OK, detail, (size_t)n + len);
}

/* Is `arg` the word `WORD`, alone or followed by a space and more? */
static int subject_word(const fzn_request_t *request, const char *word, const uint8_t **rest,
                        size_t *rest_len)
{
	const uint8_t *WORD = (const uint8_t *)word;
	const size_t w = strlen(word);

	*rest = NULL;
	*rest_len = 0;
	if (!request->arg || request->arg_len < w || memcmp(request->arg, WORD, w) != 0)
		return 0;
	if (request->arg_len == w)
		return 1;
	if (request->arg[w] != ' ')
		return 0;
	*rest = request->arg + w + 1u;
	*rest_len = request->arg_len - w - 1u;
	return 1;
}

static int subject_revocation(const fzn_request_t *request, const uint8_t **rest,
                              size_t *rest_len)
{
	return subject_word(request, "revocation", rest, rest_len);
}

/* `remove peer KEY`: un-pair a device from the RUNNING node. The store forgets
 * it and the live set is reloaded from the store, as after a pairing, so the
 * device's next frame finds no session and is dropped. */
static size_t remove_peer(fzn_node_admin_t *admin, const uint8_t *hex, size_t hex_len,
                          char *reply, size_t cap)
{
	uint8_t sender[FZN_PUBKEY_LEN];
	size_t loaded = 0;

	if (!unhex(hex, hex_len, sender, sizeof(sender)))
		return answer_text(reply, cap, FZN_REPLY_MALFORMED, "not a peer key");
	if (!fzn_node_find_peer(admin->state->peers, admin->state->peer_count, sender))
		return answer_text(reply, cap, FZN_REPLY_ERROR, "no such peer");
	if (fzn_node_peer_remove(admin->store, sender) != FZN_PERSIST_OK)
		return answer_text(reply, cap, FZN_REPLY_ERROR, "this store cannot forget the peer");
	/* THE STORE FIRST, THEN THE LIVE SET. A reload that fails leaves the
	 * node serving a set that still holds the device, and says so -- the
	 * one direction where carrying on quietly would keep serving somebody
	 * the operator has just cut off. */
	if (fzn_node_peers_load(admin->store, admin->peers, admin->peers_cap, &loaded)
	    != FZN_PERSIST_OK)
		return answer_text(reply, cap, FZN_REPLY_ERROR,
		                   "forgotten by the store, and the running peer set did not "
		                   "reload, so it is still served until a restart");
	admin->state->peers = admin->peers;
	admin->state->peer_count = loaded;
	return answer(reply, cap, FZN_REPLY_OK, (const char *)hex, hex_len);
}

/* THE CHAIN THIS NODE VOTES ON, sec 416: none when it is the estate's root,
 * whose vote needs no chain and counts alone; else its admin chain when it
 * holds one, since an admin's vote counts for any grantee; else the chain it
 * joined with. */
static const fzn_node_authority_t *voting_authority(fzn_node_admin_t *admin)
{
	const fzn_node_authority_t *chain;

	if (memcmp(admin->state->config.root, admin->id->pubkey, FZN_PUBKEY_LEN) == 0)
		return admin->authority;
	chain = fzn_node_admin_chain_view(admin->admin_chain);
	return chain ? chain : admin->authority;
}

/* Whether this node acts as a root now, by its own key or its identity. */
static int acts_as_root(fzn_node_admin_t *admin)
{
	const uint8_t *as = NULL;
	const fzn_sign_ops_t *sign = NULL;

	return admin->roots
	       && fzn_node_roots_acting(admin->roots, admin->id->pubkey, admin->id->sign, &as,
	                                &sign);
}

/* `revoke peer KEY`. */
static int log_revocation(fzn_node_admin_t *admin, const uint8_t grantee[FZN_PUBKEY_LEN]);

static size_t revoke_peer(fzn_node_admin_t *admin, const uint8_t *hex, size_t hex_len,
                          char *reply, size_t cap)
{
	static const char already[] = " already";
	char detail[(FZN_PUBKEY_LEN * 2u) + sizeof(already)];
	uint8_t grantee[FZN_PUBKEY_LEN];
	fzn_node_revoke_err_t rerr;
	uint64_t now;

	if (!unhex(hex, hex_len, grantee, sizeof(grantee)))
		return answer_text(reply, cap, FZN_REPLY_MALFORMED, "not a peer key");
	now = admin->state->clock ? admin->state->clock() : 0u;
	rerr = fzn_node_revoke(admin->id, admin->state->config.root, voting_authority(admin),
	                       &admin->state->config.remote_capability, grantee, now,
	                       admin->revocations, admin->store);
	if (rerr != FZN_NODE_REVOKE_OK && rerr != FZN_NODE_REVOKE_ALREADY)
		return answer_text(reply, cap, FZN_REPLY_ERROR, fzn_node_revoke_err_str(rerr));
	if (rerr == FZN_NODE_REVOKE_OK && !log_revocation(admin, grantee))
		return answer_text(reply, cap, FZN_REPLY_ERROR,
		                   "revoked, and not in this root's log: it would fall at this "
		                   "root's removal");
	memcpy(detail, hex, hex_len);
	if (rerr == FZN_NODE_REVOKE_ALREADY) {
		memcpy(detail + hex_len, already, sizeof(already) - 1u);
		return answer(reply, cap, FZN_REPLY_OK, detail, hex_len + sizeof(already) - 1u);
	}
	return answer(reply, cap, FZN_REPLY_OK, detail, hex_len);
}

/* LOG A REVOCATION OR WITHDRAWAL THIS NODE SIGNED AS A ROOT, sec 409: the
 * record now in slot 9 for `grantee`, when the node signs with its identity
 * and that identity stands as a root. A root's act that is not in its log
 * falls at the root's removal whatever the cut, so an unlogged one is
 * reported rather than passed off as done. 1 when logged or not a root act. */
static int log_revocation(fzn_node_admin_t *admin, const uint8_t grantee[FZN_PUBKEY_LEN])
{
	const uint8_t *as = NULL;
	const fzn_sign_ops_t *sign = NULL;
	uint8_t record[FZN_REVOCATION_LEN];

	if (!admin->roots || admin->authority
	    || !fzn_node_roots_acting(admin->roots, admin->id->pubkey, admin->id->sign, &as, &sign)
	    || memcmp(as, admin->id->pubkey, FZN_PUBKEY_LEN) != 0)
		return 1;
	if (!fzn_node_issued_revocation(admin->store, grantee, record))
		return 0;
	return fzn_node_roots_log_act(admin->roots, admin->store, as, sign,
	                              (uint8_t)FZN_ROOT_ACT_REVOCATION, record, sizeof(record))
	       == FZN_NODE_ROOTS_OK;
}

/* `add root KEY` and `remove root KEY [CUT]`: change the estate's roots as
 * this node's acting root. sec 409. */
static size_t change_root(fzn_node_admin_t *admin, int remove, const uint8_t *text,
                          size_t text_len, char *reply, size_t cap)
{
	uint8_t subject[FZN_PUBKEY_LEN], cut[FZN_ROOT_ACT_ID_LEN];
	const uint8_t *cut_at = NULL;
	fzn_node_roots_err_t err;
	size_t key_len = text_len;

	if (remove && text_len > FZN_PUBKEY_LEN * 2u) {
		key_len = FZN_PUBKEY_LEN * 2u;
		if (text[key_len] != ' '
		    || !unhex(text + key_len + 1u, text_len - key_len - 1u, cut, sizeof(cut)))
			return answer_text(reply, cap, FZN_REPLY_MALFORMED, "not a cut");
		cut_at = cut;
	}
	if (!unhex(text, key_len, subject, sizeof(subject)))
		return answer_text(reply, cap, FZN_REPLY_MALFORMED, "not a root key");
	err = fzn_node_roots_change(admin->roots, admin->store, admin->id->pubkey, admin->id->sign,
	                            remove, subject, cut_at);
	if (err != FZN_NODE_ROOTS_OK)
		return answer_text(reply, cap, FZN_REPLY_ERROR, fzn_node_roots_err_str(err));
	return answer(reply, cap, FZN_REPLY_OK, (const char *)text, key_len);
}

/* `remove revocation KEY`: undo this node's revocation of KEY (sec 386). The
 * grantee's grant is honoured again from the next frame; a device whose peer
 * record was also removed still has to be paired again to be served. */
static size_t unrevoke_peer(fzn_node_admin_t *admin, const uint8_t *hex, size_t hex_len,
                            char *reply, size_t cap)
{
	uint8_t grantee[FZN_PUBKEY_LEN];
	fzn_node_revoke_err_t rerr;
	uint64_t now;

	if (!unhex(hex, hex_len, grantee, sizeof(grantee)))
		return answer_text(reply, cap, FZN_REPLY_MALFORMED, "not a peer key");
	now = admin->state->clock ? admin->state->clock() : 0u;
	rerr = fzn_node_unrevoke(admin->id, admin->state->config.root, voting_authority(admin),
	                         grantee, now, admin->revocations, admin->store);
	if (rerr != FZN_NODE_REVOKE_OK)
		return answer_text(reply, cap, FZN_REPLY_ERROR, fzn_node_revoke_err_str(rerr));
	if (!log_revocation(admin, grantee))
		return answer_text(reply, cap, FZN_REPLY_ERROR,
		                   "withdrawn, and not in this root's log: it would fall at this "
		                   "root's removal");
	return answer(reply, cap, FZN_REPLY_OK, (const char *)hex, hex_len);
}

/* `grant admin KEY`: KEY's whole admin chain, as `h` items. sec 416. */
static size_t grant_admin(fzn_node_admin_t *admin, const uint8_t *hex, size_t hex_len,
                          char *reply, size_t cap)
{
	static uint8_t chain[FZN_CHAIN_MAX_HOPS][FZN_HOP_LEN];
	static char detail[FZN_REPLY_MAX];
	uint8_t grantee[FZN_PUBKEY_LEN];
	fzn_node_revoke_err_t err;
	size_t n = 0, i, at = 0;

	if (!unhex(hex, hex_len, grantee, sizeof(grantee)))
		return answer_text(reply, cap, FZN_REPLY_MALFORMED, "not a key");
	/* REFUSED BEFORE ANYTHING IS MINTED when the chain could not fit: a
	 * root's grant is one hop, an admin's its own chain and one more. */
	if (admin->admin_chain && admin->admin_chain->hop_count + 1u > ADMIN_CHAIN_HOPS
	    && !acts_as_root(admin))
		return answer_text(reply, cap, FZN_REPLY_ERROR,
		                   "this node's admin chain is too deep for one reply line");
	err = fzn_node_admin_grant(admin->roots, admin->store, admin->id, admin->admin_chain,
	                           &admin->state->config.admin_capability, grantee,
	                           admin->state->clock ? admin->state->clock() : 0u, chain, &n);
	if (err != FZN_NODE_REVOKE_OK)
		return answer_text(reply, cap, FZN_REPLY_ERROR, fzn_node_revoke_err_str(err));
	for (i = 0; i < n; i++) {
		detail[at++] = i ? ' ' : 'h';
		if (i)
			detail[at++] = 'h';
		put_hex(detail + at, chain[i], FZN_HOP_LEN);
		at += FZN_HOP_LEN * 2u;
	}
	return answer(reply, cap, FZN_REPLY_OK, detail, at);
}

/* `set quorum K`: the estate's k, as this node's acting root. sec 418. */
static size_t set_quorum(fzn_node_admin_t *admin, const uint8_t *text, size_t text_len,
                         char *reply, size_t cap)
{
	char detail[8];
	unsigned long k = 0;
	size_t i;
	fzn_node_roots_err_t err;
	int n;

	if (text_len == 0u || text_len > 3u)
		return answer_text(reply, cap, FZN_REPLY_MALFORMED, "k is 1 to 255");
	for (i = 0; i < text_len; i++) {
		if (text[i] < '0' || text[i] > '9')
			return answer_text(reply, cap, FZN_REPLY_MALFORMED, "k is 1 to 255");
		k = (k * 10u) + (unsigned long)(text[i] - '0');
	}
	if (k < 1u || k > 255u)
		return answer_text(reply, cap, FZN_REPLY_MALFORMED, "k is 1 to 255");
	err = fzn_node_roots_set_quorum(admin->roots, admin->store, admin->id->pubkey,
	                                admin->id->sign, (uint8_t)k);
	if (err != FZN_NODE_ROOTS_OK)
		return answer_text(reply, cap, FZN_REPLY_ERROR, fzn_node_roots_err_str(err));
	/* IN FORCE AT ONCE, as resolved: a concurrent higher k still wins. */
	if (admin->revocations) {
		uint8_t now = (uint8_t)admin->revocations->quorum;

		(void)fzn_revocation_store_set_k(admin->revocations,
		                                 fzn_node_roots_quorum(admin->roots, now));
	}
	n = snprintf(detail, sizeof(detail), "%zu",
	             admin->revocations ? admin->revocations->quorum : (size_t)k);
	return answer(reply, cap, FZN_REPLY_OK, detail, n > 0 ? (size_t)n : 0u);
}

/* `add confirm HOP`: confirm the admin grant HOP. sec 416. */
static size_t confirm_admin(fzn_node_admin_t *admin, const uint8_t *hex, size_t hex_len,
                            char *reply, size_t cap)
{
	uint8_t hop[FZN_HOP_LEN];
	fzn_chain_hop_t view;
	fzn_node_revoke_err_t err;

	if (!unhex(hex, hex_len, hop, sizeof(hop)) || fzn_hop_open(hop, sizeof(hop), &view)
	                                                       != FZN_CHAIN_OK)
		return answer_text(reply, cap, FZN_REPLY_MALFORMED, "not a hop");
	if (memcmp(fzn_hop_capability(view), &admin->state->config.admin_capability,
	           sizeof(fzn_cap_id_t)) != 0)
		return answer_text(reply, cap, FZN_REPLY_ERROR, "not a grant of admin");
	err = fzn_node_admin_confirm(admin->roots, admin->store, admin->id, admin->admin_chain,
	                             admin->state->config.root, hop, admin->revocations);
	if (err != FZN_NODE_REVOKE_OK)
		return answer_text(reply, cap, FZN_REPLY_ERROR, fzn_node_revoke_err_str(err));
	return answer_text(reply, cap, FZN_REPLY_OK, NULL);
}

size_t fzn_node_admin_handle(void *ctx, fzn_authz_verdict_t verdict, fzn_origin_t origin,
                             const fzn_peer_t *peer, const fzn_request_t *request,
                             char *reply, size_t reply_cap)
{
	fzn_node_admin_t *admin = (fzn_node_admin_t *)ctx;
	const uint8_t *rest;
	size_t rest_len;

	(void)verdict; /* not called on a denial -- node/local.h */
	(void)peer;
	if (!admin || !admin->state || !admin->id || !admin->store || !admin->peers || !request
	    || !reply)
		return 0;

	if (request->parsed == FZN_VERB_STATUS)
		return 0;

	if (fzn_verb_mutates(request->parsed) && origin != FZN_ORIGIN_SAME_USER)
		return answer_text(reply, reply_cap, FZN_REPLY_DENIED,
		                   "changing this node needs its own user");

	if (subject_peer(request, &rest, &rest_len)) {
		if (request->parsed == FZN_VERB_ADD && rest)
			return add_peer(admin, rest, rest_len, reply, reply_cap);
		if (request->parsed == FZN_VERB_REMOVE && rest)
			return remove_peer(admin, rest, rest_len, reply, reply_cap);
		if (request->parsed == FZN_VERB_LIST)
			return list_peers(admin, rest, rest_len, reply, reply_cap);
		if (request->parsed == FZN_VERB_REVOKE && rest && admin->revocations)
			return revoke_peer(admin, rest, rest_len, reply, reply_cap);
	}
	if (request->parsed == FZN_VERB_GET && subject_revocation(request, &rest, &rest_len))
		return get_revocations(admin, rest, rest_len, reply, reply_cap);
	if (request->parsed == FZN_VERB_GET && subject_word(request, "vote", &rest, &rest_len))
		return get_votes(admin, rest, rest_len, reply, reply_cap);
	if (request->parsed == FZN_VERB_GET && subject_word(request, "root", &rest, &rest_len))
		return get_roots(admin, rest, rest_len, reply, reply_cap);
	if ((request->parsed == FZN_VERB_ADD || request->parsed == FZN_VERB_REMOVE)
	    && subject_word(request, "root", &rest, &rest_len) && rest && admin->roots)
		return change_root(admin, request->parsed == FZN_VERB_REMOVE, rest, rest_len, reply,
		                   reply_cap);
	if (request->parsed == FZN_VERB_REMOVE && subject_revocation(request, &rest, &rest_len)
	    && rest && admin->revocations)
		return unrevoke_peer(admin, rest, rest_len, reply, reply_cap);
	if (request->parsed == FZN_VERB_SET && subject_word(request, "quorum", &rest, &rest_len)
	    && rest && admin->roots)
		return set_quorum(admin, rest, rest_len, reply, reply_cap);
	/* ADMINS, sec 416: only on a node whose config names the capability. */
	if (admin->state->config.has_admin && request->parsed == FZN_VERB_GRANT
	    && subject_word(request, "admin", &rest, &rest_len) && rest)
		return grant_admin(admin, rest, rest_len, reply, reply_cap);
	if (admin->state->config.has_admin && request->parsed == FZN_VERB_ADD
	    && subject_word(request, "confirm", &rest, &rest_len) && rest && admin->revocations)
		return confirm_admin(admin, rest, rest_len, reply, reply_cap);

	return answer_text(reply, reply_cap, FZN_REPLY_UNSUPPORTED, NULL);
}

size_t fzn_node_admin_remote(void *ctx, fzn_node_remote_result_t result,
                             const fzn_opened_t *req, uint8_t *reply, size_t reply_cap)
{
	fzn_node_admin_t *admin = (fzn_node_admin_t *)ctx;
	char *out = (char *)reply;
	fzn_request_t request;
	const uint8_t *line, *rest;
	size_t line_len, rest_len;

	if (!admin || !admin->state || !req || !reply || result != FZN_NODE_REMOTE_GRANTED)
		return 0;

	/* ONE LINE: the payload, with the terminator a local caller's framer
	 * would have stripped removed here if it was sent. */
	line = req->payload;
	line_len = req->payload_len;
	if (line_len && line[line_len - 1u] == '\n')
		line_len--;
	if (!line || !fzn_vocabulary_split(line, line_len, &request))
		return answer_text(out, reply_cap, FZN_REPLY_MALFORMED, NULL);

	if (fzn_verb_mutates(request.parsed))
		return answer_text(out, reply_cap, FZN_REPLY_DENIED,
		                   "a remote caller may not change this node");
	if (request.parsed == FZN_VERB_STATUS)
		return fzn_node_status_line(FZN_AUTHZ_GRANTED_BY_CHAIN, FZN_ORIGIN_REMOTE, out,
		                            reply_cap);
	if (request.parsed == FZN_VERB_LIST && subject_peer(&request, &rest, &rest_len))
		return list_peers(admin, rest, rest_len, out, reply_cap);
	if (request.parsed == FZN_VERB_GET && subject_revocation(&request, &rest, &rest_len))
		return get_revocations(admin, rest, rest_len, out, reply_cap);
	if (request.parsed == FZN_VERB_GET && subject_word(&request, "vote", &rest, &rest_len))
		return get_votes(admin, rest, rest_len, out, reply_cap);
	if (request.parsed == FZN_VERB_GET && subject_word(&request, "root", &rest, &rest_len))
		return get_roots(admin, rest, rest_len, out, reply_cap);
	return answer_text(out, reply_cap, FZN_REPLY_UNSUPPORTED, NULL);
}
