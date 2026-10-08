/* See admin.h. */

#include "admin.h"

#include "peer_persist.h"
#include "roots.h"
#include "roster.h"
#include "../provision/provision.h"
#include "../contact/contact.h"
#include "../contact/group.h"
#include "../log/rules.h"
#include "../notes/received.h"
#include "../notes/share.h"
#include "../log/cause.h"
#include "members.h"
#include "succession.h"
#include "received.h"

#include <stdio.h>
#include <string.h>

static int log_grant(struct fzn_node_admin *admin, const uint8_t device[FZN_PUBKEY_LEN]);
static int next_word(const uint8_t **rest, size_t *rest_len, const uint8_t **w, size_t *w_len);

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
	if (!log_grant(admin, record.host))
		return answer_text(reply, cap, FZN_REPLY_ERROR,
		                   "paired and saved, and the grant is not in this node's log: it "
		                   "would fall at this node's revocation");

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
	 * compose there and the caller would hear nothing. Less `ok ` and the
	 * newline: `fzn_reply_ok_room`. */
	size_t limit = fzn_reply_ok_room(cap);
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
	/* One space and 64 hex characters per key, within that room; a
	 * contact's key is followed by `,contact`, since a peer paired for a
	 * share is no member (sec 436). */
	for (i = from; i < total; i++) {
		int contact = fzn_node_peer_contact(&admin->state->config, &admin->state->peers[i]);
		size_t need = 1u + (FZN_PUBKEY_LEN * 2u) + (contact ? 8u : 0u);

		if (at + need > limit)
			break;
		detail[at++] = ' ';
		put_hex(detail + at, admin->state->peers[i].sender, FZN_PUBKEY_LEN);
		at += FZN_PUBKEY_LEN * 2u;
		if (contact) {
			memcpy(detail + at, ",contact", 8u);
			at += 8u;
		}
	}
	return answer(reply, cap, FZN_REPLY_OK, detail, at);
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

/* `revoke peer KEY [CUT|none]`. sec 497: the vote draws a line in KEY's act
 * log, and the answer says where -- `ok KEY keeping CUT` or `ok KEY keeping
 * nothing`.
 *
 * WITH NO CUT NAMED, a first vote keeps everything this node has seen KEY
 * do: the head of KEY's log as held here, or nothing when it holds none or
 * the log has forked. A later `revoke peer KEY` with no cut leaves the line
 * where it is, so asking again never widens it to whatever a thief has
 * logged since. A CUT, or `none`, moves the line of a vote already cast. */

static size_t revoke_peer(fzn_node_admin_t *admin, const uint8_t *rest, size_t rest_len,
                          char *reply, size_t cap)
{
	static const char already[] = " already";
	static const char keeping[] = " keeping ";
	char detail[(FZN_PUBKEY_LEN * 2u) + sizeof(already) + sizeof(keeping)
	            + (FZN_REVOCATION_ID_LEN * 2u)];
	uint8_t grantee[FZN_PUBKEY_LEN], cut[FZN_REVOCATION_ID_LEN], held[FZN_REVOCATION_LEN];
	const uint8_t *hex = NULL, *line = NULL;
	size_t hex_len = 0, line_len = 0, at;
	const uint8_t *drawn = NULL;
	fzn_revocation_record_t rec;
	fzn_node_revoke_err_t rerr;
	uint64_t now;
	int named;

	if (!next_word(&rest, &rest_len, &hex, &hex_len)
	    || !unhex(hex, hex_len, grantee, sizeof(grantee)))
		return answer_text(reply, cap, FZN_REPLY_MALFORMED, "not a peer key");
	named = next_word(&rest, &rest_len, &line, &line_len);
	if (named && !(line_len == 4u && memcmp(line, "none", 4u) == 0)
	    && !unhex(line, line_len, cut, sizeof(cut)))
		return answer_text(reply, cap, FZN_REPLY_MALFORMED, "not a log entry id, nor none");
	if (named)
		drawn = (line_len == 4u && memcmp(line, "none", 4u) == 0) ? NULL : cut;
	else if (admin->roots && fzn_node_roots_head(admin->roots, grantee, cut))
		drawn = cut;
	now = admin->state->clock ? admin->state->clock() : 0u;
	/* NO CUT NAMED OVER A LIVE VOTE leaves its line: `fzn_node_revoke_at`
	 * would move it to today's head, so the held vote answers `already`. */
	if (!named && fzn_node_issued_revocation(admin->store, grantee, held)
	    && fzn_revocation_open(held, sizeof(held), &rec) == FZN_CHAIN_OK
	    && !fzn_revocation_is_withdrawal(rec))
		rerr = FZN_NODE_REVOKE_ALREADY;
	else
		rerr = fzn_node_revoke_at(admin->roots, admin->id, admin->state->config.root,
		                          voting_authority(admin),
		                          &admin->state->config.remote_capability, grantee, now, drawn,
		                          admin->revocations, admin->store);
	if (rerr != FZN_NODE_REVOKE_OK && rerr != FZN_NODE_REVOKE_ALREADY)
		return answer_text(reply, cap, FZN_REPLY_ERROR, fzn_node_revoke_err_str(rerr));
	memcpy(detail, hex, hex_len);
	at = hex_len;
	if (rerr == FZN_NODE_REVOKE_ALREADY) {
		memcpy(detail + at, already, sizeof(already) - 1u);
		at += sizeof(already) - 1u;
	}
	/* THE LINE THE HELD VOTE DRAWS, read back rather than echoed. */
	memcpy(detail + at, keeping, sizeof(keeping) - 1u);
	at += sizeof(keeping) - 1u;
	if (fzn_node_issued_revocation(admin->store, grantee, held)
	    && fzn_revocation_open(held, sizeof(held), &rec) == FZN_CHAIN_OK) {
		static const uint8_t NOTHING[FZN_REVOCATION_ID_LEN] = { 0 };

		if (memcmp(fzn_revocation_cut(rec), NOTHING, sizeof(NOTHING)) == 0) {
			memcpy(detail + at, "nothing", 7u);
			at += 7u;
		} else {
			put_hex(detail + at, fzn_revocation_cut(rec), FZN_REVOCATION_ID_LEN);
			at += FZN_REVOCATION_ID_LEN * 2u;
		}
	}
	return answer(reply, cap, FZN_REPLY_OK, detail, at);
}

/* LOG THE GRANT THIS NODE JUST MADE TO `device`: the last hop of the chain
 * the peer set holds for it, under its grantor. sec 497: a device granted
 * by a member that is later revoked keeps its standing only if the grant
 * lies before the member's line, which needs the grant logged. 1 when
 * logged, or with no log. */
static int log_grant(fzn_node_admin_t *admin, const uint8_t device[FZN_PUBKEY_LEN])
{
	fzn_chain_hop_t hop;
	size_t i;

	if (!admin->roots)
		return 1;
	for (i = 0; i < admin->state->peer_count; i++) {
		const fzn_node_peer_t *p = &admin->state->peers[i];

		if (memcmp(p->sender, device, FZN_PUBKEY_LEN) != 0 || p->hop_count == 0u)
			continue;
		if (fzn_hop_open(p->hop_bytes[p->hop_count - 1u], FZN_HOP_LEN, &hop) != FZN_CHAIN_OK)
			return 0;
		return fzn_node_roots_log_signed(admin->roots, admin->store, admin->id->pubkey,
		                                 admin->id->sign, fzn_hop_grantor(hop),
		                                 (uint8_t)FZN_ROOT_ACT_GRANT,
		                                 p->hop_bytes[p->hop_count - 1u], FZN_HOP_LEN)
		       == FZN_NODE_ROOTS_OK;
	}
	return 0;
}

int fzn_node_admin_log_roster(void *ctx, const uint8_t *record, size_t len)
{
	fzn_node_admin_t *admin = (fzn_node_admin_t *)ctx;
	fzn_roster_record_t rec;

	if (!admin || !record || !admin->roots)
		return 1;
	/* UNDER ITS WRITER, root or member, sec 497. */
	if (fzn_roster_open(record, len, &rec) != FZN_ROSTER_OK)
		return 0;
	return fzn_node_roots_log_signed(admin->roots, admin->store, admin->id->pubkey,
	                                 admin->id->sign, fzn_roster_writer(rec),
	                                 (uint8_t)FZN_ROOT_ACT_ROSTER, record, len)
	       == FZN_NODE_ROOTS_OK;
}

/* ---- successions, sec 499 ---------------------------------------------- */

/* The line a vote against `old` draws: a cut named, `none`, or with neither
 * the head of `old`'s log as held here (sec 497). 0 for a word that is
 * neither an id nor `none`. */
static int line_of(fzn_node_admin_t *admin, const uint8_t old[FZN_PUBKEY_LEN],
                   const uint8_t *word, size_t word_len, uint8_t cut[FZN_REVOCATION_ID_LEN],
                   const uint8_t **drawn)
{
	*drawn = NULL;
	if (word && word_len == 4u && memcmp(word, "none", 4u) == 0)
		return 1;
	if (word) {
		if (!unhex(word, word_len, cut, FZN_REVOCATION_ID_LEN))
			return 0;
		*drawn = cut;
		return 1;
	}
	if (admin->roots && fzn_node_roots_head(admin->roots, old, cut))
		*drawn = cut;
	return 1;
}

/* This node's vote against `old` at `drawn`, logged: what a re-key and a
 * confirmation of one both cast. NULL when it stood, else the words to say. */
static const char *vote_at(fzn_node_admin_t *admin, const uint8_t old[FZN_PUBKEY_LEN],
                           const uint8_t *drawn)
{
	fzn_node_revoke_err_t rerr;
	uint64_t now = admin->state->clock ? admin->state->clock() : 0u;

	rerr = fzn_node_revoke_at(admin->roots, admin->id, admin->state->config.root,
	                          voting_authority(admin), &admin->state->config.remote_capability,
	                          old, now, drawn, admin->revocations, admin->store);
	if (rerr != FZN_NODE_REVOKE_OK && rerr != FZN_NODE_REVOKE_ALREADY)
		return fzn_node_revoke_err_str(rerr);
	return NULL;
}

/* `add succession OLD`: confirm the one succession of OLD this node holds,
 * and vote OLD revoked at its line. A fork -- two re-keys of OLD to
 * different keys -- is refused: confirming either takes a side the owner has
 * to take. */
static size_t confirm_succession(fzn_node_admin_t *admin, const uint8_t old[FZN_PUBKEY_LEN],
                                 const uint8_t *old_hex, size_t old_hex_len, char *reply,
                                 size_t cap)
{
	const fzn_succession_set_t *set = &admin->successions->set;
	const fzn_succession_t *found = NULL;
	char detail[(FZN_PUBKEY_LEN * 4u) + 16u];
	const char *why;
	fzn_node_revoke_err_t err;
	size_t i, at;

	for (i = 0; i < set->used; i++) {
		if (memcmp(set->entries[i].old, old, FZN_PUBKEY_LEN) != 0)
			continue;
		if (found && memcmp(found->new_key, set->entries[i].new_key, FZN_PUBKEY_LEN) != 0)
			return answer_text(reply, cap, FZN_REPLY_ERROR,
			                   "that key is re-keyed two ways; confirming either takes a side");
		found = &set->entries[i];
	}
	if (!found)
		return answer_text(reply, cap, FZN_REPLY_ERROR, "no succession of that key is held");
	err = fzn_node_confirm_act(admin->roots, admin->store, admin->id, admin->admin_chain,
	                           admin->state->config.root, found->id, admin->revocations);
	if (err != FZN_NODE_REVOKE_OK)
		return answer_text(reply, cap, FZN_REPLY_ERROR, fzn_node_revoke_err_str(err));
	{
		static const uint8_t NOTHING[FZN_REVOCATION_ID_LEN] = { 0 };
		int none = memcmp(found->cut, NOTHING, sizeof(NOTHING)) == 0;

		why = vote_at(admin, old, none ? NULL : found->cut);
	}
	if (why)
		return answer_text(reply, cap, FZN_REPLY_ERROR, why);
	memcpy(detail, old_hex, old_hex_len);
	at = old_hex_len;
	detail[at++] = ' ';
	put_hex(detail + at, found->new_key, FZN_PUBKEY_LEN);
	at += FZN_PUBKEY_LEN * 2u;
	{
		const char *state = fzn_succession_counts(set, (size_t)(found - set->entries),
		                                          admin->revocations,
		                                          admin->state->config.root)
		                            ? " counting"
		                            : " waiting";

		memcpy(detail + at, state, strlen(state));
		at += strlen(state);
	}
	return answer(reply, cap, FZN_REPLY_OK, detail, at);
}

/* `add succession OLD PREKEY [CUT|none]`: RE-KEY a device. Pair the device's
 * new key from PREKEY, as `add peer` does; vote OLD revoked at the line; and
 * mint the succession OLD -> NEW at the same line. The answer is the new
 * device's card. In that order so that nothing is said about OLD until its
 * successor holds a grant, and each step that fails says which steps stood.
 * With one word, `add succession OLD` confirms another's re-key instead. */
static size_t add_succession(fzn_node_admin_t *admin, const uint8_t *rest, size_t rest_len,
                             char *reply, size_t cap)
{
	uint8_t old[FZN_PUBKEY_LEN], record_bytes[FZN_PREKEY_LEN_TOTAL],
	        cut[FZN_REVOCATION_ID_LEN];
	const uint8_t *old_hex = NULL, *prekey_hex = NULL, *line = NULL, *drawn = NULL;
	size_t old_len = 0, prekey_len = 0, line_len = 0, len;
	const uint8_t *detail = NULL;
	size_t detail_len = 0;
	fzn_prekey_record_t record;
	fzn_node_revoke_err_t serr;
	const char *why;

	if (!admin->successions || !admin->revocations)
		return answer_text(reply, cap, FZN_REPLY_ERROR, "this node keeps no successions");
	if (!next_word(&rest, &rest_len, &old_hex, &old_len)
	    || !unhex(old_hex, old_len, old, sizeof(old)))
		return answer_text(reply, cap, FZN_REPLY_MALFORMED, "not a peer key");
	if (!next_word(&rest, &rest_len, &prekey_hex, &prekey_len))
		return confirm_succession(admin, old, old_hex, old_len, reply, cap);
	if (!unhex(prekey_hex, prekey_len, record_bytes, sizeof(record_bytes))
	    || fzn_prekey_open(record_bytes, sizeof(record_bytes), &record) != FZN_PREKEY_OK)
		return answer_text(reply, cap, FZN_REPLY_MALFORMED, "not a prekey record");
	if (memcmp(record.host, old, FZN_PUBKEY_LEN) == 0)
		return answer_text(reply, cap, FZN_REPLY_MALFORMED,
		                   "a key is not its own successor");
	if (!line_of(admin, old,
	             next_word(&rest, &rest_len, &line, &line_len) ? line : NULL, line_len, cut,
	             &drawn))
		return answer_text(reply, cap, FZN_REPLY_MALFORMED, "not a log entry id, nor none");

	/* THE NEW KEY'S GRANT FIRST, answered with its card. */
	len = add_peer(admin, prekey_hex, prekey_len, reply, cap);
	if (fzn_reply_of((const uint8_t *)reply, len, &detail, &detail_len) != FZN_REPLY_OK)
		return len;
	why = vote_at(admin, old, drawn);
	if (why) {
		static char said[160];

		snprintf(said, sizeof(said), "the new key is paired, and the old is not revoked: %s",
		         why);
		return answer_text(reply, cap, FZN_REPLY_ERROR, said);
	}
	serr = fzn_node_succession_issue(admin->successions, admin->roots, admin->store, admin->id,
	                                 admin->admin_chain, admin->revocations,
	                                 admin->state->config.root, old, record.host, drawn,
	                                 NULL);
	if (serr != FZN_NODE_REVOKE_OK) {
		static char said[160];

		snprintf(said, sizeof(said),
		         "the new key is paired and the old revoked, and the succession was not: %s",
		         fzn_node_revoke_err_str(serr));
		return answer_text(reply, cap, FZN_REPLY_ERROR, said);
	}
	return len;
}

/* `list succession [FROM]`: `ok TOTAL FROM OLD>NEW,STATE ...`, paged as
 * `list peer` is. STATE is `counting`, or `waiting` for confirmations. */
static size_t list_successions(fzn_node_admin_t *admin, const uint8_t *from_text,
                               size_t from_len, char *reply, size_t cap)
{
	static char detail[FZN_REPLY_MAX];
	size_t limit = fzn_reply_ok_room(cap);
	const fzn_succession_set_t *set;
	size_t from = 0, at, i;
	int n;

	if (!admin->successions)
		return answer_text(reply, cap, FZN_REPLY_ERROR, "this node keeps no successions");
	set = &admin->successions->set;
	for (i = 0; i < from_len; i++) {
		if (from_text[i] < '0' || from_text[i] > '9' || from > FZN_NODE_SUCCESSIONS_MAX)
			return answer_text(reply, cap, FZN_REPLY_MALFORMED, "not a succession index");
		from = (from * 10u) + (size_t)(from_text[i] - '0');
	}
	if (from > set->used)
		return answer_text(reply, cap, FZN_REPLY_MALFORMED, "past the last succession");
	n = snprintf(detail, sizeof(detail), "%zu %zu", set->used, from);
	if (n < 0 || (size_t)n >= sizeof(detail))
		return 0;
	at = (size_t)n;
	for (i = from; i < set->used; i++) {
		int counts = fzn_succession_counts(set, i, admin->revocations,
		                                   admin->state->config.root);
		const char *state = counts ? ",counting" : ",waiting";
		size_t need = 2u + (FZN_PUBKEY_LEN * 4u) + strlen(state);

		if (at + need > limit)
			break;
		detail[at++] = ' ';
		put_hex(detail + at, set->entries[i].old, FZN_PUBKEY_LEN);
		at += FZN_PUBKEY_LEN * 2u;
		detail[at++] = '>';
		put_hex(detail + at, set->entries[i].new_key, FZN_PUBKEY_LEN);
		at += FZN_PUBKEY_LEN * 2u;
		memcpy(detail + at, state, strlen(state));
		at += strlen(state);
	}
	return answer(reply, cap, FZN_REPLY_OK, detail, at);
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
	rerr = fzn_node_unrevoke(admin->roots, admin->id, admin->state->config.root,
	                         voting_authority(admin), grantee, now, admin->revocations,
	                         admin->store);
	if (rerr != FZN_NODE_REVOKE_OK)
		return answer_text(reply, cap, FZN_REPLY_ERROR, fzn_node_revoke_err_str(rerr));
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

/* ---- contacts, sec 435 -------------------------------------------------- */

/* Whether `key` is inside this node's estate as the node sees it: itself,
 * the estate's root, or a node paired to it. A member is never a contact. */
static int is_member(const fzn_node_admin_t *admin, const uint8_t key[FZN_PUBKEY_LEN])
{
	size_t i;

	if (memcmp(key, admin->id->pubkey, FZN_PUBKEY_LEN) == 0
	    || memcmp(key, admin->state->config.root, FZN_PUBKEY_LEN) == 0)
		return 1;
	/* EVERY ROOT THAT STANDS, not only the one this node joined through:
	 * an estate added by its roots is the estate's (sec 407). */
	if (admin->roots && fzn_root_view_stands(&admin->roots->view, key))
		return 1;
	for (i = 0; i < admin->state->peer_count; i++)
		if (memcmp(key, admin->state->peers[i].sender, FZN_PUBKEY_LEN) == 0
		    && !fzn_node_peer_contact(&admin->state->config, &admin->state->peers[i]))
			return 1;
	return 0;
}

/* The next space-separated word of `rest`, moving it on. */
static int next_word(const uint8_t **rest, size_t *rest_len, const uint8_t **w, size_t *w_len)
{
	size_t i = 0;

	while (*rest_len && **rest == ' ') {
		(*rest)++;
		(*rest_len)--;
	}
	if (!*rest_len)
		return 0;
	while (i < *rest_len && (*rest)[i] != ' ')
		i++;
	*w = *rest;
	*w_len = i;
	*rest += i;
	*rest_len -= i;
	return 1;
}

int fzn_node_admin_is_member(const fzn_node_admin_t *admin, const uint8_t key[FZN_PUBKEY_LEN])
{
	return admin && admin->id && admin->state && key && is_member(admin, key);
}

/* The estate's k a roster is judged at: the running store's, which follows
 * the estate's setting (sec 418); 0, the roster's default, without one. */
static size_t roster_k(const fzn_node_admin_t *admin)
{
	return admin->revocations ? admin->revocations->quorum : 0u;
}

/* THE CONTACT AS THE ROSTER SAYS, sec 489: this node's act on it, and the
 * words for a refusal. */
static size_t roster_refusal(char *reply, size_t cap, fzn_node_roster_err_t err)
{
	return answer_text(reply, cap,
	                   err == FZN_NODE_ROSTER_NO_STANDING ? FZN_REPLY_DENIED : FZN_REPLY_ERROR,
	                   fzn_node_roster_err_str(err));
}

static uint64_t admin_now_ms(const fzn_node_admin_t *admin)
{
	return admin->state->clock ? admin->state->clock() * 1000u : 0u;
}

/* `add contact NAME KEY`: a key outside the estate, by a name. */
static size_t add_contact(fzn_node_admin_t *admin, const uint8_t *rest, size_t rest_len,
                          char *reply, size_t cap)
{
	uint8_t key[FZN_PUBKEY_LEN];
	const uint8_t *name, *hex;
	size_t name_len, hex_len;
	fzn_contact_err_t err;

	if (!next_word(&rest, &rest_len, &name, &name_len)
	    || !next_word(&rest, &rest_len, &hex, &hex_len) || !unhex(hex, hex_len, key, sizeof(key)))
		return answer_text(reply, cap, FZN_REPLY_MALFORMED, "add contact NAME KEY");
	if (is_member(admin, key))
		return answer_text(reply, cap, FZN_REPLY_ERROR,
		                   "a member of this estate, not a contact");
	err = fzn_contact_add(admin->store, key, (const char *)name, name_len, admin_now_ms(admin));
	if (err != FZN_CONTACT_OK)
		return answer_text(reply, cap,
		                   err == FZN_CONTACT_ERR_NAME ? FZN_REPLY_MALFORMED : FZN_REPLY_ERROR,
		                   fzn_contact_err_str(err));
	/* AND THE USER'S ACT, sec 489: an add on the roster every member pulls,
	 * unless the key is already a contact there. The name is this node's
	 * and is kept whatever the roster answers. */
	if (admin->roster) {
		fzn_node_roster_err_t rerr =
		        fzn_node_roster_write(admin->roster, admin->store, admin->id, admin->authority,
		                              admin->rng, key, 1, admin->revocations, roster_k(admin));

		if (rerr != FZN_NODE_ROSTER_OK)
			return roster_refusal(reply, cap, rerr);
	}
	return answer_text(reply, cap, FZN_REPLY_OK, NULL);
}

/* `remove contact NAME`. What was granted to it is revoked as chains are,
 * not here; but removing SUSPENDS it at once, sec 454 -- the remote handler
 * serves nothing to a key the list no longer holds. */
static size_t remove_contact(fzn_node_admin_t *admin, const uint8_t *rest, size_t rest_len,
                             char *reply, size_t cap)
{
	const uint8_t *name;
	size_t name_len;
	fzn_contact_t c;
	fzn_contact_err_t err;

	if (!next_word(&rest, &rest_len, &name, &name_len))
		return answer_text(reply, cap, FZN_REPLY_MALFORMED, "remove contact NAME");
	err = fzn_contact_find(admin->store, (const char *)name, name_len, &c);
	/* THE ROSTER FIRST, sec 489: a removal every member pulls, which
	 * suspends the contact there as here. One already not active here --
	 * removed on another member -- needs none, and its name goes. */
	if (err == FZN_CONTACT_OK && admin->roster) {
		fzn_node_roster_err_t rerr =
		        fzn_node_roster_write(admin->roster, admin->store, admin->id, admin->authority,
		                              admin->rng, c.key, 0, admin->revocations,
		                              roster_k(admin));

		if (rerr != FZN_NODE_ROSTER_OK && rerr != FZN_NODE_ROSTER_ABSENT)
			return roster_refusal(reply, cap, rerr);
	}
	if (err == FZN_CONTACT_OK)
		err = fzn_contact_remove(admin->store, c.key);
	if (err != FZN_CONTACT_OK)
		return answer_text(reply, cap,
		                   err == FZN_CONTACT_ERR_NAME ? FZN_REPLY_MALFORMED : FZN_REPLY_ERROR,
		                   fzn_contact_err_str(err));
	return answer_text(reply, cap, FZN_REPLY_OK, NULL);
}

/* `list contact [FROM]`: `ok TOTAL FROM NAME,KEY ...`, a page at a time. */
static size_t list_contacts(fzn_node_admin_t *admin, const uint8_t *rest, size_t rest_len,
                            char *reply, size_t cap)
{
	static fzn_contact_t all[FZN_CONTACTS_MAX];
	static char detail[FZN_REPLY_MAX];
	size_t limit = fzn_reply_ok_room(cap);
	size_t count = 0, from = 0, used, i, k;
	const uint8_t *w;
	size_t w_len;
	int n;

	if (next_word(&rest, &rest_len, &w, &w_len))
		for (i = 0; i < w_len; i++) {
			if (w[i] < '0' || w[i] > '9' || from > FZN_CONTACTS_MAX)
				return answer_text(reply, cap, FZN_REPLY_MALFORMED, "not an index");
			from = (from * 10u) + (size_t)(w[i] - '0');
		}
	if (fzn_contact_list(admin->store, all, FZN_CONTACTS_MAX, &count) != FZN_CONTACT_OK)
		return answer_text(reply, cap, FZN_REPLY_ERROR, "the contacts did not read");
	if (from > count)
		return answer_text(reply, cap, FZN_REPLY_MALFORMED, "past the last contact");
	n = snprintf(detail, sizeof(detail), "%zu %zu", count, from);
	if (n < 0 || (size_t)n >= limit)
		return 0;
	used = (size_t)n;
	for (i = from; i < count; i++) {
		size_t need = 1u + all[i].name_len + 1u + (FZN_PUBKEY_LEN * 2u);

		if (limit - used < need)
			break;
		detail[used++] = ' ';
		memcpy(detail + used, all[i].name, all[i].name_len);
		used += all[i].name_len;
		detail[used++] = ',';
		for (k = 0; k < FZN_PUBKEY_LEN; k++)
			used += (size_t)snprintf(detail + used, 3u, "%02x", all[i].key[k]);
		/* NOT A CONTACT ON THE ROSTER, sec 489: removed on another
		 * member, retired, or held by a writer since revoked -- named
		 * here and served nothing. */
		if (admin->roster) {
			fzn_roster_state_t st = fzn_node_roster_standing(admin->roster, all[i].key,
			                                                 admin->revocations,
			                                                 roster_k(admin));
			const char *word = st == FZN_ROSTER_SUSPENDED ? ",suspended"
			                   : st == FZN_ROSTER_RETIRED ? ",retired"
			                   : st == FZN_ROSTER_ABSENT  ? ",absent"
			                                              : "";
			size_t wl = strlen(word);

			if (limit - used < wl) {
				used -= need;
				break;
			}
			memcpy(detail + used, word, wl);
			used += wl;
		}
	}
	return answer(reply, cap, FZN_REPLY_OK, detail, used);
}

/* ---- groups of contacts, sec 471 ----------------------------------------- */

static size_t group_refusal(char *reply, size_t cap, fzn_contact_err_t err)
{
	return answer_text(reply, cap,
	                   err == FZN_CONTACT_ERR_NAME ? FZN_REPLY_MALFORMED : FZN_REPLY_ERROR,
	                   fzn_contact_err_str(err));
}

/* `add group NAME` and `remove group NAME`. REMOVING A GROUP TAKES ITS
 * SHARES WITH IT, sec 478: its id is its name's, so a group made again
 * under the name would inherit them and serve the old group's notes to
 * whoever is in the new one. The shares go first, as fuzzypickles' contact
 * shares do: a group gone with its shares left is the hazard. */
static size_t change_group(fzn_node_admin_t *admin, int add, const uint8_t *rest,
                           size_t rest_len, char *reply, size_t cap)
{
	const uint8_t *name;
	size_t name_len;
	fzn_contact_err_t err;

	if (!next_word(&rest, &rest_len, &name, &name_len))
		return answer_text(reply, cap, FZN_REPLY_MALFORMED,
		                   add ? "add group NAME" : "remove group NAME");
	if (!add) {
		static fzn_group_t group;
		fzn_notes_store_t notes;
		size_t gone = 0;

		err = fzn_group_find(admin->store, (const char *)name, name_len, &group);
		if (err != FZN_CONTACT_OK)
			return group_refusal(reply, cap, err);
		if (fzn_notes_store_init(&notes, admin->store, admin->state->hash) != FZN_NOTES_OK
		    || fzn_notes_share_forget(&notes, group.id, &gone) != FZN_NOTES_OK
		    || (admin->files_forget && !admin->files_forget(admin->files_ctx, group.id)))
			return answer_text(reply, cap, FZN_REPLY_ERROR,
			                   "the group's shares would not all go, so it stays");
	}
	err = add ? fzn_group_add(admin->store, admin->rng, (const char *)name, name_len,
	                          admin->state->clock ? admin->state->clock() * 1000u : 0u)
	          : fzn_group_remove(admin->store, (const char *)name, name_len);
	return err == FZN_CONTACT_OK ? answer_text(reply, cap, FZN_REPLY_OK, NULL)
	                             : group_refusal(reply, cap, err);
}

/* `add member GROUP CONTACT` and `remove member GROUP CONTACT`: a contact
 * into a group, or out of it. A member is a contact: a key outside the
 * estate the node knows by name. */
static size_t change_member(fzn_node_admin_t *admin, int add, const uint8_t *rest,
                            size_t rest_len, char *reply, size_t cap)
{
	const uint8_t *group, *name;
	size_t group_len, name_len;
	fzn_contact_t contact;
	fzn_contact_err_t err;

	if (!next_word(&rest, &rest_len, &group, &group_len)
	    || !next_word(&rest, &rest_len, &name, &name_len))
		return answer_text(reply, cap, FZN_REPLY_MALFORMED,
		                   add ? "add member GROUP CONTACT" : "remove member GROUP CONTACT");
	err = fzn_contact_find(admin->store, (const char *)name, name_len, &contact);
	if (err == FZN_CONTACT_OK)
		err = add ? fzn_group_join(admin->store, (const char *)group, group_len, contact.key)
		          : fzn_group_leave(admin->store, (const char *)group, group_len, contact.key);
	return err == FZN_CONTACT_OK ? answer_text(reply, cap, FZN_REPLY_OK, NULL)
	                             : group_refusal(reply, cap, err);
}

/* `list group [FROM]`: `ok TOTAL FROM NAME,COUNT ...`, a page at a time. */
static size_t list_groups(fzn_node_admin_t *admin, const uint8_t *rest, size_t rest_len,
                          char *reply, size_t cap)
{
	static fzn_group_t all[FZN_GROUPS_MAX];
	static char detail[FZN_REPLY_MAX];
	size_t limit = fzn_reply_ok_room(cap);
	size_t count = 0, from = 0, used, i;
	const uint8_t *w;
	size_t w_len;
	int n;

	if (next_word(&rest, &rest_len, &w, &w_len))
		for (i = 0; i < w_len; i++) {
			if (w[i] < '0' || w[i] > '9' || from > FZN_GROUPS_MAX)
				return answer_text(reply, cap, FZN_REPLY_MALFORMED, "not an index");
			from = (from * 10u) + (size_t)(w[i] - '0');
		}
	if (fzn_group_list(admin->store, all, FZN_GROUPS_MAX, &count) != FZN_CONTACT_OK)
		return answer_text(reply, cap, FZN_REPLY_ERROR, "the groups did not read");
	if (from > count)
		return answer_text(reply, cap, FZN_REPLY_MALFORMED, "past the last group");
	n = snprintf(detail, sizeof(detail), "%zu %zu", count, from);
	if (n < 0 || (size_t)n >= limit)
		return 0;
	used = (size_t)n;
	for (i = from; i < count; i++) {
		char item[FZN_CONTACT_NAME_MAX + 8u];
		int k = snprintf(item, sizeof(item), " %s,%zu", all[i].name, all[i].count);

		if (k < 0 || limit - used < (size_t)k)
			break;
		memcpy(detail + used, item, (size_t)k);
		used += (size_t)k;
	}
	return answer(reply, cap, FZN_REPLY_OK, detail, used);
}

/* `get group NAME`: `ok COUNT NAME ...`, the members by contact name -- a
 * key that is no contact any more by its hex. */
static size_t get_group(fzn_node_admin_t *admin, const uint8_t *rest, size_t rest_len,
                        char *reply, size_t cap)
{
	static fzn_group_t g;
	static char detail[FZN_REPLY_MAX];
	size_t limit = fzn_reply_ok_room(cap);
	const uint8_t *name;
	size_t name_len, used, i, k;
	fzn_contact_err_t err;
	int n;

	if (!next_word(&rest, &rest_len, &name, &name_len))
		return answer_text(reply, cap, FZN_REPLY_MALFORMED, "get group NAME");
	err = fzn_group_find(admin->store, (const char *)name, name_len, &g);
	if (err != FZN_CONTACT_OK)
		return group_refusal(reply, cap, err);
	n = snprintf(detail, sizeof(detail), "%zu", g.count);
	if (n < 0 || (size_t)n >= limit)
		return 0;
	used = (size_t)n;
	for (i = 0; i < g.count; i++) {
		fzn_contact_t c;
		char who[(FZN_PUBKEY_LEN * 2u) + 1u];
		size_t who_len;

		if (fzn_contact_get(admin->store, g.members[i], &c) == FZN_CONTACT_OK) {
			memcpy(who, c.name, c.name_len);
			who_len = c.name_len;
		} else {
			for (k = 0; k < FZN_PUBKEY_LEN; k++)
				(void)snprintf(who + (k * 2u), 3u, "%02x", g.members[i][k]);
			who_len = FZN_PUBKEY_LEN * 2u;
		}
		if (limit - used < 1u + who_len)
			break;
		detail[used++] = ' ';
		memcpy(detail + used, who, who_len);
		used += who_len;
	}
	return answer(reply, cap, FZN_REPLY_OK, detail, used);
}

/* ---- retention rules, sec 475 ------------------------------------------- */

/* `add retention RULE` and `remove retention RULE`: a rule of
 * `log/retain.h`'s, kept in the store and applied by the writer from its
 * next pass. Either spelling of a rule removes it. */
static size_t change_retention(fzn_node_admin_t *admin, int add, const uint8_t *rest,
                               size_t rest_len, char *reply, size_t cap)
{
	fzn_retain_rule_t rule;
	fzn_log_rules_err_t err;

	if (!rest_len || fzn_retain_parse((const char *)rest, rest_len, &rule) != FZN_RETAIN_OK)
		return answer_text(reply, cap, FZN_REPLY_MALFORMED,
		                   "prune|keep PROGRAM|* [level=LETTERS] [subsystem=PATH] "
		                   "age|size|count N");
	err = add ? fzn_log_rules_add(admin->store, admin->state->hash, &rule,
	                              admin->state->clock ? admin->state->clock() * 1000u : 0u)
	          : fzn_log_rules_remove(admin->store, admin->state->hash, &rule);
	if (err == FZN_LOG_RULES_OK)
		return answer_text(reply, cap, FZN_REPLY_OK, NULL);
	return answer_text(reply, cap,
	                   err == FZN_LOG_RULES_ERR_MALFORMED ? FZN_REPLY_MALFORMED : FZN_REPLY_ERROR,
	                   fzn_log_rules_err_str(err));
}

/* `ok COUNT RULE ...`, each rule in its canonical text with a byte below
 * 0x21, `%` and `,` as `%XX`, so a rule is one word. */
static size_t rules_reply(const fzn_retain_rule_t *rules, size_t count, char *reply, size_t cap)
{
	static char detail[FZN_REPLY_MAX];
	size_t limit = fzn_reply_ok_room(cap);
	size_t used, i, j;
	int n;

	n = snprintf(detail, sizeof(detail), "%zu", count);
	if (n < 0 || (size_t)n >= limit)
		return 0;
	used = (size_t)n;
	for (i = 0; i < count; i++) {
		char text[FZN_RETAIN_TEXT_MAX], word[(FZN_RETAIN_TEXT_MAX * 3u) + 2u];
		size_t len = 0, w = 0;

		if (fzn_retain_text(&rules[i], text, sizeof(text), &len) != FZN_RETAIN_OK)
			return answer_text(reply, cap, FZN_REPLY_ERROR, "a held rule will not read");
		word[w++] = ' ';
		for (j = 0; j < len; j++) {
			unsigned char c = (unsigned char)text[j];

			if (c < 0x21u || c == '%' || c == ',' || c == 0x7fu) {
				(void)snprintf(word + w, 4u, "%%%02X", c);
				w += 3u;
			} else {
				word[w++] = (char)c;
			}
		}
		if (limit - used < w)
			return answer_text(reply, cap, FZN_REPLY_ERROR, "the rules do not fit a line");
		memcpy(detail + used, word, w);
		used += w;
	}
	return answer(reply, cap, FZN_REPLY_OK, detail, used);
}

/* `list retention`: this node's own rules. */
static size_t list_retention(fzn_node_admin_t *admin, char *reply, size_t cap)
{
	static fzn_retain_rule_t rules[FZN_LOG_RULES_MAX];
	size_t count = 0;
	fzn_log_rules_err_t err = fzn_log_rules_list(admin->store, rules, FZN_LOG_RULES_MAX, &count);

	if (err != FZN_LOG_RULES_OK)
		return answer_text(reply, cap, FZN_REPLY_ERROR, fzn_log_rules_err_str(err));
	return rules_reply(rules, count, reply, cap);
}

/* `add estate-retention RULE` and `remove estate-retention RULE`: one of the
 * estate's rules, as this node's acting root, carried with the root
 * records to every host (sec 476) -- or, with no root here, as the admin
 * this node's admin chain makes it (sec 479). */
static size_t change_estate_retention(fzn_node_admin_t *admin, int add, const uint8_t *rest,
                                      size_t rest_len, char *reply, size_t cap)
{
	fzn_retain_rule_t rule;
	fzn_node_roots_err_t err;

	if (!rest_len || fzn_retain_parse((const char *)rest, rest_len, &rule) != FZN_RETAIN_OK)
		return answer_text(reply, cap, FZN_REPLY_MALFORMED,
		                   "prune|keep PROGRAM|* [level=LETTERS] [subsystem=PATH] "
		                   "age|size|count N");
	err = fzn_node_roots_set_retention(admin->roots, admin->store, admin->id->pubkey,
	                                   admin->id->sign, &rule, add);
	/* NO ROOT HERE, AN ADMIN PERHAPS, sec 479: the holder's "admin (and
	 * root) capability". The record is this node's act, in its journal,
	 * and a reader rebuilds the admin chain from the grants (sec 505). */
	if (err == FZN_NODE_ROOTS_NOT_ROOT && admin->admin_chain && admin->admin_chain->hop_count)
		err = fzn_node_roots_set_retention_as_admin(
		        admin->roots, admin->store, admin->id->pubkey, admin->id->sign,
		        (const uint8_t (*)[FZN_HOP_LEN])admin->admin_chain->hops,
		        admin->admin_chain->hop_count, admin->state->config.root, &rule, add);
	if (err == FZN_NODE_ROOTS_OK)
		return answer_text(reply, cap, FZN_REPLY_OK, NULL);
	if (err == FZN_NODE_ROOTS_NOT_ROOT)
		return answer_text(reply, cap, FZN_REPLY_ERROR,
		                   "this node stands as neither a root nor an admin");
	return answer_text(reply, cap,
	                   err == FZN_NODE_ROOTS_MALFORMED ? FZN_REPLY_MALFORMED : FZN_REPLY_ERROR,
	                   err == FZN_NODE_ROOTS_HELD       ? "the rule is the estate's already"
	                   : err == FZN_NODE_ROOTS_REFUSED && !add ? "no such estate rule"
	                                                       : fzn_node_roots_err_str(err));
}

/* `list estate-retention`: the estate's rules as this node resolves them.
 * Non-mutating: the rules are the estate's, and travel with its root
 * records. A record whose text is no rule here is refused aloud rather
 * than listed short. */
static size_t list_estate_retention(fzn_node_admin_t *admin, char *reply, size_t cap)
{
	static fzn_retain_rule_t rules[FZN_NODE_ROOT_RETENTION_MAX];
	size_t count = 0, unread = 0;

	if (fzn_node_roots_retention(admin->roots, rules, FZN_NODE_ROOT_RETENTION_MAX, &count,
	                             &unread)
	    != FZN_NODE_ROOTS_OK)
		return answer_text(reply, cap, FZN_REPLY_ERROR, "the estate's rules did not resolve");
	if (unread)
		return answer_text(reply, cap, FZN_REPLY_ERROR,
		                   "an estate rule is not one this node reads");
	return rules_reply(rules, count, reply, cap);
}

/* `grant share NAME PREKEY`: pair the contact NAME's node, whose prekey
 * record this is, for the share capability, and answer the card it accepts.
 * sec 436. Granted by this node's own key whatever the estate's root is: a
 * share is this node's grant of its own notes. What it reaches is the share
 * table's (`add share`), so one grant serves every subtree shared with the
 * contact, and granting again replaces the pairing. */
static size_t grant_share(fzn_node_admin_t *admin, const uint8_t *rest, size_t rest_len,
                          char *reply, size_t cap)
{
	uint8_t record_bytes[FZN_PREKEY_LEN_TOTAL];
	uint8_t card[FZN_PROVISION_MAX_LEN];
	char text[FZN_PROVISION_TEXT_MAX_LEN];
	fzn_prekey_record_t record;
	fzn_contact_t contact;
	fzn_contact_err_t cerr;
	fzn_node_pair_err_t perr;
	const uint8_t *name, *hex;
	size_t name_len, hex_len, card_len = 0, loaded = 0;
	uint64_t now;

	if (!admin->state->config.has_share)
		return answer_text(reply, cap, FZN_REPLY_ERROR, "this node does not share notes");
	if (!next_word(&rest, &rest_len, &name, &name_len)
	    || !next_word(&rest, &rest_len, &hex, &hex_len))
		return answer_text(reply, cap, FZN_REPLY_MALFORMED, "grant share NAME PREKEY");
	if (!unhex(hex, hex_len, record_bytes, sizeof(record_bytes))
	    || fzn_prekey_open(record_bytes, sizeof(record_bytes), &record) != FZN_PREKEY_OK)
		return answer_text(reply, cap, FZN_REPLY_MALFORMED, "not a prekey record");
	cerr = fzn_contact_find(admin->store, (const char *)name, name_len, &contact);
	if (cerr != FZN_CONTACT_OK)
		return answer_text(reply, cap,
		                   cerr == FZN_CONTACT_ERR_NAME ? FZN_REPLY_MALFORMED : FZN_REPLY_ERROR,
		                   fzn_contact_err_str(cerr));
	/* THE CONTACT'S OWN NODE: the record must be signed by the key the
	 * contact was added under, or the grant goes to whoever handed over a
	 * prekey. */
	if (memcmp(record.host, contact.key, FZN_PUBKEY_LEN) != 0)
		return answer_text(reply, cap, FZN_REPLY_ERROR, "that prekey is not the contact's");
	/* A member is paired as one; a share chain would replace its grant. */
	if (is_member(admin, contact.key))
		return answer_text(reply, cap, FZN_REPLY_ERROR,
		                   "a member of this estate, not a contact");
	now = admin->state->clock ? admin->state->clock() : 0u;
	perr = fzn_node_pair(admin->id, admin->id->pubkey, &admin->state->config.share_capability,
	                     NULL, 0, admin->store, record, now, now + admin->card_lifetime, card,
	                     sizeof(card), &card_len);
	if (perr != FZN_NODE_PAIR_OK)
		return answer_text(reply, cap, FZN_REPLY_ERROR, fzn_node_pair_err_str(perr));
	if (fzn_node_peers_load(admin->store, admin->peers, admin->peers_cap, &loaded)
	    != FZN_PERSIST_OK)
		return answer_text(reply, cap, FZN_REPLY_ERROR,
		                   "granted and saved, and the running peer set did not reload");
	admin->state->peers = admin->peers;
	admin->state->peer_count = loaded;
	if (fzn_provision_text(card, card_len, text, sizeof(text)) != FZN_PROVISION_OK)
		return answer_text(reply, cap, FZN_REPLY_ERROR,
		                   "granted and saved, and the card would not encode");
	return answer(reply, cap, FZN_REPLY_OK, text, strlen(text));
}

/* `add received NAME HOST PORT PATH`: take the card the contact NAME's node
 * answered `grant share` with, as the pairing this node asks it under, and
 * pull from HOST PORT. sec 437. PATH is a file holding the card's text, read
 * by the node as itself: a one-hop card is some 650 characters, past what
 * one request line carries (FZN_REQUEST_MAX), where a reply has room. THE CARD IS CHECKED BEFORE IT IS TAKEN: it
 * must be one hop, granted by the contact's own key, for this node's share
 * capability -- a member's card handed over as a share would otherwise be
 * filed as one, and a share card from somebody else under this contact's
 * name. */
static size_t accept_share(fzn_node_admin_t *admin, const uint8_t *rest, size_t rest_len,
                           char *reply, size_t cap)
{
	static uint8_t card[FZN_PROVISION_MAX_LEN];
	static char text[FZN_PROVISION_TEXT_MAX_LEN + 2u];
	const uint8_t *name, *host, *port_w, *path;
	size_t name_len, host_len, port_len, path_len, text_len = 0, card_len = 0, i;
	char file[512];
	FILE *f;
	unsigned long port = 0;
	fzn_provision_card_t opened;
	fzn_chain_hop_t hop;
	fzn_node_pairing_t pairing;
	fzn_contact_t contact;
	fzn_contact_err_t cerr;
	fzn_node_pair_err_t perr;
	fzn_node_received_err_t rerr;

	if (!admin->state->config.has_share)
		return answer_text(reply, cap, FZN_REPLY_ERROR, "this node keeps no notes to share");
	if (!next_word(&rest, &rest_len, &name, &name_len)
	    || !next_word(&rest, &rest_len, &host, &host_len)
	    || !next_word(&rest, &rest_len, &port_w, &port_len)
	    || !next_word(&rest, &rest_len, &path, &path_len) || port_len > 5u
	    || path_len >= sizeof(file) || memchr(path, '\0', path_len)
	    || !fzn_node_received_host_ok((const char *)host, host_len))
		return answer_text(reply, cap, FZN_REPLY_MALFORMED, "add received NAME HOST PORT PATH");
	for (i = 0; i < port_len; i++) {
		if (port_w[i] < '0' || port_w[i] > '9')
			return answer_text(reply, cap, FZN_REPLY_MALFORMED, "not a port");
		port = (port * 10u) + (unsigned long)(port_w[i] - '0');
	}
	if (port == 0u || port > 65535u)
		return answer_text(reply, cap, FZN_REPLY_MALFORMED, "not a port");
	cerr = fzn_contact_find(admin->store, (const char *)name, name_len, &contact);
	if (cerr != FZN_CONTACT_OK)
		return answer_text(reply, cap,
		                   cerr == FZN_CONTACT_ERR_NAME ? FZN_REPLY_MALFORMED : FZN_REPLY_ERROR,
		                   fzn_contact_err_str(cerr));
	memcpy(file, path, path_len);
	file[path_len] = '\0';
	f = fopen(file, "rb");
	if (!f)
		return answer_text(reply, cap, FZN_REPLY_ERROR, "cannot read that file");
	text_len = fread(text, 1u, sizeof(text) - 1u, f);
	(void)fclose(f);
	/* THE TEXT AS `grant share` ANSWERED IT, with whatever line ending the
	 * file was saved with taken off. */
	while (text_len && (text[text_len - 1u] == '\n' || text[text_len - 1u] == '\r'
	                    || text[text_len - 1u] == ' '))
		text_len--;
	text[text_len] = '\0';
	if (fzn_provision_from_text(text, card, sizeof(card), &card_len) != FZN_PROVISION_OK
	    || fzn_provision_open(card, card_len, &opened) != FZN_PROVISION_OK
	    || fzn_hop_open(opened.hop, FZN_HOP_LEN, &hop) != FZN_CHAIN_OK)
		return answer_text(reply, cap, FZN_REPLY_MALFORMED, "not a card");
	if (opened.hop_count != 1u || memcmp(opened.root, contact.key, FZN_PUBKEY_LEN) != 0
	    || memcmp(fzn_hop_grantor(hop), contact.key, FZN_PUBKEY_LEN) != 0)
		return answer_text(reply, cap, FZN_REPLY_ERROR, "that card is not the contact's grant");
	if (memcmp(fzn_hop_capability(hop)->b, admin->state->config.share_capability.b,
	           FZN_CAP_ID_LEN)
	    != 0)
		return answer_text(reply, cap, FZN_REPLY_ERROR, "that card grants no share");
	perr = fzn_node_pairing_accept(admin->id, card, card_len,
	                               admin->state->clock ? admin->state->clock() : 0u, admin->store,
	                               &pairing);
	fzn_wipe(&pairing, sizeof(pairing));
	if (perr != FZN_NODE_PAIR_OK)
		return answer_text(reply, cap, FZN_REPLY_ERROR, fzn_node_pair_err_str(perr));
	rerr = fzn_node_received_add(admin->store, contact.key, (const char *)host, host_len,
	                             (uint16_t)port, admin_now_ms(admin));
	if (rerr != FZN_NODE_RECEIVED_OK)
		return answer_text(reply, cap, FZN_REPLY_ERROR, fzn_node_received_err_str(rerr));
	admin->received_fresh = 1;
	return answer_text(reply, cap, FZN_REPLY_OK, NULL);
}

/* `list received`: `ok COUNT NAME,HOST,PORT ...`, a share accepted from a
 * contact since forgotten naming its key. */
static size_t list_received(fzn_node_admin_t *admin, char *reply, size_t cap)
{
	fzn_node_received_t all[FZN_NODE_RECEIVED_MAX];
	static char detail[FZN_REPLY_MAX];
	size_t limit = fzn_reply_ok_room(cap);
	size_t count = 0, used, i, k;
	int n;

	if (fzn_node_received_list(admin->store, all, FZN_NODE_RECEIVED_MAX, &count)
	    != FZN_NODE_RECEIVED_OK)
		return answer_text(reply, cap, FZN_REPLY_ERROR, "the accepted shares did not read");
	n = snprintf(detail, sizeof(detail), "%zu", count);
	if (n < 0 || (size_t)n >= limit)
		return 0;
	used = (size_t)n;
	for (i = 0; i < count; i++) {
		fzn_contact_t contact;
		char who[(FZN_PUBKEY_LEN * 2u) + 1u];
		char port[8];
		size_t who_len, port_len;

		if (fzn_contact_get(admin->store, all[i].sharer, &contact) == FZN_CONTACT_OK) {
			memcpy(who, contact.name, contact.name_len);
			who_len = contact.name_len;
		} else {
			for (k = 0; k < FZN_PUBKEY_LEN; k++)
				(void)snprintf(who + (2u * k), 3u, "%02x", all[i].sharer[k]);
			who_len = FZN_PUBKEY_LEN * 2u;
		}
		n = snprintf(port, sizeof(port), "%u", (unsigned)all[i].port);
		port_len = n > 0 ? (size_t)n : 0u;
		if (limit - used < 1u + who_len + 1u + all[i].host_len + 1u + port_len)
			break;
		detail[used++] = ' ';
		memcpy(detail + used, who, who_len);
		used += who_len;
		detail[used++] = ',';
		memcpy(detail + used, all[i].host, all[i].host_len);
		used += all[i].host_len;
		detail[used++] = ',';
		memcpy(detail + used, port, port_len);
		used += port_len;
	}
	return answer(reply, cap, FZN_REPLY_OK, detail, used);
}

/* `remove received NAME`: stop pulling what the contact NAME shares, and
 * forget what was pulled. sec 437. */
static size_t remove_received(fzn_node_admin_t *admin, const uint8_t *rest, size_t rest_len,
                              char *reply, size_t cap)
{
	const uint8_t *name;
	size_t name_len, gone = 0;
	fzn_contact_t contact;
	fzn_contact_err_t cerr;
	fzn_node_received_err_t rerr;

	if (!next_word(&rest, &rest_len, &name, &name_len))
		return answer_text(reply, cap, FZN_REPLY_MALFORMED, "remove received NAME");
	cerr = fzn_contact_find(admin->store, (const char *)name, name_len, &contact);
	if (cerr != FZN_CONTACT_OK)
		return answer_text(reply, cap,
		                   cerr == FZN_CONTACT_ERR_NAME ? FZN_REPLY_MALFORMED : FZN_REPLY_ERROR,
		                   fzn_contact_err_str(cerr));
	rerr = fzn_node_received_remove(admin->store, contact.key);
	if (rerr != FZN_NODE_RECEIVED_OK)
		return answer_text(reply, cap, FZN_REPLY_ERROR, fzn_node_received_err_str(rerr));
	admin->received_fresh = 1;
	/* WHAT WAS PULLED GOES TOO: a share this node stopped taking is not
	 * one it keeps reading from a copy nobody refreshes. */
	if (fzn_notes_received_forget(admin->store, admin->state->hash, contact.key, &gone)
	    != FZN_NOTES_OK)
		return answer_text(reply, cap, FZN_REPLY_ERROR,
		                   "stopped, and the pulled notes would not all go");
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
	/* THE ESTATE'S RETENTION RULES, sec 476: set as a root, read by any. */
	if (subject_word(request, "estate-retention", &rest, &rest_len) && admin->roots) {
		if (request->parsed == FZN_VERB_LIST)
			return list_estate_retention(admin, reply, reply_cap);
		if (request->parsed == FZN_VERB_ADD || request->parsed == FZN_VERB_REMOVE)
			return change_estate_retention(admin, request->parsed == FZN_VERB_ADD, rest,
			                               rest_len, reply, reply_cap);
	}
	/* SUCCESSIONS, sec 499: re-keying a device, confirming another's
	 * re-key, and reading what is held. */
	if (request->parsed == FZN_VERB_ADD && subject_word(request, "succession", &rest, &rest_len)
	    && rest)
		return add_succession(admin, rest, rest_len, reply, reply_cap);
	if (request->parsed == FZN_VERB_LIST
	    && subject_word(request, "succession", &rest, &rest_len))
		return list_successions(admin, rest, rest_len, reply, reply_cap);
	/* ADMINS, sec 416: only on a node whose config names the capability. */
	if (admin->state->config.has_admin && request->parsed == FZN_VERB_GRANT
	    && subject_word(request, "admin", &rest, &rest_len) && rest)
		return grant_admin(admin, rest, rest_len, reply, reply_cap);
	if (admin->state->config.has_admin && request->parsed == FZN_VERB_ADD
	    && subject_word(request, "confirm", &rest, &rest_len) && rest && admin->revocations)
		return confirm_admin(admin, rest, rest_len, reply, reply_cap);
	/* SHARES, sec 436: the grant is the pairing, so it is admin's; which
	 * subtrees it reaches is the notes' `add share`. */
	if (request->parsed == FZN_VERB_GRANT && subject_word(request, "share", &rest, &rest_len)
	    && rest)
		return grant_share(admin, rest, rest_len, reply, reply_cap);
	/* RECEIVED SHARES, sec 437: the node's own user only, reads included,
	 * as for contacts. */
	if ((request->parsed == FZN_VERB_ADD || request->parsed == FZN_VERB_LIST
	     || request->parsed == FZN_VERB_REMOVE)
	    && subject_word(request, "received", &rest, &rest_len)) {
		if (origin != FZN_ORIGIN_SAME_USER)
			return answer_text(reply, reply_cap, FZN_REPLY_DENIED,
			                   "shares need this node's own user");
		if (request->parsed == FZN_VERB_LIST)
			return list_received(admin, reply, reply_cap);
		if (!rest)
			return answer_text(reply, reply_cap, FZN_REPLY_MALFORMED,
			                   request->parsed == FZN_VERB_ADD
			                           ? "add received NAME HOST PORT PATH"
			                           : "remove received NAME");
		if (request->parsed == FZN_VERB_ADD)
			return accept_share(admin, rest, rest_len, reply, reply_cap);
		return remove_received(admin, rest, rest_len, reply, reply_cap);
	}
	/* CONTACTS, sec 435: the node's own user only, reads included. */
	if (subject_word(request, "contact", &rest, &rest_len)
	    && (request->parsed == FZN_VERB_ADD || request->parsed == FZN_VERB_REMOVE
	        || request->parsed == FZN_VERB_LIST)) {
		if (origin != FZN_ORIGIN_SAME_USER)
			return answer_text(reply, reply_cap, FZN_REPLY_DENIED,
			                   "contacts need this node's own user");
		if (request->parsed == FZN_VERB_ADD)
			return add_contact(admin, rest, rest_len, reply, reply_cap);
		if (request->parsed == FZN_VERB_REMOVE)
			return remove_contact(admin, rest, rest_len, reply, reply_cap);
		return list_contacts(admin, rest, rest_len, reply, reply_cap);
	}
	/* GROUPS OF CONTACTS, sec 471: as contacts, the node's own user only. */
	{
		const uint8_t *g_rest = NULL, *m_rest = NULL;
		size_t g_len = 0, m_len = 0;
		int group = subject_word(request, "group", &g_rest, &g_len)
		            && (request->parsed == FZN_VERB_ADD || request->parsed == FZN_VERB_REMOVE
		                || request->parsed == FZN_VERB_LIST || request->parsed == FZN_VERB_GET);
		int member = !group && subject_word(request, "member", &m_rest, &m_len)
		             && (request->parsed == FZN_VERB_ADD || request->parsed == FZN_VERB_REMOVE);

		rest = member ? m_rest : g_rest;
		rest_len = member ? m_len : g_len;
		if (!group && !member)
			goto not_groups;
		if (origin != FZN_ORIGIN_SAME_USER)
			return answer_text(reply, reply_cap, FZN_REPLY_DENIED,
			                   "groups need this node's own user");
		if (!admin->state->hash)
			return answer_text(reply, reply_cap, FZN_REPLY_ERROR, "this node has no hash");
		if (member)
			return change_member(admin, request->parsed == FZN_VERB_ADD, rest, rest_len,
			                     reply, reply_cap);
		if (request->parsed == FZN_VERB_LIST)
			return list_groups(admin, rest, rest_len, reply, reply_cap);
		if (request->parsed == FZN_VERB_GET)
			return get_group(admin, rest, rest_len, reply, reply_cap);
		return change_group(admin, request->parsed == FZN_VERB_ADD, rest, rest_len, reply,
		                    reply_cap);
	}
not_groups:
	/* RETENTION RULES, sec 475: the node's own user, whose logs they are. */
	{
		const uint8_t *r_rest = NULL;
		size_t r_len = 0;

		if (subject_word(request, "retention", &r_rest, &r_len)
		    && (request->parsed == FZN_VERB_ADD || request->parsed == FZN_VERB_REMOVE
		        || request->parsed == FZN_VERB_LIST)) {
			if (origin != FZN_ORIGIN_SAME_USER)
				return answer_text(reply, reply_cap, FZN_REPLY_DENIED,
				                   "retention rules need this node's own user");
			if (!admin->store || !admin->state->hash)
				return answer_text(reply, reply_cap, FZN_REPLY_ERROR,
				                   "this node keeps no rules");
			if (request->parsed == FZN_VERB_LIST)
				return list_retention(admin, reply, reply_cap);
			return change_retention(admin, request->parsed == FZN_VERB_ADD, r_rest, r_len,
			                        reply, reply_cap);
		}
	}
	/* NOTES, sec 431, when this node keeps them. */
	if (admin->notes_local) {
		size_t n = admin->notes_local(admin->notes_ctx, origin, request, reply, reply_cap);

		if (n)
			return n;
	}
	/* TEXTS, sec 424: the shelf's, when this node has one. */
	if (admin->text_local) {
		size_t n = admin->text_local(admin->text_ctx, origin, request, reply, reply_cap);

		if (n)
			return n;
	}
	/* FILES, sec 490: the store's, when this node has one. */
	if (admin->files_local) {
		size_t n = admin->files_local(admin->files_ctx, origin, request, reply, reply_cap);

		if (n)
			return n;
	}
	/* MESSAGES, sec 527, when this node keeps them. */
	if (admin->messages_local) {
		size_t n = admin->messages_local(admin->messages_ctx, origin, request, reply,
		                                 reply_cap);

		if (n)
			return n;
	}

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

	/* THE CAUSES OFF FIRST, sec 462: whatever the request is -- a verb, a
	 * notes sync message, a text's span, a contact's -- it may come in an
	 * envelope naming the entries it was made for, and is handled as the
	 * request inside. An envelope that does not read is refused rather than
	 * handled as bytes nobody sent. */
	if (req->payload) {
		static fzn_opened_t inner;
		fzn_entry_name_t cause, origin;
		const uint8_t *in = NULL;
		size_t in_len = 0;
		fzn_cause_err_t cerr = fzn_cause_unwrap(req->payload, req->payload_len, &cause,
		                                        &origin, &in, &in_len);

		if (cerr == FZN_CAUSE_ERR_MALFORMED)
			return answer_text(out, reply_cap, FZN_REPLY_MALFORMED,
			                   "the request's causes do not read");
		if (cerr == FZN_CAUSE_OK) {
			inner = *req;
			inner.payload = in;
			inner.payload_len = in_len;
			if (admin->caused)
				admin->caused(admin->caused_ctx, req->sender, &cause, &origin);
			req = &inner;
		}
	}

	/* A CONTACT, granted the share capability and nothing else, sec 436:
	 * the notes sync messages over what is shared with it, and no verb,
	 * no shelf, no status. Asked of the same predicate the authorisation
	 * asked, so a request is answered as what it was granted as. */
	if (fzn_node_request_shared(&admin->state->config, req->capability)) {
		size_t n = 0;
		fzn_contact_t still;

		/* A REMOVED CONTACT IS SUSPENDED AT ONCE, sec 454, as sec 394 has
		 * the holder decide for removal: nothing is served to a key the
		 * contact list no longer holds, though its grant and its share
		 * rows stay -- nothing is deleted, and adding it back serves it
		 * again. */
		if (!admin->store || fzn_contact_get(admin->store, req->sender, &still) != FZN_CONTACT_OK)
			return answer_text(out, reply_cap, FZN_REPLY_DENIED, "no longer a contact");
		/* AND ACTIVE ON THE ROSTER, sec 489: removed on any member of the
		 * estate is removed here, whatever this node's name book says. */
		if (admin->roster
		    && fzn_node_roster_standing(admin->roster, req->sender, admin->revocations,
		                                roster_k(admin))
		               != FZN_ROSTER_ACTIVE)
			return answer_text(out, reply_cap, FZN_REPLY_DENIED, "no longer a contact");
		if (admin->notes_remote && req->payload)
			n = admin->notes_remote(admin->notes_ctx, req->sender, 1, req->payload,
			                        req->payload_len, reply, reply_cap);
		/* ITS NOTES' TEXTS, sec 438, and no other blob. */
		if (!n && admin->text_shared && req->payload)
			n = admin->text_shared(admin->text_shared_ctx, req->sender, req->payload,
			                       req->payload_len, reply, reply_cap);
		/* THE FILES PUBLIC OR SHARED WITH IT, sec 493. */
		if (!n && admin->files_shared && req->payload)
			n = admin->files_shared(admin->files_ctx, req->sender, req->payload,
			                        req->payload_len, reply, reply_cap);
		return n ? n
		         : answer_text(out, reply_cap, FZN_REPLY_DENIED,
		                       "a contact may only fetch what is shared with it");
	}

	/* A LOG GATHERED, sec 463: a member's query for this host's log,
	 * answered or refused by the hook as the host's scope says; 0 for what
	 * is not one. Contacts never reach here. */
	if (admin->logs_remote && req->payload) {
		size_t n = admin->logs_remote(admin->logs_ctx, req->sender, req->payload,
		                              req->payload_len, reply, reply_cap);

		if (n)
			return n;
	}

	/* A BLOB MESSAGE, before the line is split: its first byte is the
	 * message version, below any verb's first letter, so the shelf
	 * recognises it or returns 0 and the verbs follow. sec 424. */
	if (admin->text_remote && req->payload) {
		size_t n = admin->text_remote(admin->text_ctx, req->payload, req->payload_len, reply,
		                              reply_cap);

		if (n)
			return n;
	}

	/* A JOURNAL MESSAGE, version byte 5, the same way. sec 501. */
	if (admin->journal_remote && req->payload) {
		size_t n = admin->journal_remote(admin->journal_ctx, req->payload, req->payload_len,
		                                 reply, reply_cap);

		if (n)
			return n;
	}

	/* A NOTES SYNC MESSAGE, version byte 2, the same way. sec 432. */
	if (admin->notes_remote && req->payload) {
		size_t n = admin->notes_remote(admin->notes_ctx, req->sender, 0, req->payload,
		                               req->payload_len, reply, reply_cap);

		if (n)
			return n;
	}
	/* A MEMBER'S CONVERSATION KEYS, the same version byte, types 23 to
	 * 26. sec 527. Below the contact branch, so a contact never reaches
	 * them. */
	if (admin->messages_remote && req->payload) {
		size_t n = admin->messages_remote(admin->messages_ctx, req->sender, req->payload,
		                                  req->payload_len, reply, reply_cap);

		if (n)
			return n;
	}
	/* THE ESTATE'S MEMBERS, with the chains this node holds for them, for
	 * a member admitting their notes. sec 445. */
	if (req->payload) {
		size_t n = fzn_node_members_answer(&admin->state->config, admin->state->peers,
		                                   admin->state->peer_count, req->payload,
		                                   req->payload_len, reply, reply_cap);

		if (n)
			return n;
	}

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
	/* THE ESTATE'S ACTS TRAVEL IN THE JOURNAL, sec 505: `get vote`, `get
	 * root` and `get revocation` are gone, and a journal message is
	 * answered above. */
	return answer_text(out, reply_cap, FZN_REPLY_UNSUPPORTED, NULL);
}
