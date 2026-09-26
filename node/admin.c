/* See admin.h. */

#include "admin.h"

#include "peer_persist.h"
#include "../provision/provision.h"

#include <string.h>

/* `ok ` and the whole card text must fit one reply line, or `add peer` is a
 * verb this node cannot answer. FZN_PROVISION_TEXT_LEN counts the NUL. */
_Static_assert(3u + (FZN_PROVISION_TEXT_LEN - 1u) <= FZN_REPLY_MAX,
               "a pairing card does not fit one reply line");
_Static_assert(FZN_NODE_LOCAL_REPLY_MAX >= FZN_REPLY_MAX + 1u,
               "the node's local reply buffer cannot hold a whole reply line");

static const uint8_t SUBJECT_PEER[] = "peer ";

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
	uint8_t card[FZN_PROVISION_LEN_TOTAL];
	char text[FZN_PROVISION_TEXT_LEN];
	fzn_prekey_record_t record;
	fzn_node_pair_err_t perr;
	size_t card_len = 0, loaded = 0;
	uint64_t now;

	if (!unhex(hex, hex_len, record_bytes, sizeof(record_bytes))
	    || fzn_prekey_open(record_bytes, sizeof(record_bytes), &record) != FZN_PREKEY_OK)
		return answer_text(reply, cap, FZN_REPLY_MALFORMED, "not a prekey record");

	now = admin->state->clock ? admin->state->clock() : 0u;
	perr = fzn_node_pair(admin->id, admin->state->config.root,
	                     &admin->state->config.remote_capability, admin->store, record, now,
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

size_t fzn_node_admin_handle(void *ctx, fzn_authz_verdict_t verdict, fzn_origin_t origin,
                             const fzn_peer_t *peer, const fzn_request_t *request,
                             char *reply, size_t reply_cap)
{
	fzn_node_admin_t *admin = (fzn_node_admin_t *)ctx;

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

	if (request->parsed == FZN_VERB_ADD && request->arg
	    && request->arg_len > sizeof(SUBJECT_PEER) - 1u
	    && memcmp(request->arg, SUBJECT_PEER, sizeof(SUBJECT_PEER) - 1u) == 0)
		return add_peer(admin, request->arg + (sizeof(SUBJECT_PEER) - 1u),
		                request->arg_len - (sizeof(SUBJECT_PEER) - 1u), reply, reply_cap);

	return answer_text(reply, reply_cap, FZN_REPLY_UNSUPPORTED, NULL);
}
