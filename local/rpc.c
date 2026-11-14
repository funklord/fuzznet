/* usleep, getentropy, mkdtemp and lstat are past POSIX's 2008 base. */
#define _DEFAULT_SOURCE

#include "rpc.h"

#include <inttypes.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include "rpc_compat.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "rpc_encoding.h"
#include "rpc_err.h"
#include "../location/location.h"

#include "client.h"
#include "escape.h"
#include "socket.h"
#include "vocabulary.h"
#include "../prekey/prekey.h"
#include "../provision/provision.h"
#include "../messages/attachment.h"
#include "../node/contact_card.h"
#include "../sticker/pack.h"
#include "rpc_binary.h"
#include "../hex/hex.h"
#include "../wire/cmd.h"
#include "../wire/status.h"
#include "../wire/generated/objects.h"
#include "../wire/generated/objects_build.h"
#include "../wire/generated/messages_local.h"
#include "../wire/generated/messages_local_build.h"

/* A reply from fuzznetd is read into the response buffer, so it must hold
 * the longest one fuzznet allows. */
_Static_assert(sizeof(((fzn_rpc_t *)0)->resp) >= FZN_REPLY_MAX + 1u,
               "a call's buffer must hold fuzznetd's longest reply");

void fzn_rpc_init(fzn_rpc_t *c) { memset(c, 0, sizeof(*c)); }

static int fail(fzn_rpc_t *c, int code, const char *text) {
	c->error_code = code ? code : FZN_RPC_ERR_MALFORMED;
	snprintf(c->error, sizeof(c->error), "%s", text);
	return c->error_code;
}

/* The daemon took the request and its answer did not parse. */
/* Room for `need` items of `size`, grown by doubling and zeroed: FZN_RPC_OK, or the
 * refusal when memory has run out, which is what bounds a list. */
static int room_for(fzn_rpc_t *c, void *items, size_t *room, size_t need, size_t size) {
	void **at = items;
	if (need <= *room) return FZN_RPC_OK;
	size_t grown = *room ? *room * 2 : 64;
	if (grown < need) grown = need;
	void *more = realloc(*at, grown * size);
	if (!more) return fail(c, FZN_RPC_ERR_STORAGE_IO, "out of memory for that list");
	memset((char *)more + *room * size, 0, (grown - *room) * size);
	*at = more;
	*room = grown;
	return FZN_RPC_OK;
}

void fzn_rpc_peer_list_release(fzn_rpc_peer_list_resp_t *v) {
	free(v->entries);
	memset(v, 0, sizeof *v);
}
void fzn_rpc_group_list_release(fzn_rpc_group_list_resp_t *v) {
	free(v->entries);
	memset(v, 0, sizeof *v);
}
void fzn_rpc_group_show_release(fzn_rpc_group_show_resp_t *v) {
	free(v->members);
	memset(v, 0, sizeof *v);
}
void fzn_rpc_notes_list_release(fzn_rpc_notes_list_resp_t *v) {
	free(v->entries);
	memset(v, 0, sizeof *v);
}
void fzn_rpc_library_list_release(fzn_rpc_library_list_all_t *v) {
	free(v->entries);
	memset(v, 0, sizeof *v);
}

static int unreadable(fzn_rpc_t *c) {
	c->unreadable = 1;
	return fail(c, FZN_RPC_ERR_MALFORMED, "the daemon's answer did not parse");
}

/* A refusal made before fuzznetd was asked anything in this call: nothing
 * answered, whatever an earlier call on `c` left there. */
static int node_unasked(fzn_rpc_t *c, int code, const char *text) {
	c->answered = 0;
	c->unreadable = 0;
	return fail(c, code, text);
}

static int encode_failed(fzn_rpc_t *c) {
	c->answered = 0;
	return fail(c, FZN_RPC_ERR_MALFORMED, "the request could not be built -- a name too long?");
}

static int node_status(fzn_rpc_t *c, fzn_rpc_status_resp_t *out); /* with the node calls */
static int node_word(const char **p, const char *end, const char **w, size_t *w_len);
static int node_u64(const char *p, size_t len, uint64_t *out);
static int node_transfer_list(fzn_rpc_t *c, fzn_rpc_transfer_list_resp_t *out); /* likewise */
static int node_config_schema(fzn_rpc_t *c, const char *prefix, size_t prefix_len,
                              fzn_rpc_config_schema_resp_t *out);
static int node_config_get(fzn_rpc_t *c, const char *key, size_t key_len, fzn_rpc_config_get_resp_t *out);
static int node_config_set(fzn_rpc_t *c, const char *key, size_t key_len, const char *value,
                           size_t value_len, const char *expected, size_t expected_len);
static int node_config_status(fzn_rpc_t *c, const char *key, size_t key_len, const char *instance,
                              size_t instance_len, fzn_rpc_config_status_resp_t *out);

int fzn_rpc_status(fzn_rpc_t *c, fzn_rpc_status_resp_t *out) {
	return node_status(c, out);
}

/* ---- fuzznetd's replies, read (sec 284) ---- */

/* A decimal token at *at, which moves past it and one space. */
static int node_number(const char *p, size_t len, size_t *at, size_t *out) {
	size_t v = 0, i = *at, digits = 0;
	while (i < len && p[i] >= '0' && p[i] <= '9' && digits < 18) {
		v = v * 10u + (size_t)(p[i] - '0');
		i++;
		digits++;
	}
	if (!digits || (i < len && p[i] != ' ')) return 0;
	*out = v;
	*at = i < len ? i + 1 : i;
	return 1;
}

static int hex_nibble(char ch) {
	if (ch >= '0' && ch <= '9') return ch - '0';
	if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
	return -1;
}

/* Exactly 64 lowercase hex digits, as fuzznetd writes a key. */
static int node_key(const char *p, size_t len, uint8_t out[32]) {
	if (len != 64) return 0;
	for (size_t i = 0; i < 32; i++) {
		const int hi = hex_nibble(p[2 * i]), lo = hex_nibble(p[2 * i + 1]);
		if (hi < 0 || lo < 0) return 0;
		out[i] = (uint8_t)(hi << 4 | lo);
	}
	return 1;
}

/*
 * The contacts, from `list contact [FROM]`: `ok TOTAL FROM NAME,KEY[,state]
 * ...` a page at a time (fuzznet's node/admin.c), asked again from where the
 * page stopped until TOTAL is reached -- every page moving FROM on,
 * in case a daemon keeps answering without moving.
 *
 * WHAT IT CARRIES IS LESS THAN the clients' LISTING, and the gaps are fuzznet's to
 * fill rather than this side's to invent (sec 284):
 *   - the key is the USER's, fuzznet keying a contact by user, so it is
 *     root_pubkey; host_pubkey stays zero rather than repeating it under a
 *     name that says something else;
 *   - no address comes back; the location-share state is asked of each
 *     contact afterwards (node_peer_shares);
 *   - a contact carrying a state (`suspended`, `retired`, `absent` -- removed
 *     on another member, served nothing) is listed with it in `state`
 *     (sec 1118); one in a state this client does not know is left out, a
 *     contact listed as ordinary being the wrong answer.
 */
/*
 * Whether each contact may ask where this host is, and at what level: one
 * paged `list stream location granted` (fuzznet's answer to inbox
 * 20261106T1530Z), the level each grant was made at -- the clients'
 * precision, which node_location_share sends. Read back rather than assumed,
 * since both clients report a grant from this field: without it a node showed
 * every contact unshared, and a grant just made read as withdrawn. It was one
 * `get stream location NAME` a contact until a0a9542 (2026-11-06).
 */
static void node_peer_shares(fzn_rpc_t *c, fzn_rpc_peer_list_resp_t *out) {
	for (size_t i = 0; i < out->count; i++) out->entries[i].share_location = 0;
	size_t from = 0;
	for (;;) {
		char arg[48];
		const char *rest = NULL;
		size_t rest_len = 0, at = 0, total = 0, start = 0, rows = 0;
		const int arg_len = snprintf(arg, sizeof arg, "stream location granted %zu", from);
		if (fzn_rpc_node(c, "list", arg, (size_t)arg_len, &rest, &rest_len) != FZN_RPC_OK) break;
		if (!node_number(rest, rest_len, &at, &total) || !node_number(rest, rest_len, &at, &start) ||
		    start != from)
			break;
		while (at < rest_len) {
			size_t end = at, level_at = 0, level = 0;
			while (end < rest_len && rest[end] != ' ') end++;
			const char *e = rest + at, *comma = memchr(e, ',', end - at);
			const size_t e_len = end - at;
			at = end < rest_len ? end + 1 : end;
			rows++;
			if (!comma) continue;
			const size_t name_len = (size_t)(comma - e);
			if (!node_number(comma + 1, e_len - name_len - 1, &level_at, &level) ||
			    level > FZN_RPC_LOCATION_PRECISION_MAX)
				continue;
			for (size_t i = 0; i < out->count; i++) {
				fzn_rpc_peer_list_entry_t *p = &out->entries[i];
				if (p->name_len != name_len || memcmp(p->name, e, name_len) != 0) continue;
				p->share_location = 1;
				p->share_precision = (uint8_t)level;
				break;
			}
		}
		from += rows;
		if (!rows || from >= total) break;
	}
	c->error[0] = '\0';
	c->error_code = 0;
}

static int node_peer_list(fzn_rpc_t *c, fzn_rpc_peer_list_resp_t *out) {
	out->count = 0;
	size_t from = 0;
	for (;;) {
		char arg[32];
		const int arg_len = snprintf(arg, sizeof arg, "contact %zu", from);
		const char *rest = NULL;
		size_t rest_len = 0;
		int rc = fzn_rpc_node(c, "list", arg, (size_t)arg_len, &rest, &rest_len);
		if (rc != FZN_RPC_OK) return rc;
		size_t at = 0, total = 0, start = 0, listed = 0;
		if (!node_number(rest, rest_len, &at, &total) || !node_number(rest, rest_len, &at, &start) ||
		    start != from)
			return unreadable(c);
		while (at < rest_len) {
			size_t end = at;
			while (end < rest_len && rest[end] != ' ') end++;
			const char *e = rest + at;
			const size_t e_len = end - at;
			at = end < rest_len ? end + 1 : end;
			listed++;
			const char *comma = memchr(e, ',', e_len);
			if (!comma) return unreadable(c);
			const size_t name_len = (size_t)(comma - e);
			const char *key = comma + 1;
			const char *key_end = memchr(key, ',', e_len - name_len - 1);
			const size_t key_len = key_end ? (size_t)(key_end - key) : e_len - name_len - 1;
			/* A CONTACT IN A STATE, sec 1118: listed with it. A word this
			 * client does not know is passed over, since listing it as an
			 * ordinary contact would be the wrong answer. */
			uint8_t state = FZN_RPC_CONTACT_ACTIVE;
			if (key_end) {
				const char *w = key_end + 1;
				const size_t w_len = e_len - (size_t)(w - e);
				if (w_len == 9 && !memcmp(w, "suspended", 9)) state = FZN_RPC_CONTACT_SUSPENDED;
				else if (w_len == 7 && !memcmp(w, "retired", 7)) state = FZN_RPC_CONTACT_RETIRED;
				else if (w_len == 6 && !memcmp(w, "absent", 6)) state = FZN_RPC_CONTACT_ABSENT;
				else continue;
			}
			if (!name_len || name_len > FZN_RPC_PEER_NAME_MAX) return unreadable(c);
			rc = room_for(c, &out->entries, &out->room, out->count + 1, sizeof *out->entries);
			if (rc != FZN_RPC_OK) return rc;
			fzn_rpc_peer_list_entry_t *p = &out->entries[out->count];
			memset(p, 0, sizeof *p);
			if (!node_key(key, key_len, p->root_pubkey)) return unreadable(c);
			memcpy(p->name, e, name_len);
			p->name[name_len] = '\0';
			p->name_len = name_len;
			p->state = state;
			out->count++;
		}
		from += listed;
		if (!listed || from >= total) break;
	}
	return FZN_RPC_OK;
}

/*
 * Where a call stages what will not fit a request line, or what the node
 * writes for it: THE DIRECTORY OF THE NODE'S SOCKET. That is the one place
 * both sides are known to reach, since the node made its socket there and
 * this client has just connected to it. /tmp is not: a phone has none, and
 * no TMPDIR in an app's environment, so a note's text could not be saved at
 * all there (found on two emulators, 2026-11-04); and the desktop's unit
 * runs the node with PrivateTmp, so a file staged in /tmp is one it cannot
 * see and one it writes there is one this client cannot.
 *
 * $TMPDIR, then /tmp, stay behind it for a client that may not write there:
 * another local user the node's user has granted a subject (fuzznet sec
 * 852). The path goes to fuzznetd, which takes a file only by an absolute
 * path (fuzznet sec 651): a relative one would be read in its own directory.
 */
#define NODE_STAGE_MAX 160

static int node_stage_path(const fzn_rpc_t *c, int attempt, const char *name, char *out) {
	const char *tmp = getenv("TMPDIR");
	const char *slash = strrchr(c->node_socket, '/');
	const char *dir = attempt == 0 ? c->node_socket : attempt == 1 ? tmp : "/tmp";
	int dir_len = attempt == 0 ? (slash ? (int)(slash - c->node_socket) : 0)
	                           : dir ? (int)strlen(dir) : 0;
	if (!dir_len || !dir || dir[0] != '/') return 0;
	const int n = snprintf(out, NODE_STAGE_MAX, "%.*s/fzp-%s-XXXXXX", dir_len, dir, name);
	return n > 0 && n < NODE_STAGE_MAX;
}

/* A new file of this process's own, named into `path`: -1 when nowhere
 * would take one. */
static int node_stage_file(const fzn_rpc_t *c, const char *name, char path[NODE_STAGE_MAX]) {
	for (int attempt = 0; attempt < 3; attempt++) {
		if (!node_stage_path(c, attempt, name, path)) continue;
		const int fd = mkstemp(path);
		if (fd >= 0) return fd;
	}
	path[0] = '\0';
	return -1;
}

/* A contact named to a verb: its name, or its 64-hex key, which every verb
 * taking a name also takes and which is how one of two sharing a name is
 * reached (fuzznet sec 893). */
#define NODE_WHO_MAX 64
static int node_who_fits(size_t len) { return len <= FZN_RPC_PEER_NAME_MAX || len == NODE_WHO_MAX; }
/* A CONVERSATION as one word: a contact's name or key, or `@` and a group's
 * name or 64-hex id (fuzznet secs 629, 647). The `@` is not the name's, so
 * a 32-character group name and a group's id both fit. */
static int node_conversation_fits(const char *who, size_t len) {
	if (len && who[0] == '@') return len > 1 && node_who_fits(len - 1);
	return len && node_who_fits(len);
}

/*
 * A name a node will hold: fuzznet's rule, and the clients', 1 to 32 of letters,
 * digits and _. Asked here for a name that MAKES something, because a name
 * goes into a request as a word: "book club" was taken as the group "book",
 * with "club" a stray word and nothing said (2026-11-04).
 */
static int node_name_ok(const char *name, size_t len) {
	if (!name || !len || len > FZN_RPC_PEER_NAME_MAX) return 0;
	for (size_t i = 0; i < len; i++) {
		const char ch = name[i];
		if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') ||
		      ch == '_'))
			return 0;
	}
	return 1;
}

/* The six pairing calls on fuzznetd (sec 284): its sec 619 verbs, a card
 * carried as its `FZC1:` text. */

/* `get card [NAME]`: the text, as the card's bytes. The clients show a
 * card's bytes as hex, base58 or QR and decode them back to bytes, so the
 * text round-trips through every surface unchanged, and the receiving side
 * hands those bytes to `add contact` as they are. */
static int node_card_show(fzn_rpc_t *c, const char *display_name, size_t display_name_len,
                          fzn_rpc_card_show_resp_t *out) {
	memset(out, 0, sizeof(*out));
	char arg[8 + FZN_RPC_PEER_NAME_MAX + 1];
	if (display_name_len > FZN_RPC_PEER_NAME_MAX) return encode_failed(c);
	const int arg_len = display_name_len
	                        ? snprintf(arg, sizeof arg, "card %.*s", (int)display_name_len,
	                                   display_name)
	                        : snprintf(arg, sizeof arg, "card");
	const char *rest = NULL;
	size_t rest_len = 0;
	int rc = fzn_rpc_node(c, "get", arg, (size_t)arg_len, &rest, &rest_len);
	if (rc != FZN_RPC_OK) return rc;
	if (rest_len < 5 || memcmp(rest, "FZC1:", 5) != 0) return unreadable(c);
	if (rest_len > sizeof(out->card_blob))
		return fail(c, FZN_RPC_ERR_BUFFER_TOO_SMALL, "the node's card is longer than a card here holds");
	memcpy(out->card_blob, rest, rest_len);
	out->card_blob_len = rest_len;
	return FZN_RPC_OK;
}

int fzn_rpc_node_card_read(const char *text, size_t text_len, char *name, size_t name_cap,
                       char *address, size_t address_cap) {
	if (name_cap) name[0] = '\0';
	if (address_cap) address[0] = '\0';
	static uint8_t bytes[FZN_CONTACT_CARD_MAX];
	static fzn_contact_card_t card;
	size_t len = 0;
	if (!text || fzn_contact_card_from_text(text, text_len, bytes, sizeof bytes, &len) !=
	                 FZN_CONTACT_CARD_OK ||
	    fzn_contact_card_decode(bytes, len, &card) != FZN_CONTACT_CARD_OK)
		return FZN_RPC_ERR_MALFORMED;
	if (name_cap) snprintf(name, name_cap, "%.*s", (int)card.name_len, card.name);
	if (address_cap) {
		if (card.host.address_len)
			snprintf(address, address_cap, "%.*s:%u", (int)card.host.address_len,
			         card.host.address, (unsigned)card.host.port);
		else if (card.n_seeds)
			snprintf(address, address_cap, "%.*s:%u", (int)card.seeds[0].address_len,
			         card.seeds[0].address, (unsigned)card.seeds[0].port);
	}
	return FZN_RPC_OK;
}

/*
 * A name a person is about to give a contact, held by somebody else already.
 * A node takes it (fuzznet sec 893) and then refuses the name wherever it is
 * used, and the clients know a contact by its name, so two sharing one could
 * reach neither. Said here, where the person is choosing it. `key` is who is
 * being named, which may keep its own name; NULL when not known.
 */
static int node_name_is_free(fzn_rpc_t *c, const char *name, size_t name_len, const uint8_t *key) {
	static fzn_rpc_peer_list_resp_t held;
	const int rc = fzn_rpc_peer_list(c, &held);
	if (rc != FZN_RPC_OK) return rc;
	for (size_t i = 0; i < held.count; i++) {
		const fzn_rpc_peer_list_entry_t *e = &held.entries[i];
		if (e->name_len != name_len || memcmp(e->name, name, name_len) != 0) continue;
		if (key && memcmp(e->root_pubkey, key, 32) == 0) continue;
		return node_unasked(c, FZN_RPC_ERR_PEER_EXISTS,
		                    "you already have a contact of that name -- give this one another");
	}
	return FZN_RPC_OK;
}

/*
 * `add contact NAME CARD|PATH`: the card, inline when it fits the request
 * line and by a file otherwise -- a card is usually longer than the line's
 * FZN_REQUEST_MAX, and fuzznet takes a path for that (its sec 619). The
 * file is this process's own, mode 0600, and gone when the call returns.
 * The requester address and proposed name are the clients': a fuzznet card
 * carries its own, so they are not sent.
 */
static int node_peer_request_send(fzn_rpc_t *c, const uint8_t *card, size_t card_len,
                                  const char *local_name, size_t local_name_len,
                                  const char *self, size_t self_len,
                                  fzn_rpc_peer_request_send_resp_t *out) {
	memset(out, 0, sizeof(*out));
	if (!node_name_ok(local_name, local_name_len))
		return node_unasked(c, FZN_RPC_ERR_INVALID_PEER_NAME, fzn_rpc_err_str(FZN_RPC_ERR_INVALID_PEER_NAME));
	if (card_len < 5 || memcmp(card, "FZC1:", 5) != 0)
		return node_unasked(c, FZN_RPC_ERR_MALFORMED, "that is not a fuzznet card (FZC1:...)");
	/* WHO IS ASKING, `as SELF` (fuzznet sec 825): the name the asker gives
	 * itself in its card, so the other side reads more than a key. A node
	 * takes letters, digits and _ there, so another name is refused here in
	 * those words rather than sent to be refused. */
	char as[8 + FZN_RPC_PEER_NAME_MAX + 1] = "";
	if (self_len) {
		if (self_len > FZN_RPC_PEER_NAME_MAX) return node_unasked(c, FZN_RPC_ERR_MALFORMED, "that name is too long to give");
		if (!node_name_ok(self, self_len))
			return node_unasked(c, FZN_RPC_ERR_MALFORMED,
			                    "the name a node gives itself is letters, digits and _");
		snprintf(as, sizeof as, " as %.*s", (int)self_len, self);
	}
	{
		static uint8_t bytes[FZN_CONTACT_CARD_MAX];
		static fzn_contact_card_t parsed;
		size_t len = 0;
		const int read = fzn_contact_card_from_text((const char *)card, card_len, bytes, sizeof bytes,
		                                            &len) == FZN_CONTACT_CARD_OK &&
		                 fzn_contact_card_decode(bytes, len, &parsed) == FZN_CONTACT_CARD_OK;
		const int free_rc =
		    node_name_is_free(c, local_name, local_name_len, read ? parsed.host.owner : NULL);
		if (free_rc != FZN_RPC_OK) return free_rc;
	}
	char arg[FZN_REQUEST_MAX];
	char path[NODE_STAGE_MAX] = "";
	int arg_len = snprintf(arg, sizeof arg, "contact %.*s %.*s%s", (int)local_name_len, local_name,
	                       (int)card_len, (const char *)card, as);
	/* The line is `add SP ARG LF`, at most FZN_REQUEST_MAX. */
	if (arg_len < 0 || (size_t)arg_len > FZN_REQUEST_MAX - 5u) {
		const int fd = node_stage_file(c, "card", path);
		if (fd < 0) return node_unasked(c, FZN_RPC_ERR_STORAGE_IO, "could not stage the card for the node");
		const int wrote = write(fd, card, card_len) == (ssize_t)card_len;
		close(fd);
		if (!wrote) {
			unlink(path);
			return node_unasked(c, FZN_RPC_ERR_STORAGE_IO, "could not stage the card for the node");
		}
		arg_len = snprintf(arg, sizeof arg, "contact %.*s %s%s", (int)local_name_len, local_name,
		                   path, as);
	}
	const char *rest = NULL;
	size_t rest_len = 0;
	const int rc = fzn_rpc_node(c, "add", arg, (size_t)arg_len, &rest, &rest_len);
	if (path[0]) unlink(path);
	if (rc != FZN_RPC_OK) return rc;
	/* `ok ROOT`: the card's user, which is what fuzznet keys the contact by. */
	return node_key(rest, rest_len, out->target_host_pubkey) ? FZN_RPC_OK : unreadable(c);
}

/* `list request FROM`: `ok COUNT ROOT,NAME,RECEIVED[,ADDRESS] ...` from the
 * FROMth, oldest first. The requester's key is its USER's, as fuzznet keys
 * contacts, and goes where this side keeps the requester's key, so approve
 * and reject hand it back as fuzznetd gave it. A request with no name is
 * listed as `-`, read as no name: a node's names are letters, digits and _
 * (fuzznet sec 825), so `-` is never one, and the clients say "(none)". */
static int node_peer_request_list(fzn_rpc_t *c, fzn_rpc_peer_request_list_resp_t *out) {
	memset(out, 0, sizeof(*out));
	/*
	 * PAGED, `list request FROM`. The node stops adding rows at its 1024-byte
	 * reply -- about eleven requests, a row being a key, a name and a time --
	 * while COUNT still says how many it holds, and it holds up to sixteen.
	 * Read in one piece, the twelfth pending request made this listing
	 * refuse itself as short (the shape fuzznet sec 770 found in `list
	 * location`). Bounded by COUNT and by a page count.
	 */
	size_t from = 0, count = 0;
	for (unsigned page = 0; page < 16; page++) {
		char arg[32];
		const int arg_len = snprintf(arg, sizeof arg, "request %zu", from);
		const char *rest = NULL;
		size_t rest_len = 0, at = 0, rows = 0;
		int rc = fzn_rpc_node(c, "list", arg, (size_t)arg_len, &rest, &rest_len);
		if (rc != FZN_RPC_OK) return rc;
		if (!node_number(rest, rest_len, &at, &count)) return unreadable(c);
		while (at < rest_len) {
			size_t end = at;
			while (end < rest_len && rest[end] != ' ') end++;
			const char *e = rest + at;
			const size_t e_len = end - at;
			at = end < rest_len ? end + 1 : end;
			const char *c1 = memchr(e, ',', e_len);
			const char *c2 = c1 ? memchr(c1 + 1, ',', e_len - (size_t)(c1 + 1 - e)) : NULL;
			if (!c1 || !c2) return unreadable(c);
			rows++;
			if (out->count >= FZN_RPC_PEER_REQUEST_MAX) continue;
			fzn_rpc_pending_request_entry_t *r = &out->entries[out->count];
			const size_t name_len = (size_t)(c2 - c1 - 1);
			/* ROOT,NAME,RECEIVED and, since fuzznet sec 825, ,ADDRESS: where
			 * the asker's signed card says its host is, `-` for none. */
			const char *c3 = memchr(c2 + 1, ',', e_len - (size_t)(c2 + 1 - e));
			const size_t when_len = (size_t)((c3 ? c3 : e + e_len) - (c2 + 1));
			size_t when_at = 0, when = 0;
			if (!node_key(e, (size_t)(c1 - e), r->requester_host_pubkey) ||
			    name_len > FZN_RPC_PEER_NAME_MAX || !node_number(c2 + 1, when_len, &when_at, &when) ||
			    when_at != when_len)
				return unreadable(c);
			if (!(name_len == 1 && c1[1] == '-')) {
				memcpy(r->proposed_display_name, c1 + 1, name_len);
				r->proposed_display_name_len = name_len;
			}
			r->received_at = when;
			if (c3) {
				const size_t addr_len = (size_t)(e + e_len - (c3 + 1));
				if (addr_len > FZN_RPC_PEER_ADDRESS_MAX) return unreadable(c);
				if (!(addr_len == 1 && c3[1] == '-')) {
					memcpy(r->address, c3 + 1, addr_len);
					r->address_len = addr_len;
				}
			}
			out->count++;
		}
		from += rows;
		if (!rows || from >= count) break;
	}
	return out->count == count || out->count == FZN_RPC_PEER_REQUEST_MAX ? FZN_RPC_OK : unreadable(c);
}

/* `grant request ROOT NAME` and `remove request ROOT`. */
static int node_request_answer(fzn_rpc_t *c, const uint8_t key[32], const char *name,
                               size_t name_len) {
	char hex[65], arg[16 + 64 + 1 + FZN_RPC_PEER_NAME_MAX + 1];
	fzn_hex_encode(key, 32, hex);
	if (name && !node_name_ok(name, name_len))
		return node_unasked(c, FZN_RPC_ERR_INVALID_PEER_NAME, fzn_rpc_err_str(FZN_RPC_ERR_INVALID_PEER_NAME));
	const int arg_len = name ? snprintf(arg, sizeof arg, "request %s %.*s", hex, (int)name_len, name)
	                         : snprintf(arg, sizeof arg, "request %s", hex);
	const char *rest = NULL;
	size_t rest_len = 0;
	const int rc = fzn_rpc_node(c, name ? "grant" : "remove", arg, (size_t)arg_len, &rest,
	                             &rest_len);
	/* A request not there is `error no request ...`, fuzznet's form for
	 * every "no such" (its sec 646), and is narrowed to its own kind. */
	if (rc == FZN_RPC_ERR_STORAGE_IO && strncmp(c->error, "no request", 10) == 0)
		return c->error_code = FZN_RPC_ERR_NO_PEER_REQUEST;
	return rc;
}

/* `remove contact NAME`. */
static int node_peer_remove(fzn_rpc_t *c, const char *name, size_t name_len) {
	char arg[8 + NODE_WHO_MAX + 1];
	if (!name_len || !node_who_fits(name_len)) return encode_failed(c);
	const int arg_len = snprintf(arg, sizeof arg, "contact %.*s", (int)name_len, name);
	const char *rest = NULL;
	size_t rest_len = 0;
	return fzn_rpc_node(c, "remove", arg, (size_t)arg_len, &rest, &rest_len);
}

/* The group calls on fuzznetd (sec 284): its sec 626 verbs, a group named
 * by this host's name for it. Its id is `list group`'s third field and
 * `add group`'s answer (fuzznet sec 647); whether this host's user is an
 * admin is read by finding its root, from `get identity`, among `get
 * group`'s members (sec 648). */

/* `get identity`: `ok HOST ROOT`, the root a group lists this user under. */
static int node_identity_root(fzn_rpc_t *c, uint8_t root[32]) {
	const char *rest = NULL;
	size_t rest_len = 0;
	const int rc = fzn_rpc_node(c, "get", "identity", 8, &rest, &rest_len);
	if (rc != FZN_RPC_OK) return rc;
	return rest_len == 129 && rest[64] == ' ' && node_key(rest + 65, 64, root) ? FZN_RPC_OK
	                                                                            : unreadable(c);
}

/* A verb whose `ok` carries nothing this side reads. */
static int node_ack(fzn_rpc_t *c, const char *verb, const char *arg, int arg_len) {
	if (arg_len < 0) return encode_failed(c);
	const char *rest = NULL;
	size_t rest_len = 0;
	return fzn_rpc_node(c, verb, arg, (size_t)arg_len, &rest, &rest_len);
}

/* `list group [FROM]`: `ok TOTAL FROM NAME,COUNT,ID,ADMIN,LINES ...`, paged as
 * `list contact` is. */
static int node_group_rows(fzn_rpc_t *c, fzn_rpc_group_list_resp_t *out) {
	out->count = 0;
	size_t from = 0;
	for (;;) {
		char arg[32];
		const int arg_len = snprintf(arg, sizeof arg, "group %zu", from);
		const char *rest = NULL;
		size_t rest_len = 0;
		int rc = fzn_rpc_node(c, "list", arg, (size_t)arg_len, &rest, &rest_len);
		if (rc != FZN_RPC_OK) return rc;
		size_t at = 0, total = 0, start = 0, listed = 0;
		if (!node_number(rest, rest_len, &at, &total) || !node_number(rest, rest_len, &at, &start) ||
		    start != from)
			return unreadable(c);
		while (at < rest_len) {
			size_t end = at;
			while (end < rest_len && rest[end] != ' ') end++;
			const char *e = rest + at;
			const size_t e_len = end - at;
			at = end < rest_len ? end + 1 : end;
			listed++;
			const char *comma = memchr(e, ',', e_len);
			const char *id = comma ? memchr(comma + 1, ',', (size_t)(e + e_len - comma - 1)) : NULL;
			const char *admin = id ? memchr(id + 1, ',', (size_t)(e + e_len - id - 1)) : NULL;
			/* A row may go on past ADMIN: fuzznet appends. */
			if (!admin || e + e_len - admin < 2 || (admin[1] != '0' && admin[1] != '1') ||
			    (e + e_len - admin > 2 && admin[2] != ','))
				return unreadable(c);
			const size_t name_len = (size_t)(comma - e);
			size_t count_at = 0, count = 0;
			const char *count_text = comma + 1;
			const size_t count_len = (size_t)(id - comma - 1);
			uint8_t chat_id[32];
			if (!name_len || name_len > FZN_RPC_PEER_NAME_MAX ||
			    !node_number(count_text, count_len, &count_at, &count) || count_at < count_len ||
			    !node_key(id + 1, (size_t)(admin - id - 1), chat_id))
				return unreadable(c);
			rc = room_for(c, &out->entries, &out->room, out->count + 1, sizeof *out->entries);
			if (rc != FZN_RPC_OK) return rc;
			fzn_rpc_group_list_entry_t *g = &out->entries[out->count++];
			memset(g, 0, sizeof *g);
			memcpy(g->name, e, name_len);
			g->name_len = name_len;
			g->member_count = count;
			g->is_admin = admin[1] == '1';
			if (e + e_len - admin > 3 && !node_u64(admin + 3, (size_t)(e + e_len - admin - 3), &g->lines))
				return unreadable(c);
			memcpy(g->chat_id, chat_id, 32);
		}
		from += listed;
		if (!listed || from >= total) return FZN_RPC_OK;
	}
}

/* A contact's root by name, for the members a group names by name: the
 * contacts read once and sorted, and read again only for a name not there. */
static fzn_rpc_peer_list_resp_t member_peers;
static const fzn_rpc_peer_list_entry_t **member_sorted;
static size_t member_sorted_room, member_sorted_count;

static int peer_by_name_cmp(const void *a, const void *b) {
	return strcmp((*(const fzn_rpc_peer_list_entry_t *const *)a)->name,
	              (*(const fzn_rpc_peer_list_entry_t *const *)b)->name);
}

static int member_peers_read(fzn_rpc_t *c) {
	/* Nothing to search until this is whole: a listing cut short leaves its
	 * rows, which the sorted pointers do not describe, and may have moved them. */
	member_sorted_count = 0;
	const int rc = node_peer_list(c, &member_peers);
	if (rc != FZN_RPC_OK) return rc;
	const int grown = room_for(c, &member_sorted, &member_sorted_room, member_peers.count + 1,
	                           sizeof *member_sorted);
	if (grown != FZN_RPC_OK) return grown;
	for (size_t i = 0; i < member_peers.count; i++) member_sorted[i] = &member_peers.entries[i];
	qsort(member_sorted, member_peers.count, sizeof *member_sorted, peer_by_name_cmp);
	member_sorted_count = member_peers.count;
	return FZN_RPC_OK;
}

static const fzn_rpc_peer_list_entry_t *member_peer(const char *name) {
	fzn_rpc_peer_list_entry_t want;
	const fzn_rpc_peer_list_entry_t *key = &want;
	snprintf(want.name, sizeof want.name, "%s", name);
	if (!member_sorted_count) return NULL;
	const fzn_rpc_peer_list_entry_t **found = bsearch(&key, member_sorted, member_sorted_count,
	                                              sizeof *member_sorted, peer_by_name_cmp);
	return found ? *found : NULL;
}

/* `get group NAME member [FROM]`: `ok TOTAL FROM MEMBER ...`, a member by this
 * host's contact name or, with none, by its root's hex, and an admin marked `*`.
 * Paged, since a group outgrows a reply. A named member's root is read from the
 * contacts, so every member has one; this user is the row with no name. */
static int node_group_members(fzn_rpc_t *c, const char *group, size_t group_len,
                              const uint8_t self[32], fzn_rpc_group_show_resp_t *out) {
	{
		fzn_rpc_group_member_entry_t *members = out->members;
		const size_t room = out->member_room;
		memset(out, 0, sizeof(*out));
		out->members = members;
		out->member_room = room;
	}
	if (!group_len || group_len > FZN_RPC_PEER_NAME_MAX) return encode_failed(c);
	size_t from = 0;
	static char *reply;
	static size_t reply_room;
	/* The contacts are read again at most once a call: a name missing from a
	 * listing just read is not a contact's -- one whose contact carries a
	 * state the listing leaves out, say -- and reading again would not find
	 * it. Read per miss, as until 2026-11-09, a group of such members cost a
	 * whole contact listing each. */
	int reread = 0;
	for (;;) {
		char arg[24 + FZN_RPC_PEER_NAME_MAX + 24];
		const int arg_len =
		    snprintf(arg, sizeof arg, "group %.*s member %zu", (int)group_len, group, from);
		const char *rest = NULL;
		size_t rest_len = 0;
		int rc = fzn_rpc_node(c, "get", arg, (size_t)arg_len, &rest, &rest_len);
		if (rc != FZN_RPC_OK) return rc;
		/* The reply is in c->resp, which reading the contacts reuses: keep it. */
		rc = room_for(c, &reply, &reply_room, rest_len + 1, 1);
		if (rc != FZN_RPC_OK) return rc;
		memcpy(reply, rest, rest_len);
		size_t at = 0, total = 0, start = 0, listed = 0;
		if (!node_number(reply, rest_len, &at, &total) || !node_number(reply, rest_len, &at, &start) ||
		    start != from)
			return unreadable(c);
		while (at < rest_len) {
			size_t end = at;
			while (end < rest_len && reply[end] != ' ') end++;
			const char *e = reply + at;
			size_t e_len = end - at;
			at = end < rest_len ? end + 1 : end;
			listed++;
			const int admin = e_len && e[0] == '*';
			if (admin) e++, e_len--;
			rc = room_for(c, &out->members, &out->member_room, out->member_count + 1,
			              sizeof *out->members);
			if (rc != FZN_RPC_OK) return rc;
			fzn_rpc_group_member_entry_t *m = &out->members[out->member_count];
			memset(m, 0, sizeof *m);
			m->admin = admin;
			if (node_key(e, e_len, m->root_pubkey)) {
				if (admin && memcmp(m->root_pubkey, self, 32) == 0) out->is_admin = 1;
				out->member_count++;
				continue;
			}
			if (!e_len || e_len > FZN_RPC_PEER_NAME_MAX) return unreadable(c);
			memcpy(m->name, e, e_len);
			m->name_len = e_len;
			const fzn_rpc_peer_list_entry_t *p = member_peer(m->name);
			if (!p && !reread) {
				reread = 1;
				rc = member_peers_read(c);
				if (rc != FZN_RPC_OK) return rc;
				p = member_peer(m->name);
			}
			if (p) memcpy(m->root_pubkey, p->root_pubkey, 32);
			out->member_count++;
		}
		from += listed;
		if (!listed || from >= total) break;
	}
	memcpy(out->group_name, group, group_len);
	out->group_name_len = group_len;
	return FZN_RPC_OK;
}

/* The listing, its rows saying `is_admin` themselves. */
static int node_group_list(fzn_rpc_t *c, fzn_rpc_group_list_resp_t *out) {
	return node_group_rows(c, out);
}

/* A group shown: its members, then its id from the listing, by name. */
static int node_group_show(fzn_rpc_t *c, const char *group, size_t group_len,
                           fzn_rpc_group_show_resp_t *out) {
	uint8_t self[32];
	int rc = node_identity_root(c, self);
	if (rc == FZN_RPC_OK) rc = node_group_members(c, group, group_len, self, out);
	if (rc != FZN_RPC_OK) return rc;
	memcpy(out->self_root, self, 32);
	static fzn_rpc_group_list_resp_t rows;
	rc = node_group_rows(c, &rows);
	for (size_t i = 0; rc == FZN_RPC_OK && i < rows.count; i++)
		if (rows.entries[i].name_len == group_len &&
		    memcmp(rows.entries[i].name, group, group_len) == 0)
			memcpy(out->chat_id, rows.entries[i].chat_id, 32);
	return rc;
}

/* `add member GROUP CONTACT` and `remove member GROUP CONTACT`. */
static int node_group_member(fzn_rpc_t *c, const char *verb, const char *group, size_t group_len,
                             const char *peer, size_t peer_len) {
	if (!group_len || group_len > FZN_RPC_PEER_NAME_MAX || !peer_len || !node_who_fits(peer_len))
		return encode_failed(c);
	char arg[8 + FZN_RPC_PEER_NAME_MAX + NODE_WHO_MAX + 2];
	return node_ack(c, verb, arg,
	                snprintf(arg, sizeof arg, "member %.*s %.*s", (int)group_len, group,
	                         (int)peer_len, peer));
}

/* `remove group NAME`: left, its name and shares forgotten here. */
static int node_group_name(fzn_rpc_t *c, const char *verb, const char *group, size_t group_len) {
	if (!group_len || group_len > FZN_RPC_PEER_NAME_MAX) return encode_failed(c);
	char arg[8 + FZN_RPC_PEER_NAME_MAX + 1];
	return node_ack(c, verb, arg, snprintf(arg, sizeof arg, "group %.*s", (int)group_len, group));
}

/* The message calls on fuzznetd (sec 284): its sec 527 verbs, a line named
 * by a 16-byte id this side draws, as fuzznet's lines are. */

/* `add message WHO out ID TEXT | file PATH`: WHO a contact, or `@GROUP`.
 * The text goes %XX-escaped on the line when that fits, and otherwise as
 * its raw bytes in a staged file, as a card does. */
/* A new line's id, 32 hex: FZN_RPC_OK, or the refusal when there is no
 * randomness to draw it from. */
static int node_line_id(fzn_rpc_t *c, char hex[33]) {
	uint8_t id[16];
	if (fzn_rpc_entropy(id, sizeof id) != 0)
		return node_unasked(c, FZN_RPC_ERR_ENTROPY, "no randomness for the line's id");
	fzn_hex_encode(id, sizeof id, hex);
	return FZN_RPC_OK;
}

/*
 * A node's "malformed", said as what is missing where that is the reason:
 * `add message nobody ...` and `list message @nogroup` are answered with
 * the verb's usage line, so a send to a name nobody holds read as a protocol
 * fault ("add message WHO out|in ID ..."). Asked only once the node has
 * refused, so a send that works costs nothing more. `prefix` is "@" for a
 * group, "" for a contact.
 */
static int node_explain_who(fzn_rpc_t *c, int rc, const char *prefix, const char *who,
                            size_t who_len) {
	if (rc != FZN_RPC_ERR_MALFORMED || !who_len) return rc;
	const int group = prefix[0] == '@';
	int found = 0, asked = FZN_RPC_OK;
	if (group) {
		static fzn_rpc_group_list_resp_t all;
		asked = fzn_rpc_group_list(c, &all);
		for (size_t i = 0; asked == FZN_RPC_OK && i < all.count && !found; i++)
			found = all.entries[i].name_len == who_len && memcmp(all.entries[i].name, who, who_len) == 0;
	} else {
		static fzn_rpc_peer_list_resp_t all;
		asked = fzn_rpc_peer_list(c, &all);
		for (size_t i = 0; asked == FZN_RPC_OK && i < all.count && !found; i++)
			found = all.entries[i].name_len == who_len && memcmp(all.entries[i].name, who, who_len) == 0;
	}
	if (asked != FZN_RPC_OK || found) {
		/* The list failed or the name is there: the node's own answer stands,
		 * which the list call has overwritten -- so it is said generically. */
		return found ? fail(c, FZN_RPC_ERR_MALFORMED, "the node refused that request as malformed") : asked;
	}
	return fail(c, FZN_RPC_ERR_NO_PEER, group ? "no such group" : "no such contact");
}

static int node_message_add(fzn_rpc_t *c, const char *who_prefix, const char *who,
                            size_t who_len, const char *text, size_t text_len) {
	if (!who_len || !node_who_fits(who_len) || text_len > FZN_RPC_PEER_TEXT_MAX)
		return encode_failed(c);
	char hex[33];
	const int id_rc = node_line_id(c, hex);
	if (id_rc != FZN_RPC_OK) return id_rc;
	char arg[FZN_REQUEST_MAX];
	int at = snprintf(arg, sizeof arg, "message %s%.*s out %s ", who_prefix, (int)who_len, who, hex);
	size_t used = (size_t)at;
	/* The line is `add SP ARG LF`, at most FZN_REQUEST_MAX. One escaped
	 * word, by fuzznet's own escape (its sec 668): whole when it took every
	 * byte, and otherwise the text goes by a staged file. */
	const size_t room = FZN_REQUEST_MAX - 5u;
	size_t wrote = 0;
	const int inline_fits =
	    fzn_escape((const uint8_t *)text, text_len, arg + used, room - used, &wrote) == text_len;
	if (inline_fits) used += wrote;
	char path[NODE_STAGE_MAX] = "";
	if (!inline_fits) {
		const int fd = node_stage_file(c, "line", path);
		if (fd < 0) return node_unasked(c, FZN_RPC_ERR_STORAGE_IO, "could not stage the text for the node");
		const int staged = write(fd, text, text_len) == (ssize_t)text_len;
		close(fd);
		if (!staged) {
			unlink(path);
			return node_unasked(c, FZN_RPC_ERR_STORAGE_IO, "could not stage the text for the node");
		}
		used = (size_t)at + (size_t)snprintf(arg + at, sizeof arg - (size_t)at, "file %s", path);
	}
	const char *rest = NULL;
	size_t rest_len = 0;
	const int rc = fzn_rpc_node(c, "add", arg, used, &rest, &rest_len);
	if (path[0]) unlink(path);
	return node_explain_who(c, rc, who_prefix, who, who_len);
}

/* `add message WHO out ID attach ROOT NAME`: the name one escaped word. */
static int node_message_attach(fzn_rpc_t *c, const char *who_prefix, const char *who,
                               size_t who_len, const uint8_t root[32], const char *name,
                               size_t name_len) {
	if (!who_len || !node_who_fits(who_len) || !name_len || name_len > FZN_ATTACHMENT_NAME_MAX)
		return encode_failed(c);
	char hex[33], root_hex[65];
	const int id_rc = node_line_id(c, hex);
	if (id_rc != FZN_RPC_OK) return id_rc;
	fzn_hex_encode(root, 32, root_hex);
	char arg[FZN_REQUEST_MAX];
	const int at = snprintf(arg, sizeof arg, "message %s%.*s out %s attach %s ", who_prefix,
	                        (int)who_len, who, hex, root_hex);
	if (at < 0 || (size_t)at >= sizeof arg) return encode_failed(c);
	size_t wrote = 0;
	if (fzn_escape((const uint8_t *)name, name_len, arg + at, FZN_REQUEST_MAX - 5u - (size_t)at,
	               &wrote) != name_len)
		return encode_failed(c);
	const char *rest = NULL;
	size_t rest_len = 0;
	return node_explain_who(c, fzn_rpc_node(c, "add", arg, (size_t)at + wrote, &rest, &rest_len),
	                        who_prefix, who, who_len);
}

/* A field of a `list message` item, up to the next comma; 0 at the end. */
static int node_field(const char **p, const char *end, const char **f, size_t *f_len) {
	if (*p > end) return 0;
	const char *comma = memchr(*p, ',', (size_t)(end - *p));
	*f = *p;
	*f_len = (size_t)((comma ? comma : end) - *p);
	*p = comma ? comma + 1 : end + 1;
	return 1;
}

/* Up to twenty digits, all of a u64: a sticker's id derived from its art
 * is 64 bits (fuzznet sec 836), and nineteen refused about half of them,
 * so the pack holding one could not be listed. Past UINT64_MAX is refused. */
static int node_u64(const char *p, size_t len, uint64_t *out) {
	uint64_t v = 0;
	if (!len || len > 20) return 0;
	for (size_t i = 0; i < len; i++) {
		if (p[i] < '0' || p[i] > '9') return 0;
		const uint64_t d = (uint64_t)(p[i] - '0');
		if (v > (UINT64_MAX - d) / 10u) return 0;
		v = v * 10u + d;
	}
	*out = v;
	return 1;
}

/* One `list message` item, `KEY,NAME,ID,out|in,STATE,STIME,WRITTEN,READABLE,
 * TEXT`, into an inbox entry: the id is the line's name everywhere, as a
 * commitment is the clients'. 0 when it is not one; 2 for a group's line, named
 * `@GROUP` for this host's own and `@GROUP:SENDER` for a member's, whose
 * SENDER -- a contact name, or a root's first bytes in hex -- is put in
 * `sender_name` (empty for this host's own). */
static int node_line(const char *e, size_t e_len, fzn_rpc_inbox_entry_t *out, uint64_t *stime_ms,
                     const char **state, size_t *state_len) {
	const char *p = e, *end = e + e_len, *f;
	size_t f_len;
	uint64_t readable = 0;
	memset(out, 0, sizeof(*out));
	if (!node_field(&p, end, &f, &f_len) || !node_key(f, f_len, out->sender_host_pubkey)) return 0;
	if (!node_field(&p, end, &f, &f_len)) return 0;
	int kind = 1;
	if (f_len && f[0] == '@') {
		const char *colon = memchr(f, ':', f_len);
		kind = 2;
		f_len = colon ? (size_t)(f + f_len - colon - 1) : 0;
		f = colon ? colon + 1 : f;
	}
	if (f_len > FZN_RPC_PEER_NAME_MAX) return 0;
	if (!(f_len == 1 && f[0] == '-')) {
		memcpy(out->sender_name, f, f_len);
		out->sender_name_len = f_len;
	}
	if (!node_field(&p, end, &f, &f_len) || f_len != 32) return 0;
	for (size_t i = 0; i < 16; i++) {
		const int hi = hex_nibble(f[2 * i]), lo = hex_nibble(f[2 * i + 1]);
		if (hi < 0 || lo < 0) return 0;
		out->commitment[i] = (uint8_t)(hi << 4 | lo);
	}
	if (!node_field(&p, end, &f, &f_len)) return 0;
	if (f_len == 3 && memcmp(f, "out", 3) == 0)
		out->outgoing = 1;
	else if (!(f_len == 2 && memcmp(f, "in", 2) == 0))
		return 0;
	if (!node_field(&p, end, &f, &f_len)) return 0;
	/* The state, given back apart as well for a caller comparing words. */
	if (state) *state = f, *state_len = f_len;
	out->state = f_len == 9 && !memcmp(f, "delivered", 9)       ? FZN_RPC_LINE_DELIVERED
	             : f_len == 7 && !memcmp(f, "settled", 7)       ? FZN_RPC_LINE_SETTLED
	             : f_len == 11 && !memcmp(f, "handed-over", 11) ? FZN_RPC_LINE_HANDED_OVER
	             : f_len == 13 && !memcmp(f, "not-delivered", 13) ? FZN_RPC_LINE_NOT_DELIVERED
	                                                            : FZN_RPC_LINE_NONE;
	if (!node_field(&p, end, &f, &f_len) || !node_u64(f, f_len, &out->stime) ||
	    !node_field(&p, end, &f, &f_len) || !node_u64(f, f_len, &out->rtime) ||
	    !node_field(&p, end, &f, &f_len) || !node_u64(f, f_len, &readable))
		return 0;
	/* fuzznet's times are milliseconds and the clients' unix seconds. */
	if (stime_ms) *stime_ms = out->stime;
	out->stime /= 1000u;
	out->rtime /= 1000u;
	/* THE TEXT is the rest, commas escaped; one this node cannot open is
	 * left empty rather than shown as its escape. */
	f = p <= end ? p : end;
	f_len = (size_t)(end - f);
	if (readable && !fzn_unescape((const uint8_t *)f, f_len, (uint8_t *)out->text, FZN_RPC_PEER_TEXT_MAX,
	                              &out->text_len))
		return 0;
	return kind;
}

int fzn_rpc_message_read(fzn_rpc_t *c, const char *peer, size_t peer_len, const uint8_t id[16]) {
	if (!node_conversation_fits(peer, peer_len) || memchr(peer, ' ', peer_len)) return encode_failed(c);
	char hex[33];
	fzn_hex_encode(id, 16, hex);
	char arg[16 + NODE_WHO_MAX + 40];
	const int arg_len = snprintf(arg, sizeof arg, "message %.*s read %s", (int)peer_len, peer, hex);
	const char *rest = NULL;
	size_t rest_len = 0;
	const int rc = fzn_rpc_node(c, "set", arg, (size_t)arg_len, &rest, &rest_len);
	return rc == FZN_RPC_OK ? FZN_RPC_OK : node_explain_who(c, rc, "", peer, peer_len);
}

int fzn_rpc_message_unread(fzn_rpc_t *c, const char *peer, size_t peer_len, size_t *count,
                            int *more) {
	*count = 0;
	*more = 0;
	if (!node_conversation_fits(peer, peer_len) || memchr(peer, ' ', peer_len)) return encode_failed(c);
	char arg[16 + NODE_WHO_MAX + 16];
	const int arg_len = snprintf(arg, sizeof arg, "message %.*s unread", (int)peer_len, peer);
	const char *rest = NULL;
	size_t rest_len = 0, at = 0, n = 0, m = 0;
	const int rc = fzn_rpc_node(c, "get", arg, (size_t)arg_len, &rest, &rest_len);
	if (rc != FZN_RPC_OK) return node_explain_who(c, rc, "", peer, peer_len);
	if (!node_number(rest, rest_len, &at, &n) || !node_number(rest, rest_len, &at, &m) || m > 1)
		return unreadable(c);
	*count = n;
	*more = (int)m;
	return FZN_RPC_OK;
}

static int node_unescape(const char *in, size_t n, char *out, size_t cap, size_t *len, int *cut);
static int newest_all_text(fzn_rpc_t *c, fzn_rpc_newest_entry_t *out, size_t cap, size_t *count,
                           size_t *total) {
	*count = 0;
	*total = 0;
	size_t from = 0;
	/* A page that moves shows at least one conversation; this bounds the
	 * pages in case one does not. */
	for (unsigned page = 0; page <= 4096u; page++) {
		char arg[32];
		const int arg_len = from ? snprintf(arg, sizeof arg, "message newest %zu", from)
		                         : snprintf(arg, sizeof arg, "message newest");
		const char *rest = NULL;
		size_t rest_len = 0, at = 0, all = 0, start = 0, shown = 0;
		const int rc = fzn_rpc_node(c, "list", arg, (size_t)arg_len, &rest, &rest_len);
		if (rc != FZN_RPC_OK) return rc;
		if (!node_number(rest, rest_len, &at, &all) || !node_number(rest, rest_len, &at, &start) ||
		    !node_number(rest, rest_len, &at, &shown) || start != from)
			return unreadable(c);
		*total = all;
		const char *p = rest + at, *end = rest + rest_len, *w;
		size_t w_len, listed = 0;
		while (node_word(&p, end, &w, &w_len)) {
			const char *q = w, *stop = w + w_len, *f;
			size_t f_len;
			fzn_rpc_newest_entry_t e;
			memset(&e, 0, sizeof e);
			uint64_t stime = 0;
			/* KEY,STIME,DIRECTION,SENDER,KIND,TEXT */
			if (!node_field(&q, stop, &f, &f_len) || !node_key(f, f_len, e.key) ||
			    !node_field(&q, stop, &f, &f_len) || !node_u64(f, f_len, &stime) ||
			    !node_field(&q, stop, &f, &f_len))
				return unreadable(c);
			e.stime_ms = stime;
			e.outgoing = f_len == 3 && memcmp(f, "out", 3) == 0;
			if (!node_field(&q, stop, &f, &f_len) || f_len > FZN_RPC_PEER_NAME_MAX)
				return unreadable(c);
			if (!(f_len == 1 && f[0] == '-')) {
				memcpy(e.sender, f, f_len);
				e.sender_len = f_len;
			}
			if (!node_field(&q, stop, &f, &f_len)) return unreadable(c);
			e.kind = f_len == 4 && !memcmp(f, "text", 4)      ? FZN_RPC_NEWEST_TEXT
			         : f_len == 4 && !memcmp(f, "file", 4)    ? FZN_RPC_NEWEST_FILE
			         : f_len == 7 && !memcmp(f, "sticker", 7) ? FZN_RPC_NEWEST_STICKER
			         : f_len == 5 && !memcmp(f, "shell", 5)   ? FZN_RPC_NEWEST_SHELL
			                                                  : FZN_RPC_NEWEST_NONE;
			/* THE TEXT is the rest, escaped; empty for none. */
			const char *t = q <= stop ? q : stop;
			int cut = 0;
			if (!node_unescape(t, (size_t)(stop - t), e.text, FZN_RPC_NEWEST_TEXT_MAX, &e.text_len,
			                   &cut))
				return unreadable(c);
			e.text[e.text_len] = '\0';
			listed++;
			if (*count < cap) out[(*count)++] = e;
		}
		if (listed != shown) return unreadable(c);
		from += shown;
		if (!shown || from >= all || *count >= cap) return FZN_RPC_OK;
	}
	return unreadable(c);
}

static int unread_all_text(fzn_rpc_t *c, fzn_rpc_unread_entry_t *out, size_t cap, size_t *count,
                           size_t *total) {
	*count = 0;
	*total = 0;
	size_t from = 0;
	/* A page that moves shows at least one conversation; this bounds the
	 * pages in case one does not. */
	for (unsigned page = 0; page <= 4096u; page++) {
		char arg[32];
		const int arg_len = from ? snprintf(arg, sizeof arg, "message unread %zu", from)
		                         : snprintf(arg, sizeof arg, "message unread");
		const char *rest = NULL;
		size_t rest_len = 0, at = 0, all = 0, start = 0, shown = 0;
		const int rc = fzn_rpc_node(c, "list", arg, (size_t)arg_len, &rest, &rest_len);
		if (rc != FZN_RPC_OK) return rc;
		if (!node_number(rest, rest_len, &at, &all) || !node_number(rest, rest_len, &at, &start) ||
		    !node_number(rest, rest_len, &at, &shown) || start != from)
			return unreadable(c);
		*total = all;
		const char *p = rest + at, *end = rest + rest_len, *w;
		size_t w_len, listed = 0;
		while (node_word(&p, end, &w, &w_len)) {
			const char *q = w, *stop = w + w_len, *f;
			size_t f_len;
			fzn_rpc_unread_entry_t e;
			memset(&e, 0, sizeof e);
			uint64_t n = 0, more = 0;
			char hex[65];
			if (!node_field(&q, stop, &f, &f_len) || f_len != 64) return unreadable(c);
			memcpy(hex, f, 64);
			hex[64] = '\0';
			if (fzn_hex_decode(hex, e.key, sizeof e.key) != 0 || !node_field(&q, stop, &f, &f_len) ||
			    !node_u64(f, f_len, &n) || !node_field(&q, stop, &f, &f_len) ||
			    !node_u64(f, f_len, &more) || more > 1)
				return unreadable(c);
			e.count = (size_t)n;
			e.more = (int)more;
			listed++;
			if (*count < cap) out[(*count)++] = e;
		}
		if (listed != shown) return unreadable(c);
		from += shown;
		if (!shown || from >= all || *count >= cap) return FZN_RPC_OK;
	}
	return unreadable(c);
}

/* `list message [WHO] [FROM]`: `ok FROM SHOWN MORE ITEM ...`, newest first
 * as the clients' inbox is, paged from FROM + SHOWN while MORE and until `cap`
 * are held. */
static int node_inbox_lines(fzn_rpc_t *c, const char *peer, size_t peer_len,
                            fzn_rpc_inbox_entry_t *out, size_t cap, size_t *count) {
	*count = 0;
	if (peer_len && !node_who_fits(peer_len)) return encode_failed(c);
	size_t from = 0;
	int rc = FZN_RPC_OK;
	/* A page that moves shows at least one line, and `cap` bounds the lines
	 * kept: this bounds the pages, in case one does not move. (One
	 * conversation now pages at any depth -- fuzznet sec 790; everyone's
	 * listing still stops at FZN_MESSAGES_WALK_MAX.) */
	for (unsigned page = 0; page <= 4096u; page++) {
		char arg[16 + NODE_WHO_MAX + 1 + 8];
		const int arg_len = peer_len ? snprintf(arg, sizeof arg, "message %.*s %zu", (int)peer_len,
		                                        peer, from)
		                             : snprintf(arg, sizeof arg, "message %zu", from);
		const char *rest = NULL;
		size_t rest_len = 0;
		rc = fzn_rpc_node(c, "list", arg, (size_t)arg_len, &rest, &rest_len);
		if (rc != FZN_RPC_OK) break;
		size_t at = 0, start = 0, shown = 0, more = 0, listed = 0;
		if (!node_number(rest, rest_len, &at, &start) || !node_number(rest, rest_len, &at, &shown) ||
		    !node_number(rest, rest_len, &at, &more) || start != from || more > 1) {
			rc = unreadable(c);
			break;
		}
		while (at < rest_len) {
			size_t end = at;
			while (end < rest_len && rest[end] != ' ') end++;
			fzn_rpc_inbox_entry_t line;
			const int kind = node_line(rest + at, end - at, &line, NULL, NULL, NULL);
			at = end < rest_len ? end + 1 : end;
			listed++;
			if (!kind) {
				rc = unreadable(c);
				break;
			}
			if (kind == 2 || *count >= cap) continue;
			out[(*count)++] = line;
		}
		if (rc != FZN_RPC_OK || listed != shown) {
			if (rc == FZN_RPC_OK) rc = unreadable(c);
			break;
		}
		from += shown;
		if (!more || !shown || *count >= cap) break;
	}
	return rc;
}

/* `list message @GROUP [FROM]`, every page, for one sender's stream: this
 * host's own lines (`peer` empty) or the member's this host names `peer`.
 * fuzznet numbers a group's lines per sealing HOST, not per sender, so a
 * line's `seq` is its send time in milliseconds -- rising within a sender
 * and kept by a retention trim, where a place in the stream would be
 * renumbered -- and `high_water_seq` the latest. The clients only compare
 * them, against a read mark and to order (sec 284). The newest
 * FZN_RPC_GROUP_HISTORY_SHOW_PAGE_MAX are kept, newest first. */
static int node_group_history(fzn_rpc_t *c, const char *group, size_t group_len,
                              const char *peer, size_t peer_len,
                              fzn_rpc_group_history_show_resp_t *out) {
	memset(out, 0, sizeof(*out));
	if (!group_len || group_len > FZN_RPC_PEER_NAME_MAX || (peer_len && !node_who_fits(peer_len)))
		return encode_failed(c);
	size_t from = 0;
	int rc = FZN_RPC_OK;
	for (unsigned page = 0; page <= 4096u; page++) {
		char arg[16 + FZN_RPC_PEER_NAME_MAX + 1 + 8];
		const int arg_len =
		    snprintf(arg, sizeof arg, "message @%.*s %zu", (int)group_len, group, from);
		const char *rest = NULL;
		size_t rest_len = 0;
		rc = fzn_rpc_node(c, "list", arg, (size_t)arg_len, &rest, &rest_len);
		if (rc != FZN_RPC_OK) return node_explain_who(c, rc, "@", group, group_len);
		size_t at = 0, start = 0, shown = 0, more = 0, listed = 0;
		if (!node_number(rest, rest_len, &at, &start) || !node_number(rest, rest_len, &at, &shown) ||
		    !node_number(rest, rest_len, &at, &more) || start != from || more > 1)
			return unreadable(c);
		while (at < rest_len) {
			size_t end = at;
			while (end < rest_len && rest[end] != ' ') end++;
			fzn_rpc_inbox_entry_t line;
			uint64_t stime_ms = 0;
			const int kind = node_line(rest + at, end - at, &line, &stime_ms, NULL, NULL);
			at = end < rest_len ? end + 1 : end;
			listed++;
			if (kind != 2) return unreadable(c);
			const int mine = line.outgoing;
			if (peer_len ? mine || line.sender_name_len != peer_len ||
			                   memcmp(line.sender_name, peer, peer_len) != 0
			             : !mine)
				continue;
			if (stime_ms > out->high_water_seq) out->high_water_seq = stime_ms;
			if (out->count >= FZN_RPC_GROUP_HISTORY_SHOW_PAGE_MAX) continue;
			fzn_rpc_group_history_entry_t *h = &out->entries[out->count++];
			h->seq = stime_ms;
			h->stime = line.stime;
			memcpy(h->text, line.text, line.text_len);
			h->text_len = line.text_len;
		}
		if (listed != shown) return unreadable(c);
		from += shown;
		if (!more || !shown) break;
	}
	return FZN_RPC_OK;
}

int fzn_rpc_group_lines(fzn_rpc_t *c, const char *group, size_t group_len, fzn_rpc_group_line_t *out,
                         size_t cap, size_t *count) {
	*count = 0;
	if (!group_len || group_len > FZN_RPC_PEER_NAME_MAX) return encode_failed(c);
	size_t from = 0;
	while (*count < cap) {
		char arg[16 + FZN_RPC_PEER_NAME_MAX + 1 + 24];
		const int arg_len =
		    snprintf(arg, sizeof arg, "message @%.*s %zu", (int)group_len, group, from);
		const char *rest = NULL;
		size_t rest_len = 0;
		const int rc = fzn_rpc_node(c, "list", arg, (size_t)arg_len, &rest, &rest_len);
		if (rc != FZN_RPC_OK) return node_explain_who(c, rc, "@", group, group_len);
		size_t at = 0, start = 0, shown = 0, more = 0, listed = 0;
		if (!node_number(rest, rest_len, &at, &start) || !node_number(rest, rest_len, &at, &shown) ||
		    !node_number(rest, rest_len, &at, &more) || start != from || more > 1)
			return unreadable(c);
		while (at < rest_len) {
			size_t end = at;
			while (end < rest_len && rest[end] != ' ') end++;
			uint64_t stime_ms = 0;
			fzn_rpc_inbox_entry_t line;
			const int kind = node_line(rest + at, end - at, &line, &stime_ms, NULL, NULL);
			at = end < rest_len ? end + 1 : end;
			listed++;
			if (kind != 2) return unreadable(c);
			if (*count >= cap) continue;
			out[*count].line = line;
			out[(*count)++].seq = stime_ms;
		}
		if (listed != shown) return unreadable(c);
		from += shown;
		if (!more || !shown) break;
	}
	return FZN_RPC_OK;
}

/* The file calls on fuzznetd (sec 284): its sec 493-495 verbs. A file is
 * named by fuzznet's reference, the 72 bytes root, key and length (its
 * `fzn_node_file_ref_t`), as 144 hex; the clients' calls carry root and key, and
 * the length is read from the file's status where a call lacks it. */

/* A reference's 144 hex into root, key and length. */
static int node_ref(const char *p, size_t len, uint8_t root[32], uint8_t key[32],
                    uint64_t *length) {
	if (len != 144 || !node_key(p, 64, root) || !node_key(p + 64, 64, key)) return 0;
	uint64_t v = 0;
	for (size_t i = 128; i < 144; i++) {
		const int d = hex_nibble(p[i]);
		if (d < 0) return 0;
		v = v << 4 | (uint64_t)d;
	}
	*length = v;
	return 1;
}

/* `get file ROOT`: `HELD TOTAL LENGTH whole|partial|fetching
 * public|private SHARES [busy]`, HELD and TOTAL in leaves. A root this node
 * has never heard of is fuzznet's `error not all here`, which is the clients'
 * `known` 0 rather than a failure. */
static int node_file_status(fzn_rpc_t *c, const uint8_t root[32], fzn_rpc_blob_status_resp_t *out) {
	memset(out, 0, sizeof(*out));
	char hex[65], arg[8 + 64 + 1];
	fzn_hex_encode(root, 32, hex);
	const int arg_len = snprintf(arg, sizeof arg, "file %s", hex);
	const char *rest = NULL;
	size_t rest_len = 0;
	const int rc = fzn_rpc_node(c, "get", arg, (size_t)arg_len, &rest, &rest_len);
	if (rc == FZN_RPC_ERR_STORAGE_IO && strcmp(c->error, "not all here") == 0) {
		c->error[0] = '\0';
		c->error_code = 0;
		return FZN_RPC_OK;
	}
	if (rc != FZN_RPC_OK) return rc;
	size_t at = 0, held = 0, total = 0, length = 0;
	if (!node_number(rest, rest_len, &at, &held) || !node_number(rest, rest_len, &at, &total) ||
	    !node_number(rest, rest_len, &at, &length))
		return unreadable(c);
	const char *w = rest + at;
	const size_t w_len = rest_len - at;
	if (w_len >= 6 && memcmp(w, "whole ", 6) == 0) {
		out->complete = 1;
		w += 6;
	} else if (w_len >= 8 && memcmp(w, "partial ", 8) == 0) {
		w += 8;
	} else if (w_len >= 9 && memcmp(w, "fetching ", 9) == 0) {
		w += 9;
	} else {
		return unreadable(c);
	}
	if (strncmp(w, "public ", 7) == 0)
		out->tier = FZN_RPC_BLOB_TIER_PUBLIC;
	else if (strncmp(w, "private ", 8) == 0)
		out->tier = FZN_RPC_BLOB_TIER_PRIVATE;
	else
		return unreadable(c);
	out->known = 1;
	out->leaf_count = total;
	out->leaves_held = held;
	out->byte_len = length;
	return FZN_RPC_OK;
}

/* A path as the caller means it: a relative one is the caller's working
 * directory's, which fuzznetd cannot see -- it would read its own, and it
 * refuses a relative export outright (fuzznet sec 650). Into `out`, at most
 * `cap`; 0 when it does not fit. */
static int node_abs_path(const char *path, size_t path_len, char *out, size_t cap) {
	size_t at = 0;
	if (!path_len || memchr(path, '\n', path_len) || memchr(path, '\0', path_len)) return 0;
	if (path[0] != '/') {
		if (!getcwd(out, cap)) return 0;
		at = strlen(out);
		if (at + 1 >= cap) return 0;
		if (at == 0 || out[at - 1] != '/') out[at++] = '/';
	}
	if (at + path_len >= cap) return 0;
	memcpy(out + at, path, path_len);
	out[at + path_len] = '\0';
	return 1;
}

/* `put file PATH [public]`: `ok REF public|private`, the tier read back
 * from the store, which is held to the tier asked for. */
static int node_file_put(fzn_rpc_t *c, const char *path, size_t path_len, uint8_t tier,
                         fzn_rpc_blob_add_resp_t *out) {
	memset(out, 0, sizeof(*out));
	if (tier != FZN_RPC_BLOB_TIER_PUBLIC && tier != FZN_RPC_BLOB_TIER_PRIVATE) return encode_failed(c);
	/* fuzznet reads a path ending ` public` as the tier, so such a path
	 * cannot be put private unsaid. */
	char full[FZN_REQUEST_MAX];
	if (!node_abs_path(path, path_len, full, sizeof full) ||
	    (path_len >= 7 && memcmp(path + path_len - 7, " public", 7) == 0))
		return node_unasked(c, FZN_RPC_ERR_MALFORMED, "the node cannot take that path");
	char arg[FZN_REQUEST_MAX];
	const int arg_len = snprintf(arg, sizeof arg, "file %s%s", full,
	                             tier == FZN_RPC_BLOB_TIER_PUBLIC ? " public" : "");
	if (arg_len < 0 || (size_t)arg_len > FZN_REQUEST_MAX - 5u) return encode_failed(c);
	const char *rest = NULL;
	size_t rest_len = 0;
	const int rc = fzn_rpc_node(c, "put", arg, (size_t)arg_len, &rest, &rest_len);
	if (rc != FZN_RPC_OK) return rc;
	if (rest_len < 145 || rest[144] != ' ' ||
	    !node_ref(rest, 144, out->root, out->key, &out->byte_len))
		return unreadable(c);
	const int public_ = rest_len == 151 && memcmp(rest + 145, "public", 6) == 0;
	if (!public_ && !(rest_len == 152 && memcmp(rest + 145, "private", 7) == 0))
		return unreadable(c);
	if (public_ != (tier == FZN_RPC_BLOB_TIER_PUBLIC))
		return fail(c, FZN_RPC_ERR_STORAGE_IO, "the node stored it under the other tier");
	out->leaf_count = (out->byte_len + 1023u) / 1024u; /* FZN_BLOB_LEAF_SIZE */
	return FZN_RPC_OK;
}

/* `get file REF PATH`: written out. The reference is this node's own
 * (`get reference ROOT`) when no key is given, and otherwise the root and
 * key given with the length from the file's status. */
static int node_file_export(fzn_rpc_t *c, const uint8_t root[32], const uint8_t *key,
                            const char *path, size_t path_len, fzn_rpc_blob_export_resp_t *out) {
	memset(out, 0, sizeof(*out));
	char ref[145];
	uint64_t length = 0;
	const char *rest = NULL;
	size_t rest_len = 0;
	char hex[65];
	fzn_hex_encode(root, 32, hex);
	if (!key) {
		char arg[16 + 64 + 1];
		const int arg_len = snprintf(arg, sizeof arg, "reference %s", hex);
		int rc = fzn_rpc_node(c, "get", arg, (size_t)arg_len, &rest, &rest_len);
		if (rc != FZN_RPC_OK) return rc;
		uint8_t r[32], k[32];
		if (!node_ref(rest, rest_len, r, k, &length)) return unreadable(c);
		memcpy(ref, rest, 144);
	} else {
		static fzn_rpc_blob_status_resp_t st;
		int rc = node_file_status(c, root, &st);
		if (rc != FZN_RPC_OK) return rc;
		if (!st.known) return fail(c, FZN_RPC_ERR_STORAGE_IO, "not all here");
		length = st.byte_len;
		char key_hex[65];
		fzn_hex_encode(key, 32, key_hex);
		snprintf(ref, sizeof ref, "%s%s%016llx", hex, key_hex, (unsigned long long)length);
	}
	char arg[FZN_REQUEST_MAX], full[FZN_REQUEST_MAX];
	if (!node_abs_path(path, path_len, full, sizeof full)) return encode_failed(c);
	const int arg_len = snprintf(arg, sizeof arg, "file %.144s %s", ref, full);
	if (arg_len < 0 || (size_t)arg_len > FZN_REQUEST_MAX - 5u) return encode_failed(c);
	const int rc = fzn_rpc_node(c, "get", arg, (size_t)arg_len, &rest, &rest_len);
	if (rc != FZN_RPC_OK) return rc;
	out->byte_len = length;
	return FZN_RPC_OK;
}

/* `get file ROOT check`: `intact` or `dropped N`, the whole file checked
 * at rest in one answer -- so `done`, from any `from`. */
static int node_file_check(fzn_rpc_t *c, const uint8_t root[32], fzn_rpc_blob_scrub_resp_t *out) {
	memset(out, 0, sizeof(*out));
	static fzn_rpc_blob_status_resp_t st;
	int rc = node_file_status(c, root, &st);
	if (rc != FZN_RPC_OK) return rc;
	if (!st.known) return fail(c, FZN_RPC_ERR_STORAGE_IO, "not all here");
	char hex[65], arg[8 + 64 + 7];
	fzn_hex_encode(root, 32, hex);
	const int arg_len = snprintf(arg, sizeof arg, "file %s check", hex);
	const char *rest = NULL;
	size_t rest_len = 0;
	rc = fzn_rpc_node(c, "get", arg, (size_t)arg_len, &rest, &rest_len);
	if (rc != FZN_RPC_OK) return rc;
	size_t at = 8, dropped = 0;
	if (rest_len == 6 && memcmp(rest, "intact", 6) == 0)
		dropped = 0;
	else if (!(rest_len > 8 && memcmp(rest, "dropped ", 8) == 0 &&
	           node_number(rest, rest_len, &at, &dropped) && at == rest_len))
		return unreadable(c);
	out->leaf_count = st.leaf_count;
	out->checked = st.leaves_held;
	out->dropped = dropped;
	out->next_index = st.leaf_count;
	out->done = 1;
	return FZN_RPC_OK;
}

/* The note calls on fuzznetd (sec 284): its sec 431-442 verbs over this
 * node's own tree. A note is named by its 32-byte id in hex, and the top
 * level -- the clients' all-zero parent -- is `top`. Shared trees go with the
 * share calls. */

static int node_is_zero(const uint8_t *b, size_t n) {
	for (size_t i = 0; i < n; i++)
		if (b[i]) return 0;
	return 1;
}


/* `%XX` undone into `out`, at most `cap` bytes kept, by fuzznet's own
 * unescape (its sec 668). 0 for a bad escape. What this adds is the cut a
 * display needs: a text longer than `cap` is kept to `cap`, at a UTF-8
 * boundary, `*cut` set -- fuzznet's refuses an output past its bound. */
static int node_unescape(const char *in, size_t n, char *out, size_t cap, size_t *len, int *cut) {
	*cut = 0;
	*len = 0;
	/* An unescaped text is never longer than its escape. */
	uint8_t stack[1100];
	uint8_t *whole = n <= sizeof stack ? stack : malloc(n ? n : 1);
	if (!whole) return 0;
	size_t w = 0;
	const int ok = fzn_unescape((const uint8_t *)in, n, whole, n ? n : 1, &w);
	if (ok) {
		if (w > cap) {
			*cut = 1;
			w = cap;
			/* Not inside a character: back off continuation bytes, then
			 * the lead. */
			while (w && (whole[w - 1] & 0xc0u) == 0x80u) w--;
			if (w && (whole[w - 1] & 0x80u)) w--;
		}
		memcpy(out, whole, w);
		*len = w;
	}
	if (whole != stack) free(whole);
	return ok;
}

/* PARENT as fuzznet names it. */
static void node_parent(const uint8_t parent[32], char out[65]) {
	if (node_is_zero(parent, 32))
		snprintf(out, 65, "top");
	else
		fzn_hex_encode(parent, 32, out);
}

/* `list note PARENT [FROM]`, or `list shared KEY PARENT [FROM]` in a tree
 * shared with this node (`tree` the words before PARENT): `ok TOTAL FROM
 * ID,TYPE,FLAGS,REACHABLE,CONTESTED,TITLE,LABELS ...`, paged. FLAGS' 0x80
 * is fuzznet's "content not here yet", which the clients' flags have no bit
 * for, so it is dropped. */
static int node_notes_list(fzn_rpc_t *c, const char *tree, const uint8_t parent[32],
                           fzn_rpc_notes_list_resp_t *out) {
	out->count = 0;
	out->truncated = 0;
	char p[65];
	node_parent(parent, p);
	size_t from = 0;
	for (;;) {
		char arg[160];
		const int arg_len = snprintf(arg, sizeof arg, "%s %s %zu", tree, p, from);
		const char *rest = NULL;
		size_t rest_len = 0;
		int rc = fzn_rpc_node(c, "list", arg, (size_t)arg_len, &rest, &rest_len);
		if (rc != FZN_RPC_OK) return rc;
		size_t at = 0, total = 0, start = 0, listed = 0;
		if (!node_number(rest, rest_len, &at, &total) || !node_number(rest, rest_len, &at, &start) ||
		    start != from)
			return unreadable(c);
		while (at < rest_len) {
			size_t end = at;
			while (end < rest_len && rest[end] != ' ') end++;
			const char *e = rest + at, *q = e, *stop = rest + end, *f;
			size_t f_len;
			at = end < rest_len ? end + 1 : end;
			listed++;
			uint64_t type = 0, flags = 0, reachable = 0, contested = 0;
			uint8_t id[32];
			if (!node_field(&q, stop, &f, &f_len) || !node_key(f, f_len, id) ||
			    !node_field(&q, stop, &f, &f_len) || !node_u64(f, f_len, &type) ||
			    !node_field(&q, stop, &f, &f_len) || !node_u64(f, f_len, &flags) ||
			    !node_field(&q, stop, &f, &f_len) || !node_u64(f, f_len, &reachable) ||
			    !node_field(&q, stop, &f, &f_len) || !node_u64(f, f_len, &contested) ||
			    !node_field(&q, stop, &f, &f_len))
				return unreadable(c);
			rc = room_for(c, &out->entries, &out->room, out->count + 1, sizeof *out->entries);
			if (rc != FZN_RPC_OK) return rc;
			fzn_rpc_notes_list_entry_t *n = &out->entries[out->count];
			memset(n, 0, sizeof *n);
			int cut = 0;
			if (!node_unescape(f, f_len, n->title, FZN_RPC_NOTES_TITLE_MAX, &n->title_len, &cut))
				return unreadable(c);
			/* LABELS, NUL-separated and escaped (fuzznet sec 869); kept
			 * for a listing, the cut said rather than a label halved. */
			if (node_field(&q, stop, &f, &f_len) &&
			    !node_unescape(f, f_len, n->labels, sizeof n->labels, &n->labels_len, &n->labels_cut))
				return unreadable(c);
			memcpy(n->id, id, 32);
			memcpy(n->parent, parent, 32);
			n->order = out->count;
			n->content_type = (uint16_t)type;
			n->flags = (uint8_t)(flags & 0x7fu);
			n->reachable = reachable != 0;
			n->contested = contested != 0;
			out->count++;
		}
		from += listed;
		if (!listed || from >= total) return FZN_RPC_OK;
	}
}

/* A CHECKLIST on fuzznetd (sec 284): the clients read its items in the
 * note's text, each `FLAGS(1) LEN(2, big-endian) UTF-8`, FLAGS 0x01 checked;
 * fuzznet keeps them as items and changes them through its item verbs
 * (sec 442) -- `get note ID items`, `add item`, `set note ID item N
 * check|uncheck|text`, `remove item` -- and refuses a list's text. So a
 * list is shown by encoding its items, and written as the item changes
 * that make the text asked for. An item's text goes to the end of the
 * request line, so one holding a newline is refused. */
#define NODE_ITEMS_MAX 128

#define NODE_ITEM_TEXT_MAX 1024

typedef struct node_item {
	char text[NODE_ITEM_TEXT_MAX + 1];
	size_t len;
	uint8_t checked;
} node_item_t;

/* the clients' item text into items; 0 when it is not one. */
static int node_items_decode(const char *text, size_t text_len, node_item_t *items, size_t *n) {
	*n = 0;
	for (size_t at = 0; at < text_len;) {
		if (text_len - at < 3 || *n >= NODE_ITEMS_MAX) return 0;
		const size_t len = (size_t)((uint8_t)text[at + 1] << 8 | (uint8_t)text[at + 2]);
		if (len > text_len - at - 3 || len > NODE_ITEM_TEXT_MAX ||
		    memchr(text + at + 3, '\n', len) || memchr(text + at + 3, '\r', len))
			return 0;
		items[*n].checked = (uint8_t)(text[at] & 0x01);
		memcpy(items[*n].text, text + at + 3, len);
		items[*n].len = len;
		(*n)++;
		at += 3 + len;
	}
	return 1;
}

/* `get note ID items [FROM]` (or in a sharer's tree, `tree` the words
 * before ID): `ok TOTAL FROM FLAGS,TEXT ...`, paged, into `items`. */
static int node_items_read(fzn_rpc_t *c, const char *tree, const char *hex, node_item_t *items,
                           size_t *n) {
	*n = 0;
	size_t from = 0;
	for (unsigned page = 0; page <= NODE_ITEMS_MAX; page++) {
		char arg[192];
		const int arg_len = snprintf(arg, sizeof arg, "%s %s items %zu", tree, hex, from);
		const char *rest = NULL;
		size_t rest_len = 0;
		const int rc = fzn_rpc_node(c, "get", arg, (size_t)arg_len, &rest, &rest_len);
		if (rc != FZN_RPC_OK) return rc;
		size_t at = 0, total = 0, start = 0, listed = 0;
		if (!node_number(rest, rest_len, &at, &total) || !node_number(rest, rest_len, &at, &start) ||
		    start != from)
			return unreadable(c);
		while (at < rest_len) {
			size_t end = at;
			while (end < rest_len && rest[end] != ' ') end++;
			const char *q = rest + at, *stop = rest + end, *f;
			size_t f_len;
			at = end < rest_len ? end + 1 : end;
			listed++;
			uint64_t flags = 0;
			if (!node_field(&q, stop, &f, &f_len) || !node_u64(f, f_len, &flags)) return unreadable(c);
			if (*n >= NODE_ITEMS_MAX) continue;
			int cut = 0;
			const char *t = q <= stop ? q : stop;
			if (!node_unescape(t, (size_t)(stop - t), items[*n].text, NODE_ITEM_TEXT_MAX,
			                   &items[*n].len, &cut))
				return unreadable(c);
			items[*n].checked = (uint8_t)(flags & 0x01);
			(*n)++;
		}
		from += listed;
		if (!listed || from >= total) break;
	}
	return FZN_RPC_OK;
}

/* Items as the clients' text, as many whole items as FZN_RPC_NOTES_TEXT_MAX holds. */
static void node_items_encode(const node_item_t *items, size_t n, char *text, size_t *text_len) {
	*text_len = 0;
	for (size_t i = 0; i < n && *text_len + 3 + items[i].len <= FZN_RPC_NOTES_TEXT_MAX; i++) {
		text[(*text_len)++] = (char)items[i].checked;
		text[(*text_len)++] = (char)(items[i].len >> 8);
		text[(*text_len)++] = (char)(items[i].len & 0xff);
		memcpy(text + *text_len, items[i].text, items[i].len);
		*text_len += items[i].len;
	}
}

/* The list `hex` made into `want`, by the fewest item verbs: each item
 * reworded or (un)checked where it differs, then the rest added at the end,
 * or the surplus removed from the end. */
static int node_items_write(fzn_rpc_t *c, const char *hex, const node_item_t *want, size_t n_want) {
	static node_item_t have[NODE_ITEMS_MAX];
	size_t n_have = 0;
	int rc = node_items_read(c, "note", hex, have, &n_have);
	char arg[FZN_REQUEST_MAX];
	for (size_t i = 0; rc == FZN_RPC_OK && i < n_want; i++) {
		if (!want[i].len) return node_unasked(c, FZN_RPC_ERR_MALFORMED, "a checklist item cannot be empty");
		if (i >= n_have) {
			rc = node_ack(c, "add", arg,
			              snprintf(arg, sizeof arg, "item %s %.*s", hex, (int)want[i].len,
			                       want[i].text));
		} else if (have[i].len != want[i].len || memcmp(have[i].text, want[i].text, want[i].len)) {
			rc = node_ack(c, "set", arg,
			              snprintf(arg, sizeof arg, "note %s item %zu text %.*s", hex, i,
			                       (int)want[i].len, want[i].text));
		}
		const uint8_t was = i < n_have ? have[i].checked : 0;
		if (rc == FZN_RPC_OK && was != want[i].checked)
			rc = node_ack(c, "set", arg,
			              snprintf(arg, sizeof arg, "note %s item %zu %s", hex, i,
			                       want[i].checked ? "check" : "uncheck"));
	}
	for (size_t i = n_have; rc == FZN_RPC_OK && i > n_want; i--)
		rc = node_ack(c, "remove", arg, snprintf(arg, sizeof arg, "item %s %zu", hex, i - 1));
	return rc;
}

/* `get note ID`, or `get shared KEY ID` (`tree` the words before ID):
 * `TYPE FLAGS CREATED EDITED PARENT blob|pending LEN REACHABLE CONTESTED
 * TITLE`,
 * then `get note ID text FROM`, `TOTAL FROM TEXT`, a page at a time. */
static int node_notes_show(fzn_rpc_t *c, const char *tree, const uint8_t id[32],
                           fzn_rpc_notes_show_resp_t *out) {
	memset(out, 0, sizeof(*out));
	char hex[65], arg[160];
	fzn_hex_encode(id, 32, hex);
	int arg_len = snprintf(arg, sizeof arg, "%s %s", tree, hex);
	const char *rest = NULL;
	size_t rest_len = 0;
	int rc = fzn_rpc_node(c, "get", arg, (size_t)arg_len, &rest, &rest_len);
	if (rc != FZN_RPC_OK) return rc;
	size_t at = 0, type = 0, flags = 0, len = 0, created = 0, edited = 0;
	if (!node_number(rest, rest_len, &at, &type) || !node_number(rest, rest_len, &at, &flags) ||
	    !node_number(rest, rest_len, &at, &created) || !node_number(rest, rest_len, &at, &edited) ||
	    at + 65 > rest_len || !node_key(rest + at, 64, out->parent) || rest[at + 64] != ' ')
		return unreadable(c);
	at += 65;
	int pending = 0;
	if (at + 5 <= rest_len && memcmp(rest + at, "blob ", 5) == 0)
		at += 5;
	else if (at + 8 <= rest_len && memcmp(rest + at, "pending ", 8) == 0)
		at += 8, pending = 1;
	else
		return unreadable(c);
	/* LEN REACHABLE CONTESTED TITLE since fuzznet 4d7f4c3 (its sec 828): the
	 * two flags before the title, which may be empty. */
	size_t reachable = 0, contested = 0;
	if (!node_number(rest, rest_len, &at, &len) || !node_number(rest, rest_len, &at, &reachable) ||
	    !node_number(rest, rest_len, &at, &contested) || reachable > 1 || contested > 1)
		return unreadable(c);
	int cut = 0;
	if (!node_unescape(rest + at, rest_len - at, out->title, FZN_RPC_NOTES_TITLE_MAX, &out->title_len,
	                   &cut))
		return unreadable(c);
	memcpy(out->id, id, 32);
	out->content_type = (uint16_t)type;
	out->flags = (uint8_t)(flags & 0x7fu);
	out->created_at_ms = created;
	out->edited_at_ms = edited;
	/* WHETHER THE ROOT REACHES IT, from the reply (fuzznet sec 828). Before
	 * the reply carried it this said "reachable" of every note, then read
	 * it from the parent's listing, a request more. */
	out->reachable = reachable != 0;
	out->contested = contested != 0;
	if (pending) return FZN_RPC_OK; /* the text is not here yet: a title alone */
	if (type == 0x0002) { /* a checklist: its items, as the clients' text */
		static node_item_t items[NODE_ITEMS_MAX];
		size_t n = 0;
		rc = node_items_read(c, tree, hex, items, &n);
		if (rc == FZN_RPC_OK) node_items_encode(items, n, out->text, &out->text_len);
		return rc;
	}
	if (!len) return FZN_RPC_OK;
	for (;;) {
		arg_len = snprintf(arg, sizeof arg, "%s %s text %zu", tree, hex, out->text_len);
		rc = fzn_rpc_node(c, "get", arg, (size_t)arg_len, &rest, &rest_len);
		if (rc != FZN_RPC_OK) return rc;
		size_t a2 = 0, total = 0, start = 0, got = 0;
		if (!node_number(rest, rest_len, &a2, &total) || !node_number(rest, rest_len, &a2, &start) ||
		    start != out->text_len || total != len)
			return unreadable(c);
		if (!node_unescape(rest + a2, rest_len - a2, out->text + out->text_len,
		                   FZN_RPC_NOTES_TEXT_MAX - out->text_len, &got, &cut))
			return unreadable(c);
		out->text_len += got;
		if (!got || out->text_len >= total || out->text_len >= FZN_RPC_NOTES_TEXT_MAX) return FZN_RPC_OK;
	}
}

/* A text into a file of this process's own, for `set note ID file PATH`:
 * a note's text holds newlines, which the request line cannot. */
static int node_note_text(fzn_rpc_t *c, const char *hex, const char *text, size_t text_len) {
	char path[NODE_STAGE_MAX];
	const int fd = node_stage_file(c, "note", path);
	if (fd < 0) return fail(c, FZN_RPC_ERR_STORAGE_IO, "could not stage the text for the node");
	const int wrote = write(fd, text, text_len) == (ssize_t)text_len;
	close(fd);
	if (!wrote) {
		unlink(path);
		return fail(c, FZN_RPC_ERR_STORAGE_IO, "could not stage the text for the node");
	}
	char arg[NODE_STAGE_MAX + 96];
	const int rc = node_ack(c, "set", arg, snprintf(arg, sizeof arg, "note %s file %s", hex, path));
	unlink(path);
	return rc;
}

/* A title on the request line: to its end, so no newline. */
static int node_title_ok(const char *title, size_t len) {
	return len && len <= FZN_RPC_NOTES_TITLE_MAX && !memchr(title, '\n', len) &&
	       !memchr(title, '\r', len) && !memchr(title, '\0', len);
}

/* What a refused title, text or checklist lacks, said rather than left to
 * encode_failed's guess at a name too long. */
static int node_title_refused(fzn_rpc_t *c) {
	return node_unasked(c, FZN_RPC_ERR_MALFORMED, "a note's title is one line, not empty and not too long");
}
static int node_items_refused(fzn_rpc_t *c) {
	return node_unasked(c, FZN_RPC_ERR_MALFORMED, "that is not a checklist's items");
}

/* `add note PARENT TITLE` or `add folder PARENT TITLE`, answered with its
 * id, then a note's text. The types are the clients' and fuzznet's alike:
 * 0x0001 a note, 0x0003 a folder. */
static int node_notes_add(fzn_rpc_t *c, const uint8_t parent[32], const char *title,
                          size_t title_len, const char *text, size_t text_len, int skip_if_exists,
                          uint16_t content_type, fzn_rpc_notes_add_resp_t *out) {
	memset(out, 0, sizeof(*out));
	/* An import's "unless it is there already" is fuzznet's `add import`,
	 * which takes the whole export (fzn_rpc_notes_import), not a note at a
	 * time. */
	const int folder = content_type == 0x0003, list = content_type == 0x0002;
	if (skip_if_exists)
		return node_unasked(c, FZN_RPC_ERR_UNKNOWN_MSG_TYPE,
		                    "a node imports an export whole (notes_import), not a note at a time");
	if (content_type != 0x0001 && !folder && !list)
		return node_unasked(c, FZN_RPC_ERR_UNKNOWN_MSG_TYPE, "a node has no such kind of note");
	if (!node_title_ok(title, title_len)) return node_title_refused(c);
	if (text_len > FZN_RPC_NOTES_TEXT_MAX)
		return node_unasked(c, FZN_RPC_ERR_MALFORMED, "that note's text is too long");
	if (folder && text_len) return node_unasked(c, FZN_RPC_ERR_MALFORMED, "a folder has no text");
	static node_item_t items[NODE_ITEMS_MAX];
	size_t n_items = 0;
	if (list && !node_items_decode(text, text_len, items, &n_items)) return node_items_refused(c);
	char p[65], arg[16 + 64 + 1 + FZN_RPC_NOTES_TITLE_MAX + 1];
	node_parent(parent, p);
	const int arg_len = snprintf(arg, sizeof arg, "%s %s %.*s",
	                             folder ? "folder" : list ? "list" : "note", p, (int)title_len, title);
	const char *rest = NULL;
	size_t rest_len = 0;
	int rc = fzn_rpc_node(c, "add", arg, (size_t)arg_len, &rest, &rest_len);
	if (rc != FZN_RPC_OK) return rc;
	if (!node_key(rest, rest_len, out->id)) return unreadable(c);
	if (!text_len) return FZN_RPC_OK;
	char hex[65];
	fzn_hex_encode(out->id, 32, hex);
	return list ? node_items_write(c, hex, items, n_items) : node_note_text(c, hex, text, text_len);
}

/* `set note ID title TEXT`, `set note ID file PATH`, `set note ID trash`
 * and `untrash`, in that order, each its own request. */
static int node_notes_edit(fzn_rpc_t *c, const uint8_t id[32], uint8_t fields, const char *title,
                           size_t title_len, const char *text, size_t text_len) {
	if (!fields || (fields & ~FZN_RPC_NOTES_EDIT_FIELDS_KNOWN) ||
	    ((fields & FZN_RPC_NOTES_EDIT_TRASH) && (fields & FZN_RPC_NOTES_EDIT_UNTRASH)))
		return encode_failed(c);
	char hex[65], arg[16 + 64 + 8 + FZN_RPC_NOTES_TITLE_MAX + 1];
	fzn_hex_encode(id, 32, hex);
	int rc = FZN_RPC_OK;
	if (fields & FZN_RPC_NOTES_EDIT_TITLE) {
		if (!node_title_ok(title, title_len)) return node_title_refused(c);
		rc = node_ack(c, "set", arg,
		              snprintf(arg, sizeof arg, "note %s title %.*s", hex, (int)title_len, title));
	}
	if (rc == FZN_RPC_OK && (fields & FZN_RPC_NOTES_EDIT_TEXT)) {
		if (text_len > FZN_RPC_NOTES_TEXT_MAX)
			return node_unasked(c, FZN_RPC_ERR_MALFORMED, "that note's text is too long");
		/* A checklist's text is its items: which this is, asked first. */
		const char *rest = NULL;
		size_t rest_len = 0, at = 0, type = 0;
		rc = fzn_rpc_node(c, "get", arg, (size_t)snprintf(arg, sizeof arg, "note %s", hex), &rest,
		                   &rest_len);
		if (rc == FZN_RPC_OK && !node_number(rest, rest_len, &at, &type)) rc = unreadable(c);
		if (rc == FZN_RPC_OK && type == 0x0002) {
			static node_item_t items[NODE_ITEMS_MAX];
			size_t n = 0;
			rc = node_items_decode(text, text_len, items, &n) ? node_items_write(c, hex, items, n)
			                                                  : node_items_refused(c);
		} else if (rc == FZN_RPC_OK) {
			rc = node_note_text(c, hex, text, text_len);
		}
	}
	if (rc == FZN_RPC_OK && (fields & (FZN_RPC_NOTES_EDIT_TRASH | FZN_RPC_NOTES_EDIT_UNTRASH)))
		rc = node_ack(c, "set", arg,
		              snprintf(arg, sizeof arg, "note %s %s", hex,
		                       (fields & FZN_RPC_NOTES_EDIT_TRASH) ? "trash" : "untrash"));
	return rc;
}

/* `remove note trash`: `ok QUEUED PENDING`. */
static int node_notes_empty_trash(fzn_rpc_t *c, fzn_rpc_notes_empty_trash_resp_t *out) {
	memset(out, 0, sizeof(*out));
	const char *rest = NULL;
	size_t rest_len = 0, at = 0;
	const int rc = fzn_rpc_node(c, "remove", "note trash", 10, &rest, &rest_len);
	if (rc != FZN_RPC_OK) return rc;
	return node_number(rest, rest_len, &at, &out->queued) &&
	               node_number(rest, rest_len, &at, &out->pending) && at == rest_len
	           ? FZN_RPC_OK
	           : unreadable(c);
}

/* A tree shared with this node, `shared KEY`: the sharer by its key, which
 * is what the clients' `from` is and what `list sharer` prints. */
static void node_shared_tree(const uint8_t key[32], char out[80]) {
	char hex[65];
	fzn_hex_encode(key, 32, hex);
	snprintf(out, 80, "shared %s", hex);
}

/* `add share SUBTREE NAME`, `add share SUBTREE @GROUP backfill 0|1`, and
 * `remove share ...`.
 *
 * A GROUP SHARE'S CATCH-UP IS ALWAYS SAID. Whether it catches up a later
 * member is the sharer's per share, default no (sec 22); fuzznet takes the
 * flag per share and, given none, follows the group's own setting (its sec
 * 655), which is somebody else's choice. So the flag is sent every time and
 * the group's default never decides for this sharer. */
static int node_notes_share(fzn_rpc_t *c, int add, const uint8_t subtree[32], const char *peer,
                            size_t peer_len, int to_group, int backfill) {
	if (!peer_len || peer_len > 64 || memchr(peer, ' ', peer_len) || memchr(peer, '\n', peer_len))
		return encode_failed(c);
	char hex[65], arg[16 + 64 + 2 + 64 + 16];
	fzn_hex_encode(subtree, 32, hex);
	return node_ack(c, add ? "add" : "remove", arg,
	                snprintf(arg, sizeof arg, "share %s %s%.*s%s", hex, to_group ? "@" : "",
	                         (int)peer_len, peer,
	                         add && to_group ? (backfill ? " backfill 1" : " backfill 0") : ""));
}

/* What is shared both ways. Outgoing: `list share [FROM]`, `ok TOTAL FROM
 * SUBTREE,NAME ...`, a group's row `SUBTREE,@NAME,1|0` with whether it
 * catches up a later member as it stands (fuzznet sec 655), and a row
 * whose contact is gone its key in hex.
 * Incoming: `list sharer [FROM]`, `KEY,KIND,NAME`, and for each sharer the
 * roots of its tree, `list shared KEY top`, one row a root, its key the
 * issuer. A group's member is listed by `list sharer` and read through the
 * group's notebook, which is not on fuzznetd yet (sec 284), so its rows are
 * left out. */
static int node_notes_shares(fzn_rpc_t *c, fzn_rpc_notes_shares_resp_t *out) {
	memset(out, 0, sizeof(*out));
	size_t from = 0;
	for (unsigned page = 0; page <= FZN_RPC_NOTES_SHARES_LIST_MAX; page++) {
		char arg[32];
		const int arg_len = snprintf(arg, sizeof arg, "share %zu", from);
		const char *rest = NULL;
		size_t rest_len = 0;
		int rc = fzn_rpc_node(c, "list", arg, (size_t)arg_len, &rest, &rest_len);
		if (rc != FZN_RPC_OK) return rc;
		size_t at = 0, total = 0, start = 0, listed = 0;
		if (!node_number(rest, rest_len, &at, &total) || !node_number(rest, rest_len, &at, &start) ||
		    start != from)
			return unreadable(c);
		while (at < rest_len) {
			size_t end = at;
			while (end < rest_len && rest[end] != ' ') end++;
			const char *e = rest + at, *comma = memchr(e, ',', end - at);
			at = end < rest_len ? end + 1 : end;
			listed++;
			uint8_t subtree[32];
			if (!comma || !node_key(e, (size_t)(comma - e), subtree)) return unreadable(c);
			const char *who = comma + 1;
			size_t who_len = (size_t)(rest + end - who);
			const int group = who_len > 1 && who[0] == '@';
			int catch_up = 0;
			if (group) {
				const char *flag = memchr(who, ',', who_len);
				if (!flag || (size_t)(rest + end - flag) != 2 || (flag[1] != '0' && flag[1] != '1'))
					return unreadable(c);
				catch_up = flag[1] == '1';
				who_len = (size_t)(flag - who);
			}
			who += group, who_len -= (size_t)group;
			if (!who_len || who_len > FZN_RPC_PEER_NAME_MAX * 2) return unreadable(c);
			if (out->count >= FZN_RPC_NOTES_SHARES_LIST_MAX) {
				out->truncated = 1;
				continue;
			}
			fzn_rpc_notes_shares_entry_t *r = &out->entries[out->count++];
			memcpy(r->subtree, subtree, 32);
			const size_t keep = who_len > FZN_RPC_PEER_NAME_MAX ? FZN_RPC_PEER_NAME_MAX : who_len;
			memcpy(r->peer, who, keep);
			r->peer_len = keep;
			r->to_group = (uint8_t)group;
			r->backfill = (uint8_t)catch_up;
		}
		from += listed;
		if (!listed || from >= total) break;
	}
	/* THE SHARERS first, kept apart: each `list shared` reuses the reply. */
	uint8_t sharers[FZN_RPC_NOTES_SHARES_LIST_MAX][32];
	char names[FZN_RPC_NOTES_SHARES_LIST_MAX][FZN_RPC_PEER_NAME_MAX + 1];
	size_t n_sharers = 0;
	from = 0;
	for (unsigned page = 0; page <= FZN_RPC_NOTES_SHARES_LIST_MAX; page++) {
		char arg[32];
		const int arg_len = snprintf(arg, sizeof arg, "sharer %zu", from);
		const char *rest = NULL;
		size_t rest_len = 0;
		int rc = fzn_rpc_node(c, "list", arg, (size_t)arg_len, &rest, &rest_len);
		if (rc != FZN_RPC_OK) return rc;
		size_t at = 0, total = 0, start = 0, listed = 0;
		if (!node_number(rest, rest_len, &at, &total) || !node_number(rest, rest_len, &at, &start) ||
		    start != from)
			return unreadable(c);
		while (at < rest_len) {
			size_t end = at;
			while (end < rest_len && rest[end] != ' ') end++;
			const char *q = rest + at, *stop = rest + end, *f;
			size_t f_len;
			at = end < rest_len ? end + 1 : end;
			listed++;
			uint8_t key[32];
			if (!node_field(&q, stop, &f, &f_len) || !node_key(f, f_len, key) ||
			    !node_field(&q, stop, &f, &f_len))
				return unreadable(c);
			const int contact = f_len == 7 && memcmp(f, "contact", 7) == 0;
			const int gone = f_len == 4 && memcmp(f, "gone", 4) == 0;
			if (!node_field(&q, stop, &f, &f_len) || f_len > FZN_RPC_PEER_NAME_MAX) return unreadable(c);
			if ((!contact && !gone) || n_sharers >= FZN_RPC_NOTES_SHARES_LIST_MAX) continue;
			memcpy(sharers[n_sharers], key, 32);
			const size_t name_len = contact ? f_len : 0;
			memcpy(names[n_sharers], f, name_len);
			names[n_sharers][name_len] = '\0';
			n_sharers++;
		}
		from += listed;
		if (!listed || from >= total) break;
	}
	static fzn_rpc_notes_list_resp_t roots_held;
	fzn_rpc_notes_list_resp_t *roots = &roots_held;
	static const uint8_t top[32];
	int rc = FZN_RPC_OK;
	for (size_t i = 0; rc == FZN_RPC_OK && i < n_sharers; i++) {
		char tree[80];
		node_shared_tree(sharers[i], tree);
		rc = node_notes_list(c, tree, top, roots);
		for (size_t k = 0; rc == FZN_RPC_OK && k < roots->count; k++) {
			if (out->count >= FZN_RPC_NOTES_SHARES_LIST_MAX) {
				out->truncated = 1;
				break;
			}
			fzn_rpc_notes_shares_entry_t *r = &out->entries[out->count++];
			memcpy(r->subtree, roots->entries[k].id, 32);
			memcpy(r->issuer, sharers[i], 32);
			r->peer_len = strlen(names[i]);
			memcpy(r->peer, names[i], r->peer_len);
			r->incoming = 1;
		}
	}
	return rc;
}

/* The identity calls on fuzznetd (sec 284): its sec 620 and 648 verbs. */

_Static_assert(FZN_PREKEY_LEN_TOTAL == FZN_RPC_PREKEY_RECORD_LEN,
               "a prekey record fits a show's blob whole");

/* `get prekey`: the signed record, as hex. */
static int node_prekey_show(fzn_rpc_t *c, fzn_rpc_prekey_show_resp_t *out) {
	memset(out, 0, sizeof(*out));
	const char *rest = NULL;
	size_t rest_len = 0;
	const int rc = fzn_rpc_node(c, "get", "prekey", 6, &rest, &rest_len);
	if (rc != FZN_RPC_OK) return rc;
	if (rest_len != 2 * FZN_RPC_PREKEY_RECORD_LEN) return unreadable(c);
	for (size_t i = 0; i < FZN_RPC_PREKEY_RECORD_LEN; i++) {
		const int hi = hex_nibble(rest[2 * i]), lo = hex_nibble(rest[2 * i + 1]);
		if (hi < 0 || lo < 0) return unreadable(c);
		out->blob[i] = (uint8_t)(hi << 4 | lo);
	}
	return FZN_RPC_OK;
}

/* HOST:PORT, the port after the LAST colon, so a host may hold one: 0 for
 * anything else, a space included, since fuzznetd takes HOST as a word. */
static int node_split_address(const char *address, size_t address_len, size_t *host_len,
                              size_t *port) {
	const char *colon = NULL;
	for (size_t i = 0; i < address_len; i++)
		if (address[i] == ':') colon = address + i;
	size_t at = colon ? (size_t)(colon - address) + 1 : 0;
	if (!colon || colon == address || !node_number(address, address_len, &at, port) ||
	    at != address_len || !*port || *port > 65535 || memchr(address, ' ', address_len))
		return 0;
	*host_len = (size_t)(colon - address);
	return 1;
}

/* This host's own `net/address`, which fuzznet's join card carries for the
 * approver (its sec 671) and an estate reads a member's from. */
static int node_set_own_address(fzn_rpc_t *c, const char *address, size_t address_len) {
	size_t host_len = 0, port = 0;
	if (!node_split_address(address, address_len, &host_len, &port))
		return node_unasked(c, FZN_RPC_ERR_MALFORMED, "an address is HOST:PORT");
	char arg[FZN_REQUEST_MAX];
	return node_ack(c, "set", arg,
	                snprintf(arg, sizeof arg, "setting host net/address %.*s %zu", (int)host_len,
	                         address, port));
}

/* After a verb fuzznetd answers and then starts again in place -- `add
 * join` and `set admin` (fuzznet secs 638, 658) -- wait until it serves
 * again: the restart closes the socket and binds it anew within about a
 * second, and a caller's next request would otherwise meet the gap and
 * read "not running" for a node that is starting. Bounded at five
 * seconds; the act is already done either way, so it is reported done. */
static void node_wait_serving(fzn_rpc_t *c) {
	const char *rest = NULL;
	size_t rest_len = 0;
	usleep(100 * 1000);
	for (int i = 0; i < 50 && fzn_rpc_node(c, "get", "identity", 8, &rest, &rest_len) != FZN_RPC_OK;
	     i++)
		usleep(100 * 1000);
}

/*
 * The join on fuzznetd (sec 284), fuzznet's sec 638 verbs, three steps as
 * the clients' are:
 *
 * - the REQUEST is the new device's prekey record, `get prekey`. A device
 *   address given is set as its own `net/address` first. fuzznet names
 *   hosts by key, so the name the clients' request carries has nowhere to go.
 * - the APPROVAL is `add peer PREKEY delegable`'s card, `FZN4:` text. An
 *   own address given is set first, so the card says where this host is
 *   (fuzznet sec 671); `registered` is whether it does. fuzznet grants one
 *   capability per service (its sec 376), so the grant list has nothing
 *   to choose between and `conferred` is empty.
 * - the INSTALL is `add join PATH`, the card staged in a file since it is
 *   longer than a request line, joining the host the card names. fuzznetd
 *   then starts again in place; this returns once it serves again, so the
 *   caller's next request does not meet the gap.
 */
static size_t node_escape(const char *in, size_t n, char *out, size_t cap);

static int node_join_request(fzn_rpc_t *c, const char *name, size_t name_len, const char *address,
                             size_t address_len, fzn_rpc_host_join_request_resp_t *out) {
	memset(out, 0, sizeof(*out));
	_Static_assert(FZN_RPC_PREKEY_RECORD_LEN <= sizeof out->blob, "a prekey record is a request");
	if (address_len) {
		const int rc = node_set_own_address(c, address, address_len);
		if (rc != FZN_RPC_OK) return rc;
	}
	/* THE DEVICE'S NAME IS ITS OWN SETTING, `host/name` (fuzznet sec 847),
	 * set here on the asking device: it travels with its records, so the
	 * root and every sibling list it, where before a node's devices were
	 * named by key alone. Not in the request, which is fuzznet's choice --
	 * a setting can be renamed later. */
	if (name_len) {
		char esc[2 * 32 * 3 + 1], arg[64 + sizeof esc];
		const size_t esc_len = name_len <= 32 ? node_escape(name, name_len, esc, sizeof esc) : 0;
		if (!esc_len) return node_unasked(c, FZN_RPC_ERR_MALFORMED, "a device's name is 1 to 32 bytes");
		const int rc = node_ack(c, "set", arg,
		                        snprintf(arg, sizeof arg, "setting host host/name %.*s", (int)esc_len,
		                                 esc));
		if (rc != FZN_RPC_OK) return rc;
	}
	fzn_rpc_prekey_show_resp_t record;
	const int rc = node_prekey_show(c, &record);
	if (rc != FZN_RPC_OK) return rc;
	memcpy(out->blob, record.blob, FZN_RPC_PREKEY_RECORD_LEN);
	out->blob_len = FZN_RPC_PREKEY_RECORD_LEN;
	return FZN_RPC_OK;
}

static int node_join_approve(fzn_rpc_t *c, const uint8_t *request, size_t request_len,
                             const char *own_address, size_t own_address_len,
                             fzn_rpc_host_join_approve_resp_t *out) {
	memset(out, 0, sizeof(*out));
	_Static_assert(FZN_PROVISION_TEXT_MAX_LEN <= sizeof out->blob, "a card fits an approval");
	if (request_len != FZN_RPC_PREKEY_RECORD_LEN)
		return node_unasked(c, FZN_RPC_ERR_MALFORMED,
		                    "that is not a request from a node (a prekey record)");
	if (own_address_len) {
		const int rc = node_set_own_address(c, own_address, own_address_len);
		if (rc != FZN_RPC_OK) return rc;
	}
	char hex[2 * FZN_RPC_PREKEY_RECORD_LEN + 1], arg[FZN_REQUEST_MAX];
	fzn_hex_encode(request, request_len, hex);
	const char *rest = NULL;
	size_t rest_len = 0;
	const int rc = fzn_rpc_node(c, "add", arg,
	                             (size_t)snprintf(arg, sizeof arg, "peer %s delegable", hex), &rest,
	                             &rest_len);
	if (rc != FZN_RPC_OK) return rc;
	/* The card, opened here only to say whether it says where this host
	 * is: the text is what travels, unchanged. */
	static char text[FZN_PROVISION_TEXT_MAX_LEN];
	static uint8_t card[FZN_PROVISION_MAX_LEN];
	size_t card_len = 0;
	fzn_provision_card_t opened;
	if (rest_len >= sizeof text) return unreadable(c);
	memcpy(text, rest, rest_len);
	text[rest_len] = '\0';
	if (fzn_provision_from_text(text, card, sizeof card, &card_len) != FZN_PROVISION_OK ||
	    fzn_provision_open(card, card_len, &opened) != FZN_PROVISION_OK)
		return unreadable(c);
	memcpy(out->blob, rest, rest_len);
	out->blob_len = rest_len;
	out->registered = opened.host_len > 0;
	/* What a node's join confers is member, delegable (`add peer ...
	 * delegable` above). Said, so a client reports it rather than nothing. */
	out->conferred[0] = FZN_RPC_CAP_NODE_MEMBER;
	out->conferred_count = 1;
	return FZN_RPC_OK;
}

static int node_join_install(fzn_rpc_t *c, const uint8_t *approval, size_t approval_len,
                             fzn_rpc_host_join_install_resp_t *out) {
	memset(out, 0, sizeof(*out));
	if (approval_len < FZN_PROVISION_TEXT_PREFIX_LEN ||
	    memcmp(approval, FZN_PROVISION_TEXT_PREFIX, FZN_PROVISION_TEXT_PREFIX_LEN) != 0)
		return node_unasked(c, FZN_RPC_ERR_MALFORMED,
		                    "that is not an approval from a node (" FZN_PROVISION_TEXT_PREFIX
		                    "...)");
	/* This host's own key, which a join keeps: asked before the restart. */
	fzn_rpc_status_resp_t self;
	int rc = node_status(c, &self);
	if (rc != FZN_RPC_OK) return rc;
	memcpy(out->host.host_pubkey, self.host_pubkey, 32);
	char path[NODE_STAGE_MAX], arg[FZN_REQUEST_MAX];
	const int fd = node_stage_file(c, "join", path);
	if (fd < 0) return node_unasked(c, FZN_RPC_ERR_STORAGE_IO, "could not stage the approval for the node");
	const int wrote = write(fd, approval, approval_len) == (ssize_t)approval_len;
	close(fd);
	if (!wrote) {
		unlink(path);
		return node_unasked(c, FZN_RPC_ERR_STORAGE_IO, "could not stage the approval for the node");
	}
	const char *rest = NULL;
	size_t rest_len = 0;
	uint8_t root[32];
	rc = fzn_rpc_node(c, "add", arg, (size_t)snprintf(arg, sizeof arg, "join %s", path), &rest,
	                   &rest_len);
	unlink(path);
	if (rc != FZN_RPC_OK) return rc;
	/* `ok ROOT`, the estate joined. The card said where its approver is, or
	 * fuzznetd would have refused it, so the approver is held. */
	if (!node_key(rest, rest_len, root)) return unreadable(c);
	out->registered = 1;
	node_wait_serving(c);
	return FZN_RPC_OK;
}

/* `add invite delegable`: `ok FZI1:...`, a code a device joins by, shown for
 * ten minutes (fuzznet sec 896). It says where this node is, so a node with
 * no net/address is refused, in fuzznet's words. */
int fzn_rpc_device_invite(fzn_rpc_t *c, char *code, size_t cap) {
	const char *rest = NULL;
	size_t rest_len = 0;
	static const char ask[] = "invite delegable";
	const int rc = fzn_rpc_node(c, "add", ask, sizeof ask - 1, &rest, &rest_len);
	if (rc != FZN_RPC_OK) return rc;
	if (rest_len + 1 > cap || rest_len < 5 || memcmp(rest, "FZI1:", 5) != 0) return unreadable(c);
	memcpy(code, rest, rest_len);
	code[rest_len] = '\0';
	return FZN_RPC_OK;
}

int fzn_rpc_device_confirm_get(fzn_rpc_t *c, int *on) {
	static const char ask[] = "setting host invite/confirm";
	const char *rest = NULL;
	size_t rest_len = 0;
	*on = 0;
	const int rc = fzn_rpc_node(c, "get", ask, sizeof ask - 1, &rest, &rest_len);
	if (rc != FZN_RPC_OK) return rc;
	/* `RANK VALUE`, or `absent`. */
	*on = rest_len >= 3 && memcmp(rest + rest_len - 3, " on", 3) == 0;
	return FZN_RPC_OK;
}

int fzn_rpc_device_confirm_set(fzn_rpc_t *c, int on) {
	char arg[48];
	return node_ack(c, "set", arg,
	                snprintf(arg, sizeof arg, "setting host invite/confirm %s", on ? "on" : "off"));
}

/* `list invite`: a count, then a waiting device's key each. */
int fzn_rpc_device_waiting(fzn_rpc_t *c, uint8_t (*keys)[32], size_t cap, size_t *count) {
	const char *rest = NULL;
	size_t rest_len = 0, at = 0, n = 0;
	*count = 0;
	const int rc = fzn_rpc_node(c, "list", "invite", 6, &rest, &rest_len);
	if (rc != FZN_RPC_OK) return rc;
	if (!node_number(rest, rest_len, &at, &n)) return unreadable(c);
	for (size_t i = 0; i < n && *count < cap && at + 64 <= rest_len; i++, at += 65)
		if (!node_key(rest + at, 64, keys[(*count)++])) return unreadable(c);
	return FZN_RPC_OK;
}

int fzn_rpc_device_answer(fzn_rpc_t *c, const uint8_t key[32], int let_in) {
	char hex[65], arg[8 + 64 + 1];
	fzn_hex_encode(key, 32, hex);
	return node_ack(c, let_in ? "grant" : "remove", arg,
	                snprintf(arg, sizeof arg, "invite %s", hex));
}

/* `add join FZI1:...`: the node asks the host until it answers, then starts
 * again as a device of that estate, so this waits for it to serve under the
 * host's root, or says it is still asking. */
/* WHO THIS HOST SERVES AS, from `get identity` alone: HOST USER, each 64 hex. */
static int node_user_key(fzn_rpc_t *c, uint8_t user[32]) {
	const char *rest = NULL;
	size_t rest_len = 0;
	const int rc = fzn_rpc_node(c, "get", "identity", 8, &rest, &rest_len);
	if (rc != FZN_RPC_OK) return rc;
	if (rest_len != 129 || rest[64] != ' ' || !node_key(rest + 65, 64, user)) return unreadable(c);
	return FZN_RPC_OK;
}

int fzn_rpc_device_join_begin(fzn_rpc_t *c, const char *code, size_t code_len,
                              uint8_t before[32]) {
	if (code_len < 5 || memcmp(code, "FZI1:", 5) != 0 || code_len > FZN_REQUEST_MAX - 16u ||
	    memchr(code, ' ', code_len))
		return node_unasked(c, FZN_RPC_ERR_MALFORMED, "that is not a join code (FZI1:...)");
	int rc = node_user_key(c, before);
	if (rc != FZN_RPC_OK) return rc;
	char arg[FZN_REQUEST_MAX];
	const char *rest = NULL;
	size_t rest_len = 0;
	const int arg_len = snprintf(arg, sizeof arg, "join %.*s", (int)code_len, code);
	return fzn_rpc_node(c, "add", arg, (size_t)arg_len, &rest, &rest_len);
}

int fzn_rpc_device_joined(fzn_rpc_t *c, const uint8_t before[32], int *joined) {
	uint8_t now[32];
	*joined = 0;
	/* A NODE STARTING AGAIN does not answer for a moment: not joined yet,
	 * rather than a failure. */
	if (node_user_key(c, now) == FZN_RPC_OK) *joined = memcmp(now, before, 32) != 0;
	c->error[0] = '\0';
	c->error_code = 0;
	return FZN_RPC_OK;
}

int fzn_rpc_device_join(fzn_rpc_t *c, const char *code, size_t code_len, int *joined) {
	uint8_t before[32];
	*joined = 0;
	const int rc = fzn_rpc_device_join_begin(c, code, code_len, before);
	if (rc != FZN_RPC_OK) return rc;
	for (int i = 0; i < 100 && !*joined; i++) {
		(void)fzn_rpc_device_joined(c, before, joined);
		if (*joined) break;
		struct timespec tick = {0, 100000000};
		nanosleep(&tick, NULL);
	}
	c->error[0] = '\0';
	c->error_code = 0;
	return FZN_RPC_OK;
}

/* The bytes of the regular files under `dir`, counted here: fuzznetd says
 * how many files a backup wrote, and the clients' answer says how much as well.
 * Bounded by depth, and links are not followed. */
static uint64_t dir_bytes(const char *dir, int depth) {
	uint64_t total = 0;
	DIR *d = depth > 0 ? opendir(dir) : NULL;
	if (!d) return 0;
	struct dirent *e;
	while ((e = readdir(d)) != NULL) {
		if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;
		char path[1024];
		struct stat st;
		if (snprintf(path, sizeof path, "%s/%s", dir, e->d_name) >= (int)sizeof path ||
		    lstat(path, &st) != 0)
			continue;
		if (S_ISREG(st.st_mode)) total += (uint64_t)st.st_size;
		if (S_ISDIR(st.st_mode)) total += dir_bytes(path, depth - 1);
	}
	closedir(d);
	return total;
}

/* `put backup DIR`: `ok FILES`, into an empty directory of this user's;
 * DIR made absolute, as an export's path is. */
static int node_identity_backup(fzn_rpc_t *c, const char *dir, size_t dir_len,
                                fzn_rpc_identity_backup_resp_t *out) {
	memset(out, 0, sizeof(*out));
	char full[FZN_REQUEST_MAX], arg[FZN_REQUEST_MAX];
	if (!node_abs_path(dir, dir_len, full, sizeof full)) return encode_failed(c);
	const int arg_len = snprintf(arg, sizeof arg, "backup %s", full);
	if (arg_len < 0 || (size_t)arg_len > FZN_REQUEST_MAX - 5u) return encode_failed(c);
	const char *rest = NULL;
	size_t rest_len = 0, at = 0, files = 0;
	const int rc = fzn_rpc_node(c, "put", arg, (size_t)arg_len, &rest, &rest_len);
	if (rc != FZN_RPC_OK) return rc;
	if (!node_number(rest, rest_len, &at, &files) || at != rest_len) return unreadable(c);
	out->files = files;
	out->bytes = dir_bytes(full, 8);
	return FZN_RPC_OK;
}

/* `remove identity KEY`, KEY this host's own key -- fuzznet's guard. the clients'
 * call names the USER's key, so that is checked first against `get
 * identity`'s ROOT: a reset meant for one identity discards no other. The
 * node wipes its state and stops. */
static int node_identity_reset(fzn_rpc_t *c, const uint8_t user[32], fzn_rpc_identity_reset_resp_t *out) {
	memset(out, 0, sizeof(*out));
	const char *rest = NULL;
	size_t rest_len = 0;
	int rc = fzn_rpc_node(c, "get", "identity", 8, &rest, &rest_len);
	if (rc != FZN_RPC_OK) return rc;
	uint8_t root[32];
	char host[65];
	if (rest_len != 129 || rest[64] != ' ' || !node_key(rest + 65, 64, root)) return unreadable(c);
	memcpy(host, rest, 64);
	host[64] = '\0';
	if (memcmp(root, user, 32) != 0)
		return fail(c, FZN_RPC_ERR_NOT_AUTHORIZED, "that is not this node's identity");
	char arg[16 + 64 + 1];
	const int arg_len = snprintf(arg, sizeof arg, "identity %s", host);
	rc = fzn_rpc_node(c, "remove", arg, (size_t)arg_len, &rest, &rest_len);
	if (rc != FZN_RPC_OK) return rc;
	size_t at = 0, files = 0;
	if (!node_number(rest, rest_len, &at, &files) || at != rest_len) return unreadable(c);
	out->files = files;
	return FZN_RPC_OK;
}

/* The reachability reads on fuzznetd (sec 284): its sec 621 and 631 verbs. */

/* A number, or `-` for none, as `list leg` writes one. */
static int node_u64_or_dash(const char *p, size_t len, uint64_t *out) {
	if (len == 1 && p[0] == '-') {
		*out = 0;
		return 1;
	}
	return node_u64(p, len, out);
}

/* `list leg FROM` (`list link` until fuzznet f326bd0, its sec 1075, the
 * holder's rename): `ok TOTAL UNMEASURED FROM HOST:PORT,LATENCY,LOSS,
 * OBSERVATIONS,AGE,ASKED,ANSWERED,SENT,RECEIVED ...`, latency in ms and age
 * in seconds, `-` for a link nothing has been observed on. Mapped where
 * the clients' link has the same thing -- address, round trip, asked and
 * answered, time since the last observation -- and the clients' cost, metric and
 * budget, which fuzznetd does not keep, left 0, which for the budget is
 * the clients' "unlimited".
 *
 * PAGED since fuzznet sec 777 (this tree's 20261030T0231Z): the bare verb
 * stopped adding rows at the 1024-byte reply, about fifteen links of a
 * table of 64, and this refused the short listing, so a busy node's Links
 * view read as unreadable. Bounded by TOTAL and by a page count. */
static int node_link_list(fzn_rpc_t *c, fzn_rpc_link_list_resp_t *out) {
	memset(out, 0, sizeof(*out));
	size_t from = 0, count = 0;
	for (unsigned page = 0; page < 64; page++) {
		char arg[32];
		const int arg_len = snprintf(arg, sizeof arg, "leg %zu", from);
		const char *rest = NULL;
		size_t rest_len = 0;
		const int rc = fzn_rpc_node(c, "list", arg, (size_t)arg_len, &rest, &rest_len);
		if (rc != FZN_RPC_OK) return rc;
		size_t at = 0, unmeasured = 0, start = 0, rows = 0;
		if (!node_number(rest, rest_len, &at, &count) ||
		    !node_number(rest, rest_len, &at, &unmeasured) ||
		    !node_number(rest, rest_len, &at, &start) || start != from)
			return unreadable(c);
		while (at < rest_len) {
			rows++;
			size_t end = at;
			while (end < rest_len && rest[end] != ' ') end++;
			const char *q = rest + at, *stop = rest + end, *f;
			size_t f_len;
			at = end < rest_len ? end + 1 : end;
			uint64_t latency = 0, loss = 0, seen = 0, age = 0, asked = 0, answered = 0, sent = 0,
			         received = 0;
			const char *addr;
			size_t addr_len;
			if (!node_field(&q, stop, &addr, &addr_len) || !addr_len ||
			    addr_len > FZN_RPC_PEER_ADDRESS_MAX || !node_field(&q, stop, &f, &f_len) ||
			    !node_u64_or_dash(f, f_len, &latency) || !node_field(&q, stop, &f, &f_len) ||
			    !node_u64_or_dash(f, f_len, &loss) || !node_field(&q, stop, &f, &f_len) ||
			    !node_u64(f, f_len, &seen) || !node_field(&q, stop, &f, &f_len) ||
			    !node_u64_or_dash(f, f_len, &age) || !node_field(&q, stop, &f, &f_len) ||
			    !node_u64(f, f_len, &asked) || !node_field(&q, stop, &f, &f_len) ||
			    !node_u64(f, f_len, &answered) || !node_field(&q, stop, &f, &f_len) ||
			    !node_u64(f, f_len, &sent) || !node_field(&q, stop, &f, &f_len) ||
			    !node_u64(f, f_len, &received))
				return unreadable(c);
			if (out->count >= FZN_RPC_LINK_LIST_MAX) continue;
			fzn_rpc_link_entry_t *l = &out->entries[out->count++];
			memcpy(l->address, addr, addr_len);
			l->address_len = addr_len;
			l->transport = FZN_RPC_TRANSPORT_UDP;
			l->rtt_ms = (uint32_t)latency;
			l->sent = (uint32_t)asked;
			l->replied = (uint32_t)answered;
			l->since_success_ms = seen ? age * 1000u : 0;
			l->observations = seen;
			l->loss_permille = seen && loss <= 1000u ? (uint16_t)loss : 0;
		}
		out->unmeasured = unmeasured;
		from += rows;
		if (!rows || from >= count) break;
	}
	return out->count == count || out->count == FZN_RPC_LINK_LIST_MAX ? FZN_RPC_OK : unreadable(c);
}

/* `get address`: `ok COUNT AGREE REPORTER,HOST,PORT,AT ...`, the reporter
 * the first eight bytes of its key in hex and AT seconds. Asking anew
 * (`probe`) is `fetch address` first, `ok COUNT` -- the hosts it will ask,
 * at its next round -- or `ok 0 WHY` with nobody to ask (fuzznet sec 653):
 * the clients' `probes_sent`, whose 0 must read apart from "asked, no answer
 * yet". What was asked answers later; this reads what has been said. */
static int node_addr_observe(fzn_rpc_t *c, int probe, fzn_rpc_addr_observe_resp_t *out) {
	memset(out, 0, sizeof(*out));
	const char *rest = NULL;
	size_t rest_len = 0;
	if (probe) {
		const int rc = fzn_rpc_node(c, "fetch", "address", 7, &rest, &rest_len);
		if (rc != FZN_RPC_OK) return rc;
		size_t at = 0, asked = 0;
		if (!node_number(rest, rest_len, &at, &asked) || (asked && at != rest_len))
			return unreadable(c);
		out->probes_sent = (uint16_t)(asked > 0xffff ? 0xffff : asked);
	}
	const int rc = fzn_rpc_node(c, "get", "address", 7, &rest, &rest_len);
	if (rc != FZN_RPC_OK) return rc;
	size_t at = 0, count = 0, agree = 0;
	if (!node_number(rest, rest_len, &at, &count) || !node_number(rest, rest_len, &at, &agree))
		return unreadable(c);
	out->agree = agree;
	while (at < rest_len) {
		size_t end = at;
		while (end < rest_len && rest[end] != ' ') end++;
		const char *q = rest + at, *stop = rest + end, *who, *host, *f;
		size_t who_len, host_len, f_len;
		at = end < rest_len ? end + 1 : end;
		uint64_t port = 0, when = 0;
		if (!node_field(&q, stop, &who, &who_len) || !who_len || who_len > FZN_RPC_PEER_ADDRESS_MAX ||
		    !node_field(&q, stop, &host, &host_len) || !host_len ||
		    !node_field(&q, stop, &f, &f_len) || !node_u64(f, f_len, &port) || port > 65535 ||
		    !node_field(&q, stop, &f, &f_len) || !node_u64(f, f_len, &when))
			return unreadable(c);
		if (out->count >= FZN_RPC_ADDR_OBSERVE_LIST_MAX) continue;
		fzn_rpc_addr_observed_entry_t *e = &out->entries[out->count];
		const int n = snprintf(e->address, sizeof e->address, "%.*s:%llu", (int)host_len, host,
		                       (unsigned long long)port);
		if (n < 0 || (size_t)n >= sizeof e->address) return unreadable(c);
		e->address_len = (size_t)n;
		memcpy(e->reporter, who, who_len);
		e->reporter_len = who_len;
		e->observed_at = when;
		out->count++;
	}
	return out->count == count || out->count == FZN_RPC_ADDR_OBSERVE_LIST_MAX ? FZN_RPC_OK : unreadable(c);
}

/* The library on fuzznetd (sec 284): fuzznet's catalogue, sec 633 and 652.
 * A file is catalogued by its root with the labels `name` and `kind` and the
 * fact `duration`, each one escaped word; it is held where it is put, and
 * its key and size travel in its reference (sec 634), not in the
 * catalogue. Holders are the hosts asserting it, `get catalog ROOT`. */

/* One escaped word on the line, by fuzznet's own escape (its sec 668): its
 * length, or 0 when it does not fit whole. */
static size_t node_escape(const char *in, size_t n, char *out, size_t cap) {
	size_t wrote = 0;
	return fzn_escape((const uint8_t *)in, n, out, cap, &wrote) == n ? wrote : 0;
}

/* `add catalog ROOT NAME VALUE`. */
static int node_catalog_add(fzn_rpc_t *c, const char *root_hex, const char *name,
                            const char *value, size_t value_len) {
	char esc[FZN_REQUEST_MAX], arg[FZN_REQUEST_MAX];
	const size_t esc_len = node_escape(value, value_len, esc, sizeof esc);
	if (!esc_len) return encode_failed(c);
	const int arg_len =
	    snprintf(arg, sizeof arg, "catalog %s %s %.*s", root_hex, name, (int)esc_len, esc);
	if (arg_len < 0 || (size_t)arg_len > FZN_REQUEST_MAX - 5u) return encode_failed(c);
	return node_ack(c, "add", arg, arg_len);
}

/* An entry's labels as `add catalog` rows, each one given. The name is
 * optional, as the clients expect it; an entry with no label at all records
 * nothing, and is refused saying so rather than as a request too long. */
static int node_library_add(fzn_rpc_t *c, const fzn_rpc_library_add_req_t *e) {
	if (e->name_len >= sizeof e->name || e->kind_len >= sizeof e->kind) return encode_failed(c);
	if (!e->name_len && !e->kind_len && !e->duration_ms)
		return node_unasked(c, FZN_RPC_ERR_MALFORMED, "a library entry needs a name, a kind or a duration");
	char hex[65];
	fzn_hex_encode(e->root, 32, hex);
	int rc = FZN_RPC_OK;
	if (e->name_len) rc = node_catalog_add(c, hex, "name", e->name, e->name_len);
	if (rc == FZN_RPC_OK && e->kind_len) rc = node_catalog_add(c, hex, "kind", e->kind, e->kind_len);
	if (rc == FZN_RPC_OK && e->duration_ms) {
		char ms[24];
		const int n = snprintf(ms, sizeof ms, "%llu", (unsigned long long)e->duration_ms);
		rc = node_catalog_add(c, hex, "duration", ms, (size_t)n);
	}
	return rc;
}

/* One root's labels into an entry, from `list catalog`'s rows
 * `ROOT,NAME,VALUE,ISSUER`: the first value seen of each, since each host's
 * is kept apart (DISTINCT) and an entry has one. */
static int node_catalog_take(const char *name, size_t name_len, const char *value, size_t value_len,
                             fzn_rpc_library_list_entry_t *e) {
	size_t len = 0;
	int cut = 0;
	if (name_len == 4 && memcmp(name, "name", 4) == 0 && !e->name_len) {
		if (!node_unescape(value, value_len, e->name, sizeof e->name - 1, &len, &cut)) return 0;
		e->name_len = len;
	} else if (name_len == 4 && memcmp(name, "kind", 4) == 0 && !e->kind_len) {
		if (!node_unescape(value, value_len, e->kind, sizeof e->kind - 1, &len, &cut)) return 0;
		e->kind_len = len;
	} else if (name_len == 8 && memcmp(name, "duration", 8) == 0 && !e->duration_ms) {
		if (!node_u64(value, value_len, &e->duration_ms)) return 0;
	}
	return 1;
}

/* `list catalog [ROOT] [FROM]`: `ok TOTAL FROM ROOT,NAME,VALUE,ISSUER ...`,
 * paged, gathered by root into `out` (at most `cap`). */
/* The row of `root` in a listing being gathered, an open table of row numbers
 * plus one over the root's own bytes, which are a hash already: a file is read
 * as several rows, and comparing each with all before it took n squared. */
typedef struct catalog_index {
	uint32_t *slots;
	size_t size;
} catalog_index_t;

static size_t catalog_slot(const catalog_index_t *x, const fzn_rpc_library_list_entry_t *rows,
                           const uint8_t root[32]) {
	uint64_t h;
	memcpy(&h, root, sizeof h);
	size_t at = (size_t)h & (x->size - 1);
	while (x->slots[at] && memcmp(rows[x->slots[at] - 1].root, root, 32) != 0)
		at = (at + 1) & (x->size - 1);
	return at;
}

static int catalog_index_room(fzn_rpc_t *c, catalog_index_t *x,
                              const fzn_rpc_library_list_entry_t *rows, size_t count) {
	if (x->size > count * 2) return FZN_RPC_OK;
	const size_t size = x->size ? x->size * 2 : 256;
	uint32_t *slots = calloc(size, sizeof *slots);
	if (!slots) return fail(c, FZN_RPC_ERR_STORAGE_IO, "out of memory for that list");
	free(x->slots);
	x->slots = slots;
	x->size = size;
	for (size_t i = 0; i < count; i++) x->slots[catalog_slot(x, rows, rows[i].root)] = (uint32_t)i + 1;
	return FZN_RPC_OK;
}

static int catalog_gather(fzn_rpc_t *c, const char *root_hex, fzn_rpc_library_list_all_t *all,
                          catalog_index_t *index) {
	all->count = 0;
	size_t from = 0;
	for (;;) {
		char arg[96];
		const int arg_len = root_hex ? snprintf(arg, sizeof arg, "catalog %s %zu", root_hex, from)
		                             : snprintf(arg, sizeof arg, "catalog %zu", from);
		const char *rest = NULL;
		size_t rest_len = 0;
		const int rc = fzn_rpc_node(c, "list", arg, (size_t)arg_len, &rest, &rest_len);
		if (rc != FZN_RPC_OK) return rc;
		size_t at = 0, total = 0, start = 0, listed = 0;
		if (!node_number(rest, rest_len, &at, &total) || !node_number(rest, rest_len, &at, &start) ||
		    start != from)
			return unreadable(c);
		while (at < rest_len) {
			size_t end = at;
			while (end < rest_len && rest[end] != ' ') end++;
			const char *q = rest + at, *stop = rest + end, *f, *name, *value;
			size_t f_len, name_len, value_len;
			at = end < rest_len ? end + 1 : end;
			listed++;
			uint8_t root[32];
			if (!node_field(&q, stop, &f, &f_len) || !node_key(f, f_len, root) ||
			    !node_field(&q, stop, &name, &name_len) || !node_field(&q, stop, &value, &value_len) ||
			    !node_field(&q, stop, &f, &f_len))
				return unreadable(c);
			int grown = catalog_index_room(c, index, all->entries, all->count);
			if (grown == FZN_RPC_OK)
				grown = room_for(c, &all->entries, &all->room, all->count + 1, sizeof *all->entries);
			if (grown != FZN_RPC_OK) return grown;
			const size_t slot = catalog_slot(index, all->entries, root);
			size_t k = index->slots[slot] ? index->slots[slot] - 1 : all->count;
			if (k == all->count) {
				memset(&all->entries[k], 0, sizeof all->entries[k]);
				memcpy(all->entries[k].root, root, 32);
				index->slots[slot] = (uint32_t)k + 1;
				all->count++;
			}
			if (!node_catalog_take(name, name_len, value, value_len, &all->entries[k]))
				return unreadable(c);
		}
		from += listed;
		if (!listed || from >= total) return FZN_RPC_OK;
	}
}

static int node_catalog_entries(fzn_rpc_t *c, const char *root_hex, fzn_rpc_library_list_all_t *all) {
	catalog_index_t index = {NULL, 0};
	const int rc = catalog_gather(c, root_hex, all, &index);
	free(index.slots);
	return rc;
}

/* Each entry's holders, `get catalog ROOT` -- `ok COUNT ISSUER ...`, an
 * issuer the first eight bytes of its key in hex -- whether this host is
 * one, by `get identity`'s HOST, and its size from the file's status where
 * it is held here: the catalogue carries no size. */
typedef int (*node_row_fn)(void *ctx, const char *row, size_t row_len);
static int node_pages_bounded(fzn_rpc_t *c, const char *what, size_t what_len, node_row_fn row,
                              void *ctx, size_t *total_out, unsigned max_pages);

/*
 * The same answers for many rows from two listings, not two requests a row:
 * `list catalog` already names each claim's issuer (the 16 hex `get catalog`
 * gives), and `list file` each file held or arriving here with its length,
 * one still arriving marked `,fetching=` (fuzznet sec 495/955). Measured
 * before: `fzp library-list` at 20000 files asked 40000 requests. One file
 * (a detail pane) keeps the direct path, which asks two.
 */
typedef struct root_issuer {
	uint8_t root[32];
	char issuer[16];
} root_issuer_t;
typedef struct root_file {
	uint8_t root[32];
	uint64_t length;
	int whole;
	uint16_t arriving; /* per mille while fetching, sec 1132 */
} root_file_t;

static int cmp_root_issuer(const void *a, const void *b) {
	const root_issuer_t *x = a, *y = b;
	const int r = memcmp(x->root, y->root, 32);
	return r ? r : memcmp(x->issuer, y->issuer, 16);
}
static int cmp_root_file(const void *a, const void *b) {
	return memcmp(((const root_file_t *)a)->root, ((const root_file_t *)b)->root, 32);
}

struct issuers_ctx {
	fzn_rpc_t *c;
	root_issuer_t *rows;
	size_t count, room;
};
struct files_ctx {
	fzn_rpc_t *c;
	root_file_t *rows;
	size_t count, room;
};

/* `ROOT,NAME,VALUE,ISSUER` */
static int take_issuer(void *ctx, const char *w, size_t w_len) {
	struct issuers_ctx *x = ctx;
	const char *q = w, *stop = w + w_len, *f;
	size_t f_len;
	uint8_t root[32];
	if (!node_field(&q, stop, &f, &f_len) || !node_key(f, f_len, root)) return 0;
	for (int i = 0; i < 2; i++)
		if (!node_field(&q, stop, &f, &f_len)) return 0;
	if (!node_field(&q, stop, &f, &f_len) || f_len != 16) return 0;
	if (room_for(x->c, &x->rows, &x->room, x->count + 1, sizeof *x->rows) != FZN_RPC_OK) return 0;
	memcpy(x->rows[x->count].root, root, 32);
	memcpy(x->rows[x->count].issuer, f, 16);
	x->count++;
	return 1;
}

/* `ROOT,LENGTH[,public][,shared][,fetching=HELD/TOTAL]` */
static int take_file(void *ctx, const char *w, size_t w_len) {
	struct files_ctx *x = ctx;
	const char *q = w, *stop = w + w_len, *f;
	size_t f_len;
	uint8_t root[32];
	uint64_t length = 0;
	if (!node_field(&q, stop, &f, &f_len) || !node_key(f, f_len, root)) return 0;
	if (!node_field(&q, stop, &f, &f_len) || !node_u64(f, f_len, &length)) return 0;
	int whole = 1;
	uint16_t arriving = 0;
	while (q <= stop && node_field(&q, stop, &f, &f_len))
		if (f_len >= 9 && memcmp(f, "fetching=", 9) == 0) {
			whole = 0;
			/* HELD/TOTAL, in leaves: how far, per mille, at least 1. */
			const char *slash = memchr(f + 9, '/', f_len - 9);
			uint64_t held = 0, total = 0;
			if (slash && node_u64(f + 9, (size_t)(slash - f - 9), &held) &&
			    node_u64(slash + 1, (size_t)(f + f_len - slash - 1), &total) && total &&
			    held <= total) {
				const uint64_t pm = held * 1000u / total;
				arriving = (uint16_t)(pm ? pm : 1);
			} else {
				arriving = 1;
			}
		}
	if (room_for(x->c, &x->rows, &x->room, x->count + 1, sizeof *x->rows) != FZN_RPC_OK) return 0;
	memcpy(x->rows[x->count].root, root, 32);
	x->rows[x->count].length = length;
	x->rows[x->count].whole = whole;
	x->rows[x->count].arriving = arriving;
	x->count++;
	return 1;
}

static int node_library_fill_many(fzn_rpc_t *c, fzn_rpc_library_list_entry_t *e, size_t n,
                                  const char me[16]) {
	struct issuers_ctx is = {c, NULL, 0, 0};
	struct files_ctx fs = {c, NULL, 0, 0};
	size_t total = 0;
	/* Paged to the end: a library has no cap (the holder, 2026-11-06), and
	 * each page moves on or the listing stops. */
	int rc = node_pages_bounded(c, "catalog", 7, take_issuer, &is, &total, 1u << 24);
	if (rc == FZN_RPC_OK) rc = node_pages_bounded(c, "file", 4, take_file, &fs, &total, 1u << 24);
	if (rc == FZN_RPC_OK) {
		/* AN EMPTY LIST IS A NULL ARRAY, which qsort and bsearch may not be
		 * handed even with a count of 0 (snurra, inbox 20261114T0146Z). */
		if (is.count) qsort(is.rows, is.count, sizeof *is.rows, cmp_root_issuer);
		if (fs.count) qsort(fs.rows, fs.count, sizeof *fs.rows, cmp_root_file);
		for (size_t i = 0; i < n; i++) {
			root_issuer_t key;
			memcpy(key.root, e[i].root, 32);
			memset(key.issuer, 0, sizeof key.issuer);
			/* The first claim of this root: the rows are sorted by root, then
			 * issuer, so its claims follow, one per distinct issuer counted. */
			size_t lo = 0, hi = is.count;
			while (lo < hi) {
				const size_t mid = lo + (hi - lo) / 2;
				if (memcmp(is.rows[mid].root, key.root, 32) < 0) lo = mid + 1;
				else hi = mid;
			}
			size_t holders = 0;
			int claimed = 0;
			for (size_t k = lo; k < is.count && memcmp(is.rows[k].root, key.root, 32) == 0; k++) {
				if (k == lo || memcmp(is.rows[k].issuer, is.rows[k - 1].issuer, 16) != 0) holders++;
				if (memcmp(is.rows[k].issuer, me, 16) == 0) claimed = 1;
			}
			e[i].holders = (uint16_t)(holders > 0xffff ? 0xffff : holders);
			root_file_t fkey;
			memcpy(fkey.root, e[i].root, 32);
			const root_file_t *f =
			        fs.count ? bsearch(&fkey, fs.rows, fs.count, sizeof *fs.rows, cmp_root_file) : NULL;
			if (f) e[i].size = f->length;
			if (f && !f->whole) e[i].arriving_permille = f->arriving;
			/* As the one-file path: held here is the bytes whole here, not
			 * this host's own claim. */
			if (f && f->whole) {
				e[i].held_here = 1;
				if (!claimed && e[i].holders < 0xffff) e[i].holders++;
			}
			e[i].detail = 1;
		}
	}
	free(is.rows);
	free(fs.rows);
	return rc;
}

/* `many`: the rows of a listing, read from two listings whatever their
 * number; otherwise each asked on its own, which `library-show`'s one file
 * wants. */
static int node_library_fill(fzn_rpc_t *c, fzn_rpc_library_list_entry_t *e, size_t n, int many) {
	const char *rest = NULL;
	size_t rest_len = 0;
	int rc = fzn_rpc_node(c, "get", "identity", 8, &rest, &rest_len);
	if (rc != FZN_RPC_OK) return rc;
	if (rest_len != 129) return unreadable(c);
	char me[17];
	memcpy(me, rest, 16);
	me[16] = '\0';
	if (many) return node_library_fill_many(c, e, n, me);
	for (size_t i = 0; i < n; i++) {
		char hex[65], arg[96];
		fzn_hex_encode(e[i].root, 32, hex);
		int arg_len = snprintf(arg, sizeof arg, "catalog %s", hex);
		rc = fzn_rpc_node(c, "get", arg, (size_t)arg_len, &rest, &rest_len);
		if (rc != FZN_RPC_OK) return rc;
		size_t at = 0, holders = 0;
		int claimed = 0;
		if (!node_number(rest, rest_len, &at, &holders)) return unreadable(c);
		e[i].holders = (uint16_t)(holders > 0xffff ? 0xffff : holders);
		while (at < rest_len) {
			size_t end = at;
			while (end < rest_len && rest[end] != ' ') end++;
			if (end - at == 16 && memcmp(rest + at, me, 16) == 0) claimed = 1;
			at = end < rest_len ? end + 1 : end;
		}
		static fzn_rpc_blob_status_resp_t st;
		rc = node_file_status(c, e[i].root, &st);
		if (rc != FZN_RPC_OK) return rc;
		if (st.known) e[i].size = st.byte_len;
		/* HELD HERE IS THE BYTES, NOT THE CLAIM, both ways. A file fetched
		 * from another device is whole here and claimed nowhere by this
		 * node, so by the catalogue alone it read "remote" with every leaf
		 * on disk, and fzptui offered to fetch it again. And a file whose
		 * copy here was removed is still claimed by this node, so it read
		 * "already here" with nothing on disk (2026-11-10): a host's own
		 * have-set is the measurement, its published claim only a hint
		 * for others (sec 22's "a claim is a claim"). */
		if (st.known && st.complete) {
			e[i].held_here = 1;
			if (!claimed && e[i].holders < 0xffff) e[i].holders++; /* this host, beside the claimants */
		}
		e[i].detail = 1;
	}
	return FZN_RPC_OK;
}

static int node_library_list(fzn_rpc_t *c, fzn_rpc_library_list_all_t *out) {
	int rc = node_catalog_entries(c, NULL, out);
	/* Every row: two listings answer them all at one cost (2026-11-09), where
	 * two requests a file once held a listing to its first
	 * FZN_RPC_LIBRARY_DETAIL_ROWS. */
	if (rc == FZN_RPC_OK) rc = node_library_fill(c, out->entries, out->count, 1);
	return rc;
}

static int node_library_show(fzn_rpc_t *c, const uint8_t root[32], fzn_rpc_library_show_resp_t *out) {
	memset(out, 0, sizeof(*out));
	char hex[65];
	fzn_hex_encode(root, 32, hex);
	static fzn_rpc_library_list_all_t one;
	int rc = node_catalog_entries(c, hex, &one);
	if (rc != FZN_RPC_OK) return rc;
	if (!one.count) return fail(c, FZN_RPC_ERR_STORAGE_IO, "that file is not in the library");
	fzn_rpc_library_list_entry_t e = one.entries[0];
	/* `holder_keys` stay empty: fuzznetd names a holder by the first eight
	 * bytes of its key, and a key padded out to 32 would name nobody. */
	rc = node_library_fill(c, &e, 1, 0);
	if (rc != FZN_RPC_OK) return rc;
	memcpy(out->root, e.root, 32);
	memcpy(out->name, e.name, e.name_len);
	out->name_len = e.name_len;
	memcpy(out->kind, e.kind, e.kind_len);
	out->kind_len = e.kind_len;
	out->size = e.size;
	out->duration_ms = e.duration_ms;
	out->holders = e.holders;
	out->held_here = e.held_here;
	return FZN_RPC_OK;
}

/* `get file ROOT OFFSET LENGTH PATH`, a range written to a staged file and
 * read back. `playable` is the clients' contiguous prefix; fuzznetd says how many
 * leaves are held and not whether they run from the start, so it is the size
 * when the file is whole and 0 otherwise. A range the fetch has not reached
 * is an underrun -- wait and ask again -- and past the end is the end. */
/* `get file ROOT OFFSET LENGTH PATH` into `data`. A range the fetch has not
 * reached is no failure: *reached is 0, with nothing read. */
static int node_read_range(fzn_rpc_t *c, const char *hex, uint64_t offset, uint64_t len,
                           uint8_t *data, size_t *got, int *reached) {
	*got = 0;
	*reached = 1;
	char path[NODE_STAGE_MAX], arg[NODE_STAGE_MAX + 128];
	const int fd = node_stage_file(c, "play", path);
	if (fd < 0) return fail(c, FZN_RPC_ERR_STORAGE_IO, "could not stage the slice");
	close(fd);
	unlink(path); /* the name kept: fuzznetd refuses to write over a file */
	const int arg_len = snprintf(arg, sizeof arg, "file %s %llu %llu %s", hex,
	                             (unsigned long long)offset, (unsigned long long)len, path);
	const char *rest = NULL;
	size_t rest_len = 0;
	int rc = fzn_rpc_node(c, "get", arg, (size_t)arg_len, &rest, &rest_len);
	if (rc == FZN_RPC_ERR_STORAGE_IO && strstr(c->error, "not reached")) {
		unlink(path);
		c->error[0] = '\0';
		c->error_code = 0;
		*reached = 0;
		return FZN_RPC_OK;
	}
	if (rc == FZN_RPC_OK) {
		FILE *f = fopen(path, "rb");
		*got = f ? fread(data, 1, (size_t)len, f) : 0;
		if (f) fclose(f);
		if (*got != len) rc = fail(c, FZN_RPC_ERR_STORAGE_IO, "the slice did not read back");
	}
	unlink(path);
	return rc;
}

/*
 * A node does not say how far a file is contiguous, only how many leaves are
 * here, and a read of a range that has not arrived is refused. So `playable`
 * for a file still arriving is the share of it held, when a byte at that
 * point can be read: a fetch runs lowest leaves first, so that is the
 * prefix. Otherwise what this call's read proved. Under-reporting costs a
 * progress figure; the reads themselves are what a player trusts, and an
 * underrun still answers one that outruns it.
 */
static int node_library_play(fzn_rpc_t *c, const uint8_t root[32], uint64_t offset, uint16_t want,
                             fzn_rpc_library_play_resp_t *out) {
	memset(out, 0, sizeof(*out));
	if (want > FZN_RPC_LIBRARY_PLAY_MAX_SLICE) return encode_failed(c);
	/* On the stack, not static: a player reads this from its decoding
	 * thread while the window reads the same call on its own. */
	fzn_rpc_blob_status_resp_t st;
	int rc = node_file_status(c, root, &st);
	if (rc != FZN_RPC_OK) return rc;
	/* NONE OF IT HERE, sec 1153: said as what to do, not as "not in the
	 * library" of a file the library lists. */
	if (!st.known) return fail(c, FZN_RPC_ERR_NOT_FETCHED, fzn_rpc_err_str(FZN_RPC_ERR_NOT_FETCHED));
	out->size = st.byte_len;
	out->complete = st.complete;
	out->playable = st.complete ? st.byte_len : 0;
	char hex[65];
	fzn_hex_encode(root, 32, hex);
	int reached = 1;
	if (offset < st.byte_len && want) {
		const uint64_t len = st.byte_len - offset < want ? st.byte_len - offset : want;
		rc = node_read_range(c, hex, offset, len, out->data, &out->data_len, &reached);
		if (rc != FZN_RPC_OK) return rc;
		out->underrun = !reached;
		if (!st.complete && reached) out->playable = offset + len;
	}
	if (!st.complete && st.leaf_count && st.leaves_held) {
		const uint64_t share = st.byte_len / st.leaf_count * st.leaves_held;
		if (share > out->playable) {
			uint8_t byte;
			size_t got = 0;
			rc = node_read_range(c, hex, share - 1, 1, &byte, &got, &reached);
			if (rc != FZN_RPC_OK) return rc;
			if (reached) out->playable = share;
		}
	}
	return FZN_RPC_OK;
}

/* A GROUP'S NOTEBOOK on fuzznetd (sec 283): fuzznet keeps no group tree. A
 * note shared to a group lands in the sharing member's tree, so the
 * notebook is the trees `list sharer` names under that group -- KIND
 * `group`, NAME `@GROUP` by this host's name for it, found from the clients'
 * chat_id through `list group`'s id. A sharer in several groups is named by
 * the first group held (fuzznet sec 640), so it is under that one alone. */
#define NODE_GROUP_SHARERS_MAX 32
static int node_group_sharers_at(fzn_rpc_t *c, const char *want,
                                 uint8_t keys[NODE_GROUP_SHARERS_MAX][32], size_t *n);

static int node_group_sharers(fzn_rpc_t *c, const uint8_t chat_id[32],
                              uint8_t keys[NODE_GROUP_SHARERS_MAX][32], size_t *n) {
	*n = 0;
	static fzn_rpc_group_list_resp_t rows;
	int rc = node_group_rows(c, &rows);
	char want[2 + FZN_RPC_PEER_NAME_MAX + 1] = "";
	for (size_t i = 0; rc == FZN_RPC_OK && i < rows.count; i++)
		if (memcmp(rows.entries[i].chat_id, chat_id, 32) == 0)
			snprintf(want, sizeof want, "@%.*s", (int)rows.entries[i].name_len,
			         rows.entries[i].name);
	if (rc != FZN_RPC_OK) return rc;
	if (!want[0]) return fail(c, FZN_RPC_ERR_STORAGE_IO, "no such group here");
	return node_group_sharers_at(c, want, keys, n);
}

/* The same for a group named `want`, `@NAME`: a caller that has the listing
 * already, as one walking every group does, would otherwise read it again
 * for each -- groups squared, 600000 requests a keypress at 3000. */
static int node_group_sharers_at(fzn_rpc_t *c, const char *want,
                                 uint8_t keys[NODE_GROUP_SHARERS_MAX][32], size_t *n) {
	*n = 0;
	int rc;
	size_t from = 0;
	for (unsigned page = 0; page <= 4096u; page++) {
		/* `list sharer @GROUP [FROM]` (fuzznet sec 837): every held sharer
		 * who is a member of the group, contacts included. The plain list
		 * gives a contact's tree as KIND `contact`, so a member who was also
		 * a contact -- the ordinary case -- was looked for as `group` and
		 * never found, and the group's notebook read as empty. */
		char arg[16 + sizeof want + 24];
		const int arg_len = snprintf(arg, sizeof arg, "sharer %s %zu", want, from);
		const char *rest = NULL;
		size_t rest_len = 0;
		rc = fzn_rpc_node(c, "list", arg, (size_t)arg_len, &rest, &rest_len);
		if (rc != FZN_RPC_OK) return rc;
		size_t at = 0, total = 0, start = 0, listed = 0;
		if (!node_number(rest, rest_len, &at, &total) || !node_number(rest, rest_len, &at, &start) ||
		    start != from)
			return unreadable(c);
		while (at < rest_len) {
			size_t end = at;
			while (end < rest_len && rest[end] != ' ') end++;
			const char *q = rest + at, *stop = rest + end, *f, *kind, *name;
			size_t f_len, kind_len, name_len;
			at = end < rest_len ? end + 1 : end;
			listed++;
			uint8_t key[32];
			if (!node_field(&q, stop, &f, &f_len) || !node_key(f, f_len, key) ||
			    !node_field(&q, stop, &kind, &kind_len) || !node_field(&q, stop, &name, &name_len))
				return unreadable(c);
			(void)kind, (void)kind_len, (void)name, (void)name_len;
			if (*n < NODE_GROUP_SHARERS_MAX) memcpy(keys[(*n)++], key, 32);
		}
		from += listed;
		if (!listed || from >= total) break;
	}
	return FZN_RPC_OK;
}

/* The notebook's listing: the top is every sharer's roots together; below
 * it, a note is in one sharer's tree, and the others answer that they hold
 * no such note -- so a listing any sharer gave is the answer, and the last
 * refusal only when none did. */
static int node_group_notes_list(fzn_rpc_t *c, const uint8_t chat_id[32], const uint8_t parent[32],
                                 fzn_rpc_notes_list_resp_t *out) {
	uint8_t keys[NODE_GROUP_SHARERS_MAX][32];
	size_t n = 0;
	int rc = node_group_sharers(c, chat_id, keys, &n);
	out->count = 0;
	out->truncated = 0;
	if (rc != FZN_RPC_OK) return rc;
	static fzn_rpc_notes_list_resp_t one_held;
	fzn_rpc_notes_list_resp_t *one = &one_held;
	int any = 0, last = FZN_RPC_OK;
	char why[sizeof(c->error)] = "";
	for (size_t i = 0; i < n; i++) {
		char tree[80];
		node_shared_tree(keys[i], tree);
		last = node_notes_list(c, tree, parent, one);
		if (last != FZN_RPC_OK) {
			snprintf(why, sizeof why, "%s", c->error);
			continue;
		}
		any = 1;
		for (size_t k = 0; k < one->count; k++) {
			rc = room_for(c, &out->entries, &out->room, out->count + 1, sizeof *out->entries);
			if (rc != FZN_RPC_OK) return rc;
			out->entries[out->count] = one->entries[k];
			out->entries[out->count].order = out->count;
			out->count++;
		}
		out->truncated |= one->truncated;
	}
	if (any || !n) {
		c->error[0] = '\0';
		c->error_code = 0;
		return FZN_RPC_OK;
	}
	return fail(c, last, why);
}

int fzn_rpc_group_notebook_held(fzn_rpc_t *c, const char *group, size_t group_len, int *held) {
	*held = 0;
	if (!group_len || group_len > FZN_RPC_PEER_NAME_MAX) return encode_failed(c);
	char want[2 + FZN_RPC_PEER_NAME_MAX + 1];
	snprintf(want, sizeof want, "@%.*s", (int)group_len, group);
	uint8_t keys[NODE_GROUP_SHARERS_MAX][32];
	size_t n = 0;
	const int rc = node_group_sharers_at(c, want, keys, &n);
	if (rc != FZN_RPC_OK) return rc;
	static fzn_rpc_notes_list_resp_t one;
	const uint8_t top[32] = {0};
	for (size_t i = 0; i < n && !*held; i++) {
		char tree[80];
		node_shared_tree(keys[i], tree);
		if (node_notes_list(c, tree, top, &one) == FZN_RPC_OK && one.count) *held = 1;
	}
	c->error[0] = '\0';
	c->error_code = 0;
	return FZN_RPC_OK;
}

/* A note in the notebook: in whichever sharer's tree holds it. */
static int node_group_notes_show(fzn_rpc_t *c, const uint8_t chat_id[32], const uint8_t id[32],
                                 fzn_rpc_notes_show_resp_t *out) {
	uint8_t keys[NODE_GROUP_SHARERS_MAX][32];
	size_t n = 0;
	int rc = node_group_sharers(c, chat_id, keys, &n);
	if (rc != FZN_RPC_OK) return rc;
	rc = fail(c, FZN_RPC_ERR_STORAGE_IO, "no such note in the group's notebook");
	for (size_t i = 0; i < n; i++) {
		char tree[80];
		node_shared_tree(keys[i], tree);
		rc = node_notes_show(c, tree, id, out);
		if (rc == FZN_RPC_OK) return FZN_RPC_OK;
	}
	return rc;
}

/* `identity_generate` and `host_create` on fuzznetd: fuzznetd makes this
 * device's identity the first time it starts on a store, a device that has
 * never joined being its own estate's root (fuzznet sec 409), so a running
 * one always has both. Each answers as the clients expect a second generate --
 * refused as existing -- once `get identity` has shown it there, and says
 * why. (`fuzznetd --new-root` is a separate recovery root, sec 403, and no
 * part of this.) */
static int node_identity_exists(fzn_rpc_t *c, int code, const char *what) {
	const char *rest = NULL;
	size_t rest_len = 0;
	const int rc = fzn_rpc_node(c, "get", "identity", 8, &rest, &rest_len);
	if (rc != FZN_RPC_OK) return rc;
	if (rest_len != 129) return unreadable(c);
	char why[160];
	snprintf(why, sizeof why, "this node's %s was made when the node first started", what);
	return fail(c, code, why);
}

/* This node's siblings on fuzznetd (sec 284): `list sibling [FROM]`, fuzznet
 * sec 638's answer to the clients' sibling list, `ok TOTAL FROM KEY,WHERE,PAIRED,
 * HEARD ...` -- every other host of this estate this node knows, WHERE `-`
 * for nowhere. fuzznet names no sibling, so one is named here by the first
 * eight bytes of its key in hex; the clients' name fits it, and `sibling_remove`
 * resolves it back to the one key it begins. */
static int node_siblings(fzn_rpc_t *c, fzn_rpc_sibling_list_resp_t *out) {
	memset(out, 0, sizeof(*out));
	size_t from = 0;
	for (unsigned page = 0; page <= 4096u; page++) {
		char arg[32];
		const int arg_len = snprintf(arg, sizeof arg, "sibling %zu", from);
		const char *rest = NULL;
		size_t rest_len = 0;
		const int rc = fzn_rpc_node(c, "list", arg, (size_t)arg_len, &rest, &rest_len);
		if (rc != FZN_RPC_OK) return rc;
		size_t at = 0, total = 0, start = 0, listed = 0;
		if (!node_number(rest, rest_len, &at, &total) || !node_number(rest, rest_len, &at, &start) ||
		    start != from)
			return unreadable(c);
		while (at < rest_len) {
			size_t end = at;
			while (end < rest_len && rest[end] != ' ') end++;
			const char *q = rest + at, *stop = rest + end, *f, *where, *paired;
			size_t f_len, where_len, paired_len;
			at = end < rest_len ? end + 1 : end;
			listed++;
			uint8_t key[32];
			if (!node_field(&q, stop, &f, &f_len) || !node_key(f, f_len, key) ||
			    !node_field(&q, stop, &where, &where_len) ||
			    !node_field(&q, stop, &paired, &paired_len) || !node_field(&q, stop, &f, &f_len))
				return unreadable(c);
			/* KEY,WHERE,PAIRED,HEARD[,NAME]: the device's own `host/name`
			 * since fuzznet's sec 847, escaped, or `-`. */
			const char *named = NULL;
			size_t named_len = 0;
			if (q <= stop && !node_field(&q, stop, &named, &named_len)) return unreadable(c);
			if (out->count >= FZN_RPC_SIBLING_LIST_MAX) continue;
			fzn_rpc_sibling_entry_t *e = &out->entries[out->count++];
			memcpy(e->host_pubkey, key, 32);
			size_t got = 0;
			int cut = 0;
			if (named && !(named_len == 1 && named[0] == '-') &&
			    node_unescape(named, named_len, e->name, sizeof e->name - 1, &got, &cut) && got) {
				e->name_len = got;
			} else {
				/* No name given: the key's first sixteen, as before. */
				char hex[65];
				fzn_hex_encode(key, 32, hex);
				memcpy(e->name, hex, 16);
				e->name_len = 16;
			}
			if (!(where_len == 1 && where[0] == '-') && where_len < sizeof e->address) {
				memcpy(e->address, where, where_len);
				e->address_len = where_len;
			}
			/* PAIRED, as the node judged it at this listing (sec 1124): a
			 * pairing either way, `paired`, else `unpaired`. It was read and
			 * dropped, and every host listed as valid. */
			e->valid = paired_len == 6 && memcmp(paired, "paired", 6) == 0;
		}
		from += listed;
		if (!listed || from >= total) break;
	}
	return FZN_RPC_OK;
}

/* The one sibling `name` names, as 64 hex in `hex`: by the device's NAME,
 * as the Hosts tab and fzp host-list show it since fuzznet sec 847, or by
 * sixteen or more of its key's hex digits. Two callers took the key prefix
 * alone, so once a node's devices were shown by name, Unlink and Set
 * address on a shown row answered "no such sibling". */
static int node_sibling_named(fzn_rpc_t *c, const char *name, size_t name_len, char hex[65]) {
	if (!name_len || name_len > 64) return node_unasked(c, FZN_RPC_ERR_NO_PEER, "no such sibling");
	fzn_rpc_sibling_list_resp_t *all = malloc(sizeof(*all));
	if (!all) return fail(c, FZN_RPC_ERR_STORAGE_IO, "out of memory reading the siblings");
	int rc = node_siblings(c, all);
	size_t found = 0, which = 0;
	for (size_t i = 0; rc == FZN_RPC_OK && i < all->count; i++) {
		char key_hex[65];
		fzn_hex_encode(all->entries[i].host_pubkey, 32, key_hex);
		const int by_name = all->entries[i].name_len == name_len &&
		                    memcmp(all->entries[i].name, name, name_len) == 0;
		const int by_key = name_len >= 16 && memcmp(key_hex, name, name_len) == 0;
		if (by_name || by_key) found++, which = i;
	}
	if (rc == FZN_RPC_OK && found == 1) fzn_hex_encode(all->entries[which].host_pubkey, 32, hex);
	free(all);
	if (rc != FZN_RPC_OK) return rc;
	if (found != 1)
		return fail(c, FZN_RPC_ERR_NO_PEER, found ? "that names more than one sibling" : "no such sibling");
	return FZN_RPC_OK;
}

/* `remove peer KEY`, the sibling `name` names. */
static int node_sibling_remove(fzn_rpc_t *c, const char *name, size_t name_len) {
	char hex[65], arg[16 + 64 + 1];
	const int rc = node_sibling_named(c, name, name_len, hex);
	if (rc != FZN_RPC_OK) return rc;
	return node_ack(c, "remove", arg, snprintf(arg, sizeof arg, "peer %s", hex));
}

/* `lan_discover` on fuzznetd (sec 284): `fetch lan`, fuzznet sec 624, sends
 * the probes and says so -- `ok SENT ADDRESS`, or `ok 0 - WHY` when none
 * could go -- which is the clients' `probed`. Who answered is `get lan` (sec 659):
 * `ok N KEY,HOST,PORT,AT ...`, the hellos heard from local-scope addresses
 * since the last probe, AT in seconds -- only peers this host knows, since
 * nobody else answers a probe. */
static int node_lan_discover(fzn_rpc_t *c, int probe, fzn_rpc_lan_discover_resp_t *out) {
	memset(out, 0, sizeof(*out));
	const char *rest = NULL;
	size_t rest_len = 0, at = 0, sent = 0, n = 0;
	int rc;
	if (probe) {
		rc = fzn_rpc_node(c, "fetch", "lan", 3, &rest, &rest_len);
		if (rc != FZN_RPC_OK) return rc;
		if (!node_number(rest, rest_len, &at, &sent) || at >= rest_len) return unreadable(c);
		out->probed = sent > 0;
	}
	rc = fzn_rpc_node(c, "get", "lan", 3, &rest, &rest_len);
	if (rc != FZN_RPC_OK) return rc;
	at = 0;
	if (!node_number(rest, rest_len, &at, &n)) return unreadable(c);
	size_t seen = 0;
	while (at < rest_len) {
		size_t end = at;
		while (end < rest_len && rest[end] != ' ') end++;
		const char *q = rest + at, *stop = rest + end, *f, *host;
		size_t f_len, host_len;
		at = end < rest_len ? end + 1 : end;
		seen++;
		uint8_t key[32];
		uint64_t port = 0, when = 0;
		if (!node_field(&q, stop, &f, &f_len) || !node_key(f, f_len, key) ||
		    !node_field(&q, stop, &host, &host_len) || !host_len ||
		    !node_field(&q, stop, &f, &f_len) || !node_u64(f, f_len, &port) || port > 65535 ||
		    !node_field(&q, stop, &f, &f_len) || !node_u64(f, f_len, &when))
			return unreadable(c);
		if (out->count >= FZN_RPC_LAN_DISCOVER_LIST_MAX) continue;
		fzn_rpc_lan_seen_entry_t *e = &out->entries[out->count];
		memcpy(e->host_pubkey, key, 32);
		const int w = snprintf(e->address, sizeof e->address, "%.*s:%llu", (int)host_len, host,
		                       (unsigned long long)port);
		if (w < 0 || (size_t)w >= sizeof e->address) return unreadable(c);
		e->address_len = (size_t)w;
		e->seen_at = when;
		out->count++;
	}
	return seen == n ? FZN_RPC_OK : unreadable(c);
}

/* `delivery_list` on fuzznetd (sec 284): the clients' list is what is still owed
 * -- this host's lines to a contact not yet settled -- so it is `list
 * message`, every page, its `out` lines to a contact whose state is not
 * `settled`: `delivered` is the clients' delivered, and `-`, `handed-over` and
 * `not-delivered` are not yet. The commitment is the line's id and the
 * first send its send time; fuzznetd counts no attempts. A group's lines
 * are not the clients' outbox and are left out. fuzznet's walk reaches its newest
 * FZN_MESSAGES_WALK_MAX (4096) lines, so a line owed from before those is
 * not seen. */
static int node_delivery_list(fzn_rpc_t *c, fzn_rpc_delivery_list_resp_t *out) {
	memset(out, 0, sizeof(*out));
	size_t from = 0;
	for (unsigned page = 0; page <= 4096u; page++) {
		char arg[32];
		const int arg_len = snprintf(arg, sizeof arg, "message %zu", from);
		const char *rest = NULL;
		size_t rest_len = 0;
		const int rc = fzn_rpc_node(c, "list", arg, (size_t)arg_len, &rest, &rest_len);
		if (rc != FZN_RPC_OK) return rc;
		size_t at = 0, start = 0, shown = 0, more = 0, listed = 0;
		if (!node_number(rest, rest_len, &at, &start) || !node_number(rest, rest_len, &at, &shown) ||
		    !node_number(rest, rest_len, &at, &more) || start != from || more > 1)
			return unreadable(c);
		while (at < rest_len) {
			size_t end = at;
			while (end < rest_len && rest[end] != ' ') end++;
			fzn_rpc_inbox_entry_t line;
			const char *state = NULL;
			size_t state_len = 0;
			const int kind = node_line(rest + at, end - at, &line, NULL, &state, &state_len);
			at = end < rest_len ? end + 1 : end;
			listed++;
			if (!kind) return unreadable(c);
			if (kind != 1 || !line.outgoing || (state_len == 7 && memcmp(state, "settled", 7) == 0))
				continue;
			if (out->count >= FZN_RPC_DELIVERY_LIST_MAX) continue;
			fzn_rpc_delivery_entry_t *d = &out->entries[out->count++];
			memcpy(d->commitment, line.commitment, 16);
			memcpy(d->peer_name, line.sender_name, line.sender_name_len);
			d->peer_name_len = line.sender_name_len;
			d->delivered = state_len == 9 && memcmp(state, "delivered", 9) == 0;
			d->first_sent = line.stime;
		}
		if (listed != shown) return unreadable(c);
		from += shown;
		if (!more || !shown) break;
	}
	return FZN_RPC_OK;
}

/* Capabilities on fuzznetd (sec 284). fuzznet grants per capability, not by
 * a type: of the clients' six, ADMIN is `grant admin KEY`, answered with the
 * chain as `h<HOP> ...`, and kept on the grantee by `set admin CHAIN|PATH`
 * (fuzznet sec 658), which then starts that daemon again in place. The
 * chain travels as its text in `chain_blob`, as a card does. The other five
 * -- host-manage, store, relay, send, peer-manage -- have no fuzznet grant
 * and are refused, never made as some other; and fuzznet's grants take no
 * expiry, so a grant asked to end is refused rather than made for ever. */
static int node_cap_grant(fzn_rpc_t *c, fzn_rpc_capability_type_t type, const uint8_t grantee[32],
                          uint64_t expires, fzn_rpc_cap_grant_resp_t *out) {
	memset(out, 0, sizeof(*out));
	if (type != FZN_RPC_CAP_ADMIN)
		return node_unasked(c, FZN_RPC_ERR_UNKNOWN_MSG_TYPE, "the node grants no such capability");
	if (expires)
		return node_unasked(c, FZN_RPC_ERR_UNKNOWN_MSG_TYPE,
		                    "the node's grants do not expire, so one asked to end is not made");
	char hex[65], arg[16 + 64 + 1];
	fzn_hex_encode(grantee, 32, hex);
	const char *rest = NULL;
	size_t rest_len = 0;
	const int rc =
	    fzn_rpc_node(c, "grant", arg, (size_t)snprintf(arg, sizeof arg, "admin %s", hex), &rest,
	                  &rest_len);
	if (rc != FZN_RPC_OK) return rc;
	if (!rest_len || rest[0] != 'h' || rest_len > sizeof(out->chain_blob)) return unreadable(c);
	memcpy(out->chain_blob, rest, rest_len);
	out->chain_blob_len = rest_len;
	return FZN_RPC_OK;
}

/* `set admin CHAIN`, or by a staged file when the chain passes the line. */
static int node_cap_install(fzn_rpc_t *c, fzn_rpc_capability_type_t type, const uint8_t *chain,
                            size_t chain_len) {
	if (type != FZN_RPC_CAP_ADMIN)
		return node_unasked(c, FZN_RPC_ERR_UNKNOWN_MSG_TYPE,
		                    "the node keeps no such chain: its other grants arrive by the journal");
	if (!chain_len || chain[0] != 'h' || memchr(chain, '\n', chain_len) ||
	    memchr(chain, '\0', chain_len))
		return node_unasked(c, FZN_RPC_ERR_MALFORMED, "that is not a fuzznet admin chain (h<HOP> ...)");
	char arg[FZN_REQUEST_MAX], path[NODE_STAGE_MAX] = "";
	int arg_len = snprintf(arg, sizeof arg, "admin %.*s", (int)chain_len, (const char *)chain);
	if (arg_len < 0 || (size_t)arg_len > FZN_REQUEST_MAX - 5u) {
		const int fd = node_stage_file(c, "chain", path);
		if (fd < 0) return node_unasked(c, FZN_RPC_ERR_STORAGE_IO, "could not stage the chain for the node");
		const int wrote = write(fd, chain, chain_len) == (ssize_t)chain_len;
		close(fd);
		if (!wrote) {
			unlink(path);
			return node_unasked(c, FZN_RPC_ERR_STORAGE_IO, "could not stage the chain for the node");
		}
		arg_len = snprintf(arg, sizeof arg, "admin %s", path);
	}
	const char *rest = NULL;
	size_t rest_len = 0;
	const int rc = fzn_rpc_node(c, "set", arg, (size_t)arg_len, &rest, &rest_len);
	if (path[0]) unlink(path);
	/* Kept, and fuzznetd starts again in place to act with it. */
	if (rc == FZN_RPC_OK) node_wait_serving(c);
	return rc;
}

/* Location on fuzznetd (sec 284): the stream `location`, fuzznet sec 632.
 * Sharing is a grant of a level, and fuzznet's levels are the clients' precisions
 * in the clients' order -- 0 exact, 1 about a kilometre, 2 about ten -- each a
 * rendition the writer puts in the record. A grant is the user's, an estate
 * setting carried to every host (fuzznet sec 660, sec 103's rule): `ok`
 * when it became the user's, `ok host` when this host may not set the
 * estate's settings and it holds for this host's own stream alone --
 * `reaches_siblings`, which must not say a withdrawal travelled that did
 * not (control.h). */
static int node_location_share(fzn_rpc_t *c, const char *peer, size_t peer_len, int enable,
                               uint8_t precision, int *reaches_siblings) {
	if (reaches_siblings) *reaches_siblings = 0;
	if (!peer_len || !node_who_fits(peer_len) || memchr(peer, ' ', peer_len) ||
	    precision > FZN_RPC_LOCATION_PRECISION_MAX)
		return encode_failed(c);
	char arg[64 + NODE_WHO_MAX];
	const int arg_len = enable ? snprintf(arg, sizeof arg, "stream location %.*s %u", (int)peer_len,
	                                      peer, (unsigned)precision)
	                           : snprintf(arg, sizeof arg, "stream location %.*s", (int)peer_len, peer);
	const char *rest = NULL;
	size_t rest_len = 0;
	const int rc = fzn_rpc_node(c, enable ? "grant" : "revoke", arg, (size_t)arg_len, &rest,
	                             &rest_len);
	if (rc != FZN_RPC_OK) return rc;
	if (rest_len == 4 && memcmp(rest, "host", 4) == 0) return FZN_RPC_OK; /* this host's alone */
	if (rest_len) return unreadable(c);
	if (reaches_siblings) *reaches_siblings = 1;
	return FZN_RPC_OK;
}

/* `fetch stream location WHO`: asked at once of WHO's hosts; what they
 * answer is read later, as the clients' fetch is. */
static int node_location_fetch(fzn_rpc_t *c, const char *target, size_t target_len) {
	if (!target_len || !node_who_fits(target_len) || memchr(target, ' ', target_len))
		return encode_failed(c);
	char arg[64 + NODE_WHO_MAX];
	return node_ack(c, "fetch", arg,
	                snprintf(arg, sizeof arg, "stream location %.*s", (int)target_len, target));
}

/* A file fetched through fuzznetd (sec 284): `fetch file REF`, the whole
 * reference -- root, key and length -- since a file is fetched as what it
 * is, from whoever holds it, and the clients' address is not taken. By a root
 * alone, fuzznetd uses the reference it holds for it (fuzznet sec 634: one
 * a sibling handed on), and holding none answers its usage, said here as
 * what is missing. fuzznetd keeps no transfer id; the fetch's progress is
 * `blob_status`'s. */
static int node_file_fetch(fzn_rpc_t *c, const uint8_t root[32], const uint8_t *key,
                           uint64_t size, fzn_rpc_blob_fetch_resp_t *out) {
	memset(out, 0, sizeof(*out));
	char hex[65], arg[16 + 144 + 1];
	fzn_hex_encode(root, 32, hex);
	int arg_len;
	if (key) {
		char key_hex[65];
		fzn_hex_encode(key, 32, key_hex);
		arg_len = snprintf(arg, sizeof arg, "file %s%s%016llx", hex, key_hex,
		                   (unsigned long long)size);
	} else {
		arg_len = snprintf(arg, sizeof arg, "file %s", hex);
	}
	const char *rest = NULL;
	size_t rest_len = 0;
	const int rc = fzn_rpc_node(c, "fetch", arg, (size_t)arg_len, &rest, &rest_len);
	if (rc == FZN_RPC_ERR_MALFORMED && !key)
		return fail(c, FZN_RPC_ERR_MALFORMED,
		            "the node holds no reference for that file: fetch it by its whole reference");
	return rc;
}

/* fuzznet sec 638's reports. A capability's name maps onto the clients' admin, and
 * fuzznet's member, share and retention onto the node types capability.h
 * keeps for them. The listings used to carry admin's rows alone (step 3r),
 * which left out member, the capability a joined device lives on, so a
 * device that had joined listed only `admin INVALID`. A name this build does
 * not know is still left out, since nothing could say what it is. */
static int node_cap_type(const char *name, size_t len, fzn_rpc_capability_type_t *out) {
	static const struct {
		const char *name;
		fzn_rpc_capability_type_t type;
	} names[] = {{"admin", FZN_RPC_CAP_ADMIN},
	             {"member", FZN_RPC_CAP_NODE_MEMBER},
	             {"share", FZN_RPC_CAP_NODE_SHARE},
	             {"retention", FZN_RPC_CAP_NODE_RETENTION}};
	for (size_t i = 0; i < sizeof names / sizeof names[0]; i++) {
		if (strlen(names[i].name) == len && memcmp(names[i].name, name, len) == 0) {
			*out = names[i].type;
			return 1;
		}
	}
	return 0;
}

/* `list capability`: `ok N NAME,HOLDS,HOPS,EXPIRES ...`, HOLDS verified as
 * answered -- neither expired nor revoked, which it does not tell apart, so
 * `revoked` is not set from it. */
static int node_cap_list(fzn_rpc_t *c, fzn_rpc_cap_list_resp_t *out) {
	memset(out, 0, sizeof(*out));
	const char *rest = NULL;
	size_t rest_len = 0, at = 0, n = 0;
	const int rc = fzn_rpc_node(c, "list", "capability", 10, &rest, &rest_len);
	if (rc != FZN_RPC_OK) return rc;
	if (!node_number(rest, rest_len, &at, &n)) return unreadable(c);
	size_t seen = 0;
	while (at < rest_len) {
		size_t end = at;
		while (end < rest_len && rest[end] != ' ') end++;
		const char *q = rest + at, *stop = rest + end, *name, *f;
		size_t name_len, f_len;
		at = end < rest_len ? end + 1 : end;
		seen++;
		uint64_t holds = 0, hops = 0, expires = 0;
		if (!node_field(&q, stop, &name, &name_len) || !node_field(&q, stop, &f, &f_len) ||
		    !node_u64(f, f_len, &holds) || !node_field(&q, stop, &f, &f_len) ||
		    !node_u64(f, f_len, &hops) || !node_field(&q, stop, &f, &f_len) ||
		    !node_u64(f, f_len, &expires))
			return unreadable(c);
		fzn_rpc_capability_type_t type;
		if (!node_cap_type(name, name_len, &type) || out->count >= FZN_RPC_CAP_TYPE_COUNT) continue;
		fzn_rpc_cap_list_entry_t *e = &out->entries[out->count++];
		e->type = type;
		e->valid = holds != 0;
		e->hop_count = (int)hops;
		e->expires_at = expires;
	}
	return seen == n ? FZN_RPC_OK : unreadable(c);
}

/* `list grant [FROM]`: `ok TOTAL FROM GRANTEE,NAME,EXPIRES,STANDS ...`,
 * every grant this node signed, STANDS read from the revocations. fuzznetd
 * says no grant time, so `granted_at` is 0. */
static int node_cap_granted(fzn_rpc_t *c, fzn_rpc_cap_granted_resp_t *out) {
	memset(out, 0, sizeof(*out));
	size_t from = 0;
	for (unsigned page = 0; page <= 4096u; page++) {
		char arg[32];
		const int arg_len = snprintf(arg, sizeof arg, "grant %zu", from);
		const char *rest = NULL;
		size_t rest_len = 0;
		const int rc = fzn_rpc_node(c, "list", arg, (size_t)arg_len, &rest, &rest_len);
		if (rc != FZN_RPC_OK) return rc;
		size_t at = 0, total = 0, start = 0, listed = 0;
		if (!node_number(rest, rest_len, &at, &total) || !node_number(rest, rest_len, &at, &start) ||
		    start != from)
			return unreadable(c);
		while (at < rest_len) {
			size_t end = at;
			while (end < rest_len && rest[end] != ' ') end++;
			const char *q = rest + at, *stop = rest + end, *f, *name;
			size_t f_len, name_len;
			at = end < rest_len ? end + 1 : end;
			listed++;
			uint8_t grantee[32];
			uint64_t expires = 0, stands = 0;
			if (!node_field(&q, stop, &f, &f_len) || !node_key(f, f_len, grantee) ||
			    !node_field(&q, stop, &name, &name_len) || !node_field(&q, stop, &f, &f_len) ||
			    !node_u64(f, f_len, &expires) || !node_field(&q, stop, &f, &f_len) ||
			    !node_u64(f, f_len, &stands))
				return unreadable(c);
			fzn_rpc_capability_type_t type;
			if (!node_cap_type(name, name_len, &type) || out->count >= FZN_RPC_GRANT_LIST_MAX) continue;
			fzn_rpc_cap_granted_entry_t *e = &out->entries[out->count++];
			e->type = type;
			memcpy(e->grantee_pubkey, grantee, 32);
			e->expires_at = expires;
			e->revoked = stands == 0;
		}
		from += listed;
		if (!listed || from >= total) break;
	}
	return FZN_RPC_OK;
}

/* `get relay`: `ok ENABLED QUOTA WINDOW N KEY,USED,REFUSED ...`, each peer
 * whose window runs, named by its key in hex (fuzznet sec 596). */
static int node_relay_status(fzn_rpc_t *c, fzn_rpc_relay_status_resp_t *out) {
	memset(out, 0, sizeof(*out));
	const char *rest = NULL;
	size_t rest_len = 0, at = 0, enabled = 0, quota = 0, window = 0, n = 0;
	const int rc = fzn_rpc_node(c, "get", "relay", 5, &rest, &rest_len);
	if (rc != FZN_RPC_OK) return rc;
	if (!node_number(rest, rest_len, &at, &enabled) || !node_number(rest, rest_len, &at, &quota) ||
	    !node_number(rest, rest_len, &at, &window) || !node_number(rest, rest_len, &at, &n))
		return unreadable(c);
	out->enabled = enabled != 0;
	out->quota_bytes = quota;
	out->window_s = window;
	while (at < rest_len) {
		size_t end = at;
		while (end < rest_len && rest[end] != ' ') end++;
		const char *q = rest + at, *stop = rest + end, *key, *f;
		size_t key_len, f_len;
		at = end < rest_len ? end + 1 : end;
		uint64_t used = 0, refused = 0;
		if (!node_field(&q, stop, &key, &key_len) || !key_len || key_len > FZN_RPC_PEER_ADDRESS_MAX ||
		    !node_field(&q, stop, &f, &f_len) || !node_u64(f, f_len, &used) ||
		    !node_field(&q, stop, &f, &f_len) || !node_u64(f, f_len, &refused))
			return unreadable(c);
		if (out->count >= FZN_RPC_RELAY_STATUS_LIST_MAX) continue;
		fzn_rpc_relay_peer_entry_t *e = &out->entries[out->count++];
		memcpy(e->peer, key, key_len);
		e->peer_len = key_len;
		e->bytes_used = used;
		e->refused = refused;
	}
	return out->count == n || out->count == FZN_RPC_RELAY_STATUS_LIST_MAX ? FZN_RPC_OK : unreadable(c);
}

/* `sibling_set_address` on fuzznetd: the sibling's own `net/address`, set as
 * this estate's setting for that host, `set setting host=KEY net/address
 * HOST PORT` (fuzznet sec 638), the sibling named as `sibling_list` names
 * it. Who may set another host's setting is fuzznetd's to say. */
static int node_sibling_set_address(fzn_rpc_t *c, const char *name, size_t name_len,
                                    const char *address, size_t address_len) {
	size_t host_len = 0, port = 0;
	if (!node_split_address(address, address_len, &host_len, &port))
		return node_unasked(c, FZN_RPC_ERR_MALFORMED, "an address is HOST:PORT");
	char hex[65], arg[FZN_REQUEST_MAX];
	const int rc = node_sibling_named(c, name, name_len, hex);
	if (rc != FZN_RPC_OK) return rc;
	return node_ack(c, "set", arg,
	                snprintf(arg, sizeof arg, "setting host=%s net/address %.*s %zu", hex,
	                         (int)host_len, address, port));
}

/* `status` on fuzznetd (sec 284), from the verbs that say each part:
 * - `get identity`: this host's key and the user's root; a host that is its
 *   estate's own root (HOST is ROOT) holds the root's secret, the clients'
 *   `is_root`. Its name is the first sixteen hex of its key, as a
 *   sibling's is, fuzznet keeping no host names.
 * - `list capability`: `cross_signed` is the member capability holding.
 * - `get message owed` (fuzznet sec 661): `HELD DELIVERED MORE`, held
 *   undelivered and delivered unsettled; the clients' `outbox_held` is both, as
 *   it counts every message not yet settled, and `outbox_delivered` the
 *   second. MORE says the counts are lower bounds, which the clients' answer has
 *   no field for.
 * - `get node` (fuzznet sec 687): `peer_port`, the port this node serves
 *   peers on, read back from its socket. Before, it was `net/address`'s,
 *   which is where others reach a member and is unset on a node nobody
 *   configured, though the node serves on a port all the same.
 * the clients' settle and delegate counters are of mechanisms fuzznetd does not
 * have, so 0 there is true; it says no creation times, which are 0. */
static int node_status(fzn_rpc_t *c, fzn_rpc_status_resp_t *out) {
	memset(out, 0, sizeof(*out));
	const char *rest = NULL;
	size_t rest_len = 0, at = 0;
	int rc = fzn_rpc_node(c, "get", "identity", 8, &rest, &rest_len);
	if (rc != FZN_RPC_OK) return rc;
	if (rest_len != 129 || rest[64] != ' ' || !node_key(rest, 64, out->host_pubkey) ||
	    !node_key(rest + 65, 64, out->user_pubkey))
		return unreadable(c);
	out->has_host = 1;
	out->is_root = memcmp(out->host_pubkey, out->user_pubkey, 32) == 0;
	memcpy(out->host_name, rest, 16);
	out->host_name_len = 16;
	/* This device's own name where it has one, `host/name` (fuzznet sec
	 * 847): `ok SCOPE VALUE`, VALUE escaped, or `ok absent`. The key's first
	 * sixteen otherwise, as before. */
	{
		const char *nm = NULL;
		size_t nm_len = 0;
		static const char ask[] = "setting host host/name";
		if (fzn_rpc_node(c, "get", ask, sizeof ask - 1, &nm, &nm_len) == FZN_RPC_OK) {
			const char *sp = memchr(nm, ' ', nm_len);
			size_t got = 0;
			int cut = 0;
			char named[sizeof out->host_name];
			if (sp && node_unescape(sp + 1, nm_len - (size_t)(sp + 1 - nm), named, sizeof named - 1,
			                        &got, &cut) &&
			    got && !cut) {
				memcpy(out->host_name, named, got);
				out->host_name[got] = '\0';
				out->host_name_len = got;
			}
		}
	}

	rc = fzn_rpc_node(c, "list", "capability", 10, &rest, &rest_len);
	if (rc != FZN_RPC_OK) return rc;
	const char *member = NULL;
	for (size_t i = 0; i + 9 <= rest_len; i++)
		if ((i == 0 || rest[i - 1] == ' ') && memcmp(rest + i, "member,", 7) == 0) member = rest + i + 7;
	out->cross_signed = member && member < rest + rest_len && member[0] == '1';

	rc = fzn_rpc_node(c, "get", "message owed", 12, &rest, &rest_len);
	if (rc != FZN_RPC_OK) return rc;
	size_t held = 0, delivered = 0, more = 0;
	at = 0;
	if (!node_number(rest, rest_len, &at, &held) || !node_number(rest, rest_len, &at, &delivered) ||
	    !node_number(rest, rest_len, &at, &more) || at != rest_len)
		return unreadable(c);
	out->outbox_held = held + delivered;
	out->outbox_delivered = delivered;

	rc = fzn_rpc_node(c, "get", "node", 4, &rest, &rest_len);
	if (rc != FZN_RPC_OK) return rc;
	/* `ok udp PORT started UNIX`, word pairs read by name since more may
	 * come; PORT `-` when it serves on none. */
	const char *p = rest, *end = rest + rest_len, *name, *value;
	size_t name_len, value_len;
	while (node_word(&p, end, &name, &name_len) && node_word(&p, end, &value, &value_len)) {
		uint64_t port = 0;
		if (name_len == 3 && memcmp(name, "udp", 3) == 0 && !(value_len == 1 && value[0] == '-')) {
			if (!node_u64(value, value_len, &port) || !port || port > 65535) return unreadable(c);
			out->peer_port = (uint16_t)port;
		}
	}
	return FZN_RPC_OK;
}

void fzn_rpc_peer_shares(fzn_rpc_t *c, fzn_rpc_peer_list_resp_t *out) {
	node_peer_shares(c, out);
}

int fzn_rpc_peer_list(fzn_rpc_t *c, fzn_rpc_peer_list_resp_t *out) {
	return node_peer_list(c, out);
}

int fzn_rpc_group_list(fzn_rpc_t *c, fzn_rpc_group_list_resp_t *out) {
	return node_group_list(c, out);
}

int fzn_rpc_group_members(fzn_rpc_t *c, const char *group, size_t group_len,
                           fzn_rpc_group_show_resp_t *out) {
	uint8_t self[32];
	const int rc = node_identity_root(c, self);
	return rc == FZN_RPC_OK ? node_group_members(c, group, group_len, self, out) : rc;
}

int fzn_rpc_group_show(fzn_rpc_t *c, const char *group, size_t group_len,
                        fzn_rpc_group_show_resp_t *out) {
	return node_group_show(c, group, group_len, out);
}

int fzn_rpc_group_history_show(fzn_rpc_t *c, const char *group, size_t group_len,
                                const char *peer, size_t peer_len,
                                fzn_rpc_group_history_show_resp_t *out) {
	return node_group_history(c, group, group_len, peer, peer_len, out);
}

/* ---- step 2 (sec 281) ---- */

int fzn_rpc_file_remove(fzn_rpc_t *c, const uint8_t root[FZN_RPC_BLOB_HASH_LEN]) {
	char arg[8 + 2 * FZN_RPC_BLOB_HASH_LEN + 1];
	memcpy(arg, "file ", 5);
	fzn_hex_encode(root, FZN_RPC_BLOB_HASH_LEN, arg + 5);
	const char *rest = NULL;
	size_t rest_len = 0;
	return fzn_rpc_node(c, "remove", arg, 5 + 2 * FZN_RPC_BLOB_HASH_LEN, &rest, &rest_len);
}

int fzn_rpc_file_share(fzn_rpc_t *c, const uint8_t root[FZN_RPC_BLOB_HASH_LEN], const char *to,
                        int share) {
	char hex[65], arg[8 + 64 + 2 + NODE_WHO_MAX + 2];
	fzn_hex_encode(root, 32, hex);
	const char *rest = NULL;
	size_t rest_len = 0;
	if (!to) {
		const int n = snprintf(arg, sizeof arg, "file %s %s", hex, share ? "public" : "private");
		return fzn_rpc_node(c, "set", arg, (size_t)n, &rest, &rest_len);
	}
	const size_t to_len = strlen(to);
	const size_t name_len = to[0] == '@' ? to_len - 1 : to_len;
	if (!name_len || !node_who_fits(name_len) || memchr(to, ' ', to_len)) return encode_failed(c);
	const int n = snprintf(arg, sizeof arg, "file %s %s", hex, to);
	return fzn_rpc_node(c, share ? "grant" : "revoke", arg, (size_t)n, &rest, &rest_len);
}

int fzn_rpc_file_shares(fzn_rpc_t *c, const uint8_t root[FZN_RPC_BLOB_HASH_LEN],
                         fzn_rpc_file_share_t **out, size_t *room, size_t *count) {
	*count = 0;
	char hex[65];
	fzn_hex_encode(root, 32, hex);
	size_t from = 0;
	for (unsigned page = 0; page < (1u << 16); page++) {
		char arg[8 + 64 + 32];
		const int arg_len = snprintf(arg, sizeof arg, "file %s shares %zu", hex, from);
		const char *rest = NULL;
		size_t rest_len = 0, at = 0, total = 0, start = 0, listed = 0;
		int rc = fzn_rpc_node(c, "get", arg, (size_t)arg_len, &rest, &rest_len);
		if (rc != FZN_RPC_OK) return rc;
		if (!node_number(rest, rest_len, &at, &total) || !node_number(rest, rest_len, &at, &start) ||
		    start != from)
			return unreadable(c);
		const char *p = rest + at, *end = rest + rest_len, *w;
		size_t w_len;
		while (node_word(&p, end, &w, &w_len)) {
			listed++;
			rc = room_for(c, (void **)out, room, *count + 1, sizeof **out);
			if (rc != FZN_RPC_OK) return rc;
			fzn_rpc_file_share_t *s = &(*out)[*count];
			memset(s, 0, sizeof *s);
			if (w_len == 8 && memcmp(w, "everyone", 8) == 0) {
				s->kind = FZN_RPC_FILE_SHARE_EVERYONE;
				(*count)++;
				continue;
			}
			/* KIND,KEY,NAME, the name possibly empty. */
			const char *q = w, *stop = w + w_len, *f;
			size_t f_len;
			if (!node_field(&q, stop, &f, &f_len)) return unreadable(c);
			if (f_len == 7 && memcmp(f, "contact", 7) == 0)
				s->kind = FZN_RPC_FILE_SHARE_CONTACT;
			else if (f_len == 5 && memcmp(f, "group", 5) == 0)
				s->kind = FZN_RPC_FILE_SHARE_GROUP;
			else
				return unreadable(c);
			if (!node_field(&q, stop, &f, &f_len) || !node_key(f, f_len, s->key)) return unreadable(c);
			const size_t name_len = (size_t)(stop - q);
			if (name_len > FZN_RPC_PEER_NAME_MAX) return unreadable(c);
			memcpy(s->name, q, name_len);
			s->name[name_len] = '\0';
			(*count)++;
		}
		from += listed;
		if (!listed || from >= total) return FZN_RPC_OK;
	}
	return FZN_RPC_OK;
}

int fzn_rpc_file_shared_with(fzn_rpc_t *c, const char *contact, fzn_rpc_root_t **roots, size_t *room,
                              size_t *count) {
	*count = 0;
	const size_t contact_len = contact ? strlen(contact) : 0;
	if (!contact_len || !node_who_fits(contact_len) || memchr(contact, ' ', contact_len))
		return encode_failed(c);
	size_t from = 0;
	for (unsigned page = 0; page < (1u << 16); page++) {
		char arg[24 + NODE_WHO_MAX + 24];
		const int arg_len = snprintf(arg, sizeof arg, "file shared %s %zu", contact, from);
		const char *rest = NULL;
		size_t rest_len = 0, at = 0, total = 0, start = 0, listed = 0;
		int rc = fzn_rpc_node(c, "get", arg, (size_t)arg_len, &rest, &rest_len);
		if (rc != FZN_RPC_OK) return node_explain_who(c, rc, "", contact, contact_len);
		if (!node_number(rest, rest_len, &at, &total) || !node_number(rest, rest_len, &at, &start) ||
		    start != from)
			return unreadable(c);
		const char *p = rest + at, *end = rest + rest_len, *w;
		size_t w_len;
		while (node_word(&p, end, &w, &w_len)) {
			listed++;
			rc = room_for(c, (void **)roots, room, *count + 1, sizeof **roots);
			if (rc != FZN_RPC_OK) return rc;
			if (!node_key(w, w_len, (*roots)[*count])) return unreadable(c);
			(*count)++;
		}
		from += listed;
		if (!listed || from >= total) return FZN_RPC_OK;
	}
	return FZN_RPC_OK;
}

int fzn_rpc_blob_status(fzn_rpc_t *c, const uint8_t root[FZN_RPC_BLOB_HASH_LEN],
                         fzn_rpc_blob_status_resp_t *out) {
	return node_file_status(c, root, out);
}

int fzn_rpc_blob_fetch(fzn_rpc_t *c, const uint8_t root[FZN_RPC_BLOB_HASH_LEN],
                        fzn_rpc_blob_fetch_resp_t *out) {
	return node_file_fetch(c, root, NULL, 0, out);
}

int fzn_rpc_blob_fetch_at(fzn_rpc_t *c, const uint8_t root[FZN_RPC_BLOB_HASH_LEN], uint64_t offset) {
	char hex[65], arg[16 + 64 + 1];
	fzn_hex_encode(root, 32, hex);
	const char *rest = NULL;
	size_t rest_len = 0;
	int rc = fzn_rpc_node(c, "get", arg, (size_t)snprintf(arg, sizeof arg, "reference %s", hex),
	                       &rest, &rest_len);
	if (rc != FZN_RPC_OK) return rc;
	uint8_t r[32], k[32];
	uint64_t length = 0;
	if (!node_ref(rest, rest_len, r, k, &length)) return unreadable(c);
	char fetch[16 + 144 + 32];
	const int fetch_len = snprintf(fetch, sizeof fetch, "file %.144s at %llu", rest,
	                               (unsigned long long)offset);
	return fzn_rpc_node(c, "fetch", fetch, (size_t)fetch_len, &rest, &rest_len);
}

int fzn_rpc_blob_fetch_ref(fzn_rpc_t *c, const uint8_t root[FZN_RPC_BLOB_HASH_LEN],
                            const uint8_t key[32], uint64_t size, fzn_rpc_blob_fetch_resp_t *out) {
	return node_file_fetch(c, root, key, size, out);
}

int fzn_rpc_blob_export(fzn_rpc_t *c, const uint8_t root[FZN_RPC_BLOB_HASH_LEN], const uint8_t *key,
                         const char *path, size_t path_len, fzn_rpc_blob_export_resp_t *out) {
	return node_file_export(c, root, key, path, path_len, out);
}

int fzn_rpc_blob_add(fzn_rpc_t *c, const char *path, size_t path_len, uint8_t tier,
                      fzn_rpc_blob_add_resp_t *out) {
	return node_file_put(c, path, path_len, tier, out);
}

/*
 * The location settings are the node's own declared ones (fuzznet secs 678 and
 * 686: location/enabled, location/every, location/accuracy and location/gpsd
 * HOST PORT), read and set by the general path below like every other key; the
 * node judges and refuses a value itself. Until 2026-11-09 the clients kept
 * five keys of their own spelling here (location.sample_interval_s,
 * location.max_accuracy_m, location.gpsd.host and .port), mapped onto those
 * cells and judged by common/settings.c first. That layer read only `1` as
 * on, where the node takes `on` as well since sec 686, so a host set to `on`
 * by anything but these clients sampled while every screen said it did not.
 */

int fzn_rpc_config_get(fzn_rpc_t *c, const char *key, size_t key_len, fzn_rpc_config_get_resp_t *out) {
	/* Every key is the node's declared setting (fuzznet sec 686). */
	return node_config_get(c, key, key_len, out);
}

int fzn_rpc_sibling_list(fzn_rpc_t *c, fzn_rpc_sibling_list_resp_t *out) {
	return node_siblings(c, out);
}

int fzn_rpc_peer_request_list(fzn_rpc_t *c, fzn_rpc_peer_request_list_resp_t *out) {
	return node_peer_request_list(c, out);
}

int fzn_rpc_card_show(fzn_rpc_t *c, const char *display_name, size_t display_name_len,
                       fzn_rpc_card_show_resp_t *out) {
	return node_card_show(c, display_name, display_name_len, out);
}

static int send_in_binary(fzn_rpc_t *c, const char *who, size_t who_len, int attach, const uint8_t *root,
                          const char *text, size_t text_len, int *by_verb);

int fzn_rpc_message_send(fzn_rpc_t *c, const char *peer, size_t peer_len, const char *text,
                          size_t text_len) {
	int by_verb = 1;
	const int rc = send_in_binary(c, peer, peer_len, 0, NULL, text, text_len, &by_verb);
	return by_verb ? node_message_add(c, "", peer, peer_len, text, text_len) : rc;
}

int fzn_rpc_message_attach(fzn_rpc_t *c, const char *to, size_t to_len, int is_group,
                            const uint8_t root[32], const char *name, size_t name_len) {
	int by_verb = 1;
	const int rc = send_in_binary(c, to, to_len, 1, root, name, name_len, &by_verb);
	return by_verb ? node_message_attach(c, is_group ? "@" : "", to, to_len, root, name, name_len) : rc;
}

int fzn_rpc_group_send(fzn_rpc_t *c, const char *group, size_t group_len, const char *text,
                        size_t text_len) {
	int by_verb = 1;
	const int rc = send_in_binary(c, group, group_len, 0, NULL, text, text_len, &by_verb);
	return by_verb ? node_message_add(c, "@", group, group_len, text, text_len) : rc;
}

/* ---- step 3 (sec 281) ---- */

int fzn_rpc_library_play(fzn_rpc_t *c, const uint8_t root[FZN_RPC_BLOB_HASH_LEN], uint64_t offset,
                          uint16_t want, fzn_rpc_library_play_resp_t *out) {
	return node_library_play(c, root, offset, want, out);
}

int fzn_rpc_library_show(fzn_rpc_t *c, const uint8_t root[FZN_RPC_BLOB_HASH_LEN],
                          fzn_rpc_library_show_resp_t *out) {
	return node_library_show(c, root, out);
}

int fzn_rpc_library_detail(fzn_rpc_t *c, fzn_rpc_library_list_all_t *list, size_t from, size_t count) {
	if (from >= list->count) return FZN_RPC_OK;
	if (count > list->count - from) count = list->count - from;
	return node_library_fill(c, list->entries + from, count, 1);
}

int fzn_rpc_library_list(fzn_rpc_t *c, fzn_rpc_library_list_all_t *out) {
	return node_library_list(c, out);
}

int fzn_rpc_library_add(fzn_rpc_t *c, const fzn_rpc_library_add_req_t *entry) {
	return node_library_add(c, entry);
}

int fzn_rpc_transfer_list(fzn_rpc_t *c, fzn_rpc_transfer_list_resp_t *out) {
	return node_transfer_list(c, out);
}

int fzn_rpc_delivery_list(fzn_rpc_t *c, fzn_rpc_delivery_list_resp_t *out) {
	return node_delivery_list(c, out);
}

int fzn_rpc_config_set(fzn_rpc_t *c, const char *key, size_t key_len, const char *value,
                        size_t value_len, const char *expected, size_t expected_len,
                        int *restart_required) {
	if (restart_required) *restart_required = 0;
	return node_config_set(c, key, key_len, value, value_len, expected, expected_len);
}

int fzn_rpc_lan_discover(fzn_rpc_t *c, int probe, fzn_rpc_lan_discover_resp_t *out) {
	return node_lan_discover(c, probe, out);
}

int fzn_rpc_addr_observe(fzn_rpc_t *c, int probe, fzn_rpc_addr_observe_resp_t *out) {
	return node_addr_observe(c, probe, out);
}

int fzn_rpc_relay_status(fzn_rpc_t *c, fzn_rpc_relay_status_resp_t *out) {
	return node_relay_status(c, out);
}

int fzn_rpc_blob_scrub(fzn_rpc_t *c, const uint8_t root[FZN_RPC_BLOB_HASH_LEN], uint64_t from,
                        fzn_rpc_blob_scrub_resp_t *out) {
	(void)from; /* fuzznetd checks a whole file in one answer */
	return node_file_check(c, root, out);
}

/* ---- step 4 (sec 281) ---- */

int fzn_rpc_notes_list(fzn_rpc_t *c, const uint8_t parent[32], const uint8_t from[32],
                        int from_group, fzn_rpc_notes_list_resp_t *out) {
	if (from_group && !from) return encode_failed(c);
	if (from_group) return node_group_notes_list(c, from, parent, out);
	char tree[80] = "note";
	if (from && !node_is_zero(from, 32)) node_shared_tree(from, tree);
	return node_notes_list(c, tree, parent, out);
}

int fzn_rpc_notes_show(fzn_rpc_t *c, const uint8_t id[32], const uint8_t from[32],
                        int from_group, fzn_rpc_notes_show_resp_t *out) {
	if (from_group && !from) return encode_failed(c);
	if (from_group) return node_group_notes_show(c, from, id, out);
	char tree[80] = "note";
	if (from && !node_is_zero(from, 32)) node_shared_tree(from, tree);
	return node_notes_show(c, tree, id, out);
}

int fzn_rpc_notes_import(fzn_rpc_t *c, const uint8_t parent[32], const char *path,
                          size_t path_len, fzn_rpc_notes_import_resp_t *out) {
	memset(out, 0, sizeof(*out));
	char full[512], p[65], arg[16 + 64 + 24 + 512];
	if (!node_abs_path(path, path_len, full, sizeof full))
		return node_unasked(c, FZN_RPC_ERR_MALFORMED, "that path cannot be named to the node");
	node_parent(parent, p);
	/* A page at a time, from NEXT until it is 0 (fuzznet sec 991); bounded
	 * as every paging here is, should a node answer without moving on. */
	size_t from = 0;
	for (unsigned page = 0; page < (1u << 20); page++) {
		const int arg_len = from ? snprintf(arg, sizeof arg, "import %s %zu %s", p, from, full)
		                         : snprintf(arg, sizeof arg, "import %s %s", p, full);
		if (arg_len < 0 || (size_t)arg_len > FZN_REQUEST_MAX - 5u)
			return node_unasked(c, FZN_RPC_ERR_MALFORMED, "that path is too long to name to the node");
		const char *rest = NULL;
		size_t rest_len = 0, at = 0;
		const int rc = fzn_rpc_node(c, "add", arg, (size_t)arg_len, &rest, &rest_len);
		if (rc != FZN_RPC_OK) return rc;
		/* `IMPORTED ALREADY UNDATED REFUSED PENDING ATTACHED NEXT`, then each
		 * refused note as REASON,TITLE. */
		size_t v[7];
		for (size_t k = 0; k < 7; k++)
			if (!node_number(rest, rest_len, &at, &v[k])) return unreadable(c);
		out->imported += v[0];
		out->already += v[1];
		out->undated += v[2];
		out->refused += v[3];
		out->pending += v[4];
		out->attached += v[5];
		const char *q = rest + at, *end = rest + rest_len, *w;
		size_t w_len;
		while (node_word(&q, end, &w, &w_len)) {
			const char *comma = memchr(w, ',', w_len);
			if (!comma) return unreadable(c);
			const size_t why_len = (size_t)(comma - w);
			char title[FZN_RPC_NOTES_TITLE_MAX + 1];
			size_t len = 0;
			int cut = 0;
			if (!node_unescape(comma + 1, w_len - why_len - 1, title, sizeof title - 1, &len, &cut))
				return unreadable(c);
			if (out->refused_titles_len + why_len + 2 + len + 1 >= sizeof out->refused_titles) continue;
			memcpy(out->refused_titles + out->refused_titles_len, w, why_len);
			out->refused_titles_len += why_len;
			memcpy(out->refused_titles + out->refused_titles_len, ": ", 2);
			out->refused_titles_len += 2;
			memcpy(out->refused_titles + out->refused_titles_len, title, len);
			out->refused_titles_len += len;
			out->refused_titles[out->refused_titles_len++] = '\n';
		}
		out->refused_titles[out->refused_titles_len] = '\0';
		if (!v[6]) return FZN_RPC_OK;
		if (v[6] <= from) return unreadable(c); /* a page that did not move on */
		from = v[6];
	}
	return unreadable(c);
}

int fzn_rpc_notes_add(fzn_rpc_t *c, const uint8_t parent[32], const char *title,
                       size_t title_len, const char *text, size_t text_len,
                       uint64_t created_at_ms, int skip_if_exists, uint16_t content_type,
                       fzn_rpc_notes_add_resp_t *out) {
	(void)created_at_ms; /* fuzznetd stamps a note when it writes it */
	return node_notes_add(c, parent, title, title_len, text, text_len, skip_if_exists,
	                      content_type, out);
}

int fzn_rpc_notes_attach(fzn_rpc_t *c, const uint8_t parent[32], const uint8_t root[32],
                          const uint8_t key[32], uint64_t length, const char *title,
                          size_t title_len, uint8_t id[32]) {
	/* The title is the rest of the line, as the node reads it: a newline in
	 * it would end the request. Empty is refused, as an unnamed file in a
	 * listing is one nobody can choose. */
	if (!title_len || title_len > FZN_RPC_NOTES_TITLE_MAX || memchr(title, '\n', title_len) ||
	    memchr(title, '\r', title_len))
		return encode_failed(c);
	char parent_hex[65], root_hex[65], key_hex[65];
	fzn_hex_encode(parent, 32, parent_hex);
	fzn_hex_encode(root, 32, root_hex);
	fzn_hex_encode(key, 32, key_hex);
	char arg[16 + 64 + 1 + 144 + 1 + FZN_RPC_NOTES_TITLE_MAX + 1];
	const int arg_len = snprintf(arg, sizeof arg, "attachment %s %s%s%016llx %.*s", parent_hex,
	                             root_hex, key_hex, (unsigned long long)length, (int)title_len,
	                             title);
	if (arg_len < 0 || (size_t)arg_len >= sizeof arg) return encode_failed(c);
	const char *rest = NULL;
	size_t rest_len = 0;
	const int rc = fzn_rpc_node(c, "add", arg, (size_t)arg_len, &rest, &rest_len);
	if (rc != FZN_RPC_OK) return rc;
	return rest_len == 64 && node_key(rest, 64, id) ? FZN_RPC_OK : unreadable(c);
}

static int node_note_ref(fzn_rpc_t *c, const char *tree, const uint8_t id[32], uint8_t root[32],
                         uint8_t key[32], uint64_t *length) {
	char hex[65], arg[80 + 64 + 8];
	fzn_hex_encode(id, 32, hex);
	const int arg_len = snprintf(arg, sizeof arg, "%s %s ref", tree, hex);
	const char *rest = NULL;
	size_t rest_len = 0;
	const int rc = fzn_rpc_node(c, "get", arg, (size_t)arg_len, &rest, &rest_len);
	if (rc != FZN_RPC_OK) return rc;
	return node_ref(rest, rest_len, root, key, length) ? FZN_RPC_OK : unreadable(c);
}

int fzn_rpc_note_ref(fzn_rpc_t *c, const uint8_t id[32], const uint8_t *from, int from_group,
                      uint8_t root[32], uint8_t key[32], uint64_t *length) {
	char tree[80];
	if (!from) return node_note_ref(c, "note", id, root, key, length);
	if (!from_group) {
		node_shared_tree(from, tree);
		return node_note_ref(c, tree, id, root, key, length);
	}
	/* A group's notebook: in whichever sharer's tree holds the note, as a
	 * note shown there is found (node_group_notes_show). */
	uint8_t keys[NODE_GROUP_SHARERS_MAX][32];
	size_t n = 0;
	int rc = node_group_sharers(c, from, keys, &n);
	if (rc != FZN_RPC_OK) return rc;
	rc = fail(c, FZN_RPC_ERR_STORAGE_IO, "no such note in the group's notebook");
	for (size_t i = 0; i < n; i++) {
		node_shared_tree(keys[i], tree);
		rc = node_note_ref(c, tree, id, root, key, length);
		if (rc == FZN_RPC_OK) return FZN_RPC_OK;
	}
	return rc;
}

/* `get note ID meta`: `ok COLOUR LABELS` (fuzznet sec 869), LABELS escaped
 * with the NUL between two as `%00`. */
int fzn_rpc_note_meta(fzn_rpc_t *c, const uint8_t id[32], char *labels, size_t cap, size_t *len,
                       uint32_t *colour) {
	*len = 0;
	*colour = 0;
	char arg[8 + 64 + 8], hex[65];
	fzn_hex_encode(id, 32, hex);
	const int arg_len = snprintf(arg, sizeof arg, "note %s meta", hex);
	const char *rest = NULL;
	size_t rest_len = 0;
	const int rc = fzn_rpc_node(c, "get", arg, (size_t)arg_len, &rest, &rest_len);
	if (rc != FZN_RPC_OK) return rc;
	uint32_t v = 0;
	if (rest_len < 8 || (rest_len > 8 && rest[8] != ' ')) return unreadable(c);
	for (size_t i = 0; i < 8; i++) {
		const char ch = rest[i];
		const int d = ch >= '0' && ch <= '9'   ? ch - '0'
		              : ch >= 'a' && ch <= 'f' ? ch - 'a' + 10
		              : ch >= 'A' && ch <= 'F' ? ch - 'A' + 10
		                                       : -1;
		if (d < 0) return unreadable(c);
		v = v << 4 | (uint32_t)d;
	}
	int cut = 0;
	if (rest_len > 9 && !node_unescape(rest + 9, rest_len - 9, labels, cap, len, &cut))
		return unreadable(c);
	if (cut) return fail(c, FZN_RPC_ERR_BUFFER_TOO_SMALL, "that note's labels are longer than kept here");
	*colour = v;
	return FZN_RPC_OK;
}

/* `set note ID labels [LABEL]...`: `labels` NUL between two, each escaped
 * as one word; none clears them. An empty label, or the lot past what one
 * request carries, is refused here in words. */
int fzn_rpc_note_labels_set(fzn_rpc_t *c, const uint8_t id[32], const char *labels, size_t len) {
	char arg[FZN_REQUEST_MAX], hex[65];
	fzn_hex_encode(id, 32, hex);
	int at = snprintf(arg, sizeof arg, "note %s labels", hex);
	size_t from = 0;
	while (len && from <= len) {
		const char *end = memchr(labels + from, 0, len - from);
		const size_t one = end ? (size_t)(end - (labels + from)) : len - from;
		if (!one) return node_unasked(c, FZN_RPC_ERR_MALFORMED, "a label cannot be empty");
		size_t wrote = 0;
		if ((size_t)at + 1 >= sizeof arg ||
		    fzn_escape((const uint8_t *)labels + from, one, arg + at + 1,
		               sizeof arg - 5u - (size_t)at - 1, &wrote) != one)
			return node_unasked(c, FZN_RPC_ERR_MALFORMED, "those labels are too long to send");
		arg[at] = ' ';
		at += 1 + (int)wrote;
		from += one + 1;
	}
	return node_ack(c, "set", arg, at);
}

int fzn_rpc_notes_edit(fzn_rpc_t *c, const uint8_t id[32], uint8_t fields, const char *title,
                        size_t title_len, const char *text, size_t text_len) {
	return node_notes_edit(c, id, fields, title, title_len, text, text_len);
}

int fzn_rpc_notes_share(fzn_rpc_t *c, const uint8_t subtree[32], const char *peer,
                         size_t peer_len, int to_group, int backfill,
                         fzn_rpc_notes_share_resp_t *out) {
	memset(out, 0, sizeof(*out));
	out->sub_cmd = FZN_RPC_NOTES_SUBCMD_SHARE; /* fuzznetd counts nothing withheld */
	return node_notes_share(c, 1, subtree, peer, peer_len, to_group, backfill);
}

int fzn_rpc_notes_unshare(fzn_rpc_t *c, const uint8_t subtree[32], const char *peer,
                           size_t peer_len, int to_group) {
	return node_notes_share(c, 0, subtree, peer, peer_len, to_group, 0);
}

int fzn_rpc_notes_shares(fzn_rpc_t *c, fzn_rpc_notes_shares_resp_t *out) {
	return node_notes_shares(c, out);
}

int fzn_rpc_notes_empty_trash(fzn_rpc_t *c, fzn_rpc_notes_empty_trash_resp_t *out) {
	return node_notes_empty_trash(c, out);
}

/* ---- step 5 (sec 281) ---- */

int fzn_rpc_group_create(fzn_rpc_t *c, const char *group, size_t group_len,
                          fzn_rpc_group_create_resp_t *out) {
	memset(out, 0, sizeof(*out));
	if (!node_name_ok(group, group_len))
		return node_unasked(c, FZN_RPC_ERR_INVALID_GROUP_NAME, fzn_rpc_err_str(FZN_RPC_ERR_INVALID_GROUP_NAME));
	char arg[8 + FZN_RPC_PEER_NAME_MAX + 1];
	const int arg_len = snprintf(arg, sizeof arg, "group %.*s", (int)group_len, group);
	const char *rest = NULL;
	size_t rest_len = 0;
	const int rc = fzn_rpc_node(c, "add", arg, (size_t)arg_len, &rest, &rest_len);
	if (rc != FZN_RPC_OK) return rc;
	/* `ok ID`, fuzznet sec 648. */
	return node_key(rest, rest_len, out->chat_id) ? FZN_RPC_OK : unreadable(c);
}

const char *fzn_rpc_group_nameless_label(const fzn_rpc_group_show_resp_t *v, size_t i) {
	if (i >= v->member_count) return "(not a contact)";
	return memcmp(v->members[i].root_pubkey, v->self_root, 32) == 0 ? "(you)" : "(not a contact)";
}

int fzn_rpc_group_add_member(fzn_rpc_t *c, const char *group, size_t group_len,
                              const char *peer, size_t peer_len) {
	return node_group_member(c, "add", group, group_len, peer, peer_len);
}

int fzn_rpc_group_remove_member(fzn_rpc_t *c, const char *group, size_t group_len,
                                 const char *peer, size_t peer_len) {
	return node_group_member(c, "remove", group, group_len, peer, peer_len);
}

int fzn_rpc_ring(fzn_rpc_t *c, const char *who, size_t who_len, uint8_t kinds,
                  char id[FZN_RPC_ID_HEX + 1]) {
	id[0] = '\0';
	if (!who_len || who_len > 16 * (FZN_RPC_PEER_NAME_MAX + 1) || memchr(who, ' ', who_len) ||
	    !kinds || kinds > (FZN_RPC_AUDIO | FZN_RPC_VIDEO))
		return encode_failed(c);
	char arg[16 + 16 * (FZN_RPC_PEER_NAME_MAX + 1) + 8];
	const char *k = kinds == FZN_RPC_AUDIO ? "audio" : kinds == FZN_RPC_VIDEO ? "video" : "both";
	const int arg_len = snprintf(arg, sizeof arg, "call %.*s %s", (int)who_len, who, k);
	const char *rest = NULL;
	size_t rest_len = 0;
	const int rc = fzn_rpc_node(c, "add", arg, (size_t)arg_len, &rest, &rest_len);
	if (rc != FZN_RPC_OK) return rc;
	if (rest_len != FZN_RPC_ID_HEX) return unreadable(c);
	for (size_t i = 0; i < rest_len; i++)
		if (hex_nibble(rest[i]) < 0) return unreadable(c);
	memcpy(id, rest, FZN_RPC_ID_HEX);
	id[FZN_RPC_ID_HEX] = '\0';
	return FZN_RPC_OK;
}

int fzn_rpc_respond(fzn_rpc_t *c, const char *id, const char *what) {
	if (!id || strlen(id) != FZN_RPC_ID_HEX ||
	    (strcmp(what, "answer") != 0 && strcmp(what, "decline") != 0 && strcmp(what, "hangup") != 0))
		return encode_failed(c);
	char arg[8 + FZN_RPC_ID_HEX + 16];
	return node_ack(c, "set", arg, snprintf(arg, sizeof arg, "call %s %s", id, what));
}

int fzn_rpc_ended(fzn_rpc_t *c, const char *id, char *reason, size_t cap) {
	if (cap) reason[0] = '\0';
	if (!id || strlen(id) != FZN_RPC_ID_HEX || cap < 2) return encode_failed(c);
	char arg[8 + FZN_RPC_ID_HEX];
	const int arg_len = snprintf(arg, sizeof arg, "call %s", id);
	const char *rest = NULL;
	size_t rest_len = 0;
	const int rc = fzn_rpc_node(c, "get", arg, (size_t)arg_len, &rest, &rest_len);
	if (rc != FZN_RPC_OK) return rc;
	/* `ok ended REASON`; any other `ok` is a call still live. */
	if (rest_len < 6 || memcmp(rest, "ended ", 6) != 0) return FZN_RPC_OK;
	const char *w = rest + 6;
	size_t n = rest_len - 6;
	while (n && (w[n - 1] == '\n' || w[n - 1] == '\r' || w[n - 1] == ' ')) n--;
	if (!n || n >= cap) return unreadable(c);
	for (size_t i = 0; i < n; i++)
		if (!((w[i] >= 'a' && w[i] <= 'z') || w[i] == '-')) return unreadable(c);
	memcpy(reason, w, n);
	reason[n] = '\0';
	return FZN_RPC_OK;
}

int fzn_rpc_missed(const char *reason) {
	return reason && (strcmp(reason, "hung-up") == 0 || strcmp(reason, "no-answer") == 0 ||
	                  strcmp(reason, "gone") == 0);
}

const char *fzn_rpc_ended_words(const char *reason) {
	static const struct {
		const char *word, *said;
	} words[] = {
		{"declined", "declined"},
		{"hung-up", "hung up"},
		{"no-answer", "not answered"},
		{"busy", "busy"},
		{"gone", "the other end went away"},
		{"unreachable", "could not be reached"},
		{"ended", "ended"},
		{"answered-elsewhere", "answered on another of your devices"},
		{"declined-elsewhere", "turned away on another of your devices"},
	};
	for (size_t i = 0; i < sizeof words / sizeof words[0]; i++)
		if (strcmp(reason, words[i].word) == 0) return words[i].said;
	return reason;
}

/* `list call`: `ok N ID,STATE,KINDS ...`, every live call. */
int fzn_rpc_calls(fzn_rpc_t *c, fzn_rpc_entry_t *out, size_t cap, size_t *count) {
	*count = 0;
	const char *rest = NULL;
	size_t rest_len = 0, at = 0, n = 0;
	const int rc = fzn_rpc_node(c, "list", "call", 4, &rest, &rest_len);
	if (rc != FZN_RPC_OK) return rc;
	if (!node_number(rest, rest_len, &at, &n)) return unreadable(c);
	const char *p = rest + at, *end = rest + rest_len, *w;
	size_t w_len;
	while (node_word(&p, end, &w, &w_len)) {
		const char *q = w, *stop = w + w_len, *f;
		size_t f_len;
		fzn_rpc_entry_t e;
		memset(&e, 0, sizeof e);
		if (!node_field(&q, stop, &f, &f_len) || f_len != FZN_RPC_ID_HEX) return unreadable(c);
		memcpy(e.id, f, FZN_RPC_ID_HEX);
		if (!node_field(&q, stop, &f, &f_len)) return unreadable(c);
		e.state = f_len == 10 && memcmp(f, "ringing-in", 10) == 0    ? FZN_RPC_RINGING_IN
		          : f_len == 11 && memcmp(f, "ringing-out", 11) == 0 ? FZN_RPC_RINGING_OUT
		          : f_len == 2 && memcmp(f, "up", 2) == 0            ? FZN_RPC_UP
		                                                            : 0;
		uint64_t kinds = 0;
		if (!e.state || !node_field(&q, stop, &f, &f_len) || !node_u64(f, f_len, &kinds) || kinds > 3)
			return unreadable(c);
		e.kinds = (uint8_t)kinds;
		/* USER, a fourth field since fuzznet f54d1dd: 64 hex, or `-`. */
		if (node_field(&q, stop, &f, &f_len) && f_len == 64) {
			char hex[65];
			memcpy(hex, f, 64);
			hex[64] = '\0';
			e.has_user = fzn_hex_decode(hex, e.user, sizeof e.user) == 0;
		}
		if (*count < cap) out[(*count)++] = e;
	}
	return FZN_RPC_OK;
}

int fzn_rpc_user_name(fzn_rpc_t *c, const uint8_t user[32], char *name, size_t cap) {
	static fzn_rpc_peer_list_resp_t peers;
	if (!cap) return 0;
	name[0] = '\0';
	if (fzn_rpc_peer_list(c, &peers) != FZN_RPC_OK) return 0;
	for (size_t i = 0; i < peers.count; i++)
		if (memcmp(peers.entries[i].root_pubkey, user, 32) == 0) {
			snprintf(name, cap, "%s", peers.entries[i].name);
			return 1;
		}
	return 0;
}

int fzn_rpc_frame_add(fzn_rpc_t *c, const char *id, uint8_t stream, uint32_t seq, uint32_t at,
                       const uint8_t *media, size_t len, int *sent) {
	*sent = 0;
	if (!id || strlen(id) != FZN_RPC_ID_HEX || !len || len > FZN_RPC_FRAME_MAX) return encode_failed(c);
	char arg[96 + 2 * FZN_RPC_FRAME_MAX];
	int n = snprintf(arg, sizeof arg, "frame %s %u %lu %lu 0 1 ", id, (unsigned)stream,
	                 (unsigned long)seq, (unsigned long)at);
	if (n < 0 || (size_t)n + 2 * len >= sizeof arg) return encode_failed(c);
	fzn_hex_encode(media, len, arg + n);
	n += (int)(2 * len);
	const char *rest = NULL;
	size_t rest_len = 0;
	const int rc = fzn_rpc_node(c, "add", arg, (size_t)n, &rest, &rest_len);
	if (rc != FZN_RPC_OK) return rc;
	if (rest_len == 4 && memcmp(rest, "sent", 4) == 0) *sent = 1;
	else if (!(rest_len == 4 && memcmp(rest, "lost", 4) == 0)) return unreadable(c);
	return FZN_RPC_OK;
}

/* `list frame ID FROM`: `ok TOTAL FROM STREAM,SEQ,AT,PIECE,PIECES,HEX,SENDER ...`. */
int fzn_rpc_frames(fzn_rpc_t *c, const char *id, uint64_t from, fzn_rpc_frame_t *out,
                    size_t cap, size_t *count, uint64_t *next) {
	*count = 0;
	*next = from;
	if (!id || strlen(id) != FZN_RPC_ID_HEX) return encode_failed(c);
	char arg[32 + FZN_RPC_ID_HEX];
	const int arg_len = snprintf(arg, sizeof arg, "frame %s %llu", id, (unsigned long long)from);
	const char *rest = NULL;
	size_t rest_len = 0, at = 0, total = 0, start = 0;
	const int rc = fzn_rpc_node(c, "list", arg, (size_t)arg_len, &rest, &rest_len);
	if (rc != FZN_RPC_OK) return rc;
	if (!node_number(rest, rest_len, &at, &total) || !node_number(rest, rest_len, &at, &start))
		return unreadable(c);
	/* The node keeps the last 64: past them, it answers from where it has. */
	uint64_t pos = start;
	const char *p = rest + at, *end = rest + rest_len, *w;
	size_t w_len;
	while (node_word(&p, end, &w, &w_len)) {
		const char *q = w, *stop = w + w_len, *f;
		size_t f_len;
		uint64_t v[5], sender = 0;
		for (int i = 0; i < 5; i++)
			if (!node_field(&q, stop, &f, &f_len) || !node_u64(f, f_len, &v[i])) return unreadable(c);
		const char *hex;
		size_t hex_len;
		if (!node_field(&q, stop, &hex, &hex_len) || hex_len % 2 || hex_len / 2 > sizeof out->media)
			return unreadable(c);
		if (q <= stop && (!node_field(&q, stop, &f, &f_len) || !node_u64(f, f_len, &sender)))
			return unreadable(c);
		pos++;
		if (*count >= cap) continue;
		fzn_rpc_frame_t *fr = &out[*count];
		fr->stream = (uint8_t)v[0];
		fr->seq = (uint32_t)v[1];
		fr->at = (uint32_t)v[2];
		fr->piece = (uint16_t)v[3];
		fr->pieces = (uint16_t)v[4];
		fr->sender = (uint16_t)sender;
		fr->len = hex_len / 2;
		for (size_t i = 0; i < fr->len; i++) {
			const int hi = hex_nibble(hex[2 * i]), lo = hex_nibble(hex[2 * i + 1]);
			if (hi < 0 || lo < 0) return unreadable(c);
			fr->media[i] = (uint8_t)(hi << 4 | lo);
		}
		(*count)++;
	}
	*next = pos;
	(void)total;
	return FZN_RPC_OK;
}

int fzn_rpc_quality(fzn_rpc_t *c, const char *id, uint8_t stream, fzn_rpc_quality_t *out) {
	memset(out, 0, sizeof *out);
	if (!id || strlen(id) != FZN_RPC_ID_HEX) return encode_failed(c);
	char arg[32 + FZN_RPC_ID_HEX];
	const int arg_len = snprintf(arg, sizeof arg, "call %s quality", id);
	const char *rest = NULL;
	size_t rest_len = 0;
	const int rc = fzn_rpc_node(c, "get", arg, (size_t)arg_len, &rest, &rest_len);
	if (rc != FZN_RPC_OK) return rc;
	const char *p = rest, *end = rest + rest_len, *w;
	size_t w_len;
	while (node_word(&p, end, &w, &w_len)) {
		const char *q = w, *stop = w + w_len, *f, *dir;
		size_t f_len, dir_len;
		uint64_t st = 0, v[5] = {0};
		if (!node_field(&q, stop, &f, &f_len) || !node_u64(f, f_len, &st) ||
		    !node_field(&q, stop, &dir, &dir_len))
			return unreadable(c);
		const int sent = dir_len == 4 && memcmp(dir, "sent", 4) == 0;
		const int n = sent ? 5 : 3;
		for (int i = 0; i < n; i++)
			if (!node_field(&q, stop, &f, &f_len) || !node_u64(f, f_len, &v[i])) return unreadable(c);
		if (st != stream) continue;
		if (sent) {
			out->have_sent = 1;
			out->sent_received = v[0];
			out->sent_lost = v[1];
			out->sent_jitter = v[2];
			out->last_at = v[3];
			out->held_ms = v[4];
		} else {
			out->have_received = 1;
			out->received = v[0];
			out->lost = v[1];
			out->jitter = v[2];
		}
	}
	return FZN_RPC_OK;
}

int fzn_rpc_group_admin(fzn_rpc_t *c, const char *group, size_t group_len, const char *peer,
                         size_t peer_len, int make, size_t *approvals, size_t *needed) {
	*approvals = 0;
	*needed = 0;
	if (!group_len || group_len > FZN_RPC_PEER_NAME_MAX || !peer_len || !node_who_fits(peer_len))
		return encode_failed(c);
	char arg[8 + FZN_RPC_PEER_NAME_MAX + NODE_WHO_MAX + 2];
	const int arg_len = snprintf(arg, sizeof arg, "admin %.*s %.*s", (int)group_len, group,
	                             (int)peer_len, peer);
	const char *rest = NULL;
	size_t rest_len = 0, at = 0;
	const int rc = fzn_rpc_node(c, make ? "add" : "remove", arg, (size_t)arg_len, &rest, &rest_len);
	if (rc != FZN_RPC_OK || !rest_len) return rc;
	/* `proposed APPROVALS NEEDED`: waiting for more admins. */
	if (rest_len < 9 || memcmp(rest, "proposed ", 9) != 0) return unreadable(c);
	at = 9;
	if (!node_number(rest, rest_len, &at, approvals) || !node_number(rest, rest_len, &at, needed) ||
	    !*needed)
		return unreadable(c);
	return FZN_RPC_OK;
}

int fzn_rpc_group_delete(fzn_rpc_t *c, const char *group, size_t group_len) {
	return node_group_name(c, "remove", group, group_len);
}

/* `list fork`: FROM SHOWN MORE, then `SUBJECT,HOST,AT,GROUNDS,VALUE` a row. A
 * subject and a value here are whole or the row is passed over: a side cut
 * short could be chosen and written back as what somebody decided. */
int fzn_rpc_fork_list(fzn_rpc_t *c, fzn_rpc_fork_side_t *sides, size_t cap, size_t *count) {
	size_t from = 0;
	*count = 0;
	for (;;) {
		char arg[32];
		const char *rest = NULL;
		size_t rest_len = 0, at = 0, first = 0, shown = 0, more = 0;
		const int rc = fzn_rpc_node(c, "list", arg,
		                             (size_t)snprintf(arg, sizeof arg, "fork %zu", from), &rest,
		                             &rest_len);
		if (rc != FZN_RPC_OK) return rc;
		if (!node_number(rest, rest_len, &at, &first) || !node_number(rest, rest_len, &at, &shown) ||
		    !node_number(rest, rest_len, &at, &more))
			return unreadable(c);
		for (size_t i = 0; i < shown; i++) {
			const char *end = memchr(rest + at, ' ', rest_len - at);
			const size_t row_len = end ? (size_t)(end - (rest + at)) : rest_len - at;
			const char *f[5], *row_end = rest + at + row_len;
			size_t f_len[5], n = 0;
			for (const char *p = rest + at; n < 5; n++) {
				const char *comma = n < 4 ? memchr(p, ',', (size_t)(row_end - p)) : NULL;
				if (n < 4 && !comma) return unreadable(c);
				f[n] = p;
				f_len[n] = (size_t)((comma ? comma : row_end) - p);
				p = comma ? comma + 1 : row_end;
			}
			at += row_len + (end ? 1 : 0);
			if (*count >= cap) return FZN_RPC_OK;
			fzn_rpc_fork_side_t *side = &sides[*count];
			uint64_t when = 0;
			size_t value_len = 0;
			if (f_len[0] > FZN_RPC_FORK_SUBJECT_MAX ||
			    !fzn_unescape((const uint8_t *)f[4], f_len[4], (uint8_t *)side->value,
			                  FZN_RPC_FORK_VALUE_MAX, &value_len))
				continue;
			if (!node_key(f[1], f_len[1], side->host) || !node_u64(f[2], f_len[2], &when))
				return unreadable(c);
			memcpy(side->subject, f[0], f_len[0]);
			side->subject[f_len[0]] = '\0';
			side->value[value_len] = '\0';
			side->at = when;
			(*count)++;
		}
		if (!more || !shown) return FZN_RPC_OK;
		from = first + shown;
	}
}

static const char fork_contact_name[] = "contact/name/";

int fzn_rpc_fork_settle(fzn_rpc_t *c, const char *subject, const char *value) {
	const size_t prefix = sizeof fork_contact_name - 1;
	if (strncmp(subject, fork_contact_name, prefix) != 0) {
		char esc[FZN_REQUEST_MAX], arg[FZN_REQUEST_MAX];
		const size_t esc_len = node_escape(value, strlen(value), esc, sizeof esc);
		if (!esc_len) return encode_failed(c);
		return node_ack(c, "set", arg,
		                snprintf(arg, sizeof arg, "setting estate %s %.*s", subject, (int)esc_len, esc));
	}
	/* The cell holds half the key, so the contact is found by that half. */
	static fzn_rpc_peer_list_resp_t peers;
	const int rc = fzn_rpc_peer_list(c, &peers);
	if (rc != FZN_RPC_OK) return rc;
	for (size_t i = 0; i < peers.count; i++) {
		char hex[65];
		fzn_hex_encode(peers.entries[i].root_pubkey, 32, hex);
		if (strncmp(hex, subject + prefix, 32) == 0)
			return fzn_rpc_peer_rename(c, peers.entries[i].root_pubkey, value, strlen(value));
	}
	return node_unasked(c, FZN_RPC_ERR_MALFORMED, "no contact here has that name's key");
}

void fzn_rpc_fork_subject_label(fzn_rpc_t *c, const char *subject, char *out, size_t cap) {
	const size_t prefix = sizeof fork_contact_name - 1;
	snprintf(out, cap, "%s", subject);
	if (strncmp(subject, fork_contact_name, prefix) != 0) return;
	static fzn_rpc_peer_list_resp_t peers;
	if (fzn_rpc_peer_list(c, &peers) != FZN_RPC_OK) return;
	for (size_t i = 0; i < peers.count; i++) {
		char hex[65];
		fzn_hex_encode(peers.entries[i].root_pubkey, 32, hex);
		if (strncmp(hex, subject + prefix, 32) == 0) {
			snprintf(out, cap, "a contact's name, %.*s", (int)peers.entries[i].name_len,
			         peers.entries[i].name);
			return;
		}
	}
	snprintf(out, cap, "a contact's name");
}

/* `get group GROUP water [FROM]`: TOTAL FROM MINE, then a row a host,
 * `MEMBER,HOST,HAVE,AT`, `-,-` for one that has said nothing. By host, so a
 * member is as far as the furthest of its hosts. */
/* A roster's members ordered by key and by name, for the water's rows to
 * find theirs by halving: each row walked every member, members squared --
 * 400 million compares a refresh at a group of 20000 (2026-11-10). Static,
 * as qsort carries no context; a call is never re-entered. */
static const fzn_rpc_group_member_entry_t *water_members;
static size_t *water_by_key, *water_by_name, water_room;

static int water_key_cmp(const void *a, const void *b) {
	return memcmp(water_members[*(const size_t *)a].root_pubkey,
	              water_members[*(const size_t *)b].root_pubkey, 32);
}

static int water_name_cmp3(const char *a, size_t a_len, const char *b, size_t b_len) {
	const int d = memcmp(a, b, a_len < b_len ? a_len : b_len);
	return d ? d : (a_len > b_len) - (a_len < b_len);
}

static int water_name_cmp(const void *a, const void *b) {
	const fzn_rpc_group_member_entry_t *x = &water_members[*(const size_t *)a];
	const fzn_rpc_group_member_entry_t *y = &water_members[*(const size_t *)b];
	return water_name_cmp3(x->name, x->name_len, y->name, y->name_len);
}

/* The first position in `order` whose member is not before the row, by key
 * when `key`, else by name. */
static size_t water_lower(const size_t *order, size_t n, const uint8_t *key, const char *name,
                          size_t name_len) {
	size_t lo = 0, hi = n;
	while (lo < hi) {
		const size_t mid = lo + (hi - lo) / 2;
		const fzn_rpc_group_member_entry_t *m = &water_members[order[mid]];
		const int d = key ? memcmp(m->root_pubkey, key, 32)
		                  : water_name_cmp3(m->name, m->name_len, name, name_len);
		if (d < 0)
			lo = mid + 1;
		else
			hi = mid;
	}
	return lo;
}

int fzn_rpc_group_water(fzn_rpc_t *c, const char *group, size_t group_len,
                         fzn_rpc_group_show_resp_t *out) {
	if (!group_len || group_len > FZN_RPC_PEER_NAME_MAX) return encode_failed(c);
	const size_t n = out->member_count;
	if (n > water_room) {
		size_t *k = realloc(water_by_key, n * sizeof *k);
		if (k) water_by_key = k;
		size_t *m = k ? realloc(water_by_name, n * sizeof *m) : NULL;
		if (!k || !m) return fail(c, FZN_RPC_ERR_STORAGE_IO, "out of memory for that list");
		water_by_name = m;
		water_room = n;
	}
	water_members = out->members;
	for (size_t i = 0; i < n; i++) water_by_key[i] = water_by_name[i] = i;
	if (n) {
		qsort(water_by_key, n, sizeof *water_by_key, water_key_cmp);
		qsort(water_by_name, n, sizeof *water_by_name, water_name_cmp);
	}
	size_t from = 0;
	for (;;) {
		char arg[16 + FZN_RPC_PEER_NAME_MAX + 32];
		const char *rest = NULL;
		size_t rest_len = 0, at = 0, total = 0, first = 0, mine = 0, rows = 0;
		const int rc = fzn_rpc_node(c, "get", arg,
		                             (size_t)snprintf(arg, sizeof arg, "group %.*s water %zu",
		                                              (int)group_len, group, from),
		                             &rest, &rest_len);
		if (rc != FZN_RPC_OK) return rc;
		if (!node_number(rest, rest_len, &at, &total) || !node_number(rest, rest_len, &at, &first) ||
		    !node_number(rest, rest_len, &at, &mine))
			return unreadable(c);
		out->own_high_seq = mine;
		while (at < rest_len) {
			const char *row = rest + at, *space = memchr(row, ' ', rest_len - at);
			const size_t row_len = space ? (size_t)(space - row) : rest_len - at;
			const char *c1 = memchr(row, ',', row_len);
			const char *c2 = c1 ? memchr(c1 + 1, ',', (size_t)(row + row_len - c1 - 1)) : NULL;
			const char *c3 = c2 ? memchr(c2 + 1, ',', (size_t)(row + row_len - c2 - 1)) : NULL;
			if (!c3) return unreadable(c);
			at += row_len + (space ? 1 : 0);
			rows++;
			if (c2[1] == '-') continue; /* nothing said yet */
			const size_t name_len = (size_t)(c1 - row);
			uint64_t have = 0;
			uint8_t key[32];
			if (!node_u64(c2 + 1, (size_t)(c3 - c2 - 1), &have)) return unreadable(c);
			const int by_key = node_key(row, name_len, key);
			const size_t *order = by_key ? water_by_key : water_by_name;
			/* Every member the row names, as the walk credited them all. */
			for (size_t j = water_lower(order, n, by_key ? key : NULL, row, name_len); j < n; j++) {
				fzn_rpc_group_member_entry_t *m = &out->members[order[j]];
				if (by_key ? memcmp(m->root_pubkey, key, 32) != 0
				           : water_name_cmp3(m->name, m->name_len, row, name_len) != 0)
					break;
				m->heard = 1;
				if (have > m->acked_seq) m->acked_seq = have;
			}
		}
		from = first + rows;
		if (!rows || from >= total) return FZN_RPC_OK;
	}
}

/* One field of a row, to its comma or its end, `-` read as empty. */
static const char *object_field(const char *p, const char *end, char *out, size_t cap) {
	const char *stop = memchr(p, ',', (size_t)(end - p));
	if (!stop) stop = end;
	size_t n = (size_t)(stop - p);
	if (n == 1 && *p == '-') n = 0;
	if (n >= cap) n = cap - 1;
	memcpy(out, p, n);
	out[n] = '\0';
	return stop < end ? stop + 1 : NULL;
}

static int object_add_text(fzn_rpc_t *c, const char *name, const char *values) {
	char arg[FZN_REQUEST_MAX];
	const int n = snprintf(arg, sizeof arg, "object %s%s%s", name, values && *values ? " " : "",
	                       values ? values : "");
	if (n < 0 || (size_t)n >= sizeof arg) return encode_failed(c);
	return node_ack(c, "add", arg, n);
}

static int object_set_text(fzn_rpc_t *c, const char *name, const char *value) {
	char arg[FZN_REQUEST_MAX];
	const int n = snprintf(arg, sizeof arg, "object %s %s", name, value);
	if (n < 0 || (size_t)n >= sizeof arg) return encode_failed(c);
	return node_ack(c, "set", arg, n);
}

static int object_remove_text(fzn_rpc_t *c, const char *name) {
	char arg[FZN_REQUEST_MAX];
	const int n = snprintf(arg, sizeof arg, "object %s", name);
	if (n < 0 || (size_t)n >= sizeof arg) return encode_failed(c);
	return node_ack(c, "remove", arg, n);
}

/* `get object NAME`: `VALUE AT BY ALLOWED`, or `absent`. */
static int object_get_text(fzn_rpc_t *c, const char *name, fzn_rpc_object_t *out, int *found) {
	char arg[FZN_REQUEST_MAX];
	const char *rest = NULL;
	size_t rest_len = 0;
	const int n = snprintf(arg, sizeof arg, "object %s", name);
	*found = 0;
	if (n < 0 || (size_t)n >= sizeof arg) return encode_failed(c);
	const int rc = fzn_rpc_node(c, "get", arg, (size_t)n, &rest, &rest_len);
	if (rc != FZN_RPC_OK) return rc;
	if (rest_len == 6 && memcmp(rest, "absent", 6) == 0) return FZN_RPC_OK;
	memset(out, 0, sizeof *out);
	snprintf(out->name, sizeof out->name, "%s", name);
	const char *p = rest, *end = rest + rest_len, *w;
	size_t w_len;
	if (!node_word(&p, end, &w, &w_len)) return unreadable(c);
	if (!(w_len == 1 && *w == '-')) snprintf(out->value, sizeof out->value, "%.*s", (int)w_len, w);
	if (!node_word(&p, end, &w, &w_len)) return unreadable(c);
	if (!(w_len == 1 && *w == '-') && !node_u64(w, w_len, &out->at_ms)) return unreadable(c);
	if (!node_word(&p, end, &w, &w_len)) return unreadable(c);
	if (!(w_len == 1 && *w == '-')) snprintf(out->by, sizeof out->by, "%.*s", (int)w_len, w);
	if (!node_word(&p, end, &w, &w_len)) return unreadable(c);
	snprintf(out->allowed, sizeof out->allowed, "%.*s", (int)w_len, w);
	*found = 1;
	return FZN_RPC_OK;
}

/* `list object [FROM]`: FROM SHOWN MORE, then `NAME,VALUE,AT,BY,ALLOWED`. */
/* `get sync-load` -> `ok LOAD VERDICT NAME,NOW,PEAK,MEAN,TREND ...`. */
int fzn_rpc_sync_load(fzn_rpc_t *c, fzn_rpc_sync_load_t *out) {
	memset(out, 0, sizeof(*out));
	const char *rest = NULL;
	size_t rest_len = 0, at = 0, load = 0;
	const int rc = fzn_rpc_node(c, "get", "sync-load", 9, &rest, &rest_len);
	if (rc != FZN_RPC_OK) return rc;
	if (!node_number(rest, rest_len, &at, &load)) return unreadable(c);
	out->load_pct = load;
	const char *q = rest + at, *end = rest + rest_len, *w;
	size_t w_len;
	if (!node_word(&q, end, &w, &w_len) || !w_len || w_len >= sizeof out->verdict) return unreadable(c);
	memcpy(out->verdict, w, w_len);
	while (node_word(&q, end, &w, &w_len)) {
		if (out->count >= FZN_RPC_SYNC_QUEUES_MAX) break;
		fzn_rpc_sync_queue_t *e = &out->queues[out->count];
		const char *f, *stop = w + w_len, *p = w;
		size_t f_len;
		if (!node_field(&p, stop, &f, &f_len) || !f_len || f_len >= sizeof e->name) return unreadable(c);
		memcpy(e->name, f, f_len);
		uint64_t *nums[] = {&e->now, &e->peak, &e->mean};
		for (size_t i = 0; i < 3; i++)
			if (!node_field(&p, stop, &f, &f_len) || !node_u64(f, f_len, nums[i])) return unreadable(c);
		/* Fields past the trend are a newer node's, and left. */
		if (!node_field(&p, stop, &f, &f_len) || !f_len || f_len >= sizeof e->trend)
			return unreadable(c);
		memcpy(e->trend, f, f_len);
		out->count++;
	}
	return FZN_RPC_OK;
}

const char *fzn_rpc_sync_load_advice(const fzn_rpc_sync_load_t *v) {
	if (!v->verdict[0] || strcmp(v->verdict, "ok") == 0) return NULL;
	/* fuzznet's own advice (its sec 966), in the clients' words: a queue
	 * the rounds do not drain is a host told to keep or be shared more than
	 * it can carry, which rules answer, not waiting. */
	return strcmp(v->verdict, "growing") == 0
	           ? "more is waiting to sync each round than the rounds clear: narrow what this "
	             "host keeps with retention rules, or what is shared with it"
	           : "every sync round is taking its whole period: this host is syncing more "
	             "than it keeps up with; narrow what it keeps with retention rules, or what "
	             "is shared with it";
}

static int object_list_text(fzn_rpc_t *c, fzn_rpc_object_list_resp_t *out) {
	out->count = 0;
	size_t from = 0;
	for (;;) {
		char arg[32];
		const char *rest = NULL;
		size_t rest_len = 0, at = 0, first = 0, shown = 0, more = 0;
		int rc = fzn_rpc_node(c, "list", arg, (size_t)snprintf(arg, sizeof arg, "object %zu", from),
		                       &rest, &rest_len);
		if (rc != FZN_RPC_OK) return rc;
		if (!node_number(rest, rest_len, &at, &first) || !node_number(rest, rest_len, &at, &shown) ||
		    !node_number(rest, rest_len, &at, &more) || first != from)
			return unreadable(c);
		const char *p = rest + at, *end = rest + rest_len, *w;
		size_t w_len, rows = 0;
		while (node_word(&p, end, &w, &w_len)) {
			rows++;
			rc = room_for(c, &out->entries, &out->room, out->count + 1, sizeof *out->entries);
			if (rc != FZN_RPC_OK) return rc;
			fzn_rpc_object_t *o = &out->entries[out->count];
			memset(o, 0, sizeof *o);
			char when[24];
			const char *q = object_field(w, w + w_len, o->name, sizeof o->name);
			q = q ? object_field(q, w + w_len, o->value, sizeof o->value) : NULL;
			q = q ? object_field(q, w + w_len, when, sizeof when) : NULL;
			q = q ? object_field(q, w + w_len, o->by, sizeof o->by) : NULL;
			if (!q) return unreadable(c);
			object_field(q, w + w_len, o->allowed, sizeof o->allowed);
			if (when[0] && !node_u64(when, strlen(when), &o->at_ms)) return unreadable(c);
			out->count++;
		}
		from = first + rows;
		if (!more || !rows) return FZN_RPC_OK;
	}
}

int fzn_rpc_group_earlier(fzn_rpc_t *c, const char *group, size_t group_len, int on) {
	if (!group_len || group_len > FZN_RPC_PEER_NAME_MAX) return encode_failed(c);
	char arg[8 + FZN_RPC_PEER_NAME_MAX + 16];
	return node_ack(c, "set", arg,
	                snprintf(arg, sizeof arg, "group %.*s backfill %d", (int)group_len, group, !!on));
}

int fzn_rpc_group_earlier_get(fzn_rpc_t *c, const char *group, size_t group_len, int *on) {
	if (!group_len || group_len > FZN_RPC_PEER_NAME_MAX) return encode_failed(c);
	char arg[8 + FZN_RPC_PEER_NAME_MAX + 16];
	const char *rest = NULL;
	size_t rest_len = 0;
	const int rc = fzn_rpc_node(c, "get", arg,
	                             (size_t)snprintf(arg, sizeof arg, "group %.*s backfill",
	                                              (int)group_len, group),
	                             &rest, &rest_len);
	if (rc != FZN_RPC_OK) return rc;
	if (rest_len != 1 || (rest[0] != '0' && rest[0] != '1')) return unreadable(c);
	*on = rest[0] == '1';
	return FZN_RPC_OK;
}

static int node_retention(fzn_rpc_t *c, const char *verb, const char *rule, size_t rule_len) {
	char arg[FZN_REQUEST_MAX];
	if (!rule_len || rule_len > sizeof arg - 16u || memchr(rule, '\n', rule_len))
		return encode_failed(c);
	return node_ack(c, verb, arg, snprintf(arg, sizeof arg, "retention %.*s", (int)rule_len, rule));
}

int fzn_rpc_retention_add(fzn_rpc_t *c, const char *rule, size_t rule_len) {
	return node_retention(c, "add", rule, rule_len);
}

int fzn_rpc_retention_remove(fzn_rpc_t *c, const char *rule, size_t rule_len) {
	return node_retention(c, "remove", rule, rule_len);
}

/* `list retention`: a count, then each rule as one %XX-escaped word. */
int fzn_rpc_retention_list(fzn_rpc_t *c, char *text, size_t cap, size_t *text_len) {
	const char *rest = NULL;
	size_t rest_len = 0, at = 0, count = 0, used = 0;
	*text_len = 0;
	const int rc = fzn_rpc_node(c, "list", "retention", 9, &rest, &rest_len);
	if (rc != FZN_RPC_OK) return rc;
	if (!cap || !node_number(rest, rest_len, &at, &count)) return unreadable(c);
	for (; at < rest_len && used + 2u < cap; at++) {
		const char ch = rest[at];
		if (ch == ' ') {
			text[used++] = '\n';
		} else if (ch == '%' && at + 2u < rest_len && hex_nibble(rest[at + 1]) >= 0 &&
		           hex_nibble(rest[at + 2]) >= 0) {
			text[used++] = (char)(hex_nibble(rest[at + 1]) << 4 | hex_nibble(rest[at + 2]));
			at += 2;
		} else {
			text[used++] = ch;
		}
	}
	if (used && count) text[used++] = '\n';
	text[used] = '\0';
	*text_len = used;
	return FZN_RPC_OK;
}

int fzn_rpc_peer_request_send(fzn_rpc_t *c, const uint8_t *card_blob, size_t card_blob_len,
                               const char *local_name, size_t local_name_len,
                               const char *proposed_display_name,
                               size_t proposed_display_name_len,
                               fzn_rpc_peer_request_send_resp_t *out) {
	return node_peer_request_send(c, card_blob, card_blob_len, local_name, local_name_len,
	                              proposed_display_name, proposed_display_name_len, out);
}

int fzn_rpc_peer_request_approve(fzn_rpc_t *c, const uint8_t requester_host_pubkey[32],
                                  const char *name, size_t name_len,
                                  fzn_rpc_peer_request_approve_resp_t *out) {
	memset(out, 0, sizeof(*out));
	const int free_rc = node_name_is_free(c, name, name_len, requester_host_pubkey);
	if (free_rc != FZN_RPC_OK) return free_rc;
	const int rc = node_request_answer(c, requester_host_pubkey, name, name_len);
	if (rc == FZN_RPC_OK) {
		memcpy(out->host_pubkey, requester_host_pubkey, 32);
	}
	return rc;
}

int fzn_rpc_peer_request_reject(fzn_rpc_t *c, const uint8_t requester_host_pubkey[32]) {
	return node_request_answer(c, requester_host_pubkey, NULL, 0);
}

int fzn_rpc_peer_rename(fzn_rpc_t *c, const uint8_t key[32], const char *name, size_t name_len) {
	if (!node_name_ok(name, name_len))
		return node_unasked(c, FZN_RPC_ERR_INVALID_PEER_NAME, fzn_rpc_err_str(FZN_RPC_ERR_INVALID_PEER_NAME));
	char hex[65], arg[16 + 64 + FZN_RPC_PEER_NAME_MAX];
	fzn_hex_encode(key, 32, hex);
	const int arg_len = snprintf(arg, sizeof arg, "contact %.*s %s", (int)name_len, name, hex);
	const char *rest = NULL;
	size_t rest_len = 0;
	return fzn_rpc_node(c, "add", arg, (size_t)arg_len, &rest, &rest_len);
}

int fzn_rpc_peer_remove(fzn_rpc_t *c, const char *name, size_t name_len) {
	return node_peer_remove(c, name, name_len);
}

int fzn_rpc_sibling_set_address(fzn_rpc_t *c, const char *name, size_t name_len,
                                 const char *address, size_t address_len) {
	return node_sibling_set_address(c, name, name_len, address, address_len);
}

int fzn_rpc_sibling_remove(fzn_rpc_t *c, const char *name, size_t name_len) {
	return node_sibling_remove(c, name, name_len);
}

/* ---- step 6 (sec 281) ---- */

int fzn_rpc_cap_list(fzn_rpc_t *c, fzn_rpc_cap_list_resp_t *out) {
	return node_cap_list(c, out);
}

int fzn_rpc_cap_granted(fzn_rpc_t *c, fzn_rpc_cap_granted_resp_t *out) {
	return node_cap_granted(c, out);
}

int fzn_rpc_cap_grant(fzn_rpc_t *c, fzn_rpc_capability_type_t type,
                       const uint8_t grantee_pubkey[32], uint64_t expires_in_seconds,
                       fzn_rpc_cap_grant_resp_t *out) {
	return node_cap_grant(c, type, grantee_pubkey, expires_in_seconds, out);
}

int fzn_rpc_cap_install(fzn_rpc_t *c, fzn_rpc_capability_type_t type, const uint8_t *chain_blob,
                         size_t chain_blob_len) {
	return node_cap_install(c, type, chain_blob, chain_blob_len);
}

/* The next space-separated word of a reply, 0 at its end. */
static int node_word(const char **p, const char *end, const char **w, size_t *w_len) {
	while (*p < end && **p == ' ') (*p)++;
	if (*p >= end) return 0;
	*w = *p;
	while (*p < end && **p != ' ') (*p)++;
	*w_len = (size_t)(*p - *w);
	return 1;
}

/* Degrees with exactly seven places, as fuzznet prints them
 * (`fzn_location_degrees_text`), into 1e-7 degrees. */
static int node_degrees(const char *p, size_t len, int32_t *out) {
	size_t i = 0;
	int neg = 0;
	if (i < len && p[i] == '-') neg = 1, i++;
	int64_t v = 0;
	size_t whole = 0, frac = 0;
	for (; i < len && p[i] >= '0' && p[i] <= '9' && whole < 3; i++, whole++) v = v * 10 + (p[i] - '0');
	if (!whole || i >= len || p[i] != '.') return 0;
	for (i++; i < len && p[i] >= '0' && p[i] <= '9' && frac < 7; i++, frac++) v = v * 10 + (p[i] - '0');
	if (frac != 7 || i != len || v > 1800000000) return 0;
	*out = (int32_t)(neg ? -v : v);
	return 1;
}

/* A field that is a number, or `-` for what a fix lacks. */
static int node_u64_or_none(const char *p, size_t len, uint64_t *out, int *has) {
	*has = !(len == 1 && p[0] == '-');
	*out = 0;
	return !*has || node_u64(p, len, out);
}

/* The hosts whose track `origin` names, as `list location` labels them:
 * the first eight bytes of the key, as hex. This host's own for an empty
 * origin; for a contact, each device `list device` names. */
static int node_location_hosts(fzn_rpc_t *c, const char *origin, size_t origin_len,
                               char hosts[][17], size_t cap, size_t *n) {
	const char *rest = NULL;
	size_t rest_len = 0;
	*n = 0;
	if (!origin_len) {
		const int rc = fzn_rpc_node(c, "get", "identity", 8, &rest, &rest_len);
		if (rc != FZN_RPC_OK) return rc;
		if (rest_len != 129) return unreadable(c);
		memcpy(hosts[0], rest, 16);
		hosts[0][16] = '\0';
		*n = 1;
		return FZN_RPC_OK;
	}
	if (!node_who_fits(origin_len) || memchr(origin, ' ', origin_len))
		return node_unasked(c, FZN_RPC_ERR_NO_PEER, "no such contact");
	size_t from = 0;
	for (unsigned page = 0; page < 16; page++) {
		char arg[16 + NODE_WHO_MAX + 24];
		const int arg_len = snprintf(arg, sizeof arg, "device %.*s %zu", (int)origin_len, origin, from);
		int rc = fzn_rpc_node(c, "list", arg, (size_t)arg_len, &rest, &rest_len);
		if (rc != FZN_RPC_OK) return rc;
		/* `ok TOTAL FROM KEY,ADDRESS,PORT ...` */
		size_t at = 0, total = 0, start = 0;
		if (!node_number(rest, rest_len, &at, &total) || !node_number(rest, rest_len, &at, &start))
			return unreadable(c);
		size_t rows = 0;
		while (at < rest_len) {
			size_t end = at;
			while (end < rest_len && rest[end] != ' ') end++;
			if (end - at < 64) return unreadable(c);
			if (*n < cap) {
				memcpy(hosts[*n], rest + at, 16);
				hosts[*n][16] = '\0';
				(*n)++;
			}
			rows++;
			at = end < rest_len ? end + 1 : end;
		}
		from = start + rows;
		if (!rows || from >= total) return FZN_RPC_OK;
	}
	return FZN_RPC_OK;
}

/* One row of `list location`: twelve fields, then the contact, which a row
 * may go on past. The host's first 16 hex digits into `host`; -1 when the
 * row does not read. */
static int node_location_row(const char *w, size_t w_len, const char **host,
                             fzn_rpc_location_show_entry_t *out) {
	const char *q = w, *row_end = w + w_len, *f[12];
	size_t f_len[12];
	for (int i = 0; i < 12; i++)
		if (!node_field(&q, row_end, &f[i], &f_len[i])) return -1;
	if (f_len[0] != 16) return -1;
	*host = f[0];
	fzn_rpc_location_show_entry_t e;
	memset(&e, 0, sizeof e);
	uint64_t at = 0, utc = 0, alt = 0, bearing = 0, ae = 0, an = 0, av = 0, coarse = 0;
	int has_alt = 0, has_bearing = 0, has_ae = 0, has_an = 0, has_av = 0;
	const int alt_neg = f_len[6] > 1 && f[6][0] == '-';
	if (!node_u64(f[1], f_len[1], &e.seq) || !node_u64(f[2], f_len[2], &at) ||
	    !node_degrees(f[3], f_len[3], &e.lat_e7) || !node_degrees(f[4], f_len[4], &e.lon_e7) ||
	    !node_u64(f[5], f_len[5], &utc) ||
	    !node_u64_or_none(f[6] + alt_neg, f_len[6] - (size_t)alt_neg, &alt, &has_alt) ||
	    !node_u64_or_none(f[7], f_len[7], &bearing, &has_bearing) ||
	    !node_u64_or_none(f[8], f_len[8], &ae, &has_ae) ||
	    !node_u64_or_none(f[9], f_len[9], &an, &has_an) ||
	    !node_u64_or_none(f[10], f_len[10], &av, &has_av) ||
	    !node_u64(f[11], f_len[11], &coarse) || coarse > 1 || alt > 32768 || bearing > 359 ||
	    utc > UINT32_MAX)
		return -1;
	e.utc_s = (uint32_t)utc;
	e.has_alt = (uint8_t)has_alt;
	e.alt_m = (int16_t)(alt_neg ? -(int64_t)alt : (int64_t)alt);
	e.has_bearing = (uint8_t)has_bearing;
	e.bearing_deg = (uint16_t)bearing;
	/* Unknown accuracy is 0 metres, as the clients' decoder gives it: no real
	 * accuracy is 0 (location.c's fzn_location_acc_decode). */
	e.acc_e_m = has_ae ? (uint32_t)ae : 0;
	e.acc_n_m = has_an ? (uint32_t)an : 0;
	e.acc_v_m = has_av ? (uint32_t)av : 0;
	e.is_coarse = (uint8_t)coarse;
	*out = e;
	return 0;
}

/*
 * `location_show` on fuzznetd (sec 284), fuzznet sec 677's `list location`,
 * paged since its sec 770: `list location FROM` answers `ok TOTAL FROM` and
 * a row a fix, `HOST,SEQ,AT,LAT,LON,UTC,ALT,BEARING,ACC_E,ACC_N,ACC_V,
 * COARSE`, of the newest sixteen of each host held -- this host's at
 * their finest, a contact's at the level it granted. The rows of the hosts
 * `origin` names, newest first by the fix's own time.
 *
 * `answered` stays 0: the clients' says when a peer last answered a fetch, and
 * fuzznetd keeps no such thing.
 */
static int node_location_show(fzn_rpc_t *c, const char *origin, size_t origin_len,
                              fzn_rpc_location_show_resp_t *out) {
	memset(out, 0, sizeof(*out));
	char hosts[16][17];
	size_t n_hosts = 0;
	int rc = node_location_hosts(c, origin, origin_len, hosts, 16, &n_hosts);
	if (rc != FZN_RPC_OK) return rc;
	/*
	 * PAGED, `list location FROM` -> `ok TOTAL FROM ROW ...`, as the device
	 * listing above is. The bare verb lists the newest sixteen fixes of
	 * every host in one reply, and a reply is 1024 bytes: from one host's
	 * thirteenth fix -- six minutes of gpsd at 30 s -- it refused, and this
	 * returned nothing at all (fuzznet sec 770, which added FROM).
	 * Bounded by a page count as well as by TOTAL, so a node answering
	 * pages that never reach it cannot hold the caller.
	 */
	size_t from = 0;
	for (unsigned page = 0; page < 64; page++) {
		const char *rest = NULL;
		size_t rest_len = 0;
		char arg[32];
		const int arg_len = snprintf(arg, sizeof arg, "location %zu", from);
		rc = fzn_rpc_node(c, "list", arg, (size_t)arg_len, &rest, &rest_len);
		if (rc != FZN_RPC_OK) return rc;
		size_t head = 0, total = 0, start = 0;
		if (!node_number(rest, rest_len, &head, &total) || !node_number(rest, rest_len, &head, &start) ||
		    start != from)
			return unreadable(c);
		size_t rows = 0;
		const char *p = rest + head, *end = rest + rest_len, *w;
		size_t w_len;
		while (node_word(&p, end, &w, &w_len)) {
			rows++;
			const char *host;
			fzn_rpc_location_show_entry_t e;
			if (node_location_row(w, w_len, &host, &e) != 0) return unreadable(c);
			int wanted = 0;
			for (size_t h = 0; h < n_hosts && !wanted; h++) wanted = memcmp(host, hosts[h], 16) == 0;
			if (!wanted) continue;
			if (e.seq > out->high_water_seq) out->high_water_seq = e.seq;
			/* Newest first by the fix's own time, kept to the newest when full. */
			size_t at_i = out->count;
			while (at_i > 0 && out->entries[at_i - 1].utc_s < e.utc_s) at_i--;
			if (at_i >= FZN_RPC_LOCATION_SHOW_RESP_MAX) continue;
			const size_t keep = out->count < FZN_RPC_LOCATION_SHOW_RESP_MAX ? out->count : out->count - 1;
			memmove(&out->entries[at_i + 1], &out->entries[at_i], (keep - at_i) * sizeof e);
			out->entries[at_i] = e;
			if (out->count < FZN_RPC_LOCATION_SHOW_RESP_MAX) out->count++;
		}
		from = start + rows;
		if (!rows || from >= total) return FZN_RPC_OK;
	}
	return FZN_RPC_OK;
}

/*
 * `location_status` on fuzznetd (sec 284), fuzznet sec 678's `get
 * location`: `ok ENABLED LINK EVERY ACCURACY SAMPLED DROPPED LAST`, LINK
 * off, down, connecting or watching. the clients' three stopped reasons map
 * onto the link: down is a source that could not be reached, connecting
 * one that has not acknowledged the watch. The live source is the
 * `location/gpsd` cell, `HOST PORT`, while the link is up or coming up.
 */
static int node_location_status(fzn_rpc_t *c, fzn_rpc_location_status_resp_t *out) {
	memset(out, 0, sizeof(*out));
	const char *rest = NULL;
	size_t rest_len = 0;
	int rc = fzn_rpc_node(c, "get", "location", 8, &rest, &rest_len);
	if (rc != FZN_RPC_OK) return rc;
	const char *p = rest, *end = rest + rest_len, *w;
	size_t w_len;
	uint64_t on = 0, every = 0;
	if (!node_word(&p, end, &w, &w_len) || !node_u64(w, w_len, &on) || on > 1) return unreadable(c);
	const char *link;
	size_t link_len;
	if (!node_word(&p, end, &link, &link_len) || !node_word(&p, end, &w, &w_len) ||
	    !node_u64(w, w_len, &every) || every > UINT32_MAX)
		return unreadable(c);
	out->configured = (uint8_t)on;
	out->interval_s = (uint32_t)every;
	/*
	 * SOURCE, the ninth word since fuzznet sec 774: `platform` while a fix
	 * a supplier handed over (`add location`) was kept within three
	 * intervals or two minutes. A phone has no gpsd, so without this its
	 * status named a link that is never up while its track grew -- what
	 * the clients' status says as source "platform", said the same way here. An
	 * older node sends eight words and reads as it did.
	 */
	{
		const char *sp = p;
		int words = 0, platform = 0;
		while (node_word(&sp, end, &w, &w_len)) {
			if (++words == 5) platform = w_len == 8 && memcmp(w, "platform", 8) == 0;
		}
		if (on && platform) {
			out->sampling = 1;
			memcpy(out->source, "platform", 9);
			out->source_len = 8;
			return FZN_RPC_OK;
		}
	}
	const int watching = link_len == 8 && memcmp(link, "watching", 8) == 0;
	const int connecting = link_len == 10 && memcmp(link, "connecting", 10) == 0;
	const int down = link_len == 4 && memcmp(link, "down", 4) == 0;
	const int off = link_len == 3 && memcmp(link, "off", 3) == 0;
	if (!watching && !connecting && !down && !off) return unreadable(c);
	out->sampling = (uint8_t)watching;
	if (on && down) out->stopped_reason = FZN_RPC_LOCATION_STOPPED_SOURCE;
	if (on && connecting) out->stopped_reason = FZN_RPC_LOCATION_STOPPED_UNREACHABLE;
	if (!watching && !connecting) return FZN_RPC_OK;
	rc = fzn_rpc_node(c, "get", "setting host location/gpsd", 26, &rest, &rest_len);
	if (rc != FZN_RPC_OK) return FZN_RPC_OK; /* the status stands; the source is unsaid */
	/* `ok SOURCE HOST%20PORT`, or `ok absent` for the default. */
	const char *esc = memchr(rest, ' ', rest_len);
	char value[sizeof out->source] = "localhost 2947";
	size_t value_len = 14;
	int cut = 0;
	if (esc && !node_unescape(esc + 1, (size_t)(rest + rest_len - esc - 1), value, sizeof value - 1,
	                          &value_len, &cut))
		return unreadable(c);
	if (cut) return FZN_RPC_OK; /* longer than the clients' field: unsaid rather than cut */
	value[value_len] = '\0';
	char *sp = strrchr(value, ' ');
	if (!sp) return FZN_RPC_OK;
	*sp = ':';
	memcpy(out->source, value, value_len + 1);
	out->source_len = value_len;
	return FZN_RPC_OK;
}

/* `revoke peer KEY`: `ok KEY [already] keeping CUT|nothing`, the line
 * read back from the vote fuzznetd holds (its node/admin.c). */
int fzn_rpc_host_revoke(fzn_rpc_t *c, const uint8_t host_pubkey[32], fzn_rpc_host_revoke_resp_t *out) {
	memset(out, 0, sizeof(*out));
	char arg[5 + 64 + 1], hex[65];
	fzn_hex_encode(host_pubkey, 32, hex);
	const char *rest = NULL;
	size_t rest_len = 0;
	const int rc = fzn_rpc_node(c, "revoke", arg, (size_t)snprintf(arg, sizeof arg, "peer %s", hex),
	                             &rest, &rest_len);
	if (rc != FZN_RPC_OK) return rc;
	const char *p = rest, *end = rest + rest_len, *w;
	size_t w_len;
	uint8_t key[32];
	if (!node_word(&p, end, &w, &w_len) || !node_key(w, w_len, key) ||
	    memcmp(key, host_pubkey, 32) != 0 || !node_word(&p, end, &w, &w_len))
		return unreadable(c);
	if (w_len == 7 && memcmp(w, "already", 7) == 0) {
		out->already = 1;
		if (!node_word(&p, end, &w, &w_len)) return unreadable(c);
	}
	if (!(w_len == 7 && memcmp(w, "keeping", 7) == 0) || !node_word(&p, end, &w, &w_len))
		return unreadable(c);
	if (w_len == 7 && memcmp(w, "nothing", 7) == 0)
		out->keeps_nothing = 1;
	else if (!node_key(w, w_len, out->cut))
		return unreadable(c);
	return node_word(&p, end, &w, &w_len) ? unreadable(c) : FZN_RPC_OK;
}

int fzn_rpc_host_unrevoke(fzn_rpc_t *c, const uint8_t host_pubkey[32]) {
	char arg[11 + 64 + 1], hex[65];
	fzn_hex_encode(host_pubkey, 32, hex);
	return node_ack(c, "remove", arg, snprintf(arg, sizeof arg, "revocation %s", hex));
}

/* ---- step 7 (sec 281) ---- */

int fzn_rpc_identity_generate(fzn_rpc_t *c, fzn_rpc_identity_generate_resp_t *out) {
	memset(out, 0, sizeof(*out));
	return node_identity_exists(c, FZN_RPC_ERR_IDENTITY_EXISTS, "identity");
}

int fzn_rpc_identity_reset(fzn_rpc_t *c, const uint8_t user_pubkey[32],
                        fzn_rpc_identity_reset_resp_t *out) {
	return node_identity_reset(c, user_pubkey, out);
}

int fzn_rpc_identity_backup(fzn_rpc_t *c, const char *dir, size_t dir_len,
                         fzn_rpc_identity_backup_resp_t *out) {
	return node_identity_backup(c, dir, dir_len, out);
}

int fzn_rpc_host_create(fzn_rpc_t *c, const char *host_name, size_t host_name_len,
                     fzn_rpc_host_create_resp_t *out) {
	memset(out, 0, sizeof(*out));
	(void)host_name, (void)host_name_len;
	return node_identity_exists(c, FZN_RPC_ERR_HOST_EXISTS, "host key");
}

int fzn_rpc_host_join_request(fzn_rpc_t *c, const char *host_name, size_t host_name_len,
                           const char *address, size_t address_len,
                           fzn_rpc_host_join_request_resp_t *out) {
	return node_join_request(c, host_name, host_name_len, address, address_len, out);
}

int fzn_rpc_host_join_approve(fzn_rpc_t *c, const uint8_t *request_blob, size_t request_blob_len,
                           const char *own_address, size_t own_address_len,
                           fzn_rpc_host_join_approve_resp_t *out) {
	return node_join_approve(c, request_blob, request_blob_len, own_address, own_address_len, out);
}

int fzn_rpc_host_join_install(fzn_rpc_t *c, const uint8_t *approval_blob, size_t approval_blob_len,
                           fzn_rpc_host_join_install_resp_t *out) {
	return node_join_install(c, approval_blob, approval_blob_len, out);
}

int fzn_rpc_prekey_show(fzn_rpc_t *c, fzn_rpc_prekey_show_resp_t *out) {
	return node_prekey_show(c, out);
}

/* ---- step 8 (sec 281) ---- */

/*
 * `list log [FROM] [LEVEL]` (fuzznet sec 711): the node daemon's own flight
 * recorder, newest first, `ok TOTAL FROM TIME,L,SUBSYSTEM,CUT,TEXT ...`.
 * Read in pages from FROM plus what came back, as the clients' page is filled,
 * at the clients' own floor of info and up.
 *
 * Each entry becomes the clients' shape, `[DATE TIME L SUBSYSTEM] TEXT`, so the
 * clients that show the message after the bracketed head show this one the
 * same way, and a cut text says so. SEQ is the entry's place counted from
 * the oldest the recorder holds, TOTAL down to 1: the clients' seq is local and
 * never from the clock, which rules out TIME, and this keeps newest-first
 * descending. It is a place in the ring, not a number for ever, since an
 * entry the ring lets go moves every later one down.
 *
 * A daemon without a log file has no recorder and says so; that refusal
 * is passed on as fuzznetd's words.
 */
static int node_log_show(fzn_rpc_t *c, fzn_rpc_log_show_resp_t *out) {
	memset(out, 0, sizeof(*out));
	size_t from = 0;
	for (unsigned page = 0; out->count < FZN_RPC_LOG_SHOW_PAGE_MAX && page < 64u; page++) {
		char arg[32];
		const int arg_len = snprintf(arg, sizeof arg, "log %zu I", from);
		const char *rest = NULL;
		size_t rest_len = 0;
		const int rc = fzn_rpc_node(c, "list", arg, (size_t)arg_len, &rest, &rest_len);
		if (rc != FZN_RPC_OK) return rc;
		size_t at = 0, total = 0, start = 0, listed = 0;
		if (!node_number(rest, rest_len, &at, &total) || !node_number(rest, rest_len, &at, &start) ||
		    start != from)
			return unreadable(c);
		while (at < rest_len && out->count < FZN_RPC_LOG_SHOW_PAGE_MAX) {
			size_t end = at;
			while (end < rest_len && rest[end] != ' ') end++;
			const char *q = rest + at, *stop = rest + end, *f, *lv, *sub, *text;
			size_t f_len, lv_len, sub_len, text_len;
			at = end < rest_len ? end + 1 : end;
			uint64_t time_us = 0, cut = 0;
			if (!node_field(&q, stop, &f, &f_len) || !node_u64(f, f_len, &time_us) ||
			    !node_field(&q, stop, &lv, &lv_len) || lv_len != 1 ||
			    !node_field(&q, stop, &sub, &sub_len) || !node_field(&q, stop, &f, &f_len) ||
			    !node_u64(f, f_len, &cut) || !node_field(&q, stop, &text, &text_len))
				return unreadable(c);
			/* Decoded whole -- an escaped text is never longer than its
			 * reply -- and cut to the clients' line below, as the clients expect its own. */
			static uint8_t said[FZN_REPLY_MAX];
			size_t said_len = 0;
			if (!fzn_unescape((const uint8_t *)text, text_len, said, sizeof said, &said_len))
				return unreadable(c);
			const time_t secs = (time_t)(time_us / 1000000u);
			struct tm tm;
			char when[32] = "?";
			if (fzn_rpc_gmtime(&secs, &tm)) {
				char day[24];
				strftime(day, sizeof day, "%Y-%m-%d %H:%M:%S", &tm);
				snprintf(when, sizeof when, "%s.%06u", day, (unsigned)(time_us % 1000000u));
			}
			fzn_rpc_log_entry_t *e = &out->entries[out->count];
			const int n = snprintf(e->text, sizeof e->text, "[%s %c %.*s] %.*s%s", when, lv[0],
			                       (int)sub_len, sub, (int)said_len, (const char *)said,
			                       cut ? " (cut)" : "");
			e->text_len = n < 0 ? 0 : ((size_t)n < sizeof e->text ? (size_t)n : sizeof e->text - 1);
			e->seq = total > from + listed ? total - from - listed : 0;
			out->count++;
			listed++;
		}
		from += listed;
		if (!listed || from >= total) break;
	}
	return FZN_RPC_OK;
}

int fzn_rpc_log_show(fzn_rpc_t *c, fzn_rpc_log_show_resp_t *out) {
	return node_log_show(c, out);
}

int fzn_rpc_link_list(fzn_rpc_t *c, fzn_rpc_link_list_resp_t *out) {
	return node_link_list(c, out);
}

int fzn_rpc_location_status(fzn_rpc_t *c, fzn_rpc_location_status_resp_t *out) {
	return node_location_status(c, out);
}

static int location_latest_cmp(const void *a, const void *b) {
	const fzn_rpc_location_latest_t *x = a, *y = b;
	const int d = strcmp(x->name, y->name);
	if (d) return d;
	/* Newest first within a name, so the first of each is the one kept. */
	return (x->fix.utc_s < y->fix.utc_s) - (x->fix.utc_s > y->fix.utc_s);
}

int fzn_rpc_location_latest(fzn_rpc_t *c, fzn_rpc_location_latest_t **out, size_t *room,
                             size_t *count) {
	*count = 0;
	size_t from = 0;
	/* Bounded by TOTAL, and by a page count no listing of sixteen fixes a
	 * host reaches, so a node answering pages that never end cannot hold
	 * the caller. */
	for (unsigned page = 0; page < (1u << 20); page++) {
		const char *rest = NULL;
		size_t rest_len = 0, head = 0, total = 0, start = 0, rows = 0;
		char arg[32];
		int rc = fzn_rpc_node(c, "list", arg,
		                       (size_t)snprintf(arg, sizeof arg, "location %zu", from), &rest,
		                       &rest_len);
		if (rc != FZN_RPC_OK) return rc;
		if (!node_number(rest, rest_len, &head, &total) || !node_number(rest, rest_len, &head, &start) ||
		    start != from)
			return unreadable(c);
		const char *p = rest + head, *end = rest + rest_len, *w;
		size_t w_len;
		while (node_word(&p, end, &w, &w_len)) {
			rows++;
			/* The row's last field: its contact, `-` for this host's own. */
			size_t at = w_len;
			while (at && w[at - 1] != ',') at--;
			const size_t name_len = w_len - at;
			if (!at || !name_len || name_len > FZN_RPC_PEER_NAME_MAX || (name_len == 1 && w[at] == '-'))
				continue;
			const char *host;
			fzn_rpc_location_show_entry_t e;
			if (node_location_row(w, w_len, &host, &e) != 0) return unreadable(c);
			rc = room_for(c, (void **)out, room, *count + 1, sizeof **out);
			if (rc != FZN_RPC_OK) return rc;
			fzn_rpc_location_latest_t *l = &(*out)[(*count)++];
			memcpy(l->name, w + at, name_len);
			l->name[name_len] = '\0';
			l->fix = e;
		}
		from = start + rows;
		if (!rows || from >= total) break;
	}
	if (*count) qsort(*out, *count, sizeof **out, location_latest_cmp);
	size_t kept = 0;
	for (size_t i = 0; i < *count; i++)
		if (!kept || strcmp((*out)[kept - 1].name, (*out)[i].name) != 0) (*out)[kept++] = (*out)[i];
	*count = kept;
	return FZN_RPC_OK;
}

const fzn_rpc_location_show_entry_t *fzn_rpc_location_latest_find(const fzn_rpc_location_latest_t *v,
                                                          size_t count, const char *name) {
	size_t lo = 0, hi = count;
	while (lo < hi) {
		const size_t mid = lo + (hi - lo) / 2;
		const int d = strcmp(v[mid].name, name);
		if (!d) return &v[mid].fix;
		if (d < 0)
			lo = mid + 1;
		else
			hi = mid;
	}
	return NULL;
}

int fzn_rpc_location_show(fzn_rpc_t *c, const char *origin, size_t origin_len,
                           fzn_rpc_location_show_resp_t *out) {
	return node_location_show(c, origin, origin_len, out);
}

int fzn_rpc_location_fetch(fzn_rpc_t *c, const char *target, size_t target_len) {
	return node_location_fetch(c, target, target_len);
}

/* node_degrees' inverse: 1e-7 degrees out as the seven places fuzznetd's
 * `add location` reads exactly. */
static int node_degrees_text(char *out, size_t cap, int32_t e7) {
	const int64_t v = e7;
	const uint64_t mag = (uint64_t)(v < 0 ? -v : v);
	return snprintf(out, cap, "%s%" PRIu64 ".%07" PRIu64, v < 0 ? "-" : "", mag / 10000000u,
	                mag % 10000000u);
}

/* `add location LAT LON [alt M] [bearing D] [acc E N] [vacc V] [at UTC]`:
 * an accuracy the fix does not know is left unsaid, which is how the node
 * spells unknown. */
static int node_location_record(fzn_rpc_t *c, const fzn_location_fix_t *fix) {
	char lat[24], lon[24], arg[192];
	node_degrees_text(lat, sizeof lat, fix->lat_e7);
	node_degrees_text(lon, sizeof lon, fix->lon_e7);
	int n = snprintf(arg, sizeof arg, "location %s %s at %" PRIu32, lat, lon, fix->utc_s);
	if (n > 0 && fix->has_alt)
		n += snprintf(arg + n, sizeof arg - (size_t)n, " alt %d", (int)fix->alt_m);
	if (n > 0 && fix->has_bearing)
		n += snprintf(arg + n, sizeof arg - (size_t)n, " bearing %u",
		              (unsigned)fzn_location_bearing_decode(fix->bearing));
	if (n > 0 && fix->acc_e != FZN_LOCATION_ACC_UNKNOWN && fix->acc_n != FZN_LOCATION_ACC_UNKNOWN)
		n += snprintf(arg + n, sizeof arg - (size_t)n, " acc %" PRIu32 " %" PRIu32,
		              fzn_location_acc_decode(fix->acc_e), fzn_location_acc_decode(fix->acc_n));
	if (n > 0 && fix->has_alt && fix->acc_v != FZN_LOCATION_ACC_UNKNOWN)
		n += snprintf(arg + n, sizeof arg - (size_t)n, " vacc %" PRIu32,
		              fzn_location_acc_decode(fix->acc_v));
	if (n < 0 || (size_t)n >= sizeof arg) return encode_failed(c);
	return node_ack(c, "add", arg, n);
}

int fzn_rpc_location_record(fzn_rpc_t *c, const fzn_location_fix_t *fix, int *recorded) {
	*recorded = 0;
	int rc = node_location_record(c, fix);
	if (rc == FZN_RPC_OK) *recorded = 1;
	/*
	 * The node's refusals are `error` lines told apart only by their
	 * words (fuzznet sec 774): "location is off ..." is the clients'
	 * FZN_RPC_ERR_LOCATION_OFF, so a supplier stops as it does there, and
	 * "dropped: ..." is the accuracy gate -- an answer, not a failure,
	 * as the clients expect it.
	 */
	if (rc != FZN_RPC_OK && c->answered) {
		/* The node's own words stay in c->error; only the code is the clients'. */
		if (strncmp(c->error, "location is off", 15) == 0)
			return c->error_code = FZN_RPC_ERR_LOCATION_OFF;
		if (strncmp(c->error, "dropped:", 8) == 0) {
			c->error[0] = '\0';
			c->error_code = 0;
			return FZN_RPC_OK;
		}
	}
	return rc;
}

int fzn_rpc_config_schema(fzn_rpc_t *c, const char *prefix, size_t prefix_len,
                           fzn_rpc_config_schema_resp_t *out) {
	return node_config_schema(c, prefix, prefix_len, out);
}

int fzn_rpc_config_status(fzn_rpc_t *c, const char *key, size_t key_len, const char *instance,
                           size_t instance_len, fzn_rpc_config_status_resp_t *out) {
	return node_config_status(c, key, key_len, instance, instance_len, out);
}

/* Stickers on fuzznetd (sec 284): its secs 679-682. */

/* A PACK word as the node takes one: 64 hex, a saved pack's root, or 144,
 * a held pack's whole file reference. Anything else is refused unasked. */
static int node_pack_ok(const char *pack, size_t len) {
	if (len != 64 && len != 144) return 0;
	for (size_t i = 0; i < len; i++)
		if (hex_nibble(pack[i]) < 0) return 0;
	return 1;
}

/* One page of a sticker listing, fuzznet sec 684: `ok TOTAL FROM ROW ...`,
 * as many rows as fit a 1024-byte reply from the FROMth. `row` takes each
 * row's text; the next page is asked from FROM plus the rows read, until a
 * page brings none or TOTAL is reached -- bounded by `max_pages` (64 for
 * the sticker listings), in case a daemon keeps answering without moving. */
typedef int (*node_row_fn)(void *ctx, const char *row, size_t row_len);
static int node_pages_bounded(fzn_rpc_t *c, const char *what, size_t what_len, node_row_fn row,
                              void *ctx, size_t *total_out, unsigned max_pages) {
	size_t from = 0, total = 0;
	for (unsigned page = 0; page < max_pages; page++) {
		char arg[16 + 144 + 24];
		const int arg_len = snprintf(arg, sizeof arg, "%.*s %zu", (int)what_len, what, from);
		const char *rest = NULL;
		size_t rest_len = 0, at = 0, start = 0, rows = 0;
		const int rc = fzn_rpc_node(c, "list", arg, (size_t)arg_len, &rest, &rest_len);
		if (rc != FZN_RPC_OK) return rc;
		if (!node_number(rest, rest_len, &at, &total) || !node_number(rest, rest_len, &at, &start) ||
		    start != from)
			return unreadable(c);
		const char *p = rest + at, *end = rest + rest_len, *w;
		size_t w_len;
		while (node_word(&p, end, &w, &w_len)) {
			if (!row(ctx, w, w_len)) return unreadable(c);
			rows++;
		}
		from += rows;
		if (!rows || from >= total) break;
	}
	*total_out = total;
	return FZN_RPC_OK;
}

static int node_pages(fzn_rpc_t *c, const char *what, size_t what_len, node_row_fn row, void *ctx,
                      size_t *total_out) {
	return node_pages_bounded(c, what, what_len, row, ctx, total_out, 64);
}

/*
 * The settings on fuzznetd (sec 284), its sec 686: declared settings, read
 * as `list schema` and `get schema KEY`, written by `set setting SCOPE KEY
 * VALUE` and checked there. The clients' settings screens read the clients'
 * schema and split a key on '.', so a node's `relay/enabled` is shown as
 * `relay.enabled` and mapped back on the way in. A family (a key ending in
 * '/') or a key the node marks `verb` is set by its own verb -- `add
 * retention`, `put sticker` -- and is not offered as a setting.
 */
typedef struct node_schema_row {
	char key[FZN_RPC_CONFIG_KEY_MAX + 1];
	char type[12];
	int estate, host;
	int64_t min, max;
	char unit[FZN_RPC_CONFIG_UNIT_MAX + 1];
	char default_value[FZN_RPC_CONFIG_VALUE_MAX + 1];
	char summary[FZN_RPC_CONFIG_SUMMARY_MAX + 1];
	unsigned flags; /* FZN_SCHEMA_*, the node's FLAGS field read whole */
} node_schema_row_t;

static int node_unescape_field(const char *f, size_t n, char *out, size_t cap) {
	size_t len = 0;
	int cut = 0;
	if (n == 1 && f[0] == '-') {
		out[0] = '\0';
		return 1;
	}
	if (!node_unescape(f, n, out, cap - 1, &len, &cut)) return 0;
	out[len] = '\0';
	return 1;
}

/* `KEY,TYPE,SCOPES,MIN,MAX,DEFAULT,UNIT,FLAGS,SUMMARY`. */
static int node_schema_row(const char *w, size_t w_len, node_schema_row_t *r) {
	memset(r, 0, sizeof(*r));
	const char *q = w, *row_end = w + w_len, *f[9];
	size_t f_len[9];
	uint64_t min = 0, max = 0;
	for (int i = 0; i < 9; i++)
		if (!node_field(&q, row_end, &f[i], &f_len[i])) return 0;
	if (q <= row_end || !f_len[0] || f_len[0] > FZN_RPC_CONFIG_KEY_MAX || f_len[1] >= sizeof r->type ||
	    !node_u64(f[3], f_len[3], &min) || !node_u64(f[4], f_len[4], &max) || max > INT64_MAX)
		return 0;
	memcpy(r->key, f[0], f_len[0]);
	memcpy(r->type, f[1], f_len[1]);
	r->estate = f_len[2] >= 6 && memcmp(f[2], "estate", 6) == 0;
	r->host = (f_len[2] == 4 && memcmp(f[2], "host", 4) == 0) ||
	          (f_len[2] == 11 && memcmp(f[2], "estate+host", 11) == 0);
	r->min = (int64_t)min;
	r->max = (int64_t)max;
	if (!node_unescape_field(f[5], f_len[5], r->default_value, sizeof r->default_value) ||
	    !node_unescape_field(f[6], f_len[6], r->unit, sizeof r->unit) ||
	    !node_unescape_field(f[8], f_len[8], r->summary, sizeof r->summary))
		return 0;
	for (const char *p = f[7], *e = f[7] + f_len[7]; p < e;) {
		const char *plus = memchr(p, '+', (size_t)(e - p));
		const size_t n = (size_t)((plus ? plus : e) - p);
		static const struct {
			const char *word;
			unsigned bit;
		} FLAGS[] = { { "restart", FZN_SCHEMA_RESTART },         { "sensitive", FZN_SCHEMA_SENSITIVE },
		              { "advanced", FZN_SCHEMA_ADVANCED },       { "verb", FZN_SCHEMA_VERB },
		              { "safe-lower", FZN_SCHEMA_SAFE_LOWER },   { "safe-higher", FZN_SCHEMA_SAFE_HIGHER },
		              { "advertised", FZN_SCHEMA_ADVERTISED } };
		for (size_t k = 0; k < sizeof FLAGS / sizeof FLAGS[0]; k++)
			if (n == strlen(FLAGS[k].word) && memcmp(p, FLAGS[k].word, n) == 0) r->flags |= FLAGS[k].bit;
		p = plus ? plus + 1 : e;
	}
	return 1;
}

/* A node's key as the screens show it, '/' as '.', and back. */
static void node_key_dotted(const char *in, char *out, size_t cap) {
	snprintf(out, cap, "%s", in);
	for (char *p = out; *p; p++)
		if (*p == '/') *p = '.';
}
static int node_key_slashed(const char *in, size_t len, char *out, size_t cap) {
	if (!len || len >= cap || memchr(in, ' ', len) || memchr(in, '/', len)) return 0;
	for (size_t i = 0; i < len; i++) out[i] = in[i] == '.' ? '/' : in[i];
	out[len] = '\0';
	return 1;
}

/* A schema row's TYPE word as state/schema.h's type. A word this client
 * does not know is TEXT: shown and edited as words, which the node judges,
 * rather than the whole schema refused when the node grows a type. */
static fzn_schema_type_t node_schema_type(const char *word) {
	static const struct {
		const char *word;
		fzn_schema_type_t type;
	} TYPES[] = { { "flag", FZN_SCHEMA_FLAG },         { "count", FZN_SCHEMA_COUNT },
	              { "duration", FZN_SCHEMA_DURATION }, { "address", FZN_SCHEMA_ADDRESS },
	              { "text", FZN_SCHEMA_TEXT } };
	for (size_t k = 0; k < sizeof TYPES / sizeof TYPES[0]; k++)
		if (strcmp(word, TYPES[k].word) == 0) return TYPES[k].type;
	return FZN_SCHEMA_TEXT;
}

struct node_schema_ctx {
	fzn_rpc_config_schema_resp_t *out;
};

static int node_schema_take(void *ctx, const char *w, size_t w_len) {
	fzn_rpc_config_schema_resp_t *out = ((struct node_schema_ctx *)ctx)->out;
	node_schema_row_t r;
	if (!node_schema_row(w, w_len, &r)) return 0;
	const size_t key_len = strlen(r.key);
	if ((r.flags & FZN_SCHEMA_VERB) || r.key[key_len - 1] == '/') return 1;
	if (out->count >= FZN_RPC_CONFIG_SCHEMA_PAGE_MAX) {
		out->truncated = 1;
		return 1;
	}
	fzn_rpc_config_schema_entry_t *e = &out->entries[out->count++];
	node_key_dotted(r.key, e->key, sizeof e->key);
	e->key_len = strlen(e->key);
	/* THE NODE'S DECLARATION AS IT IS, sec 1098: its type, scopes and every
	 * flag, a duration still a duration -- `14d`, judged by the node. */
	e->type = node_schema_type(r.type);
	e->scopes = (r.estate ? FZN_SCHEMA_ESTATE : 0u) | (r.host ? FZN_SCHEMA_HOST : 0u);
	e->flags = r.flags;
	e->min = r.min;
	e->max = r.max;
	snprintf(e->unit, sizeof e->unit, "%s", r.unit);
	e->unit_len = strlen(e->unit);
	snprintf(e->default_value, sizeof e->default_value, "%s", r.default_value);
	e->default_value_len = strlen(e->default_value);
	snprintf(e->summary, sizeof e->summary, "%s", r.summary);
	e->summary_len = strlen(e->summary);
	return 1;
}

static int node_config_schema(fzn_rpc_t *c, const char *prefix, size_t prefix_len,
                              fzn_rpc_config_schema_resp_t *out) {
	memset(out, 0, sizeof(*out));
	char what[8 + FZN_RPC_CONFIG_KEY_MAX + 1], slashed[FZN_RPC_CONFIG_KEY_MAX + 1];
	int what_len = snprintf(what, sizeof what, "schema");
	if (prefix_len) {
		if (!node_key_slashed(prefix, prefix_len, slashed, sizeof slashed))
			return node_unasked(c, FZN_RPC_ERR_MALFORMED, "not a settings prefix");
		what_len = snprintf(what, sizeof what, "schema %s", slashed);
	}
	struct node_schema_ctx ctx = {out};
	size_t total = 0;
	return node_pages(c, what, (size_t)what_len, node_schema_take, &ctx, &total);
}

/* One key's declaration, `get schema KEY`. */
static int node_schema_of(fzn_rpc_t *c, const char *key, node_schema_row_t *r) {
	char arg[8 + FZN_RPC_CONFIG_KEY_MAX + 1];
	const char *rest = NULL;
	size_t rest_len = 0;
	const int rc = fzn_rpc_node(c, "get", arg, (size_t)snprintf(arg, sizeof arg, "schema %s", key),
	                             &rest, &rest_len);
	if (rc != FZN_RPC_OK) return rc;
	return node_schema_row(rest, rest_len, r) ? FZN_RPC_OK : unreadable(c);
}

static int node_config_get(fzn_rpc_t *c, const char *key, size_t key_len, fzn_rpc_config_get_resp_t *out) {
	memset(out, 0, sizeof(*out));
	char slashed[FZN_RPC_CONFIG_KEY_MAX + 1];
	if (!node_key_slashed(key, key_len, slashed, sizeof slashed))
		return node_unasked(c, FZN_RPC_ERR_MALFORMED, "not a setting's key");
	node_schema_row_t r;
	int rc = node_schema_of(c, slashed, &r);
	if (rc != FZN_RPC_OK) return rc;
	char arg[24 + FZN_RPC_CONFIG_KEY_MAX + 1];
	const char *rest = NULL;
	size_t rest_len = 0;
	/* A host's setting as it stands HERE (fuzznet sec 868): the host's own
	 * value, else its group's, else the estate's -- `SCOPE RANK VALUE`. Asked
	 * for the host's cell alone, as this did until 2026-11-09, a value set for
	 * a group or the whole estate read as the default. */
	rc = fzn_rpc_node(c, "get", arg,
	                   (size_t)snprintf(arg, sizeof arg, "setting %s %s", r.host ? "here" : "estate",
	                                    slashed),
	                   &rest, &rest_len);
	if (rc != FZN_RPC_OK) return rc;
	/* `ok RANK VALUE` (here: `ok SCOPE RANK VALUE`), the value escaped, or
	 * `ok absent`: the default. */
	const char *esc = NULL;
	int from_host = 0;
	if (!(rest_len == 6 && memcmp(rest, "absent", 6) == 0)) {
		const char *rank = memchr(rest, ' ', rest_len);
		if (!rank) return unreadable(c);
		if (r.host) {
			from_host = (size_t)(rank - rest) == 4 && memcmp(rest, "host", 4) == 0;
			esc = memchr(rank + 1, ' ', (size_t)(rest + rest_len - rank - 1));
			if (!esc) return unreadable(c);
		} else {
			esc = rank;
		}
	}
	char value[FZN_RPC_CONFIG_VALUE_MAX + 1];
	if (esc) {
		size_t len = 0;
		int cut = 0;
		if (!node_unescape(esc + 1, (size_t)(rest + rest_len - esc - 1), value, sizeof value - 1, &len,
		                   &cut))
			return unreadable(c);
		value[len] = '\0';
		/* SET ABOVE THIS HOST -- its group's value or the estate's -- reads as
		 * ESTATE: either way it is not this host's own. */
		out->set_at = from_host ? FZN_SCHEMA_HOST : FZN_SCHEMA_ESTATE;
	} else {
		snprintf(value, sizeof value, "%s", r.default_value);
		out->set_at = 0;
	}
	snprintf(out->value, sizeof out->value, "%s", value);
	out->value_len = strlen(out->value);
	/* Write-only, as the clients expect a sensitive one: said set or not, never
	 * shown. */
	if (r.flags & FZN_SCHEMA_SENSITIVE) {
		out->redacted = 1;
		out->configured = esc != NULL;
		out->value[0] = '\0';
		out->value_len = 0;
	}
	return FZN_RPC_OK;
}

static int node_config_set(fzn_rpc_t *c, const char *key, size_t key_len, const char *value,
                           size_t value_len, const char *expected, size_t expected_len) {
	char slashed[FZN_RPC_CONFIG_KEY_MAX + 1];
	if (!node_key_slashed(key, key_len, slashed, sizeof slashed))
		return node_unasked(c, FZN_RPC_ERR_MALFORMED, "not a setting's key");
	if (value_len > FZN_RPC_CONFIG_VALUE_MAX || memchr(value, '\n', value_len))
		return node_unasked(c, FZN_RPC_ERR_MALFORMED, "that value is not one a setting takes");
	node_schema_row_t r;
	int rc = node_schema_of(c, slashed, &r);
	if (rc != FZN_RPC_OK) return rc;
	if (expected) {
		fzn_rpc_config_get_resp_t now;
		rc = node_config_get(c, key, key_len, &now);
		if (rc != FZN_RPC_OK) return rc;
		if (now.value_len != expected_len || memcmp(now.value, expected, expected_len) != 0)
			return fail(c, FZN_RPC_ERR_CONFLICT, "the setting changed since it was read");
	}
	char given[FZN_RPC_CONFIG_VALUE_MAX + 1];
	memcpy(given, value, value_len);
	given[value_len] = '\0';
	/* the clients' true/false, as the node's on/off; anything else as typed, and
	 * the node judges it (its sec 686), answering what is wrong. */
	const char *v = given;
	if (strcmp(r.type, "flag") == 0) {
		if (!strcmp(given, "true") || !strcmp(given, "on") || !strcmp(given, "1")) v = "on";
		else if (!strcmp(given, "false") || !strcmp(given, "off") || !strcmp(given, "0")) v = "off";
	}
	char arg[FZN_REQUEST_MAX];
	return node_ack(c, "set", arg,
	                snprintf(arg, sizeof arg, "setting %s %s %s", r.host ? "host" : "estate", slashed, v));
}

int fzn_rpc_config_clear(fzn_rpc_t *c, const char *key, size_t key_len) {
	char slashed[FZN_RPC_CONFIG_KEY_MAX + 1];
	if (!node_key_slashed(key, key_len, slashed, sizeof slashed))
		return node_unasked(c, FZN_RPC_ERR_MALFORMED, "not a setting's key");
	node_schema_row_t r;
	int rc = node_schema_of(c, slashed, &r);
	if (rc != FZN_RPC_OK) return rc;
	/* WHERE `set` WRITES IT, so a clear undoes what a set did. */
	char arg[FZN_REQUEST_MAX];
	return node_ack(c, "remove", arg,
	                snprintf(arg, sizeof arg, "setting %s %s", r.host ? "host" : "estate", slashed));
}

/*
 * Which of the user's devices hold an estate setting, on fuzznetd: `list
 * setting-holders KEY [FROM]` (fuzznet sec 811), answering `ok VERSION FROM
 * SHOWN MORE HOST,HELD,AT ...`. VERSION is the version in force here, as
 * the clients' local_seq; each other device is a row, named as `list location`
 * names a host -- the first eight bytes of its key in hex, since a sibling
 * has no name on a node -- with HELD as its acked. HELD is exact for the
 * version in force and 0 for anything older, so behind is still acked <
 * local_seq, and a device never heard reads 0, as the clients' silent sibling
 * does. Paged, about nine devices a reply, asked again from FROM + SHOWN
 * while MORE is 1. A host setting stays on its host, and a node has no
 * families, so neither is asked.
 */
static int node_config_status(fzn_rpc_t *c, const char *key, size_t key_len, const char *instance,
                              size_t instance_len, fzn_rpc_config_status_resp_t *out) {
	memset(out, 0, sizeof(*out));
	char slashed[FZN_RPC_CONFIG_KEY_MAX + 1];
	if (!node_key_slashed(key, key_len, slashed, sizeof slashed))
		return node_unasked(c, FZN_RPC_ERR_MALFORMED, "not a setting's key");
	if (instance && instance_len)
		return node_unasked(c, FZN_RPC_ERR_MALFORMED, "a node's settings have no instances");
	node_schema_row_t r;
	int rc = node_schema_of(c, slashed, &r);
	if (rc != FZN_RPC_OK) return rc;
	if (!r.estate)
		return node_unasked(c, FZN_RPC_ERR_MALFORMED, "a host setting is not shared with other devices");
	size_t from = 0;
	for (unsigned page = 0; page < 16; page++) {
		char arg[24 + FZN_RPC_CONFIG_KEY_MAX + 24];
		const int arg_len = snprintf(arg, sizeof arg, "setting-holders %s %zu", slashed, from);
		const char *rest = NULL;
		size_t rest_len = 0, at = 0, version = 0, start = 0, shown = 0, more = 0;
		rc = fzn_rpc_node(c, "list", arg, (size_t)arg_len, &rest, &rest_len);
		if (rc != FZN_RPC_OK) return rc;
		if (!node_number(rest, rest_len, &at, &version) || !node_number(rest, rest_len, &at, &start) ||
		    !node_number(rest, rest_len, &at, &shown) || !node_number(rest, rest_len, &at, &more) ||
		    start != from || more > 1)
			return unreadable(c);
		out->local_seq = version;
		const char *p = rest + at, *end = rest + rest_len, *w;
		size_t w_len, rows = 0;
		while (node_word(&p, end, &w, &w_len)) {
			/* HOST,HELD,AT: 64 hex, then two numbers. */
			const char *comma = memchr(w, ',', w_len);
			const char *comma2 = comma ? memchr(comma + 1, ',', (size_t)(w + w_len - comma - 1)) : NULL;
			uint64_t held = 0;
			if (!comma || !comma2 || comma - w != 64 ||
			    !node_u64(comma + 1, (size_t)(comma2 - comma - 1), &held))
				return unreadable(c);
			rows++;
			if (out->count >= FZN_RPC_MANIFEST_FANOUT_MAX) continue;
			fzn_rpc_config_status_row_t *row = &out->rows[out->count++];
			memcpy(row->name, w, 16);
			row->name[16] = '\0';
			row->name_len = 16;
			row->acked = held;
		}
		if (rows != shown) return unreadable(c);
		from += shown;
		if (!more || !shown) break;
	}
	/* Each holder by the device's name where it has one (fuzznet sec 847),
	 * as the Hosts tab shows it; the rows give the key, whose first sixteen
	 * stay the name otherwise. */
	if (out->count) {
		fzn_rpc_sibling_list_resp_t *sibs = malloc(sizeof(*sibs));
		if (sibs && node_siblings(c, sibs) == FZN_RPC_OK)
			for (size_t row = 0; row < out->count; row++)
				for (size_t i = 0; i < sibs->count; i++) {
					char hex[65];
					fzn_hex_encode(sibs->entries[i].host_pubkey, 32, hex);
					/* The sibling's own fallback is this same prefix. */
					if (memcmp(hex, out->rows[row].name, 16) != 0 ||
					    (sibs->entries[i].name_len == 16 && memcmp(sibs->entries[i].name, hex, 16) == 0))
						continue;
					memcpy(out->rows[row].name, sibs->entries[i].name, sibs->entries[i].name_len);
					out->rows[row].name[sibs->entries[i].name_len] = '\0';
					out->rows[row].name_len = sibs->entries[i].name_len;
				}
		free(sibs);
		c->error[0] = '\0';
	}
	return FZN_RPC_OK;
}

/* The traffic meter on fuzznetd (sec 284), its sec 685. Rows are by family
 * rather than the clients' command byte, named in `family`: `get transfer` gives
 * each family's totals, `list transfer [FROM]` the rows, paged. The rows
 * are all read -- a host's totals are summed from them, and a total from
 * part of them would be a wrong number -- and the first
 * FZN_RPC_TRANSFER_LIST_MAX kept, `rows_total` saying how many there are. */
struct node_transfer_rows {
	fzn_rpc_transfer_list_resp_t *out;
	size_t seen;
};

static void node_add_bytes(uint64_t *to, uint64_t n) {
	*to = *to > UINT64_MAX - n ? UINT64_MAX : *to + n;
}

static int node_transfer_row(void *ctx, const char *w, size_t w_len) {
	struct node_transfer_rows *r = ctx;
	fzn_rpc_transfer_list_resp_t *out = r->out;
	const char *q = w, *row_end = w + w_len, *f[9];
	size_t f_len[9];
	uint64_t up = 0, down = 0, rate_up = 0, rate_down = 0, first = 0, last = 0;
	for (int i = 0; i < 9; i++)
		if (!node_field(&q, row_end, &f[i], &f_len[i])) return 0;
	if (q <= row_end || !f_len[0] || f_len[0] >= sizeof out->entries[0].family ||
	    f_len[1] > FZN_RPC_PEER_ADDRESS_MAX || !node_u64(f[3], f_len[3], &up) ||
	    !node_u64(f[4], f_len[4], &down) || !node_u64(f[5], f_len[5], &rate_up) ||
	    !node_u64(f[6], f_len[6], &rate_down) || !node_u64(f[7], f_len[7], &first) ||
	    !node_u64(f[8], f_len[8], &last))
		return 0;
	r->seen++;
	/* Its host's totals, from every row. */
	size_t h = 0;
	while (h < out->host_count && !(out->hosts[h].peer_address_len == f_len[1] &&
	                                memcmp(out->hosts[h].peer_address, f[1], f_len[1]) == 0))
		h++;
	if (h == out->host_count) {
		out->hosts_total++;
		if (out->host_count < FZN_RPC_TRANSFER_HOST_MAX) {
			memcpy(out->hosts[h].peer_address, f[1], f_len[1]);
			out->hosts[h].peer_address_len = f_len[1];
			out->host_count++;
		}
	}
	if (h < out->host_count) {
		fzn_rpc_transfer_host_t *host = &out->hosts[h];
		node_add_bytes(&host->bytes_up, up);
		node_add_bytes(&host->bytes_down, down);
		node_add_bytes(&host->rate_up, rate_up);
		node_add_bytes(&host->rate_down, rate_down);
		host->rows++;
	}
	/* Its family's rates and row count, which `get transfer` does not say. */
	for (size_t s = 0; s < out->subsystem_count; s++) {
		fzn_rpc_transfer_subsystem_t *sub = &out->subsystems[s];
		if (strlen(sub->family) == f_len[0] && memcmp(sub->family, f[0], f_len[0]) == 0) {
			node_add_bytes(&sub->rate_up, rate_up);
			node_add_bytes(&sub->rate_down, rate_down);
			sub->rows++;
		}
	}
	if (out->count >= FZN_RPC_TRANSFER_LIST_MAX) return 1;
	fzn_rpc_transfer_entry_t *e = &out->entries[out->count++];
	memcpy(e->family, f[0], f_len[0]);
	memcpy(e->peer_address, f[1], f_len[1]);
	e->peer_address_len = f_len[1];
	if (f_len[2] == 64 && node_key(f[2], 64, e->key)) {
		e->key_kind = FZN_RPC_METER_KEY_BLOB;
		e->key_len = 32;
	}
	e->bytes_up = up;
	e->bytes_down = down;
	e->rate_up = rate_up;
	e->rate_down = rate_down;
	e->first_seen = first;
	e->last_seen = last;
	return 1;
}

static int node_transfer_list(fzn_rpc_t *c, fzn_rpc_transfer_list_resp_t *out) {
	memset(out, 0, sizeof(*out));
	const char *rest = NULL;
	size_t rest_len = 0;
	int rc = fzn_rpc_node(c, "get", "transfer", 8, &rest, &rest_len);
	if (rc != FZN_RPC_OK) return rc;
	/* `ok FAMILY,UP,DOWN ...`, a family that has moved anything. */
	const char *p = rest, *end = rest + rest_len, *w;
	size_t w_len;
	while (node_word(&p, end, &w, &w_len)) {
		const char *q = w, *row_end = w + w_len, *f[3];
		size_t f_len[3];
		uint64_t up = 0, down = 0;
		for (int i = 0; i < 3; i++)
			if (!node_field(&q, row_end, &f[i], &f_len[i])) return unreadable(c);
		if (q <= row_end || !f_len[0] || f_len[0] >= sizeof out->subsystems[0].family ||
		    out->subsystem_count >= FZN_RPC_TRANSFER_SUBSYSTEM_MAX || !node_u64(f[1], f_len[1], &up) ||
		    !node_u64(f[2], f_len[2], &down))
			return unreadable(c);
		fzn_rpc_transfer_subsystem_t *sub = &out->subsystems[out->subsystem_count++];
		memcpy(sub->family, f[0], f_len[0]);
		sub->bytes_up = up;
		sub->bytes_down = down;
	}
	struct node_transfer_rows rows = {out, 0};
	size_t total = 0;
	/* A full meter is 64 rows of each of sixteen families, some 128 pages. */
	rc = node_pages_bounded(c, "transfer", 8, node_transfer_row, &rows, &total, 160);
	if (rc != FZN_RPC_OK) return rc;
	if (rows.seen != total) return unreadable(c);
	out->rows_total = total > UINT16_MAX ? UINT16_MAX : (uint16_t)total;
	return FZN_RPC_OK;
}

/* One more room in a growing list, doubling; 0 when there is none. */
static fzn_rpc_sticker_list_entry_t *packs_append(fzn_rpc_sticker_packs_t *p, size_t *cap) {
	if (p->count == *cap) {
		const size_t grown = *cap ? *cap * 2 : 16;
		fzn_rpc_sticker_list_entry_t *more = realloc(p->entries, grown * sizeof(*more));
		if (!more) return NULL;
		p->entries = more;
		*cap = grown;
	}
	fzn_rpc_sticker_list_entry_t *e = &p->entries[p->count];
	memset(e, 0, sizeof(*e));
	return e;
}

struct packs_rows {
	fzn_rpc_sticker_packs_t *out;
	size_t cap;
};

static int sticker_list_row(void *ctx, const char *w, size_t w_len) {
	struct packs_rows *rows = ctx;
	fzn_rpc_sticker_packs_t *out = rows->out;
	const char *q = w, *row_end = w + w_len, *f[5];
	size_t f_len[5];
	for (int i = 0; i < 5; i++)
		if (!node_field(&q, row_end, &f[i], &f_len[i])) return 0;
	if (q <= row_end) return 0;
	fzn_rpc_sticker_list_entry_t *e = packs_append(out, &rows->cap);
	if (!e) return 0;
	int cut = 0;
	if (!node_key(f[0], f_len[0], e->root) ||
	    !node_unescape(f[2], f_len[2], e->name, sizeof e->name - 1, &e->name_len, &cut))
		return 0;
	e->name[e->name_len] = '\0';
	out->count++;
	return 1;
}

/* `list sticker [FROM]`: rows `ROOT,LENGTH,NAME,HELD,SCOPE`, NAME escaped,
 * paged. The key is not listed, and nothing on a node needs it: its packs
 * are read by root through the verbs. */
static int node_sticker_list(fzn_rpc_t *c, fzn_rpc_sticker_packs_t *out) {
	struct packs_rows rows = {out, 0};
	size_t total = 0;
	const int rc = node_pages(c, "sticker", 7, sticker_list_row, &rows, &total);
	if (rc != FZN_RPC_OK) return rc;
	return out->count == total ? FZN_RPC_OK : unreadable(c);
}

static int node_sticker_forget(fzn_rpc_t *c, const uint8_t root[32]) {
	char hex[65], arg[8 + 64 + 1];
	fzn_hex_encode(root, 32, hex);
	return node_ack(c, "remove", arg, snprintf(arg, sizeof arg, "sticker %s", hex));
}

/* Eight hex digits, as the spec writes a colour: 1, or 0. */
static int node_rgba(const char *w, size_t n, uint32_t *out) {
	if (n != 8) return 0;
	uint32_t v = 0;
	for (size_t i = 0; i < n; i++) {
		const char ch = w[i];
		const int d = ch >= '0' && ch <= '9'   ? ch - '0'
		              : ch >= 'a' && ch <= 'f' ? ch - 'a' + 10
		              : ch >= 'A' && ch <= 'F' ? ch - 'A' + 10
		                                       : -1;
		if (d < 0) return 0;
		v = v << 4 | (uint32_t)d;
	}
	*out = v;
	return 1;
}

static int sticker_item_row(void *ctx, const char *w, size_t w_len) {
	fzn_rpc_node_sticker_items_resp_t *out = ctx;
	const char *q = w, *row_end = w + w_len, *f[14];
	size_t f_len[14];
	uint64_t id = 0, type = 0, flags = 0, limit = 0;
	for (int i = 0; i < 4; i++)
		if (!node_field(&q, row_end, &f[i], &f_len[i])) return 0;
	/* ID,TYPE,FLAGS,DESC[,TEXT_LIMIT]: the box's limit, 0 for none, since
	 * fuzznet's sec 841; a row of four, from a node before it, has none to
	 * say. */
	const int has_limit = q <= row_end;
	if (has_limit && (!node_field(&q, row_end, &f[4], &f_len[4]) || !node_u64(f[4], f_len[4], &limit) ||
	                  limit > 0xffff))
		return 0;
	/* ...,X,Y,W,H,FILL,INK,TURN,MAIN_W,MAIN_H: the box itself, its paint and
	 * the main rendition's size it is measured against, since fuzznet's sec
	 * 864 -- nine more, or none. */
	uint64_t box[9] = {0};
	uint32_t fill = 0, ink = 0;
	if (has_limit && q <= row_end) {
		for (int i = 5; i < 14; i++)
			if (!node_field(&q, row_end, &f[i], &f_len[i])) return 0;
		for (int i = 0; i < 9; i++) {
			if (i == 4 || i == 5) continue;
			if (!node_u64(f[5 + i], f_len[5 + i], &box[i]) || box[i] > 0xffff) return 0;
		}
		if (!node_rgba(f[9], f_len[9], &fill) || !node_rgba(f[10], f_len[10], &ink) || box[6] > 359)
			return 0;
	}
	if (out->count >= FZN_RPC_NODE_STICKER_ITEMS_MAX) {
		out->overflow = 1;
		return 1;
	}
	if (q <= row_end || !node_u64(f[0], f_len[0], &id) ||
	    id == 0 || !node_u64(f[1], f_len[1], &type) || type > 255 ||
	    !node_u64(f[2], f_len[2], &flags) || flags > 0xffff)
		return 0;
	fzn_rpc_node_sticker_item_t *e = &out->entries[out->count];
	int cut = 0;
	if (!node_unescape(f[3], f_len[3], e->description, sizeof e->description - 1,
	                   &e->description_len, &cut))
		return 0;
	e->description[e->description_len] = '\0';
	e->id = id;
	e->type = (uint8_t)type;
	e->flags = (uint16_t)flags;
	e->text_limit = (uint16_t)limit;
	e->text_x = (uint16_t)box[0];
	e->text_y = (uint16_t)box[1];
	e->text_w = (uint16_t)box[2];
	e->text_h = (uint16_t)box[3];
	e->text_fill = fill;
	e->text_ink = ink;
	e->text_turn = (uint16_t)box[6];
	e->main_w = (uint16_t)box[7];
	e->main_h = (uint16_t)box[8];
	out->count++;
	return 1;
}

static int node_sticker_items(fzn_rpc_t *c, const char *pack, size_t pack_len,
                              fzn_rpc_node_sticker_items_resp_t *out) {
	memset(out, 0, sizeof(*out));
	if (!node_pack_ok(pack, pack_len))
		return node_unasked(c, FZN_RPC_ERR_MALFORMED, "a pack is its root or its whole reference, as hex");
	/* `list sticker PACK [FROM]`: rows `ID,TYPE,FLAGS,DESC`, DESC escaped,
	 * paged -- a 64-sticker pack is some four pages. */
	char what[8 + 144 + 1];
	const int what_len = snprintf(what, sizeof what, "sticker %.*s", (int)pack_len, pack);
	size_t total = 0;
	const int rc = node_pages(c, what, (size_t)what_len, sticker_item_row, out, &total);
	if (rc != FZN_RPC_OK) return rc;
	if (out->overflow)
		return fail(c, FZN_RPC_ERR_BUFFER_TOO_SMALL, "that pack holds more stickers than this client lists");
	return out->count == total ? FZN_RPC_OK : unreadable(c);
}

static int node_sticker_reference(fzn_rpc_t *c, const char *pack, size_t pack_len, uint64_t id,
                                  const char *words, size_t words_len, char *text, size_t cap,
                                  size_t *text_len) {
	*text_len = 0;
	if (cap) text[0] = '\0';
	if (!node_pack_ok(pack, pack_len))
		return node_unasked(c, FZN_RPC_ERR_MALFORMED, "a pack is its root or its whole reference, as hex");
	/* "sticker ", the pack, a space and a 64-bit id's 20 digits; then, for a
	 * sticker that carries the sender's words, " text WORDS", escaped as a
	 * message's text is (fuzznet sec 830). */
	char esc[FZN_REQUEST_MAX], arg[FZN_REQUEST_MAX];
	int arg_len = snprintf(arg, sizeof arg, "sticker %.*s %" PRIu64, (int)pack_len, pack, id);
	if (words_len) {
		const size_t esc_len = node_escape(words, words_len, esc, sizeof esc);
		if (!esc_len) return node_unasked(c, FZN_RPC_ERR_MALFORMED, "those words are too long to send");
		arg_len += snprintf(arg + arg_len, sizeof arg - (size_t)arg_len, " text %.*s", (int)esc_len, esc);
		if ((size_t)arg_len > FZN_REQUEST_MAX - 5u)
			return node_unasked(c, FZN_RPC_ERR_MALFORMED, "those words are too long to send");
	}
	const char *rest = NULL;
	size_t rest_len = 0;
	const int rc = fzn_rpc_node(c, "get", arg, (size_t)arg_len, &rest, &rest_len);
	if (rc != FZN_RPC_OK) return rc;
	/* The reference a line carries, read back as one before it is handed
	 * on: a client sends exactly this. */
	fzn_sticker_ref_t ref;
	if (rest_len >= cap || !fzn_sticker_ref_parse(rest, rest_len, &ref)) return unreadable(c);
	memcpy(text, rest, rest_len);
	text[rest_len] = '\0';
	*text_len = rest_len;
	return FZN_RPC_OK;
}

static int node_sticker_draw(fzn_rpc_t *c, const char *pack, size_t pack_len, uint64_t id,
                             uint8_t role, const char *path, size_t path_len,
                             fzn_rpc_node_sticker_drawn_t *out) {
	static const char *const ROLES[] = {"thumb", "inline", "main", "popup"};
	memset(out, 0, sizeof(*out));
	if (!node_pack_ok(pack, pack_len))
		return node_unasked(c, FZN_RPC_ERR_MALFORMED, "a pack is its root or its whole reference, as hex");
	if (role < 1 || role > 4) return node_unasked(c, FZN_RPC_ERR_MALFORMED, "no such rendition role");
	char full[FZN_REQUEST_MAX], arg[FZN_REQUEST_MAX];
	if (!node_abs_path(path, path_len, full, sizeof full)) return encode_failed(c);
	const int arg_len = snprintf(arg, sizeof arg, "sticker %.*s %" PRIu64 " %s %s", (int)pack_len, pack, id,
	                             ROLES[role - 1], full);
	if (arg_len < 0 || (size_t)arg_len > FZN_REQUEST_MAX - 5u) return encode_failed(c);
	const char *rest = NULL;
	size_t rest_len = 0, at = 0, format = 0, width = 0, height = 0;
	const int rc = fzn_rpc_node(c, "get", arg, (size_t)arg_len, &rest, &rest_len);
	if (rc != FZN_RPC_OK) return rc;
	if (!node_number(rest, rest_len, &at, &format) || !node_number(rest, rest_len, &at, &width) ||
	    !node_number(rest, rest_len, &at, &height) || at != rest_len || format < 1 || format > 4 ||
	    width > 0xffff || height > 0xffff)
		return unreadable(c);
	out->format = (uint8_t)format;
	out->width = (uint16_t)width;
	out->height = (uint16_t)height;
	return FZN_RPC_OK;
}

static int node_sticker_put(fzn_rpc_t *c, const char *spec_path, size_t spec_path_len,
                            uint8_t root[32], int *host_only) {
	memset(root, 0, 32);
	if (host_only) *host_only = 0;
	char full[FZN_REQUEST_MAX], arg[FZN_REQUEST_MAX];
	if (!node_abs_path(spec_path, spec_path_len, full, sizeof full)) return encode_failed(c);
	const int arg_len = snprintf(arg, sizeof arg, "sticker %s", full);
	if (arg_len < 0 || (size_t)arg_len > FZN_REQUEST_MAX - 5u) return encode_failed(c);
	const char *rest = NULL;
	size_t rest_len = 0;
	const int rc = fzn_rpc_node(c, "put", arg, (size_t)arg_len, &rest, &rest_len);
	if (rc != FZN_RPC_OK) return rc;
	/* `ok ROOT`, or `ok ROOT host`: saved for this host alone. */
	const int host = rest_len == 69 && memcmp(rest + 64, " host", 5) == 0;
	if ((rest_len != 64 && !host) || !node_key(rest, 64, root)) return unreadable(c);
	if (host_only) *host_only = host;
	return FZN_RPC_OK;
}

int fzn_rpc_sticker_items(fzn_rpc_t *c, const char *pack, size_t pack_len,
                           fzn_rpc_node_sticker_items_resp_t *out) {
	return node_sticker_items(c, pack, pack_len, out);
}

/*
 * A pack as a file, `ID.fzs`: the node's own file of it, in fuzznet's pack
 * layout, which a pack is wherever it is held (fuzznet sec 681). Its whole
 * reference comes from any of its stickers' references, and its id, the hash
 * of its art, is what names the file (fuzznet sec 859).
 */
int fzn_rpc_sticker_file_write(fzn_rpc_t *c, const uint8_t root[32], const char *path,
                                size_t path_len, uint64_t *pack_id) {
	char hex[65];
	fzn_hex_encode(root, 32, hex);
	static fzn_rpc_node_sticker_items_resp_t items;
	int rc = node_sticker_items(c, hex, 64, &items);
	if (rc != FZN_RPC_OK) return rc;
	if (!items.count) return node_unasked(c, FZN_RPC_ERR_MALFORMED, "that pack holds no sticker");
	char text[FZN_STICKER_REF_MAX + 1];
	size_t text_len = 0;
	rc = node_sticker_reference(c, hex, 64, items.entries[0].id, NULL, 0, text, sizeof text, &text_len);
	if (rc != FZN_RPC_OK) return rc;
	static const char scheme[] = "fzn:sticker/";
	const size_t at = sizeof scheme - 1;
	uint8_t key[32];
	if (text_len < at + 129 || memcmp(text, scheme, at) != 0 || text[at + 64] != '/' ||
	    !node_key(text + at + 65, 64, key))
		return unreadable(c);
	static fzn_rpc_blob_export_resp_t written;
	rc = node_file_export(c, root, key, path, path_len, &written);
	if (rc != FZN_RPC_OK || !pack_id) return rc;
	char arg[8 + 64 + 1];
	const char *rest = NULL;
	size_t rest_len = 0;
	rc = fzn_rpc_node(c, "get", arg, (size_t)snprintf(arg, sizeof arg, "sticker %s", hex), &rest,
	                   &rest_len);
	if (rc != FZN_RPC_OK) return rc;
	/* An id is the art's hash, twenty digits about half the time. */
	return node_u64(rest, rest_len, pack_id) ? FZN_RPC_OK : unreadable(c);
}

int fzn_rpc_sticker_file_keep(fzn_rpc_t *c, const char *path, size_t path_len, uint8_t root[32],
                               int *host_only) {
	static fzn_rpc_blob_add_resp_t held;
	/* Put as the node puts a pack it builds, any file's way: the root is then
	 * this node's and the id, from the art, is what stays the same. */
	int rc = node_file_put(c, path, path_len, FZN_RPC_BLOB_TIER_PRIVATE, &held);
	if (rc != FZN_RPC_OK) return rc;
	char ref[145 + 1], *p = ref;
	fzn_hex_encode(held.root, 32, p);
	fzn_hex_encode(held.key, 32, p + 64);
	snprintf(p + 128, 17, "%016llx", (unsigned long long)held.byte_len);
	return fzn_rpc_sticker_keep(c, ref, 144, root, host_only);
}

int fzn_rpc_sticker_reference(fzn_rpc_t *c, const char *pack, size_t pack_len, uint64_t id,
                               char *text, size_t cap, size_t *text_len) {
	return node_sticker_reference(c, pack, pack_len, id, NULL, 0, text, cap, text_len);
}

int fzn_rpc_sticker_reference_words(fzn_rpc_t *c, const char *pack, size_t pack_len, uint64_t id,
                                     const char *words, size_t words_len, char *text, size_t cap,
                                     size_t *text_len) {
	return node_sticker_reference(c, pack, pack_len, id, words, words_len, text, cap, text_len);
}

int fzn_rpc_sticker_draw(fzn_rpc_t *c, const char *pack, size_t pack_len, uint64_t id,
                          uint8_t role, const char *path, size_t path_len,
                          fzn_rpc_node_sticker_drawn_t *out) {
	return node_sticker_draw(c, pack, pack_len, id, role, path, path_len, out);
}

int fzn_rpc_sticker_keep(fzn_rpc_t *c, const char *ref, size_t ref_len, uint8_t root[32],
                          int *host_only) {
	memset(root, 0, 32);
	if (host_only) *host_only = 0;
	if (ref_len != 144 || !node_pack_ok(ref, ref_len))
		return node_unasked(c, FZN_RPC_ERR_MALFORMED, "a pack is kept by its whole reference, as hex");
	char arg[8 + 144 + 1];
	const char *rest = NULL;
	size_t rest_len = 0;
	const int rc = fzn_rpc_node(c, "add", arg,
	                             (size_t)snprintf(arg, sizeof arg, "sticker %.*s", (int)ref_len, ref),
	                             &rest, &rest_len);
	if (rc != FZN_RPC_OK) return rc;
	/* `ok ROOT`, or `ok ROOT host`, as put answers. */
	const int host = rest_len == 69 && memcmp(rest + 64, " host", 5) == 0;
	if ((rest_len != 64 && !host) || !node_key(rest, 64, root)) return unreadable(c);
	if (host_only) *host_only = host;
	return FZN_RPC_OK;
}

int fzn_rpc_sticker_put(fzn_rpc_t *c, const char *spec_path, size_t spec_path_len,
                         uint8_t root[32], int *host_only) {
	return node_sticker_put(c, spec_path, spec_path_len, root, host_only);
}

int fzn_rpc_sticker_ref_read(const char *text, size_t text_len, fzn_sticker_ref_t *out,
                         uint64_t *length) {
	*length = 0;
	/* Fuzznet's parser alone (its sticker/pack.c, sec 680): it reads the
	 * `fzn:` form a node writes and the older `fzp:` one, as length 0. This
	 * tried the tree's own `fzp:` parser first until 2026-11-09. */
	fzn_sticker_ref_t ref;
	if (!fzn_sticker_ref_parse(text, text_len, &ref) || ref.description_len >= sizeof out->description)
		return FZN_RPC_ERR_MALFORMED;
	memset(out, 0, sizeof(*out));
	memcpy(out->root, ref.root, sizeof out->root);
	memcpy(out->key, ref.key, sizeof out->key);
	out->id = ref.id;
	memcpy(out->description, ref.description, ref.description_len);
	out->description_len = ref.description_len;
	/* The sender's words (fuzznet sec 830). Dropped here before, so on a
	 * node a message sticker's words reached the receiver's inbox and
	 * neither client showed them. */
	if (ref.text_len >= sizeof out->text) return FZN_RPC_ERR_MALFORMED;
	memcpy(out->text, ref.text, ref.text_len);
	out->text_len = ref.text_len;
	*length = ref.length;
	return FZN_RPC_OK;
}

void fzn_rpc_sticker_pack_word(const fzn_sticker_ref_t *ref, uint64_t length, char out[145]) {
	fzn_hex_encode(ref->root, 32, out);
	fzn_hex_encode(ref->key, 32, out + 64);
	uint8_t be[8];
	for (int i = 0; i < 8; i++) be[i] = (uint8_t)(length >> (56 - 8 * i));
	fzn_hex_encode(be, 8, out + 128);
}

int fzn_rpc_sticker_manifest(fzn_rpc_t *c, const char *pack, size_t pack_len,
                              fzn_sticker_manifest_t *out) {
	fzn_rpc_sticker_manifest_init(out, NULL, 0);
	static fzn_rpc_node_sticker_items_resp_t items;
	const int rc = fzn_rpc_sticker_items(c, pack, pack_len, &items);
	if (rc != FZN_RPC_OK) return rc;
	/* Allocated to fit, as client/sticker_read.h's readers are: released
	 * with fzn_rpc_sticker_manifest_release. */
	fzn_sticker_entry_t *entries = calloc(items.count ? items.count : 1, sizeof(*entries));
	if (!entries) return fail(c, FZN_RPC_ERR_BUFFER_TOO_SMALL, "no room for that pack's stickers");
	fzn_rpc_sticker_manifest_init(out, entries, items.count);
	for (size_t i = 0; i < items.count; i++) {
		fzn_sticker_entry_t *e = &out->entries[out->count++];
		e->id = items.entries[i].id;
		e->type = items.entries[i].type;
		e->flags = items.entries[i].flags;
		e->text_limit = items.entries[i].text_limit;
		/* The box and its paint (fuzznet sec 864), so the words are drawn
		 * on the art on a node too; the main rendition's size stands as a
		 * rendition with no path, which is what the box is scaled by. */
		e->text_x = items.entries[i].text_x;
		e->text_y = items.entries[i].text_y;
		e->text_w = items.entries[i].text_w;
		e->text_h = items.entries[i].text_h;
		e->text_fill = items.entries[i].text_fill;
		e->text_ink = items.entries[i].text_ink;
		e->text_turn = items.entries[i].text_turn;
		if (items.entries[i].main_w && items.entries[i].main_h) {
			e->renditions[0].role = FZN_STICKER_MAIN;
			e->renditions[0].width = items.entries[i].main_w;
			e->renditions[0].height = items.entries[i].main_h;
			e->rendition_count = 1;
		}
		const size_t n = items.entries[i].description_len < FZN_STICKER_DESC_MAX
		                     ? items.entries[i].description_len
		                     : FZN_STICKER_DESC_MAX;
		memcpy(e->description, items.entries[i].description, n);
		e->description_len = n;
	}
	return FZN_RPC_OK;
}

int fzn_rpc_sticker_art(fzn_rpc_t *c, const char *pack, size_t pack_len, uint64_t id,
                         uint8_t role, size_t max, uint8_t **art, size_t *art_len,
                         uint8_t *format) {
	*art = NULL;
	*art_len = 0;
	*format = 0;
	/* The node writes only a NEW file, so a fresh name inside a directory
	 * made for it rather than a mkstemp file, which already exists. */
	char dir[NODE_STAGE_MAX], path[NODE_STAGE_MAX + 8];
	int made = 0;
	for (int attempt = 0; attempt < 3 && !made; attempt++)
		made = node_stage_path(c, attempt, "art", dir) && fzn_rpc_mkdtemp(dir);
	if (!made) return node_unasked(c, FZN_RPC_ERR_STORAGE_IO, "could not make a place for the art");
	snprintf(path, sizeof path, "%s/art", dir);
	fzn_rpc_node_sticker_drawn_t drawn;
	int rc = fzn_rpc_sticker_draw(c, pack, pack_len, id, role, path, strlen(path), &drawn);
	if (rc == FZN_RPC_OK) {
		FILE *f = fopen(path, "rb");
		struct stat st;
		if (!f || fstat(fileno(f), &st) != 0 || st.st_size <= 0 || (uint64_t)st.st_size > max) {
			rc = fail(c, FZN_RPC_ERR_BUFFER_TOO_SMALL, "the art is empty, or larger than this client holds");
		} else if (!(*art = malloc((size_t)st.st_size))) {
			rc = fail(c, FZN_RPC_ERR_STORAGE_IO, "out of memory reading the art");
		} else if (fread(*art, 1, (size_t)st.st_size, f) != (size_t)st.st_size) {
			free(*art);
			*art = NULL;
			rc = fail(c, FZN_RPC_ERR_STORAGE_IO, "the art written was short");
		} else {
			*art_len = (size_t)st.st_size;
			*format = drawn.format;
		}
		if (f) fclose(f);
	}
	/* Read once and gone: art left in a temporary directory is chat content
	 * outside the store that is meant to hold it. */
	unlink(path);
	rmdir(dir);
	return rc;
}

void fzn_rpc_sticker_packs_release(fzn_rpc_sticker_packs_t *p) {
	free(p->entries);
	p->entries = NULL;
	p->count = 0;
}

/* `list clock [FROM]`: `ok TOTAL FROM KEY,DIR,SECONDS,AT ...`, read in pages
 * from FROM plus what came back until TOTAL, as `list contact` is. */
int fzn_rpc_clock_list(fzn_rpc_t *c, fzn_rpc_clock_list_t *out) {
	out->rows = NULL;
	out->count = 0;
	size_t cap = 0;
	for (unsigned page = 0; page < 1u << 16; page++) {
		char arg[32];
		const int arg_len = snprintf(arg, sizeof arg, "clock %zu", out->count);
		const char *rest = NULL;
		size_t rest_len = 0;
		const int rc = fzn_rpc_node(c, "list", arg, (size_t)arg_len, &rest, &rest_len);
		if (rc != FZN_RPC_OK) return rc;
		size_t at = 0, total = 0, start = 0, listed = 0;
		if (!node_number(rest, rest_len, &at, &total) || !node_number(rest, rest_len, &at, &start) ||
		    start != out->count)
			return unreadable(c);
		while (at < rest_len) {
			size_t end = at;
			while (end < rest_len && rest[end] != ' ') end++;
			const char *q = rest + at, *stop = rest + end, *f, *dir;
			size_t f_len, dir_len;
			at = end < rest_len ? end + 1 : end;
			fzn_rpc_clock_row_t row;
			memset(&row, 0, sizeof row);
			if (!node_field(&q, stop, &f, &f_len) || !node_key(f, f_len, row.key) ||
			    !node_field(&q, stop, &dir, &dir_len) || !node_field(&q, stop, &f, &f_len) ||
			    !node_u64(f, f_len, &row.seconds) || !node_field(&q, stop, &f, &f_len) ||
			    !node_u64(f, f_len, &row.at))
				return unreadable(c);
			if (dir_len == 6 && memcmp(dir, "behind", 6) == 0)
				row.ahead = 0;
			else if (dir_len == 5 && memcmp(dir, "ahead", 5) == 0)
				row.ahead = 1;
			else
				return unreadable(c);
			if (out->count == cap) {
				const size_t grown = cap ? cap * 2 : 8;
				fzn_rpc_clock_row_t *more = realloc(out->rows, grown * sizeof(*more));
				if (!more) return fail(c, FZN_RPC_ERR_BUFFER_TOO_SMALL, "no room for the clock list");
				out->rows = more;
				cap = grown;
			}
			out->rows[out->count++] = row;
			listed++;
		}
		if (!listed || out->count >= total) return FZN_RPC_OK;
	}
	return unreadable(c);
}

int fzn_rpc_clock_get(fzn_rpc_t *c, fzn_rpc_clock_estate_t *out) {
	memset(out, 0, sizeof(*out));
	out->state = FZN_RPC_CLOCK_UNSURE;
	const char *rest = NULL;
	size_t rest_len = 0;
	const int rc = fzn_rpc_node(c, "get", "clock", 5, &rest, &rest_len);
	if (rc != FZN_RPC_OK) return rc;
	/* OFFSET_MS DEVICES STATE, the offset signed. */
	size_t at = 0, devices = 0, magnitude = 0;
	const int negative = rest_len > 0 && rest[0] == '-';
	if (negative) at = 1;
	if (!node_number(rest, rest_len, &at, &magnitude) || !node_number(rest, rest_len, &at, &devices) ||
	    devices > UINT32_MAX)
		return unreadable(c);
	const char *word = rest + at;
	const size_t word_len = rest_len - at;
	if (word_len == 5 && memcmp(word, "right", 5) == 0)
		out->state = FZN_RPC_CLOCK_RIGHT;
	else if (word_len == 5 && memcmp(word, "wrong", 5) == 0)
		out->state = FZN_RPC_CLOCK_WRONG;
	else if (word_len == 6 && memcmp(word, "unsure", 6) == 0)
		out->state = FZN_RPC_CLOCK_UNSURE;
	else
		return unreadable(c);
	out->offset_ms = negative ? -(int64_t)magnitude : (int64_t)magnitude;
	out->devices = (uint32_t)devices;
	return FZN_RPC_OK;
}

void fzn_rpc_clock_list_release(fzn_rpc_clock_list_t *l) {
	free(l->rows);
	l->rows = NULL;
	l->count = 0;
}

int fzn_rpc_sticker_list(fzn_rpc_t *c, fzn_rpc_sticker_packs_t *out) {
	out->entries = NULL;
	out->count = 0;
	return node_sticker_list(c, out);
}

int fzn_rpc_sticker_forget(fzn_rpc_t *c, const uint8_t root[32]) {
	return node_sticker_forget(c, root);
}

int fzn_rpc_location_share(fzn_rpc_t *c, const char *peer, size_t peer_len, int enable,
                            uint8_t precision, int *reaches_siblings) {
	return node_location_share(c, peer, peer_len, enable, precision, reaches_siblings);
}

/* ---- the node's other programs (sec 284) ---- */

int fzn_rpc_set_node_socket(fzn_rpc_t *c, const char *path) {
	c->node_socket[0] = '\0';
	if (!path || !*path) return 0;
	/* `default`: fuzznet's own default socket (its sec 663), asked for by
	 * name. */
	if (strcmp(path, "default") == 0)
		return fzn_socket_default_path(c->node_socket, sizeof(c->node_socket)) == FZN_SOCKET_OK
		           ? 0
		           : (c->node_socket[0] = '\0', -1);
	if (strlen(path) >= sizeof(c->node_socket)) return -1;
	snprintf(c->node_socket, sizeof(c->node_socket), "%s", path);
	return 0;
}

/*
 * fuzznet's reply words (its sec 365), read by fuzznet's own `fzn_reply_of`
 * rather than spelled again here, and mapped onto this layer's codes. The
 * pair worth keeping apart is DENIED and UNSUPPORTED -- an access decision
 * and a daemon that has no such verb send a person to different places,
 * and fuzznet split them for exactly that.
 */
static int node_reply_code(fzn_reply_t word) {
	switch (word) {
	case FZN_REPLY_DENIED: return FZN_RPC_ERR_NOT_AUTHORIZED;
	case FZN_REPLY_UNSUPPORTED: return FZN_RPC_ERR_UNKNOWN_MSG_TYPE;
	case FZN_REPLY_MALFORMED: return FZN_RPC_ERR_MALFORMED;
	case FZN_REPLY_ERROR: return FZN_RPC_ERR_STORAGE_IO;
	default: return 0;
	}
}

int fzn_rpc_node_reply(fzn_rpc_t *c, const char *reply, size_t len, const char **rest,
                        size_t *rest_len) {
	*rest = NULL;
	*rest_len = 0;
	c->answered = 1; /* a reply line came back, whatever it says */
	c->held = 0;
	const uint8_t *detail = NULL;
	size_t detail_len = 0;
	const fzn_reply_t word = fzn_reply_of((const uint8_t *)reply, len, &detail, &detail_len);
	if (fzn_reply_ok(word)) {
		/* An `ok` with nothing after it is a bare acknowledgement. */
		*rest = detail ? (const char *)detail : reply + len;
		*rest_len = detail ? detail_len : 0;
		c->held = detail_len == 4 && memcmp(detail, "held", 4) == 0;
		return FZN_RPC_OK;
	}
	const int code = node_reply_code(word);
	/* Not one fuzznet offers: the grammar is fuzznet's, and this side does
	 * not guess at another word. */
	if (!code) return fail(c, FZN_RPC_ERR_MALFORMED, "the node's answer is not one this client reads");
	char text[sizeof(c->error)];
	/* The daemon's words where it gave some; the word itself otherwise, so a
	 * bare refusal is never an empty line. */
	if (detail && detail_len)
		snprintf(text, sizeof(text), "%.*s", (int)detail_len, (const char *)detail);
	else
		snprintf(text, sizeof(text), "the node answered %s", fzn_reply_name(word));
	return fail(c, code, text);
}

int fzn_rpc_node(fzn_rpc_t *c, const char *verb, const char *arg, size_t arg_len,
                  const char **rest, size_t *rest_len) {
	c->error[0] = '\0';
	c->error_code = 0;
	c->answered = 0;
	c->unreadable = 0;
	c->held = 0;
	*rest = NULL;
	*rest_len = 0;
	if (c->answer) {
		size_t len = 0;
		const int rc = c->answer(c->answer_ctx, verb, arg, arg ? arg_len : 0, c->resp,
		                         sizeof(c->resp) - 1u, &len);
		if (rc != FZN_RPC_OK) return fail(c, rc, "that was not answered");
		c->resp[len] = '\0';
		return fzn_rpc_node_reply(c, (const char *)c->resp, len, rest, rest_len);
	}
	if (!c->node_socket[0]) return fail(c, FZN_RPC_ERR_NO_PEER_TRANSPORT, "no node is set for this node");

	int fd = -1;
	fzn_client_err_t err = fzn_client_connect(c->node_socket, &fd);
	if (err == FZN_CLIENT_OK)
		err = fzn_client_send(fd, (const uint8_t *)verb, strlen(verb), (const uint8_t *)arg,
		                      arg ? arg_len : 0);
	size_t got = 0;
	if (err == FZN_CLIENT_OK)
		err = fzn_client_recv(fd, c->resp, sizeof(c->resp) - 1u, &got, 10000u);
	if (fd >= 0) fzn_client_close(fd);
	if (err != FZN_CLIENT_OK) {
		/*
		 * Worded per case, because fuzznet keeps them apart for the reason a
		 * person needs them apart (its sec 364): nothing listening sends
		 * somebody to start the daemon, a timeout to a daemon that is there
		 * and wedged, a broken socket to neither.
		 */
		const char *what = err == FZN_CLIENT_ERR_CONNECT   ? "is not running -- nothing answers there"
		                   : err == FZN_CLIENT_ERR_TIMEOUT ? "is there and did not answer in time"
		                   : err == FZN_CLIENT_ERR_IO      ? "broke off before answering"
		                   : err == FZN_CLIENT_ERR_PATH    ? "is not at a usable socket path"
		                   : err == FZN_CLIENT_ERR_REQUEST_TOO_LONG
		                       ? "was not asked: the request is longer than a line may be"
		                   : err == FZN_CLIENT_ERR_REPLY_TOO_LONG
		                       ? "answered more than one reply can hold"
		                       : fzn_client_err_str(err);
		char text[sizeof(c->error)];
		snprintf(text, sizeof(text), "the node at %s %s", c->node_socket, what);
		return fail(c, err == FZN_CLIENT_ERR_REQUEST_TOO_LONG ? FZN_RPC_ERR_MALFORMED
		                                                      : FZN_RPC_ERR_SEND_FAILED,
		            text);
	}
	c->resp[got] = '\0';
	return fzn_rpc_node_reply(c, (const char *)c->resp, got, rest, rest_len);
}

/* ---- fuzznetd's events (sec 284 step 4) ---- */

/* The first whole line in the buffer, taken out: its length, or -1. */
static long node_events_line(fzn_rpc_node_events_t *ev, char *line, size_t cap) {
	const char *nl = memchr(ev->buf, '\n', ev->len);
	if (!nl) return -1;
	const size_t n = (size_t)(nl - ev->buf);
	const size_t keep = n < cap - 1 ? n : cap - 1;
	memcpy(line, ev->buf, keep);
	line[keep] = '\0';
	memmove(ev->buf, nl + 1, ev->len - n - 1);
	ev->len -= n + 1;
	return (long)keep;
}

/* Read what is there into the buffer; -1 when the connection ended or a
 * line overran the buffer, which no event of fuzznet's does. */
static int node_events_fill(fzn_rpc_node_events_t *ev) {
	if (ev->len >= sizeof(ev->buf)) return -1;
	const ssize_t n = read(ev->fd, ev->buf + ev->len, sizeof(ev->buf) - ev->len);
	if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) return 0;
	if (n <= 0) return -1;
	ev->len += (size_t)n;
	return 0;
}

int fzn_rpc_node_events_open(fzn_rpc_node_events_t *ev, const char *path) {
	memset(ev, 0, sizeof(*ev));
	ev->fd = -1;
	int fd = -1;
	if (!path || !*path || fzn_client_connect(path, &fd) != FZN_CLIENT_OK) {
		snprintf(ev->why, sizeof ev->why, "the node is not running there");
		return -1;
	}
	if (fzn_client_send(fd, (const uint8_t *)"get", 3, (const uint8_t *)"events", 6) !=
	    FZN_CLIENT_OK) {
		fzn_client_close(fd);
		return -1;
	}
	ev->fd = fd;
	/* NON-BLOCKING, so a read with nothing there returns rather than waits:
	 * the caller drains every buffered line after one poll, and the read
	 * after the last of them finds none. Blocking, that read held the
	 * client until fuzznetd's next event, which on an idle node is never. */
	if (fzn_rpc_nonblocking(fd) != 0) {
		fzn_rpc_node_events_close(ev);
		return -1;
	}
	/* `ok events`, read through this buffer: an event may follow it in the
	 * same read, and fuzznet's own reader would drop what came after. As
	 * long as the buffer, so a refusal's reason reaches `why` whole -- 64
	 * bytes cut a follower's off at 63. */
	char line[sizeof(ev->buf)];
	for (int tries = 0; tries < 50; tries++) {
		if (node_events_line(ev, line, sizeof line) >= 0) {
			if (strcmp(line, "ok events") == 0) return 0;
			/* Refused: keep what it said, past the reply word. */
			const char *sp = strchr(line, ' ');
			/* Bounded on purpose: a reason past `why` is cut, not refused. */
			snprintf(ev->why, sizeof ev->why, "%.*s", (int)(sizeof ev->why - 1), sp ? sp + 1 : line);
			fzn_client_close(ev->fd);
			ev->fd = -1;
			ev->len = 0;
			return -1;
		}
		struct pollfd p = {.fd = fd, .events = POLLIN};
		if (poll(&p, 1, 100) < 0 || ((p.revents & POLLIN) && node_events_fill(ev) != 0)) break;
	}
	fzn_rpc_node_events_close(ev);
	snprintf(ev->why, sizeof ev->why, "the node did not answer the subscription");
	return -1;
}

int fzn_rpc_node_events_next(fzn_rpc_node_events_t *ev, char *subject, size_t subject_cap, char *name,
                         size_t name_cap) {
	if (ev->fd < 0 || !subject_cap || !name_cap) return -1;
	char line[sizeof(ev->buf)];
	int read_once = 0;
	for (;;) {
		if (node_events_line(ev, line, sizeof line) >= 0) {
			/* `event SUBJECT NAME`; anything else is not one, and is skipped. */
			char s[32] = "", m[80] = "";
			if (sscanf(line, "event %31s %79s", s, m) != 2) continue;
			snprintf(subject, subject_cap, "%s", s);
			snprintf(name, name_cap, "%s", m);
			return 1;
		}
		/* No whole line buffered: read once, since the fd polled readable,
		 * and no more, since it may not be again. */
		if (read_once) return 0;
		read_once = 1;
		if (node_events_fill(ev) != 0) return -1;
	}
}

void fzn_rpc_node_events_close(fzn_rpc_node_events_t *ev) {
	if (ev->fd >= 0) fzn_client_close(ev->fd);
	ev->fd = -1;
	ev->len = 0;
}

/*
 * NAMED OBJECTS IN BINARY ON THE LOCAL LEG, fuzznet sec 1152 (sec 1101's A,
 * its pilot): each call asks FZN_CMD_OBJECTS with its operation and reads
 * the STATUS or rows back, the text verb above kept where the node or this
 * client speaks text alone for it (local/rpc_binary.h).
 */
struct objects_answer {
	fzn_rpc_t *c;
	fzn_rpc_object_t *one;              /* get's, or NULL */
	fzn_rpc_object_list_resp_t *list;   /* list's, or NULL */
	int rows, bad, status_seen, room_failed;
	fzn_status_t code;
	char why[FZN_STATUS_WHY_MAX + 1];
};

static int object_row_into(fzn_rpc_object_t *o, situ_view_t b) {
	static const uint8_t none[32];
	memset(o, 0, sizeof *o);
	if (fzn_objects_row_name_len(b) > FZN_RPC_OBJECT_NAME_MAX
	    || fzn_objects_row_value_len(b) > FZN_RPC_OBJECT_VALUE_MAX
	    || fzn_objects_row_allowed_len(b) >= sizeof o->allowed)
		return 0;
	memcpy(o->name, fzn_objects_row_name_ptr(b), fzn_objects_row_name_len(b));
	memcpy(o->value, fzn_objects_row_value_ptr(b), fzn_objects_row_value_len(b));
	memcpy(o->allowed, fzn_objects_row_allowed_ptr(b), fzn_objects_row_allowed_len(b));
	o->at_ms = fzn_objects_row_at_ms_get(b);
	/* BY EMPTY while none was set, as the text verbs say `-`. */
	if (memcmp(fzn_objects_row_by_ptr(b), none, 32) != 0) fzn_hex_encode(fzn_objects_row_by_ptr(b), 32, o->by);
	return 1;
}

static void objects_each(void *ctx, const uint8_t *msg, size_t len) {
	struct objects_answer *a = ctx;
	const uint8_t *why = NULL;
	size_t why_len = 0;
	situ_msg_t m;
	situ_view_t v, b;
	if (a->bad) return;
	if (len && msg[0] == FZN_CMD_STATUS) {
		if (!fzn_status_read(msg, len, &a->code, &why, &why_len)) {
			a->bad = 1;
			return;
		}
		a->status_seen = 1;
		snprintf(a->why, sizeof a->why, "%.*s", (int)why_len, why ? (const char *)why : "");
		return;
	}
	situ_msg_init(&m, (uint8_t *)(uintptr_t)msg, (uint32_t)len);
	if (len > UINT32_MAX || fzn_objects_message_view(&m, 0u, (uint32_t)len, &v) != SITU_OK
	    || fzn_objects_message_validate(v) != SITU_OK || fzn_objects_message_op_get(v) != FZN_OBJECTS_OP_ROW
	    || fzn_objects_message_body_row_view(v, &b) != SITU_OK) {
		a->bad = 1;
		return;
	}
	if (a->list) {
		if (room_for(a->c, &a->list->entries, &a->list->room, a->list->count + 1,
		             sizeof *a->list->entries) != FZN_RPC_OK) {
			a->room_failed = 1;
			a->bad = 1;
			return;
		}
		if (!object_row_into(&a->list->entries[a->list->count], b)) {
			a->bad = 1;
			return;
		}
		a->list->count++;
	} else if (!a->one || a->rows || !object_row_into(a->one, b)) {
		a->bad = 1;
		return;
	}
	a->rows++;
}

/* The request asked; FZN_RPC_OK with *text 1 for the verb to be used. */
static int objects_ask(fzn_rpc_t *c, const uint8_t *req, size_t len, struct objects_answer *a, int *text) {
	a->c = c;
	const int rc = fzn_rpc_binary(c, req, len, objects_each, a, text);
	if (rc != FZN_RPC_OK || *text) return rc;
	if (a->room_failed) return c->error_code;
	if (a->bad) return unreadable(c);
	if (!a->status_seen && !a->rows) return unreadable(c);
	if (a->status_seen && a->code != FZN_STATUS_OK) {
		const int code = a->code == FZN_STATUS_DENIED          ? FZN_RPC_ERR_NOT_AUTHORIZED
		                 : a->code == FZN_STATUS_MALFORMED     ? FZN_RPC_ERR_MALFORMED
		                 : a->code == FZN_STATUS_UNSUPPORTED   ? FZN_RPC_ERR_UNKNOWN_MSG_TYPE
		                                                       : FZN_RPC_ERR_STORAGE_IO;
		return fail(c, code, a->why[0] ? a->why : "the node refused it");
	}
	/* TAKEN AND HELD TO ITS WINDOW, sec 1034, as the text leg says it. */
	c->held = a->status_seen && strcmp(a->why, "held") == 0;
	return FZN_RPC_OK;
}

/* A NAME AS THE SCHEMA TAKES IT: 1 to 32 bytes; the node judges the rest. */
static int object_name_ok(const char *name) {
	return name && *name && strlen(name) <= FZN_RPC_OBJECT_NAME_MAX;
}

int fzn_rpc_object_add(fzn_rpc_t *c, const char *name, const char *values) {
	uint8_t body[FZN_REQUEST_MAX], req[FZN_REQUEST_MAX], allowed[256];
	uint32_t body_len = 0, n = 0;
	size_t allowed_len = 0;
	struct objects_answer a;
	int text = 0, rc;
	/* THE WORDS JOINED as the node keeps them, `on|off`; none is `*`. */
	for (const char *p = values ? values : ""; *p;) {
		while (*p == ' ') p++;
		size_t w = strcspn(p, " ");
		if (!w) break;
		if (allowed_len + w + 1u > sizeof allowed) return encode_failed(c);
		if (allowed_len) allowed[allowed_len++] = '|';
		memcpy(allowed + allowed_len, p, w);
		allowed_len += w;
		p += w;
	}
	if (!allowed_len) allowed[allowed_len++] = '*';
	if (!object_name_ok(name)
	    || fzn_objects_add_build(body, sizeof body, (const uint8_t *)name, (uint32_t)strlen(name), allowed,
	                             (uint32_t)allowed_len, &body_len) != SITU_OK
	    || fzn_objects_message_build_add(req, sizeof req, (uint8_t)FZN_CMD_OBJECTS, body, body_len, &n)
	               != SITU_OK)
		return object_add_text(c, name, values);
	memset(&a, 0, sizeof a);
	rc = objects_ask(c, req, n, &a, &text);
	return text ? object_add_text(c, name, values) : rc;
}

int fzn_rpc_object_set(fzn_rpc_t *c, const char *name, const char *value) {
	uint8_t body[FZN_REQUEST_MAX], req[FZN_REQUEST_MAX];
	uint32_t body_len = 0, n = 0;
	struct objects_answer a;
	int text = 0, rc;
	if (!object_name_ok(name) || !value || !*value || strlen(value) > FZN_RPC_OBJECT_VALUE_MAX
	    || fzn_objects_set_build(body, sizeof body, (const uint8_t *)name, (uint32_t)strlen(name),
	                             (const uint8_t *)value, (uint32_t)strlen(value), &body_len) != SITU_OK
	    || fzn_objects_message_build_set(req, sizeof req, (uint8_t)FZN_CMD_OBJECTS, body, body_len, &n)
	               != SITU_OK)
		return object_set_text(c, name, value);
	memset(&a, 0, sizeof a);
	rc = objects_ask(c, req, n, &a, &text);
	return text ? object_set_text(c, name, value) : rc;
}

/* `remove` and `get` ask by a name alone. */
static int object_named(uint8_t *req, size_t cap, int get, const char *name, uint32_t *n) {
	uint8_t body[64];
	uint32_t body_len = 0;
	if (!object_name_ok(name)
	    || fzn_objects_named_build(body, sizeof body, (const uint8_t *)name, (uint32_t)strlen(name), &body_len)
	               != SITU_OK)
		return 0;
	return (get ? fzn_objects_message_build_get(req, (uint32_t)cap, (uint8_t)FZN_CMD_OBJECTS, body, body_len, n)
	            : fzn_objects_message_build_remove(req, (uint32_t)cap, (uint8_t)FZN_CMD_OBJECTS, body,
	                                               body_len, n)) == SITU_OK;
}

int fzn_rpc_object_remove(fzn_rpc_t *c, const char *name) {
	uint8_t req[128];
	uint32_t n = 0;
	struct objects_answer a;
	int text = 0, rc;
	if (!object_named(req, sizeof req, 0, name, &n)) return object_remove_text(c, name);
	memset(&a, 0, sizeof a);
	rc = objects_ask(c, req, n, &a, &text);
	return text ? object_remove_text(c, name) : rc;
}

int fzn_rpc_object_get(fzn_rpc_t *c, const char *name, fzn_rpc_object_t *out, int *found) {
	uint8_t req[128];
	uint32_t n = 0;
	struct objects_answer a;
	int text = 0, rc;
	*found = 0;
	if (!object_named(req, sizeof req, 1, name, &n)) return object_get_text(c, name, out, found);
	memset(&a, 0, sizeof a);
	a.one = out;
	rc = objects_ask(c, req, n, &a, &text);
	if (text) return object_get_text(c, name, out, found);
	/* NO ROW, a STATUS ok: no such object, as the text verb's `absent`. */
	if (rc == FZN_RPC_OK) *found = a.rows == 1;
	return rc;
}

int fzn_rpc_object_list(fzn_rpc_t *c, fzn_rpc_object_list_resp_t *out) {
	uint8_t req[8];
	uint32_t n = 0;
	struct objects_answer a;
	int text = 0, rc;
	out->count = 0;
	if (fzn_objects_message_build_list(req, sizeof req, (uint8_t)FZN_CMD_OBJECTS, NULL, 0, &n) != SITU_OK)
		return object_list_text(c, out);
	memset(&a, 0, sizeof a);
	a.list = out;
	rc = objects_ask(c, req, n, &a, &text);
	if (text) return object_list_text(c, out);
	/* A LIST ENDS WITH ITS STATUS: one that stopped before it is not whole. */
	if (rc == FZN_RPC_OK && !a.status_seen) return unreadable(c);
	return rc;
}

/*
 * EVERY CONVERSATION'S NEWEST LINE AND COUNT IN BINARY, fuzznet sec 1155:
 * FZN_CMD_MESSAGES with `newest` or `unread`, a row each and a STATUS ok back
 * -- what a conversation list asks on every refresh. The text verbs above are
 * kept where the node or this client speaks text alone for it.
 */
struct conversations_answer {
	fzn_rpc_newest_entry_t *newest;
	fzn_rpc_unread_entry_t *unread;
	fzn_rpc_inbox_entry_t *lines; /* a conversation's lines, sec 1159 */
	size_t cap, *count, *total;
	int bad, status_seen;
	fzn_status_t code;
	char why[FZN_STATUS_WHY_MAX + 1];
};

static void conversations_each(void *ctx, const uint8_t *msg, size_t len) {
	struct conversations_answer *a = ctx;
	const uint8_t *why = NULL;
	size_t why_len = 0;
	situ_msg_t m;
	situ_view_t v, b;
	if (a->bad) return;
	if (len && msg[0] == FZN_CMD_STATUS) {
		if (!fzn_status_read(msg, len, &a->code, &why, &why_len)) {
			a->bad = 1;
			return;
		}
		a->status_seen = 1;
		snprintf(a->why, sizeof a->why, "%.*s", (int)why_len, why ? (const char *)why : "");
		return;
	}
	situ_msg_init(&m, (uint8_t *)(uintptr_t)msg, (uint32_t)len);
	if (a->status_seen || len > UINT32_MAX || fzn_messages_local_message_view(&m, 0u, (uint32_t)len, &v) != SITU_OK
	    || fzn_messages_local_message_validate(v) != SITU_OK) {
		a->bad = 1;
		return;
	}
	(*a->total)++;
	if (a->newest && fzn_messages_local_message_op_get(v) == FZN_MESSAGES_LOCAL_OP_NEWEST_ROW
	    && fzn_messages_local_message_body_newest_row_view(v, &b) == SITU_OK) {
		if (*a->count == a->cap) return;
		fzn_rpc_newest_entry_t *e = &a->newest[*a->count];
		memset(e, 0, sizeof *e);
		memcpy(e->key, fzn_messages_local_newest_row_key_ptr(b), 32);
		e->stime_ms = fzn_messages_local_newest_row_stime_ms_get(b);
		e->outgoing = fzn_messages_local_newest_row_outgoing_get(b);
		e->kind = (uint8_t)fzn_messages_local_newest_row_kind_get(b);
		e->sender_len = fzn_messages_local_newest_row_sender_len(b);
		e->text_len = fzn_messages_local_newest_row_text_len(b);
		if (e->sender_len > FZN_RPC_PEER_NAME_MAX) e->sender_len = FZN_RPC_PEER_NAME_MAX;
		if (e->text_len > FZN_RPC_NEWEST_TEXT_MAX) e->text_len = FZN_RPC_NEWEST_TEXT_MAX;
		memcpy(e->sender, fzn_messages_local_newest_row_sender_ptr(b), e->sender_len);
		memcpy(e->text, fzn_messages_local_newest_row_text_ptr(b), e->text_len);
		(*a->count)++;
	} else if (a->lines && fzn_messages_local_message_op_get(v) == FZN_MESSAGES_LOCAL_OP_LINE_ROW
	           && fzn_messages_local_message_body_line_row_view(v, &b) == SITU_OK) {
		/* A GROUP'S LINE IS NOT AN INBOX LINE, as the text listing skips
		 * it: a group's lines are read by their own call. */
		if (fzn_messages_local_line_row_group_get(b) || *a->count == a->cap) return;
		fzn_rpc_inbox_entry_t *e = &a->lines[*a->count];
		memset(e, 0, sizeof *e);
		memcpy(e->sender_host_pubkey, fzn_messages_local_line_row_key_ptr(b), 32);
		memcpy(e->commitment, fzn_messages_local_line_row_id_ptr(b), 16);
		e->sender_name_len = fzn_messages_local_line_row_name_len(b);
		if (e->sender_name_len > FZN_RPC_PEER_NAME_MAX) e->sender_name_len = FZN_RPC_PEER_NAME_MAX;
		memcpy(e->sender_name, fzn_messages_local_line_row_name_ptr(b), e->sender_name_len);
		e->outgoing = fzn_messages_local_line_row_outgoing_get(b);
		e->state = fzn_messages_local_line_row_state_get(b);
		/* fuzznet's times are milliseconds and the clients' unix seconds. */
		e->stime = fzn_messages_local_line_row_stime_ms_get(b) / 1000u;
		e->rtime = fzn_messages_local_line_row_written_ms_get(b) / 1000u;
		e->text_len = fzn_messages_local_line_row_text_len(b);
		if (e->text_len > FZN_RPC_PEER_TEXT_MAX) e->text_len = FZN_RPC_PEER_TEXT_MAX;
		memcpy(e->text, fzn_messages_local_line_row_text_ptr(b), e->text_len);
		(*a->count)++;
	} else if (a->unread && fzn_messages_local_message_op_get(v) == FZN_MESSAGES_LOCAL_OP_UNREAD_ROW
	           && fzn_messages_local_message_body_unread_row_view(v, &b) == SITU_OK) {
		if (*a->count == a->cap) return;
		fzn_rpc_unread_entry_t *e = &a->unread[*a->count];
		memset(e, 0, sizeof *e);
		memcpy(e->key, fzn_messages_local_unread_row_key_ptr(b), 32);
		e->count = fzn_messages_local_unread_row_count_get(b);
		e->more = fzn_messages_local_unread_row_more_get(b);
		(*a->count)++;
	} else {
		a->bad = 1;
	}
}

/* The listing asked in binary; FZN_RPC_OK with *text 1 for the verb to be
 * used. `lines` is a lines request already built, for op LINES. */
static int conversations_ask(fzn_rpc_t *c, uint8_t op, struct conversations_answer *a, int *text,
                             const uint8_t *lines, uint32_t lines_len) {
	uint8_t req[8];
	uint32_t n = 0;
	const int given = op == FZN_MESSAGES_LOCAL_OP_LINES || op == FZN_MESSAGES_LOCAL_OP_SEND;
	const situ_err_t built = given ? SITU_OK
	                         : op == FZN_MESSAGES_LOCAL_OP_NEWEST
	                                 ? fzn_messages_local_message_build_newest(req, sizeof req, (uint8_t)FZN_CMD_MESSAGES,
	                                                                           NULL, 0, &n)
	                                 : fzn_messages_local_message_build_unread(req, sizeof req, (uint8_t)FZN_CMD_MESSAGES,
	                                                                           NULL, 0, &n);
	if (built != SITU_OK) {
		*text = 1;
		return FZN_RPC_OK;
	}
	const int rc = given ? fzn_rpc_binary(c, lines, lines_len, conversations_each, a, text)
	                     : fzn_rpc_binary(c, req, n, conversations_each, a, text);
	if (rc != FZN_RPC_OK || *text) return rc;
	if (a->bad) return unreadable(c);
	/* A LISTING ENDS WITH ITS STATUS: one that stopped before it is not whole. */
	if (!a->status_seen) return unreadable(c);
	if (a->code != FZN_STATUS_OK)
		return fail(c, a->code == FZN_STATUS_DENIED ? FZN_RPC_ERR_NOT_AUTHORIZED
		               : a->code == FZN_STATUS_UNSUPPORTED ? FZN_RPC_ERR_UNKNOWN_MSG_TYPE
		                                                   : FZN_RPC_ERR_STORAGE_IO,
		            a->why[0] ? a->why : "the node refused it");
	return FZN_RPC_OK;
}

int fzn_rpc_newest_all(fzn_rpc_t *c, fzn_rpc_newest_entry_t *out, size_t cap, size_t *count,
                       size_t *total) {
	struct conversations_answer a;
	int text = 0, rc;
	*count = 0;
	*total = 0;
	memset(&a, 0, sizeof a);
	a.newest = out;
	a.cap = cap;
	a.count = count;
	a.total = total;
	rc = conversations_ask(c, FZN_MESSAGES_LOCAL_OP_NEWEST, &a, &text, NULL, 0);
	if (!text) return rc;
	*count = 0;
	*total = 0;
	return newest_all_text(c, out, cap, count, total);
}

int fzn_rpc_unread_all(fzn_rpc_t *c, fzn_rpc_unread_entry_t *out, size_t cap, size_t *count,
                       size_t *total) {
	struct conversations_answer a;
	int text = 0, rc;
	*count = 0;
	*total = 0;
	memset(&a, 0, sizeof a);
	a.unread = out;
	a.cap = cap;
	a.count = count;
	a.total = total;
	rc = conversations_ask(c, FZN_MESSAGES_LOCAL_OP_UNREAD, &a, &text, NULL, 0);
	if (!text) return rc;
	*count = 0;
	*total = 0;
	return unread_all_text(c, out, cap, count, total);
}

/* A LINE SENT IN BINARY WHERE WHO IS A KEY, sec 1161: a contact's root key
 * or a group's id in 64 hex, the text whole however long -- no file staged
 * for the node to read, which a node that shares no directory with its
 * client (an Android app's) cannot. *by_verb 1 when it is to go by the verb:
 * a name, or a node that reads no binary. */
static int send_in_binary(fzn_rpc_t *c, const char *who, size_t who_len, int attach, const uint8_t *root,
                          const char *text, size_t text_len, int *by_verb) {
	static const uint8_t no_root[32];
	static uint8_t inner[640], req[660];
	uint8_t key[32], id[16];
	uint32_t inner_len = 0, req_len = 0;
	char hex[65];
	struct conversations_answer a;
	size_t count = 0, total = 0;
	int rc;
	*by_verb = 1;
	if (who_len != 64 || text_len > 512u || (attach && !root)) return FZN_RPC_OK;
	memcpy(hex, who, 64);
	hex[64] = '\0';
	if (fzn_hex_decode(hex, key, sizeof key) != 0) return FZN_RPC_OK;
	if (fzn_rpc_entropy(id, sizeof id) != 0) {
		*by_verb = 0;
		return node_unasked(c, FZN_RPC_ERR_ENTROPY, "no randomness for the line's id");
	}
	if (fzn_messages_local_send_build(inner, sizeof inner, key, id, (uint8_t)(attach ? 1 : 0),
	                                  attach ? root : no_root, (const uint8_t *)text, (uint32_t)text_len,
	                                  &inner_len) != SITU_OK
	    || fzn_messages_local_message_build_send(req, sizeof req, (uint8_t)FZN_CMD_MESSAGES, inner, inner_len,
	                                             &req_len) != SITU_OK)
		return FZN_RPC_OK;
	memset(&a, 0, sizeof a);
	a.count = &count;
	a.total = &total;
	rc = conversations_ask(c, FZN_MESSAGES_LOCAL_OP_SEND, &a, by_verb, req, req_len);
	if (*by_verb) return FZN_RPC_OK;
	/* NOBODY BY THAT KEY is no peer, as the verb's refusal of a WHO is. */
	if (rc != FZN_RPC_OK && a.status_seen && a.code == FZN_STATUS_ERROR
	    && strncmp(a.why, "no contact or group", 19) == 0)
		return fail(c, FZN_RPC_ERR_NO_PEER, a.why);
	return rc;
}

int fzn_rpc_inbox_lines(fzn_rpc_t *c, const char *peer, size_t peer_len, fzn_rpc_inbox_entry_t *out,
                         size_t cap, size_t *count) {
	/* IN BINARY WHERE WHO IS A KEY, OR EVERYONE, sec 1159: the request
	 * carries a key, never a name (the holder's: names are presentation),
	 * so a contact asked for by name is asked by the verb, which names it. */
	uint8_t key[32];
	char hex[65];
	if (peer_len == 64) {
		memcpy(hex, peer, 64);
		hex[64] = '\0';
	}
	if (!peer_len || (peer_len == 64 && fzn_hex_decode(hex, key, sizeof key) == 0)) {
		static uint8_t inner[64], req[80];
		uint32_t inner_len = 0, req_len = 0;
		struct conversations_answer a;
		size_t total = 0;
		int text = 0, rc;
		if (!peer_len) memset(key, 0, sizeof key);
		*count = 0;
		memset(&a, 0, sizeof a);
		a.lines = out;
		a.cap = cap;
		a.count = count;
		a.total = &total;
		if (fzn_messages_local_lines_ask_build(inner, sizeof inner, (uint8_t)(peer_len ? 1 : 0), key, 0u,
		                                       (uint16_t)(cap > 0xffffu ? 0xffffu : cap), &inner_len)
		            == SITU_OK
		    && fzn_messages_local_message_build_lines(req, sizeof req, (uint8_t)FZN_CMD_MESSAGES, inner, inner_len,
		                                              &req_len)
		               == SITU_OK) {
			rc = conversations_ask(c, FZN_MESSAGES_LOCAL_OP_LINES, &a, &text, req, req_len);
			if (!text) return rc;
		}
		*count = 0;
	}
	return node_inbox_lines(c, peer, peer_len, out, cap, count);
}

