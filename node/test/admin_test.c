/* node/admin.h through the real local path: a request line over a socketpair,
 * `fzn_node_serve_local` with the admin handler, and the reply read back by
 * the client library. Under real Monocypher, with a node and a device built by
 * `node/identity.h`. sec 378.
 *
 * THE CASE THAT MATTERS is pairing into a RUNNING node: after `add peer`, the
 * state the loop reads holds the device, and the card in the reply is one the
 * device accepts. The reply is 685 bytes, past the 512 the grammar used to
 * allow, so this is also the test that the raised bound is real at both ends
 * -- the node's compose and the client's framer.
 */

#include "../../log/cause.h"
#include "../../notes/share.h"
#include "../groups.h"
#include "../admin.h"
#include "../roots.h"
#include "../journal.h"
#include "../apply.h"
#include "../settings.h"
#include "../../log/rules.h"
#include "../roster.h"
#include "../types.h"
#include "../succession.h"
#include "../identity.h"
#include "../peer_persist.h"
#include "../received.h"
#include "../members.h"
#include "../../notes/received.h"
#include "../../chain/service.h"
#include "../../chain/sign_monocypher.h"
#include "../../constant_time/constant_time.h"
#include "../../provision/provision.h"
#include "../../local/client.h"
#include "../../session/agree_monocypher.h"
#include "../../session/hash_monocypher.h"
#include "../../session/random_system.h"

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int failures;
static int checks;

static void check_at(int ok, int line, const char *what)
{
	checks++;
	if (!ok) {
		failures++;
		printf("  FAIL admin_test.c:%d: %s\n", line, what);
	}
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, (what))

/* ---- an in-memory store that can list, as pair_test's ---------------- */

struct mem_entry {
	int used;
	fzn_persist_slot_t slot;
	int has_subject;
	uint8_t subject[FZN_PUBKEY_LEN];
	uint8_t bytes[FZN_NODE_PEER_BLOB_MAX];
	size_t len;
};

/* 256 rows: every pairing logs its grant since sec 497, the seventeen
 * paired below took a row each from cases that had sized this at 64, and
 * sec 704's case lists more contacts than the admin's own room. */
struct mem_store {
	struct mem_entry e[256];
	unsigned saves;
};

static struct mem_entry *find(struct mem_store *m, fzn_persist_slot_t slot,
                              const uint8_t *subject, int make)
{
	size_t i;
	struct mem_entry *free_one = NULL;

	for (i = 0; i < sizeof(m->e) / sizeof(m->e[0]); i++) {
		struct mem_entry *x = &m->e[i];

		if (!x->used) {
			if (!free_one)
				free_one = x;
			continue;
		}
		if (x->slot == slot && x->has_subject == (subject != NULL)
		    && (!subject || memcmp(x->subject, subject, FZN_PUBKEY_LEN) == 0))
			return x;
	}
	if (!make || !free_one)
		return NULL;
	memset(free_one, 0, sizeof(*free_one));
	free_one->used = 1;
	free_one->slot = slot;
	free_one->has_subject = subject != NULL;
	if (subject)
		memcpy(free_one->subject, subject, FZN_PUBKEY_LEN);
	return free_one;
}

/* Rows held in `slot`. */
static size_t rows_in(const struct mem_store *m, fzn_persist_slot_t slot)
{
	size_t i, n = 0;

	for (i = 0; i < sizeof(m->e) / sizeof(m->e[0]); i++)
		if (m->e[i].used && m->e[i].slot == slot)
			n++;
	return n;
}

static int mem_load(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject, uint8_t *out,
                    size_t cap, size_t *len)
{
	struct mem_entry *x = find((struct mem_store *)ctx, slot, subject, 0);

	if (!x || x->len > cap)
		return 0;
	memcpy(out, x->bytes, x->len);
	*len = x->len;
	return 1;
}

static int mem_save(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject,
                    const uint8_t *bytes, size_t len)
{
	struct mem_store *m = (struct mem_store *)ctx;
	struct mem_entry *x;

	if (len > sizeof(x->bytes))
		return 0;
	x = find(m, slot, subject, 1);
	if (!x)
		return 0;
	memcpy(x->bytes, bytes, len);
	x->len = len;
	m->saves++;
	return 1;
}

static int mem_remove(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject)
{
	struct mem_entry *x = find((struct mem_store *)ctx, slot, subject, 0);

	if (x)
		memset(x, 0, sizeof(*x));
	return 1;
}

static int mem_list(void *ctx, fzn_persist_slot_t slot, uint8_t *out, size_t max,
                    size_t *count)
{
	struct mem_store *m = (struct mem_store *)ctx;
	size_t i, n = 0;

	for (i = 0; i < sizeof(m->e) / sizeof(m->e[0]); i++) {
		if (!m->e[i].used || m->e[i].slot != slot || !m->e[i].has_subject)
			continue;
		if (n >= max)
			return 0;
		memcpy(out + (n * FZN_PUBKEY_LEN), m->e[i].subject, FZN_PUBKEY_LEN);
		n++;
	}
	*count = n;
	return 1;
}

struct node {
	struct mem_store store;
	fzn_persist_ops_t ops;
	fzn_sign_monocypher_t signer;
	fzn_sign_ops_t sign;
	fzn_sign_seat_t seat;
	fzn_agree_secret_t agree_secret;
	fzn_trust_t trust;
	fzn_node_identity_t id;
};

static fzn_hash_ops_t hash_ops;
static fzn_agree_ops_t agree_ops;
static fzn_random_ops_t rng_ops;

static int node_up(struct node *n)
{
	fzn_node_identity_env_t env;

	memset(n, 0, sizeof(*n));
	n->ops.load = mem_load;
	n->ops.save = mem_save;
	n->ops.list = mem_list;
	n->ops.remove = mem_remove;
	n->ops.ctx = &n->store;
	fzn_sign_monocypher_init(&n->sign, &n->signer);
	fzn_sign_monocypher_seat_init(&n->seat, &n->signer);
	fzn_trust_init(&n->trust);
	env.store = &n->ops;
	env.rng = &rng_ops;
	env.seat = &n->seat;
	env.sign = &n->sign;
	env.hash = &hash_ops;
	env.agree = &agree_ops;
	env.log = NULL;
	return fzn_node_identity_create(&env, 1000u, &n->agree_secret, &n->trust, &n->id)
	       == FZN_NODE_IDENTITY_OK;
}

static uint64_t fixed_clock(void)
{
	return 2000u;
}

/* THIS NODE'S PROOF as a host of its user, for a group act: it is its own
 * root, so its prekey record and no chain. sec 626. */
static int group_signer(void *ctx, fzn_contact_device_t *out)
{
	const struct node *n = ctx;

	memset(out, 0, sizeof(*out));
	memcpy(out->owner, n->id.pubkey, FZN_PUBKEY_LEN);
	memcpy(out->record, n->id.prekey_record, FZN_PREKEY_LEN_TOTAL);
	return 1;
}

/* ---- the node's journal, sec 508: the act log its roots keep --------- */

#define JOURNAL_ROWS 128u

struct record_row {
	int used;
	uint8_t issuer[FZN_PUBKEY_LEN];
	uint32_t stream;
	uint64_t seq;
	uint8_t bytes[FZN_RECORD_MAX_LEN];
	size_t len;
};

static struct record_row journal_rows[JOURNAL_ROWS];

static struct record_row *record_row(const uint8_t issuer[FZN_PUBKEY_LEN], uint32_t stream,
                                     uint64_t seq, int make)
{
	size_t i;

	for (i = 0; i < JOURNAL_ROWS; i++)
		if (journal_rows[i].used && journal_rows[i].stream == stream
		    && journal_rows[i].seq == seq
		    && memcmp(journal_rows[i].issuer, issuer, FZN_PUBKEY_LEN) == 0)
			return &journal_rows[i];
	for (i = 0; make && i < JOURNAL_ROWS; i++)
		if (!journal_rows[i].used)
			return &journal_rows[i];
	return NULL;
}

static int record_put(void *ctx, const uint8_t issuer[FZN_PUBKEY_LEN], uint32_t stream,
                      uint64_t seq, const uint8_t *bytes, size_t len)
{
	struct record_row *r = record_row(issuer, stream, seq, 1);

	(void)ctx;
	if (!r || len > sizeof(r->bytes))
		return 0;
	r->used = 1;
	memcpy(r->issuer, issuer, FZN_PUBKEY_LEN);
	r->stream = stream;
	r->seq = seq;
	memcpy(r->bytes, bytes, len);
	r->len = len;
	return 1;
}

static int record_get(void *ctx, const uint8_t issuer[FZN_PUBKEY_LEN], uint32_t stream,
                      uint64_t seq, uint8_t *out, size_t cap, size_t *len_out, int *found_out)
{
	struct record_row *r = record_row(issuer, stream, seq, 0);

	(void)ctx;
	*found_out = r != NULL;
	if (!r || r->len > cap)
		return 0;
	memcpy(out, r->bytes, r->len);
	*len_out = r->len;
	return 1;
}

static const fzn_record_store_ops_t journal_ops = { record_put, record_get, NULL, NULL };
static fzn_node_journal_t journal;

static int journal_logged(void *ctx, const uint8_t pubkey[FZN_PUBKEY_LEN],
                          const fzn_sign_ops_t *sign, uint8_t kind,
                          const uint8_t act[FZN_ROOT_ACT_ID_LEN], const uint8_t *record,
                          size_t len)
{
	(void)kind;
	(void)act;
	return fzn_node_journal_append_object((fzn_node_journal_t *)ctx, pubkey, sign, record, len,
	                                      2000u, NULL)
	       == FZN_NODE_JOURNAL_OK;
}

/* The acts `key` has logged here: the records of its stream. */
static uint64_t acts_by(const uint8_t key[FZN_PUBKEY_LEN])
{
	size_t e;

	for (e = 0; e < journal.journal.used; e++)
		if (journal.journal.entries[e].stream == FZN_NODE_JOURNAL_STREAM
		    && memcmp(journal.journal.entries[e].issuer, key, FZN_PUBKEY_LEN) == 0)
			return journal.journal.entries[e].received;
	return 0;
}

/* The kind -- the object's tag -- of `key`'s record at `seq`, or 0. */
static uint32_t kind_at(const uint8_t key[FZN_PUBKEY_LEN], uint64_t seq)
{
	static uint8_t buf[FZN_RECORD_MAX_LEN];
	fzn_record_t rec;

	if (fzn_record_store_get(&journal.store, key, FZN_NODE_JOURNAL_STREAM, seq, buf,
	                         sizeof(buf), &rec) != FZN_RECORD_STORE_OK)
		return 0;
	return fzn_record_kind(rec);
}

static void hex(const uint8_t *in, size_t len, char *out)
{
	static const char H[] = "0123456789abcdef";
	size_t i;

	for (i = 0; i < len; i++) {
		out[i * 2u] = H[in[i] >> 4];
		out[(i * 2u) + 1u] = H[in[i] & 0x0fu];
	}
	out[len * 2u] = '\0';
}

/* One request over a socketpair, served by the admin handler, the reply read
 * by the client library as a caller would. */
/* Whether a reply's detail, `len` bytes and not terminated, holds `what`. */
/* The count a listing of rules begins with. */
static size_t rules_counted(const uint8_t *detail, size_t len)
{
	size_t i, n = 0;

	for (i = 0; i < len && detail[i] >= '0' && detail[i] <= '9'; i++)
		n = (n * 10u) + (size_t)(detail[i] - '0');
	return n;
}

static uint64_t settings_clock(void)
{
	return 1000u;
}

/* What the remote-verb hook was told last. */
static char remote_heard[64];

static void remote_ran_stub(void *ctx, const uint8_t *sender, const uint8_t *what, size_t len)
{
	(void)ctx;
	(void)sender;
	snprintf(remote_heard, sizeof(remote_heard), "%.*s", (int)len, (const char *)what);
}

/* ROOM FOR CONTACTS, likewise: `list contact` moved onto `contacts_grown`. */
static fzn_contact_t *contacts_grown;
static size_t contacts_grown_cap, contacts_asked;

static int contacts_stub(void *ctx, size_t needed)
{
	fzn_node_admin_t *a = ctx;

	contacts_asked = needed;
	if (needed > contacts_grown_cap)
		return 0;
	a->contacts = contacts_grown;
	a->contacts_cap = contacts_grown_cap;
	return 1;
}

/* ROOM FOR THE ROSTER, sec 704: a roster found full moved onto
 * `roster_wide`. */
static fzn_roster_entry_t roster_wide[128];
static fzn_roster_writer_t roster_wide_writers[16];
static size_t roster_asked;

static int roster_stub(void *ctx, fzn_node_roster_t *nr)
{
	size_t entries = 0, writers = 0;

	(void)ctx;
	roster_asked++;
	return fzn_node_roster_wants(nr, &entries, &writers) && entries <= 128u && writers <= 16u
	       && fzn_node_roster_use(nr, roster_wide, 128u, roster_wide_writers, 16u)
	                  == FZN_NODE_ROSTER_OK;
}

/* ROOM FOR PEERS, as fuzznetd gives it, sec 704: the admin moved onto
 * `room_grown`, and the count asked noted. */
static fzn_node_peer_t *room_grown;
static size_t room_grown_cap, room_asked;

static int room_stub(void *ctx, size_t needed)
{
	fzn_node_admin_t *a = ctx;

	room_asked = needed;
	if (needed > room_grown_cap)
		return 0;
	a->peers = room_grown;
	a->peers_cap = room_grown_cap;
	return 1;
}

/* `line` from `sender` as a member's remote request: its reply's kind. */
static fzn_reply_t remote_said(fzn_node_admin_t *admin, const uint8_t *sender, const char *line,
                               uint8_t *out, size_t cap)
{
	const uint8_t *detail = NULL;
	size_t detail_len = 0, n;
	fzn_opened_t rq;

	memset(&rq, 0, sizeof(rq));
	rq.capability = admin->state->config.remote_capability.b;
	rq.sender = sender;
	rq.payload = (const uint8_t *)line;
	rq.payload_len = strlen(line);
	n = fzn_node_admin_remote(admin, FZN_NODE_REMOTE_GRANTED, &rq, out, cap);
	/* THE LINE'S TERMINATOR OFF, as `ask` takes it off. */
	if (n && out[n - 1u] == '\n')
		n--;
	return n ? fzn_reply_of(out, n, &detail, &detail_len) : FZN_REPLY_NONE;
}

/* Whether this host's setting for `rule_text`'s rule is in force. */
static int rule_in_settings(const fzn_node_settings_t *ns, fzn_scope_t scope,
                            const uint8_t *about, const char *rule_text)
{
	uint8_t key[FZN_NODE_SETTINGS_RULE_KEY_LEN], value[FZN_SETTING_VALUE_MAX];
	char text[FZN_RETAIN_TEXT_MAX];
	fzn_retain_rule_t rule;
	fzn_setting_rank_t rank;
	size_t len = 0, value_len = 0;

	return fzn_retain_parse(rule_text, strlen(rule_text), &rule) == FZN_RETAIN_OK
	       && fzn_retain_text(&rule, text, sizeof(text), &len) == FZN_RETAIN_OK
	       && fzn_node_settings_rule_key(&hash_ops, text, len, key)
	       && fzn_node_settings_get(ns, scope, about, key, sizeof(key), value, &value_len, &rank)
	       && value_len == len && memcmp(value, text, len) == 0;
}

/* `n` hex digits of `hex` into `out`: nonzero when every pair reads. */
static int unhex_into(const uint8_t *hex, size_t n, uint8_t *out)
{
	size_t i;

	if (n % 2u)
		return 0;
	for (i = 0; i < n; i++) {
		uint8_t c = hex[i], v;

		if (c >= '0' && c <= '9')
			v = (uint8_t)(c - '0');
		else if (c >= 'a' && c <= 'f')
			v = (uint8_t)(c - 'a' + 10);
		else
			return 0;
		if (i % 2u)
			out[i / 2u] = (uint8_t)(out[i / 2u] | v);
		else
			out[i / 2u] = (uint8_t)(v << 4);
	}
	return 1;
}

static int says(const uint8_t *detail, size_t len, const char *what)
{
	size_t n = strlen(what), i;

	for (i = 0; i + n <= len; i++)
		if (memcmp(detail + i, what, n) == 0)
			return 1;
	return 0;
}

/* A shelf's local hook that answers any `text` subject. sec 424. */
/* AN EXTENSION'S VERBS, sec 673: `get mine` answered, `get garbled` and
 * `get twice` answered outside the reply vocabulary and in two lines,
 * `list contact` -- which the admin answers itself -- claimed too, and
 * anything else declined. */
static int extension_asked;

static size_t extension_stub(void *ctx, fzn_origin_t origin, const fzn_request_t *request,
                             char *reply, size_t reply_cap)
{
	const char *say = NULL;

	(void)ctx;
	(void)origin;
	extension_asked++;
	if (request->arg_len == 4u && memcmp(request->arg, "mine", 4u) == 0)
		say = "ok extension\n";
	else if (request->arg_len == 7u && memcmp(request->arg, "garbled", 7u) == 0)
		say = "garbled extension\n";
	else if (request->arg_len == 5u && memcmp(request->arg, "twice", 5u) == 0)
		say = "ok one\nok two\n";
	else if (request->arg_len == 7u && memcmp(request->arg, "contact", 7u) == 0)
		say = "ok extension\n";
	if (!say || strlen(say) > reply_cap)
		return 0;
	memcpy(reply, say, strlen(say));
	return strlen(say);
}

/* ITS REMOTE REQUESTS, sec 674: type 128 answered with 129, whether the
 * sender came as a contact noted; anything else declined. */
static int extension_remote_contact = -1;
static int extension_remote_asked;

static size_t extension_remote_stub(void *ctx, const uint8_t *sender, int contact,
                                    const uint8_t *request, size_t request_len, uint8_t *reply,
                                    size_t reply_cap)
{
	(void)ctx;
	(void)sender;
	extension_remote_asked++;
	extension_remote_contact = contact;
	if (request_len < 2u || request[1] != 128u || reply_cap < 2u)
		return 0;
	reply[0] = request[0];
	reply[1] = 129u;
	return 2u;
}

/* ---- which hooks a remote caller reaches, sec 700 ------------------------ */

/* EVERY REMOTE HOOK, a bit each, set when it is asked; each answers nothing,
 * so the dispatch goes on to the next and the bits say every hook the
 * caller could reach. */
enum {
	R_RELAY = 1, R_EXTENSION = 2, R_CONTACT_DEVICES = 4, R_MESSAGES_CONTACT = 8,
	R_ROUTING = 16, R_NOTES = 32, R_TEXT_SHARED = 64, R_FILES_SHARED = 128, R_LOGS = 256,
	R_TEXT = 512, R_JOURNAL = 1024, R_HOLDINGS = 2048, R_MESSAGES = 4096
};
/* WHAT ONLY A MEMBER MAY REACH: a contact asking any of these is a leak. */
#define R_MEMBER_ONLY (R_LOGS | R_TEXT | R_JOURNAL | R_HOLDINGS | R_MESSAGES)
static unsigned reached_hooks;

static size_t r_relay(void *c, const uint8_t *s, const uint8_t *q, size_t l, uint8_t *o, size_t n)
{
	(void)c, (void)s, (void)q, (void)l, (void)o, (void)n;
	reached_hooks |= R_RELAY;
	return 0;
}

static size_t r_extension(void *c, const uint8_t *s, int k, const uint8_t *q, size_t l,
                          uint8_t *o, size_t n)
{
	(void)c, (void)s, (void)k, (void)q, (void)l, (void)o, (void)n;
	reached_hooks |= R_EXTENSION;
	return 0;
}

static size_t r_owner_contact_devices(void *c, const uint8_t *w, const uint8_t *q, size_t l,
                                      uint8_t *o, size_t n)
{
	(void)c, (void)w, (void)q, (void)l, (void)o, (void)n;
	reached_hooks |= R_CONTACT_DEVICES;
	return 0;
}

static size_t r_messages_contact(void *c, const uint8_t *w, const uint8_t *q, size_t l,
                                 uint8_t *o, size_t n)
{
	(void)c, (void)w, (void)q, (void)l, (void)o, (void)n;
	reached_hooks |= R_MESSAGES_CONTACT;
	return 0;
}

static size_t r_routing(void *c, const uint8_t *s, int k, const uint8_t *q, size_t l, uint8_t *o,
                        size_t n)
{
	(void)c, (void)s, (void)k, (void)q, (void)l, (void)o, (void)n;
	reached_hooks |= R_ROUTING;
	return 0;
}

static size_t r_notes(void *c, const uint8_t *s, int k, const uint8_t *q, size_t l, uint8_t *o,
                      size_t n)
{
	(void)c, (void)s, (void)k, (void)q, (void)l, (void)o, (void)n;
	reached_hooks |= R_NOTES;
	return 0;
}

static size_t r_text_shared(void *c, const uint8_t *s, const uint8_t *q, size_t l, uint8_t *o,
                            size_t n)
{
	(void)c, (void)s, (void)q, (void)l, (void)o, (void)n;
	reached_hooks |= R_TEXT_SHARED;
	return 0;
}

static size_t r_files_shared(void *c, const uint8_t *s, const uint8_t *q, size_t l, uint8_t *o,
                             size_t n)
{
	(void)c, (void)s, (void)q, (void)l, (void)o, (void)n;
	reached_hooks |= R_FILES_SHARED;
	return 0;
}

static size_t r_logs(void *c, const uint8_t *s, const uint8_t *q, size_t l, uint8_t *o, size_t n)
{
	(void)c, (void)s, (void)q, (void)l, (void)o, (void)n;
	reached_hooks |= R_LOGS;
	return 0;
}

static size_t r_text(void *c, const uint8_t *q, size_t l, uint8_t *o, size_t n)
{
	(void)c, (void)q, (void)l, (void)o, (void)n;
	reached_hooks |= R_TEXT;
	return 0;
}

static size_t r_journal(void *c, const uint8_t *q, size_t l, uint8_t *o, size_t n)
{
	(void)c, (void)q, (void)l, (void)o, (void)n;
	reached_hooks |= R_JOURNAL;
	return 0;
}

static size_t r_holdings(void *c, const uint8_t *s, const uint8_t *q, size_t l, uint8_t *o,
                         size_t n)
{
	(void)c, (void)s, (void)q, (void)l, (void)o, (void)n;
	reached_hooks |= R_HOLDINGS;
	return 0;
}

static size_t r_messages(void *c, const uint8_t *s, const uint8_t *q, size_t l, uint8_t *o,
                         size_t n)
{
	(void)c, (void)s, (void)q, (void)l, (void)o, (void)n;
	reached_hooks |= R_MESSAGES;
	return 0;
}

/* THE HOOKS `req` REACHES with `payload`, every one of `admin`'s stubbed
 * for the call and put back after. */
static unsigned hooks_reached(fzn_node_admin_t *admin, fzn_opened_t req, const uint8_t *payload,
                              size_t len)
{
	fzn_node_admin_t kept = *admin;
	uint8_t out[512];

	admin->relay_remote = r_relay;
	admin->extension_remote = r_extension;
	admin->contact_devices = r_owner_contact_devices;
	admin->messages_contact = r_messages_contact;
	admin->routing_remote = r_routing;
	admin->notes_remote = r_notes;
	admin->text_shared = r_text_shared;
	admin->files_shared = r_files_shared;
	admin->logs_remote = r_logs;
	admin->text_remote = r_text;
	admin->journal_remote = r_journal;
	admin->holdings_remote = r_holdings;
	admin->messages_remote = r_messages;
	reached_hooks = 0;
	req.payload = payload;
	req.payload_len = len;
	(void)fzn_node_admin_remote(admin, FZN_NODE_REMOTE_GRANTED, &req, out, sizeof(out));
	*admin = kept;
	return reached_hooks;
}

/* A REMOTE REQUEST OF BYTES, `len` of them, from `sender` granted the
 * remote capability: the reply's length. */
static size_t remote_bytes(fzn_node_admin_t *admin, const uint8_t *sender, const uint8_t *bytes,
                           size_t len, uint8_t *out, size_t cap)
{
	fzn_opened_t rq;

	memset(&rq, 0, sizeof(rq));
	rq.capability = admin->state->config.remote_capability.b;
	rq.sender = sender;
	rq.payload = bytes;
	rq.payload_len = len;
	return fzn_node_admin_remote(admin, FZN_NODE_REMOTE_GRANTED, &rq, out, cap);
}

static size_t text_local_stub(void *ctx, fzn_origin_t origin, const fzn_request_t *request,
                              char *reply, size_t reply_cap)
{
	size_t len = 0;

	(void)ctx;
	(void)origin;
	if (!request->arg || request->arg_len < 4u || memcmp(request->arg, "text", 4u) != 0
	    || fzn_reply_compose((uint8_t *)reply, reply_cap, &len, FZN_REPLY_OK,
	                         (const uint8_t *)"stub", 4u) != FZN_COMPOSE_OK)
		return 0;
	return len;
}

/* A server of members over a peer table, answering in pages of `cap` bytes;
 * `forge` names a key whose hop has a byte flipped on the way. sec 445. */
struct members_peer {
	const fzn_node_config_t *config;
	const fzn_node_peer_t *peers;
	size_t count;
	size_t cap;
	const uint8_t *forge; /* the key whose hop is altered, or NULL */
	const uint8_t *rename_from, *rename_to; /* a key relabelled, its chain kept */
	unsigned asked;
};

static int members_ask(void *ctx, const uint8_t *request, size_t request_len, uint8_t *reply,
                       size_t reply_cap, size_t *reply_len)
{
	struct members_peer *mp = (struct members_peer *)ctx;

	mp->asked++;
	*reply_len = fzn_node_members_answer(mp->config, mp->peers, mp->count, request, request_len,
	                                     reply, mp->cap < reply_cap ? mp->cap : reply_cap);
	if (mp->forge) {
		size_t at = FZN_NODE_MEMBERS_HEAD_LEN;

		while (at + FZN_PUBKEY_LEN + 1u <= *reply_len) {
			size_t hops = reply[at + FZN_PUBKEY_LEN];

			if (memcmp(reply + at, mp->forge, FZN_PUBKEY_LEN) == 0)
				reply[at + FZN_PUBKEY_LEN + 1u + 90u] ^= 0x01u;
			at += FZN_PUBKEY_LEN + 1u + (hops * FZN_HOP_LEN);
		}
	}
	if (mp->rename_from) {
		size_t at = FZN_NODE_MEMBERS_HEAD_LEN;

		while (at + FZN_PUBKEY_LEN + 1u <= *reply_len) {
			size_t hops = reply[at + FZN_PUBKEY_LEN];

			if (memcmp(reply + at, mp->rename_from, FZN_PUBKEY_LEN) == 0)
				memcpy(reply + at, mp->rename_to, FZN_PUBKEY_LEN);
			at += FZN_PUBKEY_LEN + 1u + (hops * FZN_HOP_LEN);
		}
	}
	return *reply_len > 0u;
}

static int listed(uint8_t (*keys)[FZN_PUBKEY_LEN], size_t n, const uint8_t *key)
{
	size_t i;

	for (i = 0; i < n; i++)
		if (memcmp(keys[i], key, FZN_PUBKEY_LEN) == 0)
			return 1;
	return 0;
}

/* A contact's text hook that records who asked and answers two bytes.
 * sec 438. */
/* WHO THE TEXT HOOK WAS TOLD ASKS, as bytes: the admin hands over its
 * own copy of the user a host speaks for (sec 630). */
static uint8_t text_shared_sender[FZN_PUBKEY_LEN];
static int text_shared_told;

static size_t text_shared_stub(void *ctx, const uint8_t *sender, const uint8_t *request,
                               size_t request_len, uint8_t *reply, size_t reply_cap)
{
	(void)ctx;
	(void)request;
	(void)request_len;
	text_shared_told = sender != NULL;
	if (sender)
		memcpy(text_shared_sender, sender, FZN_PUBKEY_LEN);
	if (reply_cap < 2u)
		return 0;
	reply[0] = 1u;
	reply[1] = 2u;
	return 2u;
}

/* A notes hook that records whether it was asked as a contact, and answers
 * a reply so the admin takes it. sec 436. */
static int notes_shared_seen = -1;

/* The logs hook, sec 463: called, and with a query. */
static int logs_calls;

static size_t logs_stub(void *ctx, const uint8_t *sender, const uint8_t *request,
                        size_t request_len, uint8_t *reply, size_t reply_cap)
{
	(void)ctx;
	(void)sender;
	if (request_len < 2u || request[0] != 4u || reply_cap < 2u)
		return 0;
	logs_calls++;
	reply[0] = 4u;
	reply[1] = 2u;
	return 2u;
}

static uint8_t notes_seen[64];
static size_t notes_seen_len;

/* The caused hook, sec 462: who asked, and for which entry. */
static const uint8_t *caused_sender;
static fzn_entry_name_t caused_cause;
static int caused_calls;

static void caused_stub(void *ctx, const uint8_t *sender, const fzn_entry_name_t *cause,
                        const fzn_entry_name_t *origin)
{
	(void)ctx;
	(void)origin;
	caused_sender = sender;
	caused_cause = *cause;
	caused_calls++;
}

static size_t notes_remote_stub(void *ctx, const uint8_t *sender, int shared,
                                const uint8_t *request, size_t request_len, uint8_t *reply,
                                size_t reply_cap)
{
	(void)ctx;
	(void)sender;
	notes_shared_seen = shared;
	/* WHAT ARRIVED, so a test can see an envelope was taken off. */
	notes_seen_len = request_len < sizeof(notes_seen) ? request_len : sizeof(notes_seen);
	memcpy(notes_seen, request, notes_seen_len);
	if (reply_cap < 2u)
		return 0;
	reply[0] = 2u;
	reply[1] = 9u;
	return 2u;
}

static int ask(fzn_node_admin_t *admin, const fzn_peer_t *who, const char *line,
               uint8_t *reply, size_t cap, size_t *reply_len)
{
	int sv[2];
	int ok;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
		return 0;
	ok = write(sv[0], line, strlen(line)) == (ssize_t)strlen(line)
	     && write(sv[0], "\n", 1) == 1;
	if (ok)
		(void)fzn_node_serve_local(&admin->state->config, sv[1], who,
		                           fzn_node_admin_handle, admin);
	ok = ok && fzn_client_recv(sv[0], reply, cap, reply_len, 2000u) == FZN_CLIENT_OK;
	close(sv[0]);
	close(sv[1]);
	return ok;
}

int main(void)
{
	static struct node node, device;
	static fzn_node_peer_t peers[32];
	static uint8_t reply[FZN_REPLY_MAX + 1u];
	static char line[FZN_REQUEST_MAX];
	fzn_node_state_t state;
	fzn_node_admin_t admin;
	fzn_peer_t owner, member;
	fzn_node_pairing_t pairing;
	uint8_t card[FZN_PROVISION_MAX_LEN];
	char prekey_hex[(FZN_PREKEY_LEN_TOTAL * 2u) + 1u];
	const uint8_t *detail = NULL;
	size_t reply_len = 0, detail_len = 0, card_len = 0;

	fzn_hash_monocypher_init(&hash_ops);
	fzn_agree_monocypher_init(&agree_ops);
	fzn_random_system_init(&rng_ops);
	CHECK(node_up(&node) && node_up(&device), "fixture: the nodes would not come up");

	memset(&state, 0, sizeof(state));
	state.config.uid = 1000u;
	state.config.local_origins = FZN_ORIGIN_BIT(FZN_ORIGIN_SAME_USER)
	                             | FZN_ORIGIN_BIT(FZN_ORIGIN_LOCAL);
	state.config.has_service_gid = 1;
	state.config.service_gid = 77u;
	state.config.serves_remote = 1;
	memcpy(state.config.root, node.id.pubkey, FZN_PUBKEY_LEN);
	CHECK(fzn_service_capability(7u, 3u, NULL, 0, &hash_ops, &state.config.remote_capability)
	              == FZN_CHAIN_OK,
	      "fixture: capability");
	state.clock = fixed_clock;

	memset(&admin, 0, sizeof(admin));
	admin.state = &state;
	admin.peers = peers;
	admin.peers_cap = 32;
	admin.id = &node.id;
	admin.store = &node.ops;
	admin.rng = &rng_ops;
	admin.card_lifetime = 86400u;
	{
		static fzn_revocation_t revoked_entries[8];
		static fzn_revocation_store_t revoked;

		static fzn_revocation_admin_t admins[8];
		static fzn_revocation_confirm_t confirms[8];

		/* THE ADMIN CAPABILITY AND ITS TABLES, sec 416, at quorum 1 so
		 * nothing else here changes. */
		CHECK(fzn_revocation_store_init(&revoked, revoked_entries, 8) == FZN_CHAIN_OK
		              && fzn_service_capability(7u, 3u, (const uint8_t *)FZN_NODE_ADMIN_NAME,
		                                        sizeof(FZN_NODE_ADMIN_NAME) - 1u, &hash_ops,
		                                        &state.config.admin_capability) == FZN_CHAIN_OK
		              && fzn_revocation_store_set_quorum(&revoked, 1u,
		                                                 &state.config.admin_capability,
		                                                 admins, 8u) == FZN_CHAIN_OK
		              && fzn_revocation_store_set_confirmations(&revoked, confirms, 8u,
		                                                        &hash_ops) == FZN_CHAIN_OK,
		      "fixture: revocation store");
		state.config.has_admin = 1;
		/* THE RETENTION CAPABILITY, sec 567, derived as fuzznetd derives it. */
		CHECK(fzn_service_capability(7u, 3u, (const uint8_t *)FZN_NODE_RETENTION_NAME,
		                             sizeof(FZN_NODE_RETENTION_NAME) - 1u, &hash_ops,
		                             &state.config.retention_capability) == FZN_CHAIN_OK
		              && memcmp(&state.config.retention_capability,
		                        &state.config.admin_capability, sizeof(fzn_cap_id_t)) != 0,
		      "fixture: the retention capability, not the admin one");
		state.config.has_retention = 1;
		admin.revocations = &revoked;
		state.config.revocations = &revoked;
	}
	/* THE ESTATE'S ROOTS, this node the genesis root: its root acts are
	 * logged. sec 409. */
	static fzn_node_roots_t roots;

	CHECK(fzn_node_roots_init(&roots, node.id.pubkey, &node.sign, &hash_ops)
	              == FZN_NODE_ROOTS_OK
	              && fzn_node_roots_attach(&roots, admin.revocations) == FZN_NODE_ROOTS_OK
	              && fzn_node_journal_init_store(&journal, &journal_ops, &node.sign, &hash_ops)
	                         == FZN_NODE_JOURNAL_OK
	              && fzn_node_roots_set_journal(&roots, &journal) == FZN_NODE_ROOTS_OK,
	      "fixture: the roots, judging by the node's journal");
	roots.logged = journal_logged;
	roots.logged_ctx = &journal;
	admin.roots = &roots;

	memset(&owner, 0, sizeof(owner));
	owner.pid = 1;
	owner.uid = 1000u;
	owner.primary_gid = 1000u;
	owner.groups_known = 1;
	member = owner;
	member.uid = 2000u;
	member.primary_gid = 2000u;
	member.groups[0] = 77u;
	member.group_count = 1;

	hex(device.id.prekey_record, FZN_PREKEY_LEN_TOTAL, prekey_hex);

	/* ---- A GROUP MEMBER MAY NOT CHANGE THE NODE. The count starts after
	 * the node's own identity was saved. */
	node.store.saves = 0;
	snprintf(line, sizeof(line), "add peer %s", prekey_hex);
	CHECK(ask(&admin, &member, line, reply, sizeof(reply), &reply_len)
	              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_DENIED,
	      "a service-group member was allowed to pair a device into the node");
	CHECK(node.store.saves == 0u && state.peer_count == 0u,
	      "a refused pairing changed the store or the running peer set");

	/* ---- THE NODE'S OWN USER PAIRS A DEVICE INTO THE RUNNING NODE. */
	CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
	              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK,
	      "the node's own user could not pair a device over the local socket");
	CHECK(reply_len > 512u,
	      "the pairing reply fit the old bound, so this does not show the new one is real");
	CHECK(state.peer_count == 1u && state.peers == peers
	              && memcmp(state.peers[0].sender, device.id.pubkey, FZN_PUBKEY_LEN) == 0,
	      "after pairing, the RUNNING node's peer set does not hold the device");

	/* ---- AND THE CARD IN THE REPLY IS ONE THE DEVICE ACCEPTS. */
	{
		char text[FZN_PROVISION_TEXT_MAX_LEN];

		CHECK(detail_len == FZN_PROVISION_TEXT_PREFIX_LEN
		                            + FZN_PROVISION_TEXT_BODY_LEN(FZN_PROVISION_LEN(1, 0)),
		      "the reply's detail is not a one-hop card");
		memcpy(text, detail, detail_len);
		text[detail_len] = '\0';
		CHECK(fzn_provision_from_text(text, card, sizeof(card), &card_len)
		              == FZN_PROVISION_OK
		              && fzn_node_pairing_accept(&device.id, card, card_len, 2100u,
		                                         &device.ops, &pairing)
		                         == FZN_NODE_PAIR_OK,
		      "the device would not accept the card the running node answered with");
		/* GUARDED ON THE COUNT, so a running set that never learned of the
		 * device fails the check above by name instead of crashing here and
		 * taking the buffered FAIL line with it -- which is how the reload
		 * sabotage was first "caught". */
		CHECK(state.peer_count == 1u
		              && memcmp(pairing.send_key, state.peers[0].recv_key, FZN_AEAD_KEY_LEN)
		                         == 0,
		      "the device's send key is not the running node's receive key for it");
		fzn_wipe(&pairing, sizeof(pairing));
	}

	/* ---- MORE PEERS THAN THE ROOM, sec 704: a second device paired with
	 * room for one, and the reload asks the hook for more rather than
	 * failing -- past 64 a running node once answered "the running peer
	 * set did not reload", every round, for every contact's device. */
	{
		static struct node second;
		static fzn_node_peer_t grown[4];
		char second_hex[FZN_PREKEY_LEN_TOTAL * 2u + 1u], second_line[sizeof(line)];

		CHECK(node_up(&second), "fixture: a second device");
		hex(second.id.prekey_record, FZN_PREKEY_LEN_TOTAL, second_hex);
		snprintf(second_line, sizeof(second_line), "add peer %s", second_hex);
		room_grown = grown;
		room_grown_cap = 4u;
		room_asked = 0;
		admin.peers_cap = 1u;
		admin.peers_room = room_stub;
		admin.peers_room_ctx = &admin;
		CHECK(ask(&admin, &owner, second_line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK
		              && room_asked == 2u && state.peer_count == 2u && state.peers == grown,
		      "a pairing past the peer set's room did not ask for room, or did not reload");
		/* THE FIXTURE'S OWN ROOM BACK, with both. */
		memcpy(peers, grown, 2u * sizeof(peers[0]));
		admin.peers = peers;
		admin.peers_cap = 32u;
		admin.peers_room = NULL;
		state.peers = peers;
		CHECK(fzn_node_peer_remove(&node.ops, second.id.pubkey) == FZN_PERSIST_OK,
		      "fixture: the second device forgotten");
		state.peer_count = 1u;
	}

	/* ---- AN ESTATE JOINED BY VERBS, sec 638: the device's prekey from
	 * `get prekey`, and `add peer ... delegable` a card it can join by; the
	 * card without `delegable` it cannot. */
	{
		static struct node joiner, plain;
		char want[(FZN_PREKEY_LEN_TOTAL * 2u) + 4u], h[(FZN_PREKEY_LEN_TOTAL * 2u) + 1u];
		char text[FZN_PROVISION_TEXT_MAX_LEN];
		fzn_node_pairing_t joined;

		hex(node.id.prekey_record, FZN_PREKEY_LEN_TOTAL, h);
		snprintf(want, sizeof(want), "ok %s", h);
		CHECK(ask(&admin, &owner, "get prekey", reply, sizeof(reply), &reply_len)
		              && reply_len >= strlen(want) && memcmp(reply, want, strlen(want)) == 0,
		      "get prekey did not answer this node's prekey record");
		CHECK(ask(&admin, &member, "get prekey", reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
		                         == FZN_REPLY_DENIED,
		      "another user read this node's prekey");
		CHECK(node_up(&joiner) && node_up(&plain), "fixture: two devices to join");
		hex(joiner.id.prekey_record, FZN_PREKEY_LEN_TOTAL, h);
		snprintf(line, sizeof(line), "add peer %s delegable", h);
		CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK
		              && detail_len < sizeof(text),
		      "add peer ... delegable did not answer a card");
		memcpy(text, detail, detail_len);
		text[detail_len] = '\0';
		CHECK(fzn_provision_from_text(text, card, sizeof(card), &card_len) == FZN_PROVISION_OK
		              && fzn_node_join(&joiner.id, card, card_len, 2100u, &joiner.ops,
		                               &joiner.trust, &joined) == FZN_NODE_PAIR_OK
		              && memcmp(fzn_trust_root(&joiner.trust), node.id.pubkey, FZN_PUBKEY_LEN)
		                         == 0,
		      "a device would not join by the card add peer ... delegable answered");
		fzn_wipe(&joined, sizeof(joined));
		hex(plain.id.prekey_record, FZN_PREKEY_LEN_TOTAL, h);
		snprintf(line, sizeof(line), "add peer %s", h);
		CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK,
		      "fixture: a device paired without delegable");
		memcpy(text, detail, detail_len);
		text[detail_len] = '\0';
		CHECK(fzn_provision_from_text(text, card, sizeof(card), &card_len) == FZN_PROVISION_OK
		              && fzn_node_join(&plain.id, card, card_len, 2100u, &plain.ops,
		                               &plain.trust, &joined) == FZN_NODE_PAIR_CANNOT_JOIN,
		      "a device joined by a card that is not delegable");
		snprintf(line, sizeof(line), "add peer %s twice", h);
		CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
		                         == FZN_REPLY_MALFORMED,
		      "a word after the record other than delegable was taken");
		/* THE TWO DEVICES REMOVED, so the counts below are the first's. */
		hex(joiner.id.pubkey, FZN_PUBKEY_LEN, h);
		snprintf(line, sizeof(line), "remove peer %s", h);
		(void)ask(&admin, &owner, line, reply, sizeof(reply), &reply_len);
		hex(plain.id.pubkey, FZN_PUBKEY_LEN, h);
		snprintf(line, sizeof(line), "remove peer %s", h);
		(void)ask(&admin, &owner, line, reply, sizeof(reply), &reply_len);
		CHECK(state.peer_count == 1u, "fixture: the two devices would not be removed");
		snprintf(line, sizeof(line), "add peer %s", prekey_hex);
	}

	/* ---- A SIBLING PAIRED INTO THE RUNNING NODE, sec 579: as `add peer`
	 * pairs, from a prekey and with no card; a host already served is left
	 * as it is, and this node's own prekey is refused. The sibling is then
	 * removed, so the counts below are the device's alone. */
	{
		static struct node sibling;
		char key[(FZN_PUBKEY_LEN * 2u) + 1u];
		const char *why = "unset";

		CHECK(fzn_node_admin_pair_sibling(&admin, device.id.prekey_record, &why) == 0
		              && why == NULL && state.peer_count == 1u,
		      "a host this node serves already was paired again as a sibling");
		CHECK(fzn_node_admin_pair_sibling(&admin, node.id.prekey_record, &why) == -1
		              && state.peer_count == 1u,
		      "this node paired itself as a sibling");
		CHECK(node_up(&sibling)
		              && fzn_node_admin_pair_sibling(&admin, sibling.id.prekey_record, &why) == 1
		              && why == NULL && state.peer_count == 2u
		              && memcmp(state.peers[1].sender, sibling.id.pubkey, FZN_PUBKEY_LEN) == 0
		              && state.peers[1].hop_count == 1u,
		      "a sibling was not paired into the running node");
		hex(sibling.id.pubkey, FZN_PUBKEY_LEN, key);
		snprintf(line, sizeof(line), "remove peer %s", key);
		CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK
		              && state.peer_count == 1u,
		      "fixture: the sibling would not be removed");
		snprintf(line, sizeof(line), "add peer %s", prekey_hex);
	}

	/* ---- LISTED, BY ANYONE THE NODE SERVES: listing changes nothing. */
	{
		char want[160];
		char key[(FZN_PUBKEY_LEN * 2u) + 1u];

		hex(device.id.pubkey, FZN_PUBKEY_LEN, key);
		snprintf(want, sizeof(want), "ok 1 0 %s\n", key);
		CHECK(ask(&admin, &member, "list peer", reply, sizeof(reply), &reply_len)
		              && reply_len == strlen(want) - 1u
		              && memcmp(reply, want, reply_len) == 0,
		      "list peer did not answer the total, the offset and the one paired key");
	}

	/* ---- UN-PAIRED: A GROUP MEMBER MAY NOT, THE OWNER MAY, AND IT TAKES. */
	{
		char key[(FZN_PUBKEY_LEN * 2u) + 1u];

		hex(device.id.pubkey, FZN_PUBKEY_LEN, key);
		snprintf(line, sizeof(line), "remove peer %s", key);
		CHECK(ask(&admin, &member, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
		                         == FZN_REPLY_DENIED
		              && state.peer_count == 1u,
		      "a service-group member un-paired a device");
		CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK,
		      "the node's own user could not un-pair a device");
		CHECK(state.peer_count == 0u,
		      "the un-paired device is still in the RUNNING node's peer set");
		{
			fzn_node_peer_t back[2];
			size_t n = 9;

			CHECK(fzn_node_peers_load(&node.ops, back, 2, &n) == FZN_PERSIST_OK && n == 0u,
			      "the un-paired device is still in the store, so a restart serves it");
		}
		CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
		                         == FZN_REPLY_ERROR,
		      "un-pairing a device that is not paired was answered as if it were");
	}

	/* ---- A STORE THAT CANNOT FORGET SAYS SO, AND NOTHING CHANGES. */
	{
		char key[(FZN_PUBKEY_LEN * 2u) + 1u];

		snprintf(line, sizeof(line), "add peer %s", prekey_hex);
		CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
		              && state.peer_count == 1u,
		      "fixture: re-pairing the device failed");
		node.ops.remove = NULL;
		hex(device.id.pubkey, FZN_PUBKEY_LEN, key);
		snprintf(line, sizeof(line), "remove peer %s", key);
		CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
		                         == FZN_REPLY_ERROR
		              && state.peer_count == 1u,
		      "a store with no remove un-paired a device, or the refusal changed the set");
		node.ops.remove = mem_remove;
	}

	/* ---- PAGED, NOT CUT SHORT. Seventeen devices do not fit one line, so the
	 * pages are walked and every key must turn up exactly once, and the
	 * total must be stated on every page. */
	{
		static struct node more[16];
		size_t from = 0, got = 0, i, pages = 0;
		int ok = 1, every_key = 1;

		for (i = 0; i < 16u && ok; i++) {
			char h[(FZN_PREKEY_LEN_TOTAL * 2u) + 1u];

			ok = node_up(&more[i]);
			hex(more[i].id.prekey_record, FZN_PREKEY_LEN_TOTAL, h);
			snprintf(line, sizeof(line), "add peer %s", h);
			ok = ok && ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
			     && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK;
		}
		CHECK(ok && state.peer_count == 17u, "fixture: seventeen devices would not pair");

		{
			int seen[17] = { 0 };

			while (ok && from < 17u && pages < 17u) {
				unsigned long total = 0, off = 0;
				char head[32];
				size_t head_len, at, on_page = 0;
				int consumed = 0;

				snprintf(line, sizeof(line), "list peer %zu", from);
				ok = ask(&admin, &member, line, reply, sizeof(reply), &reply_len)
				     && fzn_reply_of(reply, reply_len, &detail, &detail_len)
				                == FZN_REPLY_OK;
				if (!ok)
					break;
				head_len = detail_len < sizeof(head) - 1u ? detail_len
				                                          : sizeof(head) - 1u;
				memcpy(head, detail, head_len);
				head[head_len] = '\0';
				ok = sscanf(head, "%lu %lu%n", &total, &off, &consumed) == 2
				     && total == 17u && off == from;
				for (at = (size_t)consumed; ok && at + 65u <= detail_len; at += 65u) {
					size_t k;
					int matched = 0;

					for (k = 0; k < state.peer_count && k < 17u; k++) {
						char key[(FZN_PUBKEY_LEN * 2u) + 1u];

						hex(state.peers[k].sender, FZN_PUBKEY_LEN, key);
						if (detail[at] == ' '
						    && memcmp(detail + at + 1u, key, 64u) == 0) {
							/* A key listed twice is as wrong as
							 * one missed. */
							every_key = every_key && !seen[k];
							seen[k] = 1;
							matched = 1;
							break;
						}
					}
					every_key = every_key && matched;
					on_page++;
				}
				ok = ok && on_page > 0u;
				got += on_page;
				from += on_page;
				pages++;
			}
			for (i = 0; i < 17u; i++)
				every_key = every_key && seen[i];
		}
		CHECK(ok, "list peer did not state the total and the offset on every page");
		CHECK(ask(&admin, &member, "list peer 20", reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
		                         == FZN_REPLY_MALFORMED,
		      "an offset past the last peer was answered as an empty page");
		CHECK(got == 17u && every_key && pages >= 2u,
		      "walking list peer's pages did not return all seventeen keys exactly, "
		      "or fitted them on one page");
	}

	/* ---- REVOKED OVER THE SOCKET: by the owner only, and saying so when it
	 * already was. sec 380. */
	{
		char key[(FZN_PUBKEY_LEN * 2u) + 1u];
		char want[(FZN_PUBKEY_LEN * 2u) + (FZN_REVOCATION_ID_LEN * 2u) + 32u];
		/* THE GRANTS LOGGED BY THE PAIRINGS ABOVE, sec 497: each `add
		 * peer` logs its hop, so the counts below are past these. */
		size_t granted = (size_t)acts_by(node.id.pubkey);

		CHECK(granted > 0u && kind_at(node.id.pubkey, 1u) == (uint32_t)FZN_OBJECT_HOP,
		      "the pairings above logged no grant");
		hex(device.id.pubkey, FZN_PUBKEY_LEN, key);
		snprintf(line, sizeof(line), "revoke peer %s", key);
		CHECK(ask(&admin, &member, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
		                         == FZN_REPLY_DENIED,
		      "a service-group member revoked a grant");
		/* THE ANSWER SAYS THE LINE, sec 497: the device logged nothing
		 * here, so the vote keeps nothing of it. */
		snprintf(want, sizeof(want), "%s keeping nothing", key);
		CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK
		              && detail_len == strlen(want) && memcmp(detail, want, detail_len) == 0,
		      "the node's own user could not revoke a grant, or the answer did not name it");
		CHECK((size_t)acts_by(node.id.pubkey) == granted + 1u, "the root's revocation was not logged");
		snprintf(want, sizeof(want), "%s already keeping nothing", key);
		CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK
		              && detail_len == strlen(want) && memcmp(detail, want, detail_len) == 0,
		      "revoking again was not answered as already revoked");

		/* ---- AND UNDONE: by the owner only, once, and revocable again
		 * afterwards -- the re-revocation superseding the one undone. sec 386. */
		snprintf(line, sizeof(line), "remove revocation %s", key);
		CHECK(ask(&admin, &member, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
		                         == FZN_REPLY_DENIED,
		      "a service-group member undid a revocation");
		CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK
		              && detail_len == 64u && memcmp(detail, key, 64u) == 0,
		      "the node's own user could not undo a revocation, or the answer did not name it");
		CHECK((size_t)acts_by(node.id.pubkey) == granted + 2u, "the root's withdrawal was not logged");
		CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
		                         == FZN_REPLY_ERROR,
		      "undoing a revocation already undone was answered ok");
		snprintf(line, sizeof(line), "revoke peer %s", key);
		CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK
		              && detail_len > 64u && memcmp(detail, key, 64u) == 0,
		      "a grantee whose revocation was undone could not be revoked again");

		/* ---- AND NOT SERVED AS A VOTE: the journal carries it, sec 505,
		 * and the verbs that paged votes, root records and revocations are
		 * gone -- asked, none answers ok. */
		CHECK(ask(&admin, &member, "get vote", reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) != FZN_REPLY_OK
		              && ask(&admin, &member, "get root", reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) != FZN_REPLY_OK
		              && ask(&admin, &member, "get revocation", reply, sizeof(reply),
		                     &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) != FZN_REPLY_OK,
		      "a verb of the retired vote stream still answered ok");

		/* ADD AND REMOVE A ROOT: the owner may, a group member may not, and
		 * a cut that is not an id is refused. sec 409. */
		snprintf(line, sizeof(line), "add root %s", key);
		CHECK(ask(&admin, &member, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
		                         == FZN_REPLY_DENIED,
		      "a service-group member added a root");
		CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK
		              && fzn_root_view_stands(&roots.view, device.id.pubkey),
		      "the node's own user could not add a root");
		snprintf(line, sizeof(line), "remove root %s zz", key);
		CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
		                         == FZN_REPLY_MALFORMED,
		      "a removal naming a cut that is not an id was taken");
		snprintf(line, sizeof(line), "remove root %s none twice", key);
		CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
		                         == FZN_REPLY_MALFORMED,
		      "a removal with a word after its cut was taken");
		snprintf(line, sizeof(line), "add root %s none", key);
		CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
		                         == FZN_REPLY_MALFORMED,
		      "an add naming a cut was taken");
		/* THE REMOVAL KEEPS THE ROOT'S ACTS TO ITS HEAD as held here, sec
		 * 707, as a vote's line is drawn: the device, a root now, logs an
		 * act, and the removal's cut is that act's record. */
		{
			static uint8_t buf[FZN_RECORD_MAX_LEN];
			uint8_t head[FZN_ROOT_ACT_ID_LEN], act[FZN_ROOT_ADD_LEN];
			fzn_record_t rec;
			uint64_t at;

			CHECK(fzn_root_add_issue(device.id.pubkey, node.id.pubkey, &device.sign, act)
			                      == FZN_ROOT_LOG_OK
			              && fzn_node_journal_append_object(&journal, device.id.pubkey,
			                                                &device.sign, act, sizeof(act),
			                                                2000u, NULL)
			                         == FZN_NODE_JOURNAL_OK
			              && fzn_node_journal_head(&journal, device.id.pubkey, head),
			      "fixture: an act in the root's stream");
			/* A CUT THAT WOULD DROP A COUNTED ACT, sec 721: the device adds a
			 * root the set learns as an object, its record not yet in the
			 * device's stream. The head held is below it, so a removal with
			 * no cut is refused and the device stands; once the record is
			 * held, the removal is taken. */
			{
				uint8_t third[FZN_PUBKEY_LEN], add[FZN_ROOT_ADD_LEN];

				memset(third, 0x5b, sizeof(third));
				CHECK(fzn_root_add_issue(device.id.pubkey, third, &device.sign, add)
				                      == FZN_ROOT_LOG_OK
				              && fzn_node_roots_learn(&roots, &node.ops, add, sizeof(add))
				                         == FZN_NODE_ROOTS_OK
				              && fzn_root_view_stands(&roots.view, third),
				      "fixture: an add the set counts and the stream does not hold");
				snprintf(line, sizeof(line), "remove root %s", key);
				CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
				              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
				                         == FZN_REPLY_ERROR
				              && fzn_root_view_stands(&roots.view, device.id.pubkey),
				      "a removal cut below an act this node counts was taken");
				CHECK(fzn_node_journal_append_object(&journal, device.id.pubkey,
				                                     &device.sign, add, sizeof(add), 2001u,
				                                     NULL)
				                      == FZN_NODE_JOURNAL_OK
				              && fzn_node_journal_head(&journal, device.id.pubkey, head),
				      "fixture: the add's record held at last");
			}
			snprintf(line, sizeof(line), "remove root %s", key);
			CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
			              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK
			              && !fzn_root_view_stands(&roots.view, device.id.pubkey),
			      "the node's own user could not remove a root");
			at = acts_by(node.id.pubkey);
			CHECK(kind_at(node.id.pubkey, at) == (uint32_t)FZN_OBJECT_ROOT_REMOVE
			              && fzn_record_store_get(&journal.store, node.id.pubkey,
			                                      FZN_NODE_JOURNAL_STREAM, at, buf, sizeof(buf),
			                                      &rec) == FZN_RECORD_STORE_OK
			              && fzn_record_body_len(rec) >= FZN_ROOT_SET_OFF_CUT + FZN_ROOT_ACT_ID_LEN
			              && memcmp(fzn_record_body(rec) + FZN_ROOT_SET_OFF_CUT, head,
			                        sizeof(head)) == 0,
			      "a removal naming no cut did not keep the root's acts to its head");
		}
		/* `none`, sec 707: what no cut once meant, now said. */
		snprintf(line, sizeof(line), "add root %s", key);
		CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK,
		      "fixture: the root added again");
		snprintf(line, sizeof(line), "remove root %s none", key);
		CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK
		              && !fzn_root_view_stands(&roots.view, device.id.pubkey),
		      "a removal keeping none of the root's acts was refused");
		/* NO CUT NAMED AND NONE TO DRAW, sec 721: a root none of whose acts
		 * this node holds is refused removal without a cut, and stands;
		 * `none` then removes it. Taken as `none`, the removal once took the
		 * add that made this node a root with it. */
		{
			uint8_t stranger[FZN_PUBKEY_LEN];
			char stranger_hex[(FZN_PUBKEY_LEN * 2u) + 1u];

			memset(stranger, 0x6a, sizeof(stranger));
			hex(stranger, sizeof(stranger), stranger_hex);
			snprintf(line, sizeof(line), "add root %s", stranger_hex);
			CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
			              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
			                         == FZN_REPLY_OK,
			      "fixture: a root none of whose acts are held");
			snprintf(line, sizeof(line), "remove root %s", stranger_hex);
			CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
			              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
			                         == FZN_REPLY_ERROR
			              && fzn_root_view_stands(&roots.view, stranger),
			      "a removal with no cut to draw was taken as none");
			snprintf(line, sizeof(line), "remove root %s none", stranger_hex);
			CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
			              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
			                         == FZN_REPLY_OK
			              && !fzn_root_view_stands(&roots.view, stranger),
			      "a removal saying none was refused");
		}

		/* ---- A LINE NAMED, MOVED AND KEPT, sec 497: a cut that is not an
		 * id is refused; a named one moves the held vote's line and the
		 * answer reads it back; asking again with no cut leaves it; `none`
		 * keeps nothing. */
		{
			char line_hex[(FZN_REVOCATION_ID_LEN * 2u) + 1u];
			uint8_t named[FZN_REVOCATION_ID_LEN];
			size_t logged = (size_t)acts_by(node.id.pubkey);

			memset(named, 0xab, sizeof(named));
			hex(named, sizeof(named), line_hex);
			snprintf(line, sizeof(line), "revoke peer %s zz", key);
			CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
			              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
			                         == FZN_REPLY_MALFORMED,
			      "a cut that is not an id was taken");
			snprintf(line, sizeof(line), "revoke peer %s %s", key, line_hex);
			snprintf(want, sizeof(want), "%s keeping %s", key, line_hex);
			CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
			              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
			                         == FZN_REPLY_OK
			              && detail_len == strlen(want) && memcmp(detail, want, detail_len) == 0
			              && (size_t)acts_by(node.id.pubkey) == logged + 1u,
			      "a named cut did not move the vote's line, or the move was not logged");
			snprintf(line, sizeof(line), "revoke peer %s", key);
			snprintf(want, sizeof(want), "%s already keeping %s", key, line_hex);
			CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
			              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
			                         == FZN_REPLY_OK
			              && detail_len == strlen(want) && memcmp(detail, want, detail_len) == 0,
			      "asking again with no cut moved the line");
			snprintf(line, sizeof(line), "revoke peer %s none", key);
			snprintf(want, sizeof(want), "%s keeping nothing", key);
			CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
			              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
			                         == FZN_REPLY_OK
			              && detail_len == strlen(want) && memcmp(detail, want, detail_len) == 0,
			      "`none` did not move the line to keep nothing");
		}

		/* ---- A DEVICE RE-KEYED, sec 499: `add succession OLD PREKEY`
		 * pairs the new key and answers its card; the root's succession
		 * counts at once; `list succession` names it; `add succession
		 * OLD` confirms it; a key is not its own successor; with no
		 * successions kept the verb says so. */
		{
			static struct node fresh;
			static fzn_node_successions_t ns;
			char fresh_prekey[(FZN_PREKEY_LEN_TOTAL * 2u) + 1u];
			char own_prekey[(FZN_PREKEY_LEN_TOTAL * 2u) + 1u];
			char fresh_key[(FZN_PUBKEY_LEN * 2u) + 1u];
			size_t peers_before = admin.state->peer_count;

			CHECK(node_up(&fresh) && fzn_node_successions_init(&ns, &hash_ops)
			              == FZN_NODE_REVOKE_OK,
			      "fixture: the new key and the successions");
			hex(fresh.id.prekey_record, FZN_PREKEY_LEN_TOTAL, fresh_prekey);
			hex(fresh.id.pubkey, FZN_PUBKEY_LEN, fresh_key);
			hex(device.id.prekey_record, FZN_PREKEY_LEN_TOTAL, own_prekey);
			snprintf(line, sizeof(line), "add succession %s %s", key, fresh_prekey);
			CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
			              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
			                         == FZN_REPLY_ERROR,
			      "a node keeping no successions re-keyed a device");
			admin.successions = &ns;
			snprintf(line, sizeof(line), "add succession %s %s", key, own_prekey);
			CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
			              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
			                         == FZN_REPLY_MALFORMED,
			      "a key was made its own successor");
			snprintf(line, sizeof(line), "add succession %s", key);
			CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
			              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
			                         == FZN_REPLY_ERROR,
			      "a confirmation was taken with no succession held");
			snprintf(line, sizeof(line), "add succession %s %s", key, fresh_prekey);
			CHECK(ask(&admin, &member, line, reply, sizeof(reply), &reply_len)
			              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
			                         == FZN_REPLY_DENIED,
			      "a service-group member re-keyed a device");
			CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
			              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
			                         == FZN_REPLY_OK
			              && detail_len > 100u && ns.set.used == 1u
			              && admin.state->peer_count == peers_before + 1u
			              && fzn_succession_counts(&ns.set, 0, admin.revocations,
			                                       node.id.pubkey),
			      "the owner's re-key did not pair the new key, answer its card and "
			      "mint a succession that counts");
			snprintf(want, sizeof(want), "1 0 %s>%s,counting", key, fresh_key);
			CHECK(ask(&admin, &member, "list succession", reply, sizeof(reply), &reply_len)
			              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
			                         == FZN_REPLY_OK
			              && detail_len == strlen(want) && memcmp(detail, want, detail_len) == 0,
			      "list succession did not name the re-key as counting");
			snprintf(line, sizeof(line), "add succession %s", key);
			snprintf(want, sizeof(want), "%s %s counting", key, fresh_key);
			CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
			              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
			                         == FZN_REPLY_OK
			              && detail_len == strlen(want) && memcmp(detail, want, detail_len) == 0,
			      "confirming the held succession was not answered with both keys");
			/* A SUCCESSOR JOINS AS ITS PREDECESSOR DID, sec 707: a key paired
			 * delegable is re-keyed by a card its successor can join by, and
			 * one paired plainly by a card it cannot. */
			{
				static struct node joined_old, plain_old, heir, plain_heir;
				const struct {
					struct node *old, *heir;
					const char *how;
					fzn_node_pair_err_t joins;
				} cases[] = {
					{ &joined_old, &heir, " delegable", FZN_NODE_PAIR_OK },
					{ &plain_old, &plain_heir, "", FZN_NODE_PAIR_CANNOT_JOIN },
				};
				char h[(FZN_PREKEY_LEN_TOTAL * 2u) + 1u], old_key[(FZN_PUBKEY_LEN * 2u) + 1u];
				char text[FZN_PROVISION_TEXT_MAX_LEN];
				fzn_node_pairing_t heir_joined;
				size_t c;

				for (c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
					CHECK(node_up(cases[c].old) && node_up(cases[c].heir),
					      "fixture: a key and its successor");
					hex(cases[c].old->id.prekey_record, FZN_PREKEY_LEN_TOTAL, h);
					snprintf(line, sizeof(line), "add peer %s%s", h, cases[c].how);
					CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
					              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
					                         == FZN_REPLY_OK,
					      "fixture: the key paired");
					hex(cases[c].old->id.pubkey, FZN_PUBKEY_LEN, old_key);
					hex(cases[c].heir->id.prekey_record, FZN_PREKEY_LEN_TOTAL, h);
					snprintf(line, sizeof(line), "add succession %s %s", old_key, h);
					CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
					              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
					                         == FZN_REPLY_OK
					              && detail_len < sizeof(text),
					      "fixture: the key re-keyed, its successor's card answered");
					memcpy(text, detail, detail_len);
					text[detail_len] = '\0';
					CHECK(fzn_provision_from_text(text, card, sizeof(card), &card_len)
					                      == FZN_PROVISION_OK
					              && fzn_node_join(&cases[c].heir->id, card, card_len, 2100u,
					                               &cases[c].heir->ops, &cases[c].heir->trust,
					                               &heir_joined)
					                         == cases[c].joins,
					      c == 0u ? "a joined key's successor could not join in its place"
					              : "a plainly paired key's successor joined the estate");
					fzn_wipe(&heir_joined, sizeof(heir_joined));
				}
			}
			admin.successions = NULL;
		}
	}

	/* ---- THROUGH A ROOT KEY THE CARD WILL NOT FIT A REPLY, and add peer
	 * says so before pairing anything. sec 411. Staged by hand: the node is
	 * made a member of another estate that holds a standing root key --
	 * its own identity, the one key this set already stands. */
	{
		uint8_t pinned[FZN_PUBKEY_LEN];
		unsigned saves;

		memcpy(pinned, state.config.root, FZN_PUBKEY_LEN);
		memcpy(state.config.root, device.id.pubkey, FZN_PUBKEY_LEN);
		memcpy(roots.key, node.id.pubkey, FZN_PUBKEY_LEN);
		roots.key_held = 1;
		saves = node.store.saves;
		snprintf(line, sizeof(line), "add peer %s", prekey_hex);
		CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_ERROR
		              && says(detail, detail_len, "fuzznetd --pair")
		              && node.store.saves == saves,
		      "add peer through a root key was not refused before pairing");
		roots.key_held = 0;
		CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_ERROR
		              && !says(detail, detail_len, "fuzznetd --pair"),
		      "the control: a node holding no root key was sent to fuzznetd --pair");
		memcpy(state.config.root, pinned, FZN_PUBKEY_LEN);
	}

	/* ---- THE RETENTION CAPABILITY, sec 567: a group member may not grant
	 * it; the owner grants it as this root, one hop of that capability to
	 * that key, and logged. */
	{
		char key[(FZN_PUBKEY_LEN * 2u) + 1u];
		uint8_t hop[FZN_HOP_LEN];
		fzn_chain_hop_t view;
		size_t logged = (size_t)acts_by(node.id.pubkey), k;

		for (k = 0; k < FZN_PUBKEY_LEN; k++)
			snprintf(key + (2u * k), 3u, "%02x", device.id.pubkey[k]);
		snprintf(line, sizeof(line), "grant retention %s", key);
		CHECK(ask(&admin, &member, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
		                         == FZN_REPLY_DENIED,
		      "a service-group member granted the retention capability");
		CHECK(ask(&admin, &owner, "grant retention zz", reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
		                         == FZN_REPLY_MALFORMED,
		      "a grant to no key was not answered malformed");
		CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK
		              && detail_len == 1u + (FZN_HOP_LEN * 2u) && detail[0] == 'h'
		              && unhex_into(detail + 1, FZN_HOP_LEN * 2u, hop)
		              && fzn_hop_open(hop, FZN_HOP_LEN, &view) == FZN_CHAIN_OK
		              && memcmp(fzn_hop_capability(view), &state.config.retention_capability,
		                        sizeof(fzn_cap_id_t)) == 0
		              && memcmp(fzn_hop_grantee(view), device.id.pubkey, FZN_PUBKEY_LEN) == 0
		              && memcmp(fzn_hop_grantor(view), node.id.pubkey, FZN_PUBKEY_LEN) == 0
		              && (size_t)acts_by(node.id.pubkey) == logged + 1u,
		      "the owner's grant was not one hop of the retention capability to the device, "
		      "from this root, logged");
	}

	/* ---- ADMINS, sec 416: a group member may not grant; the owner grants
	 * the device admin as this root, one hop, and confirms it, both logged;
	 * a hop of another capability is not a grant of admin. */
	{
		uint8_t hop[FZN_HOP_LEN];
		char key[(FZN_PUBKEY_LEN * 2u) + 1u], hop_hex[(FZN_HOP_LEN * 2u) + 1u];
		size_t logged = (size_t)acts_by(node.id.pubkey), k, confirmed;

		for (k = 0; k < FZN_PUBKEY_LEN; k++)
			snprintf(key + (2u * k), 3u, "%02x", device.id.pubkey[k]);
		/* THE CONFIRMATIONS ALREADY HELD: the re-key above confirmed its
		 * succession, sec 499. */
		confirmed = admin.revocations->confirms_used;
		snprintf(line, sizeof(line), "grant admin %s", key);
		CHECK(ask(&admin, &member, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
		                         == FZN_REPLY_DENIED,
		      "a service-group member granted admin");
		CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK
		              && detail_len == 1u + (FZN_HOP_LEN * 2u) && detail[0] == 'h'
		              && (size_t)acts_by(node.id.pubkey) == logged + 1u,
		      "the owner's grant of admin was not one hop, or not logged");
		memcpy(hop_hex, detail + 1u, FZN_HOP_LEN * 2u);
		hop_hex[FZN_HOP_LEN * 2u] = '\0';
		snprintf(line, sizeof(line), "add confirm %s", hop_hex);
		CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK
		              && admin.revocations->confirms_used == confirmed + 1u
		              && (size_t)acts_by(node.id.pubkey) == logged + 2u,
		      "the root's confirmation was not admitted, or not logged");
		CHECK(fzn_chain_mint(node.id.pubkey, device.id.pubkey,
		                     &state.config.remote_capability, 1000u, FZN_NO_EXPIRY, 0,
		                     &node.sign, hop) == FZN_CHAIN_OK,
		      "fixture: a hop of the remote capability");
		for (k = 0; k < FZN_HOP_LEN; k++)
			snprintf(hop_hex + (2u * k), 3u, "%02x", hop[k]);
		snprintf(line, sizeof(line), "add confirm %s", hop_hex);
		CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
		                         == FZN_REPLY_ERROR
		              && admin.revocations->confirms_used == confirmed + 1u,
		      "a hop of another capability was confirmed as a grant of admin");
		CHECK(ask(&admin, &owner, "add confirm zz", reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
		                         == FZN_REPLY_MALFORMED,
		      "a confirmation of no hop was not answered malformed");
		/* THE ROOT VOTES AS THE ROOT even holding an admin chain: its
		 * revocation carries no chain, so no admin row is made. */
		{
			static fzn_node_admin_chain_t own;
			uint8_t chain[FZN_CHAIN_MAX_HOPS][FZN_HOP_LEN];
			size_t n = 0;

			CHECK(fzn_node_admin_grant(&roots, &node.ops, &node.id, NULL,
			                           &state.config.admin_capability, node.id.pubkey,
			                           1000u, chain, &n) == FZN_NODE_REVOKE_OK
			              && fzn_node_admin_chain_set(&node.ops, admin.revocations, &node.id,
			                                          node.id.pubkey,
			                                          &state.config.admin_capability,
			                                          (const uint8_t (*)[FZN_HOP_LEN])chain,
			                                          n, 1000u, &own) == FZN_NODE_REVOKE_OK,
			      "fixture: the root holding an admin chain of its own");
			admin.admin_chain = &own;
			for (k = 0; k < FZN_PUBKEY_LEN; k++)
				snprintf(key + (2u * k), 3u, "%02x", (unsigned)(0x60u + k));
			snprintf(line, sizeof(line), "revoke peer %s", key);
			CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
			              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
			                         == FZN_REPLY_OK
			              && admin.revocations->admins_used == 0u,
			      "the root voted on its admin chain rather than as the root");
			admin.admin_chain = NULL;
		}
	}

	/* ---- CONTACTS, sec 435: a key outside the estate, by a name. */
	{
		char key_hex[(FZN_PUBKEY_LEN * 2u) + 1u], own_hex[(FZN_PUBKEY_LEN * 2u) + 1u];
		size_t k;

		for (k = 0; k < FZN_PUBKEY_LEN; k++) {
			snprintf(key_hex + (2u * k), 3u, "%02x", (unsigned)(0x40u + k));
			snprintf(own_hex + (2u * k), 3u, "%02x", node.id.pubkey[k]);
		}
		snprintf(line, sizeof(line), "add contact alice %s", key_hex);
		CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK,
		      "a contact was not added");
		CHECK(ask(&admin, &owner, "list contact", reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK
		              && says(detail, detail_len, "1 0 alice,")
		              && says(detail, detail_len, key_hex),
		      "the contact was not listed by name and key");
		snprintf(line, sizeof(line), "add contact me %s", own_hex);
		CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_ERROR,
		      "this node's own key was taken as a contact: a member is never one");
		/* ANOTHER ROOT OF THE ESTATE is a member too, not only the one this
		 * node joined through. */
		{
			static fzn_node_roots_t with_second;
			uint8_t add[FZN_ROOT_ADD_LEN], second[FZN_PUBKEY_LEN];
			char second_hex[(FZN_PUBKEY_LEN * 2u) + 1u];
			struct fzn_node_roots *was = admin.roots;

			memset(second, 0x5e, sizeof(second));
			hex(second, FZN_PUBKEY_LEN, second_hex);
			CHECK(fzn_node_roots_init(&with_second, node.id.pubkey, &node.sign, &hash_ops)
			                      == FZN_NODE_ROOTS_OK
			              && fzn_root_add_issue(node.id.pubkey, second, &node.sign, add)
			                         == FZN_ROOT_LOG_OK
			              && fzn_node_roots_learn(&with_second, &node.ops, add, sizeof(add))
			                         == FZN_NODE_ROOTS_OK,
			      "fixture: an estate with a second root");
			admin.roots = &with_second;
			snprintf(line, sizeof(line), "add contact second %s", second_hex);
			CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
			              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
			                         == FZN_REPLY_ERROR,
			      "a second root of the estate was taken as a contact");
			admin.roots = was;
		}
		snprintf(line, sizeof(line), "add contact al-ice %s", key_hex);
		CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
		                         == FZN_REPLY_MALFORMED,
		      "a name outside [A-Za-z0-9_] was not malformed");
		CHECK(ask(&admin, &member, "list contact", reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_DENIED,
		      "another user read the contacts");
		CHECK(ask(&admin, &owner, "remove contact alice", reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK
		              && ask(&admin, &owner, "list contact", reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK
		              && says(detail, detail_len, "0 0"),
		      "a removed contact was still listed");
		/* MORE CONTACTS THAN THE ADMIN'S OWN ROOM, sec 704: listed whole once
		 * the hook gives room, and refused aloud without one -- never a page
		 * of the first 64. */
		{
			static fzn_contact_t grown[80];
			uint8_t ck[FZN_PUBKEY_LEN];
			char name[8];
			size_t i, added = 0;

			for (i = 0; i < 66u; i++) {
				memset(ck, 0x2c, sizeof(ck));
				ck[1] = (uint8_t)i;
				snprintf(name, sizeof(name), "m%02zu", i);
				added += fzn_contact_add(admin.store, ck, name, strlen(name), 1u)
				         == FZN_CONTACT_OK;
			}
			CHECK(added == 66u, "fixture: 66 contacts");
			CHECK(ask(&admin, &owner, "list contact", reply, sizeof(reply), &reply_len)
			              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
			                         == FZN_REPLY_ERROR,
			      "66 contacts with no room for them listed as a page of some");
			contacts_grown = grown;
			contacts_grown_cap = 80u;
			contacts_asked = 0;
			admin.contacts_room = contacts_stub;
			admin.contacts_room_ctx = &admin;
			CHECK(ask(&admin, &owner, "list contact", reply, sizeof(reply), &reply_len)
			              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK
			              && says(detail, detail_len, "66 0") && contacts_asked == 66u,
			      "66 contacts did not list once the hook gave room");
			admin.contacts_room = NULL;
			admin.contacts = NULL;
			admin.contacts_cap = 0;
			for (i = 0; i < 66u; i++) {
				memset(ck, 0x2c, sizeof(ck));
				ck[1] = (uint8_t)i;
				(void)fzn_contact_remove(admin.store, ck);
			}
		}
	}

	/* ---- GROUPS, sec 626: the verbs, the node's user only. The node acts
	 * as its own user, its root its own host. */
	{
		const fzn_hash_ops_t *was = state.hash;
		char key_hex[(FZN_PUBKEY_LEN * 2u) + 1u], owner_hex[(FZN_PUBKEY_LEN * 2u) + 1u];
		static fzn_node_groups_t groups;
		static fzn_cap_id_t any_member;
		char gone_hex[65] = "";
		size_t k;

		for (k = 0; k < FZN_PUBKEY_LEN; k++) {
			snprintf(key_hex + (2u * k), 3u, "%02x", (unsigned)(0x60u + k));
			snprintf(owner_hex + (2u * k), 3u, "%02x", node.id.pubkey[k]);
		}
		CHECK(ask(&admin, &owner, "add group family", reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) != FZN_REPLY_OK,
		      "a node keeping no groups made one");
		memset(&any_member, 0x4d, sizeof(any_member));
		groups.log.store = admin.store;
		groups.log.hash = &hash_ops;
		groups.log.sign = &node.sign;
		groups.log.member = &any_member;
		groups.host_sign = &node.sign;
		groups.signer = group_signer;
		groups.signer_ctx = &node;
		groups.rng = &rng_ops;
		groups.clock = fixed_clock;
		groups.forget = fzn_node_admin_group_forget;
		groups.forget_ctx = &admin;
		admin.groups = &groups;

		state.hash = &hash_ops;
		snprintf(line, sizeof(line), "add contact erin %s", key_hex);
		CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK,
		      "fixture: the contact erin");
		CHECK(ask(&admin, &member, "add group family", reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_DENIED,
		      "another user made a group");
		CHECK(ask(&admin, &owner, "add group fam-ily", reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
		                         == FZN_REPLY_MALFORMED,
		      "a group name outside [A-Za-z0-9_] was not malformed");
		CHECK(ask(&admin, &owner, "add group family", reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK
		              && ask(&admin, &owner, "add group family", reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_ERROR,
		      "a group was not made, or was made twice");
		CHECK(says(detail, detail_len, "has that name"),
		      "a group made twice was not refused for its name");
		CHECK(ask(&admin, &owner, "list group", reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK
		              && says(detail, detail_len, "1 0 family,1"),
		      "a name already taken made a second group, left unnamed");
		CHECK(ask(&admin, &owner, "add member family nobody", reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_ERROR,
		      "a name that is no contact joined a group");
		CHECK(ask(&admin, &owner, "add member family", reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
		                         == FZN_REPLY_MALFORMED,
		      "a member with no contact was not malformed");
		CHECK(ask(&admin, &owner, "add member family erin", reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK
		              && ask(&admin, &owner, "get group family", reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK
		              && detail_len == 1u + 1u + 1u + 64u + 5u && says(detail, detail_len, "2 *")
		              && memcmp(detail + 3, owner_hex, 64u) == 0
		              && memcmp(detail + 67, " erin", 5u) == 0
		              && ask(&admin, &owner, "list group", reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK
		              && says(detail, detail_len, "1 0 family,2"),
		      "erin did not join, or the group did not read back with her");
		/* BY ITS ID, sec 647: listed last on its row, and found by it as by
		 * its name -- what a client keys on, a name being this host's. */
		{
			uint8_t fid[FZN_PUBKEY_LEN];
			char fid_hex[65], by_name[FZN_REPLY_MAX], want[100];
			size_t by_name_len = 0;

			CHECK(fzn_node_group_find(admin.store, "family", 6u, fid) == FZN_CONTACT_OK,
			      "fixture: family's id");
			for (k = 0; k < sizeof(fid); k++)
				snprintf(fid_hex + 2u * k, 3u, "%02x", fid[k]);
			snprintf(want, sizeof(want), "1 0 family,2,%s", fid_hex);
			CHECK(ask(&admin, &owner, "list group", reply, sizeof(reply), &reply_len)
			              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK
			              && detail_len == strlen(want) && memcmp(detail, want, detail_len) == 0,
			      "list group did not end family's row with its id");
			CHECK(ask(&admin, &owner, "get group family", reply, sizeof(reply), &reply_len)
			              && reply_len < sizeof(by_name),
			      "fixture: family read by name");
			memcpy(by_name, reply, reply_len);
			by_name_len = reply_len;
			snprintf(line, sizeof(line), "get group %s", fid_hex);
			CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
			              && reply_len == by_name_len && memcmp(reply, by_name, reply_len) == 0,
			      "family read by its id did not answer as by its name");
			fid_hex[0] = fid_hex[0] == 'f' ? '0' : 'f';
			snprintf(line, sizeof(line), "get group %s", fid_hex);
			CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
			              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
			                         == FZN_REPLY_ERROR,
			      "an id no group has found one");
			memcpy(gone_hex, fid_hex, sizeof(gone_hex));
			gone_hex[0] = gone_hex[0] == 'f' ? '0' : 'f';
		}
		CHECK(ask(&admin, &member, "get group family", reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_DENIED,
		      "another user read a group");
		CHECK(ask(&admin, &owner, "remove member family erin", reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK
		              && ask(&admin, &owner, "remove member family erin", reply, sizeof(reply),
		                     &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_ERROR,
		      "erin did not leave, or left twice");
		/* ITS SHARES GO WITH IT, sec 478: made again under the name, the
		 * group inherits nothing. Another contact's share stays. */
		{
			fzn_notes_store_t notes;
			uint8_t gid[FZN_PUBKEY_LEN], other[FZN_PUBKEY_LEN], sub[FZN_TREE_ID_LEN];
			uint8_t seen[4][FZN_TREE_ID_LEN];
			size_t n = 9;

			memset(other, 0x6e, sizeof(other));
			memset(sub, 0x51, sizeof(sub));
			CHECK(fzn_notes_store_init(&notes, admin.store, &hash_ops) == FZN_NOTES_OK
			              && fzn_node_group_find(admin.store, "family", 6u, gid) == FZN_CONTACT_OK
			              && fzn_notes_share_add(&notes, sub, gid, 1u) == FZN_NOTES_OK
			              && fzn_notes_share_add(&notes, sub, other, 1u) == FZN_NOTES_OK,
			      "fixture: a subtree shared with the group and with another contact");
			CHECK(ask(&admin, &owner, "remove group family", reply, sizeof(reply), &reply_len)
			              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
			                         == FZN_REPLY_OK
			              && ask(&admin, &owner, "list group", reply, sizeof(reply), &reply_len)
			              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
			                         == FZN_REPLY_OK
			              && says(detail, detail_len, "0 0"),
			      "a removed group was still listed");
			/* LEFT, ITS NAME FORGOTTEN: no more found by its id than by it. */
			snprintf(line, sizeof(line), "get group %s", gone_hex);
			CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
			              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
			                         == FZN_REPLY_ERROR,
			      "a removed group was found by its id");
			CHECK(ask(&admin, &owner, "add group family", reply, sizeof(reply), &reply_len)
			              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
			                         == FZN_REPLY_OK
			              && fzn_notes_share_with(&notes, gid, seen, 4u, &n) == FZN_NOTES_OK
			              && n == 0u,
			      "a group made again under a removed one's name inherited its shares");
			/* ITS ID ANSWERED, sec 648: the group the name now finds. */
			{
				uint8_t again[FZN_PUBKEY_LEN];
				char again_hex[65];

				CHECK(fzn_node_group_find(admin.store, "family", 6u, again) == FZN_CONTACT_OK,
				      "fixture: the new family's id");
				for (k = 0; k < sizeof(again); k++)
					snprintf(again_hex + 2u * k, 3u, "%02x", again[k]);
				CHECK(ask(&admin, &owner, "remove group family", reply, sizeof(reply),
				          &reply_len)
				              && ask(&admin, &owner, "add group family", reply, sizeof(reply),
				                     &reply_len)
				              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
				                         == FZN_REPLY_OK
				              && detail_len == 64u
				              && fzn_node_group_find(admin.store, "family", 6u, again)
				                         == FZN_CONTACT_OK,
				      "add group did not answer an id");
				for (k = 0; k < sizeof(again); k++)
					snprintf(again_hex + 2u * k, 3u, "%02x", again[k]);
				CHECK(memcmp(detail, again_hex, 64u) == 0,
				      "add group answered an id that is not the group's");
			}
			CHECK(fzn_notes_share_with(&notes, other, seen, 4u, &n) == FZN_NOTES_OK && n == 1u,
			      "removing a group took another contact's share with it");
			(void)fzn_notes_share_remove(&notes, sub, other);
			(void)ask(&admin, &owner, "remove group family", reply, sizeof(reply), &reply_len);
		}
		CHECK(ask(&admin, &owner, "remove contact erin", reply, sizeof(reply), &reply_len),
		      "fixture: erin forgotten");
		admin.groups = NULL;
		state.hash = was;
	}

	/* ---- RETENTION RULES, sec 475: kept, listed one word each, removed. */
	{
		const fzn_hash_ops_t *was = state.hash;

		state.hash = &hash_ops;
		CHECK(ask(&admin, &member, "list retention", reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_DENIED,
		      "another user read this user's retention rules");
		CHECK(ask(&admin, &owner, "add retention prune * level=D ages 1d", reply, sizeof(reply),
		          &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
		                         == FZN_REPLY_MALFORMED,
		      "a rule that is not one was not malformed");
		CHECK(ask(&admin, &owner, "add retention prune fuzznetd level=TD age 48h", reply,
		          sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK
		              && ask(&admin, &owner, "add retention prune fuzznetd level=DT age 2d", reply,
		                     sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_ERROR,
		      "a rule was not kept, or its other spelling was kept twice");
		CHECK(ask(&admin, &owner, "list retention", reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK
		              && detail_len == strlen("1 prune%20fuzznetd%20level=DT%20age%202d")
		              && says(detail, detail_len, "1 prune%20fuzznetd%20level=DT%20age%202d"),
		      "the rule was not listed once, in one escaped word of its canonical text");
		CHECK(ask(&admin, &owner, "remove retention prune fuzznetd level=D level=T age 2d",
		          reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
		                         == FZN_REPLY_MALFORMED
		              && ask(&admin, &owner, "remove retention prune fuzznetd level=DT age 172800",
		                     reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK
		              && ask(&admin, &owner, "list retention", reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK
		              && detail_len == 1u && detail[0] == '0',
		      "the rule was not removed by a third spelling of it");
		/* A POLICY, sec 566, kept, listed and removed as a rule is. */
		CHECK(ask(&admin, &owner, "add retention policy messages drop", reply, sizeof(reply),
		          &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK
		              && ask(&admin, &owner, "list retention", reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK
		              && says(detail, detail_len, "1 policy%20messages%20drop")
		              && ask(&admin, &owner, "remove retention policy messages drop", reply,
		                     sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK,
		      "a policy was not kept, listed and removed as a rule is");
		state.hash = was;
	}

	/* ---- SHARES, sec 436: `grant share` pairs a contact's node for the
	 * share capability, from this node's own key; the contact is then a
	 * peer and still no member, and its requests reach only the notes. */
	{
		static struct node outside;
		char key_hex[(FZN_PUBKEY_LEN * 2u) + 1u], dev_hex[(FZN_PUBKEY_LEN * 2u) + 1u];
		char out_prekey[(FZN_PREKEY_LEN_TOTAL * 2u) + 1u];
		const fzn_node_peer_t *granted = NULL;
		size_t before = state.peer_count, i;
		char text[FZN_PROVISION_TEXT_MAX_LEN];
		fzn_opened_t req;
		uint8_t out[256];
		size_t n;
		size_t k;

		for (k = 0; k < FZN_PUBKEY_LEN; k++)
			snprintf(key_hex + (2u * k), 3u, "%02x", (unsigned)(0x40u + k));
		CHECK(node_up(&outside), "fixture: a node outside the estate");
		hex(outside.id.pubkey, FZN_PUBKEY_LEN, dev_hex);
		hex(outside.id.prekey_record, FZN_PREKEY_LEN_TOTAL, out_prekey);
		snprintf(line, sizeof(line), "add contact bob %s", dev_hex);
		CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK,
		      "fixture: the outside node as the contact bob");
		snprintf(line, sizeof(line), "add contact carol %s", key_hex);
		CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK,
		      "fixture: another contact, carol");

		snprintf(line, sizeof(line), "grant share bob %s", out_prekey);
		CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_ERROR
		              && state.peer_count == before,
		      "a node that does not share granted a share");
		CHECK(fzn_service_capability(7u, 3u, (const uint8_t *)"fuzznet.notes.share", 19u,
		                             &hash_ops, &state.config.share_capability)
		              == FZN_CHAIN_OK,
		      "fixture: the share capability");
		memcpy(state.config.share_root, node.id.pubkey, FZN_PUBKEY_LEN);
		state.config.has_share = 1;

		CHECK(ask(&admin, &member, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_DENIED
		              && state.peer_count == before,
		      "a service-group member granted a share");
		snprintf(line, sizeof(line), "grant share carol %s", out_prekey);
		CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_ERROR
		              && state.peer_count == before,
		      "a share was granted to carol through bob's node's prekey");
		CHECK(ask(&admin, &owner, "grant share dave 00", reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
		                         == FZN_REPLY_MALFORMED,
		      "a grant with no prekey record was not malformed");
		snprintf(line, sizeof(line), "grant share dave %s", out_prekey);
		CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_ERROR,
		      "a share was granted to a name that is no contact");

		snprintf(line, sizeof(line), "grant share bob %s", out_prekey);
		CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK
		              && state.peer_count == before + 1u,
		      "the owner's grant did not pair bob's node as a contact");
		for (i = 0; i < state.peer_count; i++)
			if (memcmp(state.peers[i].sender, outside.id.pubkey, FZN_PUBKEY_LEN) == 0)
				granted = &state.peers[i];
		CHECK(granted && fzn_node_peer_contact(&state.config, granted),
		      "the granted peer is not a contact");

		memcpy(text, detail, detail_len);
		text[detail_len] = '\0';
		CHECK(fzn_provision_from_text(text, card, sizeof(card), &card_len) == FZN_PROVISION_OK
		              && fzn_node_pairing_accept(&outside.id, card, card_len, 2100u, &outside.ops,
		                                         &pairing)
		                         == FZN_NODE_PAIR_OK
		              && memcmp(pairing.capability.b, state.config.share_capability.b,
		                        FZN_CAP_ID_LEN)
		                         == 0,
		      "bob's node would not accept the card, or it carries another capability");
		fzn_wipe(&pairing, sizeof(pairing));
		{
			char marked[(FZN_PUBKEY_LEN * 2u) + 16u], page[32];

			snprintf(marked, sizeof(marked), "%s,contact", dev_hex);
			snprintf(page, sizeof(page), "list peer %zu",
			         granted ? (size_t)(granted - state.peers) : 0u);
			CHECK(ask(&admin, &owner, page, reply, sizeof(reply), &reply_len)
			              && says(reply, reply_len, marked),
			      "list peer did not mark the contact among the members");
		}
		snprintf(line, sizeof(line), "add contact bobby %s", dev_hex);
		CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK,
		      "a contact holding a share grant was counted a member of the estate");

		/* ITS REQUESTS: the notes hook only, and told it is a contact. */
		memset(&req, 0, sizeof(req));
		req.capability = state.config.share_capability.b;
		req.sender = outside.id.pubkey;
		req.payload = (const uint8_t *)"list peer";
		req.payload_len = 9u;
		n = fzn_node_admin_remote(&admin, FZN_NODE_REMOTE_GRANTED, &req, out, sizeof(out));
		CHECK(n && fzn_reply_of(out, n, &detail, &detail_len) == FZN_REPLY_DENIED,
		      "a contact's verb was answered as a member's");
		/* A TEXT REQUEST reaches the scoped text hook, told who asks. */
		admin.text_shared = text_shared_stub;
		text_shared_told = 0;
		n = fzn_node_admin_remote(&admin, FZN_NODE_REMOTE_GRANTED, &req, out, sizeof(out));
		CHECK(n == 2u && text_shared_told
		              && memcmp(text_shared_sender, outside.id.pubkey, FZN_PUBKEY_LEN) == 0,
		      "a contact's request did not reach the text hook with its sender");
		admin.text_shared = NULL;
		admin.notes_remote = notes_remote_stub;
		notes_shared_seen = -1;
		n = fzn_node_admin_remote(&admin, FZN_NODE_REMOTE_GRANTED, &req, out, sizeof(out));
		CHECK(n && notes_shared_seen == 1,
		      "a contact's request did not reach the notes hook as shared");
		/* REMOVED, IT IS SUSPENDED, sec 454: refused before either hook,
		 * and served again once added back -- and, sec 576, its share pulled
		 * no further, by the same predicate. */
		{
			uint8_t stranger[FZN_PUBKEY_LEN];

			memset(stranger, 0x7e, sizeof(stranger));
			CHECK(fzn_node_admin_contact_stands(&admin, outside.id.pubkey)
			              && !fzn_node_admin_contact_stands(&admin, stranger)
			              && !fzn_node_admin_contact_stands(&admin, NULL),
			      "a standing contact does not stand, or a stranger or no key does");
		}
		/* THE HOOKS IT REACHES, standing, removed and added back, sec 700:
		 * every contact hook and no member's while it stands; once removed,
		 * the relay alone -- asked of every sender before the two part,
		 * and each message behind it judges standing for itself -- and no
		 * extension, which is told only "a contact" and cannot tell a
		 * removed one. */
		{
			static const uint8_t generic[] = { 2u, 0x7eu, 0u, 0u };
			static const uint8_t extension[] = { FZN_TYPES_VERSION_SHARED,
			                                     FZN_TYPES_EXTENSION_FIRST, 0u, 0u };
			const unsigned contact_hooks = R_RELAY | R_CONTACT_DEVICES | R_MESSAGES_CONTACT
			                               | R_ROUTING | R_NOTES | R_TEXT_SHARED
			                               | R_FILES_SHARED;
			unsigned got = hooks_reached(&admin, req, generic, sizeof(generic));

			CHECK(got == contact_hooks,
			      "a standing contact did not reach every contact hook, or reached a "
			      "member's");
			got = hooks_reached(&admin, req, extension, sizeof(extension));
			CHECK(got == (R_RELAY | R_EXTENSION),
			      "a standing contact's extension request did not reach the extension alone");
			CHECK(ask(&admin, &owner, "remove contact bobby", reply, sizeof(reply),
			          &reply_len)
			              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
			                         == FZN_REPLY_OK,
			      "fixture: bob removed as a contact, for the table");
			got = hooks_reached(&admin, req, generic, sizeof(generic));
			CHECK(got == R_RELAY, "a removed contact reached a hook past the relay");
			got = hooks_reached(&admin, req, extension, sizeof(extension));
			CHECK(got == R_RELAY,
			      "a removed contact's extension request reached the extension, as a "
			      "contact");
			CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
			              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
			                         == FZN_REPLY_OK
			              && hooks_reached(&admin, req, generic, sizeof(generic))
			                         == contact_hooks,
			      "a contact added back did not reach the contact hooks again");
		}
		CHECK(ask(&admin, &owner, "remove contact bobby", reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK,
		      "fixture: bob removed as a contact");
		CHECK(!fzn_node_admin_contact_stands(&admin, outside.id.pubkey),
		      "a removed contact still stands");
		notes_shared_seen = -1;
		n = fzn_node_admin_remote(&admin, FZN_NODE_REMOTE_GRANTED, &req, out, sizeof(out));
		CHECK(n && fzn_reply_of(out, n, &detail, &detail_len) == FZN_REPLY_DENIED
		              && notes_shared_seen == -1,
		      "a removed contact's request was still served");
		CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK,
		      "fixture: bob added back");
		n = fzn_node_admin_remote(&admin, FZN_NODE_REMOTE_GRANTED, &req, out, sizeof(out));
		CHECK(n && notes_shared_seen == 1, "a contact added back was not served again");
		CHECK(fzn_node_admin_contact_stands(&admin, outside.id.pubkey),
		      "a contact added back does not stand again");
		/* THE CONTACTS AS THE ROSTER, sec 489. With a roster and nothing on
		 * it, a named contact is no contact; carried onto it, it is again.
		 * A removal on the roster -- here the root's own, which retires
		 * alone -- denies it while its name stays here, marked; the verbs
		 * write roster records; adding back is a new incarnation. */
		{
			static fzn_node_roster_t ro;
			size_t carried = 0, rows;
			char marked[(FZN_PUBKEY_LEN * 2u) + 32u];

			CHECK(fzn_node_roster_init(&ro, node.id.pubkey, &state.config.remote_capability,
			                           &node.sign, NULL, &hash_ops) == FZN_NODE_ROSTER_OK,
			      "fixture: a roster");
			admin.roster = &ro;
			admin.rng = &rng_ops;
			notes_shared_seen = -1;
			req.capability = state.config.share_capability.b;
			n = fzn_node_admin_remote(&admin, FZN_NODE_REMOTE_GRANTED, &req, out, sizeof(out));
			CHECK(n && fzn_reply_of(out, n, &detail, &detail_len) == FZN_REPLY_DENIED
			              && notes_shared_seen == -1,
			      "a contact named here and on no roster was served");
			CHECK(fzn_node_roster_carry_names(&ro, &node.ops, &node.id, NULL, &rng_ops,
			                                  &carried) == FZN_NODE_ROSTER_OK
			              && carried >= 2u,
			      "the contacts named here were not carried onto the roster");
			n = fzn_node_admin_remote(&admin, FZN_NODE_REMOTE_GRANTED, &req, out, sizeof(out));
			CHECK(n && notes_shared_seen == 1, "a contact carried onto the roster was not served");
			CHECK(fzn_node_roster_write(&ro, &node.ops, &node.id, NULL, &rng_ops,
			                            outside.id.pubkey, 0, admin.revocations, 0u)
			              == FZN_NODE_ROSTER_OK,
			      "fixture: bob removed on the roster, not here");
			notes_shared_seen = -1;
			n = fzn_node_admin_remote(&admin, FZN_NODE_REMOTE_GRANTED, &req, out, sizeof(out));
			CHECK(n && fzn_reply_of(out, n, &detail, &detail_len) == FZN_REPLY_DENIED
			              && notes_shared_seen == -1,
			      "a contact removed on the roster was served on its name here");
			snprintf(marked, sizeof(marked), "bobby,%s,retired", dev_hex);
			CHECK(ask(&admin, &owner, "list contact", reply, sizeof(reply), &reply_len)
			              && says(reply, reply_len, marked),
			      "list contact did not mark the retired contact");
			rows = rows_in(&node.store, FZN_PERSIST_ROSTER);
			CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
			              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK
			              && rows_in(&node.store, FZN_PERSIST_ROSTER) == rows + 1u
			              && fzn_node_roster_standing(&ro, outside.id.pubkey, admin.revocations, 0u)
			                         == FZN_ROSTER_ACTIVE,
			      "add contact did not write a new incarnation for a retired contact");
			n = fzn_node_admin_remote(&admin, FZN_NODE_REMOTE_GRANTED, &req, out, sizeof(out));
			CHECK(n && notes_shared_seen == 1, "a contact added on the roster again was not served");
			rows = rows_in(&node.store, FZN_PERSIST_ROSTER);
			CHECK(ask(&admin, &owner, "remove contact bobby", reply, sizeof(reply), &reply_len)
			              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK
			              && rows_in(&node.store, FZN_PERSIST_ROSTER) == rows + 1u
			              && fzn_node_roster_standing(&ro, outside.id.pubkey, admin.revocations, 0u)
			                         == FZN_ROSTER_RETIRED,
			      "remove contact did not write a removal on the roster");
			CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
			              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK,
			      "fixture: bob added back on the roster");
			/* A ROSTER FULL TO THE LAST ENTRY, sec 704: the add asks for
			 * room and is written in it, rather than answered an error
			 * with the name kept and the roster without it. */
			{
				static fzn_roster_entry_t tight[64];
				static fzn_roster_writer_t tight_writers[8];
				uint8_t carla[FZN_PUBKEY_LEN];
				char carla_line[(FZN_PUBKEY_LEN * 2u) + 32u];
				size_t b;

				memset(carla, 0x77, sizeof(carla));
				snprintf(carla_line, sizeof(carla_line), "add contact carla ");
				for (b = 0; b < FZN_PUBKEY_LEN; b++)
					snprintf(carla_line + strlen(carla_line), 3, "%02x", carla[b]);
				CHECK(ro.roster.used <= 64u && ro.roster.writers_used <= 8u
				              && fzn_node_roster_use(&ro, tight, ro.roster.used, tight_writers,
				                                     ro.roster.writers_used)
				                         == FZN_NODE_ROSTER_OK,
				      "fixture: the roster's tables exactly full");
				admin.roster_room = roster_stub;
				roster_asked = 0;
				CHECK(ask(&admin, &owner, carla_line, reply, sizeof(reply), &reply_len)
				              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
				                         == FZN_REPLY_OK
				              && roster_asked == 1u
				              && fzn_node_roster_standing(&ro, carla, admin.revocations, 0u)
				                         == FZN_ROSTER_ACTIVE,
				      "a contact added to a full roster was not written once it had room");
				admin.roster_room = NULL;
			}
		}
		req.capability = state.config.remote_capability.b;
		notes_shared_seen = -1;
		n = fzn_node_admin_remote(&admin, FZN_NODE_REMOTE_GRANTED, &req, out, sizeof(out));
		CHECK(n && notes_shared_seen == 0,
		      "a member's request reached the notes hook as a contact's");
		/* IN ITS ENVELOPE, sec 462: the same request with its causes is
		 * handled as the bare one, and the node is told who asked for
		 * which entry. */
		{
			static uint8_t env[FZN_CAUSE_OVERHEAD_MAX + 16u];
			static const uint8_t bare[] = { 2u, 1u, 0u, 0u };
			fzn_entry_name_t cause;
			size_t env_len = 0;

			memset(&cause, 0, sizeof(cause));
			memset(cause.machine, 0x3c, sizeof(cause.machine));
			strcpy(cause.user, "root");
			strcpy(cause.program, "fuzznetd");
			cause.pid = 7u;
			cause.start_ms = 1u;
			cause.position = 42u;
			CHECK(fzn_cause_wrap(&cause, &cause, bare, sizeof(bare), env, sizeof(env),
			                     &env_len)
			              == FZN_CAUSE_OK,
			      "fixture: a request in its envelope");
			admin.caused = caused_stub;
			caused_calls = 0;
			req.payload = env;
			req.payload_len = env_len;
			notes_seen_len = 0;
			n = fzn_node_admin_remote(&admin, FZN_NODE_REMOTE_GRANTED, &req, out, sizeof(out));
			CHECK(n == 2u && notes_seen_len == sizeof(bare)
			              && memcmp(notes_seen, bare, sizeof(bare)) == 0 && caused_calls == 1
			              && caused_sender == outside.id.pubkey
			              && caused_cause.position == 42u,
			      "a request in its envelope reached the hook bare, and the node was told "
			      "who asked and for which entry");
			env[20] = 0u; /* inside the cause's name */
			env[17] = 0u; /* the cause's user, empty */
			n = fzn_node_admin_remote(&admin, FZN_NODE_REMOTE_GRANTED, &req, out, sizeof(out));
			CHECK(n && fzn_reply_of(out, n, &detail, &detail_len) == FZN_REPLY_MALFORMED
			              && caused_calls == 1,
			      "an envelope that does not read was handled rather than refused");
			admin.caused = NULL;
			req.payload = (const uint8_t *)"list peer";
			req.payload_len = 9u;
		}
		/* A LOG GATHERED, sec 463: a member's query reaches the logs hook;
		 * a contact's never does. */
		{
			static const uint8_t query[] = { 4u, 1u, 0u };

			admin.logs_remote = logs_stub;
			logs_calls = 0;
			req.payload = query;
			req.payload_len = sizeof(query);
			n = fzn_node_admin_remote(&admin, FZN_NODE_REMOTE_GRANTED, &req, out, sizeof(out));
			CHECK(n == 2u && out[0] == 4u && logs_calls == 1,
			      "a member's gather query did not reach the logs hook");
			req.capability = state.config.share_capability.b;
			n = fzn_node_admin_remote(&admin, FZN_NODE_REMOTE_GRANTED, &req, out, sizeof(out));
			CHECK(logs_calls == 1,
			      "a contact's gather query reached the logs hook");
			req.capability = state.config.remote_capability.b;
			admin.logs_remote = NULL;
			req.payload = (const uint8_t *)"list peer";
			req.payload_len = 9u;
		}
		admin.notes_remote = NULL;

		snprintf(line, sizeof(line), "remove peer %s", dev_hex);
		CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK
		              && state.peer_count == before,
		      "fixture: bob's node un-paired");

		/* ---- RECEIVED, sec 437: the other way round. bob's node shares
		 * with this one; this node takes the card and records where to
		 * pull from. */
		{
			static char card_text[FZN_PROVISION_TEXT_MAX_LEN];
			uint8_t member_card[FZN_PROVISION_MAX_LEN];
			static char member_text[FZN_PROVISION_TEXT_MAX_LEN];
			size_t member_len = 0;
			fzn_prekey_record_t mine;
			fzn_node_pairing_t held;
			fzn_node_received_t row;
			fzn_persist_ops_t tree;
			fzn_notes_received_t seam;
			uint8_t blob[FZN_PERSIST_HEAD_LEN + 1u], claim[FZN_PUBKEY_LEN];
			size_t gone_len = 0;
			char card_path[64], member_path[64], junk_path[64];
			FILE *f;

			CHECK(fzn_prekey_open(node.id.prekey_record, FZN_PREKEY_LEN_TOTAL, &mine)
			                      == FZN_PREKEY_OK
			              && fzn_node_pair(&outside.id, outside.id.pubkey,
			                               &state.config.share_capability, NULL, 0,
			                               &outside.ops, mine, 2000u, 2000u + 86400u, card,
			                               sizeof(card), &card_len)
			                         == FZN_NODE_PAIR_OK
			              && fzn_provision_text(card, card_len, card_text, sizeof(card_text))
			                         == FZN_PROVISION_OK,
			      "fixture: bob's node grants this one a share");
			CHECK(fzn_node_pair(&outside.id, outside.id.pubkey,
			                    &state.config.remote_capability, NULL, 0, &outside.ops, mine,
			                    2000u, 2000u + 86400u, member_card, sizeof(member_card),
			                    &member_len)
			                      == FZN_NODE_PAIR_OK
			              && fzn_provision_text(member_card, member_len, member_text,
			                                    sizeof(member_text))
			                         == FZN_PROVISION_OK,
			      "fixture: and a card for another capability");
			/* THE CARDS AS FILES: a card's text is past one request line. */
			snprintf(card_path, sizeof(card_path), "/tmp/fzn-admin-card-%d", (int)getpid());
			snprintf(member_path, sizeof(member_path), "/tmp/fzn-admin-member-%d",
			         (int)getpid());
			snprintf(junk_path, sizeof(junk_path), "/tmp/fzn-admin-junk-%d", (int)getpid());
			CHECK((f = fopen(card_path, "w")) && fprintf(f, "%s\n", card_text) > 0
			              && fclose(f) == 0
			              && (f = fopen(member_path, "w")) && fputs(member_text, f) >= 0
			              && fclose(f) == 0
			              && (f = fopen(junk_path, "w")) && fputs("notacard", f) >= 0
			              && fclose(f) == 0,
			      "fixture: the cards written to files");

			state.config.has_share = 0;
			snprintf(line, sizeof(line), "add received bobby 127.0.0.1 7000 %s", card_path);
			CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
			              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
			                         == FZN_REPLY_ERROR,
			      "a node keeping no notes took a share");
			state.config.has_share = 1;
			CHECK(ask(&admin, &member, line, reply, sizeof(reply), &reply_len)
			              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
			                         == FZN_REPLY_DENIED,
			      "a service-group member took a share");
			snprintf(line, sizeof(line), "add received carol 127.0.0.1 7000 %s", card_path);
			CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
			              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
			                         == FZN_REPLY_ERROR,
			      "bob's card was taken as carol's share");
			snprintf(line, sizeof(line), "add received bobby 127.0.0.1 7000 %s", member_path);
			CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
			              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
			                         == FZN_REPLY_ERROR,
			      "a card for another capability was taken as a share");
			snprintf(line, sizeof(line), "add received bobby 127.0.0.1 0 %s", card_path);
			CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
			              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
			                         == FZN_REPLY_MALFORMED,
			      "port 0 was taken");
			snprintf(line, sizeof(line), "add received bobby 127.0.0.1 7000 %s", junk_path);
			CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
			              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
			                         == FZN_REPLY_MALFORMED,
			      "a word that is no card was taken");
			CHECK(fzn_node_pairing_load(&node.ops, outside.id.pubkey, &held) != FZN_PERSIST_OK,
			      "a refused card left a pairing behind");
			CHECK(ask(&admin, &owner, "add received bobby 127.0.0.1 7000 /nonexistent/card",
			          reply, sizeof(reply), &reply_len)
			              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
			                         == FZN_REPLY_ERROR,
			      "a card file that cannot be read was not refused");

			admin.received_fresh = 0;
			snprintf(line, sizeof(line), "add received bobby 127.0.0.1 7000 %s", card_path);
			CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
			              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
			                         == FZN_REPLY_OK
			              && admin.received_fresh,
			      "the owner could not take bob's share, or the daemon was not told");
			CHECK(fzn_node_pairing_load(&node.ops, outside.id.pubkey, &held) == FZN_PERSIST_OK
			              && memcmp(held.capability.b, state.config.share_capability.b,
			                        FZN_CAP_ID_LEN)
			                         == 0,
			      "the share's pairing was not kept, or is for another capability");
			fzn_wipe(&held, sizeof(held));
			CHECK(fzn_node_received_get(&node.ops, outside.id.pubkey, &row)
			                      == FZN_NODE_RECEIVED_OK
			              && row.port == 7000u && row.host_len == 9u
			              && memcmp(row.host, "127.0.0.1", 9u) == 0,
			      "the share's address was not recorded");
			CHECK(ask(&admin, &member, "list received", reply, sizeof(reply), &reply_len)
			              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
			                         == FZN_REPLY_DENIED,
			      "another user read the received shares");
			CHECK(ask(&admin, &owner, "list received", reply, sizeof(reply), &reply_len)
			              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
			                         == FZN_REPLY_OK
			              && says(detail, detail_len, "1 bobby,127.0.0.1,7000"),
			      "list received did not name the share by contact, host and port");

			/* A ROW OF bob's TREE, so forgetting can be seen to take it. */
			memset(claim, 0x3c, sizeof(claim));
			CHECK(fzn_notes_received_ops(&seam, &node.ops, &hash_ops, outside.id.pubkey, &tree)
			                      == FZN_NOTES_OK
			              && fzn_persist_head_write(blob, sizeof(blob), 1u,
			                                        FZN_PERSIST_BLOB_NOTE)
			                         == FZN_PERSIST_OK
			              && tree.save(tree.ctx, FZN_PERSIST_NOTE, claim, blob, sizeof(blob)),
			      "fixture: a note in bob's tree");
			admin.received_fresh = 0;
			/* THE DAEMON'S HASH, which files the wrap keys bob's tree held
			 * and forgetting it destroys (sec 520). */
			state.hash = &hash_ops;
			CHECK(ask(&admin, &owner, "remove received bobby", reply, sizeof(reply), &reply_len)
			              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
			                         == FZN_REPLY_OK
			              && admin.received_fresh,
			      "the owner could not stop bob's share, or the daemon was not told");
			state.hash = NULL;
			CHECK(!tree.load(tree.ctx, FZN_PERSIST_NOTE, claim, blob, sizeof(blob), &gone_len),
			      "what was pulled from bob stayed after the share was removed");
			CHECK(ask(&admin, &owner, "list received", reply, sizeof(reply), &reply_len)
			              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
			                         == FZN_REPLY_OK
			              && detail_len == 1u && detail[0] == '0',
			      "a removed share was still listed");
			CHECK(ask(&admin, &owner, "remove received bobby", reply, sizeof(reply), &reply_len)
			              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
			                         == FZN_REPLY_ERROR,
			      "removing it again was answered as if it were there");

			(void)unlink(card_path);
			(void)unlink(member_path);
			(void)unlink(junk_path);

			/* THE TABLE'S OWN RULES. */
			CHECK(!fzn_node_received_host_ok("a b", 3u) && !fzn_node_received_host_ok("", 0u)
			              && fzn_node_received_host_ok("example.org", 11u),
			      "a host with a space, or none, was taken; or a plain one refused");
			{
				uint8_t rk[FZN_PUBKEY_LEN];
				unsigned ri;

				for (ri = 0; ri < FZN_NODE_RECEIVED_MAX; ri++) {
					memset(rk, (int)(0x70u + ri), sizeof(rk));
					CHECK(fzn_node_received_add(&node.ops, rk, "h", 1u, 1u, 0u)
					              == FZN_NODE_RECEIVED_OK,
					      "fixture: a share up to the bound");
				}
				memset(rk, 0x7f, sizeof(rk));
				CHECK(fzn_node_received_add(&node.ops, rk, "h", 1u, 1u, 0u)
				              == FZN_NODE_RECEIVED_ERR_FULL,
				      "a share past the bound was taken");
				memset(rk, 0x70, sizeof(rk));
				CHECK(fzn_node_received_add(&node.ops, rk, "other", 5u, 2u, 0u)
				                      == FZN_NODE_RECEIVED_OK
				              && fzn_node_received_get(&node.ops, rk, &row)
				                         == FZN_NODE_RECEIVED_OK
				              && row.port == 2u,
				      "at the bound, a held share's address could not change");
				for (ri = 0; ri < FZN_NODE_RECEIVED_MAX; ri++) {
					memset(rk, (int)(0x70u + ri), sizeof(rk));
					(void)fzn_node_received_remove(&node.ops, rk);
				}
			}
		}
		state.config.has_share = 0;
		fzn_sign_monocypher_wipe(&outside.signer);
	}

	/* ---- TEXTS GO TO THE SHELF'S HOOK, sec 424, and what it does not take
	 * falls through to the verbs' own refusal. */
	admin.text_local = text_local_stub;
	CHECK(ask(&admin, &owner, "get text x", reply, sizeof(reply), &reply_len)
	              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK
	              && says(detail, detail_len, "stub"),
	      "get text did not reach the shelf's hook");
	CHECK(ask(&admin, &owner, "get nothing", reply, sizeof(reply), &reply_len)
	              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
	                         == FZN_REPLY_UNSUPPORTED,
	      "what the shelf's hook does not take was not unsupported");
	admin.text_local = NULL;
	CHECK(ask(&admin, &owner, "get text x", reply, sizeof(reply), &reply_len)
	              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
	                         == FZN_REPLY_UNSUPPORTED,
	      "with no shelf, get text was not unsupported");

	/* ---- AN EXTENSION'S VERBS, sec 673: asked last, so what the admin
	 * answers stays the admin's; held to the reply vocabulary and one
	 * line; and what it declines is unsupported. */
	admin.extension_local = extension_stub;
	CHECK(ask(&admin, &owner, "get mine", reply, sizeof(reply), &reply_len)
	              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK
	              && says(detail, detail_len, "extension"),
	      "an extension's verb was not answered by the extension");
	extension_asked = 0;
	CHECK(ask(&admin, &owner, "list contact", reply, sizeof(reply), &reply_len)
	              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK
	              && !says(detail, detail_len, "extension") && extension_asked == 0,
	      "a verb the admin answers reached the extension");
	CHECK(ask(&admin, &owner, "get garbled", reply, sizeof(reply), &reply_len)
	              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_ERROR,
	      "an extension's answer outside the vocabulary was passed on");
	CHECK(ask(&admin, &owner, "get twice", reply, sizeof(reply), &reply_len)
	              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_ERROR,
	      "an extension's answer of two lines was passed on");
	CHECK(ask(&admin, &owner, "get nothing", reply, sizeof(reply), &reply_len)
	              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
	                         == FZN_REPLY_UNSUPPORTED,
	      "what the extension declines was not unsupported");
	admin.extension_local = NULL;

	/* AND ITS REMOTE TYPES, sec 674: its range alone reaches it, a member
	 * as a member; one it declines, and any of its range with no
	 * extension, is `unsupported`; a type below the range never reaches
	 * it. */
	{
		static const uint8_t mine[] = { 2u, 128u, 7u }, declined[] = { 2u, 191u },
		                     below[] = { 2u, 127u }, other_version[] = { 7u, 128u };
		size_t n;

		admin.extension_remote = extension_remote_stub;
		n = remote_bytes(&admin, device.id.pubkey, mine, sizeof(mine), reply, sizeof(reply));
		CHECK(n == 2u && reply[0] == 2u && reply[1] == 129u && extension_remote_contact == 0,
		      "an extension's remote type was not answered by it, as from a member");
		n = remote_bytes(&admin, device.id.pubkey, declined, sizeof(declined), reply,
		                 sizeof(reply));
		CHECK(n && fzn_reply_of(reply, n - 1u, &detail, &detail_len) == FZN_REPLY_UNSUPPORTED,
		      "a type of the range the extension declines was not unsupported");
		extension_remote_asked = 0;
		(void)remote_bytes(&admin, device.id.pubkey, below, sizeof(below), reply,
		                   sizeof(reply));
		(void)remote_bytes(&admin, device.id.pubkey, other_version, sizeof(other_version),
		                   reply, sizeof(reply));
		CHECK(extension_remote_asked == 0,
		      "a type outside the range, or another version's, reached the extension");
		admin.extension_remote = NULL;
		n = remote_bytes(&admin, device.id.pubkey, mine, sizeof(mine), reply, sizeof(reply));
		CHECK(n && fzn_reply_of(reply, n - 1u, &detail, &detail_len) == FZN_REPLY_UNSUPPORTED,
		      "with no extension, its type was not unsupported");
	}
	/* AND A MEMBER'S ROW OF THE TABLE, sec 700: every member hook, and none
	 * a contact's own -- a line filed under the contact it speaks for,
	 * what is shared with it, a text or a file shared with it. */
	{
		static const uint8_t generic[] = { 2u, 0x7eu, 0u, 0u };
		fzn_opened_t rq;
		unsigned got;

		memset(&rq, 0, sizeof(rq));
		rq.capability = admin.state->config.remote_capability.b;
		rq.sender = device.id.pubkey;
		got = hooks_reached(&admin, rq, generic, sizeof(generic));
		CHECK(got == (R_RELAY | R_CONTACT_DEVICES | R_LOGS | R_ROUTING | R_TEXT | R_JOURNAL
		              | R_HOLDINGS | R_NOTES | R_MESSAGES),
		      "a member did not reach every member hook, or reached a contact's own");
	}
	CHECK(ask(&admin, &owner, "get mine", reply, sizeof(reply), &reply_len)
	              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
	                         == FZN_REPLY_UNSUPPORTED,
	      "with no extension, its verb was not unsupported");

	/* ---- AS A ROOT BY IDENTITY, sec 419: the node is made a member of an
	 * estate whose genesis is the device's key and which has added the
	 * node's identity as a root; `add peer` then pairs with one hop and
	 * that add, a card that fits the reply. */
	{
		static fzn_node_roots_t other;
		uint8_t pinned[FZN_PUBKEY_LEN], add[FZN_ROOT_ADD_LEN];
		struct fzn_node_roots *was = admin.roots;

		memcpy(pinned, state.config.root, FZN_PUBKEY_LEN);
		CHECK(fzn_node_roots_init(&other, device.id.pubkey, &node.sign, &hash_ops)
		              == FZN_NODE_ROOTS_OK
		              && fzn_root_add_issue(device.id.pubkey, node.id.pubkey, &device.sign, add)
		                         == FZN_ROOT_LOG_OK
		              && fzn_node_roots_learn(&other, &node.ops, add, sizeof(add))
		                         == FZN_NODE_ROOTS_OK,
		      "fixture: an estate rooted at the device that added this node");
		memcpy(state.config.root, device.id.pubkey, FZN_PUBKEY_LEN);
		admin.roots = &other;
		snprintf(line, sizeof(line), "add peer %s", prekey_hex);
		CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK
		              && detail_len == FZN_PROVISION_TEXT_PREFIX_LEN
		                                       + FZN_PROVISION_TEXT_BODY_LEN(
		                                               FZN_PROVISION_LEN(1, 1)),
		      "a root by identity did not pair with one hop and its add");

		/* TWO ADDS AWAY, the card would not fit: refused, not cut short. */
		{
			static fzn_node_roots_t deep;
			static struct node middle;
			uint8_t first[FZN_ROOT_ADD_LEN], second[FZN_ROOT_ADD_LEN];

			CHECK(node_up(&middle)
			              && fzn_node_roots_init(&deep, device.id.pubkey, &node.sign,
			                                     &hash_ops) == FZN_NODE_ROOTS_OK
			              && fzn_root_add_issue(device.id.pubkey, middle.id.pubkey,
			                                    &device.sign, first) == FZN_ROOT_LOG_OK
			              && fzn_root_add_issue(middle.id.pubkey, node.id.pubkey,
			                                    &middle.sign, second) == FZN_ROOT_LOG_OK
			              && fzn_node_roots_learn(&deep, &node.ops, first, sizeof(first))
			                         == FZN_NODE_ROOTS_OK
			              && fzn_node_roots_learn(&deep, &node.ops, second, sizeof(second))
			                         == FZN_NODE_ROOTS_OK,
			      "fixture: an estate that reaches this node in two adds");
			admin.roots = &deep;
			CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
			              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
			                         == FZN_REPLY_ERROR,
			      "a root two adds away paired at the verb with a card past a reply");
		}
		admin.roots = was;
		memcpy(state.config.root, pinned, FZN_PUBKEY_LEN);
	}

	/* ---- THE ESTATE'S k, sec 418: the owner sets it as this root and the
	 * running store takes it; a group member may not; 0 is refused. */
	CHECK(ask(&admin, &member, "set quorum 3", reply, sizeof(reply), &reply_len)
	              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_DENIED,
	      "a service-group member set k");
	CHECK(ask(&admin, &owner, "set quorum 3", reply, sizeof(reply), &reply_len)
	              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK
	              && detail_len == 1u && detail[0] == '3' && admin.revocations->quorum == 3u,
	      "the owner's k of 3 was not answered, or the running store did not take it");
	CHECK(ask(&admin, &owner, "set quorum 0", reply, sizeof(reply), &reply_len)
	              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
	                         == FZN_REPLY_MALFORMED
	              && admin.revocations->quorum == 3u,
	      "a k of 0 was taken");

	/* ---- THE ESTATE'S RETENTION RULES, sec 476: the owner adds one as this
	 * root, logged as its act -- which the journal carries since sec 505 --
	 * a store loaded afresh resolves it, and a removal by another spelling
	 * takes it away. */
	{
		static fzn_node_roots_t again;
		fzn_retain_rule_t rules[4];
		size_t n = 0, unread = 9, loaded = 0;

		CHECK(ask(&admin, &member, "add estate-retention prune * level=D age 2d", reply,
		          sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_DENIED,
		      "a service-group member set an estate rule");
		CHECK(ask(&admin, &owner, "add estate-retention prune * level=D age 48h", reply,
		          sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK
		              && ask(&admin, &owner, "add estate-retention prune * level=D age 2d", reply,
		                     sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_ERROR
		              && says(detail, detail_len, "the estate's already"),
		      "an estate rule was not set, or its other spelling was set twice");
		CHECK(ask(&admin, &member, "list estate-retention", reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK
		              && detail_len == strlen("1 prune%20*%20level=D%20age%202d")
		              && says(detail, detail_len, "1 prune%20*%20level=D%20age%202d"),
		      "the estate's rule was not listed to a member, once, in its canonical text");
		CHECK(fzn_node_roots_init(&again, node.id.pubkey, &node.sign, &hash_ops)
		                      == FZN_NODE_ROOTS_OK
		              && fzn_node_roots_load(&again, &node.ops, &loaded) == FZN_NODE_ROOTS_OK
		              && fzn_node_roots_retention(&again, rules, 4u, &n, &unread)
		                         == FZN_NODE_ROOTS_OK
		              && n == 1u && unread == 0u && rules[0].levels == (1u << FZN_ENTRY_DEBUG),
		      "the rule did not survive a reload of the root records");
		CHECK(fzn_node_roots_retention(&again, rules, 0u, &n, &unread) == FZN_NODE_ROOTS_OK
		              && n == 0u && unread == 1u,
		      "a rule past the caller's room was dropped unseen rather than counted");
		{
			size_t before = (size_t)acts_by(node.id.pubkey);

			CHECK(ask(&admin, &owner, "remove estate-retention prune * level=I age 2d", reply,
			          sizeof(reply), &reply_len)
			              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
			                         == FZN_REPLY_ERROR
			              && says(detail, detail_len, "no such estate rule")
			              && (size_t)acts_by(node.id.pubkey) == before,
			      "a rule the estate does not have was removed, or its refusal still logged "
			      "an act");
		}
		CHECK(ask(&admin, &owner, "remove estate-retention prune * level=D age 172800", reply,
		          sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK
		              && ask(&admin, &owner, "list estate-retention", reply, sizeof(reply),
		                     &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK
		              && detail_len == 1u && detail[0] == '0',
		      "the rule was not removed by another spelling of it");
	}

	/* ---- RETENTION RULES AS SETTINGS, sec 541: with settings attached the
	 * verbs write them, and a rule in the store's older rows is still
	 * listed and removed. */
	{
		static fzn_node_apply_t ap;
		static fzn_node_settings_t ns;
		const fzn_hash_ops_t *was = state.hash;
		size_t before = 0, estate_before = 0, n = 0, unread = 0;
		fzn_retain_rule_t rules[8];

		state.hash = &hash_ops;
		CHECK(ask(&admin, &owner, "add retention prune * age 9d", reply, sizeof(reply),
		          &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK
		              && ask(&admin, &owner, "list retention", reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK,
		      "fixture: a rule in the store's older rows, before settings are attached");
		before = rules_counted(detail, detail_len);
		memset(&ap, 0, sizeof(ap));
		ap.journal = &journal;
		ap.revocations = admin.revocations;
		ap.store = admin.store;
		ap.root = node.id.pubkey;
		ap.capability = &state.config.remote_capability;
		ap.sign = &node.sign;
		ap.hash = &hash_ops;
		ap.settings = &ns;
		memset(&ns, 0, sizeof(ns));
		ns.store = admin.store;
		ns.hash = &hash_ops;
		ns.verify = &node.sign;
		ns.journal = &journal;
		ns.id = &node.id;
		ns.apply = &ap;
		ns.estate = node.id.pubkey;
		ns.now = settings_clock;
		admin.settings = &ns;

		CHECK(ask(&admin, &owner, "add retention prune fuzznetd age 3d", reply, sizeof(reply),
		          &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK
		              && rule_in_settings(&ns, FZN_SCOPE_HOST, node.id.pubkey,
		                                  "prune fuzznetd age 3d")
		              && ask(&admin, &owner, "list retention", reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK
		              && rules_counted(detail, detail_len) == before + 1u
		              && says(detail, detail_len, "prune%20fuzznetd%20age%203d")
		              && says(detail, detail_len, "prune%20*%20age%209d"),
		      "a rule added with settings attached is not this host's setting, or the listing "
		      "lost the older row");
		CHECK(ask(&admin, &owner, "remove retention prune * age 216h", reply, sizeof(reply),
		          &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK
		              && ask(&admin, &owner, "remove retention prune fuzznetd age 72h", reply,
		                     sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK
		              && !rule_in_settings(&ns, FZN_SCOPE_HOST, node.id.pubkey,
		                                   "prune fuzznetd age 3d")
		              && ask(&admin, &owner, "list retention", reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK
		              && rules_counted(detail, detail_len) == before - 1u,
		      "the older row and the setting were not both removed, by other spellings");
		CHECK(ask(&admin, &owner, "remove retention prune fuzznetd age 3d", reply,
		          sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_ERROR,
		      "removing a rule held nowhere was not refused");

		CHECK(fzn_node_roots_retention(admin.roots, rules, 8u, &estate_before, &unread)
		              == FZN_NODE_ROOTS_OK
		              && ask(&admin, &owner, "add estate-retention prune * level=D age 5d", reply,
		                     sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK
		              && rule_in_settings(&ns, FZN_SCOPE_ESTATE, node.id.pubkey,
		                                  "prune * level=D age 5d")
		              && fzn_node_roots_retention(admin.roots, rules, 8u, &n, &unread)
		                         == FZN_NODE_ROOTS_OK
		              && n == estate_before
		              && ask(&admin, &owner, "list estate-retention", reply, sizeof(reply),
		                     &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK
		              && rules_counted(detail, detail_len) == estate_before + 1u,
		      "an estate rule added with settings attached is not the estate's setting, or "
		      "went into the older records");
		CHECK(ask(&admin, &owner, "remove estate-retention prune * level=D age 120h", reply,
		          sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK
		              && !rule_in_settings(&ns, FZN_SCOPE_ESTATE, node.id.pubkey,
		                                   "prune * level=D age 5d")
		              && ask(&admin, &owner, "list estate-retention", reply, sizeof(reply),
		                     &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK
		              && rules_counted(detail, detail_len) == estate_before,
		      "the estate's setting was not removed by another spelling");
		/* THE ESTATE'S k AS A SETTING, sec 542: this node is the root. */
		if (admin.revocations)
			CHECK(ask(&admin, &owner, "set quorum 3", reply, sizeof(reply), &reply_len)
			              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
			                         == FZN_REPLY_OK
			              && admin.revocations->quorum == 3u
			              && fzn_node_settings_quorum(&ns, 9u) == 3u,
			      "set quorum with settings attached did not write the estate's setting and "
			      "put k in force");
		/* AND NOT A ROOT'S TO SET from a node judged as no root. */
		{
			uint8_t elsewhere[FZN_PUBKEY_LEN];
			size_t k_was = admin.revocations ? admin.revocations->quorum : 0u;

			memset(elsewhere, 0x7e, sizeof(elsewhere));
			ap.root = elsewhere;
			CHECK(ask(&admin, &owner, "set quorum 4", reply, sizeof(reply), &reply_len)
			              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
			                         == FZN_REPLY_ERROR
			              && says(detail, detail_len, "a root's to set")
			              && (!admin.revocations || admin.revocations->quorum == k_was),
			      "a node that is no root set the estate's k");
			ap.root = node.id.pubkey;
		}

		/* REMOTE VERBS, sec 543: every verb, as this node's own user's, from a
		 * sender judged an admin or a root, on a node whose setting says
		 * so; off by default. The node is the root here, so the root's own
		 * key is the admin sending. */
		{
			uint8_t stranger[FZN_PUBKEY_LEN], out[2048];

			memset(stranger, 0x6d, sizeof(stranger));
			admin.remote_ran = remote_ran_stub;
			remote_heard[0] = '\0';
			CHECK(remote_said(&admin, node.id.pubkey, "add retention prune * age 13d", out,
			                  sizeof(out))
			                      == FZN_REPLY_DENIED
			              && remote_heard[0] == '\0',
			      "a remote verb was run on a node not configured to take them");
			CHECK(fzn_node_settings_write(&ns, FZN_SCOPE_HOST, node.id.pubkey,
			                              (const uint8_t *)"remote/admin", 12u, 1,
			                              (const uint8_t *)"on", 2u)
			                      == FZN_NODE_SETTINGS_OK
			              && remote_said(&admin, node.id.pubkey, "add retention prune * age 13d",
			                             out, sizeof(out))
			                         == FZN_REPLY_OK
			              && rule_in_settings(&ns, FZN_SCOPE_HOST, node.id.pubkey,
			                                  "prune * age 13d")
			              && strcmp(remote_heard, "add retention") == 0
			              && remote_said(&admin, node.id.pubkey, "list retention", out,
			                             sizeof(out))
			                         == FZN_REPLY_OK,
			      "with remote/admin on, a root's remote verbs were not run as the owner's, "
			      "or the hook was told more than the verb and its subject");
			CHECK(remote_said(&admin, stranger, "add retention prune * age 14d", out,
			                  sizeof(out))
			                      == FZN_REPLY_DENIED
			              && !rule_in_settings(&ns, FZN_SCOPE_HOST, node.id.pubkey,
			                                   "prune * age 14d"),
			      "a member judged no admin ran a remote verb");
			CHECK(fzn_node_settings_write(&ns, FZN_SCOPE_HOST, node.id.pubkey,
			                              (const uint8_t *)"remote/admin", 12u, 1,
			                              (const uint8_t *)"off", 3u)
			                      == FZN_NODE_SETTINGS_OK
			              && remote_said(&admin, node.id.pubkey, "remove retention prune * age 13d",
			                             out, sizeof(out))
			                         == FZN_REPLY_DENIED,
			      "with remote/admin off again, a remote verb still ran");
			/* A CALLER OF HOST RANK, sec 562: another node the root, this
			 * node a member under its grant, so this node's own key over
			 * the remote hop ranks HOST for its own cells -- enough to set
			 * them, and not an admin, so refused a remote verb. */
			{
				static struct node other;
				static fzn_revocation_t none[2];
				fzn_revocation_store_t bare;
				fzn_revocation_store_t *was_revs = ap.revocations;
				uint8_t hop[FZN_HOP_LEN], value[FZN_SETTING_VALUE_MAX];
				fzn_node_apply_tally_t at;
				fzn_setting_rank_t rank = FZN_SETTING_RANK_ROOT;
				size_t value_len = 0;

				memset(&at, 0, sizeof(at));
				/* THE ROOT'S off WITHDRAWN first, so the host's own value is
				 * the one in force: a clear takes only its rank's layer. */
				CHECK(fzn_node_settings_write(&ns, FZN_SCOPE_HOST, node.id.pubkey,
				                              (const uint8_t *)"remote/admin", 12u, 0, NULL, 0u)
				                      == FZN_NODE_SETTINGS_OK
				              && node_up(&other)
				              && fzn_chain_mint(other.id.pubkey, node.id.pubkey,
				                                &state.config.remote_capability, 0u,
				                                FZN_NO_EXPIRY, 0, &other.sign, hop)
				                         == FZN_CHAIN_OK,
				      "fixture: another node's member grant to this one");
				/* A STORE WITH NO ROOT SET, so chains are judged against
				 * `ap.root` alone: the node's own store pins this node's
				 * key as the genesis root. */
				CHECK(fzn_revocation_store_init(&bare, none, 2u) == FZN_CHAIN_OK,
				      "fixture: a revocation store with no root set");
				ap.revocations = &bare;
				ap.root = other.id.pubkey;
				CHECK(fzn_node_apply_object(&ap, hop, sizeof(hop), &at) == FZN_NODE_APPLY_APPLIED
				              && fzn_node_settings_write(&ns, FZN_SCOPE_HOST, node.id.pubkey,
				                                         (const uint8_t *)"remote/admin", 12u, 1,
				                                         (const uint8_t *)"on", 2u)
				                         == FZN_NODE_SETTINGS_OK
				              && fzn_node_settings_get(&ns, FZN_SCOPE_HOST, node.id.pubkey,
				                                       (const uint8_t *)"remote/admin", 12u, value,
				                                       &value_len, &rank)
				              && value_len == 2u && memcmp(value, "on", 2u) == 0
				              && rank == FZN_SETTING_RANK_HOST,
				      "fixture: this node, a member, sets its own remote/admin on at host rank");
				CHECK(remote_said(&admin, node.id.pubkey, "add retention prune * age 15d", out,
				                  sizeof(out))
				                      == FZN_REPLY_DENIED
				              && !rule_in_settings(&ns, FZN_SCOPE_HOST, node.id.pubkey,
				                                   "prune * age 15d"),
				      "a caller of host rank ran a remote verb");
				/* A HIGHER RANK KEEPS THE RULE, sec 541's untested answer:
				 * this node adds a rule at its host rank, the root sets the
				 * same cell, and this node's removal clears only its own
				 * layer -- so it says the rule stays. */
				{
					uint8_t key[FZN_NODE_SETTINGS_RULE_KEY_LEN], obj[FZN_SETTING_MAX];
					char text[FZN_RETAIN_TEXT_MAX];
					fzn_retain_rule_t rule;
					size_t text_len = 0, obj_len = 0;

					CHECK(ask(&admin, &owner, "add retention prune * age 16d", reply,
					          sizeof(reply), &reply_len)
					              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
					                         == FZN_REPLY_OK
					              && fzn_retain_parse("prune * age 16d", 15u, &rule)
					                         == FZN_RETAIN_OK
					              && fzn_retain_text(&rule, text, sizeof(text), &text_len)
					                         == FZN_RETAIN_OK
					              && fzn_node_settings_rule_key(&hash_ops, text, text_len, key)
					              && fzn_setting_issue(other.id.pubkey, &other.sign,
					                                   FZN_SCOPE_HOST, node.id.pubkey, 1u, key,
					                                   sizeof(key), 1, (const uint8_t *)text,
					                                   text_len, obj, &obj_len)
					                         == FZN_SETTING_OK
					              && fzn_node_apply_object(&ap, obj, obj_len, &at)
					                         == FZN_NODE_APPLY_APPLIED,
					      "fixture: this node's rule at host rank, and the root's on the "
					      "same cell");
					CHECK(ask(&admin, &owner, "remove retention prune * age 384h", reply,
					          sizeof(reply), &reply_len)
					              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
					                         == FZN_REPLY_ERROR
					              && says(detail, detail_len, "a higher rank keeps the rule")
					              && rule_in_settings(&ns, FZN_SCOPE_HOST, node.id.pubkey,
					                                  "prune * age 16d"),
					      "a removal a higher rank outlasts did not say the rule stays");
				}
				ap.root = node.id.pubkey;
				ap.revocations = was_revs;
				fzn_sign_monocypher_wipe(&other.signer);
			}
			admin.remote_ran = NULL;
		}

		/* AND THE OLDER ROWS MOVED: a rule left in slot 26 becomes this
		 * host's setting, and leaves the slot. */
		{
			size_t moved = 9, held = 9;

			admin.settings = NULL;
			CHECK(ask(&admin, &owner, "add retention prune * age 11d", reply, sizeof(reply),
			          &reply_len)
			              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
			                         == FZN_REPLY_OK
			              && fzn_node_settings_take_rules(&ns, node.id.pubkey, &moved)
			                         == FZN_NODE_SETTINGS_OK
			              && moved == 1u
			              && rule_in_settings(&ns, FZN_SCOPE_HOST, node.id.pubkey,
			                                  "prune * age 11d")
			              && fzn_log_rules_list(admin.store, rules, 8u, &held)
			                         == FZN_LOG_RULES_OK
			              && held == before - 1u,
			      "an older row was not moved into this host's settings, or stayed in the "
			      "slot");
		}
		admin.settings = NULL;
		state.hash = was;
	}

	/* ---- WHAT IT DOES NOT SERVE, IT SAYS SO. */
	CHECK(ask(&admin, &owner, "get peer", reply, sizeof(reply), &reply_len)
	              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
	                         == FZN_REPLY_UNSUPPORTED,
	      "a verb the node does not serve was not answered unsupported");
	CHECK(ask(&admin, &owner, "add peer 00", reply, sizeof(reply), &reply_len)
	              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
	                         == FZN_REPLY_MALFORMED,
	      "a pairing request with no prekey record in it was not answered malformed");
	CHECK(ask(&admin, &member, "status", reply, sizeof(reply), &reply_len)
	              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK,
	      "status was not answered with the node's own status line");

	/* ---- THE ESTATE'S MEMBERS, sec 445: listed with their chains, admitted
	 * by a puller only on proof against its own root. */
	{
		static struct node m1, m2, m3, m4;
		static fzn_node_peer_t all[64];
		static uint8_t got[64][FZN_PUBKEY_LEN];
		fzn_prekey_record_t r;
		size_t loaded = 0, n = 0, refused = 0, i;
		uint8_t mcard[FZN_PROVISION_MAX_LEN];
		size_t mcard_len = 0;
		char m2_hex[(FZN_PUBKEY_LEN * 2u) + 1u];
		struct members_peer mp;

		CHECK(node_up(&m1) && node_up(&m2) && node_up(&m3) && node_up(&m4),
		      "fixture: four more nodes");
		CHECK(fzn_service_capability(7u, 3u, (const uint8_t *)"fuzznet.notes.share", 19u,
		                             &hash_ops, &state.config.share_capability)
		              == FZN_CHAIN_OK,
		      "fixture: the share capability");
		memcpy(state.config.share_root, node.id.pubkey, FZN_PUBKEY_LEN);
		state.config.has_share = 1;
		CHECK(fzn_prekey_open(m1.id.prekey_record, FZN_PREKEY_LEN_TOTAL, &r) == FZN_PREKEY_OK
		              && fzn_node_pair(&node.id, node.id.pubkey, &state.config.remote_capability,
		                               NULL, 0, &node.ops, r, 2000u, 2000u + 86400u, mcard,
		                               sizeof(mcard), &mcard_len)
		                         == FZN_NODE_PAIR_OK
		              && fzn_prekey_open(m2.id.prekey_record, FZN_PREKEY_LEN_TOTAL, &r)
		                         == FZN_PREKEY_OK
		              && fzn_node_pair(&node.id, node.id.pubkey, &state.config.remote_capability,
		                               NULL, 0, &node.ops, r, 2000u, 2000u + 86400u, mcard,
		                               sizeof(mcard), &mcard_len)
		                         == FZN_NODE_PAIR_OK,
		      "fixture: two members paired by the estate's root");
		CHECK(fzn_prekey_open(m3.id.prekey_record, FZN_PREKEY_LEN_TOTAL, &r) == FZN_PREKEY_OK
		              && fzn_node_pair(&node.id, node.id.pubkey, &state.config.share_capability,
		                               NULL, 0, &node.ops, r, 2000u, 2000u + 86400u, mcard,
		                               sizeof(mcard), &mcard_len)
		                         == FZN_NODE_PAIR_OK,
		      "fixture: a contact paired for a share");
		CHECK(fzn_prekey_open(m4.id.prekey_record, FZN_PREKEY_LEN_TOTAL, &r) == FZN_PREKEY_OK
		              && fzn_node_pair(&m1.id, m1.id.pubkey, &state.config.remote_capability,
		                               NULL, 0, &node.ops, r, 2000u, 2000u + 86400u, mcard,
		                               sizeof(mcard), &mcard_len)
		                         == FZN_NODE_PAIR_OK,
		      "fixture: a peer whose chain starts at another root");
		CHECK(fzn_node_peers_load(&node.ops, all, 64u, &loaded) == FZN_PERSIST_OK,
		      "fixture: the peers loaded");

		mp.config = &state.config;
		mp.peers = all;
		mp.count = loaded;
		mp.cap = 500u;
		mp.forge = NULL;
		mp.rename_from = NULL;
		mp.rename_to = NULL;
		mp.asked = 0;
		CHECK(fzn_node_members_pull(members_ask, &mp, node.id.pubkey,
		                            &state.config.remote_capability, 2100u, &node.sign,
		                            admin.revocations, got, 64u, &n, &refused)
		              == FZN_NODE_MEMBERS_OK,
		      "the members are pulled");
		CHECK(mp.asked > 1u, "a page of two members at most, so more than one was asked");
		CHECK(listed(got, n, m1.id.pubkey) && listed(got, n, m2.id.pubkey),
		      "both members the root paired are admitted");
		CHECK(!listed(got, n, m3.id.pubkey), "a contact paired for a share is not");
		/* BY ITS STEPS, sec 636: the same pages, each answer handed in, and
		 * an unanswered request ending the pull. */
		{
			static uint8_t page[16384];
			fzn_node_members_pulling_t pull;
			uint8_t req[FZN_NODE_MEMBERS_QUERY_LEN];
			size_t req_len = 0, page_len, pages = 0;
			int done = 0;
			fzn_node_members_err_t merr;

			mp.asked = 0;
			merr = fzn_node_members_pull_begin(&pull, node.id.pubkey,
			                                   &state.config.remote_capability, 2100u,
			                                   &node.sign, admin.revocations, got, 64u, req,
			                                   sizeof(req), &req_len);
			while (merr == FZN_NODE_MEMBERS_OK && !done && pages++ < 64u) {
				page_len = 0;
				(void)members_ask(&mp, req, req_len, page, sizeof(page), &page_len);
				merr = fzn_node_members_pull_step(&pull, page, page_len, req, sizeof(req),
				                                  &req_len, &done);
			}
			CHECK(merr == FZN_NODE_MEMBERS_OK && done && pages > 1u && pull.count == n
			              && listed(got, pull.count, m1.id.pubkey)
			              && listed(got, pull.count, m2.id.pubkey),
			      "the members pulled by steps are not the members pulled at once");
			CHECK(fzn_node_members_pull_begin(&pull, node.id.pubkey,
			                                  &state.config.remote_capability, 2100u,
			                                  &node.sign, admin.revocations, got, 64u, req,
			                                  sizeof(req), &req_len) == FZN_NODE_MEMBERS_OK
			              && fzn_node_members_pull_step(&pull, NULL, 0, req, sizeof(req),
			                                            &req_len, &done)
			                         == FZN_NODE_MEMBERS_ERR_NO_ANSWER
			              && done
			              && fzn_node_members_pull_step(&pull, page, 8, req, sizeof(req),
			                                            &req_len, &done)
			                         == FZN_NODE_MEMBERS_ERR_MALFORMED,
			      "a members pull with no answer did not end, refusing a step after");
		}
		{
			static uint8_t page[16384];
			uint8_t q[FZN_NODE_MEMBERS_QUERY_LEN] = { 2u, FZN_NODE_MEMBERS_QUERY, 0u, 0u };
			size_t len = fzn_node_members_answer(&state.config, all, loaded, q, sizeof(q), page,
			                                     sizeof(page)), at;
			int seen_contact = 0;

			for (at = 0; len && at + FZN_PUBKEY_LEN <= len; at++)
				seen_contact |= memcmp(page + at, m3.id.pubkey, FZN_PUBKEY_LEN) == 0;
			CHECK(len > FZN_NODE_MEMBERS_HEAD_LEN && !seen_contact,
			      "and its key is not even listed: a share is no membership to reveal");
		}
		CHECK(!listed(got, n, m4.id.pubkey) && refused >= 1u,
		      "a peer whose chain starts at another root is refused and counted");

		hex(m2.id.pubkey, FZN_PUBKEY_LEN, m2_hex);
		snprintf(line, sizeof(line), "revoke peer %s", m2_hex);
		CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK,
		      "fixture: the second member's grant revoked");
		CHECK(fzn_node_members_pull(members_ask, &mp, node.id.pubkey,
		                            &state.config.remote_capability, 2100u, &node.sign,
		                            admin.revocations, got, 64u, &n, &refused)
		                      == FZN_NODE_MEMBERS_OK
		              && listed(got, n, m1.id.pubkey) && !listed(got, n, m2.id.pubkey),
		      "a member whose grant is revoked is no longer admitted");

		/* A CHAIN FROM ANOTHER ROOT OF THE ESTATE: once m1 is added as a
		 * root, m4's chain from it proves through the root set the
		 * revocation store carries (sec 406). */
		{
			uint8_t add[FZN_ROOT_ADD_LEN];

			CHECK(fzn_root_add_issue(node.id.pubkey, m1.id.pubkey, &node.sign, add)
			                      == FZN_ROOT_LOG_OK
			              && fzn_node_roots_learn(&roots, &node.ops, add, sizeof(add))
			                         == FZN_NODE_ROOTS_OK,
			      "fixture: m1 added as a root of the estate");
			CHECK(fzn_node_members_pull(members_ask, &mp, node.id.pubkey,
			                            &state.config.remote_capability, 2100u, &node.sign,
			                            admin.revocations, got, 64u, &n, &refused)
			                      == FZN_NODE_MEMBERS_OK
			              && listed(got, n, m4.id.pubkey),
			      "a member whose chain starts at another root of the estate is admitted");
		}
		mp.rename_from = m1.id.pubkey;
		mp.rename_to = m4.id.pubkey;
		CHECK(fzn_node_members_pull(members_ask, &mp, node.id.pubkey,
		                            &state.config.remote_capability, 2100u, &node.sign, NULL, got,
		                            64u, &n, &refused)
		                      == FZN_NODE_MEMBERS_OK
		              && !listed(got, n, m4.id.pubkey),
		      "a key listed with another member's chain is not admitted: the chain names whom");
		mp.rename_from = NULL;
		mp.forge = m1.id.pubkey;
		CHECK(fzn_node_members_pull(members_ask, &mp, node.id.pubkey,
		                            &state.config.remote_capability, 2100u, &node.sign, NULL, got,
		                            64u, &n, &refused)
		                      == FZN_NODE_MEMBERS_OK
		              && !listed(got, n, m1.id.pubkey),
		      "an entry whose hop was altered does not prove");
		mp.forge = NULL;
		for (i = 0; i < loaded; i++)
			fzn_wipe(&all[i], sizeof(all[i]));
		state.config.has_share = 0;
		fzn_sign_monocypher_wipe(&m1.signer);
		fzn_sign_monocypher_wipe(&m2.signer);
		fzn_sign_monocypher_wipe(&m3.signer);
		fzn_sign_monocypher_wipe(&m4.signer);
	}

	fzn_sign_monocypher_wipe(&node.signer);
	fzn_sign_monocypher_wipe(&device.signer);
	printf("admin_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
