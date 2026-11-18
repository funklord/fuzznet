/*
 * THE TYPED CLIENT OVER A SCRIPTED NODE, sec 1098: fuzzypickles' fzn_rpc_
 * calls, driven through `fzn_rpc_t.answer` so no socket is opened. Each case
 * checks what the call asked and what it made of the answer -- the node's
 * grammar as the client reads it, paging, a refusal's code and words, `ok
 * held`, an answer that does not parse, and nothing answering at all; and the
 * named objects' calls in binary (sec 1152) through `binary_answer`, falling
 * back to text where a node answers that it does not read them.
 */
#include "../rpc.h"
#include "../rpc_encoding.h"
#include "../rpc_err.h"
#include "../rpc_limits.h"
#include "../rpc_media.h"
#include "../rpc_binary.h"
#include "../../wire/cmd.h"
#include "../../wire/status.h"
#include "../../wire/generated/objects_build.h"
#include "../../wire/generated/messages_local_build.h"
#include "../../wire/generated/contacts_local_build.h"
#include "../../wire/generated/groups_local_build.h"
#include "../../wire/generated/streams_local_build.h"
#include "../../wire/generated/stickers_local_build.h"
#include "../../wire/generated/files_local_build.h"
#include "../../wire/generated/members_local_build.h"
#include "../../wire/generated/call_build.h"
#include "../../wire/generated/meter_local_build.h"
#include "../../wire/generated/reach_local_build.h"
#include "../../wire/generated/notes_local_build.h"
#include "../../wire/generated/time_local_build.h"
#include "../../wire/generated/settings_local_build.h"

#include <sys/socket.h>
#include <unistd.h>

#include <stdlib.h>

#include <stdio.h>
#include <string.h>

static int failures = 0;

#define CHECK(cond, what)                                                \
	do {                                                             \
		if (!(cond)) {                                           \
			fprintf(stderr, "  FAIL rpc_test.c:%d: %s\n", __LINE__, what); \
			failures++;                                      \
		}                                                        \
	} while (0)

/* A SCRIPTED NODE: answers in order, and keeps what it was asked. */
#define SCRIPT_MAX 8
struct script {
	const char *replies[SCRIPT_MAX];
	int refuse; /* answer nothing at all: the hook's own failure */
	size_t n, at;
	char asked[SCRIPT_MAX][256];
};

static int scripted(void *ctx, const char *verb, const char *arg, size_t arg_len, uint8_t *reply,
                    size_t reply_cap, size_t *reply_len)
{
	struct script *s = ctx;
	size_t len;

	if (s->at < SCRIPT_MAX)
		snprintf(s->asked[s->at], sizeof(s->asked[0]), "%s %.*s", verb, (int)arg_len,
		         arg ? arg : "");
	if (s->refuse || s->at >= s->n)
		return FZN_RPC_ERR_SEND_FAILED;
	len = strlen(s->replies[s->at]);
	if (len > reply_cap)
		return FZN_RPC_ERR_SEND_FAILED;
	memcpy(reply, s->replies[s->at++], len);
	*reply_len = len;
	return FZN_RPC_OK;
}

static void on(fzn_rpc_t *c, struct script *s)
{
	fzn_rpc_init(c);
	c->answer = scripted;
	c->answer_ctx = s;
}

#define ID_A "aa00000000000000000000000000000000000000000000000000000000000001"
#define ID_B "bb00000000000000000000000000000000000000000000000000000000000002"

static fzn_rpc_t c;

/* `list group FROM`: paged, each row NAME,COUNT,ID,ADMIN[,LINES]. */
static void test_groups_are_read_across_pages(void)
{
	struct script s = { { "ok 2 0 crew,3," ID_A ",1,7", "ok 2 1 band,2," ID_B ",0" }, 0, 2, 0,
		            { { 0 } } };
	fzn_rpc_group_list_resp_t out;

	memset(&out, 0, sizeof(out));
	on(&c, &s);
	CHECK(fzn_rpc_group_list(&c, &out) == FZN_RPC_OK && out.count == 2,
	      "two groups on two pages were not both read");
	CHECK(strcmp(s.asked[0], "list group 0") == 0 && strcmp(s.asked[1], "list group 1") == 0,
	      "the second page was not asked from where the first ended");
	CHECK(out.count == 2 && out.entries[0].name_len == 4 && memcmp(out.entries[0].name, "crew", 4) == 0
	              && out.entries[0].member_count == 3 && out.entries[0].is_admin
	              && out.entries[0].lines == 7 && out.entries[0].chat_id[0] == 0xaa
	              && out.entries[0].chat_id[31] == 0x01,
	      "a group's row was not read field by field");
	CHECK(out.count == 2 && !out.entries[1].is_admin && out.entries[1].lines == 0
	              && out.entries[1].chat_id[0] == 0xbb,
	      "a row without LINES was not read as holding none");
	fzn_rpc_group_list_release(&out);
}

/* A ROW THAT IS NOT ONE, and a page that answers from the wrong place. */
static void test_a_group_row_that_does_not_parse_is_unreadable(void)
{
	struct script s = { { "ok 1 0 crew,3," ID_A ",2" }, 0, 1, 0, { { 0 } } };
	struct script moved = { { "ok 1 5 crew,3," ID_A ",1" }, 0, 1, 0, { { 0 } } };
	fzn_rpc_group_list_resp_t out;

	memset(&out, 0, sizeof(out));
	on(&c, &s);
	CHECK(fzn_rpc_group_list(&c, &out) == FZN_RPC_ERR_MALFORMED && c.unreadable && c.answered,
	      "an ADMIN neither 0 nor 1 was read, or not called unreadable");
	fzn_rpc_group_list_release(&out);
	memset(&out, 0, sizeof(out));
	on(&c, &moved);
	CHECK(fzn_rpc_group_list(&c, &out) == FZN_RPC_ERR_MALFORMED && c.unreadable,
	      "a page from another FROM than asked was taken");
	fzn_rpc_group_list_release(&out);
}

/* `list message unread`: TOTAL FROM SHOWN, then KEY,COUNT,MORE (sec 1084). */
static void test_every_unread_count_is_read(void)
{
	struct script s = { { "ok 2 0 2 " ID_A ",4,0 " ID_B ",1,1" }, 0, 1, 0, { { 0 } } };
	fzn_rpc_unread_entry_t got[4];
	size_t count = 0, total = 0;

	on(&c, &s);
	CHECK(fzn_rpc_unread_all(&c, got, 4, &count, &total) == FZN_RPC_OK && count == 2 && total == 2,
	      "two conversations' unread counts were not read");
	CHECK(strcmp(s.asked[0], "list message unread") == 0, "the unread counts were not asked so");
	CHECK(count == 2 && got[0].key[0] == 0xaa && got[0].count == 4 && !got[0].more
	              && got[1].key[0] == 0xbb && got[1].count == 1 && got[1].more,
	      "an unread row was not read as KEY,COUNT,MORE");
}

/* WHY A CALL ENDED, in a person's words, and which endings are a missed call
 * (secs 1082, 1090): answered or turned away on another of the user's hosts
 * is said so and never missed; a ring the caller gave up on, or nobody took,
 * is. */
static void test_a_missed_call_is_told_from_one_taken_elsewhere(void)
{
	CHECK(strcmp(fzn_rpc_ended_words("answered-elsewhere"), "answered on another of your devices") == 0,
	      "answered-elsewhere was not said in words");
	CHECK(strcmp(fzn_rpc_ended_words("declined-elsewhere"), "turned away on another of your devices") == 0,
	      "declined-elsewhere was not said in words");
	CHECK(strcmp(fzn_rpc_ended_words("eclipsed"), "eclipsed") == 0, "an unknown reason was not said as it came");
	CHECK(fzn_rpc_missed("hung-up") && fzn_rpc_missed("no-answer") && fzn_rpc_missed("gone"),
	      "a ring nobody took was not missed");
	CHECK(!fzn_rpc_missed("answered-elsewhere") && !fzn_rpc_missed("declined-elsewhere")
	              && !fzn_rpc_missed("declined") && !fzn_rpc_missed("ended") && !fzn_rpc_missed(NULL),
	      "a call taken or turned away was called missed");
}

/* A REFUSAL: the node's code mapped, its words kept, and it was answered. */
static void test_a_refusal_keeps_the_node_s_words(void)
{
	struct script s = { { "denied only the user may set that" }, 0, 1, 0, { { 0 } } };
	struct script bare = { { "unsupported" }, 0, 1, 0, { { 0 } } };

	on(&c, &s);
	CHECK(fzn_rpc_object_set(&c, "lamp", "on") == FZN_RPC_ERR_NOT_AUTHORIZED && c.answered
	              && !c.unreadable && strcmp(c.error, "only the user may set that") == 0,
	      "a denial was not mapped, or its words were lost");
	CHECK(strcmp(s.asked[0], "set object lamp on") == 0, "the set was not asked so");
	on(&c, &bare);
	CHECK(fzn_rpc_object_set(&c, "lamp", "on") == FZN_RPC_ERR_UNKNOWN_MSG_TYPE && c.error[0],
	      "a bare refusal was not told apart from a denial, or left no words");
}

/* `ok held`, sec 1037: taken, and to be written a moment later. */
static void test_a_held_set_says_so(void)
{
	struct script held = { { "ok held" }, 0, 1, 0, { { 0 } } };
	struct script plain = { { "ok" }, 0, 1, 0, { { 0 } } };

	on(&c, &held);
	CHECK(fzn_rpc_object_set(&c, "lamp", "on") == FZN_RPC_OK && c.held,
	      "an `ok held` was not said to be held");
	on(&c, &plain);
	CHECK(fzn_rpc_object_set(&c, "lamp", "on") == FZN_RPC_OK && !c.held,
	      "a plain `ok` was said to be held");
}

/* `get object NAME`: VALUE AT BY ALLOWED, `-` for none; `absent`. */
static void test_an_object_is_read_or_absent(void)
{
	struct script s = { { "ok on 1700000000000 " ID_A " on|off", "ok absent" }, 0, 2, 0,
		            { { 0 } } };
	fzn_rpc_object_t o;
	int found = 0;

	on(&c, &s);
	CHECK(fzn_rpc_object_get(&c, "lamp", &o, &found) == FZN_RPC_OK && found
	              && strcmp(o.value, "on") == 0 && o.at_ms == 1700000000000ull
	              && strcmp(o.by, ID_A) == 0 && strcmp(o.allowed, "on|off") == 0,
	      "an object's value, time, setter and allowed words were not read");
	CHECK(fzn_rpc_object_get(&c, "door", &o, &found) == FZN_RPC_OK && !found,
	      "an absent object was found");
}

/* NOTHING ANSWERED: not `answered`, which is what tells a person to start
 * the node rather than read a refusal. */
static void test_nothing_answering_is_not_a_refusal(void)
{
	struct script s = { { 0 }, 1, 0, 0, { { 0 } } };

	on(&c, &s);
	CHECK(fzn_rpc_object_set(&c, "lamp", "on") == FZN_RPC_ERR_SEND_FAILED && !c.answered,
	      "a node that answered nothing was said to have answered");
	fzn_rpc_init(&c);
	CHECK(fzn_rpc_object_set(&c, "lamp", "on") == FZN_RPC_ERR_NO_PEER_TRANSPORT && !c.answered,
	      "a client with no node set asked one anyway");
}

/* WHAT A PAIRING REQUEST MAY SHOW, rpc_limits.h: an unauthenticated name is
 * printed in the list a person reads to decide whom to trust, so a control
 * character could forge or hide the key line beside it. UTF-8 stays. */
static void test_a_name_or_address_with_a_control_is_refused(void)
{
	CHECK(fzn_rpc_display_name_printable("alice", 5) && fzn_rpc_display_name_printable("", 0)
	              && fzn_rpc_display_name_printable("\xc3\xa5sa", 4),
	      "a plain, an empty or a UTF-8 display name was refused");
	CHECK(!fzn_rpc_display_name_printable("ali\nce", 6) && !fzn_rpc_display_name_printable("a\x1b[2J", 5)
	              && !fzn_rpc_display_name_printable("a\x7f", 2),
	      "a display name with a newline, an escape or DEL was let through");
	CHECK(fzn_rpc_address_printable("127.0.0.1:48080", 15) && !fzn_rpc_address_printable("", 0)
	              && !fzn_rpc_address_printable("host\r", 5),
	      "an address was judged wrongly: empty, or carrying a control");
}

/* A GROUP'S UNREAD, rpc_describe.c: lines past the read position, not at it. */
static void test_unread_counts_past_the_read_line(void)
{
	fzn_rpc_group_history_entry_t h[3];

	memset(h, 0, sizeof(h));
	h[0].seq = 4;
	h[1].seq = 5;
	h[2].seq = 6;
	CHECK(fzn_rpc_group_unread_since(h, 3, 4) == 2 && fzn_rpc_group_unread_since(h, 3, 6) == 0,
	      "a group's unread counted the line read, or one before it");
}

/* UNTRUSTED TEXT TO A TERMINAL: C0, DEL and UTF-8's C1 in caret form. */
static void test_untrusted_text_is_shown_in_caret_form(void)
{
	char out[32];

	CHECK(strcmp(fzn_rpc_tty_escape("a\x1b[0m\x7f", 6, out, sizeof(out)), "a^[[0m^?") == 0,
	      "an escape or DEL reached the terminal raw");
	CHECK(strcmp(fzn_rpc_tty_escape("x\xc2\x9b", 3, out, sizeof(out)), "xM-^[") == 0,
	      "a C1 control encoded as UTF-8 reached the terminal raw");
	CHECK(strlen(fzn_rpc_tty_escape("abcdef", 6, out, 4)) == 3, "the escape wrote past its room");
}

/* A SPEC PAST THE FIRST GUESS, rpc_sticker_read.c: 70 stickers, where room
 * for 64 is made first and grown to what the parse says it needs. */
static void test_a_long_sticker_spec_is_read_whole(void)
{
	static char spec[16384];
	fzn_sticker_manifest_t m;
	char err[128] = "";
	size_t at = 0, i;

	at += (size_t)snprintf(spec + at, sizeof(spec) - at, "name many\n");
	for (i = 1; i <= 70; i++)
		at += (size_t)snprintf(spec + at, sizeof(spec) - at,
		                       "sticker %zu static\ninline png 128 128 art/s%zu.png\n", i, i);
	CHECK(fzn_rpc_sticker_spec_read(spec, at, &m, err, sizeof(err)) == FZN_RPC_OK && m.count == 70,
	      "a spec of 70 stickers was not read whole");
	fzn_rpc_sticker_manifest_release(&m);
}

/* THE SCHEMA IN state/schema.h's WORDS, sec 1098: `list schema FROM` rows
 * KEY,TYPE,SCOPES,MIN,MAX,DEFAULT,UNIT,FLAGS,SUMMARY -- every type and flag
 * the node declares, kept, and a row written by its own verb left out. */
static void test_the_schema_is_read_in_the_node_s_words(void)
{
	static fzn_rpc_config_schema_resp_t out;
	struct script s = { { "ok 4 0 net/address,address,estate+host,0,64,-,-,advertised,where "
		              "peers/retention,duration,estate,60,99999,14d,s,safe-lower+restart,how "
		              "ui/odd,shiny,host,0,0,x,-,-,a-new-type "
		              "net/verbal,flag,host,0,1,off,-,verb,its-own-verb" },
		            0, 1, 0, { { 0 } } };

	on(&c, &s);
	CHECK(fzn_rpc_config_schema(&c, "", 0, &out) == FZN_RPC_OK && out.count == 3,
	      "the schema was not read, or a verb's own row was kept");
	CHECK(strcmp(s.asked[0], "list schema 0") == 0, "the schema was not asked so");
	CHECK(out.count == 3 && out.entries[0].type == FZN_SCHEMA_ADDRESS
	              && out.entries[0].scopes == (FZN_SCHEMA_ESTATE | FZN_SCHEMA_HOST)
	              && out.entries[0].flags == FZN_SCHEMA_ADVERTISED
	              && strcmp(out.entries[0].key, "net.address") == 0,
	      "an address setting lost its type, a scope or its advertised flag");
	CHECK(out.count == 3 && out.entries[1].type == FZN_SCHEMA_DURATION
	              && out.entries[1].scopes == FZN_SCHEMA_ESTATE
	              && out.entries[1].flags == (FZN_SCHEMA_SAFE_LOWER | FZN_SCHEMA_RESTART)
	              && out.entries[1].min == 60 && out.entries[1].max == 99999
	              && strcmp(out.entries[1].default_value, "14d") == 0,
	      "a duration lost its type, bounds, default or safe direction");
	CHECK(out.count == 3 && out.entries[2].type == FZN_SCHEMA_TEXT,
	      "a type this client does not know was not read as text");
}

/* A VALUE AND WHERE IT STANDS: `get schema KEY`, then `get setting here
 * KEY` -- `ok SCOPE RANK VALUE` or `ok absent`. A flag reads `on`, the
 * node's word. */
static void test_a_setting_says_where_it_stands(void)
{
	fzn_rpc_config_get_resp_t got;
	struct script host = { { "ok net/gps,flag,host,0,1,off,-,-,gps", "ok host 2 on" }, 0, 2, 0,
		               { { 0 } } };
	struct script above = { { "ok net/gps,flag,host,0,1,off,-,-,gps", "ok estate 2 off" }, 0, 2,
		                0, { { 0 } } };
	struct script none = { { "ok net/gps,flag,host,0,1,off,-,-,gps", "ok absent" }, 0, 2, 0,
		               { { 0 } } };

	on(&c, &host);
	CHECK(fzn_rpc_config_get(&c, "net.gps", 7, &got) == FZN_RPC_OK && got.set_at == FZN_SCHEMA_HOST
	              && strcmp(got.value, "on") == 0,
	      "a host's own value was not read as the host's, or not as `on`");
	CHECK(strcmp(host.asked[1], "get setting here net/gps") == 0, "the value was not asked here");
	on(&c, &above);
	CHECK(fzn_rpc_config_get(&c, "net.gps", 7, &got) == FZN_RPC_OK
	              && got.set_at == FZN_SCHEMA_ESTATE && strcmp(got.value, "off") == 0,
	      "a value set above the host was read as its own");
	on(&c, &none);
	CHECK(fzn_rpc_config_get(&c, "net.gps", 7, &got) == FZN_RPC_OK && got.set_at == 0
	              && strcmp(got.value, "off") == 0,
	      "an unset value did not read as the default");
}

/* BACK TO THE DEFAULT: `remove setting SCOPE KEY` where `set` writes it. */
static void test_a_setting_is_cleared_where_it_was_set(void)
{
	struct script host = { { "ok net/gps,flag,host,0,1,off,-,-,gps", "ok" }, 0, 2, 0, { { 0 } } };
	struct script estate = { { "ok call/ring,duration,estate,5,600,45s,s,-,ring", "ok" }, 0, 2, 0,
		                 { { 0 } } };

	on(&c, &host);
	CHECK(fzn_rpc_config_clear(&c, "net.gps", 7) == FZN_RPC_OK
	              && strcmp(host.asked[1], "remove setting host net/gps") == 0,
	      "a host's setting was not cleared on the host");
	on(&c, &estate);
	CHECK(fzn_rpc_config_clear(&c, "call.ring", 9) == FZN_RPC_OK
	              && strcmp(estate.asked[1], "remove setting estate call/ring") == 0,
	      "an estate's setting was not cleared for the estate");
}

/* A CALL'S MEDIA CHANNEL, sec 1113, over a socketpair standing in for the
 * node: the asking and the node's answer, a whole frame sent as two bytes of
 * length and a MEDIA, one received in two writes and handed out whole, the
 * next receive dropping it, nothing yet, and the node closing the channel. */
static void peer_write(int fd, const uint8_t *b, size_t n)
{
	if (write(fd, b, n) != (ssize_t)n)
		failures++;
}

static void test_a_media_channel_carries_whole_frames(void)
{
	static const uint8_t call[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
	static const uint8_t ok_status[] = { 0, 3, 19, 0, 0 };
	static const uint8_t denied[] = { 0, 9, 19, 1, 6, 'n', 'o', ' ', 'w', 'a', 'y' };
	uint8_t got[64], frame[300], wire[2 + 10 + 11 + 300];
	fzn_rpc_media_t m;
	fzn_rpc_media_frame_t f;
	int sv[2];
	size_t i;

	for (i = 0; i < sizeof(frame); i++)
		frame[i] = (uint8_t)(i * 11u);
	/* REFUSED, in the node's words. */
	CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "fixture: a socketpair");
	peer_write(sv[1], denied, sizeof(denied));
	fzn_rpc_init(&c);
	CHECK(fzn_rpc_media_attach(&c, &m, sv[0], call) == FZN_RPC_ERR_NOT_AUTHORIZED
	              && strcmp(c.error, "no way") == 0,
	      "a refused channel was not said in the node's words");
	close(sv[0]);
	close(sv[1]);

	CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "fixture: a socketpair");
	peer_write(sv[1], ok_status, sizeof(ok_status));
	CHECK(fzn_rpc_media_attach(&c, &m, sv[0], call) == FZN_RPC_OK, "an accepted channel did not open");
	/* THE ASKING, as the node reads it: length 10, CALL, 128, the call. */
	CHECK(read(sv[1], got, 12) == 12 && got[0] == 0 && got[1] == 10 && got[2] == 18 && got[3] == 128
	              && memcmp(got + 4, call, 8) == 0,
	      "the channel's asking was not two bytes of length and a MEDIA_OPEN");

	/* A WHOLE FRAME SENT: length, CALL, 129, the call, stream, from, seq, at, media. */
	CHECK(fzn_rpc_media_send(&m, 2, 77, 1234, frame, sizeof(frame)) == FZN_RPC_OK,
	      "a whole frame was not sent");
	CHECK(read(sv[1], wire, sizeof(wire)) == (ssize_t)sizeof(wire)
	              && ((size_t)wire[0] << 8 | wire[1]) == 21u + sizeof(frame) && wire[3] == 129
	              && wire[12] == 2 && wire[18] == 77 && memcmp(wire + 23, frame, sizeof(frame)) == 0,
	      "a whole frame did not go as one MEDIA");
	CHECK(fzn_rpc_media_send(&m, 2, 78, 0, frame, FZN_RPC_MEDIA_MAX + 1u) == FZN_RPC_ERR_MALFORMED,
	      "a frame past the most was sent");

	/* ONE RECEIVED IN TWO WRITES: nothing until it is whole, then it whole. */
	wire[13] = 0;
	wire[14] = 3; /* from 3 */
	peer_write(sv[1], wire, 40);
	CHECK(fzn_rpc_media_recv(&m, &f) == 0, "half a frame was handed out");
	peer_write(sv[1], wire + 40, sizeof(wire) - 40);
	CHECK(fzn_rpc_media_recv(&m, &f) == 1 && f.stream == 2 && f.from == 3 && f.seq == 77
	              && f.at_ms == 1234 && f.media_len == sizeof(frame)
	              && memcmp(f.media, frame, sizeof(frame)) == 0,
	      "a frame in two writes was not handed out whole");
	CHECK(fzn_rpc_media_recv(&m, &f) == 0, "a frame was handed out twice");

	/* THE NODE LETS IT GO. */
	close(sv[1]);
	CHECK(fzn_rpc_media_recv(&m, &f) == FZN_RPC_ERR_SEND_FAILED, "a closed channel read as quiet");
	fzn_rpc_media_close(&m);
}


static void test_the_suite_can_tell_pass_from_fail(void)
{
	int before = failures;

	CHECK(0, "deliberate");
	CHECK(failures == before + 1, "a failing check was not counted");
	failures = before;
}

/* A DEVICE JOINING IN TWO STEPS, sec 1122: `begin` reads who the host is and
 * hands the code over; `joined` is 0 while the node serves as before, 0 again
 * while it is starting again and does not answer, and 1 once it serves under
 * another identity. A code of the wrong shape is refused unasked. */
static void test_a_join_is_asked_and_then_seen(void)
{
	struct script s = { { "ok " ID_A " " ID_A, "ok", "ok " ID_A " " ID_A, "ok " ID_A " " ID_B },
	                    0, 4, 0, { { 0 } } };
	uint8_t before[32];
	int joined = -1;

	on(&c, &s);
	CHECK(fzn_rpc_device_join_begin(&c, "FZI1:ABCD", 9, before) == FZN_RPC_OK
	              && !strcmp(s.asked[0], "get identity") && !strcmp(s.asked[1], "add join FZI1:ABCD")
	              && before[0] == 0xaa,
	      "begin did not read the identity and hand the code over");
	CHECK(fzn_rpc_device_joined(&c, before, &joined) == FZN_RPC_OK && joined == 0,
	      "a host serving as before was read as joined");
	CHECK(fzn_rpc_device_joined(&c, before, &joined) == FZN_RPC_OK && joined == 1,
	      "a host serving under another identity was not read as joined");
	s.refuse = 1;
	CHECK(fzn_rpc_device_joined(&c, before, &joined) == FZN_RPC_OK && joined == 0,
	      "a node starting again was read as joined or as a failure");
	s.refuse = 0;
	s.at = s.n;
	CHECK(fzn_rpc_device_join_begin(&c, "ABCD", 4, before) == FZN_RPC_ERR_MALFORMED,
	      "a code of the wrong shape was asked");
}

/* THE NODE'S FIGURES CARRIED, sec 1125: the legs it counts unmeasured,
 * and how many reporters agree on this host's address. */
static void test_dropped_figures_are_carried(void)
{
	static const char *const legs_reply = "ok 1 1 0 192.0.2.7:4000,-,-,0,-,4,0,4,0";
	static const char *const address_reply =
	        "ok 2 2 0123456789abcdef,192.0.2.9,4000,7 fedcba9876543210,192.0.2.9,4000,8";
	struct script s = { { legs_reply, address_reply }, 0, 2, 0, { { 0 } } };
	static fzn_rpc_leg_list_resp_t legs;
	fzn_rpc_addr_observe_resp_t seen;

	on(&c, &s);
	CHECK(fzn_rpc_leg_list(&c, &legs) == FZN_RPC_OK && legs.count == 1 && legs.unmeasured == 1
	              && legs.entries[0].observations == 0,
	      "the node's unmeasured count, or a leg's want of observations, was lost");
	CHECK(fzn_rpc_addr_observe(&c, 0, &seen) == FZN_RPC_OK && seen.count == 2 && seen.agree == 2,
	      "how many reporters agree was lost");
}

/* EVERY CONVERSATION'S NEWEST LINE, sec 1136: a file sent, a group member's
 * text with an escape, and a contact with nothing yet, read whole. */
static void test_every_newest_line_is_read(void)
{
	static const char *const reply =
	        "ok 4 0 4 " ID_B ",40000,in,-,call,2:1:0 " ID_A ",30000,out,-,file,photo.jpg " ID_B
	        ",20000,in,carol,text,see%20you%20at%208 " ID_A ",0,-,-,none,";
	struct script s = { { reply }, 0, 1, 0, { { 0 } } };
	static fzn_rpc_newest_entry_t all[5], *out = all + 1;
	size_t count = 0, total = 0;

	on(&c, &s);
	CHECK(fzn_rpc_newest_all(&c, all, 5, &count, &total) == FZN_RPC_OK && count == 4 && total == 4
	              && !strcmp(s.asked[0], "list message newest"),
	      "the newest lines were not read in one listing");
	/* A MISSED VOICE CALL newer than any line, sec 1270. */
	CHECK(all[0].kind == FZN_RPC_NEWEST_CALL && !all[0].outgoing && all[0].stime_ms == 40000
	              && all[0].call_outcome == FZN_RPC_CALL_MISSED && all[0].call_kinds == 1
	              && all[0].call_seconds == 0 && !all[0].text_len,
	      "a call as a conversation's newest was not read with its outcome and kinds");
	CHECK(out[0].kind == FZN_RPC_NEWEST_FILE && out[0].outgoing && out[0].stime_ms == 30000
	              && !strcmp(out[0].text, "photo.jpg") && !out[0].sender_len,
	      "a file sent was not read as one, by its name");
	CHECK(out[1].kind == FZN_RPC_NEWEST_TEXT && !out[1].outgoing && !strcmp(out[1].sender, "carol")
	              && !strcmp(out[1].text, "see you at 8"),
	      "a member's line was not read with its writer and its text unescaped");
	CHECK(out[2].kind == FZN_RPC_NEWEST_NONE && out[2].stime_ms == 0 && !out[2].text_len,
	      "a conversation with no line yet was not read as none");
}

/* A SCRIPTED BINARY NODE: one answer of framed messages a request, in order,
 * and the bytes it was asked. */
struct bscript {
	uint8_t replies[4][1024];
	size_t lens[4], n, at;
	uint8_t asked[4][128];
	size_t asked_len[4];
};

static int bscripted(void *ctx, const uint8_t *msg, size_t len, uint8_t *reply, size_t reply_cap,
                     size_t *reply_len)
{
	struct bscript *s = ctx;

	if (s->at >= s->n || s->lens[s->at] > reply_cap)
		return FZN_RPC_ERR_SEND_FAILED;
	if (len <= sizeof(s->asked[0])) {
		memcpy(s->asked[s->at], msg, len);
		s->asked_len[s->at] = len;
	}
	memcpy(reply, s->replies[s->at], s->lens[s->at]);
	*reply_len = s->lens[s->at++];
	return FZN_RPC_OK;
}

/* One message framed onto answer `i`, as the node frames it. */
static void framed(struct bscript *s, size_t i, const uint8_t *msg, size_t len)
{
	s->replies[i][s->lens[i]] = (uint8_t)(len >> 8);
	s->replies[i][s->lens[i] + 1u] = (uint8_t)len;
	memcpy(s->replies[i] + s->lens[i] + 2u, msg, len);
	s->lens[i] += 2u + len;
	if (s->n < i + 1u)
		s->n = i + 1u;
}

static void status_onto(struct bscript *s, size_t i, fzn_status_t code, const char *why)
{
	uint8_t m[FZN_STATUS_LEN_MAX];

	framed(s, i, m, fzn_status_write(m, sizeof(m), code, why));
}

static void row_onto(struct bscript *s, size_t i, const char *name, const char *value)
{
	uint8_t row[256], m[300], by[32];
	uint32_t row_len = 0, n = 0;

	memset(by, 0x11, sizeof(by));
	if (fzn_objects_row_build(row, sizeof(row), (const uint8_t *)name, (uint32_t)strlen(name),
	                          (const uint8_t *)value, (uint32_t)strlen(value), 1700000000000ull, by,
	                          (const uint8_t *)"on|off", 6u, &row_len) != SITU_OK
	    || fzn_objects_message_build_row(m, sizeof(m), (uint8_t)FZN_CMD_OBJECTS, row, row_len, &n) != SITU_OK)
		return;
	framed(s, i, m, n);
}

static void bon(fzn_rpc_t *client, struct bscript *s)
{
	fzn_rpc_init(client);
	client->binary_answer = bscripted;
	client->binary_ctx = s;
}

/* NAMED OBJECTS IN BINARY, sec 1152: asked in the schema's bytes, rows and a
 * STATUS read back, a list known whole by its closing STATUS, and a node
 * answering a binary request malformed asked again in text. */
static void test_objects_in_binary(void)
{
	static struct bscript get, list, cut, set, denied, add;
	static const uint8_t get_lamp[] = { 0x15, 0x82, 4, 'l', 'a', 'm', 'p' };
	static const uint8_t set_lamp_on[] = { 0x15, 0x81, 4, 'l', 'a', 'm', 'p', 2, 'o', 'n' };
	static const uint8_t add_lamp[] = { 0x15, 0x80, 4, 'l', 'a', 'm', 'p', 6, 'o', 'n', '|', 'o', 'f', 'f' };
	static const uint8_t add_dial[] = { 0x15, 0x80, 4, 'd', 'i', 'a', 'l', 1, '*' };
	static fzn_rpc_object_list_resp_t l;
	fzn_rpc_object_t o;
	int found = 0;

	row_onto(&get, 0, "lamp", "on");
	status_onto(&get, 1, FZN_STATUS_OK, NULL);
	bon(&c, &get);
	CHECK(fzn_rpc_object_get(&c, "lamp", &o, &found) == FZN_RPC_OK && found && strcmp(o.value, "on") == 0
	              && o.at_ms == 1700000000000ull && strncmp(o.by, "1111", 4) == 0 && strlen(o.by) == 64
	              && strcmp(o.allowed, "on|off") == 0,
	      "an object's row was not read in binary");
	CHECK(get.asked_len[0] == sizeof(get_lamp) && memcmp(get.asked[0], get_lamp, sizeof(get_lamp)) == 0,
	      "a get was not asked in the schema's bytes");
	CHECK(fzn_rpc_object_get(&c, "door", &o, &found) == FZN_RPC_OK && !found,
	      "no row and an ok was not read as no such object");

	row_onto(&list, 0, "lamp", "on");
	row_onto(&list, 0, "fan", "off");
	status_onto(&list, 0, FZN_STATUS_OK, NULL);
	bon(&c, &list);
	CHECK(fzn_rpc_object_list(&c, &l) == FZN_RPC_OK && l.count == 2 && strcmp(l.entries[1].name, "fan") == 0,
	      "a list of two rows and its ok was not read");
	row_onto(&cut, 0, "lamp", "on");
	bon(&c, &cut);
	CHECK(fzn_rpc_object_list(&c, &l) != FZN_RPC_OK, "a list with no closing STATUS was read as whole");

	status_onto(&set, 0, FZN_STATUS_OK, "held");
	bon(&c, &set);
	CHECK(fzn_rpc_object_set(&c, "lamp", "on") == FZN_RPC_OK && c.held, "a held set in binary was not said held");
	CHECK(set.asked_len[0] == sizeof(set_lamp_on)
	              && memcmp(set.asked[0], set_lamp_on, sizeof(set_lamp_on)) == 0,
	      "a set was not asked in the schema's bytes");

	status_onto(&denied, 0, FZN_STATUS_DENIED, "only read is granted on objects");
	bon(&c, &denied);
	CHECK(fzn_rpc_object_remove(&c, "lamp") == FZN_RPC_ERR_NOT_AUTHORIZED
	              && strcmp(c.error, "only read is granted on objects") == 0,
	      "a binary denial was not mapped, or its words were lost");

	status_onto(&add, 0, FZN_STATUS_OK, NULL);
	status_onto(&add, 1, FZN_STATUS_OK, NULL);
	bon(&c, &add);
	CHECK(fzn_rpc_object_add(&c, "lamp", "on off") == FZN_RPC_OK && fzn_rpc_object_add(&c, "dial", "") == FZN_RPC_OK
	              && memcmp(add.asked[0], add_lamp, sizeof(add_lamp)) == 0
	              && memcmp(add.asked[1], add_dial, sizeof(add_dial)) == 0,
	      "an add's words were not joined as the node keeps them, or none as *");
	l.count = 0;
}

/* A NODE FROM BEFORE THE CATEGORY answers any binary request but a channel's
 * with a STATUS malformed: the call is asked again in text. */
static void test_a_node_that_reads_no_binary_is_asked_in_text(void)
{
	static struct bscript old;
	struct script s = { { "ok on 1700000000000 " ID_A " on|off" }, 0, 1, 0, { { 0 } } };
	fzn_rpc_object_t o;
	int found = 0;

	status_onto(&old, 0, FZN_STATUS_MALFORMED, "not a channel's asking");
	on(&c, &s);
	c.binary_answer = bscripted;
	c.binary_ctx = &old;
	CHECK(fzn_rpc_object_get(&c, "lamp", &o, &found) == FZN_RPC_OK && found && strcmp(o.value, "on") == 0
	              && strcmp(s.asked[0], "get object lamp") == 0,
	      "a node reading no binary was not asked in text");
}

/* AN EMPTY LIBRARY LISTED, a node just made (snurra's inbox 20261114T0146Z):
 * no row, and no NULL array handed to qsort or bsearch, which a sanitized
 * build of this test (`make sancheck`) reports. */
static void test_an_empty_library_lists_nothing(void)
{
	struct script s = { { "ok 0 0", "ok " ID_A " " ID_B, "ok 0 0", "ok 0 0" }, 0, 4, 0, { { 0 } } };
	static fzn_rpc_library_list_all_t l;

	on(&c, &s);
	CHECK(fzn_rpc_library_list(&c, &l) == FZN_RPC_OK && l.count == 0, "an empty library did not list as empty");
	fzn_rpc_library_list_release(&l);
}

/* A FILE NONE OF WHICH IS HERE, read to play (sec 1153): its own code and
 * words saying to fetch it, where "not in the library" was said of a file
 * the library lists. */
static void test_a_file_not_fetched_says_so(void)
{
	static const char listed[] = "ok 1 0 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"
	                             ",name,song,aa00000000000000";
	struct script s = { { "error not all here", listed, "ok " ID_A " " ID_B, "ok 1 aa00000000000000", "error not all here" },
	                    0, 5, 0, { { 0 } } };
	struct script nobody = { { "error not all here", "ok 0 0" }, 0, 2, 0, { { 0 } } };
	static fzn_rpc_library_play_resp_t out;
	uint8_t root[32];

	memset(root, 0x5a, sizeof(root));
	on(&c, &s);
	CHECK(fzn_rpc_library_play(&c, root, 0, 1, &out) == FZN_RPC_ERR_NOT_FETCHED && c.answered
	              && strstr(c.error, "fetch it") != NULL,
	      "a file the library lists, none of which is here, was not told apart, with what to do");
	/* A ROOT NOBODY CATALOGUED, sec 1195: not in the library, not to fetch. */
	on(&c, &nobody);
	CHECK(fzn_rpc_library_play(&c, root, 0, 1, &out) == FZN_RPC_ERR_STORAGE_IO
	              && strcmp(c.error, "not in the library") == 0 && strncmp(nobody.asked[1], "list catalog", 12) == 0,
	      "a root no library lists was told to be fetched");
}

/* A CONVERSATION'S NEWEST ROW framed onto answer `i`, sec 1155. */
static void newest_onto(struct bscript *s, size_t i, uint8_t first, uint8_t kind, const char *sender,
                        const char *text)
{
	uint8_t key[32], row[300], m[320];
	uint32_t row_len = 0, n = 0;

	memset(key, first, sizeof(key));
	if (fzn_messages_local_newest_row_build(row, sizeof(row), key, 1700000000000ull, 0u,
	                                        (fzn_messages_local_kind_t)kind, (const uint8_t *)sender,
	                                        (uint32_t)strlen(sender), (const uint8_t *)text,
	                                        (uint32_t)strlen(text), kind == 5u ? 1u : 0u, kind == 5u ? 2u : 0u,
	                                        kind == 5u ? 42u : 0u, &row_len) != SITU_OK
	    || fzn_messages_local_message_build_newest_row(m, sizeof(m), (uint8_t)FZN_CMD_MESSAGES, row, row_len, &n)
	               != SITU_OK)
		return;
	framed(s, i, m, n);
}

static void unread_onto(struct bscript *s, size_t i, uint8_t first, uint32_t count)
{
	uint8_t key[32], row[64], m[80];
	uint32_t row_len = 0, n = 0;

	memset(key, first, sizeof(key));
	if (fzn_messages_local_unread_row_build(row, sizeof(row), key, count, 0u, &row_len) != SITU_OK
	    || fzn_messages_local_message_build_unread_row(m, sizeof(m), (uint8_t)FZN_CMD_MESSAGES, row, row_len, &n)
	               != SITU_OK)
		return;
	framed(s, i, m, n);
}

/* EVERY CONVERSATION'S NEWEST LINE AND COUNT IN BINARY, sec 1155: asked as
 * FZN_CMD_MESSAGES newest or unread, a row each read in, the cap honoured
 * while the total counts every row, a listing cut before its STATUS
 * refused, and a denial's words kept. */
static void test_conversations_in_binary(void)
{
	static struct bscript newest, unread, cut, denied;
	static const uint8_t ask_newest[] = { 0x0a, 0x80 }, ask_unread[] = { 0x0a, 0x81 };
	static fzn_rpc_newest_entry_t n[2];
	static fzn_rpc_unread_entry_t u[4];
	size_t count = 0, total = 0;

	newest_onto(&newest, 0, 0xaa, 1, "carol", "see you at 8");
	newest_onto(&newest, 0, 0xbb, 2, "", "photo.jpg");
	newest_onto(&newest, 0, 0xcc, 0, "", "");
	status_onto(&newest, 0, FZN_STATUS_OK, NULL);
	bon(&c, &newest);
	/* AN ANSWERED VIDEO CALL OF 42 SECONDS, sec 1270, read with its words. */
	{
		static struct bscript called;
		static fzn_rpc_newest_entry_t one[1];

		newest_onto(&called, 0, 0xdd, 5, "", "");
		status_onto(&called, 0, FZN_STATUS_OK, NULL);
		bon(&c, &called);
		CHECK(fzn_rpc_newest_all(&c, one, 1, &count, &total) == FZN_RPC_OK && count == 1
		              && one[0].kind == FZN_RPC_NEWEST_CALL && one[0].call_outcome == FZN_RPC_CALL_ANSWERED
		              && one[0].call_kinds == 2 && one[0].call_seconds == 42,
		      "a call as the newest row was not read in binary with its outcome, kinds and seconds");
		bon(&c, &newest);
	}
	CHECK(fzn_rpc_newest_all(&c, n, 2, &count, &total) == FZN_RPC_OK && count == 2 && total == 3
	              && n[0].key[0] == 0xaa && n[0].kind == FZN_RPC_NEWEST_TEXT && n[0].stime_ms == 1700000000000ull
	              && strcmp(n[0].sender, "carol") == 0 && strcmp(n[0].text, "see you at 8") == 0
	              && n[1].kind == FZN_RPC_NEWEST_FILE && strcmp(n[1].text, "photo.jpg") == 0,
	      "the newest lines were not read in binary, or the cap not honoured with every row counted");
	CHECK(newest.asked_len[0] == 2 && memcmp(newest.asked[0], ask_newest, 2) == 0,
	      "the newest lines were not asked in the schema's bytes");

	unread_onto(&unread, 0, 0xaa, 2);
	unread_onto(&unread, 0, 0xbb, 0);
	status_onto(&unread, 0, FZN_STATUS_OK, NULL);
	bon(&c, &unread);
	CHECK(fzn_rpc_unread_all(&c, u, 4, &count, &total) == FZN_RPC_OK && count == 2 && total == 2
	              && u[0].key[0] == 0xaa && u[0].count == 2 && u[1].count == 0
	              && memcmp(unread.asked[0], ask_unread, 2) == 0,
	      "the unread counts were not read in binary");

	/* NO ROOM, THE TOTAL STILL (fuzzypickles, inbox 20261117T0037Z): room 0
	 * asked first, then room for the total, as over the verb. */
	unread.at = 0;
	bon(&c, &unread);
	CHECK(fzn_rpc_unread_all(&c, NULL, 0, &count, &total) == FZN_RPC_OK && count == 0 && total == 2,
	      "the unread counts asked with no room were not the total");
	newest.at = 0;
	bon(&c, &newest);
	CHECK(fzn_rpc_newest_all(&c, NULL, 0, &count, &total) == FZN_RPC_OK && count == 0 && total == 3,
	      "the newest lines asked with no room were not the total");
	unread.at = 0;
	bon(&c, &unread);
	CHECK(fzn_rpc_newest_all(&c, NULL, 0, &count, &total) != FZN_RPC_OK,
	      "an unread row answering the newest lines, with no room, was taken");

	unread_onto(&cut, 0, 0xaa, 2);
	bon(&c, &cut);
	CHECK(fzn_rpc_unread_all(&c, u, 4, &count, &total) != FZN_RPC_OK, "a listing cut before its STATUS was read as whole");

	status_onto(&denied, 0, FZN_STATUS_DENIED, "conversations need this node's own user");
	bon(&c, &denied);
	CHECK(fzn_rpc_newest_all(&c, n, 2, &count, &total) == FZN_RPC_ERR_NOT_AUTHORIZED
	              && strcmp(c.error, "conversations need this node's own user") == 0,
	      "a binary denial of the listing was not mapped, or its words were lost");
}

/* ONE LINE ROW framed onto answer `i`, sec 1159. */
static void line_onto(struct bscript *s, size_t i, uint8_t first, uint8_t group, uint8_t outgoing, uint8_t state,
                      const char *name, const char *sender, const char *text)
{
	uint8_t key[32], id[16], row[700], m[720];
	uint32_t row_len = 0, n = 0;

	memset(key, first, sizeof(key));
	memset(id, first ^ 0xff, sizeof(id));
	if (fzn_messages_local_line_row_build(row, sizeof(row), key, id, group, outgoing, state, 1u, 1700000000000ull,
	                                      1700000005000ull, (const uint8_t *)name, (uint32_t)strlen(name),
	                                      (const uint8_t *)sender, (uint32_t)strlen(sender), (const uint8_t *)text,
	                                      (uint32_t)strlen(text), &row_len) != SITU_OK
	    || fzn_messages_local_message_build_line_row(m, sizeof(m), (uint8_t)FZN_CMD_MESSAGES, row, row_len, &n)
	               != SITU_OK)
		return;
	framed(s, i, m, n);
}

/* A CONVERSATION'S LINES IN BINARY, sec 1159: asked by key as
 * FZN_CMD_MESSAGES lines, a row each read into an inbox entry with its
 * name, id, mark and times in seconds; a group's line left out as the text
 * listing leaves it; a contact asked for by NAME asked by the verb, which
 * names it, since the request carries a key. */
static void test_lines_in_binary(void)
{
	static struct bscript lines;
	static fzn_rpc_inbox_entry_t out[4];
	static const char key_hex[] = "abababababababababababababababababababababababababababababababab";
	size_t count = 0;

	line_onto(&lines, 0, 0xab, 0, 1, 2, "alice", "", "see you at 8");
	line_onto(&lines, 0, 0xcd, 1, 0, 0, "team", "carol", "in the group");
	line_onto(&lines, 0, 0xab, 0, 0, 0, "alice", "", "on my way");
	status_onto(&lines, 0, FZN_STATUS_OK, NULL);
	bon(&c, &lines);
	CHECK(fzn_rpc_inbox_lines(&c, key_hex, 64, out, 4, &count) == FZN_RPC_OK && count == 2
	              && out[0].sender_host_pubkey[0] == 0xab && out[0].commitment[0] == 0x54 && out[0].outgoing
	              && out[0].state == FZN_RPC_LINE_SETTLED && out[0].stime == 1700000000u
	              && out[0].rtime == 1700000005u && strcmp(out[0].sender_name, "alice") == 0
	              && strcmp(out[0].text, "see you at 8") == 0 && !out[1].outgoing
	              && strcmp(out[1].text, "on my way") == 0,
	      "a conversation's lines were not read in binary, or a group's line was taken for one");
	CHECK(lines.asked_len[0] == 41 && lines.asked[0][0] == 0x0a && lines.asked[0][1] == 0x84
	              && lines.asked[0][2] == 1 && lines.asked[0][3] == 0xab && lines.asked[0][39] == 0
	              && lines.asked[0][40] == 4,
	      "the lines were not asked in the schema's bytes, by key, at most the cap");

	{
		struct script s = { { "ok 0 0 0" }, 0, 1, 0, { { 0 } } };

		on(&c, &s);
		CHECK(fzn_rpc_inbox_lines(&c, "alice", 5, out, 4, &count) == FZN_RPC_OK && count == 0
		              && strcmp(s.asked[0], "list message alice 0") == 0,
		      "a conversation named by a contact's name was not asked by the verb");
	}
}

/* A GROUP'S LINES IN BINARY, sec 1175: asked by the group's id as the
 * lines request with ONE 1, each row a group line with the member who wrote
 * it as its sender and its time in ms kept as SEQ; a contact's line under a
 * group's key refuses the listing; a group by its name goes by the verb. */
static void test_group_lines_in_binary(void)
{
	static struct bscript lines, wrong;
	static fzn_rpc_group_line_t out[4];
	static const char id_hex[] = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";
	size_t count = 0;

	line_onto(&lines, 0, 0xcd, 1, 0, 0, "team", "carol", "in the group");
	line_onto(&lines, 0, 0xcd, 1, 1, 1, "team", "", "mine");
	status_onto(&lines, 0, FZN_STATUS_OK, NULL);
	bon(&c, &lines);
	CHECK(fzn_rpc_group_lines(&c, id_hex, 64, out, 4, &count) == FZN_RPC_OK && count == 2
	              && out[0].line.sender_host_pubkey[0] == 0xcd && strcmp(out[0].line.sender_name, "carol") == 0
	              && !out[0].line.outgoing && strcmp(out[0].line.text, "in the group") == 0
	              && out[0].seq == 1700000000000ull && out[0].line.stime == 1700000000u
	              && out[1].line.outgoing && out[1].line.sender_name_len == 0
	              && out[1].line.state == FZN_RPC_LINE_DELIVERED,
	      "a group's lines were not read in binary, the member as sender and the time as seq");
	CHECK(lines.asked_len[0] == 41 && lines.asked[0][0] == 0x0a && lines.asked[0][1] == 0x84
	              && lines.asked[0][2] == 1 && lines.asked[0][3] == 0xcd && lines.asked[0][40] == 4,
	      "a group's lines were not asked by its id, at most the cap");
	line_onto(&wrong, 0, 0xab, 0, 1, 2, "alice", "", "not a group's");
	status_onto(&wrong, 0, FZN_STATUS_OK, NULL);
	bon(&c, &wrong);
	CHECK(fzn_rpc_group_lines(&c, id_hex, 64, out, 4, &count) != FZN_RPC_OK,
	      "a contact's line under a group's key was read as the group's");
	{
		struct script s = { { "ok 0 0 0" }, 0, 1, 0, { { 0 } } };

		on(&c, &s);
		CHECK(fzn_rpc_group_lines(&c, "team", 4, out, 4, &count) == FZN_RPC_OK && count == 0
		              && strcmp(s.asked[0], "list message @team 0") == 0,
		      "a group named by its name was not asked by the verb");
	}
}

/* A LINE SENT IN BINARY, sec 1161: to a key, asked as FZN_CMD_MESSAGES
 * send with the key, a fresh id and the text whole; a key nobody holds is
 * no peer; a contact named by NAME sent by the verb. */
static void test_a_line_is_sent_in_binary(void)
{
	static struct bscript sent, nobody;
	static const char key_hex[] = "abababababababababababababababababababababababababababababababab";

	status_onto(&sent, 0, FZN_STATUS_OK, NULL);
	bon(&c, &sent);
	CHECK(fzn_rpc_message_send(&c, key_hex, 64, "hello", 5) == FZN_RPC_OK && sent.asked_len[0] == 2u + 32u + 16u + 1u + 32u + 2u + 5u
	              && sent.asked[0][0] == 0x0a && sent.asked[0][1] == 0x86 && sent.asked[0][2] == 0xab
	              && sent.asked[0][50] == 0 && sent.asked[0][84] == 5 && memcmp(sent.asked[0] + 85, "hello", 5) == 0,
	      "a line to a key was not sent in the schema's bytes");

	status_onto(&nobody, 0, FZN_STATUS_ERROR, "no contact or group by that key");
	bon(&c, &nobody);
	CHECK(fzn_rpc_message_send(&c, key_hex, 64, "hello", 5) == FZN_RPC_ERR_NO_PEER
	              && strcmp(c.error, "no contact or group by that key") == 0,
	      "a line to a key nobody holds was not said to have no peer");

	{
		struct script s = { { "ok" }, 0, 1, 0, { { 0 } } };

		on(&c, &s);
		CHECK(fzn_rpc_message_send(&c, "alice", 5, "hi", 2) == FZN_RPC_OK
		              && strncmp(s.asked[0], "add message alice out ", 22) == 0,
		      "a line to a contact named by NAME was not sent by the verb");
	}
}

/* ONE CONTACT ROW framed onto answer `i`, sec 1162. */
static void contact_onto(struct bscript *s, size_t i, uint8_t first, uint8_t standing, const char *name)
{
	uint8_t key[32], row[80], m[96];
	uint32_t row_len = 0, n = 0;

	memset(key, first, sizeof(key));
	if (fzn_contacts_local_row_build(row, sizeof(row), key, (fzn_contacts_local_standing_t)standing,
	                                 (const uint8_t *)name, (uint32_t)strlen(name), &row_len) != SITU_OK
	    || fzn_contacts_local_message_build_row(m, sizeof(m), (uint8_t)FZN_CMD_CONTACTS, row, row_len, &n) != SITU_OK)
		return;
	framed(s, i, m, n);
}

/* THIS USER'S CONTACTS IN BINARY, sec 1162: asked as FZN_CMD_CONTACTS list,
 * a row each into the list with its standing, ended by a STATUS; a listing
 * cut before it refused. */
static void test_contacts_in_binary(void)
{
	static struct bscript two, cut;
	static fzn_rpc_peer_list_resp_t out;

	contact_onto(&two, 0, 0xaa, 0, "alice");
	contact_onto(&two, 0, 0xbb, 2, "bob");
	status_onto(&two, 0, FZN_STATUS_OK, NULL);
	bon(&c, &two);
	CHECK(fzn_rpc_peer_list(&c, &out) == FZN_RPC_OK && out.count == 2 && out.entries[0].root_pubkey[0] == 0xaa
	              && strcmp(out.entries[0].name, "alice") == 0 && out.entries[0].state == FZN_RPC_CONTACT_ACTIVE
	              && strcmp(out.entries[1].name, "bob") == 0 && out.entries[1].state == FZN_RPC_CONTACT_RETIRED
	              && two.asked_len[0] == 2 && two.asked[0][0] == 0x0b && two.asked[0][1] == 0x80,
	      "the contacts were not read in binary, with their standings");
	contact_onto(&cut, 0, 0xaa, 0, "alice");
	bon(&c, &cut);
	CHECK(fzn_rpc_peer_list(&c, &out) != FZN_RPC_OK, "a contacts listing cut before its STATUS was read as whole");
	fzn_rpc_peer_list_release(&out);
}

/* A CONTACT RENAMED AND REMOVED IN BINARY, sec 1167: the requests' bytes,
 * a clash row passed over before the ok, a denial mapped; and a node that
 * reads no binary asked by name, the name found by the key. */
static void test_contact_changes_in_binary(void)
{
	static struct bscript renamed, removed, denied;
	uint8_t key[32], other[32];
	uint8_t clash[2 + 32] = { 0x0b, 0x84 };

	memset(key, 0xab, sizeof(key));
	memset(other, 0xcd, sizeof(other));
	memcpy(clash + 2, other, 32);
	framed(&renamed, 0, clash, sizeof(clash));
	status_onto(&renamed, 0, FZN_STATUS_OK, NULL);
	bon(&c, &renamed);
	CHECK(fzn_rpc_peer_rename(&c, key, "alice", 5) == FZN_RPC_OK && renamed.asked_len[0] == 2u + 32u + 1u + 5u
	              && renamed.asked[0][1] == 0x82 && renamed.asked[0][2] == 0xab && renamed.asked[0][34] == 5
	              && memcmp(renamed.asked[0] + 35, "alice", 5) == 0,
	      "a rename was not asked in binary, or its clash row taken for a failure");
	status_onto(&removed, 0, FZN_STATUS_OK, NULL);
	bon(&c, &removed);
	CHECK(fzn_rpc_contact_remove(&c, key) == FZN_RPC_OK && removed.asked_len[0] == 34u
	              && removed.asked[0][1] == 0x83 && removed.asked[0][33] == 0xab,
	      "a removal was not asked in binary by key");
	status_onto(&denied, 0, FZN_STATUS_DENIED, "no standing to write the roster");
	bon(&c, &denied);
	CHECK(fzn_rpc_contact_remove(&c, key) == FZN_RPC_ERR_NOT_AUTHORIZED
	              && strcmp(c.error, "no standing to write the roster") == 0,
	      "a removal refused for want of standing was not mapped, or its words were lost");
	{
		static const char LISTED[] =
		        "ok 1 0 alice,abababababababababababababababababababababababababababababababab";
		struct script s = { { LISTED, "ok" }, 0, 2, 0, { { 0 } } };

		on(&c, &s);
		CHECK(fzn_rpc_contact_remove(&c, key) == FZN_RPC_OK && strcmp(s.asked[1], "remove contact alice") == 0,
		      "a node reading no binary was not asked to remove the contact by its name");
	}
}

/* THE CONTACT REQUESTS IN BINARY, sec 1169: listed with name, time and
 * where, then let in and turned away by key, the requests' bytes checked. */
static void test_requests_in_binary(void)
{
	static struct bscript listed, granted, refused;
	static fzn_rpc_peer_request_list_resp_t out;
	static fzn_rpc_peer_request_approve_resp_t let_in;
	uint8_t key[32], row[120], m[136];
	uint32_t row_len = 0, n = 0;

	memset(key, 0xab, sizeof(key));
	if (fzn_contacts_local_request_row_build(row, sizeof(row), key, 1700000000000ull, (const uint8_t *)"bob", 3,
	                                         (const uint8_t *)"10.0.0.2:40001", 14, &row_len)
	            == SITU_OK
	    && fzn_contacts_local_message_build_request_row(m, sizeof(m), (uint8_t)FZN_CMD_CONTACTS, row, row_len, &n)
	               == SITU_OK)
		framed(&listed, 0, m, n);
	status_onto(&listed, 0, FZN_STATUS_OK, NULL);
	bon(&c, &listed);
	CHECK(fzn_rpc_peer_request_list(&c, &out) == FZN_RPC_OK && out.count == 1
	              && out.entries[0].requester_host_pubkey[0] == 0xab
	              && strcmp(out.entries[0].proposed_display_name, "bob") == 0
	              && strcmp(out.entries[0].address, "10.0.0.2:40001") == 0
	              && out.entries[0].received_at == 1700000000000ull && listed.asked_len[0] == 2
	              && listed.asked[0][1] == 0x85,
	      "the requests were not read in binary, with name, time and where");

	/* LET IN: the name checked free first, by the contact listing -- itself
	 * in binary now, answered empty -- and then granted. */
	status_onto(&granted, 0, FZN_STATUS_OK, NULL);
	status_onto(&granted, 1, FZN_STATUS_OK, NULL);
	bon(&c, &granted);
	CHECK(fzn_rpc_peer_request_approve(&c, key, "bob", 3, &let_in) == FZN_RPC_OK && granted.asked[0][1] == 0x80
	              && granted.asked[1][1] == 0x87 && granted.asked[1][34] == 3
	              && memcmp(granted.asked[1] + 35, "bob", 3) == 0 && let_in.host_pubkey[0] == 0xab,
	      "a request was not let in in binary under its name");
	status_onto(&refused, 0, FZN_STATUS_ERROR, "no request from that root");
	bon(&c, &refused);
	CHECK(fzn_rpc_peer_request_reject(&c, key) == FZN_RPC_ERR_NO_PEER_REQUEST && refused.asked[0][1] == 0x88
	              && strcmp(c.error, "no request from that root") == 0,
	      "a request turned away in binary was not asked by key, or the refusal's code or words lost");
}

/* THIS USER'S GROUPS IN BINARY, sec 1170: a row read into the list with its
 * id, members, admin and lines, the request's bytes, a cut listing refused. */
static void test_groups_in_binary(void)
{
	static struct bscript two, cut;
	static fzn_rpc_group_list_resp_t out;
	uint8_t id[32], row[96], m[112];
	uint32_t row_len = 0, n = 0;

	memset(id, 0xcd, sizeof(id));
	if (fzn_groups_local_row_build(row, sizeof(row), id, 3u, 1u, 7u, (const uint8_t *)"team", 4, &row_len)
	            == SITU_OK
	    && fzn_groups_local_message_build_row(m, sizeof(m), (uint8_t)FZN_CMD_GROUPS, row, row_len, &n) == SITU_OK) {
		framed(&two, 0, m, n);
		framed(&cut, 0, m, n);
	}
	status_onto(&two, 0, FZN_STATUS_OK, NULL);
	bon(&c, &two);
	CHECK(fzn_rpc_group_list(&c, &out) == FZN_RPC_OK && out.count == 1 && strcmp(out.entries[0].name, "team") == 0
	              && out.entries[0].chat_id[0] == 0xcd && out.entries[0].member_count == 3 && out.entries[0].is_admin
	              && out.entries[0].lines == 7 && two.asked_len[0] == 2 && two.asked[0][0] == 0x0d
	              && two.asked[0][1] == 0x80,
	      "the groups were not read in binary, with id, members, admin and lines");
	bon(&c, &cut);
	CHECK(fzn_rpc_group_list(&c, &out) != FZN_RPC_OK, "a groups listing cut before its STATUS was read as whole");
	fzn_rpc_group_list_release(&out);
}

/* ONE FIX framed onto answer `i`, sec 1171. */
static void fix_onto(struct bscript *s, size_t i, uint64_t seq, uint32_t utc, const char *whose)
{
	uint8_t host[32], row[160], m[176];
	uint32_t row_len = 0, n = 0;

	memset(host, 0x5a, sizeof(host));
	if (fzn_streams_local_location_row_build(row, sizeof(row), host, seq, 1700000000000ull, 593293234, 180685815, utc,
	                                         31, 90u, 5u, 9u, 19u, 1u, 1u, 0u, (const uint8_t *)whose,
	                                         (uint32_t)strlen(whose), &row_len)
	            != SITU_OK
	    || fzn_streams_local_message_build_location_row(m, sizeof(m), (uint8_t)FZN_CMD_STREAMS, row, row_len, &n)
	               != SITU_OK)
		return;
	framed(s, i, m, n);
}

/* THE POSITIONS HELD IN BINARY, sec 1171: a contact's newest fix kept of
 * two, its fields as sent, this user's own host passed over. */
static void test_positions_in_binary(void)
{
	static struct bscript held;
	fzn_rpc_location_latest_t *out = NULL;
	size_t room = 0, count = 0;

	fix_onto(&held, 0, 7u, 1700000100u, "alice");
	fix_onto(&held, 0, 8u, 1700000200u, "alice");
	fix_onto(&held, 0, 9u, 1700000300u, "");
	status_onto(&held, 0, FZN_STATUS_OK, NULL);
	bon(&c, &held);
	CHECK(fzn_rpc_location_latest(&c, &out, &room, &count) == FZN_RPC_OK && count == 1
	              && strcmp(out[0].name, "alice") == 0 && out[0].fix.seq == 8u && out[0].fix.utc_s == 1700000200u
	              && out[0].fix.lat_e7 == 593293234 && out[0].fix.alt_m == 31 && out[0].fix.bearing_deg == 90
	              && out[0].fix.acc_e_m == 5u && out[0].fix.acc_n_m == 9u && out[0].fix.acc_v_m == 19u
	              && held.asked[0][0] == 0x0e && held.asked[0][1] == 0x80,
	      "the positions were not read in binary, newest of a contact's kept, own hosts passed over");
	free(out);
}

/* THIS HOST'S FIXES IN BINARY, sec 1252: its host named in text, its
 * fixes read from the binary rows, newest first; another host's left out. */
static void test_show_in_binary(void)
{
	static struct bscript held;
	static struct script s = { { "ok abababababababababababababababababababababababababababababababab "
		                     "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a" },
		                   0, 1, 0, { { 0 } } };
	static fzn_rpc_location_show_resp_t out;
	static const struct {
		uint8_t host;
		uint64_t seq;
		uint32_t utc;
	} FIXES[] = { { 0xab, 4u, 100u }, { 0xcd, 9u, 300u }, { 0xab, 5u, 200u } };
	uint8_t host[32], row[160], m[176];
	uint32_t row_len = 0, n = 0;
	size_t i;

	for (i = 0; i < 3u; i++) {
		memset(host, FIXES[i].host, sizeof(host));
		if (fzn_streams_local_location_row_build(row, sizeof(row), host, FIXES[i].seq, 0u, 590000000, 180000000,
		                                         FIXES[i].utc, 0, 0u, 12u, 12u, 0u, 0u, 0u, 0u, NULL, 0u, &row_len)
		            == SITU_OK
		    && fzn_streams_local_message_build_location_row(m, sizeof(m), (uint8_t)FZN_CMD_STREAMS, row, row_len, &n)
		               == SITU_OK)
			framed(&held, 0, m, n);
	}
	status_onto(&held, 0, FZN_STATUS_OK, NULL);
	on(&c, &s);
	c.binary_answer = bscripted;
	c.binary_ctx = &held;
	CHECK(fzn_rpc_location_show(&c, "", 0, &out) == FZN_RPC_OK && out.count == 2u && out.entries[0].utc_s == 200u
	              && out.entries[1].utc_s == 100u && out.entries[0].acc_e_m == 12u && out.high_water_seq == 5u
	              && held.asked[0][0] == 0x0e && held.asked[0][1] == 0x80,
	      "this host's fixes were not read in binary, newest first, another host's left out");
}

/* THIS HOST IN ONE ROW, sec 1266: read as the five verbs were -- named,
 * not root where its user's key is another, the member capability, its
 * owed lines held and delivered, its port; and unnamed, its key's first
 * sixteen hex. */
static void test_self_in_binary(void)
{
	static struct bscript named, unnamed;
	static fzn_rpc_status_resp_t out;
	uint8_t host[32], user[32], row[200], m[220];
	uint32_t row_len = 0, n = 0;

	memset(host, 0xab, sizeof(host));
	memset(user, 0xcd, sizeof(user));
	if (fzn_members_local_self_row_build(row, sizeof(row), host, user, (const uint8_t *)"kitchen", 7u, 1u, 3u, 2u, 45524u,
	                                     &row_len)
	            == SITU_OK
	    && fzn_members_local_message_build_self_row(m, sizeof(m), (uint8_t)FZN_CMD_MEMBERS, row, row_len, &n) == SITU_OK)
		framed(&named, 0, m, n);
	status_onto(&named, 0, FZN_STATUS_OK, NULL);
	bon(&c, &named);
	CHECK(fzn_rpc_status(&c, &out) == FZN_RPC_OK && out.has_host && !out.is_root && !strcmp(out.host_name, "kitchen")
	              && out.cross_signed && out.outbox_held == 5u && out.outbox_delivered == 2u && out.peer_port == 45524u
	              && out.user_pubkey[0] == 0xcd && named.asked[0][0] == 0x09 && named.asked[0][1] == 0x96,
	      "this host was not read from one row as the five verbs were");
	if (fzn_members_local_self_row_build(row, sizeof(row), host, host, NULL, 0u, 0u, 0u, 0u, 0u, &row_len) == SITU_OK
	    && fzn_members_local_message_build_self_row(m, sizeof(m), (uint8_t)FZN_CMD_MEMBERS, row, row_len, &n) == SITU_OK)
		framed(&unnamed, 0, m, n);
	status_onto(&unnamed, 0, FZN_STATUS_OK, NULL);
	bon(&c, &unnamed);
	CHECK(fzn_rpc_status(&c, &out) == FZN_RPC_OK && out.is_root && !strcmp(out.host_name, "abababababababab"),
	      "an unnamed root was not named by its key's first sixteen hex");
}

/* THE GOVERNANCE IN BINARY, sec 1265: k from its row, roots with the one
 * acted as, a vote withdrawn, a staged change's three words, a re-key's
 * state, and the profile in force among the choices. */
static void test_governance_in_binary(void)
{
	static struct bscript roots, votes, staged, rekeys, presets;
	static fzn_rpc_roots_t r;
	static fzn_rpc_votes_t v;
	static fzn_rpc_staged_t g;
	static fzn_rpc_successions_t s;
	static fzn_rpc_presets_t p;
	uint8_t a[32], b[32], row[600], m[640];
	uint32_t row_len = 0, n = 0;

	memset(a, 0x5a, sizeof(a));
	memset(b, 0x6b, sizeof(b));
#define ONTO(script, build, msg_build, ...)                                                              \
	do {                                                                                             \
		if (build(row, sizeof(row), __VA_ARGS__, &row_len) == SITU_OK                            \
		    && msg_build(m, sizeof(m), (uint8_t)FZN_CMD_MEMBERS, row, row_len, &n) == SITU_OK)  \
			framed(&script, 0, m, n);                                                        \
	} while (0)
	ONTO(roots, fzn_members_local_quorum_row_build, fzn_members_local_message_build_quorum_row, 2u);
	ONTO(roots, fzn_members_local_root_row_build, fzn_members_local_message_build_root_row, a, 1u);
	ONTO(roots, fzn_members_local_root_row_build, fzn_members_local_message_build_root_row, b, 0u);
	status_onto(&roots, 0, FZN_STATUS_OK, NULL);
	bon(&c, &roots);
	CHECK(fzn_rpc_roots(&c, &r) == FZN_RPC_OK && r.k == 2u && r.count == 2u && r.root[0].acting && !r.root[1].acting
	              && r.root[1].key[0] == '6' && roots.asked[0][0] == 0x09 && roots.asked[0][1] == 0x8b,
	      "the roots were not read in binary, k and the one acted as");
	ONTO(votes, fzn_members_local_quorum_row_build, fzn_members_local_message_build_quorum_row, 2u);
	ONTO(votes, fzn_members_local_vote_row_build, fzn_members_local_message_build_vote_row, a, b, 1u);
	status_onto(&votes, 0, FZN_STATUS_OK, NULL);
	bon(&c, &votes);
	CHECK(fzn_rpc_votes(&c, &v) == FZN_RPC_OK && v.k == 2u && v.count == 1u && v.vote[0].withdrawn
	              && v.vote[0].voter[0] == '6',
	      "a vote was not read in binary, withdrawn, with its voter");
	ONTO(staged, fzn_members_local_staged_row_build, fzn_members_local_message_build_staged_row,
	     (const uint8_t *)"tok1", 4u, (const uint8_t *)"1700000000", 10u, (const uint8_t *)"a,b,c", 5u);
	status_onto(&staged, 0, FZN_STATUS_OK, NULL);
	bon(&c, &staged);
	CHECK(fzn_rpc_staged(&c, &g) == FZN_RPC_OK && g.count == 1u && !strcmp(g.change[0].token, "tok1")
	              && !strcmp(g.change[0].key, "a,b,c"),
	      "a staged change was not read in binary, its key whole");
	ONTO(rekeys, fzn_members_local_rekey_row_build, fzn_members_local_message_build_rekey_row, a, b,
	     (const uint8_t *)"confirmed", 9u);
	status_onto(&rekeys, 0, FZN_STATUS_OK, NULL);
	bon(&c, &rekeys);
	CHECK(fzn_rpc_successions(&c, &s) == FZN_RPC_OK && s.count == 1u && !strcmp(s.rekey[0].state, "confirmed")
	              && s.rekey[0].new_key[0] == '6',
	      "a re-key was not read in binary");
	ONTO(presets, fzn_members_local_preset_row_build, fzn_members_local_message_build_preset_row, 0u,
	     (const uint8_t *)"standard", 8u);
	ONTO(presets, fzn_members_local_preset_row_build, fzn_members_local_message_build_preset_row, 1u,
	     (const uint8_t *)"lean", 4u);
	status_onto(&presets, 0, FZN_STATUS_OK, NULL);
	bon(&c, &presets);
	CHECK(fzn_rpc_presets(&c, &p) == FZN_RPC_OK && !strcmp(p.current, "lean") && p.count == 2u,
	      "the profiles were not read in binary, the one in force said");
#undef ONTO
}

/* THE ESTATE'S GOVERNANCE, TYPED, sec 1261: each listing read as the node
 * words it -- roots with the one acted as, votes with who cast them and
 * whether withdrawn, a re-key's two keys, a staged change, a vote on a
 * host's setting, the profiles -- and an act's line as the node reads it. */
static void test_governance_typed(void)
{
	static struct script roots = { { "ok 2 2 " ID_A ",acting " ID_B }, 0, 1, 0, { { 0 } } };
	static struct script votes = { { "ok 2 2 " ID_B "," ID_A ",standing " ID_B "," ID_A ",withdrawn" }, 0, 1, 0,
		                       { { 0 } } };
	static struct script rekeys = { { "ok 1 0 " ID_A ">" ID_B ",confirmed" }, 0, 1, 0, { { 0 } } };
	static struct script staged = { { "ok 1 tok1,1700000000,setting,with,commas" }, 0, 1, 0, { { 0 } } };
	static struct script svotes = { { "ok 0 1 0 " ID_A ",vote/abcd/net/x,5,on%20air" }, 0, 1, 0, { { 0 } } };
	static struct script presets = { { "ok standard", "ok 2 standard lean" }, 0, 2, 0, { { 0 } } };
	static struct script quorum = { { "ok 3" }, 0, 1, 0, { { 0 } } };
	static fzn_rpc_roots_t r;
	static fzn_rpc_votes_t v;
	static fzn_rpc_successions_t s;
	static fzn_rpc_staged_t g;
	static fzn_rpc_setting_votes_t sv;
	static fzn_rpc_presets_t p;

	on(&c, &roots);
	CHECK(fzn_rpc_roots(&c, &r) == FZN_RPC_OK && r.k == 2u && r.count == 2u && r.root[0].acting && !r.root[1].acting
	              && strcmp(r.root[1].key, ID_B) == 0 && !strcmp(roots.asked[0], "list root"),
	      "the roots were not read with k and the one this host acts as");
	on(&c, &votes);
	CHECK(fzn_rpc_votes(&c, &v) == FZN_RPC_OK && v.count == 2u && !v.vote[0].withdrawn && v.vote[1].withdrawn
	              && strcmp(v.vote[0].voter, ID_A) == 0,
	      "the votes were not read with their voters, a withdrawn one said so");
	on(&c, &rekeys);
	CHECK(fzn_rpc_successions(&c, &s) == FZN_RPC_OK && s.count == 1u && strcmp(s.rekey[0].new_key, ID_B) == 0
	              && strcmp(s.rekey[0].state, "confirmed") == 0,
	      "a re-key was not read as its two keys and its state");
	on(&c, &staged);
	CHECK(fzn_rpc_staged(&c, &g) == FZN_RPC_OK && g.count == 1u && strcmp(g.change[0].token, "tok1") == 0
	              && strcmp(g.change[0].key, "setting,with,commas") == 0,
	      "a staged change was not read, its key taking the rest");
	on(&c, &svotes);
	CHECK(fzn_rpc_setting_votes(&c, &sv) == FZN_RPC_OK && sv.count == 1u && sv.vote[0].version == 5u
	              && strcmp(sv.vote[0].cell, "vote/abcd/net/x") == 0 && !strcmp(svotes.asked[0], "list record under vote/ 0"),
	      "a vote on a host's setting was not read, paged from 0");
	on(&c, &presets);
	CHECK(fzn_rpc_presets(&c, &p) == FZN_RPC_OK && strcmp(p.current, "standard") == 0 && p.count == 2u
	              && strcmp(p.choice[1], "lean") == 0,
	      "the profile in force and the choices were not read");
	on(&c, &quorum);
	CHECK(fzn_rpc_quorum_set(&c, 3u) == FZN_RPC_OK && !strcmp(quorum.asked[0], "set quorum 3"),
	      "k was not set by the node's own line");
}

/* THE RETENTION RULES IN BINARY, sec 1258: the estate's asked by its scope,
 * each row read in its words; one added for the estate, the request's
 * bytes as sent; a refusal in the node's words; and the old call for this
 * host's rules the same request with scope 0. */
static void test_rules_in_binary(void)
{
	static struct bscript held, added, refused, old;
	static fzn_rpc_rules_t out;
	static const char *const RULES[] = { "prune * age 30d", "keep messages count 500" };
	uint8_t row[300], m[320];
	uint32_t row_len = 0, n = 0;
	size_t i;

	for (i = 0; i < 2u; i++)
		if (fzn_settings_local_rule_row_build(row, sizeof(row), (const uint8_t *)RULES[i], (uint32_t)strlen(RULES[i]),
		                                      &row_len)
		            == SITU_OK
		    && fzn_settings_local_message_build_rule_row(m, sizeof(m), (uint8_t)FZN_CMD_SETTINGS, row, row_len, &n)
		               == SITU_OK)
			framed(&held, 0, m, n);
	status_onto(&held, 0, FZN_STATUS_OK, NULL);
	bon(&c, &held);
	CHECK(fzn_rpc_rules(&c, 1, &out) == FZN_RPC_OK && out.count == 2u && strcmp(out.rule[1], RULES[1]) == 0
	              && !out.overflow && held.asked[0][0] == 0x18 && held.asked[0][1] == 0x82 && held.asked[0][2] == 1,
	      "the estate's rules were not read in binary, each in its words, asked by its scope");
	status_onto(&added, 0, FZN_STATUS_OK, NULL);
	bon(&c, &added);
	CHECK(fzn_rpc_rule_change(&c, 1, 1, RULES[0], strlen(RULES[0])) == FZN_RPC_OK && added.asked[0][1] == 0x84
	              && added.asked[0][2] == 1 && added.asked[0][4] == 15u && memcmp(added.asked[0] + 5, "prune", 5) == 0,
	      "an estate rule was not added in binary, its words as sent");
	status_onto(&refused, 0, FZN_STATUS_ERROR, "this node stands as neither a root nor an admin");
	bon(&c, &refused);
	CHECK(fzn_rpc_rule_change(&c, 1, 0, RULES[0], strlen(RULES[0])) != FZN_RPC_OK
	              && strstr(c.error, "neither a root nor an admin") && refused.asked[0][1] == 0x85,
	      "a rule the node would not remove was not refused in its words");
	status_onto(&old, 0, FZN_STATUS_OK, NULL);
	bon(&c, &old);
	CHECK(fzn_rpc_retention_add(&c, RULES[0], strlen(RULES[0])) == FZN_RPC_OK && old.asked[0][1] == 0x84
	              && old.asked[0][2] == 0,
	      "the old call for this host's rules did not ask in binary with its scope");
}

/* A CONTACT'S PAST CALLS IN BINARY, sec 1255: asked by the name, each row
 * read with its id, direction, kinds, outcome, start and length, one past
 * the room left out; a refusal in the node's words. */
static void test_call_history_in_binary(void)
{
	static struct bscript held, refused;
	static const uint8_t ids[2][8] = { { 0xb1, 0, 0, 0, 0, 0, 0, 0xb8 }, { 0xa1, 0, 0, 0, 0, 0, 0, 0xa8 } };
	fzn_rpc_call_past_t out[1];
	uint8_t row[32], m[64];
	uint32_t row_len = 0, n = 0;
	size_t count = 0, i;

	for (i = 0; i < 2u; i++)
		if (fzn_call_past_row_build(row, sizeof(row), i ? 2u : 1u, i ? 1u : 3u, i ? 2u : 1u, i ? 1700005850u : 1700005990u,
		                            i ? 0u : 252u, &row_len)
		            == SITU_OK
		    && fzn_call_message_build_past_row(m, sizeof(m), (uint8_t)FZN_CMD_CALL, ids[i], row, row_len, &n) == SITU_OK)
			framed(&held, 0, m, n);
	status_onto(&held, 0, FZN_STATUS_OK, NULL);
	bon(&c, &held);
	CHECK(fzn_rpc_call_history(&c, "bob", 3, out, 1u, &count) == FZN_RPC_OK && count == 1u
	              && strcmp(out[0].id, "b1000000000000b8") == 0 && out[0].out && out[0].kinds == 3u
	              && out[0].outcome == FZN_RPC_CALL_ANSWERED && out[0].started == 1700005990u && out[0].seconds == 252u
	              && held.asked[0][0] == 0x12 && held.asked[0][1] == 0x87 && held.asked[0][10] == 3u
	              && memcmp(held.asked[0] + 11, "bob", 3) == 0,
	      "a contact's past calls were not read in binary, asked by the name, one past the room left out");
	status_onto(&refused, 0, FZN_STATUS_ERROR, "no such contact");
	bon(&c, &refused);
	CHECK(fzn_rpc_call_history(&c, "nobody", 6, out, 1u, &count) != FZN_RPC_OK && strstr(c.error, "no such contact"),
	      "a contact nobody has was not refused in the node's words");
}

/* THIS USER'S CALLS IN BINARY, sec 1251: rows read with their id, state,
 * kinds and user, one past the room given left out; a reason read; a live
 * call no reason; answered by its id; a refusal in the node's words. */
static void test_calls_in_binary(void)
{
	static struct bscript list, ended, live, answered, refused;
	static const uint8_t id[8] = { 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8 };
	uint8_t row[64], m[96], user[32];
	uint32_t row_len = 0, n = 0;
	fzn_rpc_entry_t out[1];
	size_t count = 0, i;
	char why[24];

	memset(user, 0x5a, sizeof(user));
	for (i = 0; i < 2u; i++)
		if (fzn_call_call_row_build(row, sizeof(row), i ? 3u : 1u, 3u, 1u, user, &row_len) == SITU_OK
		    && fzn_call_message_build_call_row(m, sizeof(m), (uint8_t)FZN_CMD_CALL, id, row, row_len, &n) == SITU_OK)
			framed(&list, 0, m, n);
	status_onto(&list, 0, FZN_STATUS_OK, NULL);
	bon(&c, &list);
	CHECK(fzn_rpc_calls(&c, out, 1u, &count) == FZN_RPC_OK && count == 1u && strcmp(out[0].id, "a1a2a3a4a5a6a7a8") == 0
	              && out[0].state == FZN_RPC_RINGING_IN && out[0].kinds == 3u && out[0].has_user
	              && out[0].user[0] == 0x5a && list.asked[0][0] == 0x12 && list.asked[0][1] == 0x82,
	      "the calls were not read in binary, by id, state, kinds and user, one past the room left out");

	if (fzn_call_ended_row_build(row, sizeof(row), (const uint8_t *)"busy", 4u, &row_len) == SITU_OK
	    && fzn_call_message_build_ended_row(m, sizeof(m), (uint8_t)FZN_CMD_CALL, id, row, row_len, &n) == SITU_OK)
		framed(&ended, 0, m, n);
	status_onto(&ended, 0, FZN_STATUS_OK, NULL);
	bon(&c, &ended);
	CHECK(fzn_rpc_ended(&c, "a1a2a3a4a5a6a7a8", why, sizeof(why)) == FZN_RPC_OK && strcmp(why, "busy") == 0
	              && ended.asked[0][1] == 0x84 && ended.asked[0][2] == 0xa1,
	      "why a call ended was not read in binary, asked by its id");
	status_onto(&live, 0, FZN_STATUS_OK, NULL);
	bon(&c, &live);
	CHECK(fzn_rpc_ended(&c, "a1a2a3a4a5a6a7a8", why, sizeof(why)) == FZN_RPC_OK && why[0] == '\0',
	      "a live call was read in binary as ended");

	status_onto(&answered, 0, FZN_STATUS_OK, NULL);
	bon(&c, &answered);
	CHECK(fzn_rpc_respond(&c, "a1a2a3a4a5a6a7a8", "decline") == FZN_RPC_OK && answered.asked[0][1] == 0x86
	              && answered.asked[0][9] == 0xa8 && answered.asked[0][10] == 3,
	      "a call was not declined in binary by its id");
	status_onto(&refused, 0, FZN_STATUS_ERROR, "no such call");
	bon(&c, &refused);
	CHECK(fzn_rpc_respond(&c, "a1a2a3a4a5a6a7a8", "hangup") != FZN_RPC_OK && strstr(c.error, "no such call")
	              && refused.asked[0][10] == 4,
	      "hanging up a call nobody holds was not refused in the node's words");
}

/* A DEVICE INVITED, WAITING AND ANSWERED IN BINARY, sec 1250: the code read
 * as sent, asked delegable; two devices waiting where room was for one,
 * the first kept; let in by key; a refusal in the node's words. */
static void test_invites_in_binary(void)
{
	static struct bscript code, wait, in, refused;
	static const char said[] = "FZI1:ABCDEFG";
	uint8_t row[64], m[80], keys[1][32], key[32];
	uint32_t row_len = 0, n = 0;
	char got[64];
	size_t count = 0, i;

	if (fzn_members_local_invite_row_build(row, sizeof(row), (const uint8_t *)said, sizeof(said) - 1u, &row_len)
	            == SITU_OK
	    && fzn_members_local_message_build_invite_row(m, sizeof(m), (uint8_t)FZN_CMD_MEMBERS, row, row_len, &n)
	               == SITU_OK)
		framed(&code, 0, m, n);
	status_onto(&code, 0, FZN_STATUS_OK, NULL);
	bon(&c, &code);
	CHECK(fzn_rpc_device_invite(&c, got, sizeof(got)) == FZN_RPC_OK && strcmp(got, said) == 0
	              && code.asked[0][0] == 0x09 && code.asked[0][1] == 0x86 && code.asked[0][2] == 1,
	      "an invite was not read in binary as sent, asked delegable");

	for (i = 0; i < 2u; i++) {
		memset(key, i ? 0x22 : 0x11, sizeof(key));
		if (fzn_members_local_message_build_waiting_row(m, sizeof(m), (uint8_t)FZN_CMD_MEMBERS, key, 32u, &n)
		    == SITU_OK)
			framed(&wait, 0, m, n);
	}
	status_onto(&wait, 0, FZN_STATUS_OK, NULL);
	bon(&c, &wait);
	CHECK(fzn_rpc_device_waiting(&c, keys, 1u, &count) == FZN_RPC_OK && count == 1u && keys[0][0] == 0x11
	              && wait.asked[0][1] == 0x88,
	      "the devices waiting were not read in binary, the first kept where room was for one");

	status_onto(&in, 0, FZN_STATUS_OK, NULL);
	bon(&c, &in);
	memset(key, 0x33, sizeof(key));
	CHECK(fzn_rpc_device_answer(&c, key, 1) == FZN_RPC_OK && in.asked[0][1] == 0x8a && in.asked[0][2] == 0x33
	              && in.asked[0][34] == 1,
	      "a waiting device was not let in by its key in binary");

	status_onto(&refused, 0, FZN_STATUS_ERROR, "no device waits by that key");
	bon(&c, &refused);
	CHECK(fzn_rpc_device_answer(&c, key, 0) != FZN_RPC_OK && strstr(c.error, "no device waits by that key")
	              && refused.asked[0][34] == 0,
	      "turning away a key nobody waits by was not refused in the node's words");
}

/* THIS HOST'S SAMPLING IN BINARY, sec 1249: read as the text is -- gpsd
 * watching, sampling from where it is; connecting, not sampling and why;
 * a fix supplied, sampling from `platform`. */
static void test_location_status_in_binary(void)
{
	static struct bscript watching, connecting, supplied;
	static const struct {
		struct bscript *s;
		uint8_t link, source;
		const char *gpsd;
	} CASES[] = { { &watching, 3u, 1u, "127.0.0.1:2947" },
		      { &connecting, 2u, 0u, "127.0.0.1:2947" },
		      { &supplied, 0u, 2u, "" } };
	fzn_rpc_location_status_resp_t out;
	uint8_t row[320], m[336];
	uint32_t row_len = 0, n = 0;
	size_t i;

	for (i = 0; i < 3u; i++) {
		if (fzn_streams_local_status_row_build(row, sizeof(row), 1u, CASES[i].link, 30u, 100u, 5u, 1u, 1700000000u,
		                                       CASES[i].source, 1700000000u, (const uint8_t *)CASES[i].gpsd,
		                                       (uint32_t)strlen(CASES[i].gpsd), &row_len)
		            == SITU_OK
		    && fzn_streams_local_message_build_status_row(m, sizeof(m), (uint8_t)FZN_CMD_STREAMS, row, row_len, &n)
		               == SITU_OK)
			framed(CASES[i].s, 0, m, n);
		status_onto(CASES[i].s, 0, FZN_STATUS_OK, NULL);
	}
	bon(&c, &watching);
	CHECK(fzn_rpc_location_status(&c, &out) == FZN_RPC_OK && out.configured && out.sampling && out.interval_s == 30u
	              && strcmp(out.source, "127.0.0.1:2947") == 0 && watching.asked[0][0] == 0x0e
	              && watching.asked[0][1] == 0x82,
	      "gpsd watching was not read in binary as sampling from where it is");
	bon(&c, &connecting);
	CHECK(fzn_rpc_location_status(&c, &out) == FZN_RPC_OK && !out.sampling
	              && out.stopped_reason == FZN_RPC_LOCATION_STOPPED_UNREACHABLE,
	      "gpsd connecting was not read in binary as not sampling, unreachable");
	bon(&c, &supplied);
	CHECK(fzn_rpc_location_status(&c, &out) == FZN_RPC_OK && out.sampling && strcmp(out.source, "platform") == 0,
	      "a fix supplied was not read in binary as sampling from platform");
}

/* THE STICKER PACKS IN BINARY, sec 1172: a row read with its root and raw
 * name, the request's bytes, a listing cut before its STATUS refused. */
static void test_packs_in_binary(void)
{
	static struct bscript held, cut;
	static fzn_rpc_sticker_packs_t out;
	uint8_t root[32], row[112], m[128];
	uint32_t row_len = 0, n = 0;

	memset(root, 0x6c, sizeof(root));
	if (fzn_stickers_local_pack_row_build(row, sizeof(row), root, 65536u, 1u, 1u, (const uint8_t *)"cats and moods", 14,
	                                      &row_len)
	            == SITU_OK
	    && fzn_stickers_local_message_build_pack_row(m, sizeof(m), (uint8_t)FZN_CMD_STICKERS, row, row_len, &n)
	               == SITU_OK) {
		framed(&held, 0, m, n);
		framed(&cut, 0, m, n);
	}
	status_onto(&held, 0, FZN_STATUS_OK, NULL);
	bon(&c, &held);
	CHECK(fzn_rpc_sticker_list(&c, &out) == FZN_RPC_OK && out.count == 1 && out.entries[0].root[0] == 0x6c
	              && strcmp(out.entries[0].name, "cats and moods") == 0 && held.asked[0][0] == 0x16
	              && held.asked[0][1] == 0x80,
	      "the packs were not read in binary, by root and raw name");
	fzn_rpc_sticker_packs_release(&out);
	bon(&c, &cut);
	CHECK(fzn_rpc_sticker_list(&c, &out) != FZN_RPC_OK, "a packs listing cut before its STATUS was read as whole");
	fzn_rpc_sticker_packs_release(&out);
}

/* A PACK'S STICKERS, A PACK KEPT AND LET GO, IN BINARY, sec 1248: a row's
 * every field read as sent, asked by the root; kept answered with its root
 * and for whom; let go by its root; a refusal said in the node's words. */
static void test_stickers_in_binary(void)
{
	static struct bscript items, kept, gone, refused;
	static fzn_rpc_node_sticker_items_resp_t out;
	uint8_t root[32], row[160], m[176];
	uint32_t row_len = 0, n = 0;
	char ref[145];
	uint8_t got_root[32];
	int host_only = 1;

	memset(root, 0x6c, sizeof(root));
	if (fzn_stickers_local_item_row_build(row, sizeof(row), 7u, 1u, 2u, 16u, 8u, 8u, 112u, 48u, 0xffffffffu, 0xffu, 90u,
	                                      128u, 128u, (const uint8_t *)"waving", 6, &row_len)
	            == SITU_OK
	    && fzn_stickers_local_message_build_item_row(m, sizeof(m), (uint8_t)FZN_CMD_STICKERS, row, row_len, &n)
	               == SITU_OK)
		framed(&items, 0, m, n);
	status_onto(&items, 0, FZN_STATUS_OK, NULL);
	bon(&c, &items);
	CHECK(fzn_rpc_sticker_items(&c, "6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c", 64, &out)
	              == FZN_RPC_OK
	              && out.count == 1 && out.entries[0].id == 7u && out.entries[0].flags == 2u
	              && out.entries[0].text_limit == 16u && out.entries[0].text_w == 112u
	              && out.entries[0].text_fill == 0xffffffffu && out.entries[0].text_turn == 90u
	              && out.entries[0].main_h == 128u && strcmp(out.entries[0].description, "waving") == 0
	              && items.asked[0][0] == 0x16 && items.asked[0][1] == 0x82 && items.asked[0][2] == 0x6c,
	      "a pack's stickers were not read in binary, every field as sent, asked by its root");

	if (fzn_stickers_local_kept_row_build(row, sizeof(row), root, 0u, &row_len) == SITU_OK
	    && fzn_stickers_local_message_build_kept(m, sizeof(m), (uint8_t)FZN_CMD_STICKERS, row, row_len, &n) == SITU_OK)
		framed(&kept, 0, m, n);
	status_onto(&kept, 0, FZN_STATUS_OK, NULL);
	bon(&c, &kept);
	memset(ref, '6', 144);
	memcpy(ref, "6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c", 64);
	ref[144] = '\0';
	CHECK(fzn_rpc_sticker_keep(&c, ref, 144, got_root, &host_only) == FZN_RPC_OK && got_root[0] == 0x6c
	              && host_only == 1 && kept.asked[0][1] == 0x84 && kept.asked[0][2] == 0x6c,
	      "a pack kept in binary was not answered with its root, kept for this host alone");

	status_onto(&gone, 0, FZN_STATUS_OK, NULL);
	bon(&c, &gone);
	CHECK(fzn_rpc_sticker_forget(&c, root) == FZN_RPC_OK && gone.asked[0][1] == 0x86 && gone.asked[0][2] == 0x6c,
	      "a pack was not let go in binary, by its root");

	status_onto(&refused, 0, FZN_STATUS_ERROR, "no such pack is saved");
	bon(&c, &refused);
	CHECK(fzn_rpc_sticker_forget(&c, root) != FZN_RPC_OK && strstr(c.error, "no such pack is saved"),
	      "a pack nobody keeps was not refused in the node's words");
}

/* THE LIBRARY IN BINARY, sec 1174: every field of a row read as sent, the
 * request's bytes, a listing cut before its STATUS refused, and a node
 * reading no binary asked the text join instead. */
static void test_library_in_binary(void)
{
	static struct bscript held, cut, old;
	static fzn_rpc_library_list_all_t out;
	uint8_t root[32], row[400], m[416];
	uint32_t row_len = 0, n = 0;

	memset(root, 0x7e, sizeof(root));
	if (fzn_files_local_library_row_build(row, sizeof(row), root, 20000u, 120000u, 2u, 1u, 0u,
	                                      (const uint8_t *)"video", 5, (const uint8_t *)"a holiday", 9, &row_len)
	            == SITU_OK
	    && fzn_files_local_message_build_library_row(m, sizeof(m), (uint8_t)FZN_CMD_FILES, row, row_len, &n)
	               == SITU_OK) {
		framed(&held, 0, m, n);
		framed(&cut, 0, m, n);
	}
	if (fzn_files_local_library_row_build(row, sizeof(row), root, 1u << 20, 0u, 1u, 0u, 500u, NULL, 0, NULL, 0,
	                                      &row_len)
	            == SITU_OK
	    && fzn_files_local_message_build_library_row(m, sizeof(m), (uint8_t)FZN_CMD_FILES, row, row_len, &n)
	               == SITU_OK)
		framed(&held, 0, m, n);
	status_onto(&held, 0, FZN_STATUS_OK, NULL);
	bon(&c, &held);
	CHECK(fzn_rpc_library_list(&c, &out) == FZN_RPC_OK && out.count == 2 && out.entries[0].root[0] == 0x7e
	              && strcmp(out.entries[0].name, "a holiday") == 0 && out.entries[0].name_len == 9
	              && strcmp(out.entries[0].kind, "video") == 0 && out.entries[0].size == 20000u
	              && out.entries[0].duration_ms == 120000u && out.entries[0].holders == 2
	              && out.entries[0].held_here && !out.entries[0].arriving_permille && out.entries[0].detail
	              && !out.entries[1].held_here && out.entries[1].arriving_permille == 500
	              && out.entries[1].name_len == 0 && held.asked[0][0] == 0x01 && held.asked[0][1] == 0x80,
	      "the library was not read in binary, every field of a row as sent");
	bon(&c, &cut);
	CHECK(fzn_rpc_library_list(&c, &out) != FZN_RPC_OK, "a library cut before its STATUS was read as whole");
	{
		struct script s = { { "ok 0 0", "ok " ID_A " " ID_B, "ok 0 0", "ok 0 0" }, 0, 4, 0, { { 0 } } };

		status_onto(&old, 0, FZN_STATUS_MALFORMED, "not a channel's asking");
		on(&c, &s);
		c.binary_answer = bscripted;
		c.binary_ctx = &old;
		CHECK(fzn_rpc_library_list(&c, &out) == FZN_RPC_OK && out.count == 0
		              && strncmp(s.asked[0], "list catalog", 12) == 0,
		      "a node reading no library in binary was not asked the text join");
	}
	fzn_rpc_library_list_release(&out);
}

/* ONE FILE'S ROW IN BINARY, sec 1190: the request names the root, the row
 * read as sent, a row for another file refused, a refusal said, and a node
 * reading no binary asked the text path. */
static void test_library_show_in_binary(void)
{
	static struct bscript held, wrong, absent, old;
	static fzn_rpc_library_show_resp_t out;
	uint8_t root[32], other[32], row[400], m[416];
	uint32_t row_len = 0, n = 0;

	memset(root, 0x7e, sizeof(root));
	memset(other, 0x7f, sizeof(other));
	if (fzn_files_local_library_row_build(row, sizeof(row), root, 20000u, 120000u, 2u, 1u, 0u,
	                                      (const uint8_t *)"video", 5, (const uint8_t *)"a holiday", 9, &row_len)
	            == SITU_OK
	    && fzn_files_local_message_build_library_row(m, sizeof(m), (uint8_t)FZN_CMD_FILES, row, row_len, &n)
	               == SITU_OK)
		framed(&held, 0, m, n);
	if (fzn_files_local_library_row_build(row, sizeof(row), other, 1u, 0u, 1u, 1u, 0u, NULL, 0, NULL, 0,
	                                      &row_len)
	            == SITU_OK
	    && fzn_files_local_message_build_library_row(m, sizeof(m), (uint8_t)FZN_CMD_FILES, row, row_len, &n)
	               == SITU_OK)
		framed(&wrong, 0, m, n);
	status_onto(&held, 0, FZN_STATUS_OK, NULL);
	status_onto(&wrong, 0, FZN_STATUS_OK, NULL);
	bon(&c, &held);
	CHECK(fzn_rpc_library_show(&c, root, &out) == FZN_RPC_OK && out.root[0] == 0x7e
	              && strcmp(out.name, "a holiday") == 0 && out.name_len == 9 && strcmp(out.kind, "video") == 0
	              && out.size == 20000u && out.duration_ms == 120000u && out.holders == 2 && out.held_here
	              && held.asked_len[0] == 34u && held.asked[0][0] == 0x01 && held.asked[0][1] == 0x82
	              && held.asked[0][2] == 0x7e && held.asked[0][33] == 0x7e,
	      "one file was not read in binary, by its root, every field as sent");
	bon(&c, &wrong);
	CHECK(fzn_rpc_library_show(&c, root, &out) != FZN_RPC_OK, "another file's row was read as the one asked");
	status_onto(&absent, 0, FZN_STATUS_ERROR, "that file is not in the library");
	bon(&c, &absent);
	CHECK(fzn_rpc_library_show(&c, root, &out) == FZN_RPC_ERR_STORAGE_IO
	              && strstr(c.error, "not in the library"),
	      "a file the node does not list was not said so");
	{
		struct script s = { { "ok 0 0" }, 0, 1, 0, { { 0 } } };

		status_onto(&old, 0, FZN_STATUS_MALFORMED, "not a channel's asking");
		on(&c, &s);
		c.binary_answer = bscripted;
		c.binary_ctx = &old;
		CHECK(fzn_rpc_library_show(&c, root, &out) != FZN_RPC_OK
		              && strncmp(s.asked[0], "list catalog", 12) == 0,
		      "a node reading no library in binary was not asked the text path");
	}
}

/* ONE FILE'S STATE IN BINARY, sec 1203: the request names the root, a
 * part-held row read as sent, ok alone read as not here, a second row and
 * a reply cut before its STATUS refused, a refusal said, and a node reading
 * no binary asked the verb. */
static void test_file_status_in_binary(void)
{
	static struct bscript part, whole, absent, two, cut, refused, old;
	static fzn_rpc_blob_status_resp_t out;
	uint8_t root[32], row[64], m[80];
	uint32_t row_len = 0, n = 0;

	memset(root, 0x6d, sizeof(root));
	if (fzn_files_local_file_row_build(row, sizeof(row), 2u, 3u, 40000u, 1u, 0u, 1u, 1u, &row_len) == SITU_OK
	    && fzn_files_local_message_build_file_row(m, sizeof(m), (uint8_t)FZN_CMD_FILES, row, row_len, &n)
	               == SITU_OK) {
		framed(&part, 0, m, n);
		framed(&two, 0, m, n);
		framed(&two, 0, m, n);
		framed(&cut, 0, m, n);
	}
	if (fzn_files_local_file_row_build(row, sizeof(row), 3u, 3u, 40000u, 2u, 1u, 0u, 0u, &row_len) == SITU_OK
	    && fzn_files_local_message_build_file_row(m, sizeof(m), (uint8_t)FZN_CMD_FILES, row, row_len, &n)
	               == SITU_OK)
		framed(&whole, 0, m, n);
	status_onto(&part, 0, FZN_STATUS_OK, NULL);
	status_onto(&whole, 0, FZN_STATUS_OK, NULL);
	status_onto(&two, 0, FZN_STATUS_OK, NULL);
	status_onto(&absent, 0, FZN_STATUS_OK, NULL);
	bon(&c, &part);
	CHECK(fzn_rpc_blob_status(&c, root, &out) == FZN_RPC_OK && out.known && !out.complete
	              && out.leaves_held == 2u && out.leaf_count == 3u && out.byte_len == 40000u
	              && out.tier == FZN_RPC_BLOB_TIER_PRIVATE && part.asked_len[0] == 34u
	              && part.asked[0][0] == 0x01 && part.asked[0][1] == 0x83 && part.asked[0][2] == 0x6d
	              && part.asked[0][33] == 0x6d,
	      "a file part here was not read in binary, by its root, every field as sent");
	bon(&c, &whole);
	CHECK(fzn_rpc_blob_status(&c, root, &out) == FZN_RPC_OK && out.known && out.complete
	              && out.leaves_held == 3u && out.tier == FZN_RPC_BLOB_TIER_PUBLIC,
	      "a file whole here, served to every contact, was not read so");
	bon(&c, &absent);
	CHECK(fzn_rpc_blob_status(&c, root, &out) == FZN_RPC_OK && !out.known,
	      "a file the node neither holds nor fetches was not read as unknown");
	bon(&c, &two);
	CHECK(fzn_rpc_blob_status(&c, root, &out) != FZN_RPC_OK && !out.known,
	      "two rows for one file were read as an answer");
	bon(&c, &cut);
	CHECK(fzn_rpc_blob_status(&c, root, &out) != FZN_RPC_OK && !out.known,
	      "a state cut before its STATUS was read as whole");
	status_onto(&refused, 0, FZN_STATUS_ERROR, "the file's state would not read");
	bon(&c, &refused);
	CHECK(fzn_rpc_blob_status(&c, root, &out) == FZN_RPC_ERR_STORAGE_IO && strstr(c.error, "would not read"),
	      "a refusal was not said");
	{
		struct script s = { { "ok 1 3 40000 partial private 0" }, 0, 1, 0, { { 0 } } };

		status_onto(&old, 0, FZN_STATUS_MALFORMED, "not a channel's asking");
		on(&c, &s);
		c.binary_answer = bscripted;
		c.binary_ctx = &old;
		CHECK(fzn_rpc_blob_status(&c, root, &out) == FZN_RPC_OK && out.known && out.leaves_held == 1u
		              && strncmp(s.asked[0], "get file 6d6d", 13) == 0,
		      "a node reading no file state in binary was not asked the verb");
	}
}

/* THE NOTEBOOK'S WRITES IN BINARY, sec 1218: an add's id read from its
 * row, a change's request bytes, a refusal in the node's words, a second
 * row refused, and a node reading no binary asked the verb. */
static void test_note_writes_in_binary(void)
{
	static struct bscript added, ok, refused, two, old;
	uint8_t id[32], got[32], row[64], m[80];
	uint32_t row_len = 0, n = 0;

	memset(id, 0x4d, sizeof(id));
	if (fzn_notes_local_added_build(row, sizeof(row), id, &row_len) == SITU_OK
	    && fzn_notes_local_message_build_added(m, sizeof(m), (uint8_t)FZN_CMD_NOTES, row, row_len, &n) == SITU_OK) {
		framed(&added, 0, m, n);
		framed(&two, 0, m, n);
		framed(&two, 0, m, n);
	}
	status_onto(&added, 0, FZN_STATUS_OK, NULL);
	status_onto(&two, 0, FZN_STATUS_OK, NULL);
	status_onto(&ok, 0, FZN_STATUS_OK, NULL);
	status_onto(&refused, 0, FZN_STATUS_ERROR, "no such note");
	bon(&c, &added);
	CHECK(fzn_rpc_note_add(&c, NULL, 2u, "shop", 4u, got) == FZN_RPC_OK && got[0] == 0x4d && got[31] == 0x4d
	              && added.asked[0][0] == 0x08 && added.asked[0][1] == 0x89 && added.asked[0][2] == 0
	              && added.asked[0][35] == 2 && added.asked[0][36] == 4,
	      "an add was not asked in binary, its id read from its row");
	bon(&c, &two);
	CHECK(fzn_rpc_note_add(&c, NULL, 1u, "x", 1u, got) != FZN_RPC_OK, "two ids for one add were read as an answer");
	bon(&c, &ok);
	CHECK(fzn_rpc_note_set(&c, id, FZN_RPC_NOTE_SET_TRASH, NULL, 0) == FZN_RPC_OK && ok.asked[0][1] == 0x8b
	              && ok.asked[0][34] == 7,
	      "a trash was not asked in binary as field 7");
	bon(&c, &refused);
	CHECK(fzn_rpc_note_item(&c, id, FZN_RPC_NOTE_ITEM_TICK, 3u, NULL, 0) == FZN_RPC_ERR_STORAGE_IO
	              && strstr(c.error, "no such note"),
	      "a refused item was not said in the node's words");
	{
		struct script s = { { "ok" }, 0, 1, 0, { { 0 } } };

		status_onto(&old, 0, FZN_STATUS_MALFORMED, "not a notes request");
		on(&c, &s);
		c.binary_answer = bscripted;
		c.binary_ctx = &old;
		CHECK(fzn_rpc_note_set(&c, id, FZN_RPC_NOTE_SET_PIN, NULL, 0) == FZN_RPC_OK
		              && strncmp(s.asked[0], "set note 4d4d", 13) == 0 && strstr(s.asked[0], " pin"),
		      "a node reading no binary was not asked the verb");
	}
}

/* THE NOTES UNDER A PARENT IN BINARY, sec 1191: the request's sharer and
 * parent, every field read, a title past the write bound listed whole
 * (sec 1194), the pending bit said as `pending`, a listing
 * cut before its STATUS refused, and an old node asked the verbs. */
static void test_notes_in_binary(void)
{
	static struct bscript held, cut, old;
	static fzn_rpc_notes_list_resp_t out;
	uint8_t id[32], parent[32], sharer[32], row[1400], m[1416];
	char title[200];
	uint32_t row_len = 0, n = 0;

	memset(id, 0x5a, sizeof(id));
	memset(parent, 0x3c, sizeof(parent));
	memset(sharer, 0xc4, sizeof(sharer));
	memset(title, 'x', sizeof(title));
	memcpy(title + 98, "\xc3\xa9", 2); /* an e-acute past the write bound of 100, listed */
	if (fzn_notes_local_note_row_build(row, sizeof(row), id, 2u, 0x81u, 1u, 0u, (const uint8_t *)"milk", 4,
	                                   (const uint8_t *)"a\0b", 3, &row_len)
	            == SITU_OK
	    && fzn_notes_local_message_build_note_row(m, sizeof(m), (uint8_t)FZN_CMD_NOTES, row, row_len, &n)
	               == SITU_OK) {
		framed(&held, 0, m, n);
		framed(&cut, 0, m, n);
	}
	if (fzn_notes_local_note_row_build(row, sizeof(row), parent, 1u, 0u, 0u, 1u, (const uint8_t *)title, 200,
	                                   NULL, 0, &row_len)
	            == SITU_OK
	    && fzn_notes_local_message_build_note_row(m, sizeof(m), (uint8_t)FZN_CMD_NOTES, row, row_len, &n)
	               == SITU_OK)
		framed(&held, 0, m, n);
	status_onto(&held, 0, FZN_STATUS_OK, NULL);
	bon(&c, &held);
	CHECK(fzn_rpc_notes_list(&c, parent, sharer, 0, &out) == FZN_RPC_OK && out.count == 2
	              && out.entries[0].id[0] == 0x5a && out.entries[0].parent[0] == 0x3c
	              && strcmp(out.entries[0].title, "milk") == 0 && out.entries[0].content_type == 2
	              && out.entries[0].flags == 0x01 && out.entries[0].pending && !out.entries[1].pending
	              && out.entries[0].reachable && !out.entries[0].contested
	              && out.entries[0].labels_len == 3 && memcmp(out.entries[0].labels, "a\0b", 3) == 0
	              && out.entries[1].order == 1 && out.entries[1].contested && !out.entries[1].reachable
	              && out.entries[1].title_len == 200 && held.asked_len[0] == 66u && held.asked[0][0] == 0x08
	              && held.asked[0][1] == 0x80 && held.asked[0][2] == 0xc4 && held.asked[0][34] == 0x3c,
	      "the notes were not read in binary, every field, a long title whole, pending said");
	bon(&c, &cut);
	CHECK(fzn_rpc_notes_list(&c, parent, NULL, 0, &out) != FZN_RPC_OK
	              && cut.asked[0][2] == 0 && cut.asked[0][33] == 0,
	      "a notes listing cut before its STATUS was read as whole, or this user's own not asked as zero");
	{
		struct script s = { { "ok 0 0" }, 0, 1, 0, { { 0 } } };

		status_onto(&old, 0, FZN_STATUS_MALFORMED, "not a channel's asking");
		on(&c, &s);
		c.binary_answer = bscripted;
		c.binary_ctx = &old;
		CHECK(fzn_rpc_notes_list(&c, parent, NULL, 0, &out) == FZN_RPC_OK && out.count == 0
		              && strncmp(s.asked[0], "list note", 9) == 0,
		      "a node reading no notes in binary was not asked the verbs");
	}
	fzn_rpc_notes_list_release(&out);
}

/* A GROUP'S NOTEBOOK IN BINARY, sec 1192: the group found by its id, its
 * sharers listed, each sharer's tree asked by key in binary, the rows of
 * every tree that answered together and one that holds nothing passed over. */
static void test_group_notebook_in_binary(void)
{
	static struct bscript b;
	static fzn_rpc_notes_list_resp_t out;
	uint8_t chat[32], top[32], id[32], row[160], m[176];
	uint32_t row_len = 0, n = 0;
	struct script s = { { "ok 2 0 " ID_A ",contact,ann " ID_B ",group,bob" }, 0, 1, 0, { { 0 } } };

	memset(chat, 0xcd, sizeof(chat));
	memset(top, 0, sizeof(top));
	if (fzn_groups_local_row_build(row, sizeof(row), chat, 3u, 1u, 7u, (const uint8_t *)"team", 4, &row_len)
	            == SITU_OK
	    && fzn_groups_local_message_build_row(m, sizeof(m), (uint8_t)FZN_CMD_GROUPS, row, row_len, &n) == SITU_OK)
		framed(&b, 0, m, n);
	status_onto(&b, 0, FZN_STATUS_OK, NULL);
	memset(id, 0x5a, sizeof(id));
	if (fzn_notes_local_note_row_build(row, sizeof(row), id, 1u, 0u, 0u, 0u, (const uint8_t *)"ann's", 5, NULL, 0,
	                                   &row_len)
	            == SITU_OK
	    && fzn_notes_local_message_build_note_row(m, sizeof(m), (uint8_t)FZN_CMD_NOTES, row, row_len, &n)
	               == SITU_OK)
		framed(&b, 1, m, n);
	status_onto(&b, 1, FZN_STATUS_OK, NULL);
	status_onto(&b, 2, FZN_STATUS_ERROR, "no such note");
	on(&c, &s);
	c.binary_answer = bscripted;
	c.binary_ctx = &b;
	CHECK(fzn_rpc_notes_list(&c, top, chat, 1, &out) == FZN_RPC_OK && out.count == 1
	              && strcmp(out.entries[0].title, "ann's") == 0 && strncmp(s.asked[0], "list sharer @team", 17) == 0
	              && b.asked_len[1] == 66u && b.asked[1][0] == 0x08 && b.asked[1][1] == 0x80
	              && b.asked[1][2] == 0xaa && b.asked[1][33] == 0x01 && b.asked_len[2] == 66u
	              && b.asked[2][2] == 0xbb,
	      "a group's notebook was not each sharer's tree asked in binary, by key");
	fzn_rpc_notes_list_release(&out);
}

/* THE NOTES' STAMP IN BINARY, sec 1199: the request's two bytes, the
 * number read, a stamp cut before its STATUS or sent twice refused, and an
 * old node asked `get notes`. */
static void test_notes_stamp_in_binary(void)
{
	static struct bscript held, cut, twice, old;
	uint8_t row[16], m[32];
	uint32_t row_len = 0, n = 0;
	uint64_t stamp = 0;

	if (fzn_notes_local_stamp_row_build(row, sizeof(row), 300u, &row_len) == SITU_OK
	    && fzn_notes_local_message_build_stamp_row(m, sizeof(m), (uint8_t)FZN_CMD_NOTES, row, row_len, &n)
	               == SITU_OK) {
		framed(&held, 0, m, n);
		framed(&cut, 0, m, n);
		framed(&twice, 0, m, n);
		framed(&twice, 0, m, n);
	}
	status_onto(&held, 0, FZN_STATUS_OK, NULL);
	status_onto(&twice, 0, FZN_STATUS_OK, NULL);
	bon(&c, &held);
	CHECK(fzn_rpc_notes_stamp(&c, &stamp) == FZN_RPC_OK && stamp == 300u && held.asked_len[0] == 2u
	              && held.asked[0][0] == 0x08 && held.asked[0][1] == 0x82,
	      "the notes' stamp was not read in binary");
	bon(&c, &cut);
	CHECK(fzn_rpc_notes_stamp(&c, &stamp) != FZN_RPC_OK, "a stamp cut before its STATUS was read as whole");
	bon(&c, &twice);
	CHECK(fzn_rpc_notes_stamp(&c, &stamp) != FZN_RPC_OK, "two stamps in one answer were taken");
	{
		struct script s = { { "ok 42" }, 0, 1, 0, { { 0 } } };

		status_onto(&old, 0, FZN_STATUS_MALFORMED, "not a channel's asking");
		on(&c, &s);
		c.binary_answer = bscripted;
		c.binary_ctx = &old;
		CHECK(fzn_rpc_notes_stamp(&c, &stamp) == FZN_RPC_OK && stamp == 42u && !strcmp(s.asked[0], "get notes"),
		      "an old node was not asked the stamp in text");
	}
}

/* THIS USER'S SHARES IN BINARY, sec 1200: a contact's row by name, a
 * group's with its catching up, the request's two bytes, a listing cut
 * before its STATUS refused, and an old node asked `list share`. */
static void test_shares_in_binary(void)
{
	static struct bscript held, cut, old;
	static fzn_rpc_notes_shares_resp_t out;
	uint8_t sub[32], row[128], m[144];
	uint32_t row_len = 0, n = 0;

	memset(sub, 0x3c, sizeof(sub));
	if (fzn_notes_local_share_row_build(row, sizeof(row), sub, 0u, 0u, (const uint8_t *)"carol", 5, &row_len)
	            == SITU_OK
	    && fzn_notes_local_message_build_share_row(m, sizeof(m), (uint8_t)FZN_CMD_NOTES, row, row_len, &n) == SITU_OK) {
		framed(&held, 0, m, n);
		framed(&cut, 0, m, n);
	}
	if (fzn_notes_local_share_row_build(row, sizeof(row), sub, 1u, 1u, (const uint8_t *)"family", 6, &row_len)
	            == SITU_OK
	    && fzn_notes_local_message_build_share_row(m, sizeof(m), (uint8_t)FZN_CMD_NOTES, row, row_len, &n) == SITU_OK)
		framed(&held, 0, m, n);
	status_onto(&held, 0, FZN_STATUS_OK, NULL);
	bon(&c, &held);
	CHECK(fzn_rpc_notes_shares_outgoing(&c, &out) == FZN_RPC_OK && out.count == 2 && out.entries[0].subtree[0] == 0x3c
	              && strcmp(out.entries[0].peer, "carol") == 0 && !out.entries[0].to_group
	              && strcmp(out.entries[1].peer, "family") == 0 && out.entries[1].to_group
	              && out.entries[1].backfill && held.asked_len[0] == 2u && held.asked[0][1] == 0x84,
	      "this user's shares were not read in binary, a group's with its catching up");
	bon(&c, &cut);
	CHECK(fzn_rpc_notes_shares_outgoing(&c, &out) != FZN_RPC_OK, "a shares listing cut before its STATUS was read as whole");
	{
		struct script s = { { "ok 1 0 3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c,@family,0" },
			            0, 1, 0, { { 0 } } };

		status_onto(&old, 0, FZN_STATUS_MALFORMED, "not a channel's asking");
		on(&c, &s);
		c.binary_answer = bscripted;
		c.binary_ctx = &old;
		CHECK(fzn_rpc_notes_shares_outgoing(&c, &out) == FZN_RPC_OK && out.count == 1 && out.entries[0].to_group
		              && !out.entries[0].backfill && !strcmp(s.asked[0], "list share 0"),
		      "an old node was not asked `list share`");
	}
}

/* A NOTE'S FIELDS ROW framed onto answer `i`, sec 1201, its text `length`. */
static void fields_onto(struct bscript *s, size_t i, uint32_t length, const uint8_t *ref, uint32_t ref_len)
{
	uint8_t parent[32], row[400], m[416];
	uint32_t row_len = 0, n = 0;

	memset(parent, 0xcd, sizeof(parent));
	if (fzn_notes_local_note_fields_build(row, sizeof(row), 1u, 0x01u, 1000u, 2000u, parent, 0u, length, 1u, 0u,
	                                      0xFF8000C0u, (const uint8_t *)"milk", 4, (const uint8_t *)"a\0b", 3, ref,
	                                      ref_len, &row_len)
	            == SITU_OK
	    && fzn_notes_local_message_build_note_fields(m, sizeof(m), (uint8_t)FZN_CMD_NOTES, row, row_len, &n)
	               == SITU_OK)
		framed(s, i, m, n);
}

static void piece_onto(struct bscript *s, size_t i, uint32_t at, const char *text)
{
	uint8_t row[64], m[80];
	uint32_t row_len = 0, n = 0;

	if (fzn_notes_local_note_text_build(row, sizeof(row), at, (const uint8_t *)text, (uint32_t)strlen(text),
	                                    &row_len)
	            == SITU_OK
	    && fzn_notes_local_message_build_note_text(m, sizeof(m), (uint8_t)FZN_CMD_NOTES, row, row_len, &n)
	               == SITU_OK)
		framed(s, i, m, n);
}

/* ONE NOTE WHOLE IN BINARY, sec 1201: fields, meta and text in pieces read,
 * the request's sharer and id, a piece out of order and a text short of its
 * length each refused, and an old node said to read none. */
static void test_note_open_in_binary(void)
{
	static struct bscript held, gap, shorter, old;
	static fzn_rpc_note_open_t out;
	uint8_t id[32], sharer[32];

	memset(id, 0x5a, sizeof(id));
	memset(sharer, 0xc4, sizeof(sharer));
	fields_onto(&held, 0, 11u, NULL, 0);
	piece_onto(&held, 0, 0, "two pi");
	piece_onto(&held, 0, 6, "nts");
	piece_onto(&held, 0, 9, ", ");
	status_onto(&held, 0, FZN_STATUS_OK, NULL);
	bon(&c, &held);
	CHECK(fzn_rpc_note_open(&c, sharer, id, &out) == FZN_RPC_OK && out.content_type == 1 && out.flags == 0x01
	              && out.created_ms == 1000u && out.edited_ms == 2000u && out.parent[0] == 0xcd && !out.pending
	              && out.length == 11u && out.reachable && !out.contested && out.colour == 0xFF8000C0u
	              && !strcmp(out.title, "milk") && out.labels_len == 3 && !memcmp(out.labels, "a\0b", 3)
	              && out.ref_len == 0 && out.text_len == 11u && !strcmp(out.text, "two pints, ")
	              && held.asked_len[0] == 66u && held.asked[0][1] == 0x86 && held.asked[0][2] == 0xc4
	              && held.asked[0][34] == 0x5a,
	      "a note was not read whole in binary, its text from its pieces");
	fields_onto(&gap, 0, 11u, NULL, 0);
	/* OVERLAPPING THE LAST, its bytes still adding up to the length: only
	 * the order says it is no text. */
	piece_onto(&gap, 0, 0, "two pi");
	piece_onto(&gap, 0, 5, "nts, ");
	status_onto(&gap, 0, FZN_STATUS_OK, NULL);
	bon(&c, &gap);
	CHECK(fzn_rpc_note_open(&c, NULL, id, &out) != FZN_RPC_OK, "a piece not starting where the last ended was taken");
	fields_onto(&shorter, 0, 11u, NULL, 0);
	piece_onto(&shorter, 0, 0, "two pi");
	status_onto(&shorter, 0, FZN_STATUS_OK, NULL);
	bon(&c, &shorter);
	CHECK(fzn_rpc_note_open(&c, NULL, id, &out) != FZN_RPC_OK, "a text short of its length was taken");
	status_onto(&old, 0, FZN_STATUS_MALFORMED, "not a channel's asking");
	bon(&c, &old);
	CHECK(fzn_rpc_note_open(&c, NULL, id, &out) == FZN_RPC_ERR_UNKNOWN_MSG_TYPE,
	      "a node reading no note in binary was not said so");
	fzn_rpc_note_open_release(&out);
}

/* ONE SIBLING framed onto answer `i`, sec 1176. */
static void sibling_onto(struct bscript *s, size_t i, uint8_t first, uint8_t paired, const char *where,
                         const char *name)
{
	uint8_t key[32], row[400], m[420];
	uint32_t row_len = 0, n = 0;

	memset(key, first, sizeof(key));
	if (fzn_members_local_sibling_row_build(row, sizeof(row), key, paired, 1u, 42u, (const uint8_t *)where,
	                                        (uint32_t)strlen(where), (const uint8_t *)name, (uint32_t)strlen(name),
	                                        &row_len)
	            != SITU_OK
	    || fzn_members_local_message_build_sibling_row(m, sizeof(m), (uint8_t)FZN_CMD_MEMBERS, row, row_len, &n)
	               != SITU_OK)
		return;
	framed(s, i, m, n);
}

/* THIS ESTATE'S OTHER HOSTS IN BINARY, sec 1176: a named host by its name,
 * address and pairing; an unnamed one by its key's first sixteen, as the
 * text row is read; the request's bytes; a listing cut before its STATUS
 * refused; a node reading no binary asked by the verb. */
static void test_siblings_in_binary(void)
{
	static struct bscript held, cut, old;
	static fzn_rpc_sibling_list_resp_t out;

	sibling_onto(&held, 0, 0x5a, 1u, "10.0.0.2:7000", "my laptop");
	sibling_onto(&held, 0, 0x6b, 0u, "", "");
	status_onto(&held, 0, FZN_STATUS_OK, NULL);
	bon(&c, &held);
	CHECK(fzn_rpc_sibling_list(&c, &out) == FZN_RPC_OK && out.count == 2 && out.entries[0].host_pubkey[0] == 0x5a
	              && strcmp(out.entries[0].name, "my laptop") == 0 && strcmp(out.entries[0].address, "10.0.0.2:7000") == 0
	              && out.entries[0].valid && strcmp(out.entries[1].name, "6b6b6b6b6b6b6b6b") == 0
	              && out.entries[1].address_len == 0 && !out.entries[1].valid && held.asked[0][0] == 0x09
	              && held.asked[0][1] == 0x80,
	      "the siblings were not read in binary, by name, address and pairing");
	sibling_onto(&cut, 0, 0x5a, 1u, "", "");
	bon(&c, &cut);
	CHECK(fzn_rpc_sibling_list(&c, &out) != FZN_RPC_OK, "a siblings listing cut before its STATUS was read as whole");
	{
		struct script s = { { "ok 0 0" }, 0, 1, 0, { { 0 } } };

		status_onto(&old, 0, FZN_STATUS_MALFORMED, "not a channel's asking");
		on(&c, &s);
		c.binary_answer = bscripted;
		c.binary_ctx = &old;
		CHECK(fzn_rpc_sibling_list(&c, &out) == FZN_RPC_OK && out.count == 0
		              && strcmp(s.asked[0], "list sibling 0") == 0,
		      "a node reading no siblings in binary was not asked by the verb");
	}
}

/* ONE TRANSFER ROW framed onto answer `i`, sec 1177. */
static void transfer_onto(struct bscript *s, size_t i, const char *family, const char *peer, int keyed,
                          uint64_t up, uint64_t down)
{
	uint8_t key[32], row[192], m[200];
	uint32_t row_len = 0, n = 0;

	memset(key, keyed ? 0x3c : 0, sizeof(key));
	if (fzn_meter_local_transfer_row_build(row, sizeof(row), (const uint8_t *)family, (uint32_t)strlen(family),
	                                       (const uint8_t *)peer, (uint32_t)strlen(peer), (uint8_t)(keyed ? 1 : 0),
	                                       key, up, down, 3u, 4u, 1700000000u, 1700000060u, &row_len)
	            != SITU_OK
	    || fzn_meter_local_message_build_transfer_row(m, sizeof(m), (uint8_t)FZN_CMD_TRANSFER, row, row_len, &n)
	               != SITU_OK)
		return;
	framed(s, i, m, n);
}

/* WHAT THE NODE HAS MOVED, IN BINARY, sec 1177: a family's totals, then two
 * rows with one host and one file between them -- folded into the hosts
 * and the family's rates as the text rows are -- the request's bytes; a
 * listing cut before its STATUS refused; a family after a row refused. */
static void test_transfers_in_binary(void)
{
	static struct bscript held, cut, late;
	static fzn_rpc_transfer_list_resp_t out;
	uint8_t row[64], m[80];
	uint32_t row_len = 0, n = 0;

	if (fzn_meter_local_family_row_build(row, sizeof(row), (const uint8_t *)"files", 5u, 4096u, 1048576u, &row_len)
	            == SITU_OK
	    && fzn_meter_local_message_build_family_row(m, sizeof(m), (uint8_t)FZN_CMD_TRANSFER, row, row_len, &n)
	               == SITU_OK) {
		framed(&held, 0, m, n);
		framed(&cut, 0, m, n);
	}
	transfer_onto(&held, 0, "files", "10.0.0.2:7000", 1, 100u, 200u);
	transfer_onto(&held, 0, "files", "10.0.0.2:7000", 0, 5u, 6u);
	status_onto(&held, 0, FZN_STATUS_OK, NULL);
	bon(&c, &held);
	CHECK(fzn_rpc_transfer_list(&c, &out) == FZN_RPC_OK && out.subsystem_count == 1
	              && strcmp(out.subsystems[0].family, "files") == 0 && out.subsystems[0].bytes_up == 4096u
	              && out.subsystems[0].bytes_down == 1048576u && out.subsystems[0].rows == 2
	              && out.subsystems[0].rate_up == 6u && out.count == 2 && out.entries[0].key_len == 32
	              && out.entries[0].key[0] == 0x3c && out.entries[1].key_len == 0 && out.host_count == 1
	              && out.hosts[0].bytes_up == 105u && out.hosts[0].rows == 2 && out.rows_total == 2
	              && out.entries[0].last_seen == 1700000060u && held.asked[0][0] == 0x17 && held.asked[0][1] == 0x80,
	      "the transfers were not read in binary, folded into hosts and families as the text rows are");
	bon(&c, &cut);
	CHECK(fzn_rpc_transfer_list(&c, &out) != FZN_RPC_OK, "a transfers listing cut before its STATUS was read as whole");
	transfer_onto(&late, 0, "files", "10.0.0.2:7000", 0, 1u, 1u);
	if (n) framed(&late, 0, m, n);
	status_onto(&late, 0, FZN_STATUS_OK, NULL);
	bon(&c, &late);
	CHECK(fzn_rpc_transfer_list(&c, &out) != FZN_RPC_OK, "a family's totals after its rows were taken");
}

/* ONE MEMBER framed onto answer `i`, sec 1179. */
static void member_onto(struct bscript *s, size_t i, const uint8_t key[32], uint8_t admin, const char *name)
{
	uint8_t row[96], m[112];
	uint32_t row_len = 0, n = 0;

	if (fzn_groups_local_member_row_build(row, sizeof(row), key, admin, (const uint8_t *)name,
	                                      (uint32_t)strlen(name), &row_len) != SITU_OK
	    || fzn_groups_local_message_build_member_row(m, sizeof(m), (uint8_t)FZN_CMD_GROUPS, row, row_len, &n)
	               != SITU_OK)
		return;
	framed(s, i, m, n);
}

/* A GROUP'S ROSTER IN BINARY, sec 1179: a group asked by its name is found
 * among this user's groups and its roster asked by id; each member read
 * with its root key, its name where it has one, and this user an admin; a
 * roster cut before its STATUS refused. */
static void test_roster_in_binary(void)
{
	static struct bscript held, cut;
	static fzn_rpc_group_show_resp_t out;
	uint8_t id[32], self[32], carol[32], row[96], m[112];
	uint32_t row_len = 0, n = 0;
	struct script s = { { "ok " ID_A " " ID_B, "ok " ID_A " " ID_B }, 0, 2, 0, { { 0 } } };

	memset(id, 0xcd, sizeof(id));
	memset(self, 0, sizeof(self));
	self[0] = 0xbb;
	self[31] = 0x02;
	memset(carol, 0x5a, sizeof(carol));
	if (fzn_groups_local_row_build(row, sizeof(row), id, 2u, 1u, 7u, (const uint8_t *)"team", 4, &row_len)
	            == SITU_OK
	    && fzn_groups_local_message_build_row(m, sizeof(m), (uint8_t)FZN_CMD_GROUPS, row, row_len, &n) == SITU_OK) {
		framed(&held, 0, m, n);
		framed(&cut, 0, m, n);
	}
	status_onto(&held, 0, FZN_STATUS_OK, NULL);
	status_onto(&cut, 0, FZN_STATUS_OK, NULL);
	member_onto(&held, 1, self, 1u, "");
	member_onto(&held, 1, carol, 0u, "carol");
	status_onto(&held, 1, FZN_STATUS_OK, NULL);
	member_onto(&cut, 1, carol, 0u, "carol");
	on(&c, &s);
	c.binary_answer = bscripted;
	c.binary_ctx = &held;
	CHECK(fzn_rpc_group_show(&c, "team", 4, &out) == FZN_RPC_OK && out.member_count == 2 && out.is_admin
	              && memcmp(out.members[0].root_pubkey, self, 32) == 0 && out.members[0].admin
	              && out.members[1].root_pubkey[0] == 0x5a && strcmp(out.members[1].name, "carol") == 0
	              && !out.members[1].admin && out.chat_id[0] == 0xcd && memcmp(out.self_root, self, 32) == 0
	              && held.asked_len[1] == 34 && held.asked[1][0] == 0x0d && held.asked[1][1] == 0x82
	              && held.asked[1][2] == 0xcd,
	      "a group's roster was not read in binary by its id, each member by root key");
	c.binary_ctx = &cut;
	CHECK(fzn_rpc_group_show(&c, "team", 4, &out) != FZN_RPC_OK, "a roster cut before its STATUS was read as whole");
	free(out.members);
}

/* THE DELIVERIES IN BINARY, sec 1180: everyone's lines asked once, this
 * user's own to a contact kept while not settled -- one delivered, one not
 * yet -- and a settled one, an incoming one and a group's left out. */
static void test_deliveries_in_binary(void)
{
	static struct bscript lines;
	static fzn_rpc_delivery_list_resp_t out;

	line_onto(&lines, 0, 0xab, 0, 1, 1, "alice", "", "delivered");
	line_onto(&lines, 0, 0xab, 0, 1, 2, "alice", "", "settled");
	line_onto(&lines, 0, 0xab, 0, 0, 0, "alice", "", "incoming");
	line_onto(&lines, 0, 0xcd, 1, 1, 1, "team", "", "a group's");
	line_onto(&lines, 0, 0xef, 0, 1, 0, "bob", "", "on its way");
	status_onto(&lines, 0, FZN_STATUS_OK, NULL);
	bon(&c, &lines);
	CHECK(fzn_rpc_delivery_list(&c, &out) == FZN_RPC_OK && out.count == 2 && out.entries[0].delivered
	              && strcmp(out.entries[0].peer_name, "alice") == 0 && out.entries[0].commitment[0] == 0x54
	              && out.entries[0].first_sent == 1700000000u && !out.entries[1].delivered
	              && strcmp(out.entries[1].peer_name, "bob") == 0,
	      "the deliveries were not this user's unsettled lines to a contact, read in binary");
	CHECK(lines.asked_len[0] == 41 && lines.asked[0][0] == 0x0a && lines.asked[0][1] == 0x84
	              && lines.asked[0][2] == 0 && lines.asked[0][39] == 0xff && lines.asked[0][40] == 0xff,
	      "the deliveries were not asked as everyone's lines, a full page at a time");
}

/* ONE LEG framed onto answer `i`, sec 1183; with sec 1210's figures, a
 * measured one's: asked 1.5 s ago, answered 2.5 s ago, one ask out, in
 * use, costing 43 ms, unlimited -- and an unmeasured one's: asked 2 s ago,
 * four lost in a row, no peer at it, its budget spent. */
static void leg_onto(struct bscript *s, size_t i, const char *address, uint8_t measured, uint64_t latency,
                     uint64_t loss, uint64_t seen, uint64_t age)
{
	uint8_t row[256], m[272];
	uint32_t row_len = 0, n = 0;

	if (fzn_reach_local_leg_row_build(row, sizeof(row), (const uint8_t *)address, (uint32_t)strlen(address),
	                                  measured, latency, loss, seen, age, 10u, 9u, 900u, 800u,
	                                  measured ? 1500u : 2000u, measured ? 2500u : 0u, measured ? 0u : 4u,
	                                  measured ? 1u : 0u, measured ? 1u : 0u, measured ? 43u : 0u,
	                                  measured ? 0u : 1000000u, measured ? 1700u : 1000000u, 86400000u, &row_len)
	            != SITU_OK
	    || fzn_reach_local_message_build_leg_row(m, sizeof(m), (uint8_t)FZN_CMD_REACH, row, row_len, &n) != SITU_OK)
		return;
	framed(s, i, m, n);
}

static void legs_summary_onto(struct bscript *s, size_t i, uint64_t unmeasured)
{
	uint8_t row[16], m[24];
	uint32_t row_len = 0, n = 0;

	if (fzn_reach_local_legs_summary_build(row, sizeof(row), unmeasured, &row_len) != SITU_OK
	    || fzn_reach_local_message_build_legs_summary(m, sizeof(m), (uint8_t)FZN_CMD_REACH, row, row_len, &n)
	               != SITU_OK)
		return;
	framed(s, i, m, n);
}

/* THE LEGS IN BINARY, sec 1183: the unmeasured count, a measured leg and
 * one nothing has been observed on, read as the text rows are, with sec
 * 1210's figures -- the last ANSWER's age, not the last observation's; a
 * row before the summary, and a listing cut before its STATUS, refused. */
static void test_legs_in_binary(void)
{
	static struct bscript held, early, late, cut;
	static fzn_rpc_leg_list_resp_t out;

	legs_summary_onto(&held, 0, 3u);
	leg_onto(&held, 0, "192.0.2.7:4000", 1u, 42u, 25u, 1u, 3u);
	leg_onto(&held, 0, "198.51.100.2:4000", 0u, 0u, 0u, 0u, 0u);
	status_onto(&held, 0, FZN_STATUS_OK, NULL);
	bon(&c, &held);
	CHECK(fzn_rpc_leg_list(&c, &out) == FZN_RPC_OK && out.count == 2 && out.unmeasured == 3
	              && strcmp(out.entries[0].address, "192.0.2.7:4000") == 0 && out.entries[0].rtt_ms == 42
	              && out.entries[0].loss_permille == 25 && out.entries[0].since_success_ms == 2500
	              && out.entries[0].sent == 10 && out.entries[0].replied == 9 && out.entries[1].observations == 0
	              && out.entries[1].since_success_ms == 0 && held.asked[0][0] == 0x0c && held.asked[0][1] == 0x80,
	      "the legs were not read in binary as the text rows are");
	CHECK(out.entries[0].since_attempt_ms == 1500 && out.entries[0].consecutive_failures == 0
	              && out.entries[0].outstanding && out.entries[0].in_use && out.entries[0].cost == 43
	              && out.entries[0].budget_limit == 0 && out.entries[0].budget_spent == 1700
	              && out.entries[0].budget_window_ms == 86400000u && out.entries[1].consecutive_failures == 4
	              && !out.entries[1].outstanding && !out.entries[1].in_use && out.entries[1].cost == 0
	              && out.entries[1].budget_limit == 1000000u && out.entries[1].budget_spent == 1000000u,
	      "a leg's sec 1210 figures were not read as sent");
	leg_onto(&early, 0, "192.0.2.7:4000", 1u, 42u, 25u, 1u, 3u);
	status_onto(&early, 0, FZN_STATUS_OK, NULL);
	bon(&c, &early);
	CHECK(fzn_rpc_leg_list(&c, &out) != FZN_RPC_OK, "a leg before the summary was taken");
	/* AND ONE BEFORE A SUMMARY THAT COMES AFTER IT: a listing out of order. */
	leg_onto(&late, 0, "192.0.2.7:4000", 1u, 42u, 25u, 1u, 3u);
	legs_summary_onto(&late, 0, 0u);
	status_onto(&late, 0, FZN_STATUS_OK, NULL);
	bon(&c, &late);
	CHECK(fzn_rpc_leg_list(&c, &out) != FZN_RPC_OK, "a leg before a later summary was taken");
	legs_summary_onto(&cut, 0, 0u);
	leg_onto(&cut, 0, "192.0.2.7:4000", 1u, 42u, 25u, 1u, 3u);
	bon(&c, &cut);
	CHECK(fzn_rpc_leg_list(&c, &out) != FZN_RPC_OK, "a legs listing cut before its STATUS was read as whole");
}

/* ONE CLOCK framed onto answer `i`, sec 1184. */
static void clock_onto(struct bscript *s, size_t i, uint8_t first, uint8_t ahead, uint64_t seconds, uint64_t at)
{
	uint8_t key[32], row[64], m[80];
	uint32_t row_len = 0, n = 0;

	memset(key, first, sizeof(key));
	if (fzn_time_local_clock_row_build(row, sizeof(row), key, ahead, seconds, at, &row_len) != SITU_OK
	    || fzn_time_local_message_build_clock_row(m, sizeof(m), (uint8_t)FZN_CMD_TIME, row, row_len, &n) != SITU_OK)
		return;
	framed(s, i, m, n);
}

/* THE CLOCKS IN BINARY, sec 1184: a peer ahead and one behind, each with
 * its seconds and when, the request's bytes; a cut listing refused. */
static void test_clocks_in_binary(void)
{
	static struct bscript held, cut;
	fzn_rpc_clock_list_t out = { NULL, 0 };

	clock_onto(&held, 0, 0x11, 1u, 42u, 1700000000u);
	clock_onto(&held, 0, 0x22, 0u, 7u, 1700000060u);
	status_onto(&held, 0, FZN_STATUS_OK, NULL);
	bon(&c, &held);
	CHECK(fzn_rpc_clock_list(&c, &out) == FZN_RPC_OK && out.count == 2 && out.rows[0].key[0] == 0x11
	              && out.rows[0].ahead && out.rows[0].seconds == 42u && out.rows[0].at == 1700000000u
	              && !out.rows[1].ahead && out.rows[1].seconds == 7u && held.asked[0][0] == 0x0f
	              && held.asked[0][1] == 0x80,
	      "the clocks were not read in binary, each peer's direction, seconds and when");
	fzn_rpc_clock_list_release(&out);
	clock_onto(&cut, 0, 0x11, 1u, 42u, 1700000000u);
	bon(&c, &cut);
	CHECK(fzn_rpc_clock_list(&c, &out) != FZN_RPC_OK, "a clocks listing cut before its STATUS was read as whole");
	fzn_rpc_clock_list_release(&out);
}

/* ONE HEAD OF A FORK framed onto answer `i`, sec 1187. */
static void fork_onto(struct bscript *s, size_t i, uint8_t host_byte, const char *subject, const char *value)
{
	uint8_t host[32], row[440], m[456];
	uint32_t row_len = 0, n = 0;

	memset(host, host_byte, sizeof(host));
	if (fzn_settings_local_fork_row_build(row, sizeof(row), (const uint8_t *)subject, (uint32_t)strlen(subject), host,
	                                      1700000000000ull, (const uint8_t *)"user", 4u, (const uint8_t *)value,
	                                      (uint32_t)strlen(value), &row_len) != SITU_OK
	    || fzn_settings_local_message_build_fork_row(m, sizeof(m), (uint8_t)FZN_CMD_SETTINGS, row, row_len, &n)
	               != SITU_OK)
		return;
	framed(s, i, m, n);
}

/* THE FORKS IN BINARY, sec 1187: both sides of a fork read with subject,
 * host, when and the value raw -- a space in it kept, which the text
 * escapes -- the request's bytes; a cut listing refused. */
static void test_forks_in_binary(void)
{
	static struct bscript held, cut;
	static fzn_rpc_fork_side_t sides[4];
	size_t count = 0;

	fork_onto(&held, 0, 0xaa, "host/name", "my laptop");
	fork_onto(&held, 0, 0xbb, "host/name", "laptop");
	status_onto(&held, 0, FZN_STATUS_OK, NULL);
	bon(&c, &held);
	CHECK(fzn_rpc_fork_list(&c, sides, 4, &count) == FZN_RPC_OK && count == 2
	              && strcmp(sides[0].subject, "host/name") == 0 && strcmp(sides[0].value, "my laptop") == 0
	              && sides[0].host[0] == 0xaa && sides[0].at == 1700000000000ull
	              && strcmp(sides[1].value, "laptop") == 0 && held.asked[0][0] == 0x18 && held.asked[0][1] == 0x80,
	      "the forks were not read in binary, each side with its subject, host and raw value");
	fork_onto(&cut, 0, 0xaa, "host/name", "my laptop");
	bon(&c, &cut);
	CHECK(fzn_rpc_fork_list(&c, sides, 4, &count) != FZN_RPC_OK, "a forks listing cut before its STATUS was read as whole");
}

/* WHAT THIS NODE HOLDS AND HAS GRANTED, IN BINARY, sec 1188: member held
 * by two hops, a name this client does not know passed over, a grant of
 * admin revoked; the requests' bytes; a cut listing refused. */
static void test_capabilities_in_binary(void)
{
	static struct bscript held, granted, cut;
	static fzn_rpc_cap_list_resp_t caps;
	static fzn_rpc_cap_granted_resp_t grants;
	uint8_t row[80], m[96], grantee[32];
	uint32_t row_len = 0, n = 0;

	if (fzn_members_local_capability_row_build(row, sizeof(row), (const uint8_t *)"member", 6u, 1u, 2u, 1700000000u,
	                                           &row_len) == SITU_OK
	    && fzn_members_local_message_build_capability_row(m, sizeof(m), (uint8_t)FZN_CMD_MEMBERS, row, row_len, &n)
	               == SITU_OK) {
		framed(&held, 0, m, n);
		framed(&cut, 0, m, n);
	}
	if (fzn_members_local_capability_row_build(row, sizeof(row), (const uint8_t *)"teleport", 8u, 1u, 1u, 0u,
	                                           &row_len) == SITU_OK
	    && fzn_members_local_message_build_capability_row(m, sizeof(m), (uint8_t)FZN_CMD_MEMBERS, row, row_len, &n)
	               == SITU_OK)
		framed(&held, 0, m, n);
	status_onto(&held, 0, FZN_STATUS_OK, NULL);
	bon(&c, &held);
	CHECK(fzn_rpc_cap_list(&c, &caps) == FZN_RPC_OK && caps.count == 1 && caps.entries[0].valid
	              && caps.entries[0].hop_count == 2 && caps.entries[0].expires_at == 1700000000u
	              && held.asked[0][0] == 0x09 && held.asked[0][1] == 0x82,
	      "the capabilities were not read in binary, an unknown name passed over");
	memset(grantee, 0x5a, sizeof(grantee));
	if (fzn_members_local_grant_row_build(row, sizeof(row), grantee, (const uint8_t *)"admin", 5u, 0u, 0u, &row_len)
	            == SITU_OK
	    && fzn_members_local_message_build_grant_row(m, sizeof(m), (uint8_t)FZN_CMD_MEMBERS, row, row_len, &n)
	               == SITU_OK)
		framed(&granted, 0, m, n);
	status_onto(&granted, 0, FZN_STATUS_OK, NULL);
	bon(&c, &granted);
	CHECK(fzn_rpc_cap_granted(&c, &grants) == FZN_RPC_OK && grants.count == 1
	              && grants.entries[0].grantee_pubkey[0] == 0x5a && grants.entries[0].revoked
	              && grants.entries[0].expires_at == 0 && granted.asked[0][1] == 0x84,
	      "the grants were not read in binary, a grant that no longer stands as revoked");
	bon(&c, &cut);
	CHECK(fzn_rpc_cap_list(&c, &caps) != FZN_RPC_OK, "a capabilities listing cut before its STATUS was read as whole");
}

int main(void)
{
	test_capabilities_in_binary();
	test_forks_in_binary();
	test_clocks_in_binary();
	test_legs_in_binary();
	test_deliveries_in_binary();
	test_roster_in_binary();
	test_transfers_in_binary();
	test_siblings_in_binary();
	test_group_lines_in_binary();
	test_library_in_binary();
	test_library_show_in_binary();
	test_file_status_in_binary();
	test_note_writes_in_binary();
	test_notes_in_binary();
	test_group_notebook_in_binary();
	test_notes_stamp_in_binary();
	test_shares_in_binary();
	test_note_open_in_binary();
	test_packs_in_binary();
	test_location_status_in_binary();
	test_invites_in_binary();
	test_show_in_binary();
	test_calls_in_binary();
	test_call_history_in_binary();
	test_rules_in_binary();
	test_governance_typed();
	test_governance_in_binary();
	test_self_in_binary();
	test_stickers_in_binary();
	test_positions_in_binary();
	test_groups_in_binary();
	test_requests_in_binary();
	test_contact_changes_in_binary();
	test_contacts_in_binary();
	test_a_line_is_sent_in_binary();
	test_lines_in_binary();
	test_conversations_in_binary();
	test_a_file_not_fetched_says_so();
	test_an_empty_library_lists_nothing();
	test_objects_in_binary();
	test_a_node_that_reads_no_binary_is_asked_in_text();
	test_groups_are_read_across_pages();
	test_a_group_row_that_does_not_parse_is_unreadable();
	test_every_unread_count_is_read();
	test_a_missed_call_is_told_from_one_taken_elsewhere();
	test_a_refusal_keeps_the_node_s_words();
	test_a_held_set_says_so();
	test_an_object_is_read_or_absent();
	test_nothing_answering_is_not_a_refusal();
	test_a_name_or_address_with_a_control_is_refused();
	test_unread_counts_past_the_read_line();
	test_untrusted_text_is_shown_in_caret_form();
	test_a_long_sticker_spec_is_read_whole();
	test_the_schema_is_read_in_the_node_s_words();
	test_a_setting_says_where_it_stands();
	test_a_setting_is_cleared_where_it_was_set();
	test_a_media_channel_carries_whole_frames();
	test_a_join_is_asked_and_then_seen();
	test_dropped_figures_are_carried();
	test_every_newest_line_is_read();
	test_the_suite_can_tell_pass_from_fail();
	if (failures) {
		fprintf(stderr, "local rpc_test: %d check(s) failed\n", failures);
		return 1;
	}
	printf("local rpc_test: all passed\n");
	return 0;
}
