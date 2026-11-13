/*
 * THE TYPED CLIENT OVER A SCRIPTED NODE, sec 1098: fuzzypickles' fzn_rpc_
 * calls, driven through `fzn_rpc_t.answer` so no socket is opened. Each case
 * checks what the call asked and what it made of the answer -- the node's
 * grammar as the client reads it, paging, a refusal's code and words, `ok
 * held`, an answer that does not parse, and nothing answering at all.
 */
#include "../rpc.h"
#include "../rpc_encoding.h"
#include "../rpc_err.h"
#include "../rpc_limits.h"

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

static void test_the_suite_can_tell_pass_from_fail(void)
{
	int before = failures;

	CHECK(0, "deliberate");
	CHECK(failures == before + 1, "a failing check was not counted");
	failures = before;
}

int main(void)
{
	test_groups_are_read_across_pages();
	test_a_group_row_that_does_not_parse_is_unreadable();
	test_every_unread_count_is_read();
	test_a_refusal_keeps_the_node_s_words();
	test_a_held_set_says_so();
	test_an_object_is_read_or_absent();
	test_nothing_answering_is_not_a_refusal();
	test_a_name_or_address_with_a_control_is_refused();
	test_unread_counts_past_the_read_line();
	test_untrusted_text_is_shown_in_caret_form();
	test_a_long_sticker_spec_is_read_whole();
	test_the_suite_can_tell_pass_from_fail();
	if (failures) {
		fprintf(stderr, "local rpc_test: %d check(s) failed\n", failures);
		return 1;
	}
	printf("local rpc_test: all passed\n");
	return 0;
}
