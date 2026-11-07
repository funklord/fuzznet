/* sessions_test -- `node/sessions.h`, sec 932: at most two a sender, an ask heard
 * again granted the same, and no replay reaches the session in use. */
#include "../sessions.h"
#include "../../session/aead_monocypher.h"
#include "../../session/hash_monocypher.h"
#include "../../session/random_system.h"
#include "../../wire/bytes.h"

#include <stdio.h>
#include <string.h>

static int failures, checks;

static void check_at(int ok, int line, const char *what)
{
	checks++;
	if (ok)
		return;
	failures++;
	fprintf(stderr, "  FAIL sessions_test.c:%d: %s\n", line, what);
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, what)

static fzn_hash_ops_t hash;
static fzn_random_ops_t rng;
static fzn_aead_ops_t aead;
static fzn_node_sessions_t table;
static uint8_t capability[FZN_CAP_ID_LEN], root[FZN_AEAD_KEY_LEN];

static uint32_t handle_of(const uint8_t *grant)
{
	return fzn_get_be32(grant + FZN_SESSION_RANDOM_LEN);
}

static size_t used(void)
{
	size_t i, n = 0;

	for (i = 0; i < table.cap; i++)
		n += table.table[i].used;
	return n;
}

static int grant(const uint8_t *sender, uint8_t fill_with, uint8_t *out, uint8_t *ask_out)
{
	memset(ask_out, fill_with, FZN_SESSION_ASK_LEN);
	return fzn_node_sessions_grant(&table, sender, capability, root, ask_out, 5000u, &hash, &rng,
	                               out);
}

/* THE ASKER'S FIRST FRAME, opened at the table. */
static void first_frame(const uint8_t *ask, const uint8_t *g)
{
	fzn_session_end_t asker;
	fzn_session_opened_t got;
	fzn_node_session_t *s;
	uint8_t frame[FZN_SESSION_FRAME_MAX];
	size_t n = 0;

	CHECK(fzn_session_end_derive(&asker, &hash, root, ask, g, 1), "the asker did not derive");
	CHECK(fzn_session_frame_seal(&asker, 1u, 9u, NULL, 0u, frame, sizeof(frame), &n, &aead)
	              == FZN_SESSION_FRAME_OK,
	      "the asker did not seal");
	s = fzn_node_sessions_find(&table, handle_of(g));
	CHECK(s != NULL, "a grant is not in the table");
	if (!s)
		return;
	CHECK(fzn_session_frame_open(&s->end, frame, n, &aead, &got) == FZN_SESSION_FRAME_OK,
	      "the two ends do not agree");
	fzn_node_sessions_confirm(&table, s);
}

int main(void)
{
	uint8_t alice[FZN_PUBKEY_LEN], bob[FZN_PUBKEY_LEN];
	uint8_t g1[FZN_SESSION_GRANT_LEN], g2[FZN_SESSION_GRANT_LEN], g3[FZN_SESSION_GRANT_LEN];
	uint8_t a1[FZN_SESSION_ASK_LEN], a2[FZN_SESSION_ASK_LEN], a3[FZN_SESSION_ASK_LEN];
	fzn_node_session_t *s;
	uint32_t old;
	size_t i;

	fzn_hash_monocypher_init(&hash);
	fzn_aead_monocypher_init(&aead);
	fzn_random_system_init(&rng);
	memset(alice, 0xA1, sizeof(alice));
	memset(bob, 0xB0, sizeof(bob));
	memset(capability, 0x0C, sizeof(capability));
	memset(root, 0x77, sizeof(root));

	/* GRANTED, and found. The time is in it. */
	CHECK(grant(alice, 1u, g1, a1), "an ask was not granted");
	CHECK(fzn_get_be64(g1 + FZN_SESSION_RANDOM_LEN + 4u) == 5000u, "the grant says no time");
	s = fzn_node_sessions_find(&table, handle_of(g1));
	CHECK(s && !s->confirmed && memcmp(s->sender, alice, sizeof(alice)) == 0
	              && memcmp(s->capability, capability, sizeof(capability)) == 0,
	      "a grant does not name its sender and capability");
	CHECK(!fzn_node_sessions_find(&table, handle_of(g1) ^ 0x80000000u),
	      "a handle's high bits were not read");
	CHECK(!fzn_node_sessions_find(&table, 0xFFFFFFFFu), "a slot past the table was read");

	/* THE SAME ASK AGAIN: its grant was lost, and the first still stands. */
	CHECK(grant(alice, 1u, g2, a1), "an ask heard again was not answered");
	CHECK(memcmp(g1, g2, sizeof(g1)) == 0, "an ask heard again was granted anew");
	CHECK(used() == 1u, "an ask heard again took a slot");

	/* ANOTHER ASK, none confirmed: the newest stands, and one slot. */
	CHECK(grant(alice, 2u, g2, a2), "a second ask was not granted");
	/* BY ITS ASK, not by the first handle: the new one takes the slot, and draws the
	 * same eight bits above it one time in 256. A frame of the old session is then
	 * refused by the keys, which is why that may stand. */
	s = fzn_node_sessions_find(&table, handle_of(g2));
	CHECK(used() == 1u && s && memcmp(s->ask, a2, sizeof(a2)) == 0,
	      "two unconfirmed sessions for one sender");

	/* CONFIRMED, by a frame. */
	first_frame(a2, g2);
	s = fzn_node_sessions_find(&table, handle_of(g2));
	CHECK(s && s->confirmed, "a frame did not confirm its session");

	/* AN OLD ASK REPLAYED reaches nothing: granted, unusable, and the session in
	 * use still there. */
	CHECK(grant(alice, 1u, g1, a1), "a replayed ask was not answered");
	CHECK(used() == 2u, "a replayed ask did not take the second slot");
	s = fzn_node_sessions_find(&table, handle_of(g2));
	CHECK(s && s->confirmed, "a replayed ask took the session in use");

	/* AND A REAL NEW ONE takes over only at its first frame. */
	CHECK(grant(alice, 3u, g3, a3), "a new ask was not granted");
	CHECK(used() == 2u, "more than two for one sender");
	CHECK(fzn_node_sessions_find(&table, handle_of(g2)) != NULL, "an ask dropped the session");
	first_frame(a3, g3);
	CHECK(used() == 1u && !fzn_node_sessions_find(&table, handle_of(g2)),
	      "a confirmed session left the old one standing");

	/* ANOTHER SENDER'S ARE ITS OWN. */
	CHECK(grant(bob, 4u, g1, a1), "a second sender was not granted");
	first_frame(a1, g1);
	CHECK(used() == 2u && fzn_node_sessions_find(&table, handle_of(g3)),
	      "a sender's session reached another's");

	/* A SLOT REUSED does not answer to the old handle. */
	s = fzn_node_sessions_find(&table, handle_of(g1));
	old = handle_of(g1);
	fzn_node_sessions_drop(s);
	CHECK(!fzn_node_sessions_find(&table, old), "a dropped session was found");
	for (i = 0; i < 4u; i++) {
		CHECK(grant(bob, (uint8_t)(5u + i), g1, a1), "an ask was not granted");
		if (handle_of(g1) != old)
			break;
	}
	CHECK(handle_of(g1) != old, "a reused slot kept its handle");
	CHECK(!fzn_node_sessions_find(&table, old), "an old handle found a new session");

	/* MANY SENDERS: the table grows, and what it held still finds its own. */
	old = handle_of(g3);
	for (i = 0; i < 3000u; i++) {
		uint8_t who[FZN_PUBKEY_LEN];

		memset(who, 0, sizeof(who));
		fzn_put_be32(who, (uint32_t)i + 1u);
		CHECK(grant(who, 9u, g2, a2), "an ask was not granted as the table grew");
		CHECK(fzn_node_sessions_find(&table, handle_of(g2)) != NULL, "a grant was lost");
	}
	s = fzn_node_sessions_find(&table, old);
	CHECK(s && memcmp(s->sender, alice, sizeof(alice)) == 0, "growing lost a session");

	fzn_node_sessions_release(&table);
	CHECK(!table.table && !table.cap, "a table let go still holds");
	printf("sessions_test: %d checks, %d failure(s)\n", checks, failures);
	return failures ? 1 : 0;
}
