/*
 * A fuzz harness for a conversation's record bodies, `messages/line.c`:
 * sec 689's journey 2, 1:1 chat. A line, a mark on one and a read position
 * each reach this host in a record another of the user's devices signed,
 * so a device that is lost, or a bug in one, writes them.
 *
 * THE CLAIMS, from line.h: a line part opens only where it was sealed for,
 * its parts tile its text one way only, and a mark or a position has one
 * encoding.
 *
 * Each case seals a random text of up to FZN_MESSAGE_TEXT_MAX bytes into
 * its parts, or writes a random mark and position, and then bends the
 * bodies with even odds: bits flipped, cut short, grown, a slice repeated
 * or two bytes swapped.
 *
 * THE PROPERTIES:
 *   1. ROUND TRIP: every part a seal writes reads back with the fields it
 *      was sealed with, opens under its key and contact, and the opened
 *      parts are the text again; a mark and a position read back as
 *      written.
 *   2. BOUND: a part opens under no other contact, and under no other key.
 *   3. A BENT PART DOES NOT OPEN: every byte of a part is bound by its
 *      header, its additional data or its tag, so a bent body either fails
 *      to read or fails to open.
 *   4. ONE ENCODING: a mark or a position that reads writes back as the
 *      same bytes, and a part that reads has exactly the tiling line.h
 *      states.
 *
 * FLOORS: a run with no two-part text, no bent part that still read, or no
 * bent mark that still read has not tested what it claims.
 */

#include "../line.h"
#include "../../session/aead_monocypher.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FUZZ_DEFAULT_CASES 4000u
#define FUZZ_MIN_CASES 1000u

static int failures;

static void fail(const char *what, unsigned long c)
{
	failures++;
	if (failures <= 10)
		fprintf(stderr, "  FAIL line_fuzz.c: case %lu: %s\n", c, what);
}

static uint64_t state = 0x2545f4914f6cdd1dull;

static uint64_t next(void)
{
	state ^= state << 13;
	state ^= state >> 7;
	state ^= state << 17;
	return state;
}

static void fill(uint8_t *b, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		b[i] = (uint8_t)next();
}

/* Bend `b`, `len` bytes of `cap`, and return its new length. Never returns
 * the bytes unchanged: a bend that would is a flip instead. */
static size_t bend(uint8_t *b, size_t len, size_t cap)
{
	size_t k, i, j;
	uint8_t t;

	switch (next() % 5u) {
	case 1:
		if (len)
			return (size_t)(next() % len);
		break;
	case 2:
		if (len < cap) {
			for (k = 1u + next() % 8u; k > 0u && len < cap; k--)
				b[len++] = (uint8_t)next();
			return len;
		}
		break;
	case 3:
		if (len >= 8u) {
			i = next() % (len - 4u);
			for (j = 0; j < 4u && b[i + j] == b[i + j + 4u]; j++)
				;
			if (j < 4u) {
				memmove(b + i + 4u, b + i, len - i - 4u);
				return len;
			}
		}
		break;
	case 4:
		if (len >= 2u) {
			i = next() % len;
			j = next() % len;
			if (b[i] != b[j]) {
				t = b[i];
				b[i] = b[j];
				b[j] = t;
				return len;
			}
		}
		break;
	default:
		break;
	}
	for (k = 1u + next() % 4u; k > 0u && len; k--)
		b[next() % len] ^= (uint8_t)(1u << (next() % 8u));
	if (len)
		b[next() % len] ^= 0x80u; /* at least one bit, even if two flips cancel */
	return len;
}

static int same_part(const fzn_message_part_t *p, uint8_t direction, uint8_t part, uint8_t parts,
                     const uint8_t *id, uint64_t stime, uint32_t epoch, const uint8_t *nonce)
{
	return p->direction == direction && p->part == part && p->parts == parts
	       && memcmp(p->id, id, FZN_MESSAGE_ID_LEN) == 0 && p->stime == stime
	       && p->epoch == epoch && memcmp(p->nonce, nonce, FZN_AEAD_NONCE_LEN) == 0;
}

/* The tiling line.h states, of a part that read. */
static int tiles(const fzn_message_part_t *p)
{
	if (p->parts == 1u)
		return p->part == 0u && p->text_len <= FZN_MESSAGE_PART_MAX;
	if (p->parts != 2u)
		return 0;
	if (p->part == 0u)
		return p->text_len == FZN_MESSAGE_PART_MAX;
	return p->part == 1u && p->text_len > 0u
	       && p->text_len <= FZN_MESSAGE_TEXT_MAX - FZN_MESSAGE_PART_MAX;
}

int main(int argc, char **argv)
{
	static uint8_t text[FZN_MESSAGE_TEXT_MAX], opened[FZN_MESSAGE_TEXT_MAX];
	static uint8_t body[FZN_MESSAGE_PARTS_MAX][FZN_RECORD_BODY_MAX + 16u];
	static uint8_t bent[FZN_RECORD_BODY_MAX + 16u];
	fzn_aead_ops_t aead;
	unsigned long cases = FUZZ_DEFAULT_CASES, c;
	unsigned long two_parts = 0, bent_read = 0, bent_marks_read = 0;

	if (argc > 1)
		cases = strtoul(argv[1], NULL, 10);
	if (cases < FUZZ_MIN_CASES)
		cases = FUZZ_MIN_CASES;
	fzn_aead_monocypher_init(&aead);

	for (c = 0; c < cases; c++) {
		uint8_t key[FZN_CONVERSATION_KEY_LEN], other_key[FZN_CONVERSATION_KEY_LEN];
		uint8_t contact[FZN_PUBKEY_LEN], other[FZN_PUBKEY_LEN];
		uint8_t id[FZN_MESSAGE_ID_LEN], nonce[FZN_MESSAGE_PARTS_MAX][FZN_AEAD_NONCE_LEN];
		uint8_t direction = (next() & 1u) ? FZN_MESSAGE_OUT : FZN_MESSAGE_IN;
		uint64_t stime = next() >> (next() % 64u);
		uint32_t epoch = (uint32_t)next();
		size_t len = (size_t)(next() % (FZN_MESSAGE_TEXT_MAX + 1u));
		size_t parts = fzn_message_parts_for(len), body_len[FZN_MESSAGE_PARTS_MAX] = { 0 };
		size_t got_len = 0, at = 0, n, p;
		fzn_message_part_t part;
		fzn_message_mark_t mark, mark_back;
		uint8_t mark_body[FZN_MESSAGE_MARK_LEN + 8u], mark_again[FZN_MESSAGE_MARK_LEN];
		uint8_t position[FZN_MESSAGE_READ_LEN + 8u], position_id[FZN_MESSAGE_ID_LEN];

		fill(key, sizeof(key));
		fill(other_key, sizeof(other_key));
		fill(contact, sizeof(contact));
		memcpy(other, contact, sizeof(other));
		other[next() % FZN_PUBKEY_LEN] ^= (uint8_t)(1u << (next() % 8u));
		fill(id, sizeof(id));
		fill(&nonce[0][0], sizeof(nonce));
		fill(text, len);
		if (parts == 0u || parts > FZN_MESSAGE_PARTS_MAX) {
			fail("a text of at most FZN_MESSAGE_TEXT_MAX takes no parts", c);
			continue;
		}
		if (parts == 2u)
			two_parts++;

		/* 1. ROUND TRIP, and 2. BOUND. */
		for (p = 0; p < parts; p++) {
			if (!fzn_message_line_seal(&aead, key, contact, direction, id, stime, epoch,
			                           nonce[p], text, len, (uint8_t)p, (uint8_t)parts, body[p],
			                           &body_len[p])) {
				fail("a seal refused a well-formed part", c);
				goto marks;
			}
			if (!fzn_message_line_read(body[p], body_len[p], &part)
			    || !same_part(&part, direction, (uint8_t)p, (uint8_t)parts, id, stime, epoch,
			                  nonce[p])
			    || !tiles(&part)) {
				fail("a sealed part does not read back as sealed", c);
				goto marks;
			}
			if (!fzn_message_line_open(&aead, key, contact, &part, opened + at,
			                           sizeof(opened) - at, &n)) {
				fail("a sealed part does not open under its key", c);
				goto marks;
			}
			at += n;
			if (fzn_message_line_open(&aead, key, other, &part, bent, sizeof(bent), &got_len))
				fail("a part opened under another contact", c);
			if (fzn_message_line_open(&aead, other_key, contact, &part, bent, sizeof(bent),
			                          &got_len))
				fail("a part opened under another key", c);
		}
		if (at != len || memcmp(opened, text, len) != 0)
			fail("the opened parts are not the text", c);

		/* 3. A BENT PART DOES NOT OPEN, and 4. its tiling where it reads. */
		p = (size_t)(next() % parts);
		memcpy(bent, body[p], body_len[p]);
		n = bend(bent, body_len[p], sizeof(bent));
		if (fzn_message_line_read(bent, n, &part)) {
			bent_read++;
			if (!tiles(&part))
				fail("a part read with a tiling line.h does not allow", c);
			if (n != FZN_MESSAGE_LINE_HEAD + part.text_len)
				fail("a part read whose text is not the rest of its body", c);
			if (fzn_message_line_open(&aead, key, contact, &part, opened, sizeof(opened),
			                          &got_len))
				fail("a bent part opened", c);
		}

	marks:
		/* 1 and 4 for a mark and a position. */
		mark.direction = direction;
		mark.state = (uint8_t)(FZN_MESSAGE_DELIVERED + next() % 4u);
		memcpy(mark.id, id, FZN_MESSAGE_ID_LEN);
		if (!fzn_message_mark_write(&mark, mark_body)
		    || !fzn_message_mark_read(mark_body, FZN_MESSAGE_MARK_LEN, &mark_back)
		    || mark_back.direction != mark.direction || mark_back.state != mark.state
		    || memcmp(mark_back.id, mark.id, FZN_MESSAGE_ID_LEN) != 0)
			fail("a mark does not read back as written", c);
		n = bend(mark_body, FZN_MESSAGE_MARK_LEN, sizeof(mark_body));
		if (fzn_message_mark_read(mark_body, n, &mark_back)) {
			bent_marks_read++;
			if (n != FZN_MESSAGE_MARK_LEN || !fzn_message_mark_write(&mark_back, mark_again)
			    || memcmp(mark_again, mark_body, FZN_MESSAGE_MARK_LEN) != 0)
				fail("a mark read that does not write back as its bytes", c);
		}
		if (!fzn_message_position_write(id, position)
		    || !fzn_message_position_read(position, FZN_MESSAGE_READ_LEN, position_id)
		    || memcmp(position_id, id, FZN_MESSAGE_ID_LEN) != 0)
			fail("a position does not read back as written", c);
		n = bend(position, FZN_MESSAGE_READ_LEN, sizeof(position));
		if (fzn_message_position_read(position, n, position_id)) {
			uint8_t again[FZN_MESSAGE_READ_LEN];

			if (n != FZN_MESSAGE_READ_LEN || !fzn_message_position_write(position_id, again)
			    || memcmp(again, position, FZN_MESSAGE_READ_LEN) != 0)
				fail("a position read that does not write back as its bytes", c);
		}
	}

	if (two_parts == 0u)
		fail("no text took two parts", cases);
	if (bent_read == 0u)
		fail("no bent part still read: the open was never asked of one", cases);
	if (bent_marks_read == 0u)
		fail("no bent mark still read: its encoding was never asked of one", cases);
	printf("line_fuzz: %lu cases, %lu of two parts, %lu bent parts read, %lu bent marks read, "
	       "%d failure(s)\n",
	       cases, two_parts, bent_read, bent_marks_read, failures);
	return failures ? 1 : 0;
}
