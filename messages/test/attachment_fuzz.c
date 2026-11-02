/*
 * A fuzz harness for a file sent in a conversation, `messages/attachment.c`:
 * sec 689's journey 2, 1:1 chat, the input sec 794 added to it. The
 * reference rides a line's text, so a contact writes it, and every client
 * that shows an attachment reads it through `fzn_attachment_parse`.
 *
 * THE CLAIMS, from attachment.h: a reference is whole or it is refused; a
 * name it gives is one a client may show and save under -- 1 to 64 bytes,
 * no `/` or `\`, no control byte, no leading dot, no space at either end;
 * and a file has one spelling, save the scheme fuzzypickles wrote and the
 * case of the hex.
 *
 * Each case makes a random attachment -- its name drawn from every byte the
 * rules allow, high bytes among them -- formats it, and bends the text with
 * even odds: bits flipped, cut short, grown, a slice repeated or two bytes
 * swapped. Every parse reads from a heap copy of exactly the text's length,
 * so a read one byte past the end is the sanitizer's to report.
 *
 * THE PROPERTIES:
 *   1. ROUND TRIP: a formatted reference parses back as the attachment it
 *      was made from, and so does the same under `fzp:` with its hex in
 *      either case.
 *   2. ONE SPELLING: a bent text that parses is exactly what formatting its
 *      parse writes, once its scheme is read as `fzn:` and its hex as lower
 *      case. Formatting refuses a name the rules forbid, so this also holds
 *      every parsed name to them.
 *
 * FLOORS: a run in which no bent text parsed, or none was refused, has not
 * tested what it claims.
 */

#include "../attachment.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FUZZ_DEFAULT_CASES 20000u
#define FUZZ_MIN_CASES 2000u

/* Where the two hex fields lie: after "fzn:file/", and after the first and
 * its "/". */
#define ROOT_AT 9u
#define KEY_AT (ROOT_AT + 2u * FZN_ATTACHMENT_ROOT_LEN + 1u)
#define HEX_END (KEY_AT + 2u * FZN_ATTACHMENT_KEY_LEN)

static int failures;

static void fail(const char *what, unsigned long c)
{
	failures++;
	if (failures <= 10)
		fprintf(stderr, "  FAIL attachment_fuzz.c: case %lu: %s\n", c, what);
}

static uint64_t state = 0x6a09e667f3bcc909ull;

static uint64_t next(void)
{
	state ^= state << 13;
	state ^= state >> 7;
	state ^= state << 17;
	return state;
}

/* A byte a name may hold anywhere: not a control byte, 0x7f, `/` or `\`. */
static char name_byte(void)
{
	for (;;) {
		unsigned char c = (unsigned char)next();

		if (c >= 0x20u && c != 0x7fu && c != '/' && c != '\\')
			return (char)c;
	}
}

static void make(fzn_attachment_t *a)
{
	size_t i;

	memset(a, 0, sizeof(*a));
	for (i = 0; i < FZN_ATTACHMENT_ROOT_LEN; i++)
		a->root[i] = (uint8_t)next();
	for (i = 0; i < FZN_ATTACHMENT_KEY_LEN; i++)
		a->key[i] = (uint8_t)next();
	a->size = next() >> (next() % 64u);
	a->name_len = 1u + (size_t)(next() % FZN_ATTACHMENT_NAME_MAX);
	for (i = 0; i < a->name_len; i++)
		a->name[i] = name_byte();
	while (a->name[0] == '.' || a->name[0] == ' ')
		a->name[0] = name_byte();
	while (a->name[a->name_len - 1u] == ' ')
		a->name[a->name_len - 1u] = name_byte();
}

static int same(const fzn_attachment_t *a, const fzn_attachment_t *b)
{
	return memcmp(a->root, b->root, sizeof(a->root)) == 0
	       && memcmp(a->key, b->key, sizeof(a->key)) == 0 && a->size == b->size
	       && a->name_len == b->name_len && memcmp(a->name, b->name, a->name_len) == 0
	       && b->name[b->name_len] == '\0';
}

/* Parse `len` bytes from a heap copy of exactly that length. */
static int parse_exact(const char *text, size_t len, fzn_attachment_t *out)
{
	char *copy = malloc(len ? len : 1u);
	int r;

	if (!copy)
		abort();
	memcpy(copy, text, len);
	r = fzn_attachment_parse(copy, len, out);
	free(copy);
	return r;
}

/* As line_fuzz's bend, over a text: never returns it unchanged. */
static size_t bend(char *b, size_t len, size_t cap)
{
	static char was[FZN_ATTACHMENT_REF_MAX + 16u];
	size_t k, i, j;
	char t;

	memcpy(was, b, len);
	switch (next() % 5u) {
	case 1:
		if (len)
			return (size_t)(next() % len);
		break;
	case 2:
		if (len < cap) {
			for (k = 1u + next() % 8u; k > 0u && len < cap; k--)
				b[len++] = (char)next();
			return len;
		}
		break;
	case 3:
		if (len >= 8u) {
			i = next() % (len - 4u);
			for (j = 0; j < 4u && i + j + 4u < len && b[i + j] == b[i + j + 4u]; j++)
				;
			if (j < 4u && i + j + 4u < len) {
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
	for (k = 1u + next() % 2u; k > 0u && len; k--)
		b[next() % len] ^= (char)(1u << (next() % 8u));
	if (len && memcmp(b, was, len) == 0)
		b[next() % len] ^= 0x01;
	return len;
}

/* `text` as fuzznet writes it: `fzn:` for `fzp:`, the hex in lower case. */
static void canonical(char *text, size_t len)
{
	size_t i;

	if (len >= 3u && memcmp(text, "fzp", 3u) == 0)
		text[2] = 'n';
	for (i = ROOT_AT; i < HEX_END && i < len; i++)
		if (text[i] >= 'A' && text[i] <= 'F')
			text[i] = (char)(text[i] - 'A' + 'a');
}

int main(int argc, char **argv)
{
	static char text[FZN_ATTACHMENT_REF_MAX + 16u], bent[FZN_ATTACHMENT_REF_MAX + 16u];
	static char again[FZN_ATTACHMENT_REF_MAX + 16u];
	unsigned long cases = FUZZ_DEFAULT_CASES, c;
	unsigned long bent_parsed = 0, bent_refused = 0;

	if (argc > 1)
		cases = strtoul(argv[1], NULL, 10);
	if (cases < FUZZ_MIN_CASES)
		cases = FUZZ_MIN_CASES;

	for (c = 0; c < cases; c++) {
		fzn_attachment_t a, back;
		size_t len = 0, again_len = 0, n, i;

		make(&a);
		if (!fzn_attachment_format(&a, text, sizeof(text), &len)) {
			fail("an attachment the rules allow did not format", c);
			continue;
		}
		if (!parse_exact(text, len, &back) || !same(&a, &back))
			fail("a formatted reference does not parse back as its attachment", c);

		/* FUZZYPICKLES' SCHEME, and the hex in either case. */
		memcpy(bent, text, len);
		bent[2] = 'p';
		for (i = ROOT_AT; i < HEX_END; i++)
			if (bent[i] >= 'a' && bent[i] <= 'f' && (next() & 1u))
				bent[i] = (char)(bent[i] - 'a' + 'A');
		if (!parse_exact(bent, len, &back) || !same(&a, &back))
			fail("an fzp: reference with upper-case hex does not parse as its attachment", c);

		/* BENT. */
		memcpy(bent, text, len);
		n = bend(bent, len, sizeof(bent));
		if (!parse_exact(bent, n, &back)) {
			bent_refused++;
			continue;
		}
		bent_parsed++;
		canonical(bent, n);
		if (!fzn_attachment_format(&back, again, sizeof(again), &again_len))
			fail("a bent reference parsed to a name the rules forbid", c);
		else if (again_len != n || memcmp(again, bent, n) != 0)
			fail("a bent reference parsed that is not the one spelling of its parse", c);
	}

	if (bent_parsed == 0u)
		fail("no bent reference parsed: one spelling was never asked of one", cases);
	if (bent_refused == 0u)
		fail("no bent reference was refused", cases);
	printf("attachment_fuzz: %lu cases, %lu bent parsed, %lu bent refused, %d failure(s)\n",
	       cases, bent_parsed, bent_refused, failures);
	return failures ? 1 : 0;
}
