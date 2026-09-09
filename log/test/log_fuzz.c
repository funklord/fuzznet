/* A fuzz harness for rendering a record body as text.
 *
 * A BODY IS OPAQUE BYTES AN ISSUER CHOSE, and `log.h` says what that means
 * for anything that displays one:
 *
 *   "NEWLINES ARE ESCAPED, AND THAT IS THE POINT RATHER THAN TIDINESS. A
 *   viewer showing one entry per line, handed a body containing a newline and
 *   a plausible sequence number, would display a SECOND ENTRY THAT NO ISSUER
 *   EVER SIGNED. Escaping is what stops a body forging a neighbour. Every byte
 *   outside printable ASCII goes to `\xNN`, so the same argument covers a
 *   terminal escape sequence."
 *
 * So this function stands between an attacker's bytes and a terminal, and the
 * property is exact rather than statistical: for ANY input at all, every byte
 * that reaches the output is printable ASCII. A harness is the right
 * instrument because a written case tests the byte its author thought of, and
 * the bytes that matter here are the ones nobody thinks of -- an escape
 * introducer, a carriage return without a newline, a byte that is printable in
 * one locale and not in C.
 *
 * THE IDENTITY CASE IS THE CONTROL. A renderer that escaped everything, or
 * emitted nothing at all, would satisfy "the output is printable" perfectly.
 * So a body that is already printable and carries no backslash must come back
 * unchanged, or the property above is being met by destroying the input.
 *
 * sec 233 found this the same way it found the relay budget: by re-deriving
 * the parser population from the SHAPE of a signature rather than from a
 * naming convention. `fzn_log_body_text` is not called `_open`.
 */

#include "../log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FUZZ_DEFAULT_CASES 20000u
#define FUZZ_MIN_CASES 1000u

struct coverage {
	unsigned long rendered;
	unsigned long refused;
	unsigned long escaped;
	unsigned long identity;
	unsigned long newlines;
	unsigned long empty;
};

static uint32_t next_rand(uint32_t *seed)
{
	*seed = (*seed * 1103515245u) + 12345u;
	return (*seed >> 16) & 0x7fffu;
}

static int printable(uint8_t c)
{
	return c >= 0x20u && c <= 0x7eu;
}

static int fuzz_one(uint32_t seed, struct coverage *cov)
{
	uint8_t body[64];
	char out[FZN_LOG_TEXT_MAX];
	char guard[FZN_LOG_TEXT_MAX];
	size_t body_len, i;
	int all_safe = 1;
	int had_newline = 0;
	fzn_log_err_t err;

	body_len = (size_t)(next_rand(&seed) % (sizeof(body) + 1u));

	/* A THIRD OF THE BODIES ARE ALREADY PRINTABLE, so the identity control
	 * below is reached rather than waited for: a uniform draw over 0..255
	 * produces an all-printable body of any length about never. */
	if ((next_rand(&seed) % 3u) == 0u) {
		for (i = 0; i < body_len; i++)
			body[i] = (uint8_t)(0x20u + (next_rand(&seed) % 0x5fu));
		for (i = 0; i < body_len; i++) {
			if (body[i] == (uint8_t)'\\')
				body[i] = (uint8_t)'x';
		}
	} else {
		for (i = 0; i < body_len; i++)
			body[i] = (uint8_t)(next_rand(&seed) & 0xffu);
	}

	for (i = 0; i < body_len; i++) {
		if (!printable(body[i]) || body[i] == (uint8_t)'\\')
			all_safe = 0;
		if (body[i] == (uint8_t)'\n')
			had_newline = 1;
	}
	if (!body_len)
		cov->empty++;
	if (had_newline)
		cov->newlines++;

	memset(out, 0x7f, sizeof(out));
	memcpy(guard, out, sizeof(guard));

	err = fzn_log_body_text(body_len ? body : NULL, body_len, out, sizeof(out));
	if (err != FZN_LOG_OK) {
		cov->refused++;
		/* IT REFUSES RATHER THAN TRUNCATES, so a refusal must not have
		 * written a partial line somebody would display. */
		if (memcmp(out, guard, sizeof(out)) != 0) {
			printf("log_fuzz: a refused render wrote into the caller's buffer, "
			       "so a caller ignoring the status shows a partial line\n");
			return 0;
		}
		return 1;
	}

	cov->rendered++;

	/* ---- THE PROPERTY. Every byte that reaches a terminal is printable
	 * ASCII, so no body can carry a control sequence or forge a neighbour
	 * by ending a line. */
	{
		size_t n = strlen(out);

		if (n + 1u > sizeof(out)) {
			printf("log_fuzz: the rendered line is not terminated inside the "
			       "buffer it was given\n");
			return 0;
		}
		for (i = 0; i < n; i++) {
			if (!printable((uint8_t)out[i])) {
				printf("log_fuzz: byte %zu of the rendered line is 0x%02x, "
				       "which is not printable ASCII -- a body reached a "
				       "terminal unescaped\n",
				       i, (unsigned)(uint8_t)out[i]);
				return 0;
			}
		}
		if (n > (size_t)FZN_RECORD_BODY_MAX * 4u) {
			printf("log_fuzz: a %zu-byte body rendered to %zu characters, past "
			       "the four-per-byte bound this buffer is sized on\n",
			       body_len, n);
			return 0;
		}
		if (all_safe) {
			/* THE CONTROL. Without it, a renderer that emitted
			 * nothing would satisfy every assertion above. */
			if (n != body_len || memcmp(out, body, body_len) != 0) {
				printf("log_fuzz: a body that was already printable came back "
				       "changed, so the escaping is destroying input rather "
				       "than escaping it\n");
				return 0;
			}
			cov->identity++;
		} else if (body_len) {
			cov->escaped++;
		}
	}

	return 1;
}

#ifdef FZN_LIBFUZZER
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	uint32_t seed = 1u;
	size_t i;
	struct coverage cov = { 0, 0, 0, 0, 0, 0 };

	for (i = 0; i < size; i++)
		seed = (seed * 31u) + data[i];
	if (seed == 0u)
		seed = 1u;
	(void)fuzz_one(seed, &cov);
	return 0;
}
#else

static unsigned long floor_of(unsigned long cases, unsigned long per)
{
	unsigned long f = cases / per;

	return f == 0u ? 1u : f;
}

int main(int argc, char **argv)
{
	unsigned long cases = FUZZ_DEFAULT_CASES;
	struct coverage cov = { 0, 0, 0, 0, 0, 0 };
	unsigned long i;

	if (argc > 1)
		cases = strtoul(argv[1], NULL, 10);
	if (cases < FUZZ_MIN_CASES) {
		printf("log_fuzz: %lu cases is below the floor of %u, at which the\n"
		       "log_fuzz: coverage checks below are cleared by luck.\n",
		       cases, FUZZ_MIN_CASES);
		return 1;
	}

	for (i = 0; i < cases; i++) {
		if (!fuzz_one((uint32_t)(i + 1u), &cov))
			return 1;
	}

	/* FLOORS ON WHAT WAS REACHED. A run that never rendered a body
	 * containing a NEWLINE never tested the case this escaping exists for,
	 * and one that never took the identity path has only watched the
	 * property that emitting nothing would also satisfy. */
	if (cov.rendered < floor_of(cases, 4u) || cov.escaped < floor_of(cases, 8u)
	    || cov.identity < floor_of(cases, 8u) || cov.newlines < floor_of(cases, 20u)) {
		printf("log_fuzz: REACHED TOO LITTLE -- %lu rendered, %lu escaped, "
		       "%lu identity, %lu with a newline, %lu empty, %lu refused in "
		       "%lu cases.\n",
		       cov.rendered, cov.escaped, cov.identity, cov.newlines, cov.empty,
		       cov.refused, cases);
		return 1;
	}

	printf("log_fuzz: %lu cases, %lu rendered (%lu escaped, %lu unchanged), "
	       "%lu carried a newline, %lu empty, %lu refused\n",
	       cases, cov.rendered, cov.escaped, cov.identity, cov.newlines, cov.empty,
	       cov.refused);
	return 0;
}
#endif
