/* A fuzz harness for the filestore's wire vocabulary.
 *
 * `spool/message.c` is the newest decoder in this library and the only one
 * that had no harness: eleven modules carry seventeen between them, and every
 * other thing here that parses a stranger's bytes is fuzzed. project.md sec
 * 116 has the measurement that found it -- twenty-nine of message.c's
 * branches were taken one way only after its unit tests had been swept for
 * guard operands, and almost all of them are on the PARSE side, which is the
 * half a peer chooses and a caller cannot.
 *
 * WHAT IT CHECKS, beyond not crashing:
 *
 *   - **Round trip.** Anything the decoder ACCEPTS, re-encoded from what it
 *     handed back, must reproduce the input byte for byte. That is the
 *     strongest property this format has and the one its "exact length"
 *     refusals exist to protect: two encodings of one message is how a
 *     receiver that de-duplicates by bytes sees two questions where a peer
 *     asked one.
 *   - **Every value handed back is inside its bound.** Ranges inside the
 *     leaf count, spans no wider than FZN_MSG_MAX_SPAN, proof counts no
 *     deeper than FZN_MSG_MAX_PROOF.
 *   - **Every leaf pointer points into the message.** `fzn_msg_data_parse`
 *     hands back pointers rather than copies, so a wrong offset is a read
 *     into whatever follows the buffer, and the caller has no way to know.
 *   - **Nothing is written outside the caller's arrays.** They sit inside
 *     canaries, because an overrun by one entry lands in the next array and
 *     a plain -Os build says nothing.
 *
 * A SANITIZER DOES NOT MAKE THE CANARIES REDUNDANT, for the reason
 * `chunk/test/reassembly_fuzz.c` records: ASan brackets objects, and one
 * static arena is one object, so a write from one array into the next is in
 * bounds as far as it is concerned.
 *
 * TERMINATION, because it runs unattended. `main` performs a fixed number of
 * cases -- argv[1] or FUZZ_DEFAULT_CASES -- from a seeded generator with no
 * entropy in it, so the run is bounded, reproducible from the source alone,
 * and prints the failing case's seed. It allocates nothing, opens nothing
 * and spawns nothing.
 *
 * It compiles as a libFuzzer target too: `fuzz_one` is the entry point and
 * `LLVMFuzzerTestOneInput` forwards to it under -DFZN_LIBFUZZER.
 */

#include "../message.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FUZZ_DEFAULT_CASES 20000u

/* The floor below which this harness refuses to report success, for the
 * reason the other harnesses give: a run short enough that its coverage
 * floors are cleared by one lucky hit is a different and much weaker claim
 * than a campaign, so it is refused rather than reported. */
#define FUZZ_MIN_CASES 1000u

/* Small enough that a maximal DATA fits the buffer below and a case stays
 * cheap; large enough that spans cross cell and range boundaries. */
#define FUZZ_LEAVES 64u
#define FUZZ_LEAF_MAX 48u
#define FUZZ_RANGES 8u
#define BUF_BYTES 8192u

#define CANARY 16
#define CANARY_BYTE 0x7e

static uint32_t next(uint32_t *s)
{
	*s ^= *s << 13;
	*s ^= *s >> 17;
	*s ^= *s << 5;
	return *s;
}

/* Output arrays with a canary on each side. */
static struct {
	uint8_t front[CANARY];
	fzn_spool_range_t ranges[FZN_MSG_MAX_RANGES];
	uint8_t mid[CANARY];
	const uint8_t *sealed[FZN_MSG_MAX_SPAN];
	uint8_t mid2[CANARY];
	size_t sealed_len[FZN_MSG_MAX_SPAN];
	uint8_t back[CANARY];
} out;

static void arm_canaries(void)
{
	memset(out.front, CANARY_BYTE, CANARY);
	memset(out.mid, CANARY_BYTE, CANARY);
	memset(out.mid2, CANARY_BYTE, CANARY);
	memset(out.back, CANARY_BYTE, CANARY);
}

static int canaries_intact(void)
{
	int i;

	for (i = 0; i < CANARY; i++) {
		if (out.front[i] != CANARY_BYTE || out.mid[i] != CANARY_BYTE ||
		    out.mid2[i] != CANARY_BYTE || out.back[i] != CANARY_BYTE)
			return 0;
	}
	return 1;
}

struct cov {
	unsigned long accepted;
	unsigned long have_query;
	unsigned long have;
	unsigned long want;
	unsigned long data;
	unsigned long refused;
};

/* Re-encodes what a parse handed back and compares it with the input. A
 * decoder that accepts two spellings of one message fails here. */
static int round_trips(fzn_msg_type_t type, const uint8_t *in, size_t len)
{
	static uint8_t again[BUF_BYTES];
	uint8_t root[FZN_BLOB_HASH_LEN], cookie[FZN_MSG_COOKIE_LEN];
	uint64_t leaf_count = 0, first = 0, count = 0;
	uint32_t transfer = 0;
	unsigned proof_count = 0;
	const uint8_t *proof = NULL;
	size_t n = 0, out_len = 0;

	switch (type) {
	case FZN_MSG_HAVE_QUERY:
		if (fzn_msg_have_query_parse(in, len, root) != FZN_MSG_OK)
			return 1;
		if (fzn_msg_have_query_encode(root, again, sizeof(again), &out_len) != FZN_MSG_OK)
			return 0;
		break;
	case FZN_MSG_HAVE:
		if (fzn_msg_have_parse(in, len, root, &leaf_count, cookie, out.ranges,
		                       FZN_MSG_MAX_RANGES, &n) != FZN_MSG_OK)
			return 1;
		if (fzn_msg_have_encode(root, leaf_count, cookie, out.ranges, n, again,
		                        sizeof(again), &out_len) != FZN_MSG_OK)
			return 0;
		break;
	case FZN_MSG_WANT:
		if (fzn_msg_want_parse(in, len, &transfer, cookie, root, &first, &count)
		    != FZN_MSG_OK)
			return 1;
		if (fzn_msg_want_encode(transfer, cookie, root, first, count, again,
		                        sizeof(again), &out_len) != FZN_MSG_OK)
			return 0;
		break;
	case FZN_MSG_DATA:
		if (fzn_msg_data_parse(in, len, &transfer, &first, &count, &proof, &proof_count,
		                       out.sealed, out.sealed_len, FZN_MSG_MAX_SPAN)
		    != FZN_MSG_OK)
			return 1;
		if (fzn_msg_data_encode(transfer, first, count, proof, proof_count, out.sealed,
		                        out.sealed_len, again, sizeof(again), &out_len)
		    != FZN_MSG_OK)
			return 0;
		break;
	default:
		return 1;
	}
	return out_len == len && memcmp(again, in, len) == 0;
}

/* One input, parsed every way it might be, with every invariant checked
 * after. Returns non-zero when something is broken. */
static int fuzz_one(const uint8_t *in, size_t len, struct cov *cov)
{
	uint8_t root[FZN_BLOB_HASH_LEN], cookie[FZN_MSG_COOKIE_LEN];
	uint64_t leaf_count = 0, first = 0, count = 0;
	uint32_t transfer = 0;
	unsigned proof_count = 0;
	const uint8_t *proof = NULL;
	fzn_msg_type_t type;
	size_t n = 99u, i;

	arm_canaries();

	if (fzn_msg_peek(in, len, &type) != FZN_MSG_OK) {
		cov->refused++;
		return !canaries_intact();
	}

	switch (type) {
	case FZN_MSG_HAVE_QUERY:
		if (fzn_msg_have_query_parse(in, len, root) != FZN_MSG_OK) {
			cov->refused++;
			break;
		}
		cov->accepted++;
		cov->have_query++;
		break;

	case FZN_MSG_HAVE:
		if (fzn_msg_have_parse(in, len, root, &leaf_count, cookie, out.ranges,
		                       FZN_MSG_MAX_RANGES, &n) != FZN_MSG_OK) {
			cov->refused++;
			break;
		}
		cov->accepted++;
		cov->have++;
		if (n == 0u || n > FZN_MSG_MAX_RANGES)
			return 1;
		if (leaf_count == 0u || leaf_count > FZN_SPOOL_MAX_LEAVES)
			return 1;
		for (i = 0; i < n; i++) {
			/* Inside the blob, and neither side able to wrap. */
			if (out.ranges[i].count == 0u)
				return 1;
			if (out.ranges[i].first > leaf_count)
				return 1;
			if (out.ranges[i].count > leaf_count - out.ranges[i].first)
				return 1;
		}
		break;

	case FZN_MSG_WANT:
		if (fzn_msg_want_parse(in, len, &transfer, cookie, root, &first, &count)
		    != FZN_MSG_OK) {
			cov->refused++;
			break;
		}
		cov->accepted++;
		cov->want++;
		if (count == 0u || count > FZN_MSG_MAX_SPAN)
			return 1;
		if (first > FZN_SPOOL_MAX_LEAVES || count > FZN_SPOOL_MAX_LEAVES - first)
			return 1;
		break;

	case FZN_MSG_DATA:
		if (fzn_msg_data_parse(in, len, &transfer, &first, &count, &proof, &proof_count,
		                       out.sealed, out.sealed_len, FZN_MSG_MAX_SPAN)
		    != FZN_MSG_OK) {
			cov->refused++;
			break;
		}
		cov->accepted++;
		cov->data++;
		if (count == 0u || count > FZN_MSG_MAX_SPAN)
			return 1;
		if (proof_count > FZN_MSG_MAX_PROOF)
			return 1;
		if (proof_count > 0u && (proof < in || proof >= in + len))
			return 1;
		for (i = 0; i < count; i++) {
			/* EVERY LEAF MUST POINT INTO THE MESSAGE. A wrong
			 * offset here is a read into whatever follows the
			 * buffer and the caller cannot tell. */
			if (out.sealed_len[i] == 0u)
				return 1;
			if (out.sealed[i] < in || out.sealed[i] > in + len)
				return 1;
			if ((size_t)(in + len - out.sealed[i]) < out.sealed_len[i])
				return 1;
		}
		break;
	}

	if (!canaries_intact())
		return 1;
	if (cov->accepted > 0u && !round_trips(type, in, len))
		return 1;
	return 0;
}

#ifdef FZN_LIBFUZZER
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct cov cov;

	memset(&cov, 0, sizeof(cov));
	if (fuzz_one(data, size, &cov))
		abort();
	return 0;
}
#else

/* Builds something shaped like a message, so the decoder is reached rather
 * than refused at its first byte. Random bytes essentially never carry a
 * valid version, type and exact length at once; without this the harness
 * would exercise `peek` and nothing else. */
static size_t plausible(uint32_t *s, uint8_t *buf, size_t cap)
{
	static uint8_t leaf[FUZZ_LEAF_MAX];
	const uint8_t *parts[FZN_MSG_MAX_SPAN];
	size_t parts_len[FZN_MSG_MAX_SPAN];
	static uint8_t proof[FZN_MSG_MAX_PROOF * FZN_BLOB_HASH_LEN];
	fzn_spool_range_t ranges[FUZZ_RANGES];
	uint8_t root[FZN_BLOB_HASH_LEN], cookie[FZN_MSG_COOKIE_LEN];
	size_t len = 0, i, n;
	uint64_t leaves = 1u + (next(s) % FUZZ_LEAVES);
	unsigned pc;

	for (i = 0; i < sizeof(root); i++)
		root[i] = (uint8_t)next(s);
	for (i = 0; i < sizeof(cookie); i++)
		cookie[i] = (uint8_t)next(s);
	for (i = 0; i < sizeof(leaf); i++)
		leaf[i] = (uint8_t)next(s);

	switch (next(s) % 4u) {
	case 0:
		if (fzn_msg_have_query_encode(root, buf, cap, &len) != FZN_MSG_OK)
			return 0;
		break;
	case 1:
		n = 1u + (next(s) % FUZZ_RANGES);
		for (i = 0; i < n; i++) {
			ranges[i].first = next(s) % leaves;
			ranges[i].count = 1u + (next(s) % (leaves - ranges[i].first));
		}
		if (fzn_msg_have_encode(root, leaves, cookie, ranges, n, buf, cap, &len)
		    != FZN_MSG_OK)
			return 0;
		break;
	case 2: {
		uint64_t first = next(s) % leaves;
		uint64_t count = 1u + (next(s) % FZN_MSG_MAX_SPAN);

		if (fzn_msg_want_encode(next(s), cookie, root, first, count, buf, cap, &len)
		    != FZN_MSG_OK)
			return 0;
		break;
	}
	default:
		n = 1u + (next(s) % 16u);
		for (i = 0; i < n; i++) {
			parts[i] = leaf;
			parts_len[i] = 1u + (next(s) % FUZZ_LEAF_MAX);
		}
		pc = (unsigned)(next(s) % 4u);
		for (i = 0; i < sizeof(proof); i++)
			proof[i] = (uint8_t)next(s);
		if (fzn_msg_data_encode(next(s), next(s) % leaves, n, proof, pc, parts,
		                        parts_len, buf, cap, &len) != FZN_MSG_OK)
			return 0;
		break;
	}
	return len;
}

/* One occurrence per `per` cases, never zero, so a short run cannot pass by
 * demanding nothing. */
static unsigned long floor_of(unsigned long cases, unsigned long per)
{
	unsigned long f = cases / per;

	return f == 0u ? 1u : f;
}

int main(int argc, char **argv)
{
	static uint8_t buf[BUF_BYTES];
	struct cov cov;
	unsigned long cases = FUZZ_DEFAULT_CASES;
	unsigned long c;

	memset(&cov, 0, sizeof(cov));
	if (argc > 1)
		cases = strtoul(argv[1], NULL, 10);
	if (cases < FUZZ_MIN_CASES) {
		printf("message_fuzz: %lu cases is below the %u-case floor; the coverage "
		       "floors below would be cleared by a single lucky hit. Re-run with "
		       "%u or more.\n",
		       cases, (unsigned)FUZZ_MIN_CASES, (unsigned)FUZZ_MIN_CASES);
		return 1;
	}

	for (c = 0; c < cases; c++) {
		uint32_t state = (uint32_t)c + 1u;
		size_t len;

		/* Three inputs in four are a well-formed message with some
		 * bytes flipped; the fourth is noise, so the refusal paths and
		 * `peek` itself keep being exercised. */
		if ((next(&state) % 4u) != 0u) {
			len = plausible(&state, buf, sizeof(buf));
			if (len == 0u)
				continue;
			{
				unsigned flips = next(&state) % 4u;
				unsigned f;

				for (f = 0; f < flips; f++)
					buf[next(&state) % len] ^= (uint8_t)(1u
					        << (next(&state) % 8u));
			}
		} else {
			len = (size_t)(next(&state) % 128u);
			for (size_t i = 0; i < len; i++)
				buf[i] = (uint8_t)next(&state);
		}

		if (fuzz_one(buf, len, &cov)) {
			printf("message_fuzz: FAILED on case %lu (seed %lu, %zu bytes)\n", c,
			       c + 1u, len);
			return 1;
		}
	}

	/* The harness's own positive control. A generator that produced only
	 * refusals would prove nothing and would otherwise pass silently, so
	 * every message type must have been decoded at least sometimes. */
	if (cov.have_query < floor_of(cases, 200u) || cov.have < floor_of(cases, 200u) ||
	    cov.want < floor_of(cases, 200u) || cov.data < floor_of(cases, 200u) ||
	    cov.refused == 0u) {
		printf("message_fuzz: REACHED NOTHING -- %lu have_query, %lu have, %lu want, "
		       "%lu data, %lu refused in %lu cases. The generator is not producing "
		       "inputs the decoder accepts, so this run proves nothing.\n",
		       cov.have_query, cov.have, cov.want, cov.data, cov.refused, cases);
		return 1;
	}

	printf("message_fuzz: %lu cases, %lu accepted (%lu have_query, %lu have, %lu want, "
	       "%lu data), %lu refused, every accepted message round-tripped\n",
	       cases, cov.accepted, cov.have_query, cov.have, cov.want, cov.data, cov.refused);
	return 0;
}
#endif
