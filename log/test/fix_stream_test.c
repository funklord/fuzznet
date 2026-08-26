/* A telemetry stream, built on `record/` and `log/` with no new module.
 *
 * WHAT THIS IS EVIDENCE FOR. fuzzypickles' `location.c` is described in its
 * own header as "a log-type subsystem like log_relay and group chat history:
 * the same (origin, seq) append-only stream over append_log, with the same
 * dedup, high-water and catch-up behaviour". If that is true, absorbing it
 * needs no machinery -- the machinery is already here -- and the way to find
 * out is to build one and see what is missing.
 *
 * Nothing was. This file is that demonstration, and it is a test rather than
 * a module because **there is nothing to add**.
 *
 * WHAT STAYED OUT, AND WHY IT HAD TO. A fix is 19 bytes of packed
 * little-endian latitude, longitude, time, quantised accuracy and bearing,
 * and a flags byte. That is an ENCODING, and sec 2 keeps encodings out of this
 * library for the same reason `log/` took `append_log`'s sequencing and left
 * its `"<seq> <escaped text>"` line format behind: netcfgd would reject it,
 * and a library that owned one consumer's record layout would have chosen
 * that consumer's product.
 *
 * So the fix below is packed and unpacked BY THIS TEST, exactly as a consumer
 * would, and everything between the two is fuzznet's. The point is the seam:
 * `record/` carries an opaque body, and neither `log/` nor anything under it
 * ever learns what these nineteen bytes mean.
 *
 * THE THIRD KIND OF STREAM. Permissions, logs and now telemetry all ride the
 * same (issuer, seq) machinery, which is the claim sec 5 rests on when it says
 * the three consumers use this library in almost exactly the same way. Two
 * kinds would be a coincidence.
 *
 * "KIND" IS A LABEL AND "STREAM" IS THE KEY, and the two are not
 * interchangeable however alike the words sound. `log.c` keys on (issuer,
 * stream, seq) and never looks at `kind`, so what keeps one host's telemetry
 * out of its configuration's sequence space is `stream` alone. This file said
 * the opposite for as long as it has existed; the last block is the test that
 * stops it being said again.
 */

#include "../../chain/chain.h" /* fzn_sign_ops_t */
#include "../log.h"

#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

static void expect(int ok, const char *what)
{
	checks++;
	if (!ok) {
		failures++;
		printf("  FAIL: %s\n", what);
	}
}

/* The consumer's own layout, and the consumer's own arithmetic. Nineteen
 * bytes: two signed degrees at 1e7, a UTC second, accuracy and bearing codes,
 * and flags. Little-endian, packed by hand -- which is what a consumer does
 * and what this library declines to do for it. */
#define FIX_SIZE 19u

static void fix_pack(uint8_t out[FIX_SIZE], int32_t lat_e7, int32_t lon_e7, uint32_t utc_s,
                     uint8_t acc, uint8_t bearing, uint8_t flags)
{
	out[0] = (uint8_t)(lat_e7 & 0xff);
	out[1] = (uint8_t)((lat_e7 >> 8) & 0xff);
	out[2] = (uint8_t)((lat_e7 >> 16) & 0xff);
	out[3] = (uint8_t)((lat_e7 >> 24) & 0xff);
	out[4] = (uint8_t)(lon_e7 & 0xff);
	out[5] = (uint8_t)((lon_e7 >> 8) & 0xff);
	out[6] = (uint8_t)((lon_e7 >> 16) & 0xff);
	out[7] = (uint8_t)((lon_e7 >> 24) & 0xff);
	out[8] = (uint8_t)(utc_s & 0xff);
	out[9] = (uint8_t)((utc_s >> 8) & 0xff);
	out[10] = (uint8_t)((utc_s >> 16) & 0xff);
	out[11] = (uint8_t)((utc_s >> 24) & 0xff);
	out[12] = acc;
	out[13] = bearing;
	out[14] = flags;
	out[15] = 0;
	out[16] = 0;
	out[17] = 0;
	out[18] = 0;
}

static int32_t fix_lat(const uint8_t *b)
{
	return (int32_t)((uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) |
	                 ((uint32_t)b[3] << 24));
}

#define TRACK 12u
#define FLAG_COARSE 0x01u

/* A signer and storage for the fixture's records.
 *
 * A record is a VIEW over the bytes its signature covers, so a fixture
 * encodes one rather than filling a struct -- which is the property bought:
 * a field cannot disagree with the signature because there is only one of
 * them. This suite never verifies, so the signer answers for nobody in
 * particular; what it must do is sign the bytes it is handed. */
static int fixture_sign(void *ctx, uint8_t sig[FZN_SIG_LEN], const uint8_t *msg, size_t msg_len)
{
	uint32_t acc = 0x9e3779b9u;
	size_t i;

	(void)ctx;
	for (i = 0; i < msg_len; i++)
		acc = (acc * 31u) + msg[i];
	for (i = 0; i < FZN_SIG_LEN; i++)
		sig[i] = (uint8_t)(acc >> ((i % 4u) * 8u));
	return 1;
}

#define WIRE_SLOTS 32u
static uint8_t wire_pool[WIRE_SLOTS][FZN_RECORD_MAX_LEN];
static size_t wire_next;

static int fixture_record(fzn_record_t *r, const uint8_t issuer[FZN_PUBKEY_LEN], uint32_t stream,
                          uint32_t kind, uint64_t seq, const uint8_t *body, size_t body_len)
{
	uint8_t subject[FZN_SUBJECT_LEN];
	fzn_sign_ops_t ops;
	uint8_t *slot = wire_pool[wire_next % WIRE_SLOTS];
	size_t wrote = 0;

	wire_next++;
	memset(subject, 0, sizeof(subject));
	memset(&ops, 0, sizeof(ops));
	ops.sign = fixture_sign;

	if (fzn_record_sign(issuer, subject, stream, kind, seq, 1, body, body_len, &ops, slot,
	                    FZN_RECORD_MAX_LEN, &wrote) != FZN_RECORD_OK)
		return 0;
	return fzn_record_open(slot, wrote, r) == FZN_RECORD_OK;
}


int main(void)
{
	fzn_log_t track;
	fzn_log_entry_t rows[4];
	/* A CONSUMER OF A TRACK KEEPS A POSITION LIKE ANY OTHER CONSUMER, and
	 * `fzn_log_get` needs it: whether an aged-out fix is GONE or was never
	 * sent is a question about what this host RECEIVED, which the log
	 * cannot answer once it has evicted the evidence. */
	fzn_journal_t position;
	fzn_journal_entry_t seen[2];
	static uint8_t fixes[8][FIX_SIZE];
	fzn_record_t rec;
	const fzn_log_entry_t *got;
	const fzn_log_entry_t *page[8];
	uint8_t receiver[FZN_PUBKEY_LEN];
	uint64_t first, last;

	memset(receiver, 0x77, sizeof(receiver));
	expect(fzn_log_init(&track, rows, 4) == FZN_LOG_OK, "a track is an ordinary log");
	expect(fzn_journal_init(&position, seen, 2) == FZN_JOURNAL_OK, "and an ordinary position");
	expect(fzn_journal_anchor(&position, receiver, 0, 0) == FZN_JOURNAL_OK,
	       "followed from the beginning");

	/* Six fixes along a path, appended as an (issuer, seq) stream. */
	for (uint64_t seq = 1; seq <= 6; seq++) {
		uint8_t *body = fixes[seq - 1u];

		fix_pack(body, 515000000 + (int32_t)seq * 1000, -1200000, 1700000000u + (uint32_t)seq,
		         3, 90, 0);
		expect(fixture_record(&rec, receiver, 0, TRACK, seq, body, FIX_SIZE),
		       "the fixture could not build a record");
		expect(fzn_log_append(&track, &rec) == FZN_LOG_OK, "appending a fix");
		expect(fzn_journal_admit(&position, receiver, 0, seq) == FZN_JOURNAL_OK,
		       "and taking it into the position");
	}

	/* RETENTION IS THE SAME RETENTION. A track is bounded like any stream,
	 * and the oldest fixes age out. */
	fzn_log_range(&track, receiver, 0, &first, &last);
	expect(first == 3 && last == 6, "a four-entry log holds the last four fixes");
	expect(fzn_log_dropped(&track) == 2, "and says it dropped two");
	expect(fzn_log_get(&track, &position, receiver, 0, 1, &got) == FZN_LOG_ERR_GONE,
	       "an aged-out fix answers GONE, exactly as a log line does");
	expect(fzn_log_get(&track, &position, receiver, 0, 7, &got) == FZN_LOG_ERR_ABSENT,
	       "and a fix that has not been taken yet answers ABSENT");

	/* SERVING A CATCH-UP IS THE SAME SERVING. */
	{
		size_t n = fzn_log_read_since(&track, receiver, 0, 4, page, 8);

		expect(n == 2, "two fixes after the fourth");
		expect(n == 2 && page[0]->seq == 5 && page[1]->seq == 6, "oldest first");
		/* And the bytes are the consumer's, unchanged and uninterpreted
		 * on the way through. */
		expect(n == 2 && fix_lat(page[0]->body) == 515005000,
		       "the fix survived the library without being understood by it");
		expect(n == 2 && page[0]->body_len == FIX_SIZE, "at its own length");
	}

	/* A COARSE FIX IS AN ORDINARY ENTRY. Per-peer precision degradation is
	 * an open design question in fuzzypickles and is not solved here -- but
	 * nothing in this library stands in its way, because a degraded fix is
	 * just different bytes under the same sequence. */
	{
		uint8_t *body = fixes[6];

		fix_pack(body, 515000000, -1200000, 1700000007u, 200, 0, FLAG_COARSE);
		expect(fixture_record(&rec, receiver, 0, TRACK, 7, body, FIX_SIZE),
		       "the fixture could not build a record");
		expect(fzn_log_append(&track, &rec) == FZN_LOG_OK, "appending a coarse fix");
		expect(fzn_journal_admit(&position, receiver, 0, 7) == FZN_JOURNAL_OK, "and taking it");
		expect(fzn_log_get(&track, &position, receiver, 0, 7, &got) == FZN_LOG_OK,
		       "and reading it back");
		expect(got != NULL && (got->body[14] & FLAG_COARSE) != 0,
		       "the flag is the consumer's to set and read");
	}

	/* A DIFFERENT KIND IS NOT A DIFFERENT STREAM, and this comment used to
	 * say it was -- "which is what lets one host carry telemetry and
	 * configuration without either knowing about the other". It does not.
	 * `log.c` keys an entry on (ISSUER, STREAM, SEQ); `kind` is carried
	 * beside them and compared by nothing. Two records differing only in
	 * their kind are the SAME entry, and the second is refused as a
	 * duplicate.
	 *
	 * The claim was wrong in a way that reads as safe, which is why it
	 * needs a test rather than a correction: a consumer that believed it
	 * would number its telemetry and its configuration in one sequence
	 * space, and every configuration record whose sequence a fix had
	 * already used would be silently dropped as an echo. What actually
	 * separates them is `stream`, exactly as `record/record.h` and the
	 * journal's per-(issuer, stream) position say -- and the pair below
	 * pins both halves so that neither can drift back into prose. */
	expect(fzn_log_get(&track, &position, receiver, 0, 7, &got) == FZN_LOG_OK &&
	           got->kind == TRACK,
	       "the kind travels with the entry");
	{
		const uint32_t OTHER_KIND = TRACK + 1u;
		uint8_t *body = fixes[7];

		fix_pack(body, 0, 0, 1700000008u, 0, 0, 0);
		expect(fixture_record(&rec, receiver, 0, OTHER_KIND, 7, body, FIX_SIZE),
		       "the fixture could not build a record");
		expect(fzn_log_append(&track, &rec) == FZN_LOG_ERR_DUPLICATE,
		       "a different kind at a held sequence is a duplicate, not a second entry");
		expect(fzn_log_get(&track, &position, receiver, 0, 7, &got) == FZN_LOG_OK &&
		           got->kind == TRACK,
		       "and the entry that was already there is untouched");

		/* THE STREAM IS WHAT SEPARATES THEM. The same issuer, the same
		 * sequence, the same kind even -- a different stream, and it is
		 * a different entry. */
		expect(fixture_record(&rec, receiver, 1, OTHER_KIND, 7, body, FIX_SIZE),
		       "the fixture could not build a record on another stream");
		expect(fzn_log_append(&track, &rec) == FZN_LOG_OK,
		       "the same sequence in another stream is a new entry");
	}

	printf("fix_stream_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
