/* Tests for record/store.c: where a record's bytes wait, and the two checks
 * that make sharing the place safe.
 *
 * THE CASE THIS FILE EXISTS FOR is the one project.md sec 132 is built on: a
 * store several processes read and exactly one writes, kept safe not by
 * trusting the store but by every reader checking what it got. So the
 * assertions here are mostly about a store that MISBEHAVES -- one that
 * returns another record, a truncated one, or nothing -- because a store that
 * behaves is the case that cannot tell a guard from its absence.
 *
 * The last case is sec 132's arrangement carried out in one process: an owner
 * puts records in and a reader with its OWN journal replays them, having
 * fetched none of them itself. That is the feature this seam exists for, and
 * without it every function here would be correct and nothing would be wired.
 */

#include "../store.h"
#include "../journal.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

#if defined(__GNUC__)
#define FZN_CHECK_PRINTF __attribute__((format(printf, 3, 4)))
#else
#define FZN_CHECK_PRINTF
#endif

static void check_at(int ok, int line, const char *fmt, ...) FZN_CHECK_PRINTF;

static void check_at(int ok, int line, const char *fmt, ...)
{
	va_list ap;

	checks++;
	if (ok)
		return;

	failures++;
	fprintf(stderr, "  FAIL store_test.c:%d: ", line);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

#define CHECK(cond, ...) check_at((cond) ? 1 : 0, __LINE__, __VA_ARGS__)
#define REQUIRE(cond, ...)                                   \
	do {                                                 \
		int require_ok = (cond) ? 1 : 0;             \
		check_at(require_ok, __LINE__, __VA_ARGS__); \
		if (!require_ok)                             \
			return;                              \
	} while (0)

/* ---- a signer, so the fixtures are real records ------------------------ */

static void tag(uint8_t out[FZN_SIG_LEN], const uint8_t key[FZN_PUBKEY_LEN],
                const uint8_t *msg, size_t msg_len)
{
	uint64_t h = 1469598103934665603u;
	size_t i;

	for (i = 0; i < FZN_PUBKEY_LEN; i++) {
		h ^= key[i];
		h *= 1099511628211u;
	}
	for (i = 0; i < msg_len; i++) {
		h ^= msg[i];
		h *= 1099511628211u;
	}
	for (i = 0; i < FZN_SIG_LEN; i++) {
		h ^= (uint64_t)i;
		h *= 1099511628211u;
		out[i] = (uint8_t)(h >> 32);
	}
}

static uint8_t signing_key[FZN_PUBKEY_LEN];

static int stub_sign(void *ctx, uint8_t sig[FZN_SIG_LEN], const uint8_t *msg, size_t msg_len)
{
	(void)ctx;
	tag(sig, signing_key, msg, msg_len);
	return 1;
}

static int stub_verify(void *ctx, const uint8_t pubkey[FZN_PUBKEY_LEN], const uint8_t *msg,
                       size_t msg_len, const uint8_t sig[FZN_SIG_LEN])
{
	uint8_t want[FZN_SIG_LEN];

	(void)ctx;
	tag(want, pubkey, msg, msg_len);
	return memcmp(want, sig, FZN_SIG_LEN) == 0 ? 1 : 0;
}

static fzn_sign_ops_t SIGN;

/* ---- a backend: a small table, which is what an in-memory store is ----- */

#define SLOTS 16

struct slot {
	uint8_t issuer[FZN_PUBKEY_LEN];
	uint32_t stream;
	uint64_t seq;
	uint8_t bytes[FZN_RECORD_MAX_LEN];
	size_t len;
	int used;
};

struct table {
	struct slot slots[SLOTS];
	/* Knobs, so the misbehaviour a reader must survive can be produced on
	 * demand. A backend that only ever works cannot show a guard working. */
	int put_fails;
	int get_fails_hard;
	int truncate_by;
	int answer_with_slot;
	int puts;
	int gets;
};

static int table_put(void *ctx, const uint8_t issuer[FZN_PUBKEY_LEN], uint32_t stream,
                     uint64_t seq, const uint8_t *bytes, size_t len)
{
	struct table *t = (struct table *)ctx;
	int i;

	t->puts++;
	if (t->put_fails)
		return 0;
	for (i = 0; i < SLOTS; i++) {
		if (t->slots[i].used)
			continue;
		memcpy(t->slots[i].issuer, issuer, FZN_PUBKEY_LEN);
		t->slots[i].stream = stream;
		t->slots[i].seq = seq;
		memcpy(t->slots[i].bytes, bytes, len);
		t->slots[i].len = len;
		t->slots[i].used = 1;
		return 1;
	}
	return 0;
}

static int table_get(void *ctx, const uint8_t issuer[FZN_PUBKEY_LEN], uint32_t stream,
                     uint64_t seq, uint8_t *out, size_t cap, size_t *len_out, int *found_out)
{
	struct table *t = (struct table *)ctx;
	int i;

	t->gets++;
	if (found_out)
		*found_out = 0;

	if (t->get_fails_hard) {
		if (found_out)
			*found_out = 1;
		return 0;
	}

	/* Hand back a nominated slot whatever was asked for -- a store that
	 * misfiles, which is what the placement check exists for. */
	if (t->answer_with_slot >= 0) {
		i = t->answer_with_slot;
	} else {
		for (i = 0; i < SLOTS; i++) {
			if (t->slots[i].used && t->slots[i].stream == stream
			    && t->slots[i].seq == seq
			    && memcmp(t->slots[i].issuer, issuer, FZN_PUBKEY_LEN) == 0)
				break;
		}
		if (i == SLOTS)
			return 0;
	}

	if (!t->slots[i].used)
		return 0;
	if (found_out)
		*found_out = 1;
	if (t->slots[i].len > cap)
		return 0;

	memcpy(out, t->slots[i].bytes, t->slots[i].len);
	*len_out = t->slots[i].len - (size_t)t->truncate_by;
	return 1;
}

static const fzn_record_store_ops_t TABLE_OPS = { table_put, table_get, NULL };

static void table_init(struct table *t, fzn_record_store_ops_t *ops)
{
	memset(t, 0, sizeof(*t));
	t->answer_with_slot = -1;
	*ops = TABLE_OPS;
	ops->ctx = t;
}

/* ---- fixtures ---------------------------------------------------------- */

static uint8_t ISSUER[FZN_PUBKEY_LEN];
static uint8_t OTHER_ISSUER[FZN_PUBKEY_LEN];
static uint8_t SUBJECT[FZN_SUBJECT_LEN];

/* Build a record into `buf` and open it. Returns an unopened view on
 * failure, which every caller REQUIREs against. */
static fzn_record_t make(uint8_t *buf, size_t cap, const uint8_t *issuer, uint32_t stream,
                         uint64_t seq, uint8_t body_byte)
{
	uint8_t body[4];
	fzn_record_t r;
	size_t wrote = 0;

	memset(&r, 0, sizeof(r));
	memset(body, body_byte, sizeof(body));
	memcpy(signing_key, issuer, FZN_PUBKEY_LEN);
	if (fzn_record_sign(issuer, SUBJECT, stream, 1u, seq, 1u, body, sizeof(body), &SIGN,
	                    buf, cap, &wrote) != FZN_RECORD_OK)
		return r;
	if (fzn_record_open(buf, wrote, &r) != FZN_RECORD_OK)
		memset(&r, 0, sizeof(r));
	return r;
}

/* ---- the cases --------------------------------------------------------- */

static void test_a_record_comes_back_as_it_went_in(void)
{
	struct table t;
	fzn_record_store_ops_t ops;
	fzn_record_store_t store;
	uint8_t buf[FZN_RECORD_MAX_LEN], out[FZN_RECORD_MAX_LEN];
	fzn_record_t in, got;

	table_init(&t, &ops);
	REQUIRE(fzn_record_store_init(&store, &ops) == FZN_RECORD_STORE_OK, "init refused");
	in = make(buf, sizeof(buf), ISSUER, 7u, 3u, 0x11);
	REQUIRE(fzn_record_is_open(in), "the fixture would not build");

	CHECK(fzn_record_store_put(&store, in) == FZN_RECORD_STORE_OK, "put refused a record");
	REQUIRE(fzn_record_store_get(&store, ISSUER, 7u, 3u, out, sizeof(out), &got)
	                == FZN_RECORD_STORE_OK,
	        "a stored record could not be read back");
	CHECK(got.len == in.len && memcmp(got.base, in.base, in.len) == 0,
	      "the record that came back is not the one that went in");
	CHECK(got.base == out, "the view does not point into the caller's buffer");
	CHECK(fzn_record_verify(got, &SIGN) == FZN_RECORD_OK,
	      "a record that survived the store no longer verifies");
}

/* THE ADDRESS IS THE RECORD'S, NOT THE CALLER'S. There is no argument to
 * pass a wrong one in, so this checks the backend was told what the record
 * says rather than anything else. */
static void test_put_files_under_the_records_own_address(void)
{
	struct table t;
	fzn_record_store_ops_t ops;
	fzn_record_store_t store;
	uint8_t buf[FZN_RECORD_MAX_LEN];
	fzn_record_t in;

	table_init(&t, &ops);
	REQUIRE(fzn_record_store_init(&store, &ops) == FZN_RECORD_STORE_OK, "init refused");
	in = make(buf, sizeof(buf), ISSUER, 9u, 5u, 0x22);
	REQUIRE(fzn_record_is_open(in), "the fixture would not build");
	REQUIRE(fzn_record_store_put(&store, in) == FZN_RECORD_STORE_OK, "put refused");

	CHECK(t.slots[0].stream == 9u, "the record was filed under another stream");
	CHECK(t.slots[0].seq == 5u, "the record was filed under another sequence");
	CHECK(memcmp(t.slots[0].issuer, ISSUER, FZN_PUBKEY_LEN) == 0,
	      "the record was filed under another issuer");
}

/* A store that hands back somebody else's record must be caught BEFORE the
 * signature is checked, because the record it returns is properly signed. */
static void test_a_misplaced_record_is_refused(void)
{
	struct table t;
	fzn_record_store_ops_t ops;
	fzn_record_store_t store;
	uint8_t a[FZN_RECORD_MAX_LEN], b[FZN_RECORD_MAX_LEN], out[FZN_RECORD_MAX_LEN];
	fzn_record_t ra, rb, got;

	table_init(&t, &ops);
	REQUIRE(fzn_record_store_init(&store, &ops) == FZN_RECORD_STORE_OK, "init refused");
	ra = make(a, sizeof(a), ISSUER, 7u, 1u, 0x31);
	rb = make(b, sizeof(b), ISSUER, 7u, 2u, 0x32);
	REQUIRE(fzn_record_is_open(ra) && fzn_record_is_open(rb), "the fixtures would not build");
	REQUIRE(fzn_record_store_put(&store, ra) == FZN_RECORD_STORE_OK, "put a refused");
	REQUIRE(fzn_record_store_put(&store, rb) == FZN_RECORD_STORE_OK, "put b refused");

	/* THE CONTROL: slot 1 really is a valid, verifying record. Without it
	 * "the get was refused" is satisfied by a store that returns rubbish. */
	CHECK(fzn_record_verify(rb, &SIGN) == FZN_RECORD_OK,
	      "the record the store will misplace does not itself verify");

	t.answer_with_slot = 1;
	CHECK(fzn_record_store_get(&store, ISSUER, 7u, 1u, out, sizeof(out), &got)
	              == FZN_RECORD_STORE_ERR_MISPLACED,
	      "a record filed under another sequence was handed back as the one asked for");

	/* The same, one field over: a different issuer's record at the right
	 * stream and sequence. */
	table_init(&t, &ops);
	REQUIRE(fzn_record_store_init(&store, &ops) == FZN_RECORD_STORE_OK, "re-init refused");
	ra = make(a, sizeof(a), OTHER_ISSUER, 7u, 1u, 0x33);
	REQUIRE(fzn_record_is_open(ra), "the other issuer's fixture would not build");
	REQUIRE(fzn_record_store_put(&store, ra) == FZN_RECORD_STORE_OK, "put refused");
	t.answer_with_slot = 0;
	CHECK(fzn_record_store_get(&store, ISSUER, 7u, 1u, out, sizeof(out), &got)
	              == FZN_RECORD_STORE_ERR_MISPLACED,
	      "another issuer's record was handed back as this issuer's");
}

static void test_absent_and_broken_are_told_apart(void)
{
	struct table t;
	fzn_record_store_ops_t ops;
	fzn_record_store_t store;
	uint8_t out[FZN_RECORD_MAX_LEN];
	fzn_record_t got;

	table_init(&t, &ops);
	REQUIRE(fzn_record_store_init(&store, &ops) == FZN_RECORD_STORE_OK, "init refused");

	CHECK(fzn_record_store_get(&store, ISSUER, 7u, 1u, out, sizeof(out), &got)
	              == FZN_RECORD_STORE_ERR_ABSENT,
	      "an empty store did not answer absent");

	t.get_fails_hard = 1;
	CHECK(fzn_record_store_get(&store, ISSUER, 7u, 1u, out, sizeof(out), &got)
	              == FZN_RECORD_STORE_ERR_BACKEND,
	      "a broken store looked like an empty one, so a reader would refetch the world");
}

static void test_a_truncated_record_is_shape_not_absence(void)
{
	struct table t;
	fzn_record_store_ops_t ops;
	fzn_record_store_t store;
	uint8_t buf[FZN_RECORD_MAX_LEN], out[FZN_RECORD_MAX_LEN];
	fzn_record_t in, got;

	table_init(&t, &ops);
	REQUIRE(fzn_record_store_init(&store, &ops) == FZN_RECORD_STORE_OK, "init refused");
	in = make(buf, sizeof(buf), ISSUER, 7u, 1u, 0x41);
	REQUIRE(fzn_record_is_open(in), "the fixture would not build");
	REQUIRE(fzn_record_store_put(&store, in) == FZN_RECORD_STORE_OK, "put refused");

	t.truncate_by = 3;
	CHECK(fzn_record_store_get(&store, ISSUER, 7u, 1u, out, sizeof(out), &got)
	              == FZN_RECORD_STORE_ERR_SHAPE,
	      "a truncated record was accepted");
}

static void test_the_caller_bugs_are_refused(void)
{
	struct table t;
	fzn_record_store_ops_t ops;
	fzn_record_store_t store;
	uint8_t buf[FZN_RECORD_MAX_LEN], out[FZN_RECORD_MAX_LEN];
	fzn_record_t got, never_opened;

	memset(&never_opened, 0, sizeof(never_opened));
	table_init(&t, &ops);
	CHECK(fzn_record_store_init(NULL, &ops) == FZN_RECORD_STORE_ERR_MALFORMED,
	      "a null store was accepted");
	CHECK(fzn_record_store_init(&store, NULL) == FZN_RECORD_STORE_ERR_MALFORMED,
	      "null ops were accepted");
	ops.put = NULL;
	CHECK(fzn_record_store_init(&store, &ops) == FZN_RECORD_STORE_ERR_MALFORMED,
	      "ops with no put were accepted");
	table_init(&t, &ops);
	ops.get = NULL;
	CHECK(fzn_record_store_init(&store, &ops) == FZN_RECORD_STORE_ERR_MALFORMED,
	      "ops with no get were accepted");

	table_init(&t, &ops);
	REQUIRE(fzn_record_store_init(&store, &ops) == FZN_RECORD_STORE_OK, "init refused");
	CHECK(fzn_record_store_put(&store, never_opened) == FZN_RECORD_STORE_ERR_MALFORMED,
	      "a view that was never opened was filed");
	CHECK(t.puts == 0, "an unopened view reached the backend");
	CHECK(fzn_record_store_get(&store, ISSUER, 7u, 0u, out, sizeof(out), &got)
	              == FZN_RECORD_STORE_ERR_MALFORMED,
	      "sequence zero was answered rather than refused");
	CHECK(t.gets == 0, "sequence zero reached the backend");
	CHECK(fzn_record_store_get(&store, NULL, 7u, 1u, out, sizeof(out), &got)
	              == FZN_RECORD_STORE_ERR_MALFORMED, "a null issuer was accepted");
	CHECK(fzn_record_store_get(&store, ISSUER, 7u, 1u, NULL, sizeof(out), &got)
	              == FZN_RECORD_STORE_ERR_MALFORMED, "a null buffer was accepted");
	CHECK(fzn_record_store_get(&store, ISSUER, 7u, 1u, out, sizeof(out), NULL)
	              == FZN_RECORD_STORE_ERR_MALFORMED, "a null view was accepted");
	(void)buf;
}

static void test_a_failing_put_is_reported(void)
{
	struct table t;
	fzn_record_store_ops_t ops;
	fzn_record_store_t store;
	uint8_t buf[FZN_RECORD_MAX_LEN];
	fzn_record_t in;

	table_init(&t, &ops);
	REQUIRE(fzn_record_store_init(&store, &ops) == FZN_RECORD_STORE_OK, "init refused");
	in = make(buf, sizeof(buf), ISSUER, 7u, 1u, 0x51);
	REQUIRE(fzn_record_is_open(in), "the fixture would not build");

	t.put_fails = 1;
	CHECK(fzn_record_store_put(&store, in) == FZN_RECORD_STORE_ERR_BACKEND,
	      "a refusing backend reported a successful put");
}

/*
 * WHAT THE SEAM IS FOR, carried out in one process.
 *
 * The owner fetches four records and puts them in the store. The reader
 * fetched none of them and has its own journal; it anchors the stream,
 * admits each position, and reads the bytes out of the store -- verifying
 * every one, because the store is not trusted.
 *
 * Without this case every function above is correct and nothing is wired,
 * which is the failure `evidence.md` calls a correct function that is not a
 * working feature.
 */
static void test_a_reader_replays_what_an_owner_fetched(void)
{
	struct table t;
	fzn_record_store_ops_t ops;
	fzn_record_store_t owner_store, reader_store;
	fzn_journal_entry_t entries[4];
	fzn_journal_t reader_journal;
	uint8_t buf[FZN_RECORD_MAX_LEN], out[FZN_RECORD_MAX_LEN];
	fzn_record_t in, got;
	uint64_t seq;
	int verified = 0;

	table_init(&t, &ops);
	REQUIRE(fzn_record_store_init(&owner_store, &ops) == FZN_RECORD_STORE_OK,
	        "the owner's store would not init");
	/* The SAME backend, two store handles -- which is the arrangement: one
	 * store on disk, several processes over it. */
	REQUIRE(fzn_record_store_init(&reader_store, &ops) == FZN_RECORD_STORE_OK,
	        "the reader's store would not init");
	REQUIRE(fzn_journal_init(&reader_journal, entries, 4) == FZN_JOURNAL_OK,
	        "the reader's journal would not init");
	REQUIRE(fzn_journal_anchor(&reader_journal, ISSUER, 7u, 0u) == FZN_JOURNAL_OK,
	        "the reader could not follow the stream");

	for (seq = 1u; seq <= 4u; seq++) {
		in = make(buf, sizeof(buf), ISSUER, 7u, seq, (uint8_t)(0x60u + seq));
		REQUIRE(fzn_record_is_open(in), "the owner could not build record %llu",
		        (unsigned long long)seq);
		REQUIRE(fzn_record_store_put(&owner_store, in) == FZN_RECORD_STORE_OK,
		        "the owner could not store record %llu", (unsigned long long)seq);
	}

	for (seq = 1u; seq <= 4u; seq++) {
		REQUIRE(fzn_record_store_get(&reader_store, ISSUER, 7u, seq, out, sizeof(out),
		                             &got) == FZN_RECORD_STORE_OK,
		        "the reader could not read record %llu it never fetched",
		        (unsigned long long)seq);
		/* THE STORE IS NOT TRUSTED. Every read is verified, which is what
		 * makes a shared cache safe without a shared trust decision. */
		REQUIRE(fzn_record_verify(got, &SIGN) == FZN_RECORD_OK,
		        "record %llu did not verify out of the store",
		        (unsigned long long)seq);
		/* The position comes from the RECORD that was verified, not from
		 * the loop counter -- a journal advanced by what a caller meant
		 * to read rather than by what it actually got is the misplacement
		 * hazard again, one layer up. */
		REQUIRE(fzn_journal_admit(&reader_journal, fzn_record_issuer(got),
		                          fzn_record_stream(got), fzn_record_seq(got))
		                == FZN_JOURNAL_OK,
		        "the reader's journal refused record %llu",
		        (unsigned long long)seq);
		verified++;
	}

	CHECK(verified == 4, "the reader did not replay every record the owner fetched");
	CHECK(fzn_journal_next(&reader_journal, ISSUER, 7u) == 5u,
	      "the reader's journal is not caught up after replaying four records");
	CHECK(t.puts == 4 && t.gets == 4, "the backend was not used once per record");
}

static void test_the_errors_render(void)
{
	CHECK(fzn_record_store_err_str(FZN_RECORD_STORE_OK)[0] != '\0', "OK renders empty");
	CHECK(fzn_record_store_err_str(FZN_RECORD_STORE_ERR_MALFORMED)[0] != '\0',
	      "MALFORMED renders empty");
	CHECK(fzn_record_store_err_str(FZN_RECORD_STORE_ERR_ABSENT)[0] != '\0',
	      "ABSENT renders empty");
	CHECK(fzn_record_store_err_str(FZN_RECORD_STORE_ERR_BACKEND)[0] != '\0',
	      "BACKEND renders empty");
	CHECK(fzn_record_store_err_str(FZN_RECORD_STORE_ERR_SHAPE)[0] != '\0',
	      "SHAPE renders empty");
	CHECK(fzn_record_store_err_str(FZN_RECORD_STORE_ERR_MISPLACED)[0] != '\0',
	      "MISPLACED renders empty");
	CHECK(fzn_record_store_err_str((fzn_record_store_err_t)-99)[0] != '\0',
	      "an unknown error renders empty");
}

static void test_the_suite_can_tell_pass_from_fail(void)
{
	int before = failures;

	check_at(0, __LINE__, "deliberate");
	CHECK(failures == before + 1, "a failing check did not count");
	failures = before;
	checks -= 1;
}

#ifdef FZN_FLOG_ON
#include "flog.h"

/* Borrowed strings, so anything kept is copied. */
static struct {
	int calls;
	flog_msg_type_t type;
	char subsystem[64];
	char text[512];
} rstore_log_seen;

static int rstore_log_capture(flog_t *p, const flog_msg_t *m)
{
	(void)p;
	rstore_log_seen.calls++;
	rstore_log_seen.type = m->type;
	rstore_log_seen.subsystem[0] = '\0';
	rstore_log_seen.text[0] = '\0';
	if (m->subsystem)
		snprintf(rstore_log_seen.subsystem, sizeof(rstore_log_seen.subsystem), "%s",
		         m->subsystem);
	if (m->text)
		snprintf(rstore_log_seen.text, sizeof(rstore_log_seen.text), "%s", m->text);
	return 0;
}

/*
 * A MISPLACED RECORD IS A STORAGE FAULT, NOT A PROTOCOL ONE. sec 216.
 *
 * The record handed back may be perfectly well signed -- which is why a
 * signature check further up would not have caught it -- so this layer is the
 * only one that can see that what came back is not what was asked for. The
 * return value names the fault and not the discrepancy, and the discrepancy is
 * what tells somebody whether their backend is confusing sequences or
 * issuers.
 */
static void test_the_store_says_what_came_back_instead(void)
{
	struct table t;
	fzn_record_store_ops_t ops;
	fzn_record_store_t store;
	fzn_record_t ra, rb;
	uint8_t a[FZN_RECORD_MAX_LEN], b[FZN_RECORD_MAX_LEN], out[FZN_RECORD_MAX_LEN];
	fzn_record_t got;
	flog_t log;

	init_flog_t(&log);
	log.name = NULL;
	log.accepted_msg_type = FLOG_ACCEPT_ALL;
	log.output_func = rstore_log_capture;

	table_init(&t, &ops);
	REQUIRE(fzn_record_store_init(&store, &ops) == FZN_RECORD_STORE_OK, "init refused");
	/* Sequence starts at one here; zero is not a record this store holds. */
	ra = make(a, sizeof(a), ISSUER, 7u, 1u, 0x31);
	rb = make(b, sizeof(b), ISSUER, 7u, 2u, 0x32);
	REQUIRE(fzn_record_is_open(ra) && fzn_record_is_open(rb), "fixtures");
	REQUIRE(fzn_record_store_put(&store, ra) == FZN_RECORD_STORE_OK, "put a");
	REQUIRE(fzn_record_store_put(&store, rb) == FZN_RECORD_STORE_OK, "put b");

	/* QUIET UNTIL ASKED: planted before the init that clears it. */
	fzn_record_store_set_log(&store, &log);
	REQUIRE(fzn_record_store_init(&store, &ops) == FZN_RECORD_STORE_OK, "re-init");
	memset(&rstore_log_seen, 0, sizeof(rstore_log_seen));
	t.answer_with_slot = 1;
	CHECK(fzn_record_store_get(&store, ISSUER, 7u, 1u, out, sizeof(out), &got)
	              == FZN_RECORD_STORE_ERR_MISPLACED,
	      "a misplaced record was accepted");
	CHECK(rstore_log_seen.calls == 0, "a store nobody gave a log to emitted anyway");

	fzn_record_store_set_log(&store, &log);
	memset(&rstore_log_seen, 0, sizeof(rstore_log_seen));
	CHECK(fzn_record_store_get(&store, ISSUER, 7u, 1u, out, sizeof(out), &got)
	              == FZN_RECORD_STORE_ERR_MISPLACED,
	      "a misplaced record was accepted");
	CHECK(rstore_log_seen.calls == 1, "a misplaced record was refused and nothing said so");
	CHECK(rstore_log_seen.type == FLOG_ERR,
	      "a storage-integrity fault was not reported as an error");
	CHECK(strcmp(rstore_log_seen.subsystem, "record/store") == 0,
	      "the event did not name its subsystem");
	CHECK(strstr(rstore_log_seen.text, "wanted stream") != NULL,
	      "the line names the fault and not the discrepancy, which is what says "
	      "whether a backend is confusing sequences or issuers");
}
#endif

int main(void)
{
	memset(ISSUER, 0xa1, sizeof(ISSUER));
	memset(OTHER_ISSUER, 0xb2, sizeof(OTHER_ISSUER));
	memset(SUBJECT, 0x51, sizeof(SUBJECT));
	memset(&SIGN, 0, sizeof(SIGN));
	SIGN.sign = stub_sign;
	SIGN.verify = stub_verify;
	SIGN.ctx = NULL;

	test_a_record_comes_back_as_it_went_in();
	test_put_files_under_the_records_own_address();
	test_a_misplaced_record_is_refused();
	test_absent_and_broken_are_told_apart();
	test_a_truncated_record_is_shape_not_absence();
	test_the_caller_bugs_are_refused();
	test_a_failing_put_is_reported();
	test_a_reader_replays_what_an_owner_fetched();
	test_the_errors_render();
	test_the_suite_can_tell_pass_from_fail();

#ifdef FZN_FLOG_ON
	test_the_store_says_what_came_back_instead();
#endif

	printf("store_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
