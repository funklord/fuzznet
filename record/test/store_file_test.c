/* Tests for record/store_file.c: the sparse-slot backend behind the store
 * seam.
 *
 * THE CASES THIS FILE EXISTS FOR are the three properties project.md sec 135
 * claims and nothing else can check: that an unwritten slot reads as absent
 * without anything recording its absence, that a slot written out of order --
 * bytes without a length -- reads as absent rather than as a record, and that
 * the file really is sparse, so the space a high sequence implies is not the
 * space it costs.
 *
 * The last of those is measured with `stat`, comparing blocks against size,
 * because "it is sparse" is otherwise a claim about the filesystem that
 * nobody took.
 *
 * HOW IT TERMINATES: no forks, no loops without a bound. The scratch
 * directory is named for the process and every file in it is removed by name
 * -- a sweep over a prefix would take a concurrent run's, which on this
 * machine is somebody else's live state -- and the removals are checked,
 * because a cleanup nobody reads is how a directory fills under a green
 * suite.
 */
#define _POSIX_C_SOURCE 200809L

#include "../store_file.h"

#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

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
	fprintf(stderr, "  FAIL store_file_test.c:%d: ", line);
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
static uint8_t ISSUER[FZN_PUBKEY_LEN];
static uint8_t OTHER_ISSUER[FZN_PUBKEY_LEN];
static uint8_t SUBJECT[FZN_SUBJECT_LEN];

/* Named for the process so two runs cannot collide, and removed BY NAME. */
static char dir[128];

static fzn_record_t make(uint8_t *buf, size_t cap, const uint8_t *issuer, uint32_t stream,
                         uint64_t seq, size_t body_len)
{
	uint8_t body[FZN_RECORD_BODY_MAX];
	fzn_record_t r;
	size_t wrote = 0;

	memset(&r, 0, sizeof(r));
	memset(body, (int)(seq & 0xffu), body_len);
	memcpy(signing_key, issuer, FZN_PUBKEY_LEN);
	if (fzn_record_sign(issuer, SUBJECT, stream, 1u, seq, 1u, body, body_len, &SIGN, buf,
	                    cap, &wrote) != FZN_RECORD_OK)
		return r;
	if (fzn_record_open(buf, wrote, &r) != FZN_RECORD_OK)
		memset(&r, 0, sizeof(r));
	return r;
}

/* The path this backend derives, reproduced here so the suite can look at
 * the file it wrote. If the two ever disagree the sparse case fails, which
 * is the only reason it is safe to have a second copy of this rule. */
static void stream_path(char *out, size_t cap, const uint8_t *issuer, uint32_t stream)
{
	static const char DIGITS[] = "0123456789abcdef";
	char issuer_hex[FZN_PUBKEY_LEN * 2u + 1u];
	size_t i;

	for (i = 0; i < FZN_PUBKEY_LEN; i++) {
		issuer_hex[i * 2u] = DIGITS[issuer[i] >> 4];
		issuer_hex[i * 2u + 1u] = DIGITS[issuer[i] & 0x0fu];
	}
	issuer_hex[FZN_PUBKEY_LEN * 2u] = '\0';
	snprintf(out, cap, "%s/%s-%08lx.rec", dir, issuer_hex, (unsigned long)stream);
}

static void unlink_stream(const uint8_t *issuer, uint32_t stream)
{
	char path[512];

	stream_path(path, sizeof(path), issuer, stream);
	(void)unlink(path);
}

/* ---- the cases --------------------------------------------------------- */

static void test_a_record_survives_the_round_trip(void)
{
	fzn_record_store_file_t backend;
	const fzn_record_store_ops_t *ops;
	fzn_record_store_t store;
	uint8_t buf[FZN_RECORD_MAX_LEN], out[FZN_RECORD_MAX_LEN];
	fzn_record_t in, got;

	ops = fzn_record_store_file_open(&backend, dir);
	REQUIRE(ops != NULL, "the backend would not open");
	REQUIRE(fzn_record_store_init(&store, ops) == FZN_RECORD_STORE_OK, "init refused");

	in = make(buf, sizeof(buf), ISSUER, 3u, 1u, 4u);
	REQUIRE(fzn_record_is_open(in), "the fixture would not build");
	CHECK(fzn_record_store_put(&store, in) == FZN_RECORD_STORE_OK, "put refused");
	REQUIRE(fzn_record_store_get(&store, ISSUER, 3u, 1u, out, sizeof(out), &got)
	                == FZN_RECORD_STORE_OK,
	        "a stored record could not be read back");
	CHECK(got.len == in.len && memcmp(got.base, in.base, in.len) == 0,
	      "the record that came back is not the one that went in");
	CHECK(fzn_record_verify(got, &SIGN) == FZN_RECORD_OK,
	      "a record that survived the file no longer verifies");

	fzn_record_store_file_close(&backend);
	unlink_stream(ISSUER, 3u);
}

/* A body of zero and a body at the bound, because the length prefix is the
 * one field this layout adds and both ends of it should survive. */
static void test_both_ends_of_the_length_survive(void)
{
	fzn_record_store_file_t backend;
	const fzn_record_store_ops_t *ops;
	fzn_record_store_t store;
	uint8_t buf[FZN_RECORD_MAX_LEN], out[FZN_RECORD_MAX_LEN];
	fzn_record_t in, got;

	ops = fzn_record_store_file_open(&backend, dir);
	REQUIRE(ops != NULL, "the backend would not open");
	REQUIRE(fzn_record_store_init(&store, ops) == FZN_RECORD_STORE_OK, "init refused");

	in = make(buf, sizeof(buf), ISSUER, 4u, 1u, 0u);
	REQUIRE(fzn_record_is_open(in), "the empty-bodied fixture would not build");
	REQUIRE(fzn_record_store_put(&store, in) == FZN_RECORD_STORE_OK, "put refused an empty body");
	REQUIRE(fzn_record_store_get(&store, ISSUER, 4u, 1u, out, sizeof(out), &got)
	                == FZN_RECORD_STORE_OK, "an empty-bodied record would not read back");
	CHECK(got.len == in.len, "the shortest record changed length");

	in = make(buf, sizeof(buf), ISSUER, 4u, 2u, FZN_RECORD_BODY_MAX);
	REQUIRE(fzn_record_is_open(in), "the full fixture would not build");
	REQUIRE(fzn_record_store_put(&store, in) == FZN_RECORD_STORE_OK, "put refused a full body");
	REQUIRE(fzn_record_store_get(&store, ISSUER, 4u, 2u, out, sizeof(out), &got)
	                == FZN_RECORD_STORE_OK, "a full record would not read back");
	CHECK(got.len == in.len && got.len == FZN_RECORD_MAX_LEN,
	      "the longest record did not fit its slot");

	fzn_record_store_file_close(&backend);
	unlink_stream(ISSUER, 4u);
}

/* THE HOLE. Writing sequence 9 must leave 1..8 absent, with nothing anywhere
 * recording that they are missing. */
static void test_an_unwritten_slot_reads_as_absent(void)
{
	fzn_record_store_file_t backend;
	const fzn_record_store_ops_t *ops;
	fzn_record_store_t store;
	uint8_t buf[FZN_RECORD_MAX_LEN], out[FZN_RECORD_MAX_LEN];
	fzn_record_t in, got;
	uint64_t seq;
	int absent = 0;

	ops = fzn_record_store_file_open(&backend, dir);
	REQUIRE(ops != NULL, "the backend would not open");
	REQUIRE(fzn_record_store_init(&store, ops) == FZN_RECORD_STORE_OK, "init refused");

	in = make(buf, sizeof(buf), ISSUER, 5u, 9u, 8u);
	REQUIRE(fzn_record_is_open(in), "the fixture would not build");
	REQUIRE(fzn_record_store_put(&store, in) == FZN_RECORD_STORE_OK, "put refused");

	for (seq = 1u; seq <= 8u; seq++) {
		if (fzn_record_store_get(&store, ISSUER, 5u, seq, out, sizeof(out), &got)
		    == FZN_RECORD_STORE_ERR_ABSENT)
			absent++;
	}
	CHECK(absent == 8, "%d of the eight slots before a written one were not absent",
	      8 - absent);
	/* THE CONTROL: the slot that WAS written is not absent, so "absent"
	 * above is not simply what this backend always says. */
	CHECK(fzn_record_store_get(&store, ISSUER, 5u, 9u, out, sizeof(out), &got)
	              == FZN_RECORD_STORE_OK,
	      "the written slot was absent too, so the check above says nothing");
	CHECK(fzn_record_store_get(&store, ISSUER, 5u, 10u, out, sizeof(out), &got)
	              == FZN_RECORD_STORE_ERR_ABSENT, "past the end was not absent");

	fzn_record_store_file_close(&backend);
	unlink_stream(ISSUER, 5u);
}

/*
 * THE CRASH ORDER. `put` writes the bytes and then the length, so a process
 * that dies between them leaves a slot with bytes and a zero length. That is
 * reproduced here by writing the record's bytes into the slot directly and
 * never writing the prefix -- which is exactly the state a crash leaves --
 * and the reader must call it absent rather than framing whatever follows.
 */
static void test_bytes_without_a_length_are_absent(void)
{
	fzn_record_store_file_t backend;
	const fzn_record_store_ops_t *ops;
	fzn_record_store_t store;
	uint8_t buf[FZN_RECORD_MAX_LEN], out[FZN_RECORD_MAX_LEN];
	fzn_record_t in, got;
	char path[512];
	int fd;

	in = make(buf, sizeof(buf), ISSUER, 6u, 1u, 16u);
	REQUIRE(fzn_record_is_open(in), "the fixture would not build");

	stream_path(path, sizeof(path), ISSUER, 6u);
	fd = open(path, O_RDWR | O_CREAT, 0600);
	REQUIRE(fd >= 0, "the half-written slot could not be made");
	/* The record's bytes at the slot's data offset, and NO length prefix. */
	REQUIRE(pwrite(fd, in.base, in.len, 2) == (ssize_t)in.len,
	        "the record's bytes could not be written");
	REQUIRE(close(fd) == 0, "the half-written slot could not be closed");

	ops = fzn_record_store_file_open(&backend, dir);
	REQUIRE(ops != NULL, "the backend would not open");
	REQUIRE(fzn_record_store_init(&store, ops) == FZN_RECORD_STORE_OK, "init refused");

	CHECK(fzn_record_store_get(&store, ISSUER, 6u, 1u, out, sizeof(out), &got)
	              == FZN_RECORD_STORE_ERR_ABSENT,
	      "a slot holding bytes with no length was read as a record");

	fzn_record_store_file_close(&backend);
	unlink_stream(ISSUER, 6u);
}

/* A wrong length cannot produce a wrong record, because the seam checks
 * shape and placement over whatever this hands back. */
static void test_a_corrupt_length_is_refused_not_believed(void)
{
	fzn_record_store_file_t backend;
	const fzn_record_store_ops_t *ops;
	fzn_record_store_t store;
	uint8_t buf[FZN_RECORD_MAX_LEN], out[FZN_RECORD_MAX_LEN];
	uint8_t prefix[2];
	fzn_record_t in, got;
	char path[512];
	int fd;
	fzn_record_store_err_t err;

	ops = fzn_record_store_file_open(&backend, dir);
	REQUIRE(ops != NULL, "the backend would not open");
	REQUIRE(fzn_record_store_init(&store, ops) == FZN_RECORD_STORE_OK, "init refused");
	in = make(buf, sizeof(buf), ISSUER, 8u, 1u, 32u);
	REQUIRE(fzn_record_is_open(in), "the fixture would not build");
	REQUIRE(fzn_record_store_put(&store, in) == FZN_RECORD_STORE_OK, "put refused");
	fzn_record_store_file_close(&backend);

	/* Bend the length by one, which is what a torn two-byte write can do. */
	stream_path(path, sizeof(path), ISSUER, 8u);
	fd = open(path, O_RDWR, 0600);
	REQUIRE(fd >= 0, "the slot could not be reopened");
	prefix[0] = (uint8_t)((in.len - 1u) >> 8);
	prefix[1] = (uint8_t)((in.len - 1u) & 0xffu);
	REQUIRE(pwrite(fd, prefix, sizeof(prefix), 0) == 2, "the length could not be bent");
	REQUIRE(close(fd) == 0, "the slot could not be closed");

	ops = fzn_record_store_file_open(&backend, dir);
	REQUIRE(ops != NULL, "the backend would not reopen");
	REQUIRE(fzn_record_store_init(&store, ops) == FZN_RECORD_STORE_OK, "re-init refused");
	err = fzn_record_store_get(&store, ISSUER, 8u, 1u, out, sizeof(out), &got);
	CHECK(err == FZN_RECORD_STORE_ERR_SHAPE || err == FZN_RECORD_STORE_ERR_MISPLACED,
	      "a bent length produced something other than a refusal: %s",
	      fzn_record_store_err_str(err));

	fzn_record_store_file_close(&backend);
	unlink_stream(ISSUER, 8u);
}

/* THE SPARSENESS, MEASURED. A record at a high sequence must not cost the
 * blocks its offset implies -- otherwise the fixed-slot layout is paying its
 * whole cost rather than only the slots written. */
static void test_the_file_is_sparse(void)
{
	fzn_record_store_file_t backend;
	const fzn_record_store_ops_t *ops;
	fzn_record_store_t store;
	uint8_t buf[FZN_RECORD_MAX_LEN];
	fzn_record_t in;
	struct stat st;
	char path[512];
	long long implied, used;

	ops = fzn_record_store_file_open(&backend, dir);
	REQUIRE(ops != NULL, "the backend would not open");
	REQUIRE(fzn_record_store_init(&store, ops) == FZN_RECORD_STORE_OK, "init refused");

	in = make(buf, sizeof(buf), ISSUER, 11u, 20000u, 8u);
	REQUIRE(fzn_record_is_open(in), "the fixture would not build");
	REQUIRE(fzn_record_store_put(&store, in) == FZN_RECORD_STORE_OK, "put refused");
	fzn_record_store_file_close(&backend);

	stream_path(path, sizeof(path), ISSUER, 11u);
	REQUIRE(stat(path, &st) == 0, "the stream file could not be measured");

	implied = (long long)st.st_size;
	used = (long long)st.st_blocks * 512;
	CHECK(implied > 13000000, "the file is not as large as sequence 20000 implies: %lld",
	      implied);
	/* Generous, because a filesystem may round to any block size -- what is
	 * being refused is the file being FULLY allocated, which is the case
	 * the header warns about. */
	CHECK(used < implied / 100,
	      "the file is not sparse: %lld bytes of blocks for %lld bytes of size", used,
	      implied);

	unlink_stream(ISSUER, 11u);
}

/* Two issuers and two streams are four files, so nothing can be read out of
 * another's. The cached descriptor is what could get this wrong. */
static void test_streams_and_issuers_do_not_share_a_file(void)
{
	fzn_record_store_file_t backend;
	const fzn_record_store_ops_t *ops;
	fzn_record_store_t store;
	uint8_t buf[FZN_RECORD_MAX_LEN], out[FZN_RECORD_MAX_LEN];
	fzn_record_t a, b, got;

	ops = fzn_record_store_file_open(&backend, dir);
	REQUIRE(ops != NULL, "the backend would not open");
	REQUIRE(fzn_record_store_init(&store, ops) == FZN_RECORD_STORE_OK, "init refused");

	a = make(buf, sizeof(buf), ISSUER, 12u, 1u, 4u);
	REQUIRE(fzn_record_is_open(a), "fixture a would not build");
	REQUIRE(fzn_record_store_put(&store, a) == FZN_RECORD_STORE_OK, "put a refused");
	b = make(buf, sizeof(buf), OTHER_ISSUER, 12u, 1u, 4u);
	REQUIRE(fzn_record_is_open(b), "fixture b would not build");
	REQUIRE(fzn_record_store_put(&store, b) == FZN_RECORD_STORE_OK, "put b refused");

	/* Reading back in the other order forces the cached descriptor to be
	 * replaced twice -- the arrangement in which a stale cache shows. */
	CHECK(fzn_record_store_get(&store, ISSUER, 12u, 1u, out, sizeof(out), &got)
	              == FZN_RECORD_STORE_OK, "the first issuer's record went missing");
	CHECK(fzn_record_store_get(&store, ISSUER, 13u, 1u, out, sizeof(out), &got)
	              == FZN_RECORD_STORE_ERR_ABSENT,
	      "another stream answered from the first stream's file");
	CHECK(fzn_record_store_get(&store, OTHER_ISSUER, 12u, 1u, out, sizeof(out), &got)
	              == FZN_RECORD_STORE_OK, "the second issuer's record went missing");

	fzn_record_store_file_close(&backend);
	unlink_stream(ISSUER, 12u);
	unlink_stream(OTHER_ISSUER, 12u);
	unlink_stream(ISSUER, 13u);
}

/* A sequence whose slot offset would not fit must be refused rather than
 * wrapping onto another record's slot. */
static void test_an_unaddressable_sequence_is_refused(void)
{
	fzn_record_store_file_t backend;
	const fzn_record_store_ops_t *ops;
	fzn_record_store_t store;
	uint8_t out[FZN_RECORD_MAX_LEN];
	fzn_record_t got;

	ops = fzn_record_store_file_open(&backend, dir);
	REQUIRE(ops != NULL, "the backend would not open");
	REQUIRE(fzn_record_store_init(&store, ops) == FZN_RECORD_STORE_OK, "init refused");

	CHECK(fzn_record_store_get(&store, ISSUER, 14u, 0xffffffffffffffffull, out, sizeof(out),
	                           &got) == FZN_RECORD_STORE_ERR_ABSENT,
	      "a sequence past the addressable range was not refused");

	fzn_record_store_file_close(&backend);
	unlink_stream(ISSUER, 14u);
}

/*
 * THE WRITE ORDER, TESTED RATHER THAN CLAIMED.
 *
 * `put` writes the record's bytes and then the length, so a failure between
 * them leaves the length at zero and the slot absent. Written the other way
 * round, a failure would leave a length promising bytes that were never
 * stored -- and that is what this reproduces.
 *
 * The failure is made with RLIMIT_FSIZE set to exactly the slot's data
 * offset, so the two-byte length write at `offset` fits and the record write
 * at `offset + 2` does not. Correct order: the record write fails first and
 * nothing is recorded. Reversed: the length lands, the record does not, and
 * the slot afterwards claims a record it does not hold.
 *
 * SIGXFSZ is ignored for the duration, since its default action would end the
 * process rather than let `pwrite` return, and the limit is put back before
 * anything else runs.
 */
static void test_the_length_is_written_after_the_record(void)
{
	fzn_record_store_file_t backend;
	const fzn_record_store_ops_t *ops;
	fzn_record_store_t store;
	uint8_t buf[FZN_RECORD_MAX_LEN], out[FZN_RECORD_MAX_LEN];
	fzn_record_t in, got;
	struct rlimit before, capped;
	void (*prev)(int);
	fzn_record_store_err_t err;
	const uint64_t seq = 3u;
	rlim_t at = (rlim_t)((seq - 1u) * FZN_RECORD_STORE_FILE_SLOT);

	REQUIRE(getrlimit(RLIMIT_FSIZE, &before) == 0, "the file size limit could not be read");
	ops = fzn_record_store_file_open(&backend, dir);
	REQUIRE(ops != NULL, "the backend would not open");
	REQUIRE(fzn_record_store_init(&store, ops) == FZN_RECORD_STORE_OK, "init refused");
	in = make(buf, sizeof(buf), ISSUER, 15u, seq, 64u);
	REQUIRE(fzn_record_is_open(in), "the fixture would not build");

	prev = signal(SIGXFSZ, SIG_IGN);
	capped = before;
	capped.rlim_cur = at + 2u;
	REQUIRE(setrlimit(RLIMIT_FSIZE, &capped) == 0, "the file size limit could not be set");

	/* The put must fail either way; what differs is what it leaves behind. */
	CHECK(fzn_record_store_put(&store, in) == FZN_RECORD_STORE_ERR_BACKEND,
	      "a put that could not write the record reported success");

	(void)setrlimit(RLIMIT_FSIZE, &before);
	if (prev != SIG_ERR)
		(void)signal(SIGXFSZ, prev);

	err = fzn_record_store_get(&store, ISSUER, 15u, seq, out, sizeof(out), &got);
	CHECK(err == FZN_RECORD_STORE_ERR_ABSENT,
	      "a slot whose record could not be written claims to hold one: %s",
	      fzn_record_store_err_str(err));

	fzn_record_store_file_close(&backend);
	unlink_stream(ISSUER, 15u);
}

/*
 * THE SEQUENCE BOUND, AND WHY IT IS NOT DECORATION.
 *
 * A slot offset is `(seq - 1) * 670` in unsigned arithmetic, which WRAPS.
 * 670 is even, so a sequence of 2^63 + 1 multiplies to exactly 2^64 and lands
 * on offset zero -- slot one. Without the bound this backend would answer a
 * request for that sequence with record one, and the seam would catch it as
 * MISPLACED. Caught is not the same as not produced: the bound is what stops
 * this backend manufacturing the error the seam exists to detect.
 */
static void test_a_wrapping_sequence_does_not_land_on_another_slot(void)
{
	fzn_record_store_file_t backend;
	const fzn_record_store_ops_t *ops;
	fzn_record_store_t store;
	uint8_t buf[FZN_RECORD_MAX_LEN], out[FZN_RECORD_MAX_LEN];
	uint8_t other[FZN_RECORD_MAX_LEN];
	fzn_record_t in, got, wrapped;
	fzn_record_store_err_t err;
	const uint64_t wraps = (uint64_t)1 << 63;

	/* The arithmetic this depends on, asserted rather than assumed: if the
	 * slot size ever stops being even this case tests nothing. */
	CHECK((wraps * (uint64_t)FZN_RECORD_STORE_FILE_SLOT) == 0u,
	      "the chosen sequence no longer wraps to offset zero");

	ops = fzn_record_store_file_open(&backend, dir);
	REQUIRE(ops != NULL, "the backend would not open");
	REQUIRE(fzn_record_store_init(&store, ops) == FZN_RECORD_STORE_OK, "init refused");
	in = make(buf, sizeof(buf), ISSUER, 16u, 1u, 8u);
	REQUIRE(fzn_record_is_open(in), "the fixture would not build");
	REQUIRE(fzn_record_store_put(&store, in) == FZN_RECORD_STORE_OK, "put refused");

	/* THE CONTROL: slot one really does hold a readable record, so the
	 * refusal below is the bound rather than an empty file. */
	CHECK(fzn_record_store_get(&store, ISSUER, 16u, 1u, out, sizeof(out), &got)
	              == FZN_RECORD_STORE_OK, "slot one is empty, so the case below says nothing");

	CHECK(fzn_record_store_get(&store, ISSUER, 16u, wraps + 1u, out, sizeof(out), &got)
	              == FZN_RECORD_STORE_ERR_ABSENT,
	      "a sequence that wraps to offset zero was answered from slot one");

	/* AND THE SAME BOUND ON THE WRITING SIDE, which is the worse half: a
	 * wrapping GET reads the wrong record and a wrapping PUT DESTROYS the
	 * right one. Record one must survive a put addressed past the end. */
	wrapped = make(other, sizeof(other), ISSUER, 16u, wraps + 1u, 8u);
	REQUIRE(fzn_record_is_open(wrapped), "the wrapping fixture would not build");
	CHECK(fzn_record_store_put(&store, wrapped) == FZN_RECORD_STORE_ERR_BACKEND,
	      "a record at an unaddressable sequence was stored");
	err = fzn_record_store_get(&store, ISSUER, 16u, 1u, out, sizeof(out), &got);
	CHECK(err == FZN_RECORD_STORE_OK && got.len == in.len
	              && memcmp(got.base, in.base, in.len) == 0,
	      "record one was overwritten by a put that wrapped onto its slot: %s",
	      fzn_record_store_err_str(err));

	fzn_record_store_file_close(&backend);
	unlink_stream(ISSUER, 16u);
}

static void test_the_caller_bugs_are_refused(void)
{
	fzn_record_store_file_t backend;
	char too_long[FZN_RECORD_STORE_FILE_PATH_MAX + 8];
	char just_fits[FZN_RECORD_STORE_FILE_PATH_MAX];
	size_t fits;

	memset(too_long, 'x', sizeof(too_long));
	too_long[sizeof(too_long) - 1u] = '\0';
	/* The longest directory that still leaves room for the name this
	 * backend appends. A path is `dir` plus 78 characters plus a
	 * terminator, so this is PATH_MAX minus NAME_LEN exactly. */
	fits = FZN_RECORD_STORE_FILE_PATH_MAX - FZN_RECORD_STORE_FILE_NAME_LEN;
	memset(just_fits, 'x', sizeof(just_fits));
	just_fits[fits + 1u] = '\0';

	CHECK(fzn_record_store_file_open(NULL, dir) == NULL, "a null backend was accepted");
	CHECK(fzn_record_store_file_open(&backend, NULL) == NULL, "a null directory was accepted");
	CHECK(fzn_record_store_file_open(&backend, "") == NULL, "an empty directory was accepted");
	CHECK(fzn_record_store_file_open(&backend, too_long) == NULL,
	      "a directory too long to hold was accepted");
	/* THE BOUND IS THE NAME'S, NOT THE BUFFER'S. A directory that fits the
	 * buffer and leaves no room for the file name would produce a truncated
	 * path, and a truncated path merges issuers into one file. */
	CHECK(fzn_record_store_file_open(&backend, just_fits) == NULL,
	      "a directory one character too long for the file name was accepted");
	just_fits[fits] = '\0';
	CHECK(fzn_record_store_file_open(&backend, just_fits) != NULL,
	      "the longest usable directory was refused, so the bound is off by one");
	/* Idempotent, and safe on a backend that never opened a file. */
	REQUIRE(fzn_record_store_file_open(&backend, dir) != NULL, "the backend would not open");
	fzn_record_store_file_close(&backend);
	fzn_record_store_file_close(&backend);
	CHECK(1, "close is idempotent");
}

/* A directory that does not exist is a broken store, not an empty one --
 * `record/store.h` says why the two must not be collapsed. */
static void test_a_missing_directory_is_a_broken_store(void)
{
	fzn_record_store_file_t backend;
	const fzn_record_store_ops_t *ops;
	fzn_record_store_t store;
	uint8_t out[FZN_RECORD_MAX_LEN];
	fzn_record_t got;

	ops = fzn_record_store_file_open(&backend, "/nonexistent-directory-for-fuzznet");
	REQUIRE(ops != NULL, "the backend refused a path it cannot check yet");
	REQUIRE(fzn_record_store_init(&store, ops) == FZN_RECORD_STORE_OK, "init refused");

	CHECK(fzn_record_store_get(&store, ISSUER, 1u, 1u, out, sizeof(out), &got)
	              == FZN_RECORD_STORE_ERR_BACKEND,
	      "a store that cannot be opened looked like an empty one");

	fzn_record_store_file_close(&backend);
}

static void test_the_suite_can_tell_pass_from_fail(void)
{
	int before = failures;

	check_at(0, __LINE__, "deliberate");
	CHECK(failures == before + 1, "a failing check did not count");
	failures = before;
	checks -= 1;
}

int main(void)
{
	memset(ISSUER, 0xa1, sizeof(ISSUER));
	memset(OTHER_ISSUER, 0xb2, sizeof(OTHER_ISSUER));
	memset(SUBJECT, 0x51, sizeof(SUBJECT));
	memset(&SIGN, 0, sizeof(SIGN));
	SIGN.sign = stub_sign;
	SIGN.verify = stub_verify;

	snprintf(dir, sizeof(dir), "fzn-store-test-%ld", (long)getpid());
	if (mkdir(dir, 0700) != 0) {
		fprintf(stderr, "store_file_test: could not make %s\n", dir);
		return 1;
	}

	test_a_record_survives_the_round_trip();
	test_both_ends_of_the_length_survive();
	test_an_unwritten_slot_reads_as_absent();
	test_bytes_without_a_length_are_absent();
	test_a_corrupt_length_is_refused_not_believed();
	test_the_file_is_sparse();
	test_streams_and_issuers_do_not_share_a_file();
	test_an_unaddressable_sequence_is_refused();
	test_the_length_is_written_after_the_record();
	test_a_wrapping_sequence_does_not_land_on_another_slot();
	test_the_caller_bugs_are_refused();
	test_a_missing_directory_is_a_broken_store();
	test_the_suite_can_tell_pass_from_fail();

	/* THE CLEANUP IS AN ASSERTION. Every case removed the files it named;
	 * if the directory is not empty now, something was left behind and the
	 * suite says so rather than reporting success above a growing tree. */
	if (rmdir(dir) != 0)
		check_at(0, __LINE__, "the scratch directory %s was not empty at the end", dir);

	printf("store_file_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
