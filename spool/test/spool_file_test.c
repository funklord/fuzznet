/* Tests for spool/spool_file.c, the default sparse-file backend.
 *
 * GATED, like persist/test/persist_file_test.c: a target with no filesystem
 * builds neither the backend nor this file, and `make test` says which.
 *
 * WHAT IS WORTH TESTING HERE IS NOT THAT A WRITE COMES BACK. It is the two
 * properties a consumer would have got wrong writing this themselves, and
 * both are silent in a working run:
 *
 *   - REOPENING MUST NOT EMPTY THE FILE. That is the resume path, and one
 *     O_TRUNC in the open flags turns every restart into a transfer starting
 *     over while the bitmap still says the leaves are present -- a store
 *     lying about itself rather than an error.
 *   - A LEAF WRITTEN AT A HIGH INDEX MUST NOT REQUIRE THE ONES BELOW IT.
 *     Out-of-order arrival is the ordinary case on a lossy transport, so the
 *     first leaf to land is routinely the last one.
 */

/* For ftruncate and fileno, which the sidecar cases use to damage a file
 * deliberately. The backend's own translation unit sets this too. */
#define _POSIX_C_SOURCE 200809L

#include "../spool_file.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
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
	fprintf(stderr, "  FAIL spool_file_test.c:%d: ", line);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

#define CHECK(cond, ...) check_at((cond) ? 1 : 0, __LINE__, __VA_ARGS__)

/* Named for the process so two runs cannot collide, and removed BY NAME --
 * a sweep over a prefix deletes a concurrent run's scratch, which on this
 * machine is somebody else's live state. */
static char path[256];

/* ---- a hash, and a real little blob ------------------------------------ */

static int stub_hash(void *ctx, uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len)
{
	uint64_t h = 0xcbf29ce484222325ull;
	size_t i;

	(void)ctx;
	h ^= (uint64_t)out_len;
	h *= 0x100000001b3ull;
	for (i = 0; i < in_len; i++) {
		h ^= in[i];
		h *= 0x100000001b3ull;
	}
	for (i = 0; i < out_len; i++) {
		h ^= (uint64_t)i + 0x9e3779b97f4a7c15ull;
		h *= 0x100000001b3ull;
		out[i] = (uint8_t)(h >> 32);
	}
	return 1;
}

static const fzn_hash_ops_t HASH = { stub_hash, NULL };

#define TEST_LEAVES 5u

static uint8_t sealed[TEST_LEAVES][FZN_BLOB_SEALED_MAX];
static size_t sealed_len[TEST_LEAVES];
static uint8_t leaf_hash[TEST_LEAVES][FZN_BLOB_HASH_LEN];
static uint8_t root[FZN_BLOB_HASH_LEN];
static uint8_t proof[TEST_LEAVES][FZN_BLOB_MAX_DEPTH * FZN_BLOB_HASH_LEN];
static unsigned proof_len[TEST_LEAVES];

static int build_blob(void)
{
	fzn_blob_tree_t tree;
	unsigned i;

	fzn_blob_tree_init(&tree);
	for (i = 0; i < TEST_LEAVES; i++) {
		size_t j;

		/* Deliberately not all one length: the backend writes a
		 * variable-length leaf into a fixed stride, and a fixture whose
		 * leaves are all the same size cannot tell a stride from a
		 * length. */
		sealed_len[i] = 100u + (size_t)(i * 13u);
		for (j = 0; j < sealed_len[i]; j++)
			sealed[i][j] = (uint8_t)((i * 91u) + j + 3u);
		if (fzn_blob_leaf_hash(&HASH, sealed[i], sealed_len[i], leaf_hash[i])
		    != FZN_BLOB_OK)
			return 0;
		if (fzn_blob_tree_push(&HASH, &tree, leaf_hash[i]) != FZN_BLOB_OK)
			return 0;
	}
	if (fzn_blob_tree_root(&HASH, &tree, root) != FZN_BLOB_OK)
		return 0;
	for (i = 0; i < TEST_LEAVES; i++) {
		if (fzn_blob_proof_build(&HASH, leaf_hash[0], TEST_LEAVES, i, proof[i],
		                         sizeof(proof[i]), &proof_len[i]) != FZN_BLOB_OK)
			return 0;
	}
	return 1;
}

/* ---- the cases -------------------------------------------------------- */

/* THE CASE THE WHOLE FILE EXISTS FOR. Half a blob is written, the store is
 * closed as a restart would close it, and a second store over the SAME file
 * and the same bitmap finishes the transfer and reads every leaf back.
 *
 * The bitmap is carried across by hand here rather than through persist/,
 * which is what a consumer does with FZN_PERSIST_* -- this file is about the
 * backend, and coupling it to the other subsystem would mean neither could
 * be built without the other. */
static void test_a_reopened_spool_still_has_what_it_had(void)
{
	fzn_spool_file_t backend;
	const fzn_spool_ops_t *ops;
	fzn_spool_t spool;
	uint8_t map[FZN_SPOOL_BITMAP_LEN(TEST_LEAVES)];
	uint8_t out[FZN_BLOB_SEALED_MAX];
	size_t out_len = 0;
	unsigned i;

	memset(map, 0, sizeof(map));

	ops = fzn_spool_file_open(&backend, path);
	CHECK(ops != NULL, "the backend refused a path it should have created");
	if (!ops)
		return;

	CHECK(fzn_spool_open(&spool, root, TEST_LEAVES, map, sizeof(map), ops) == FZN_SPOOL_OK,
	      "the store refused to open over a fresh file");

	/* HIGH INDEX FIRST, so a backend that needed the leaves below it would
	 * fail here rather than passing by luck of ordering. */
	CHECK(fzn_spool_place(&spool, &HASH, 4u, sealed[4], sealed_len[4], proof[4], proof_len[4])
	              == FZN_SPOOL_OK,
	      "the last leaf could not be placed first");
	CHECK(fzn_spool_place(&spool, &HASH, 1u, sealed[1], sealed_len[1], proof[1], proof_len[1])
	              == FZN_SPOOL_OK,
	      "placing leaf 1 failed");

	/* A SIZE ASSERTION RATHER THAN A BLOCK COUNT. `st_blocks` is what
	 * would actually prove the holes are holes, and it is the filesystem's
	 * answer rather than the backend's -- a tmpfs, a compressed volume and
	 * an ext4 all answer differently for the same correct behaviour, so a
	 * test asserting on it would fail for the machine rather than for the
	 * code. What is the backend's own is that the file grew to cover an
	 * offset whose predecessors were never written, which is the property
	 * that matters and is the same on every filesystem. */
	{
		struct stat st;

		CHECK(stat(path, &st) == 0, "the spool file was not created");
		/* NOT WORLD-READABLE. A partially assembled blob says what a
		 * host is fetching even though its leaves are sealed, and a
		 * mode is set at creation or not at all -- a chmod afterwards
		 * leaves a window. */
		CHECK((st.st_mode & 0777) == 0600, "the spool file was created mode %o",
		      (unsigned)(st.st_mode & 0777));
		/* The WHOLE slot, not the leaf's own length: a short leaf
		 * has its slot filled, which is what makes it readable at
		 * all. Asserting the leaf's length here would pass against
		 * the defect this file found. */
		CHECK((uint64_t)st.st_size == 5u * FZN_BLOB_SEALED_MAX,
		      "the file did not grow to cover a high short leaf's whole slot, so "
		      "reading that leaf back runs past the end");
	}

	/* CHECKPOINTED THROUGH THE SHIPPED PATH rather than carried across by
	 * hand. Carrying the bitmap in a variable that survives the close is
	 * what a test does and what a restart cannot, so a test doing it
	 * proves the file and not the resume. */
	CHECK(fzn_spool_file_checkpoint(&backend, &spool) == FZN_SPOOL_OK, "the checkpoint failed");
	fzn_spool_file_close(&backend);

	/* THE RESTART. The bitmap is scribbled over first, so anything that
	 * survives is something `resume` put there. */
	memset(map, 0xff, sizeof(map));
	ops = fzn_spool_file_open(&backend, path);
	CHECK(ops != NULL, "the backend refused to reopen its own file");
	if (!ops)
		return;
	CHECK(fzn_spool_file_resume(&backend, root, TEST_LEAVES, map, sizeof(map)) == FZN_SPOOL_OK,
	      "the sidecar did not restore");
	CHECK(fzn_spool_open(&spool, root, TEST_LEAVES, map, sizeof(map), ops) == FZN_SPOOL_OK,
	      "the store refused to resume");
	CHECK(spool.have == 2u, "the resumed store holds %u leaves, expected 2",
	      (unsigned)spool.have);
	CHECK(fzn_spool_has(&spool, 4u) && fzn_spool_has(&spool, 1u),
	      "the resumed store forgot which leaves it held");
	CHECK(!fzn_spool_has(&spool, 0u) && !fzn_spool_has(&spool, 3u),
	      "the resumed store claims leaves it never had -- the scribble survived");

	CHECK(fzn_spool_read(&spool, 4u, out, sizeof(out), &out_len) == FZN_SPOOL_OK,
	      "a leaf written before the restart could not be read after it");
	CHECK(out_len == FZN_BLOB_SEALED_MAX, "a read returned something other than a slot");
	CHECK(memcmp(out, sealed[4], sealed_len[4]) == 0,
	      "a leaf came back changed across a restart -- the file was emptied or "
	      "the stride moved");

	for (i = 0; i < TEST_LEAVES; i++) {
		if (fzn_spool_has(&spool, i))
			continue;
		CHECK(fzn_spool_place(&spool, &HASH, i, sealed[i], sealed_len[i], proof[i],
		                      proof_len[i]) == FZN_SPOOL_OK,
		      "placing leaf %u after the restart failed", i);
	}
	CHECK(fzn_spool_complete(&spool), "the resumed transfer never completed");

	/* AND EVERY LEAF READS BACK, not only the one written last. A stride
	 * that was off by a leaf would still return the newest one correctly. */
	for (i = 0; i < TEST_LEAVES; i++) {
		out_len = 0;
		CHECK(fzn_spool_read(&spool, i, out, sizeof(out), &out_len) == FZN_SPOOL_OK,
		      "leaf %u could not be read from the completed spool", i);
		CHECK(memcmp(out, sealed[i], sealed_len[i]) == 0,
		      "leaf %u came back changed -- leaves are overlapping in the file", i);
		/* AND THE SLOT'S TAIL IS ZEROS rather than the neighbouring
		 * leaf. This is what separates "the stride is right" from
		 * "the leaves happen not to overlap at these lengths": with
		 * the fill removed, the tail holds whatever the file had, and
		 * with the stride wrong it holds the next leaf. */
		{
			size_t t;
			int clean = 1;

			for (t = sealed_len[i]; t < FZN_BLOB_SEALED_MAX; t++)
				if (out[t] != 0u)
					clean = 0;
			CHECK(clean, "leaf %u's slot tail was not filled -- a reader gets bytes "
			             "the sender never sealed", i);
		}
	}

	CHECK(ops->sync(ops->ctx), "the backend refused to sync a file it holds open");
	fzn_spool_file_close(&backend);
}

/* THE CASE THE SIDECAR'S HEADER EXISTS FOR, and the reason it carries more
 * than bits. A bitmap is opaque: `fzn_spool_open` takes a root and a bitmap
 * and cannot tell they belong together, so a bitmap restored for the wrong
 * blob makes the store report leaves present that hold another blob's
 * ciphertext -- and the transfer completes without ever re-requesting them.
 *
 * A reused path is how it happens, not an attack. */
static void test_a_bitmap_from_another_blob_is_refused(void)
{
	fzn_spool_file_t backend;
	const fzn_spool_ops_t *ops;
	fzn_spool_t spool;
	uint8_t map[FZN_SPOOL_BITMAP_LEN(TEST_LEAVES)];
	uint8_t other_root[FZN_BLOB_HASH_LEN];
	unsigned i;

	memset(map, 0, sizeof(map));
	ops = fzn_spool_file_open(&backend, path);
	CHECK(ops != NULL, "the backend refused a path it should have opened");
	if (!ops)
		return;

	CHECK(fzn_spool_open(&spool, root, TEST_LEAVES, map, sizeof(map), ops) == FZN_SPOOL_OK,
	      "the store refused to open");
	CHECK(fzn_spool_place(&spool, &HASH, 0u, sealed[0], sealed_len[0], proof[0], proof_len[0])
	              == FZN_SPOOL_OK,
	      "placing a leaf failed");
	CHECK(fzn_spool_file_checkpoint(&backend, &spool) == FZN_SPOOL_OK, "the checkpoint failed");

	/* A ROOT DIFFERING IN ONE BYTE. The whole-root case would also pass
	 * against a header that compared only a prefix. */
	memcpy(other_root, root, sizeof(other_root));
	other_root[FZN_BLOB_HASH_LEN - 1u] ^= 0x01u;
	memset(map, 0xff, sizeof(map));
	CHECK(fzn_spool_file_resume(&backend, other_root, TEST_LEAVES, map, sizeof(map))
	              == FZN_SPOOL_ERR_ABSENT,
	      "a sidecar written for another blob was restored onto it");
	for (i = 0; i < sizeof(map); i++)
		CHECK(map[i] == 0u, "a refused resume left byte %u of the bitmap set, so the "
		                    "caller would report leaves it does not have", i);

	/* AND A DIFFERENT LEAF COUNT, which is the same blob's root over a
	 * different manifest -- refused for the same reason. */
	memset(map, 0xff, sizeof(map));
	CHECK(fzn_spool_file_resume(&backend, root, TEST_LEAVES - 1u, map, sizeof(map))
	              == FZN_SPOOL_ERR_ABSENT,
	      "a sidecar written for a different leaf count was restored");
	CHECK(map[0] == 0u, "a refused resume left the bitmap set");

	/* The matching pair still restores, so the refusals above are not a
	 * resume that never works. */
	memset(map, 0xff, sizeof(map));
	CHECK(fzn_spool_file_resume(&backend, root, TEST_LEAVES, map, sizeof(map)) == FZN_SPOOL_OK,
	      "the matching sidecar was refused too, so the checks reject everything");
	CHECK(map[0] == 0x01u, "the restored bitmap does not hold leaf 0 alone: %02x", map[0]);

	fzn_spool_file_close(&backend);
}

/* NOTHING TO RESTORE, A TRUNCATED SIDECAR, AND A VERSION THAT MOVED all take
 * the same exit, and all must zero the caller's buffer. A caller that
 * ignores the return value has to get the fresh transfer, because the other
 * direction is a store claiming leaves that are nowhere. */
static void test_an_unusable_sidecar_leaves_a_fresh_transfer(void)
{
	fzn_spool_file_t backend;
	const fzn_spool_ops_t *ops;
	fzn_spool_t spool;
	uint8_t map[FZN_SPOOL_BITMAP_LEN(TEST_LEAVES)];
	char bits[512];
	FILE *f;

	snprintf(bits, sizeof(bits), "%s.bits", path);

	ops = fzn_spool_file_open(&backend, path);
	CHECK(ops != NULL, "the backend refused a path it should have opened");
	if (!ops)
		return;

	memset(map, 0xff, sizeof(map));
	CHECK(fzn_spool_file_resume(&backend, root, TEST_LEAVES, map, sizeof(map))
	              == FZN_SPOOL_ERR_ABSENT,
	      "a resume with no sidecar reported success");
	CHECK(map[0] == 0u, "a resume with no sidecar left the buffer as it found it");

	memset(map, 0, sizeof(map));
	CHECK(fzn_spool_open(&spool, root, TEST_LEAVES, map, sizeof(map), ops) == FZN_SPOOL_OK,
	      "the store refused to open");
	CHECK(fzn_spool_place(&spool, &HASH, 3u, sealed[3], sealed_len[3], proof[3], proof_len[3])
	              == FZN_SPOOL_OK,
	      "placing a leaf failed");
	CHECK(fzn_spool_file_checkpoint(&backend, &spool) == FZN_SPOOL_OK, "the checkpoint failed");

	/* TRUNCATED INTO THE BITMAP, not before the header: a file cut short
	 * of its header is caught by the header read, which is a different
	 * branch and would hide this one. */
	f = fopen(bits, "r+b");
	CHECK(f != NULL, "the sidecar was not written");
	if (f) {
		CHECK(ftruncate(fileno(f), 41) == 0, "could not truncate the sidecar");
		(void)fclose(f);
	}
	memset(map, 0xff, sizeof(map));
	CHECK(fzn_spool_file_resume(&backend, root, TEST_LEAVES, map, sizeof(map))
	              == FZN_SPOOL_ERR_ABSENT,
	      "a sidecar with a header and no bits was restored");
	CHECK(map[0] == 0u, "a truncated sidecar left the buffer set");

	/* A VERSION THAT MOVED. A future format must not be read as this one
	 * -- the bits would be interpreted under the wrong layout. */
	CHECK(fzn_spool_file_checkpoint(&backend, &spool) == FZN_SPOOL_OK, "the checkpoint failed");
	f = fopen(bits, "r+b");
	if (f) {
		uint8_t bad = 0xfeu;

		CHECK(fwrite(&bad, 1u, 1u, f) == 1u, "could not rewrite the version byte");
		(void)fclose(f);
	}
	memset(map, 0xff, sizeof(map));
	CHECK(fzn_spool_file_resume(&backend, root, TEST_LEAVES, map, sizeof(map))
	              == FZN_SPOOL_ERR_ABSENT,
	      "a sidecar of an unknown version was read as this one");
	CHECK(map[0] == 0u, "an unknown version left the buffer set");

	/* A BITMAP CUT THROUGH THE MIDDLE, which needs a blob whose bitmap is
	 * more than one byte -- TEST_LEAVES is five, so its bitmap is a single
	 * byte and a partial read of it cannot happen. The first version of
	 * this case truncated to the header and proved nothing: `fread`
	 * returned zero, the pre-zero had already cleared the buffer, and
	 * deleting the second clear changed no result.
	 *
	 * `resume` needs no blob, only a root and a count, so the sidecar is
	 * written by hand at a size that can tear. */
	{
		uint8_t hand[41u + 2u];
		uint8_t wide_root[FZN_BLOB_HASH_LEN];
		uint8_t two[2];

		memset(wide_root, 0x2d, sizeof(wide_root));
		memset(hand, 0, sizeof(hand));
		hand[0] = 1u;
		memcpy(hand + 1u, wide_root, sizeof(wide_root));
		hand[33u + 7u] = 16u; /* leaves = 16, big-endian, so a 2-byte bitmap */
		hand[41u] = 0xffu;
		hand[42u] = 0xffu;

		f = fopen(bits, "wb");
		CHECK(f != NULL, "could not write a sidecar by hand");
		if (f) {
			/* One byte of the two, so the read is SHORT rather
			 * than empty. */
			CHECK(fwrite(hand, 1u, 42u, f) == 42u, "short hand-write");
			(void)fclose(f);
		}
		memset(two, 0xff, sizeof(two));
		CHECK(fzn_spool_file_resume(&backend, wide_root, 16u, two, sizeof(two))
		              == FZN_SPOOL_ERR_ABSENT,
		      "a bitmap cut through the middle was accepted");
		CHECK(two[0] == 0u && two[1] == 0u,
		      "a partly-read bitmap was left partly used: %02x %02x -- the store "
		      "would claim leaves whose bytes are not on the disk",
		      two[0], two[1]);
	}

	/* And a checkpoint on a closed backend refuses rather than writing a
	 * bitmap for data it can no longer sync. */
	fzn_spool_file_close(&backend);
	CHECK(fzn_spool_file_checkpoint(&backend, &spool) == FZN_SPOOL_ERR_MALFORMED,
	      "a closed backend checkpointed, so the bitmap outran its own fsync");

	(void)unlink(bits);
}

/* A CLOSED OR NEVER-OPENED BACKEND RETURNS, rather than reading through a
 * negative descriptor. This is the shape of every cleanup path a caller
 * writes, so it is the one a consumer reaches by accident. */
static void test_a_closed_backend_refuses_rather_than_faults(void)
{
	fzn_spool_file_t backend;
	const fzn_spool_ops_t *ops;
	uint8_t byte = 0;

	ops = fzn_spool_file_open(&backend, path);
	CHECK(ops != NULL, "the backend refused a path it should have opened");
	if (!ops)
		return;

	fzn_spool_file_close(&backend);
	CHECK(!ops->read_at(ops->ctx, 0u, &byte, 1u), "a read on a closed backend reported success");
	CHECK(!ops->write_at(ops->ctx, 0u, &byte, 1u),
	      "a write on a closed backend reported success, so a caller would set a "
	      "present bit for a leaf that is nowhere");
	CHECK(!ops->sync(ops->ctx), "a sync on a closed backend reported success");

	/* Closing twice is what a caller does when an error path and a success
	 * path both clean up. */
	fzn_spool_file_close(&backend);
}

/* READING PAST WHAT WAS WRITTEN IS A FAILURE, NOT A BUFFER OF ZEROS. The
 * bitmap should stop a caller asking -- so this is the case where the bitmap
 * and the file DISAGREE, which is what a truncated file or a bitmap restored
 * from a newer run looks like. Silently returning zeros there would hand a
 * relay a leaf of zeros to serve on. */
static void test_a_hole_is_refused_rather_than_read_as_zeros(void)
{
	fzn_spool_file_t backend;
	const fzn_spool_ops_t *ops;
	uint8_t out[64];
	uint8_t one = 0x5a;

	ops = fzn_spool_file_open(&backend, path);
	CHECK(ops != NULL, "the backend refused a path it should have opened");
	if (!ops)
		return;

	memset(out, 0xff, sizeof(out));
	CHECK(!ops->read_at(ops->ctx, 0u, out, sizeof(out)),
	      "reading an empty file reported success");

	/* One byte written a long way in. Everything below it is a hole the
	 * filesystem invents, and reading INSIDE that hole succeeds -- which
	 * is correct, and is why the bitmap rather than the file is what says
	 * a leaf is present. Reading BEYOND the byte does not. */
	CHECK(ops->write_at(ops->ctx, 4096u, &one, 1u), "a write at an offset failed");
	CHECK(ops->read_at(ops->ctx, 0u, out, sizeof(out)),
	      "reading a hole below written data failed");
	CHECK(out[0] == 0u && out[63] == 0u, "a hole did not read as zeros");
	CHECK(!ops->read_at(ops->ctx, 4090u, out, sizeof(out)),
	      "a read running past the end of the file reported success");

	fzn_spool_file_close(&backend);
}

static void test_the_arguments_are_checked(void)
{
	fzn_spool_file_t backend;
	uint8_t byte = 0;

	CHECK(fzn_spool_file_open(&backend, NULL) == NULL, "a null path was accepted");
	CHECK(fzn_spool_file_open(NULL, path) == NULL, "a null struct was accepted");
	fzn_spool_file_close(NULL);

	{
		const fzn_spool_ops_t *ops = fzn_spool_file_open(&backend, path);

		CHECK(ops != NULL, "the backend refused a path it should have opened");
		if (ops) {
			CHECK(!ops->read_at(ops->ctx, 0u, NULL, 1u), "a null read buffer was accepted");
			CHECK(!ops->write_at(ops->ctx, 0u, NULL, 1u), "a null write buffer was accepted");
			CHECK(!ops->read_at(NULL, 0u, &byte, 1u), "a null context was accepted");
			CHECK(!ops->write_at(NULL, 0u, &byte, 1u), "a null context was accepted");
			CHECK(!ops->sync(NULL), "a null context was accepted by sync");
			fzn_spool_file_close(&backend);
		}
	}
}

int main(void)
{
	int left;

	snprintf(path, sizeof(path), "spool-test-%ld.spool", (long)getpid());

	if (!build_blob()) {
		fprintf(stderr, "  FAIL: the blob fixture does not build\n");
		return 1;
	}

	test_a_reopened_spool_still_has_what_it_had();
	{
		char bits[512];

		snprintf(bits, sizeof(bits), "%s.bits", path);
		(void)unlink(bits);
	}
	(void)unlink(path);
	test_a_closed_backend_refuses_rather_than_faults();
	(void)unlink(path);
	test_a_hole_is_refused_rather_than_read_as_zeros();
	(void)unlink(path);
	test_a_bitmap_from_another_blob_is_refused();
	{
		char bits[512];

		snprintf(bits, sizeof(bits), "%s.bits", path);
		(void)unlink(bits);
	}
	(void)unlink(path);
	test_an_unusable_sidecar_leaves_a_fresh_transfer();
	(void)unlink(path);
	test_the_arguments_are_checked();

	/* CLEANED UP BY NAME, AND THE LEFTOVER IS AN ASSERTION rather than a
	 * hope -- `running-code.md` records a suite printing "all passed"
	 * directly above the failure of its own cleanup. */
	(void)unlink(path);
	{
		struct stat st;
		char bits[512];
		char tmp[512];

		snprintf(bits, sizeof(bits), "%s.bits", path);
		snprintf(tmp, sizeof(tmp), "%s.bits.tmp", path);
		(void)unlink(bits);
		(void)unlink(tmp);
		left = stat(path, &st) == 0 ? 1 : 0;
		left |= stat(bits, &st) == 0 ? 2 : 0;
		left |= stat(tmp, &st) == 0 ? 4 : 0;
		CHECK(!left, "the test left files behind (mask %d)", left);
	}

	printf("spool_file_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
