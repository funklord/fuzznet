/* Tests for persist/persist_file.c, the default POSIX backend.
 *
 * GATED, because the backend is a subsystem: a target without a filesystem
 * builds neither it nor this file. `make test` says so when it is off, for
 * the reason the Monocypher notice exists -- an absent test and a passing
 * one look identical in a green run.
 *
 * WHAT IS WORTH TESTING HERE IS NOT THE ROUND TRIP. It is the two properties
 * a consumer would have got wrong writing this themselves: that a save is
 * atomic, so a crash cannot leave a half-written trust anchor that PARSES;
 * and that a secret is never briefly world-readable. Both are invisible in a
 * working run and both are why this ships rather than being left to three
 * consumers.
 */

#include "../persist_file.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int failures;
static int checks;

static void expect(int ok, const char *what)
{
	checks++;
	if (!ok) {
		failures++;
		fprintf(stderr, "  FAIL: %s\n", what);
	}
}

/* A directory this test makes and removes. Named for the process so two
 * runs cannot collide, and removed by NAME rather than by pattern -- an
 * atexit sweep over a prefix deletes a concurrent run's scratch, which on a
 * machine running many sessions is somebody else's live state. */
static char dir[256];
static char made[8][320];
static size_t made_len;

static void note(const char *slot_name)
{
	if (made_len < 8u)
		snprintf(made[made_len++], sizeof(made[0]), "%s/%s", dir, slot_name);
}

int main(void)
{
	fzn_persist_file_t store;
	const fzn_persist_ops_t *ops;
	uint8_t in[16], out[FZN_PERSIST_MAX];
	uint8_t subject[32];
	size_t len = 0;
	struct stat st;
	size_t i;
	int left = 0;

	snprintf(dir, sizeof(dir), "persist-test-%ld", (long)getpid());
	if (mkdir(dir, 0700) != 0) {
		fprintf(stderr, "  FAIL: could not make the scratch directory\n");
		return 1;
	}

	ops = fzn_persist_file_init(&store, dir);
	expect(ops != NULL, "the backend refused a directory it should accept");
	if (!ops)
		goto out;

	for (i = 0; i < sizeof(in); i++)
		in[i] = (uint8_t)(i + 1u);
	memset(subject, 0xab, sizeof(subject));

	/* ABSENT IS NOT AN ERROR AND MUST BE DISTINGUISHABLE. A first run has
	 * no files; a caller that cannot tell that from a broken disk does not
	 * know whether to mint a fresh prekey or to stop and shout. */
	expect(!ops->load(ops->ctx, FZN_PERSIST_TRUST, NULL, out, sizeof(out), &len),
	       "loading a slot that was never saved reported success");

	expect(ops->save(ops->ctx, FZN_PERSIST_TRUST, NULL, in, sizeof(in)) == 1,
	       "saving refused");
	note("1-h");
	expect(ops->load(ops->ctx, FZN_PERSIST_TRUST, NULL, out, sizeof(out), &len) == 1,
	       "loading what was just saved refused");
	expect(len == sizeof(in) && memcmp(out, in, sizeof(in)) == 0,
	       "the bytes did not survive the round trip");

	/* MODE 0600, AND AT CREATION RATHER THAN AFTER. Creating with the
	 * umask and chmod'ing afterwards leaves a prekey secret readable for
	 * exactly as long as the write takes. */
	{
		char path[320];

		snprintf(path, sizeof(path), "%s/1-h", dir);
		expect(stat(path, &st) == 0, "the saved file is not where the backend says");
		expect((st.st_mode & 07777) == 0600,
		       "a stored secret is not owner-only, so anything on the box can read it");
	}

	/* NO TEMPORARY SURVIVES A SUCCESSFUL SAVE. A leftover .tmp is the
	 * visible end of a rename that did not happen, and it is how a
	 * directory fills up unnoticed. */
	{
		char path[320];

		snprintf(path, sizeof(path), "%s/1-h.tmp", dir);
		expect(stat(path, &st) != 0, "a successful save left its temporary behind");
	}

	/* THE SUBJECT IS PART OF THE KEY, WHOLE. Two peers differing only in
	 * their last byte must not share a file -- the same length mistake a
	 * comparison reading a prefix makes, and this tree has had one. */
	{
		uint8_t other[32];
		uint8_t got[FZN_PERSIST_MAX];
		size_t got_len = 0;

		memset(other, 0xab, sizeof(other));
		other[31] = 0xac;
		expect(ops->save(ops->ctx, FZN_PERSIST_PEER, subject, in, 8u) == 1, "save refused");
		note("3-abababababababababababababababababababababababababababababababab");
		expect(!ops->load(ops->ctx, FZN_PERSIST_PEER, other, got, sizeof(got), &got_len),
		       "two subjects differing in their last byte share a file");
	}

	/* A FILE LARGER THAN THE CALLER'S BUFFER IS REFUSED, not truncated --
	 * a truncated read would be refused by the format anyway, but this
	 * says which layer found it. */
	{
		uint8_t small[4];
		size_t small_len = 0;

		expect(!ops->load(ops->ctx, FZN_PERSIST_TRUST, NULL, small, sizeof(small),
		                  &small_len),
		       "a file larger than the buffer was read into it");
	}

	/* A directory too deep for a bounded path is refused at init rather
	 * than at the first save, so a caller learns at start-up. */
	{
		fzn_persist_file_t deep;
		char long_dir[600];

		memset(long_dir, 'd', sizeof(long_dir) - 1u);
		long_dir[sizeof(long_dir) - 1u] = '\0';
		expect(fzn_persist_file_init(&deep, long_dir) == NULL,
		       "a path too long for the bounded buffer was accepted, so it would be "
		       "truncated into a different file");
	}

	expect(fzn_persist_file_init(&store, NULL) == NULL, "a null directory was accepted");

out:
	/* CLEANED UP BY NAME, AND THE LEFTOVER COUNT IS AN ASSERTION. A
	 * cleanup nobody checks is one that silently stops working --
	 * `running-code.md` records 31 directories accumulating under a suite
	 * that printed "all passed" directly above the failure. */
	for (i = 0; i < made_len; i++)
		(void)unlink(made[i]);
	if (rmdir(dir) != 0)
		left = 1;
	expect(!left, "the test could not remove its scratch directory, so it left files");

	printf("persist_file_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
