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

#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
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


/* THE PATHS A WORKING FILESYSTEM DOES NOT TAKE.
 *
 * Everything above runs against a directory that behaves. These are the
 * refusals -- a directory that cannot be written, a name already taken by a
 * directory, a write the kernel will not accept -- and each is produced by
 * the real kernel rather than by a stub, because a stub for `open` would
 * assert that this file handles a case the filesystem is what decides.
 *
 * Two techniques do the work and neither needs privilege. A directory at
 * mode 0500 makes `open(..., O_CREAT)` fail inside it; and RLIMIT_FSIZE set
 * to zero makes the flush fail with EFBIG while the create still succeeds,
 * which is the shape of a full disk arriving part way through a save.
 *
 * THE LIMIT IS RESTORED IMMEDIATELY and the restore is asserted. Left in
 * place it would fail every later write in this process, including gcov's
 * own .gcda at exit -- so a case that forgot to restore it would corrupt the
 * measurement that justified writing it.
 */
static void test_the_filesystem_refusing(const char *scratch)
{
	fzn_persist_file_t store;
	const fzn_persist_ops_t *ops;
	uint8_t bytes[8], out[FZN_PERSIST_MAX];
	size_t len = 0;
	char deep[600];
	char ro[320], target[320], blocker[400];
	size_t i;

	memset(bytes, 0x5a, sizeof(bytes));

	ops = fzn_persist_file_init(&store, scratch);
	expect(ops != NULL, "the backend refused the scratch directory");
	if (!ops)
		return;

	/* ---- the operands each entry point guards, past the first. */
	expect(!ops->load(NULL, FZN_PERSIST_TRUST, NULL, out, sizeof(out), &len),
	       "load accepted a null store");
	expect(!ops->load(ops->ctx, FZN_PERSIST_TRUST, NULL, NULL, sizeof(out), &len),
	       "load accepted a null out");
	expect(!ops->load(ops->ctx, FZN_PERSIST_TRUST, NULL, out, sizeof(out), NULL),
	       "load accepted a null length");
	expect(!ops->save(NULL, FZN_PERSIST_TRUST, NULL, bytes, sizeof(bytes)),
	       "save accepted a null store");
	expect(!ops->save(ops->ctx, FZN_PERSIST_TRUST, NULL, NULL, sizeof(bytes)),
	       "save accepted null bytes");
	/* A ZERO-LENGTH SAVE IS REFUSED, not written. An empty file reads back
	 * as absent, so accepting one would let a host quietly re-anchor. */
	expect(!ops->save(ops->ctx, FZN_PERSIST_TRUST, NULL, bytes, 0u),
	       "save accepted a zero length, which would write a file that reads as absent");

	/* ---- a store whose directory is gone. `_init` refuses a null and a
	 * path too long, so neither reaches `path_for` through the front door;
	 * a struct filled by hand is what a caller has who memcpy'd one. */
	{
		fzn_persist_file_t hollow = store;

		hollow.dir = NULL;
		hollow.ops.ctx = &hollow;
		expect(!hollow.ops.load(hollow.ops.ctx, FZN_PERSIST_TRUST, NULL, out,
		                        sizeof(out), &len),
		       "load accepted a store with no directory");
		expect(!hollow.ops.save(hollow.ops.ctx, FZN_PERSIST_TRUST, NULL, bytes,
		                        sizeof(bytes)),
		       "save accepted a store with no directory");
	}

	/* ---- a directory too deep for the bounded path buffer. Refused at
	 * init, which is the promise: a caller learns at start-up rather than
	 * on the day it first pins a peer. */
	for (i = 0; i < sizeof(deep) - 1u; i++)
		deep[i] = 'd';
	deep[sizeof(deep) - 1u] = '\0';
	expect(fzn_persist_file_init(&store, deep) == NULL,
	       "a directory too long for the path buffer was accepted at init");
	/* And through the ops, where the same refusal has to hold rather than
	 * truncating -- a truncated path names a different file. */
	{
		fzn_persist_file_t hollow;

		hollow.dir = deep;
		hollow.ops.load = ops->load;
		hollow.ops.save = ops->save;
		hollow.ops.ctx = &hollow;
		expect(!hollow.ops.load(hollow.ops.ctx, FZN_PERSIST_TRUST, NULL, out,
		                        sizeof(out), &len),
		       "load built a truncated path from an over-long directory");
		expect(!hollow.ops.save(hollow.ops.ctx, FZN_PERSIST_TRUST, NULL, bytes,
		                        sizeof(bytes)),
		       "save built a truncated path from an over-long directory");
	}

	ops = fzn_persist_file_init(&store, scratch);
	if (!ops)
		return;

	/* ---- a directory that cannot be written into. */
	snprintf(ro, sizeof(ro), "%s/ro", scratch);
	if (mkdir(ro, 0500) == 0) {
		fzn_persist_file_t rostore;
		const fzn_persist_ops_t *roops = fzn_persist_file_init(&rostore, ro);

		if (roops) {
			expect(!roops->save(roops->ctx, FZN_PERSIST_TRUST, NULL, bytes,
			                    sizeof(bytes)),
			       "save reported success into a directory it cannot create in");
			/* AND LEFT NOTHING BEHIND. A refused save that has
			 * dropped a temporary is a leak the next run inherits. */
			expect(access(ro, W_OK) != 0, "the read-only directory became writable");
		}
		(void)rmdir(ro);
	}

	/* ---- the target name already taken by a directory, so the rename at
	 * the end fails after everything before it succeeded. This is the one
	 * case that exercises the unwind AFTER the bytes are safely on disk. */
	/* The name is the slot's own digit -- `name_for` writes
	 * '0' + slot % 10 -- so the blocker has to be built from the slot
	 * rather than from a literal. Blocking the wrong name lets the save
	 * succeed, and the case then passes for having tested nothing. */
	snprintf(target, sizeof(target), "%s/%u-h", scratch, (unsigned)FZN_PERSIST_PEER % 10u);
	if (mkdir(target, 0700) == 0) {
		expect(!ops->save(ops->ctx, FZN_PERSIST_PEER, NULL, bytes, sizeof(bytes)),
		       "save reported success when the rename could not replace a directory");
		snprintf(blocker, sizeof(blocker), "%s/%u-h.tmp", scratch,
		         (unsigned)FZN_PERSIST_PEER % 10u);
		expect(access(blocker, F_OK) != 0,
		       "a failed rename left its temporary behind, which the next run inherits");
		(void)unlink(blocker);
		(void)rmdir(target);
	}

	/* ---- a write the kernel refuses part way through. */
	{
		struct rlimit old, zero;

		if (getrlimit(RLIMIT_FSIZE, &old) == 0) {
			void (*prev)(int) = signal(SIGXFSZ, SIG_IGN);

			zero.rlim_cur = 0;
			zero.rlim_max = old.rlim_max;
			if (setrlimit(RLIMIT_FSIZE, &zero) == 0) {
				expect(!ops->save(ops->ctx, FZN_PERSIST_OWN_PREKEY, NULL, bytes,
				                  sizeof(bytes)),
				       "save reported success for a write the kernel refused");
				expect(setrlimit(RLIMIT_FSIZE, &old) == 0,
				       "the file-size limit could not be restored, so every "
				       "later write in this process is unreliable");
			}
			(void)signal(SIGXFSZ, prev);
			/* The restore is proved by writing, not by the return
			 * code above: a limit still at zero fails here. */
			expect(ops->save(ops->ctx, FZN_PERSIST_OWN_PREKEY, NULL, bytes, sizeof(bytes)),
			       "a save after the limit was restored still failed");
			snprintf(blocker, sizeof(blocker), "%s/%u-h", scratch,
			         (unsigned)FZN_PERSIST_OWN_PREKEY % 10u);
			(void)unlink(blocker);
			snprintf(blocker, sizeof(blocker), "%s/%u-h.tmp", scratch,
			         (unsigned)FZN_PERSIST_OWN_PREKEY % 10u);
			(void)unlink(blocker);
		}
	}

	/* ---- A DIRECTORY THAT FITS THE PATH AND NOT THE TEMPORARY. The
	 * window is four characters wide: `path_for` is called twice, once
	 * bare and once with ".tmp", and a directory long enough for the
	 * first and not the second must be refused BEFORE anything is
	 * created. Otherwise a save writes a file it can never rename into
	 * place. `_init` refuses this at start-up -- it probes with ".tmp"
	 * for exactly this reason -- so reaching it needs a struct filled by
	 * hand, which is what a caller has who memcpy'd one. */
	{
		static char window[520];
		fzn_persist_file_t hollow;
		size_t n;

		/* dir + '/' + "0-h" + '\0' must fit 512, and the same with
		 * ".tmp" must not: 504 through 507 inclusive. */
		for (n = 0; n < 505u; n++)
			window[n] = 'w';
		window[505] = '\0';

		hollow.dir = window;
		hollow.ops.load = ops->load;
		hollow.ops.save = ops->save;
		hollow.ops.ctx = &hollow;
		expect(hollow.ops.load(hollow.ops.ctx, FZN_PERSIST_TRUST, NULL, out,
		                       sizeof(out), &len) == 0,
		       "load accepted a directory at the edge of the path buffer");
		expect(!hollow.ops.save(hollow.ops.ctx, FZN_PERSIST_TRUST, NULL, bytes,
		                        sizeof(bytes)),
		       "save accepted a directory whose path fits but whose temporary "
		       "does not, which would write a file it can never rename");
	}

	/* ---- A WRITE TOO BIG TO BUFFER, so the failure lands in `fwrite`
	 * itself rather than in the flush after it. FZN_PERSIST_MAX is 96
	 * bytes and stdio buffers 8192, so every save this library makes is
	 * buffered and `fwrite` cannot fail -- but the seam takes a length
	 * from its caller and this function is written to handle one. */
	{
		struct rlimit old, zero;
		static uint8_t big[16384];

		memset(big, 0x3c, sizeof(big));
		if (getrlimit(RLIMIT_FSIZE, &old) == 0) {
			void (*prev)(int) = signal(SIGXFSZ, SIG_IGN);

			zero.rlim_cur = 0;
			zero.rlim_max = old.rlim_max;
			if (setrlimit(RLIMIT_FSIZE, &zero) == 0) {
				expect(!ops->save(ops->ctx, FZN_PERSIST_SEND_CHAIN, NULL, big,
				                  sizeof(big)),
				       "save reported success for a write that could not be "
				       "buffered and that the kernel refused");
				expect(setrlimit(RLIMIT_FSIZE, &old) == 0,
				       "the file-size limit could not be restored");
			}
			(void)signal(SIGXFSZ, prev);
			expect(ops->save(ops->ctx, FZN_PERSIST_SEND_CHAIN, NULL, bytes,
			                 sizeof(bytes)),
			       "a save after the limit was restored still failed");
			snprintf(blocker, sizeof(blocker), "%s/%u-h", scratch,
			         (unsigned)FZN_PERSIST_SEND_CHAIN % 10u);
			(void)unlink(blocker);
			snprintf(blocker, sizeof(blocker), "%s/%u-h.tmp", scratch,
			         (unsigned)FZN_PERSIST_SEND_CHAIN % 10u);
			(void)unlink(blocker);
		}
	}
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

	test_the_filesystem_refusing(dir);

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
