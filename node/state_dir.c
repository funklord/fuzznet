/* A node's state directory: project.md sec 620, and the header. */
#define _POSIX_C_SOURCE 200809L

#include "state_dir.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* The deepest a state directory is walked: the store's own layout is two
 * deep, and a walk that will not end is refused rather than taken. */
#define DEPTH_MAX 8u
#define PATH_MAX_HERE 4096u

static int say_why(const char **why, const char *text)
{
	if (why)
		*why = text;
	return 0;
}

int fzn_state_dir_backup_ok(const char *dir, const char **why)
{
	struct stat st;
	struct dirent *e;
	DIR *d;
	int empty = 1;

	if (!dir || !*dir)
		return say_why(why, "no directory named");
	if (lstat(dir, &st) != 0)
		return say_why(why, "the directory does not exist");
	if (!S_ISDIR(st.st_mode))
		return say_why(why, "not a directory, or a link to one");
	if (st.st_uid != geteuid())
		return say_why(why, "not this user's directory");
	if ((st.st_mode & 07777) != 0700)
		return say_why(why, "not mode 0700: a backup holds the identity's seed");
	if ((d = opendir(dir)) == NULL)
		return say_why(why, "the directory will not open");
	while ((e = readdir(d)) != NULL)
		if (strcmp(e->d_name, ".") != 0 && strcmp(e->d_name, "..") != 0) {
			empty = 0;
			break;
		}
	closedir(d);
	return empty ? 1 : say_why(why, "not empty: a backup overwrites nothing");
}

/* ONE FILE COPIED WHOLE, created anew. */
static int copy_file(const char *from, const char *to)
{
	char buf[65536];
	int in = open(from, O_RDONLY | O_NOFOLLOW), out;
	ssize_t n;
	int ok = 1;

	if (in < 0)
		return 0;
	out = open(to, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
	if (out < 0) {
		close(in);
		return 0;
	}
	while ((n = read(in, buf, sizeof(buf))) != 0) {
		ssize_t at = 0;

		if (n < 0) {
			if (errno == EINTR)
				continue;
			ok = 0;
			break;
		}
		while (at < n) {
			ssize_t w = write(out, buf + at, (size_t)(n - at));

			if (w < 0) {
				if (errno == EINTR)
					continue;
				ok = 0;
				break;
			}
			at += w;
		}
		if (!ok)
			break;
	}
	if (fsync(out) != 0)
		ok = 0;
	if (close(out) != 0)
		ok = 0;
	close(in);
	return ok;
}

static int copy_tree(const char *from, const char *to, unsigned depth, size_t *files,
                     const char **why)
{
	char a[PATH_MAX_HERE], b[PATH_MAX_HERE];
	struct dirent *e;
	struct stat st;
	DIR *d;
	int ok = 1;

	if (depth > DEPTH_MAX)
		return say_why(why, "the state directory is deeper than any store makes");
	if ((d = opendir(from)) == NULL)
		return say_why(why, "a directory would not open");
	while (ok && (e = readdir(d)) != NULL) {
		if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
			continue;
		if ((size_t)snprintf(a, sizeof(a), "%s/%s", from, e->d_name) >= sizeof(a)
		    || (size_t)snprintf(b, sizeof(b), "%s/%s", to, e->d_name) >= sizeof(b)) {
			ok = say_why(why, "a path is too long");
			break;
		}
		if (lstat(a, &st) != 0) {
			ok = say_why(why, "a file vanished while it was copied");
			break;
		}
		if (S_ISREG(st.st_mode)) {
			if (!copy_file(a, b)) {
				ok = say_why(why, "a file would not copy whole");
				break;
			}
			(*files)++;
		} else if (S_ISDIR(st.st_mode)) {
			if (mkdir(b, 0700) != 0) {
				ok = say_why(why, "a directory would not be made");
				break;
			}
			ok = copy_tree(a, b, depth + 1u, files, why);
		} else {
			ok = say_why(why, "the state directory holds a link or a special file");
		}
	}
	closedir(d);
	return ok;
}

int fzn_state_dir_copy(const char *from, const char *to, size_t *files, const char **why)
{
	struct stat st;

	if (files)
		*files = 0;
	if (!from || !*from || !to || !*to || !files)
		return say_why(why, "no directory named");
	if (lstat(from, &st) != 0 || !S_ISDIR(st.st_mode))
		return say_why(why, "the state directory is not a directory");
	if (lstat(to, &st) != 0 || !S_ISDIR(st.st_mode))
		return say_why(why, "the backup directory is not a directory");
	return copy_tree(from, to, 0u, files, why);
}

static int wipe_tree(const char *dir, unsigned depth, size_t *files, const char **why)
{
	char p[PATH_MAX_HERE];
	struct dirent *e;
	struct stat st;
	DIR *d;
	int ok = 1;

	if (depth > DEPTH_MAX)
		return say_why(why, "the state directory is deeper than any store makes");
	if ((d = opendir(dir)) == NULL)
		return say_why(why, "a directory would not open");
	while ((e = readdir(d)) != NULL) {
		if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
			continue;
		if ((size_t)snprintf(p, sizeof(p), "%s/%s", dir, e->d_name) >= sizeof(p)) {
			ok = say_why(why, "a path is too long");
			continue;
		}
		/* LSTAT, so a link is seen as a link and never followed. */
		if (lstat(p, &st) != 0)
			continue;
		if (S_ISDIR(st.st_mode)) {
			if (!wipe_tree(p, depth + 1u, files, why))
				ok = 0;
		} else if (S_ISREG(st.st_mode)) {
			/* TRUNCATED FIRST, so a file held open elsewhere gives its
			 * bytes up too; then gone. */
			if (truncate(p, 0) != 0 || unlink(p) != 0)
				ok = say_why(why, "a file would not go");
			else
				(*files)++;
		}
	}
	closedir(d);
	return ok;
}

int fzn_state_dir_wipe_ok(const char *dir, const char **why)
{
	struct stat st;

	if (!dir || !*dir)
		return say_why(why, "no directory named");
	if (strcmp(dir, "/") == 0)
		return say_why(why, "the filesystem's root is no state directory");
	if (lstat(dir, &st) != 0 || !S_ISDIR(st.st_mode))
		return say_why(why, "not a directory, or a link to one");
	return 1;
}

int fzn_state_dir_wipe(const char *dir, size_t *files, const char **why)
{
	if (files)
		*files = 0;
	/* THE PATH CHECKED BEFORE ANYTHING GOES. */
	if (!files || !fzn_state_dir_wipe_ok(dir, why))
		return 0;
	return wipe_tree(dir, 0u, files, why);
}
