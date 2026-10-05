/* See logger.h. */

#define _POSIX_C_SOURCE 200809L

#include "logger.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* The classic line being written: one at a time, a logger being one
 * process's and used from one thread. */
static char line_buf[FZN_ENTRY_LINE_MAX];

const char *fzn_logger_err_str(fzn_logger_err_t err)
{
	switch (err) {
	case FZN_LOGGER_OK:
		return "ok";
	case FZN_LOGGER_ERR_MALFORMED:
		return "malformed";
	case FZN_LOGGER_ERR_IDENTITY:
		return "the machine, the host or the account would not read";
	case FZN_LOGGER_ERR_FILE:
		return "the log directory or file refused";
	}
	return "unknown";
}

static uint64_t wall_us(void)
{
	struct timespec t;

	if (clock_gettime(CLOCK_REALTIME, &t) != 0 || t.tv_sec < 0)
		return 0;
	return ((uint64_t)t.tv_sec * 1000000u) + ((uint64_t)t.tv_nsec / 1000u);
}

static uint64_t now(const fzn_logger_t *l)
{
	return l->now_us ? l->now_us() : wall_us();
}

/* A word as an entry's name holds it: what fzn_entry_classic accepts. */
static int word_ok(const char *w)
{
	size_t i;

	if (!w || !w[0])
		return 0;
	for (i = 0; w[i]; i++) {
		char c = w[i];

		if (i >= FZN_ENTRY_WORD_MAX
		    || !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		         || c == '_' || c == '-' || c == '.' || c == '+' || c == '$'))
			return 0;
	}
	return 1;
}

fzn_logger_err_t fzn_logger_identify(fzn_entry_name_t *self, char host[FZN_ENTRY_WORD_MAX + 1u],
                                     const char *program, const char *machine_id_path)
{
	char text[64], hostname[256];
	struct passwd *pw;
	FILE *f;
	size_t got;

	if (!self || !host || !word_ok(program))
		return FZN_LOGGER_ERR_MALFORMED;
	memset(self, 0, sizeof(*self));
	host[0] = '\0';
	/* /etc/machine-id, else D-Bus's, which it was adopted from and which a
	 * machine without systemd still has -- this tree's own did. sec 461. */
	f = fopen(machine_id_path ? machine_id_path : "/etc/machine-id", "r");
	if (!f && !machine_id_path)
		f = fopen("/var/lib/dbus/machine-id", "r");
	if (!f)
		return FZN_LOGGER_ERR_IDENTITY;
	got = fread(text, 1u, sizeof(text), f);
	(void)fclose(f);
	if (fzn_entry_machine_parse(text, got, self->machine) != FZN_ENTRY_OK)
		return FZN_LOGGER_ERR_IDENTITY;
	if (gethostname(hostname, sizeof(hostname)) != 0)
		return FZN_LOGGER_ERR_IDENTITY;
	hostname[sizeof(hostname) - 1u] = '\0';
	if (!word_ok(hostname))
		return FZN_LOGGER_ERR_IDENTITY;
	strcpy(host, hostname);
	/* THE ACCOUNT BY NAME, as `ls -l` shows it; by number when the
	 * password database does not know it. */
	pw = getpwuid(geteuid());
	if (pw && word_ok(pw->pw_name))
		strcpy(self->user, pw->pw_name);
	else
		(void)snprintf(self->user, sizeof(self->user), "uid%lu", (unsigned long)geteuid());
	strcpy(self->program, program);
	self->pid = (uint32_t)getpid();
	self->start_ms = wall_us() / 1000u;
	self->position = 0u;
	return FZN_LOGGER_OK;
}

fzn_logger_err_t fzn_logger_default_dir(char *out, size_t cap)
{
	const char *state = getenv("XDG_STATE_HOME"), *home = getenv("HOME");
	int k;

	if (!out || cap == 0u)
		return FZN_LOGGER_ERR_MALFORMED;
	if (geteuid() == 0)
		k = snprintf(out, cap, "/var/log/fuzznet");
	/* XDG: a relative value is invalid and is ignored. */
	else if (state && state[0] == '/')
		k = snprintf(out, cap, "%s/fuzznet/log", state);
	else if (home && home[0] == '/')
		k = snprintf(out, cap, "%s/.local/state/fuzznet/log", home);
	else
		return FZN_LOGGER_ERR_MALFORMED;
	return (k > 0 && (size_t)k < cap) ? FZN_LOGGER_OK : FZN_LOGGER_ERR_MALFORMED;
}

/* Every directory down to `dir`, mode 0700 where one is made. */
static int make_dirs(const char *dir)
{
	char p[FZN_LOGGER_PATH_MAX];
	size_t i, n = strlen(dir);

	if (n == 0u || n >= sizeof(p))
		return 0;
	memcpy(p, dir, n + 1u);
	for (i = 1; i <= n; i++) {
		if (p[i] != '/' && p[i] != '\0')
			continue;
		p[i] = '\0';
		if (mkdir(p, 0700) != 0 && errno != EEXIST)
			return 0;
		p[i] = i == n ? '\0' : '/';
	}
	return 1;
}

/* The program's current file, made with its header if nobody has. */
static int open_file(fzn_logger_t *l)
{
	char hex[(FZN_ENTRY_MACHINE_LEN * 2u) + 1u], head[160];
	static const char HEX[] = "0123456789abcdef";
	size_t i;
	int fd, k;

	fd = open(l->path, O_WRONLY | O_APPEND | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	if (fd >= 0) {
		for (i = 0; i < FZN_ENTRY_MACHINE_LEN; i++) {
			hex[i * 2u] = HEX[l->self.machine[i] >> 4];
			hex[(i * 2u) + 1u] = HEX[l->self.machine[i] & 0x0fu];
		}
		hex[FZN_ENTRY_MACHINE_LEN * 2u] = '\0';
		k = snprintf(head, sizeof(head), "#fuzznet-log 1 machine=%s host=%s\n", hex, l->host);
		if (k <= 0 || (size_t)k >= sizeof(head) || write(fd, head, (size_t)k) != (ssize_t)k) {
			(void)close(fd);
			return 0;
		}
	} else if (errno == EEXIST) {
		fd = open(l->path, O_WRONLY | O_APPEND | O_CLOEXEC);
		if (fd < 0)
			return 0;
	} else {
		return 0;
	}
	l->fd = fd;
	return 1;
}

fzn_logger_err_t fzn_logger_open(fzn_logger_t *logger, const fzn_entry_name_t *self,
                                 const char *host, const char *dir, fzn_entry_level_t keep,
                                 fzn_ring_t *ring, uint64_t segment_max)
{
	int k;

	if (!logger || !self || !word_ok(host) || !dir || !fzn_entry_level_letter(keep)
	    || !word_ok(self->user) || !word_ok(self->program))
		return FZN_LOGGER_ERR_MALFORMED;
	memset(logger, 0, sizeof(*logger));
	logger->fd = -1;
	logger->self = *self;
	strcpy(logger->host, host);
	logger->keep = keep;
	logger->ring = ring;
	logger->segment_max = segment_max ? segment_max : FZN_LOGGER_SEGMENT_DEFAULT;
	k = snprintf(logger->dir, sizeof(logger->dir), "%s", dir);
	if (k <= 0 || (size_t)k >= sizeof(logger->dir))
		return FZN_LOGGER_ERR_MALFORMED;
	k = snprintf(logger->path, sizeof(logger->path), "%s/%s.log", dir, self->program);
	if (k <= 0 || (size_t)k >= sizeof(logger->path))
		return FZN_LOGGER_ERR_MALFORMED;
	if (!make_dirs(dir) || !open_file(logger))
		return FZN_LOGGER_ERR_FILE;
	return FZN_LOGGER_OK;
}

/* STILL THE PROGRAM'S FILE: another instance may have rotated it away. */
static int current(fzn_logger_t *l)
{
	struct stat on_path, held;

	if (l->fd >= 0 && stat(l->path, &on_path) == 0 && fstat(l->fd, &held) == 0
	    && on_path.st_dev == held.st_dev && on_path.st_ino == held.st_ino)
		return 1;
	if (l->fd >= 0)
		(void)close(l->fd);
	l->fd = -1;
	return open_file(l);
}

/* Past the segment size, the file is closed under a name of its own. */
static int rotate_if_full(fzn_logger_t *l, size_t adding, uint64_t at_us)
{
	char closed[FZN_LOGGER_PATH_MAX];
	struct stat held;
	int k;

	if (fstat(l->fd, &held) != 0)
		return 0;
	if (held.st_size <= 0 || (uint64_t)held.st_size + adding <= l->segment_max)
		return 1;
	k = snprintf(closed, sizeof(closed), "%s/%s.%llu.%lu.log", l->dir, l->self.program,
	             (unsigned long long)at_us, (unsigned long)l->self.pid);
	if (k <= 0 || (size_t)k >= sizeof(closed))
		return 0;
	/* GONE ALREADY is another instance's rotation, and fine. */
	if (rename(l->path, closed) != 0 && errno != ENOENT)
		return 0;
	(void)close(l->fd);
	l->fd = -1;
	if (!open_file(l))
		return 0;
	if (l->rotated)
		l->rotated(l->rotated_ctx);
	return 1;
}

fzn_logger_err_t fzn_logger_log(fzn_logger_t *logger, fzn_entry_level_t level,
                                const char *subsystem, const fzn_entry_name_t *cause,
                                const fzn_entry_name_t *origin, const uint8_t *text,
                                size_t text_len, fzn_entry_name_t *named)
{
	fzn_entry_t e;
	size_t len = 0, n;
	int kept;

	if (!logger || !subsystem || (!cause) != (!origin) || (!text && text_len))
		return FZN_LOGGER_ERR_MALFORMED;
	memset(&e, 0, sizeof(e));
	e.name = logger->self;
	e.time_us = now(logger);
	e.level = level;
	n = strlen(subsystem);
	if (n == 0u || n > FZN_ENTRY_SUBSYSTEM_MAX)
		return FZN_LOGGER_ERR_MALFORMED;
	memcpy(e.subsystem, subsystem, n + 1u);
	if (cause) {
		e.caused = 1;
		e.cause = *cause;
		e.origin = *origin;
	}
	e.text = text;
	e.text_len = text_len;
	kept = fzn_entry_level_letter(level) && level <= logger->keep;
	/* THE LINE FIRST WHEN IT IS KEPT, so an entry the line refuses is
	 * refused before it takes a position or a place in the ring. */
	if (kept && fzn_entry_classic(&e, logger->host, line_buf, sizeof(line_buf), &len)
	                    != FZN_ENTRY_OK)
		return FZN_LOGGER_ERR_MALFORMED;
	if (logger->ring && fzn_ring_put(logger->ring, &e) != FZN_RING_OK)
		return FZN_LOGGER_ERR_MALFORMED;
	if (!kept && !logger->ring && fzn_entry_pack(&e, (uint8_t *)line_buf, sizeof(line_buf), &n)
	                                      != FZN_ENTRY_OK)
		return FZN_LOGGER_ERR_MALFORMED;
	logger->self.position++;
	if (named)
		*named = e.name;
	if (!kept)
		return FZN_LOGGER_OK;
	if (!current(logger) || !rotate_if_full(logger, len, e.time_us)
	    || write(logger->fd, line_buf, len) != (ssize_t)len)
		return FZN_LOGGER_ERR_FILE;
	return FZN_LOGGER_OK;
}

void fzn_logger_close(fzn_logger_t *logger)
{
	if (logger && logger->fd >= 0) {
		(void)close(logger->fd);
		logger->fd = -1;
	}
}

/* ---- retention ----------------------------------------------------------- */

/* Segments one pass plans over; past it the oldest wait for the next. */
#define RETAIN_MAX 1024u

/* `PROGRAM.TIME.PID.log`, packed or not: its closing time, or 0. */
static uint64_t segment_closed(const char *name, const char *program)
{
	size_t plen = strlen(program), i;
	const char *t, *dot;
	uint64_t v = 0;

	if (strncmp(name, program, plen) != 0 || name[plen] != '.')
		return 0;
	t = name + plen + 1u;
	dot = strchr(t, '.');
	if (!dot || dot == t)
		return 0;
	for (i = 0; t + i < dot; i++) {
		if (t[i] < '0' || t[i] > '9' || v > (UINT64_MAX - 9u) / 10u)
			return 0;
		v = (v * 10u) + (uint64_t)(t[i] - '0');
	}
	t = dot + 1;
	dot = strchr(t, '.');
	if (!dot || dot == t || (strcmp(dot, ".log") != 0 && strcmp(dot, ".log.zst") != 0))
		return 0;
	for (; t < dot; t++)
		if (*t < '0' || *t > '9')
			return 0;
	return v;
}

/* `name` as a log file's: its program, into `out`, or 0. A program may hold
 * a dot, so a segment's is what is left with its TIME.PID.log taken off. */
static int program_of(const char *name, char out[FZN_ENTRY_WORD_MAX + 1u])
{
	size_t len = strlen(name), k, fields = 0;
	int packed = 0;

	if (len > 8u && !strcmp(name + len - 8u, ".log.zst")) {
		len -= 8u;
		packed = 1;
	} else if (len > 4u && !strcmp(name + len - 4u, ".log"))
		len -= 4u;
	else
		return 0;
	k = len;
	while (fields < 2u && k > 0u) {
		size_t end = k;

		while (k > 0u && name[k - 1u] >= '0' && name[k - 1u] <= '9')
			k--;
		if (k == end || k == 0u || name[k - 1u] != '.')
			break;
		k--;
		fields++;
	}
	if (fields == 2u)
		len = k;
	else if (packed) /* only a closed segment is packed */
		return 0;
	if (!len || len > FZN_ENTRY_WORD_MAX)
		return 0;
	memcpy(out, name, len);
	out[len] = '\0';
	return word_ok(out);
}

fzn_logger_err_t fzn_logger_programs(const char *dir, char (*out)[FZN_ENTRY_WORD_MAX + 1u],
                                     size_t max, size_t *n)
{
	char program[FZN_ENTRY_WORD_MAX + 1u], swap[FZN_ENTRY_WORD_MAX + 1u];
	struct dirent *e;
	size_t k, j;
	DIR *d;

	if (!dir || !out || !n)
		return FZN_LOGGER_ERR_MALFORMED;
	*n = 0;
	d = opendir(dir);
	if (!d)
		return FZN_LOGGER_ERR_FILE;
	while ((e = readdir(d)) != NULL && *n < max) {
		if (!program_of(e->d_name, program))
			continue;
		for (k = 0; k < *n && strcmp(out[k], program) != 0; k++)
			;
		if (k == *n)
			memcpy(out[(*n)++], program, sizeof(program));
	}
	(void)closedir(d);
	for (k = 1; k < *n; k++)
		for (j = k; j > 0u && strcmp(out[j - 1u], out[j]) > 0; j--) {
			memcpy(swap, out[j], sizeof(swap));
			memcpy(out[j], out[j - 1u], sizeof(swap));
			memcpy(out[j - 1u], swap, sizeof(swap));
		}
	return FZN_LOGGER_OK;
}

fzn_logger_err_t fzn_logger_retain(const char *dir, const char *program,
                                   const fzn_retain_rule_t *rules, size_t n_rules,
                                   uint64_t now_us, size_t *removed)
{
	static char names[RETAIN_MAX][256];
	static fzn_retain_segment_t segs[RETAIN_MAX];
	static uint8_t gone[RETAIN_MAX];
	char path[FZN_LOGGER_PATH_MAX];
	struct dirent *e;
	size_t n = 0, i;
	DIR *d;

	if (!dir || !removed || !word_ok(program) || (!rules && n_rules))
		return FZN_LOGGER_ERR_MALFORMED;
	*removed = 0;
	d = opendir(dir);
	if (!d)
		return FZN_LOGGER_ERR_FILE;
	while ((e = readdir(d)) != NULL && n < RETAIN_MAX) {
		uint64_t at = segment_closed(e->d_name, program);
		struct stat st;
		int k;

		if (at == 0u || strlen(e->d_name) >= sizeof(names[0]))
			continue;
		k = snprintf(path, sizeof(path), "%s/%s", dir, e->d_name);
		if (k <= 0 || (size_t)k >= sizeof(path) || stat(path, &st) != 0)
			continue;
		strcpy(names[n], e->d_name);
		segs[n].closed_us = at;
		segs[n].bytes = st.st_size > 0 ? (uint64_t)st.st_size : 0u;
		n++;
	}
	(void)closedir(d);
	if (fzn_retain_plan(program, segs, n, rules, n_rules, now_us, gone) != FZN_RETAIN_OK)
		return FZN_LOGGER_ERR_MALFORMED;
	for (i = 0; i < n; i++) {
		if (!gone[i])
			continue;
		if (snprintf(path, sizeof(path), "%s/%.255s", dir, names[i]) >= (int)sizeof(path))
			return FZN_LOGGER_ERR_MALFORMED;
		/* GONE ALREADY is another instance's pass, and fine. */
		if (remove(path) != 0 && errno != ENOENT)
			return FZN_LOGGER_ERR_FILE;
		(*removed)++;
	}
	return FZN_LOGGER_OK;
}
