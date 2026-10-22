#define _POSIX_C_SOURCE 200809L
#include "fault.h"

#ifdef FZN_TEST_FAULTS

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static struct {
	int read;
	uint64_t state;
	unsigned loss, dup, reorder;
	char crash[64];
	unsigned long crash_at, reached;
	int budgeted;
	unsigned long long budget, spent;
	int full_said;
} f;

static unsigned percent(const char *name)
{
	const char *v = getenv(name);
	unsigned long n = v ? strtoul(v, NULL, 10) : 0u;

	return n > 100u ? 100u : (unsigned)n;
}

static void read_once(void)
{
	const char *v;

	if (f.read)
		return;
	f.read = 1;
	v = getenv("FZN_FAULT_SEED");
	f.state = v ? (uint64_t)strtoull(v, NULL, 10) : (uint64_t)(unsigned long)getpid();
	if (!f.state)
		f.state = 0x9e3779b97f4a7c15u;
	f.loss = percent("FZN_FAULT_LOSS");
	f.dup = percent("FZN_FAULT_DUP");
	f.reorder = percent("FZN_FAULT_REORDER");
	v = getenv("FZN_FAULT_CRASH");
	if (v && *v) {
		const char *colon = strchr(v, ':');
		size_t n = colon ? (size_t)(colon - v) : strlen(v);

		if (n < sizeof(f.crash)) {
			memcpy(f.crash, v, n);
			f.crash[n] = '\0';
		}
		f.crash_at = colon ? strtoul(colon + 1, NULL, 10) : 1u;
		if (!f.crash_at)
			f.crash_at = 1u;
	}
	v = getenv("FZN_FAULT_WRITE_BUDGET");
	if (v && *v) {
		f.budgeted = 1;
		f.budget = strtoull(v, NULL, 10);
	}
}

/* xorshift64: a test's faults repeat under one seed. */
static unsigned roll(void)
{
	f.state ^= f.state << 13;
	f.state ^= f.state >> 7;
	f.state ^= f.state << 17;
	return (unsigned)(f.state % 100u);
}

fzn_fault_datagram_t fzn_fault_datagram(void)
{
	read_once();
	if (f.loss && roll() < f.loss)
		return FZN_FAULT_DROP;
	if (f.dup && roll() < f.dup)
		return FZN_FAULT_TWICE;
	if (f.reorder && roll() < f.reorder)
		return FZN_FAULT_HOLD;
	return FZN_FAULT_SEND;
}

void fzn_fault_point(const char *name)
{
	read_once();
	if (!f.crash[0] || !name || strcmp(name, f.crash) != 0)
		return;
	if (++f.reached < f.crash_at)
		return;
	(void)fprintf(stderr, "fault: dying at %s, reach %lu\n", name, f.reached);
	(void)fflush(stderr);
	(void)kill(getpid(), SIGKILL);
	_exit(137);
}

int fzn_fault_write(size_t n)
{
	read_once();
	if (!f.budgeted)
		return 1;
	if (f.spent + n > f.budget) {
		if (!f.full_said) {
			f.full_said = 1;
			(void)fprintf(stderr, "fault: the disk is full after %llu byte(s)\n", f.spent);
		}
		errno = ENOSPC;
		return 0;
	}
	f.spent += n;
	return 1;
}

unsigned long fzn_fault_tune(const char *name, unsigned long def, unsigned long max)
{
	char var[64];
	const char *v;
	unsigned long n;

	if (!name || snprintf(var, sizeof(var), "FZN_TUNE_%s", name) >= (int)sizeof(var))
		return def;
	v = getenv(var);
	if (!v || !*v)
		return def;
	n = strtoul(v, NULL, 10);
	if (n < 1u || n > max)
		return def;
	(void)fprintf(stderr, "fault: %s tuned to %lu (default %lu)\n", name, n, def);
	return n;
}

#else

/* NOTHING IN ANY OTHER BUILD: ISO C wants a declaration in every unit. */
typedef int fzn_fault_compiled_out_t;

#endif
