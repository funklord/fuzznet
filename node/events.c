/* See events.h. */

#define _POSIX_C_SOURCE 200809L

#include "events.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

void fzn_node_events_init(fzn_node_events_t *ev)
{
	if (!ev)
		return;
	memset(ev, 0, sizeof(*ev));
	ev->next = 1u;
}

/* What `s` costs escaped: a byte outside A-Z a-z 0-9 - . _ ~ three. */
static size_t escaped_cost(const char *s, size_t n)
{
	size_t i, c = 0;

	for (i = 0; i < n; i++) {
		char b = s[i];

		c += ((b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
		      || b == '-' || b == '.' || b == '_' || b == '~')
		             ? 1u
		             : 3u;
	}
	return c;
}

size_t fzn_node_events_since(const fzn_node_events_t *ev, uint64_t from, char *out, size_t cap,
                             size_t escaped_cap)
{
	uint64_t first, seq, next;
	size_t len, cost;
	char head[48];
	int n;

	if (!ev || !out || !ev->next)
		return 0;
	first = ev->next > FZN_NODE_EVENTS_KEPT ? ev->next - FZN_NODE_EVENTS_KEPT : 1u;
	seq = from < first ? first : from;
	/* NEXT AS FAR AS THE PAGE GOES, found before the head is written:
	 * the head names it. */
	cost = 0;
	next = seq;
	for (; next < ev->next; next++) {
		const fzn_node_event_kept_t *k = &ev->kept[(next - 1u) % FZN_NODE_EVENTS_KEPT];
		size_t sl = strlen(k->subject), nl = strlen(k->name);

		/* " SUBJECT NAME": two spaces escaped, and the two words; and
		 * room kept for the head, two numbers of 20 digits and a space
		 * escaped, 43 at most. */
		if (cost + 6u + escaped_cost(k->subject, sl) + escaped_cost(k->name, nl) + 43u
		    > escaped_cap)
			break;
		cost += 6u + escaped_cost(k->subject, sl) + escaped_cost(k->name, nl);
	}
	if (from > ev->next)
		next = ev->next;
	n = snprintf(head, sizeof(head), "%llu %llu", (unsigned long long)next,
	             (unsigned long long)first);
	if (n <= 0 || (size_t)n >= sizeof(head) || (size_t)n >= cap
	    || escaped_cost(head, (size_t)n) + cost > escaped_cap)
		return 0;
	memcpy(out, head, (size_t)n);
	len = (size_t)n;
	for (; seq < next; seq++) {
		const fzn_node_event_kept_t *k = &ev->kept[(seq - 1u) % FZN_NODE_EVENTS_KEPT];

		n = snprintf(out + len, cap - len, " %s %s", k->subject, k->name);
		if (n <= 0 || (size_t)n >= cap - len)
			return 0;
		len += (size_t)n;
	}
	return len;
}

int fzn_node_events_room(const fzn_node_events_t *ev)
{
	return ev && ev->n < FZN_NODE_EVENTS_MAX;
}

int fzn_node_events_add(fzn_node_events_t *ev, int fd)
{
	int flags;

	if (!fzn_node_events_room(ev) || fd < 0)
		return 0;
	flags = fcntl(fd, F_GETFL);
	if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0)
		return 0;
	ev->fds[ev->n++] = fd;
	return 1;
}

/* Subscriber `i` dropped and closed; the last takes its place. */
static void drop(fzn_node_events_t *ev, size_t i)
{
	(void)close(ev->fds[i]);
	ev->fds[i] = ev->fds[--ev->n];
	ev->dropped++;
}

/* A word of `allowed` characters, 1 to `max` long. */
static int word_of(const char *s, size_t max, const char *allowed)
{
	size_t n = s ? strlen(s) : 0u;

	return n > 0u && n <= max && strspn(s, allowed) == n;
}

size_t fzn_node_events_publish(fzn_node_events_t *ev, const char *subject, const char *name)
{
	char line[16u + FZN_NODE_EVENTS_SUBJECT_MAX + FZN_NODE_EVENTS_NAME_MAX];
	size_t i, took = 0;
	int len;

	if (!name)
		name = "-";
	if (!ev || !word_of(subject, FZN_NODE_EVENTS_SUBJECT_MAX, "abcdefghijklmnopqrstuvwxyz-")
	    || !(strcmp(name, "-") == 0
	         || word_of(name, FZN_NODE_EVENTS_NAME_MAX, "0123456789abcdef")))
		return 0;
	len = snprintf(line, sizeof(line), "event %s %s\n", subject, name);
	if (len <= 0 || (size_t)len >= sizeof(line))
		return 0;
	/* KEPT, numbered, subscribers or none (sec 866). */
	if (!ev->next)
		ev->next = 1u;
	{
		fzn_node_event_kept_t *k = &ev->kept[(ev->next - 1u) % FZN_NODE_EVENTS_KEPT];

		k->seq = ev->next++;
		(void)snprintf(k->subject, sizeof(k->subject), "%s", subject);
		(void)snprintf(k->name, sizeof(k->name), "%s", name);
	}
	/* A WHOLE LINE OR THE SUBSCRIBER GOES: a part of one would leave the
	 * next line joined to it, and waiting for room would block the node. */
	for (i = 0; i < ev->n;) {
		ssize_t w = send(ev->fds[i], line, (size_t)len, MSG_NOSIGNAL | MSG_DONTWAIT);

		if (w == (ssize_t)len) {
			took++;
			ev->sent++;
			i++;
			continue;
		}
		if (w < 0 && errno == EINTR)
			continue;
		drop(ev, i);
	}
	return took;
}

int fzn_node_events_ready(fzn_node_events_t *ev, int fd)
{
	size_t i;

	if (!ev)
		return 0;
	for (i = 0; i < ev->n; i++)
		if (ev->fds[i] == fd) {
			drop(ev, i);
			return 1;
		}
	return 0;
}

void fzn_node_events_close(fzn_node_events_t *ev)
{
	if (!ev)
		return;
	while (ev->n)
		drop(ev, ev->n - 1u);
}
