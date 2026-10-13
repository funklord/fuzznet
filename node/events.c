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
