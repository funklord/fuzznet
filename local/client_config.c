/* See client_config.h. */

#define _POSIX_C_SOURCE 200809L

#include "client_config.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int put(fzn_client_config_t *c, const char *key, size_t key_len, const char *value)
{
	size_t i;
	char *v = strdup(value), *k;

	if (!v)
		return 0;
	for (i = 0; i < c->n; i++)
		if (strlen(c->rows[i].key) == key_len && memcmp(c->rows[i].key, key, key_len) == 0) {
			free(c->rows[i].value);
			c->rows[i].value = v;
			return 1;
		}
	if (c->n == c->cap) {
		size_t cap = c->cap ? c->cap * 2u : 16u;
		fzn_client_config_row_t *more = realloc(c->rows, cap * sizeof(*more));

		if (!more) {
			free(v);
			return 0;
		}
		c->rows = more;
		c->cap = cap;
	}
	k = malloc(key_len + 1u);
	if (!k) {
		free(v);
		return 0;
	}
	memcpy(k, key, key_len);
	k[key_len] = '\0';
	c->rows[c->n].key = k;
	c->rows[c->n++].value = v;
	return 1;
}

int fzn_client_config_load(fzn_client_config_t *c, const char *path)
{
	FILE *f;
	char *line = NULL;
	size_t cap = 0;
	ssize_t got;
	int ok = 1;

	if (!c || !path)
		return 0;
	memset(c, 0, sizeof(*c));
	c->path = strdup(path);
	if (!c->path)
		return 0;
	f = fopen(path, "r");
	if (!f)
		return errno == ENOENT;
	while (ok && (got = getline(&line, &cap, f)) >= 0) {
		char *space;

		while (got && (line[got - 1] == '\n' || line[got - 1] == '\r'))
			line[--got] = '\0';
		space = strchr(line, ' ');
		if (!got || line[0] == '#' || !space || space == line)
			continue;
		ok = put(c, line, (size_t)(space - line), space + 1);
	}
	free(line);
	if (ferror(f))
		ok = 0;
	(void)fclose(f);
	return ok;
}

const char *fzn_client_config_get(const fzn_client_config_t *c, const char *key)
{
	size_t i;

	for (i = 0; c && key && i < c->n; i++)
		if (!strcmp(c->rows[i].key, key))
			return c->rows[i].value;
	return NULL;
}

static int save(const fzn_client_config_t *c)
{
	size_t len = strlen(c->path) + 8u, i;
	char *tmp = malloc(len);
	FILE *f;
	int ok;

	if (!tmp)
		return 0;
	(void)snprintf(tmp, len, "%s.new", c->path);
	f = fopen(tmp, "w");
	ok = f != NULL;
	for (i = 0; ok && i < c->n; i++)
		ok = fprintf(f, "%s %s\n", c->rows[i].key, c->rows[i].value) > 0;
	if (f && fclose(f) != 0)
		ok = 0;
	if (ok)
		ok = rename(tmp, c->path) == 0;
	else
		(void)unlink(tmp);
	free(tmp);
	return ok;
}

int fzn_client_config_set(fzn_client_config_t *c, const char *key, const char *value)
{
	if (!c || !c->path || !key || !value || !key[0] || key[0] == '#'
	    || strpbrk(key, " \t\r\n") || strpbrk(value, "\r\n"))
		return 0;
	return put(c, key, strlen(key), value) && save(c);
}

static int ops_get(void *ctx, const char *key, char *value, size_t cap, size_t *len)
{
	const char *v = fzn_client_config_get(ctx, key);

	if (!v || strlen(v) > cap)
		return 0;
	*len = strlen(v);
	memcpy(value, v, *len);
	return 1;
}

static int ops_set(void *ctx, const char *key, const char *value)
{
	return fzn_client_config_set(ctx, key, value);
}

void fzn_client_config_ops(fzn_client_config_t *c, fzn_preset_ops_t *ops)
{
	ops->ctx = c;
	ops->get = ops_get;
	ops->set = ops_set;
}

void fzn_client_config_free(fzn_client_config_t *c)
{
	size_t i;

	if (!c)
		return;
	for (i = 0; i < c->n; i++) {
		free(c->rows[i].key);
		free(c->rows[i].value);
	}
	free(c->rows);
	free(c->path);
	memset(c, 0, sizeof(*c));
}
