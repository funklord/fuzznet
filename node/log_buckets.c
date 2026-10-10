/* See log_buckets.h. */

#define _POSIX_C_SOURCE 200809L

#include "log_buckets.h"

#include "../log/copy.h"
#include "../log/pack.h"
#include "../messages/line.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define PATH_MAX_ 1024u

static const char HEX[] = "0123456789abcdef";

static void hex_of(const uint8_t *in, size_t n, char *out)
{
	size_t i;

	for (i = 0; i < n; i++) {
		out[2u * i] = HEX[in[i] >> 4];
		out[(2u * i) + 1u] = HEX[in[i] & 15u];
	}
	out[2u * n] = '\0';
}

int fzn_log_buckets_init(fzn_log_buckets_t *lb, const fzn_buckets_t *b, const char *dir,
                         const fzn_hash_ops_t *hash, const fzn_sign_ops_t *sign,
                         const uint8_t self[32])
{
	size_t n;

	if (!lb || !b || !dir || !hash || !hash->hash || !sign || !self)
		return 0;
	n = strlen(dir);
	if (n == 0u || n >= sizeof(lb->dir))
		return 0;
	memset(lb, 0, sizeof(*lb));
	lb->b = b;
	memcpy(lb->dir, dir, n + 1u);
	lb->hash = hash;
	lb->sign = sign;
	memcpy(lb->self, self, 32u);
	return 1;
}

void fzn_log_buckets_close(fzn_log_buckets_t *lb)
{
	if (!lb)
		return;
	free(lb->staging);
	lb->staging = NULL;
	lb->staging_cap = lb->staged = 0;
}

/* ---- refs ------------------------------------------------------------------ */

/* A REF, read: its file's path into `path`, and the segment's name. `o/NAME`
 * is this host's own; `c/HOSTHEX/NAME` a copy. 0 for anything else. */
static int ref_path(const fzn_log_buckets_t *lb, const uint8_t *ref, size_t ref_len,
                    char path[PATH_MAX_], const char **name, size_t *name_len)
{
	char r[FZN_BUCKETS_REF_MAX + 1u];
	int k;

	if (ref_len == 0u || ref_len > FZN_BUCKETS_REF_MAX)
		return 0;
	memcpy(r, ref, ref_len);
	r[ref_len] = '\0';
	if (memchr(r, '\0', ref_len))
		return 0;
	if (ref_len > 2u && r[0] == 'o' && r[1] == '/') {
		*name = (const char *)ref + 2;
		*name_len = ref_len - 2u;
		if (!fzn_log_copy_packed_time(r + 2))
			return 0;
		k = snprintf(path, PATH_MAX_, "%s/%s", lb->dir, r + 2);
		/* ARCHIVED, sec 588: moved to the fossil class, still this
		 * host's and still held. */
		if (k > 0 && (size_t)k < PATH_MAX_ && lb->archive[0] && access(path, F_OK) != 0)
			k = snprintf(path, PATH_MAX_, "%s/%s", lb->archive, r + 2);
	} else if (ref_len > 67u && r[0] == 'c' && r[1] == '/' && r[66] == '/') {
		size_t i;

		for (i = 2; i < 66u; i++)
			if (!strchr(HEX, r[i]) || !r[i])
				return 0;
		*name = (const char *)ref + 67;
		*name_len = ref_len - 67u;
		if (!fzn_log_copy_packed_time(r + 67))
			return 0;
		r[66] = '\0';
		k = snprintf(path, PATH_MAX_, "%s/copy/%s/%s", lb->dir, r + 2, r + 67);
	} else {
		return 0;
	}
	return k > 0 && (size_t)k < PATH_MAX_ && *name_len <= FZN_LOG_BUCKETS_NAME_MAX;
}

/* ---- reading ------------------------------------------------------------------ */

/* `n` bytes of the item `ref` names from `offset`: its head -- the name's
 * length and the name -- then the file's bytes. The file read with pread on
 * each call: a piece is a few KiB, and nothing here outlives the call. */
static int item_read(void *ctx, const uint8_t *ref, size_t ref_len, uint64_t offset,
                     uint8_t *out, size_t n)
{
	fzn_log_buckets_t *lb = (fzn_log_buckets_t *)ctx;
	char path[PATH_MAX_];
	const char *name;
	size_t name_len, head;
	int fd;

	if (!lb || !out || !ref_path(lb, ref, ref_len, path, &name, &name_len))
		return 0;
	head = 1u + name_len;
	while (n && offset < head) {
		*out++ = offset == 0u ? (uint8_t)name_len : (uint8_t)name[offset - 1u];
		offset++;
		n--;
	}
	if (!n)
		return 1;
	fd = open(path, O_RDONLY);
	if (fd < 0)
		return 0;
	while (n) {
		ssize_t got = pread(fd, out, n, (off_t)(offset - head));

		if (got <= 0) {
			(void)close(fd);
			return 0;
		}
		out += got;
		offset += (uint64_t)got;
		n -= (size_t)got;
	}
	return close(fd) == 0;
}

/* ---- this host's own segments ------------------------------------------------- */

/* The whole file at `path` after a head naming `name`, as an item, into a
 * buffer this allocates: its length in `*len`, NULL on failure or past
 * FZN_BUCKETS_LARGE_MAX. */
static uint8_t *item_of_file(const char *path, const char *name, size_t *len)
{
	size_t name_len = strlen(name), at, size;
	struct stat st;
	uint8_t *item;
	FILE *f;

	if (name_len > FZN_LOG_BUCKETS_NAME_MAX || stat(path, &st) != 0 || st.st_size < 0
	    || (uint64_t)st.st_size + 1u + name_len > FZN_BUCKETS_LARGE_MAX)
		return NULL;
	size = (size_t)st.st_size;
	item = malloc(1u + name_len + size + 1u);
	if (!item)
		return NULL;
	item[0] = (uint8_t)name_len;
	memcpy(item + 1, name, name_len);
	at = 1u + name_len;
	f = fopen(path, "rb");
	if (!f || fread(item + at, 1u, size, f) != size) {
		if (f)
			(void)fclose(f);
		free(item);
		return NULL;
	}
	(void)fclose(f);
	*len = at + size;
	return item;
}

/* EVERY ITEM WHOSE FILE IS GONE, let go, sec 572: a segment this host's
 * rules removed, or a copy the copy rules did. Its id stays in its bucket,
 * served as not held. */
static int sweep(fzn_log_buckets_t *lb, size_t *let_go)
{
	static fzn_bucket_t buckets[FZN_BUCKETS_MAX];
	size_t n = 0, k;
	int ok = 1;

	if (fzn_buckets_list(lb->b, FZN_BUCKETS_LOGS, buckets, FZN_BUCKETS_MAX, &n)
	    != FZN_BUCKETS_OK)
		return 0;
	for (k = 0; k < n; k++) {
		uint8_t ids[64][FZN_BUCKETS_ID_LEN];
		uint64_t at = 0, total = 0;
		size_t got = 0, i;

		do {
			if (fzn_buckets_ids(lb->b, FZN_BUCKETS_LOGS, buckets[k].subject, buckets[k].month,
			                    at, ids, 64u, &got, &total)
			    != FZN_BUCKETS_OK)
				return 0;
			for (i = 0; i < got; i++) {
				uint8_t ref[FZN_BUCKETS_REF_MAX];
				char path[PATH_MAX_];
				const char *name;
				size_t ref_len = 0, name_len = 0;
				uint64_t size = 0;
				struct stat st;

				if (fzn_buckets_ref(lb->b, FZN_BUCKETS_LOGS, ids[i], ref, &ref_len, &size)
				            != FZN_BUCKETS_OK
				    || !ref_path(lb, ref, ref_len, path, &name, &name_len))
					continue;
				if (stat(path, &st) == 0 || errno != ENOENT)
					continue;
				if (fzn_buckets_let_go(lb->b, FZN_BUCKETS_LOGS, ids[i]) != FZN_BUCKETS_OK)
					ok = 0;
				else if (let_go)
					(*let_go)++;
			}
			at += got;
		} while (got && at < total);
	}
	return ok;
}

int fzn_log_buckets_scan(fzn_log_buckets_t *lb, size_t *taken, size_t *let_go)
{
	struct dirent *e;
	DIR *d;
	int ok = 1;

	if (taken)
		*taken = 0;
	if (let_go)
		*let_go = 0;
	if (!lb || !lb->b)
		return 0;
	d = opendir(lb->dir);
	if (!d)
		return errno == ENOENT;
	while ((e = readdir(d)) != NULL) {
		uint64_t closed = fzn_log_copy_packed_time(e->d_name), held = 0;
		char ref[FZN_BUCKETS_REF_MAX + 1u], path[PATH_MAX_];
		uint8_t id[FZN_BUCKETS_ID_LEN], *item;
		size_t name_len = strlen(e->d_name), len = 0;
		struct stat st;
		int added = 0;

		if (!closed || name_len > FZN_LOG_BUCKETS_NAME_MAX
		    || snprintf(ref, sizeof(ref), "o/%s", e->d_name) >= (int)sizeof(ref)
		    || snprintf(path, sizeof(path), "%s/%s", lb->dir, e->d_name) >= (int)sizeof(path)
		    || stat(path, &st) != 0)
			continue;
		/* KNOWN, AT THIS LENGTH: not read again. KNOWN AT ANOTHER -- the
		 * segment repacked under its name (sec 474) -- the old id is let go
		 * before the new is taken, so its bucket never names a file that
		 * no longer hashes to it. sec 572. */
		if (fzn_buckets_by_ref(lb->b, FZN_BUCKETS_LOGS, (const uint8_t *)ref, strlen(ref), id,
		                       &held)
		    == FZN_BUCKETS_OK) {
			uint8_t was[FZN_BUCKETS_REF_MAX];
			size_t was_len = 0;
			uint64_t was_size = 0;
			fzn_buckets_err_t gone;

			/* AT THIS LENGTH AND STILL HELD: nothing new. LET GO, its file
			 * back -- a log directory moved away and back -- it is read
			 * again and, its bytes the same, restored by the taking below. */
			if (held == 1u + name_len + (uint64_t)st.st_size) {
				if (fzn_buckets_ref(lb->b, FZN_BUCKETS_LOGS, id, was, &was_len, &was_size)
				    == FZN_BUCKETS_OK)
					continue;
				goto read;
			}
			gone = fzn_buckets_let_go(lb->b, FZN_BUCKETS_LOGS, id);
			if (gone != FZN_BUCKETS_OK && gone != FZN_BUCKETS_ABSENT)
				ok = 0;
			if (let_go)
				(*let_go)++;
		}
	read:
		item = item_of_file(path, e->d_name, &len);
		if (!item)
			continue;
		if (!fzn_buckets_id(lb->hash, item, len, id)
		    || fzn_buckets_add_ref(lb->b, FZN_BUCKETS_LOGS, lb->self,
		                           fzn_message_epoch_of(closed / 1000u), id, len,
		                           (const uint8_t *)ref, strlen(ref), &added)
		               != FZN_BUCKETS_OK)
			ok = 0;
		free(item);
		if (taken && added)
			(*taken)++;
	}
	(void)closedir(d);
	return sweep(lb, let_go) && ok;
}

/* ---- keeping another's, or this host's own come back ------------------------ */

/* KEEP `item` -- a segment named in its head -- as `subject`'s, of `month`:
 * written beside the copies, checked signed by `subject`, renamed into
 * place and taken. Its id, `id`, the caller has checked. */
static fzn_node_apply_outcome_t keep(fzn_log_buckets_t *lb, const uint8_t subject[32],
                                     uint32_t month, const uint8_t *item, size_t len,
                                     const uint8_t id[FZN_BUCKETS_ID_LEN])
{
	char name[FZN_LOG_BUCKETS_NAME_MAX + 1u], host[65], dir[PATH_MAX_], path[PATH_MAX_],
	        tmp[PATH_MAX_ + 8u], ref[FZN_BUCKETS_REF_MAX + 1u];
	uint8_t prev[32], next[32], key[32];
	size_t name_len, body;
	uint64_t closed;
	int is_signed = 0;
	FILE *f;

	if (len < 2u || (name_len = item[0]) == 0u || name_len > FZN_LOG_BUCKETS_NAME_MAX
	    || len <= 1u + name_len)
		return FZN_NODE_APPLY_REFUSED;
	memcpy(name, item + 1, name_len);
	name[name_len] = '\0';
	closed = fzn_log_copy_packed_time(name);
	/* A SEGMENT, OF THE MONTH IT WAS OFFERED UNDER. */
	if (!closed || memchr(name, '\0', name_len) || fzn_message_epoch_of(closed / 1000u) != month)
		return FZN_NODE_APPLY_REFUSED;
	hex_of(subject, 32u, host);
	if (snprintf(dir, sizeof(dir), "%s/copy/%s", lb->dir, host) >= (int)sizeof(dir)
	    || snprintf(path, sizeof(path), "%s/%s", dir, name) >= (int)sizeof(path)
	    || snprintf(tmp, sizeof(tmp), "%s/.%s.new", dir, name) >= (int)sizeof(tmp)
	    || snprintf(ref, sizeof(ref), "c/%s/%s", host, name) >= (int)sizeof(ref))
		return FZN_NODE_APPLY_REFUSED;
	if (!fzn_log_copy_make_dir(dir))
		return FZN_NODE_APPLY_NOT_SAVED;
	body = len - 1u - name_len;
	f = fopen(tmp, "wb");
	if (!f)
		return FZN_NODE_APPLY_NOT_SAVED;
	if (fwrite(item + 1u + name_len, 1u, body, f) != body || fflush(f) != 0
	    || fsync(fileno(f)) != 0) {
		(void)fclose(f);
		(void)remove(tmp);
		return FZN_NODE_APPLY_NOT_SAVED;
	}
	(void)fclose(f);
	/* SIGNED BY ITS SUBJECT, from the prev its own trailer names. NO
	 * SIGNER UNTIL ONE IS READ: an unsigned trailer writes none. */
	memset(key, 0, sizeof(key));
	if (fzn_log_pack_trailer_prev(tmp, prev) != FZN_LOG_PACK_OK
	    || fzn_log_pack_verify_signed(tmp, prev, lb->hash, lb->sign, next, &is_signed, key)
	               != FZN_LOG_PACK_OK
	    || !is_signed || memcmp(key, subject, 32u) != 0) {
		(void)remove(tmp);
		return FZN_NODE_APPLY_REFUSED;
	}
	if (rename(tmp, path) != 0) {
		(void)remove(tmp);
		return FZN_NODE_APPLY_NOT_SAVED;
	}
	return fzn_buckets_add_ref(lb->b, FZN_BUCKETS_LOGS, subject, month, id, len,
	                           (const uint8_t *)ref, strlen(ref), NULL)
	                       == FZN_BUCKETS_OK
	               ? FZN_NODE_APPLY_APPLIED
	               : FZN_NODE_APPLY_NOT_SAVED;
}

static fzn_node_apply_outcome_t item_file(void *ctx, const uint8_t subject[FZN_PUBKEY_LEN],
                                          uint32_t month, const uint8_t *item, size_t len)
{
	fzn_log_buckets_t *lb = (fzn_log_buckets_t *)ctx;
	uint8_t id[FZN_BUCKETS_ID_LEN];

	if (!lb || !fzn_buckets_id(lb->hash, item, len, id))
		return FZN_NODE_APPLY_REFUSED;
	return keep(lb, subject, month, item, len, id);
}

static int item_stage(void *ctx, const uint8_t id[FZN_BUCKETS_ID_LEN], uint64_t total,
                      uint64_t offset, const uint8_t *bytes, size_t n)
{
	fzn_log_buckets_t *lb = (fzn_log_buckets_t *)ctx;

	if (!lb || total == 0u || total > FZN_BUCKETS_LARGE_MAX)
		return 0;
	/* A PIECE AT 0 BEGINS AN ITEM afresh, whatever was staged. */
	if (offset == 0u) {
		if (lb->staging_cap < total) {
			uint8_t *grown = realloc(lb->staging, (size_t)total);

			if (!grown)
				return 0;
			lb->staging = grown;
			lb->staging_cap = (size_t)total;
		}
		memcpy(lb->stage_id, id, FZN_BUCKETS_ID_LEN);
		lb->stage_total = total;
		lb->staged = 0;
	}
	if (memcmp(lb->stage_id, id, FZN_BUCKETS_ID_LEN) != 0 || total != lb->stage_total
	    || offset != lb->staged || n > total - offset)
		return 0;
	memcpy(lb->staging + offset, bytes, n);
	lb->staged += n;
	return 1;
}

static fzn_node_apply_outcome_t item_finish(void *ctx, const uint8_t subject[FZN_PUBKEY_LEN],
                                            uint32_t month, const uint8_t id[FZN_BUCKETS_ID_LEN],
                                            uint64_t total)
{
	fzn_log_buckets_t *lb = (fzn_log_buckets_t *)ctx;
	uint8_t got[FZN_BUCKETS_ID_LEN];

	/* THE WHOLE, ITS ID'S: this module holds the bytes, so the check is
	 * here. */
	if (!lb || lb->staged != total || lb->stage_total != total
	    || memcmp(lb->stage_id, id, FZN_BUCKETS_ID_LEN) != 0
	    || !fzn_buckets_id(lb->hash, lb->staging, lb->staged, got)
	    || memcmp(got, id, FZN_BUCKETS_ID_LEN) != 0)
		return FZN_NODE_APPLY_REFUSED;
	lb->staged = 0;
	return keep(lb, subject, month, lb->staging, (size_t)total, id);
}

/* ---- wanted -------------------------------------------------------------------- */

/* WHETHER A MONTH IS HELD BY `rules`, judged at the month's end by what
 * does not depend on the program: the log policy, an age prune of every
 * program, and any keep -- an age keep within its age, a count or size
 * keep counted as covering, since only the segments themselves could say
 * it does not. Entry rules thin a segment and never remove it whole. */
static int month_held(const fzn_retain_rule_t *rules, size_t n, uint32_t month, uint64_t now_us)
{
	uint64_t end_us = fzn_message_epoch_start(month + 1u) * 1000u;
	uint64_t age = now_us > end_us ? now_us - end_us : 0u;
	int kept = 0, pruned = 0;
	size_t i;

	for (i = 0; i < n; i++) {
		const fzn_retain_rule_t *r = &rules[i];

		if (r->kind == FZN_RETAIN_POLICY || r->data != FZN_RETAIN_LOG
		    || fzn_retain_rule_selects_entries(r))
			continue;
		if (r->kind == FZN_RETAIN_KEEP)
			kept |= r->limit != FZN_RETAIN_AGE || age <= r->value;
		else if (r->limit == FZN_RETAIN_AGE && age > r->value && strcmp(r->program, "*") == 0)
			pruned = 1;
	}
	return kept || (!pruned && !fzn_retain_policy_drops(rules, n, FZN_RETAIN_LOG));
}

static int item_wanted(void *ctx, const uint8_t subject[FZN_PUBKEY_LEN], uint32_t month)
{
	static fzn_retain_rule_t source[FZN_RETAIN_RULES_MAX];
	fzn_log_buckets_t *lb = (fzn_log_buckets_t *)ctx;
	size_t n;

	if (!lb)
		return 1;
	if (memcmp(subject, lb->self, 32u) == 0)
		return month_held(lb->own_rules, lb->own_rules ? lb->n_own : 0u, month, lb->now_us);
	if (!lb->copy_rules || lb->n_copy > FZN_RETAIN_RULES_MAX)
		return month_held(NULL, 0u, month, lb->now_us);
	n = fzn_retain_select_source(lb->copy_rules, lb->n_copy, subject, source);
	return month_held(source, n, month, lb->now_us);
}

void fzn_log_buckets_filer(fzn_log_buckets_t *lb, fzn_reconcile_filer_t *out)
{
	if (!out)
		return;
	memset(out, 0, sizeof(*out));
	out->file = item_file;
	out->wanted = item_wanted;
	out->ctx = lb;
	out->stage = item_stage;
	out->finish = item_finish;
	out->read = item_read;
}
