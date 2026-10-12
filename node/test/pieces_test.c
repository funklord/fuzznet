/* Tests for node/pieces.c: an item cut into erasure-coded pieces on disk,
 * and rebuilt from any k of them that hash to its id. sec 595. */

#include "../pieces.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int failures;
static int checks;

#define CHECK(cond, what)                                                                      \
	do {                                                                                   \
		checks++;                                                                      \
		if (!(cond)) {                                                                 \
			failures++;                                                            \
			fprintf(stderr, "  FAIL pieces_test.c:%d: %s\n", __LINE__, what);       \
		}                                                                              \
	} while (0)

static int mix_hash(void *ctx, uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len)
{
	uint64_t h = 0x84222325cbf29ce4ull;
	size_t i;

	(void)ctx;
	for (i = 0; i < in_len; i++)
		h = (h ^ in[i]) * 0x100000001b3ull;
	for (i = 0; i < out_len; i++) {
		h = (h ^ (uint64_t)i) * 0x100000001b3ull;
		out[i] = (uint8_t)(h >> 40);
	}
	return 1;
}

static const fzn_hash_ops_t HASH = { mix_hash, NULL };
static char dir[64];
static uint8_t item[10000], back[10000];

/* Piece `index`'s path. */
static void path_of(char *out, size_t cap, const uint8_t id[FZN_BUCKETS_ID_LEN], unsigned index)
{
	static const char H[] = "0123456789abcdef";
	char hex[65];
	size_t i;

	for (i = 0; i < 32u; i++) {
		hex[2u * i] = H[id[i] >> 4];
		hex[2u * i + 1u] = H[id[i] & 15u];
	}
	hex[64] = '\0';
	snprintf(out, cap, "%s/%s.%u.piece", dir, hex, index);
}

/* One byte of piece `index` flipped, past its head. */
static int flip(const uint8_t id[FZN_BUCKETS_ID_LEN], unsigned index)
{
	char path[200];
	FILE *f;
	int c;

	path_of(path, sizeof(path), id, index);
	f = fopen(path, "r+b");
	if (!f || fseek(f, (long)FZN_PIECE_HEAD_LEN + 7L, SEEK_SET) != 0 || (c = fgetc(f)) == EOF
	    || fseek(f, (long)FZN_PIECE_HEAD_LEN + 7L, SEEK_SET) != 0 || fputc(c ^ 0x21, f) == EOF) {
		if (f)
			(void)fclose(f);
		return 0;
	}
	return fclose(f) == 0;
}

int main(void)
{
	uint8_t id[FZN_BUCKETS_ID_LEN];
	uint8_t host[32], keepers[32][32];
	const uint8_t (*to)[32] = (const uint8_t (*)[32])keepers;
	char path[200];
	size_t written = 0, len = 0, i;
	uint32_t mask = 0, used = 0;
	uint32_t x = 12345u;

	snprintf(dir, sizeof(dir), "/tmp/fzn-pieces-test-%ld", (long)getpid());
	for (i = 0; i < sizeof(item); i++) {
		x ^= x << 13;
		x ^= x >> 17;
		x ^= x << 5;
		item[i] = (uint8_t)x;
	}
	CHECK(fzn_buckets_id(&HASH, item, sizeof(item), id), "fixture: the item's id");
	memset(host, 0x5a, sizeof(host));
	for (i = 0; i < 32u; i++)
		memset(keepers[i], (int)(0x80u + i), 32u);

	CHECK(fzn_pieces_cut(dir, 1u, id, host, to, item, sizeof(item), 4u, 2u, &written)
	                  == FZN_PIECES_OK
	              && written == 6u && fzn_pieces_held(dir, id, &mask) == FZN_PIECES_OK
	              && mask == 0x3fu,
	      "an item was not cut into six pieces, each on disk under its name");
	CHECK(fzn_pieces_rebuild(dir, 1u, id, &HASH, back, sizeof(back), &len, &used)
	                      == FZN_PIECES_OK
	              && len == sizeof(item) && memcmp(back, item, len) == 0 && used == 0x0fu,
	      "all six held, the item was not rebuilt from the four data pieces");

	/* A DATA PIECE WRONG: another four rebuild it. */
	CHECK(flip(id, 1u)
	              && fzn_pieces_rebuild(dir, 1u, id, &HASH, back, sizeof(back), &len, &used)
	                         == FZN_PIECES_OK
	              && memcmp(back, item, len) == 0 && !(used & 0x02u),
	      "with piece 1 wrong, no other four rebuilt the item, or piece 1 was used");
	path_of(path, sizeof(path), id, 0u);
	CHECK(remove(path) == 0, "fixture: piece 0 gone");
	path_of(path, sizeof(path), id, 4u);
	CHECK(remove(path) == 0
	              && fzn_pieces_rebuild(dir, 1u, id, &HASH, back, sizeof(back), &len, &used)
	                         == FZN_PIECES_ERR_NO_MATCH,
	      "four held, one of them wrong, was not said to rebuild to nothing");

	/* A HEAD OF ANOTHER KIND is not the item's piece. */
	CHECK(fzn_pieces_rebuild(dir, 0u, id, &HASH, back, sizeof(back), &len, &used)
	              == FZN_PIECES_ERR_TOO_FEW,
	      "pieces of another kind were taken");
	path_of(path, sizeof(path), id, 5u);
	CHECK(remove(path) == 0
	              && fzn_pieces_rebuild(dir, 1u, id, &HASH, back, sizeof(back), &len, &used)
	                         == FZN_PIECES_ERR_TOO_FEW,
	      "three held rebuilt, or were not said too few");

	CHECK(fzn_pieces_cut(dir, 1u, id, host, to, item, 0u, 4u, 2u, &written)
	                  == FZN_PIECES_ERR_MALFORMED
	              && fzn_pieces_cut(dir, 1u, id, host, to, item, sizeof(item), 30u, 3u, &written)
	                         == FZN_PIECES_ERR_MALFORMED
	              && fzn_pieces_cut(dir, 9u, id, host, to, item, sizeof(item), 4u, 2u, &written)
	                         == FZN_PIECES_ERR_MALFORMED,
	      "an empty item, too many pieces, or a kind past the last was cut");
	CHECK(fzn_pieces_cut(dir, 2u, id, host, to, item, sizeof(item), 4u, 2u, &written)
	              == FZN_PIECES_ERR_MALFORMED,
	      "pieces were cut into pieces again");

	/* UNDER A DIRECTORY NOT MADE YET, sec 597: a host that never archived
	 * has no archive to keep `pieces/` in, and both are made. */
	{
		char nested[200], above[200], name[300];
		unsigned at;

		snprintf(above, sizeof(above), "%s/archive", dir);
		snprintf(nested, sizeof(nested), "%s/archive/pieces", dir);
		CHECK(fzn_pieces_cut(nested, 1u, id, host, to, item, sizeof(item), 1u, 1u,
		                     &written)
		                  == FZN_PIECES_OK
		          && written == 2u,
		      "pieces were not cut under an archive not made yet");
		for (at = 0; at < 2u; at++) {
			char hex[65];

			for (i = 0; i < 32u; i++)
				snprintf(hex + 2u * i, 3u, "%02x", id[i]);
			snprintf(name, sizeof(name), "%s/%s.%u.piece", nested, hex, at);
			CHECK(remove(name) == 0, "a piece cut under a new archive is not under its name");
		}
		CHECK(rmdir(nested) == 0 && rmdir(above) == 0,
		      "the archive and its pieces were not made, or held something else");
	}

	for (i = 0; i < 6u; i++) {
		path_of(path, sizeof(path), id, (unsigned)i);
		(void)remove(path);
	}
	CHECK(rmdir(dir) == 0, "the scratch directory held something else, or would not go");
	if (failures) {
		fprintf(stderr, "pieces_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("pieces_test: all %d checks passed\n", checks);
	return 0;
}
