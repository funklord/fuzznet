#ifndef FZN_RPC_CLIENT_STICKER_READ_H
#define FZN_RPC_CLIENT_STICKER_READ_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "../sticker/pack.h"

/*
 * A spec read into storage these calls allocate. Core allocates nothing and
 * puts no limit on how many stickers a pack holds (the holder, 2026-10-23),
 * so its reader takes the caller's storage and says how much it needed when
 * that was not enough. This makes room and reads again, which is what every
 * client wants. Release with fzn_rpc_sticker_manifest_release, also after a
 * failure; a released or zeroed manifest may be released again.
 */
/* How much of a spec file the clients read: 1 MiB, some 7000 stickers of
 * LINE's kind, so a spec can never be what exhausts memory. Kept from the
 * clients' own sticker code when it was retired for fuzznet's, which has no
 * bound of its own for a caller's file. */
#define FZN_RPC_STICKER_SPEC_MAX (1024u * 1024u)

int fzn_rpc_sticker_spec_read(const char *text, size_t len, fzn_sticker_manifest_t *out, char *err,
                          size_t err_cap);
void fzn_rpc_sticker_manifest_release(fzn_sticker_manifest_t *m);
/* A manifest emptied and given `cap` entries of room at `entries` (which may
 * be NULL with cap 0): fuzznet's manifest has no initialiser of its own. */
void fzn_rpc_sticker_manifest_init(fzn_sticker_manifest_t *m, fzn_sticker_entry_t *entries, size_t cap);

#ifdef __cplusplus
}
#endif

#endif /* FZN_RPC_CLIENT_STICKER_READ_H */
