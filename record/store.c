#include "store.h"

/* Diagnostics through flog, vendored and possibly absent. sec 209. */
#ifdef FZN_FLOG_ON
#include "flog.h"
#define RSTORE_LOG(st, sub, sev, ...)                                                      \
	do {                                                                               \
		if ((st) && (st)->log)                                                     \
			flog_printf((st)->log, sub, sev, FLOG_MSG_NONE, __VA_ARGS__);       \
	} while (0)
#else
#define RSTORE_LOG(st, sub, sev, ...) ((void)0)
#endif

#include <string.h>

void fzn_record_store_set_log(fzn_record_store_t *store, struct flog_t *log)
{
	if (!store)
		return;

	store->log = log;
}

fzn_record_store_err_t fzn_record_store_init(fzn_record_store_t *store,
                                             const fzn_record_store_ops_t *ops)
{
	if (!store || !ops || !ops->put || !ops->get)
		return FZN_RECORD_STORE_ERR_MALFORMED;

	store->ops = ops;
	/* Quiet unless somebody asks. */
	store->log = NULL;
	return FZN_RECORD_STORE_OK;
}

fzn_record_store_err_t fzn_record_store_put(fzn_record_store_t *store, fzn_record_t record)
{
	if (!store || !store->ops)
		return FZN_RECORD_STORE_ERR_MALFORMED;
	/* A view that was never opened has no accessors to read an address
	 * from, so this is refused before any of them is called rather than
	 * being allowed to read whatever `base` points at. */
	if (!fzn_record_is_open(record))
		return FZN_RECORD_STORE_ERR_MALFORMED;

	/* THE ADDRESS COMES OUT OF THE RECORD. There is no argument to pass a
	 * wrong one in, which is the whole of why a caller cannot misfile. */
	if (!store->ops->put(store->ops->ctx, fzn_record_issuer(record),
	                     fzn_record_stream(record), fzn_record_seq(record),
	                     record.base, record.len))
		return FZN_RECORD_STORE_ERR_BACKEND;
	return FZN_RECORD_STORE_OK;
}

fzn_record_store_err_t fzn_record_store_get(fzn_record_store_t *store,
                                            const uint8_t issuer[FZN_PUBKEY_LEN],
                                            uint32_t stream, uint64_t seq,
                                            uint8_t *out, size_t cap,
                                            fzn_record_t *record_out)
{
	size_t len = 0;
	int found = 0;
	fzn_record_t record;

	if (!store || !store->ops || !issuer || !out || !record_out)
		return FZN_RECORD_STORE_ERR_MALFORMED;
	/* A sequence of zero is one `fzn_record_open` refuses to produce, so
	 * nothing can be filed there and asking is a caller's confusion rather
	 * than a miss. Refused rather than answered ABSENT, which would read as
	 * "not fetched yet" and be waited on for ever. */
	if (seq == 0u)
		return FZN_RECORD_STORE_ERR_MALFORMED;

	if (!store->ops->get(store->ops->ctx, issuer, stream, seq, out, cap, &len, &found))
		return found ? FZN_RECORD_STORE_ERR_BACKEND : FZN_RECORD_STORE_ERR_ABSENT;

	if (fzn_record_open(out, len, &record) != FZN_RECORD_OK)
		return FZN_RECORD_STORE_ERR_SHAPE;

	/* PLACEMENT, CHECKED AGAINST THE BYTES RATHER THAN TRUSTED. Three
	 * integer comparisons, before any signature -- and a misplaced record
	 * may be perfectly well signed, which is why a signature check further
	 * up would not have caught this. */
	if (memcmp(fzn_record_issuer(record), issuer, FZN_PUBKEY_LEN) != 0
	    || fzn_record_stream(record) != stream || fzn_record_seq(record) != seq) {
		/* A STORAGE-INTEGRITY FAULT, NOT A PROTOCOL ONE. The record may
		 * be perfectly well signed -- which is why a signature check
		 * further up would not have caught it -- and this is the only
		 * layer that can see that what came back is not what was asked
		 * for. */
		RSTORE_LOG(store, "record/store", FLOG_ERR,
		           "backend returned a record that is not the one asked for: "
		           "wanted stream %lu seq %llu, got stream %lu seq %llu",
		           (unsigned long)stream, (unsigned long long)seq,
		           (unsigned long)fzn_record_stream(record),
		           (unsigned long long)fzn_record_seq(record));
		return FZN_RECORD_STORE_ERR_MISPLACED;
	}

	*record_out = record;
	return FZN_RECORD_STORE_OK;
}

const char *fzn_record_store_err_str(fzn_record_store_err_t err)
{
	switch (err) {
	case FZN_RECORD_STORE_OK:
		return "ok";
	case FZN_RECORD_STORE_ERR_MALFORMED:
		return "malformed";
	case FZN_RECORD_STORE_ERR_ABSENT:
		return "not held";
	case FZN_RECORD_STORE_ERR_BACKEND:
		return "backend refused";
	case FZN_RECORD_STORE_ERR_SHAPE:
		return "not a record";
	case FZN_RECORD_STORE_ERR_MISPLACED:
		return "filed under another address";
	}
	return "unknown";
}
