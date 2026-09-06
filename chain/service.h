/* Service and product namespaces, carried inside a capability id.
 *
 * project.md sec 129. The copyright holder settled two things here: the
 * service namespace is MANDATORY in a capability, and a product identifier
 * gives an optional filter so that two consumers sharing one subsystem --
 * two projects both keeping logs -- can be told apart, with some entitled to
 * see only their own and some entitled to see everything.
 *
 * DERIVED, NOT STORED, AND THAT IS THE WHOLE MECHANISM. A capability id is
 * thirty-two opaque bytes and stays thirty-two opaque bytes; nothing on the
 * wire moves and `wire/generated/` is untouched. The service is mandatory
 * because the only way to obtain a capability id is through this function
 * and this function refuses to make one without a service -- so a capability
 * naming no service does not exist to be presented. `chain/authz.h` reaches
 * the same shape for origin and says it best: it cannot be forged because
 * there is no field.
 *
 * A verifier never reads the service back out, and does not need to. A
 * daemon for a service knows which service it is: it derives the capability
 * it requires and compares. That is strictly stronger than a readable field,
 * which could be read and then not checked.
 *
 * INTEGERS, NOT STRINGS, following `record/ledger.h` -- "fuzzypickles spells
 * it as a scope string; here it is an integer for the reason every key in
 * this library is". The consumer's own meaning goes in `name`, which is free
 * bytes and is where a verb belongs.
 *
 * WHY THE WILDCARD IS NOT ZERO. FZN_PRODUCT_ANY is 0xffffffff, and the
 * tempting encoding -- nought means all -- is refused on purpose: a caller
 * that forgets to set the field, or hands us a zeroed struct, would then be
 * asking for the widest scope there is. Zero is FZN_PRODUCT_NONE and is
 * refused, so the failure of an uninitialised product is a returned error
 * rather than a silent grant over every project's records.
 */
#ifndef FZN_SERVICE_H
#define FZN_SERVICE_H

#include "chain.h"
#include "../session/commitment.h"

#include <stddef.h>
#include <stdint.h>

/* Unspelled, and refused by every function here. Zero for the same reason
 * FZN_ORIGIN_NONE is zero: a zeroed structure must not mean anything a
 * caller would have had to ask for. */
#define FZN_SERVICE_NONE 0u
#define FZN_PRODUCT_NONE 0u

/* Every product, for a holder entitled to see across projects. Deliberately
 * not zero -- see the header comment. */
#define FZN_PRODUCT_ANY 0xffffffffu

/* The longest consumer-supplied name. Bounded so the derivation's input
 * buffer is a fixed size and the function allocates nothing, which is this
 * library's rule rather than this function's. */
#define FZN_SERVICE_NAME_MAX 64

/* Derive a capability id naming a service, a product and a consumer's own
 * name for what the capability permits.
 *
 * `service` must not be FZN_SERVICE_NONE. `product` must not be
 * FZN_PRODUCT_NONE and may be FZN_PRODUCT_ANY. `name` may be empty, in
 * which case `name_len` is zero and `name` may be null: a service with one
 * capability does not have to invent a word for it.
 *
 * THE ENCODING IS UNAMBIGUOUS BECAUSE THE VARIABLE FIELD IS LAST. Service
 * and product are four big-endian bytes each and the name follows, so no two
 * distinct triples produce the same input. If a field is ever added, it goes
 * BEFORE the name or it brings a length prefix with it; appending one after
 * a variable-length field is how two different capabilities come to hash the
 * same.
 *
 * A domain label is prepended here rather than by the caller, which is
 * `session/commitment.h`'s settled reason: a label the caller supplies is a
 * label the caller can forget, and forgetting it works perfectly until two
 * uses overlap.
 *
 * `out` is left untouched unless the derivation succeeds, so a caller that
 * ignores the return value presents a capability it did not build rather
 * than half of one.
 *
 * Returns FZN_CHAIN_ERR_MALFORMED for a null argument, an unspelled service
 * or product, or a name past FZN_SERVICE_NAME_MAX -- all caller bugs.
 * A refusing hash seam is reported as FZN_CHAIN_ERR_MALFORMED, which is
 * `chain/revocation.c`'s existing answer for the same event rather than a
 * new enum value invented here. */
fzn_chain_err_t fzn_service_capability(uint32_t service, uint32_t product,
                                       const uint8_t *name, size_t name_len,
                                       const fzn_hash_ops_t *hash,
                                       fzn_cap_id_t *out);

/* Derive both capabilities an access check needs: the one scoped to this
 * record's product, and the see-everything one.
 *
 * WHY THIS EXISTS RATHER THAN LEAVING THE CALLER TO CALL THE ABOVE TWICE.
 * The optional filter is two capabilities, not one, and a caller that checks
 * only the scoped one silently stops honouring every cross-project grant it
 * ever issued. That failure is quiet and closed -- nobody is let in who
 * should not be, so no test written against a scoped holder can see it --
 * which is exactly the shape this tree keeps paying for. Deriving the pair
 * in one call makes the second one hard to leave out.
 *
 * `product` here is the RECORD'S product and must be a real one:
 * FZN_PRODUCT_ANY is refused, because a record does not belong to every
 * project and a check that passes ANY as the subject is asking the wrong
 * question.
 *
 * A holder is permitted when the chain authorises EITHER. */
fzn_chain_err_t fzn_service_capability_pair(uint32_t service, uint32_t product,
                                            const uint8_t *name, size_t name_len,
                                            const fzn_hash_ops_t *hash,
                                            fzn_cap_id_t *scoped_out,
                                            fzn_cap_id_t *any_out);

#endif
