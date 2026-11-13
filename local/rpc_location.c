#include "rpc_location.h"

#include "../location/location.h"

/*
 * A fix's accuracy and bearing, as fuzznet codes them (`location/location.c`,
 * compiled into this build through its manifest). These were this tree's own
 * until 2026-11-09, a copy that agreed with fuzznet's on every value when
 * compared over the whole range; the codec of a location fix is fuzznet's, as
 * the wire is. The names stay for the clients that call them.
 */
_Static_assert(FZN_RPC_LOCATION_ACC_UNKNOWN == FZN_LOCATION_ACC_UNKNOWN, "one unknown");

uint8_t fzn_rpc_location_acc_encode(uint32_t metres) {
	return fzn_location_acc_encode(metres);
}

uint32_t fzn_rpc_location_acc_decode(uint8_t code) {
	return fzn_location_acc_decode(code);
}

uint8_t fzn_rpc_location_bearing_encode(uint16_t degrees) {
	return fzn_location_bearing_encode(degrees);
}

uint16_t fzn_rpc_location_bearing_decode(uint8_t code) {
	return fzn_location_bearing_decode(code);
}
