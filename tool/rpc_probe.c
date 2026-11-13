/*
 * THE TYPED CLIENT AGAINST A RUNNING NODE, sec 1098: `rpc_probe SOCKET`.
 *
 * rpc_test checks fzn_rpc_ against the grammar the client believes; this
 * checks the belief. Each call is made to a fresh host's fuzznetd and must
 * come back FZN_RPC_OK with an answer that parsed -- a verb renamed, a field
 * added in the middle or a reply word changed on the daemon's side fails here
 * by the call's name. Run by `tool/live_rpc.py`, which starts the daemon.
 *
 * Exit 0 when every call read, 1 when one did not, 2 on usage.
 */
#include "../local/rpc.h"
#include "../local/rpc_err.h"

#include <stdio.h>
#include <string.h>

static fzn_rpc_t c;
static int failed, made;

static void said(const char *call, int rc)
{
	made++;
	if (rc == FZN_RPC_OK && !c.unreadable)
		return;
	failed++;
	fprintf(stderr, "rpc_probe: %s: %s (%d)\n", call, c.error, rc);
}

#define ASK(call, ...) said(#call, call(&c, __VA_ARGS__))

int main(int argc, char **argv)
{
	static fzn_rpc_status_resp_t status;
	static fzn_rpc_object_list_resp_t objects;
	static fzn_rpc_sync_load_t load;
	static fzn_rpc_peer_list_resp_t peers;
	static fzn_rpc_group_list_resp_t groups;
	static fzn_rpc_sibling_list_resp_t siblings;
	static fzn_rpc_peer_request_list_resp_t requests;
	static fzn_rpc_library_list_all_t library;
	static fzn_rpc_transfer_list_resp_t transfers;
	static fzn_rpc_delivery_list_resp_t deliveries;
	static fzn_rpc_relay_status_resp_t relay;
	static fzn_rpc_notes_shares_resp_t shares;
	static fzn_rpc_cap_list_resp_t caps;
	static fzn_rpc_cap_granted_resp_t granted;
	static fzn_rpc_prekey_show_resp_t prekey;
	static fzn_rpc_log_show_resp_t log;
	static fzn_rpc_link_list_resp_t legs;
	static fzn_rpc_location_status_resp_t location;
	static fzn_rpc_clock_list_t clocks;
	static fzn_rpc_clock_estate_t clock;
	static fzn_rpc_sticker_packs_t stickers;
	static fzn_rpc_config_schema_resp_t schema;
	static fzn_rpc_config_get_resp_t setting;
	static fzn_rpc_group_create_resp_t made_group;
	static fzn_rpc_object_t object;
	static fzn_rpc_unread_entry_t unread[8];
	size_t count = 0, total = 0, i;
	int found = 0;

	if (argc != 2) {
		fprintf(stderr, "usage: rpc_probe SOCKET\n");
		return 2;
	}
	fzn_rpc_init(&c);
	if (fzn_rpc_set_node_socket(&c, argv[1]) != 0) {
		fprintf(stderr, "rpc_probe: %s is no usable socket path\n", argv[1]);
		return 2;
	}

	/* WHAT A FRESH HOST HAS TO SAY, each read whole. */
	ASK(fzn_rpc_status, &status);
	ASK(fzn_rpc_object_list, &objects);
	ASK(fzn_rpc_sync_load, &load);
	ASK(fzn_rpc_peer_list, &peers);
	ASK(fzn_rpc_sibling_list, &siblings);
	ASK(fzn_rpc_peer_request_list, &requests);
	ASK(fzn_rpc_library_list, &library);
	ASK(fzn_rpc_transfer_list, &transfers);
	ASK(fzn_rpc_delivery_list, &deliveries);
	ASK(fzn_rpc_relay_status, &relay);
	ASK(fzn_rpc_notes_shares, &shares);
	ASK(fzn_rpc_cap_list, &caps);
	ASK(fzn_rpc_cap_granted, &granted);
	ASK(fzn_rpc_prekey_show, &prekey);
	ASK(fzn_rpc_log_show, &log);
	ASK(fzn_rpc_link_list, &legs);
	ASK(fzn_rpc_location_status, &location);
	ASK(fzn_rpc_clock_list, &clocks);
	ASK(fzn_rpc_clock_get, &clock);
	ASK(fzn_rpc_sticker_list, &stickers);
	/* EVERY SETTING THE NODE DECLARES, each row in the schema's words, and
	 * one read back with where it stands. */
	ASK(fzn_rpc_config_schema, "", 0, &schema);
	if (!schema.count) {
		failed++;
		fprintf(stderr, "rpc_probe: the node declared no settings\n");
	}
	ASK(fzn_rpc_config_get, "net.address", 11, &setting);

	/* AND WHAT IT IS GIVEN, read back: an object, a group, the unread. */
	ASK(fzn_rpc_object_add, "probe_lamp", "on off");
	ASK(fzn_rpc_object_set, "probe_lamp", "on");
	ASK(fzn_rpc_object_get, "probe_lamp", &object, &found);
	if (!found || (strcmp(object.value, "on") != 0 && !c.held)) {
		failed++;
		fprintf(stderr, "rpc_probe: the object set was not read back: found %d, value %s\n",
		        found, object.value);
	}
	ASK(fzn_rpc_group_create, "probe_crew", 10, &made_group);
	ASK(fzn_rpc_group_list, &groups);
	for (i = 0, found = 0; i < groups.count; i++)
		found |= groups.entries[i].name_len == 10
		         && memcmp(groups.entries[i].name, "probe_crew", 10) == 0;
	if (!found) {
		failed++;
		fprintf(stderr, "rpc_probe: the group made was not listed\n");
	}
	ASK(fzn_rpc_unread_all, unread, 8, &count, &total);

	if (failed) {
		fprintf(stderr, "rpc_probe: %d of %d calls did not read\n", failed, made);
		return 1;
	}
	printf("rpc_probe: %d calls, each answered and read\n", made);
	return 0;
}
