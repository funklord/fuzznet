/*
 * The own-address ranking (project.md sec 253): what both clients offer as
 * "your address", best first.
 */
#include "../own_address.h"

#include <stdio.h>
#include <string.h>

static int failures = 0;
#define CHECK(cond)                                                   \
	do {                                                              \
		if (!(cond)) {                                                \
			fprintf(stderr, "FAIL own_address_test.c:%d: %s\n", __LINE__, #cond); \
			failures++;                                               \
		}                                                             \
	} while (0)

static void test_the_ranking(void) {
	const fzn_iface_addr_t locals[] = {
		{"eth1", "169.254.226.3"},
		{"docker0", "172.17.0.1"},
		{"rmnet_data0", "100.64.3.9"},
		{"eth0", "10.0.0.3"},
		{"mystery0", "192.168.5.5"},
		{"wlan0", "10.0.0.107"},
	};
	static char out[8][FZN_OWN_ADDRESS_MAX + 1];
	size_t n = fzn_own_address_candidates(" me.example:4000 ", locals, 6, 48080, out, 8);
	/* The link-local address is last though its interface is named like
	 * Ethernet: it reaches only the same link. */
	const char *want[] = {"me.example:4000",   "10.0.0.3:48080",   "10.0.0.107:48080",
	                      "192.168.5.5:48080", "172.17.0.1:48080", "100.64.3.9:48080",
	                      "169.254.226.3:48080"};
	CHECK(n == 7);
	for (size_t i = 0; i < n && i < 7; i++) {
		if (strcmp(out[i], want[i]) != 0)
			fprintf(stderr, "  candidate %zu is %s, want %s\n", i, out[i], want[i]);
		CHECK(strcmp(out[i], want[i]) == 0);
	}
	/* No port, no interface guess -- only what was advertised. */
	CHECK(fzn_own_address_candidates(NULL, locals, 6, 0, out, 8) == 0);
	CHECK(fzn_own_address_candidates("a:1", locals, 6, 0, out, 8) == 1 && strcmp(out[0], "a:1") == 0);
	/* An advertised address that is also an interface's is listed once. */
	n = fzn_own_address_candidates("10.0.0.3:48080", locals, 6, 48080, out, 8);
	size_t seen = 0;
	for (size_t i = 0; i < n; i++) seen += strcmp(out[i], "10.0.0.3:48080") == 0;
	CHECK(seen == 1);
	/* And the cap holds. */
	CHECK(fzn_own_address_candidates(NULL, locals, 6, 48080, out, 2) == 2);
}

static void test_the_machine_answers(void) {
	/* Read the real interfaces: whatever they are, each must be a dotted
	 * IPv4 with a name, and loopback must not be among them. */
	fzn_iface_addr_t got[32];
	size_t n = fzn_local_ipv4_addresses(got, 32);
	for (size_t i = 0; i < n; i++) {
		CHECK(got[i].iface[0] != '\0');
		CHECK(strcmp(got[i].ip, "127.0.0.1") != 0);
		CHECK(strchr(got[i].ip, '.') != NULL);
	}
}

int main(void) {
	test_the_ranking();
	test_the_machine_answers();
	if (failures) {
		fprintf(stderr, "%d failure(s)\n", failures);
		return 1;
	}
	printf("own_address_test: all passed\n");
	return 0;
}
