/* getifaddrs' interface flags (IFF_UP and the rest) are past C11's base,
 * which a strict build asks for. */
#define _DEFAULT_SOURCE

#include "own_address.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdlib.h>

/* Windows names an adapter by a GUID, so the kind it reports stands in for
 * the name the ranking below reads: wlan, eth, or what it is otherwise. */
size_t fzn_local_ipv4_addresses(fzn_iface_addr_t *out, size_t cap) {
	ULONG size = 16 * 1024;
	IP_ADAPTER_ADDRESSES *all = NULL;
	ULONG rc = ERROR_BUFFER_OVERFLOW;
	for (int tries = 0; tries < 3 && rc == ERROR_BUFFER_OVERFLOW; tries++) {
		free(all);
		all = malloc(size);
		if (!all) return 0;
		rc = GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST, NULL, all,
		                          &size);
	}
	size_t n = 0;
	if (!out || cap == 0 || rc != NO_ERROR) {
		free(all);
		return 0;
	}
	for (IP_ADAPTER_ADDRESSES *a = all; a && n < cap; a = a->Next) {
		if (a->OperStatus != IfOperStatusUp || a->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
		for (IP_ADAPTER_UNICAST_ADDRESS *u = a->FirstUnicastAddress; u && n < cap; u = u->Next) {
			if (u->Address.lpSockaddr->sa_family != AF_INET) continue;
			const struct sockaddr_in *in = (const struct sockaddr_in *)u->Address.lpSockaddr;
			if (!inet_ntop(AF_INET, &in->sin_addr, out[n].ip, sizeof out[n].ip)) continue;
			snprintf(out[n].iface, sizeof out[n].iface, "%s",
			         a->IfType == IF_TYPE_IEEE80211      ? "wlan"
			         : a->IfType == IF_TYPE_ETHERNET_CSMACD ? "eth"
			                                                 : "other");
			n++;
		}
	}
	free(all);
	return n;
}
#else
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>

size_t fzn_local_ipv4_addresses(fzn_iface_addr_t *out, size_t cap) {
	struct ifaddrs *all = NULL;
	if (!out || cap == 0 || getifaddrs(&all) != 0) return 0;
	size_t n = 0;
	for (struct ifaddrs *a = all; a && n < cap; a = a->ifa_next) {
		if (!a->ifa_addr || a->ifa_addr->sa_family != AF_INET || !a->ifa_name) continue;
		if (!(a->ifa_flags & IFF_UP) || !(a->ifa_flags & IFF_RUNNING) ||
		    (a->ifa_flags & IFF_LOOPBACK))
			continue;
		const struct sockaddr_in *in = (const struct sockaddr_in *)a->ifa_addr;
		if (!inet_ntop(AF_INET, &in->sin_addr, out[n].ip, sizeof out[n].ip)) continue;
		snprintf(out[n].iface, sizeof out[n].iface, "%s", a->ifa_name);
		n++;
	}
	freeifaddrs(all);
	return n;
}
#endif

static int starts_with(const char *s, const char *prefix) {
	return strncmp(s, prefix, strlen(prefix)) == 0;
}

/* 0 best, 3 worst. By name, because that is all every platform agrees on --
 * except a self-assigned link-local address (169.254/16), which is ranked
 * last whatever carries it: it reaches only the same link with no DHCP, which
 * a phone and a desktop almost never share, so it goes after even a bridge. */
static int rank_of(const char *iface, const char *ip) {
	if (starts_with(ip, "169.254.")) return 3;
	static const char *const remote[] = {"docker", "br-", "virbr", "veth", "lxc", "lxd", "tun",
	                                     "tap", "wg", "zt", "vmnet", "vboxnet", "utun", "rmnet",
	                                     "ccmni", "clat", "pdp", "dummy"};
	static const char *const physical[] = {"wlan", "wlp", "wl", "eth", "enp", "eno", "ens", "en"};
	for (size_t i = 0; i < sizeof remote / sizeof remote[0]; i++)
		if (starts_with(iface, remote[i])) return 2;
	for (size_t i = 0; i < sizeof physical / sizeof physical[0]; i++)
		if (starts_with(iface, physical[i])) return 0;
	return 1;
}

static int held(char out[][FZN_OWN_ADDRESS_MAX + 1], size_t n, const char *c) {
	for (size_t i = 0; i < n; i++)
		if (strcmp(out[i], c) == 0) return 1;
	return 0;
}

size_t fzn_own_address_candidates(const char *advertised, const fzn_iface_addr_t *locals,
                                  size_t n, uint16_t port,
                                  char out[][FZN_OWN_ADDRESS_MAX + 1], size_t cap) {
	size_t w = 0;
	if (!out || cap == 0) return 0;
	if (advertised) {
		/* As given, less surrounding whitespace. */
		while (isspace((unsigned char)*advertised)) advertised++;
		size_t len = strlen(advertised);
		while (len > 0 && isspace((unsigned char)advertised[len - 1])) len--;
		if (len > 0 && len <= FZN_OWN_ADDRESS_MAX) {
			memcpy(out[w], advertised, len);
			out[w][len] = '\0';
			w++;
		}
	}
	if (port == 0 || !locals) return w;
	for (int rank = 0; rank <= 3; rank++) {
		for (size_t i = 0; i < n && w < cap; i++) {
			if (rank_of(locals[i].iface, locals[i].ip) != rank) continue;
			char c[FZN_OWN_ADDRESS_MAX + 1];
			snprintf(c, sizeof c, "%s:%u", locals[i].ip, (unsigned)port);
			if (held(out, w, c)) continue;
			memcpy(out[w], c, strlen(c) + 1);
			w++;
		}
	}
	return w;
}
