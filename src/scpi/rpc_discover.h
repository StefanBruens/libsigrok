/*
 * This file is part of the libsigrok project.
 *
 * Copyright (C) 2016 Stefan Brüns <stefan.bruens@rwth-aachen.de>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef LIBSIGROK_SCPI_RPC_DISCOVER_H
#define LIBSIGROK_SCPI_RPC_DISCOVER_H

#include <netinet/in.h>
#include <libsigrok/libsigrok.h>

SR_PRIV void sr_rpc_fill_getport_msg(char* buf, size_t* len,
		uint32_t prog, uint32_t version, uint32_t proto);
SR_PRIV short sr_rpc_parse_getport_response(char* buf, size_t len);

struct ifaddrs;
struct in6_addr;
SR_PRIV void sr_rpc_send_broadcast_ipv4(int sockfd, struct iovec* io,
		const struct ifaddrs *ifp, short port);
SR_PRIV void sr_rpc_send_multicast_ipv6(int sockfd, struct iovec* io,
		const struct ifaddrs *ifp, short port,
		const struct in6_addr* dest);
SR_PRIV int sr_rpc_create_broadcast_socket(sa_family_t family);

#endif /* LIBSIGROK_SCPI_RPC_DISCOVER_H */

