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

#define _GNU_SOURCE
#include "rpc_discover.h"
#include <ifaddrs.h>
#include <string.h>
#include <rpc/xdr.h>
#include <rpc/rpc_msg.h>
#include <rpc/pmap_prot.h>
#include <assert.h>

int sr_rpc_create_broadcast_socket(sa_family_t family)
{
	int one = 1;
	int udp_socket;

	if ((family != AF_INET) && (family != AF_INET6))
		return -1;

	udp_socket = socket(family, SOCK_DGRAM, 0);
	if (udp_socket < 0) {
		return -1;
	}

	setsockopt(udp_socket, SOL_SOCKET, SO_BROADCAST, &one, sizeof(one));

	if (family == AF_INET) {
		setsockopt(udp_socket, IPPROTO_IP, IP_PKTINFO,
			   &one, sizeof(one));
	}

	return udp_socket;
}

void sr_rpc_send_broadcast_ipv4(int sockfd, struct iovec* io,
		const struct ifaddrs *ifp, short port)
{
	struct sockaddr_in* srcaddr = (struct sockaddr_in*)ifp->ifa_addr;
	struct sockaddr_in* broadaddr = (struct sockaddr_in*)ifp->ifa_broadaddr;
	struct sockaddr_in* netmask = (struct sockaddr_in*)ifp->ifa_netmask;
	struct sockaddr_in destaddr;
	struct msghdr msgh;
	struct cmsghdr *cmsg;
	size_t ctlbuf[128];
	struct in_pktinfo* pktinfo;

	memset(&destaddr, 0, sizeof(destaddr));
	memset(&msgh, 0, sizeof(msgh));
	memset(ctlbuf, 0, sizeof(ctlbuf));

	msgh.msg_name = &destaddr;
	msgh.msg_namelen = sizeof(destaddr);
	msgh.msg_iov = io;
	msgh.msg_iovlen = 1;
	msgh.msg_control = ctlbuf;
	msgh.msg_controllen = sizeof(ctlbuf);

	cmsg = CMSG_FIRSTHDR(&msgh);
	cmsg->cmsg_len = CMSG_LEN(sizeof(*pktinfo));
	cmsg->cmsg_level = IPPROTO_IP;
	cmsg->cmsg_type = IP_PKTINFO;
	msgh.msg_controllen = CMSG_SPACE(sizeof(*pktinfo));


	/* Set destination, calculate directed broadcast address from
	* addr/netmask if necessary.
	*/
	if (srcaddr->sin_addr.s_addr == broadaddr->sin_addr.s_addr) {
		destaddr.sin_addr.s_addr = srcaddr->sin_addr.s_addr |
			(~netmask->sin_addr.s_addr);
	} else {
		destaddr.sin_addr.s_addr = broadaddr->sin_addr.s_addr;
	}
	destaddr.sin_family = AF_INET;
	destaddr.sin_port = htons(port);

	/* Set source */
	pktinfo = (struct in_pktinfo*) CMSG_DATA(cmsg);
	memcpy(&pktinfo->ipi_spec_dst.s_addr, &srcaddr->sin_addr, sizeof(srcaddr->sin_addr));

	sendmsg(sockfd, &msgh, 0);
}

void sr_rpc_send_multicast_ipv6(int sockfd, struct iovec* io,
		const struct ifaddrs *ifp, short port,
		const struct in6_addr* addr)
{
	struct sockaddr_in6* srcaddr = (struct sockaddr_in6*)ifp->ifa_addr;
	struct sockaddr_in6 destaddr;
	struct msghdr msgh;
	struct cmsghdr *cmsg;
	size_t ctlbuf[128];
	struct in6_pktinfo* pktinfo;

	memset(&destaddr, 0, sizeof(destaddr));
	memset(&msgh, 0, sizeof(msgh));
	memset(ctlbuf, 0, sizeof(ctlbuf));

	msgh.msg_name = &destaddr;
	msgh.msg_namelen = sizeof(destaddr);
	msgh.msg_iov = io;
	msgh.msg_iovlen = 1;
	msgh.msg_control = ctlbuf;
	msgh.msg_controllen = sizeof(ctlbuf);

	cmsg = CMSG_FIRSTHDR(&msgh);
	cmsg->cmsg_len = CMSG_LEN(sizeof(*pktinfo));
	cmsg->cmsg_level = IPPROTO_IPV6;
	cmsg->cmsg_type = IPV6_PKTINFO;
	msgh.msg_controllen = CMSG_SPACE(sizeof(*pktinfo));

	/* Set destination */
	destaddr.sin6_family = AF_INET6;
	destaddr.sin6_port = htons(port);
	memcpy(&destaddr.sin6_addr, addr, sizeof(destaddr.sin6_addr));

	/* Set source */
	pktinfo = (struct in6_pktinfo*) CMSG_DATA(cmsg);
	memcpy(&pktinfo->ipi6_addr, &srcaddr->sin6_addr, sizeof(srcaddr->sin6_addr));
	if (srcaddr->sin6_scope_id)
		pktinfo->ipi6_ifindex = srcaddr->sin6_scope_id;

	sendmsg(sockfd, &msgh, 0);
}

void sr_rpc_fill_getport_msg(char* buf, size_t* len, uint32_t prog,
		uint32_t version, uint32_t proto)
{
	XDR xdr;
	xdrmem_create(&xdr, buf, *len, XDR_ENCODE);

	static uint32_t xid = 0; // random number
	uint32_t dummy = 0;
	xid++;

	struct call_body callb = {
		2, // RPC version
		PMAPPROG,
		PMAPVERS,
		PMAPPROC_GETPORT,
		_null_auth,
		_null_auth,
	};
	struct rpc_msg msg = {
		xid,
		CALL,
		{ callb },
	};

	assert(xdr_getpos(&xdr) == 0);
	// push message header and call body
	xdr_callmsg(&xdr, &msg);
	assert(xdr_getpos(&xdr) == 4*10);

	// push GETPORT parameters
	xdr_u_int(&xdr, &prog);
	xdr_u_int(&xdr, &version);
	xdr_u_int(&xdr, &proto);
	xdr_u_int(&xdr, &dummy);

	assert(xdr_getpos(&xdr) == 4*14);
	*len = xdr_getpos(&xdr);
}

short sr_rpc_parse_getport_response(char* buf, size_t len)
{
	XDR xdr;
	struct rpc_msg msg;
	int port;

	xdrmem_create(&xdr, buf, len, XDR_DECODE);

	msg.acpted_rply.ar_results.where = 0;
	msg.acpted_rply.ar_results.proc = (xdrproc_t)(xdr_void);
	// pull message header
	xdr_replymsg(&xdr, &msg);

	if (msg.rm_direction != REPLY)
		return 0;
	if (msg.rm_reply.rp_stat != MSG_ACCEPTED)
		return 0;

	xdr_int(&xdr, &port);

	return (short)(port);
}

