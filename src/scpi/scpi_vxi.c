/*
 * This file is part of the libsigrok project.
 *
 * Copyright (C) 2014 Aurelien Jacobs <aurel@gnuage.org>
 *
 * Inspired by the VXI11 Ethernet Protocol for Linux:
 * http://optics.eee.nottingham.ac.uk/vxi11/
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
#include <config.h>
#include "vxi.h"
#include <rpc/rpc.h>
#include <string.h>
#include <libsigrok/libsigrok.h>
#include "libsigrok-internal.h"
#include "scpi.h"
#include "rpc_discover.h"
#include <arpa/inet.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <unistd.h>

#define LOG_PREFIX "scpi_vxi"
#define VXI_DEFAULT_TIMEOUT_MS 2000

/* from RPC specification (RFC1832) */
#define RPC_PROTO_TCP 6
#define PMAPPORT 111

struct scpi_vxi {
	char *address;
	char *instrument;
	CLIENT *client;
	Device_Link link;
	unsigned int max_send_size;
	unsigned int read_complete;
};

static GSList *scpi_vxi_scan(struct drv_context *drvc)
{
	int udp_socket_v4, udp_socket_v6, lastfd;
	struct in6_addr rpc_mc_addr;
	struct ifaddrs *ifap, *ifp;
	GSList *resources = NULL;
	char *res;
	char buf[200];
	size_t len = sizeof(buf);
	struct timeval timeout = { 1, 0 };
	fd_set fds;

	sr_dbg("Start VXI-11 broadcast discovery");

	if (getifaddrs(&ifap) != 0)
		return NULL;

	udp_socket_v4 = sr_rpc_create_broadcast_socket(AF_INET);
	if (udp_socket_v4 < 0)
		sr_err("Could not create IPv4 UDP broadcast socket");

	udp_socket_v6 = sr_rpc_create_broadcast_socket(AF_INET6);
	if (udp_socket_v6 < 0)
		sr_err("Could not create IPv6 UDP broadcast socket");

	sr_rpc_fill_getport_msg(buf, &len, DEVICE_CORE,
		DEVICE_CORE_VERSION, RPC_PROTO_TCP);

	inet_pton(AF_INET6, "FF02::202", &rpc_mc_addr);

	for (ifp = ifap; ifp; ifp = ifp->ifa_next) {
		struct iovec io;

		if ((ifp->ifa_flags & (IFF_MULTICAST | IFF_BROADCAST)) == 0)
			continue;

		io.iov_base = &buf;
		io.iov_len = len;

		if (ifp->ifa_addr->sa_family == AF_INET)
			sr_rpc_send_broadcast_ipv4(udp_socket_v4, &io,
				ifp, PMAPPORT);
		else if (ifp->ifa_addr->sa_family == AF_INET6)
			sr_rpc_send_multicast_ipv6(udp_socket_v6, &io,
				ifp, PMAPPORT, &rpc_mc_addr);
	}
	freeifaddrs(ifap);

	FD_ZERO(&fds);
	FD_SET(udp_socket_v4, &fds);
	FD_SET(udp_socket_v6, &fds);
	lastfd = udp_socket_v4 > udp_socket_v6 ?
		 udp_socket_v4 : udp_socket_v6;

	while (1) {
		struct sockaddr_storage address;
		struct msghdr msgh;
		struct iovec io;
		size_t ctlbuf[128];
		char addrbuf[INET6_ADDRSTRLEN];

		if (select(lastfd + 1, &fds, 0, 0, &timeout) == 0)
			break;

		if (!FD_ISSET(udp_socket_v4, &fds) && !FD_ISSET(udp_socket_v6, &fds))
			continue;

		io.iov_base = &buf;
		io.iov_len = sizeof(buf);

		memset(&msgh, 0, sizeof(msgh));
		msgh.msg_name = &address;
		msgh.msg_namelen = sizeof(address);
		msgh.msg_iov = &io;
		msgh.msg_iovlen = 1;
		msgh.msg_control = ctlbuf;
		msgh.msg_controllen = sizeof(ctlbuf);

		if (FD_ISSET(udp_socket_v4, &fds))
			len = recvmsg(udp_socket_v4, &msgh, 0);
		else if (FD_ISSET(udp_socket_v6, &fds))
			len = recvmsg(udp_socket_v6, &msgh, 0);

		if (sr_rpc_parse_getport_response(buf, len) == 0)
			continue;

		if (address.ss_family == AF_INET) {
			struct sockaddr_in* inaddr = (struct sockaddr_in*)(&address);
			if (inet_ntop(AF_INET, &inaddr->sin_addr, addrbuf, INET6_ADDRSTRLEN) == 0)
				continue;
		}
		if (address.ss_family == AF_INET6) {
			struct sockaddr_in6* in6addr = (struct sockaddr_in6*)(&address);
			if (inet_ntop(AF_INET6, &in6addr->sin6_addr, addrbuf, INET6_ADDRSTRLEN) == 0)
				continue;
		}

		res = g_strdup_printf("vxi/%s", addrbuf);
		resources = g_slist_append(resources, res);

		sr_dbg("Got VXI-11 response from %s", addrbuf);
	}

	sr_dbg("Found %d device(s).", g_slist_length(resources));

	close(udp_socket_v4);
	close(udp_socket_v6);

	return resources;
}

static int scpi_vxi_dev_inst_new(void *priv, struct drv_context *drvc,
		const char *resource, char **params, const char *serialcomm)
{
	struct scpi_vxi *vxi = priv;

	(void)drvc;
	(void)resource;
	(void)serialcomm;

	if (!params || !params[1]) {
		sr_err("Invalid parameters.");
		return SR_ERR;
	}

	vxi->address    = g_strdup(params[1]);
	vxi->instrument = g_strdup(params[2] ? params[2] : "inst0");

	return SR_OK;
}

static int scpi_vxi_open(struct sr_scpi_dev_inst *scpi)
{
	struct scpi_vxi *vxi = scpi->priv;
	Create_LinkParms link_parms;
	Create_LinkResp *link_resp;

	vxi->client = clnt_create(vxi->address, DEVICE_CORE, DEVICE_CORE_VERSION, "tcp");
	if (!vxi->client) {
		sr_err("Client creation failed for %s", vxi->address);
		return SR_ERR;
	}

	/* Set link parameters */
	link_parms.clientId = (long) vxi->client;
	link_parms.lockDevice = 0;
	link_parms.lock_timeout = VXI_DEFAULT_TIMEOUT_MS;
	link_parms.device = (char *)"inst0";

	if (!(link_resp = create_link_1(&link_parms, vxi->client))) {
		sr_err("Link creation failed for %s", vxi->address);
		return SR_ERR;
	}
	vxi->link = link_resp->lid;
	vxi->max_send_size = link_resp->maxRecvSize;

	/* Set a default maxRecvSize for devices which do not specify it */
	if (vxi->max_send_size <= 0)
		vxi->max_send_size = 4096;

	return SR_OK;
}

static int scpi_vxi_source_add(struct sr_session *session, void *priv,
		int events, int timeout, sr_receive_data_callback cb, void *cb_data)
{
	(void)priv;

	/* Hook up a dummy handler to receive data from the device. */
	return sr_session_source_add(session, -1, events, timeout, cb, cb_data);
}

static int scpi_vxi_source_remove(struct sr_session *session, void *priv)
{
	(void)priv;

	return sr_session_source_remove(session, -1);
}

/* Operation Flags */
#define DF_WAITLOCK  0x01  /* wait if the operation is locked by another link */
#define DF_END       0x08  /* an END indicator is sent with last byte of buffer */
#define DF_TERM      0x80  /* a termination char is set during a read */

static int scpi_vxi_send(void *priv, const char *command)
{
	struct scpi_vxi *vxi = priv;
	Device_WriteResp *write_resp;
	Device_WriteParms write_parms;
	unsigned long len;

	len = strlen(command);

	write_parms.lid           = vxi->link;
	write_parms.io_timeout    = VXI_DEFAULT_TIMEOUT_MS;
	write_parms.lock_timeout  = VXI_DEFAULT_TIMEOUT_MS;
	write_parms.flags         = DF_END;
	write_parms.data.data_len = MIN(len, vxi->max_send_size);
	write_parms.data.data_val = (char *)command;

	if (!(write_resp = device_write_1(&write_parms, vxi->client))
	    || write_resp->error) {
		sr_err("Device write failed for %s with error %ld",
		       vxi->address, write_resp ? write_resp->error : 0);
		return SR_ERR;
	}

	if (write_resp->size < len)
		sr_dbg("Only sent %lu/%lu bytes of SCPI command: '%s'.",
		       write_resp->size, len, command);
	else
		sr_spew("Successfully sent SCPI command: '%s'.", command);

	return SR_OK;
}

static int scpi_vxi_read_begin(void *priv)
{
	struct scpi_vxi *vxi = priv;

	vxi->read_complete = 0;

	return SR_OK;
}

/* Read Response Reason Flags */
#define RRR_SIZE  0x01  /* requestSize bytes have been transferred */
#define RRR_TERM  0x02  /* a termination char has been read */
#define RRR_END   0x04  /* an END indicator has been read */

static int scpi_vxi_read_data(void *priv, char *buf, int maxlen)
{
	struct scpi_vxi *vxi = priv;
	Device_ReadParms read_parms;
	Device_ReadResp *read_resp;

	read_parms.lid          = vxi->link;
	read_parms.io_timeout   = VXI_DEFAULT_TIMEOUT_MS;
	read_parms.lock_timeout = VXI_DEFAULT_TIMEOUT_MS;
	read_parms.flags        = 0;
	read_parms.termChar     = 0;
	read_parms.requestSize  = maxlen;

	if (!(read_resp = device_read_1(&read_parms, vxi->client))
	    || read_resp->error) {
		sr_err("Device read failed for %s with error %ld",
		       vxi->address, read_resp ? read_resp->error : 0);
		return SR_ERR;
	}

	memcpy(buf, read_resp->data.data_val, read_resp->data.data_len);
	vxi->read_complete = read_resp->reason & (RRR_TERM | RRR_END);
	return read_resp->data.data_len;  /* actual number of bytes received */
}

static int scpi_vxi_read_complete(void *priv)
{
	struct scpi_vxi *vxi = priv;

	return vxi->read_complete;
}

static int scpi_vxi_close(struct sr_scpi_dev_inst *scpi)
{
	struct scpi_vxi *vxi = scpi->priv;
	Device_Error *dev_error;

	if (!vxi->client)
		return SR_ERR;

	if (!(dev_error = destroy_link_1(&vxi->link, vxi->client))) {
		sr_err("Link destruction failed for %s", vxi->address);
		return SR_ERR;
	}

	clnt_destroy(vxi->client);
	vxi->client = NULL;

	return SR_OK;
}

static void scpi_vxi_free(void *priv)
{
	struct scpi_vxi *vxi = priv;

	g_free(vxi->address);
	g_free(vxi->instrument);
}

SR_PRIV const struct sr_scpi_dev_inst scpi_vxi_dev = {
	.name          = "VXI",
	.prefix        = "vxi",
	.priv_size     = sizeof(struct scpi_vxi),
	.scan          = scpi_vxi_scan,
	.dev_inst_new  = scpi_vxi_dev_inst_new,
	.open          = scpi_vxi_open,
	.source_add    = scpi_vxi_source_add,
	.source_remove = scpi_vxi_source_remove,
	.send          = scpi_vxi_send,
	.read_begin    = scpi_vxi_read_begin,
	.read_data     = scpi_vxi_read_data,
	.read_complete = scpi_vxi_read_complete,
	.close         = scpi_vxi_close,
	.free          = scpi_vxi_free,
};
