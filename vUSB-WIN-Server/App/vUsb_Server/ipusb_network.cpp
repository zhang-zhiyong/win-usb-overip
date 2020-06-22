/*
 * Copyright (C) 2013 Daniel Danzberger <ipusb@dd-wrt.com>
 *               2005-2007 Takahiro Hirofuchi
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#define WINVER 0x0501
#include "ipusb.h"
//char err_buf[256];
static int connect_timo(SOCKET sockfd,
                struct sockaddr *addr,
                size_t addrlen,
                int timo);

void pack_uint32_t(int pack, uint32_t *num)
{
	uint32_t i;

	if (pack)
		i = htonl(*num);
	else
		i = ntohl(*num);

	*num = i;
}

void pack_uint16_t(int pack, uint16_t *num)
{
	uint16_t i;

	if (pack)
		i = htons(*num);
	else
		i = ntohs(*num);

	*num = i;
}

void pack_usb_device(int pack, struct usb_device *udev)
{
	pack_uint32_t(pack, &udev->busnum);
	pack_uint32_t(pack, &udev->devnum);
	pack_uint32_t(pack, &udev->speed );

	pack_uint16_t(pack, &udev->idVendor );
	pack_uint16_t(pack, &udev->idProduct);
	pack_uint16_t(pack, &udev->bcdDevice);
}

void pack_usb_interface(int pack, struct usb_interface *udev)
{
	/* uint8_t members need nothing */
}

void ipusb_dump_buffer(unsigned char *buff, int bufflen)
{
	int i,j;
	char linebuf[80];
	int pos=0;

	for (i = 0; i < bufflen; i += 16) {
		pos += sprintf(linebuf + pos, "%8i: ", i);
		for (j = i; j < i + 16; j++) {
			if (j < bufflen)
				pos+=sprintf(linebuf +pos,
						"%02X ",
						(int)(buff)[j]
						);
			else
				pos+=sprintf(linebuf + pos,"   ");
		}
		for (j = i; j < i + 16; j++) {
			if (j < bufflen)
				pos += sprintf(linebuf + pos,
						"%c",
						(buff[j] >= 32 && buff[j] < 128)
						? ((char*)buff)[j] : '.'
						);
			else
				pos += sprintf(linebuf + pos, " ");
		}
		pos += sprintf(linebuf + pos, "\n");
		dbg_file("%s", linebuf);
//		printk(KERN_DEBUG "%s",linebuf);
		pos = 0;
	}

}

static ssize_t ipusb_xmit(int sockfd, void *buff, size_t bufflen, int sending)
{
	ssize_t total = 0;
#ifdef DEBUG
	void * orgbuf=buff;
#endif

	if (!bufflen)
		return 0;

	dbg_file("do %d: len:%d\n", sending, bufflen);

	do {
		ssize_t nbytes;

		if (sending) {
                        nbytes = ::send(sockfd, (const char *)buff, bufflen, 0);
		}
		else {
                        nbytes = ::recv(sockfd, (char *)buff, bufflen, 0);
			dbg_file("Number of bytes received from socket"
				"synchronously: %d\n",nbytes);
		}

		if (nbytes <= 0)
			return -1;

		buff	= (void *)((char *)buff + nbytes);
		bufflen	-= nbytes;
		total	+= nbytes;

	} while (bufflen > 0);

#ifdef DEBUG
	ipusb_dump_buffer(orgbuf,total);
#endif
//	dbg_file("do %d: len:%d finish\n", sending, bufflen);

	return total;
}

ssize_t ipusb_recv(int sockfd, void *buff, size_t bufflen)
{
	return ipusb_xmit(sockfd, buff, bufflen, 0);
}

ssize_t ipusb_send(int sockfd, void *buff, size_t bufflen)
{
	return ipusb_xmit(sockfd, buff, bufflen, 1);
}

int ipusb_send_op_common(int sockfd, uint32_t code, uint32_t status)
{
	int ret;
	struct op_common op_common;

	memset(&op_common, 0, sizeof(op_common));

	op_common.version	= IPUSB_VERSION;
	op_common.code		= code;
	op_common.status	= status;

	PACK_OP_COMMON(1, &op_common);

	ret = ipusb_send(sockfd, (void *) &op_common, sizeof(op_common));
	if (ret < 0) {
		printf("send op_common");
		return -1;
	}

	return 0;
}

int ipusb_recv_op_common(int sockfd, uint16_t *code)
{
	int ret;
	struct op_common op_common;

	memset(&op_common, 0, sizeof(op_common));

	ret = ipusb_recv(sockfd, (void *) &op_common, sizeof(op_common));
	if (ret < 0) {
		printf("recv op_common, %d", ret);
		goto err;
	}

	PACK_OP_COMMON(0, &op_common);

	if (op_common.version != IPUSB_VERSION) {
		printf("version mismatch, %d %d", 
			op_common.version, IPUSB_VERSION);
		goto err;
	}

	switch(*code) {
		case OP_UNSPEC:
			break;
		default:
			if (op_common.code != *code) {
				info("unexpected pdu %d for %d", 
					op_common.code, *code);
				goto err;
			}
	}

	if (op_common.status != ST_OK) {
		info("request failed at peer, %d", op_common.status);
		goto err;
	}

	*code = op_common.code;

	return 0;
err:
	return -1;
}


int ipusb_set_reuseaddr(int sockfd)
{
	const int val = 1;
	int ret;

	ret = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, 
			(const char *)&val, sizeof(val));
	if (ret)
		printf("setsockopt SO_REUSEADDR");

	return ret;
}

int ipusb_set_nodelay(int sockfd)
{
	const int val = 1;
	int ret;

	ret = setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, 
			(const char *)&val, sizeof(val));
	if (ret)
		printf("setsockopt TCP_NODELAY");

	return ret;
}

int ipusb_set_keepalive(int sockfd)
{
	const int val = 1;
	int ret;

	ret = setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE,
			(const char *)&val, sizeof(val));
	if (ret)
		printf("setsockopt SO_KEEPALIVE");

	return ret;
}

/* IPv6 Ready */
/*
 * moved here from vhci_attach.c
 */
SOCKET tcp_connect(char *hostname, char *service)
{
	struct addrinfo hints, *res, *res0;
	SOCKET sockfd;
	int ret;

	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;

	/* get all possible addresses */
	ret = getaddrinfo(hostname, service, &hints, &res0);
	if (ret) {
                printf("%s", gai_strerrorA(ret));
                return INVALID_SOCKET;
	}

	/* try all the addresses */
	for (res = res0; res; res = res->ai_next) {
		char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];

		ret = getnameinfo(res->ai_addr, res->ai_addrlen,
				hbuf, sizeof(hbuf), sbuf, sizeof(sbuf), 
				NI_NUMERICHOST | NI_NUMERICSERV);
		if (ret) {
                        printf("%s", gai_strerrorA(ret));
			continue;
		}

                dbg("trying %s port %s\n", hbuf, sbuf);

		sockfd = socket(res->ai_family, 
				res->ai_socktype, 
				res->ai_protocol
				);
		if (INVALID_SOCKET == sockfd ) {
			printf("socket");
			continue;
		}

		/* should set TCP_NODELAY for ipusb */
		ipusb_set_nodelay(sockfd);
		/* TODO: write code for heatbeat */
		ipusb_set_keepalive(sockfd);

                ret = connect_timo(sockfd, res->ai_addr, res->ai_addrlen, 6);
                if (ret < 0) {
                        printf("select failed %s", gai_strerrorA(ret));
                        closesocket(sockfd);
                        continue;
                } else if (ret == 0) {
                        printf("connect timeout");
                        closesocket(sockfd);
                        continue;
                }

		/* connected */
                dbg("connected to %s:%s", hbuf, sbuf);
                freeaddrinfo(res0);
		return sockfd;
	}


	dbg("%s:%s, %s", hostname, service, "no destination to connect to");
	freeaddrinfo(res0);

	return INVALID_SOCKET;
}

static int connect_timo(SOCKET sockfd,
                struct sockaddr *addr,
                size_t addrlen,
                int timo)
{
        fd_set socks;
        struct timeval timeout = { timo, 0 };
        u_long nonblock = 1;
        int ret;

        FD_ZERO(&socks);
        FD_SET((unsigned)sockfd, &socks);

        ioctlsocket(sockfd, FIONBIO, &nonblock);
        connect(sockfd, (const struct sockaddr *)addr, addrlen);

        ret = select(sockfd+1, NULL, &socks, NULL, &timeout);
        nonblock = 0;
        ioctlsocket(sockfd, FIONBIO, &nonblock);

        return ret;
}


int init_winsock(void)
{
	unsigned short version = 0x202; /* winsock 2.2 */
	WSADATA data;
	int ret;

	ret = WSAStartup( version, &data);
	if (ret)
		return -1;
	return 0;
}

