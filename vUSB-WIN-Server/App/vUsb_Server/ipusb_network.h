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

#ifndef _IPUSB_NETWORK_H
#define _IPUSB_NETWORK_H

ssize_t ipusb_recv(int sockfd, void *buff, size_t bufflen);
ssize_t ipusb_send(int sockfd, void *buff, size_t bufflen);
int ipusb_send_op_common(int sockfd, uint32_t code, uint32_t status);
int ipusb_recv_op_common(int sockfd, uint16_t *code);
int ipusb_set_reuseaddr(int sockfd);
int ipusb_set_nodelay(int sockfd);
int ipusb_set_keepalive(int sockfd);

SOCKET tcp_connect(char *hostname, char *service);

int init_winsock(void);

#endif
