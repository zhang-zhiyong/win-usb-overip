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

#ifndef _IPUSB_VBUS_UI_H
#define _IPUSB_VBUS_UI_H
/* char * ipusb_vbus_dev_node_name(char *buf, int buf_len); */
HANDLE ipusb_vbus_open(void);
int ipusb_vbus_get_free_port(HANDLE fd);
int ipusb_vbus_get_ports_status(HANDLE fd, char *buf, int len);
int ipusb_vbus_attach_device(HANDLE fd, int port,
		struct usb_device *udev, struct usb_interface * uinf0);
int ipusb_vbus_detach_device(HANDLE fd, int port);
void ipusb_vbus_forward(SOCKET sockfd, HANDLE devfd, volatile bool *stop_cond);

#endif
