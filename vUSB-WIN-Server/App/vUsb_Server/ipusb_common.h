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

#ifndef _IPUSB_COMMON_H
#define _IPUSB_COMMON_H

#include <sys/types.h>

#define to_string(s)	#s

void dump_usb_interface(struct usb_interface *);
void dump_usb_device(struct usb_device *);
void ipusb_dump_buffer(unsigned char *buff, int bufflen);

int read_usb_interface(struct usb_device *udev, 
			int i, 
			struct usb_interface *uinf);

const char *ipusb_speed_string(int num);

void ipusb_names_get_product(char *buff, 
				size_t size, 
				uint16_t vendor, 
				uint16_t product);

void ipusb_names_get_class(char *buff, 
			size_t size, 
			uint8_t _class, 
			uint8_t subclass, 
			uint8_t protocol);

#endif
