/*
 * Copyright (C) 2013 Daniel Danzberger <ipusb@dd-wrt.com>
 *               2011 matt mooney <mfm@muteddisk.com>
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

#ifndef __IPUSB_HOST_DRIVER_H
#define __IPUSB_HOST_DRIVER_H

#include <stdint.h>
#include "ipusb_common.h"

struct ipusb_host_driver {
	int ndevs;
	struct sysfs_driver *sysfs_driver;
	/* list of exported device */
	struct dlist *edev_list;
};

struct ipusb_exported_device {
	struct sysfs_device *sudev;
	int32_t status;
	struct ipusb_usb_device udev;
	struct ipusb_usb_interface uinf[];
};

extern struct ipusb_host_driver *host_driver;

int ipusb_host_driver_open(void);
void ipusb_host_driver_close(void);

int ipusb_host_refresh_device_list(void);
int ipusb_host_export_device(struct ipusb_exported_device *edev, int sockfd);
struct ipusb_exported_device *ipusb_host_get_device(int num);

#endif /* __IPUSB_HOST_DRIVER_H */
