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
#include "ipusb.h"
#include <stdlib.h>
#include <stdio.h>


struct speed_string {
	int num;
	char *speed;
	char *desc;
};

static const struct speed_string speed_strings[] = {
        { USB_SPEED_UNKNOWN, "unknown", "Unknown Speed"},
        { USB_SPEED_LOW,  "1.5", "Low Speed(1.5Mbps)"  },
	{ USB_SPEED_FULL, "12",  "Full Speed(12Mbps)" },
	{ USB_SPEED_HIGH, "480", "High Speed(480Mbps)" },
	{ 0, NULL, NULL }
};

const char *ipusb_speed_string(int num)
{
	int i;
	for (i=0; speed_strings[i].speed != NULL; i++)
		if (speed_strings[i].num == num)
			return speed_strings[i].desc;

	return "Unknown Speed";
}


#define DBG_UDEV_INTEGER(name)\
	dbg("%-20s = %x", to_string(name), (int) udev->name)

#define DBG_UINF_INTEGER(name)\
	dbg("%-20s = %x", to_string(name), (int) uinf->name)

void dump_usb_interface(struct usb_interface *uinf)
{
	char buff[100];
	ipusb_names_get_class(buff, sizeof(buff),
			uinf->bInterfaceClass,
			uinf->bInterfaceSubClass,
			uinf->bInterfaceProtocol);
	dbg("%-20s = %s", "Interface(C/SC/P)", buff);
}

void dump_usb_device(struct usb_device *udev)
{
	char buff[100];


	dbg("%-20s = %s", "path",  udev->path);
	dbg("%-20s = %s", "busid", udev->busid);

	ipusb_names_get_class(buff, sizeof(buff),
			udev->bDeviceClass,
			udev->bDeviceSubClass,
			udev->bDeviceProtocol);
	dbg("%-20s = %s", "Device(C/SC/P)", buff);

	DBG_UDEV_INTEGER(bcdDevice);

	ipusb_names_get_product(buff, sizeof(buff),
			udev->idVendor,
			udev->idProduct);
	dbg("%-20s = %s", "Vendor/Product", buff);

	DBG_UDEV_INTEGER(bNumConfigurations);
	DBG_UDEV_INTEGER(bNumInterfaces);

	dbg("%-20s = %s", "speed",
			ipusb_speed_string(udev->speed));

	DBG_UDEV_INTEGER(busnum);
	DBG_UDEV_INTEGER(devnum);
}

void 
ipusb_names_get_product(char *buff, 
			size_t size, 
			uint16_t vendor, 
			uint16_t product)
{
	const char *prod, *vend;
	prod = "unknown product";
	vend = "unknown vendor";
	_snprintf(buff, size, "%s : %s (%04x:%04x)", 
			vend, prod, vendor, product);
}

void 
ipusb_names_get_class(char *buff, 
			size_t size, 
			uint8_t _class, 
			uint8_t subclass, 
			uint8_t protocol)
{
	const char *c, *s, *p;

        if (_class == 0 && subclass == 0 && protocol == 0) {
                _snprintf(buff, size, 
			"(Defined at Interface level) (%02x/%02x/%02x)", 
			_class, subclass, protocol);
		return;
	}

	p = "unknown protocol";
	s = "unknown subclass";
	c = "unknown class";
        _snprintf(buff, size, 
		"%s / %s / %s (%02x/%02x/%02x)", 
		c, s, p, _class, subclass, protocol);
}
