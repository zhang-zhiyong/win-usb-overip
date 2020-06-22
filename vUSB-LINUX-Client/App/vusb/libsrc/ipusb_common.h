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

#ifndef __IPUSB_COMMON_H
#define __IPUSB_COMMON_H

#include <sysfs/libsysfs.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <syslog.h>
#include <unistd.h>

#ifndef USBIDS_FILE
#define USBIDS_FILE "/usr/share/hwdata/usb.ids"
#endif

#ifndef IPHCI_STATE_PATH
#define IPHCI_STATE_PATH "/var/run/vhci_hcd"
#endif

/* kernel module names */
#define IPUSB_HOST_DRV_NAME	"vanxum-usbredir"
#define IPUSB_IPHCI_DRV_NAME	"iphci_hcd"

extern int ipusb_use_syslog;
extern int ipusb_use_stderr;
extern int ipusb_use_debug ;

#define PROGNAME "ipusb"

#define pr_fmt(fmt)	"%s: %s: " fmt "\n", PROGNAME
#define dbg_fmt(fmt)	pr_fmt("<%s>:%d " fmt), "debug",	\
		        __FUNCTION__, __LINE__

#define err(fmt, args...)						\
	do {								\
		if (ipusb_use_syslog) {					\
			syslog(LOG_ERR, pr_fmt(fmt), "error", ##args);	\
		}							\
		if (ipusb_use_stderr) {					\
			fprintf(stderr, pr_fmt(fmt), "error", ##args);	\
		}							\
	} while (0)

#define info(fmt, args...)						\
	do {								\
		if (ipusb_use_syslog) {					\
			syslog(LOG_INFO, pr_fmt(fmt), "info", ##args);	\
		}							\
		if (ipusb_use_stderr) {					\
			fprintf(stderr, pr_fmt(fmt), "info", ##args);	\
		}							\
	} while (0)

#define dbg(fmt, args...)						\
	do {								\
	if (ipusb_use_debug) {						\
		if (ipusb_use_syslog) {					\
			syslog(LOG_DEBUG, dbg_fmt(fmt), ##args);	\
		}							\
		if (ipusb_use_stderr) {					\
			fprintf(stderr, dbg_fmt(fmt), ##args);		\
		}							\
	}								\
	} while (0)

#define BUG()						\
	do {						\
		err("sorry, it's a bug!");		\
		abort();				\
	} while (0)

enum usb_device_speed {
	USB_SPEED_UNKNOWN = 0,                  /* enumerating */
	USB_SPEED_LOW, USB_SPEED_FULL,          /* usb 1.1 */
	USB_SPEED_HIGH,                         /* usb 2.0 */
	USB_SPEED_VARIABLE                      /* wireless (usb 2.5) */
};

/* FIXME: how to sync with drivers/ipusb_common.h ? */
enum ipusb_device_status{
	/* sdev is available. */
	SDEV_ST_AVAILABLE = 0x01,
	/* sdev is now used. */
	SDEV_ST_USED,
	/* sdev is unusable because of a fatal error. */
	SDEV_ST_ERROR,

	/* vdev does not connect a remote device. */
	VDEV_ST_NULL,
	/* vdev is used, but the USB address is not assigned yet */
	VDEV_ST_NOTASSIGNED,
	VDEV_ST_USED,
	VDEV_ST_ERROR
};

struct ipusb_usb_interface {
	uint8_t bInterfaceClass;
	uint8_t bInterfaceSubClass;
	uint8_t bInterfaceProtocol;
	uint8_t padding;	/* alignment */
} __attribute__((packed));

struct ipusb_usb_device {
	char path[SYSFS_PATH_MAX];
	char busid[SYSFS_BUS_ID_SIZE];
	char vendor_name[SYSFS_NAME_LEN];

	uint32_t busnum;
	uint32_t devnum;
	uint32_t speed;

	uint16_t idVendor;
	uint16_t idProduct;
	uint16_t bcdDevice;

	uint8_t bDeviceClass;
	uint8_t bDeviceSubClass;
	uint8_t bDeviceProtocol;
	uint8_t bConfigurationValue;
	uint8_t bNumConfigurations;
	uint8_t bNumInterfaces;
} __attribute__((packed));

#define to_string(s)	#s

void dump_usb_interface(struct ipusb_usb_interface *);
void dump_usb_device(struct ipusb_usb_device *);
int read_usb_device(struct sysfs_device *sdev, struct ipusb_usb_device *udev);
int read_attr_value(struct sysfs_device *dev, const char *name, const char *format);
int read_usb_interface(struct ipusb_usb_device *udev, int i,
		       struct ipusb_usb_interface *uinf);

const char *ipusb_speed_string(int num);
const char *ipusb_status_string(int32_t status);

int ipusb_names_init(char *);
void ipusb_names_free(void);
void ipusb_names_get_product(char *buff, size_t size, uint16_t vendor, uint16_t product);
void ipusb_names_get_class(char *buff, size_t size, uint8_t class, uint8_t subclass, uint8_t protocol);

#endif /* __IPUSB_COMMON_H */
