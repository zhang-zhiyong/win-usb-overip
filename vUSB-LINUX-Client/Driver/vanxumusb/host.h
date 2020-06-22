/*
 * Copyright (C) 2003-2008 Takahiro Hirofuchi
 *
 * This is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307,
 * USA.
 */

#include <linux/list.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/usb.h>
#include <linux/wait.h>

#define STUB_BUSID_OTHER 0
#define STUB_BUSID_REMOV 1
#define STUB_BUSID_ADDED 2
#define STUB_BUSID_ALLOC 3

struct ipusb_host_device {
	struct usb_interface *interface;
	struct usb_device *udev;
	struct list_head list;

	struct ipusb_device ud;
	__u32 devid;

	/*
	 * ipusb_host_priv preserves private data of each urb.
	 * It is allocated as ipusb_host_priv_cache and assigned to urb->context.
	 *
	 * ipusb_host_priv is always linked to any one of 3 lists;
	 *	priv_init: linked to this until the comletion of a urb.
	 *	priv_tx  : linked to this after the completion of a urb.
	 *
	 * Any of these list operations should be locked by list_lock.
	 */
	spinlock_t lock;

	struct list_head priv_init;
	struct list_head priv_tx;

	wait_queue_head_t tx_waitq;
};

/* private data into urb->priv */
struct ipusb_host_priv {
	unsigned long seqnum;
	struct list_head list;
	struct ipusb_host_device *sdev;
	struct urb *urb;
};

/* same as SYSFS_BUS_ID_SIZE */
#define BUSID_SIZE 32

struct bus_id_priv {
	char name[BUSID_SIZE];
	char status;
	int interf_count;
	struct ipusb_host_device *sdev;
	char shutdown_busid;
};

/* ipusb_host_priv is allocated from ipusb_host_priv_cache */
extern struct kmem_cache *ipusb_host_priv_cache;

/* ipusb_host_dev.c */
extern struct usb_driver ipusb_host_driver;

/* ipusb_host_main.c */
struct bus_id_priv *get_busid_priv(const char *busid);
int del_match_busid(char *busid);
void ipusb_host_device_cleanup_urbs(struct ipusb_host_device *sdev);

/* ipusb_host_rx.c */
int ipusb_host_rx_loop(void *data);

/* ipusb_host_tx.c */
void ipusb_host_complete(struct urb *urb);
int ipusb_host_tx_loop(void *data);
