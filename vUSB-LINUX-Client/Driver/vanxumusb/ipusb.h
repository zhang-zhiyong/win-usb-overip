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

#ifndef __IPUSB_COMMON_H
#define __IPUSB_COMMON_H

#include <linux/compiler.h>
#include <linux/device.h>
#include <linux/interrupt.h>
#include <linux/net.h>
#include <linux/printk.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/usb.h>
#include <linux/wait.h>

#define IPUSB_VERSION "0.1.0"

#ifdef DEBUG
#define ipusb_dbg(fmt, args...) \
	printk(KBUILD_MODNAME ": %s:%d: " fmt, __func__, __LINE__, ##args)

#define ipusb_generic_dbg(fmt, args...) \
	printk("ipusb: %s:%d: " fmt, __func__, __LINE__, ##args)

#else 
#define ipusb_dbg(fmt, args...)	
#define ipusb_generic_dbg(fmt, args...)	
#endif

#ifdef DEBUG_VERBOSE
#define ipusb_dbg_verbose(fmt, args...) \
	printk(KBUILD_MODNAME ": %s:%d: " fmt, __func__, __LINE__, ##args)
#else
#define ipusb_dbg_verbose(fmt, args...)	
#endif


#define ipusb_info(fmt, args...) \
	pr_info("ipusb: " fmt, ##args)

#define ipusb_err(fmt, args...) \
	pr_err("ipusb: " fmt, ##args)



/*
 * USB/IP request headers
 *
 * Each request is transferred across the network to its counterpart, which
 * facilitates the normal USB communication. The values contained in the headers
 * are basically the same as in a URB. Currently, four request types are
 * defined:
 *
 *  - IPUSB_CMD_SUBMIT: a USB request block, corresponds to usb_submit_urb()
 *    (client to server)
 *
 *  - IPUSB_RET_SUBMIT: the result of IPUSB_CMD_SUBMIT
 *    (server to client)
 *
 *  - IPUSB_CMD_UNLINK: an unlink request of a pending IPUSB_CMD_SUBMIT,
 *    corresponds to usb_unlink_urb()
 *    (client to server)
 *
 *  - IPUSB_RET_UNLINK: the result of IPUSB_CMD_UNLINK
 *    (server to client)
 *
 */
#define IPUSB_CMD_SUBMIT	0x0001
#define IPUSB_CMD_UNLINK	0x0002
#define IPUSB_RET_SUBMIT	0x0003
#define IPUSB_RET_UNLINK	0x0004

#define IPUSB_DIR_OUT	0x00
#define IPUSB_DIR_IN	0x01

/**
 * struct ipusb_header_basic - data pertinent to every request
 * @command: the ipusb request type
 * @seqnum: sequential number that identifies requests; incremented per
 *	    connection
 * @devid: specifies a remote USB device uniquely instead of busnum and devnum;
 *	   in the stub driver, this value is ((busnum << 16) | devnum)
 * @direction: direction of the transfer
 * @ep: endpoint number
 */
struct ipusb_header_basic {
	__u32 command;
	__u32 seqnum;
	__u32 devid;
	__u32 direction;
	__u32 ep;
} __packed;

/**
 * struct ipusb_header_cmd_submit - IPUSB_CMD_SUBMIT packet header
 * @transfer_flags: URB flags
 * @transfer_buffer_length: the data size for (in) or (out) transfer
 * @start_frame: initial frame for isochronous or interrupt transfers
 * @number_of_packets: number of isochronous packets
 * @interval: maximum time for the request on the server-side host controller
 * @setup: setup data for a control request
 */
struct ipusb_header_cmd_submit {
	__u32 transfer_flags;
	__s32 transfer_buffer_length;

	/* it is difficult for ipusb to sync frames (reserved only?) */
	__s32 start_frame;
	__s32 number_of_packets;
	__s32 interval;

	unsigned char setup[8];
} __packed;

/**
 * struct ipusb_header_ret_submit - IPUSB_RET_SUBMIT packet header
 * @status: return status of a non-iso request
 * @actual_length: number of bytes transferred
 * @start_frame: initial frame for isochronous or interrupt transfers
 * @number_of_packets: number of isochronous packets
 * @error_count: number of errors for isochronous transfers
 */
struct ipusb_header_ret_submit {
	__s32 status;
	__s32 actual_length;
	__s32 start_frame;
	__s32 number_of_packets;
	__s32 error_count;
} __packed;

/**
 *  * struct ipusb_header_ret_unlink - IPUSB_RET_UNLINK packet header
 *   * @status: return status of the request
 *    */
struct ipusb_header_ret_unlink {
	        __s32 status;
} __packed;

/**
 * struct ipusb_header_cmd_unlink - IPUSB_CMD_UNLINK packet header
 * @seqnum: the URB seqnum to unlink
 */
struct ipusb_header_cmd_unlink {
	__u32 seqnum;
} __packed;

/**
 * struct ipusb_header - common header for all ipusb packets
 * @base: the basic header
 * @u: packet type dependent header
 */
struct ipusb_header {
	struct ipusb_header_basic base;

	union {
		struct ipusb_header_cmd_submit	cmd_submit;
		struct ipusb_header_ret_submit	ret_submit;
		struct ipusb_header_cmd_unlink	cmd_unlink;
		struct ipusb_header_ret_unlink	ret_unlink;
	} u;
} __packed;

/*
 * This is the same as usb_iso_packet_descriptor but packed for pdu.
 */
struct ipusb_iso_packet_descriptor {
	__u32 offset;
	__u32 length;			/* expected length */
	__u32 actual_length;
	__u32 status;
} __packed;

enum ipusb_side {
	IPUSB_IPHCI,
	IPUSB_STUB,
};

enum ipusb_status {
	SDEV_ST_AVAILABLE = 0x01,
	SDEV_ST_USED,
	SDEV_ST_ERROR,

	/* vdev does not connect a remote device. */
	VDEV_ST_NULL,
	/* vdev is used, but the USB address is not assigned yet */
	VDEV_ST_NOTASSIGNED,
	VDEV_ST_USED,
	/* vdev is disconnected and releasing resources */
	VDEV_ST_RELEASING,
	VDEV_ST_ERROR
};

/* event handler */
#define IPUSB_EH_SHUTDOWN	(1 << 0)
#define IPUSB_EH_BYE		(1 << 1)
#define IPUSB_EH_RESET		(1 << 2)
#define IPUSB_EH_UNUSABLE	(1 << 3)

#define SDEV_EVENT_REMOVED   (IPUSB_EH_SHUTDOWN | IPUSB_EH_RESET | IPUSB_EH_BYE)
#define	SDEV_EVENT_DOWN		(IPUSB_EH_SHUTDOWN | IPUSB_EH_RESET)
#define	SDEV_EVENT_ERROR_TCP	(IPUSB_EH_SHUTDOWN | IPUSB_EH_RESET)
#define	SDEV_EVENT_ERROR_SUBMIT	(IPUSB_EH_SHUTDOWN | IPUSB_EH_RESET)
#define	SDEV_EVENT_ERROR_MALLOC	(IPUSB_EH_SHUTDOWN | IPUSB_EH_UNUSABLE)

#define	VDEV_EVENT_REMOVED	(IPUSB_EH_SHUTDOWN | IPUSB_EH_BYE)
#define	VDEV_EVENT_DOWN		(IPUSB_EH_SHUTDOWN | IPUSB_EH_RESET)
#define	VDEV_EVENT_ERROR_TCP	(IPUSB_EH_SHUTDOWN | IPUSB_EH_RESET)
#define	VDEV_EVENT_ERROR_MALLOC	(IPUSB_EH_SHUTDOWN | IPUSB_EH_UNUSABLE)

/* a common structure for stub_device and vhci_device */
struct ipusb_device {
	enum ipusb_side side;
	enum ipusb_status status;

	/* lock for status */
	spinlock_t lock;

	struct socket *tcp_socket;

	struct task_struct *tcp_rx;
	struct task_struct *tcp_tx;

	unsigned long event;
	struct task_struct *eh;
	wait_queue_head_t eh_waitq;

	struct eh_ops {
		void (*shutdown)(struct ipusb_device *);
		void (*reset)(struct ipusb_device *);
		void (*unusable)(struct ipusb_device *);
	} eh_ops;
};


/* ipusb_common.c */
void ipusb_dump_urb(struct urb *purb);
void ipusb_dump_header(struct ipusb_header *pdu);
void ipusb_dump_buffer(unsigned char *buff, int bufflen);

int ipusb_xmit(int send, struct socket *sock, char *buf, int size,
	       int msg_flags);
struct socket *sockfd_to_socket(unsigned int sockfd);

void ipusb_pack_pdu(struct ipusb_header *pdu, struct urb *urb, int cmd,
		    int pack);
void ipusb_header_correct_endian(struct ipusb_header *pdu, int send);

struct ipusb_iso_packet_descriptor*
ipusb_alloc_iso_desc_pdu(struct urb *urb, ssize_t *bufflen);

/* some members of urb must be substituted before. */
int ipusb_recv_iso(struct ipusb_device *ud, struct urb *urb);
int ipusb_pad_iso(struct ipusb_device *ud, struct urb *urb);
int ipusb_recv_xbuff(struct ipusb_device *ud, struct urb *urb);

/* ipusb_event.c */
int ipusb_start_eh(struct ipusb_device *ud);
void ipusb_stop_eh(struct ipusb_device *ud);
void ipusb_event_add(struct ipusb_device *ud, unsigned long event);
int ipusb_event_happened(struct ipusb_device *ud);

static inline int interface_to_busnum(struct usb_interface *interface)
{
	struct usb_device *udev = interface_to_usbdev(interface);
	return udev->bus->busnum;
}

static inline int interface_to_devnum(struct usb_interface *interface)
{
	struct usb_device *udev = interface_to_usbdev(interface);
	return udev->devnum;
}

static inline int interface_to_infnum(struct usb_interface *interface)
{
	return interface->cur_altsetting->desc.bInterfaceNumber;
}

#endif /* __IPUSB_COMMON_H */
