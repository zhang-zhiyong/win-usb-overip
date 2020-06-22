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

#include <linux/kthread.h>
#include <linux/socket.h>

#include "ipusb.h"
#include "host.h"


static void ipusb_host_free_priv_and_urb(struct ipusb_host_priv *priv)
{
	struct urb *urb = priv->urb;
	struct ipusb_host_device *sdev = priv->sdev;
	unsigned long flags;

	spin_lock_irqsave(&sdev->lock, flags);
	list_del(&priv->list);
	spin_unlock_irqrestore(&sdev->lock, flags);

	if (likely(urb->setup_packet))
		kfree(urb->setup_packet);
	if (likely(urb->transfer_buffer))
		kfree(urb->transfer_buffer);

	kmem_cache_free(ipusb_host_priv_cache, priv);
	usb_free_urb(urb);
}


void ipusb_host_complete(struct urb *urb)
{
	struct ipusb_host_priv *priv = (struct ipusb_host_priv *) urb->context;
	struct ipusb_host_device *sdev = priv->sdev;

	ipusb_dbg("complete! status %d\n", urb->status);

	switch (urb->status) {
	case 0:
		/* OK */
		break;
	case -ENOENT:
		dev_info(&urb->dev->dev, "stopped by a call to usb_kill_urb() "
			 "because of cleaning up a virtual connection\n");
		return;
	case -ECONNRESET:
		dev_info(&urb->dev->dev, "unlinked by a call to "
			 "usb_unlink_urb()\n");
		break;
	case -EPIPE:
		dev_info(&urb->dev->dev, "endpoint %d is stalled\n",
			 usb_pipeendpoint(urb->pipe));

		break;
	case -EREMOTEIO:
		dev_info(&urb->dev->dev, "remote io error\n");
		break;
	case -ESHUTDOWN:
		dev_info(&urb->dev->dev, "device removed?\n");
		break;
	default:
		dev_info(&urb->dev->dev, "urb completion with non-zero status "
			 "%d\n", urb->status);
		break;
	}

	/* urb completed, 
	 * move it to the tx queue */
	spin_lock(&sdev->lock);
	list_move_tail(&priv->list, &sdev->priv_tx);
	spin_unlock(&sdev->lock);

	wake_up(&sdev->tx_waitq);
}

static inline void setup_base_pdu(struct ipusb_header_basic *base,
				  __u32 command, __u32 seqnum)
{
	base->command	= command;
	base->seqnum	= seqnum;
	base->devid	= 0;
	base->ep	= 0;
	base->direction = 0;
}

static void setup_ret_submit_pdu(struct ipusb_header *rpdu, struct urb *urb)
{
	struct ipusb_host_priv *priv = (struct ipusb_host_priv *) urb->context;

	setup_base_pdu(&rpdu->base, IPUSB_RET_SUBMIT, priv->seqnum);
	ipusb_pack_pdu(rpdu, urb, IPUSB_RET_SUBMIT, 1);
}

static inline struct ipusb_host_priv * dequeue_tx_urb(struct ipusb_host_device *sdev)
{
	struct ipusb_host_priv *priv, *tmp;
	unsigned long flags;

	spin_lock_irqsave(&sdev->lock, flags);
	list_for_each_entry_safe(priv, tmp, &sdev->priv_tx, list) {
		goto out;
	}
	priv = NULL;

out:
	spin_unlock_irqrestore(&sdev->lock, flags);
	return priv;
}

static int ipusb_host_send_ret_submit(struct ipusb_host_device *sdev)
{
	struct ipusb_host_priv *priv;
	struct msghdr msg;
	size_t txsize;
	size_t total_size = 0;

	while ( (priv = dequeue_tx_urb(sdev)) ) {

		int ret;
		struct urb *urb = priv->urb;
		struct ipusb_header pdu_header;
		struct ipusb_iso_packet_descriptor *iso_buffer = NULL;
		struct kvec *iov = NULL;
		int iovnum = 0;

		txsize = 0;
		memset(&pdu_header, 0, sizeof(pdu_header));
		memset(&msg, 0, sizeof(msg));

		if (usb_pipetype(urb->pipe) == PIPE_ISOCHRONOUS)
			iovnum = 2 + urb->number_of_packets;
		else
			iovnum = 2;

		iov = kzalloc(iovnum * sizeof(struct kvec), GFP_KERNEL);
		if (!iov) {
			ipusb_event_add(&sdev->ud, SDEV_EVENT_ERROR_MALLOC);
			return -1;
		}

		iovnum = 0;

		/* 1. setup ipusb_header */
		setup_ret_submit_pdu(&pdu_header, urb);
		ipusb_dbg("setup txdata seqnum: %d urb: %p\n",
				  pdu_header.base.seqnum, urb);
		/*ipusb_dump_header(pdu_header);*/
		ipusb_header_correct_endian(&pdu_header, 1);

		iov[iovnum].iov_base = &pdu_header;
		iov[iovnum].iov_len  = sizeof(pdu_header);
		iovnum++;
		txsize += sizeof(pdu_header);

		/* 2. setup transfer buffer */
		if (usb_pipein(urb->pipe) &&
		    usb_pipetype(urb->pipe) != PIPE_ISOCHRONOUS &&
		    urb->actual_length > 0) {
			iov[iovnum].iov_base = urb->transfer_buffer;
			iov[iovnum].iov_len  = urb->actual_length;

			ipusb_dump_buffer((char *)iov[iovnum].iov_base, 
					iov[iovnum].iov_len 
					);
			iovnum++;
			txsize += urb->actual_length;

		} else if (usb_pipein(urb->pipe) &&
			   usb_pipetype(urb->pipe) == PIPE_ISOCHRONOUS) {
			/*
			 * For isochronous packets: actual length is the sum of
			 * the actual length of the individual, packets, but as
			 * the packet offsets are not changed there will be
			 * padding between the packets. To optimally use the
			 * bandwidth the padding is not transmitted.
			 */

			int i;
			for (i = 0; i < urb->number_of_packets; i++) {
				iov[iovnum].iov_base = urb->transfer_buffer +
					urb->iso_frame_desc[i].offset;
				iov[iovnum].iov_len =
					urb->iso_frame_desc[i].actual_length;
				iovnum++;
				txsize += urb->iso_frame_desc[i].actual_length;
			}

			if (txsize != sizeof(pdu_header) + urb->actual_length) {
				dev_err(&sdev->interface->dev,
					"actual length of urb %d does not "
					"match iso packet sizes %zu\n",
					urb->actual_length,
					txsize-sizeof(pdu_header));
				kfree(iov);
				ipusb_event_add(&sdev->ud,
						SDEV_EVENT_ERROR_TCP);
			   return -1;
			}
		}

		/* 3. setup iso_packet_descriptor */
		if (usb_pipetype(urb->pipe) == PIPE_ISOCHRONOUS) {
			ssize_t len = 0;

			iso_buffer = ipusb_alloc_iso_desc_pdu(urb, &len);
			if (!iso_buffer) {
				ipusb_event_add(&sdev->ud,
						SDEV_EVENT_ERROR_MALLOC);
				kfree(iov);
				return -1;
			}

			iov[iovnum].iov_base = iso_buffer;
			iov[iovnum].iov_len  = len;
			txsize += len;
			iovnum++;
		}

		ret = kernel_sendmsg(sdev->ud.tcp_socket, &msg,
						iov,  iovnum, txsize);
		if (ret != txsize) {
			dev_err(&sdev->interface->dev,
				"sendmsg failed!, retval %d for %zd\n",
				ret, txsize);
			kfree(iov);
			kfree(iso_buffer);
			ipusb_event_add(&sdev->ud, SDEV_EVENT_ERROR_TCP);
			return -1;
		}
		kfree(iov);
		kfree(iso_buffer);
		ipusb_host_free_priv_and_urb(priv);
		total_size += txsize;
	}

	return total_size;
}


int ipusb_host_tx_loop(void *data)
{
	struct ipusb_device *ud = data;
	struct ipusb_host_device *sdev = container_of(ud, struct ipusb_host_device, ud);

	while (!kthread_should_stop()) {
		if (ipusb_event_happened(ud))
			break;

		if ( (ipusb_host_send_ret_submit(sdev)) < 0)
			break;

		wait_event_interruptible(sdev->tx_waitq,
					(!list_empty(&sdev->priv_tx)) ||
					kthread_should_stop()
					);
	}

	return 0;
}
