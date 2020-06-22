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
#include <linux/module.h>

#include "ipusb.h"

static int event_handler(struct ipusb_device *ud)
{
	/*
	 * Events are handled by only this thread.
	 */
	while (ipusb_event_happened(ud)) {

		/*
		 * NOTE: shutdown must come first.
		 * Shutdown the device.
		 */
		if (ud->event & IPUSB_EH_SHUTDOWN) {
			ud->eh_ops.shutdown(ud);
			ud->event &= ~IPUSB_EH_SHUTDOWN;
		}

		/* Reset the device. */
		if (ud->event & IPUSB_EH_RESET) {
			ud->eh_ops.reset(ud);
			ud->event &= ~IPUSB_EH_RESET;
		}

		/* Mark the device as unusable. */
		if (ud->event & IPUSB_EH_UNUSABLE) {
			ud->eh_ops.unusable(ud);
			ud->event &= ~IPUSB_EH_UNUSABLE;
		}

		/* Stop the error handler. */
		if (ud->event & IPUSB_EH_BYE)
			return -1;
	}

	return 0;
}

static int event_handler_loop(void *data)
{
	struct ipusb_device *ud = data;

	while (!kthread_should_stop()) {
		wait_event_interruptible(ud->eh_waitq,
					 ipusb_event_happened(ud) ||
					 kthread_should_stop());

		if (event_handler(ud) < 0)
			break;
	}

	return 0;
}

int ipusb_start_eh(struct ipusb_device *ud)
{
	init_waitqueue_head(&ud->eh_waitq);
	ud->event = 0;

	ud->eh = kthread_run(event_handler_loop, ud, "ipusb_eh");
	if (IS_ERR(ud->eh)) {
		pr_warning("Unable to start control thread\n");
		return PTR_ERR(ud->eh);
	}

	return 0;
}

void ipusb_stop_eh(struct ipusb_device *ud)
{
	if (ud->eh == current)
		return; /* do not wait for myself */

	kthread_stop(ud->eh);
}

void ipusb_event_add(struct ipusb_device *ud, unsigned long event)
{
	unsigned long flags;

	spin_lock_irqsave(&ud->lock, flags);
	ud->event |= event;
	spin_unlock_irqrestore(&ud->lock, flags);

	wake_up(&ud->eh_waitq);
}

int ipusb_event_happened(struct ipusb_device *ud)
{
	return ud->event;
}
