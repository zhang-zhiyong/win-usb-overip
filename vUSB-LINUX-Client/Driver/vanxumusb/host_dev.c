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

#include <linux/device.h>
#include <linux/file.h>
#include <linux/kthread.h>
#include <linux/module.h>

#include "ipusb.h"
#include "host.h"

/*
 * Define device IDs here if you want to explicitly limit exportable devices.
 * In most cases, wildcard matching will be okay because driver binding can be
 * changed dynamically by a userland program.
 */
static struct usb_device_id ipusb_host_table[] = {
#if 0
	/* just an example */
	{ USB_DEVICE(0x05ac, 0x0301) },   /* Mac 1 button mouse */
	{ USB_DEVICE(0x0430, 0x0009) },   /* Plat Home Keyboard */
	{ USB_DEVICE(0x059b, 0x0001) },   /* Iomega USB Zip 100 */
	{ USB_DEVICE(0x04b3, 0x4427) },   /* IBM USB CD-ROM */
	{ USB_DEVICE(0x05a9, 0xa511) },   /* LifeView USB cam */
	{ USB_DEVICE(0x55aa, 0x0201) },   /* Imation card reader */
	{ USB_DEVICE(0x046d, 0x0870) },   /* Qcam Express(QV-30) */
	{ USB_DEVICE(0x04bb, 0x0101) },   /* IO-DATA HD 120GB */
	{ USB_DEVICE(0x04bb, 0x0904) },   /* IO-DATA USB-ET/TX */
	{ USB_DEVICE(0x04bb, 0x0201) },   /* IO-DATA USB-ET/TX */
	{ USB_DEVICE(0x08bb, 0x2702) },   /* ONKYO USB Speaker */
	{ USB_DEVICE(0x046d, 0x08b2) },   /* Logicool Qcam 4000 Pro */
#endif
	/* magic for wild card */
	{ .driver_info = 1 },
	{ 0, }                                     /* Terminating entry */
};
MODULE_DEVICE_TABLE(usb, ipusb_host_table);

/*
 * ipusb_status shows the status of ipusb-host as long as this driver is bound
 * to the target device.
 */
static ssize_t show_status(struct device *dev, struct device_attribute *attr,
			   char *buf)
{
	struct ipusb_host_device *sdev = dev_get_drvdata(dev);

	if (!sdev) {
		dev_err(dev, "sdev is null\n");
		return -ENODEV;
	}

	return snprintf(buf, PAGE_SIZE, "%d\n", sdev->ud.status);
}
static DEVICE_ATTR(ipusb_status, S_IRUGO, show_status, NULL);

/*
 * ipusb_sockfd gets a socket descriptor of an established TCP connection that
 * is used to transfer ipusb requests by kernel threads. -1 is a magic number
 * by which ipusb connection is finished.
 */
static ssize_t store_sockfd(struct device *dev, struct device_attribute *attr,
			    const char *buf, size_t count)
{
	struct ipusb_host_device *sdev = dev_get_drvdata(dev);
	int sockfd = 0;
	struct socket *socket;

	if (!sdev) {
		dev_err(dev, "sdev is null\n");
		return -ENODEV;
	}

	sscanf(buf, "%d", &sockfd);

	if (sockfd != -1) {
		dev_info(dev, "ipusb_host up\n");

		spin_lock(&sdev->ud.lock);

		if (sdev->ud.status != SDEV_ST_AVAILABLE) {
			dev_err(dev, "not ready\n");
			spin_unlock(&sdev->ud.lock);
			return -EINVAL;
		}

		socket = sockfd_to_socket(sockfd);
		if (!socket) {
			spin_unlock(&sdev->ud.lock);
			return -EINVAL;
		}
#if 0
		setnodelay(socket);
		setkeepalive(socket);
		setreuse(socket);
#endif
		sdev->ud.tcp_socket = socket;

		spin_unlock(&sdev->ud.lock);

		sdev->ud.tcp_rx = kthread_run(ipusb_host_rx_loop, &sdev->ud, "ipusb_host_rx");
		sdev->ud.tcp_tx = kthread_run(ipusb_host_tx_loop, &sdev->ud, "ipusb_host_tx");

		spin_lock(&sdev->ud.lock);
		sdev->ud.status = SDEV_ST_USED;
		spin_unlock(&sdev->ud.lock);

	} else {
		dev_info(dev, "ipusb_host down\n");

		spin_lock(&sdev->ud.lock);
		if (sdev->ud.status != SDEV_ST_USED) {
			spin_unlock(&sdev->ud.lock);
			return -EINVAL;
		}
		spin_unlock(&sdev->ud.lock);

		ipusb_event_add(&sdev->ud, SDEV_EVENT_DOWN);
	}

	return count;
}
static DEVICE_ATTR(ipusb_sockfd, S_IWUSR, NULL, store_sockfd);

static int ipusb_host_add_files(struct device *dev)
{
	int err = 0;

	err = device_create_file(dev, &dev_attr_ipusb_status);
	if (err)
		goto err_status;

	err = device_create_file(dev, &dev_attr_ipusb_sockfd);
	if (err)
		goto err_sockfd;

	return 0;

err_sockfd:
	device_remove_file(dev, &dev_attr_ipusb_status);
err_status:
	return err;
}

static void ipusb_host_remove_files(struct device *dev)
{
	device_remove_file(dev, &dev_attr_ipusb_status);
	device_remove_file(dev, &dev_attr_ipusb_sockfd);
}

static void ipusb_host_shutdown_connection(struct ipusb_device *ud)
{
	struct ipusb_host_device *sdev = container_of(ud, struct ipusb_host_device, ud);

	ipusb_dbg("shutdown\n");
	/*
	 * When removing an exported device, kernel panic sometimes occurred
	 * and then EIP was sk_wait_data of ipusb_host_rx thread. Is this because
	 * sk_wait_data returned though ipusb_host_rx thread was already finished by
	 * step 1?
	 */
	if (ud->tcp_socket) {
		dev_dbg(&sdev->udev->dev, "shutdown tcp_socket %p\n",
			ud->tcp_socket);
		kernel_sock_shutdown(ud->tcp_socket, SHUT_RDWR);
	}

	ipusb_dbg("stop rx/tx threads\n");

	/* 1. stop threads */
	if (ud->tcp_rx)
		kthread_stop(ud->tcp_rx);
	if (ud->tcp_tx)
		kthread_stop(ud->tcp_tx);

	/*
	 * 2. close the socket
	 *
	 * tcp_socket is freed after threads are killed so that ipusb_xmit does
	 * not touch NULL socket.
	 */
	ipusb_dbg("release socket\n");
	if (ud->tcp_socket) {
		fput(ud->tcp_socket->file);
		ud->tcp_socket = NULL;
	}

	ipusb_dbg("ipusb_host_dev cleanup\n");

	/* 3. free used data */
	ipusb_host_device_cleanup_urbs(sdev);

	ipusb_dbg("done\n");
}

static void ipusb_host_device_reset(struct ipusb_device *ud)
{
	struct ipusb_host_device *sdev = container_of(ud, struct ipusb_host_device, ud);
	struct usb_device *udev = sdev->udev;
	int ret;

	dev_dbg(&udev->dev, "device reset");

	ret = usb_lock_device_for_reset(udev, sdev->interface);
	if (ret < 0) {
		dev_err(&udev->dev, "lock for reset\n");
		spin_lock(&ud->lock);
		ud->status = SDEV_ST_ERROR;
		spin_unlock(&ud->lock);
		return;
	}

	/* try to reset the device */
	ret = usb_reset_device(udev);
	usb_unlock_device(udev);

	spin_lock(&ud->lock);
	if (ret) {
		dev_err(&udev->dev, "device reset\n");
		ud->status = SDEV_ST_ERROR;
	} else {
		dev_info(&udev->dev, "device reset\n");
		ud->status = SDEV_ST_AVAILABLE;
	}
	spin_unlock(&ud->lock);
}

static void ipusb_host_device_unusable(struct ipusb_device *ud)
{
	spin_lock(&ud->lock);
	ud->status = SDEV_ST_ERROR;
	spin_unlock(&ud->lock);
}

/**
 * ipusb_host_device_alloc - allocate a new ipusb_host_device struct
 * @interface: usb_interface of a new device
 *
 * Allocates and initializes a new ipusb_host_device struct.
 */
static struct ipusb_host_device *ipusb_host_device_alloc(struct usb_device *udev,
					     struct usb_interface *interface)
{
	struct ipusb_host_device *sdev;
	int busnum = interface_to_busnum(interface);
	int devnum = interface_to_devnum(interface);

	dev_dbg(&interface->dev, "allocating ipusb_host device");

	/* yes, it's a new device */
	sdev = kzalloc(sizeof(struct ipusb_host_device), GFP_KERNEL);
	if (!sdev) {
		dev_err(&interface->dev, "no memory for ipusb_host_device\n");
		return NULL;
	}

	sdev->interface = usb_get_intf(interface);
	sdev->udev = usb_get_dev(udev);

	/*
	 * devid is defined with devnum when this driver is first allocated.
	 * devnum may change later if a device is reset. However, devid never
	 * changes during a ipusb connection.
	 */
	sdev->devid		= (busnum << 16) | devnum;
	sdev->ud.side		= IPUSB_STUB;
	sdev->ud.status		= SDEV_ST_AVAILABLE;
	spin_lock_init(&sdev->ud.lock);
	sdev->ud.tcp_socket	= NULL;

	spin_lock_init(&sdev->lock);

	INIT_LIST_HEAD(&sdev->priv_init);
	INIT_LIST_HEAD(&sdev->priv_tx);

	init_waitqueue_head(&sdev->tx_waitq);

	sdev->ud.eh_ops.shutdown = ipusb_host_shutdown_connection;
	sdev->ud.eh_ops.reset    = ipusb_host_device_reset;
	sdev->ud.eh_ops.unusable = ipusb_host_device_unusable;

	ipusb_start_eh(&sdev->ud);

	dev_dbg(&interface->dev, "register new interface\n");

	return sdev;
}

static int ipusb_host_device_free(struct ipusb_host_device *sdev)
{
	if (!sdev)
		return -EINVAL;

	kfree(sdev);
	return 0;
}

/*
 * If a usb device has multiple active interfaces, this driver is bound to all
 * the active interfaces. However, ipusb exports *a* usb device (i.e., not *an*
 * active interface). Currently, a userland program must ensure that it
 * looks at the ipusb's sysfs entries of only the first active interface.
 *
 * TODO: use "struct usb_device_driver" to bind a usb device.
 * However, it seems it is not fully supported in mainline kernel yet
 * (2.6.19.2).
 */
static int ipusb_host_probe(struct usb_interface *interface,
		      const struct usb_device_id *id)
{
	struct usb_device *udev = interface_to_usbdev(interface);
	struct ipusb_host_device *sdev = NULL;
	const char *udev_busid = dev_name(interface->dev.parent);
	int err = 0;
	struct bus_id_priv *busid_priv;

	dev_dbg(&interface->dev, "Enter\n");

	/* check we should claim or not by busid_table */
	busid_priv = get_busid_priv(udev_busid);
	if (!busid_priv || (busid_priv->status == STUB_BUSID_REMOV) ||
	    (busid_priv->status == STUB_BUSID_OTHER)) {
		dev_info(&interface->dev, "%s is not in match_busid table... "
			 "skip!\n", udev_busid);

		/*
		 * Return value should be ENODEV or ENOXIO to continue trying
		 * other matched drivers by the driver core.
		 * See driver_probe_device() in driver/base/dd.c
		 */
		return -ENODEV;
	}

	if (udev->descriptor.bDeviceClass == USB_CLASS_HUB) {
		dev_dbg(&udev->dev, "%s is a usb hub device... skip!\n",
			 udev_busid);
		return -ENODEV;
	}

	if (!strcmp(udev->bus->bus_name, "vhci_hcd")) {
		dev_dbg(&udev->dev, "%s is attached on vhci_hcd... skip!\n",
			 udev_busid);
		return -ENODEV;
	}

	if (busid_priv->status == STUB_BUSID_ALLOC) {
		sdev = busid_priv->sdev;
		if (!sdev)
			return -ENODEV;

		busid_priv->interf_count++;
		dev_info(&interface->dev, "ipusb-host: register new interface "
			 "(bus %u dev %u ifn %u)\n",
			 udev->bus->busnum, udev->devnum,
			 interface->cur_altsetting->desc.bInterfaceNumber);

		/* set private data to usb_interface */
		usb_set_intfdata(interface, sdev);

		err = ipusb_host_add_files(&interface->dev);
		if (err) {
			dev_err(&interface->dev, "ipusb_host_add_files for %s\n",
				udev_busid);
			usb_set_intfdata(interface, NULL);
			busid_priv->interf_count--;
			return err;
		}

		usb_get_intf(interface);
		return 0;
	}

	/* ok, this is my device */
	sdev = ipusb_host_device_alloc(udev, interface);
	if (!sdev)
		return -ENOMEM;

	dev_info(&interface->dev, "ipusb-host: register new device "
		 "(bus %u dev %u ifn %u)\n", udev->bus->busnum, udev->devnum,
		 interface->cur_altsetting->desc.bInterfaceNumber);

	busid_priv->interf_count = 0;
	busid_priv->shutdown_busid = 0;

	/* set private data to usb_interface */
	usb_set_intfdata(interface, sdev);
	busid_priv->interf_count++;
	busid_priv->sdev = sdev;

	err = ipusb_host_add_files(&interface->dev);
	if (err) {
		dev_err(&interface->dev, "ipusb_host_add_files for %s\n", udev_busid);
		usb_set_intfdata(interface, NULL);
		usb_put_intf(interface);
		usb_put_dev(udev);
		kthread_stop(sdev->ud.eh);

		busid_priv->interf_count = 0;
		busid_priv->sdev = NULL;
		ipusb_host_device_free(sdev);
		return err;
	}
	busid_priv->status = STUB_BUSID_ALLOC;

	return 0;
}

static void shutdown_busid(struct bus_id_priv *busid_priv)
{
	if (busid_priv->sdev && !busid_priv->shutdown_busid) {
		busid_priv->shutdown_busid = 1;
		ipusb_event_add(&busid_priv->sdev->ud, SDEV_EVENT_REMOVED);

		/* 2. wait for the stop of the event handler */
		ipusb_stop_eh(&busid_priv->sdev->ud);
	}
}

/*
 * called in usb_disconnect() or usb_deregister()
 * but only if actconfig(active configuration) exists
 */
static void ipusb_host_disconnect(struct usb_interface *interface)
{
	struct ipusb_host_device *sdev;
	const char *udev_busid = dev_name(interface->dev.parent);
	struct bus_id_priv *busid_priv;

	dev_dbg(&interface->dev, "Enter\n");

	busid_priv = get_busid_priv(udev_busid);
	if (!busid_priv) {
		BUG();
		return;
	}

	sdev = usb_get_intfdata(interface);

	/* get ipusb_host_device */
	if (!sdev) {
		dev_err(&interface->dev, "could not get device");
		/* BUG(); */
		return;
	}

	usb_set_intfdata(interface, NULL);

	/*
	 * NOTE:
	 * rx/tx threads are invoked for each usb_device.
	 */
	ipusb_host_remove_files(&interface->dev);

	/*If usb reset called from event handler*/
	if (busid_priv->sdev->ud.eh == current) {
		busid_priv->interf_count--;
		return;
	}

	if (busid_priv->interf_count > 1) {
		busid_priv->interf_count--;
		shutdown_busid(busid_priv);
		usb_put_intf(interface);
		return;
	}

	busid_priv->interf_count = 0;

	/* 1. shutdown the current connection */
	shutdown_busid(busid_priv);

	usb_put_dev(sdev->udev);
	usb_put_intf(interface);

	/* 3. free sdev */
	busid_priv->sdev = NULL;
	ipusb_host_device_free(sdev);

	if (busid_priv->status == STUB_BUSID_ALLOC) {
		busid_priv->status = STUB_BUSID_ADDED;
	} else {
		busid_priv->status = STUB_BUSID_OTHER;
		del_match_busid((char *)udev_busid);
	}
}

/* 
 * Presence of pre_reset and post_reset prevents the driver from being unbound
 * when the device is being reset
 */
 
int ipusb_host_pre_reset(struct usb_interface *interface)
{
	dev_dbg(&interface->dev, "pre_reset\n");
	return 0;
}

int ipusb_host_post_reset(struct usb_interface *interface)
{
	dev_dbg(&interface->dev, "post_reset\n");
	return 0;
}

struct usb_driver ipusb_host_driver = {
	.name		= "vanxum-usbredir",
	.probe		= ipusb_host_probe,
	.disconnect	= ipusb_host_disconnect,
	.id_table	= ipusb_host_table,
	.pre_reset	= ipusb_host_pre_reset,
	.post_reset	= ipusb_host_post_reset,
 };
