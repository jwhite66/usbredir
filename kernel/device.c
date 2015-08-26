/*
 * Copyright (C) 2015 Jeremy White based on work by
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
 */

#include <linux/kthread.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/net.h>

#include "usbredir.h"


static void device_timer(unsigned long arg)
{
	struct usbredir_device *udev = (struct usbredir_device *) arg;
	struct usbredir_unlink *unlink, *tmp;
	unsigned long j = 0;
	int dequeue = -1;
	pr_debug("%ld(%d): device_timer\n", jiffies, udev->rhport);

	if (! atomic_read(&udev->active))
		return;

	spin_lock(&udev->lock);

	/* Dequeue at most one per invocation, so we can unlock */
	list_for_each_entry_safe(unlink, tmp, &udev->unlink_rx, list) {
		if (dequeue == -1 && time_after_eq(jiffies, unlink->expires)) {
			dequeue = unlink->unlink_seqnum;
			list_del(&unlink->list);
			kfree(unlink);
		}
		else if (j == 0 || time_after(j, unlink->expires)) {
			j = unlink->expires;
		}
	}

	if (j)
		mod_timer(&udev->timer, j);
	spin_unlock(&udev->lock);

	if (dequeue != -1) {
		usbredir_cancel_urb(udev, dequeue);
	}
}


void usbredir_device_init(struct usbredir_device *udev, int port,
			  struct usbredir_hub *hub)
{
	memset(udev, 0, sizeof(*udev));

	udev->rhport = port;
	udev->hub = hub;
	atomic_set(&udev->active, 0);
	spin_lock_init(&udev->lock);

	INIT_LIST_HEAD(&udev->urblist_rx);
	INIT_LIST_HEAD(&udev->urblist_tx);
	INIT_LIST_HEAD(&udev->unlink_tx);
	INIT_LIST_HEAD(&udev->unlink_rx);

	init_waitqueue_head(&udev->waitq_tx);

	init_timer(&udev->timer);
	udev->timer.data = (unsigned long) udev;
	udev->timer.function = device_timer;
}

void usbredir_device_allocate(struct usbredir_device *udev,
			      const char *devid,
			      struct socket *socket)
{
	char pname[32];

	udev->parser = redir_parser_init(udev);
	if (!udev->parser) {
		pr_err("Unable to allocate USBREDIR parser.\n");
		return;
	}

	udev->devid  = kstrdup(devid, GFP_ATOMIC);
	usbredir_sysfs_expose_devid(udev);

	udev->socket = socket;

	udev->port_status = 0;

	sprintf(pname, "usbredir/rx:%d", udev->rhport);
	udev->rx = kthread_run(usbredir_rx_loop, udev, pname);
	sprintf(pname, "usbredir/tx:%d", udev->rhport);
	udev->tx = kthread_run(usbredir_tx_loop, udev, pname);
}


/* Caller must hold lock */
static void usbredir_device_cleanup_unlink(struct usbredir_device *udev)
{
	struct usbredir_unlink *unlink, *tmp;

	list_for_each_entry_safe(unlink, tmp, &udev->unlink_tx, list) {
		list_del(&unlink->list);
		kfree(unlink);
	}

	list_for_each_entry_safe(unlink, tmp, &udev->unlink_rx, list) {
		list_del(&unlink->list);
		kfree(unlink);
	}
}

void usbredir_device_deallocate(struct usbredir_device *udev,
				bool stoprx, bool stoptx)
{
	pr_debug("%s %d/%d (active %d)\n", __func__, udev->hub->id,
		 udev->rhport, atomic_read(&udev->active));

	/* atomic_dec_if_positive is not available in 2.6.32 */
	if (atomic_dec_return(&udev->active) < 0) {
		atomic_inc(&udev->active);
		return;
	}

	del_timer(&udev->timer);

	/* Release the rx thread */
	if (udev->socket)
		kernel_sock_shutdown(udev->socket, SHUT_RDWR);

	/* Release the tx thread */
	wake_up_interruptible(&udev->waitq_tx);

	/* The key is that kthread_stop waits until that thread has exited,
	 *   so we don't clean up resources still in use */
	if (stoprx && udev->rx)
		kthread_stop(udev->rx);

	if (stoptx && udev->tx)
		kthread_stop(udev->tx);

	/* TODO - this lock is covering a bit too much... */
	spin_lock(&udev->lock);

	udev->rx = NULL;
	udev->tx = NULL;

	if (udev->socket) {
		sockfd_put(udev->socket);
		udev->socket = NULL;
	}

	usb_put_dev(udev->usb_dev);
	udev->usb_dev = NULL;

	usbredir_sysfs_remove_devid(udev);

	kfree(udev->devid);
	udev->devid = NULL;

	if (udev->parser) {
		usbredirparser_destroy(udev->parser);
		udev->parser = NULL;
	}

	usbredir_device_cleanup_unlink(udev);
	usbredir_urb_cleanup_urblists(udev);

	spin_unlock(&udev->lock);
}

static u32 speed_to_portflag(enum usb_device_speed speed)
{
	switch (speed) {
	case usb_redir_speed_low:   return USB_PORT_STAT_LOW_SPEED;
	case usb_redir_speed_high:  return USB_PORT_STAT_HIGH_SPEED;

	case usb_redir_speed_full:
	case usb_redir_speed_super:
	default:		    return 0;
	}
}

/* TODO - no thought at all to Super speed stuff... */
void usbredir_device_connect(struct usbredir_device *udev)
{
	spin_lock(&udev->lock);
	pr_debug("%s %d/%d:%s\n", __func__,
		 udev->hub->id, udev->rhport, udev->devid);
	udev->port_status |= USB_PORT_STAT_CONNECTION |
			    (1 << USB_PORT_FEAT_C_CONNECTION);
	udev->port_status |= speed_to_portflag(udev->connect_header.speed);
	spin_unlock(&udev->lock);

	usb_hcd_poll_rh_status(udev->hub->hcd);
}

void usbredir_device_disconnect(struct usbredir_device *udev)
{
	spin_lock(&udev->lock);
	pr_debug("%s %d/%d:%s\n", __func__,
		 udev->hub->id, udev->rhport, udev->devid);
	udev->port_status  &= ~USB_PORT_STAT_CONNECTION;
	udev->port_status  |= (1 << USB_PORT_FEAT_C_CONNECTION);
	spin_unlock(&udev->lock);

	usb_hcd_poll_rh_status(udev->hub->hcd);
}



static struct usbredir_device *usbredir_device_get(struct usbredir_hub *hub,
						 int rhport)
{
	struct usbredir_device *udev;

	if (rhport < 0 || rhport >= hub->device_count) {
		return NULL;
	}
	udev = hub->devices + rhport;

	return udev;
}

int usbredir_device_clear_port_feature(struct usbredir_hub *hub,
			       int rhport, u16 wValue)
{
	struct usbredir_device *udev = usbredir_device_get(hub, rhport);
	struct socket *shutdown = NULL;

	if (!udev)
		return -ENODEV;

	spin_lock(&udev->lock);

	switch (wValue) {
	case USB_PORT_FEAT_SUSPEND:
		pr_debug(" ClearPortFeature: USB_PORT_FEAT_SUSPEND\n");
		if (udev->port_status & USB_PORT_STAT_SUSPEND) {
			/* 20msec signaling */
			/* TODO - see note on suspend/resume below */
			hub->resuming = 1;
			hub->re_timeout =
				jiffies + msecs_to_jiffies(20);
		}
		break;
	case USB_PORT_FEAT_POWER:
		pr_debug(" ClearPortFeature: USB_PORT_FEAT_POWER\n");
		udev->port_status = 0;
		hub->resuming = 0;
		break;
	case USB_PORT_FEAT_C_RESET:
		pr_debug(" ClearPortFeature: USB_PORT_FEAT_C_RESET\n");
		/* TODO - USB 3.0 stuff as well? */
		switch (udev->connect_header.speed) {
		case usb_redir_speed_high:
			udev->port_status |= USB_PORT_STAT_HIGH_SPEED;
			break;
		case usb_redir_speed_low:
			udev->port_status |= USB_PORT_STAT_LOW_SPEED;
			break;
		default:
			break;
		}
		udev->port_status &= ~(1 << wValue);
		break;
	case USB_PORT_FEAT_ENABLE:
		pr_debug(" ClearPortFeature: USB_PORT_FEAT_ENABLE\n");
		if (udev->socket)
			shutdown = udev->socket;
		udev->port_status &= ~(1 << wValue);
		break;
	default:
		pr_debug(" ClearPortFeature: default %x\n", wValue);
		udev->port_status &= ~(1 << wValue);
		break;
	}

	spin_unlock(&udev->lock);
	if (shutdown)
		kernel_sock_shutdown(shutdown, SHUT_RDWR);

	return 0;
}

int usbredir_device_port_status(struct usbredir_hub *hub, int rhport, char *buf)
{
	struct usbredir_device *udev = usbredir_device_get(hub, rhport);

	if (!udev)
		return -ENODEV;

	pr_debug("%s %d/%d 0x%x\n", __func__,
		 udev->hub->id, rhport, udev->port_status);

	/* TODO - the logic on resume/reset etc is really
	 *   just blindly copied from USBIP.  Make sure
	 *   this eventually gets thoughtful review and testing. */

	/* whoever resets or resumes must GetPortStatus to
	 * complete it!!
	 */
	if (hub->resuming && time_after(jiffies, hub->re_timeout)) {
		udev->port_status |= (1 << USB_PORT_FEAT_C_SUSPEND);
		udev->port_status &= ~(1 << USB_PORT_FEAT_SUSPEND);
		hub->resuming = 0;
		hub->re_timeout = 0;
	}

	spin_lock(&udev->lock);
	if ((udev->port_status & (1 << USB_PORT_FEAT_RESET)) &&
	     time_after(jiffies, hub->re_timeout)) {
		udev->port_status |= (1 << USB_PORT_FEAT_C_RESET);
		udev->port_status &= ~(1 << USB_PORT_FEAT_RESET);
		hub->re_timeout = 0;

		if (atomic_read(&udev->active)) {
			pr_debug(" enable rhport %d\n", rhport);
			udev->port_status |= USB_PORT_STAT_ENABLE;
		}
	}

	((__le16 *) buf)[0] = cpu_to_le16(udev->port_status);
	((__le16 *) buf)[1] =
		cpu_to_le16(udev->port_status >> 16);

	pr_debug(" GetPortStatus bye %x %x\n", ((u16 *)buf)[0],
			  ((u16 *)buf)[1]);

	spin_unlock(&udev->lock);

	return 0;
}

int usbredir_device_set_port_feature(struct usbredir_hub *hub,
			       int rhport, u16 wValue)
{
	struct usbredir_device *udev = usbredir_device_get(hub, rhport);

	if (!udev)
		return -ENODEV;

	spin_lock(&udev->lock);

	switch (wValue) {
	case USB_PORT_FEAT_SUSPEND:
		pr_debug(" SetPortFeature: USB_PORT_FEAT_SUSPEND\n");
		break;
	case USB_PORT_FEAT_RESET:
		pr_debug(" SetPortFeature: USB_PORT_FEAT_RESET\n");
		udev->port_status &= ~USB_PORT_STAT_ENABLE;

		/* 50msec reset signaling */
		/* TODO - why?  Seems like matching core/hub.c
		 *	SHORT_RESET_TIME would be better */
		hub->re_timeout = jiffies + msecs_to_jiffies(50);

		/* FALLTHROUGH */
	default:
		pr_debug(" SetPortFeature: default %d\n", wValue);
		udev->port_status |= (1 << wValue);
		break;
	}

	spin_unlock(&udev->lock);

	return 0;
}

ssize_t usbredir_device_devid(struct device *dev,
				struct device_attribute *attr,
				char *buf)
{
	int id;
	struct usb_hcd *hcd = dev_get_drvdata(dev);
	struct usbredir_hub *hub = usbredir_hub_from_hcd(hcd);
	struct usbredir_device *udev;

	sscanf(attr->attr.name, "devid.%d", &id);

	udev = usbredir_device_get(hub, id);
	if (udev && udev->devid) {
		spin_lock(&udev->lock);
		sprintf(buf, "%s\n", udev->devid);
		spin_unlock(&udev->lock);
		return strlen(buf);
	}

	return 0;
}
