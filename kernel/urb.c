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

#include <linux/slab.h>
#include <linux/usb.h>
#include <linux/usb/hcd.h>

#include "usbredir.h"

/* Lock must be held by caller */
static void queue_urb(struct usbredir_device *udev, struct urb *urb)
{
	struct usbredir_urb *uurb;

	uurb = kzalloc(sizeof(struct usbredir_urb), GFP_ATOMIC);
	if (!uurb) {
		/* TODO - handle this failure... discon/dealloc? */
		return;
	}

	uurb->seqnum = usbredir_hub_seqnum(udev->hub);

	uurb->urb = urb;

	urb->hcpriv = (void *) uurb;

	list_add_tail(&uurb->list, &udev->urblist_tx);
}

static bool intercept_urb_request(struct usbredir_device *udev,
				  struct urb *urb, int *ret)
{
	struct device *dev = &urb->dev->dev;
	__u8 type = usb_pipetype(urb->pipe);
	struct usb_ctrlrequest *ctrlreq =
		(struct usb_ctrlrequest *) urb->setup_packet;

	if (usb_pipedevice(urb->pipe) != 0)
		return false;

	if (type != PIPE_CONTROL || !ctrlreq) {
		dev_err(dev, "invalid request to devnum 0; type %x, req %p\n",
			type, ctrlreq);
		*ret = -EINVAL;
		return true;
	}

	if (ctrlreq->bRequest == USB_REQ_GET_DESCRIPTOR) {
		pr_debug("Requesting descriptor; wValue %x\n", ctrlreq->wValue);

		usb_put_dev(udev->usb_dev);
		udev->usb_dev = usb_get_dev(urb->dev);

		if (ctrlreq->wValue == cpu_to_le16(USB_DT_DEVICE << 8))
			pr_debug("TODO: GetDescriptor unexpected.\n");

		return false;
	}

	if (ctrlreq->bRequest == USB_REQ_SET_ADDRESS) {
		dev_info(dev, "SetAddress Request (%d) to port %d\n",
			 ctrlreq->wValue, udev->rhport);

		usb_put_dev(udev->usb_dev);
		udev->usb_dev = usb_get_dev(urb->dev);

		if (urb->status == -EINPROGRESS) {
			/* This request is successfully completed. */
			/* If not -EINPROGRESS, possibly unlinked. */
			urb->status = 0;
		}
		return true;
	}

	dev_err(dev,
		"invalid request to devnum 0 bRequest %u, wValue %u\n",
		ctrlreq->bRequest,
		ctrlreq->wValue);
	*ret =  -EINVAL;

	return true;
}

/* Caller must hold lock */
void usbredir_urb_cleanup_urblists(struct usbredir_device *udev)
{
	struct usbredir_urb *uurb, *tmp;

	list_for_each_entry_safe(uurb, tmp, &udev->urblist_rx, list) {
		list_del(&uurb->list);
		usb_hcd_unlink_urb_from_ep(udev->hub->hcd, uurb->urb);
		/* TODO - kernel panics suggest we may need to unlock here */
		usb_hcd_giveback_urb(udev->hub->hcd, uurb->urb, -ENODEV);
		kfree(uurb);
	}

	list_for_each_entry_safe(uurb, tmp, &udev->urblist_tx, list) {
		list_del(&uurb->list);
		usb_hcd_unlink_urb_from_ep(udev->hub->hcd, uurb->urb);
		/* TODO - kernel panics suggest we may need to unlock here */
		usb_hcd_giveback_urb(udev->hub->hcd, uurb->urb, -ENODEV);
		kfree(uurb);
	}
}



int usbredir_urb_enqueue(struct usb_hcd *hcd, struct urb *urb, gfp_t mem_flags)
{
	struct device *dev = &urb->dev->dev;
	int ret = 0;
	struct usbredir_hub *hub = usbredir_hub_from_hcd(hcd);
	struct usbredir_device *udev;
	unsigned long flags;

	spin_lock_irqsave(&hub->lock, flags);

	udev = hub->devices + urb->dev->portnum - 1;

	if (!atomic_read(&udev->active)) {
		dev_err(dev, "enqueue for inactive port %d\n", udev->rhport);
		spin_unlock_irqrestore(&hub->lock, flags);
		return -ENODEV;
	}

	ret = usb_hcd_link_urb_to_ep(hcd, urb);
	if (ret) {
		spin_unlock_irqrestore(&hub->lock, flags);
		return ret;
	}

	if (intercept_urb_request(udev, urb, &ret)) {
		usb_hcd_unlink_urb_from_ep(hcd, urb);
		spin_unlock_irqrestore(&hub->lock, flags);
		usb_hcd_giveback_urb(hub->hcd, urb, urb->status);
		return 0;
	}

	queue_urb(udev, urb);
	spin_unlock_irqrestore(&hub->lock, flags);

	wake_up_interruptible(&udev->waitq_tx);

	return 0;
}

static void usbredir_free_uurb(struct usbredir_device *udev, struct urb *urb)
{
	struct usbredir_urb *uurb = urb->hcpriv;
	if (uurb) {
		spin_lock(&udev->lock);
		list_del(&uurb->list);
		kfree(uurb);
		urb->hcpriv = NULL;
		spin_unlock(&udev->lock);
	}
}

/* TODO - find justification for a timeout value; 250ms is pulled from air*/
#define DEQUEUE_TIMEOUT		((250 * HZ) / 1000)
int usbredir_urb_dequeue(struct usb_hcd *hcd, struct urb *urb, int status)
{
	struct usbredir_urb *uurb;
	struct usbredir_device *udev;
	struct usbredir_hub *hub = usbredir_hub_from_hcd(hcd);
	int ret = 0;
	unsigned long flags;

	pr_debug("%s %p\n", __func__, urb);

	uurb = urb->hcpriv;

	spin_lock_irqsave(&hub->lock, flags);
	udev = hub->devices + urb->dev->portnum - 1;

	ret = usb_hcd_check_unlink_urb(hcd, urb, status);
	if (ret) {
		/* TODO - figure out if this is an unlink send case as well */
		usbredir_free_uurb(udev, urb);
		spin_unlock_irqrestore(&hub->lock, flags);
		return ret;
	}

	if (usb_pipetype(urb->pipe) == PIPE_INTERRUPT) {
		/* TODO - wrong in all kinds of ways... */
		pr_debug("FIXME agreeably dequeing an INTERRUPT.\n");
		usbredir_free_uurb(udev, urb);

		usb_hcd_unlink_urb_from_ep(hcd, urb);
		spin_unlock_irqrestore(&hub->lock, flags);

		usb_hcd_giveback_urb(hub->hcd, urb, urb->status);
		return ret;
	}

	if (atomic_read(&udev->active) && uurb) {
		struct usbredir_unlink *unlink;

		unlink = kzalloc(sizeof(struct usbredir_unlink), GFP_ATOMIC);
		if (!unlink) {
			/* TODO complain somehow... */
			spin_unlock_irqrestore(&hub->lock, flags);
			return -ENOMEM;
		}

		unlink->seqnum = usbredir_hub_seqnum(hub);
		unlink->unlink_seqnum = uurb->seqnum;
		unlink->expires = jiffies + DEQUEUE_TIMEOUT;

		/* TODO - are we failing to pass through the status here? */
		spin_lock(&udev->lock);
		if (! timer_pending(&udev->timer))
			mod_timer(&udev->timer, unlink->expires);

		list_add_tail(&unlink->list, &udev->unlink_tx);
		spin_unlock(&udev->lock);

		spin_unlock_irqrestore(&hub->lock, flags);

		wake_up(&udev->waitq_tx);
	} else {
		/* Connection is dead already */
		usbredir_free_uurb(udev, urb);

		usb_hcd_unlink_urb_from_ep(hcd, urb);
		spin_unlock_irqrestore(&hub->lock, flags);

		usb_hcd_giveback_urb(hub->hcd, urb, urb->status);
	}

	return ret;
}

struct urb *usbredir_pop_rx_urb(struct usbredir_device *udev, int seqnum)
{
	struct usbredir_urb *uurb, *tmp;
	struct urb *urb = NULL;
	int status;

	spin_lock(&udev->lock);

	list_for_each_entry_safe(uurb, tmp, &udev->urblist_rx, list) {
		if (uurb->seqnum != seqnum)
			continue;

		urb = uurb->urb;
		status = urb->status;

		switch (status) {
		case -ENOENT:
			/* fall through */
		case -ECONNRESET:
			dev_info(&urb->dev->dev,
				 "urb %p was unlinked %ssynchronuously.\n", urb,
				 status == -ENOENT ? "" : "a");
			break;
		case -EINPROGRESS:
			/* no info output */
			break;
		default:
			dev_info(&urb->dev->dev,
				 "urb %p may be in a error, status %d\n", urb,
				 status);
		}

		list_del(&uurb->list);
		kfree(uurb);
		urb->hcpriv = NULL;

		break;
	}
	spin_unlock(&udev->lock);

	return urb;
}

void usbredir_cancel_urb(struct usbredir_device *udev, int seqnum)
{
	struct urb *urb = usbredir_pop_rx_urb(udev, seqnum);
	if (urb) {
		usb_hcd_unlink_urb_from_ep(udev->hub->hcd, urb);
		usb_hcd_giveback_urb(udev->hub->hcd, urb, urb->status);
	}
}

