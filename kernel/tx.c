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

#include "usbredir.h"

static struct usbredir_urb *get_next_urb(struct usbredir_device *udev)
{
	struct usbredir_urb *uurb, *tmp;

	spin_lock(&udev->lock);

	list_for_each_entry_safe(uurb, tmp, &udev->urblist_tx, list) {
		list_move_tail(&uurb->list, &udev->urblist_rx);
		spin_unlock(&udev->lock);
		return uurb;
	}

	spin_unlock(&udev->lock);

	return NULL;
}

static void send_packet(struct usbredir_device *udev, struct usbredir_urb *uurb)
{
	struct urb *urb = uurb->urb;
	__u8 type = usb_pipetype(urb->pipe);

	if (type == PIPE_CONTROL && urb->setup_packet) {
		struct usb_ctrlrequest *ctrlreq =
			(struct usb_ctrlrequest *) urb->setup_packet;
		struct usb_redir_control_packet_header ctrl;

		ctrl.endpoint = usb_pipeendpoint(urb->pipe) |
				usb_pipein(urb->pipe);
		ctrl.request = ctrlreq->bRequest;
		ctrl.requesttype = ctrlreq->bRequestType;
		ctrl.status = 0;
		ctrl.value = le16_to_cpu(ctrlreq->wValue);
		ctrl.index = le16_to_cpu(ctrlreq->wIndex);
		ctrl.length = le16_to_cpu(ctrlreq->wLength);

		usbredirparser_send_control_packet(udev->parser,
			uurb->seqnum, &ctrl,
			usb_pipein(urb->pipe) ?
				NULL : urb->transfer_buffer,
			usb_pipein(urb->pipe) ?
				0 : urb->transfer_buffer_length);

	}

	if (type == PIPE_BULK) {
		struct usb_redir_bulk_packet_header bulk;

		bulk.endpoint = usb_pipeendpoint(urb->pipe) |
				usb_pipein(urb->pipe);
		bulk.status = 0;
		bulk.length = urb->transfer_buffer_length & 0xFFFF;
		bulk.stream_id = urb->stream_id;
		bulk.length_high = urb->transfer_buffer_length >> 16;

		usbredirparser_send_bulk_packet(udev->parser,
			uurb->seqnum, &bulk,
			usb_pipein(urb->pipe) ?
				NULL : urb->transfer_buffer,
			usb_pipein(urb->pipe) ?
				0 : urb->transfer_buffer_length);
	}
}

static struct usbredir_unlink *get_next_unlink(struct usbredir_device *udev)
{
	struct usbredir_unlink *unlink, *tmp;

	spin_lock(&udev->lock);

	list_for_each_entry_safe(unlink, tmp, &udev->unlink_tx, list) {
		list_move_tail(&unlink->list, &udev->unlink_rx);
		spin_unlock(&udev->lock);
		return unlink;
	}

	spin_unlock(&udev->lock);

	return NULL;
}

static void send_unlink(struct usbredir_device *udev,
		       struct usbredir_unlink *unlink)
{
	/* This is a separate TODO; need to process unlink_rx... */
	pr_debug("TODO partially unimplemented: unlink request of ");
	pr_debug("seqnum %d, unlink seqnum %d\n",
		unlink->seqnum, unlink->unlink_seqnum);

	/* TODO - if the other side never responds, which it may
		not do if the seqnum doesn't match, then we
		never clear this entry.  That's probably not ideal */
	usbredirparser_send_cancel_data_packet(udev->parser,
					       unlink->unlink_seqnum);
}

int usbredir_tx_loop(void *data)
{
	struct usbredir_device *udev = data;
	struct usbredir_urb *uurb;
	struct usbredir_unlink *unlink;

	while (!kthread_should_stop() && atomic_read(&udev->active)) {
		if (usbredirparser_has_data_to_write(udev->parser))
			if (usbredirparser_do_write(udev->parser))
				break;

		/* TODO - consider while versus if here */
		while ((uurb = get_next_urb(udev)) != NULL)
			send_packet(udev, uurb);

		/* TODO - consider while versus if here */
		while ((unlink = get_next_unlink(udev)) != NULL)
			send_unlink(udev, unlink);

		/* TODO - can I check list_empty without locking... */
		wait_event_interruptible(udev->waitq_tx,
			 (!list_empty(&udev->urblist_tx) ||
			  !list_empty(&udev->unlink_tx) ||
			  kthread_should_stop() ||
			 usbredirparser_has_data_to_write(udev->parser) ||
			 !atomic_read(&udev->active)));
	}

	pr_debug("%s exit\n", __func__);
	usbredir_device_disconnect(udev);
	usbredir_device_deallocate(udev, true, false);

	return 0;
}
