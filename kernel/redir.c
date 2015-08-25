/*
 * Copyright (C) 2015 Jeremy White
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


#include <linux/net.h>
#include <linux/kthread.h>
#include <net/sock.h>
#include <linux/semaphore.h>
#include <linux/slab.h>
#include <linux/printk.h>

#include "usbredirparser.h"
#include "usbredir.h"


#define TODO_IMPLEMENT pr_err("Error: %s unimplemented.\n", __func__)

static void redir_log(void *priv, int level, const char *msg)
{
	switch (level) {
	case usbredirparser_error:
		pr_err("%s", msg);
		break;

	case usbredirparser_warning:
		pr_warn("%s", msg);
		break;

	case usbredirparser_info:
		pr_info("%s", msg);
		break;

	default:
		pr_debug("%s", msg);
		break;
	}
}

static int redir_read(void *priv, uint8_t *data, int count)
{
	struct usbredir_device *udev = (struct usbredir_device *) priv;
	struct msghdr msg;
	struct kvec iov;
	struct socket *socket;
	int rc;

	if (kthread_should_stop() || !atomic_read(&udev->active))
		return -ESRCH;

	spin_lock(&udev->lock);
	socket = udev->socket;
	/* TODO - reference/dereference the socket? */
	spin_unlock(&udev->lock);

	socket->sk->sk_allocation = GFP_NOIO;
	iov.iov_base    = data;
	iov.iov_len     = count;
	msg.msg_name    = NULL;
	msg.msg_namelen = 0;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags = MSG_NOSIGNAL;

	rc = kernel_recvmsg(socket, &msg, &iov, 1, count, MSG_WAITALL);

	return rc;
}

static int redir_write(void *priv, uint8_t *data, int count)
{
	struct usbredir_device *udev = (struct usbredir_device *) priv;
	struct msghdr msg;
	struct kvec iov;
	int rc;
	struct socket *socket;

	memset(&msg, 0, sizeof(msg));
	memset(&iov, 0, sizeof(iov));
	msg.msg_flags = MSG_NOSIGNAL | MSG_DONTWAIT;
	iov.iov_base = data;
	iov.iov_len  = count;

	spin_lock(&udev->lock);
	socket = udev->socket;
	/* TODO - reference/dereference the socket? */
	spin_unlock(&udev->lock);

	while (!kthread_should_stop() && atomic_read(&udev->active)) {
		rc = kernel_sendmsg(socket, &msg, &iov, 1, count);

		if (rc == -EAGAIN) {
			/* TODO - add schedule() ? */
			continue;
		}
		/* TODO - In theory, a return of 0 should be okay,
		 *        but, again, in theory, it will cause an error. */
		if (rc <= 0)
			pr_err("Error: TODO - unexpected write return code %d.\n", rc);

		break;
	}

	return rc;
}


/* Locking functions for use by multithread apps */
static void *redir_alloc_lock(void)
{
	struct semaphore *s = kmalloc(sizeof(*s), GFP_KERNEL);

	sema_init(s, 1);
	return s;
}

static void redir_lock(void *lock)
{
	while (down_interruptible((struct semaphore *) lock))
		;
}

static void redir_unlock(void *lock)
{
	up((struct semaphore *) lock);
}

static void redir_free_lock(void *lock)
{
	kfree(lock);
}

static bool find_device(const char *list, int vendor, int id)
{
	const char *p;
	char buf[24];

	sprintf(buf, "%04x:%04x", vendor, id);

	for (p = list; strlen(p) >= strlen(buf); p++)
		if (strncasecmp(p, buf, strlen(buf)) == 0)
			return true;

	return false;
}

/* The below callbacks are called when a complete packet of the relevant
   type has been received.

   Note that the passed in packet-type-specific-header's lifetime is only
   guarenteed to be that of the callback.

*/
static void redir_hello(void *priv, struct usb_redir_hello_header *hello)
{
	pr_debug("Hello!\n");
}

extern char *whitelist;
extern char *blacklist;
static void redir_device_connect(void *priv,
	struct usb_redir_device_connect_header *device_connect)
{
	struct usbredir_device *udev = (struct usbredir_device *) priv;

	pr_debug("  connect: class %2d subclass %2d protocol %2d",
		device_connect->device_class, device_connect->device_subclass,
		device_connect->device_protocol);
	pr_debug("  vendor 0x%04x product %04x\n",
		device_connect->vendor_id, device_connect->product_id);

	if (whitelist && ! find_device(whitelist, device_connect->vendor_id,
			device_connect->product_id)) {
		pr_err("Device %04x:%04x not in white list.\n",
		device_connect->vendor_id, device_connect->product_id);
		if (udev->socket)
			kernel_sock_shutdown(udev->socket, SHUT_RDWR);
		return;
	}

	if (blacklist && find_device(blacklist, device_connect->vendor_id,
			device_connect->product_id)) {
		pr_err("Device %04x:%04x in black list.\n",
		device_connect->vendor_id, device_connect->product_id);
		if (udev->socket)
			kernel_sock_shutdown(udev->socket, SHUT_RDWR);
		return;
	}


	spin_lock(&udev->lock);
	udev->connect_header = *device_connect;
	spin_unlock(&udev->lock);

	usbredir_device_connect(udev);
}

static void redir_device_disconnect(void *priv)
{
	TODO_IMPLEMENT;
}

static void redir_reset(void *priv)
{
	TODO_IMPLEMENT;
}

static void redir_interface_info(void *priv,
	struct usb_redir_interface_info_header *info)
{
	struct usbredir_device *udev = (struct usbredir_device *) priv;
	int i;

	for (i = 0; i < info->interface_count; i++) {
		pr_debug("interface %d class %2d subclass %2d protocol %2d",
			info->interface[i], info->interface_class[i],
			info->interface_subclass[i],
			info->interface_protocol[i]);
	}

	spin_lock(&udev->lock);
	udev->info_header = *info;
	spin_unlock(&udev->lock);
}

static void redir_ep_info(void *priv,
	struct usb_redir_ep_info_header *ep_info)
{
	struct usbredir_device *udev = (struct usbredir_device *) priv;

	spin_lock(&udev->lock);
	udev->ep_info_header = *ep_info;
	spin_unlock(&udev->lock);
}

static void redir_set_configuration(void *priv,
	uint64_t id,
	struct usb_redir_set_configuration_header *set_configuration)
{
	TODO_IMPLEMENT;
}

static void redir_get_configuration(void *priv, uint64_t id)
{
	TODO_IMPLEMENT;
}

static void redir_configuration_status(void *priv,
	uint64_t id,
	struct usb_redir_configuration_status_header *configuration_status)
{
	TODO_IMPLEMENT;
}

static void redir_set_alt_setting(void *priv,
	uint64_t id,
	struct usb_redir_set_alt_setting_header *set_alt_setting)
{
	TODO_IMPLEMENT;
}

static void redir_get_alt_setting(void *priv,
	uint64_t id,
	struct usb_redir_get_alt_setting_header *get_alt_setting)
{
	TODO_IMPLEMENT;
}

static void redir_alt_setting_status(void *priv,
	uint64_t id,
	struct usb_redir_alt_setting_status_header *alt_setting_status)
{
	TODO_IMPLEMENT;
}

static void redir_start_iso_stream(void *priv,
	uint64_t id,
	struct usb_redir_start_iso_stream_header *start_iso_stream)
{
	TODO_IMPLEMENT;
}

static void redir_stop_iso_stream(void *priv,
	uint64_t id,
	struct usb_redir_stop_iso_stream_header *stop_iso_stream)
{
	TODO_IMPLEMENT;
}

static void redir_iso_stream_status(void *priv,
	uint64_t id,
	struct usb_redir_iso_stream_status_header *iso_stream_status)
{
	TODO_IMPLEMENT;
}

static void redir_start_interrupt_receiving(void *priv,
	uint64_t id,
	struct usb_redir_start_interrupt_receiving_header
		*start_interrupt_receiving)
{
	TODO_IMPLEMENT;
}

static void redir_stop_interrupt_receiving(void *priv,
	uint64_t id,
	struct usb_redir_stop_interrupt_receiving_header
		*stop_interrupt_receiving)
{
	TODO_IMPLEMENT;
}

static void redir_interrupt_receiving_status(void *priv,
	uint64_t id,
	struct usb_redir_interrupt_receiving_status_header
		*interrupt_receiving_status)
{
	TODO_IMPLEMENT;
}

static void redir_alloc_bulk_streams(void *priv,
	uint64_t id,
	struct usb_redir_alloc_bulk_streams_header *alloc_bulk_streams)
{
	TODO_IMPLEMENT;
}

static void redir_free_bulk_streams(void *priv,
	uint64_t id,
	struct usb_redir_free_bulk_streams_header *free_bulk_streams)
{
	TODO_IMPLEMENT;
}

static void redir_bulk_streams_status(void *priv,
	uint64_t id,
	struct usb_redir_bulk_streams_status_header *bulk_streams_status)
{
	TODO_IMPLEMENT;
}

static void redir_cancel_data_packet(void *priv, uint64_t id)
{
	TODO_IMPLEMENT;
}

static void redir_filter_reject(void *priv)
{
	TODO_IMPLEMENT;
}

static void redir_filter_filter(void *priv,
	struct usbredirfilter_rule *rules, int rules_count)
{
	TODO_IMPLEMENT;
}

static void redir_device_disconnect_ack(void *priv)
{
	TODO_IMPLEMENT;
}

static void redir_start_bulk_receiving(void *priv,
	uint64_t id,
	struct usb_redir_start_bulk_receiving_header *start_bulk_receiving)
{
	TODO_IMPLEMENT;
}

static void redir_stop_bulk_receiving(void *priv,
	uint64_t id,
	struct usb_redir_stop_bulk_receiving_header *stop_bulk_receiving)
{
	TODO_IMPLEMENT;
}

static void redir_bulk_receiving_status(void *priv,
	uint64_t id,
	struct usb_redir_bulk_receiving_status_header *bulk_receiving_status)
{
	TODO_IMPLEMENT;
}

static int redir_map_status(int redir_status)
{
	switch (redir_status) {
	case usb_redir_success:
		return 0;
	case usb_redir_cancelled:
		return -ENOENT;
	case usb_redir_inval:
		return -EINVAL;
	case usb_redir_stall:
		return -EPIPE;
	case usb_redir_timeout:
		return -ETIMEDOUT;
	case usb_redir_babble:
		return -EOVERFLOW;
		/* Catchall error condition */
	case usb_redir_ioerror:
	default:
		return -ENODEV;
	}
}


static void redir_control_packet(void *priv,
	uint64_t id,
	struct usb_redir_control_packet_header *control_header,
	uint8_t *data, int data_len)
{
	struct usbredir_device *udev = (struct usbredir_device *) priv;
	struct urb *urb;

	urb = usbredir_pop_rx_urb(udev, id);
	if (!urb) {
		pr_err("Error: control id %lu with no matching entry.\n",
		       (unsigned long) id);
		return;
	}

	/* TODO - handle more than this flavor... */
	urb->status = redir_map_status(control_header->status);
	if (usb_pipein(urb->pipe)) {
		urb->actual_length = min_t(u32, data_len,
					 urb->transfer_buffer_length);
		if (urb->transfer_buffer)
			memcpy(urb->transfer_buffer, data, urb->actual_length);
	} else {
		urb->actual_length = control_header->length;
	}

	usb_hcd_unlink_urb_from_ep(udev->hub->hcd, urb);
	usb_hcd_giveback_urb(udev->hub->hcd, urb, urb->status);
}

static void redir_bulk_packet(void *priv,
	uint64_t id,
	struct usb_redir_bulk_packet_header *bulk_header,
	uint8_t *data, int data_len)
{
	struct usbredir_device *udev = (struct usbredir_device *) priv;
	struct urb *urb;

	urb = usbredir_pop_rx_urb(udev, id);
	if (!urb) {
		pr_err("Error: bulk id %lu with no matching entry.\n",
		       (unsigned long) id);
		return;
	}

	urb->status = redir_map_status(bulk_header->status);
	if (usb_pipein(urb->pipe)) {
		urb->actual_length = min_t(u32, data_len,
					 urb->transfer_buffer_length);
		if (urb->transfer_buffer)
			memcpy(urb->transfer_buffer, data, urb->actual_length);
	} else {
		urb->actual_length = bulk_header->length;
	}

	/* TODO - what to do with stream_id */
	/* TODO - handle more than this flavor... */

	usb_hcd_unlink_urb_from_ep(udev->hub->hcd, urb);
	usb_hcd_giveback_urb(udev->hub->hcd, urb, urb->status);
}

static void redir_iso_packet(void *priv,
	uint64_t id,
	struct usb_redir_iso_packet_header *iso_header,
	uint8_t *data, int data_len)
{
	TODO_IMPLEMENT;
}

static void redir_interrupt_packet(void *priv,
	uint64_t id,
	struct usb_redir_interrupt_packet_header *interrupt_header,
	uint8_t *data, int data_len)
{
	TODO_IMPLEMENT;
}

static void redir_buffered_bulk_packet(void *priv, uint64_t id,
	struct usb_redir_buffered_bulk_packet_header *buffered_bulk_header,
	uint8_t *data, int data_len)
{
	TODO_IMPLEMENT;
}


struct usbredirparser *redir_parser_init(void *priv)
{
	struct usbredirparser *parser;
	char version[40];

	uint32_t caps[USB_REDIR_CAPS_SIZE];

	parser = usbredirparser_create();

	parser->priv = priv;

	parser->log_func = redir_log;
	parser->read_func = redir_read;
	parser->write_func = redir_write;
	parser->device_connect_func = redir_device_connect;
	parser->device_disconnect_func = redir_device_disconnect;
	parser->reset_func = redir_reset;
	parser->interface_info_func = redir_interface_info;
	parser->ep_info_func = redir_ep_info;
	parser->set_configuration_func = redir_set_configuration;
	parser->get_configuration_func = redir_get_configuration;
	parser->configuration_status_func = redir_configuration_status;
	parser->set_alt_setting_func = redir_set_alt_setting;
	parser->get_alt_setting_func = redir_get_alt_setting;
	parser->alt_setting_status_func = redir_alt_setting_status;
	parser->start_iso_stream_func = redir_start_iso_stream;
	parser->stop_iso_stream_func = redir_stop_iso_stream;
	parser->iso_stream_status_func = redir_iso_stream_status;
	parser->start_interrupt_receiving_func =
		redir_start_interrupt_receiving;
	parser->stop_interrupt_receiving_func = redir_stop_interrupt_receiving;
	parser->interrupt_receiving_status_func =
		redir_interrupt_receiving_status;
	parser->alloc_bulk_streams_func = redir_alloc_bulk_streams;
	parser->free_bulk_streams_func = redir_free_bulk_streams;
	parser->bulk_streams_status_func = redir_bulk_streams_status;
	parser->cancel_data_packet_func = redir_cancel_data_packet;
	parser->control_packet_func = redir_control_packet;
	parser->bulk_packet_func = redir_bulk_packet;
	parser->iso_packet_func = redir_iso_packet;
	parser->interrupt_packet_func = redir_interrupt_packet;
	parser->alloc_lock_func = redir_alloc_lock;
	parser->lock_func = redir_lock;
	parser->unlock_func = redir_unlock;
	parser->free_lock_func = redir_free_lock;
	parser->hello_func = redir_hello;
	parser->filter_reject_func = redir_filter_reject;
	parser->filter_filter_func = redir_filter_filter;
	parser->device_disconnect_ack_func = redir_device_disconnect_ack;
	parser->start_bulk_receiving_func = redir_start_bulk_receiving;
	parser->stop_bulk_receiving_func = redir_stop_bulk_receiving;
	parser->bulk_receiving_status_func = redir_bulk_receiving_status;
	parser->buffered_bulk_packet_func = redir_buffered_bulk_packet;

	memset(caps, 0, sizeof(caps));
	usbredirparser_caps_set_cap(caps, usb_redir_cap_32bits_bulk_length);

	/* TODO - figure out which of these we really can use */
#if defined(USE_ALL_CAPS)
	usbredirparser_caps_set_cap(caps, usb_redir_cap_bulk_streams);
	usbredirparser_caps_set_cap(caps, usb_redir_cap_connect_device_version);
	usbredirparser_caps_set_cap(caps, usb_redir_cap_filter);
	usbredirparser_caps_set_cap(caps, usb_redir_cap_device_disconnect_ack);
	usbredirparser_caps_set_cap(caps,
				usb_redir_cap_ep_info_max_packet_size);
	usbredirparser_caps_set_cap(caps, usb_redir_cap_64bits_ids);
	usbredirparser_caps_set_cap(caps, usb_redir_cap_bulk_receiving);
#endif

	sprintf(version, "kmodule v%s. Protocol %x",
		USBREDIR_MODULE_VERSION, USBREDIR_VERSION);
	usbredirparser_init(parser, version, caps, USB_REDIR_CAPS_SIZE, 0);

	return parser;
}

