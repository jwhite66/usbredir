/*
 * Copyright (C) 2015 Jeremy White based on work by
 * Copyright (C) 2003-2008 Takahiro Hirofuchi
 *
 * This is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 */

#ifndef __USBREDIR_H
#define __USBREDIR_H

#include <linux/device.h>
#include <linux/timer.h>
#include <linux/list.h>
#include <linux/platform_device.h>
#include <linux/usb.h>
#include <linux/usb/hcd.h>

#include "usbredirparser.h"

#define USBREDIR_MODULE_VERSION	"1.0"


/**
 * struct usbredir_device - Describe a redirected usb device
 * @lock		spinlock for port_status, usb_dev, and other misc fields
 * @active		indicates whether the device is actively connected
 * @usb_dev		The usb device actively in use; captured on our first
 *			useful control urb.  We mostly use it to signal that
 *			a device is in use.
 * @hub			The root hub that is associated with this device.
 * @attr		The sysfs atrribute to show our devid
 * @port_status		A status variable to track usb/core.c style status;
 *			e.g. USB_PORT_STAT_ENABLE et all
 * @socket		The socket used to connect to the remote device
 * @parser		A parser which drives the socket
 * @rx			The task structure for the receive thread
 * @tx			The task structure for the transmit thread
 * @devid		A user space provided id for this device; must be unique
 * @connect_header	Stored USBREDIR connection header information
 * @info_header		Stored USBREDIR connection information
 * @ep_info_header	Stored USBREDIR endpoint header info
 * @rhport		0 based port number on our root hub
 * @urblist_tx		A list of urb's ready to be transmitted
 * @urblist_rx		A list of urbs already transmitted, awaiting
 *                      a response
 * @unlink_tx		A list of urb's to be send to be unlinked
 * @unlink_xx		A list of urb's we have requested cancellation of
 * @waitq_tx		Wait queue the transmit thread sleeps on
 *
 * @timer               A timer to clear stale URBs
 */
struct usbredir_device {
	spinlock_t lock;

	atomic_t active;

	struct usb_device *usb_dev;
	struct usbredir_hub *hub;
	struct device_attribute attr;

	u32 port_status;

	struct socket *socket;
	struct usbredirparser *parser;

	struct task_struct *rx;
	struct task_struct *tx;

	char *devid;

	struct usb_redir_device_connect_header connect_header;
	struct usb_redir_interface_info_header info_header;
	struct usb_redir_ep_info_header ep_info_header;

	__u32 rhport;

	spinlock_t lists_lock;

	struct list_head urblist_tx;
	struct list_head urblist_rx;

	struct list_head unlink_tx;
	struct list_head unlink_rx;

	wait_queue_head_t waitq_tx;

	struct timer_list timer;
};

/**
 * struct usbredir_hub - Describe a virtual usb hub, which can hold
 *			 redirected usb devices
 *
 * @lock		Spinlock controlling access to variables,
 *			mostly needed for timeout and resuming flags
 * @list		Place holder for stashing inside a larger hub list
 * @id			A numeric identifier for this hub
 * @pdev		A registered platform device for this hub
 * @hcd			The usb_hcd associated with this hub
 * @device_count	The number of devices that can be connected to this hub
 * @devices		An array of devices
 * @aseqnum		Sequence number for transmissions
 * @resuming		Flag to indicate we are resuming
 * @re_timeout		General settle timeout for our hub
 *
 * The usbredir_hubs are allocated dynamically, as needed, but not freed.
 * A new devices is assigned to the first hub with a free slot.
 */
struct usbredir_hub {
	spinlock_t lock;
	struct list_head	list;
	int			id;
	struct platform_device	pdev;
	struct usb_hcd		*hcd;

	int			device_count;
	struct usbredir_device *devices;

	atomic_t aseqnum;

	unsigned resuming:1;
	unsigned long re_timeout;
};

/**
 * struct usbredir_urb - Hold our information regarding a URB
 * @seqnum		Sequence number of the urb
 * @list		Place holder to keep it in device/urblist_[rt]x
 * @urb			A pointer to the associated urb
 */
struct usbredir_urb {
	int seqnum;
	struct list_head list;

	struct urb *urb;
};

/**
 * struct usbredir_unlink  - Hold unlink requests
 * @seqnum		Sequence number of this request
 * @list		Place holder to keep it in device/unlink_[rt]x
 * @unlink_seqnum	Sequence number of the urb to unlink
 * @expires		When we should forcibly terminate this urb
 */
struct usbredir_unlink {
	int seqnum;

	struct list_head list;

	int unlink_seqnum;
	unsigned long expires;
};


/* main.c */
extern unsigned int max_hubs;
extern unsigned int devices_per_hub;

extern const char driver_name[];
extern const char driver_desc[];

/* sysfs.c */
int usbredir_sysfs_register(struct device_driver *dev);
void usbredir_sysfs_unregister(struct device_driver *dev);
void usbredir_sysfs_expose_devid(struct usbredir_device *udev);
void usbredir_sysfs_remove_devid(struct usbredir_device *udev);

/* hub.c */
void usbredir_hub_init(void);
void usbredir_hub_exit(void);
struct usbredir_device *usbredir_hub_allocate_device(const char *devid,
						     struct socket *socket);
struct usbredir_device *usbredir_hub_find_device(const char *devid);
int usbredir_hub_show_global_status(char *out);


/* device.c */
void usbredir_device_init(struct usbredir_device *udev, int port,
			  struct usbredir_hub *hub);
void usbredir_device_allocate(struct usbredir_device *udev,
			      const char *devid,
			      struct socket *socket);
void usbredir_device_deallocate(struct usbredir_device *udev,
				bool stop, bool stoptx);
void usbredir_device_connect(struct usbredir_device *udev);
void usbredir_device_create_sysfs(struct usbredir_device *udev, struct device
				  *dev);
void usbredir_device_disconnect(struct usbredir_device *udev);
int usbredir_device_clear_port_feature(struct usbredir_hub *hub,
			       int rhport, u16 wValue);
int usbredir_device_port_status(struct usbredir_hub *hub, int rhport,
				char *buf);
int usbredir_device_set_port_feature(struct usbredir_hub *hub,
			       int rhport, u16 wValue);
ssize_t usbredir_device_devid(struct device *dev,
				struct device_attribute *attr,
				char *buf);

/* redir.c */
struct usbredirparser *redir_parser_init(void *priv);

/* rx.c */
int usbredir_rx_loop(void *data);

/* tx.c */
int usbredir_tx_loop(void *data);

/* urb.c */
int usbredir_urb_enqueue(struct usb_hcd *hcd, struct urb *urb,
			    gfp_t mem_flags);
int usbredir_urb_dequeue(struct usb_hcd *hcd, struct urb *urb, int status);
struct urb *usbredir_pop_rx_urb(struct usbredir_device *udev, int seqnum);
void usbredir_urb_cleanup_urblists(struct usbredir_device *udev);
void usbredir_cancel_urb(struct usbredir_device *udev, int seqnum);

/* Fast lookup functions */
static inline struct usbredir_hub *usbredir_hub_from_hcd(struct usb_hcd *hcd)
{
	return *(struct usbredir_hub **) hcd->hcd_priv;
}

static inline int usbredir_hub_seqnum(struct usbredir_hub *hub)
{
	int ret = atomic_inc_return(&hub->aseqnum);
	/* Atomics are only guaranteed to 24 bits */
	if (ret < 0 || ret > (1 << 23)) {
		ret = 1;
		atomic_set(&hub->aseqnum, 1);
	}
	return ret;
}

#endif /* __USBREDIR_H */
