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
#include <linux/spinlock.h>
#include <linux/usb.h>
#include <linux/usb/hcd.h>
#include <linux/kthread.h>

#include "usbredir.h"

static spinlock_t hubs_lock;
static struct list_head hubs;
static atomic_t hub_count;

static int usbredir_hcd_start(struct usb_hcd *hcd)
{
	struct usbredir_hub *hub = usbredir_hub_from_hcd(hcd);
	int i;
	unsigned long flags;

	spin_lock_irqsave(&hub->lock, flags);
	pr_debug("%s %d\n", __func__, hub->id);

	hub->device_count = devices_per_hub;
	hub->devices = kcalloc(hub->device_count, sizeof(*hub->devices),
			       GFP_ATOMIC);
	if (!hub->devices) {
		spin_unlock_irqrestore(&hub->lock, flags);
		return -ENOMEM;
	}

	for (i = 0; i < hub->device_count; i++)
		usbredir_device_init(hub->devices + i, i, hub);

	hcd->power_budget = 0; /* no limit */
	hcd->uses_new_polling = 1;
	atomic_set(&hub->aseqnum, 0);
	spin_unlock_irqrestore(&hub->lock, flags);

	return 0;
}

static void usbredir_hub_stop(struct usbredir_hub *hub)
{
	int i;
	unsigned long flags;

	pr_debug("%s %d\n", __func__, hub->id);

	/* TODO - the dummy hcd does not have this equivalent in its stop... */
	for (i = 0; i < hub->device_count && hub->devices; i++) {
		usbredir_device_disconnect(hub->devices + i);
		usbredir_device_deallocate(hub->devices + i, true, true);
	}

	spin_lock_irqsave(&hub->lock, flags);
	kfree(hub->devices);
	hub->devices = NULL;
	hub->device_count = 0;
	spin_unlock_irqrestore(&hub->lock, flags);
}

static void usbredir_hcd_stop(struct usb_hcd *hcd)
{
	usbredir_hub_stop(usbredir_hub_from_hcd(hcd));
}

static int usbredir_get_frame_number(struct usb_hcd *hcd)
{
	pr_err("TODO: get_frame_number: not implemented\n");
	return 0;
}

static int usbredir_hub_status(struct usb_hcd *hcd, char *buf)
{
	struct usbredir_hub *hub = usbredir_hub_from_hcd(hcd);
	int		ret;
	int		rhport;
	int		changed = 0;
	unsigned long   flags;

	spin_lock_irqsave(&hub->lock, flags);

	pr_debug("%s %d\n", __func__, hub->id);

	ret = DIV_ROUND_UP(hub->device_count + 1, 8);
	memset(buf, 0, ret);

	if (!HCD_HW_ACCESSIBLE(hcd)) {
		pr_debug("hw accessible flag not on?\n");
	        spin_unlock_irqrestore(&hub->lock, flags);
		return 0;
	}

	/* TODO - dummy_hcd checks resuming here */

	/* check pseudo status register for each port */
	for (rhport = 0; rhport < hub->device_count; rhport++) {
		struct usbredir_device *udev = hub->devices + rhport;

		spin_lock(&udev->lock);
		if (udev->port_status &
			((USB_PORT_STAT_C_CONNECTION
			  | USB_PORT_STAT_C_ENABLE
			  | USB_PORT_STAT_C_SUSPEND
			  | USB_PORT_STAT_C_OVERCURRENT
			  | USB_PORT_STAT_C_RESET) << 16)) {

			/* The status of a port has been changed, */
			pr_debug("port %d status changed\n", rhport);

			buf[(rhport + 1) / 8] |= 1 << (rhport + 1) % 8;
			changed = 1;
		}
		spin_unlock(&udev->lock);
	}

	spin_unlock_irqrestore(&hub->lock, flags);

	if ((hcd->state == HC_STATE_SUSPENDED) && (changed == 1))
		usb_hcd_resume_root_hub(hcd);

	pr_debug("%s %schanged\n", __func__, changed ? "" : "un");

	return changed ? ret : 0;
}

static inline void usbredir_hub_descriptor(struct usbredir_hub *hub,
					   struct usb_hub_descriptor *desc)
{
	memset(desc, 0, sizeof(*desc));
	desc->bDescriptorType = USB_DT_HUB;
	desc->bDescLength = 9;
	desc->wHubCharacteristics = cpu_to_le16(
			HUB_CHAR_INDV_PORT_LPSM |
			HUB_CHAR_COMMON_OCPM);
	desc->bNbrPorts = hub->device_count;
	/* All ports un removable by default */
	desc->u.hs.DeviceRemovable[0] = 0xff;
	desc->u.hs.DeviceRemovable[1] = 0xff;
}

static int usbredir_hub_control(struct usb_hcd *hcd, u16 typeReq, u16 wValue,
			    u16 wIndex, char *buf, u16 wLength)
{
	struct usbredir_hub *hub;
	int             ret = 0;
	int		rhport;

	/* TODO - confirm this is still necessary */
	if (!HCD_HW_ACCESSIBLE(hcd))
		return -ETIMEDOUT;

	hub = usbredir_hub_from_hcd(hcd);
	/* TODO - spin lock irqsave */

	pr_debug("%s hub %d: ", __func__, hub->id);
	pr_debug("[wValue %x|wIndex%u|wLength %u]",
		 wValue, wIndex, wLength);

	/* wIndex is 1 based */
	rhport = ((__u8)(wIndex & 0x00ff)) - 1;

	/* TODO - dummy has SetHubDepth */
	/* TODO - dummy has DeviceRequest | USB_REQ_GET_DESCRIPTOR - USB3 */
	/* TODO - dummy has GetPortErrorcount */
	switch (typeReq) {
	case ClearHubFeature:
		pr_debug(" ClearHubFeature\n");
		break;
	case SetHubFeature:
		pr_debug(" SetHubFeature\n");
		ret = -EPIPE;
		break;
	case GetHubDescriptor:
		/* TODO - USB 3 */
		pr_debug(" GetHubDescriptor\n");
		usbredir_hub_descriptor(hub, (struct usb_hub_descriptor *) buf);
		break;
	case GetHubStatus:
		pr_debug(" GetHubStatus\n");
		*(__le32 *) buf = cpu_to_le32(0);
		break;
	case ClearPortFeature:
		pr_debug(" ClearPortFeature\n");
		return usbredir_device_clear_port_feature(hub, rhport, wValue);
	case SetPortFeature:
		pr_debug(" SetPortFeature\n");
		return usbredir_device_set_port_feature(hub, rhport, wValue);
	case GetPortStatus:
		pr_debug(" GetPortStatus\n");
		return usbredir_device_port_status(hub, rhport, buf);
	default:
		pr_debug(" unknown type %x\n", typeReq);
		pr_err("usbredir_hub_control: no handler for request %x\n",
		       typeReq);

		/* "protocol stall" on error */
		ret = -EPIPE;
	}

	/* TODO - dummy invokes a poll on certain status changes */
	return ret;
}

#ifdef CONFIG_PM
/* FIXME: suspend/resume */
static int usbredir_bus_suspend(struct usb_hcd *hcd)
{
	dev_dbg(&hcd->self.root_hub->dev, "%s\n", __func__);

	hcd->state = HC_STATE_SUSPENDED;

	return 0;
}

static int usbredir_bus_resume(struct usb_hcd *hcd)
{
	int rc = 0;

	dev_dbg(&hcd->self.root_hub->dev, "%s\n", __func__);

	if (!HCD_HW_ACCESSIBLE(hcd))
		rc = -ESHUTDOWN;
	else
		hcd->state = HC_STATE_RUNNING;
	return rc;
}
#else

#define usbredir_bus_suspend      NULL
#define usbredir_bus_resume       NULL
#endif


static void usbredir_release_hub_dev(struct device *dev)
{
	/* TODO - what do we need to implement here? */
	/* This is called to free memory when the last device ref is done */
	/* Question: can we forcibly remove a device without unloading our
	 * module? If so, then this may be our entry point. */
	pr_err("%s: not implemented\n", __func__);
}

static int usbredir_register_hub(struct usbredir_hub *hub)
{
	int ret;

	hub->pdev.name = driver_name;
	hub->pdev.id = hub->id;
	hub->pdev.dev.release = usbredir_release_hub_dev;

	ret = platform_device_register(&hub->pdev);
	if (ret) {
		pr_err("Unable to register platform device %d\n", hub->id);
		return ret;
	}

	return 0;
}

static void usbredir_unregister_hub(struct usbredir_hub *hub)
{
	platform_device_unregister(&hub->pdev);
}


static struct hc_driver usbredir_hc_driver = {
	.description	= driver_name,
	.product_desc	= driver_desc,
	.hcd_priv_size	= sizeof(struct usbredir_hub *),

	/* TODO = what other flags are available and what of USB3|SHARED? */
	.flags		= HCD_USB2,

	/* TODO - reset - aka setup? */
	.start		= usbredir_hcd_start,
	.stop		= usbredir_hcd_stop,

	.urb_enqueue	= usbredir_urb_enqueue,
	.urb_dequeue	= usbredir_urb_dequeue,

	.get_frame_number = usbredir_get_frame_number,

	.hub_status_data = usbredir_hub_status,
	.hub_control    = usbredir_hub_control,
	.bus_suspend	= usbredir_bus_suspend,
	.bus_resume	= usbredir_bus_resume,

	/* TODO - alloc/free streams? */
};


static int usbredir_create_hcd(struct usbredir_hub *hub)
{
	int ret;

	hub->hcd = usb_create_hcd(&usbredir_hc_driver, &hub->pdev.dev,
			     dev_name(&hub->pdev.dev));
	if (!hub->hcd) {
		pr_err("usb_create_hcd failed\n");
		return -ENOMEM;
	}

	hub->hcd->has_tt = 1;

	*((struct usbredir_hub **) hub->hcd->hcd_priv) = hub;

	ret = usb_add_hcd(hub->hcd, 0, 0);
	if (ret != 0) {
		pr_err("usb_add_hcd failed %d\n", ret);
		usb_put_hcd(hub->hcd);
		return ret;
	}

	return 0;
}

static void usbredir_destroy_hcd(struct usbredir_hub *hub)
{
	if (hub->hcd) {
		usb_remove_hcd(hub->hcd);
		usb_put_hcd(hub->hcd);
		hub->hcd = NULL;
	}
}

static struct usbredir_hub *usbredir_hub_create(void)
{
	struct usbredir_hub *hub;
	int id = atomic_inc_return(&hub_count);

	if (id > max_hubs)
		goto dec_exit;

	hub = kzalloc(sizeof(*hub), GFP_ATOMIC);
	if (!hub)
		goto dec_exit;
	hub->id = id - 1;

	if (usbredir_register_hub(hub)) {
		kfree(hub);
		goto dec_exit;
	}

	if (usbredir_create_hcd(hub)) {
		usbredir_unregister_hub(hub);
		kfree(hub);
		goto dec_exit;
	}

	spin_lock(&hubs_lock);
	list_add_tail(&hub->list, &hubs);
	spin_unlock(&hubs_lock);
	return hub;
dec_exit:
	atomic_dec(&hub_count);
	return NULL;
}

static void usbredir_hub_destroy(struct usbredir_hub *hub)
{
	usbredir_hub_stop(hub);
	usbredir_destroy_hcd(hub);
	usbredir_unregister_hub(hub);
}

struct usbredir_device *usbredir_hub_find_device(const char *devid)
{
	struct usbredir_device *ret = NULL;
	struct usbredir_hub *hub;
	int i;
	unsigned long flags;

	spin_lock(&hubs_lock);
	list_for_each_entry(hub, &hubs, list) {
		spin_lock_irqsave(&hub->lock, flags);
		for (i = 0; i < hub->device_count; i++) {
			struct usbredir_device *udev = hub->devices + i;

			spin_lock(&udev->lock);
			if (atomic_read(&udev->active) &&
			    udev->devid &&
			    strcmp(udev->devid, devid) == 0)
				ret = udev;
			spin_unlock(&udev->lock);
			if (ret)
				break;
		}
		spin_unlock_irqrestore(&hub->lock, flags);
		if (ret)
			break;
	}
	spin_unlock(&hubs_lock);
	return ret;
}

struct usbredir_device *usbredir_hub_allocate_device(const char *devid,
						     struct socket *socket)
{
	int found = 0;
	struct usbredir_hub *hub;
	struct usbredir_device *udev = NULL;
	int i;
	unsigned long flags;

	spin_lock(&hubs_lock);
	list_for_each_entry(hub, &hubs, list) {
		spin_lock_irqsave(&hub->lock, flags);
		for (i = 0; !found && i < hub->device_count; i++) {
			udev = hub->devices + i;
			spin_lock(&udev->lock);
			if (!atomic_read(&udev->active)) {
				atomic_set(&udev->active, 1);
				found++;
			}
			spin_unlock(&udev->lock);
		}
		spin_unlock_irqrestore(&hub->lock, flags);
		if (found)
			break;
	}
	spin_unlock(&hubs_lock);

	if (found) {
		usbredir_device_allocate(udev, devid, socket);
		return udev;
	}

	hub = usbredir_hub_create();
	if (!hub)
		return NULL;

	return usbredir_hub_allocate_device(devid, socket);
}

int usbredir_hub_show_global_status(char *out)
{
	int count = 0;
	int active = 0;
	int used = 0;
	unsigned long flags;

	struct usbredir_hub *hub;
	struct usbredir_device *udev;
	int i;

	spin_lock(&hubs_lock);
	list_for_each_entry(hub, &hubs, list) {
		spin_lock_irqsave(&hub->lock, flags);
		for (i = 0; i < hub->device_count; count++, i++) {
			udev = hub->devices + i;
			spin_lock(&udev->lock);
			active += atomic_read(&udev->active);
			if (udev->usb_dev)
				used++;
			spin_unlock(&udev->lock);
		}
		spin_unlock_irqrestore(&hub->lock, flags);
	}
	spin_unlock(&hubs_lock);

	sprintf(out, "%d/%d hubs. %d/%d devices (%d active, %d used).\n",
			atomic_read(&hub_count), max_hubs,
			count, max_hubs * devices_per_hub, active, used);

	return strlen(out);
}


void usbredir_hub_init(void)
{
	INIT_LIST_HEAD(&hubs);
	atomic_set(&hub_count, 0);
	spin_lock_init(&hubs_lock);
}

void usbredir_hub_exit(void)
{
	struct usbredir_hub *hub, *tmp;

	spin_lock(&hubs_lock);
	list_for_each_entry_safe(hub, tmp, &hubs, list) {
		usbredir_hub_destroy(hub);
		list_del(&hub->list);
		kfree(hub);
	}
	spin_unlock(&hubs_lock);
}
