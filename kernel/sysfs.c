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
#include <linux/file.h>
#include <linux/net.h>

#include "usbredir.h"


static ssize_t status_show(struct device_driver *driver, char *out)
{
	return usbredir_hub_show_global_status(out);
}
static DRIVER_ATTR(status, S_IRUSR, status_show, NULL);

static ssize_t store_attach(struct device_driver *driver,
			    const char *buf, size_t count)
{
	struct socket *socket;
	int sockfd = 0;
	char devid[256];
	int err;

	/*
	 * usbredir sysfs attach file
	 * @sockfd: socket descriptor of an established TCP connection
	 * @devid: user supplied unique device identifier
	 */
	memset(devid, 0, sizeof(devid));
	if (sscanf(buf, "%u %255s", &sockfd, devid) != 2)
		return -EINVAL;

	pr_debug("attach sockfd(%u) devid(%s)\n", sockfd, devid);

	socket = sockfd_lookup(sockfd, &err);
	if (!socket)
		return -EINVAL;

	if (usbredir_hub_find_device(devid)) {
		pr_err("%s: already in use\n", devid);
		sockfd_put(socket);
		return -EINVAL;
	}

	if (!usbredir_hub_allocate_device(devid, socket)) {
		pr_err("%s: unable to create\n", devid);
		sockfd_put(socket);
		return -EINVAL;
	}

	return count;
}
static DRIVER_ATTR(attach, S_IWUSR, NULL, store_attach);


static ssize_t store_detach(struct device_driver *driver,
			    const char *buf, size_t count)
{
	char devid[256];
	struct usbredir_device *udev;

	/*
	 * usbredir sysfs detach file
	 * @devid: user supplied unique device identifier
	 */
	memset(devid, 0, sizeof(devid));
	if (sscanf(buf, "%255s", devid) != 1)
		return -EINVAL;

	pr_debug("detach devid(%s)\n", devid);

	udev = usbredir_hub_find_device(devid);
	if (!udev) {
		pr_warn("USBREDIR device %s detach requested, but not found\n",
			devid);
		return count;
	}

	usbredir_device_disconnect(udev);
	usbredir_device_deallocate(udev, true, true);

	return count;
}
static DRIVER_ATTR(detach, S_IWUSR, NULL, store_detach);


/**
 * usbredir_sysfs_register()
 * @driver	The platform driver associated with usbredir
 *
 * This function will register new sysfs files called 'attach', 'detach',
 * and 'status'.
 *
 * To start a new connection, a user space program should establish
 * a socket that is connected to a process that provides a USB device
 * and that speaks the USBREDIR protocol.  The usbredirserver program
 * is one such example.
 *
 * Next, the user space program should write that socket as well as a
 * unique device id of no more than 255 characters to the 'attach' file.
 * That should begin a connection.
 *
 * Writing the same id to the 'detach' file should end the connection,
 * and examining the contents of the 'status' file should show the number
 * of connections.
 *
 */
int usbredir_sysfs_register(struct device_driver *driver)
{
	int ret;

	ret = driver_create_file(driver, &driver_attr_status);
	if (ret)
		return ret;

	ret = driver_create_file(driver, &driver_attr_detach);
	if (ret)
		return ret;

	return driver_create_file(driver, &driver_attr_attach);
}

/**
 * usbredir_sysfs_unregister()
 * @dev The device driver associated with usbredir
 */
void usbredir_sysfs_unregister(struct device_driver *dev)
{
	driver_remove_file(dev, &driver_attr_status);
	driver_remove_file(dev, &driver_attr_detach);
	driver_remove_file(dev, &driver_attr_attach);
}

void usbredir_sysfs_expose_devid(struct usbredir_device *udev)
{
	char aname[32];

	sprintf(aname, "devid.%d", udev->rhport);
	udev->attr.attr.mode = S_IRUSR;
	udev->attr.attr.name = kstrdup(aname, GFP_ATOMIC);
	udev->attr.show = usbredir_device_devid;

	device_create_file(&udev->hub->pdev.dev, &udev->attr);
}

void usbredir_sysfs_remove_devid(struct usbredir_device *udev)
{
	device_remove_file(&udev->hub->pdev.dev, &udev->attr);
	kfree(udev->attr.attr.name);
}
