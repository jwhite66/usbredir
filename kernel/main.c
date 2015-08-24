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

#include <linux/device.h>
#include <linux/platform_device.h>
#include <linux/usb.h>
#include <linux/module.h>

#include "usbredir.h"

#define DRIVER_NAME	"usbredir"
#define DRIVER_AUTHOR	"Jeremy White"
#define DRIVER_DESC	"USBREDIR Host Controller Driver"
#define DRIVER_VERSION	USBREDIR_MODULE_VERSION

const char driver_name[] = DRIVER_NAME;
const char driver_desc[] = DRIVER_DESC;


static struct platform_driver usbredir_driver = {
	.driver	= {
		.name = driver_name,
	},
	/* TODO - why not remove, suspend, and resume? */
};

static int __init usbredir_main_init(void)
{
	int ret;

	pr_debug("usbredir loaded\n");

	if (usb_disabled())
		return -ENODEV;

	if (devices_per_hub > USB_MAXCHILDREN) {
		pr_err("Error:  cannot use %d devices per hub; max %d\n",
		       devices_per_hub, USB_MAXCHILDREN);
		return -ENODEV;
	}


	ret = platform_driver_register(&usbredir_driver);
	if (ret) {
		pr_err("Unable to register usbredir_driver.\n");
		return ret;
	}

	usbredir_hub_init();

	ret = usbredir_sysfs_register(&usbredir_driver.driver);
	if (ret) {
		pr_err("Unable to create sysfs files for usbredir driver.\n");
		usbredir_hub_exit();
		platform_driver_unregister(&usbredir_driver);
		return ret;
	}

	return ret;
}

static void __exit usbredir_main_exit(void)
{
	usbredir_sysfs_unregister(&usbredir_driver.driver);
	usbredir_hub_exit();
	platform_driver_unregister(&usbredir_driver);
	pr_debug("usbredir exited\n");
}

unsigned int max_hubs = 64;
module_param(max_hubs, uint, S_IRUSR|S_IWUSR);
MODULE_PARM_DESC(max_hubs, "Maximum number of USB hubs to create; default 64");

unsigned int devices_per_hub = 16;
module_param(devices_per_hub, uint, S_IRUSR|S_IWUSR);
MODULE_PARM_DESC(devices_per_hub,
		"Maximum number of devices per hub; default 16");

module_init(usbredir_main_init);
module_exit(usbredir_main_exit);

MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_LICENSE("GPL");
MODULE_VERSION(DRIVER_VERSION);
