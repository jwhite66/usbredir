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

#include <linux/kthread.h>

#include "usbredir.h"

int usbredir_rx_loop(void *data)
{
	struct usbredir_device *udev = data;
	int rc;

	while (!kthread_should_stop() && atomic_read(&udev->active)) {
		rc = usbredirparser_do_read(udev->parser);
		if (rc != -EAGAIN) {
			pr_info("usbredir/rx:%d connection closed\n",
				udev->rhport);
			break;
		}
	}

	pr_debug("%s exit\n", __func__);

	usbredir_device_disconnect(udev);
	usbredir_device_deallocate(udev, false, true);

	return 0;
}
