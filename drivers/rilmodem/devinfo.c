/*
 *
 *  oFono - Open Source Telephony - RIL Modem Support
 *
 *  Copyright (C) 2008-2011  Intel Corporation. All rights reserved.
 *  Copyright (C) 2012 Canonical Ltd.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <glib.h>

#include <ofono/log.h>
#include <ofono/modem.h>
#include <ofono/devinfo.h>

#include "gril.h"

#include "rilmodem.h"

/*
 * TODO: The functions in this file are stubbed out, and
 * will need to be re-worked to talk to the /gril layer
 * in order to get real values from RILD.
 */

static void ril_query_manufacturer(struct ofono_devinfo *info,
					ofono_devinfo_query_cb_t cb,
					void *data)
{
	const char *attr = "Fake Manufacturer";
	struct cb_data *cbd = cb_data_new(cb, data);
	struct ofono_error error;
	decode_ril_error(&error, "OK");

	cb(&error, attr, cbd->data);

	/* Note: this will need to change if cbd passed to gril layer */
	g_free(cbd);
}

static void ril_query_model(struct ofono_devinfo *info,
				ofono_devinfo_query_cb_t cb,
				void *data)
{
	const char *attr = "Fake Modem Model";
	struct cb_data *cbd = cb_data_new(cb, data);
	struct ofono_error error;
	decode_ril_error(&error, "OK");

	cb(&error, attr, cbd->data);

	/* Note: this will need to change if cbd passed to gril layer */
	g_free(cbd);
}

static void ril_query_revision(struct ofono_devinfo *info,
				ofono_devinfo_query_cb_t cb,
				void *data)
{
	const char *attr = "Fake Revision";
	struct cb_data *cbd = cb_data_new(cb, data);
	struct ofono_error error;
	decode_ril_error(&error, "OK");

	cb(&error, attr, cbd->data);

	/* Note: this will need to change if cbd passed to gril layer */
	g_free(cbd);
}

static void ril_query_serial(struct ofono_devinfo *info,
				ofono_devinfo_query_cb_t cb,
				void *data)
{
	const char *attr = "THIS-IS-A-FAKE-SERIAL-NO";
	struct cb_data *cbd = cb_data_new(cb, data);
	struct ofono_error error;
	decode_ril_error(&error, "OK");

	cb(&error, attr, cbd->data);

	/* Note: this will need to change if cbd passed to gril layer */
	g_free(cbd);
}

static gboolean ril_delayed_register(gpointer user_data)
{
	struct ofono_devinfo *info = user_data;
	DBG("");
	ofono_devinfo_register(info);

	/* This makes the timeout a single-shot */
	return FALSE;
}

static int ril_devinfo_probe(struct ofono_devinfo *info, unsigned int vendor,
				void *data)
{
	GRil *ril = NULL;

	if (data != NULL)
		ril = g_ril_clone(data);

	ofono_devinfo_set_data(info, ril);

	DBG("");

        /*
	 * TODO: analyze if capability check is needed
	 * and/or timer should be adjusted.
	 *
	 * ofono_devinfo_register() needs to be called after
	 * the driver has been set in ofono_devinfo_create(),
	 * which calls this function.  Most other drivers make
	 * some kind of capabilities query to the modem, and then
	 * call register in the callback; we use a timer instead.
	 */
        g_timeout_add_seconds(1, ril_delayed_register, info);

	return 0;
}

static void ril_devinfo_remove(struct ofono_devinfo *info)
{
	GRil *ril = ofono_devinfo_get_data(info);

	ofono_devinfo_set_data(info, NULL);

	g_ril_unref(ril);
}

static struct ofono_devinfo_driver driver = {
	.name			= "rilmodem",
	.probe			= ril_devinfo_probe,
	.remove			= ril_devinfo_remove,
	.query_manufacturer	= ril_query_manufacturer,
	.query_model		= ril_query_model,
	.query_revision		= ril_query_revision,
	.query_serial		= ril_query_serial
};

void ril_devinfo_init(void)
{
	ofono_devinfo_driver_register(&driver);
}

void ril_devinfo_exit(void)
{
	ofono_devinfo_driver_unregister(&driver);
}
