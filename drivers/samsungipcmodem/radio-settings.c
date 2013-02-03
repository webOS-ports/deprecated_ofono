/*
 *
 *  oFono - Open Source Telephony
 *
 *  Copyright (C) 2012 Simon Busch <morphis@gravedo.de>. All rights reserved.
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

#include <ofono/log.h>
#include <ofono/modem.h>
#include <ofono/radio-settings.h>

#include <glib.h>

#include "samsungipcmodem.h"
#include "ipc.h"
#include "util.h"

struct settings_data {
	struct ipc_device *device;
};

static void get_net_mode_sel_cb(uint16_t cmd, void *data, uint16_t length, uint8_t error, void *user_data)
{
	struct cb_data *cbd = user_data;
	ofono_radio_settings_rat_mode_query_cb_t cb = cbd->cb;
	struct ipc_net_mode_sel *resp = data;
	enum ofono_radio_access_mode mode;

	if (error) {
		CALLBACK_WITH_FAILURE(cb, -1, cbd->data);
		goto cleanup;
	}

	switch (resp->mode_sel) {
	case IPC_NET_MODE_SEL_GSM_UMTS:
		mode = OFONO_RADIO_ACCESS_MODE_ANY;
		break;
	case IPC_NET_MODE_SEL_GSM_ONLY:
		mode = OFONO_RADIO_ACCESS_MODE_GSM;
		break;
	case IPC_NET_MODE_SEL_UMTS_ONLY:
		mode = OFONO_RADIO_ACCESS_MODE_UMTS;
		break;
	default:
		CALLBACK_WITH_FAILURE(cb, -1, cbd->data);
		goto cleanup;
	}

	CALLBACK_WITH_SUCCESS(cb, mode, cbd->data);

cleanup:
	g_free(cbd);
}

static void samsungipc_query_rat_mode(struct ofono_radio_settings *rs,
				ofono_radio_settings_rat_mode_query_cb_t cb, void *data)
{
	struct settings_data *sd = ofono_radio_settings_get_data(rs);
	struct cb_data *cbd;

	cbd = cb_data_new(cb, data);

	if(ipc_device_enqueue_message(sd->device, IPC_NET_MODE_SEL, IPC_TYPE_GET,
						NULL, 0, get_net_mode_sel_cb, cbd) > 0)
		return;

	CALLBACK_WITH_FAILURE(cb, -1, cbd->data);
	g_free(cbd);
}

static void set_net_mode_sel_cb(uint16_t cmd, void *data, uint16_t length, uint8_t error, void *user_data)
{
	struct cb_data *cbd = user_data;
	ofono_radio_settings_rat_mode_set_cb_t cb = cbd->cb;
	struct ipc_gen_phone_res *resp = data;

	if (error || ipc_gen_phone_res_check(resp) < 0) {
		CALLBACK_WITH_FAILURE(cb, cbd->data);
	}
	else {
		CALLBACK_WITH_SUCCESS(cb, cbd->data);
	}

	g_free(cbd);
}

static void samsungipc_set_rat_mode(struct ofono_radio_settings *rs,
				enum ofono_radio_access_mode mode,
				ofono_radio_settings_rat_mode_set_cb_t cb, void *data)
{
	struct settings_data *sd = ofono_radio_settings_get_data(rs);
	struct cb_data *cbd;
	struct ipc_net_mode_sel *req;

	req = g_try_new0(struct ipc_net_mode_sel, 1);
	if (!req) {
		CALLBACK_WITH_FAILURE(cb, data);
		return;
	}

	cbd = cb_data_new(cb, data);

	switch (mode) {
	case OFONO_RADIO_ACCESS_MODE_ANY:
		req->mode_sel = IPC_NET_MODE_SEL_GSM_UMTS;
		break;
	case OFONO_RADIO_ACCESS_MODE_UMTS:
		req->mode_sel = IPC_NET_MODE_SEL_UMTS_ONLY;
		break;
	case OFONO_RADIO_ACCESS_MODE_LTE:
		goto error;
	case OFONO_RADIO_ACCESS_MODE_GSM:
		req->mode_sel = IPC_NET_MODE_SEL_GSM_ONLY;
		break;
	default:
		goto error;
	}

	if(ipc_device_enqueue_message(sd->device, IPC_NET_MODE_SEL, IPC_TYPE_SET,
						req, sizeof(struct ipc_net_mode_sel), set_net_mode_sel_cb, cbd) > 0)
		return;

error:
	CALLBACK_WITH_FAILURE(cb, cbd->data);
	g_free(cbd);
	g_free(req);
}

static int samsungipc_radio_settings_probe(struct ofono_radio_settings *rs,
					unsigned int vendor, void *user_data)
{
	struct settings_data *data;

	DBG("");

	data = g_new0(struct settings_data, 1);
	ofono_radio_settings_set_data(rs, data);

	data->device = user_data;

	ofono_radio_settings_register(rs);

	return 0;
}

static void samsungipc_radio_settings_remove(struct ofono_radio_settings *rs)
{
	struct settings_data *data = ofono_radio_settings_get_data(rs);

	DBG("");

	ofono_radio_settings_set_data(rs, NULL);

	g_free(data);
}

static struct ofono_radio_settings_driver driver = {
	.name		= "samsungipcmodem",
	.probe		= samsungipc_radio_settings_probe,
	.remove		= samsungipc_radio_settings_remove,
	.query_rat_mode		= samsungipc_query_rat_mode,
	.set_rat_mode		= samsungipc_set_rat_mode,
};

void samsungipc_radio_settings_init(void)
{
	ofono_radio_settings_driver_register(&driver);
}

void samsungipc_radio_settings_exit(void)
{
	ofono_radio_settings_driver_unregister(&driver);
}
