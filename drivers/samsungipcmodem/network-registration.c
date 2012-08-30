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

#define _GNU_SOURCE
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include <glib.h>

#include <ofono/log.h>
#include <ofono/modem.h>
#include <ofono/netreg.h>
#include <ofono/gprs-context.h>
#include <ofono/gprs-provision.h>

#include "samsungipcmodem.h"
#include "ipc.h"
#include "util.h"

struct netreg_data {
	struct ipc_device *device;
	guint status_watch;
	guint rssi_watch;
	guint time_watch;
	int strength;
	struct ofono_network_time time;
};

static void list_operators_cb(uint16_t cmd, void *data, uint16_t length, uint8_t error, void *user_data)
{
	struct cb_data *cbd = user_data;
	ofono_netreg_operator_list_cb_t cb = cbd->cb;
	struct ofono_network_operator *list;
	struct ofono_network_operator *op;
	struct ipc_net_plmn_entries *resp = data;
	struct ipc_net_plmn_entry *entries = data + sizeof(struct ipc_net_plmn_entries);
	struct ipc_net_plmn_entry *entry;
	int i;

	DBG("Got %d elements", resp->num);

	if (error) {
		CALLBACK_WITH_FAILURE(cb, 0, NULL, cbd->data);
		goto done;
	}

	list = g_try_new0(struct ofono_network_operator, resp->num);
	if (list == NULL) {
		CALLBACK_WITH_FAILURE(cb, 0, NULL, cbd->data);
		goto done;
	}

	for (i = 0; i < resp->num; i++) {
		op = &list[i];
		entry = &entries[i];

		op->status = entry->status - 1;

		strncpy(op->mcc, entry->plmn, 3);
		op->mcc[OFONO_MAX_MCC_LENGTH] = '\0';

		strncpy(op->mnc, entry->plmn + 3, 2);
		op->mnc[OFONO_MAX_MNC_LENGTH] = '\0';

		memset(op->name, 0, OFONO_MAX_OPERATOR_NAME_LENGTH);
	}

	CALLBACK_WITH_SUCCESS(cb, resp->num, list, cbd->data);

done:
	g_free(cbd);
}

static void samsungipc_list_operators(struct ofono_netreg *netreg,
				ofono_netreg_operator_list_cb_t cb, void *data)
{
	struct netreg_data *nd = ofono_netreg_get_data(netreg);
	struct cb_data *cbd = cb_data_new(cb, data);

	if(ipc_device_enqueue_message(nd->device, IPC_NET_PLMN_LIST, IPC_TYPE_GET,
						NULL, 0, list_operators_cb, cbd) > 0)
		return;

	g_free(cbd);

	CALLBACK_WITH_FAILURE(cb, 0, NULL, data);
}

static void samsungipc_signal_strength(struct ofono_netreg *netreg,
				ofono_netreg_strength_cb_t cb, void *data)
{
	struct netreg_data *nd = ofono_netreg_get_data(netreg);

	CALLBACK_WITH_SUCCESS(cb, nd->strength, data);
}

static void network_register_cb(uint16_t cmd, void *data, uint16_t length, uint8_t error, void *user_data)
{
	struct cb_data *cbd = user_data;
	ofono_netreg_register_cb_t cb = cbd->cb;
	struct ipc_gen_phone_res *resp = data;

	if (error || ipc_gen_phone_res_check(resp) < 0) {
		CALLBACK_WITH_FAILURE(cb, cbd->data);
		goto done;
	}

	CALLBACK_WITH_SUCCESS(cb, cbd->data);

done:
	g_free(cbd);
}

static void samsungipc_register_manual(struct ofono_netreg *netreg,
				const char *mcc, const char *mnc,
				ofono_netreg_register_cb_t cb, void *data)
{
	struct netreg_data *nd = ofono_netreg_get_data(netreg);
	struct cb_data *cbd;
	struct ipc_net_plmn_sel_set *req;
	char plmn[5];

	req = g_try_new0(struct ipc_net_plmn_sel_set, 1);
	if (!req) {
		CALLBACK_WITH_FAILURE(cb, data);
		return;
	}

	cbd = cb_data_new(cb, data);

	snprintf(plmn, 5, "%s%s", mcc, mnc);
	ipc_net_plmn_sel_set_setup(req, IPC_NET_PLMN_SEL_MANUAL, plmn,
						IPC_NET_ACCESS_TECHNOLOGY_UMTS);

	if(ipc_device_enqueue_message(nd->device, IPC_NET_PLMN_SEL, IPC_TYPE_SET,
						req, sizeof(struct ipc_net_plmn_sel_set),
						network_register_cb, cbd) > 0)
		return;

	g_free(cbd);

	CALLBACK_WITH_FAILURE(cb, data);
}

static void samsungipc_register_auto(struct ofono_netreg *netreg,
				ofono_netreg_register_cb_t cb, void *data)
{
	struct netreg_data *nd = ofono_netreg_get_data(netreg);
	struct cb_data *cbd;
	struct ipc_net_plmn_sel_set *req;

	req = g_try_new0(struct ipc_net_plmn_sel_set, 1);
	if (!req) {
		CALLBACK_WITH_FAILURE(cb, data);
		return;
	}

	cbd = cb_data_new(cb, data);

	ipc_net_plmn_sel_set_setup(req, IPC_NET_PLMN_SEL_AUTO, NULL,
						IPC_NET_ACCESS_TECHNOLOGY_UNKNOWN);

	if(ipc_device_enqueue_message(nd->device, IPC_NET_PLMN_SEL, IPC_TYPE_SET,
						req, sizeof(struct ipc_net_plmn_sel_set),
						network_register_cb, cbd) > 0)
		return;

	g_free(cbd);

	CALLBACK_WITH_FAILURE(cb, data);
}

static void current_operator_cb(uint16_t cmd, void *data, uint16_t length, uint8_t error, void *user_data)
{
	struct cb_data *cbd = user_data;
	ofono_netreg_operator_cb_t cb = cbd->cb;
	struct ipc_net_current_plmn_response *resp = data;
	struct ofono_network_operator op;
	GSList *apns;
	struct ofono_gprs_provision_data *ap;

	if (error) {
		CALLBACK_WITH_FAILURE(cb, NULL, cbd->data);
		goto done;
	}

	strncpy(op.mcc, resp->plmn, 3);
	op.mcc[OFONO_MAX_MCC_LENGTH] = '\0';

	strncpy(op.mnc, &resp->plmn[3], 2);
	op.mnc[OFONO_MAX_MCC_LENGTH-1] = '\0';

	memset(op.name, 0, OFONO_MAX_OPERATOR_NAME_LENGTH);

	/* Set to current */
	op.status = 2;

	/* workaround possible invalid values */
	op.tech = -1;
	if (resp->type >= 0 && resp->type <= 7)
		op.tech = resp->type;

	DBG("current_operator_cb: mcc=%s, mnc=%s, reg_state=%d, tech=%d, name=%s",
		op.mcc, op.mnc, op.status, op.tech, op.name);

	CALLBACK_WITH_SUCCESS(cb, &op, cbd->data);

done:
	g_free(cbd);
}

static void samsungipc_current_operator(struct ofono_netreg *netreg,
				ofono_netreg_operator_cb_t cb, void *data)
{
	struct netreg_data *nd = ofono_netreg_get_data(netreg);
	struct cb_data *cbd = cb_data_new(cb, data);

	if(ipc_device_enqueue_message(nd->device, IPC_NET_CURRENT_PLMN, IPC_TYPE_GET,
						NULL, 0, current_operator_cb, cbd) > 0)
		return;

	CALLBACK_WITH_FAILURE(cb, NULL, data);

	g_free(cbd);
}

static void net_status_cb(uint16_t cmd, void *data, uint16_t length, uint8_t error, void *user_data)
{
	struct cb_data *cbd = user_data;
	ofono_netreg_status_cb_t cb = cbd->cb;
	struct ipc_net_regist_response *resp = data;

	if (error) {
		CALLBACK_WITH_FAILURE(cb, -1, -1, -1, -1, cbd->data);
		goto done;
	}

	DBG("reg_state=%i, lac=%i, cid=%i, act=%i", resp->reg_state - 1,
		resp->lac, resp->cid, resp->act);

	CALLBACK_WITH_SUCCESS(cb, resp->reg_state - 1, resp->lac,
					resp->cid, resp->act, cbd->data);

done:
	g_free(cbd);
}

static void samsungipc_registration_status(struct ofono_netreg *netreg,
					ofono_netreg_status_cb_t cb,
					void *data)
{
	struct netreg_data *nd = ofono_netreg_get_data(netreg);
	struct cb_data *cbd;
	struct ipc_net_regist_get *req;

	req = g_try_new0(struct ipc_net_regist_get, 1);
	if (!req) {
		CALLBACK_WITH_FAILURE(cb, -1, -1, -1, -1, data);
		return;
	}

	cbd = cb_data_new(cb, data);

	ipc_net_regist_get_setup(req, IPC_NET_SERVICE_DOMAIN_GSM);

	if(ipc_device_enqueue_message(nd->device, IPC_NET_REGIST, IPC_TYPE_GET,
						req, sizeof(struct ipc_net_regist_get),
						net_status_cb, cbd) > 0)
		return;

	CALLBACK_WITH_FAILURE(cb, -1, -1, -1, -1, data);

	g_free(cbd);
}

static void notify_status_cb(uint16_t cmd, void *data, uint16_t length, void *user_data)
{
	struct ofono_netreg *netreg = user_data;
	struct ipc_net_regist_response *resp = data;
	int act = -1;

	if (resp->domain == IPC_NET_SERVICE_DOMAIN_GPRS)
		return;

	DBG("reg_state=%i, lac=%i, cid=%i, act=%i", resp->reg_state - 1,
		resp->lac, resp->cid, resp->act);

	/* workaround wrong values */
	if (resp->act >= 0 && resp->act <= 7)
		act = resp->act;

	ofono_netreg_status_notify(netreg, resp->reg_state - 1,
							resp->lac, resp->cid, act);
}

static int convert_signal_strength(unsigned char rssi)
{
	int strength = 0;

	if (rssi < 0x6f)
		strength = ((((rssi - 0x71) * -1) - (((rssi - 0x71) * -1) % 2)) / 2);

	if (strength > 31)
		strength = 31;

	return ((strength * 100) / (31));
}

static void notify_rssi_cb(uint16_t cmd, void *data, uint16_t length, void *user_data)
{
	struct ofono_netreg *netreg = user_data;
	struct netreg_data *nd = ofono_netreg_get_data(netreg);
	struct ipc_disp_rssi_info *resp = data;

	nd->strength = convert_signal_strength(resp->rssi);

	DBG("rssi=%i, strength=%i", resp->rssi, nd->strength);

	ofono_netreg_strength_notify(netreg, nd->strength);
}

static void notify_time_info_cb(uint16_t cmd, void *data, uint16_t length, void *user_data)
{
	struct ofono_netreg *netreg = user_data;
	struct netreg_data *nd = ofono_netreg_get_data(netreg);
	struct ipc_misc_time_info *resp = data;

	nd->time.sec = resp->sec;
	nd->time.min = resp->min;
	nd->time.hour = resp->hour;
	nd->time.mday = resp->day;
	nd->time.mon = resp->mon;
	nd->time.year = resp->year;

	nd->time.utcoff = resp->tz * 15 * 60;

	ofono_netreg_time_notify(netreg, &nd->time);
}

static void initial_status_cb(uint16_t cmd, void *data, uint16_t length, void *user_data)
{
	struct ofono_netreg *netreg = user_data;
	struct ipc_net_regist_response *resp = data;
	struct netreg_data *nd = ofono_netreg_get_data(netreg);

	ofono_netreg_register(netreg);

	ofono_netreg_status_notify(netreg, resp->reg_state - 1,
							resp->lac, resp->cid, resp->act);

	ipc_device_remove_watch(nd->device, nd->status_watch);

	nd->status_watch = ipc_device_add_notifcation_watch(nd->device, IPC_NET_REGIST,
								notify_status_cb, netreg);

	nd->rssi_watch = ipc_device_add_notifcation_watch(nd->device, IPC_DISP_RSSI_INFO,
													notify_rssi_cb, netreg);

	nd->time_watch = ipc_device_add_notifcation_watch(nd->device, IPC_MISC_TIME_INFO,
												notify_time_info_cb, netreg);
}

static int samsungipc_netreg_probe(struct ofono_netreg *netreg, unsigned int vendor,
				void *data)
{
	struct netreg_data *nd;

	nd = g_new0(struct netreg_data, 1);
	if (!nd)
		return -ENOMEM;

	nd->device = data;
	nd->strength = 0;

	ofono_netreg_set_data(netreg, nd);

	nd->status_watch = ipc_device_add_notifcation_watch(nd->device, IPC_NET_REGIST,
												initial_status_cb, netreg);

	return 0;
}

static void samsungipc_netreg_remove(struct ofono_netreg *netreg)
{
	struct netreg_data *nd = ofono_netreg_get_data(netreg);

	ipc_device_remove_watch(nd->device, nd->status_watch);
	ipc_device_remove_watch(nd->device, nd->rssi_watch);
	ipc_device_remove_watch(nd->device, nd->time_watch);

	ofono_netreg_set_data(netreg, NULL);

	g_free(nd);
}

static struct ofono_netreg_driver driver = {
	.name					= "samsungipcmodem",
	.probe					= samsungipc_netreg_probe,
	.remove					= samsungipc_netreg_remove,
	.registration_status	= samsungipc_registration_status,
	.current_operator		= samsungipc_current_operator,
	.register_auto			= samsungipc_register_auto,
	.register_manual		= samsungipc_register_manual,
	.strength				= samsungipc_signal_strength,
	.list_operators			= samsungipc_list_operators,
};

void samsungipc_netreg_init(void)
{
	ofono_netreg_driver_register(&driver);
}

void samsungipc_netreg_exit(void)
{
	ofono_netreg_driver_unregister(&driver);
}
