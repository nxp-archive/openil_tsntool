// SPDX-License-Identifier: (GPL-2.0 OR MIT)
/*
 * Copyright 2018 NXP
 */

#include <unistd.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/netlink.h>
#include <main.h>
#include "tsn/genl_tsn.h"

int tsn_qci_streampara_get(struct tsn_qci_psfp_stream_param *sp)
{
	return -1;
}

/* tsn_cb_streamid_set()
 * To set the stream identify status as spec 8021CB clause 6
 * portname: port name of the net device
 * sid_index: index of the stream identify table
 * enable:	1: set the stream identify table enable work.
 *			0: set hte stream identify table disable/delete work.
 * sid: structure of stream identify tables parameters
 *		which should malloc from up layer and input values for setting
 * return: < 0 error, 0 is ok, all values set to device
 */
int tsn_cb_streamid_set(char *portname, uint32_t sid_index, bool enable,
		struct tsn_cb_streamid *sid)
{
	struct msgtemplate *msg;
	struct nlattr *sidattr;
	int ret;

	if ((sid == NULL) && enable)
		return -1;

	if (portname == NULL)
		return -1;

	msg = tsn_send_cmd_prepare(TSN_CMD_CB_STREAMID_SET);
	if (msg == NULL) {
		loge("fail to allocate genl msg.\n");
		return -1;
	}

	tsn_send_cmd_append_attr(msg, TSN_ATTR_IFNAME, portname, strlen(portname) + 1);

	sidattr = tsn_nla_nest_start(msg, TSN_ATTR_STREAM_IDENTIFY);
	if (!sidattr)
		goto err;

	tsn_send_cmd_append_attr(msg, TSN_STREAMID_ATTR_INDEX, &sid_index, sizeof(sid_index));

	/* If disable the stream filter instance just send disable ATTR */
	if (!enable) {
		tsn_send_cmd_append_attr(msg, TSN_STREAMID_ATTR_DISABLE, &enable, 0);
		goto sendmsg1;
	} else if (enable == 1) {
		tsn_send_cmd_append_attr(msg, TSN_STREAMID_ATTR_ENABLE, &enable, 0);
	}

	tsn_send_cmd_append_attr(msg, TSN_STREAMID_ATTR_STREAM_HANDLE,
			&(sid->handle), sizeof(sid->handle));
	tsn_send_cmd_append_attr(msg, TSN_STREAMID_ATTR_SSID,
			&(sid->ssid), sizeof(sid->ssid));
	tsn_send_cmd_append_attr(msg, TSN_STREAMID_ATTR_IFOP,
			&(sid->ifac_oport), sizeof(sid->ifac_oport));
	tsn_send_cmd_append_attr(msg, TSN_STREAMID_ATTR_OFOP,
			&(sid->ofac_oport), sizeof(sid->ofac_oport));
	tsn_send_cmd_append_attr(msg, TSN_STREAMID_ATTR_IFIP,
			&(sid->ifac_iport), sizeof(sid->ifac_iport));
	tsn_send_cmd_append_attr(msg, TSN_STREAMID_ATTR_OFIP,
			&(sid->ofac_iport), sizeof(sid->ofac_iport));

	switch (sid->type) {
	case STREAMID_NULL:
		tsn_send_cmd_append_attr(msg, TSN_STREAMID_ATTR_NDMAC,
				&(sid->para.nid.dmac), sizeof(sid->para.nid.dmac));
		printf("null stream identify, tagged is %x\n", sid->para.nid.tagged);
		if ((sid->para.nid.tagged > 3) || (!sid->para.nid.tagged))
			sid->para.nid.tagged = 3;
		tsn_send_cmd_append_attr(msg, TSN_STREAMID_ATTR_NTAGGED,
				&(sid->para.nid.tagged), sizeof(sid->para.nid.tagged));
		tsn_send_cmd_append_attr(msg, TSN_STREAMID_ATTR_NVID,
				&(sid->para.nid.vid), sizeof(sid->para.nid.vid));
		break;
	case STREAMID_SMAC_VLAN:
		tsn_send_cmd_append_attr(msg, TSN_STREAMID_ATTR_SMAC,
				&(sid->para.sid.smac), sizeof(sid->para.sid.smac));
	printf("source stream identify, tagged is %x\n", sid->para.sid.tagged);
		if ((sid->para.nid.tagged > 3) || (!sid->para.nid.tagged))
			sid->para.nid.tagged = 3;
		tsn_send_cmd_append_attr(msg, TSN_STREAMID_ATTR_STAGGED,
				&(sid->para.sid.tagged), sizeof(sid->para.sid.tagged));
		tsn_send_cmd_append_attr(msg, TSN_STREAMID_ATTR_SVID,
				&(sid->para.sid.vid), sizeof(sid->para.sid.vid));
		break;
	case STREAMID_DMAC_VLAN:
	case STREAMID_IP:
	default:
		loge("error streamid type: only null stream identify supported now");
		goto err;
	}

	tsn_send_cmd_append_attr(msg, TSN_STREAMID_ATTR_TYPE,
			&(sid->type), sizeof(sid->type));

sendmsg1:
	tsn_nla_nest_end(msg, sidattr);

	ret = tsn_send_to_kernel(msg);
	if (ret < 0) {
		loge("genl send to kernel error\n");
		return -1;
	}

	tsn_msg_recv_analysis();

	return 0;

err:
	free(msg);
	return -1;
}

/* tsn_cb_streamid_get()
 * To get the stream identify status as spec 8021CB clause 6
 * portname: port name of the net device
 * sid_index: index of the stream identify table
 * sid: structure of stream identify tables parameters
 *		which should malloc from up layer
 * return: < 0 error, 0 is ok, all values input to sid
 */
int tsn_cb_streamid_get(char *portname, uint32_t sid_index, struct tsn_cb_streamid *sid)
{
	struct msgtemplate *msg;
	struct nlattr *sidattr;
	int ret;

	if (portname == NULL)
		return -1;

	if (sid == NULL) {
		loge("error: please allocate the struct tsn_cb_streamid ");
		return -1;
	}

	msg = tsn_send_cmd_prepare(TSN_CMD_CB_STREAMID_GET);
	if (msg == NULL) {
		loge("fail to allocate genl msg.\n");
		return -1;
	}

	tsn_send_cmd_append_attr(msg, TSN_ATTR_IFNAME, portname, strlen(portname) + 1);

	sidattr = tsn_nla_nest_start(msg, TSN_ATTR_STREAM_IDENTIFY);
	if (!sidattr)
		goto err;

	tsn_send_cmd_append_attr(msg, TSN_STREAMID_ATTR_INDEX, &sid_index, sizeof(sid_index));

	tsn_nla_nest_end(msg, sidattr);

	ret = tsn_send_to_kernel(msg);
	if (ret < 0) {
		loge("genl send to kernel error\n");
		return -1;
	}

	/* TODO : fill the sid */

	tsn_msg_recv_analysis();

	return 0;

err:
	free(msg);
	return -1;
}

/* tsn_qci_psfp_sfi_set()
 * Add a stream filter instance table.
 *
 * portname: which port to add psfp sfi.
 *
 * sfi_handle: the number of stream filter instances
 *
 * enable: 1: enable , 0: disable
 *
 * sfi:	struct tsn_qci_psfp_sfi_conf add the stream filter instance,
 *		hardware will assign a stream filter instance ID.
 *
 * return: = 0 will successfully run , -1 get error.
 */
int tsn_qci_psfp_sfi_set(char *portname, uint32_t sfi_handle, bool enable,
						struct tsn_qci_psfp_sfi_conf *sfi)
{
	struct msgtemplate *msg;
	struct nlattr *qcisfi;
	int ret;

	if ((sfi == NULL) && enable)
		return -1;

	if (portname == NULL)
		return -1;

	msg = tsn_send_cmd_prepare(TSN_CMD_QCI_SFI_SET);
	if (msg == NULL) {
		loge("fail to allocate genl msg.\n");
		return -1;
	}

	tsn_send_cmd_append_attr(msg, TSN_ATTR_IFNAME, portname, strlen(portname) + 1);

	qcisfi = tsn_nla_nest_start(msg, TSN_ATTR_QCI_SFI);
	if (!qcisfi)
		goto err;

	tsn_send_cmd_append_attr(msg, TSN_QCI_SFI_ATTR_INDEX, &sfi_handle, sizeof(sfi_handle));

	/* If disable the stream filter instance just send disable ATTR */
	if (!enable) {
		tsn_send_cmd_append_attr(msg, TSN_QCI_SFI_ATTR_DISABLE, &enable, 0);
		goto sendmsg1;
	} else {
		tsn_send_cmd_append_attr(msg, TSN_QCI_SFI_ATTR_ENABLE, &enable, 0);
	}

	if (sfi->stream_handle_spec >= 0)
		tsn_send_cmd_append_attr(msg, TSN_QCI_SFI_ATTR_STREAM_HANDLE,
			&(sfi->stream_handle_spec), sizeof(sfi->stream_handle_spec));

	if (sfi->priority_spec >= 0)
		tsn_send_cmd_append_attr(msg, TSN_QCI_SFI_ATTR_PRIO_SPEC,
			&(sfi->priority_spec), sizeof(sfi->priority_spec));

	tsn_send_cmd_append_attr(msg, TSN_QCI_SFI_ATTR_GATE_ID,
			&(sfi->stream_gate_instance_id), sizeof(sfi->stream_gate_instance_id));

	if (sfi->stream_filter.maximum_sdu_size)
		tsn_send_cmd_append_attr(msg, TSN_QCI_SFI_ATTR_MAXSDU,
				&(sfi->stream_filter.maximum_sdu_size),
				sizeof(sfi->stream_filter.maximum_sdu_size));

	if (sfi->stream_filter.flow_meter_instance_id >= 0)
		tsn_send_cmd_append_attr(msg, TSN_QCI_SFI_ATTR_FLOW_ID,
				&(sfi->stream_filter.flow_meter_instance_id),
				sizeof(sfi->stream_filter.flow_meter_instance_id));

	if (sfi->block_oversize_enable) {
		tsn_send_cmd_append_attr(msg, TSN_QCI_SFI_ATTR_OVERSIZE_ENABLE,
				&(sfi->block_oversize_enable), 0);
		if (sfi->block_oversize)
			tsn_send_cmd_append_attr(msg, TSN_QCI_SFI_ATTR_OVERSIZE,
				&(sfi->block_oversize), 0);
	}

sendmsg1:
	tsn_nla_nest_end(msg, qcisfi);

	ret = tsn_send_to_kernel(msg);
	if (ret < 0) {
		loge("genl send to kernel error\n");
		return -1;
	}

	tsn_msg_recv_analysis();

	return 0;

err:
	free(msg);
	return -1;
}

/* tsn_qci_psfp_sfi_get()
 * Get a stream filter instance table.
 *
 * portname: which port to get psfp sfi.
 *
 * sfi_handle: the number of stream filter instances
 *
 * sfi:	struct tsn_qci_psfp_sfi_conf add the stream filter instance,
 *		hardware will assign a stream filter instance ID.
 *
 * return: = 0 will successfully run , -1 get error.
 */
int tsn_qci_psfp_sfi_get(char *portname, uint32_t sfi_handle,
						struct tsn_qci_psfp_sfi_conf *sfi)
{
	struct msgtemplate *msg;
	struct nlattr *qcisfi;
	int ret;

	if (portname == NULL)
		return -1;

	msg = tsn_send_cmd_prepare(TSN_CMD_QCI_SFI_GET);
	if (msg == NULL) {
		loge("fail to allocate genl msg.\n");
		return -1;
	}

	tsn_send_cmd_append_attr(msg, TSN_ATTR_IFNAME, portname, strlen(portname) + 1);

	qcisfi = tsn_nla_nest_start(msg, TSN_ATTR_QCI_SFI);
	if (!qcisfi)
		goto err;

	tsn_send_cmd_append_attr(msg, TSN_QCI_SFI_ATTR_INDEX, &sfi_handle, sizeof(sfi_handle));

	tsn_nla_nest_end(msg, qcisfi);

	ret = tsn_send_to_kernel(msg);
	if (ret < 0) {
		loge("genl send to kernel error\n");
		return -1;
	}

	/* TODO: receive the feedback and return */
	tsn_msg_recv_analysis();

	return 0;

err:
	free(msg);
	return -1;
}

/* tsn_qci_psfp_sfi_counters_get()
 * Get a stream filter instance table.
 *
 * portname: which port to get psfp sfi.
 *
 * sfi_handle: the number of stream filter instances
 *
 * sfi:	struct tsn_qci_psfp_sfi_counters  the stream filter instance counters fill in,
 *
 * return: = 0 will successfully run , -1 get error.
 */
int tsn_qci_psfp_sfi_counters_get(char *portname, uint32_t sfi_handle,
						struct tsn_qci_psfp_sfi_counters *sfic)
{
	struct msgtemplate *msg;
	struct nlattr *qcisfi;
	int ret;

	if (portname == NULL)
		return -1;

	msg = tsn_send_cmd_prepare(TSN_CMD_QCI_SFI_GET_COUNTS);
	if (msg == NULL) {
		loge("fail to allocate genl msg.\n");
		return -1;
	}

	tsn_send_cmd_append_attr(msg, TSN_ATTR_IFNAME, portname, strlen(portname) + 1);

	qcisfi = tsn_nla_nest_start(msg, TSN_ATTR_QCI_SFI);
	if (!qcisfi)
		goto err;

	tsn_send_cmd_append_attr(msg, TSN_QCI_SFI_ATTR_INDEX, &sfi_handle, sizeof(sfi_handle));

	tsn_nla_nest_end(msg, qcisfi);

	ret = tsn_send_to_kernel(msg);
	if (ret < 0) {
		loge("genl send to kernel error\n");
		return -1;
	}

	/* TODO: receive the feedback and return */
	tsn_msg_recv_analysis();

	return 0;

err:
	free(msg);
	return -1;
}

int tsn_qci_psfp_sgi_set(char *portname, uint32_t sgi_handle, bool enable,
						struct tsn_qci_psfp_sgi_conf *sgi)
{
	struct msgtemplate *msg;
	struct nlattr *conf, *admin, *entry;
	struct tsn_qci_psfp_gcl *gcl;
	int ret;
	uint32_t i = 0;
	uint8_t listcount;
	uint32_t cycle = 0;

	if ((sgi == NULL) && enable)
		return -1;

	if (portname == NULL)
		return -1;

	msg = tsn_send_cmd_prepare(TSN_CMD_QCI_SGI_SET);
	if (msg == NULL) {
		loge("fail to allocate genl msg.\n");
		return -1;
	}

	tsn_send_cmd_append_attr(msg, TSN_ATTR_IFNAME, portname, strlen(portname) + 1);

	conf = tsn_nla_nest_start(msg, TSN_ATTR_QCI_SGI);

	tsn_send_cmd_append_attr(msg, TSN_QCI_SGI_ATTR_INDEX, &sgi_handle, sizeof(sgi_handle));

	if (!enable) {
		tsn_send_cmd_append_attr(msg, TSN_QCI_SGI_ATTR_DISABLE, &enable, 0);
		goto out2;
	} else
		tsn_send_cmd_append_attr(msg, TSN_QCI_SGI_ATTR_ENABLE, &enable, 0);

	/* Other config parameters */
	if (sgi->config_change)
		tsn_send_cmd_append_attr(msg, TSN_QCI_SGI_ATTR_CONFCHANGE,
				&(sgi->config_change), 0);

	if (sgi->block_invalid_rx_enable)
		tsn_send_cmd_append_attr(msg, TSN_QCI_SGI_ATTR_IRXEN,
				&(sgi->block_invalid_rx_enable), 0);

	if (sgi->block_invalid_rx)
		tsn_send_cmd_append_attr(msg, TSN_QCI_SGI_ATTR_IRX,
				&(sgi->block_invalid_rx), 0);

	if (sgi->block_octets_exceeded_enable)
		tsn_send_cmd_append_attr(msg, TSN_QCI_SGI_ATTR_OEXEN,
				&(sgi->block_octets_exceeded_enable), 0);

	if (sgi->block_octets_exceeded)
		tsn_send_cmd_append_attr(msg, TSN_QCI_SGI_ATTR_OEX,
				&(sgi->block_octets_exceeded), 0);

	/* Add list control parameters */
	admin = tsn_nla_nest_start(msg, TSN_QCI_SGI_ATTR_ADMINENTRY);

	if (sgi->admin.gate_states)
		tsn_send_cmd_append_attr(msg, TSN_SGI_ATTR_CTRL_INITSTATE,
				&(sgi->admin.gate_states), 0);

	tsn_send_cmd_append_attr(msg, TSN_SGI_ATTR_CTRL_CYTIMEEX,
			&(sgi->admin.cycle_time_extension),	sizeof(sgi->admin.cycle_time_extension));

	tsn_send_cmd_append_attr(msg, TSN_SGI_ATTR_CTRL_BTIME,
			&(sgi->admin.base_time), sizeof(sgi->admin.base_time));

	if (sgi->admin.init_ipv >= 0)
		tsn_send_cmd_append_attr(msg, TSN_SGI_ATTR_CTRL_INITIPV,
			&(sgi->admin.init_ipv), sizeof(sgi->admin.init_ipv));

	listcount = sgi->admin.control_list_length;
	if (!listcount)
		goto out1;

	if (sgi->admin.gcl == NULL) {
		loge("error: list lenghth is not zero, but no gate control list\n");
		return -1;
	}

	gcl = sgi->admin.gcl;

	for (i = 0; i < listcount; i++) {
		int8_t ipv;
		uint32_t ti, omax;

		if ((gcl + i) == NULL) {
			loge("Could not get as many as gate list entry compare control_list_length");
			return -1;
		}

		entry = tsn_nla_nest_start(msg, TSN_SGI_ATTR_CTRL_GCLENTRY);

		ipv = (gcl + i)->ipv;
		ti = (gcl + i)->time_interval;
		omax = (gcl + i)->octet_max;

		if ((gcl + i)->gate_state)
			tsn_send_cmd_append_attr(msg, TSN_SGI_ATTR_GCL_GATESTATE, &((gcl + i)->gate_state), 0);
		tsn_send_cmd_append_attr(msg, TSN_SGI_ATTR_GCL_IPV, &ipv, sizeof(ipv));
		tsn_send_cmd_append_attr(msg, TSN_SGI_ATTR_GCL_INTERVAL, &ti, sizeof(ti));
		tsn_send_cmd_append_attr(msg, TSN_SGI_ATTR_GCL_OCTMAX, &omax, sizeof(omax));
		cycle += ti;
		printf("tsn: gate: %d  ipv: %d  time: %d octet: %d\n", (gcl + i)->gate_state,
				ipv, ti, omax);
		tsn_nla_nest_end(msg, entry);
	}

	if (cycle > sgi->admin.cycle_time)
		sgi->admin.cycle_time = cycle;
	tsn_send_cmd_append_attr(msg, TSN_SGI_ATTR_CTRL_CYTIME,
			&(sgi->admin.cycle_time), sizeof(sgi->admin.cycle_time));

	tsn_send_cmd_append_attr(msg, TSN_SGI_ATTR_CTRL_LEN, &listcount, sizeof(listcount));

out1:
	tsn_nla_nest_end(msg, admin);
out2:

	tsn_nla_nest_end(msg, conf);

	ret = tsn_send_to_kernel(msg);
	if (ret < 0) {
		loge("genl send to kernel error\n");
		free(msg);
		return -1;
	}

	tsn_msg_recv_analysis();

	return 0;
}

int tsn_qci_psfp_sgi_get(char *portname, uint32_t sgi_handle, struct tsn_qci_psfp_sgi_conf *sgi)
{
	struct msgtemplate *msg;
	struct nlattr *sgiattr;
	int ret;

	if (portname == NULL)
		return -1;

	msg = tsn_send_cmd_prepare(TSN_CMD_QCI_SGI_GET);
	if (msg == NULL) {
		loge("fail to allocate genl msg.\n");
		return -1;
	}

	tsn_send_cmd_append_attr(msg, TSN_ATTR_IFNAME, portname, strlen(portname) + 1);

	sgiattr = tsn_nla_nest_start(msg, TSN_ATTR_QCI_SGI);
	if (!sgiattr)
		goto err;

	tsn_send_cmd_append_attr(msg, TSN_QCI_SGI_ATTR_INDEX, &sgi_handle, sizeof(sgi_handle));

	tsn_nla_nest_end(msg, sgiattr);

	ret = tsn_send_to_kernel(msg);
	if (ret < 0) {
		loge("genl send to kernel error\n");
		return -1;
	}

	/* TODO: receive the feedback and return */
	tsn_msg_recv_analysis();

	return 0;

err:
	free(msg);
	return -1;
}

int tsn_qci_psfp_sgi_status_get(char *portname, uint32_t sgi_handle, struct tsn_psfp_sgi_status *sgi)
{
	struct msgtemplate *msg;
	struct nlattr *sgiattr;
	int ret;

	if (portname == NULL)
		return -1;

	msg = tsn_send_cmd_prepare(TSN_CMD_QCI_SGI_GET_STATUS);
	if (msg == NULL) {
		loge("fail to allocate genl msg.\n");
		return -1;
	}

	tsn_send_cmd_append_attr(msg, TSN_ATTR_IFNAME, portname, strlen(portname) + 1);

	sgiattr = tsn_nla_nest_start(msg, TSN_ATTR_QCI_SGI);
	if (!sgiattr)
		goto err;

	tsn_send_cmd_append_attr(msg, TSN_QCI_SGI_ATTR_INDEX, &sgi_handle, sizeof(sgi_handle));

	tsn_nla_nest_end(msg, sgiattr);

	ret = tsn_send_to_kernel(msg);
	if (ret < 0) {
		loge("genl send to kernel error\n");
		return -1;
	}

	/* TODO: receive the feedback and return */
	tsn_msg_recv_analysis();

	return 0;

err:
	free(msg);
	return -1;
}

int tsn_qci_psfp_fmi_set(char *portname, uint32_t fmi_id, bool enable, struct tsn_qci_psfp_fmi *fmiconf)
{
	struct msgtemplate *msg;
	struct nlattr *qcifmi;
	int ret;

	if (fmiconf == NULL)
		return -1;

	if (portname == NULL)
		return -1;

	msg = tsn_send_cmd_prepare(TSN_CMD_QCI_FMI_SET);
	if (msg == NULL) {
		loge("fail to allocate genl msg.\n");
		return -1;
	}

	tsn_send_cmd_append_attr(msg, TSN_ATTR_IFNAME, portname, strlen(portname) + 1);

	qcifmi = tsn_nla_nest_start(msg, TSN_ATTR_QCI_FMI);
	if (!qcifmi)
		goto err;

	tsn_send_cmd_append_attr(msg, TSN_QCI_FMI_ATTR_INDEX, &fmi_id, sizeof(fmi_id));

	if (!enable) {
		tsn_send_cmd_append_attr(msg, TSN_QCI_FMI_ATTR_DISABLE, &enable, 0);
		goto sendmsg;
	} else
		tsn_send_cmd_append_attr(msg, TSN_QCI_FMI_ATTR_ENABLE, &enable, 0);

	tsn_send_cmd_append_attr(msg, TSN_QCI_FMI_ATTR_CIR,
			&(fmiconf->cir), sizeof(fmiconf->cir));
	tsn_send_cmd_append_attr(msg, TSN_QCI_FMI_ATTR_CBS,
			&(fmiconf->cbs), sizeof(fmiconf->cbs));
	tsn_send_cmd_append_attr(msg, TSN_QCI_FMI_ATTR_EIR,
			&(fmiconf->eir), sizeof(fmiconf->eir));
	tsn_send_cmd_append_attr(msg, TSN_QCI_FMI_ATTR_EBS,
			&(fmiconf->ebs), sizeof(fmiconf->ebs));

	if (fmiconf->cf)
		tsn_send_cmd_append_attr(msg, TSN_QCI_FMI_ATTR_CF, &(fmiconf->cf), 0);

	if (fmiconf->cm)
		tsn_send_cmd_append_attr(msg, TSN_QCI_FMI_ATTR_CM, &(fmiconf->cm), 0);

	if (fmiconf->drop_on_yellow)
		tsn_send_cmd_append_attr(msg, TSN_QCI_FMI_ATTR_DROPYL, &(fmiconf->drop_on_yellow), 0);
	if (fmiconf->mark_red_enable)
		tsn_send_cmd_append_attr(msg, TSN_QCI_FMI_ATTR_MAREDEN, &(fmiconf->mark_red_enable), 0);
	if (fmiconf->mark_red)
		tsn_send_cmd_append_attr(msg, TSN_QCI_FMI_ATTR_MARED, &(fmiconf->mark_red), 0);

sendmsg:
	tsn_nla_nest_end(msg, qcifmi);

	ret = tsn_send_to_kernel(msg);
	if (ret < 0) {
		loge("genl send to kernel error\n");
		return -1;
	}

	tsn_msg_recv_analysis();

	return 0;

err:
	free(msg);
	return -1;
}

int tsn_qci_psfp_fmi_get(char *portname, uint32_t fmi_id, struct tsn_qci_psfp_fmi *fmiconf)
{
	struct msgtemplate *msg;
	struct nlattr *qcifmi;
	int ret;

	if (fmiconf == NULL)
		return -1;

	if (portname == NULL)
		return -1;

	msg = tsn_send_cmd_prepare(TSN_CMD_QCI_FMI_GET);
	if (msg == NULL) {
		loge("fail to allocate genl msg.\n");
		return -1;
	}

	tsn_send_cmd_append_attr(msg, TSN_ATTR_IFNAME, portname, strlen(portname) + 1);

	qcifmi = tsn_nla_nest_start(msg, TSN_ATTR_QCI_FMI);
	if (!qcifmi)
		goto err;

	tsn_send_cmd_append_attr(msg, TSN_QCI_FMI_ATTR_INDEX, &fmi_id, sizeof(fmi_id));

	tsn_nla_nest_end(msg, qcifmi);

	ret = tsn_send_to_kernel(msg);
	if (ret < 0) {
		loge("genl send to kernel error\n");
		return -1;
	}

	tsn_msg_recv_analysis();

	return 0;

err:
	free(msg);
	return -1;
}

int tsn_qos_port_qbv_set(char *portname, struct tsn_qbv_conf *adminconf, bool enable)
{
	struct msgtemplate *msg;
	struct nlattr *qbv, *qbvadmin;
	struct nlattr *qbv_entry;
	struct tsn_qbv_entry *gatelist;
	int cycletime = 0;
	int ret;
	uint32_t i = 0, count = 0;

	if ((adminconf == NULL) && enable)
		return -1;

	if (portname == NULL)
		return -1;

	msg = tsn_send_cmd_prepare(TSN_CMD_QBV_SET);
	if (msg == NULL) {
		loge("fail to allocate genl msg.\n");
		return -1;
	}

	tsn_send_cmd_append_attr(msg, TSN_ATTR_IFNAME, portname, strlen(portname) + 1);


	qbv = tsn_nla_nest_start(msg, TSN_ATTR_QBV);
	if (!qbv)
		return -1;

	/* If disable the port Qbv just send disable ATTR */
	if (!enable) {
		tsn_send_cmd_append_attr(msg, TSN_QBV_ATTR_DISABLE, &enable, 0);
		goto sendmsg1;
	}

	if (enable == 1)
		tsn_send_cmd_append_attr(msg, TSN_QBV_ATTR_ENABLE, &enable, 0);

	if (adminconf->config_change)
		tsn_send_cmd_append_attr(msg, TSN_QBV_ATTR_CONFIGCHANGE, &(adminconf->config_change), 0);

	qbvadmin = tsn_nla_nest_start(msg, TSN_QBV_ATTR_ADMINENTRY);
	if (!qbvadmin)
		return -1;

	if (adminconf->admin.gate_states)
		tsn_send_cmd_append_attr(msg, TSN_QBV_ATTR_CTRL_GATESTATE, &(adminconf->admin.gate_states),
				sizeof(adminconf->admin.gate_states));

	if (adminconf->admin.cycle_time_extension)
		tsn_send_cmd_append_attr(msg, TSN_QBV_ATTR_CTRL_CYCLETIMEEXT, &(adminconf->admin.cycle_time_extension),
				sizeof(adminconf->admin.cycle_time_extension));

	if (adminconf->admin.base_time)
		tsn_send_cmd_append_attr(msg, TSN_QBV_ATTR_CTRL_BASETIME, &(adminconf->admin.base_time),
				sizeof(adminconf->admin.base_time));


	if (adminconf->admin.control_list_length)
		tsn_send_cmd_append_attr(msg, TSN_QBV_ATTR_CTRL_LISTCOUNT, &(adminconf->admin.control_list_length),
				sizeof(adminconf->admin.control_list_length));

	gatelist = adminconf->admin.control_list;

	while ((gatelist + i) != NULL) {
		if ((gatelist + i)->time_interval) {
			qbv_entry = tsn_nla_nest_start(msg, TSN_QBV_ATTR_CTRL_LISTENTRY);
			logv("set tsn_nla_nest_start TSN_QBV_ATTR_ADMINENTRY %d\n", i);

			if (!qbv_entry)
				return -1;

			uint8_t gs = (gatelist + i)->gate_state;
			uint32_t ti = (gatelist + i)->time_interval;

			tsn_send_cmd_append_attr(msg, TSN_QBV_ATTR_ENTRY_ID, &i, sizeof(i));
			tsn_send_cmd_append_attr(msg, TSN_QBV_ATTR_ENTRY_GC, &gs, sizeof(gs));
			tsn_send_cmd_append_attr(msg, TSN_QBV_ATTR_ENTRY_TM, &ti, sizeof(ti));

			count++; cycletime += ti;

			if (count > adminconf->admin.control_list_length) {
				loge("entries count bigger than input cnt.\n");
				return -1;
			}

			tsn_nla_nest_end(msg, qbv_entry);

		}

		i++;

		if (i > MAX_ENTRY_SIZE/sizeof(struct tsn_qbv_entry))
			break;
	}

	if (!adminconf->admin.cycle_time)
		adminconf->admin.cycle_time = cycletime;

	if (adminconf->admin.cycle_time)
		tsn_send_cmd_append_attr(msg, TSN_QBV_ATTR_CTRL_CYCLETIME, &(adminconf->admin.cycle_time),
				sizeof(adminconf->admin.cycle_time));

	tsn_nla_nest_end(msg, qbvadmin);

sendmsg1:
	tsn_nla_nest_end(msg, qbv);

	ret = tsn_send_to_kernel(msg);
	if (ret < 0) {
		loge("genl send to kernel error\n");
		return -1;
	}

	tsn_msg_recv_analysis();

	return 0;
}

/* tsn_qos_port_gce_conf_get()
 * portname: interface name, which port to get tsn qbv entries.
 * conf: where to save the table entries
 *
 * return : count of entris get.
 */
int tsn_qos_port_qbv_get(char *portname, struct tsn_qbv_conf *qbvconf)
{
	struct msgtemplate *msg;
	int ret;

	if (qbvconf == NULL)
		return -1;

	msg = tsn_send_cmd_prepare(TSN_CMD_QBV_GET);
	if (msg == NULL) {
		loge("fail to allocate genl msg.\n");
		return -1;
	}

	tsn_send_cmd_append_attr(msg, TSN_ATTR_IFNAME, portname, strlen(portname) + 1);

	ret = tsn_send_to_kernel(msg);
	if (ret < 0) {
		loge("genl send to kernel error\n");
		return -1;
	}
	/* TODO save to tsn_qbv_conf and admin list */
	tsn_msg_recv_analysis();
	return 0;
}

int tsn_qos_port_qbv_status_get(char *portname, struct tsn_qbv_status *qbvstatus)
{
	struct msgtemplate *msg;
	int ret;

	if (qbvstatus == NULL)
		return -1;

	msg = tsn_send_cmd_prepare(TSN_CMD_QBV_GET_STATUS);
	if (msg == NULL) {
		loge("fail to allocate genl msg.\n");
		return -1;
	}

	tsn_send_cmd_append_attr(msg, TSN_ATTR_IFNAME, portname, strlen(portname) + 1);

	ret = tsn_send_to_kernel(msg);
	if (ret < 0) {
		loge("genl send to kernel error\n");
		return -1;
	}
	/* TODO save to struct tsn_qbv_status and oper list */
	tsn_msg_recv_analysis();
	return 0;
}

int tsn_cbs_set(char *portname, uint8_t tc, uint8_t percent)
{
	struct msgtemplate *msg;
	struct nlattr *cbsattr;
	int ret;

	if (portname == NULL)
		return -1;

	msg = tsn_send_cmd_prepare(TSN_CMD_CBS_SET);
	if (msg == NULL) {
		loge("fail to allocate genl msg.\n");
		return -1;
	}

	tsn_send_cmd_append_attr(msg, TSN_ATTR_IFNAME, portname, strlen(portname) + 1);


	cbsattr = tsn_nla_nest_start(msg, TSN_ATTR_CBS);
	if (!cbsattr)
		return -1;

	tsn_send_cmd_append_attr(msg, TSN_CBS_ATTR_TC_INDEX, &tc, sizeof(tc));

	tsn_send_cmd_append_attr(msg, TSN_CBS_ATTR_BW, &percent, sizeof(percent));

	tsn_nla_nest_end(msg, cbsattr);

	ret = tsn_send_to_kernel(msg);
	if (ret < 0) {
		loge("genl send to kernel error\n");
		return -1;
	}

	tsn_msg_recv_analysis();
	return 0;
}

int tsn_cbs_get(char *portname, uint8_t tc)
{
	struct msgtemplate *msg;
	struct nlattr *cbsattr;
	int ret;

	if (portname == NULL)
		return -1;

	msg = tsn_send_cmd_prepare(TSN_CMD_CBS_GET);
	if (msg == NULL) {
		loge("fail to allocate genl msg.\n");
		return -1;
	}

	tsn_send_cmd_append_attr(msg, TSN_ATTR_IFNAME, portname, strlen(portname) + 1);

	cbsattr = tsn_nla_nest_start(msg, TSN_ATTR_CBS);
	if (!cbsattr)
		return -1;

	tsn_send_cmd_append_attr(msg, TSN_CBS_ATTR_TC_INDEX, &tc, sizeof(tc));

	tsn_nla_nest_end(msg, cbsattr);

	ret = tsn_send_to_kernel(msg);
	if (ret < 0) {
		loge("genl send to kernel error\n");
		return -1;
	}

	tsn_msg_recv_analysis();
	return 0;
}

int tsn_tsd_set(char *portname, bool enable, uint32_t period, uint32_t frame_num, bool imme)
{
	struct msgtemplate *msg;
	struct nlattr *cbsattr;
	int ret;

	if (portname == NULL)
		return -1;

	msg = tsn_send_cmd_prepare(TSN_CMD_TSD_SET);
	if (msg == NULL) {
		loge("fail to allocate genl msg.\n");
		return -1;
	}

	tsn_send_cmd_append_attr(msg, TSN_ATTR_IFNAME, portname, strlen(portname) + 1);


	cbsattr = tsn_nla_nest_start(msg, TSN_ATTR_TSD);
	if (!cbsattr)
		return -1;

	if (enable) {
		tsn_send_cmd_append_attr(msg, TSN_TSD_ATTR_ENABLE, &enable, 0);
		tsn_send_cmd_append_attr(msg, TSN_TSD_ATTR_PERIOD, &period, sizeof(period));
		tsn_send_cmd_append_attr(msg, TSN_TSD_ATTR_MAX_FRM_NUM, &frame_num, sizeof(frame_num));
		if (imme)
			tsn_send_cmd_append_attr(msg, TSN_TSD_ATTR_SYN_IMME, &imme, 0);

	} else {
		tsn_send_cmd_append_attr(msg, TSN_TSD_ATTR_DISABLE, &enable, 0);
	}

	tsn_nla_nest_end(msg, cbsattr);

	ret = tsn_send_to_kernel(msg);
	if (ret < 0) {
		loge("genl send to kernel error\n");
		return -1;
	}

	tsn_msg_recv_analysis();
	return 0;
}

int tsn_tsd_get(char *portname)
{
	struct msgtemplate *msg;
		struct nlattr *cbsattr;
		int ret;

		if (portname == NULL)
			return -1;

		msg = tsn_send_cmd_prepare(TSN_CMD_TSD_GET);
		if (msg == NULL) {
			loge("fail to allocate genl msg.\n");
			return -1;
		}

		tsn_send_cmd_append_attr(msg, TSN_ATTR_IFNAME, portname, strlen(portname) + 1);

		cbsattr = tsn_nla_nest_start(msg, TSN_ATTR_TSD);
		if (!cbsattr)
			return -1;

		tsn_nla_nest_end(msg, cbsattr);

		ret = tsn_send_to_kernel(msg);
		if (ret < 0) {
			loge("genl send to kernel error\n");
			return -1;
		}

		tsn_msg_recv_analysis();
		return 0;
}

int tsn_qbu_set(char *portname, uint8_t pt_vector)
{
	struct msgtemplate *msg;
	struct nlattr *qbuattr;
	int ret;

	if (portname == NULL)
		return -1;

	msg = tsn_send_cmd_prepare(TSN_CMD_QBU_SET);
	if (msg == NULL) {
		loge("fail to allocate genl msg.\n");
		return -1;
	}

	tsn_send_cmd_append_attr(msg, TSN_ATTR_IFNAME, portname, strlen(portname) + 1);


	qbuattr = tsn_nla_nest_start(msg, TSN_ATTR_QBU);
	if (!qbuattr)
		return -1;

	tsn_send_cmd_append_attr(msg, TSN_QBU_ATTR_ADMIN_STATE, &pt_vector, sizeof(pt_vector));

	tsn_nla_nest_end(msg, qbuattr);

	ret = tsn_send_to_kernel(msg);
	if (ret < 0) {
		loge("genl send to kernel error\n");
		return -1;
	}

	tsn_msg_recv_analysis();
	return 0;
}

int tsn_qbu_get_status(char *portname, struct tsn_preempt_status *pts)
{
	struct msgtemplate *msg;
	int ret;

	if (portname == NULL)
		return -1;

	msg = tsn_send_cmd_prepare(TSN_CMD_QBU_GET_STATUS);
	if (msg == NULL) {
		loge("fail to allocate genl msg.\n");
		return -1;
	}

	tsn_send_cmd_append_attr(msg, TSN_ATTR_IFNAME, portname, strlen(portname) + 1);

	ret = tsn_send_to_kernel(msg);
	if (ret < 0) {
		loge("genl send to kernel error\n");
		return -1;
	}

	tsn_msg_recv_analysis();
	return 0;
}

int tsn_ct_set(char *portname, uint8_t pt_vector)
{
	struct msgtemplate *msg;
	struct nlattr *ctattr;
	int ret;

	if (portname == NULL)
		return -1;

	msg = tsn_send_cmd_prepare(TSN_CMD_CT_SET);
	if (msg == NULL) {
		loge("fail to allocate genl msg.\n");
		return -1;
	}

	tsn_send_cmd_append_attr(msg, TSN_ATTR_IFNAME, portname, strlen(portname) + 1);


	ctattr = tsn_nla_nest_start(msg, TSN_ATTR_CT);
	if (!ctattr)
		return -1;

	tsn_send_cmd_append_attr(msg, TSN_CT_ATTR_QUEUE_STATE, &pt_vector, sizeof(pt_vector));

	tsn_nla_nest_end(msg, ctattr);

	ret = tsn_send_to_kernel(msg);
	if (ret < 0) {
		loge("genl send to kernel error\n");
		return -1;
	}

	tsn_msg_recv_analysis();
	return 0;
}

int tsn_cbgen_set(char *portname, uint32_t index,
		  struct tsn_seq_gen_conf *sg)
{
	struct msgtemplate *msg;
	struct nlattr *cbgenattr;
	int ret;

	if (portname == NULL)
		return -1;

	msg = tsn_send_cmd_prepare(TSN_CMD_CBGEN_SET);
	if (msg == NULL) {
		loge("fail to allocate genl msg.\n");
		return -1;
	}

	tsn_send_cmd_append_attr(msg, TSN_ATTR_IFNAME, portname, strlen(portname) + 1);


	cbgenattr = tsn_nla_nest_start(msg, TSN_ATTR_CBGEN);
	if (!cbgenattr)
		return -1;

	tsn_send_cmd_append_attr(msg, TSN_CBGEN_ATTR_INDEX, &index, sizeof(index));

	tsn_send_cmd_append_attr(msg, TSN_CBGEN_ATTR_PORT_MASK, &(sg->iport_mask), sizeof(sg->iport_mask));

	tsn_send_cmd_append_attr(msg, TSN_CBGEN_ATTR_SPLIT_MASK, &(sg->split_mask), sizeof(sg->split_mask));

	tsn_send_cmd_append_attr(msg, TSN_CBGEN_ATTR_SEQ_LEN, &(sg->seq_len), sizeof(sg->seq_len));

	tsn_send_cmd_append_attr(msg, TSN_CBGEN_ATTR_SEQ_NUM, &(sg->seq_num), sizeof(sg->seq_num));

	tsn_nla_nest_end(msg, cbgenattr);

	ret = tsn_send_to_kernel(msg);
	if (ret < 0) {
		loge("genl send to kernel error\n");
		return -1;
	}

	tsn_msg_recv_analysis();
	return 0;
}

int tsn_cbrec_set(char *portname, uint32_t index,
		  struct tsn_seq_rec_conf *sr)
{
	struct msgtemplate *msg;
	struct nlattr *cbrecattr;
	int ret;

	if (portname == NULL)
		return -1;

	msg = tsn_send_cmd_prepare(TSN_CMD_CBREC_SET);
	if (msg == NULL) {
		loge("fail to allocate genl msg.\n");
		return -1;
	}

	tsn_send_cmd_append_attr(msg, TSN_ATTR_IFNAME, portname, strlen(portname) + 1);


	cbrecattr = tsn_nla_nest_start(msg, TSN_ATTR_CBREC);
	if (!cbrecattr)
		return -1;

	tsn_send_cmd_append_attr(msg, TSN_CBREC_ATTR_INDEX, &index, sizeof(index));

	tsn_send_cmd_append_attr(msg, TSN_CBREC_ATTR_SEQ_LEN, &(sr->seq_len), sizeof(sr->seq_len));

	tsn_send_cmd_append_attr(msg, TSN_CBREC_ATTR_HIS_LEN, &(sr->his_len), sizeof(sr->his_len));

	if(sr->rtag_pop_en)
		tsn_send_cmd_append_attr(msg, TSN_CBREC_ATTR_TAG_POP_EN,
					 &(sr->rtag_pop_en), 0);
	tsn_nla_nest_end(msg, cbrecattr);

	ret = tsn_send_to_kernel(msg);
	if (ret < 0) {
		loge("genl send to kernel error\n");
		return -1;
	}

	tsn_msg_recv_analysis();
	return 0;
}
