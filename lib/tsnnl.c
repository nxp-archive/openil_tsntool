// SPDX-License-Identifier: (GPL-2.0 OR MIT)
/*
 * Copyright 2018-2019 NXP
 */

#include <unistd.h>
#include <netlink/attr.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/netlink.h>
#include <sys/file.h>
#include "tsn/genl_tsn.h"
#include <errno.h>

struct linkpara tsn_cap_para[TSN_CAP_ATTR_MAX + 1] = {
	[TSN_CAP_ATTR_QBV]	= {NLA_FLAG, 2, "Qbv" },
	[TSN_CAP_ATTR_QCI]	= {NLA_FLAG, 2, "Qci" },
	[TSN_CAP_ATTR_QBU]	= {NLA_FLAG, 2, "Qbu" },
	[TSN_CAP_ATTR_CBS]	= {NLA_FLAG, 2, "Qav Credit-based Shapter" },
	[TSN_CAP_ATTR_CB]	= {NLA_FLAG, 2, "8021CB" },
	[TSN_CAP_ATTR_TBS]	= {NLA_FLAG, 2, "time based schedule" },
	[TSN_CAP_ATTR_CTH]	= {NLA_FLAG, 2, "cut through forward" },
};

struct linkpara qbv_base[TSN_QBV_ATTR_MAX + 1] = {
	[TSN_QBV_ATTR_CONFIGCHANGE]			= {0,0,0},
	[TSN_QBV_ATTR_GRANULARITY]			= {0,0,0},
	[TSN_QBV_ATTR_CONFIGCHANGEERROR]	= {0,0,0},
	[TSN_QBV_ATTR_ADMINENTRY]   		= { NLA_NESTED, 1, "admin"},
	[TSN_QBV_ATTR_OPERENTRY] 			= { NLA_NESTED, 1, "oper"},
	[TSN_QBV_ATTR_ENABLE] 				= { NLA_FLAG, 2, "enable"},
	[TSN_QBV_ATTR_DISABLE] 				= { NLA_FLAG, 2 , "disable"},
	[TSN_QBV_ATTR_CONFIGCHANGETIME] 	= { NLA_U64, 2, "configchangetime"},
	[TSN_QBV_ATTR_MAXSDU] 				= { NLA_U32, 2, "maxsdu"},
	[TSN_QBV_ATTR_CURRENTTIME] 			= { NLA_U64, 2, "currenttime"},
	[TSN_QBV_ATTR_CONFIGPENDING] 		= { NLA_FLAG, 2, "configpending"},
	[TSN_QBV_ATTR_LISTMAX] 				= { NLA_U32, 2, "listmax"},
};

struct linkpara qbv_ctrl[TSN_QBV_ATTR_CTRL_MAX + 1] = {
	[TSN_QBV_ATTR_CTRL_LISTCOUNT]		= {NLA_U32, 2, "listcount"},
	[TSN_QBV_ATTR_CTRL_GATESTATE]		= {NLA_U8, 2, "gatestate" },
	[TSN_QBV_ATTR_CTRL_CYCLETIME]		= {NLA_U32, 2, "cycletime"},
	[TSN_QBV_ATTR_CTRL_CYCLETIMEEXT]	= {NLA_U32, 2, "cycletimeext" },
	[TSN_QBV_ATTR_CTRL_BASETIME]		= {NLA_U64, 2, "basetime" },
	[TSN_QBV_ATTR_CTRL_LISTENTRY]		= {NLA_NESTED + __NLA_TYPE_MAX, 1 , "list"},
};

struct linkpara qbv_entry[TSN_QBV_ATTR_ENTRY_MAX + 1] = {
	[TSN_QBV_ATTR_ENTRY_ID]	= {NLA_U32 +  __NLA_TYPE_MAX, 2, "entryid" },
	[TSN_QBV_ATTR_ENTRY_GC]	= {NLA_U8 + __NLA_TYPE_MAX, 2, "gate" },
	[TSN_QBV_ATTR_ENTRY_TM]	= {NLA_U32 + __NLA_TYPE_MAX, 2, "timeperiod" },
};

struct linkpara cb_streamid[TSN_STREAMID_ATTR_MAX + 1] = {
	[TSN_STREAMID_ATTR_INDEX] 	= { NLA_U32, 2, "index"},
	[TSN_STREAMID_ATTR_ENABLE] 	= { NLA_FLAG, 2, "enable"},
	[TSN_STREAMID_ATTR_DISABLE]	= { NLA_FLAG, 2, "disable"},
	[TSN_STREAMID_ATTR_STREAM_HANDLE]	= { NLA_U32, 3, "streamhandle"},
	[TSN_STREAMID_ATTR_IFOP]	= { NLA_U32, 2, "in face out port"},
	[TSN_STREAMID_ATTR_OFOP]	= { NLA_U32, 2, "out face out port"},
	[TSN_STREAMID_ATTR_IFIP]	= { NLA_U32, 2, "in face in port"},
	[TSN_STREAMID_ATTR_OFIP]	= { NLA_U32, 2, "out face in port"},
	[TSN_STREAMID_ATTR_TYPE]	= { NLA_U8, 2, "identify type"},
	[TSN_STREAMID_ATTR_NDMAC]	= { NLA_U64, 4, "null dmac"},
	[TSN_STREAMID_ATTR_NTAGGED]	= { NLA_U8, 2, "null tag type"},
	[TSN_STREAMID_ATTR_NVID]		= { NLA_U16, 2, "null vlanid"},
	[TSN_STREAMID_ATTR_SMAC]	= { NLA_U64, 4, "source mac"},
	[TSN_STREAMID_ATTR_STAGGED]	= { NLA_U8, 2, "source tag type"},
	[TSN_STREAMID_ATTR_SVID]		= { NLA_U16, 2, "source vlanid"},
	[TSN_STREAMID_ATTR_COUNTERS_PSI] = { NLA_U64, 2, "counter per-steram-in"},
	[TSN_STREAMID_ATTR_COUNTERS_PSO] = { NLA_U64, 2, "counter per-stream-out"},
	[TSN_STREAMID_ATTR_COUNTERS_PSPPI] = { NLA_U64, 2, "counter per-stream-per-port-in"},
	[TSN_STREAMID_ATTR_COUNTERS_PSPPO] = { NLA_U64, 2, "counter per-stream-per-port-out"},
};

struct linkpara qci_sfi[TSN_QCI_SFI_ATTR_MAX + 1] = {
	[TSN_QCI_SFI_ATTR_INDEX]		= { NLA_U32, 2, "index"},
	[TSN_QCI_SFI_ATTR_ENABLE]		= { NLA_FLAG, 2, "enable"},
	[TSN_QCI_SFI_ATTR_DISABLE]		= { NLA_FLAG, 2, "disable"},
	[TSN_QCI_SFI_ATTR_STREAM_HANDLE] = { NLA_U32, 3, "streamhandle"},
	[TSN_QCI_SFI_ATTR_PRIO_SPEC] 	= { NLA_U8, 3, "priority"},
	[TSN_QCI_SFI_ATTR_GATE_ID]		= { NLA_U32, 2, "gateid"},
	[TSN_QCI_SFI_ATTR_FILTER_TYPE]	= { NLA_U8, 2, "filtertype"},
	[TSN_QCI_SFI_ATTR_FLOW_ID]		= { NLA_U32, 3, "flowid"},
	[TSN_QCI_SFI_ATTR_MAXSDU]		= { NLA_U16, 2, "maxsdu"},
	[TSN_QCI_SFI_ATTR_COUNTERS]		= { __NLA_TYPE_MAX + 10, sizeof(struct tsn_qci_psfp_sfi_counters), "\nmatch   pass   gate_drop   sdu_pass   sdu_drop   red\n"},
	[TSN_QCI_SFI_ATTR_OVERSIZE_ENABLE]	= { NLA_FLAG, 2, "oversize enable"},
	[TSN_QCI_SFI_ATTR_OVERSIZE]		= { NLA_FLAG, 2, "oversize"},
};

struct linkpara qci_stream_para[TSN_QCI_STREAM_ATTR_MAX + 1] = {
	 [TSN_QCI_STREAM_ATTR_MAX_SFI]	= { NLA_U32, 3,
					"max stream filter instances"},
	 [TSN_QCI_STREAM_ATTR_MAX_SGI]	= { NLA_U32, 3,
					"max stream gate instances"},
	 [TSN_QCI_STREAM_ATTR_MAX_FMI]	= { NLA_U32, 3,
					"max flow meter instances"},
	 [TSN_QCI_STREAM_ATTR_SLM]	= { NLA_U32, 3, "supported list max"},
};

#if 0
static const struct nla_policy qci_sfi_counters_policy[TSN_QCI_SFI_ATTR_COUNT_MAX + 1] = {
	[TSN_QCI_SFI_ATTR_MATCH]		= { NLA_U64},
	[TSN_QCI_SFI_ATTR_PASS]			= { NLA_U64},
	[TSN_QCI_SFI_ATTR_DROP]			= { NLA_U64},
	[TSN_QCI_SFI_ATTR_SDU_DROP]		= { NLA_U64},
	[TSN_QCI_SFI_ATTR_SDU_PASS]		= { NLA_U64},
	[TSN_QCI_SFI_ATTR_RED]			= { NLA_U64},
};
#endif

struct linkpara qci_sgi[TSN_QCI_SGI_ATTR_MAX + 1] = {
	[TSN_QCI_SGI_ATTR_INDEX]		= { NLA_U32, 2, "index"},
	[TSN_QCI_SGI_ATTR_ENABLE]		= { NLA_FLAG, 2, "enable"},
	[TSN_QCI_SGI_ATTR_DISABLE]		= { NLA_FLAG, 2, "disable"},
	[TSN_QCI_SGI_ATTR_CONFCHANGE]	= { NLA_FLAG, 2, "configchange"},
	[TSN_QCI_SGI_ATTR_IRXEN]		= { NLA_FLAG, 2, "invalid rx enable"},		/* Invalid rx enable*/
	[TSN_QCI_SGI_ATTR_IRX]			= { NLA_FLAG, 2, "invalid rx"},
	[TSN_QCI_SGI_ATTR_OEXEN]		= { NLA_FLAG, 2, "octet exceed enable"},		/* Octet exceed enable */
	[TSN_QCI_SGI_ATTR_OEX]			= { NLA_FLAG, 2, "octet exceed"},
	[TSN_QCI_SGI_ATTR_ADMINENTRY]	= { NLA_NESTED, 1, "adminentry"},
	[TSN_QCI_SGI_ATTR_OPERENTRY]	= { NLA_NESTED, 1, "operentry"},
	[TSN_QCI_SGI_ATTR_CCTIME]		= { NLA_U64, 2, "configchange time"},	/* config change time */
	[TSN_QCI_SGI_ATTR_TICKG]		= { NLA_U32, 2, "tick"},
	[TSN_QCI_SGI_ATTR_CUTIME]		= { NLA_U64, 2, "currenttime"},
	[TSN_QCI_SGI_ATTR_CPENDING]		= { NLA_FLAG, 2, "config pending"},
	[TSN_QCI_SGI_ATTR_CCERROR]		= { NLA_U64, 2, "configchange error"},
};

struct linkpara qci_sgi_ctrl[TSN_SGI_ATTR_CTRL_MAX + 1] = {
	[TSN_SGI_ATTR_CTRL_INITSTATE]	= { NLA_FLAG, 2, "initial state"},
	[TSN_SGI_ATTR_CTRL_LEN]			= { NLA_U8, 2, "length"},
	[TSN_SGI_ATTR_CTRL_CYTIME]		= { NLA_U32, 2, "cycle time"},
	[TSN_SGI_ATTR_CTRL_CYTIMEEX]	= { NLA_U32, 2, "cycle time extend"},
	[TSN_SGI_ATTR_CTRL_BTIME]		= { NLA_U64, 2, "basetime"},
	[TSN_SGI_ATTR_CTRL_INITIPV]		= { NLA_U8, 3, "initial ipv"},
	[TSN_SGI_ATTR_CTRL_GCLENTRY]	= { NLA_NESTED + __NLA_TYPE_MAX, 1, "gatelist"},
};

struct linkpara qci_sgi_gcl[TSN_SGI_ATTR_GCL_MAX + 1] = {
	[TSN_SGI_ATTR_GCL_GATESTATE]	= { NLA_FLAG + __NLA_TYPE_MAX, 2, "gate state"},
	[TSN_SGI_ATTR_GCL_IPV]			= { NLA_U8 + __NLA_TYPE_MAX , 3, "ipv"},
	[TSN_SGI_ATTR_GCL_INTERVAL]		= { NLA_U32 + __NLA_TYPE_MAX, 2, "time interval"},
	[TSN_SGI_ATTR_GCL_OCTMAX]		= { NLA_U32 + __NLA_TYPE_MAX, 2, "octmax"},
};

struct linkpara qci_fmi[TSN_QCI_FMI_ATTR_MAX + 1] = {
	[TSN_QCI_FMI_ATTR_INDEX]	= { NLA_U32, 2, "index"},
	[TSN_QCI_FMI_ATTR_ENABLE]	= { NLA_FLAG, 2, "enable"},
	[TSN_QCI_FMI_ATTR_DISABLE]	= { NLA_FLAG, 2, "disable"},
	[TSN_QCI_FMI_ATTR_CIR]		= { NLA_U32, 2, "cir"},
	[TSN_QCI_FMI_ATTR_CBS]		= { NLA_U32, 2, "cbs"},
	[TSN_QCI_FMI_ATTR_EIR]		= { NLA_U32, 2, "eir"},
	[TSN_QCI_FMI_ATTR_EBS]		= { NLA_U32, 2, "ebs"},
	[TSN_QCI_FMI_ATTR_CF]		= { NLA_FLAG, 2, "couple flag"},
	[TSN_QCI_FMI_ATTR_CM]		= { NLA_FLAG, 2, "color mode"},
	[TSN_QCI_FMI_ATTR_DROPYL]	= { NLA_FLAG, 2, "drop yellow"},
	[TSN_QCI_FMI_ATTR_MAREDEN]	= { NLA_FLAG, 2, "mark red enable"},
	[TSN_QCI_FMI_ATTR_MARED]	= { NLA_FLAG, 2, "mark red"},
	[TSN_QCI_FMI_ATTR_COUNTERS] = { __NLA_TYPE_MAX + 11, sizeof(struct tsn_qci_psfp_fmi_counters), "\nbytecount   drop   dr0_green   dr1_green   dr2_yellow   remark_yellow   dr3_red   remark_red\n"},
};

struct linkpara cb_get[TSN_CBSTAT_ATTR_MAX + 1] = {
	[TSN_CBSTAT_ATTR_INDEX]		= { NLA_U32, 2, "index"},
	[TSN_CBSTAT_ATTR_GEN_REC]	= { NLA_U8, 2, "gen_rec"},
	[TSN_CBSTAT_ATTR_ERR]		= { NLA_U8, 2, "err"},
	[TSN_CBSTAT_ATTR_SEQ_NUM]	= { NLA_U32, 3, "seq_num"},
	[TSN_CBSTAT_ATTR_SEQ_LEN]	= { NLA_U8, 2, "seq_len"},
	[TSN_CBSTAT_ATTR_SPLIT_MASK]	= { NLA_U8, 2, "split_mask"},
	[TSN_CBSTAT_ATTR_PORT_MASK]	= { NLA_U8, 2, "iport_mask"},
	[TSN_CBSTAT_ATTR_HIS_LEN]	= { NLA_U8, 2, "his_len"},
	[TSN_CBSTAT_ATTR_SEQ_HIS]	= { NLA_U32, 3, "seq_history"},
};

struct linkpara qbu_get[TSN_QBU_ATTR_MAX + 1] = {
	[TSN_QBU_ATTR_ADMIN_STATE]	= { NLA_U8, 2, "preemtable"},
	[TSN_QBU_ATTR_HOLD_ADVANCE]	= { NLA_U32, 3, "holdadvance"},
	[TSN_QBU_ATTR_RELEASE_ADVANCE]	= { NLA_U32, 3, "releaseadvance"},
	[TSN_QBU_ATTR_ACTIVE]		= { NLA_FLAG, 2, "active"},
	[TSN_QBU_ATTR_HOLD_REQUEST]     = { NLA_U8, 2, "holdrequest"},
};

static void get_tsn_cap_para_from_json(cJSON *json, void *para)
{
	cJSON *item;
	struct tsn_cap *cap;
	int index;

	cap = (struct tsn_cap_para *)para;

	item = cJSON_GetObjectItem(json, tsn_cap_para[TSN_CAP_ATTR_QBV].name);
	if (item)
		cap->qbv = 1;

	item = cJSON_GetObjectItem(json, tsn_cap_para[TSN_CAP_ATTR_QCI].name);
	if (item)
		cap->qci = 1;

	item = cJSON_GetObjectItem(json, tsn_cap_para[TSN_CAP_ATTR_QBU].name);
	if (item)
		cap->qbu = 1;

	item = cJSON_GetObjectItem(json, tsn_cap_para[TSN_CAP_ATTR_CBS].name);
	if (item)
		cap->cbs = 1;

	item = cJSON_GetObjectItem(json, tsn_cap_para[TSN_CAP_ATTR_CB].name);
	if (item)
		cap->cb = 1;

	item = cJSON_GetObjectItem(json, tsn_cap_para[TSN_CAP_ATTR_TBS].name);
	if (item)
		cap->tbs = 1;

	item = cJSON_GetObjectItem(json, tsn_cap_para[TSN_CAP_ATTR_CTH].name);
	if (item)
		cap->cut_through = 1;
}

static void get_qci_cap_para_from_json(cJSON *json, void *para)
{
	cJSON *item;
	char *name;
	struct tsn_qci_psfp_stream_param *sp;

	sp = (struct tsn_qci_psfp_stream_param *)para;

	name = qci_stream_para[TSN_QCI_STREAM_ATTR_MAX_SFI].name;
	item = cJSON_GetObjectItem(json, name);
	if (item)
		sp->max_sf_instance = (int32_t)(item->valuedouble);

	name = qci_stream_para[TSN_QCI_STREAM_ATTR_MAX_SGI].name;
	item = cJSON_GetObjectItem(json, name);
	if (item)
		sp->max_sg_instance = (int32_t)(item->valuedouble);

	name = qci_stream_para[TSN_QCI_STREAM_ATTR_MAX_FMI].name;
	item = cJSON_GetObjectItem(json, name);
	if (item)
		sp->max_fm_instance = (int32_t)(item->valuedouble);

	name = qci_stream_para[TSN_QCI_STREAM_ATTR_SLM].name;
	item = cJSON_GetObjectItem(json, name);
	if (item)
		sp->supported_list_max = (int32_t)(item->valuedouble);
}

void get_para_from_json(int type, cJSON *json, void *para)
{
	switch (type) {
	case TSN_ATTR_QBV:
	case TSN_ATTR_STREAM_IDENTIFY:
		break;
	case TSN_ATTR_CAP:
		get_tsn_cap_para_from_json(json, para);
	case TSN_ATTR_QCI_SP:
		get_qci_cap_para_from_json(json, para);
		break;
	case TSN_ATTR_QCI_SFI:
	case TSN_ATTR_QCI_SGI:
	case TSN_ATTR_QCI_FMI:
	case TSN_ATTR_CBS:
	case TSN_ATTR_QBU:
	case TSN_ATTR_TSD:
	case TSN_ATTR_CT:
	case TSN_ATTR_CBGEN:
	case TSN_ATTR_CBREC:
	case TSN_ATTR_CBSTAT:
	case TSN_ATTR_DSCP:
	default:
		break;
	}
}

#ifdef CONF_MONITOR
#define TSN_MON_FILE "/tmp/tsn-oper-record.json"
bool conf_monitor_switch = true;

void create_record(char *portname, int cmd, uint32_t index)
{
	FILE *fp;
	char *buf;
	pid_t pid;
	cJSON *json = NULL;
	cJSON *item = NULL;
	struct tsn_conf_record record;

	if (!portname)
		return;

	sprintf(record.portname, portname);
	record.cmd = cmd;
	record.para = index;
	
	errno = 0;
	fp = fopen(TSN_MON_FILE, "w");
	if (!fp) {
		lloge("open '%s' failed: %s", TSN_MON_FILE,
		      strerror(errno));
		return;
	}
	errno = 0;
	if (flock(fp->_fileno, LOCK_EX) == -1) {
		lloge("lock '%s' failed: %s", TSN_MON_FILE,
		      strerror(errno));
		fclose(fp);
		return;
	}
	json = cJSON_CreateObject();
	if (!json) {
		lloge("create cJSON object failed!");
		fclose(fp);
		return;
	}
	item = cJSON_CreateNumber((double)getpid());
	cJSON_AddItemToObject(json, "pid", item);
	item = cJSON_CreateString(record.portname);
	cJSON_AddItemToObject(json, "port", item);
	item = cJSON_CreateNumber((double)record.cmd);
	cJSON_AddItemToObject(json, "command", item);
	item = cJSON_CreateNumber((double)record.para);
	cJSON_AddItemToObject(json, "parameter", item);
	buf = cJSON_Print(json);
	fwrite(buf, strlen(buf), 1, fp);
	free(buf);
	cJSON_Delete(json);
	flock(fp->_fileno, LOCK_UN);
	fclose(fp);
}

int get_tsn_record(struct tsn_conf_record *record)
{
	FILE *fp;
	cJSON *json = NULL;
	cJSON *item = NULL;
	char *json_data;
	int len = 0;

	errno = 0;
	fp = fopen(TSN_MON_FILE, "r");
	if (!fp) {
		lloge("open '%s' failed: %s", TSN_MON_FILE,
		      strerror(errno));
		return -1;
	}
	errno = 0;
	if (flock(fp->_fileno, LOCK_EX) == -1) {
		lloge("lock '%s' failed: %s", TSN_MON_FILE,
		      strerror(errno));
		fclose(fp);
		return -1;
	}
	fseek(fp, 0, SEEK_END);
	len = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	json_data = (char *)malloc(len + 1);
	if (json_data) {
		fread(json_data, 1, len, fp);
		json = cJSON_Parse(json_data);
		if (!json) {
			lloge("json parse error");
			free(json_data);
			flock(fp->_fileno, LOCK_UN);
			fclose(fp);
			return -1;
		}
	} else {
		lloge("malloc error");
		flock(fp->_fileno, LOCK_UN);
		fclose(fp);
		return -1;
	}
	item = cJSON_GetObjectItem(json, "pid");
	if (!item) {
		lloge("get pid failed!");
		cJSON_Delete(json);
		return -1;
	}
	record->pid = (__u32)(item->valuedouble);
	item = cJSON_GetObjectItem(json, "port");
	if (!item) {
		lloge("get port failed!");
		cJSON_Delete(json);
		return -1;
	}
	sprintf(record->portname, item->valuestring);
	item = cJSON_GetObjectItem(json, "command");
	if (!item) {
		lloge("get command failed!");
		cJSON_Delete(json);
		return -1;
	}
	record->cmd = (__u32)item->valuedouble;
	item = cJSON_GetObjectItem(json, "parameter");
	if (!item) {
		lloge("get parameter failed!");
		cJSON_Delete(json);
		return -1;
	}
	record->para = (__u32)item->valuedouble;
	cJSON_Delete(json);
	flock(fp->_fileno, LOCK_UN);
	fclose(fp);
	return 0;
}
#else
bool conf_monitor_switch = false;

int get_tsn_record(struct tsn_conf_record *record)
{
	return -1;
}

void create_record(char *portname, int cmd, uint32_t index)
{
}
#endif

bool get_conf_monitor_status(void)
{
	return conf_monitor_switch;
}

/* tsn_capability_get()
 * To get the device's tsn capabilities
 * portname: port name of the net device
 * cap: pointer of tsn-capability, it is output parameter

 * return: < 0 error, 0 is ok
 */
int tsn_capability_get(char *portname, struct tsn_cap *cap)
{
	struct msgtemplate *msg;
	struct nlattr *stream_para_attr;
	int ret;
	struct showtable stream_para;

	if (portname == NULL)
		return -EINVAL;

	msg = tsn_send_cmd_prepare(TSN_CMD_CAP_GET);
	if (msg == NULL) {
		lloge("fail to allocate genl msg.\n");
		return -ENOMEM;
	}

	tsn_send_cmd_append_attr(msg, TSN_ATTR_IFNAME, portname,
				 strlen(portname) + 1);


	ret = tsn_send_to_kernel(msg);
	if (ret < 0) {
		lloge("genl send to kernel error\n");
		return ret;
	}

	/* TODO: receive the feedback and return */
	stream_para.type = TSN_CMD_CAP_GET;
	stream_para.len1 = TSN_CAP_ATTR_MAX;
	stream_para.link1 = &tsn_cap_para;
	stream_para.len2 = 0;
	stream_para.link2 = 0;
	stream_para.len3 = 0;
	stream_para.link3 = 0;
	return tsn_msg_recv_analysis(&stream_para, (void *)cap);

err:
	free(msg);
	return ret;
}

/* tsn_qci_streampara_get()
 * To get the stream parameter as spec 802.1Qci clause 12.31.1
 * portname: port name of the net device
 * sp: pointer of stream parameter struct, it is output parameter

 * return: < 0 error, 0 is ok
 */
int tsn_qci_streampara_get(char *portname,
				      struct tsn_qci_psfp_stream_param *sp)
{
	struct msgtemplate *msg;
	struct nlattr *stream_para_attr;
	int ret;
	struct showtable stream_para;

	if (portname == NULL)
		return -EINVAL;

	msg = tsn_send_cmd_prepare(TSN_CMD_QCI_CAP_GET);
	if (msg == NULL) {
		lloge("fail to allocate genl msg.\n");
		return -ENOMEM;
	}

	tsn_send_cmd_append_attr(msg, TSN_ATTR_IFNAME, portname,
				 strlen(portname) + 1);

	ret = tsn_send_to_kernel(msg);
	if (ret < 0) {
		lloge("genl send to kernel error\n");
		return ret;
	}

	/* TODO: receive the feedback and return */
	stream_para.type = TSN_ATTR_QCI_SP;
	stream_para.len1 = TSN_QCI_STREAM_ATTR_MAX;
	stream_para.link1 = &qci_stream_para;
	stream_para.len2 = 0;
	stream_para.link2 = 0;
	stream_para.len3 = 0;
	stream_para.link3 = 0;
	return tsn_msg_recv_analysis(&stream_para, (void *)sp);

err:
	free(msg);
	return ret;
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
		return -EINVAL;

	if (portname == NULL)
		return -EINVAL;

	msg = tsn_send_cmd_prepare(TSN_CMD_CB_STREAMID_SET);
	if (msg == NULL) {
		lloge("fail to allocate genl msg.\n");
		return -ENOMEM;
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
		lloge("error streamid type: only null stream identify supported now");
		goto err;
	}

	tsn_send_cmd_append_attr(msg, TSN_STREAMID_ATTR_TYPE,
			&(sid->type), sizeof(sid->type));

sendmsg1:
	tsn_nla_nest_end(msg, sidattr);

	ret = tsn_send_to_kernel(msg);
	if (ret < 0) {
		lloge("genl send to kernel error\n");
		return ret;
	}

	ret = tsn_msg_recv_analysis(NULL, NULL);
	if (ret >= 0 && get_conf_monitor_status())
		create_record(portname, TSN_CMD_CB_STREAMID_SET, sid_index);

	return ret;
err:
	free(msg);
	return -EINVAL;
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
	struct showtable streamidget;

	if (portname == NULL)
		return -EINVAL;

	if (sid == NULL) {
		lloge("error: please allocate the struct tsn_cb_streamid ");
		return -EINVAL;
	}

	msg = tsn_send_cmd_prepare(TSN_CMD_CB_STREAMID_GET);
	if (msg == NULL) {
		lloge("fail to allocate genl msg.\n");
		return -ENOMEM;
	}

	tsn_send_cmd_append_attr(msg, TSN_ATTR_IFNAME, portname, strlen(portname) + 1);

	sidattr = tsn_nla_nest_start(msg, TSN_ATTR_STREAM_IDENTIFY);
	if (!sidattr)
		goto err;

	tsn_send_cmd_append_attr(msg, TSN_STREAMID_ATTR_INDEX, &sid_index, sizeof(sid_index));

	tsn_nla_nest_end(msg, sidattr);

	ret = tsn_send_to_kernel(msg);
	if (ret < 0) {
		lloge("genl send to kernel error\n");
		return ret;
	}

	/* TODO : fill the sid */
	streamidget.type = TSN_ATTR_STREAM_IDENTIFY;
	streamidget.len1 = TSN_STREAMID_ATTR_MAX;
	streamidget.link1 = &cb_streamid;
	streamidget.len2 = 0;
	streamidget.len3 = 0;
	return tsn_msg_recv_analysis(&streamidget, (void *)sid);

err:
	free(msg);
	return -EINVAL;
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
		return -EINVAL;

	if (portname == NULL)
		return -EINVAL;

	msg = tsn_send_cmd_prepare(TSN_CMD_QCI_SFI_SET);
	if (msg == NULL) {
		lloge("fail to allocate genl msg.\n");
		return -ENOMEM;
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
		lloge("genl send to kernel error\n");
		return ret;
	}

	ret = tsn_msg_recv_analysis(NULL, NULL);
	if (ret >= 0 && get_conf_monitor_status())
		create_record(portname, TSN_CMD_QCI_SFI_SET, sfi_handle);

	return ret;
err:
	free(msg);
	return -EINVAL;
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
	struct showtable sfiget;

	if (portname == NULL)
		return -EINVAL;

	msg = tsn_send_cmd_prepare(TSN_CMD_QCI_SFI_GET);
	if (msg == NULL) {
		lloge("fail to allocate genl msg.\n");
		return -ENOMEM;
	}

	tsn_send_cmd_append_attr(msg, TSN_ATTR_IFNAME, portname, strlen(portname) + 1);

	qcisfi = tsn_nla_nest_start(msg, TSN_ATTR_QCI_SFI);
	if (!qcisfi)
		goto err;

	tsn_send_cmd_append_attr(msg, TSN_QCI_SFI_ATTR_INDEX, &sfi_handle, sizeof(sfi_handle));

	tsn_nla_nest_end(msg, qcisfi);

	ret = tsn_send_to_kernel(msg);
	if (ret < 0) {
		lloge("genl send to kernel error\n");
		return ret;
	}

	/* TODO: receive the feedback and return */
	sfiget.type = TSN_ATTR_QCI_SFI;
	sfiget.len1 = TSN_QCI_SFI_ATTR_MAX;
	sfiget.link1 = &qci_sfi;
	sfiget.len2 = 0;
	sfiget.len3 = 0;
	return tsn_msg_recv_analysis(&sfiget, (void *)sfi);
err:
	free(msg);
	return -EINVAL;
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
		return -EINVAL;

	msg = tsn_send_cmd_prepare(TSN_CMD_QCI_SFI_GET_COUNTS);
	if (msg == NULL) {
		lloge("fail to allocate genl msg.\n");
		return -ENOMEM;
	}

	tsn_send_cmd_append_attr(msg, TSN_ATTR_IFNAME, portname, strlen(portname) + 1);

	qcisfi = tsn_nla_nest_start(msg, TSN_ATTR_QCI_SFI);
	if (!qcisfi)
		goto err;

	tsn_send_cmd_append_attr(msg, TSN_QCI_SFI_ATTR_INDEX, &sfi_handle, sizeof(sfi_handle));

	tsn_nla_nest_end(msg, qcisfi);

	ret = tsn_send_to_kernel(msg);
	if (ret < 0) {
		lloge("genl send to kernel error\n");
		return ret;
	}

	/* TODO: receive the feedback and return */
	return tsn_msg_recv_analysis(NULL, (void *)sfic);

err:
	free(msg);
	return -EINVAL;
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
		return -EINVAL;

	if (portname == NULL)
		return -EINVAL;

	msg = tsn_send_cmd_prepare(TSN_CMD_QCI_SGI_SET);
	if (msg == NULL) {
		lloge("fail to allocate genl msg.\n");
		return -ENOMEM;
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
		lloge("error: list lenghth is not zero, but no gate control list\n");
		return -EINVAL;
	}

	gcl = sgi->admin.gcl;

	for (i = 0; i < listcount; i++) {
		int8_t ipv;
		uint32_t ti, omax;

		if ((gcl + i) == NULL) {
			lloge("Could not get as many as gate list entry compare control_list_length");
			return -EINVAL;
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
		lloge("genl send to kernel error\n");
		free(msg);
		return ret;
	}

	ret = tsn_msg_recv_analysis(NULL, NULL);
	if (ret >= 0 && get_conf_monitor_status())
		create_record(portname, TSN_CMD_QCI_SGI_SET, sgi_handle);

	return ret;
}

int tsn_qci_psfp_sgi_get(char *portname, uint32_t sgi_handle, struct tsn_qci_psfp_sgi_conf *sgi)
{
	struct msgtemplate *msg;
	struct nlattr *sgiattr;
	int ret;
	struct showtable sgiget;

	if (portname == NULL)
		return -EINVAL;

	msg = tsn_send_cmd_prepare(TSN_CMD_QCI_SGI_GET);
	if (msg == NULL) {
		lloge("fail to allocate genl msg.\n");
		return -ENOMEM;
	}

	tsn_send_cmd_append_attr(msg, TSN_ATTR_IFNAME, portname, strlen(portname) + 1);

	sgiattr = tsn_nla_nest_start(msg, TSN_ATTR_QCI_SGI);
	if (!sgiattr)
		goto err;

	tsn_send_cmd_append_attr(msg, TSN_QCI_SGI_ATTR_INDEX, &sgi_handle, sizeof(sgi_handle));

	tsn_nla_nest_end(msg, sgiattr);

	ret = tsn_send_to_kernel(msg);
	if (ret < 0) {
		lloge("genl send to kernel error\n");
		return ret;
	}

	/* TODO: receive the feedback and return */
	sgiget.type = TSN_ATTR_QCI_SGI;
	sgiget.len1 = TSN_QCI_SGI_ATTR_MAX;
	sgiget.link1 = &qci_sgi;
	sgiget.len2 = TSN_SGI_ATTR_CTRL_MAX;
	sgiget.link2 = &qci_sgi_ctrl;
	sgiget.len3 = TSN_SGI_ATTR_GCL_MAX;
	sgiget.link3 = qci_sgi_gcl;
	return tsn_msg_recv_analysis(&sgiget, (void *)sgi);

err:
	free(msg);
	return -EINVAL;
}

int tsn_qci_psfp_sgi_status_get(char *portname, uint32_t sgi_handle, struct tsn_psfp_sgi_status *sgi)
{
	struct msgtemplate *msg;
	struct nlattr *sgiattr;
	int ret;
	struct showtable sgiget;

	if (portname == NULL)
		return -EINVAL;

	msg = tsn_send_cmd_prepare(TSN_CMD_QCI_SGI_GET_STATUS);
	if (msg == NULL) {
		lloge("fail to allocate genl msg.\n");
		return -ENOMEM;
	}

	tsn_send_cmd_append_attr(msg, TSN_ATTR_IFNAME, portname, strlen(portname) + 1);

	sgiattr = tsn_nla_nest_start(msg, TSN_ATTR_QCI_SGI);
	if (!sgiattr)
		goto err;

	tsn_send_cmd_append_attr(msg, TSN_QCI_SGI_ATTR_INDEX, &sgi_handle, sizeof(sgi_handle));

	tsn_nla_nest_end(msg, sgiattr);

	ret = tsn_send_to_kernel(msg);
	if (ret < 0) {
		lloge("genl send to kernel error\n");
		return ret;
	}

	/* TODO: receive the feedback and return */
	sgiget.type = TSN_ATTR_QCI_SGI;
	sgiget.len1 = TSN_QCI_SGI_ATTR_MAX;
	sgiget.link1 = &qci_sgi;
	sgiget.len2 = TSN_SGI_ATTR_CTRL_MAX;
	sgiget.link2 = &qci_sgi_ctrl;
	sgiget.len3 = TSN_SGI_ATTR_GCL_MAX;
	sgiget.link3 = qci_sgi_gcl;
	return tsn_msg_recv_analysis(&sgiget, (void *)sgi);

err:
	free(msg);
	return -EINVAL;
}

int tsn_qci_psfp_fmi_set(char *portname, uint32_t fmi_id, bool enable, struct tsn_qci_psfp_fmi *fmiconf)
{
	struct msgtemplate *msg;
	struct nlattr *qcifmi;
	int ret;

	if (fmiconf == NULL)
		return -EINVAL;

	if (portname == NULL)
		return -EINVAL;

	msg = tsn_send_cmd_prepare(TSN_CMD_QCI_FMI_SET);
	if (msg == NULL) {
		lloge("fail to allocate genl msg.\n");
		return -ENOMEM;
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
		lloge("genl send to kernel error\n");
		return ret;
	}

	ret = tsn_msg_recv_analysis(NULL, NULL);
	if (ret >= 0 && get_conf_monitor_status())
		create_record(portname, TSN_CMD_QCI_FMI_SET, fmi_id);

	return ret;

err:
	free(msg);
	return -EINVAL;
}

int tsn_qci_psfp_fmi_get(char *portname, uint32_t fmi_id, struct tsn_qci_psfp_fmi *fmiconf)
{
	struct msgtemplate *msg;
	struct nlattr *qcifmi;
	int ret;
	struct showtable linkfmi;

	if (fmiconf == NULL)
		return -EINVAL;

	if (portname == NULL)
		return -EINVAL;

	msg = tsn_send_cmd_prepare(TSN_CMD_QCI_FMI_GET);
	if (msg == NULL) {
		lloge("fail to allocate genl msg.\n");
		return -ENOMEM;
	}

	tsn_send_cmd_append_attr(msg, TSN_ATTR_IFNAME, portname, strlen(portname) + 1);

	qcifmi = tsn_nla_nest_start(msg, TSN_ATTR_QCI_FMI);
	if (!qcifmi)
		goto err;

	tsn_send_cmd_append_attr(msg, TSN_QCI_FMI_ATTR_INDEX, &fmi_id, sizeof(fmi_id));

	tsn_nla_nest_end(msg, qcifmi);

	ret = tsn_send_to_kernel(msg);
	if (ret < 0) {
		lloge("genl send to kernel error\n");
		return ret;
	}

	linkfmi.type = TSN_ATTR_QCI_FMI; 
	linkfmi.len1 = TSN_QCI_FMI_ATTR_MAX;
	linkfmi.link1 = &qci_fmi;
	return tsn_msg_recv_analysis(&linkfmi, (void *)fmiconf);

err:
	free(msg);
	return -EINVAL;
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
		return -EINVAL;

	if (portname == NULL)
		return -EINVAL;

	msg = tsn_send_cmd_prepare(TSN_CMD_QBV_SET);
	if (msg == NULL) {
		lloge("fail to allocate genl msg.\n");
		return -ENOMEM;
	}

	tsn_send_cmd_append_attr(msg, TSN_ATTR_IFNAME, portname, strlen(portname) + 1);


	qbv = tsn_nla_nest_start(msg, TSN_ATTR_QBV);
	if (!qbv)
		return -EINVAL;

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
		return -EINVAL;

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
			llogv("set tsn_nla_nest_start TSN_QBV_ATTR_ADMINENTRY %d\n", i);

			if (!qbv_entry)
				return -EINVAL;

			uint8_t gs = (gatelist + i)->gate_state;
			uint32_t ti = (gatelist + i)->time_interval;

			tsn_send_cmd_append_attr(msg, TSN_QBV_ATTR_ENTRY_ID, &i, sizeof(i));
			tsn_send_cmd_append_attr(msg, TSN_QBV_ATTR_ENTRY_GC, &gs, sizeof(gs));
			tsn_send_cmd_append_attr(msg, TSN_QBV_ATTR_ENTRY_TM, &ti, sizeof(ti));

			count++; cycletime += ti;

			if (count > adminconf->admin.control_list_length) {
				lloge("entries count bigger than input cnt.\n");
				return -EINVAL;
			}

			tsn_nla_nest_end(msg, qbv_entry);

		}

		i++;

		if (i >= MAX_ENTRY_SIZE/sizeof(struct tsn_qbv_entry))
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
		lloge("genl send to kernel error\n");
		return ret;
	}

	ret = tsn_msg_recv_analysis(NULL, NULL);
	if (ret >= 0 && get_conf_monitor_status())
		create_record(portname, TSN_CMD_QBV_SET, 0);

	return ret;
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
	struct showtable qbvget; 

	if (qbvconf == NULL)
		return -EINVAL;

	msg = tsn_send_cmd_prepare(TSN_CMD_QBV_GET);
	if (msg == NULL) {
		lloge("fail to allocate genl msg.\n");
		return -ENOMEM;
	}

	tsn_send_cmd_append_attr(msg, TSN_ATTR_IFNAME, portname, strlen(portname) + 1);

	ret = tsn_send_to_kernel(msg);
	if (ret < 0) {
		lloge("genl send to kernel error\n");
		return ret;
	}
	/* TODO save to tsn_qbv_conf and admin list */
	qbvget.type = TSN_ATTR_QBV;
	qbvget.len1 = TSN_QBV_ATTR_MAX;
	qbvget.link1 = &qbv_base;
	qbvget.len2 = TSN_QBV_ATTR_CTRL_MAX;
	qbvget.link2 = &qbv_ctrl;
	qbvget.len3 = TSN_QBV_ATTR_ENTRY_MAX;
	qbvget.link3 = &qbv_entry;

	return tsn_msg_recv_analysis(&qbvget, (void *)qbvconf);
}

int tsn_qos_port_qbv_status_get(char *portname, struct tsn_qbv_status *qbvstatus)
{
	struct msgtemplate *msg;
	int ret;
	struct showtable qbvget;

	if (qbvstatus == NULL)
		return -EINVAL;

	msg = tsn_send_cmd_prepare(TSN_CMD_QBV_GET_STATUS);
	if (msg == NULL) {
		lloge("fail to allocate genl msg.\n");
		return -ENOMEM;
	}

	tsn_send_cmd_append_attr(msg, TSN_ATTR_IFNAME, portname, strlen(portname) + 1);

	ret = tsn_send_to_kernel(msg);
	if (ret < 0) {
		lloge("genl send to kernel error\n");
		return ret;
	}
	/* TODO save to struct tsn_qbv_status and oper list */
	qbvget.type = TSN_ATTR_QBV;
	qbvget.len1 = TSN_QBV_ATTR_MAX;
	qbvget.link1 = &qbv_base;
	qbvget.len2 = TSN_QBV_ATTR_CTRL_MAX;
	qbvget.link2 = &qbv_ctrl;
	qbvget.len3 = TSN_QBV_ATTR_ENTRY_MAX;
	qbvget.link3 = &qbv_entry;

	return tsn_msg_recv_analysis(&qbvget, (void *)qbvstatus);
}

int tsn_cbs_set(char *portname, uint8_t tc, uint8_t percent)
{
	struct msgtemplate *msg;
	struct nlattr *cbsattr;
	int ret;

	if (portname == NULL)
		return -EINVAL;

	msg = tsn_send_cmd_prepare(TSN_CMD_CBS_SET);
	if (msg == NULL) {
		lloge("fail to allocate genl msg.\n");
		return -ENOMEM;
	}

	tsn_send_cmd_append_attr(msg, TSN_ATTR_IFNAME, portname, strlen(portname) + 1);


	cbsattr = tsn_nla_nest_start(msg, TSN_ATTR_CBS);
	if (!cbsattr)
		return -EINVAL;

	tsn_send_cmd_append_attr(msg, TSN_CBS_ATTR_TC_INDEX, &tc, sizeof(tc));

	tsn_send_cmd_append_attr(msg, TSN_CBS_ATTR_BW, &percent, sizeof(percent));

	tsn_nla_nest_end(msg, cbsattr);

	ret = tsn_send_to_kernel(msg);
	if (ret < 0) {
		lloge("genl send to kernel error\n");
		return ret;
	}

	ret = tsn_msg_recv_analysis(NULL, NULL);
	if (ret >= 0 && get_conf_monitor_status())
		create_record(portname, TSN_CMD_CBS_SET, 0);

	return ret;
}

int tsn_cbs_get(char *portname, uint8_t tc)
{
	struct msgtemplate *msg;
	struct nlattr *cbsattr;
	int ret;

	if (portname == NULL)
		return -EINVAL;

	msg = tsn_send_cmd_prepare(TSN_CMD_CBS_GET);
	if (msg == NULL) {
		lloge("fail to allocate genl msg.\n");
		return -ENOMEM;
	}

	tsn_send_cmd_append_attr(msg, TSN_ATTR_IFNAME, portname, strlen(portname) + 1);

	cbsattr = tsn_nla_nest_start(msg, TSN_ATTR_CBS);
	if (!cbsattr)
		return -EINVAL;

	tsn_send_cmd_append_attr(msg, TSN_CBS_ATTR_TC_INDEX, &tc, sizeof(tc));

	tsn_nla_nest_end(msg, cbsattr);

	ret = tsn_send_to_kernel(msg);
	if (ret < 0) {
		lloge("genl send to kernel error\n");
		return ret;
	}

	return tsn_msg_recv_analysis(NULL, NULL);
}

int tsn_tsd_set(char *portname, bool enable, uint32_t period, uint32_t frame_num, bool imme)
{
	struct msgtemplate *msg;
	struct nlattr *cbsattr;
	int ret;

	if (portname == NULL)
		return -EINVAL;

	msg = tsn_send_cmd_prepare(TSN_CMD_TSD_SET);
	if (msg == NULL) {
		lloge("fail to allocate genl msg.\n");
		return -ENOMEM;
	}

	tsn_send_cmd_append_attr(msg, TSN_ATTR_IFNAME, portname, strlen(portname) + 1);


	cbsattr = tsn_nla_nest_start(msg, TSN_ATTR_TSD);
	if (!cbsattr)
		return -EINVAL;

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
		lloge("genl send to kernel error\n");
		return ret;
	}

	ret = tsn_msg_recv_analysis(NULL, NULL);
	if (ret >= 0 && get_conf_monitor_status())
		create_record(portname, TSN_CMD_TSD_SET, 0);

	return ret;
}

int tsn_tsd_get(char *portname)
{
	struct msgtemplate *msg;
	struct nlattr *cbsattr;
	int ret;

	if (portname == NULL)
		return -EINVAL;

	msg = tsn_send_cmd_prepare(TSN_CMD_TSD_GET);
	if (msg == NULL) {
		lloge("fail to allocate genl msg.\n");
		return -ENOMEM;
	}

	tsn_send_cmd_append_attr(msg, TSN_ATTR_IFNAME,
				 portname, strlen(portname) + 1);

	cbsattr = tsn_nla_nest_start(msg, TSN_ATTR_TSD);
	if (!cbsattr)
		return -EINVAL;

	tsn_nla_nest_end(msg, cbsattr);

	ret = tsn_send_to_kernel(msg);
	if (ret < 0) {
		lloge("genl send to kernel error\n");
		return ret;
	}

	return tsn_msg_recv_analysis(NULL, NULL);
}

int tsn_qbu_set(char *portname, uint8_t pt_vector)
{
	struct msgtemplate *msg;
	struct nlattr *qbuattr;
	int ret;

	if (portname == NULL)
		return -EINVAL;

	msg = tsn_send_cmd_prepare(TSN_CMD_QBU_SET);
	if (msg == NULL) {
		lloge("fail to allocate genl msg.\n");
		return -ENOMEM;
	}

	tsn_send_cmd_append_attr(msg, TSN_ATTR_IFNAME, portname, strlen(portname) + 1);


	qbuattr = tsn_nla_nest_start(msg, TSN_ATTR_QBU);
	if (!qbuattr)
		return -EINVAL;

	tsn_send_cmd_append_attr(msg, TSN_QBU_ATTR_ADMIN_STATE, &pt_vector, sizeof(pt_vector));

	tsn_nla_nest_end(msg, qbuattr);

	ret = tsn_send_to_kernel(msg);
	if (ret < 0) {
		lloge("genl send to kernel error\n");
		return ret;
	}

	ret = tsn_msg_recv_analysis(NULL, NULL);
	if (ret >= 0 && get_conf_monitor_status())
		create_record(portname, TSN_CMD_QBU_SET, 0);

	return ret;
}

int tsn_qbu_get_status(char *portname, struct tsn_preempt_status *pts)
{
	struct msgtemplate *msg;
	int ret;
	struct showtable qbuget;

	if (portname == NULL)
		return -EINVAL;

	msg = tsn_send_cmd_prepare(TSN_CMD_QBU_GET_STATUS);
	if (msg == NULL) {
		lloge("fail to allocate genl msg.\n");
		return -ENOMEM;
	}

	tsn_send_cmd_append_attr(msg, TSN_ATTR_IFNAME, portname, strlen(portname) + 1);

	ret = tsn_send_to_kernel(msg);
	if (ret < 0) {
		lloge("genl send to kernel error\n");
		return ret;
	}

	qbuget.type = TSN_ATTR_QBU;
	qbuget.len1 = TSN_QBU_ATTR_MAX;
	qbuget.link1 = &qbu_get;

	return tsn_msg_recv_analysis(&qbuget, (void *)pts);
}

int tsn_ct_set(char *portname, uint8_t pt_vector)
{
	struct msgtemplate *msg;
	struct nlattr *ctattr;
	int ret;

	if (portname == NULL)
		return -EINVAL;

	msg = tsn_send_cmd_prepare(TSN_CMD_CT_SET);
	if (msg == NULL) {
		lloge("fail to allocate genl msg.\n");
		return -ENOMEM;
	}

	tsn_send_cmd_append_attr(msg, TSN_ATTR_IFNAME, portname, strlen(portname) + 1);


	ctattr = tsn_nla_nest_start(msg, TSN_ATTR_CT);
	if (!ctattr)
		return -EINVAL;

	tsn_send_cmd_append_attr(msg, TSN_CT_ATTR_QUEUE_STATE, &pt_vector, sizeof(pt_vector));

	tsn_nla_nest_end(msg, ctattr);

	ret = tsn_send_to_kernel(msg);
	if (ret < 0) {
		lloge("genl send to kernel error\n");
		return ret;
	}

	ret = tsn_msg_recv_analysis(NULL, NULL);
	if (ret >= 0 && get_conf_monitor_status())
		create_record(portname, TSN_CMD_CT_SET, 0);

	return ret;
}

int tsn_cbgen_set(char *portname, uint32_t index,
		  struct tsn_seq_gen_conf *sg)
{
	struct msgtemplate *msg;
	struct nlattr *cbgenattr;
	int ret;

	if (portname == NULL)
		return -EINVAL;

	msg = tsn_send_cmd_prepare(TSN_CMD_CBGEN_SET);
	if (msg == NULL) {
		lloge("fail to allocate genl msg.\n");
		return -ENOMEM;
	}

	tsn_send_cmd_append_attr(msg, TSN_ATTR_IFNAME, portname, strlen(portname) + 1);


	cbgenattr = tsn_nla_nest_start(msg, TSN_ATTR_CBGEN);
	if (!cbgenattr)
		return -EINVAL;

	tsn_send_cmd_append_attr(msg, TSN_CBGEN_ATTR_INDEX, &index, sizeof(index));

	tsn_send_cmd_append_attr(msg, TSN_CBGEN_ATTR_PORT_MASK, &(sg->iport_mask), sizeof(sg->iport_mask));

	tsn_send_cmd_append_attr(msg, TSN_CBGEN_ATTR_SPLIT_MASK, &(sg->split_mask), sizeof(sg->split_mask));

	tsn_send_cmd_append_attr(msg, TSN_CBGEN_ATTR_SEQ_LEN, &(sg->seq_len), sizeof(sg->seq_len));

	tsn_send_cmd_append_attr(msg, TSN_CBGEN_ATTR_SEQ_NUM, &(sg->seq_num), sizeof(sg->seq_num));

	tsn_nla_nest_end(msg, cbgenattr);

	ret = tsn_send_to_kernel(msg);
	if (ret < 0) {
		lloge("genl send to kernel error\n");
		return ret;
	}

	ret = tsn_msg_recv_analysis(NULL, NULL);
	if (ret >= 0 && get_conf_monitor_status())
		create_record(portname, TSN_CMD_CBGEN_SET, index);

	return ret;
}

int tsn_cbrec_set(char *portname, uint32_t index,
		  struct tsn_seq_rec_conf *sr)
{
	struct msgtemplate *msg;
	struct nlattr *cbrecattr;
	int ret;

	if (portname == NULL)
		return -EINVAL;

	msg = tsn_send_cmd_prepare(TSN_CMD_CBREC_SET);
	if (msg == NULL) {
		lloge("fail to allocate genl msg.\n");
		return -ENOMEM;
	}

	tsn_send_cmd_append_attr(msg, TSN_ATTR_IFNAME, portname, strlen(portname) + 1);


	cbrecattr = tsn_nla_nest_start(msg, TSN_ATTR_CBREC);
	if (!cbrecattr)
		return -EINVAL;

	tsn_send_cmd_append_attr(msg, TSN_CBREC_ATTR_INDEX, &index, sizeof(index));

	tsn_send_cmd_append_attr(msg, TSN_CBREC_ATTR_SEQ_LEN, &(sr->seq_len), sizeof(sr->seq_len));

	tsn_send_cmd_append_attr(msg, TSN_CBREC_ATTR_HIS_LEN, &(sr->his_len), sizeof(sr->his_len));

	if(sr->rtag_pop_en)
		tsn_send_cmd_append_attr(msg, TSN_CBREC_ATTR_TAG_POP_EN,
					 &(sr->rtag_pop_en), 0);
	tsn_nla_nest_end(msg, cbrecattr);

	ret = tsn_send_to_kernel(msg);
	if (ret < 0) {
		lloge("genl send to kernel error\n");
		return ret;
	}

	ret = tsn_msg_recv_analysis(NULL, NULL);
	if (ret >= 0 && get_conf_monitor_status())
		create_record(portname, TSN_CMD_CBREC_SET, index);

	return ret;
}

int tsn_cbstatus_get(char *portname, uint32_t index,
		     struct tsn_cb_status *cbstat)
{
	struct msgtemplate *msg;
	struct nlattr *cbattr;
	int ret;
	struct showtable cbstatget;

	if (portname == NULL)
		return -EINVAL;

	msg = tsn_send_cmd_prepare(TSN_CMD_CBSTAT_GET);
	if (msg == NULL) {
		lloge("fail to allocate genl msg.\n");
		return -ENOMEM;
	}

	tsn_send_cmd_append_attr(msg, TSN_ATTR_IFNAME, portname, strlen(portname) + 1);

	cbattr = tsn_nla_nest_start(msg, TSN_ATTR_CBSTAT);
	if (!cbattr)
		goto err;

	tsn_send_cmd_append_attr(msg, TSN_CBSTAT_ATTR_INDEX, &index, sizeof(index));

	tsn_nla_nest_end(msg, cbattr);

	ret = tsn_send_to_kernel(msg);
	if (ret < 0) {
		lloge("genl send to kernel error\n");
		return ret;
	}

	/* TODO: receive the feedback and return */
	cbstatget.type = TSN_ATTR_CBSTAT;
	cbstatget.len1 = TSN_CBSTAT_ATTR_MAX;
	cbstatget.link1 = &cb_get;
	cbstatget.len2 = 0;
	cbstatget.len3 = 0;
	return tsn_msg_recv_analysis(&cbstatget, (void *)cbstat);
err:
	free(msg);
	return -EINVAL;
}

int tsn_dscp_set(char *portname, bool disable, int index,
		 struct tsn_qos_switch_dscp_conf *dscp_conf)
{
	struct msgtemplate *msg;
	struct nlattr *dscpattr;
	int ret;

	if (portname == NULL)
		return -EINVAL;

	msg = tsn_send_cmd_prepare(TSN_CMD_DSCP_SET);
	if (msg == NULL) {
		lloge("fail to allocate genl msg.\n");
		return -ENOMEM;
	}

	tsn_send_cmd_append_attr(msg, TSN_ATTR_IFNAME, portname, strlen(portname) + 1);


	dscpattr = tsn_nla_nest_start(msg, TSN_ATTR_DSCP);
	if (!dscpattr)
		return -EINVAL;

	tsn_send_cmd_append_attr(msg, TSN_DSCP_ATTR_INDEX, &index, sizeof(index));
	if (disable)
		tsn_send_cmd_append_attr(msg, TSN_DSCP_ATTR_DISABLE,
					 &(disable), 0);


	tsn_send_cmd_append_attr(msg, TSN_DSCP_ATTR_COS, &(dscp_conf->cos), sizeof(int)/*sizeof(dscp_conf->cos)*/);

	tsn_send_cmd_append_attr(msg, TSN_DSCP_ATTR_DPL, &(dscp_conf->dpl), sizeof(int)/*sizeof(dscp_conf->dpl)*/);

	tsn_nla_nest_end(msg, dscpattr);

	ret = tsn_send_to_kernel(msg);
	if (ret < 0) {
		lloge("genl send to kernel error\n");
		return ret;
	}

	ret = tsn_msg_recv_analysis(NULL, NULL);
	if (ret >= 0 && get_conf_monitor_status())
		create_record(portname, TSN_CMD_DSCP_SET, index);

	return ret;
}
