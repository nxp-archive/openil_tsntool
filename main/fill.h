// SPDX-License-Identifier: (GPL-2.0 OR MIT)
/*
 * Copyright 2018-2019 NXP
 */

#ifndef __END_DEF_FILL_H__
#define __END_DEF_FILL_H__
int fill_qbv_set(char *portname, char *config, bool enable, uint8_t configchange,
		uint64_t basetime, uint32_t cycletime,
		uint32_t cycletimeext, uint32_t maxsdu, uint8_t initgate);

int fill_qbv_get(char *portname);

int fill_qci_sfi_set(char *portname, uint32_t streamfilterid, uint8_t enable,
			int32_t streamhandle, int8_t priority, uint32_t gateid,
			uint16_t maxsdu, int32_t flowmeterid, uint8_t osenable, uint8_t oversize);

int fill_qci_sfi_get(char *portname, int32_t streamfilter);

int fill_cb_streamid_set(char *portname, uint32_t index, int8_t enable,
						struct tsn_cb_streamid *streamid);

int fill_cbstreamid_get(char *portname, int32_t index);

int fill_qci_sgi_set(char *portname, uint32_t index, bool enable, char *listtable,
				bool configchange, bool blkinvrx_en, bool blkinvrx,
				bool blkoctex_en, bool blkoctex,
				bool initgate, int8_t initipv, uint64_t basetime,
				uint32_t cycletime, uint32_t cycletimeext);

int fill_qci_sgi_status_get(char *portname, int32_t sgi_handle);

int fill_qci_fmi_set(char *portname, uint32_t index, bool enable, uint32_t cir,
		uint32_t cbs, uint32_t eir, uint32_t ebs, bool cf, bool cm,
		bool dropyellow, bool markred_en, bool markred);
int fill_qci_fmi_get(char *portname, uint32_t index);
int fill_cbs_set(char *portname, uint8_t tc, uint8_t percentage);
int fill_cbs_get(char *portname, uint8_t tc);
int fill_tsd_set(char *portname, bool enable, uint32_t period, uint32_t frame_num, bool imme);
int fill_tsd_get(char *portname);
int fill_qbu_set(char *portname, uint8_t preemptable);
int fill_qbu_get_status(char *portname);
int fill_ct_set(char *portname, uint8_t queue_stat);
int fill_cbgen_set(char *portname, uint32_t index, uint8_t iport_mask, uint8_t split_mask, uint8_t seq_len, uint32_t seq_num);
int fill_cbrec_set(char *portname, uint32_t index, uint8_t seq_len, uint8_t his_len, bool rtag_pop_en);
int fill_pcpmap_set(char *portname, bool enable);
int fill_dscp_set(char *portname, bool disable, int index, int cos, int dpl);
#endif
