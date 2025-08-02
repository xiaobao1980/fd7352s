/* SPDX-License-Identifier: GPL-2.0 */

/******************************************************************************
 *
 * Copyright (C) 2020 SeekWave Technology Co.,Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 ******************************************************************************/

#ifndef __SKW_RX_H__
#define __SKW_RX_H__

#include <net/ieee80211_radiotap.h>

#include "skw_platform_data.h"
#include "skw_iface.h"
#include "skw_core.h"
#include "skw_tx.h"

#define SKW_MAX_AMPDU_BUF_SIZE            0x100 /* 256 */

#define SKW_AMSDU_FLAG_TAINT              BIT(0)
#define SKW_AMSDU_FLAG_VALID              BIT(1)

#define SKW_SDIO_RX_DESC_HDR_OFFSET       0
#define SKW_SDIO_RX_DESC_MSDU_OFFSET      52
#define SKW_USB_RX_DESC_HDR_OFFSET        52
#define SKW_USB_RX_DESC_MSDU_OFFSET       0
#define SKW_PCIE_RX_DESC_HDR_OFFSET       44
#define SKW_PCIE_RX_DESC_MSDU_OFFSET      8
#define SKW_RX_DESC_PUSH_OFFSET           0
#define SKW_RX_DESC_PN_REUSE_PUSH_OFFSET  4
#define SKW_RX_PN_REUSE_MSDU_OFFSET       74

#ifndef ETH_P_80211_RAW
#define ETH_P_80211_RAW (ETH_P_ECONET + 1)
#endif

#define CalRssiVal(RssiInit) (RssiInit & BIT(10) ? ((s16)((u16)(RssiInit>>3) | 0xFF00)) : ((s16)(RssiInit>>3)))

#define SKW_RX_MSDU_LEN(skw, desc) \
	(test_bit(SKW_FLAG_FW_PN_REUSE, &skw->flags) ? (desc)->pn_reuse.msdu_len : (desc)->msdu.msdu_len)

#define SKW_RX_MSDU_OFFSET(skw, desc) \
	(test_bit(SKW_FLAG_FW_PN_REUSE, &skw->flags) ? (desc)->pn_reuse.msdu_offset : (desc)->msdu.msdu_offset)

#define SKW_RX_AMSDU_IDX(skw, desc) \
	(test_bit(SKW_FLAG_FW_PN_REUSE, &skw->flags) ? (desc)->pn_reuse.amsdu_idx : (desc)->msdu.amsdu_idx)

#define SKW_RX_PN(skw, desc) \
	(test_bit(SKW_FLAG_FW_PN_REUSE, &skw->flags) ? (desc)->pn_reuse.pn : (desc)->pn_not_reuse)

enum SKW_RELEASE_REASON {
	SKW_RELEASE_INVALID,
	SKW_RELEASE_EXPIRED,
	SKW_RELEASE_OOB,
	SKW_RELEASE_BAR,
	SKW_RELEASE_FREE,
};

struct skw_skb_rxcb {
	unsigned long rx_time;
	u16 rx_desc_offset;
	u8 amsdu_bitmap;
	u8 amsdu_mask;
	u16 amsdu_flags;
	u8 skw_created;
	u8 lmac_id;
	u8 skip_replay_detect;
	dma_addr_t pa;
	u16 edma_node_idx;
};

struct skw_drop_sn_info {
	u16 sn;
	u8 amsdu_idx;
	u8 amsdu_first:1;
	u8 amsdu_last:1;
	u8 is_amsdu:1;
	u8 qos:1;
	u8 tid:4;
	u32 peer_idx:5;
	u32 inst:2;
	u32 resved:25;
} __packed;

struct skw_rt_hdr {
	struct ieee80211_radiotap_header rt_hdr;
	u32 it_present1;
	u32 it_present2;
	u8 rt_flags;	/* radiotap packet flags */
	u8 rt_rate;	/* rate in 500kb/s */
	u16 rt_channel;	/* channel in mhz */
	u16 rt_chbitmask;	/* channel bitfield */
	s8 rt_antenna_signal;
	u8 rt_antenna;
	u16 rt_rx_flags;
	s8 rt_antenna0_signal;
	u8 rt_antenna0;
	s8 rt_antenna1_signal;
	u8 rt_antenna1;
	u8 payload[];  /* payload... */
} __packed;

struct skw_rx_mpdu_desc {
    /*word0*/
    u32 NextMpduBuffAddrL;
    /*word1*/
    u8 NextMpduBuffAddrH;
    u8 Rvd0[2];
    u8 SwUseForChan;
    /*word2*/
    u16 HostPktLen; /*desc + mac header + Algin 8byte + msdu (no cipher)*/
    u8 BuffNumOfMpdu;
    u8 MpduProcStatus;
    /*word3*/
    u16 MpduLen:14; /*mac header + msdu  + cipher + Fcs (If no aggr,psdu len)*/
    u16 Rvd1:2;
    u16 MpduIdxInPsdu:9;
    u16 MpduMacHdrLen:6;
    u16 Rvd2:1;
    /*word4*/
    u8 FrameType:6;
    u8 MpduUcDirectFlag:1;
    u8 MpduUBcMcFlag:1;
    u8 Rvd6:1;
    u8 AmpduFlag:1;
    u8 AmsduFlag:1;
    u8 MpduDataFrmToHost:1;
    u8 MpduDefrgFlag:1;
    u8 SwUseForBand:3;
    u8 PeerLutIndex:5;
    u8 PeerLutIndexVld:1;
    u8 Rvd4:2;
    u8 CipherTypeInLut:4;
    u8 MpduRaIndex:2;
    u8 MpduRaIndexVld:1;
    u8 RttInProc:1;
    /*word5*/
    u32 MpduPnL;
    /*word6*/
    u16 MpduPnH;
    u16 MpduSn:12;
    u16 MpduFragNum:4;
    /*word7*/
    u32 TimeStamp_RxFtmT2;    //only rtt proc valid(0x40820288 bit1) indicate RxFtmT2
    /*word8*/
    u32 MpduComTsf_RxFtmT3;   //only rtt proc valid(0x40820288 bit1) indicate RxFtmT3
    /*word9*/
    u32 FlockRssi0:11;
    u32 FlockRssi1:11;
    u32 LpSnr0:7;
    u32 Nss:2;
    u32 SigbDcm:1;
    /*word10*/
    u32 FullRssi0:11;
    u32 FullRssi1:11;
    u32 LpSnr1:7;
    u32 Sbw:3;
    /*word11*/
    u32 Ch0AgcGain0:8;
    u32 Ch0AgcGain1:8;
    u32 PpduMode:4; //RX_MPDU_PPDUMODE_E
    u32 Dcm:1;
    u32 GiType:2;
    u32 FecCoding:1;
    u32 Rate:6;
    u32 EssNExtSs:2;
    /*word12*/
    u32 StaId:11;
    u32 RuSize:3;
    u32 SigbCompre:1;
    u32 Doppler:1;
    u32 Sr4:4;
    u32 Sr3:4;
    u32 Sr2:4;
    u32 Sr1:4;
    /*word13*/
    u32 GroupId:6;
    u32 PartialAid:9;
    u32 Beamfored:1;
    u32 TxopDuration:14;
    u32 LtfType:2;
    /*word14*/
    u32 Ch1AgcGain0:8;
    u32 Ch1AgcGain1:8;
    u32 ServiceField:16;
    /*word15*/
    u32 SfoPpmInit:24;
    u32 PhyRxPlcpDelay:8;
    /*word16*/
    u32 SlockRssi0:11;
    u32 SlockRssi1:11;
    u32 Nsts:2;
    u32 BssColor:6;
    u32 TgnfFlag0:1;
    u32 TgnfFlag1:1;
    /*word17*/
    u32 MacHdrProcStatus:7;
    u32 Rsv5:1;
    u32 UserNum:7;
    u32 Stbc:1;
    u32 Mu3Nsts:3;
    u32 Mu2Nsts:3;
    u32 Mu1Nsts:3;
    u32 Mu0Nsts:3;
};

struct skw_rx_desc {
	/* word 14 */
	union {
		u32 resv;
		struct {
			u16 msdu_len:14;
			u16 resv:2;
			u8 msdu_offset;
			u8 amsdu_idx;
		}__packed msdu;
	};
	//u16 pkt_len; //caculate it

	/* word 15 */
	u16 csum;
	u8 msdu_filter;

	u8 csum_valid:1;
	u8 snap_type:1;
	u8 snap_match:1;
	u8 vlan:1;
	u8 eapol:1;
	u8 amsdu_first_idx:1;
	u8 amsdu_last_idx:1;
	u8 first_msdu_in_buff:1;

	/* word 16 */
	u16 sn:12; /* seq number */
	u16 frag_num:4;

	u16 inst_id:2; //mpdu_ra_index
	u16 inst_id_valid:1;
	u16 more_frag:1;
	u32 peer_idx:5;
	u32 peer_idx_valid:1;
	u16 more_data:1;
	u16 pm:1;
	u16 eosp:1;
	u16 ba_session:1;
	u16 rcv_in_ps_mode:1;
	u16 mac_drop_frag:1;

	/* word 17 & word18*/
	union {
		struct {
			u16 msdu_len:14;
			u16 resv:2;
			u8  msdu_offset;
			u8  amsdu_idx;
			u8  pn[2];
		}__packed pn_reuse;
		u8 pn_not_reuse[6];
	};
	//u16 credit; //6316 doesn't provide it keep it with 0
	u16 tid:4;
	u16 rsvd:4;
	u16 is_amsdu:1;
	u16 is_qos_data:1;
	u16 retry_frame:1;
	u16 is_ampdu:1;
	u16 need_forward:1;//da_ra_diff
	u16 is_mc_addr:1; //bc_mc_flag
	u16 is_eof:1; //mpdu_eof_flag
	u16 rx_dma_wr_comp:1;
} __packed;

static inline void skw_snap_unmatch_handler(struct sk_buff *skb)
{
	skb_reset_mac_header(skb);
	eth_hdr(skb)->h_proto = htons(skb->len & 0xffff);
}

static inline void skw_event_add_credit(struct skw_core *skw, void *data)
{
	u16 *credit = data;

	skw_add_credit(skw, 0, *credit);
	skw_add_credit(skw, 1, *(credit + 1));
}

static inline void skw_data_add_credit(struct skw_core *skw, void *data)
{
}

static inline bool is_skw_monitor_data(struct skw_core *skw, void *data)
{
	bool ret;
	struct skw_iface *iface;
	struct skw_rx_desc *desc;

	desc = (struct skw_rx_desc *)data;
	iface = to_skw_iface(skw, desc->inst_id);
	if (iface && iface->ndev && iface->ndev->ieee80211_ptr->iftype == NL80211_IFTYPE_MONITOR)
		ret = true;
	else
		ret = false;

	skw_detail("is_skw_monitor_data:%d\n", ret);

	return ret;
}

static inline struct skw_skb_rxcb *SKW_SKB_RXCB(struct sk_buff *skb)
{
	return (struct skw_skb_rxcb *)skb->cb;
}

int skw_add_tid_rx(struct skw_peer *peer, u16 tid, u16 ssn, u16 buf_size);
int skw_update_tid_rx(struct skw_peer *peer, u16 tid, u16 ssn, u16 win_size);
int skw_del_tid_rx(struct skw_peer *peer, u16 tid);

int skw_rx_process(struct skw_core *skw,
	struct sk_buff_head *rx_dat_q, struct skw_list *rx_todo_list);
void skw_rx_todo(struct skw_list *todo_list);

int skw_rx_init(struct skw_core *skw);
int skw_rx_deinit(struct skw_core *skw);
int skw_rx_cb(int port, struct scatterlist *sglist, int nents, void *priv);
int skw_register_rx_callback(struct skw_core *skw, void *cmd_cb, void *cmd_ctx,
			void *dat_cb, void *dat_ctx);

#endif
