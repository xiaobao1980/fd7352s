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

#ifndef __SKW_EDMA_H__
#define __SKW_EDMA_H__

#define SKW_EDMA_VIRTUAL_CMD_PORT                      32
#define SKW_EDMA_CHN_CMD                               14
#define SKW_EDMA_CHN_SHORT_EVENT                       15
#define SKW_EDMA_CHN_LONG_EVENT                        16
#define SKW_EDMA_CHN_MAC_0_RX_FITER                    17
#define SKW_EDMA_CHN_MAC_1_RX_FITER                    18
#define SKW_EDMA_CHN_MAC_0_TX                          19
#define SKW_EDMA_CHN_MAC_1_TX                          20
#define SKW_EDMA_CHN_MAC_0_TXC                         21
#define SKW_EDMA_CHN_MAC_1_TXC                         22
#define SKW_EDMA_CHN_MAC_0_RX_RING                     23
#define SKW_EDMA_CHN_MAC_1_RX_RING                     24
#define SKW_EDMA_CHN_MAC_0_RX                          25
#define SKW_EDMA_CHN_MAC_1_RX                          26

#define SKW_EDMA_NODE_NUM_CMD                          1
#define SKW_EDMA_NODE_NUM_SHORT_EVENT                  2
#define SKW_EDMA_NODE_NUM_LONG_EVENT                   8
#define SKW_EDMA_NODE_NUM_RX_FILTER                    4
#define SKW_EDMA_NODE_NUM_TX                           64
#define SKW_EDMA_NODE_NUM_TXC                          16
#define SKW_EDMA_NODE_NUM_RX_RING                      12 // max skb: 32 * 24
#define SKW_EDMA_NODE_NUM_RX                           12

#define SKW_EDMA_BUFF_LEN_DEFAULT                      2312 // 2304 + 8
#define SKW_EDMA_BUFF_LEN_TX                           768  // 64 * sizeof(struct skw_edma_elem)
#define SKW_EDMA_BUFF_LEN_TXC                          512  // 64 * ADDR_LEN(8)
#define SKW_EDMA_BUFF_LEN_RX_RING                      480  // 60 * ADDR_LEN(8)
#define SKW_EDMA_BUFF_LEN_RX                           512  // 64 * ADDR_LEN(8)

#define SKW_EDMA_SKB_DATA_LEN                          2048

#define SKW_EDMA_ADDR_LEN                              8
#define SKW_EDMA_ADDR_ALIGN                            32
#define SKW_EDMA_ADDR_FLAG                             (1ULL << 39)
#define SKW_EDMA_ADDR_MASK                             ((1ULL << 39) - 1)

#define SKW_EDMA_TX_HIGH_THRESHOLD                      3000
#define SKW_EDMA_TX_LOW_THRESHOLD                       1800

#define SKW_EDMA_INIT_ALLOC_SG                         BIT(0)
#define SKW_EDMA_INIT_ADDR_BUFF                        BIT(1)

typedef int (*skw_edma_isr)(void *priv, u64 first_pa, u64 last_pa, int cnt);
typedef void (*show_func)(struct seq_file *seq, void *data);

enum SKW_EDMA_DIRECTION {
	SKW_HOST_TO_FW = 0,
	SKW_FW_TO_HOST,
};

enum SKW_EDMA_CHN_PRIORITY {
	SKW_EDMA_CHN_PRIORITY_0,
	SKW_EDMA_CHN_PRIORITY_1,
	SKW_EDMA_CHN_PRIORITY_2,
	SKW_EDMA_CHN_PRIORITY_3
};

enum SKW_EDMA_CHN_BUFF_ATTR {
	SKW_EDMA_CHN_BUFF_LINNER,
	SKW_EDMA_CHN_BUFF_NON_LINNER,
};

enum SKW_EDMA_CHN_BUFF_TYPE {
	SKW_EDMA_CHN_LIST_BUFF,
	SKW_EDMA_CHN_RING_BUFF
};

enum SKW_EDMA_CHN_TRANS_MODE {
	SKW_EDMA_CHN_STD_MODE,
	SKW_EDMA_CHN_LINKLIST_MODE,
};

struct skw_edma_elem {
	u64 eth_hdr_pa:40;
	u64 rsv:8;

	u64 eth_type:16;

	u8 id_rsv:2;
	u8 mac_id:2;
	u8 tid:4;

	u8 peer_idx:5;
	u8 prot:1;
	u8 encry_dis:1;
	u8 rate:1;

	u16 msdu_len:12;
	u16 resv:4;
} __packed;

struct skw_edma_hw {
	u64 list_addr;
	int idx;
	int buff_len;

	u64 buff_addr:40;
	u64 resv:16;
	u64 tx_int:1;
	u64 rsv1:6;
	u64 done:1;

	struct {
		u64 next_list:40;
		u64 rsv2:8;
		u64 xmit_len:16;
	} list;

	char buff[0];
};

struct skw_edma_node {
	struct skw_edma_node *next;
	struct sk_buff_head skb_list;
	struct skw_edma_hw *hw;
	atomic_t ref;
};

struct skw_edma_ctx {
	void *dma_va;
	struct skw_edma_node *node, *cur;

	int nr_node;
	int dma_size;
	dma_addr_t dma_pa;
};

#define SKW_EDMA_FLAG_CHAN_INIT             0
#define SKW_EDMA_FLAG_MASK_IRQ              1
#define SKW_EDMA_FLAG_ADDR_BUFF             2

struct skw_edma_channel {
	struct scatterlist *sgl; // for command ack & event

	struct device *dev;
	struct skw_core *skw;
	struct skw_lmac *lmac;
	struct skw_edma_ctx ctx;

	atomic_t flags;
	struct skw_channel_cfg cfg;
	// spinlock_t lock;
	show_func show;

	int channel;
};

#ifdef CONFIG_SKW6316_EDMA
int skw_edma_pending_skb(struct skw_core *skw, int id);
int skw_edma_init(struct wiphy *wiphy);
void skw_edma_deinit(struct wiphy *wiphy);
void skw_edma_enable(struct skw_core *skw, int id);
void skw_edma_disable(struct skw_core *skw, int id);
int skw_edma_req(struct skw_edma_channel *echn, int nr_node);
void skw_edma_msg_enable(struct skw_core *skw);
#else
static inline int skw_edma_init(struct wiphy *wiphy)
{
	return 0;
}

static inline void skw_edma_deinit(struct wiphy *wiphy)
{
}

static inline void skw_edma_msg_enable(struct skw_core *skw)
{
}

static inline void skw_edma_enable(struct skw_core *skw, int id)
{
}

static inline void skw_edma_disable(struct skw_core *skw, int id)
{
}

static inline int skw_edma_req(struct skw_edma_channel *echn, int nr_node)
{
	return 0;
}

static inline int skw_edma_pending_skb(struct skw_core *skw, int id)
{
	return 0;
}

#endif
#endif
