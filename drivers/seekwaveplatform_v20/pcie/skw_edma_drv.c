/*
 * Copyright (C) 2022 Seekwave Tech Inc.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#include "asm-generic/int-ll64.h"
#include "linux/compiler.h"
#include "linux/gfp.h"
#include <linux/platform_device.h>
#include <uapi/linux/sched/types.h>
#include <linux/scatterlist.h>
#include <linux/dma-mapping.h>
#include <linux/version.h>
#include <linux/semaphore.h>
#include <linux/pm_runtime.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/err.h>
#include <linux/delay.h>
#include <linux/tracepoint.h>
#include <linux/iopoll.h>
#include <linux/dma-direct.h>
#include "skw_pcie_drv.h"
#include "skw_pcie_log.h"
#include "skw_pcie_debugfs.h"
#include "skw_edma_reg.h"
#include "skw_edma_drv.h"
#include "trace.h"


extern int cp_exception_sts;
static u64 port_dmamask = DMA_BIT_MASK(32);
struct edma_port edma_ports[MAX_PORT_NUM] = {0};
static struct platform_device *wifi_data_pdev;
#ifdef CONFIG_BT_SEEKWAVE
static struct platform_device *bt_data_pdev;
#endif
char firmware_version[128];
u32 last_sent_wifi_cmd[3];
u32 port_sta_rec[32] = {0};
u8 *at_buffer;
char *bt_rx_buffer[4];
char *port_state[] = {"IDLE", "OPEN", "CLOSE", "ASSERT", "BUSY"};

extern int send_modem_assert_command(void);
struct skw_channel_cfg edma_channels[MAX_EDMA_COUNT];
struct edma_chn_info edma_chns_info[32] = {0};

void __attribute__((unused)) skw_edma_unlock(void)
{
	struct wcn_pcie_info *priv = get_pcie_device_info();
#ifdef CONFIG_WAKELOCK
	__pm_relax(&priv->wake_lock.ws);
#else
	__pm_relax(priv->ws);
#endif
}

static void __attribute__((unused)) skw_edma_lock(void)
{
	struct wcn_pcie_info *priv = get_pcie_device_info();
#ifdef CONFIG_WAKELOCK
	__pm_stay_awake(&priv->wake_lock.ws);
#else
	__pm_stay_awake(priv->ws);
#endif
}

void __attribute__((unused)) skw_edma_lock_event(void)
{
	struct wcn_pcie_info *priv = get_pcie_device_info();
	
#ifdef CONFIG_WAKELOCK
	wake_lock_timeout(&priv->wake_lock, jiffies_to_msecs(HZ / 2));
#else
	__pm_wakeup_event(priv->ws_event, jiffies_to_msecs(HZ / 2));
#endif
}

static void __attribute__((unused)) skw_edma_wakeup_source_init(void)
{
	struct wcn_pcie_info *priv = get_pcie_device_info();
#ifdef CONFIG_WAKELOCK
	wake_lock_init(&priv->wake_lock, WAKE_LOCK_SUSPEND,"skw edma wake lock");
	wake_lock_init(&priv->wake_lockevent, WAKE_LOCK_SUSPEND,"skw edma wake lock evevnt");
#else
	priv->ws = skw_wakeup_source_register(NULL, "skw edma wake lock");
	priv->ws_event = skw_wakeup_source_register(NULL, "skw edma wake lock evevnt");
#endif
}
static void skw_edma_wakeup_source_destroy(void)
{
	struct wcn_pcie_info *priv = get_pcie_device_info();
#ifdef CONFIG_WAKELOCK
	wake_lock_destroy(&priv->rx_wl);
	wake_lock_destroy(&priv->wake_lockevent);
#else
	wakeup_source_unregister(priv->ws);
	wakeup_source_unregister(priv->ws_event);
#endif
}

void skw_get_port_statistic(char *buffer, int size)
{
	int ret = 0;
	int i;
	if(!buffer)
		return;
	for(i=0; i<MAX_PORT_NUM; i++)
	{
		if(ret >= size)
			break;
		if(edma_ports[i].state)
			ret += sprintf(&buffer[ret], "port%d: rx %d, tx  %d\n",
					i,edma_ports[i].rx_size,edma_ports[i].tx_size);
	}
}

static void edma_spin_lock_init(struct wcn_pcie_info *priv)
{
	priv->spin_lock = kmalloc(sizeof(spinlock_t), GFP_KERNEL);
	spin_lock_init(priv->spin_lock);
}

struct edma_chn_info *get_edma_channel_info(int id)
{
	return &edma_chns_info[id];
}

struct edma_port *get_edma_port_info(int portno)
{
	return &edma_ports[portno];
}

void *edma_coherent_rcvheader_to_cpuaddr(u64 rcv_pcie_addr, struct edma_chn_info *edma_chp)
{
	u32 offset;
	void *cpu_addr;

	offset = rcv_pcie_addr - edma_chp->chn_cfg.header;
	cpu_addr = (void *)((char *)edma_chp->hdr_virt_addr + 8 + offset);
	return cpu_addr;
}

u32 edma_clear_node_count(int channel)
{
	u32 ret = 0;
	struct edma_chn_info *edma_chp = get_edma_channel_info(channel);

	if (edma_chp->chn_cfg.direction == EDMA_TX)
		ret = skw_pcie_read32(DMA_SRC_INT_DSCR_HIGH(channel));
	else
		ret = skw_pcie_read32(DMA_DST_INT_DSCR_HIGH(channel));

	return ret;
}

int edma_get_node_tot_cnt(int channel)
{
	DMA_NODE_TOT_CNT_S node_cnt;

	node_cnt.u32 = skw_pcie_read32(DMA_NODE_TOT_CNT(channel));

	return node_cnt.src_tot_node_num;
}

static int inline is_legacy_irq_wifi_takeover(int ch_id)
{
#define SKW_EDMA_WIFI_CHANNELS_BITMAP      0x7FFC000   /* channel 14 - 26 */
	return SKW_EDMA_WIFI_CHANNELS_BITMAP & BIT(ch_id);
}

int legacy_edma_irq_handle(void)
{
	struct edma_chn_info *edma_chp;
	struct wcn_pcie_info *priv = get_pcie_device_info();
	int ch_id;
	EDMA_ADDR_T node_addr0={0}, node_addr1={0};
	u64 header, tail;
	u32 count;
	u64 val;

	DMA_SRC_INT_DSCR_HIGH_S chn_src_node_cnt;
	DMA_DST_INT_DSCR_HIGH_S chn_dst_node_cnt;
	DMA_SRC_INT_S reg_chn_src_int = {0};
	DMA_DST_INT_S reg_chn_dst_int = {0};
	u32 status;
	ulong flags;

	spin_lock_irqsave(priv->spin_lock, flags);
	status = skw_pcie_read32(DMA_INT_MASK_STS);

	if (!status) {
		spin_unlock_irqrestore(priv->spin_lock, flags);
		return 0;
	}

	for (ch_id=0; ch_id<MAX_EDMA_COUNT;ch_id++) {
		if (status & (1<<ch_id)) {
			edma_chp = get_edma_channel_info(ch_id);
			if (edma_chp->chn_cfg.direction == EDMA_TX) {//tx
				reg_chn_src_int.u32 = skw_pcie_read32(DMA_SRC_INT(ch_id));
				if (reg_chn_src_int.src_complete_mask_sts) {
					if (is_legacy_irq_wifi_takeover(ch_id)) {
						legacy_irq_wifi_takeover_handler(ch_id);
						continue;
					}

					reg_chn_src_int.src_complete_int_clr = 1;
					skw_pcie_write32(DMA_SRC_INT(ch_id), reg_chn_src_int.u32);
					node_addr0.addr_l32 = skw_pcie_read32(DMA_SRC_INT_DSCR_HEAD_LOW(ch_id));
					node_addr1.addr_l32 = skw_pcie_read32(DMA_SRC_INT_DSCR_TAIL_LOW(ch_id));
					chn_src_node_cnt.u32 = skw_pcie_read32(DMA_SRC_INT_DSCR_HIGH(ch_id));
					count = chn_src_node_cnt.src_node_done_num;

					node_addr0.addr_h8 = chn_src_node_cnt.src_int_dscr_head_high;
					val = node_addr0.addr_h8;
					header = (u64)(((node_addr0.addr_l32 & 0xffffffff) | ((val & 0xff) << 32)));

					node_addr1.addr_h8 = chn_src_node_cnt.src_int_dscr_tail_high;
					val = node_addr1.addr_h8;
					tail = (u64)(((node_addr1.addr_l32 & 0xffffffff) | ((val & 0xff) << 32)));
					if(edma_chp->chn_cfg.complete_callback){
						edma_chp->chn_cfg.complete_callback(edma_chp->chn_cfg.context, header,tail, count);
					}
					if(reg_chn_src_int.src_list_empty_mask_sts){
						reg_chn_src_int.src_list_empty_int_clr = 1;
						skw_pcie_write32(DMA_SRC_INT(ch_id), reg_chn_src_int.u32);
						if (edma_chp->chn_cfg.empty_callback)
							edma_chp->chn_cfg.empty_callback(edma_chp->chn_cfg.context);
					}
				}
			} else {//rx
				reg_chn_dst_int.u32 = skw_pcie_read32(DMA_DST_INT(ch_id));
				if (reg_chn_dst_int.dst_complete_mask_sts) {
					if (is_legacy_irq_wifi_takeover(ch_id)) {
						legacy_irq_wifi_takeover_handler(ch_id);
						continue;
					}

					reg_chn_dst_int.dst_complete_int_clr = 1;
					skw_pcie_write32(DMA_DST_INT(ch_id), reg_chn_dst_int.u32);
					node_addr0.addr_l32 = skw_pcie_read32(DMA_DST_INT_DSCR_HEAD_LOW(ch_id));
					node_addr1.addr_l32 = skw_pcie_read32(DMA_DST_INT_DSCR_TAIL_LOW(ch_id));
					chn_dst_node_cnt.u32 = skw_pcie_read32(DMA_DST_INT_DSCR_HIGH(ch_id));
					count = chn_dst_node_cnt.dst_node_done_num;

					node_addr0.addr_h8 = chn_dst_node_cnt.dst_int_dscr_head_high;
					val = node_addr0.addr_h8;
					header = (u64)(((node_addr0.addr_l32 & 0xffffffff) | ((val & 0xff) << 32)));

					node_addr1.addr_h8 = chn_dst_node_cnt.dst_int_dscr_tail_high;
					val = node_addr1.addr_h8;
					tail = (u64)(((node_addr1.addr_l32 & 0xffffffff) | ((val & 0xff) << 32)));
					if(edma_chp->chn_cfg.complete_callback){
						edma_chp->chn_cfg.complete_callback(edma_chp->chn_cfg.context, header, tail, count);
					}
					if(reg_chn_dst_int.dst_list_empty_mask_sts){
						reg_chn_dst_int.dst_list_empty_int_clr = 1;
						skw_pcie_write32(DMA_DST_INT(ch_id), reg_chn_dst_int.u32);
						if (edma_chp->chn_cfg.empty_callback)
							edma_chp->chn_cfg.empty_callback(edma_chp->chn_cfg.context);
					}
				}

			}
		}
	}
	spin_unlock_irqrestore(priv->spin_lock, flags);
	return 0;
}

int msi_edma_channel_irq_handler(int irq_num)
{
	struct edma_chn_info *edma_chp;
	struct wcn_pcie_info *priv = get_pcie_device_info();
	int ch_id;
	EDMA_ADDR_T node_addr0={0}, node_addr1={0};
	u64 header, tail;
	u32 count;
	u64 val;
	DMA_SRC_INT_DSCR_HIGH_S chn_src_node_cnt;
	DMA_DST_INT_DSCR_HIGH_S chn_dst_node_cnt;

	DMA_SRC_INT_S reg_chn_src_int = {0};
	DMA_DST_INT_S reg_chn_dst_int = {0};
	unsigned long flags;

	spin_lock_irqsave(priv->spin_lock, flags);

	if (priv->msix_en == 1)
		ch_id = irq_num/2;
	else
		ch_id = irq_num;

	edma_chp = get_edma_channel_info(ch_id);

	if (edma_chp->chn_cfg.req_mode == EDMA_STD_MODE) {
		if (edma_chp->chn_cfg.direction == EDMA_TX){
			reg_chn_src_int.u32 = skw_pcie_read32(DMA_SRC_INT(ch_id));
			if (priv->msix_en == 1) {
				if ((irq_num % 2 == 0) && reg_chn_src_int.src_complete_mask_sts){
					reg_chn_src_int.src_complete_int_clr = 1;
					skw_pcie_write32(DMA_SRC_INT(ch_id), reg_chn_src_int.u32);
					if (edma_chp->chn_cfg.complete_callback)
						edma_chp->chn_cfg.complete_callback(edma_chp->chn_cfg.context, 0, 0, 0);
				}
				if((irq_num % 2 == 1) && reg_chn_src_int.src_list_empty_mask_sts){
					reg_chn_src_int.src_list_empty_int_clr = 1;
					skw_pcie_write32(DMA_SRC_INT(ch_id), reg_chn_src_int.u32);
					if (edma_chp->chn_cfg.empty_callback)
						edma_chp->chn_cfg.empty_callback(edma_chp->chn_cfg.context);
				}
			} else if (priv->msi_en == 1) {
				if (reg_chn_src_int.src_complete_mask_sts){
					reg_chn_src_int.src_complete_int_clr = 1;
					skw_pcie_write32(DMA_SRC_INT(ch_id), reg_chn_src_int.u32);
					if (edma_chp->chn_cfg.complete_callback)
							edma_chp->chn_cfg.complete_callback(edma_chp->chn_cfg.context, 0, 0, 0);
				}
				if(reg_chn_src_int.src_list_empty_mask_sts){
					reg_chn_src_int.src_list_empty_int_clr = 1;
					skw_pcie_write32(DMA_SRC_INT(ch_id), reg_chn_src_int.u32);
					if (edma_chp->chn_cfg.empty_callback)
						edma_chp->chn_cfg.empty_callback(edma_chp->chn_cfg.context);
				}
			}
		} else if (edma_chp->chn_cfg.direction == EDMA_RX){
			reg_chn_dst_int.u32 = skw_pcie_read32(DMA_DST_INT(ch_id));
			if (priv->msix_en == 1) {
				if ((irq_num % 2 == 0) && reg_chn_dst_int.dst_complete_mask_sts){
					reg_chn_dst_int.dst_complete_int_clr = 1;
					skw_pcie_write32(DMA_DST_INT(ch_id), reg_chn_dst_int.u32);
					if (edma_chp->chn_cfg.complete_callback)
						edma_chp->chn_cfg.complete_callback(edma_chp->chn_cfg.context, 0, 0, 0);
				}
				if((irq_num % 2 == 1) && reg_chn_dst_int.dst_list_empty_mask_sts){
					reg_chn_dst_int.dst_list_empty_int_clr = 1;
					skw_pcie_write32(DMA_DST_INT(ch_id), reg_chn_dst_int.u32);
					if (edma_chp->chn_cfg.empty_callback)
						edma_chp->chn_cfg.empty_callback(edma_chp->chn_cfg.context);
				}
			} else if (priv->msi_en == 1) {
				if (reg_chn_dst_int.dst_complete_mask_sts){
					reg_chn_dst_int.dst_complete_int_clr = 1;
					skw_pcie_write32(DMA_DST_INT(ch_id), reg_chn_dst_int.u32);
					if (edma_chp->chn_cfg.complete_callback)
							edma_chp->chn_cfg.complete_callback(edma_chp->chn_cfg.context, 0, 0, 0);
				}
				if(reg_chn_dst_int.dst_list_empty_mask_sts){
					reg_chn_dst_int.dst_list_empty_int_clr = 1;
					skw_pcie_write32(DMA_DST_INT(ch_id), reg_chn_dst_int.u32);
					if (edma_chp->chn_cfg.empty_callback)
						edma_chp->chn_cfg.empty_callback(edma_chp->chn_cfg.context);
				}
			}
		}
	} else if (edma_chp->chn_cfg.req_mode == EDMA_LINKLIST_MODE) {
		if(edma_chp->chn_cfg.direction == EDMA_TX){
			reg_chn_src_int.u32 = skw_pcie_read32(DMA_SRC_INT(ch_id));
			if (priv->msix_en == 1) {
				if ((irq_num % 2 == 0) && reg_chn_src_int.src_complete_mask_sts){
					reg_chn_src_int.src_complete_int_clr = 1;
					skw_pcie_write32(DMA_SRC_INT(ch_id), reg_chn_src_int.u32);
					node_addr0.addr_l32 = skw_pcie_read32(DMA_SRC_INT_DSCR_HEAD_LOW(ch_id));
					node_addr1.addr_l32 = skw_pcie_read32(DMA_SRC_INT_DSCR_TAIL_LOW(ch_id));
					chn_src_node_cnt.u32 = skw_pcie_read32(DMA_SRC_INT_DSCR_HIGH(ch_id));
					count = chn_src_node_cnt.src_node_done_num;

					node_addr0.addr_h8 = chn_src_node_cnt.src_int_dscr_head_high;
					val = node_addr0.addr_h8;
					header = (u64)(((node_addr0.addr_l32 & 0xffffffff) | ((val & 0xff) << 32)));

					node_addr1.addr_h8 = chn_src_node_cnt.src_int_dscr_tail_high;
					val = node_addr1.addr_h8;
					tail = (u64)(((node_addr1.addr_l32 & 0xffffffff) | ((val & 0xff) << 32)));

					PCIE_DBG("ch_id:%d, EDMA_TX, header:%llx, tail:%llx, node_cnt:%d\n",
						ch_id, header, tail, count);

					if(edma_chp->chn_cfg.complete_callback){
						edma_chp->chn_cfg.complete_callback(edma_chp->chn_cfg.context, header, tail, count);
					}
				}
				if((irq_num % 2 == 1) && reg_chn_src_int.src_list_empty_mask_sts){
					reg_chn_src_int.src_list_empty_int_clr = 1;
					skw_pcie_write32(DMA_SRC_INT(ch_id), reg_chn_src_int.u32);
					if (edma_chp->chn_cfg.empty_callback)
						edma_chp->chn_cfg.empty_callback(edma_chp->chn_cfg.context);
				}
			} else if (priv->msi_en == 1) {
				if (reg_chn_src_int.src_complete_mask_sts){
					reg_chn_src_int.src_complete_int_clr = 1;
					skw_pcie_write32(DMA_SRC_INT(ch_id), reg_chn_src_int.u32);

					node_addr0.addr_l32 = skw_pcie_read32(DMA_SRC_INT_DSCR_HEAD_LOW(ch_id));
					node_addr1.addr_l32 = skw_pcie_read32(DMA_SRC_INT_DSCR_TAIL_LOW(ch_id));
					chn_src_node_cnt.u32 = skw_pcie_read32(DMA_SRC_INT_DSCR_HIGH(ch_id));
					count = chn_src_node_cnt.src_node_done_num;

					node_addr0.addr_h8 = chn_src_node_cnt.src_int_dscr_head_high;
					val = node_addr0.addr_h8;
					header = (u64)(((node_addr0.addr_l32 & 0xffffffff) | ((val & 0xff) << 32)));

					node_addr1.addr_h8 = chn_src_node_cnt.src_int_dscr_tail_high;
					val = node_addr1.addr_h8;
					tail = (u64)(((node_addr1.addr_l32 & 0xffffffff) | ((val & 0xff) << 32)));

					PCIE_DBG("ch_id:%d, EDMA_TX, header:%llx, tail:%llx, node_cnt:%d\n",
						ch_id, header, tail, count);

					if(edma_chp->chn_cfg.complete_callback)
						edma_chp->chn_cfg.complete_callback(edma_chp->chn_cfg.context, header, tail, count);
				}
				if(reg_chn_src_int.src_list_empty_mask_sts){
					reg_chn_src_int.src_list_empty_int_clr = 1;
					skw_pcie_write32(DMA_SRC_INT(ch_id), reg_chn_src_int.u32);
					if (edma_chp->chn_cfg.empty_callback) {
						edma_chp->chn_cfg.empty_callback(edma_chp->chn_cfg.context);
					}
				}
			}
		} else if (edma_chp->chn_cfg.direction == EDMA_RX) {
			reg_chn_dst_int.u32 = skw_pcie_read32(DMA_DST_INT(ch_id));
			if (priv->msix_en == 1) {
				if ((irq_num % 2 == 0) && reg_chn_dst_int.dst_complete_mask_sts){
					reg_chn_dst_int.dst_complete_int_clr = 1;
					//reg_chn_dst_int.dst_complete_int_en = 0;
					skw_pcie_write32(DMA_DST_INT(ch_id), reg_chn_dst_int.u32);

					node_addr0.addr_l32 = skw_pcie_read32(DMA_DST_INT_DSCR_HEAD_LOW(ch_id));
					node_addr1.addr_l32 = skw_pcie_read32(DMA_DST_INT_DSCR_TAIL_LOW(ch_id));
					chn_dst_node_cnt.u32 = skw_pcie_read32(DMA_DST_INT_DSCR_HIGH(ch_id));
					count = chn_dst_node_cnt.dst_node_done_num;

					node_addr0.addr_h8 = chn_dst_node_cnt.dst_int_dscr_head_high;
					val = node_addr0.addr_h8;
					//pcie_addr
					header = (u64)(((node_addr0.addr_l32 & 0xffffffff) | ((val & 0xff) << 32)));

					node_addr1.addr_h8 = chn_dst_node_cnt.dst_int_dscr_tail_high;
					val = node_addr1.addr_h8;
					//pcie_addr
					tail = (u64)(((node_addr1.addr_l32 & 0xffffffff) | ((val & 0xff) << 32)));

					PCIE_DBG("ch_id:%d, EDMA_RX, header:%llx, tail:%llx, node_cnt:%d\n",
						ch_id, header, tail, count);

					if(edma_chp->chn_cfg.complete_callback)
						edma_chp->chn_cfg.complete_callback(edma_chp->chn_cfg.context, header, tail, count);

					PCIE_DBG("exit irq!!!!!!!!!!!!\n");
					////trace_skw_edma_channel_irq_handler(__LINE__, "exit rx irq!!!", 0);
					reg_chn_dst_int.u32 = skw_pcie_read32(DMA_DST_INT(ch_id));
					//reg_chn_dst_int.dst_complete_int_en = 1;
					skw_pcie_write32(DMA_DST_INT(ch_id), reg_chn_dst_int.u32);
				}
				if((irq_num % 2 == 1) && reg_chn_dst_int.dst_list_empty_mask_sts){
					reg_chn_dst_int.dst_list_empty_int_clr = 1;
					skw_pcie_write32(DMA_DST_INT(ch_id), reg_chn_dst_int.u32);
					if (edma_chp->chn_cfg.empty_callback)
						edma_chp->chn_cfg.empty_callback(edma_chp->chn_cfg.context);
				}
			} else if (priv->msi_en == 1) {
				if (reg_chn_dst_int.dst_complete_mask_sts){
					reg_chn_dst_int.dst_complete_int_clr = 1;
					skw_pcie_write32(DMA_DST_INT(ch_id), reg_chn_dst_int.u32);

					node_addr0.addr_l32 = skw_pcie_read32(DMA_DST_INT_DSCR_HEAD_LOW(ch_id));
					node_addr1.addr_l32 = skw_pcie_read32(DMA_DST_INT_DSCR_TAIL_LOW(ch_id));
					chn_dst_node_cnt.u32 = skw_pcie_read32(DMA_DST_INT_DSCR_HIGH(ch_id));
					count = chn_dst_node_cnt.dst_node_done_num;

					node_addr0.addr_h8 = chn_dst_node_cnt.dst_int_dscr_head_high;
					val = node_addr0.addr_h8;
					header = (u64)(((node_addr0.addr_l32 & 0xffffffff) | ((val & 0xff) << 32)));

					node_addr1.addr_h8 = chn_dst_node_cnt.dst_int_dscr_tail_high;
					val = node_addr1.addr_h8;
					tail = (u64)(((node_addr1.addr_l32 & 0xffffffff) | ((val & 0xff) << 32)));

					PCIE_DBG("ch_id:%d, EDMA_RX, header:%llx, tail:%llx, node_cnt:%d\n",
						ch_id, header, tail, count);

					if(edma_chp->chn_cfg.complete_callback)
						edma_chp->chn_cfg.complete_callback(edma_chp->chn_cfg.context, header, tail, count);

					if(reg_chn_dst_int.dst_list_empty_mask_sts){
						reg_chn_dst_int.dst_list_empty_int_clr = 1;
						skw_pcie_write32(DMA_DST_INT(ch_id), reg_chn_dst_int.u32);
						if (edma_chp->chn_cfg.empty_callback) {
							edma_chp->chn_cfg.empty_callback(edma_chp->chn_cfg.context);
						}
					}
				}
			}
		}
	}

	spin_unlock_irqrestore(priv->spin_lock, flags);

	return 0;
}

int submit_list_to_edma_channel(int ch_id, u64 header, int count)
{
	struct edma_chn_info *dma_chp = get_edma_channel_info(ch_id);
	u32 edma_req = 0;
	DMA_NODE_TOT_CNT_S node_cnt;
	DMA_SRC_DSCR_PTR_HIGH_S src_addr_h8 = {0};
	DMA_SRC_DSCT_PTR_LOW_S src_addr_l32 = {0};
	DMA_DST_DSCR_PTR_HIGH_S dst_addr_h8 = {0};
	DMA_DST_DSCR_PTR_LOW_S dst_addr_l32 = {0};

	if(ch_id >= MAX_EDMA_COUNT || !count)
		return -EINVAL;
	//skw_edma_lock();
	if (ch_id < MAX_EDMA_COUNT) {
		PCIE_DBG("ch_id:%d direction:%s,header=0x%llx count:%d\n",
			ch_id, (dma_chp->chn_cfg.direction == EDMA_TX)?"EDMA_TX":"EDMA_RX",header, count);
		edma_req |= (count << NODE_NUM_OFFSET);
		edma_req |= EDMA_REQ;
		node_cnt.u32 = skw_pcie_read32(DMA_NODE_TOT_CNT(ch_id));
		if(dma_chp->chn_cfg.direction == EDMA_TX) {//ap is src
			if(header) {
				if (!node_cnt.src_tot_node_num) {
					src_addr_l32.src_next_dscr_ptr_low = (u64)header & 0xffffffff;
					skw_pcie_write32(DMA_SRC_DSCT_PTR_LOW(ch_id), src_addr_l32.u32);
					src_addr_h8.src_next_dscr_ptr_high = ((u64)header>>32) & 0xff;
					skw_pcie_write32(DMA_SRC_DSCR_PTR_HIGH(ch_id), src_addr_h8.u32);
					PCIE_DBG("tx_reg_header=0x%x@@\n",
						skw_pcie_read32(DMA_SRC_DSCT_PTR_LOW(ch_id)));
				} else
					return -EBUSY;
			}
			skw_pcie_write32(DMA_SRC_REQ(ch_id), edma_req);
		} else {
			if(header) {
				if (!node_cnt.dst_tot_node_num) {
					dst_addr_l32.dst_next_dscr_ptr_low = (u64)header & 0xffffffff;
					skw_pcie_write32(DMA_DST_DSCR_PTR_LOW(ch_id), dst_addr_l32.u32);
					dst_addr_h8.dst_next_dscr_ptr_high = ((u64)header>>32) & 0xff;
					skw_pcie_write32(DMA_DST_DSCR_PTR_HIGH(ch_id), dst_addr_h8.u32);
					PCIE_DBG("rx_reg_header=0x%x\n",
						skw_pcie_read32(DMA_DST_DSCR_PTR_LOW(ch_id)));
				} else
					return -EBUSY;
			}
			skw_pcie_write32(DMA_DST_REQ(ch_id), edma_req);
		}
	}
	//skw_edma_unlock();

	return 0;
}

int edma_channel_init(int ch_id, void *channel_config, void *data)
{
	struct edma_chn_info *edma_chp = get_edma_channel_info(ch_id);
	struct skw_channel_cfg *chn_cfg = (struct skw_channel_cfg *)channel_config;
	DMA_SRC_NODE_S reg_src_chn_node_cfg = {0};
	DMA_DST_NODE_S reg_dst_chn_node_cfg = {0};
	DMA_SRC_INT_S reg_chn_int = {0};
	DMA_CFG_S reg_chn_cfg = {0};
	u32 reg_edma_len = 0;
	DMA_SRC_DSCR_PTR_HIGH_S src_addr_h8 = {0};
	DMA_SRC_DSCT_PTR_LOW_S src_addr_l32 = {0};
	DMA_DST_DSCR_PTR_HIGH_S dst_addr_h8 = {0};
	DMA_DST_DSCR_PTR_LOW_S dst_addr_l32 = {0};

	edma_chp->chn_cfg.direction = chn_cfg->direction;
	edma_chp->chn_cfg.priority = chn_cfg->priority;
	edma_chp->chn_cfg.endian = chn_cfg->endian;
	edma_chp->chn_cfg.node_count = chn_cfg->node_count;
	edma_chp->chn_cfg.req_mode = chn_cfg->req_mode;
	edma_chp->chn_cfg.timeout = chn_cfg->timeout;
	edma_chp->chn_cfg.irq_threshold = chn_cfg->irq_threshold;
	edma_chp->chn_cfg.header = chn_cfg->header;
	edma_chp->chn_cfg.context = (void *)chn_cfg->context;
	edma_chp->chn_cfg.complete_callback = chn_cfg->complete_callback;
	edma_chp->chn_cfg.rx_callback = chn_cfg->rx_callback;
	edma_chp->chn_cfg.empty_callback = chn_cfg->empty_callback;
	edma_chp->chn_cfg.trsc_len = chn_cfg->trsc_len;
	edma_chp->chn_cfg.split = chn_cfg->split;
	edma_chp->chn_cfg.ring = chn_cfg->ring;
	edma_chp->chn_cfg.opposite_node_done = chn_cfg->opposite_node_done;
	edma_chp->chn_cfg.buf_cnt = chn_cfg->buf_cnt;
	edma_chp->chn_cfg.buf_level = chn_cfg->buf_level;

	PCIE_DBG("ch_id=%d\n", ch_id);
	PCIE_DBG("@@########direction = %s@@\n", (edma_chp->chn_cfg.direction == EDMA_TX)?"EDMA_TX":"EDMA_RX");
	PCIE_DBG("@@priority = 0x%x@@\n", edma_chp->chn_cfg.priority);
	PCIE_DBG("@@endian = 0x%x@@\n", edma_chp->chn_cfg.endian);
	PCIE_DBG("@@node_count = 0x%x@@\n", edma_chp->chn_cfg.node_count);
	PCIE_DBG("@@req_mode = %s@@\n", (edma_chp->chn_cfg.req_mode == EDMA_STD_MODE)?"STD":"LINKLIST");
	PCIE_DBG("@@header = 0x%llx@@\n", edma_chp->chn_cfg.header);
	PCIE_DBG("@@split = 0x%x@@\n", edma_chp->chn_cfg.split);
	PCIE_DBG("@@irq_threshold = 0x%x@@\n", edma_chp->chn_cfg.irq_threshold);

	reg_chn_int.src_complete_int_en = 1;
	reg_chn_int.src_cfg_err_int_en = 1;

	if (edma_chp->chn_cfg.trsc_len != 0) {
		reg_edma_len |= (edma_chp->chn_cfg.trsc_len << TRANS_LEN_OFFSET);
	}

	reg_chn_cfg.u32 = skw_pcie_read32(DMA_CFG(ch_id));
	PCIE_DBG("1. [%d]:0x%08x\n", ch_id, reg_chn_cfg.u32);
	//channel enable
	skw_pcie_write32(DMA_CFG(ch_id)+0x10, BIT(0));

	reg_chn_cfg.u32 = skw_pcie_read32(DMA_CFG(ch_id));
	PCIE_DBG("2. [%d]:0x%08x\n", ch_id, reg_chn_cfg.u32);
	reg_chn_cfg.endian_mode = edma_chp->chn_cfg.endian;
	reg_chn_cfg.priority = edma_chp->chn_cfg.priority;

	if (edma_chp->chn_cfg.req_mode == EDMA_STD_MODE) {
		reg_chn_cfg.req_mode = 0;
		skw_pcie_write32(DMA_CFG(ch_id)+0x20, BIT(13));
		if (edma_chp->chn_cfg.direction == EDMA_TX) {//AP is src
			reg_chn_cfg.dir = 0;
			skw_pcie_write32(DMA_CFG(ch_id), reg_chn_cfg.u32);
			skw_pcie_write32(DMA_SRC_INT(ch_id), reg_chn_int.u32);

			src_addr_l32.src_next_dscr_ptr_low = edma_chp->chn_cfg.header & 0xffffffff;
			skw_pcie_write32(DMA_SRC_DSCT_PTR_LOW(ch_id), src_addr_l32.u32);
			src_addr_h8.src_next_dscr_ptr_high = ((edma_chp->chn_cfg.header)>>32) & 0xff;
			skw_pcie_write32(DMA_SRC_DSCR_PTR_HIGH(ch_id), src_addr_h8.u32);
		} else {//AP is dst
			reg_chn_cfg.dir = 1;
			skw_pcie_write32(DMA_CFG(ch_id), reg_chn_cfg.u32);
			skw_pcie_write32(DMA_DST_INT(ch_id), reg_chn_int.u32);
			dst_addr_l32.dst_next_dscr_ptr_low = edma_chp->chn_cfg.header & 0xffffffff;
			skw_pcie_write32(DMA_DST_DSCR_PTR_LOW(ch_id), dst_addr_l32.u32);
			dst_addr_h8.dst_next_dscr_ptr_high = ((edma_chp->chn_cfg.header)>>32) & 0xff;
			skw_pcie_write32(DMA_DST_DSCR_PTR_HIGH(ch_id), dst_addr_h8.u32);
		}
		//trans len
		skw_pcie_write32(DMA_LEN_CFG(ch_id), reg_edma_len);
	} else if (edma_chp->chn_cfg.req_mode == EDMA_LINKLIST_MODE) {
		reg_chn_cfg.req_mode = 1;
		skw_pcie_write32(DMA_CFG(ch_id)+0x10, BIT(13));

		if (edma_chp->chn_cfg.empty_callback)
			reg_chn_int.src_list_empty_int_en = 1;

		if (edma_chp->chn_cfg.direction == EDMA_TX) {//AP is src
			reg_chn_cfg.dir = 0;
			reg_chn_int.src_cmplt_en_wi_dst_node_done = edma_chp->chn_cfg.opposite_node_done;
			reg_src_chn_node_cfg.u32 = skw_pcie_read32(DMA_SRC_NODE(ch_id));
			reg_src_chn_node_cfg.src_data_split_en = edma_chp->chn_cfg.split;
			reg_src_chn_node_cfg.src_ring_buf_en = edma_chp->chn_cfg.ring;
			if (edma_chp->chn_cfg.irq_threshold != 0) {
				reg_src_chn_node_cfg.node_num_thr_en = 1;
				reg_src_chn_node_cfg.node_num_thr = edma_chp->chn_cfg.irq_threshold;
			} else
				reg_src_chn_node_cfg.node_num_thr_en = 0;
			skw_pcie_write32(DMA_CFG(ch_id), reg_chn_cfg.u32);
			skw_pcie_write32(DMA_SRC_INT(ch_id), reg_chn_int.u32);
			skw_pcie_write32(DMA_SRC_NODE(ch_id), reg_src_chn_node_cfg.u32);

			src_addr_l32.src_next_dscr_ptr_low = edma_chp->chn_cfg.header & 0xffffffff;
			skw_pcie_write32(DMA_SRC_DSCT_PTR_LOW(ch_id), src_addr_l32.u32);
			src_addr_h8.src_next_dscr_ptr_high = ((edma_chp->chn_cfg.header)>>32) & 0xff;
			skw_pcie_write32(DMA_SRC_DSCR_PTR_HIGH(ch_id), src_addr_h8.u32);

		} else {//AP is dst
			reg_chn_cfg.dir = 1;
			reg_chn_int.src_cmplt_en_wi_dst_node_done = edma_chp->chn_cfg.opposite_node_done;
			reg_dst_chn_node_cfg.u32 = skw_pcie_read32(DMA_DST_NODE(ch_id));
			reg_dst_chn_node_cfg.dst_data_split_en = 1;
			reg_dst_chn_node_cfg.dst_ring_buf_en = edma_chp->chn_cfg.ring;
			if (edma_chp->chn_cfg.irq_threshold != 0) {
				reg_dst_chn_node_cfg.dst_node_num_thr_en = 1;
				reg_dst_chn_node_cfg.dst_node_num_thr = edma_chp->chn_cfg.irq_threshold;
			} else
				reg_dst_chn_node_cfg.dst_node_num_thr_en = 0;
			skw_pcie_write32(DMA_CFG(ch_id), reg_chn_cfg.u32);
			skw_pcie_write32(DMA_DST_INT(ch_id), reg_chn_int.u32);
			skw_pcie_write32(DMA_DST_NODE(ch_id), reg_dst_chn_node_cfg.u32);

			dst_addr_l32.dst_next_dscr_ptr_low = edma_chp->chn_cfg.header & 0xffffffff;
			skw_pcie_write32(DMA_DST_DSCR_PTR_LOW(ch_id), dst_addr_l32.u32);
			dst_addr_h8.dst_next_dscr_ptr_high = ((edma_chp->chn_cfg.header)>>32) & 0xff;
			skw_pcie_write32(DMA_DST_DSCR_PTR_HIGH(ch_id), dst_addr_h8.u32);

		}
	}


	return 0;
}

static int close_edma_channel(int ch_id)
{
	struct edma_chn_info *dma_chp = get_edma_channel_info(ch_id);
	DMA_SRC_NODE_S reg_chn_node_cfg = {0};
	DMA_SRC_INT_S reg_chn_int = {0};

	if(ch_id >= MAX_EDMA_COUNT)
		return -1;

	PCIE_INFO("ch_id:%d\n", ch_id);
	dma_chp->chn_cfg.complete_callback = NULL;
	dma_chp->chn_cfg.empty_callback = NULL;
	dma_chp->chn_cfg.irq_threshold = 0;
	reg_chn_int.src_complete_int_en = 0;
	reg_chn_int.src_cfg_err_int_en = 0;
	reg_chn_int.src_list_empty_int_en = 0;
	reg_chn_node_cfg.node_num_thr_en = 0;

	if(dma_chp->chn_cfg.direction == EDMA_TX) {
		skw_pcie_write32(DMA_SRC_INT(ch_id), reg_chn_int.u32);
		skw_pcie_write32(DMA_SRC_NODE(ch_id), reg_chn_node_cfg.u32);
	} else {
		skw_pcie_write32(DMA_DST_INT(ch_id), reg_chn_int.u32);
		skw_pcie_write32(DMA_DST_NODE(ch_id), reg_chn_node_cfg.u32);
	}
	//channel close
	skw_pcie_write32(DMA_CFG(ch_id)+0x20, BIT(0));

	return 0;
}

int edma_adma_send(int ch_id, struct scatterlist *sg, int node_cnt, int size)
{
	struct edma_chn_info *edma_chp = get_edma_channel_info(ch_id);
	u32 edma_req = 0;

	if(ch_id >= MAX_EDMA_COUNT)
		return -EINVAL;

	//skw_edma_lock();
	PCIE_DBG("req_mod=%d, ch_id=%d\n", edma_chp->chn_cfg.req_mode, ch_id);
	if (edma_chp->chn_cfg.req_mode == EDMA_STD_MODE) {
		edma_req |= EDMA_REQ;
		if (edma_chp->chn_cfg.direction == EDMA_TX)
			skw_pcie_write32(DMA_SRC_REQ(ch_id), edma_req);
		else
			skw_pcie_write32(DMA_DST_REQ(ch_id), edma_req);

	} else if (edma_chp->chn_cfg.req_mode == EDMA_LINKLIST_MODE) {
		edma_req |= (node_cnt << NODE_NUM_OFFSET);
		edma_req |= EDMA_REQ;
		if (edma_chp->chn_cfg.direction == EDMA_TX) {
			skw_pcie_write32(DMA_SRC_REQ(ch_id), edma_req);
		} else {
			skw_pcie_write32(DMA_DST_REQ(ch_id), edma_req);
		}
	}
	//skw_edma_unlock();
	return 0;
}
#if 0
static int ch_alloc_coherent(struct edma_chn_info *edma_chp, int size)
{
	struct wcn_pcie_info *priv = get_pcie_device_info();
	struct device *dev = &(priv->dev->dev);

	edma_chp->pld_virt_addr = dma_alloc_coherent(dev, size, &edma_chp->pld_dma_addr, GFP_KERNEL);
	if (!edma_chp->pld_virt_addr) {
		PCIE_ERR("Alloc ch %d tmpbuf fail\n", edma_chp->chn_id);
		return -ENOMEM;
	}
	PCIE_DBG("ch %d alloc tmpbuf:0x%llx\n", edma_chp->chn_id, edma_chp->pld_dma_addr);
	memset(edma_chp->pld_virt_addr, 0, size);

	return 0;
}

static void ch_free_coherent(struct edma_chn_info *edma_chp, int size)
{
	struct wcn_pcie_info *priv = get_pcie_device_info();
	struct device *dev = &(priv->dev->dev);

	dma_free_coherent(dev, size, edma_chp->pld_virt_addr, edma_chp->pld_dma_addr);
	PCIE_DBG("ch %d free tmpbuf:0x%llx\n", edma_chp->chn_id, edma_chp->pld_dma_addr);
}
#endif
static noinline int edma_port_read(struct edma_port *port, char *buffer, int size)
{
	u8 ch_id = port->rx_ch;
	struct wcn_pcie_info *priv= get_pcie_device_info();
	struct edma_chn_info *edma_chp = get_edma_channel_info(ch_id);
	EDMA_HDR_T *nodep = port->rx_node;
	int ret;

	//mutex_lock(&port->rx_mutex);
	PCIE_DBG("[+], port%d state=%s\n", port->portno, port_state[port->state]);
	//edma_chp->n_pld_sz = size;
	if (port->state != PORT_STATE_OPEN) {
		PCIE_ERR("port%d is not open:%s, exit\n", port->portno, port_state[port->state]);
		return -110;
	}
#if 0
	ret = ch_alloc_coherent(edma_chp, size);
	if (ret) {
		PCIE_ERR("ch %d alloc coherent mem fail\n", ch_id);
		return ret;
	}
#endif
#if 0
	if (port->portno != EDMA_AT_PORT)
		nodep->data_addr = edma_virtaddr_to_pcieaddr(buffer);
	else
		nodep->data_addr = edma_virtaddr_to_pcieaddr(at_buffer);
	//map payload
	if (port->portno != EDMA_AT_PORT)
		edma_chp->map_pld_addr = dma_map_single(dev, buffer, edma_chp->n_pld_sz, DMA_FROM_DEVICE);
	else
		edma_chp->map_pld_addr = dma_map_single(dev, at_buffer, edma_chp->n_pld_sz, DMA_FROM_DEVICE);
	if (dma_mapping_error(dev, edma_chp->map_pld_addr)) {
			PCIE_ERR("dma_mapping_error\n");
			BUG_ON(1);
			return -1;
	}
#else
	/**
	 * If wait_for_completion_interruptible(...) interrupted by 
	 * SIGKILL(return -ERESTARTSYS), while data may be on the way,
	 * so we need to read it again
	*/
	if (port->rx_int_done == 1) {
		port->rx_int_done = 0;
		goto read_last;
	}
	nodep->data_addr = edma_phyaddr_to_pcieaddr(edma_chp->pld_dma_addr);
	PCIE_DBG("nodep->data_addr = 0x%llx\n", (u64)nodep->data_addr);
#endif
	reinit_completion(&port->rx_done);

	memset(edma_chp->pld_virt_addr, 0, EDMA_PORT_BUFFER_SIZE);
	barrier();
	edma_adma_send(ch_id, NULL, 1, 0);

	if (port->rx_submit) {
		port->rx_submit(port->portno, NULL, 0, nodep);
	}

	ret = wait_for_completion_interruptible(&port->rx_done);
	if(ret == -ERESTARTSYS) {
		//ch_free_coherent(edma_chp, size);
		PCIE_INFO("port%d read interrupted, pid:%d, comm:%s\n",
			port->portno, current->pid, current->comm);
		if (port->portno == EDMA_AT_PORT)
			skw_pcie_write32(DMA_NODE_TOT_CNT(ch_id), 0x80000000);//clr dst node num
		return 0;
	}
	port->rx_int_done = 0;
	if(port->state == PORT_STATE_CLSE) {
		//port->state = PORT_STATE_IDLE;
		PCIE_INFO("port%d closed\n", port->portno);
		goto err_out;
	} else if(port->state == PORT_STATE_ASST) {
		PCIE_INFO("CP ASSERT! port%d exit\n", port->portno);
		if (priv->cp_state != CP_READY) {
			if(port->portno == EDMA_LOG_PORT) {
				port->state = PORT_STATE_OPEN;
				PCIE_INFO("log port open\n");
			}
			goto err_out;
		}
	}

read_last:
	if (edma_chp->hdr_virt_addr == NULL) {
		PCIE_ERR("hdr_virt_addr is NULL, ch_id:%d\n", ch_id);
		goto err_out;
	}
	memcpy(buffer, edma_chp->pld_virt_addr, size);

	if (port->portno == EDMA_LOOPCHECK_PORT)
		print_hex_dump(KERN_ERR, "loopcheck:", 0, 16, 1, buffer, 32, 1);

	if(port->state == PORT_STATE_CLSE) {
		//port->state = PORT_STATE_IDLE;
		PCIE_ERR("port%d closed\n", port->portno);
		goto err_out;
	}

	PCIE_DBG("[-], port%d state=%s, ch_id=%d\n", port->portno, port_state[port->state], ch_id);
	//mutex_unlock(&port->rx_mutex);
	//ch_free_coherent(edma_chp, size);
	PCIE_DBG("[-]\n");
	return nodep->data_len;
err_out:
	//ch_free_coherent(edma_chp, size);
	PCIE_DBG("[-]\n");
	return -110;
}

static noinline int edma_port_write(struct edma_port *port, char *buffer, int size)
{
	u8 ch_id = port->tx_ch;
	struct edma_chn_info *edma_chp = get_edma_channel_info(ch_id);
	struct wcn_pcie_info *priv= get_pcie_device_info();
	EDMA_HDR_T *nodep = port->tx_node;
	int ret;

	//PCIE_DBG("[+]\n");
	PCIE_DBG("portno=%d, port_state=%d, ch_id=%d\n", port->portno, port->state, ch_id);

	//edma_chp->n_pld_sz = size;
	if (port->state != PORT_STATE_OPEN) {
		PCIE_ERR("port %d is not open:%s, exit\n", port->portno, port_state[port->state]);
		return size;
	}
	//nodep->data_addr = edma_virtaddr_to_pcieaddr(buffer);

	if (port->portno == EDMA_LOG_PORT)
		dump_stack();

	//nodep->data_addr = edma_virtaddr_to_pcieaddr(buffer);
#if 0
	ret = ch_alloc_coherent(edma_chp, size);
	if (ret) {
	    PCIE_ERR("ch %d alloc coherent mem fail\n", ch_id);
	    return ret;
	}
#endif
	nodep->data_len = size;
	nodep->data_addr = edma_phyaddr_to_pcieaddr(edma_chp->pld_dma_addr);
	//PCIE_INFO("nodep->data_addr = 0x%x\n", nodep->data_addr);
	memset(edma_chp->pld_virt_addr, 0, EDMA_PORT_BUFFER_SIZE);
	barrier();
	memcpy(edma_chp->pld_virt_addr, buffer, size); 
	//print_hex_dump(KERN_ERR, "port write:", 0, 16, 1, edma_chp->pld_virt_addr, 32, 1);

	//print_hex_dump(KERN_ERR, "plt:", 0, 16, 1, buffer, 64, 1);
	PCIE_DBG("portno=%d, port_state=%s, ch_id=%d\n", port->portno, port_state[port->state], ch_id);
#if 0
	//map payload
	edma_chp->map_pld_addr = dma_map_single(dev, buffer, edma_chp->n_pld_sz, DMA_TO_DEVICE);
	if (dma_mapping_error(dev, edma_chp->map_pld_addr)) {
			BUG_ON(1);
			return -1;
	}
#endif
	reinit_completion(&port->tx_done);
	barrier();
	edma_adma_send(ch_id, NULL, 1, 0);


	ret = wait_for_completion_interruptible(&port->tx_done);
	if(ret == -ERESTARTSYS) {
		//ch_free_coherent(edma_chp, size);
		PCIE_INFO("port%d write interrupted, pid:%d, comm:%s\n",
				port->portno, current->pid, current->comm);
		if (port->portno == EDMA_AT_PORT)
			return size;
		return 0;
	}
	if(port->state == PORT_STATE_CLSE) {
		//port->state = PORT_STATE_IDLE;
		PCIE_INFO("port%d closed\n", port->portno);
		goto err_out;
	} else if(port->state == PORT_STATE_ASST) {
		PCIE_INFO("CP asserted  portno =%d error code =%d!!!!\n", port->portno, ENOTCONN);
		if (priv->cp_state != CP_READY) {
			if(port->portno == EDMA_LOG_PORT) {
				port->state = PORT_STATE_OPEN;
				PCIE_INFO("log port open\n");
			}
			goto err_out;
		}
	}
	PCIE_DBG("[-]\n");
	//ch_free_coherent(edma_chp, size);
	return size;
err_out:
	PCIE_DBG("[-]\n");
	//ch_free_coherent(edma_chp, size);
	return size;
}


int recv_data(int portno, char *buffer, int size)
{
	struct edma_port *port;
	char *data = buffer;
	int read;

	if (portno == EDMA_LOOPCHECK_PORT)
		PCIE_DBG("[+] portno=%d!! \n",portno);
	if(size==0)
		return 0;
	if(portno >= MAX_PORT_NUM)
		return -EINVAL;
	port = &edma_ports[portno];
	if(!port->state)
		return -EIO;
	read = edma_port_read(port, data, size);
	if (portno == EDMA_LOOPCHECK_PORT)
		PCIE_DBG("[-] portno=%d!! \n",portno);
	return read;
}

int send_data(int portno, char *buffer, int size)
{
	struct edma_port *port = get_edma_port_info(portno);

	PCIE_DBG("[+]\n");
	PCIE_DBG("size:%d portno:%d port->state:%s\n", size, portno, port_state[port->state]);
	if(size==0)
		return 0;
	if(portno >= MAX_PORT_NUM)
		return -EINVAL;
	if(!port->state)
		return -EIO;

	return edma_port_write(port, buffer, size);
}

static void *edma_build_port_node(u8 ch)
{
	struct wcn_pcie_info *priv= get_pcie_device_info();
	struct device *dev = &(priv->dev->dev);
	struct edma_chn_info *edma_chp = get_edma_channel_info(ch);
	EDMA_HDR_T *nodep;

	if (!dev) {
		PCIE_ERR("(NULL)\n");
		return NULL;
	}

	edma_chp->hdr_virt_addr = (EDMA_HDR_T *)dma_alloc_coherent(dev, PAGE_ALIGN(sizeof(EDMA_HDR_T) + EDMA_PORT_BUFFER_SIZE),
					(dma_addr_t *)(&(edma_chp->hdr_dma_addr)), GFP_KERNEL);
	if (!edma_chp->hdr_virt_addr) {
		PCIE_ERR("alloc mem fail\n");
		return NULL;
	}
	nodep = edma_chp->hdr_virt_addr;
	edma_chp->pld_virt_addr = edma_chp->hdr_virt_addr + sizeof(EDMA_HDR_T);
	edma_chp->pld_dma_addr = edma_chp->hdr_dma_addr + sizeof(EDMA_HDR_T);
	memset(edma_chp->pld_virt_addr, 0, EDMA_PORT_BUFFER_SIZE);
	nodep->next_hdr = edma_phyaddr_to_pcieaddr(edma_chp->hdr_dma_addr) + 8;
	PCIE_DBG("ch %d alloc tmpbuf:0x%llx\n", edma_chp->chn_id, edma_chp->hdr_dma_addr);

#if 0
	/* build ring linklist */
	for (i = 0;i < count;i++) {
			edma_chp->hdr_virt_addr[i].next_hdr =
				edma_phyaddr_to_pcieaddr(edma_chp->hdr_dma_addr + ((i + 1) % count) * sizeof(EDMA_HDR_T) + 8);
	}
#endif
	nodep = (EDMA_HDR_T *)edma_chp->hdr_virt_addr;

	return nodep;
}

static int port_rx_int_cb(void *context, u64 head, u64 tail, int count)
{
	struct edma_chn_info *edma_chp = context;
	u8 ch = edma_chp->chn_id;
	u8 portno = EDMACH2PORTNO(ch);
	struct edma_port *port = &edma_ports[portno];

	edma_chp = get_edma_channel_info(ch);
	edma_chp->rcv_tail_cpu_addr = edma_coherent_rcvheader_to_cpuaddr((u64)tail, edma_chp);
	edma_chp->rcv_header_cpu_addr = edma_coherent_rcvheader_to_cpuaddr((u64)head, edma_chp);
	while(!(((EDMA_HDR_T *)((char *)edma_chp->rcv_tail_cpu_addr-8))->done)){
		mdelay(1);
		barrier();
		PCIE_DBG("wait for ch_id:%d node done flag...\n", ch);
	}
	((EDMA_HDR_T *)((char *)edma_chp->rcv_header_cpu_addr-8))->done = 0;

	port->rx_int_done = 1;
	complete(&port->rx_done);

	return 0;
}

static int port_tx_int_cb(void *context, u64 head, u64 tail, int count)
{
	struct edma_chn_info *edma_chp = context;
	u8 ch = edma_chp->chn_id;
	u8 portno = EDMACH2PORTNO(ch);
	struct edma_port *port = &edma_ports[portno];

	complete(&port->tx_done);

	return 0;
}

#ifdef CONFIG_BT_SEEKWAVE
static int pcie_bt_rx_entry(void *para)
{
	struct edma_port *port = para;
	char *buffer;
	int read, size;

	PCIE_INFO("port%d bt rx thread entry\n", port->portno);
	size = 2048;
	buffer = kzalloc(size, GFP_KERNEL);
	while(port->state == PORT_STATE_OPEN && buffer) {
		read = 0;
		memset(buffer, 0, size);
		read = recv_data(port->portno, buffer, size);
		if(read <= 0) {
			PCIE_DBG("edma read_len=%d\n", read);
			break;
		}
		if(port->rx_submit)
			port->rx_submit(port->portno, port->rx_data, read, buffer);
	}
	PCIE_INFO("port%d is stopped\n", port->portno);

	if(buffer)
		kfree(buffer);
	up(&port->sem);
	return 0;
}
#endif


int open_edma_port(int portno, void *callback, void *data)
{
	struct edma_port *port;
	EDMA_HDR_T *nodep;
	struct skw_channel_cfg chn_cfg_rx = {0}, chn_cfg_tx = {0};
	struct edma_chn_info *rx_edma_chp;
	struct edma_chn_info *tx_edma_chp;
#ifdef CONFIG_BT_SEEKWAVE
	char thread_name[32];
#endif

	if(portno >= MAX_PORT_NUM){
		PCIE_ERR("portno:%d error\n", portno);
		return -EINVAL;
	}
	port = &edma_ports[portno];
	port->rx_ch = PORT_TO_EDMA_RX_CHANNEL(portno);
	port->tx_ch = PORT_TO_EDMA_TX_CHANNEL(portno);
	rx_edma_chp = get_edma_channel_info(port->rx_ch);
	tx_edma_chp = get_edma_channel_info(port->tx_ch);

	PCIE_INFO("[+]port[%d] state:%s, pid:%d, comm:%s\n",
			portno, port_state[port->state], current->pid, current->comm);
	if((port->state==PORT_STATE_OPEN) || port->rx_submit) {
		PCIE_INFO("[-]port[%d] opened already, exit!!!\n", portno);
		return -EBUSY;
	}
	port->rx_submit = callback;
	port->rx_data = data;
	port->rx_wp = port->rx_rp = 0;
	port->portno = portno;
	init_completion(&port->rx_done);
	init_completion(&port->tx_done);
	port->state = PORT_STATE_OPEN;

	chn_cfg_rx.direction = EDMA_RX;
	nodep = edma_build_port_node(port->rx_ch);
	if(nodep) {
		//nodep->next_hdr = edma_phyaddr_to_pcieaddr(rx_edma_chp->hdr_dma_addr) + 8;
		chn_cfg_rx.complete_callback = port_rx_int_cb;
		chn_cfg_rx.empty_callback = NULL;
		chn_cfg_rx.header = edma_phyaddr_to_pcieaddr(rx_edma_chp->hdr_dma_addr) + 8;
		chn_cfg_rx.split = 1;
		chn_cfg_rx.node_count = 1;
		chn_cfg_rx.req_mode = EDMA_LINKLIST_MODE;
		chn_cfg_rx.context = get_edma_channel_info(port->rx_ch);
		edma_channel_init(port->rx_ch, &chn_cfg_rx, NULL);
		port->rx_node = nodep;
	} else{
		PCIE_ERR("[-]port[%d] build rx node failed\n", portno);
		return -EINVAL;
	}

	chn_cfg_tx.direction = EDMA_TX;
	chn_cfg_tx.split = 1;
	nodep = edma_build_port_node(port->tx_ch);
	if(nodep) {
		//nodep->next_hdr = edma_phyaddr_to_pcieaddr(tx_edma_chp->hdr_dma_addr) + 8;
		chn_cfg_tx.complete_callback = port_tx_int_cb;
		chn_cfg_tx.empty_callback = NULL;
		chn_cfg_tx.header = edma_phyaddr_to_pcieaddr(tx_edma_chp->hdr_dma_addr) + 8;
		chn_cfg_tx.split = 1;
		chn_cfg_tx.node_count = 1;
		chn_cfg_tx.req_mode = EDMA_LINKLIST_MODE;
		chn_cfg_tx.context = get_edma_channel_info(port->tx_ch);
		edma_channel_init(port->tx_ch, &chn_cfg_tx, NULL);
		port->tx_node = nodep;
	} else{
		PCIE_ERR("[-]port[%d] build tx node failed\n", portno);
		return -EINVAL;
	}
#ifdef CONFIG_BT_SEEKWAVE
	if (portno == EDMA_BTCMD_PORT || portno == EDMA_BTACL_PORT ||
			portno == EDMA_BTAUDIO_PORT || portno == EDMA_ISOC_PORT) {
		if(callback && data && !port->thread) {
			sema_init(&port->sem, 0);
			sprintf(thread_name, "%s%d", "BTRX", portno);
			port->thread = kthread_create(pcie_bt_rx_entry, port, thread_name);
			if (IS_ERR(port->thread)) {
				long err = PTR_ERR(port->thread);
				PCIE_ERR("[-] create port%d rx thread failed with error %ld\n", portno, err);
				port_sta_rec[portno] = 1;
				return err;
			}
			wake_up_process(port->thread);
		}
	}
#endif
	if(portno == EDMA_LOG_PORT){
		skw_pcie_cp_log(0);
		mdelay(100);
	}
	port_sta_rec[portno] = 1;
	PCIE_INFO("[-]port[%d] state:%s\n", portno, port_state[port->state]);
	return 0;
}

int close_edma_port(int portno)
{
	struct edma_port *port = &edma_ports[portno];
	struct wcn_pcie_info *priv= get_pcie_device_info();
	struct device *dev = &(priv->dev->dev);
	struct edma_chn_info *edma_chp;
	u32 val;
	u8 edma_int_pending = 0;
	u8 pcie_link_down = 0;
	int ret = 0;

	mutex_lock(&priv->close_mutex);
	PCIE_INFO("[+]port[%d] state:%s, pid:%d, comm:%s\n", portno, port_state[port->state], current->pid, current->comm);
	if (portno == EDMA_BTACL_PORT || portno == EDMA_BTCMD_PORT || portno == EDMA_BTAUDIO_PORT || portno == EDMA_ISOC_PORT) {
		if (priv->svc_op != BT_STOP) {
			mutex_unlock(&priv->close_mutex);
			PCIE_INFO("[-]port[%d] wait bt service stop\n", portno);
			return 0;
		}
	}

	if(portno == EDMA_LOG_PORT){
		skw_pcie_cp_log(1);
		mdelay(100);
	}

	if (port_sta_rec[portno] == 0) {
		PCIE_INFO("[-]port[%d] no open, exit\n", portno);
		mutex_unlock(&priv->close_mutex);
		return 0;
	}

	if (!pci_device_is_present(priv->dev)) {
		PCIE_ERR("PCIe link is Down!!!\n");
		pcie_link_down = 1;
	}

#if 1 //XXX: for debug
	val = skw_pcie_read32(DMA_SRC_INT(port->tx_ch));
	if (val & BIT(8)) {
		PCIE_INFO("edma_src_int[%d]=0x%08x\n", port->tx_ch, val);
		mdelay(10);
		val = skw_pcie_read32(DMA_SRC_INT(port->tx_ch));
		PCIE_INFO("edma_src_int[%d]=0x%08x\n", port->tx_ch, val);
		mdelay(10);
		val = skw_pcie_read32(DMA_SRC_INT(port->tx_ch));
		PCIE_INFO("edma_src_int[%d]=0x%08x\n", port->tx_ch, val);
		edma_int_pending = 1;
	}
	val = skw_pcie_read32(DMA_DST_INT(port->rx_ch));
	if (val & BIT(8)) {
		PCIE_INFO("edma_dst_int[%d]=0x%08x\n", port->rx_ch, val);
		mdelay(10);
		val = skw_pcie_read32(DMA_DST_INT(port->rx_ch));
		PCIE_INFO("edma_dst_int[%d]=0x%08x\n", port->rx_ch, val);
		mdelay(10);
		val = skw_pcie_read32(DMA_DST_INT(port->rx_ch));
		PCIE_INFO("edma_dst_int[%d]=0x%08x\n", port->rx_ch, val);
		edma_int_pending = 1;
	}
#endif
	close_edma_channel(port->tx_ch);
	close_edma_channel(port->rx_ch);

	edma_chp = get_edma_channel_info(port->tx_ch);
	dma_free_coherent(dev, PAGE_ALIGN(sizeof(EDMA_HDR_T) + EDMA_PORT_BUFFER_SIZE),
			edma_chp->hdr_virt_addr, edma_chp->hdr_dma_addr);
	edma_chp->hdr_virt_addr = NULL;
	edma_chp->hdr_dma_addr = 0;
	edma_chp->pld_virt_addr = NULL;
	edma_chp->pld_dma_addr = 0;

	barrier();
	edma_chp = get_edma_channel_info(port->rx_ch);
	dma_free_coherent(dev, PAGE_ALIGN(sizeof(EDMA_HDR_T) + EDMA_PORT_BUFFER_SIZE),
			edma_chp->hdr_virt_addr, edma_chp->hdr_dma_addr);
	edma_chp->hdr_virt_addr = NULL;
	edma_chp->hdr_dma_addr = 0;
	edma_chp->pld_virt_addr = NULL;
	edma_chp->pld_dma_addr = 0;

	port->state = PORT_STATE_CLSE;
	port->tx_line = NULL;
	port->rx_line = NULL;
	port->tx_index = 0;
	port->rx_wp = port->rx_rp = 0;
	port->rx_submit = NULL;

#ifdef CONFIG_BT_SEEKWAVE
	if(port->thread && !down_interruptible(&port->sem))
		PCIE_INFO("port%d rx thread exit\n", portno);
	port->thread = NULL;
#endif
	//memset(port, 0, sizeof(struct edma_port));
	port_sta_rec[portno] = 0;
	if (edma_int_pending)
		PCIE_ERR("port[%d] edma int pending!!!\n", portno);
	if (pcie_link_down){
		ret = -ENODEV;
	}
	PCIE_INFO("[-]port[%d] state:%s, pid:%d, comm:%s\n", portno, port_state[port->state], current->pid, current->comm);
	complete(&port->rx_done);
	complete(&port->tx_done);
	mutex_unlock(&priv->close_mutex);
	return ret;
}

static int wifi_service_start(void)
{
	int ret = 0;
	struct wcn_pcie_info *priv = get_pcie_device_info();
	if (priv->boot_data == NULL)
		return ret;

	ret = priv->boot_data->wifi_start();
	return ret;
}

static int wifi_service_stop(void)
{
	int ret = 0;
	struct wcn_pcie_info *priv = get_pcie_device_info();
	if (priv->boot_data == NULL || priv->cp_state != CP_READY)
		return ret;

	ret = priv->boot_data->wifi_stop();
	return ret;
}

static int bt_service_start(void)
{
	int ret = 0;
	struct wcn_pcie_info *priv = get_pcie_device_info();
	if(priv->boot_data == NULL)
		return ret;

	ret = priv->boot_data->bt_start();
	return ret;
}

static int bt_service_stop(void)
{
	int ret = 0;
	struct wcn_pcie_info *priv = get_pcie_device_info();
	if (priv->boot_data == NULL || priv->cp_state != CP_READY)
		return ret;

	ret = priv->boot_data->bt_stop();
	return ret;
}

void edma_unmask_channel(int channel)
{
	DMA_DST_INT_S reg_chn_dst_int = {0};
	DMA_SRC_INT_S reg_chn_src_int = {0};
	struct edma_chn_info *edma_chp = get_edma_channel_info(channel);

	if (edma_chp->chn_cfg.direction == EDMA_TX) {
		reg_chn_src_int.u32 = skw_pcie_read32(DMA_SRC_INT(channel));
		reg_chn_src_int.src_complete_int_en = 1;
		reg_chn_src_int.src_cfg_err_int_en = 1;
		reg_chn_src_int.src_list_empty_int_en = 0;

		skw_pcie_write32(DMA_SRC_INT(channel), reg_chn_src_int.u32);
	} else {
		reg_chn_dst_int.u32 = skw_pcie_read32(DMA_DST_INT(channel));
		reg_chn_dst_int.dst_complete_int_en = 1;
		reg_chn_dst_int.dst_cfg_err_int_en = 1;
		reg_chn_dst_int.dst_list_empty_int_en = 0;

		skw_pcie_write32(DMA_DST_INT(channel), reg_chn_dst_int.u32);
	}
}

void edma_mask_channel(int channel)
{
	DMA_DST_INT_S reg_chn_dst_int = {0};
	DMA_SRC_INT_S reg_chn_src_int = {0};
	struct edma_chn_info *edma_chp = get_edma_channel_info(channel);

	if (edma_chp->chn_cfg.direction == EDMA_TX) {
		reg_chn_src_int.u32 = skw_pcie_read32(DMA_SRC_INT(channel));
		reg_chn_src_int.src_complete_int_clr = 1;
		reg_chn_src_int.src_complete_int_en = 0;
		reg_chn_src_int.src_cfg_err_int_en = 0;
		reg_chn_src_int.src_list_empty_int_en = 0;

		skw_pcie_write32(DMA_SRC_INT(channel), reg_chn_src_int.u32);
	} else {
		reg_chn_dst_int.u32 = skw_pcie_read32(DMA_DST_INT(channel));
		reg_chn_dst_int.dst_complete_int_clr = 1;
		reg_chn_dst_int.dst_complete_int_en = 0;
		reg_chn_dst_int.dst_cfg_err_int_en = 0;
		reg_chn_dst_int.dst_list_empty_int_en = 0;

		skw_pcie_write32(DMA_DST_INT(channel), reg_chn_dst_int.u32);
	}
}

int edma_channel_irq_info(int channel, u64 *head, u64 *tail, int *count)
{
	u64 val;
	EDMA_ADDR_T node_addr0={0}, node_addr1={0};
	DMA_SRC_INT_DSCR_HIGH_S chn_src_node_cnt;
	DMA_DST_INT_DSCR_HIGH_S chn_dst_node_cnt;
	struct edma_chn_info *edma_chp = get_edma_channel_info(channel);

	if (edma_chp->chn_cfg.direction == EDMA_TX) {
		node_addr0.addr_l32 = skw_pcie_read32(DMA_SRC_INT_DSCR_HEAD_LOW(channel));
		node_addr1.addr_l32 = skw_pcie_read32(DMA_SRC_INT_DSCR_TAIL_LOW(channel));
		chn_src_node_cnt.u32 = skw_pcie_read32(DMA_SRC_INT_DSCR_HIGH(channel));
		*count = chn_src_node_cnt.src_node_done_num;

		val = chn_src_node_cnt.src_int_dscr_head_high & 0xff;
		*head = (u64)(node_addr0.addr_l32 | (val << 32));

		val = chn_src_node_cnt.src_int_dscr_tail_high & 0xff;
		*tail = (u64)(node_addr1.addr_l32 | (val << 32));
	} else {
		node_addr0.addr_l32 = skw_pcie_read32(DMA_DST_INT_DSCR_HEAD_LOW(channel));
		node_addr1.addr_l32 = skw_pcie_read32(DMA_DST_INT_DSCR_TAIL_LOW(channel));
		chn_dst_node_cnt.u32 = skw_pcie_read32(DMA_DST_INT_DSCR_HIGH(channel));
		*count = chn_dst_node_cnt.dst_node_done_num;

		val = chn_dst_node_cnt.dst_int_dscr_head_high & 0xff;
		*head = (u64)(node_addr0.addr_l32 | (val << 32));

		val = chn_dst_node_cnt.dst_int_dscr_tail_high & 0xff;
		*tail = (u64)(node_addr1.addr_l32 | (val << 32));
	}

	return 0;
}

int msi_irq_wifi_takeover_handler(int irq_num)
{
	struct edma_chn_info *edma_chp;
	struct wcn_pcie_info *priv = get_pcie_device_info();
	int ch_id;
	unsigned long flags;
	DMA_DST_INT_S reg_chn_dst_int = {0};

	spin_lock_irqsave(priv->spin_lock, flags);

	if (priv->msix_en == 1)
		ch_id = irq_num/2;
	else
		ch_id = irq_num;

	edma_chp = get_edma_channel_info(ch_id);
	if (ch_id == EDMA_WIFI_TX0_FREE_ADDR || ch_id == EDMA_WIFI_TX1_FREE_ADDR
		|| ch_id == EDMA_WIFI_RX0_PKT_ADDR || ch_id == EDMA_WIFI_RX1_PKT_ADDR
		|| ch_id == EDMA_WIFI_RX0_FILTER_DATA_CHN || ch_id == EDMA_WIFI_RX1_FILTER_DATA_CNH) {

		reg_chn_dst_int.u32 = skw_pcie_read32(DMA_DST_INT(ch_id));
		reg_chn_dst_int.dst_complete_int_clr = 1;
		reg_chn_dst_int.dst_complete_int_en = 0;
		skw_pcie_write32(DMA_DST_INT(ch_id), reg_chn_dst_int.u32);
		skw_pcie_read32(DMA_DST_INT_DSCR_HIGH(ch_id));
	}

	if(edma_chp->chn_cfg.complete_callback)
		edma_chp->chn_cfg.complete_callback(edma_chp->chn_cfg.context, 0, 0, 0);

	spin_unlock_irqrestore(priv->spin_lock, flags);

	return 0;
}

int legacy_irq_wifi_takeover_handler(int ch_id)
{
	int num;
	u64 head, tail;
	struct edma_chn_info *edma_chp = get_edma_channel_info(ch_id);

	if(edma_chp->chn_cfg.complete_callback)
		return edma_chp->chn_cfg.complete_callback(edma_chp->chn_cfg.context, 0, 0, -1);

	edma_mask_channel(ch_id);

	edma_channel_irq_info(ch_id, &head, &tail, &num);

	edma_unmask_channel(ch_id);

	return 0;
}

struct sv6160_platform_data wifi_pdata = {
	.cmd_port =  14,
	.data_port =  19,
	.bus_type = PCIE_LINK|TX_ADMA|RX_ADMA,
	.max_buffer_size = 0xFFFF,
	.align_value = 4,
	.hw_channel_init = edma_channel_init,
	.hw_channel_deinit = close_edma_channel,
	.hw_adma_tx = edma_adma_send,
	.modem_assert = send_modem_assert_command,
	.service_start = wifi_service_start,
	.service_stop = wifi_service_stop,
	.phyaddr_to_pcieaddr = edma_phyaddr_to_pcieaddr,
	.pcieaddr_to_phyaddr = edma_pcieaddr_to_phyaddr,
	.virtaddr_to_pcieaddr = edma_virtaddr_to_pcieaddr,
	.pcieaddr_to_virtaddr = edma_pcieaddr_to_virtaddr,
	.submit_list_to_edma_channel = submit_list_to_edma_channel,
	.wifi_channel_map = 0x7FF,
	.edma_mask_irq = edma_mask_channel,
	.edma_unmask_irq = edma_unmask_channel,
	.modem_register_notify = modem_register_notify,
	.modem_unregister_notify = modem_unregister_notify,
	.at_ops = {
		  .port =EDMA_AT_PORT,
		  .open = open_edma_port,
		  .close = close_edma_port,
		  .read = recv_data,
		  .write = send_data,
	},
	.edma_get_node_tot_cnt = edma_get_node_tot_cnt,
	.edma_clear_node_count = edma_clear_node_count,
	.edma_channel_irq_info = edma_channel_irq_info,
};

struct sv6160_platform_data ucom_pdata = {
	.data_port =  EDMA_BTACL_PORT,
	.cmd_port =  EDMA_BTCMD_PORT,
	.audio_port =  EDMA_BTAUDIO_PORT,
	.bus_type = PCIE_LINK|TX_ADMA|RX_ADMA,
	.max_buffer_size = 0x800,
	.align_value = 4,
	.hw_sdma_rx = recv_data,
	.hw_sdma_tx = send_data,
	.open_port = open_edma_port,
	.close_port = close_edma_port,
	.modem_assert = send_modem_assert_command,
	.modem_register_notify = modem_register_notify,
	.modem_unregister_notify = modem_unregister_notify,
	.service_start = bt_service_start,
	.service_stop = bt_service_stop,
	.skw_dump_mem = skw_pcie_mem_dump,
};

int skw_pcie_bind_platform_driver(struct platform_device *boot_dev)
{
	struct platform_device *pdev;
	char	pdev_name[32];
	struct edma_port *port;
	int ret = 0;
	struct wcn_pcie_info *priv = get_pcie_device_info();
	struct device *parent_dev = &priv->dev->dev;

	PCIE_INFO("[+]\n");
	memset(edma_ports, 0, sizeof(struct edma_port) * MAX_PORT_NUM);
	sprintf(pdev_name, "skw_ucom");
/*
 *	creaete AT device
 */
	pdev = platform_device_alloc(pdev_name, PLATFORM_DEVID_AUTO);
	if(!pdev)
		return -ENOMEM;
	pdev->dev.parent = parent_dev;
	pdev->dev.dma_mask = &port_dmamask;
	pdev->dev.coherent_dma_mask = port_dmamask;
	ucom_pdata.port_name = "ATC";
	ucom_pdata.data_port = EDMA_AT_PORT;
	memcpy(ucom_pdata.chipid, priv->chip_id, SKW_CHIP_ID_LENGTH);
	ret = platform_device_add_data(pdev, &ucom_pdata, sizeof(ucom_pdata));
	if(ret) {
		PCIE_ERR("failed to add platform data \n");
		platform_device_put(pdev);
		return ret;
	}
	port = &edma_ports[ucom_pdata.data_port];
	port->pdev = pdev;
	port->state = PORT_STATE_IDLE;
	ret = platform_device_add(pdev);
	if(ret) {
		PCIE_ERR("failt to register platform device\n");
		platform_device_put(pdev);
		return ret;
	}

/*
 *	creaete log device
 */
	pdev = platform_device_alloc(pdev_name, PLATFORM_DEVID_AUTO);
	if(!pdev)
		return -ENOMEM;
	pdev->dev.parent = parent_dev;
	pdev->dev.dma_mask = &port_dmamask;
	pdev->dev.coherent_dma_mask = port_dmamask;
	ucom_pdata.port_name = "LOG";
	ucom_pdata.data_port = EDMA_LOG_PORT;
	ret = platform_device_add_data(pdev, &ucom_pdata, sizeof(ucom_pdata));
	if(ret) {
		PCIE_ERR("failed to add %s device \n", ucom_pdata.port_name);
		platform_device_put(pdev);
		return ret;
	}

	port = &edma_ports[ucom_pdata.data_port];
	port->pdev = pdev;
	port->state = PORT_STATE_IDLE;
	ret = platform_device_add(pdev);
	if(ret) {
		PCIE_ERR("failt to register platform device\n");
		platform_device_put(pdev);
		return ret;
	}

/*
 *	creaete LOOPCHECK device
 */
	pdev = platform_device_alloc(pdev_name, PLATFORM_DEVID_AUTO);
	if(!pdev)
		return -ENOMEM;
	pdev->dev.parent = parent_dev;
	pdev->dev.dma_mask = &port_dmamask;
	pdev->dev.coherent_dma_mask = port_dmamask;
	ucom_pdata.port_name = "LOOPCHECK";
	ucom_pdata.data_port = EDMA_LOOPCHECK_PORT;
	ret = platform_device_add_data(pdev, &ucom_pdata, sizeof(ucom_pdata));
	if(ret) {
		PCIE_ERR("failed to add platform data \n");
		platform_device_put(pdev);
		return ret;
	}

	port = &edma_ports[ucom_pdata.data_port];
	port->pdev = pdev;
	port->state = PORT_STATE_IDLE;
	ret = platform_device_add(pdev);
	if(ret) {
		PCIE_ERR("failt to register platform device\n");
		platform_device_put(pdev);
		return ret;
	}

	PCIE_INFO("[-]\n");
	return ret;
}

int skw_pcie_bind_wifi_driver(struct platform_device *boot_dev)
{
	struct platform_device *pdev;
	char	pdev_name[32];
	int ret = 0;
	struct wcn_pcie_info *priv = get_pcie_device_info();
	struct device *parent_dev = &priv->dev->dev;

	PCIE_INFO("[+]\n");
	sprintf(pdev_name, "%s%d", SV6316_WIRELESS, 1);
	pdev = platform_device_alloc(pdev_name, PLATFORM_DEVID_AUTO);
	if(!pdev)
		return -ENOMEM;
	pdev->dev.parent = parent_dev;
	pdev->dev.dma_mask = &port_dmamask;
	pdev->dev.coherent_dma_mask = port_dmamask;
	memcpy(wifi_pdata.chipid, priv->chip_id, SKW_CHIP_ID_LENGTH);
	wifi_pdata.pcie_dev = &(priv->dev->dev);
	ret = platform_device_add_data(pdev, &wifi_pdata, sizeof(wifi_pdata));
	if(ret) {
		PCIE_ERR("failed to add platform data\n");
		platform_device_put(pdev);
		return ret;
	}

	wifi_data_pdev = pdev;
	ret = platform_device_add(pdev);
	if(ret) {
		PCIE_ERR("fail to register platform device\n");
		platform_device_put(pdev);
	}
	PCIE_DBG("add device successful\n");
	PCIE_INFO("[-]\n");

	return ret;
}

#ifdef CONFIG_BT_SEEKWAVE
int skw_pcie_bind_bt_driver(struct platform_device *boot_dev)
{
	struct platform_device *pdev;
	char	pdev_name[32];
	struct edma_port *port;
	int ret = 0;
	struct wcn_pcie_info *priv = get_pcie_device_info();
	struct device *parent_dev = &priv->dev->dev;

	PCIE_INFO("[+]\n");
	sprintf(pdev_name, "btseekwave");

	/*creaete BT DATA device*/
	pdev = platform_device_alloc(pdev_name, PLATFORM_DEVID_AUTO);
	if(!pdev){
		PCIE_ERR("[-]failed to allocate platform device\n");
		return -ENOMEM;
	}
	pdev->dev.parent = parent_dev;
	pdev->dev.dma_mask = &port_dmamask;
	pdev->dev.coherent_dma_mask = port_dmamask;
	memcpy(ucom_pdata.chipid, priv->chip_id, SKW_CHIP_ID_LENGTH);
	ucom_pdata.data_port = EDMA_BTACL_PORT;
	ucom_pdata.cmd_port = EDMA_BTCMD_PORT;
	ucom_pdata.audio_port = EDMA_BTAUDIO_PORT;
	ret = platform_device_add_data(pdev, &ucom_pdata, sizeof(ucom_pdata));
	if(ret) {
		PCIE_ERR("[-]failed to add platform data\n");
		platform_device_put(pdev);
		return ret;
	}

	bt_data_pdev = pdev;
	port = get_edma_port_info(ucom_pdata.data_port);
	port->pdev = pdev;
	port->state = PORT_STATE_IDLE;

	port = get_edma_port_info(ucom_pdata.cmd_port);
	port->pdev = pdev;
	port->state = PORT_STATE_IDLE;

	port = get_edma_port_info(ucom_pdata.audio_port);
	port->pdev = pdev;
	port->state = PORT_STATE_IDLE;

	ret = platform_device_add(pdev);
	if(ret) {
		PCIE_INFO("[-]fail to register platform device\n")
		platform_device_put(pdev);
		return ret;
	}

	PCIE_INFO("[-]\n");
	return ret;
}
#else
int skw_pcie_bind_bt_driver(struct platform_device *boot_dev)
{
	struct platform_device *pdev;
	char	pdev_name[32];
	struct edma_port *port;
	int ret = 0;
	struct wcn_pcie_info *priv = get_pcie_device_info();
	struct device *parent_dev = &priv->dev->dev;

	PCIE_INFO("[+]\n");
	sprintf(pdev_name, "skw_ucom");
/*
 *	creaete BT DATA device
 */
	pdev = platform_device_alloc(pdev_name, PLATFORM_DEVID_AUTO);
	if(!pdev)
		return -ENOMEM;
	pdev->dev.parent = parent_dev;
	pdev->dev.dma_mask = &port_dmamask;
	pdev->dev.coherent_dma_mask = port_dmamask;
	ucom_pdata.port_name = "BTDATA";
	ucom_pdata.data_port = EDMA_BTACL_PORT;
	memcpy(ucom_pdata.chipid, priv->chip_id, SKW_CHIP_ID_LENGTH);
	ret = platform_device_add_data(pdev, &ucom_pdata, sizeof(ucom_pdata));
	if(ret) {
		PCIE_ERR("failed to add platform data \n");
		platform_device_put(pdev);
		return ret;
	}

	port = &edma_ports[ucom_pdata.data_port];
	port->pdev = pdev;
	port->state = PORT_STATE_IDLE;

	ret = platform_device_add(pdev);
	if(ret) {
		PCIE_ERR("failt to register platform device\n");
		platform_device_put(pdev);
		return ret;
	}

/*
 *	creaete BT COMMAND device
 */
	pdev = platform_device_alloc(pdev_name, PLATFORM_DEVID_AUTO);
	if(!pdev)
		return -ENOMEM;
	pdev->dev.parent = parent_dev;
	pdev->dev.dma_mask = &port_dmamask;
	pdev->dev.coherent_dma_mask = port_dmamask;
	ucom_pdata.port_name = "BTCMD";
	ucom_pdata.data_port = EDMA_BTCMD_PORT;
	ret = platform_device_add_data(pdev, &ucom_pdata, sizeof(ucom_pdata));
	if(ret) {
		PCIE_ERR("failed to add %s device \n", ucom_pdata.port_name);
		platform_device_put(pdev);
		return ret;
	}

	port = &edma_ports[ucom_pdata.data_port];
	port->pdev = pdev;
	port->state = PORT_STATE_IDLE;

	ret = platform_device_add(pdev);
	if(ret) {
		PCIE_ERR("failt to register platform device\n");
		platform_device_put(pdev);
		return ret;
	}

/*
 *	creaete BT audio device
 */
	pdev = platform_device_alloc(pdev_name, PLATFORM_DEVID_AUTO);
	if(!pdev)
		return -ENOMEM;
	pdev->dev.parent = parent_dev;
	pdev->dev.dma_mask = &port_dmamask;
	pdev->dev.coherent_dma_mask = port_dmamask;
	ucom_pdata.port_name = "BTAUDIO";
	ucom_pdata.data_port = EDMA_BTAUDIO_PORT;
	ret = platform_device_add_data(pdev, &ucom_pdata, sizeof(ucom_pdata));
	if(ret) {
		PCIE_ERR("failed to add platform data \n");
		platform_device_put(pdev);
		return ret;
	}

	port = &edma_ports[ucom_pdata.data_port];
	port->pdev = pdev;
	port->state = PORT_STATE_IDLE;

	ret = platform_device_add(pdev);
	if(ret) {
		PCIE_ERR("failt to register platform device\n");
		platform_device_put(pdev);
		return ret;
	}

/*
 *	creaete BT isoc  device
 */
	pdev = platform_device_alloc(pdev_name, PLATFORM_DEVID_AUTO);
	if(!pdev)
		return -ENOMEM;
	pdev->dev.parent = parent_dev;
	pdev->dev.dma_mask = &port_dmamask;
	pdev->dev.coherent_dma_mask = port_dmamask;
	ucom_pdata.port_name = "BTISOC";
	ucom_pdata.data_port = EDMA_ISOC_PORT;
	ret = platform_device_add_data(pdev, &ucom_pdata, sizeof(ucom_pdata));
	if(ret) {
		PCIE_ERR("failed to add platform data \n");
		platform_device_put(pdev);
		return ret;
	}

	port = &edma_ports[ucom_pdata.data_port];
	port->pdev = pdev;
	port->state = PORT_STATE_IDLE;

	ret = platform_device_add(pdev);
	if(ret) {
		PCIE_ERR("failt to register platform device\n");
		platform_device_put(pdev);
		return ret;
	}

/*
 *	creaete BT LOG  device
 */
	pdev = platform_device_alloc(pdev_name, PLATFORM_DEVID_AUTO);
	if(!pdev)
		return -ENOMEM;
	pdev->dev.parent = parent_dev;
	pdev->dev.dma_mask = &port_dmamask;
	pdev->dev.coherent_dma_mask = port_dmamask;
	ucom_pdata.port_name = "BTLOG";
	ucom_pdata.data_port = EDMA_BTLOG_PORT;
	ret = platform_device_add_data(pdev, &ucom_pdata, sizeof(ucom_pdata));
	if(ret) {
		PCIE_ERR("failed to add platform data \n");
		platform_device_put(pdev);
		return ret;
	}

	port = &edma_ports[ucom_pdata.data_port];
	port->pdev = pdev;
	port->state = PORT_STATE_IDLE;

	ret = platform_device_add(pdev);
	if(ret) {
		PCIE_ERR("failt to register platform device\n");
		platform_device_put(pdev);
		return ret;
	}

	PCIE_INFO("[-]\n");
	return ret;
}
#endif

int skw_pcie_unbind_wifi_driver(struct platform_device *boot_dev)
{
	int ret = 0;

	return ret;
}

int skw_pcie_unbind_bt_driver(struct platform_device *boot_dev)
{
	int ret = 0;

	return ret;
}

int  skw_edma_init(void)
{
	int i;
	struct wcn_pcie_info *priv = get_pcie_device_info();
#ifdef CONFIG_SKW_MSI_AS_LEGACY
	int val;
#endif

	if (priv->msix_en)
		skw_pcie_write32(DMA_INT_TYPE_CFG, 0x2);
	else if (priv->msi_en)
		skw_pcie_write32(DMA_INT_TYPE_CFG, 0x0);
	else if (priv->legacy_en)
		skw_pcie_write32(DMA_INT_TYPE_CFG, 0x1);
	else
		skw_pcie_write32(DMA_INT_TYPE_CFG, 0x2);

	skw_pcie_write32(DMA_DST_RING_NODE_NUM, 0x3ff);
	skw_pcie_write32(DMA_SRC_RING_NODE_NUM, 0x3ff);

	memset(&edma_chns_info[0], 0, sizeof(edma_chns_info));
	memset(&edma_ports[0], 0, sizeof(edma_ports));
	for (i = 0;i < MAX_EDMA_COUNT;i++) {
		edma_chns_info[i].chn_id = i;
#ifdef CONFIG_SKW_MSI_AS_LEGACY
		val = skw_pcie_read32(DMA_CFG(i));
		val &= ~0xf8000000;
		skw_pcie_write32(DMA_CFG(i), val);
#endif
	}

	edma_spin_lock_init(priv);
	skw_edma_wakeup_source_init();
#ifdef CONFIG_BT_SEEKWAVE
	//INIT_WORK(&priv->bt_rx_work, bt_rx_work);
#endif

	mutex_init(&priv->close_mutex);
	return 0;
}

int skw_edma_pause(void)
{
	struct wcn_pcie_info *priv = get_pcie_device_info();
	int status, ret;

	skw_pcie_write32(DMA_PAUSE, 0xffffffff);
	ret = readl_poll_timeout(priv->pcimem + (DMA_PAUSE_DONE - 0x40000000),
				 status, (status == 0xffffffff), 5, 100);
	if (ret) {
		PCIE_ERR("Failed to pause,done:0x%08x,rawint:0x%08x\n", status, skw_pcie_read32(DMA_INT_MASK_STS-4));
		return -EBUSY;
	}

	ret = readl_poll_timeout(priv->pcimem + (DMA_REQ_STS - 0x40000000),
				 status, (status == 0), 5, 100);
	if (ret) {
		PCIE_ERR("EDMA is busy\n");
		return -EBUSY;
	}

	return 0;
}

void skw_edma_restore(void)
{
	skw_pcie_write32(DMA_PAUSE, 0);
}

void recovery_close_all_ports(void)
{
	int i = 0;
	struct edma_port *port;

	PCIE_INFO("[+]\n");
	for(i=0; i<MAX_PORT_NUM;i++) {
		PCIE_INFO("[+]portno=%d\n", i);
		port = get_edma_port_info(i);
#if !defined(CONFIG_BT_SEEKWAVE)
		if (i <= EDMA_BTLOG_PORT) {//bt port
			PCIE_INFO("port_sta_rec[%d]=%d, %d\n", i, port_sta_rec[i], completion_done(&port->rx_done));
			if (port_sta_rec[i] == 1 && !completion_done(&port->rx_done)) {
				complete(&port->rx_done);
				if (i == EDMA_BTCMD_PORT)//for bt stop service pass before recovery in skw_boot.c
					cp_exception_sts = 0;
			}
			continue;
		}
#endif
		if(port->pdev)
			close_edma_port(i);
		PCIE_INFO("[-]portno=%d\n", i);
	}
	PCIE_INFO("[-]\n");
}

int skw_pcie_unbind_port_driver(void)
{
	int i = 0;
	struct edma_port *port;
	struct wcn_pcie_info *priv = get_pcie_device_info();

	PCIE_INFO("[+]\n");
	if (priv->cp_state == CP_READY) {//remove driver
		if (wifi_data_pdev != NULL) {
			platform_device_unregister(wifi_data_pdev);
			wifi_data_pdev = NULL;
		}
		PCIE_INFO("\n");
#ifdef CONFIG_BT_SEEKWAVE
		if (bt_data_pdev != NULL) {
			platform_device_unregister(bt_data_pdev);
			bt_data_pdev = NULL;
		}
		for(i=EDMA_LOOPCHECK_PORT; i<MAX_PORT_NUM;i++)
#else
		for(i=0; i<MAX_PORT_NUM;i++)
#endif
		{
			PCIE_INFO("portno=%d\n", i);
			port = get_edma_port_info(i);
			if(port->pdev) {
				close_edma_port(i);
				platform_device_unregister(port->pdev);
			}
			PCIE_INFO("portno=%d\n", i);
		}
	} else {
		PCIE_INFO("cpsts:%s, recv no unbind driver\n", str_cpsts[priv->cp_state]);
	}
	PCIE_INFO("[-]\n");
	return 0;
 }

void skw_edma_deinit(void)
{
	struct wcn_pcie_info *priv = get_pcie_device_info();
	//struct edma_chn_info *edma_chp = get_edma_channel_info(6);

	PCIE_INFO("[+]\n");
#if 0
	//kfree(at_buffer);
	dma_free_coherent(&priv->dev->dev, PAGE_ALIGN(EDMA_PORT_BUFFER_SIZE),
			at_buffer, edma_chp->hdr_dma_addr);
#endif
	kfree(priv->spin_lock);
	skw_edma_wakeup_source_destroy();
	skw_pcie_unbind_port_driver();
	PCIE_INFO("[-]\n");
}
