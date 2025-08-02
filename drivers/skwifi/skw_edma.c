// SPDX-License-Identifier: GPL-2.0

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

#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/dma-direct.h>

#include "skw_core.h"
#include "skw_compat.h"
#include "skw_edma.h"
#include "skw_log.h"
#include "skw_rx.h"
#include "skw_tx.h"
#include "trace.h"

static void skw_edma_proc_com_show(struct seq_file *seq, void *data)
{
	int j, sz;
	u64 *addr = NULL;
	struct skw_edma_node *node = data;

	sz = node->hw->list.xmit_len >> 3;

	addr = (u64 *)node->hw->buff;
	for (j = 0; j < sz; j++)
		seq_printf(seq,	"\t    addr[%d]: 0x%llx\n", j, addr[j]);
}

void skw_edma_tx_proc_show(struct seq_file *seq, void *data)
{
	int j, sz;
	struct skw_edma_elem *addr = NULL;
	struct skw_edma_node *node = data;

	sz = node->hw->list.xmit_len / sizeof(struct skw_edma_elem);

	addr = (struct skw_edma_elem *)node->hw->buff;
	for (j = 0; j < sz; j++)
		seq_printf(seq,	"\t    addr[%d]: 0x%llx\n", j, addr[j]);
}

void skw_edma_filter_proc_show(struct seq_file *seq, void *data)
{
	int i;
	u8 *addr = NULL;
	struct skw_edma_node *node = data;

	addr = (u8 *)node->hw->buff;

	for (i = 0; i < node->hw->list.xmit_len; i++) {
		if(i%16 == 0)
			seq_printf(seq, "\n\t");
		seq_printf(seq, " 0x%02x", addr[i]);
	}
	seq_printf(seq, "\n");

}

static int skw_edma_proc_show(struct seq_file *seq, void *data)
{
	//int i, j, sz;
	int i;
	//u64 *addr = NULL;
	struct skw_edma_node *node;
	struct skw_edma_channel *echn = seq->private;

	seq_puts(seq, "\n");

	seq_printf(seq, "channel: %d\n", echn->channel);

	seq_printf(seq, "nr_node: %d\n"
			"node buff size: %d\n"
			"current node: %d\n"
			"flags:%x\n"
			"napi_rx status:%x\n",
			echn->ctx.nr_node,
			echn->ctx.node[0].hw->buff_len,
			echn->ctx.cur->hw->idx,
			atomic_read(&echn->flags),
			echn->lmac->napi_rx.state);

	seq_puts(seq, "\n");

	for (i = 0; i < echn->ctx.nr_node; i++) {
		node = &echn->ctx.node[i];

		seq_printf(seq, "node[%d]: 0x%llx\n", i, node->hw->list_addr);

		seq_printf(seq, "\tdone: %d (ref: %d)\n"
				"\tskb qlen: %d\n"
				"\txmit len: %d\n",
				node->hw->done,
				atomic_read(&node->ref),
				skb_queue_len(&node->skb_list),
				node->hw->list.xmit_len);

		seq_puts(seq, "\tbuff:\n");
		if (echn->show)
			echn->show(seq, node);

		seq_puts(seq, "\n");
	}

	return 0;
}

static int skw_edma_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, skw_edma_proc_show, skw_pde_data(inode));
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops skw_edma_proc_fops = {
	.proc_open = skw_edma_proc_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};
#else
static const struct file_operations skw_edma_proc_fops = {
	.owner = THIS_MODULE,
	.open = skw_edma_proc_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};
#endif

static int skw_edma_hw_channel_init(struct skw_edma_channel *echn,
			struct skw_channel_cfg *cfg, void *data)
{
	struct skw_core *skw = echn->skw;

	if (!skw || !skw->hw_pdata || !skw->hw_pdata->hw_channel_init)
		return -ENOTSUPP;

	//set_bit(SKW_EDMA_FLAG_CHAN_INIT, &echn->flags);
	atomic_or(BIT(SKW_EDMA_FLAG_CHAN_INIT), &echn->flags);

	return skw->hw_pdata->hw_channel_init(echn->channel, cfg, data);
}

static int skw_edma_hw_channel_deinit(struct skw_edma_channel *echn)
{
	struct skw_core *skw = echn->skw;

	if (!skw || !skw->hw_pdata || !skw->hw_pdata->hw_channel_deinit)
		return -ENOTSUPP;

	//if (test_and_clear_bit(SKW_EDMA_FLAG_CHAN_INIT, &echn->flags))
	if (atomic_fetch_and((int)~BIT(SKW_EDMA_FLAG_CHAN_INIT), &echn->flags))
		return skw->hw_pdata->hw_channel_deinit(echn->channel);

	return 0;
}

static int skw_edma_irq_info(struct skw_edma_channel *echn, u64 *head, u64 *tail, int *num)
{
	struct skw_core *skw = echn->skw;

	if (!skw || !skw->hw_pdata || !skw->hw_pdata->edma_channel_irq_info)
		return -ENOTSUPP;

	return skw->hw_pdata->edma_channel_irq_info(echn->channel, head, tail, num);
}

static int skw_edma_mask_irq(struct skw_edma_channel *echn)
{
	struct skw_core *skw = echn->skw;

	if (!skw || !skw->hw_pdata || !skw->hw_pdata->edma_mask_irq)
		return -ENOTSUPP;

	skw->hw_pdata->edma_mask_irq(echn->channel);

	//set_bit(SKW_EDMA_FLAG_MASK_IRQ, &echn->flags);
	atomic_or(BIT(SKW_EDMA_FLAG_MASK_IRQ), &echn->flags);

	return 0;
}

static inline int skw_edma_unmask_irq(struct skw_edma_channel *echn)
{
	struct skw_core *skw = echn->skw;

	if (!skw || !skw->hw_pdata || !skw->hw_pdata->edma_unmask_irq)
		return -ENOTSUPP;

	//if (test_and_clear_bit(SKW_EDMA_FLAG_MASK_IRQ, &echn->flags))
	if (atomic_fetch_and((int)~BIT(SKW_EDMA_FLAG_MASK_IRQ), &echn->flags))
		skw->hw_pdata->edma_unmask_irq(echn->channel);

	return 0;
}

int skw_edma_req(struct skw_edma_channel *echn, int nr_node)
{
	struct skw_core *skw = echn->skw;

	if (!skw || !skw->hw_pdata || !skw->hw_pdata->hw_adma_tx)
		return -ENOTSUPP;

	return  skw->hw_pdata->hw_adma_tx(echn->channel, NULL, nr_node, 0);
}

static inline int skw_edma_nr_node_released(struct skw_edma_channel *echn)
{
	struct skw_core *skw = echn->skw;

	if (!skw || !skw->hw_pdata || !skw->hw_pdata->edma_get_node_tot_cnt)
		return -ENOTSUPP;

	return skw->hw_pdata->edma_get_node_tot_cnt(echn->channel);
}

static inline void *skw_pcie_to_virt(struct skw_edma_channel *echn, u64 pcie_addr)
{
	u64 addr = pcie_addr & SKW_EDMA_ADDR_MASK;

	return phys_to_virt(dma_to_phys(echn->dev, (dma_addr_t)addr));
}

static int skw_edma_set_rx_ring(struct skw_edma_channel *echn,
				struct skw_edma_node *node)
{
	u64 *addr;
	int i, max, qlen;
	dma_addr_t dma_addr;

	qlen = skb_queue_len(&node->skb_list);
	if (qlen && !node->hw->done) {
		skw_warn("qlen: %d, xmit_len: %d\n",
			 qlen, node->hw->list.xmit_len);

		return 0;
	}

	addr = (u64 *)node->hw->buff;
	max = node->hw->buff_len / SKW_EDMA_ADDR_LEN;

	for (i = 0; i < max; i++) {
		struct sk_buff *skb  = dev_alloc_skb(SKW_EDMA_SKB_DATA_LEN);
		if (!skb)
			break;

		__skb_trim(skb, SKW_EDMA_SKB_DATA_LEN);

		dma_addr = dma_map_single(echn->dev, skb->data, skb->len, DMA_FROM_DEVICE);
		if (dma_mapping_error(echn->dev, dma_addr)) {
			skw_warn("dma mapping error\n");

			dev_kfree_skb_any(skb);
			continue;
		}

		SKW_SKB_RXCB(skb)->edma_node_idx = node->hw->idx;
		SKW_SKB_RXCB(skb)->pa = dma_addr;

		addr[i] = dma_addr | SKW_EDMA_ADDR_FLAG;

		skb_queue_tail(&node->skb_list, skb);
	}

	qlen = skb_queue_len(&node->skb_list);
	node->hw->list.xmit_len = qlen * SKW_EDMA_ADDR_LEN;

	trace_skw_edma_set_rx_ring(echn->channel, qlen);

	if (qlen)
		atomic_set(&node->ref, 1);

	return qlen ? 0 : -ENOMEM;
}

static int skw_edma_node_init(struct skw_edma_channel *echn, struct skw_edma_node *node)
{
	//node->hw->list.xmit_len = node->hw->buff_len;

	return 0;
}

int skw_edma_pending_skb(struct skw_core *skw, int id)
{
	return atomic_read(&skw->edma.lmac[id].skb_qlen);
}

static int skw_edma_channel_enable(struct skw_edma_channel *echn,
		int (*init)(struct skw_edma_channel *c, struct skw_edma_node *n),
		bool dma_request)
{
	int i, nr_node;
	struct skw_edma_node *node;

	skw_detail("channel: %d, dma request: %d\n", echn->channel, dma_request);

	echn->ctx.cur = node = &echn->ctx.node[0];

	for (i = 0, nr_node = 0; i < echn->ctx.nr_node; i++) {
		node->hw->done = 0;

		if (init(echn, node))
			break;

		nr_node++;
		node = node->next;
	}

	if (nr_node != echn->ctx.nr_node)
		skw_warn("channel: %d, nr_node: %d, total: %d\n",
			 echn->channel, nr_node, echn->ctx.nr_node);

	skw_edma_hw_channel_init(echn, &echn->cfg, NULL);

	if (dma_request)
		skw_edma_req(echn, nr_node);

	return 0;
}

static void skw_edma_channel_disable(struct skw_edma_channel *echn)
{
	int i;
	struct sk_buff *skb;

	skw_dbg("channel: %d\n", echn->channel);

	skw_edma_hw_channel_deinit(echn);

	for (i = 0; i < echn->ctx.nr_node; i++) {
		struct skw_edma_node *node = &echn->ctx.node[i];

		while ((skb = skb_dequeue(&node->skb_list)) != NULL) {
			if (atomic_read(&echn->flags) & BIT(SKW_EDMA_FLAG_ADDR_BUFF))
			//if (test_bit(SKW_EDMA_FLAG_ADDR_BUFF, &echn->flags))
				dma_unmap_single(echn->dev, SKW_SKB_TXCB(skb)->pa,
						skb->len, DMA_TO_DEVICE);

			kfree_skb(skb);
		}
	}
}

void skw_edma_enable(struct skw_core *skw, int id)
{
	int credit;
	struct skw_edma_channel *echn;

	if (skw->hw.bus != SKW_BUS_PCIE)
		return;

	skw_dbg("lmac id: %d\n", id);

	skw_edma_channel_enable(&skw->edma.lmac[id].filter,
			      skw_edma_node_init, true);

	skw_edma_channel_enable(&skw->edma.lmac[id].rx_ring,
			      skw_edma_set_rx_ring, true);

	skw_edma_channel_enable(&skw->edma.lmac[id].rx,
			      skw_edma_node_init, true);

	skw_edma_channel_enable(&skw->edma.lmac[id].txc,
			      skw_edma_node_init, true);

	skw_edma_channel_enable(&skw->edma.lmac[id].tx,
			      skw_edma_node_init, false);

	echn = &skw->edma.lmac[id].tx;
	credit = echn->ctx.node[0].hw->buff_len / sizeof(struct skw_edma_elem);
	skw_detail("buff_len: %d, elem per node: %d, nr_node: %d, credit: %d\n",
		echn->ctx.node[0].hw->buff_len, credit, echn->ctx.nr_node,
		credit * echn->ctx.nr_node);

	credit *= echn->ctx.nr_node;
	atomic_set(&skw->hw.lmac[id].fw_credit, credit);

	skw_edma_unmask_irq(&skw->edma.lmac[id].tx);
	skw_edma_unmask_irq(&skw->edma.lmac[id].txc);
	skw_edma_unmask_irq(&skw->edma.lmac[id].rx);
	skw_edma_unmask_irq(&skw->edma.lmac[id].rx_ring);
	skw_edma_unmask_irq(&skw->edma.lmac[id].filter);

	napi_enable(&skw->hw.lmac[id].napi_rx);
	napi_enable(&skw->hw.lmac[id].napi_tx);

	set_bit(SKW_LMAC_NAPI_ENABLE, &skw->hw.lmac[id].flags);
}

void skw_edma_disable(struct skw_core *skw, int id)
{
	int num;
	u64 head, tail;

	if (skw->hw.bus != SKW_BUS_PCIE)
		return;

	skw_dbg("lmac id: %d\n", id);

	skw_edma_mask_irq(&skw->edma.lmac[id].tx);
	skw_edma_mask_irq(&skw->edma.lmac[id].txc);
	skw_edma_mask_irq(&skw->edma.lmac[id].rx);
	skw_edma_mask_irq(&skw->edma.lmac[id].rx_ring);
	skw_edma_mask_irq(&skw->edma.lmac[id].filter);

	skw_edma_irq_info(&skw->edma.lmac[id].tx, &head, &tail, &num);
	skw_edma_irq_info(&skw->edma.lmac[id].txc, &head, &tail, &num);
	skw_edma_irq_info(&skw->edma.lmac[id].rx, &head, &tail, &num);
	skw_edma_irq_info(&skw->edma.lmac[id].rx_ring, &head, &tail, &num);
	skw_edma_irq_info(&skw->edma.lmac[id].filter, &head, &tail, &num);

	skw_edma_channel_disable(&skw->edma.lmac[id].tx);
	skw_edma_channel_disable(&skw->edma.lmac[id].txc);
	skw_edma_channel_disable(&skw->edma.lmac[id].rx);
	skw_edma_channel_disable(&skw->edma.lmac[id].rx_ring);
	skw_edma_channel_disable(&skw->edma.lmac[id].filter);

	atomic_set(&skw->hw.lmac[id].fw_credit, 0);

	if (test_and_clear_bit(SKW_LMAC_NAPI_ENABLE, &skw->hw.lmac[id].flags)) {
		napi_synchronize(&skw->hw.lmac[id].napi_tx);
		napi_disable(&skw->hw.lmac[id].napi_tx);

		napi_synchronize(&skw->hw.lmac[id].napi_rx);
		napi_disable(&skw->hw.lmac[id].napi_rx);
	}
}

static struct skw_edma_node *skw_edma_map_node(struct skw_edma_channel *echn, u64 addr)
{
	u64 dma, offset;
	struct skw_edma_hw *hw;

	dma = addr & SKW_EDMA_ADDR_MASK;
	if (dma < echn->ctx.dma_pa ||
	    dma > echn->ctx.dma_pa + echn->ctx.dma_size) {
		skw_warn("invalid addr: 0x%llx\n", addr);

		return NULL;
	}

	offset = dma - echn->ctx.dma_pa - offsetof(struct skw_edma_hw, list);
	hw = (struct skw_edma_hw *)(echn->ctx.dma_va + offset);

	return &echn->ctx.node[hw->idx];
}

static int skw_edma_poll_txc(struct napi_struct *napi, int budget)
{
	int tx_done = 0, nr_node = 0;
	struct skw_lmac *lmac = container_of(napi, struct skw_lmac, napi_tx);
	struct skw_core *skw = lmac->skw;
	struct skw_edma_channel *echn = &skw->edma.lmac[lmac->id].txc;

	while (tx_done < budget) {
		u64 *addr;
		int i, total, done;

		done = echn->ctx.cur->hw->done;

		trace_skw_edma_tx_poll(echn->channel, echn->ctx.cur->hw->idx,
				echn->ctx.cur->hw->list_addr, done,
				echn->ctx.cur->hw->list.xmit_len);

		skw_detail("chan: %d, node idx: %d, dma: 0x%08llx, done: %d, data_len: %d, budget: %d\n",
			echn->channel, echn->ctx.cur->hw->idx,
			echn->ctx.cur->hw->list_addr, done,
			echn->ctx.cur->hw->list.xmit_len, budget);

		if (!done)
			break;

		nr_node++;
	 	total = echn->ctx.cur->hw->list.xmit_len / SKW_EDMA_ADDR_LEN;

		addr = (u64 *)echn->ctx.cur->hw->buff;
		for (i = 0; i < total; i++) {
			int idx;
			void *data = NULL;
			struct sk_buff *skb;
			struct skw_edma_node *txn;
			struct skw_addr_ref *ref;

			data = skw_pcie_to_virt(echn, addr[i] - sizeof(struct skw_tx_desc_conf));
			if (!data) {
				skw_warn("invalid addr: 0x%llx\n", addr[i]);
				continue;
			}

			ref = (struct skw_addr_ref *)(data - sizeof(struct skw_addr_ref));
			if (ref->magic != SKW_XMIT_REF_MAGIC) {
				skw_warn("invalid magic\n");
				skw_hex_dump("txc", data, 32, true);

				continue;
			}

			skb = ref->addr;
			idx = SKW_SKB_TXCB(ref->addr)->edma_node_idx;
			txn = &skw->edma.lmac[lmac->id].tx.ctx.node[idx];

			skw_detail("tx node: %d, done: %d, skb: 0x%lx, qlen: %d\n",
				idx, txn->hw->done, ref->addr, skb_queue_len(&txn->skb_list));

			skb_unlink(ref->addr, &txn->skb_list);

			dma_unmap_single(echn->dev, SKW_SKB_TXCB(skb)->pa,
					skb->len, DMA_TO_DEVICE);

			skb->dev->stats.tx_packets++;
			skb->dev->stats.tx_bytes += SKW_SKB_TXCB(skb)->skb_native_len;
			atomic_dec(&skw->edma.lmac[lmac->id].skb_qlen);
			skw_skb_kfree(skw, skb);
		}

		echn->ctx.cur->hw->done = 0;
		//echn->ctx.cur->hw->list.xmit_len = echn->ctx.cur->hw->buff_len;
		echn->ctx.cur = echn->ctx.cur->next;

		skw_edma_req(echn, 1);

		//tx_done += total;
	}

	if (skw_edma_pending_skb(skw, lmac->id) < SKW_EDMA_TX_LOW_THRESHOLD) {
		skw_wakeup_tx(skw, 0);
	}

	if (tx_done < budget) {
		napi_complete_done(napi, tx_done);

		if (atomic_read(&echn->flags) & BIT(SKW_EDMA_FLAG_MASK_IRQ))
		//if (test_bit(SKW_EDMA_FLAG_MASK_IRQ, &echn->flags))
			skw_edma_unmask_irq(echn);
	}

	return min(tx_done, budget);
}

static int skw_edma_txc_isr(void *priv, u64 head, u64 tail, int num)
{
	struct skw_edma_channel *echn = priv;

	skw_edma_mask_irq(echn);
	skw_edma_irq_info(echn, &head, &tail, &num);

	trace_skw_edma_tx_complete_isr(echn->channel, head, tail, num);

	skw_detail("chn: %d, head: 0x%llx, tail: 0x%llx, num: %d\n",
		echn->channel, head, tail, num);

	napi_schedule(&echn->lmac->napi_tx);

	return 0;
}

static int skw_edma_tx_isr(void *priv, u64 head, u64 tail, int num)
{
	int i, valid;
	struct skw_edma_node *node;
	struct skw_edma_channel *echn = priv;

	skw_edma_mask_irq(echn);

	skw_edma_irq_info(echn, &head, &tail, &num);

	node = skw_edma_map_node(echn, head);

	trace_skw_edma_tx_isr(echn->channel, head, tail, num);

	skw_detail("chn: %d, head: 0x%llx(idx: %d), tail: 0x%llx, num: %d\n",
		echn->channel, head, node->hw->idx, tail, num);

	for (valid = 0, i = 0; i < num; i++) {
		atomic_set(&node->ref, 0);

		node = node->next;
	}

	skw_add_credit(echn->skw, echn->lmac->id, 64 * num);

	skw_edma_unmask_irq(echn);

	return 0;
}

static int skw_edma_poll_rxc(struct napi_struct *napi, int budget)
{
	int rx_done = 0, idx;
	struct skw_lmac *lmac = container_of(napi, struct skw_lmac, napi_rx);
	struct skw_core *skw = lmac->skw;
	struct skw_edma_channel *echn = &skw->edma.lmac[lmac->id].rx;
	struct skw_edma_channel *ring_chn = &skw->edma.lmac[lmac->id].rx_ring;

	skw_detail("cpu_id:%d lmac:%d enter budget:%d\n", smp_processor_id(), lmac->id, budget);

	if (!spin_trylock(&lmac->napi_rx_lock)) {
		napi_complete_done(napi, 0);
		skw_detail("cpu_id:%d lmac:%d napi_rx already running exit\n", smp_processor_id(), lmac->id);

		goto _exit;
	}

	while (rx_done < budget) {
		u64 *addr;
		int i, total, done;

		done = echn->ctx.cur->hw->done;

		trace_skw_edma_rx_poll(echn->channel, echn->ctx.cur->hw->idx,
				echn->ctx.cur->hw->list_addr, done,
				echn->ctx.cur->hw->list.xmit_len);

		skw_detail("chan: %d, node: %d, dma: 0x%08llx, done: %d, data_len: %d\n",
			echn->channel, echn->ctx.cur->hw->idx,
			echn->ctx.cur->hw->list_addr, done,
			echn->ctx.cur->hw->list.xmit_len);

		if (!done)
			break;

		addr = (u64 *)echn->ctx.cur->hw->buff;
	 	total = echn->ctx.cur->hw->list.xmit_len / SKW_EDMA_ADDR_LEN;

		for (i = 0; i < total; i++) {
			struct sk_buff *skb;
			struct skw_edma_node *node;

			if (!ring_chn->ctx.cur->skb_list.qlen)
				ring_chn->ctx.cur = ring_chn->ctx.cur->next;

			skb = skb_peek(&ring_chn->ctx.cur->skb_list);
			if (!skb) {
				skw_dbg("invalid skb\n");
				continue;
			}

			if (SKW_SKB_RXCB(skb)->pa != (addr[i] & SKW_EDMA_ADDR_MASK)) {
				skw_warn("skb(0x%llx) is out of order\n", addr[i]);

				skw_hw_assert(echn->skw, false);

				continue;
			}

			//dma_sync_single_for_cpu(echn->dev, addr[i] & SKW_EDMA_ADDR_MASK,
			//			SKW_EDMA_SKB_DATA_LEN, DMA_FROM_DEVICE);

			dma_unmap_single(ring_chn->dev, SKW_SKB_RXCB(skb)->pa,
					skb->len, DMA_FROM_DEVICE);

			// remove skb from ring buffer list
			idx = SKW_SKB_RXCB(skb)->edma_node_idx;
			SKW_SKB_RXCB(skb)->lmac_id = echn->lmac->id;
			node = &ring_chn->ctx.node[idx];
			skb_unlink(skb, &node->skb_list);

			skw_detail("remove skb from node: %d, qlen: %d, currnt: %d, qlen: %d\n",
				node->hw->idx, skb_queue_len(&node->skb_list),
				ring_chn->ctx.cur->hw->idx,
				skb_queue_len(&ring_chn->ctx.cur->skb_list));

			if (skb_queue_len(&ring_chn->ctx.cur->skb_list) == 0) {
				atomic_set(&ring_chn->ctx.cur->ref, 0);

				if (!skw_edma_set_rx_ring(ring_chn, ring_chn->ctx.cur)) {
					skw_detail("add ring node: %d, qlen: %d\n",
						ring_chn->ctx.cur->hw->idx,
						skb_queue_len(&ring_chn->ctx.cur->skb_list));

					skw_edma_req(ring_chn, 1);

					ring_chn->ctx.cur = ring_chn->ctx.cur->next;
					// TODO:
					// check current node ring buffer
				} else {
					// TODO:
					// refill buffer failed
				}
			}

			/* skip 8 byte for skw_rx_desc */
			skb_pull(skb, 8);
			skb_queue_tail(&lmac->rx_dat_q, skb);
		}

		rx_done += total;
		//skw_rx_process(skw, &skw->rx_dat_q, &lmac->rx_todo_list);

		echn->ctx.cur->hw->done = 0;
		//echn->ctx.cur->hw->list.xmit_len = echn->ctx.cur->hw->buff_len;

		skw_edma_req(echn, 1);
		echn->ctx.cur = echn->ctx.cur->next;
	}

	skw_rx_process(skw, &lmac->rx_dat_q, &lmac->rx_todo_list);
	rx_done = atomic_xchg(&lmac->napi_work_done, 0);
	if (rx_done < budget) {
		napi_complete_done(napi, rx_done);

		//if (test_bit(SKW_EDMA_FLAG_MASK_IRQ, &echn->flags))
		if (atomic_read(&echn->flags) & BIT(SKW_EDMA_FLAG_MASK_IRQ))
			skw_edma_unmask_irq(echn);
	}

	spin_unlock(&lmac->napi_rx_lock);
_exit:
	skw_detail("cpu_id:%d exit rx_done:%d budget:%d\n", smp_processor_id(), rx_done, budget);

	return min(rx_done, budget);
}

static int skw_edma_rx_ring_isr(void *priv, u64 head, u64 tail, int num)
{
	struct skw_edma_channel *echn = priv;

	skw_edma_mask_irq(echn);

	skw_edma_irq_info(echn, &head, &tail, &num);

	trace_skw_edma_rx_ring_isr(echn->channel, head, tail, num);

	skw_detail("chn: %d, head: 0x%llx, tail: 0x%llx, num: %d\n",
		echn->channel, head, tail, num);

	skw_edma_unmask_irq(echn);

	return 0;
}

static int skw_edma_rxc_isr(void *priv, u64 head, u64 tail, int num)
{
	struct skw_edma_channel *echn = priv;

	skw_edma_mask_irq(echn);

	skw_edma_irq_info(echn, &head, &tail, &num);

	trace_skw_edma_rx_complete_isr(echn->channel, head, tail, num);

	skw_detail("chn: %d, head: 0x%llx, tail: 0x%llx, num: %d\n",
		echn->channel, head, tail, num);

	napi_schedule(&echn->lmac->napi_rx);

	return 0;
}

static int skw_edma_rx_filter_isr(void *priv, u64 head, u64 tail, int num)
{
	int nr = 0;
	struct skw_edma_channel *echn = priv;
	struct skw_edma_node *node;

	skw_edma_mask_irq(echn);

	skw_edma_irq_info(echn, &head, &tail, &num);

	trace_skw_edma_rx_filter_isr(echn->channel, head, tail, num);

	skw_detail("chn: %d, head: 0x%llx, tail: 0x%llx, num: %d\n",
		echn->channel, head, tail, num);

	node= skw_edma_map_node(priv, head);

	for (nr = 0; nr < num; nr++, node = node->next) {
		struct sk_buff *skb;
		int data_len = node->hw->list.xmit_len;
		node->hw->done = 0;

		//node->hw->list.xmit_len = node->hw->buff_len;
		skb = netdev_alloc_skb_ip_align(NULL, data_len);
		if (!skb) {
			// TBD:
			// ADD RX Drop
			continue;
		}

		SKW_SKB_RXCB(skb)->lmac_id = echn->lmac->id;
		skw_put_skb_data(skb, node->hw->buff, data_len);
		skb_queue_tail(&echn->lmac->rx_dat_q, skb);
	}

	skw_edma_req(echn, num);

	skw_edma_unmask_irq(echn);

	napi_schedule(&echn->lmac->napi_rx);

	return 0;
}

int skw_edma_rx_msg_isr(void *priv, u64 head, u64 tail, int num)
{
	int nr = 0;
	struct skw_edma_channel *echn = priv;
	struct skw_edma_node *node;

	skw_edma_mask_irq(echn);

	skw_edma_irq_info(echn, &head, &tail, &num);

	skw_detail("chn: %d, head: 0x%llx, tail: 0x%llx, num: %d\n",
		echn->channel, head, tail, num);

	echn->skw->isr_cpu_id = smp_processor_id();
	sg_init_table(echn->sgl, num);
	node = skw_edma_map_node(priv, head);

	for (nr = 0; nr < num; nr++, node = node->next) {
		int data_len = node->hw->list.xmit_len;
		void *data = NULL;

		//node->hw->list.xmit_len = node->hw->buff_len;

		/* reserve 12 bytes for msg handler */
		data = netdev_alloc_frag(data_len + echn->skw->skb_share_len + 12);
		if (!data) {
			skw_warn("alloc failed, size: %d\n", data_len);
			continue;
		}

		memcpy(data + 12, node->hw->buff, data_len);
		sg_set_buf(echn->sgl, data, data_len + 12);
	}

	skw_edma_req(echn, num);

	sg_mark_end(echn->sgl);

	nr = sg_nents(echn->sgl);
	if (nr)
		skw_rx_cb(SKW_EDMA_VIRTUAL_CMD_PORT, echn->sgl, nr, echn->skw);

	skw_edma_unmask_irq(echn);

	return 0;
}

static void skw_edma_channel_deinit(struct skw_edma_channel *echn)
{
	skw_edma_channel_disable(echn);

	if (echn->ctx.dma_va)
		dma_free_coherent(echn->dev, echn->ctx.dma_size,
				echn->ctx.dma_va, echn->ctx.dma_pa);

	SKW_KFREE(echn->sgl);

	SKW_KFREE(echn->ctx.node);
}

static int skw_edma_channel_init(struct skw_core *skw, struct skw_lmac *lmac,
			     struct skw_edma_channel *echn, int channel,
			     int nr_node, int node_buff_len, unsigned long flags,
			     enum SKW_EDMA_DIRECTION direction,
			     skw_edma_isr isr, int irq_threshold,
			     enum SKW_EDMA_CHN_PRIORITY priority,
			     enum SKW_EDMA_CHN_BUFF_ATTR attr,
			     enum SKW_EDMA_CHN_BUFF_TYPE buff_type,
			     enum SKW_EDMA_CHN_TRANS_MODE trans_mode,
				 show_func show)
{
	int i, hw_node_size;
	u64 dma_base, dma_addr;

	skw_dbg("channel: %d, nr_node: %d\n", channel, nr_node);

	memset(echn, 0, sizeof(struct skw_edma_channel));

	echn->skw = skw;
	echn->lmac = lmac;
	echn->channel = channel;
	echn->dev = skw->hw_pdata->pcie_dev;
	//echn->flags = 0;
	atomic_set(&echn->flags, 0);

	if (flags & SKW_EDMA_INIT_ALLOC_SG) {
		echn->sgl = kcalloc(nr_node, sizeof(struct scatterlist), GFP_KERNEL);
		if (!echn->sgl) {
			skw_err("alloc sgl failed, channel: %d, nr_node: %d\n",
				channel, nr_node);

			return -ENOMEM;
		}
	}

	if (flags & SKW_EDMA_INIT_ADDR_BUFF)
		atomic_or(BIT(SKW_EDMA_FLAG_ADDR_BUFF), &echn->flags);
		//set_bit(SKW_EDMA_FLAG_ADDR_BUFF, &echn->flags);

	echn->ctx.nr_node = nr_node;

	echn->ctx.node = SKW_ZALLOC(nr_node * sizeof(struct skw_edma_node), GFP_KERNEL);
	if (!echn->ctx.node) {
		skw_err("alloc node failed, channel: %d, nr_node: %d\n",
			channel, nr_node);

		goto alloc_node_failed;
	}

	hw_node_size = sizeof(struct skw_edma_hw) + node_buff_len;
	hw_node_size = ALIGN(hw_node_size, SKW_EDMA_ADDR_ALIGN);

	echn->ctx.dma_size = ALIGN(hw_node_size * nr_node + SKW_EDMA_ADDR_ALIGN, PAGE_SIZE);
	echn->ctx.dma_va = dma_alloc_coherent(echn->dev, echn->ctx.dma_size,
					&echn->ctx.dma_pa, GFP_KERNEL);
	if (!echn->ctx.dma_va) {
		skw_err("alloc node failed, channel: %d, nr_node: %d\n",
			channel, nr_node);

		goto alloc_dma_failed;
	}

	dma_base = PTR_ALIGN(echn->ctx.dma_pa, SKW_EDMA_ADDR_ALIGN);
	dma_base |= SKW_EDMA_ADDR_FLAG;

	for (i = 0; i < nr_node; i++) {
		struct skw_edma_hw *hw;
		struct skw_edma_node *node;
		int next = (i + 1) % nr_node;

		dma_addr = dma_base + i * hw_node_size;

		hw = ((dma_addr & SKW_EDMA_ADDR_MASK) - echn->ctx.dma_pa) + echn->ctx.dma_va;
		hw->idx = i;
		hw->done = 0;

		hw->buff_len = node_buff_len;
		hw->buff_addr = dma_addr + offsetof(struct skw_edma_hw, buff);
		hw->list_addr = dma_addr + offsetof(struct skw_edma_hw, list);
		hw->list.next_list = (dma_base + next * hw_node_size) +
				offsetof(struct skw_edma_hw, list);

		node = &echn->ctx.node[i];
		node->hw = hw;
		node->next = &echn->ctx.node[next];
		atomic_set(&node->ref, 0);
		skb_queue_head_init(&node->skb_list);

		skw_detail("list addr: 0x%llx, next link: 0x%llx, data addr: 0x%llx\n",
			node->hw->list_addr, node->hw->list.next_list,
			node->hw->buff_addr);
	}

	echn->ctx.cur = &echn->ctx.node[0];

	echn->cfg.priority = priority;
	echn->cfg.split = attr;
	echn->cfg.ring = buff_type;
	echn->cfg.req_mode = trans_mode;
	echn->cfg.irq_threshold = irq_threshold;
	echn->cfg.node_count = nr_node;
	echn->cfg.header = echn->ctx.node[0].hw->list_addr;
	echn->cfg.complete_callback = isr;
	echn->cfg.direction = direction;
	echn->cfg.context = echn;
	echn->show = show;

	return 0;

alloc_dma_failed:
	SKW_KFREE(echn->ctx.node);

alloc_node_failed:
	SKW_KFREE(echn->sgl);

	return -ENOMEM;
}

static void skw_edma_msg_disable(struct skw_core *skw)
{
	skw_edma_channel_deinit(&skw->edma.cmd);
	skw_edma_channel_deinit(&skw->edma.short_event);
	skw_edma_channel_deinit(&skw->edma.long_event);
}

void skw_edma_msg_enable(struct skw_core *skw)
{
	if (skw->hw.bus != SKW_BUS_PCIE)
		return;

	skw_edma_channel_enable(&skw->edma.cmd, skw_edma_node_init, false);
	skw->cmd.data = skw->edma.cmd.ctx.cur->hw->buff;

	skw_edma_channel_enable(&skw->edma.short_event, skw_edma_node_init, true);
	skw_edma_channel_enable(&skw->edma.long_event, skw_edma_node_init, true);

	skw_edma_unmask_irq(&skw->edma.cmd);
	skw_edma_unmask_irq(&skw->edma.short_event);
	skw_edma_unmask_irq(&skw->edma.long_event);
}

int skw_edma_init(struct wiphy *wiphy)
{
	int ret, i;
	struct skw_lmac *lmac = NULL;
	struct skw_core *skw = wiphy_priv(wiphy);

	// cmd channel
	ret = skw_edma_channel_init(skw,
				NULL,                           /* lmac */
				&skw->edma.cmd,                 /* struct skw_edma_channel */
				SKW_EDMA_CHN_CMD,               /* channel */
				SKW_EDMA_NODE_NUM_CMD,          /* node count */
				SKW_EDMA_BUFF_LEN_DEFAULT,      /* node buffer length */
				SKW_EDMA_INIT_ALLOC_SG,         /* flags */
				SKW_HOST_TO_FW,                 /* dma direction */
				NULL,			        /* irq callback */
				1,                              /* irq threshold */
				SKW_EDMA_CHN_PRIORITY_0,
				SKW_EDMA_CHN_BUFF_NON_LINNER,
				SKW_EDMA_CHN_RING_BUFF,
				SKW_EDMA_CHN_LINKLIST_MODE,
				skw_edma_proc_com_show);
	if (ret)
		goto deinit_cmd;

	// short event channel
	ret = skw_edma_channel_init(skw,
				NULL,
				&skw->edma.short_event,
				SKW_EDMA_CHN_SHORT_EVENT,
				SKW_EDMA_NODE_NUM_SHORT_EVENT,
				SKW_EDMA_BUFF_LEN_DEFAULT,
				SKW_EDMA_INIT_ALLOC_SG,
				SKW_FW_TO_HOST,
				skw_edma_rx_msg_isr,
				1,
				SKW_EDMA_CHN_PRIORITY_0,
				SKW_EDMA_CHN_BUFF_NON_LINNER,
				SKW_EDMA_CHN_LIST_BUFF,
				SKW_EDMA_CHN_LINKLIST_MODE,
				skw_edma_proc_com_show);
	if (ret)
		goto deinit_short_evt;

	// long event channel
	ret = skw_edma_channel_init(skw,
				NULL,
				&skw->edma.long_event,
				SKW_EDMA_CHN_LONG_EVENT,
				SKW_EDMA_NODE_NUM_LONG_EVENT,
				SKW_EDMA_BUFF_LEN_DEFAULT,
				SKW_EDMA_INIT_ALLOC_SG,
				SKW_FW_TO_HOST,
				skw_edma_rx_msg_isr,
				1,
				SKW_EDMA_CHN_PRIORITY_0,
				SKW_EDMA_CHN_BUFF_NON_LINNER,
				SKW_EDMA_CHN_LIST_BUFF,
				SKW_EDMA_CHN_LINKLIST_MODE,
				skw_edma_proc_com_show);
	if (ret)
		goto deinit_long_evt;

	// RX filter channel
	ret = skw_edma_channel_init(skw,
				&skw->hw.lmac[0],
				&skw->edma.lmac[0].filter,
				SKW_EDMA_CHN_MAC_0_RX_FITER,
				SKW_EDMA_NODE_NUM_RX_FILTER,
				SKW_EDMA_SKB_DATA_LEN,
				0,
				SKW_FW_TO_HOST,
				skw_edma_rx_filter_isr,
				1,
				SKW_EDMA_CHN_PRIORITY_0,
				SKW_EDMA_CHN_BUFF_NON_LINNER,
				SKW_EDMA_CHN_LIST_BUFF,
				SKW_EDMA_CHN_LINKLIST_MODE,
				skw_edma_filter_proc_show);
	if (ret)
		goto deinit_0_filter;

	ret = skw_edma_channel_init(skw,
				&skw->hw.lmac[1],
				&skw->edma.lmac[1].filter,
				SKW_EDMA_CHN_MAC_1_RX_FITER,
				SKW_EDMA_NODE_NUM_RX_FILTER,
				SKW_EDMA_BUFF_LEN_DEFAULT,
				0,
				SKW_FW_TO_HOST,
				skw_edma_rx_filter_isr,
				1,
				SKW_EDMA_CHN_PRIORITY_0,
				SKW_EDMA_CHN_BUFF_NON_LINNER,
				SKW_EDMA_CHN_LIST_BUFF,
				SKW_EDMA_CHN_LINKLIST_MODE,
				skw_edma_filter_proc_show);
	if (ret)
		goto deinit_1_filter;

	// TX chan
	ret = skw_edma_channel_init(skw,
				&skw->hw.lmac[0],
				&skw->edma.lmac[0].tx,
				SKW_EDMA_CHN_MAC_0_TX,
				SKW_EDMA_NODE_NUM_TX,
				SKW_EDMA_BUFF_LEN_TX,
				SKW_EDMA_INIT_ADDR_BUFF,
				SKW_HOST_TO_FW,
				skw_edma_tx_isr,
				2,
				SKW_EDMA_CHN_PRIORITY_0,
				SKW_EDMA_CHN_BUFF_NON_LINNER,
				SKW_EDMA_CHN_RING_BUFF,
				SKW_EDMA_CHN_LINKLIST_MODE,
				skw_edma_tx_proc_show);
	if (ret)
		goto deinit_0_tx;

	ret = skw_edma_channel_init(skw,
				&skw->hw.lmac[1],
				&skw->edma.lmac[1].tx,
				SKW_EDMA_CHN_MAC_1_TX,
				SKW_EDMA_NODE_NUM_TX,
				SKW_EDMA_BUFF_LEN_TX,
				SKW_EDMA_INIT_ADDR_BUFF,
				SKW_HOST_TO_FW,
				skw_edma_tx_isr,
				2,
				SKW_EDMA_CHN_PRIORITY_0,
				SKW_EDMA_CHN_BUFF_NON_LINNER,
				SKW_EDMA_CHN_RING_BUFF,
				SKW_EDMA_CHN_LINKLIST_MODE,
				skw_edma_tx_proc_show);
	if (ret)
		goto deinit_1_tx;

	// TXC chan
	ret = skw_edma_channel_init(skw,
				&skw->hw.lmac[0],
				&skw->edma.lmac[0].txc,
				SKW_EDMA_CHN_MAC_0_TXC,
				SKW_EDMA_NODE_NUM_TXC,
				SKW_EDMA_BUFF_LEN_TXC,
				SKW_EDMA_INIT_ADDR_BUFF,
				SKW_FW_TO_HOST,
				skw_edma_txc_isr,
				1,
				SKW_EDMA_CHN_PRIORITY_0,
				SKW_EDMA_CHN_BUFF_NON_LINNER,
				SKW_EDMA_CHN_RING_BUFF,
				SKW_EDMA_CHN_LINKLIST_MODE,
				skw_edma_proc_com_show);
	if (ret)
		goto deinit_0_txc;

	ret = skw_edma_channel_init(skw,
				&skw->hw.lmac[1],
				&skw->edma.lmac[1].txc,
				SKW_EDMA_CHN_MAC_1_TXC,
				SKW_EDMA_NODE_NUM_TXC,
				SKW_EDMA_BUFF_LEN_TXC,
				SKW_EDMA_INIT_ADDR_BUFF,
				SKW_FW_TO_HOST,
				skw_edma_txc_isr,
				1,
				SKW_EDMA_CHN_PRIORITY_0,
				SKW_EDMA_CHN_BUFF_NON_LINNER,
				SKW_EDMA_CHN_RING_BUFF,
				SKW_EDMA_CHN_LINKLIST_MODE,
				skw_edma_proc_com_show);
	if (ret)
		goto deinit_1_txc;

	// RX RING chan
	ret = skw_edma_channel_init(skw,
				&skw->hw.lmac[0],
				&skw->edma.lmac[0].rx_ring,
				SKW_EDMA_CHN_MAC_0_RX_RING,
				SKW_EDMA_NODE_NUM_RX_RING,
				SKW_EDMA_BUFF_LEN_RX_RING,
				SKW_EDMA_INIT_ADDR_BUFF,
				SKW_HOST_TO_FW,
				skw_edma_rx_ring_isr,
				2,
				SKW_EDMA_CHN_PRIORITY_0,
				SKW_EDMA_CHN_BUFF_NON_LINNER,
				SKW_EDMA_CHN_RING_BUFF,
				SKW_EDMA_CHN_LINKLIST_MODE,
				skw_edma_proc_com_show);
	if (ret)
		goto deinit_0_ring;

	ret = skw_edma_channel_init(skw,
				&skw->hw.lmac[1],
				&skw->edma.lmac[1].rx_ring,
				SKW_EDMA_CHN_MAC_1_RX_RING,
				SKW_EDMA_NODE_NUM_RX_RING,
				SKW_EDMA_BUFF_LEN_RX_RING,
				SKW_EDMA_INIT_ADDR_BUFF,
				SKW_HOST_TO_FW,
				skw_edma_rx_ring_isr,
				2,
				SKW_EDMA_CHN_PRIORITY_0,
				SKW_EDMA_CHN_BUFF_NON_LINNER,
				SKW_EDMA_CHN_RING_BUFF,
				SKW_EDMA_CHN_LINKLIST_MODE,
				skw_edma_proc_com_show);
	if (ret)
		goto deinit_1_ring;

	// RX chan
	ret = skw_edma_channel_init(skw,
				&skw->hw.lmac[0],
				&skw->edma.lmac[0].rx,
				SKW_EDMA_CHN_MAC_0_RX,
				SKW_EDMA_NODE_NUM_RX,
				SKW_EDMA_BUFF_LEN_RX,
				SKW_EDMA_INIT_ADDR_BUFF,
				SKW_FW_TO_HOST,
				skw_edma_rxc_isr,
				1,
				SKW_EDMA_CHN_PRIORITY_0,
				SKW_EDMA_CHN_BUFF_NON_LINNER,
				SKW_EDMA_CHN_RING_BUFF,
				SKW_EDMA_CHN_LINKLIST_MODE,
				skw_edma_proc_com_show);
	if (ret)
		goto deinit_0_rx;

	ret = skw_edma_channel_init(skw,
				&skw->hw.lmac[1],
				&skw->edma.lmac[1].rx,
				SKW_EDMA_CHN_MAC_1_RX,
				SKW_EDMA_NODE_NUM_RX,
				SKW_EDMA_BUFF_LEN_RX,
				SKW_EDMA_INIT_ADDR_BUFF,
				SKW_FW_TO_HOST,
				skw_edma_rxc_isr,
				1,
				SKW_EDMA_CHN_PRIORITY_0,
				SKW_EDMA_CHN_BUFF_NON_LINNER,
				SKW_EDMA_CHN_RING_BUFF,
				SKW_EDMA_CHN_LINKLIST_MODE,
				skw_edma_proc_com_show);
	if (ret)
		goto deinit_1_rx;

	skw_edma_msg_enable(skw);

	skw->edma.pentry = skw_procfs_subdir("edma", skw->pentry);

	for (i = 0; i < SKW_MAX_LMAC_SUPPORT; i++) {
		char name[32] = {0};

		lmac = &skw->hw.lmac[i];

		init_dummy_netdev(&lmac->dummy_dev);

		skw_compat_netif_napi_add_weight(&lmac->dummy_dev, &lmac->napi_tx,
				skw_edma_poll_txc, NAPI_POLL_WEIGHT);

		spin_lock_init(&lmac->napi_rx_lock);
		atomic_set(&lmac->napi_work_done, 0);

		skw_compat_netif_napi_add_weight(&lmac->dummy_dev, &lmac->napi_rx,
				skw_edma_poll_rxc, NAPI_POLL_WEIGHT);

		skw_list_init(&lmac->rx_todo_list);

		set_bit(SKW_LMAC_FLAG_INIT, &lmac->flags);

		snprintf(name, sizeof(name), "mac%d", i);
		skw->edma.lmac[i].pentry = skw_procfs_subdir(name, skw->edma.pentry);

		skw_procfs_file(skw->edma.lmac[i].pentry, "chn_tx", 0444,
				&skw_edma_proc_fops, &skw->edma.lmac[i].tx);

		skw_procfs_file(skw->edma.lmac[i].pentry, "chn_txc", 0444,
				&skw_edma_proc_fops, &skw->edma.lmac[i].txc);

		skw_procfs_file(skw->edma.lmac[i].pentry, "chn_rx", 0444,
				&skw_edma_proc_fops, &skw->edma.lmac[i].rx);

		skw_procfs_file(skw->edma.lmac[i].pentry, "chn_rx_ring", 0444,
				&skw_edma_proc_fops, &skw->edma.lmac[i].rx_ring);

		skw_procfs_file(skw->edma.lmac[i].pentry, "chn_filter", 0444,
				&skw_edma_proc_fops, &skw->edma.lmac[i].filter);
	}

	return 0;

deinit_1_rx:
	skw_edma_channel_deinit(&skw->edma.lmac[1].rx);

deinit_0_rx:
	skw_edma_channel_deinit(&skw->edma.lmac[0].rx);

deinit_1_ring:
	skw_edma_channel_deinit(&skw->edma.lmac[0].rx_ring);

deinit_0_ring:
	skw_edma_channel_deinit(&skw->edma.lmac[0].rx_ring);

deinit_1_txc:
	skw_edma_channel_deinit(&skw->edma.lmac[1].txc);

deinit_0_txc:
	skw_edma_channel_deinit(&skw->edma.lmac[0].txc);

deinit_1_tx:
	skw_edma_channel_deinit(&skw->edma.lmac[1].tx);

deinit_0_tx:
	skw_edma_channel_deinit(&skw->edma.lmac[0].tx);

deinit_1_filter:
	skw_edma_channel_deinit(&skw->edma.lmac[1].filter);

deinit_0_filter:
	skw_edma_channel_deinit(&skw->edma.lmac[0].filter);

deinit_long_evt:
	skw_edma_channel_deinit(&skw->edma.long_event);

deinit_short_evt:
	skw_edma_channel_deinit(&skw->edma.short_event);

deinit_cmd:
	skw_edma_channel_deinit(&skw->edma.cmd);

	return -ENOMEM;
}

void skw_edma_deinit(struct wiphy *wiphy)
{
	int i = 0;
	struct skw_lmac *lmac = NULL;
	struct skw_core *skw = wiphy_priv(wiphy);

	skw_edma_msg_disable(skw);

	for (i = 0; i < SKW_MAX_LMAC_SUPPORT; i++) {
		lmac = &skw->hw.lmac[i];

		netif_napi_del(&lmac->napi_tx);
		netif_napi_del(&lmac->napi_rx);

		skw_edma_channel_deinit(&skw->edma.lmac[i].txc);
		skw_edma_channel_deinit(&skw->edma.lmac[i].tx);

		skw_edma_channel_deinit(&skw->edma.lmac[i].rx);
		skw_edma_channel_deinit(&skw->edma.lmac[i].rx_ring);

		skw_edma_channel_deinit(&skw->edma.lmac[i].filter);

		skw_rx_todo(&lmac->rx_todo_list);
		skb_queue_purge(&lmac->rx_dat_q);
	}
}
