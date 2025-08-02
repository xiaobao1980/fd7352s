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
#include <linux/kthread.h>
#include <linux/ip.h>
#include <linux/ctype.h>
#include <linux/dma-mapping.h>
#include <linux/dma-direct.h>

#include "skw_core.h"
#include "skw_tx.h"
#include "skw_msg.h"
#include "skw_iface.h"
#include "skw_edma.h"
#include "trace.h"

#define SKW_BASE_VO                    16
#define SKW_BASE_VI                    24
#define SKW_TX_TIMEOUT                 200
#define SKW_TX_RUNING_TIMES            20

struct skw_tx_info {
	int quota;
	bool reset;
	struct sk_buff_head *list;
};

struct skw_tx_lmac {
	bool reset;
	int cred;
	u16 txq_map;
	u16 nr_txq;
	int bk_tx_limit;
	int current_qlen;
	int ac_reset;
	int tx_count_limit;
	int pending_qlen;

	struct sk_buff_head tx_list;
	struct skw_tx_info tx[SKW_NR_IFACE];
};

unsigned int tx_wait_time;

static int skw_tx_time_show(struct seq_file *seq, void *data)
{
	seq_printf(seq, "current tx_wait_time = %dus\n", tx_wait_time);
	return 0;
}

static int skw_tx_time_open(struct inode *inode, struct file *file)
{
	return single_open(file, skw_tx_time_show, inode->i_private);
}

static ssize_t skw_tx_time_write(struct file *fp, const char __user *buf,
				size_t len, loff_t *offset)
{
	int i;
	char cmd[32] = {0};
	unsigned int res = 0;

	for (i = 0; i < 32; i++) {
		char c;

		if (get_user(c, buf))
			return -EFAULT;

		if (c == '\n' || c == '\0')
			break;

		if (isdigit(c) != 0)
			cmd[i] = c;
		else {
			skw_warn("set fail, not number\n");
			return -EFAULT;
		}
		buf++;
	}

	if (kstrtouint(cmd, 10, &res))
		return -EFAULT;

	skw_info("set tx_wait_time = %dus\n", res);
	tx_wait_time = res;

	return len;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops skw_tx_time_fops = {
	.proc_open = skw_tx_time_open,
	.proc_read = seq_read,
	.proc_release = single_release,
	.proc_write = skw_tx_time_write,
};
#else
static const struct file_operations skw_tx_time_fops = {
	.owner = THIS_MODULE,
	.open = skw_tx_time_open,
	.read = seq_read,
	.release = single_release,
	.write = skw_tx_time_write,
};
#endif

#ifdef CONFIG_SKW6316_SKB_RECYCLE
void skw_recycle_skb_free(struct skw_core *skw, struct sk_buff *skb)
{
	if (!skb)
		return;
	skb->data = skb->head;
	skb_reset_tail_pointer(skb);

	skb->mac_header = (typeof(skb->mac_header))~0U;
	skb->transport_header = (typeof(skb->transport_header))~0U;
	skb->network_header = 0;

	skb->len = 0;

	skb_reserve(skb, NET_SKB_PAD);

	skb_queue_tail(&skw->skb_recycle_qlist, skb);

	return;
}

int skw_recycle_skb_copy(struct skw_core *skw, struct sk_buff *skb_recycle, struct sk_buff *skb)
{
	if (!skw || !skb_recycle || !skb)
		return -1;

	skb_recycle->dev = skb->dev;

	skb_reserve(skb_recycle, skw->skb_headroom);
	skb_put(skb_recycle, skb->len);
	memcpy(skb_recycle->data, skb->data, skb->len);

	skb_set_mac_header(skb_recycle, 0);
	skb_set_network_header(skb_recycle, ETH_HLEN);
	skb_set_transport_header(skb_recycle, skb->transport_header - skb->mac_header);
	if (skb->ip_summed == CHECKSUM_PARTIAL) {
		skb_recycle->ip_summed = skb->ip_summed;
		skb_recycle->csum_start = skb_headroom(skb_recycle) + skb_checksum_start_offset(skb);
	}

	return 0;
}

struct sk_buff *skw_recycle_skb_get(struct skw_core *skw)
{
	unsigned long flags;
	struct sk_buff *skb = NULL;

	spin_lock_irqsave(&skw->skb_recycle_qlist.lock, flags);
	if (skw->skb_recycle_qlist.qlen > 0) {
		skb = skb_peek(&skw->skb_recycle_qlist);
		__skb_unlink(skb, &skw->skb_recycle_qlist);
	}
	spin_unlock_irqrestore(&skw->skb_recycle_qlist.lock, flags);

	return skb;
}
#endif

void skw_skb_kfree(struct skw_core *skw, struct sk_buff *skb)
{
#ifdef CONFIG_SKW6316_SKB_RECYCLE
	if (SKW_XMIT_RECYCLE_MAGIC == SKW_SKB_TXCB(skb)->recycle)
		skw_recycle_skb_free(skw, skb);
	else
		dev_kfree_skb_any(skb);
#else
	dev_kfree_skb_any(skb);
#endif
}

int skw_pcie_cmd_xmit(struct skw_core *skw, void *data, int data_len)
{
	struct skw_edma_node *node = skw->edma.cmd.ctx.cur;

	node->hw->done = 0;
	node->hw->list.xmit_len = data_len;

	return skw_edma_req(&skw->edma.cmd, 1);
}

int skw_sdio_cmd_xmit(struct skw_core *skw, void *data, int data_len)
{
	int nr = 0, total_len;

	sg_init_table(skw->sgl_cmd, SKW_NR_SGL_CMD);
	sg_set_buf(&skw->sgl_cmd[nr++], data, data_len);
	total_len = data_len;

	skw_set_extra_hdr(skw, skw->eof_blk, skw->hw.cmd_port, skw->hw.align, 0, 1);
	sg_set_buf(&skw->sgl_cmd[nr++], skw->eof_blk, skw->hw.align);
	total_len += skw->hw.align;

	if (test_bit(SKW_CMD_FLAG_DISABLE_IRQ, &skw->cmd.flags))
		return skw->hw.cmd_disable_irq_xmit(skw, NULL, -1,
				skw->hw.cmd_port, skw->sgl_cmd, nr, total_len);
	else
		return skw->hw.cmd_xmit(skw, NULL, -1, skw->hw.cmd_port,
					skw->sgl_cmd, nr, total_len);
}

int skw_usb_cmd_xmit(struct skw_core *skw, void *data, int data_len)
{
	int nr = 0, total_len;

	sg_init_table(skw->sgl_cmd, SKW_NR_SGL_CMD);
	sg_set_buf(&skw->sgl_cmd[nr++], data, data_len);
	total_len = data_len;

	return skw->hw.cmd_xmit(skw, NULL, -1, skw->hw.cmd_port,
			skw->sgl_cmd, nr, total_len);
}

static int skw_sync_sdma_tx(struct skw_core *skw, struct sk_buff_head *list,
			int lmac_id, int port, struct scatterlist *sgl,
			int nents, int tx_len)
{
	int total_len;
	int ret;
	struct sk_buff *skb, *tmp;

	if (!skw->hw_pdata || !skw->hw_pdata->hw_sdma_tx)
		return -EINVAL;

	if (!skw->sdma_buff) {
		skw_err("invalid buff\n");
		return -ENOMEM;
	}

	total_len = sg_copy_to_buffer(sgl, nents, skw->sdma_buff,
				skw->hw_pdata->max_buffer_size);

	ret = skw->hw_pdata->hw_sdma_tx(port, skw->sdma_buff, total_len);
	if (ret < 0) 
		skw_err("failed, ret: %d nents:%d\n", ret, nents);
	if (list) {
		if (likely(0 == ret))
			skw_sub_credit(skw, lmac_id, skb_queue_len(list));

		skb_queue_walk_safe(list, skb, tmp) {
			if (likely(0 == ret)) {
				skb->dev->stats.tx_packets++;
				skb->dev->stats.tx_bytes += SKW_SKB_TXCB(skb)->skb_native_len;
			} else
				skb->dev->stats.tx_errors++;

			__skb_unlink(skb, list);
			//kfree_skb(skb);
			skw_skb_kfree(skw, skb);
		}
		//skw_sub_credit(skw, lmac_id, skb_queue_len(list));
		//__skb_queue_purge(list);
	}

	return ret;
}

static int skw_sync_sdma_cmd_disable_irq_tx(struct skw_core *skw,
		struct sk_buff_head *list, int lmac_id, int port,
		struct scatterlist *sgl, int nents, int tx_len)
{
	int total_len;

	if (!skw->hw_pdata || !skw->hw_pdata->suspend_sdma_cmd)
		return -EINVAL;

	if (!skw->sdma_buff) {
		skw_err("invalid buff\n");
		return -ENOMEM;
	}

	total_len = sg_copy_to_buffer(sgl, nents, skw->sdma_buff,
				skw->hw_pdata->max_buffer_size);

	return skw->hw_pdata->suspend_sdma_cmd(port, skw->sdma_buff, total_len);
}


static int skw_async_sdma_tx(struct skw_core *skw, struct sk_buff_head *list,
			int lmac_id, int port, struct scatterlist *sgl,
			int nents, int tx_len)
{
	void *buff;
	int ret, total_len;
	struct sk_buff *skb, *tmp;
	struct skw_sg_node *node;

	if (!skw->hw_pdata || !skw->hw_pdata->hw_sdma_tx_async)
		return -EINVAL;

	tx_len += sizeof(struct skw_sg_node);

	buff = SKW_ZALLOC(tx_len, GFP_KERNEL);
	if (!buff) {
		skw_err("invalid buffer\n");
		return -ENOMEM;
	}
	node = (struct skw_sg_node *) buff;
	buff = (u8 *)buff + sizeof(struct skw_sg_node);

	total_len = sg_copy_to_buffer(sgl, nents, buff, tx_len);
	node->lmac_id = lmac_id;
	node->data = (void *)skw;
	node->nents = nents;
	ret = skw->hw_pdata->hw_sdma_tx_async(port, buff, total_len);
	if (ret < 0) {
		skw_err("failed, ret: %d nents:%d\n", ret, nents);
		SKW_KFREE(buff);
	}

	if (list) {
		if (likely(0 == ret))
			skw_sub_credit(skw, lmac_id, skb_queue_len(list));

		skb_queue_walk_safe(list, skb, tmp) {
			if (likely(0 == ret)) {
				skb->dev->stats.tx_packets++;
				skb->dev->stats.tx_bytes += SKW_SKB_TXCB(skb)->skb_native_len;
			} else
				skb->dev->stats.tx_errors++;

			__skb_unlink(skb, list);
			//kfree_skb(skb);
			skw_skb_kfree(skw, skb);
		}

		//skw_sub_credit(skw, lmac_id, skb_queue_len(list));
		//__skb_queue_purge(list);
	}

	return ret;
}

static int skw_sync_adma_tx(struct skw_core *skw, struct sk_buff_head *list,
			int lmac_id, int port, struct scatterlist *sgl,
			int nents, int tx_len)
{
	struct sk_buff *skb, *tmp;
	int ret;
	unsigned long flags;

	if (!skw->hw_pdata || !skw->hw_pdata->hw_adma_tx)
		return -EINVAL;

	ret = skw->hw_pdata->hw_adma_tx(port, sgl, nents, tx_len);
	trace_skw_hw_adma_tx_done(nents);
	if (ret < 0)
		skw_err("failed, ret: %d nents:%d\n", ret, nents);

	if (list) {
		if (likely(0 == ret))
			skw_sub_credit(skw, lmac_id, skb_queue_len(list));
		else
			skb_queue_walk_safe(list, skb, tmp)
				SKW_SKB_TXCB(skb)->ret = 1;

		spin_lock_irqsave(&skw->kfree_skb_qlist.lock, flags);
		skb_queue_splice_tail_init(list, &skw->kfree_skb_qlist);
		spin_unlock_irqrestore(&skw->kfree_skb_qlist.lock, flags);
		schedule_work(&skw->kfree_skb_task);
	}

	return ret;
}

static int skw_sync_adma_cmd_disable_irq_tx(struct skw_core *skw,
		struct sk_buff_head *list, int lmac_id, int port,
		struct scatterlist *sgl, int nents, int tx_len)
{
	if (!skw->hw_pdata || !skw->hw_pdata->suspend_adma_cmd)
		return -EINVAL;

	return skw->hw_pdata->suspend_adma_cmd(port, sgl, nents, tx_len);
}

static int skw_async_adma_tx(struct skw_core *skw, struct sk_buff_head *list,
			int lmac_id, int port, struct scatterlist *sgl,
			int nents, int tx_len)
{
	int ret, idx;
	struct sk_buff *skb;
	struct scatterlist *sg_list, *sg;
	unsigned long *skb_addr, *sg_addr;

	if (!skw->hw_pdata || !skw->hw_pdata->hw_adma_tx_async)
		return -EINVAL;

	if (!sgl) {
		ret = -ENOMEM;
		skw_err("sgl is NULL\n");
		goto out;
	}

	sg_list = kcalloc(SKW_NR_SGL_DAT, sizeof(*sg_list), GFP_KERNEL);

	ret = skw->hw_pdata->hw_adma_tx_async(port, sgl, nents, tx_len);
	if (unlikely(ret < 0)) {
		skw_err("failed, ret: %d nents:%d\n", ret, nents);

		for_each_sg(sgl, sg, nents, idx) {
			sg_addr = (unsigned long *)sg_virt(sg);

			skb_addr = sg_addr - 1;
			skb = (struct sk_buff *)*skb_addr;

			skb->dev->stats.tx_errors++;
			//kfree_skb(skb);
			skw_skb_kfree(skw, skb);
		}

		SKW_KFREE(sgl);
	} else {
		atomic_add(nents, &skw->txqlen_pending);
		skw_sub_credit(skw, lmac_id, nents);
	}

	skw->sgl_dat = sg_list;
out:
	return ret;
}

static int skw_async_adma_tx_free(int id, struct scatterlist *sg, int nents,
			   void *data, int status)
{
	struct skw_sg_node node;
	struct skw_core *skw = data;
	struct wiphy *wiphy = priv_to_wiphy(skw);

	node.sg = sg;
	node.nents = nents;
	node.status = status;

	skw_queue_work(wiphy, NULL, SKW_WORK_TX_FREE, &node, sizeof(node));

	return 0;
}

static int skw_async_sdma_tx_free(int id,  void *buffer, int size,
			   void *data, int status)
{
	struct skw_sg_node *node;

	if (unlikely(!buffer)) {
		skw_err("buffer is invalid\n");
		return 0;
	}

	node = (struct skw_sg_node *) ((u8 *)buffer - sizeof(struct skw_sg_node));
	if (unlikely(status < 0)) {
		skw_err("failed status:%d\n", status);
		skw_add_credit((struct skw_core *)node->data, node->lmac_id, node->nents);
	}

	buffer = (void *) node;
	SKW_KFREE(buffer);

	return 0;
}

int skw_sdio_xmit(struct skw_core *skw, int lmac_id, struct sk_buff_head *txq)
{
	struct sk_buff *skb;
	int nents = 0, tx_bytes = 0;
	struct skw_lmac *lmac = &skw->hw.lmac[lmac_id];

	sg_init_table(skw->sgl_dat, SKW_NR_SGL_DAT);

	skb_queue_walk(txq, skb) {
		int aligned;
		struct skw_packet_header *extra_hdr;

		extra_hdr = (void *)skb_push(skb, SKW_EXTER_HDR_SIZE);

		aligned = round_up(skb->len, skw->hw.align);
		skw_set_extra_hdr(skw, extra_hdr, lmac->lport, aligned, 0, 0);

		sg_set_buf(&skw->sgl_dat[nents++], skb->data, aligned);

		tx_bytes += aligned;
	}

	skw_set_extra_hdr(skw, skw->eof_blk, lmac->lport, skw->hw.align, 0, 1);
	sg_set_buf(&skw->sgl_dat[nents++], skw->eof_blk, skw->hw.align);
	tx_bytes += skw->hw.align;
	skw_detail("nents:%d", nents);

	return skw->hw.dat_xmit(skw, txq, lmac_id, lmac->dport,
				skw->sgl_dat, nents, tx_bytes);
}

int skw_usb_xmit(struct skw_core *skw, int lmac_id, struct sk_buff_head *txq)
{
	struct sk_buff *skb, *tmp;
	int nents = 0, tx_bytes = 0;
	unsigned long *skb_addr;
	struct skw_lmac *lmac = &skw->hw.lmac[lmac_id];

	sg_init_table(skw->sgl_dat, SKW_NR_SGL_DAT);

	skb_queue_walk_safe(txq, skb, tmp) {
		int aligned;
		struct skw_packet_header *extra_hdr;

		extra_hdr = (void *)skb_push(skb, SKW_EXTER_HDR_SIZE);

		aligned = round_up(skb->len, skw->hw.align);
		skw_set_extra_hdr(skw, extra_hdr, lmac->lport, aligned, 0, 0);

		sg_set_buf(&skw->sgl_dat[nents++], skb->data, aligned);

		skb_addr = (unsigned long *)skb_push(skb, sizeof(unsigned long));
		*skb_addr = (unsigned long)skb;
		skb_pull(skb, sizeof(unsigned long));

		tx_bytes += aligned;

		if (skb && skw->hw.dma == SKW_ASYNC_ADMA_TX)
			__skb_unlink(skb, txq);
	}

	return skw->hw.dat_xmit(skw, txq, lmac_id, lmac->dport,
				skw->sgl_dat, nents, tx_bytes);
}

int skw_pcie_xmit(struct skw_core *skw, int lmac_id, struct sk_buff_head *txq)
{
	u64 pa;
	int ret, credit;
	struct sk_buff *skb;
	int elem_sz, nr_node;
	struct skw_addr_ref *ref;
	struct skw_edma_node *start = NULL, *end = NULL;
	struct skw_edma_channel *echn = &skw->edma.lmac[lmac_id].tx;

	if (!skb_queue_len(txq)) {
		skw_warn("txq: 0\n");
		return 0;
	}

	credit = txq->qlen;
	start = end = echn->ctx.cur;
	elem_sz = sizeof(struct skw_edma_elem);

	end->hw->list.xmit_len = 0;

	while ((skb = skb_dequeue(txq)) != NULL) {

		if (atomic_read(&end->ref)) {
			skw_warn("exception, node: %d(qlen: %d), txq: %d mac_id:%d\n",
				 end->hw->idx, skb_queue_len(&end->skb_list),
				 skb_queue_len(txq), echn->lmac->id);
			// SKW_BUG_ON(1);
			// skw_hw_assert(skw, false);

			// fixme:
			// wait until node is valid

			return 0;
		}

		if (skb_headroom(skb) < sizeof(*ref)) {
			skw_warn("headroom: %d, sizeof ref: %d\n",
				 skb_headroom(skb), sizeof(*ref));
			skw_skb_kfree(skw, skb);

			continue;
		}

		ref = (void *)skb_push(skb, sizeof(*ref));
		ref->magic = SKW_XMIT_REF_MAGIC;
		ref->addr = skb;

		pa = dma_map_single(echn->dev, skb->data, skb->len, DMA_TO_DEVICE);
		if (dma_mapping_error(priv_to_wiphy(skw)->dev.parent, pa)) {
			skw_warn("dma mapping error\n");
			skw_skb_kfree(skw, skb);

			continue;
		}
		dma_sync_single_for_device(echn->dev, pa, skb->len, DMA_TO_DEVICE);

		SKW_SKB_TXCB(skb)->pa = pa;
		SKW_SKB_TXCB(skb)->e.eth_hdr_pa = pa + skb_mac_offset(skb);
		SKW_SKB_TXCB(skb)->e.eth_hdr_pa |= SKW_EDMA_ADDR_FLAG;

		if (end->hw->list.xmit_len + elem_sz > end->hw->buff_len) {
			atomic_set(&end->ref, 1);
			end = end->next;
			end->hw->list.xmit_len = 0;
		}

		pa |= SKW_EDMA_ADDR_FLAG;

		memcpy(end->hw->buff + end->hw->list.xmit_len, &SKW_SKB_TXCB(skb)->e, elem_sz);

		end->hw->list.xmit_len += elem_sz;

		SKW_SKB_TXCB(skb)->edma_node_idx = end->hw->idx;
		skb_queue_tail(&end->skb_list, skb);
		atomic_inc(&skw->edma.lmac[lmac_id].skb_qlen);

		skw_detail("cpu: %d, node: %d, eth addr: %llx, data_addr: %llx, qlen: %d\n",
			current->on_cpu, end->hw->idx, SKW_SKB_TXCB(skb)->e.eth_hdr_pa,
			skb->data, end->skb_list.qlen);
	}

	atomic_set(&end->ref, 1);
	nr_node = end->hw->idx - start->hw->idx + 1;
	if (nr_node < 0)
		nr_node += echn->ctx.nr_node;

	ret = skw_edma_req(echn, nr_node);
	if (ret < 0) {
		skw_err("failed, ret: %d\n", ret);
		// TODO:
#if 0
		for (end = start, i = 0; i < nr_node; i++) {
			// unmap
			dev_kfree_skb_any(skb);
		}
#endif

		return ret;
	}

	credit = nr_node << 6;
	skw_sub_credit(skw, lmac_id, credit);
	echn->ctx.cur = end->next;

	return 0;
}

static inline int skw_bus_data_xmit(struct skw_core *skw, int mac_id,
			struct sk_buff_head *txq_list)
{
	int ret;

	if (!skb_queue_len(txq_list))
		return 0;

	skw->tx_packets += skb_queue_len(txq_list);

	skw->dbg.dat_idx = (skw->dbg.dat_idx + 1) % skw->dbg.nr_dat;
	skw->dbg.dat[skw->dbg.dat_idx].qlen = skb_queue_len(txq_list);
	skw->dbg.dat[skw->dbg.dat_idx].trigger = skw_local_clock();

	ret = skw->hw.bus_dat_xmit(skw, mac_id, txq_list);

	skw->dbg.dat[skw->dbg.dat_idx].done = skw_local_clock();

	return ret;
}

static inline int skw_bus_cmd_xmit(struct skw_core *skw, void *cmd, int cmd_len)
{
	int ret;
	unsigned long flags = READ_ONCE(skw->flags);

	if (test_bit(SKW_CMD_FLAG_IGNORE_BLOCK_TX, &skw->cmd.flags))
		flags &= ~BIT(SKW_FLAG_BLOCK_TX);

	if (!skw_tx_allowed(flags)) {
		skw_warn("cmd: %s[%d] not allowed, flags: 0x%lx, cmd flags: 0x%lx\n",
			 skw->cmd.name, skw->cmd.id, skw->flags, skw->cmd.flags);

		skw_abort_cmd(skw);

		return 0;
	}

	skw->dbg.cmd[skw->dbg.cmd_idx].xmit = skw_local_clock();
	skw->dbg.cmd[skw->dbg.cmd_idx].loop = atomic_read(&skw->dbg.loop);

	ret = skw->hw.bus_cmd_xmit(skw, cmd, cmd_len);

	skw->dbg.cmd[skw->dbg.cmd_idx].done = skw_local_clock();

	return ret;
}

static inline bool is_skw_same_tcp_stream(struct sk_buff *skb,
					struct sk_buff *next)
{
	return ip_hdr(skb)->saddr == ip_hdr(next)->saddr &&
	       ip_hdr(skb)->daddr == ip_hdr(next)->daddr &&
	       tcp_hdr(skb)->source == tcp_hdr(next)->source &&
	       tcp_hdr(skb)->dest == tcp_hdr(next)->dest;
}

static void skw_merge_pure_ack(struct skw_core *skw, struct sk_buff_head *ackq,
				struct sk_buff_head *txq)
{
	int i, drop = 0;
	struct sk_buff *skb, *tmp;

	while ((skb = __skb_dequeue_tail(ackq))) {
		for (i = 0; i < ackq->qlen; i++) {
			tmp = __skb_dequeue(ackq);
			if (!tmp)
				break;

			if (is_skw_same_tcp_stream(skb, tmp)) {
				if (tcp_optlen(tmp) == 0 &&
				    tcp_flag_word(tcp_hdr(tmp)) == TCP_FLAG_ACK) {
					skw_skb_kfree(skw, tmp);
					drop++;
				} else {
					__skb_queue_tail(txq, tmp);
				}
			} else {
				__skb_queue_tail(ackq, tmp);
			}
		}

		__skb_queue_tail(txq, skb);
	}
}

static bool is_skw_peer_data_valid(struct skw_core *skw, struct sk_buff *skb)
{
	struct skw_ctx_entry *entry;
	bool valid = true;
	int peer_idx = SKW_SKB_TXCB(skb)->peer_idx;
	int i;

	rcu_read_lock();
	for (i = 0; i < skw->hw.nr_lmac; i++) {
		entry = rcu_dereference(skw->hw.lmac[i].peer_ctx[peer_idx].entry);
		if (entry) {
			if (entry->peer) {
				entry->peer->tx.bytes += skb->len;
				entry->peer->tx.pkts++;

				if (test_bit(SKW_PEER_FLAG_DEAUTHED, &entry->peer->flags))
					valid = false;
			} else {
				if (is_unicast_ether_addr(eth_hdr(skb)->h_dest))
					valid = false;
			}
		}
	}
	rcu_read_unlock();

	return valid;
}

static inline void skw_reset_ac(struct skw_tx_lmac *txlp)
{
	int i;

	for (i = 0; i < SKW_MAX_LMAC_SUPPORT; i++) {
		txlp->ac_reset = 0xF;
		txlp++;
	}
}


bool skw_check_txq(struct skw_core *skw)
{
	bool ret;
	int ac, i;
	unsigned long flags;
	struct skw_iface *iface;

	ret = false;
	for (ac = 0; ac < SKW_WMM_AC_MAX; ac++) {
		for (i = 0; i < SKW_NR_IFACE; i++) {
			iface = skw->vif.iface[i];
			if (!iface || !iface->ndev)
				continue;

			if (skb_queue_len(&iface->tx_cache[ac]) != 0) {
				ret = true;
				goto _exit;
			}

			spin_lock_irqsave(&iface->txq[ac].lock, flags);
			if (skb_queue_len(&iface->txq[ac]) != 0) {
				ret = true;
				spin_unlock_irqrestore(&iface->txq[ac].lock, flags);
				goto _exit;

			}
			spin_unlock_irqrestore(&iface->txq[ac].lock, flags);
		}
	}

_exit:
	return ret;
}

bool skw_tx_exit_check(struct skw_core *skw, struct skw_tx_lmac *txlp)
{
	bool ret;
	int mac, credit = 0, pending_qlen = 0;

	ret = true;

	if (skw->hw.bus == SKW_BUS_USB || skw->hw.bus == SKW_BUS_USB2) {
		for (mac = 0; mac < skw->hw.nr_lmac; mac++) {
			if (skw_lmac_is_actived(skw, mac)) {
				credit = skw_get_hw_credit(skw, mac);
				if (credit > 0 && txlp[mac].pending_qlen > 0)
					ret = false;
			}
			trace_skw_tx_exit_check(mac, credit, txlp[mac].pending_qlen);
		}
	}

	if (skw->hw.bus == SKW_BUS_SDIO || skw->hw.bus == SKW_BUS_SDIO2) {
		for (mac = 0; mac < skw->hw.nr_lmac; mac++) {
			pending_qlen += txlp[mac].pending_qlen;
		}

		if (pending_qlen == 0) {
			if (skw_check_txq(skw))
			ret = false;
		} else
			ret = false;

		if (msecs_to_jiffies(100) > (jiffies - skw->trans_start))
			ret = true;
	}

	if (test_bit(SKW_CMD_FLAG_XMIT, &skw->cmd.flags))
		ret = false;

	return ret;
}

int skw_tx_running_check(struct skw_core *skw, int times)
{
	int all_credit, mac, ret;

	ret = SKW_TX_RUNNING_EXIT;
	if (!skw_tx_allowed(READ_ONCE(skw->flags))) {

		return ret;
	}

	all_credit = 0;
	for (mac = 0; mac < skw->hw.nr_lmac; mac++)
		if (skw_lmac_is_actived(skw, mac))
			all_credit += skw_get_hw_credit(skw, mac);

	if (all_credit == 0) {
		if (skw->hw.bus == SKW_BUS_SDIO || skw->hw.bus == SKW_BUS_SDIO2) {
			if (times < tx_wait_time)
				ret = SKW_TX_RUNNING_RESTART;
		}
	} else
		ret = SKW_TX_RUNNING_GO;

	return ret;
}

void skw_cmd_do(struct skw_core *skw)
{
	if (test_and_clear_bit(SKW_CMD_FLAG_XMIT, &skw->cmd.flags)) {
		skw_bus_cmd_xmit(skw, skw->cmd.data, skw->cmd.data_len);

		if (test_bit(SKW_CMD_FLAG_NO_ACK, &skw->cmd.flags)) {
			set_bit(SKW_CMD_FLAG_DONE, &skw->cmd.flags);
			skw->cmd.callback(skw);
		}
	}

	return ;
}

int skw_txq_prepare(struct skw_core *skw, struct sk_buff_head *pure_ack_list, struct skw_tx_lmac *txl, int ac)
{
	int i, qlen, ac_qlen = 0;
	unsigned long flags;
	struct sk_buff *skb;
	struct skw_iface *iface;
	struct sk_buff_head *qlist;
	struct netdev_queue *txq;
	struct skw_tx_lmac *txlp;

	for (i = 0; i < SKW_NR_IFACE; i++) {
		iface = skw->vif.iface[i];
		// if (!iface || skw_lmac_is_actived(skw, iface->lmac_id))
		if (!iface || !iface->ndev)
			continue;

		if (ac == SKW_WMM_AC_BE && iface->txq[SKW_ACK_TXQ].qlen) {
			qlist = &iface->txq[SKW_ACK_TXQ];

			__skb_queue_head_init(pure_ack_list);

			spin_lock_irqsave(&qlist->lock, flags);
			skb_queue_splice_tail_init(&iface->txq[SKW_ACK_TXQ],
						pure_ack_list);
			spin_unlock_irqrestore(&qlist->lock, flags);

			skw_merge_pure_ack(skw, pure_ack_list,
					&iface->tx_cache[ac]);
		}

		qlist = &iface->txq[ac];
		if (!skb_queue_empty(qlist)) {
			spin_lock_irqsave(&qlist->lock, flags);
			skb_queue_splice_tail_init(qlist,
					&iface->tx_cache[ac]);
			spin_unlock_irqrestore(&qlist->lock, flags);
		}

		if (test_bit(SKW_IFACE_FLAG_DEAUTH, &iface->flags)) {
			while ((skb = __skb_dequeue(&iface->tx_cache[ac])) != NULL)
				skw_skb_kfree(skw, skb);
		}

		qlen = skb_queue_len(&iface->tx_cache[ac]);
		if (qlen < SKW_TXQ_LOW_THRESHOLD) {
			txq = netdev_get_tx_queue(iface->ndev, ac);
			if (netif_tx_queue_stopped(txq)) {
				netif_tx_start_queue(txq);
				netif_schedule_queue(txq);
			}
		}

		if (qlen) {
			txlp = &txl[iface->lmac_id];
			txlp->current_qlen += qlen;

			trace_skw_txq_prepare(iface->ndev->name, qlen);

			txlp->txq_map |= BIT(txlp->nr_txq);

			txlp->tx[txlp->nr_txq].list = &iface->tx_cache[ac];
			txlp->tx[txlp->nr_txq].reset = true;
			txlp->reset = true;
			if (txlp->ac_reset & BIT(ac)) {
				txlp->tx[txlp->nr_txq].quota = iface->wmm.factor[ac];
				txlp->ac_reset ^= BIT(ac);
			}

			txlp->nr_txq++;
			ac_qlen += qlen;
		}
	}

	return ac_qlen;
}

void skw_start_dev_queue(struct skw_core *skw)
{
	int i, ac;
	struct skw_iface *iface;
	struct netdev_queue *txq;

	for (i = 0; i < SKW_NR_IFACE; i++) {
		iface = skw->vif.iface[i];
		if (!iface || !iface->ndev)
			continue;
		if (iface->ndev->flags & IFF_UP)
			for (ac = 0; ac < SKW_WMM_AC_MAX; ac++) {
				if (skb_queue_len(&iface->tx_cache[ac]) < SKW_TXQ_LOW_THRESHOLD) {
					txq = netdev_get_tx_queue(iface->ndev, ac);
					if (netif_tx_queue_stopped(txq)) {
						netif_tx_start_queue(txq);
						netif_schedule_queue(txq);
						skw_set_trans_start(iface->ndev);
					}
				}
			}
	}
}

#ifdef CONFIG_SKW6316_TX_WORKQUEUE
void skw_tx_worker(struct work_struct *work)
{
	int i, ac, mac;
	int base = 0;
	//unsigned long flags;
	int lmac_tx_capa;
	//int qlen, pending_qlen = 0;
	int pending_qlen = 0;
	int max_tx_count_limit = 0;
	struct sk_buff *skb;
	//struct skw_iface *iface;
	//struct sk_buff_head *qlist;
	struct skw_tx_lmac txl[SKW_MAX_LMAC_SUPPORT];
	struct skw_tx_lmac *txlp;
	struct sk_buff_head pure_ack_list;
	//int xmit_tx_flag;
	struct skw_core *skw = container_of(to_delayed_work(work), struct skw_core, tx_worker);
	int times = 0, ret;

start:

	memset(txl, 0, sizeof(txl));
	skw_reset_ac(txl);

	max_tx_count_limit = skw->hw.pkt_limit;

	/* reserve one for eof block */
	if (skw->hw.bus == SKW_BUS_SDIO)
		max_tx_count_limit--;

	for (i = 0; i < skw->hw.nr_lmac; i++) {
		__skb_queue_head_init(&txl[i].tx_list);
		txl[i].tx_count_limit = max_tx_count_limit;
	}

	while (!atomic_read(&skw->exit)) {

		// TODO:
		/* CPU bind */
		/* check if frame in pending queue is timeout */

		atomic_inc(&skw->dbg.loop);
		skw_cmd_do(skw);

		pending_qlen = 0;
		ret = skw_tx_running_check(skw, times++);
		if (ret == SKW_TX_RUNNING_RESTART)
			goto start;
		else if (ret == SKW_TX_RUNNING_EXIT)
			return ;

		for (ac = 0; ac < SKW_WMM_AC_MAX; ac++) {
			int ac_qlen = 0;

			ac_qlen = skw_txq_prepare(skw, &pure_ack_list, txl, ac);

			if (!ac_qlen)
				continue;

			pending_qlen += ac_qlen;

			lmac_tx_capa = 0;

			for (mac = 0; mac < skw->hw.nr_lmac; mac++) {
				int credit;

				txlp = &txl[mac];
				if (!txlp->txq_map)
					goto reset;

				credit = txlp->cred = skw_get_hw_credit(skw, mac);
				trace_skw_get_credit(credit, mac);
				if (!txlp->cred)
					goto reset;

				if (skw_edma_pending_skb(skw, mac) > SKW_EDMA_TX_HIGH_THRESHOLD)
					goto reset;

				if (txlp->reset) {
					switch (ac) {
					case SKW_WMM_AC_VO:
						base = SKW_BASE_VO;
						break;

					case SKW_WMM_AC_VI:
						base = SKW_BASE_VI;
						break;

					case SKW_WMM_AC_BK:
						if (txlp->bk_tx_limit) {
							base = min(txlp->cred, txlp->bk_tx_limit);
							txlp->bk_tx_limit = 0;
						} else {
							base = txlp->cred;
						}

						base = base / txlp->nr_txq;
						break;

					default:
						base = min(txlp->cred, txlp->current_qlen);
						//base = base / txlp->nr_txq;
						txlp->bk_tx_limit = (txlp->cred + 1) >> 1;
						break;
					}

					base = base ? base : 1;
					txlp->reset = false;
				} else
					base = 0;

				trace_skw_txlp_mac(mac, txlp->cred, txlp->current_qlen, base);

				for (i = 0; txlp->txq_map != 0; i++) {

					i = i % txlp->nr_txq;
					if (!(txlp->txq_map & BIT(i)))
						continue;

					if (!txlp->cred)
						break;

					if (txlp->tx[i].reset) {
						txlp->tx[i].quota += base;

						if (txlp->tx[i].quota < 0)
							txlp->tx[i].quota = 0;

						txlp->tx[i].reset = false;
					}

					skb = skb_peek(txlp->tx[i].list);
					if (!skb) {
						txlp->txq_map ^= BIT(i);
						continue;
					}

					if (!is_skw_peer_data_valid(skw, skb)) {
						skw_detail("drop dest: %pM\n",
							   eth_hdr(skb)->h_dest);

						__skb_unlink(skb, txlp->tx[i].list);
						skw_skb_kfree(skw, skb);

						continue;
					}

					if (!txlp->tx_count_limit--)
						break;

					if (txlp->tx[i].quota) {
						txlp->tx[i].quota--;
					} else {
						txlp->txq_map ^= BIT(i);
						continue;
					}

					if (skw->hw.bus != SKW_BUS_PCIE &&
						(long)skb->data & SKW_DATA_ALIGN_MASK)
						skw_warn("address unaligned\n");

#if 0
					if (skb->len % skw->hw_pdata->align_value)
						skw_warn("len: %d unaligned\n", skb->len);
#endif

					__skb_unlink(skb, txlp->tx[i].list);
					__skb_queue_tail(&txlp->tx_list, skb);

					// trace_skw_txlp_tx_list(skb->dev->name, ((struct skw_iface *)(netdev_priv(skb->dev)))->id);

					txlp->cred--;
				}

				pending_qlen = pending_qlen - credit + txlp->cred;
				txlp->pending_qlen = pending_qlen;

				trace_skw_tx_info(mac, ac, credit, credit - txlp->cred, txlp->current_qlen, pending_qlen);

				if (skw->hw.bus == SKW_BUS_PCIE) {
					int txq_len = skb_queue_len(&txlp->tx_list);
					int val = round_up(txq_len, 64) - txq_len;

					txlp->cred = txlp->cred >= val ? txlp->cred - val : 0;
				}

				if (skw_bus_data_xmit(skw, mac, &txlp->tx_list) >= 0)
					skw->trans_start = jiffies;

				txlp->tx_count_limit = max_tx_count_limit;

				if (txlp->cred)
					lmac_tx_capa |= BIT(mac);

reset:
				txlp->nr_txq = 0;
				txlp->txq_map = 0;
				txlp->current_qlen = 0;
			}

			if (!lmac_tx_capa)
				break;
		}

		if (ac == SKW_WMM_AC_MAX)
			skw_reset_ac(txl);

		if (skw_tx_exit_check(skw, txl)) {
			skw_start_dev_queue(skw);
			return;
		}
	}
}

static void skw_kfree_skb_worker(struct work_struct *work)
{
	unsigned long flags;
	struct sk_buff *skb, *tmp;
	struct sk_buff_head qlist;
	struct skw_core *skw = container_of(work, struct skw_core, kfree_skb_task);

	__skb_queue_head_init(&qlist);

	while (!skb_queue_empty(&skw->kfree_skb_qlist)) {
		spin_lock_irqsave(&skw->kfree_skb_qlist.lock, flags);
		skb_queue_splice_tail_init(&skw->kfree_skb_qlist, &qlist);
		spin_unlock_irqrestore(&skw->kfree_skb_qlist.lock, flags);

		skb_queue_walk_safe(&qlist, skb, tmp) {
			if (likely(0 == SKW_SKB_TXCB(skb)->ret)) {
				skb->dev->stats.tx_packets++;
				skb->dev->stats.tx_bytes += SKW_SKB_TXCB(skb)->skb_native_len;
			} else
				skb->dev->stats.tx_errors++;

			__skb_unlink(skb, &qlist);
			skw_skb_kfree(skw, skb);
		}
	}

	return ;
}

static int __skw_tx_init(struct skw_core *skw)
{
	//struct workqueue_attrs wq_attrs;
#ifdef CONFIG_SKW6316_SKB_RECYCLE
	int i;
	struct sk_buff *skb;
#endif

	skw->tx_wq = alloc_workqueue("skwifid_txwq.%d",
			WQ_UNBOUND | WQ_CPU_INTENSIVE | WQ_HIGHPRI | WQ_SYSFS,
			0, skw->idx);
	if (!skw->tx_wq) {
		skw_err("alloc skwtx_workqueue failed\n");
		return -EFAULT;
	}

	//memset(&wq_attrs, 0, sizeof(wq_attrs));

	//wq_attrs.nice = MIN_NICE;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 16, 0) && LINUX_VERSION_CODE <= KERNEL_VERSION(5, 2, 0)
	//apply_workqueue_attrs(skw->tx_wq, &wq_attrs);
#endif

	INIT_DELAYED_WORK(&skw->tx_worker, skw_tx_worker);
	queue_delayed_work(skw->tx_wq, &skw->tx_worker, msecs_to_jiffies(0));
	//queue_work_on(cpumask_last(cpu_online_mask), skw->tx_wq, &skw->tx_worker);
	skw->trans_start = 0;

	skb_queue_head_init(&skw->kfree_skb_qlist);
	INIT_WORK(&skw->kfree_skb_task, skw_kfree_skb_worker);

	skb_queue_head_init(&skw->skb_recycle_qlist);
#ifdef CONFIG_SKW6316_SKB_RECYCLE
	for (i = 0; i < SKW_SKB_RECYCLE_COUNT; i++) {
		skb = dev_alloc_skb(SKW_2K_SIZE);
		if (skb)
			skb_queue_tail(&skw->skb_recycle_qlist, skb);
		else {
			__skb_queue_purge(&skw->skb_recycle_qlist);
			destroy_workqueue(skw->tx_wq);
			skw_err("alloc skb recycle failed\n");
			return -ENOMEM;
		}
	}
#endif

	return 0;
}

static void __skw_tx_deinit(struct skw_core *skw)
{
	atomic_set(&skw->exit, 1);
	cancel_delayed_work_sync(&skw->tx_worker);
	cancel_work_sync(&skw->kfree_skb_task);
	skb_queue_purge(&skw->kfree_skb_qlist);
	destroy_workqueue(skw->tx_wq);
	skb_queue_purge(&skw->skb_recycle_qlist);
}

#else

static int skw_tx_thread(void *data)
{
	struct skw_core *skw = data;
	int i, ac, mac;
	int base = 0;
	unsigned long flags;
	int lmac_tx_capa;
	int qlen, pending_qlen = 0;
	int max_tx_count_limit = 0;
	int lmac_tx_map = 0;
	struct sk_buff *skb;
	struct skw_iface *iface;
	struct sk_buff_head *qlist;
	struct skw_tx_lmac txl[SKW_MAX_LMAC_SUPPORT];
	struct skw_tx_lmac *txlp;
	struct sk_buff_head pure_ack_list;
	int xmit_tx_flag;
	int all_credit;

	memset(txl, 0, sizeof(txl));
	skw_reset_ac(txl);

	max_tx_count_limit = skw->hw.pkt_limit;

	/* reserve one for eof block */
	if (skw->hw.bus == SKW_BUS_SDIO)
		max_tx_count_limit--;

	for (i = 0; i < skw->hw.nr_lmac; i++) {
		__skb_queue_head_init(&txl[i].tx_list);
		txl[i].tx_count_limit = max_tx_count_limit;
	}

	while (!kthread_should_stop()) {
		// TODO:
		/* CPU bind */
		/* check if frame in pending queue is timeout */

		atomic_inc(&skw->dbg.loop);

		if (test_and_clear_bit(SKW_CMD_FLAG_XMIT, &skw->cmd.flags)) {
			skw_bus_cmd_xmit(skw, skw->cmd.data, skw->cmd.data_len);

			if (test_bit(SKW_CMD_FLAG_NO_ACK, &skw->cmd.flags)) {
				set_bit(SKW_CMD_FLAG_DONE, &skw->cmd.flags);
				skw->cmd.callback(skw);
			}
		}

		if (!skw_tx_allowed(skw->flags)) {
			set_current_state(TASK_INTERRUPTIBLE);
			schedule_timeout(msecs_to_jiffies(200));
			continue;
		}

		pending_qlen = 0;
		lmac_tx_map = 0;

		for (ac = 0; ac < SKW_WMM_AC_MAX; ac++) {
			int ac_qlen = 0;

			for (i = 0; i < SKW_NR_IFACE; i++) {
				iface = skw->vif.iface[i];
				// if (!iface || skw_lmac_is_actived(skw, iface->lmac_id))
				if (!iface || !iface->ndev)
					continue;

				if (ac == SKW_WMM_AC_BE && iface->txq[SKW_ACK_TXQ].qlen) {
					qlist = &iface->txq[SKW_ACK_TXQ];
					__skb_queue_head_init(&pure_ack_list);

					spin_lock_irqsave(&qlist->lock, flags);
					skb_queue_splice_tail_init(&iface->txq[SKW_ACK_TXQ],
								&pure_ack_list);
					spin_unlock_irqrestore(&qlist->lock, flags);

					skw_merge_pure_ack(skw, &pure_ack_list, &iface->tx_cache[ac]);
				}

				qlist = &iface->txq[ac];
				if (!skb_queue_empty(qlist)) {
					spin_lock_irqsave(&qlist->lock, flags);
					skb_queue_splice_tail_init(qlist, &iface->tx_cache[ac]);
					spin_unlock_irqrestore(&qlist->lock, flags);
				}

				qlen = skb_queue_len(&iface->tx_cache[ac]);
				if (qlen) {
					txlp = &txl[iface->lmac_id];
					txlp->current_qlen += qlen;
					txlp->txq_map |= BIT(txlp->nr_txq);
					txlp->tx[txlp->nr_txq].list = &iface->tx_cache[ac];

					if (txlp->ac_reset & BIT(ac)) {
						txlp->tx[txlp->nr_txq].quota = iface->wmm.factor[ac];
						txlp->tx[txlp->nr_txq].reset = true;
						txlp->reset = true;
						txlp->ac_reset ^= BIT(ac);
					}

					txlp->nr_txq++;
					ac_qlen += qlen;
				}
			}

			if (!ac_qlen)
				continue;

			pending_qlen += ac_qlen;
			lmac_tx_capa = 0;

			all_credit = 0;
			for (mac = 0; mac < skw->hw.nr_lmac; mac++)
				all_credit += skw_get_hw_credit(skw, mac);

			if (all_credit == 0) {
				skw_stop_dev_queue(skw);
				wait_event_interruptible_exclusive(skw->tx_wait_q,
					atomic_xchg(&skw->tx_wake, 0) || atomic_xchg(&skw->exit, 0));
				skw_start_dev_queue(skw);
			}

			for (mac = 0; mac < skw->hw.nr_lmac; mac++) {
				int credit;

				txlp = &txl[mac];
				if (!txlp->txq_map)
					goto reset;

				credit = txlp->cred = skw_get_hw_credit(skw, mac);
				if (!txlp->cred)
					goto reset;

				if (txlp->reset) {
					switch (ac) {
					case SKW_WMM_AC_VO:
						base = SKW_BASE_VO;
						break;

					case SKW_WMM_AC_VI:
						base = SKW_BASE_VI;
						break;

					case SKW_WMM_AC_BK:
						if (txlp->bk_tx_limit) {
							base = min(txlp->cred, txlp->bk_tx_limit);
							txlp->bk_tx_limit = 0;
						} else {
							base = txlp->cred;
						}

						base = base / txlp->nr_txq;

						break;
					default:
						base = min(txlp->cred, txlp->current_qlen);
						base = base / txlp->nr_txq;
						txlp->bk_tx_limit = (txlp->cred + 1) >> 1;

						break;
					}

					base = base ? base : 1;
					txlp->reset = false;
				}

				for (i = 0; txlp->txq_map != 0; i++) {
					i = i % txlp->nr_txq;

					if (!(txlp->txq_map & BIT(i)))
						continue;

					if (!txlp->cred)
						break;

					if (txlp->tx[i].reset) {
						txlp->tx[i].quota += base;

						if (txlp->tx[i].quota < 0)
							txlp->tx[i].quota = 0;

						txlp->tx[i].reset = false;
					}

					skb = skb_peek(txlp->tx[i].list);
					if (!skb) {
						txlp->txq_map ^= BIT(i);
						continue;
					}

					if (!is_skw_peer_data_valid(skw, skb)) {
						skw_detail("drop dest: %pM\n",
							   eth_hdr(skb)->h_dest);

						__skb_unlink(skb, txlp->tx[i].list);
						kfree_skb(skb);

						continue;
					}

					if (!txlp->tx_count_limit--)
						break;

					if (txlp->tx[i].quota) {
						txlp->tx[i].quota--;
					} else {
						txlp->txq_map ^= BIT(i);
						continue;
					}

					if ((long)skb->data & SKW_DATA_ALIGN_MASK)
						skw_warn("address unaligned\n");
#if 0
					if (skb->len % skw->hw_pdata->align_value)
						skw_warn("len: %d unaligned\n", skb->len);
#endif
					__skb_unlink(skb, txlp->tx[i].list);
					__skb_queue_tail(&txlp->tx_list, skb);
					txlp->cred--;
				}

				pending_qlen = pending_qlen - credit + txlp->cred;

				trace_skw_tx_info(mac, ac, credit, credit - txlp->cred, txlp->current_qlen);

				// skw_lmac_tx(skw, mac, &txlp->tx_list);
				skw_bus_data_xmit(skw, mac, &txlp->tx_list);
				txlp->tx_count_limit = max_tx_count_limit;

				lmac_tx_map |= BIT(mac);

				if (txlp->cred)
					lmac_tx_capa |= BIT(mac);
reset:
				txlp->nr_txq = 0;
				txlp->txq_map = 0;
				txlp->current_qlen = 0;
			}

			if (!lmac_tx_capa)
				break;
		}

		if (ac == SKW_WMM_AC_MAX)
			skw_reset_ac(txl);

		if (pending_qlen == 0) {
			xmit_tx_flag = 0;

			for (ac = 0; ac < SKW_WMM_AC_MAX; ac++) {
				for (i = 0; i < SKW_NR_IFACE; i++) {
					iface = skw->vif.iface[i];
					if (!iface || !iface->ndev)
						continue;

					if (skb_queue_len(&iface->tx_cache[ac]) != 0) {
						xmit_tx_flag = 1;
						goto need_running;
					}

					spin_lock_irqsave(&iface->txq[ac].lock, flags);
					if (skb_queue_len(&iface->txq[ac]) != 0) {
						xmit_tx_flag = 1;
						spin_unlock_irqrestore(&iface->txq[ac].lock, flags);
						goto need_running;

					}
					spin_unlock_irqrestore(&iface->txq[ac].lock, flags);
				}
			}
need_running:

			if (xmit_tx_flag == 0) {
				//skw_start_dev_queue(skw);
				wait_event_interruptible_exclusive(skw->tx_wait_q,
					atomic_xchg(&skw->tx_wake, 0) || atomic_xchg(&skw->exit, 0));
			}
		}
	}

	skw_info("exit");

	return 0;
}

static int __skw_tx_init(struct skw_core *skw)
{
	skw->tx_thread = kthread_create(skw_tx_thread, skw, "skwifid_tx.%d", skw->idx);
	if (IS_ERR(skw->tx_thread)) {
		skw_err("create tx thread failed\n");
		return  PTR_ERR(skw->tx_thread);
	}

	//kthread_bind(skw->tx_thread, cpumask_last(cpu_online_mask));

	skw_set_thread_priority(skw->tx_thread, SCHED_RR, 1);
	set_user_nice(skw->tx_thread, MIN_NICE);
	wake_up_process(skw->tx_thread);

	return 0;
}

static void __skw_tx_deinit(struct skw_core *skw)
{
	if (skw->tx_thread) {
		atomic_set(&skw->exit, 1);
		kthread_stop(skw->tx_thread);
		skw->tx_thread = NULL;
	}
}

#endif

static int skw_register_tx_callback(struct skw_core *skw, void *func, void *data)
{
	int i, map, ret = 0;

	for (map = 0, i = 0; i < SKW_MAX_LMAC_SUPPORT; i++) {
		if (!test_bit(SKW_LMAC_FLAG_TXCB, &skw->hw.lmac[i].flags))
			continue;

		ret = skw_register_tx_cb(skw, skw->hw.lmac[i].dport, func, data);
		if (ret < 0) {
			skw_err("chip: %d, hw mac: %d, port: %d failed, ret: %d\n",
				skw->idx, i, skw->hw.lmac[i].dport, ret);

			break;
		}

		map |= BIT(skw->hw.lmac[i].dport);
	}

	skw_dbg("chip: %d, %s data port: 0x%x\n",
		skw->idx, func ? "register" : "unregister", map);

	return ret;
}

int skw_hw_xmit_init(struct skw_core *skw, int dma)
{
	int ret = 0;

	skw_dbg("dma: %d\n", dma);

	switch (dma) {
	case SKW_SYNC_ADMA_TX:
		skw->hw.dat_xmit = skw_sync_adma_tx;
		skw->hw.cmd_xmit = skw_sync_adma_tx;
		skw->hw.cmd_disable_irq_xmit = skw_sync_adma_cmd_disable_irq_tx;
		break;

	case SKW_SYNC_SDMA_TX:
		skw->hw.dat_xmit = skw_sync_sdma_tx;
		skw->hw.cmd_xmit = skw_sync_sdma_tx;
		skw->hw.cmd_disable_irq_xmit = skw_sync_sdma_cmd_disable_irq_tx;

		if (skw->sdma_buff)
			break;
		skw->sdma_buff = SKW_ZALLOC(skw->hw_pdata->max_buffer_size, GFP_KERNEL);
		if (!skw->sdma_buff)
			ret = -ENOMEM;

		break;

	case SKW_ASYNC_ADMA_TX:
		skw->hw.dat_xmit = skw_async_adma_tx;
		skw->hw.cmd_xmit = skw_sync_adma_tx;
		skw->hw.cmd_disable_irq_xmit = NULL;

		ret = skw_register_tx_callback(skw, skw_async_adma_tx_free, skw);
		break;

	case SKW_ASYNC_SDMA_TX:
		skw->hw.dat_xmit = skw_async_sdma_tx;
		skw->hw.cmd_xmit = skw_sync_sdma_tx;
		skw->hw.cmd_disable_irq_xmit = NULL;

		ret = skw_register_tx_callback(skw, skw_async_sdma_tx_free, skw);

		if (skw->sdma_buff)
			break;
		skw->sdma_buff = SKW_ZALLOC(skw->hw_pdata->max_buffer_size, GFP_KERNEL);
		if (!skw->sdma_buff)
			ret = -ENOMEM;
		break;

	case SKW_ASYNC_EDMA_TX:
		skw->hw.dat_xmit = NULL;
		skw->hw.cmd_xmit = skw_sync_adma_tx;
		skw->hw.cmd_disable_irq_xmit = NULL;
		break;

	default:
		ret = -EINVAL;
		skw->hw.dat_xmit = NULL;
		skw->hw.cmd_xmit = NULL;
		break;
	}

	return ret;
}

int skw_tx_init(struct skw_core *skw)
{
	int ret;

	skw->skb_share_len = SKB_DATA_ALIGN(sizeof(struct skb_shared_info));
	skw->skb_headroom = sizeof(struct skw_tx_desc_hdr) +
			    sizeof(struct skw_tx_desc_conf) +
			    skw->hw.extra.hdr_len +
			    sizeof(struct skw_addr_ref) +
			    SKW_DATA_ALIGN_SIZE;

	if (skw->hw.bus == SKW_BUS_SDIO) {
		skw->eof_blk = SKW_ZALLOC(skw->hw.align, GFP_KERNEL);
		if (!skw->eof_blk)
			return -ENOMEM;
	} else if (skw->hw.bus == SKW_BUS_PCIE) {
		skw->skb_headroom = sizeof(struct skw_tx_desc_conf) +
				    SKW_DATA_ALIGN_SIZE + 2 * sizeof(unsigned long);
	}

	ret = skw_hw_xmit_init(skw, skw->hw.dma);
	if (ret < 0) {
		SKW_KFREE(skw->eof_blk);
		return ret;
	}

	ret = __skw_tx_init(skw);
	if (ret < 0) {
		SKW_KFREE(skw->eof_blk);
		SKW_KFREE(skw->sdma_buff);
	}

	tx_wait_time = 0;
	skw_procfs_file(skw->pentry, "tx_wait_time", 0666, &skw_tx_time_fops, NULL);

	return ret;
}

int skw_tx_deinit(struct skw_core *skw)
{
	__skw_tx_deinit(skw);

	skw_register_tx_callback(skw, NULL, NULL);

	SKW_KFREE(skw->eof_blk);
	SKW_KFREE(skw->sdma_buff);

	return 0;
}
