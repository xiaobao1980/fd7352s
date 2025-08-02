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
#include <linux/module.h>
#include <linux/device.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/skbuff.h>
#include <linux/inetdevice.h>
#include <net/addrconf.h>
#include <linux/ctype.h>
#include <net/tcp.h>
#include <net/arp.h>
#include <linux/platform_device.h>
#include <linux/if_tunnel.h>
#include <linux/firmware.h>
#include <generated/utsrelease.h>
#include <linux/dma-mapping.h>
#include <linux/dma-direct.h>

#include "skw_core.h"
#include "skw_cfg80211.h"
#include "skw_tx.h"
#include "skw_rx.h"
#include "skw_iw.h"
#include "skw_timer.h"
#include "skw_work.h"
#include "version.h"
#include "skw_calib.h"
#include "skw_vendor.h"
#include "skw_regd.h"
#include "skw_recovery.h"
#include "skw_config.h"
#include "trace.h"

extern unsigned int tx_wait_time;

struct skw_global_config {
	atomic_t index;
	struct skw_config conf;
};

static u8 skw_mac[ETH_ALEN];
static struct skw_global_config g_skw_config;

static atomic_t skw_chip_idx = ATOMIC_INIT(0);

static const int g_skw_up_to_ac[8] = {
	SKW_WMM_AC_BE,
	SKW_WMM_AC_BK,
	SKW_WMM_AC_BK,
	SKW_WMM_AC_BE,
	SKW_WMM_AC_VI,
	SKW_WMM_AC_VI,
	SKW_WMM_AC_VO,
	SKW_WMM_AC_VO
};

static int skw_repeater_show(struct seq_file *seq, void *data)
{
	struct skw_core *skw = seq->private;

	if (test_bit(SKW_FLAG_REPEATER, &skw->flags))
		seq_puts(seq, "enable\n");
	else
		seq_puts(seq, "disable\n");

	return 0;
}

static int skw_repeater_open(struct inode *inode, struct file *file)
{
	return single_open(file, skw_repeater_show, inode->i_private);
}

static ssize_t skw_repeater_write(struct file *fp, const char __user *buf,
				size_t len, loff_t *offset)
{
	int i;
	char cmd[32] = {0};
	struct skw_core *skw = fp->f_inode->i_private;

	for (i = 0; i < len; i++) {
		char c;

		if (get_user(c, buf))
			return -EFAULT;

		if (c == '\n' || c == '\0')
			break;

		cmd[i] = tolower(c);
		buf++;
	}

	if (strcmp(cmd, "enable") == 0)
		set_bit(SKW_FLAG_REPEATER, &skw->flags);
	else if (strcmp(cmd, "disable") == 0)
		clear_bit(SKW_FLAG_REPEATER, &skw->flags);
	else
		skw_warn("rx_reorder support setting values of \"enable\" or \"disable\"\n");

	return len;
}

static const struct file_operations skw_repeater_fops = {
	.owner = THIS_MODULE,
	.open = skw_repeater_open,
	.read = seq_read,
	.release = single_release,
	.write = skw_repeater_write,
};

static void skw_dbg_print(struct skw_core *skw, struct seq_file *seq)
{
	int i;
	u64 nsecs;
	unsigned long rem_nsec;

	for (i = 0; i < skw->dbg.nr_cmd; i++) {
		struct skw_dbg_cmd *cmd = &skw->dbg.cmd[i];

		seq_printf(seq, "cmd[%d].id: %d, seq: %d, flags: 0x%lx, loop: %d\n",
			i, cmd->id, cmd->seq, cmd->flags, cmd->loop);

		nsecs = cmd->trigger;
		rem_nsec = do_div(nsecs, 1000000000);
		seq_printf(seq, "    cmd.%d.%d.trigger: %5lu.%06lu\n", cmd->id, cmd->seq,
			(unsigned long)nsecs, rem_nsec / 1000);

		nsecs = cmd->build;
		rem_nsec = do_div(nsecs, 1000000000);
		seq_printf(seq, "    cmd.%d.%d.build: %5lu.%06lu\n", cmd->id, cmd->seq,
			(unsigned long)nsecs, rem_nsec / 1000);

		nsecs = cmd->xmit;
		rem_nsec = do_div(nsecs, 1000000000);
		seq_printf(seq, "    cmd.%d.%d.xmit: %5lu.%06lu\n", cmd->id, cmd->seq,
			(unsigned long)nsecs, rem_nsec / 1000);

		nsecs = cmd->done;
		rem_nsec = do_div(nsecs, 1000000000);
		seq_printf(seq, "    cmd.%d.%d.done: %5lu.%06lu\n", cmd->id, cmd->seq,
			(unsigned long)nsecs, rem_nsec / 1000);

		nsecs = cmd->ack;
		rem_nsec = do_div(nsecs, 1000000000);
		seq_printf(seq, "    cmd.%d.%d.ack: %5lu.%06lu\n", cmd->id, cmd->seq,
			(unsigned long)nsecs, rem_nsec / 1000);

		nsecs = cmd->assert;
		rem_nsec = do_div(nsecs, 1000000000);
		seq_printf(seq, "    cmd.%d.%d.assert: %5lu.%06lu\n", cmd->id, cmd->seq,
			(unsigned long)nsecs, rem_nsec / 1000);

		seq_puts(seq, "\n");
	}

	for (i = 0; i < skw->dbg.nr_dat; i++) {
		struct skw_dbg_dat *dat = &skw->dbg.dat[i];

		seq_printf(seq, "dat[%d], tx_qlen: %d\n", i, dat->qlen);

		nsecs = dat->trigger;
		rem_nsec = do_div(nsecs, 1000000000);
		seq_printf(seq, "    dat.%d.%d.trigger: %5lu.%06lu\n",
			i, dat->qlen, (unsigned long)nsecs, rem_nsec / 1000);

		nsecs = dat->done;
		rem_nsec = do_div(nsecs, 1000000000);
		seq_printf(seq, "    dat.%d.%d.done: %5lu.%06lu\n",
			i, dat->qlen, (unsigned long)nsecs, rem_nsec / 1000);

		seq_puts(seq, "\n");
	}
}

static void skw_timestap_print(struct skw_core *skw, struct seq_file *seq)
{
	u64 ts;
	struct rtc_time tm;
	unsigned long rem_nsec;

	ts = skw->fw.host_timestamp;
	rem_nsec = do_div(ts, 1000000000);
	skw_compat_rtc_time_to_tm(skw->fw.host_seconds, &tm);

	seq_printf(seq,
		   "Timestamp: %u - %lu.%06lu (%d-%02d-%02d %02d:%02d:%02d UTC)\n",
		   skw->fw.timestamp, (unsigned long)ts,
		   rem_nsec / 1000, tm.tm_year + 1900,
		   tm.tm_mon + 1, tm.tm_mday, tm.tm_hour,
		   tm.tm_min, tm.tm_sec);
}

static void skw_drv_info_print(struct skw_core *skw, struct seq_file *seq)
{
	int i;

#define FLAG_TEST(n) test_bit(SKW_FLAG_##n, &skw->flags)
	seq_printf(seq,
		   "SKW Flags:\t 0x%lx %s\n"
		   "TX Packets:\t %ld\n"
		   "RX Packets:\t %ld\n"
		   "txqlen_pending:\t %d\n"
		   "nr lmac:\t %d\n"
		   "skb_recycle_qlist:%d\n",
		   skw->flags, FLAG_TEST(FW_ASSERT) ? "(Assert)" : "",
		   skw->tx_packets,
		   skw->rx_packets,
		   atomic_read(&skw->txqlen_pending),
		   skw->hw.nr_lmac,
		   READ_ONCE(skw->skb_recycle_qlist.qlen));

	for (i = 0; i < skw->hw.nr_lmac; i++)
		seq_printf(seq, "    credit[%d]:\t %d (%s) pendind_skb:%d\n",
			   i, skw_get_hw_credit(skw, i),
			   skw_lmac_is_actived(skw, i) ? "active" : "inactive",
			   skw_edma_pending_skb(skw, i));
#undef FLAG_TEST
}

static void skw_fw_info_print(struct skw_core *skw, struct seq_file *seq)
{
	if (!skw->hw_pdata)
		return;

	/* Firmware & BSP Info */
	seq_printf(seq, "Calib File:\t %s\n"
			"FW Build:\t %s\n"
			"FW Version:\t %s-%s (BSP-MAC)\n"
			"BUS Type:\t 0x%x (%s)\n"
			"Align Size:\t %d\n"
			"TX Limit:\t %d\n",
			skw->fw.calib_file,
			skw->fw.build_time,
			skw->fw.plat_ver,
			skw->fw.wifi_ver,
			skw->hw_pdata->bus_type,
			skw_bus_name(skw->hw.bus),
			skw->hw_pdata->align_value,
			skw->hw.pkt_limit);
}

static int skw_core_show(struct seq_file *seq, void *data)
{
	struct skw_core *skw = seq->private;

	seq_puts(seq, "\n");
	skw_timestap_print(skw, seq);

	seq_puts(seq, "\n");
	skw_drv_info_print(skw, seq);

	seq_puts(seq, "\n");
	skw_fw_info_print(skw, seq);

	seq_puts(seq, "\n");
	skw_dbg_print(skw, seq);

	seq_puts(seq, "\n");

	return 0;
}

static int skw_core_open(struct inode *inode, struct file *file)
{
	// return single_open(file, skw_core_show, inode->i_private);
	return single_open(file, skw_core_show, skw_pde_data(inode));
}

void skw_debug_print_hw_tx_info(struct seq_file *seq, struct skw_get_hw_tx_info_s *info) {
	int i = 0;
	if (!info) {
		seq_printf(seq, "HW Tx Info structure is NULL\n");
		return;
	}
	seq_printf(seq, "Hardware Tx info:\n\n");
	seq_printf(seq, "\tHIF TX All Count: %u\n", info->hif_tx_all_cnt);
	seq_printf(seq, "\tHIF Report All Credit Count: %u\n", info->hif_rpt_all_credit_cnt);
	seq_printf(seq, "\tCurrent Free Buffer Count: %u\n", info->cur_free_buf_cnt);
	seq_printf(seq, "\tPending TX Packet Count: %u\n", info->pendding_tx_pkt_cnt);
	seq_printf(seq, "\tLast Command Sequence: %u\n", info->lst_cmd_seq);
	seq_printf(seq, "\tLast Event Sequence: %u\n", info->lst_evt_seq);
	seq_printf(seq, "\tLMAC TX Broadcast Count: %u\n", info->lmac_tx_bc_cnt);
	seq_printf(seq, "\tLMAC TX Unicast Count: %u\n", info->lmac_tx_uc_cnt[0]);

	// Print array lmac_tx_uc_cnt
	seq_printf(seq, "\tLMAC TX Unicast Count Array: ");
	for (i = 0; i < 5; i++) {
		seq_printf(seq, "%u ", info->lmac_tx_uc_cnt[i]);
	}
	seq_puts(seq, "\n");

	// Print hmac_tx_stat
	seq_printf(seq, "\tHMAC TX Stat: ");
	for (i = 0; i < 7; i++) {
		seq_printf(seq, "%u ", info->hmac_tx_stat.hmac_tx_stat[i]);
	}
	seq_puts(seq, "\n");

	// Print tx_mib_acc_info
	seq_printf(seq, "\tAccumulated TX PSDU Count: %u\n", info->tx_mib_acc_info.acc_tx_psdu_cnt);
	seq_printf(seq, "\tAccumulated TX With ACK Timeout Count: %u\n", info->tx_mib_acc_info.acc_tx_wi_ack_to_cnt);
	seq_printf(seq, "\tAccumulated TX With ACK Fail Count: %u\n", info->tx_mib_acc_info.acc_tx_wi_ack_fail_cnt);
	seq_printf(seq, "\tAccumulated RTS Without CTS Count: %u\n", info->tx_mib_acc_info.acc_rts_wo_cts_cnt);
	seq_printf(seq, "\tAccumulated TX Post Busy Count: %u\n", info->tx_mib_acc_info.acc_tx_post_busy_cnt);
	seq_printf(seq, "\tTX Enable Percentage: %u%%\n", info->tx_mib_acc_info.tx_en_perct);

	// Print tx_mib_tb_acc_info
	seq_printf(seq, "\tTB Basic Trigger Count: %u\n", info->tx_mib_tb_acc_info.rx_basic_trig_cnt);
	seq_printf(seq, "\tTB Basic Trigger Success Count: %u\n", info->tx_mib_tb_acc_info.rx_basic_trig_succ_cnt);
	seq_printf(seq, "\tTB Generate Invoke Count: %u\n", info->tx_mib_tb_acc_info.tb_gen_invoke_cnt);
	seq_printf(seq, "\tTB Generate Abort Count: %u\n", info->tx_mib_tb_acc_info.tb_gen_abort_cnt);
	seq_printf(seq, "\tTB CS Fail Accumulated Count: %u\n", info->tx_mib_tb_acc_info.tb_cs_fail_acc_cnt);
	seq_printf(seq, "\tAll TB Pre TX Count: %u\n", info->tx_mib_tb_acc_info.all_tb_pre_tx_cnt);
	seq_printf(seq, "\tTB TX Accumulated Count: %u\n", info->tx_mib_tb_acc_info.tb_tx_acc_cnt);
	seq_printf(seq, "\tTB TX Success Accumulated Count: %u\n", info->tx_mib_tb_acc_info.tb_tx_acc_scucc_cnt);
	seq_printf(seq, "\tTB TX Success Ratio: %u\n", info->tx_mib_tb_acc_info.tb_tx_suc_ratio);
	seq_printf(seq, "\tRX Trigger Register Count: %u\n", info->tx_mib_tb_acc_info.rx_trig_reg_cnt);
	seq_printf(seq, "\tRX Trigger Start TX Count: %u\n", info->tx_mib_tb_acc_info.rx_trig_start_tx_cnt);
	seq_printf(seq, "\tRX Trigger Success Ratio: %u\n", info->tx_mib_tb_acc_info.rx_trig_suc_ratio);
}

void skw_debug_print_inst_info(struct seq_file *seq, struct skw_get_inst_info_s *info)
{
	int i = 0;
	if (!info) {
		seq_printf(seq, "\tInst Info structure is NULL\n");
		return;
	}
	seq_printf(seq, "Inst info:\n\n");
	seq_printf(seq, "\tInst Mode: %u\n", info->inst_mode);
	seq_printf(seq, "\tHW ID: %u\n", info->hw_id);
	seq_printf(seq, "\tEnable: %u\n", info->enable);
	seq_printf(seq, "\tMAC ID: %u\n", info->mac_id);
	seq_printf(seq, "\tASOC Peer Map: %u\n", info->asoc_peer_map);
	seq_printf(seq, "\tPeer PS State: %u\n", info->peer_ps_state);

	seq_printf(seq, "\tCS Info:\n");
	seq_printf(seq, "\t\tP20 Last Busy Percentage: %u\n", info->cs_info.p20_lst_busy_perctage);
	seq_printf(seq, "\t\tP40 Last Busy Percentage: %u\n", info->cs_info.p40_lst_busy_perctage);
	seq_printf(seq, "\t\tP80 Last Busy Percentage: %u\n", info->cs_info.p80_lst_busy_perctage);
	seq_printf(seq, "\t\tP20 Last NAV Percentage: %u\n", info->cs_info.p20_lst_nav_perctage);
	seq_printf(seq, "\t\tP40 Last NAV Percentage: %u\n", info->cs_info.p40_lst_nav_perctage);
	seq_printf(seq, "\t\tP80 Last NAV Percentage: %u\n", info->cs_info.p80_lst_nav_perctage);

	seq_printf(seq, "\tRPI Info:\n");
	seq_printf(seq, "\t\tNo UC Direct RPI Level: %d\n", info->rpi_info.no_uc_direct_rpi_level);
	seq_printf(seq, "\t\tUC Direct RPI Level: %d\n", info->rpi_info.uc_direct_rpi_level);
	seq_printf(seq, "\t\tRX BA RSSI: %d\n", info->rpi_info.rx_ba_rssi);
	seq_printf(seq, "\t\tRX Idle Percent in RPI: %u\n", info->rpi_info.rx_idle_percent_in_rpi);
	seq_printf(seq, "\t\tRX Percent in RPI: %u\n", info->rpi_info.rx_percent_in_rpi);
	seq_printf(seq, "\t\tRPI Class Duration: ");
	for (i = 0; i < RPI_MAX_LEVEL; i++) {
		seq_printf(seq, "%u ", info->rpi_info.rpi_class_dur[i]);
	}
	seq_printf(seq, "\n");

	seq_printf(seq, "\tNoise Info:\n");
	seq_printf(seq, "\t\tNoise Class Duration: ");
	for (i = 0; i < NOISE_MAX_LEVEL; i++) {
		seq_printf(seq, "%u ", info->noise_info.noise_class_dur[i]);
	}
	seq_printf(seq, "\n");
}

void skw_debug_print_peer_info(struct seq_file *seq, struct skw_get_peer_info *peer_info)
{
	int i = 0;
	if (!peer_info) {
		seq_printf(seq, "\tPeer Info structure is NULL\n");
	return;
	}

	seq_printf(seq, "Peer info:\n\n");
	seq_printf(seq, "\tIs Valid: %u\n", peer_info->is_valid);
	seq_printf(seq, "\tInstance ID: %u\n", peer_info->inst_id);
	seq_printf(seq, "\tHW ID: %u\n", peer_info->hw_id);
	seq_printf(seq, "\tRX RSSI: %d\n", peer_info->rx_rsp_rssi);
	seq_printf(seq, "\tAverage ADD Delay (ms): %u\n", peer_info->avg_add_delay_in_ms);
	seq_printf(seq, "\tTX Max Delay Time: %u\n", peer_info->tx_max_delay_time);

	// Print TX Hmac Per Peer Report
	seq_printf(seq, "\tHMAC TX Stat:\n");
	seq_printf(seq, "\t\t");
	for (i = 0; i < 5; i++) {
		seq_printf(seq, "%u ", peer_info->hmac_tx_stat.hmac_tx_stat[i]);
	}
	seq_printf(seq, "\n");
	seq_printf(seq, "\tTXC ISR Read DSCR FIFO Count: %u\n", peer_info->hmac_tx_stat.txc_isr_read_dscr_fifo_cnt);

	// Print TX Rate Info
	seq_printf(seq, "\tTX Rate Info:\n");
	seq_printf(seq, "\t\tFlags: %u\n", peer_info->tx_rate_info.flags);
	seq_printf(seq, "\t\tMCS Index: %u\n", peer_info->tx_rate_info.mcs_idx);
	seq_printf(seq, "\t\tLegacy Rate: %u\n", peer_info->tx_rate_info.legacy_rate);
	seq_printf(seq, "\t\tNSS: %u\n", peer_info->tx_rate_info.nss);
	seq_printf(seq, "\t\tBW: %u\n", peer_info->tx_rate_info.bw);
	seq_printf(seq, "\t\tGI: %u\n", peer_info->tx_rate_info.gi);
	seq_printf(seq, "\t\tRU: %u\n", peer_info->tx_rate_info.ru);
	seq_printf(seq, "\t\tDCM: %u\n", peer_info->tx_rate_info.dcm);

	// Print RX MSDU Info Report
	seq_printf(seq, "\tRX MSDU Info:\n");
	seq_printf(seq, "\t\tPPDU Mode: %u\n", peer_info->rx_msdu_info_rpt.ppdu_mode);
	seq_printf(seq, "\t\tData Rate: %u\n", peer_info->rx_msdu_info_rpt.data_rate);
	seq_printf(seq, "\t\tGI Type: %u\n", peer_info->rx_msdu_info_rpt.gi_type);
	seq_printf(seq, "\t\tSBW: %u\n", peer_info->rx_msdu_info_rpt.sbw);
	seq_printf(seq, "\t\tDCM: %u\n", peer_info->rx_msdu_info_rpt.dcm);
	seq_printf(seq, "\t\tNSS: %u\n", peer_info->rx_msdu_info_rpt.nss);

	// Print TX Debug Stats Per Peer
	seq_printf(seq, "\tTX Stats Info:\n");
	seq_printf(seq, "\t\tRTS Fail Count: %u\n", peer_info->tx_stats_info.rts_fail_cnt);
	seq_printf(seq, "\t\tPSDU Ack Timeout Count: %u\n", peer_info->tx_stats_info.psdu_ack_timeout_cnt);
	seq_printf(seq, "\t\tTX MPDU Count: %u\n", peer_info->tx_stats_info.tx_mpdu_cnt);
	seq_printf(seq, "\t\tTX Wait Time: %u\n", peer_info->tx_stats_info.tx_wait_time);

	// Print TX Pending Packet Count
	seq_printf(seq, "\tTX Pending Packet Count: ");
	for (i = 0; i < 4; i++) {
		seq_printf(seq, "%u ", peer_info->tx_pending_pkt_cnt[i]);
	}
	seq_printf(seq, "\n");
}

void skw_debug_print_hw_rx_info(struct seq_file *seq, struct skw_get_hw_rx_info *rx_info)
{
	if (!rx_info) {
		seq_printf(seq, "\tInfo structure is NULL\n");
	return;
	}
	seq_printf(seq, "rx info:\n\n");
	seq_printf(seq, "\tPHY RX All Count: %u\n", rx_info->phy_rx_all_cnt);
	seq_printf(seq, "\tPHY RX 11B Count: %u\n", rx_info->phy_rx_11b_cnt);
	seq_printf(seq, "\tPHY RX 11G Count: %u\n", rx_info->phy_rx_11g_cnt);
	seq_printf(seq, "\tPHY RX 11N Count: %u\n", rx_info->phy_rx_11n_cnt);
	seq_printf(seq, "\tPHY RX 11AC Count: %u\n", rx_info->phy_rx_11ac_cnt);
	seq_printf(seq, "\tPHY RX 11AX Count: %u\n", rx_info->phy_rx_11ax_cnt);
	seq_printf(seq, "\tMAC RX MPDU Count: %u\n", rx_info->mac_rx_mpdu_cnt);
	seq_printf(seq, "\tMAC RX MPDU FCS Pass Count: %u\n", rx_info->mac_rx_mpdu_fcs_pass_cnt);
	seq_printf(seq, "\tMAC RX MPDU FCS Pass Direct Count: %u\n", rx_info->mac_rx_mpdu_fcs_pass_dir_cnt);
}

void skw_debug_print_inst_tsf(struct seq_file *seq, struct skw_inst_tsf *inst_tsf)
{
	if (!inst_tsf) {
		seq_printf(seq, "\tInst tsf structure is NULL\n");
		return;
	}
	seq_printf(seq, "inst tsf:\n\n");
	seq_printf(seq, "\tInst tsf low: %u\n", inst_tsf->tsf_l);
	seq_printf(seq, "\tInst tsf high: %u\n", inst_tsf->tsf_h);
}

void skw_debug_print_winfo(struct seq_file *seq, struct skw_debug_info_w  *w_info)
{
	int i, j;
	int percent;

	seq_puts(seq, "debug_w info:\n");

	for (i = 0; i < SKW_MAX_LMAC_SUPPORT; i++) {
		seq_printf(seq, "    hw[%d]:\t total[%d]\t other_count:%d\n",
			i, w_info->hw_w[i].w_total_cnt,
			w_info->hw_w[i].w_cnt[SKW_MAX_W_LEVEL - 1]);
		seq_puts(seq, "\n");
		for (j = 0; j < SKW_MAX_W_LEVEL - 1; j++) {
			percent = w_info->hw_w[i].w_cnt[j] * 1000
					/ w_info->hw_w[i].w_total_cnt;
			seq_printf(seq, "\t  %d:thresh[%d]\t"
			"count:%d\t     percent:%d.%d%%\n", j,
				w_info->hw_w[i].w_ctrl_thresh[j],
				w_info->hw_w[i].w_cnt[j],
				percent/10, percent%10);
		}
		seq_puts(seq, "\n");
	}

	seq_puts(seq, "\n");

}

void skw_debug_print_nss_info(struct seq_file *seq, struct skw_mac_nss_info  *nss_info)
{
	int i;

	seq_puts(seq, "nss info:\n");
	seq_printf(seq,
		"\t mac0 nss: %d,\tmac1 nss: %d.\t"
		" dbdc mode:%d\n\n"
		"\t instence num:%d\n",
		nss_info->mac_nss[0],
		nss_info->mac_nss[1],
		nss_info->is_dbdc_mode,
		nss_info->max_inst_num);

	for (i = 0; i < nss_info->max_inst_num; i++)
		if (nss_info->inst_nss[i].valid_id)
			seq_printf(seq, "\t  inst[%d]:\t valid:%d\t"
				"rx_nss:%d\t tx_nss:%d\n",
				i, nss_info->inst_nss[i].valid_id,
				nss_info->inst_nss[i].inst_rx_nss,
				nss_info->inst_nss[i].inst_tx_nss);

	seq_puts(seq, "\n");

}

int skw_debug_get_hw_tx_info(struct skw_core *skw, u8 *buf, int len)
{
	int ret = -1;
	struct skw_tlv *tlv;

	struct skw_debug_info_s debug_info_param = {0};
	debug_info_param.tlv = SKW_MIB_GET_HW_TX_INFO_E;
	ret = skw_msg_xmit(priv_to_wiphy(skw), 0, SKW_CMD_GET_DEBUG_INFO,
						&debug_info_param, sizeof(struct skw_debug_info_s),
						buf, len);

	if (ret) {
		skw_warn("failed, ret: %d\n", ret);
		return ret;
	}

	tlv = (struct skw_tlv *)buf;
	if (tlv->type != SKW_MIB_GET_HW_TX_INFO_E ||
		tlv->len != sizeof(struct skw_get_hw_tx_info_s))
		return -1;

	return 0;
}

int skw_debug_get_inst_info(struct skw_core *skw, u8 inst_id, u8 *buf, int len)
{
	int ret = -1;
	struct skw_tlv *tlv;

	struct skw_debug_info_s debug_info_param = {0};
	debug_info_param.tlv = SKW_MIB_GET_INST_INFO_E;
	ret = skw_msg_xmit(priv_to_wiphy(skw), inst_id, SKW_CMD_GET_DEBUG_INFO,
						&debug_info_param, sizeof(struct skw_debug_info_s),
						buf, len);

	if (ret) {
		skw_warn("failed, ret: %d\n", ret);
		return ret;
	}

	tlv = (struct skw_tlv *)buf;
	if (tlv->type != SKW_MIB_GET_INST_INFO_E ||
		tlv->len != sizeof(struct skw_get_inst_info_s))
		return -1;

	return 0;
}

int skw_debug_get_peer_info(struct skw_core *skw, u8 peer_idx, u8 *buf, int len)
{
	int ret = -1;
	struct skw_tlv *tlv;

	struct skw_debug_info_s debug_info_param = {0};
	debug_info_param.tlv = SKW_MIB_GET_PEER_INFO_E;
	debug_info_param.val[0] = peer_idx;
	ret = skw_msg_xmit(priv_to_wiphy(skw), 0, SKW_CMD_GET_DEBUG_INFO,
						&debug_info_param, sizeof(struct skw_debug_info_s),
						buf, len);

	if (ret) {
		skw_warn("failed, ret: %d\n", ret);
		return ret;
	}

	tlv = (struct skw_tlv *)buf;
	if (tlv->type != SKW_MIB_GET_PEER_INFO_E ||
		tlv->len != sizeof(struct skw_get_peer_info))
		return -1;

	return 0;
}


int skw_debug_get_hw_rx_info(struct skw_core *skw,  u8 *buf, int len)
{
	int ret = -1;
	struct skw_tlv *tlv;

	struct skw_debug_info_s debug_info_param = {0};
	debug_info_param.tlv = SKW_MIB_GET_HW_RX_INFO_E;
	ret = skw_msg_xmit(priv_to_wiphy(skw), 0, SKW_CMD_GET_DEBUG_INFO,
						&debug_info_param, sizeof(struct skw_debug_info_s),
						buf, len);

	if (ret) {
		skw_warn("failed, ret: %d\n", ret);
		return ret;
	}

	tlv = (struct skw_tlv *)buf;
	if (tlv->type != SKW_MIB_GET_HW_RX_INFO_E ||
		tlv->len != sizeof(struct skw_get_hw_rx_info))
		return -1;

	return 0;
}

int skw_debug_get_inst_tsf(struct skw_core *skw, u8 *buf, int len)
{
	int ret = -1;
	struct skw_tlv *tlv;

	struct skw_debug_info_s debug_info_param = {0};
	debug_info_param.tlv = SKW_MIB_GET_INST_TSF_E;
	ret = skw_msg_xmit(priv_to_wiphy(skw), 0, SKW_CMD_GET_DEBUG_INFO,
						&debug_info_param, sizeof(struct skw_debug_info_s),
						buf, len);

	if (ret) {
		skw_warn("failed, ret: %d\n", ret);
		return ret;
	}

	tlv = (struct skw_tlv *)buf;
	if (tlv->type != SKW_MIB_GET_INST_TSF_E ||
		tlv->len != sizeof(struct skw_inst_tsf))
		return -1;

	return 0;
}

int skw_debug_get_winfo(struct skw_core *skw, u8 *buf, int len)
{
	int ret = -1;
	struct skw_tlv *tlv;

	struct skw_debug_info_s debug_info_param = {0};
	debug_info_param.tlv = SKW_MIB_W_INFO;
	ret = skw_msg_xmit(priv_to_wiphy(skw), 0, SKW_CMD_GET_DEBUG_INFO,
						&debug_info_param, sizeof(struct skw_debug_info_s),
						buf, len);

	if (ret) {
		skw_warn("failed, ret: %d\n", ret);
		return ret;
	}

	tlv = (struct skw_tlv *)buf;
	if (tlv->type != SKW_MIB_W_INFO ||
		tlv->len != sizeof(struct skw_debug_info_w))
		return -1;

	return 0;
}

int skw_debug_get_nss_info(struct skw_core *skw, u8 *buf, int len)
{
	int ret = -1;
	struct skw_tlv *tlv;

	struct skw_debug_info_s debug_info_param = {0};
	debug_info_param.tlv = SKW_MIB_MAC_NSS_INFO;
	ret = skw_msg_xmit(priv_to_wiphy(skw), 0, SKW_CMD_GET_DEBUG_INFO,
						&debug_info_param, sizeof(struct skw_debug_info_s),
						buf, len);

	if (ret) {
		skw_warn("failed, ret: %d\n", ret);
		return ret;
	}

	tlv = (struct skw_tlv *)buf;
	if (tlv->type != SKW_MIB_MAC_NSS_INFO ||
		tlv->len != sizeof(struct skw_mac_nss_info))
		return -1;

	return 0;
}

static int skw_debug_info_show(struct seq_file *seq, void *data)
{
	struct skw_core *skw = seq->private;
	u8 *tx_info = NULL;
	u8 *inst_info = NULL;
	u8 *peer_info = NULL;
	u8 *rx_info = NULL;
	u8 *inst_tsf = NULL;
	u8 *nss_buf = NULL;
	u8 *w_info = NULL;
	int len;

	len = sizeof(struct skw_get_hw_tx_info_s) + sizeof(struct skw_tlv);
	tx_info = SKW_ZALLOC(len, GFP_KERNEL);
	if (!tx_info) {
		skw_err("tx_info failed\n");
	} else {
		if (skw_debug_get_hw_tx_info(skw, tx_info, len) == 0) {
			seq_puts(seq, "\n");
			skw_debug_print_hw_tx_info(seq, (void *)(tx_info + sizeof(struct skw_tlv)));
			seq_puts(seq, "\n");
		}

		SKW_KFREE(tx_info);
	}

	len = sizeof(struct skw_get_inst_info_s) + sizeof(struct skw_tlv);
	inst_info = SKW_ZALLOC(len, GFP_KERNEL);
	if (!inst_info) {
		skw_err("inst_info failed\n");
	} else {
		if (skw_debug_get_inst_info(skw, 0, inst_info, len) == 0) {
			seq_puts(seq, "\n");
			skw_debug_print_inst_info(seq, (void *)(inst_info + sizeof(struct skw_tlv)));
			seq_puts(seq, "\n");
		}

		SKW_KFREE(inst_info);
	}

	len = sizeof(struct skw_get_peer_info) + sizeof(struct skw_tlv);
	peer_info = SKW_ZALLOC(len, GFP_KERNEL);
	if (!peer_info) {
		skw_err("peer_info failed\n");
	} else {
		if (skw_debug_get_peer_info(skw, 0, peer_info, len) == 0) {
			seq_puts(seq, "\n");
			skw_debug_print_peer_info(seq, (void *)(peer_info + sizeof(struct skw_tlv)));
			seq_puts(seq, "\n");
		}

		SKW_KFREE(peer_info);
	}

	len = sizeof(struct skw_get_hw_rx_info) + sizeof(struct skw_tlv);
	rx_info = SKW_ZALLOC(len, GFP_KERNEL);
	if (!rx_info) {
		skw_err("rx_info failed\n");
	} else {
		if (skw_debug_get_hw_rx_info(skw, rx_info, len) == 0) {
			seq_puts(seq, "\n");
			skw_debug_print_hw_rx_info(seq, (void *)(rx_info + sizeof(struct skw_tlv)));
			seq_puts(seq, "\n");
		}

		SKW_KFREE(rx_info);
	}

	len = sizeof(struct skw_inst_tsf) + sizeof(struct skw_tlv);
	inst_tsf = SKW_ZALLOC(len, GFP_KERNEL);
	if (!inst_tsf) {
		skw_err("inst_tsf failed\n");
	} else {
		if (skw_debug_get_inst_tsf(skw, inst_tsf, len) == 0) {
			seq_puts(seq, "\n");
			skw_debug_print_inst_tsf(seq, (void *)(inst_tsf + sizeof(struct skw_tlv)));
			seq_puts(seq, "\n");
		}

		SKW_KFREE(inst_tsf);
	}

	len = sizeof(struct skw_debug_info_w) + sizeof(struct skw_tlv);
	w_info = SKW_ZALLOC(len, GFP_KERNEL);
	if (!w_info) {
		skw_err("w_info failed\n");
	} else {
		if (skw_debug_get_winfo(skw, w_info, len) == 0) {
			seq_puts(seq, "\n");
			skw_debug_print_winfo(seq, (void *)(w_info + sizeof(struct skw_tlv)));
			seq_puts(seq, "\n");
		}

		SKW_KFREE(w_info);
	}

	len = sizeof(struct skw_mac_nss_info) + sizeof(struct skw_tlv);
	nss_buf = SKW_ZALLOC(len, GFP_KERNEL);
	if (!nss_buf) {
		skw_err("nss_buf failed\n");
	} else {
		if (skw_debug_get_nss_info(skw, nss_buf, len) == 0) {
			seq_puts(seq, "\n");
			skw_debug_print_nss_info(seq, (void *)(nss_buf + sizeof(struct skw_tlv)));
			seq_puts(seq, "\n");
		}

		SKW_KFREE(nss_buf);
	}

	seq_puts(seq, "\n");

	return 0;
}

static int skw_debug_info_open(struct inode *inode, struct file *file)
{
	return single_open(file, skw_debug_info_show, skw_pde_data(inode));
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops skw_core_fops = {
	.proc_open = skw_core_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};
static const struct proc_ops skw_debug_info_fops = {
	.proc_open = skw_debug_info_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};
#else
static const struct file_operations skw_core_fops = {
	.owner = THIS_MODULE,
	.open = skw_core_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};
static const struct file_operations skw_debug_info_fops = {
	.owner = THIS_MODULE,
	.open = skw_debug_info_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};
#endif

static int skw_assert_show(struct seq_file *seq, void *data)
{
	return 0;
}

static int skw_assert_open(struct inode *inode, struct file *file)
{
	return single_open(file, skw_assert_show, inode->i_private);
}

static ssize_t skw_assert_write(struct file *fp, const char __user *buf,
				size_t len, loff_t *offset)
{
	struct skw_core *skw = fp->f_inode->i_private;

	skw_hw_assert(skw, false);

	return len;
}

static const struct file_operations skw_assert_fops = {
	.owner = THIS_MODULE,
	.open = skw_assert_open,
	.read = seq_read,
	.write = skw_assert_write,
	.release = single_release,
};

static int skw_ndo_open(struct net_device *dev)
{
	struct skw_iface *iface = netdev_priv(dev);
	struct skw_core *skw = iface->skw;

	skw_dbg("dev: %s, type: %s\n", netdev_name(dev),
		skw_iftype_name(dev->ieee80211_ptr->iftype));

	if (test_bit(SKW_FLAG_FW_THERMAL, &skw->flags)) {
		skw_warn("disable TX for thermal warnning");
		netif_tx_stop_all_queues(dev);
	}

	netif_carrier_off(dev);

	if (dev->ieee80211_ptr->iftype == NL80211_IFTYPE_MONITOR) {
		dev->type = ARPHRD_IEEE80211_RADIOTAP;
		netif_tx_stop_all_queues(dev);
	} else
		dev->type = ARPHRD_ETHER;

	return 0;
}

static int skw_ndo_stop(struct net_device *dev)
{
	struct skw_iface *iface = netdev_priv(dev);
	struct skw_core *skw = iface->skw;

	skw_dbg("dev: %s, type: %s\n", netdev_name(dev),
		skw_iftype_name(dev->ieee80211_ptr->iftype));

	//netif_tx_stop_all_queues(dev);

	// fixme:
	// check if sched scan is going on current netdev
	skw_scan_done(skw, iface, true);

	switch (dev->ieee80211_ptr->iftype) {
	case NL80211_IFTYPE_STATION:
	case NL80211_IFTYPE_P2P_CLIENT:
		// if (iface->sta.sm.state !=  SKW_STATE_NONE)
			//skw_disconnect(iface->wdev.wiphy, iface->ndev,
			//		WLAN_REASON_DEAUTH_LEAVING);
		break;

	case NL80211_IFTYPE_AP:
	case NL80211_IFTYPE_P2P_GO:
		// skw_flush_sta_info(iface);
		break;

	case NL80211_IFTYPE_MONITOR:
		skw_cmd_monitor(priv_to_wiphy(skw), NULL, SKW_MONITOR_CLOSE);
		break;

	default:
		break;
	}

	return 0;
}

static bool skw_udp_filter(struct net_device *ndev, struct sk_buff *skb)
{
	bool ret = false;
	struct udphdr *udp = udp_hdr(skb);

#define DHCP_SERVER_PORT         67
#define DHCP_CLIENT_PORT         68
#define DHCPV6_SERVER_PORT       546
#define DHCPV6_CLIENT_PORT       547

	switch (ntohs(udp->dest)) {
	case DHCP_CLIENT_PORT:
	case DHCP_SERVER_PORT:
		if (ndev->priv_flags & IFF_BRIDGE_PORT) {
			/* set BOOTP flag to broadcast */
			*((u8 *)udp + 18) = 0x80;
			udp->check = 0;
		}

		skw_fallthrough;

	case DHCPV6_CLIENT_PORT:
	case DHCPV6_SERVER_PORT:
		ret = true;
		skw_dbg("DHCP, port: %d\n", ntohs(udp->dest));
		break;

	default:
		ret = false;
		break;
	}

	return ret;
}

static void skw_setup_txba(struct skw_core *skw, struct skw_iface *iface,
			   struct skw_peer *peer, int tid)
{
	int ret;
	struct skw_ba_action tx_ba;

	if (tid >= SKW_NR_TID) {
		skw_warn("tid: %d invalid\n", tid);
		return;
	}

	if ((peer->txba.bitmap | peer->txba.blacklist) & BIT(tid))
		return;

	tx_ba.tid = tid;
	tx_ba.win_size = 64;
	tx_ba.lmac_id = iface->lmac_id;
	tx_ba.peer_idx = peer->idx;
	tx_ba.action = SKW_ADD_TX_BA;

	ret = skw_queue_work(priv_to_wiphy(skw), iface, SKW_WORK_SETUP_TXBA,
				&tx_ba, sizeof(tx_ba));
	if (!ret)
		peer->txba.bitmap |= BIT(tid);
}

struct skw_ctx_entry *skw_get_ctx_entry(struct skw_core *skw, const u8 *addr)
{
	int i, j;
	struct skw_ctx_entry *entry;

	for (i = 0; i < skw->hw.nr_lmac; i++) {
		for (j = 0; j < SKW_MAX_PEER_SUPPORT; j++) {
			entry = rcu_dereference(skw->hw.lmac[i].peer_ctx[j].entry);
			if (entry && ether_addr_equal(entry->addr, addr))
				return entry;
		}
	}

	return NULL;
}

struct skw_peer_ctx *skw_get_ctx(struct skw_core *skw, u8 lmac_id, u8 idx)
{
	if (idx >= SKW_MAX_PEER_SUPPORT)
		return NULL;

	return &skw->hw.lmac[lmac_id].peer_ctx[idx];
}

static int skw_downgrade_ac(struct skw_iface *iface, int aci)
{
#if 1
	while (iface->wmm.acm & BIT(aci)) {
		if (aci == SKW_WMM_AC_BK)
			break;
		aci++;
	}
#else
	if (iface->wmm.acm & BIT(aci)) {
		int i;
		int acm = SKW_WMM_AC_BK;

		for (i = SKW_WMM_AC_BK; i >= 0; i--) {
			if (!(iface->wmm.acm & BIT(i))) {
				acm = i;
				break;
			}
		}

		aci = acm;
	}
#endif

	return aci;
}

static inline bool is_skw_tcp_pure_ack(struct sk_buff *skb)
{
	return tcp_hdr(skb)->ack &&
	       ntohs(ip_hdr(skb)->tot_len) == ip_hdrlen(skb) + tcp_hdrlen(skb);
}

static netdev_tx_t skw_ndo_xmit(struct sk_buff *skb, struct net_device *ndev)
{
	int ret = -1;
	u8 tid;
	u8 fixed_rate = 0;
	u8 fixed_tid = SKW_INVALID_ID;
	u8 peer_index = SKW_INVALID_ID;
	u8 ac_idx = 0, padding = 0;
	u8 prot = 0, tcp_pkt = 0, do_csum = 0;
	bool is_prot_filter = false;
	bool is_udp_filter = false;
	bool is_802_3_frame = false;
	bool pure_tcp_ack = false;
	const u8 tid_map[] = {6, 4, 0, 1};
	int l4_hdr_offset = 0, reset_l4_offset = 0;
	int msdu_len, align_len;
	int nhead, ntail, nroom, txq_len;
	bool is_completed = true;
	struct netdev_queue *txq;
	struct skw_peer_ctx *ctx;
	struct skw_iface *iface = netdev_priv(ndev);
	struct ethhdr *eth = eth_hdr(skb);
	struct skw_ctx_entry *entry = NULL;
	struct sk_buff_head *qlist;
	struct skw_tx_desc_hdr *desc_hdr;
	struct skw_tx_desc_conf *desc_conf;
	struct skw_core *skw = iface->skw;
#ifdef CONFIG_SKW6316_SKB_RECYCLE
	struct sk_buff *skb_recycle;
#endif
	s16 pkt_limit;

	__net_timestamp(skb);

	//test for CPU power
	if (tx_wait_time == 0xFFFFFFFF) {
		goto free;
	}

	/* Mini frame size that HW support */
	if (unlikely(skb->len <= 16)) {
		skw_dbg("current: %s\n", current->comm);
		skw_hex_dump("short skb", skb->data, skb->len, true);

		if (skb->len != ETH_HLEN || eth->h_proto != htons(ETH_P_IP))
			SKW_BUG_ON(1);

		goto free;
	}

	if (skb_linearize(skb))
		goto free;

	msdu_len = skb->len;
	SKW_SKB_TXCB(skb)->skb_native_len = skb->len;
	if (skb->ip_summed == CHECKSUM_PARTIAL) {
		l4_hdr_offset = skb_checksum_start_offset(skb);
		do_csum = 1;
	}

	switch (eth->h_proto) {
	case htons(ETH_P_IP):
		prot = ip_hdr(skb)->protocol;
		reset_l4_offset = ETH_HLEN + ip_hdrlen(skb);

		if (prot == IPPROTO_TCP)
			pure_tcp_ack = is_skw_tcp_pure_ack(skb);

		break;

	case htons(ETH_P_IPV6):
		prot = ipv6_hdr(skb)->nexthdr;
		// fixme:
		// get tcp/udp head offset
		reset_l4_offset = ETH_HLEN + sizeof(struct ipv6hdr);
		break;

	case htons(ETH_P_ARP):
		if (test_bit(SKW_FLAG_FW_FILTER_ARP, &skw->flags))
			is_prot_filter = true;

		if (unlikely(test_bit(SKW_FLAG_REPEATER, &skw->flags)) &&
		    ndev->priv_flags & IFF_BRIDGE_PORT) {
			if (iface->wdev.iftype == NL80211_IFTYPE_STATION) {
				struct sk_buff *arp_skb;
				struct skw_ctx_entry *e;
				struct skw_arphdr *arp = skw_arp_hdr(skb);

				if (arp->ar_op == ntohs(ARPOP_REPLY) && arp->ar_tip == 0
					&& memcmp(arp->ar_tha, arp->ar_sha, ETH_ALEN) == 0)
					goto _done;

				rcu_read_lock();
				e = skw_get_ctx_entry(iface->skw, arp->ar_sha);
				if (e)
					e->peer->ip_addr = arp->ar_sip;

				rcu_read_unlock();

				arp_skb = arp_create(ntohs(arp->ar_op),
						ETH_P_ARP, arp->ar_tip,
						iface->ndev,
						arp->ar_sip, eth->h_dest,
						iface->addr, arp->ar_tha);

				kfree_skb(skb);

				skb = arp_skb;
				if (!skb)
					return NETDEV_TX_OK;

				eth = skw_eth_hdr(skb);
			}
		}

_done:
		//fixed_rate = 1;
		//fixed_tid = 4;
		break;

	case htons(ETH_P_PAE):
	case htons(SKW_ETH_P_WAPI):
	case htons(ETH_P_TDLS):
		is_prot_filter = true;
		break;

	default:
		if (eth->h_proto < ETH_P_802_3_MIN)
			is_802_3_frame = true;

		break;
	}

	if (!do_csum && (prot == IPPROTO_UDP || prot == IPPROTO_TCP))
		skb_set_transport_header(skb, reset_l4_offset);

	// fixme:
	/* enable checksum for TCP & UDP frame, except framgment frame */
	switch (prot) {
	case IPPROTO_UDP:
		is_udp_filter = skw_udp_filter(ndev, skb);
		if (udp_hdr(skb)->check == 0)
			do_csum = 0;

		break;

	case IPPROTO_TCP:
		tcp_pkt = 1;

		break;

	default:
		break;
	}

	ac_idx = skw_downgrade_ac(iface, g_skw_up_to_ac[skb->priority]);
	tid = fixed_tid != SKW_INVALID_ID ? fixed_tid : tid_map[ac_idx];

	rcu_read_lock();

	switch (iface->wdev.iftype) {
	case NL80211_IFTYPE_AP:
	case NL80211_IFTYPE_P2P_GO:
		if (is_unicast_ether_addr(eth->h_dest)) {
			entry = skw_get_ctx_entry(skw, eth->h_dest);
			peer_index = entry ? entry->idx : SKW_INVALID_ID;

			if (entry && entry->peer->sm.state != SKW_STATE_COMPLETED)
				is_completed = false;
		} else {
			fixed_rate = 1;
			peer_index = iface->default_multicast;
		}

		break;

	case NL80211_IFTYPE_STATION:
	case NL80211_IFTYPE_P2P_CLIENT:
	case NL80211_IFTYPE_ADHOC:

		if (atomic_read(&iface->actived_ctx) > 1)
			entry = skw_get_ctx_entry(skw, eth->h_dest);

		if (!entry) {
			ctx = skw_get_ctx(skw, iface->lmac_id, iface->sta.core.bss.ctx_idx);
			if (ctx)
				entry = rcu_dereference(ctx->entry);
		}

		peer_index = entry ? entry->idx : SKW_INVALID_ID;

		if (peer_index != SKW_INVALID_ID &&
			is_multicast_ether_addr(eth->h_dest)) {
			fixed_rate = 1;
			peer_index = iface->default_multicast;
		}

		if (iface->sta.core.sm.state != SKW_STATE_COMPLETED)
			is_completed = false;

		break;

	default:
		peer_index = SKW_INVALID_ID;
		break;
	}

	if (entry && is_completed)
		skw_setup_txba(skw, iface, entry->peer, tid);

	rcu_read_unlock();

	if (peer_index == SKW_INVALID_ID) {
		skw_detail("%s drop dst: %pM, proto: 0x%x\n",
			netdev_name(ndev), eth->h_dest, htons(eth->h_proto));

		goto free;
	}

#ifdef CONFIG_SKW6316_SKB_RECYCLE
	if (!is_prot_filter && !is_udp_filter && !is_802_3_frame && !is_multicast_ether_addr(eth->h_dest)) {
		skb_recycle = skw_recycle_skb_get(skw);
		if (skb_recycle) {
			if (!skw_recycle_skb_copy(skw, skb_recycle, skb)) {
				dev_kfree_skb_any(skb);
				skb = skb_recycle;
				eth = skw_eth_hdr(skb);
				SKW_SKB_TXCB(skb)->recycle = SKW_XMIT_RECYCLE_MAGIC;
			} else {
				skw_err("skw_recycle_skb_copy failed\n");
				skw_recycle_skb_free(skw, skb_recycle);
			}
		} else {
			skb_recycle = skb_copy(skb, GFP_ATOMIC);
			if (skb_recycle) {
				dev_kfree_skb_any(skb);
				skb = skb_recycle;
				eth = skw_eth_hdr(skb);
			}
		}
	}
#endif

	SKW_SKB_TXCB(skb)->ret = 0;
	padding = (long)(skb->data - skw->skb_headroom) & SKW_DATA_ALIGN_MASK;
	if (padding)
		padding = SKW_DATA_ALIGN_SIZE - padding;

	nroom = skb_headroom(skb);
	nhead = skw->skb_headroom > nroom ? skw->skb_headroom - nroom : 0;

	nroom = skb->len + skw->skb_headroom + padding - SKW_DATA_ALIGN_SIZE;
	align_len = round_up(nroom, skw->hw.align);
	nroom = align_len - nroom;
	ntail = nroom > skb_tailroom(skb) ? nroom - skb_tailroom(skb) : 0;

	if (nhead || ntail || skb_cloned(skb)) {
		if (unlikely(pskb_expand_head(skb, nhead, ntail, GFP_ATOMIC))) {
			skw_dbg("failed, nhead: %d, ntail: %d\n", nhead, ntail);
			goto free;
		}

		eth = skw_eth_hdr(skb);
	}

	desc_conf = (void *)skb_push(skb, sizeof(*desc_conf));
	desc_conf->csum = do_csum;
	desc_conf->ip_prot = tcp_pkt;
	desc_conf->l4_hdr_offset = l4_hdr_offset;

	if (skw->hw.bus == SKW_BUS_PCIE) {
		SKW_SKB_TXCB(skb)->lmac_id = iface->lmac_id;
		SKW_SKB_TXCB(skb)->e.eth_type = eth->h_proto;
		SKW_SKB_TXCB(skb)->e.mac_id = iface->id;
		SKW_SKB_TXCB(skb)->e.tid = tid;
		SKW_SKB_TXCB(skb)->e.peer_idx = peer_index;
		SKW_SKB_TXCB(skb)->e.prot = SKW_ETHER_FRAME;
		SKW_SKB_TXCB(skb)->e.encry_dis = 0;
		SKW_SKB_TXCB(skb)->e.rate = fixed_rate;
		SKW_SKB_TXCB(skb)->e.msdu_len = msdu_len;
	} else {
		if (padding)
			skb_push(skb, padding);

		desc_hdr = (void *)skb_push(skb, sizeof(*desc_hdr));
		desc_hdr->padding_gap = padding;
		desc_hdr->inst = iface->id & 0x3;
		desc_hdr->lmac_id = iface->lmac_id;

		desc_hdr->tid = tid;
		desc_hdr->peer_lut = peer_index;
		desc_hdr->frame_type = SKW_ETHER_FRAME;
		skw_set_tx_desc_eth_type(desc_hdr, eth->h_proto);

		desc_hdr->encry_dis = 0;
		desc_hdr->msdu_len = msdu_len;
		desc_hdr->rate = fixed_rate;
	}

	if (unlikely(is_prot_filter || is_udp_filter || is_802_3_frame)) {
		skw_dbg("proto: 0x%x, udp filter: %d, 802.3 frame: %d\n",
			htons(eth->h_proto), is_udp_filter, is_802_3_frame);

		if (skw->hw.bus == SKW_BUS_PCIE) {
			desc_hdr = (void *)skb_push(skb, sizeof(*desc_hdr));
			//desc_hdr->padding_gap = padding;
			desc_hdr->padding_gap = 0;
			desc_hdr->inst = iface->id & 0x3;
			desc_hdr->lmac_id = iface->lmac_id;

			desc_hdr->tid = tid;
			desc_hdr->peer_lut = peer_index;
			desc_hdr->frame_type = SKW_ETHER_FRAME;

			desc_hdr->encry_dis = 0;
			desc_hdr->msdu_len = msdu_len;
			desc_hdr->rate = fixed_rate;
			skw_dbg("Add desc hdr for spec data\n");
		}

		ret = skw_msg_try_send(skw, iface->id, SKW_CMD_TX_DATA_FRAME,
				       skb->data, skb->len, NULL, 0,
				       "SKW_CMD_TX_DATA_FRAME");
		if (ret < 0) {
			if (SKW_SKB_TXCB(skb)->tx_retry++ > 3) {
				skw_queue_work(priv_to_wiphy(skw), iface,
					       SKW_WORK_TX_ETHER_DATA,
					       skb->data, skb->len);
			} else {
				skb_pull(skb, skb->len - msdu_len);
				return NETDEV_TX_BUSY;
			}
		}

		goto free;
	}

	SKW_SKB_TXCB(skb)->peer_idx = peer_index;

	if (pure_tcp_ack)
		ac_idx = SKW_ACK_TXQ;

	qlist = &iface->txq[ac_idx];

	skb_queue_tail(qlist, skb);
	if (skw->hw.bus != SKW_BUS_PCIE && skw_get_hw_credit(skw, iface->lmac_id) == 0)
		goto _ok;
	if (skw_edma_pending_skb(skw, iface->lmac_id) > SKW_EDMA_TX_HIGH_THRESHOLD)
		goto _ok;

#ifdef CONFIG_SKW6316_SKB_RECYCLE
	if (skw->hw.bus == SKW_BUS_PCIE || skw->hw.bus == SKW_BUS_SDIO)
		pkt_limit = 32;
	else
		pkt_limit = skw->hw.pkt_limit;
#ifdef CONFIG_SKW6316_TX_WORKQUEUE
	if (prot == IPPROTO_UDP || prot == IPPROTO_TCP) {
		if (skb_queue_len(qlist) < pkt_limit) {
			if (!timer_pending(&skw->tx_worker.timer))
				skw_wakeup_tx(skw, msecs_to_jiffies(1));
		} else
			skw_wakeup_tx(skw, 0);
	} else
		skw_wakeup_tx(skw, 0);
#else
	skw_wakeup_tx(skw, 0);
#endif
#else
	if (skw->hw.bus == SKW_BUS_PCIE)
		pkt_limit = 32;
	else
		pkt_limit = skw->hw.pkt_limit;

#ifdef CONFIG_SKW6316_TX_WORKQUEUE
	if (prot == IPPROTO_UDP && skb_queue_len(qlist) < pkt_limit) {
		if (!timer_pending(&skw->tx_worker.timer))
			skw_wakeup_tx(skw, msecs_to_jiffies(1));
	} else
		skw_wakeup_tx(skw, 0);
#else
	skw_wakeup_tx(skw, 0);
#endif

#endif
	trace_skw_tx_xmit(eth->h_dest, peer_index, prot, fixed_rate,
			  do_csum, ac_idx, skb_queue_len(qlist));

	txq_len = skb_queue_len(qlist) + skb_queue_len(&iface->tx_cache[ac_idx]);
	if (txq_len >= SKW_TXQ_HIGH_THRESHOLD) {
		txq = netdev_get_tx_queue(ndev, ac_idx);
		if (!netif_tx_queue_stopped(txq))
			netif_tx_stop_queue(txq);
	}

_ok:
	return NETDEV_TX_OK;

free:
	if (ret != 0)
		ndev->stats.tx_dropped++;

	skw_skb_kfree(skw, skb);

	return NETDEV_TX_OK;
}

static u16 skw_ndo_select(struct net_device *dev, struct sk_buff *skb
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0)
		, struct net_device *sb_dev
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0)
		, struct net_device *sb_dev,
		select_queue_fallback_t fallback
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)
		, void *accel_priv,
		select_queue_fallback_t fallback
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
		, void *accel_priv
#endif
		SKW_NULL)
{
	struct skw_iface *iface = netdev_priv(dev);

	if (!iface->wmm.qos_enabled) {
		skb->priority = 0;
		return SKW_WMM_AC_BE;
	}

	skb->priority = skw_compat_classify8021d(skb, iface->qos_map);

	return g_skw_up_to_ac[skb->priority];
}

#define SKW_ANDROID_CMD_LEN    128
static int skw_android_cmd(struct net_device *dev, void __user *priv_data)
{
	char command[SKW_ANDROID_CMD_LEN], *data;
	struct android_wifi_priv_cmd priv_cmd;
	bool compat_task = false;

	if (!priv_data)
		return  -EINVAL;

#ifdef CONFIG_COMPAT
	if (SKW_IS_COMPAT_TASK()) {
		struct compat_android_wifi_priv_cmd compat;

		if (copy_from_user(&compat, priv_data, sizeof(compat)))
			return -EFAULT;

		priv_cmd.buf = compat_ptr(compat.buf);
		priv_cmd.used_len = compat.used_len;
		priv_cmd.total_len = compat.total_len;

		compat_task = true;
	}
#endif

	if (!compat_task &&
	    copy_from_user(&priv_cmd, priv_data, sizeof(priv_cmd)))
		return -EFAULT;

	if (copy_from_user(command, priv_cmd.buf, sizeof(command)))
		return -EFAULT;

	command[SKW_ANDROID_CMD_LEN - 1] = 0;

	skw_dbg("%s: %s\n", netdev_name(dev), command);

#define IS_SKW_CMD(c, k)        \
	!strncasecmp(c, SKW_ANDROID_PRIV_##k, strlen(SKW_ANDROID_PRIV_##k))

#define SKW_CMD_DATA(c, k)     \
	(c + strlen(SKW_ANDROID_PRIV_##k) + 1)

#define SKW_CMD_DATA_LEN(c, k) \
	(sizeof(command) - strlen(SKW_ANDROID_PRIV_##k) - 1)

	if (IS_SKW_CMD(command, COUNTRY)) {
		data = SKW_CMD_DATA(command, COUNTRY);
		skw_set_regdom(dev->ieee80211_ptr->wiphy, data);
	} else if (IS_SKW_CMD(command, BTCOEXSCAN_STOP)) {
	} else if (IS_SKW_CMD(command, RXFILTER_START)) {
	} else if (IS_SKW_CMD(command, RXFILTER_STOP)) {
	} else if (IS_SKW_CMD(command, RXFILTER_ADD)) {
	} else if (IS_SKW_CMD(command, RXFILTER_REMOVE)) {
	} else if (IS_SKW_CMD(command, SETSUSPENDMODE)) {
	} else if (IS_SKW_CMD(command, BTCOEXMODE)) {
	} else if (IS_SKW_CMD(command, SET_AP_WPS_P2P_IE)) {
	} else {
		skw_info("Unsupport cmd: %s - ignored\n", command);
	}

#undef IS_SKW_CMD

	return 0;
}

static int skw_ioctl(struct net_device *dev, void __user *user_data)
{
	int is_outdoor = 0;
	int ret = -ENOTSUPP;
	char country[4] = {0};
	struct skw_ioctl_cmd cmd;
	struct skw_core *skw = wiphy_priv(dev->ieee80211_ptr->wiphy);

	if (copy_from_user(&cmd, user_data, sizeof(cmd)))
		return -ENOMEM;

	switch (cmd.id) {
	case SKW_IOCTL_SUBCMD_COUNTRY:
		if (cmd.len > sizeof(country))
			return -EINVAL;

		if (copy_from_user(country, user_data + sizeof(cmd), cmd.len))
			return -EINVAL;

		if (strlen(country) != 2)
			return -EINVAL;

		ret = skw_set_regdom(dev->ieee80211_ptr->wiphy, country);

		break;

	case SKW_IOCTL_SUBCMD_OUTDOOR:
		ret = get_user(is_outdoor, (int __user *)(user_data + sizeof(cmd)));
		if (ret) {
			skw_err("failed to get user data, ret: %d\n", ret);
		} else {
			skw_dbg("out door: %d\n", is_outdoor);

			if (is_outdoor)
				set_bit(SKW_FLAG_OUTDOOR, &skw->flags);
			else
				clear_bit(SKW_FLAG_OUTDOOR, &skw->flags);
		}

		break;

	default:
		skw_warn("unsupport cmd: 0x%x, len: %d\n", cmd.id, cmd.len);
		break;
	}

	return ret;
}

static int skw_ndo_ioctl(struct net_device *dev, struct ifreq *ifr,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)
			void __user *data,
#endif
			int cmd)
{
	int ret;
	void __user *priv = ifr->ifr_data;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)
	priv = data;
#endif

	switch (cmd) {
	case SKW_IOCTL_ANDROID_CMD:
		ret = skw_android_cmd(dev, priv);
		break;

	case SKW_IOCTL_CMD:
		ret = skw_ioctl(dev, priv);
		break;

	default:
		ret = -ENOTSUPP;
		skw_warn("%s, unsupport cmd: 0x%x\n", netdev_name(dev), cmd);

		break;
	}

	return ret;
}

static void skw_ndo_tx_timeout(struct net_device *dev
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
				, unsigned int txqueue
#endif
				SKW_NULL)
{
	struct skw_iface *iface = (struct skw_iface *)netdev_priv(dev);
	struct skw_core *skw;

	if (!iface) {
		skw_err("iface NULL\n");
		return;
	}

	skw = iface->skw;

	skw_warn("ndev:%s,flag:0x%lx\n", netdev_name(dev), skw->flags);
}

static void skw_ndo_set_rx_mode(struct net_device *dev)
{
	int count, total_len;
	struct skw_mc_list *mc;
	struct netdev_hw_addr *ha;

	skw_dbg("%s, mc: %d, uc: %d\n", netdev_name(dev),
		netdev_mc_count(dev), netdev_uc_count(dev));

	count = netdev_mc_count(dev);
	if (!count)
		return;

	total_len = sizeof(*mc) + sizeof(struct mac_address) * count;
	mc = SKW_ZALLOC(total_len, GFP_ATOMIC);
	if (!mc) {
		skw_err("alloc failed, mc count: %d, total_len: %d\n",
			count, total_len);
		return;
	}

	mc->count = count;

	count = 0;
	netdev_for_each_mc_addr(ha, dev)
		skw_ether_copy(mc->mac[count++].addr, ha->addr);

	skw_queue_work(dev->ieee80211_ptr->wiphy, netdev_priv(dev),
		SKW_WORK_SET_MC_ADDR, mc, total_len);

	SKW_KFREE(mc);
}
#if 0
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 11, 0)
static struct rtnl_link_stats64 *
#else
static void
#endif
skw_ndo_get_stats64(struct net_device *dev,
		    struct rtnl_link_stats64 *stats)
{
	int i;

	for_each_possible_cpu(i) {
		const struct pcpu_sw_netstats *tstats;
		u64 rx_packets, rx_bytes, tx_packets, tx_bytes;
		unsigned int start;

		tstats = per_cpu_ptr(dev->tstats, i);

		do {
			start = u64_stats_fetch_begin_irq(&tstats->syncp);
			rx_packets = tstats->rx_packets;
			tx_packets = tstats->tx_packets;
			rx_bytes = tstats->rx_bytes;
			tx_bytes = tstats->tx_bytes;
		} while (u64_stats_fetch_retry_irq(&tstats->syncp, start));

		stats->rx_packets += rx_packets;
		stats->tx_packets += tx_packets;
		stats->rx_bytes   += rx_bytes;
		stats->tx_bytes   += tx_bytes;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 11, 0)
	return stats;
#endif
}
#endif

static int skw_ndo_set_mac_address(struct net_device *dev, void *addr)
{
	struct skw_iface *iface = (struct skw_iface *)netdev_priv(dev);
	struct sockaddr *sa = addr;
	int ret = 0;

	skw_dbg("mac: %pM\n", sa->sa_data);

	ret = eth_mac_addr(dev, sa);
	if (ret) {
		skw_err("failed, addr: %pM, ret: %d\n", sa->sa_data, ret);
		return ret;
	}

	ret = skw_send_msg(iface->wdev.wiphy, dev, SKW_CMD_RANDOM_MAC,
			sa->sa_data, ETH_ALEN, NULL, 0);
	if (ret) {
		skw_err("set mac: %pM failed, ret: %d\n",
			sa->sa_data, ret);

		eth_mac_addr(dev, iface->addr);

		return ret;
	}

	skw_ether_copy(iface->addr, sa->sa_data);

	return 0;
}

#if 0
static void skw_ndo_uninit(struct net_device *ndev)
{
	struct skw_iface *iface = netdev_priv(ndev);
	struct wiphy *wiphy = ndev->ieee80211_ptr->wiphy;

	skw_dbg("%s\n", netdev_name(ndev));

	free_percpu(ndev->tstats);

	skw_del_vif(wiphy, iface);
	skw_iface_teardown(wiphy, iface);
	skw_release_inst(wiphy, iface->id);
}
#endif

static const struct net_device_ops skw_netdev_ops = {
	// .ndo_uninit = skw_ndo_uninit,
	.ndo_open = skw_ndo_open,
	.ndo_stop = skw_ndo_stop,
	.ndo_start_xmit = skw_ndo_xmit,
	.ndo_select_queue = skw_ndo_select,
	.ndo_tx_timeout = skw_ndo_tx_timeout,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)
	.ndo_siocdevprivate = skw_ndo_ioctl,
#else
	.ndo_do_ioctl = skw_ndo_ioctl,
#endif
	//.ndo_get_stats64 = skw_ndo_get_stats64,
	.ndo_set_rx_mode = skw_ndo_set_rx_mode,
	.ndo_set_mac_address = skw_ndo_set_mac_address,
};

int skw_netdev_init(struct wiphy *wiphy, struct net_device *ndev, u8 *addr)
{
	struct skw_core *skw;
	struct skw_iface *iface;

	if (!ndev)
		return -EINVAL;

	skw = wiphy_priv(wiphy);
	iface = netdev_priv(ndev);
	SET_NETDEV_DEV(ndev, wiphy_dev(wiphy));

	ndev->features = NETIF_F_GRO |
			 NETIF_F_IP_CSUM |
			 NETIF_F_IPV6_CSUM;

	ndev->ieee80211_ptr = &iface->wdev;
	ndev->netdev_ops = &skw_netdev_ops;
	ndev->watchdog_timeo = 3 * HZ;
	ndev->needed_headroom =	skw->skb_headroom;
	ndev->needed_tailroom = skw->hw_pdata->align_value;
	// ndev->priv_destructor = skw_netdev_deinit;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
	ndev->destructor = free_netdev;
#else
	ndev->needs_free_netdev = true;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
	eth_hw_addr_set(ndev, addr);
#else
	skw_ether_copy(ndev->dev_addr, addr);
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 14, 0)
	ndev->tstats = netdev_alloc_pcpu_stats(struct pcpu_tstats);
#else
	ndev->tstats = netdev_alloc_pcpu_stats(struct pcpu_sw_netstats);
#endif
	if (!ndev->tstats)
		return -ENOMEM;

#ifdef CONFIG_WIRELESS_EXT
	ndev->wireless_handlers = skw_iw_handlers(wiphy);
#endif

#ifdef CONFIG_RPS
	iface->cpu_id = skw->isr_cpu_id;
	skw_queue_work(priv_to_wiphy(iface->skw), iface,
		SKW_WORK_IFACE_RPS_INIT, NULL, 0);
#endif

	return 0;
}

void skw_netdev_deinit(struct net_device *ndev)
{
	free_percpu(ndev->tstats);
}

#if 0
void skw_netdev_deinit(struct net_device *dev)
{
	struct skw_iface *iface = netdev_priv(dev);

	skw_dbg("%s\n", netdev_name(dev));

#if 0 //move these actions to ndo_uninit
	free_percpu(dev->tstats);
	skw_cmd_close_dev(iface->wdev.wiphy, iface->id);
	skw_del_vif(iface->skw, iface);
	skw_iface_teardown(iface);
#endif
}
#endif

int skw_sync_cmd_event_version(struct wiphy *wiphy)
{
	int i, ret = 0;
	struct skw_version_info *skw_fw_ver;

#define SKW_CMD_VER(id, ver)   .cmd[id] = ver
#define SKW_EVENT_VER(id, ver) .event[id] = ver
	const struct skw_version_info skw_drv_ver = {
		SKW_CMD_VER(SKW_CMD_DOWNLOAD_INI, V1),
		SKW_CMD_VER(SKW_CMD_GET_INFO, V1),
		SKW_CMD_VER(SKW_CMD_SYN_VERSION, V1),
		SKW_CMD_VER(SKW_CMD_OPEN_DEV, V1),
		SKW_CMD_VER(SKW_CMD_CLOSE_DEV, V1),
		SKW_CMD_VER(SKW_CMD_START_SCAN, V1),
		SKW_CMD_VER(SKW_CMD_STOP_SCAN, V1),
		SKW_CMD_VER(SKW_CMD_START_SCHED_SCAN, V1),
		SKW_CMD_VER(SKW_CMD_STOP_SCHED_SCAN, V1),
		SKW_CMD_VER(SKW_CMD_JOIN, V1),
		SKW_CMD_VER(SKW_CMD_AUTH, V1),
		SKW_CMD_VER(SKW_CMD_ASSOC, V1),
		SKW_CMD_VER(SKW_CMD_ADD_KEY, V1),
		SKW_CMD_VER(SKW_CMD_DEL_KEY, V1),
		SKW_CMD_VER(SKW_CMD_TX_MGMT, V1),
		SKW_CMD_VER(SKW_CMD_TX_DATA_FRAME, V1),
		SKW_CMD_VER(SKW_CMD_SET_IP, V1),
		SKW_CMD_VER(SKW_CMD_DISCONNECT, V1),
		SKW_CMD_VER(SKW_CMD_RPM_REQ, V1),
		SKW_CMD_VER(SKW_CMD_START_AP, V1),
		SKW_CMD_VER(SKW_CMD_STOP_AP, V1),
		SKW_CMD_VER(SKW_CMD_ADD_STA, V1),
		SKW_CMD_VER(SKW_CMD_DEL_STA, V1),
		SKW_CMD_VER(SKW_CMD_GET_STA, V1),
		SKW_CMD_VER(SKW_CMD_RANDOM_MAC, V1),
		SKW_CMD_VER(SKW_CMD_GET_LLSTAT, V1),
		SKW_CMD_VER(SKW_CMD_SET_MC_ADDR, V1),
		SKW_CMD_VER(SKW_CMD_RESUME, V1),
		SKW_CMD_VER(SKW_CMD_SUSPEND, V1),
		SKW_CMD_VER(SKW_CMD_REMAIN_ON_CHANNEL, V1),
		SKW_CMD_VER(SKW_CMD_BA_ACTION, V1),
		SKW_CMD_VER(SKW_CMD_TDLS_MGMT, V1),
		SKW_CMD_VER(SKW_CMD_TDLS_OPER, V1),
		SKW_CMD_VER(SKW_CMD_TDLS_CHANNEL_SWITCH, V1),
		SKW_CMD_VER(SKW_CMD_SET_CQM_RSSI, V1),
		SKW_CMD_VER(SKW_CMD_NPI_MSG, V1),
		SKW_CMD_VER(SKW_CMD_IBSS_JOIN, V1),
		SKW_CMD_VER(SKW_CMD_SET_IBSS_ATTR, V1),
		SKW_CMD_VER(SKW_CMD_RSSI_MONITOR, V1),
		SKW_CMD_VER(SKW_CMD_SET_IE, V1),
		SKW_CMD_VER(SKW_CMD_SET_MIB, V1),
		SKW_CMD_VER(SKW_CMD_REGISTER_FRAME, V1),
		SKW_CMD_VER(SKW_CMD_ADD_TX_TS, V1),
		SKW_CMD_VER(SKW_CMD_DEL_TX_TS, V1),
		SKW_CMD_VER(SKW_CMD_REQ_CHAN_SWITCH, V1),
		SKW_CMD_VER(SKW_CMD_CHANGE_BEACON, V1),
		SKW_CMD_VER(SKW_CMD_DPD_ILC_GEAR_PARAM, V1),
		SKW_CMD_VER(SKW_CMD_DPD_ILC_MARTIX_PARAM, V1),
		SKW_CMD_VER(SKW_CMD_DPD_ILC_COEFF_PARAM, V1),
		SKW_CMD_VER(SKW_CMD_WIFI_RECOVER, V1),
		SKW_CMD_VER(SKW_CMD_PHY_BB_CFG, V1),
		SKW_CMD_VER(SKW_CMD_SET_REGD, V1),
		SKW_CMD_VER(SKW_CMD_SET_EFUSE, V1),
		SKW_CMD_VER(SKW_CMD_SET_PROBEREQ_FILTER, V1),
		SKW_CMD_VER(SKW_CMD_CFG_ANT, V1),
		SKW_CMD_VER(SKW_CMD_RTT, V1),
		SKW_CMD_VER(SKW_CMD_GSCAN, V1),
		SKW_CMD_VER(SKW_CMD_DFS, V1),
		SKW_CMD_VER(SKW_CMD_SET_SPD_ACTION, V1),
		SKW_CMD_VER(SKW_CMD_SET_DPD_RESULT, V1),
		SKW_CMD_VER(SKW_CMD_SET_MONITOR_PARAM, V1),

		/* event */
	};

	skw_fw_ver = SKW_ZALLOC(sizeof(struct skw_version_info), GFP_KERNEL);
	if (!skw_fw_ver)
		return -ENOMEM;

	ret = skw_msg_xmit(wiphy, 0, SKW_CMD_SYN_VERSION,
			   NULL, 0, skw_fw_ver,
			   sizeof(struct skw_version_info));
	if (ret) {
		skw_err("ret: %d\n", ret);
		SKW_KFREE(skw_fw_ver);

		return ret;
	}

	for (i = 0; i < SKW_MAX_MSG_ID; i++) {
		if (skw_fw_ver->cmd[i] == 0 || skw_drv_ver.cmd[i] == 0)
			continue;

		if (skw_drv_ver.cmd[i] != skw_fw_ver->cmd[i]) {
			skw_warn("cmd: %d, drv ver: %d, fw ver: %d\n",
				 i, skw_drv_ver.cmd[i], skw_fw_ver->cmd[i]);

			ret = -EINVAL;
		}
	}

	SKW_KFREE(skw_fw_ver);

	return ret;
}

static int skw_set_capa(struct skw_core *skw, int capa)
{
	int idx, bit;
	int size = sizeof(skw->ext_capa);

	idx = capa / BITS_PER_BYTE;
	bit = capa % BITS_PER_BYTE;

	BUG_ON(idx >= size);

	skw->ext_capa[idx] |= BIT(bit);

	return 0;
}

static int skw_set_ext_capa(struct skw_core *skw, struct skw_chip_info *chip)
{
	skw_set_capa(skw, SKW_EXT_CAPA_BSS_TRANSITION);
	skw_set_capa(skw, SKW_EXT_CAPA_MBSSID);
	skw_set_capa(skw, SKW_EXT_CAPA_TDLS_SUPPORT);
	skw_set_capa(skw, SKW_EXT_CAPA_TWT_REQ_SUPPORT);

	return 0;
}

static const char *skw_get_chip_id(u32 chip_type)
{
	switch (chip_type) {
	case 0x100:
		return "EA6621Q";

	case 0x101:
		return "EA6521QF";

	case 0x102:
		return "EA6621QT";

	case 0x103:
		return "EA6521QT";

	case 0x200:
		return "EA6316";

	default:
		skw_err("Unsupport chip type: 0x%x\n", chip_type);
		break;
	}

	return NULL;
}

static int skw_set_link_loss_mib(struct wiphy *wiphy, u8 to)
{
	int ret;
	u16 *plen;
	struct skw_tlv_conf conf;

	skw_dbg("beacon to: %d\n", to);

	ret = skw_tlv_alloc(&conf, 128, GFP_KERNEL);
	if (ret) {
		skw_err("alloc failed\n");
		return ret;
	}

	plen = skw_tlv_reserve(&conf, 2);
	if (!plen) {
		skw_err("reserve failed\n");
		skw_tlv_free(&conf);
		return -ENOMEM;
	}

	if (skw_tlv_add(&conf, SKW_MIB_SET_LINK_LOSS_THOLD, &to, 1)) {
		skw_err("set link loss failed\n");
		skw_tlv_free(&conf);

		return -EINVAL;
	}

	*plen = conf.total_len;

	ret = skw_msg_xmit(wiphy, 0, SKW_CMD_SET_MIB, conf.buff,
			   conf.total_len, NULL, 0);
	if (ret)
		skw_warn("failed, ret: %d\n", ret);

	skw_tlv_free(&conf);

	return ret;
}

static int skw_set_24ghz_band_mib(struct wiphy *wiphy, u32 band)
{
	int ret;
	u16 *plen;
	struct skw_tlv_conf conf;

	skw_dbg("24ghz_band: %d\n", band);

	ret = skw_tlv_alloc(&conf, 128, GFP_KERNEL);
	if (ret) {
		skw_err("alloc failed\n");
		return ret;
	}

	plen = skw_tlv_reserve(&conf, 2);
	if (!plen) {
		skw_err("reserve failed\n");
		skw_tlv_free(&conf);
		return -ENOMEM;
	}

	if (skw_tlv_add(&conf, SKW_MIB_SET_BAND_2G, &band, sizeof(band))) {
		skw_err("set 24ghz band failed\n");
		skw_tlv_free(&conf);

		return -EINVAL;
	}

	*plen = conf.total_len;

	ret = skw_msg_xmit(wiphy, 0, SKW_CMD_SET_MIB, conf.buff,
			   conf.total_len, NULL, 0);
	if (ret)
		skw_warn("failed, ret: %d\n", ret);

	skw_tlv_free(&conf);

	return ret;
}

static void skw_common_mib_set(struct wiphy *wiphy,
		struct skw_core *skw) {

	skw_set_link_loss_mib(wiphy, skw->config.fw.link_loss_thrd);
	skw_set_24ghz_band_mib(wiphy, skw->config.fw.band_24ghz);
}

int skw_sync_chip_info(struct wiphy *wiphy, struct skw_chip_info *chip)
{
	int ret;
	const char *chipid;
	int vendor, revision;
	u64 ts = local_clock();
	struct skw_core *skw = wiphy_priv(wiphy);

	skw->fw.host_timestamp = ts;
	skw->fw.host_seconds = skw_get_seconds();

	do_div(ts, 1000000);
	ret = skw_msg_xmit(wiphy, 0, SKW_CMD_GET_INFO, &ts, sizeof(ts),
			   chip, sizeof(*chip));
	if (ret) {
		skw_err("ret: %d\n", ret);
		return ret;
	}

	if (chip->priv_filter_arp)
		set_bit(SKW_FLAG_FW_FILTER_ARP, &skw->flags);

	if (chip->priv_ignore_cred)
		set_bit(SKW_FLAG_FW_IGNORE_CRED, &skw->flags);

	if (chip->priv_p2p_common_port)
		set_bit(SKW_FLAG_LEGACY_P2P_COMMON_PORT, &skw->flags);

	if (chip->priv_dfs_master_enabled)
		skw->dfs.fw_enabled = true;

	if (chip->nr_hw_mac)
		skw->hw.nr_lmac = chip->nr_hw_mac;
	else
		skw->hw.nr_lmac = 1;

	BUG_ON(skw->hw.nr_lmac > SKW_MAX_LMAC_SUPPORT);

	memcpy(skw->fw.build_time, chip->fw_build_time,
	       sizeof(skw->fw.build_time));
	memcpy(skw->fw.plat_ver, chip->fw_plat_ver, sizeof(skw->fw.plat_ver));
	memcpy(skw->fw.wifi_ver, chip->fw_wifi_ver, sizeof(skw->fw.wifi_ver));

	skw->fw.timestamp = chip->fw_timestamp;
	skw->fw.max_num_sta = chip->max_sta_allowed;
	skw->fw.fw_bw_capa = chip->fw_bw_capa;

	chipid = skw_get_chip_id(chip->fw_chip_type);
	if (!chipid) {
		skw_err("chip id 0x%x not support\n", chip->fw_chip_type);
		return -ENOTSUPP;
	}

	if (test_bit(SKW_CFG_FLAG_OVERLAY_MODE, &g_skw_config.conf.global.flags)) {
		int j = 0;
		char *pos, cfg[64] = {0};

		if (strlen(g_skw_config.conf.calib.chip))
			pos = g_skw_config.conf.calib.chip;
		else
			pos = (char *)chipid;

		snprintf(cfg, sizeof(cfg) - 1, "%s.cfg", pos);

		for (j = 0; j < strlen(cfg); j++)
			cfg[j] = tolower(cfg[j]);

		skw_update_config(NULL, cfg, &skw->config);
	}

	/* BIT[0:1] Reserved
	 * BIT[2:3] BUS Type
	 * BIT[4:7] Vendor ID
	 */
	vendor = 0;

	if (test_bit(SKW_CFG_CALIB_STRICT_MODE, &skw->config.calib.flags))
		vendor |= ((skw->hw.bus & 0x3) << 2);

#ifdef CONFIG_SKW6316_CALIB_APPEND_MODULE_ID
	if (chip->calib_module_id) {
		int i;
		int vdata = chip->calib_module_id;

		for (i = 0; i < 4; i++) {
			if ((vdata & 0xf) == 0xf)
				vendor |= BIT(4 + i);

			vdata >>= 4;
		}
	}
#endif

	revision = skw->hw_pdata->chipid[15];

	if (strlen(skw->config.calib.chip))
		chipid = skw->config.calib.chip;

	snprintf(skw->fw.calib_file, sizeof(skw->fw.calib_file),
		"%s_%s_R%02X%03X.bin", chipid, skw->config.calib.project,
		vendor & 0xff, revision);

	if (chip->priv_pn_reuse) {
		set_bit(SKW_FLAG_FW_PN_REUSE, &skw->flags);
		skw->hw.rx_desc.push_offset = SKW_RX_DESC_PN_REUSE_PUSH_OFFSET;
	}

	skw_set_ext_capa(skw, chip);
	/* HT capa */

	skw_common_mib_set(wiphy, skw);

	skw_dbg("efuse mac: %pM, %s\n", chip->mac,
		is_valid_ether_addr(chip->mac) ? "valid" : "invalid");

	return 0;
}

static void skw_setup_mac_address(struct wiphy *wiphy, u8 *user_mac, u8 *hw_mac)
{
	int i;
	u8 addr[ETH_ALEN] = {0};
	struct skw_core *skw = wiphy_priv(wiphy);

	if (user_mac && is_valid_ether_addr(user_mac)) {
		skw_ether_copy(addr, user_mac);
	} else if (hw_mac && is_valid_ether_addr(hw_mac)) {
		skw_ether_copy(addr, hw_mac);
	} else {
		eth_random_addr(addr);
		addr[0] = 0xFE;
		addr[1] = 0xFD;
		addr[2] = 0xFC;
	}

	for (i = 0; i < SKW_NR_IFACE; i++) {
		skw_ether_copy(skw->address[i].addr, addr);

		if (i != 0) {
			skw->address[i].addr[0] |= BIT(1);
			skw->address[i].addr[3] ^= BIT(i);
		}

		skw_dbg("addr[%d]: %pM\n", i, skw->address[i].addr);
	}
}

static int skw_buffer_init(struct skw_core *skw)
{
	int ret, size;

	if (skw->hw.bus == SKW_BUS_PCIE) {
		ret = skw_edma_init(priv_to_wiphy(skw));
		if (ret < 0) {
			skw_err("edma init failed, ret: %d\n", ret);
			return ret;
		}
	} else {
		size = sizeof(struct scatterlist);

		skw->sgl_dat = kcalloc(SKW_NR_SGL_DAT, size, GFP_KERNEL);
		if (!skw->sgl_dat) {
			skw_err("sg list malloc failed, sg length: %d\n",
				SKW_NR_SGL_DAT);

			return -ENOMEM;
		}

		skw->sgl_cmd = kcalloc(SKW_NR_SGL_CMD, size, GFP_KERNEL);
		if (!skw->sgl_cmd) {
			skw_err("sg list malloc failed, sg length: %d\n",
				SKW_NR_SGL_CMD);

			SKW_KFREE(skw->sgl_dat);
			return -ENOMEM;
		}

		skw->cmd.data = SKW_ZALLOC(SKW_MSG_BUFFER_LEN, GFP_KERNEL);
		if (!skw->cmd.data) {
			skw_err("mallc data buffer failed\n");
			SKW_KFREE(skw->sgl_dat);
			SKW_KFREE(skw->sgl_cmd);
			return -ENOMEM;
		}
	}

	return 0;
}

static void skw_buffer_deinit(struct skw_core *skw)
{
	if (skw->hw.bus == SKW_BUS_PCIE) {
		skw_edma_deinit(priv_to_wiphy(skw));
	} else {
		SKW_KFREE(skw->sgl_dat);
		SKW_KFREE(skw->sgl_cmd);
		SKW_KFREE(skw->cmd.data);

		//TODO : recycle txqlen_pending if BSP support API
		if (unlikely(atomic_read(&skw->txqlen_pending)))
			skw_err("txqlen_pending:%d remind\n", atomic_read(&skw->txqlen_pending));
	}
}

static struct wakeup_source *skw_wakeup_source_init(const char *name)
{
	struct wakeup_source *ws;

	ws = wakeup_source_create(name);
	if (ws)
		wakeup_source_add(ws);

	return ws;
}

static void skw_wakeup_source_deinit(struct wakeup_source *ws)
{
	if (ws) {
		wakeup_source_remove(ws);
		wakeup_source_destroy(ws);
	}
}

static void skw_hw_hal_init(struct skw_core *skw, struct sv6160_platform_data *pdata)
{
	int i, j, bus;
	bool extra_v2;
	struct {
		u8 dat_port;
		u8 logic_port;
		u8 flags;
		u8 resv;
	} skw_port[SKW_MAX_LMAC_SUPPORT] = {0};

	atomic_set(&skw->hw.credit, 0);
	skw->hw.align = pdata->align_value;
	skw->hw.cmd_port = pdata->cmd_port;
	skw->hw.pkt_limit = pdata->max_buffer_size / SKW_TX_PACK_SIZE;
	skw->hw.dma = (pdata->bus_type >> 3) & 0x3;

	if (skw->hw.pkt_limit >= SKW_NR_SGL_DAT) {
		WARN_ONCE(1, "pkt limit(%d) larger than buffer", skw->hw.pkt_limit);
		skw->hw.pkt_limit = SKW_NR_SGL_DAT - 1;
	}

	bus = pdata->bus_type & SKW_BUS_TYPE_MASK;
	if (bus == SKW_BUS_SDIO2) {
		bus = SKW_BUS_SDIO;
		extra_v2 = true;
	} else if (bus == SKW_BUS_USB2) {
		bus = SKW_BUS_USB;
		extra_v2 = true;
	} else {
		extra_v2 = false;
	}

	switch (bus) {
	case  SKW_BUS_SDIO:
		skw->hw.bus = SKW_BUS_SDIO;
		skw->hw.bus_dat_xmit = skw_sdio_xmit;
		skw->hw.bus_cmd_xmit = skw_sdio_cmd_xmit;

		skw->hw.extra.hdr_len = SKW_EXTER_HDR_SIZE;
		if (extra_v2)
			skw->hw.extra.len_offset = 0;
		else
			skw->hw.extra.len_offset = 7;

		skw->hw.extra.eof_offset = 23;
		skw->hw.extra.chn_offset = 24;

		skw->hw.rx_desc.hdr_offset = SKW_SDIO_RX_DESC_HDR_OFFSET;
		skw->hw.rx_desc.msdu_offset = SKW_SDIO_RX_DESC_MSDU_OFFSET;
		skw->hw.rx_desc.push_offset = SKW_RX_DESC_PUSH_OFFSET;

		skw->hw.flags = SKW_HW_FLAG_SDIO_V2 | SKW_HW_FLAG_EXTRA_HDR;

		skw_port[0].dat_port = pdata->data_port & 0xf;
		skw_port[0].logic_port = skw_port[0].dat_port;
		skw_port[0].flags = BIT(SKW_LMAC_FLAG_INIT) |
				    BIT(SKW_LMAC_FLAG_RXCB);

		skw_port[1].dat_port = (pdata->data_port >> 4) & 0xf;
		skw_port[1].logic_port = skw_port[1].dat_port;
		if (skw_port[1].logic_port) {
			skw_port[1].flags = BIT(SKW_LMAC_FLAG_INIT) |
					    BIT(SKW_LMAC_FLAG_RXCB);

		}

		break;

	case SKW_BUS_USB:
		skw->hw.bus = SKW_BUS_USB;
		skw->hw.bus_dat_xmit = skw_usb_xmit;
		skw->hw.bus_cmd_xmit = skw_usb_cmd_xmit;
		skw->hw.flags = SKW_HW_FLAG_EXTRA_HDR;
		skw->hw.extra.hdr_len = SKW_EXTER_HDR_SIZE;
		if (extra_v2)
			skw->hw.extra.len_offset = 0;
		else
			skw->hw.extra.len_offset = 7;

		skw->hw.extra.eof_offset = 23;
		skw->hw.extra.chn_offset = 24;

		skw->hw.rx_desc.hdr_offset = SKW_USB_RX_DESC_HDR_OFFSET;
		skw->hw.rx_desc.msdu_offset = SKW_USB_RX_DESC_MSDU_OFFSET;
		skw->hw.rx_desc.push_offset = SKW_RX_DESC_PUSH_OFFSET;

		skw_port[0].dat_port = pdata->data_port;
		skw_port[0].logic_port = 0;
		skw_port[0].flags = BIT(SKW_LMAC_FLAG_INIT) |
				    BIT(SKW_LMAC_FLAG_RXCB) |
				    BIT(SKW_LMAC_FLAG_TXCB);

		skw_port[1].dat_port = pdata->data_port;
		skw_port[1].logic_port = 1;
		skw_port[1].flags = BIT(SKW_LMAC_FLAG_INIT);

		break;

	case SKW_BUS_PCIE:
		skw->hw.bus = SKW_BUS_PCIE;
		skw->hw.bus_dat_xmit = skw_pcie_xmit;
		skw->hw.bus_cmd_xmit = skw_pcie_cmd_xmit;
		skw->hw.dma = SKW_ASYNC_EDMA_TX;

		skw->hw.rx_desc.hdr_offset = SKW_PCIE_RX_DESC_HDR_OFFSET;
		skw->hw.rx_desc.msdu_offset = SKW_PCIE_RX_DESC_MSDU_OFFSET;
		skw->hw.rx_desc.push_offset = SKW_RX_DESC_PUSH_OFFSET;

		skw->hw.cmd_port = SKW_EDMA_VIRTUAL_CMD_PORT;

		skw->hw.pkt_limit = 1024;

		skw_port[0].dat_port = 0;
		skw_port[0].logic_port = 0;
		skw_port[0].flags = BIT(SKW_LMAC_FLAG_INIT);

		skw_port[1].logic_port = 0;
		skw_port[1].dat_port = 0;
		skw_port[1].flags = BIT(SKW_LMAC_FLAG_INIT);

		break;

	default:
		break;
	}

	for (i = 0; i < SKW_MAX_LMAC_SUPPORT; i++) {
		skw->hw.lmac[i].id = i;
		skw->hw.lmac[i].lport = skw_port[i].logic_port;
		skw->hw.lmac[i].dport = skw_port[i].dat_port;
		skw->hw.lmac[i].flags = skw_port[i].flags;
		WRITE_ONCE(skw->hw.lmac[i].iface_bitmap, 0);

		skw->hw.lmac[i].skw = skw;

		skb_queue_head_init(&skw->hw.lmac[i].rx_dat_q);
		atomic_set(&skw->hw.lmac[i].fw_credit, 0);

		for (j = 0; j < SKW_MAX_PEER_SUPPORT; j++) {
			skw->hw.lmac[i].peer_ctx[j].idx = j;
			mutex_init(&skw->hw.lmac[i].peer_ctx[j].lock);
		}
	}
}

static int skw_core_init(struct skw_core *skw, struct platform_device *pdev, int idx)
{
	int ret;
	char name[32] = {0};

	skw->hw_pdata = dev_get_platdata(&pdev->dev);
	if (!skw->hw_pdata) {
		skw_err("get drv data failed\n");
		return -ENODEV;
	}

	memcpy(&skw->config, &g_skw_config.conf, sizeof(struct skw_config));

	skw->idx = idx;
	skw_hw_hal_init(skw, skw->hw_pdata);

	snprintf(name, sizeof(name), "chip%d.%s", idx, skw_bus_name(skw->hw.bus));
	skw->dentry = skw_debugfs_subdir(name, NULL);
	skw->pentry = skw_procfs_subdir(name, NULL);

	mutex_init(&skw->lock);

#ifdef CONFIG_SKW6316_SAP_SME_EXT
	set_bit(SKW_FLAG_SAP_SME_EXTERNAL, &skw->flags);
#endif

#ifdef CONFIG_SKW6316_STA_SME_EXT
	set_bit(SKW_FLAG_STA_SME_EXTERNAL, &skw->flags);
#endif

#ifdef CONFIG_SKW6316_REPEATER_MODE
	set_bit(SKW_FLAG_REPEATER, &skw->flags);
#endif
	skw->regd = NULL;
	skw->country[0] = '0';
	skw->country[1] = '0';

	atomic_set(&skw->exit, 0);
	atomic_set(&skw->tx_wake, 0);
	atomic_set(&skw->rx_wake, 0);

	init_waitqueue_head(&skw->tx_wait_q);
	init_waitqueue_head(&skw->rx_wait_q);

	skb_queue_head_init(&skw->rx_dat_q);
	atomic_set(&skw->txqlen_pending, 0);

	spin_lock_init(&skw->dfs.skw_pool_lock);
	INIT_LIST_HEAD(&skw->dfs.skw_pulse_pool);
	INIT_LIST_HEAD(&skw->dfs.skw_pseq_pool);

	sema_init(&skw->cmd.lock, 1);
	init_waitqueue_head(&skw->cmd.wq);
	skw->cmd.ws = skw_wakeup_source_init("skwifi_cmd");
	sema_init(&skw->cmd.mgmt_cmd_lock, 1);

	spin_lock_init(&skw->vif.lock);

	skw_event_work_init(&skw->event_work, skw_default_event_work);
	skw->event_wq = alloc_workqueue("skwifid_evt_wq.%d", WQ_UNBOUND | WQ_MEM_RECLAIM, 1, idx);
	if (!skw->event_wq) {
		ret = -ENOMEM;
		skw_err("alloc event wq failed, ret: %d\n", ret);

		goto deinit_ws;
	}

	ret = skw_dpd_init(&skw->dpd);
	if (ret < 0)
		goto deinit_wq;

	ret = skw_buffer_init(skw);
	if (ret < 0)
		goto deinit_dpd;

	ret = skw_rx_init(skw);
	if (ret < 0) {
		skw_err("rx init failed, ret: %d\n", ret);
		goto deinit_buff;
	}

	ret = skw_tx_init(skw);
	if (ret < 0) {
		skw_err("tx init failed, ret: %d\n", ret);
		goto deinit_rx;
	}

	skw_debugfs_file(skw->dentry, "repeater", 0666, &skw_repeater_fops, skw);

	skw->dbg.nr_cmd = SKW_DBG_NR_CMD;
	skw->dbg.nr_dat = SKW_DBG_NR_DAT;
	atomic_set(&skw->dbg.loop, 0);
	skw->isr_cpu_id = -1;

	return 0;

deinit_rx:
	skw_rx_deinit(skw);

deinit_buff:
	skw_buffer_deinit(skw);

deinit_dpd:
	skw_dpd_deinit(&skw->dpd);

deinit_wq:
	destroy_workqueue(skw->event_wq);
	skw_event_work_deinit(&skw->event_work);

deinit_ws:
	skw_wakeup_source_deinit(skw->cmd.ws);

	debugfs_remove_recursive(skw->dentry);
	proc_remove(skw->pentry);

	return ret;
}

static void skw_core_deinit(struct skw_core *skw)
{
	skw_tx_deinit(skw);

	skw_rx_deinit(skw);

	skw_buffer_deinit(skw);

	skw_dpd_deinit(&skw->dpd);

	destroy_workqueue(skw->event_wq);

	skw_event_work_deinit(&skw->event_work);

	skw_wakeup_source_deinit(skw->cmd.ws);

	debugfs_remove_recursive(skw->dentry);
	proc_remove(skw->pentry);
}

int skw_set_ip(struct wiphy *wiphy, struct net_device *ndev,
		struct skw_setip_param *setip_param, int size)
{
	int ret = 0;
	//int size = 0;

	//size = sizeof(struct skw_setip_param);
	ret = skw_queue_work(wiphy, netdev_priv(ndev),
			SKW_WORK_SET_IP, setip_param, size);
	if (ret)
		skw_err("Set IP failed\n");

	return ret;
}

/*
 * Get the IP address for both IPV4 and IPV6, set it
 * to firmware while they are valid.
 */
void skw_set_ip_to_fw(struct wiphy *wiphy, struct net_device *ndev)
{
	struct in_device *in_dev;
	struct in_ifaddr *ifa;

	struct inet6_dev *idev;
	struct inet6_ifaddr *ifp;

	struct skw_setip_param setip_param[SKW_FW_IPV6_COUNT_LIMIT+1];
	int ip_count = 0, ipv6_count = 0;

	in_dev = __in_dev_get_rtnl(ndev);
	if (!in_dev)
		goto ipv6;

	ifa = in_dev->ifa_list;
	if (!ifa || !ifa->ifa_local)
		goto ipv6;

	skw_info("ip addr: %pI4\n", &ifa->ifa_local);
	setip_param[ip_count].ip_type = SKW_IP_IPV4;
	setip_param[ip_count].ipv4 = ifa->ifa_local;
	ip_count++;

ipv6:
	idev = __in6_dev_get(ndev);
	if (!idev)
		goto ip_apply;

	read_lock_bh(&idev->lock);
	list_for_each_entry_reverse(ifp, &idev->addr_list, if_list) {
		skw_info("ip addr: %pI6\n", &ifp->addr);
		if (++ipv6_count > SKW_FW_IPV6_COUNT_LIMIT) {
			skw_warn("%s set first %d of %d ipv6 address\n",
				ndev->name, SKW_FW_IPV6_COUNT_LIMIT, ipv6_count);

			read_unlock_bh(&idev->lock);
			goto ip_apply;
		}

		setip_param[ip_count].ip_type = SKW_IP_IPV6;
		memcpy(&setip_param[ip_count].ipv6, &ifp->addr, 16);
		ip_count++;
	}
	read_unlock_bh(&idev->lock);

ip_apply:
	if (ip_count)
		skw_set_ip(wiphy, ndev, setip_param, ip_count*sizeof(struct skw_setip_param));

}

#ifdef CONFIG_INET
static int skw_ifa4_notifier(struct notifier_block *nb,
			unsigned long action, void *data)
{
	struct in_ifaddr *ifa = data;
	struct net_device *ndev;
	struct wireless_dev *wdev;
	struct skw_core *skw = container_of(nb, struct skw_core, ifa4_nf);

	skw_dbg("action: %ld\n", action);

	if (!ifa->ifa_dev)
		return NOTIFY_DONE;

	ndev = ifa->ifa_dev->dev;
	wdev = ndev->ieee80211_ptr;

	if (!wdev || wdev->wiphy != priv_to_wiphy(skw))
		return NOTIFY_DONE;

	if (ndev->ieee80211_ptr->iftype != NL80211_IFTYPE_STATION &&
	    ndev->ieee80211_ptr->iftype != NL80211_IFTYPE_P2P_CLIENT)
		return NOTIFY_DONE;

	switch (action) {
	case NETDEV_UP:
//	case NETDEV_DOWN:
		skw_set_ip_to_fw(wdev->wiphy, ndev);

		break;

	default:
		break;
	}

	return NOTIFY_DONE;
}

#endif

#ifdef CONFIG_IPV6
static int skw_ifa6_notifier(struct notifier_block *nb,
			unsigned long action, void *data)
{
	struct inet6_ifaddr *ifa6 = data;
	struct skw_core *skw = container_of(nb, struct skw_core, ifa6_nf);

	struct net_device *ndev;
	struct wireless_dev *wdev;

	skw_dbg("action: %ld\n", action);

	if (!ifa6->idev || !ifa6->idev->dev)
		return NOTIFY_DONE;

	ndev = ifa6->idev->dev;
	wdev = ndev->ieee80211_ptr;

	if (!wdev || wdev->wiphy != priv_to_wiphy(skw))
		return NOTIFY_DONE;

	switch (action) {
	case NETDEV_UP:
	// case NETDEV_DOWN:

		skw_set_ip_to_fw(wdev->wiphy, ndev);

		break;

	default:
		break;
	}

	return NOTIFY_DONE;
}

#endif

static int skw_bsp_notifier(struct notifier_block *nb,
			unsigned long action, void *data)
{
	struct skw_core *skw = container_of(nb, struct skw_core, bsp_nf);

	skw_dbg("action: %ld, skw flags: 0x%lx\n", action, skw->flags);

	switch (action) {
	case SKW_BSP_NF_ASSERT:
	case SKW_BSP_NF_BLOCKED:
		set_bit(SKW_FLAG_FW_ASSERT, &skw->flags);
		skw_abort_cmd(skw);
		cancel_work_sync(&skw->recovery_work);
		skw_wifi_disable(skw->hw_pdata);
		break;

	case SKW_BSP_NF_READY:
		if (test_bit(SKW_FLAG_FW_ASSERT, &skw->flags))
			schedule_work(&skw->recovery_work);
		else
			clear_bit(SKW_FLAG_BLOCK_TX, &skw->flags);

		break;

#if 0
	case SKW_BSP_NF_DISCONNECT:
		set_bit(SKW_FLAG_BLOCK_TX, &skw->flags);
		break;
#endif

	default:
		break;
	}

	return NOTIFY_DONE;
}

static void skw_ifa_notifier_register(struct skw_core *skw)
{
#ifdef CONFIG_INET
	skw->ifa4_nf.notifier_call = skw_ifa4_notifier;
	register_inetaddr_notifier(&skw->ifa4_nf);
#endif

#ifdef CONFIG_IPV6
	skw->ifa6_nf.notifier_call = skw_ifa6_notifier;
	register_inet6addr_notifier(&skw->ifa6_nf);
#endif

	skw->bsp_nf.notifier_call = skw_bsp_notifier;
	skw_register_bsp_notifier(skw, &skw->bsp_nf);
}

static void skw_ifa_notifier_unregister(struct skw_core *skw)
{
#ifdef CONFIG_INET
	unregister_inetaddr_notifier(&skw->ifa4_nf);
#endif

#ifdef CONFIG_IPV6
	unregister_inet6addr_notifier(&skw->ifa6_nf);
#endif

	skw_unregister_bsp_notifier(skw, &skw->bsp_nf);
}

int skw_lmac_bind_iface(struct skw_core *skw, struct skw_iface *iface, int lmac_id)
{
	struct skw_lmac *lmac;
	unsigned long bitmap = 0;

	if (lmac_id >= skw->hw.nr_lmac) {
		skw_err("invalid lmac id: %d\n", skw->hw.nr_lmac);
		return 0;
	}

	iface->lmac_id = lmac_id;
	lmac = &skw->hw.lmac[lmac_id];
	bitmap = READ_ONCE(lmac->iface_bitmap);

	BUG_ON(!test_bit(SKW_LMAC_FLAG_INIT, &lmac->flags));

	set_bit(iface->id, &lmac->iface_bitmap);

	if (bitmap)
		return 0;

	if (skw->hw.bus == SKW_BUS_PCIE)
		skw_edma_enable(skw, lmac_id);

	set_bit(SKW_LMAC_FLAG_ACTIVATED, &lmac->flags);

	return 0;
}

int skw_lmac_unbind_iface(struct skw_core *skw, int lmac_id, int iface_id)
{
	struct skw_lmac *lmac;

	if (lmac_id >= skw->hw.nr_lmac) {
		skw_err("invalid lmac id: %d\n", skw->hw.nr_lmac);
		return 0;
	}

	lmac = &skw->hw.lmac[lmac_id];

	if (READ_ONCE(lmac->iface_bitmap))
		return 0;

	clear_bit(SKW_LMAC_FLAG_ACTIVATED, &lmac->flags);

	if (skw->hw.bus == SKW_BUS_PCIE)
		skw_edma_disable(skw, lmac_id);

	atomic_set(&skw->hw.lmac[lmac_id].fw_credit, 0);

	skw_detail("reset fw credit for mac:%d", lmac_id);

	return 0;
}

void skw_add_credit(struct skw_core *skw, int lmac_id, int cred)
{
	trace_skw_tx_add_credit(lmac_id, cred);

	atomic_add(cred, &skw->hw.lmac[lmac_id].fw_credit);
	smp_wmb();

	skw_wakeup_tx(skw, 0);
	skw_detail("lmac_id: %d cred: %d", lmac_id, cred);
}

static int skw_add_default_iface(struct wiphy *wiphy)
{
	int ret = 0;
	struct skw_iface *iface = NULL;
#ifdef CONFIG_SKW6316_LEGACY_P2P
	struct skw_iface *p2p = NULL;
	struct skw_core *skw = wiphy_priv(wiphy);
#endif

	rtnl_lock();

	iface = skw_add_iface(wiphy, "wlan%d", NL80211_IFTYPE_STATION,
				skw_mac, SKW_INVALID_ID, true);
	if (IS_ERR(iface)) {
		ret = PTR_ERR(iface);
		skw_err("add iface failed, ret: %d\n", ret);

		goto unlock;
	}

#ifdef CONFIG_SKW6316_LEGACY_P2P
	if (test_bit(SKW_FLAG_LEGACY_P2P_COMMON_PORT, &skw->flags))
		p2p = skw_add_iface(wiphy, "p2p%d", NL80211_IFTYPE_STATION,
				NULL, SKW_LAST_IFACE_ID, true);
	else
		p2p = skw_add_iface(wiphy, "p2p%d", NL80211_IFTYPE_P2P_DEVICE,
				NULL, SKW_LAST_IFACE_ID, true);

	if (IS_ERR(p2p)) {
		ret = PTR_ERR(p2p);
		skw_err("add p2p legacy interface failed, ret: %d\n", ret);

		skw_del_iface(wiphy, iface);

		goto unlock;
	}

	if (!test_bit(SKW_FLAG_LEGACY_P2P_COMMON_PORT, &skw->flags))
		set_bit(SKW_IFACE_FLAG_LEGACY_P2P_DEV, &p2p->flags);
#endif

unlock:
	rtnl_unlock();

	return ret;
}

static int skw_calib_bin_download(struct wiphy *wiphy, const u8 *data, u32 size)
{
	int i = 0, ret = 0;
	int buf_size, remain = size;
	struct skw_calib_param calib;

	skw_dbg("file size: %d\n", size);

	buf_size = sizeof(calib.data);

	while (remain > 0) {
		calib.len = (remain < buf_size) ? remain : buf_size;
		calib.seq = i;
		remain -= calib.len;

		memcpy(calib.data, data, calib.len);

		if (!remain)
			calib.end = 1;
		else
			calib.end = 0;

		skw_dbg("bb_file remain: %d, seq: %d len: %d end: %d\n",
			remain, calib.seq, calib.len, calib.end);

		ret = skw_msg_xmit_timeout(wiphy, 0, SKW_CMD_PHY_BB_CFG,
			&calib, sizeof(calib), NULL, 0,
			"SKW_CMD_PHY_BB_CFG", msecs_to_jiffies(5000), 0);
		if (ret) {
			skw_err("failed, ret: %d,  seq: %d\n", ret, i);
			break;
		}

		i++;
		data += calib.len;
	}

	return ret;
}

int skw_calib_download(struct wiphy *wiphy, const char *fname)
{
	int ret = 0;
	const struct firmware *fw;

	skw_dbg("fw file: %s\n", fname);

	ret = request_firmware(&fw, fname, &wiphy->dev);
	if (ret) {
		skw_err("load %s failed, ret: %d\n", fname, ret);
		return ret;
	}

	ret = skw_calib_bin_download(wiphy, fw->data, fw->size);
	if (ret != 0)
		skw_err("bb_file cali msg fail\n");

	release_firmware(fw);

	return ret;
}

void skw_dbg_dump(struct skw_core *skw)
{
	int i;
	u64 nsecs;
	unsigned long rem_nsec;

	for (i = 0; i < skw->dbg.nr_cmd; i++) {
		struct skw_dbg_cmd *cmd = &skw->dbg.cmd[i];

		skw_dbg("cmd[%d].id: %d, seq: %d, flags: 0x%lx, loop: %d\n",
			i, cmd->id, cmd->seq, cmd->flags, cmd->loop);

		nsecs = cmd->trigger;
		rem_nsec = do_div(nsecs, 1000000000);
		skw_dbg("cmd.%d.%d.trigger: %5lu.%06lu\n", cmd->id, cmd->seq,
			(unsigned long)nsecs, rem_nsec / 1000);

		nsecs = cmd->build;
		rem_nsec = do_div(nsecs, 1000000000);
		skw_dbg("cmd.%d.%d.build: %5lu.%06lu\n", cmd->id, cmd->seq,
			(unsigned long)nsecs, rem_nsec / 1000);

		nsecs = cmd->xmit;
		rem_nsec = do_div(nsecs, 1000000000);
		skw_dbg("cmd.%d.%d.xmit: %5lu.%06lu\n", cmd->id, cmd->seq,
			(unsigned long)nsecs, rem_nsec / 1000);

		nsecs = cmd->done;
		rem_nsec = do_div(nsecs, 1000000000);
		skw_dbg("cmd.%d.%d.done: %5lu.%06lu\n", cmd->id, cmd->seq,
			(unsigned long)nsecs, rem_nsec / 1000);

		nsecs = cmd->ack;
		rem_nsec = do_div(nsecs, 1000000000);
		skw_dbg("cmd.%d.%d.ack: %5lu.%06lu\n", cmd->id, cmd->seq,
			(unsigned long)nsecs, rem_nsec / 1000);

		nsecs = cmd->assert;
		rem_nsec = do_div(nsecs, 1000000000);
		skw_dbg("cmd.%d.%d.assert: %5lu.%06lu\n", cmd->id, cmd->seq,
			(unsigned long)nsecs, rem_nsec / 1000);
	}

	for (i = 0; i < skw->dbg.nr_dat; i++) {
		struct skw_dbg_dat *dat = &skw->dbg.dat[i];

		nsecs = dat->trigger;
		rem_nsec = do_div(nsecs, 1000000000);
		skw_dbg("dat.%d.%d.trigger: %5lu.%06lu\n",
			i, dat->qlen, (unsigned long)nsecs, rem_nsec / 1000);

		nsecs = dat->done;
		rem_nsec = do_div(nsecs, 1000000000);
		skw_dbg("dat.%d.%d.done: %5lu.%06lu\n",
			i, dat->qlen, (unsigned long)nsecs, rem_nsec / 1000);
	}
}

static int skw_drv_probe(struct platform_device *pdev)
{
	int ret = 0;
	struct skw_chip_info chip;
	struct wiphy *wiphy = NULL;
	struct skw_core *skw = NULL;
	int idx = atomic_inc_return(&skw_chip_idx);

	skw_info("chip: %d, MAC: %pM\n", idx, skw_mac);

	wiphy = skw_alloc_wiphy(sizeof(struct skw_core));
	if (!wiphy) {
		ret = -ENOMEM;
		skw_err("malloc wiphy failed\n");

		goto failed;
	}

	set_wiphy_dev(wiphy, &pdev->dev);

	skw = wiphy_priv(wiphy);

	ret = skw_core_init(skw, pdev, idx);
	if (ret) {
		skw_err("core init failed, ret: %d\n", ret);
		goto free_wiphy;
	}

	skw_regd_init(wiphy);
	skw_vendor_init(wiphy);
	skw_work_init(wiphy);
	skw_timer_init(skw);
	skw_recovery_init(skw);

	skw_wifi_enable(dev_get_platdata(&pdev->dev));

	if (skw_sync_cmd_event_version(wiphy) ||
	    skw_sync_chip_info(wiphy, &chip))
		goto core_deinit;

	skw_setup_mac_address(wiphy, skw_mac, chip.mac);

	if (skw_calib_download(wiphy, skw->fw.calib_file) < 0)
		goto core_deinit;

	ret = skw_setup_wiphy(wiphy, &chip);
	if (ret) {
		skw_err("setup wiphy failed, ret: %d\n", ret);
		goto core_deinit;
	}

	rtnl_lock();

	skw_set_wiphy_regd(wiphy, skw->country);

	if (skw->config.regd.country[0] != '0' &&
	    skw->config.regd.country[1] != '0')
		skw_set_regdom(wiphy, skw->config.regd.country);

	rtnl_unlock();

	ret = skw_add_default_iface(wiphy);
	if (ret)
		goto unregister_wiphy;

	skw_ifa_notifier_register(skw);

	platform_set_drvdata(pdev, skw);

	skw_procfs_file(skw->pentry, "core", 0444, &skw_core_fops, skw);

	skw_debugfs_file(SKW_WIPHY_DENTRY(wiphy), "assert", 0444,
			 &skw_assert_fops, skw);

	skw_procfs_file(skw->pentry, "debug_info", 0444, &skw_debug_info_fops, skw);

	return 0;

unregister_wiphy:
	wiphy_unregister(wiphy);

core_deinit:
	skw_wifi_disable(dev_get_platdata(&pdev->dev));
	skw_recovery_deinit(skw);
	skw_timer_deinit(skw);
	skw_work_deinit(wiphy);
	skw_vendor_deinit(wiphy);
	skw_core_deinit(skw);

free_wiphy:
	wiphy_free(wiphy);

failed:
	atomic_dec(&skw_chip_idx);

	return ret;
}

static int skw_drv_remove(struct platform_device *pdev)
{
	int i;
	struct wiphy *wiphy;
	struct skw_core *skw = platform_get_drvdata(pdev);

	skw_info("%s\n", pdev->name);

	if (!skw)
		return 0;

	wiphy = priv_to_wiphy(skw);

	skw_ifa_notifier_unregister(skw);

	rtnl_lock();

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 16, 0)
	cfg80211_shutdown_all_interfaces(wiphy);
#endif

	for (i = 0; i < SKW_NR_IFACE; i++)
		skw_del_iface(wiphy, skw->vif.iface[i]);

	rtnl_unlock();

	wiphy_unregister(wiphy);

	skw_wifi_disable(dev_get_platdata(&pdev->dev));

	skw_recovery_deinit(skw);

	skw_timer_deinit(skw);

	skw_work_deinit(wiphy);

	skw_vendor_deinit(wiphy);

	skw_core_deinit(skw);

	wiphy_free(wiphy);

	atomic_dec(&skw_chip_idx);

	return 0;
}

static struct platform_driver skw_drv = {
	.probe = skw_drv_probe,
	.remove = skw_drv_remove,
	.driver = {
		.owner = THIS_MODULE,
		.name = "sv6316_wireless1",
	},
};

static void skw_global_config_init(struct skw_global_config *gconf)
{
	memset(gconf, 0x0, sizeof(struct skw_global_config));

	atomic_set(&gconf->index, 0);

	/* global */
	gconf->conf.global.dma_addr_align = 4;

	gconf->conf.global.reorder_timeout = 100;

	gconf->conf.fw.link_loss_thrd = 6;

	gconf->conf.fw.band_24ghz = SKW_CHAN_WIDTH_40;

	gconf->conf.fw.cca_en = 0;

#ifdef CONFIG_SKW6316_RX_REORDER_TIMEOUT
	gconf->conf.global.reorder_timeout = CONFIG_SKW6316_RX_REORDER_TIMEOUT;
#endif

#ifdef CONFIG_SKW6316_STA_SME_EXT
	set_bit(SKW_CFG_FLAG_STA_EXT, &gconf->conf.global.flags);
#endif

#ifdef  CONFIG_SKW6316_SAP_SME_EXT
	set_bit(SKW_CFG_FLAG_SAP_EXT, &gconf->conf.global.flags);
#endif

#ifdef CONFIG_SKW6316_REPEATER_MODE
	set_bit(SKW_CFG_FLAG_REPEATER, &gconf->conf.global.flags);
#endif

#ifdef CONFIG_SKW6316_OFFCHAN_TX
	set_bit(SKW_CFG_FLAG_OFFCHAN_TX, &gconf->conf.global.flags);
#endif

	/* interface */
	strcpy(gconf->conf.intf.interface[0].name, "wlan%d");
	gconf->conf.intf.interface[0].inst = SKW_INVALID_ID;
	gconf->conf.intf.interface[0].iftype = NL80211_IFTYPE_STATION;

#ifdef CONFIG_SKW6316_LEGACY_P2P
	set_bit(SKW_CFG_FLAG_P2P_DEV, &gconf->conf.global.flags);
	strcpy(gconf->conf.intf.interface[3].name, "p2p%d");
	gconf->conf.intf.interface[3].inst = 3;
	gconf->conf.intf.interface[3].iftype = NL80211_IFTYPE_P2P_DEVICE;
#endif

	/* regdom */
	gconf->conf.regd.country[0] = '0';
	gconf->conf.regd.country[1] = '0';

#ifdef CONFIG_SKW6316_REGD_SELF_MANAGED
	set_bit(SKW_CFG_REGD_SELF_MANAGED, &gconf->conf.regd.flags);
#endif

#ifdef CONFIG_SKW6316_DEFAULT_COUNTRY
	if (strlen(CONFIG_SKW6316_DEFAULT_COUNTRY) == 2 &&
	    is_skw_valid_reg_code(CONFIG_SKW6316_DEFAULT_COUNTRY))
		memcpy(gconf->conf.regd.country,
		       CONFIG_SKW6316_DEFAULT_COUNTRY, 2);

#endif

	/* calib */
#ifdef CONFIG_SKW6316_CALIB_APPEND_BUS_ID
	set_bit(SKW_CFG_CALIB_STRICT_MODE, &gconf->conf.calib.flags);
#endif

#ifdef CONFIG_SKW6316_CHIP_ID
	if (strlen(CONFIG_SKW6316_CHIP_ID))
		strncpy(gconf->conf.calib.chip, CONFIG_SKW6316_CHIP_ID,
			sizeof(gconf->conf.calib.chip) - 1);
#endif

	strcpy(gconf->conf.calib.project, "SEEKWAVE");

#ifdef CONFIG_SKW6316_PROJECT_NAME
	if (strlen(CONFIG_SKW6316_PROJECT_NAME))
		strncpy(gconf->conf.calib.project, CONFIG_SKW6316_PROJECT_NAME,
			sizeof(gconf->conf.calib.project) - 1);
#endif

	skw_update_config(NULL, "skwifid.dat", &g_skw_config.conf);
}

static int __init skw_module_init(void)
{
	int ret = 0;

	pr_info("[%s] VERSION: %s (%s)\n",
		SKW_TAG_INFO, SKW_VERSION, UTS_RELEASE);

	skw_dentry_init();
	skw_log_level_init();

	skw_power_on_chip();

	skw_global_config_init(&g_skw_config);

	ret = platform_driver_register(&skw_drv);
	if (ret) {
		skw_err("register %s failed, ret: %d\n",
			skw_drv.driver.name, ret);

		skw_power_off_chip();

		skw_log_level_deinit();
		skw_dentry_deinit();
	}

	return ret;
}

static void __exit skw_module_exit(void)
{
	skw_info("unload\n");

	platform_driver_unregister(&skw_drv);

	skw_power_off_chip();

	skw_log_level_deinit();
	skw_dentry_deinit();
}

module_init(skw_module_init);
module_exit(skw_module_exit);

module_param_array_named(mac, skw_mac, byte, NULL, 0444);
MODULE_PARM_DESC(mac, "config mac address");

MODULE_LICENSE("GPL v2");
MODULE_VERSION("1.0.0");
MODULE_AUTHOR("seekwavetech");
