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
#include <linux/etherdevice.h>

#include "skw_core.h"
#include "skw_util.h"
#include "skw_cfg80211.h"

#ifdef CONFIG_PRINTK_TIME_FROM_ARM_ARCH_TIMER
#include <clocksource/arm_arch_timer.h>
u64 skw_local_clock(void)
{
        u64 ns;

        ns = arch_timer_read_counter() * 1000;
        do_div(ns, 24);

        return ns;
}
#else
u64 skw_local_clock(void)
{
        return local_clock();
}
#endif


#ifdef SKW_IMPORT_NS
struct file *skw_file_open(const char *path, int flags, int mode)
{
	struct file *fp = NULL;

	fp = filp_open(path, flags, mode);
	if (IS_ERR(fp)) {
		skw_err("open fail\n");
		return NULL;
	}

	return fp;
}

int skw_file_read(struct file *fp, unsigned char *data,
		size_t size, loff_t offset)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
	return kernel_read(fp, data, size, &offset);
#else
	return kernel_read(fp, offset, data, size);
#endif
}

int skw_file_write(struct file *fp, unsigned char *data,
		size_t size, loff_t offset)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
	return kernel_write(fp, data, size, &offset);
#else
	return kernel_write(fp, data, size, offset);
#endif
}

int skw_file_sync(struct file *fp)
{
	return vfs_fsync(fp, 0);
}

void skw_file_close(struct file *fp)
{
	filp_close(fp, NULL);
}

MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
#endif

void *skw_build_presp_frame(struct wiphy *wiphy, struct skw_iface *iface,
			u8 *da, u8 *sa, u8 *bssid, u8 *ssid, int ssid_len,
			u16 chan, struct ieee80211_supported_band *sband,
			u16 capa, u64 tsf, int beacon_int, void *ie, int ie_len)
{
	u8 *pos;
	int i, rate;
	struct skw_template *temp;
	struct ieee80211_mgmt *mgmt;

	skw_dbg("ssid: %s, bssid: %pM\n", ssid, bssid);

	temp = SKW_ZALLOC(1600, GFP_KERNEL);
	if (!temp)
		return NULL;

	mgmt = temp->mgmt;
	mgmt->frame_control = cpu_to_le16(IEEE80211_FTYPE_MGMT |
					IEEE80211_STYPE_PROBE_RESP);
	memcpy(mgmt->sa, sa, ETH_ALEN);
	memcpy(mgmt->da, da, ETH_ALEN);
	memcpy(mgmt->bssid, bssid, ETH_ALEN);

	mgmt->u.beacon.beacon_int = cpu_to_le16(beacon_int);
	mgmt->u.beacon.timestamp = cpu_to_le64(tsf);
	mgmt->u.beacon.capab_info = cpu_to_le16(capa);

	pos = mgmt->u.beacon.variable;

	*pos++ = WLAN_EID_SSID;
	*pos++ = ssid_len;
	memcpy(pos, ssid, ssid_len);
	pos += ssid_len;

	*pos++ = WLAN_EID_SUPP_RATES;
	*pos++ = SKW_BASIC_RATE_COUNT;
	for (i = 0; i < SKW_BASIC_RATE_COUNT; i++) {
		rate = DIV_ROUND_UP(sband->bitrates[i].bitrate, 5);
		if (sband->bitrates[i].flags & 0x1)
			rate |= 0x80;
		*pos++ = rate;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 7, 0)
	if (sband->band == IEEE80211_BAND_2GHZ) {
#else
	if (sband->band == NL80211_BAND_2GHZ) {
#endif
		*pos++ = WLAN_EID_DS_PARAMS;
		*pos++ = 1;
		*pos++ = chan;
	}

	if (iface->wdev.iftype == NL80211_IFTYPE_ADHOC) {
		*pos++ = WLAN_EID_IBSS_PARAMS;
		*pos++ = 2;
		*pos++ = 0;
		*pos++ = 0;
	}

	*pos++ = WLAN_EID_EXT_SUPP_RATES;
	*pos++ = sband->n_bitrates - SKW_BASIC_RATE_COUNT;
	for (i = SKW_BASIC_RATE_COUNT; i < sband->n_bitrates; i++) {
		rate = DIV_ROUND_UP(sband->bitrates[i].bitrate, 5);
		if (sband->bitrates[i].flags & 0x1)
			rate |= 0x80;
		*pos++ = rate;
	}

	if (ie_len) {
		memcpy(pos, ie, ie_len);
		pos += ie_len;
	}

	return temp;
}

int skw_key_idx(unsigned long bitmap)
{
	static u8 idx[] = {0xff, 0x00, 0x01, 0xff,
			   0x02, 0xff, 0xff, 0xff,
			   0x03, 0xff, 0xff, 0xff,
			   0xff, 0xff, 0xff, 0xff};

	return idx[bitmap & 0xf];
}

int skw_build_deauth_frame(void *buf, int buf_len, u8 *da, u8 *sa,
			u8 *bssid, u16 reason_code)
{
	u16 fc = IEEE80211_FTYPE_MGMT | IEEE80211_STYPE_DEAUTH;
	struct ieee80211_mgmt *mgmt = buf;

	if (!buf || buf_len < SKW_DEAUTH_FRAME_LEN)
		return -EINVAL;

	mgmt->frame_control = cpu_to_le16(fc);
	mgmt->duration = 0;
	mgmt->seq_ctrl = 0;
	skw_ether_copy(mgmt->da, da);
	skw_ether_copy(mgmt->sa, sa);
	skw_ether_copy(mgmt->bssid, bssid);

	mgmt->u.deauth.reason_code = cpu_to_le16(reason_code);

	return SKW_DEAUTH_FRAME_LEN;
}

char *skw_mgmt_name(u16 fc)
{
#define SKW_STYPE_STR(n) {case IEEE80211_STYPE_##n: return #n; }

	switch (fc) {
	SKW_STYPE_STR(ASSOC_REQ);
	SKW_STYPE_STR(ASSOC_RESP);
	SKW_STYPE_STR(REASSOC_REQ);
	SKW_STYPE_STR(REASSOC_RESP);
	SKW_STYPE_STR(PROBE_REQ);
	SKW_STYPE_STR(PROBE_RESP);
	SKW_STYPE_STR(BEACON);
	SKW_STYPE_STR(ATIM);
	SKW_STYPE_STR(DISASSOC);
	SKW_STYPE_STR(AUTH);
	SKW_STYPE_STR(DEAUTH);
	SKW_STYPE_STR(ACTION);

	default:
		break;
	}

#undef SKW_STYPE_STR

	return "UNDEFINE";
}

int skw_freq_to_chn(int freq)
{
	if (freq == 2484)
		return 14;
	else if (freq >= 2407 && freq < 2484)
		return (freq - 2407) / 5;
	else if (freq >= 4910 && freq <= 4980)
		return (freq - 4000) / 5;
	else if (freq >= 5000 && freq <= 45000)
		return (freq - 5000) / 5;
	else if (freq >= 58320 && freq <= 64800)
		return (freq - 56160) / 2160;
	else
		return 0;
}

u32 skw_calc_rate(u64 bytes, u32 delta_ms)
{
	struct skw_tp_rate ret;
	u64 cal_bytes = bytes;
	u16 bps;
	u16 Kbps;
	u16 Mbps;
	u16 Gbps;
	u16 Tbps;

	ret.ret = 0;
	cal_bytes *= 8 * 1000;
	do_div(cal_bytes, delta_ms);
	bps = do_div(cal_bytes, 1 << 10);
	Kbps = do_div(cal_bytes, 1 << 10);
	Mbps = do_div(cal_bytes, 1 << 10);
	Gbps = do_div(cal_bytes, 1 << 10);
	Tbps = cal_bytes;

	if (Tbps) {
		ret.rate.value = Tbps;
		ret.rate.unit = 'T';
		ret.rate.two_dec = Gbps * 100 >> 10;
	} else if (Gbps) {
		ret.rate.value = Gbps;
		ret.rate.unit = 'G';
		ret.rate.two_dec = Mbps * 100 >> 10;
	} else if (Mbps) {
		ret.rate.value = Mbps;
		ret.rate.unit = 'M';
		ret.rate.two_dec = Kbps * 100 >> 10;
	} else {
		ret.rate.value = Kbps;
		ret.rate.unit = 'K';
		ret.rate.two_dec = bps * 100 >> 10;
	}

	return ret.ret;
}

static u32 skw_peer_rate(struct skw_stats_info *stat)
{
	u64 total_bytes, total_jiffies;

	total_bytes = stat->bytes - stat->cal_bytes;
	stat->cal_bytes = stat->bytes;
	total_jiffies = jiffies - stat->cal_time;
	stat->cal_time = jiffies;

	return skw_calc_rate(total_bytes, jiffies_to_msecs(total_jiffies));
}

int skw_tx_throughput(struct skw_iface *iface, u8 *mac)
{
	int ret = 0;
	struct skw_peer_ctx *ctx;


	if (!iface) {
		ret = -ENOENT;
		goto exit;
	}

	if (!mac || is_broadcast_ether_addr(mac)) {
		ret = -EINVAL;
		goto exit;
	}

	ctx = skw_peer_ctx(iface, mac);
	if (!ctx) {
		ret = -ENOENT;
		goto exit;
	}

	skw_peer_ctx_lock(ctx);

	if (ctx->peer)
		ret = skw_peer_rate(&ctx->peer->tx);

	skw_peer_ctx_unlock(ctx);

exit:
	return ret;
}

int skw_rx_throughput(struct skw_iface *iface, u8 *mac)
{
	int ret = 0;
	struct skw_peer_ctx *ctx;


	if (!iface) {
		ret = -ENOENT;
		goto exit;
	}

	if (!mac || is_broadcast_ether_addr(mac)) {
		ret = -EINVAL;
		goto exit;
	}

	ctx = skw_peer_ctx(iface, mac);
	if (!ctx) {
		ret = -ENOENT;
		goto exit;
	}

	skw_peer_ctx_lock(ctx);

	if (ctx->peer)
		ret = skw_peer_rate(&ctx->peer->rx);

	skw_peer_ctx_unlock(ctx);

exit:
	return ret;
}

int skw_tx_throughput_whole(struct skw_iface *iface, u32 *tp)
{
	int idx, ret = 0;
	struct skw_peer_ctx *ctx;
	unsigned long peer_idx_map;

	if (!iface) {
		ret = -ENOENT;
		goto exit;
	}

	peer_idx_map = READ_ONCE(iface->peer_map);

	while (peer_idx_map) {
		idx = ffs(peer_idx_map) - 1;
		SKW_CLEAR(peer_idx_map, BIT(idx));

		ctx = &iface->skw->hw.lmac[iface->lmac_id].peer_ctx[idx];

		skw_peer_ctx_lock(ctx);

		if (ctx->peer)
			*(&(tp[idx])) = skw_peer_rate(&ctx->peer->tx);

		skw_peer_ctx_unlock(ctx);
	}

exit:
	return ret;
}

int skw_rx_throughput_whole(struct skw_iface *iface, u32 *tp)
{
	int idx, ret = 0;
	struct skw_peer_ctx *ctx;
	unsigned long peer_idx_map;


	if (!iface) {
		ret = -ENOENT;
		goto exit;
	}

	peer_idx_map = READ_ONCE(iface->peer_map);

	while (peer_idx_map) {
		idx = ffs(peer_idx_map) - 1;
		SKW_CLEAR(peer_idx_map, BIT(idx));

		ctx = &iface->skw->hw.lmac[iface->lmac_id].peer_ctx[idx];

		skw_peer_ctx_lock(ctx);

		if (ctx->peer)
			*(&(tp[idx])) = skw_peer_rate(&ctx->peer->rx);

		skw_peer_ctx_unlock(ctx);
	}

exit:
	return ret;
}

const u8 *skw_find_ie_match(u8 eid, const u8 *ies, int len, const u8 *match,
			    int match_len, int match_offset)
{
	const struct skw_element *elem;

	/* match_offset can't be smaller than 2, unless match_len is
	 * zero, in which case match_offset must be zero as well.
	 */
	if (WARN_ON((match_len && match_offset < 2) ||
		    (!match_len && match_offset)))
		return NULL;

	skw_foreach_element_id(elem, eid, ies, len) {
		if (elem->datalen >= match_offset - 2 + match_len &&
		    !memcmp(elem->data + match_offset - 2, match, match_len))
			return (void *)elem;
	}

	return NULL;
}

bool skw_bss_check_vendor_name(struct cfg80211_bss *bss, const u8 *oui)
{
	const struct cfg80211_bss_ies *ies;
	const struct skw_element *elem;
	bool ret = false;
	u8 eid = WLAN_EID_VENDOR_SPECIFIC;

	ies = rcu_dereference(bss->beacon_ies);
	if (!ies)
		return false;

	skw_hex_dump("beacon ies:", ies->data, ies->len, false);

	skw_foreach_element_id(elem, eid, ies->data, ies->len) {
		if (!memcmp(elem->data, oui, 3)) {
			ret = true;
			break;
		}
	}

	return ret;
}

int skw_desc_get_rx_rate(struct skw_rate *rate, u8 bw, u8 mode, u8 gi,
		    u8 nss, u8 dcm, u16 data_rate)
{
	u16 skw_supp_bs_rate[] = {
		20, 55, 110,
		/*2M,5.5M,11M*/
	};
	u16 skw_supp_bl_rate[] = {
		10, 20, 55, 110,
		/*1M,2M,5.5M,11M*/
	};
	u16 skw_supp_g_rate[] = {
		60, 90, 120, 180, 240, 360, 480, 540,
		/*6M, 9M, 12M, 18M, 24M, 36M, 48M, 54M*/
	};

	memset(rate, 0x0, sizeof(struct skw_rate));

	rate->bw = bw;
	rate->nss = nss;

	switch (mode) {
	case SKW_PPDUMODE_HT_MIXED:
		rate->flags = SKW_RATE_INFO_FLAGS_HT;
		rate->mcs_idx = 0x3F & data_rate;
		rate->gi = gi;
		break;

	case SKW_PPDUMODE_VHT_SU:
	case SKW_PPDUMODE_VHT_MU:
		rate->flags = SKW_RATE_INFO_FLAGS_VHT;
		rate->mcs_idx = 0xF & data_rate;
		rate->gi = gi;
		break;

	case SKW_PPDUMODE_HE_SU:
	case SKW_PPDUMODE_HE_TB:
	case SKW_PPDUMODE_HE_ER_SU:
	case SKW_PPDUMODE_HE_MU:
		rate->flags = SKW_RATE_INFO_FLAGS_HE;
		rate->mcs_idx = 0xF & data_rate;

		if (dcm) {
			rate->mcs_idx = 0x3 & data_rate;
			rate->he_dcm = dcm;
		} else if (mode == SKW_PPDUMODE_HE_ER_SU) {
			rate->mcs_idx = 0x3 & data_rate;
		}

		rate->gi = gi;

		if (bw != SKW_DESC_BW_USED_RU)
			rate->he_ru = bw + 3;
		break;

	case SKW_PPDUMODE_11B_SHORT:
		rate->flags = SKW_RATE_INFO_FLAGS_LEGACY;

		if (data_rate < sizeof(skw_supp_bs_rate))
			rate->legacy_rate = skw_supp_bs_rate[data_rate];
		else
			skw_warn("illegal 11B_SHORT rate:%d\n", data_rate);
		break;

	case SKW_PPDUMODE_11B_LONG:
		rate->flags = SKW_RATE_INFO_FLAGS_LEGACY;

		if (data_rate < sizeof(skw_supp_bl_rate))
			rate->legacy_rate = skw_supp_bl_rate[data_rate];
		else
			skw_warn("illegal 11B_LONG rate:%d\n", data_rate);
		break;

	case SKW_PPDUMODE_11G:
		rate->flags = SKW_RATE_INFO_FLAGS_LEGACY;

		if (data_rate < sizeof(skw_supp_g_rate))
			rate->legacy_rate = skw_supp_g_rate[data_rate];
		else
			skw_warn("illegal 11G rate:%d\n", data_rate);
		break;

	default:
		skw_warn("unsupport ppdu mode:%d\n", mode);
		break;
	};

	return 0;
}

int skw_tlv_add(struct skw_tlv_conf *conf, int type, void *dat, int dat_len)
{
	struct skw_tlv *tlv;

	if (!conf || !conf->buff)
		return -EINVAL;

	if (conf->total_len + dat_len + 4 > conf->buff_len)
		return -ENOMEM;

	tlv = (struct skw_tlv *)(conf->buff + conf->total_len);
	tlv->type = type;
	tlv->len = dat_len;
	memcpy(tlv->value, dat, dat_len);

	conf->total_len += dat_len + 4;

	return 0;
}

int skw_tlv_alloc(struct skw_tlv_conf *conf, int len, gfp_t gfp)
{
	if (!conf)
		return -EINVAL;

	conf->buff = SKW_ZALLOC(len, GFP_KERNEL);
	if (!conf->buff)
		return -ENOMEM;

	conf->total_len = 0;
	conf->buff_len = len;

	return 0;
}

void *skw_tlv_reserve(struct skw_tlv_conf *conf, int len)
{
	void *start = NULL;

	if (!conf || !conf->buff)
		return NULL;

	if (conf->total_len + len > conf->buff_len)
		return NULL;

	start = conf->buff + conf->total_len;
	conf->total_len += len;

	return start;
}

void skw_tlv_free(struct skw_tlv_conf *conf)
{
	if (conf) {
		SKW_KFREE(conf->buff);
		conf->total_len = 0;
		conf->buff_len = 0;
	}
}

int skw_util_set_mib_enable(struct wiphy *wiphy, int inst, int mib_id, bool enable)
{
	int ret;
	u16 *plen;
	struct skw_tlv_conf conf;
	bool state = !!enable;

	skw_dbg("set %d mib:%d\n", mib_id, enable);

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

	if (skw_tlv_add(&conf, mib_id, &state, 1)) {
		skw_err("set mib failed\n");
		skw_tlv_free(&conf);

		return -EINVAL;
	}

	*plen = conf.total_len;

	ret = skw_msg_xmit(wiphy, inst, SKW_CMD_SET_MIB, conf.buff,
			   conf.total_len, NULL, 0);
	if (ret)
		skw_warn("failed, ret: %d\n", ret);

	skw_tlv_free(&conf);

	return ret;
}
