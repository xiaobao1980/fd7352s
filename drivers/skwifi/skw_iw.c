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

#include <linux/string.h>
#include <linux/ctype.h>
#include <net/iw_handler.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <net/cfg80211-wext.h>

#include "skw_core.h"
#include "skw_cfg80211.h"
#include "skw_iface.h"
#include "skw_iw.h"
#include "skw_log.h"
#include "skw_regd.h"

#if 0
static int skw_iw_commit(struct net_device *dev, struct iw_request_info *info,
			 union iwreq_data *wrqu, char *extra)
{
	skw_dbg("traced\n");

	return 0;
}

static int skw_iw_get_name(struct net_device *dev, struct iw_request_info *info,
			   union iwreq_data *wrqu, char *extra)
{
	skw_dbg("traced\n");

	return 0;
}

static int skw_iw_set_freq(struct net_device *dev, struct iw_request_info *info,
			   union iwreq_data *wrqu, char *extra)
{
	skw_dbg("traced\n");

	return 0;
}

static int skw_iw_get_freq(struct net_device *dev, struct iw_request_info *info,
			   union iwreq_data *wrqu, char *extra)
{
	skw_dbg("traced\n");
	dump_stack();

	return 0;
}

static int skw_iw_set_mode(struct net_device *dev, struct iw_request_info *info,
			   union iwreq_data *wrqu, char *extra)
{
	skw_dbg("traced\n");

	return 0;
}

static int skw_iw_get_mode(struct net_device *dev, struct iw_request_info *info,
			   union iwreq_data *wrqu, char *extra)
{
	skw_dbg("traced\n");

	return 0;
}

static struct iw_statistics *skw_get_wireless_stats(struct net_device *dev)
{
	skw_dbg("traced\n");

	return NULL;
}

static const iw_handler skw_iw_standard_handlers[] = {
	IW_HANDLER(SIOCSIWCOMMIT, (iw_handler)skw_iw_commit),
	IW_HANDLER(SIOCGIWNAME, (iw_handler)skw_iw_get_name),
	IW_HANDLER(SIOCSIWFREQ, (iw_handler)skw_iw_set_freq),
	IW_HANDLER(SIOCGIWFREQ, (iw_handler)skw_iw_get_freq),
	IW_HANDLER(SIOCSIWMODE,	(iw_handler)skw_iw_set_mode),
	IW_HANDLER(SIOCGIWMODE,	(iw_handler)skw_iw_get_mode),
#ifdef CONFIG_CFG80211_WEXT_EXPORT
	IW_HANDLER(SIOCGIWRANGE, (iw_handler)cfg80211_wext_giwrange),
	IW_HANDLER(SIOCSIWSCAN,	(iw_handler)cfg80211_wext_siwscan),
	IW_HANDLER(SIOCGIWSCAN,	(iw_handler)cfg80211_wext_giwscan),
#endif
};
#endif

#ifdef CONFIG_WEXT_PRIV

#define SKW_SET_LEN_64                  64
#define SKW_SET_LEN_128                 128
#define SKW_SET_LEN_256                 256
#define SKW_SET_LEN_512                 512
#define SKW_GET_LEN_512                 512
#define SKW_SET_LEN_1024                1024
#define SKW_GET_LEN_1024                1024
#define SKW_KEEP_BUF_SIZE               1024

/* max to 16 commands */
#define SKW_IW_PRIV_SET                (SIOCIWFIRSTPRIV + 1)
#define SKW_IW_PRIV_GET                (SIOCIWFIRSTPRIV + 3)
#define SKW_IW_PRIV_AT                 (SIOCIWFIRSTPRIV + 5)
#define SKW_IW_PRIV_80211MODE          (SIOCIWFIRSTPRIV + 6)
#define SKW_IW_PRIV_GET_80211MODE      (SIOCIWFIRSTPRIV + 7)
#define SKW_IW_PRIV_KEEP_ALIVE         (SIOCIWFIRSTPRIV + 8)
#define SKW_IW_PRIV_WOW_FILTER         (SIOCIWFIRSTPRIV + 9)

#define SKW_IW_PRIV_LAST               SIOCIWLASTPRIV

static struct skw_keep_active_setup kp_set = {0,};
static u8 skw_wow_flted[256];

static int skw_keep_alive_add_checksum(u8 *buff, u32 len)
{
	u8 *ptr = buff;
	struct iphdr *ip;
	struct udphdr *udp;
	__sum16 sum, sum1;
	u32 udp_len;

	ptr += sizeof(struct ethhdr);
	ip = (struct iphdr *)ptr;
	ip->check = 0;
	ip->check = cpu_to_le16(ip_compute_csum(ip, 20));

	ptr += sizeof(struct iphdr);
	udp = (struct udphdr *)ptr;
	udp->check = 0;

	udp_len = len - sizeof(struct ethhdr)
		 - sizeof(struct iphdr);
	sum1 = csum_partial(ptr,
					udp_len, 0);
	sum = csum_tcpudp_magic(ip->saddr, ip->daddr,
				udp_len, IPPROTO_UDP, sum1);
	udp->check = cpu_to_le16(sum);

	skw_dbg("chsum %x %x\n", ip->check, sum);
	return 0;
}

static int skw_keep_active_rule_save(struct skw_core *skw,
	 struct skw_keep_active_rule *kp, u8 idx, u8 en, u32 flags)
{
	int ret;

	if (!skw || idx >= SKW_KEEPACTIVE_RULE_MAX) {
		ret = -EFAULT;
		return ret;
	}

	if (kp) {
		if (kp_set.rule[idx])
			SKW_KFREE(kp_set.rule[idx]);

		kp_set.rule[idx] = SKW_ZALLOC(kp->payload_len
			 + sizeof(*kp), GFP_KERNEL);
		memcpy(kp_set.rule[idx], kp, kp->payload_len + sizeof(*kp));
		skw_keep_alive_add_checksum(kp_set.rule[idx]->data[0].payload,
				kp_set.rule[idx]->payload_len
				- sizeof(struct skw_keep_active_rule_data));
		kp_set.rule[idx]->data[0].is_chksumed = 0;
		kp_set.flags[idx] = flags;
	}

	if (en)
		kp_set.en_bitmap |= BIT(idx);
	else
		kp_set.en_bitmap &= ~BIT(idx);

	skw_dbg("enable bitmap 0x%x\n", kp_set.en_bitmap);
	skw_hex_dump("kpsave", &kp_set, sizeof(kp_set), false);

	return 0;
}

static int skw_keep_active_disable_cmd(struct net_device *ndev,
	 u16 next_cmd, int next_rules)
{
	struct skw_spd_action_param spd;
	int ret = 0;

	if (!next_rules)
		spd.sub_cmd = ACTION_DIS_ALL_KEEPALIVE;
	else if (next_cmd == ACTION_EN_ALWAYS_KEEPALIVE)
		spd.sub_cmd = ACTION_DIS_KEEPALIVE;
	else
		spd.sub_cmd = ACTION_DIS_ALWAYS_KEEPALIVE;

	spd.len = 0;

	skw_hex_dump("dpdis:", &spd, sizeof(spd), true);
	ret = skw_send_msg(ndev->ieee80211_ptr->wiphy, ndev,
			 SKW_CMD_SET_SPD_ACTION, &spd, sizeof(spd), NULL, 0);
	if (ret)
		skw_err("failed, ret: %d\n", ret);

	return ret;
}

static int skw_keep_active_cmd(struct net_device *ndev, struct skw_core *skw,
		 u8 en, u32 flags)
{
	int ret = 0;
	u32 idx_map, idx, rules = 0;
	int total, fixed, len = 0, offset = 0;
	struct skw_spd_action_param *spd = NULL;
	struct skw_keep_active_param *kp_param = NULL;

	fixed = sizeof(struct skw_spd_action_param) +
		 sizeof(struct skw_keep_active_param);
	total = fixed + SKW_KEEPACTIVE_LENGTH_MAX;

	spd = SKW_ZALLOC(total, GFP_KERNEL);
	if (!spd) {
		skw_err("malloc failed, size: %d\n", total);
		return -ENOMEM;
	}

	kp_param = (struct skw_keep_active_param *)((u8 *)spd
			+ sizeof(*spd));
	offset = fixed;
	idx_map = kp_set.en_bitmap;

	while (idx_map) {
		idx = ffs(idx_map) - 1;
		SKW_CLEAR(idx_map, BIT(idx));

		if (!kp_set.rule[idx]) {
			skw_err("rule exception\n");
			break;
		}

		if (offset + sizeof(struct skw_keep_active_rule)
			 + kp_set.rule[idx]->payload_len > total)
			break;

		memcpy((u8 *)spd + offset, kp_set.rule[idx],
				 sizeof(struct skw_keep_active_rule)
				 + kp_set.rule[idx]->payload_len);

		offset += sizeof(struct skw_keep_active_rule)
			+ kp_set.rule[idx]->payload_len;

		if (kp_set.flags[idx] & SKW_KEEPALIVE_ALWAYS_FLAG)
			spd->sub_cmd = ACTION_EN_ALWAYS_KEEPALIVE;
		else
			spd->sub_cmd = ACTION_EN_KEEPALIVE;

		if (++rules > SKW_KEEPACTIVE_RULE_MAX)
			break;
	}

	kp_param->rule_num = rules;
	spd->len = offset - sizeof(struct skw_spd_action_param);
	len = offset;

	if (en) {
		if (flags & SKW_KEEPALIVE_ALWAYS_FLAG)
			spd->sub_cmd = ACTION_EN_ALWAYS_KEEPALIVE;
		else
			spd->sub_cmd = ACTION_EN_KEEPALIVE;
	}

	ret = skw_keep_active_disable_cmd(ndev, spd->sub_cmd, rules);

	skw_dbg("len:%d rule num:%d\n", len, rules);
	if (rules) {
		skw_hex_dump("actv:", spd, len, true);
		ret = skw_send_msg(ndev->ieee80211_ptr->wiphy, ndev,
				SKW_CMD_SET_SPD_ACTION, spd, len, NULL, 0);
		if (ret)
			skw_err("failed, ret: %d\n", ret);
	}

	SKW_KFREE(spd);
	return ret;
}

//iwpriv wlan0 keep_alive idx=0,en=1,period=1000,flags=0/1,
//pkt=7c:7a:3c:81:e5:72:00:0b
static int skw_keep_active_set(struct net_device *dev, u8 *param, int len)
{
	int result_len = 0;
	u8 *ch, *result_val;
	char *hex = NULL;
	u8 idx, en = 0, get_pkt = 0;
	u32 flags = 0;
	u8 keep_alive[SKW_KEEPACTIVE_LENGTH_MAX];
	struct skw_keep_active_rule *kp =
		(struct skw_keep_active_rule *)keep_alive;
	int pos = 0, ret = 0;
	struct skw_iface *iface = netdev_priv(dev);
	struct skw_core *skw = iface->skw;

	memset(kp, 0, sizeof(*kp));

	hex = param;
	hex = strstr(hex, "idx=");
	if (hex) {
		ch = strsep(&hex, "=");
		if ((ch == NULL) || (strlen(ch) == 0)) {
			skw_err("idx param\n");
			ret = -EFAULT;
			goto error;
		}

		ch = strsep(&hex, ",");
		if ((ch == NULL) || (strlen(ch) == 0)) {
			skw_err("idx param\n");
			ret = -ERANGE;
			goto error;
		}

		ret = kstrtou8(ch, 0, &idx);
		if (ret) {
			skw_err("idx param\n");
			ret = -EINVAL;
			goto error;
		}
	} else {
		skw_err("idx not found\n");
		ret = -EFAULT;
		goto error;
	}

	if (!hex) {
		ret = -EBADF;
		goto error;
	}

	hex = strstr(hex, "en=");
	if (hex) {
		ch = strsep(&hex, "=");
		if ((ch == NULL) || (strlen(ch) == 0)) {
			skw_err("en param\n");
			ret = -EFAULT;
			goto error;
		}

		ch = strsep(&hex, ",");
		if ((ch == NULL) || (strlen(ch) == 0)) {
			skw_err("en param\n");
			ret = -ERANGE;
			goto error;
		}

		ret = kstrtou8(ch, 0, &en);
		if (ret) {
			skw_err("en param\n");
			ret = -EINVAL;
			goto error;
		}
	} else {
		skw_err("en not found\n");
		ret = -EFAULT;
		goto error;
	}

	if (!hex)
		goto done;

	hex = strstr(hex, "period=");
	if (hex) {
		ch = strsep(&hex, "=");
		if ((ch == NULL) || (strlen(ch) == 0)) {
			skw_err("period param\n");
			ret = -EFAULT;
			goto error;
		}

		ch = strsep(&hex, ",");
		if ((ch == NULL) || (strlen(ch) == 0)) {
			skw_err("period param\n");
			ret = -ERANGE;
			goto error;
		}

		ret = kstrtou32(ch, 0, &kp->keep_interval);
		if (ret) {
			skw_err("period param\n");
			ret = -EINVAL;
			goto error;
		}

	}

	if (!hex)
		goto done;

	hex = strstr(hex, "flags=");
	if (hex) {
		ch = strsep(&hex, "=");
		if ((ch == NULL) || (strlen(ch) == 0)) {
			skw_err("flags param\n");
			ret = -EFAULT;
			goto error;
		}

		ch = strsep(&hex, ",");
		if ((ch == NULL) || (strlen(ch) == 0)) {
			skw_err("flags param\n");
			ret = -ERANGE;
			goto error;
		}

		ret = kstrtou32(ch, 0, &flags);
		if (ret) {
			skw_err("flags param\n");
			ret = -EINVAL;
			goto error;
		}
	}

	if (!hex)
		goto done;

	hex = strstr(hex, "pkt=");
	if (hex) {
		ch = strsep(&hex, "=");
		if ((ch == NULL) || (strlen(ch) == 0)) {
			skw_err("pkt param\n");
			ret = -EFAULT;
			goto error;
		}

		result_val = kp->data[0].payload;
		while (1) {
			u8 temp = 0;
			char *cp = strchr(hex, ':');

			if (cp) {
				*cp = 0;
				cp++;
			}

			ret = kstrtou8(hex, 16, &temp);
			if (ret) {
				skw_err("pkt param\n");
				ret = -EINVAL;
				goto error;
			}

			if (temp < 0 || temp > 255) {
				skw_err("pkt param\n");
				ret = -ERANGE;
				goto error;
			}

			result_val[pos] = temp;
			result_len++;
			pos++;

			if (!cp)
				break;

			if (result_len + sizeof(*kp) >=
				SKW_KEEPACTIVE_LENGTH_MAX)
				break;

			hex = cp;
		}
		get_pkt = 1;
	}

	kp->payload_len = result_len + sizeof(struct skw_keep_active_rule_data);

done:
	skw_dbg("idx:%d en:%d pr:%d pkt:%d len:%d\n", idx, en,
		 kp->keep_interval, get_pkt, result_len);
	skw_hex_dump("kp", kp, sizeof(*kp) + kp->payload_len, false);

	if (!(kp->keep_interval && get_pkt))
		kp = NULL;

	ret = skw_keep_active_rule_save(skw, kp, idx, en, flags);
	if (ret) {
		skw_err("save rule\n");
		goto error;
	}

	ret = skw_keep_active_cmd(dev, skw, en, flags);
	if (ret) {
		skw_err("send rule\n");
		goto error;
	}

	return 0;

error:
	skw_err("error:%d\n", ret);
	return ret;
}

//iwpriv wlan0 wow_filter enable,pattern=6+7c:7a:3c:81:e5:72#20+0b#20+!ee:66
//iwpriv wlan0 wow_filter disable
int skw_wow_filter_set(struct net_device *ndev, u8 *param, int len, char *resp)
{
	u8 *ch, *result_val;
	char *hex, *ptr;
	struct skw_spd_action_param *spd = NULL;
	struct skw_wow_input_param *wow_param = NULL;
	struct skw_wow_rule *rule = NULL;
	int pos = 0, ret = 0, rule_idx = 0, offset, total, result_len = 0;
	struct skw_pkt_pattern *ptn;
	u8 data[256];
	u32 temp, resp_len = 0, i;
	char help[] = "Usage:[list]|[disable]|[enable,pattern=6+10#23+!11,pattern=45+31:31]";

	memcpy(data, param, len);
	hex = data;
	ptr = hex;

	if (!strcmp(hex, "list")) {
		if (len != sizeof("list")) {
			resp_len = sprintf(resp, "ERROR: %s\n %s\n",
				"list cmd", help);
			return -EFAULT;
		}
		resp_len = sprintf(resp, "List: %s\n", skw_wow_flted);
		resp_len += sprintf(resp + resp_len, "%s\n", "OK");
		return ret;
	}

	if (!strcmp(hex, "disable")) {
		if (len != sizeof("disable")) {
			resp_len = sprintf(resp, "ERROR: %s\n %s\n",
				 "dis cmd", help);
			return -EFAULT;
		}
		ret = skw_wow_disable(ndev->ieee80211_ptr->wiphy);
		if (!ret) {
			memset(skw_wow_flted, 0, sizeof(skw_wow_flted));
			memcpy(skw_wow_flted, param, len);
		}

		resp_len = sprintf(resp, "%s\n", "OK");
		return ret;
	}

	ret = strncmp(hex, "enable", strlen("enable"));
	if (ret) {
		resp_len = sprintf(resp, "ERROR: %s\n %s\n",
			 "en cmd", help);
		return -EFAULT;
	}

	hex += strlen("enable");
	if (hex >= ptr + len - 1) {
		resp_len = sprintf(resp, "ERROR: %s\n %s\n",
			 "en cmd", help);
		return -EFAULT;
	}

	total = sizeof(struct skw_spd_action_param) +
		sizeof(struct skw_wow_input_param) +
		sizeof(struct skw_wow_rule) * SKW_MAX_WOW_RULE_NUM;

	spd = SKW_ZALLOC(total, GFP_KERNEL);
	if (!spd) {
		skw_err("malloc failed, size: %d\n", total);
		resp_len = sprintf(resp, "ERROR: %s\n", "malloc failed");
		return -ENOMEM;
	}

	wow_param = (struct skw_wow_input_param *)((u8 *)spd
		+ sizeof(*spd));
	spd->sub_cmd = ACTION_EN_WOW;
	wow_param->wow_flags |= SKW_WOW_BLACKLIST_FILTER;

	while (hex < ptr + len - 1) {
		rule = &wow_param->rules[rule_idx];
		result_len = 0;

		ret = strncmp(hex, ",pattern=", strlen(",pattern="));
		if (!ret) {
			hex += strlen(",pattern=");
			result_val = rule->rule;

			while (hex < ptr + len - 1) {
				ret = sscanf(hex, "%d+%02x",
					&offset, &temp);
				if (ret != 2) {
					ret = sscanf(hex, "%d+!%02x",
						&offset, &temp);
					if (ret != 2) {
						resp_len = sprintf(resp,
							"ERROR: %s\n",
							"match char + +!");
						ret = -EINVAL;
						goto err;
					}
				}

				if (offset > ETH_DATA_LEN) {
					resp_len = sprintf(resp,
						"ERROR: offset:%d over limit\n",
						offset);
					ret = -EINVAL;
					goto err;
				}

				ptn = (struct skw_pkt_pattern *)result_val;
				result_val += sizeof(*ptn);
				result_len += sizeof(*ptn);

				if (result_len >= sizeof(rule->rule)) {
					resp_len = sprintf(resp,
						"ERROR: %s\n",
						"ptn over limit\n");
					break;
				}

				ptn->op = PAT_TYPE_ETH;
				ptn->offset = offset;

				ch = strsep(&hex, "+");
				if ((ch == NULL) || (strlen(ch) == 0)) {
					resp_len = sprintf(resp,
						"ERROR: %s\n",
						"match char +\n");
					ret = -EINVAL;
					goto err;
				}

				if (hex[0] == '!') {
					ptn->type_offset = PAT_OP_TYPE_DIFF;
					ch = strsep(&hex, "!");
				}

				pos = 0;
				while (hex < ptr + len - 1) {
					char *cp;

					if (isxdigit(hex[0]) &&
						isxdigit(hex[1]) &&
						(sscanf(hex, "%2x", &temp)
							== 1)) {
					} else {
						resp_len = sprintf(resp,
							"ERROR: match char %c%c end\n",
							hex[0], hex[1]);
						ret = -EINVAL;
						goto err;
					}

					result_val[pos] = temp;
					result_len++;
					pos++;

					if (result_len >= sizeof(rule->rule)) {
						resp_len = sprintf(resp,
							"ERROR: %s\n",
							"size over limit\n");
						break;
					}

					if (hex[2] == ',' || hex[2] == '#')
						break;
					else if (hex[2] == '\0') {
						hex += 2;
						break;
					} else  if (hex[2] != ':') {
						resp_len = sprintf(resp,
							"ERROR: char data %c\n",
							hex[2]);
						ret = -EINVAL;
						goto err;
					}

					cp = strchr(hex, ':');
					if (cp) {
						*cp = 0;
						cp++;
					}

					hex = cp;
				}
				result_val += pos;
				ptn->len = pos;

				if (hex[2] == ',') {
					hex += 2;
					break;
				} else if (hex[2] == '#')
					ch = strsep(&hex, "#");
			}
		} else {
			resp_len = sprintf(resp, "ERROR: %s\n",
				"match char pattern=\n");
			ret = -EINVAL;
			goto err;
		}

		rule->len = result_len;
		rule_idx++;
		skw_hex_dump("rule", rule, sizeof(*rule), false);

		if (rule_idx > SKW_MAX_WOW_RULE_NUM)
			break;
	}

	if (!rule_idx) {
		resp_len = sprintf(resp, "ERROR: %s\n", "no rule\n");
		ret = -EINVAL;
		goto err;
	}

	for (i = 0; i < rule_idx; i++)
		if (!wow_param->rules[i].len) {
			resp_len = sprintf(resp, "ERROR: %s\n", "rule len 0\n");
			ret = -EINVAL;
			goto err;
		}

	wow_param->rule_num = rule_idx;
	spd->len = sizeof(struct skw_wow_input_param) +
		sizeof(struct skw_wow_rule) * rule_idx;

	skw_dbg("len:%d %d\n", spd->len, total);
	skw_hex_dump("wow", spd, total, true);

	ret = skw_send_msg(ndev->ieee80211_ptr->wiphy, ndev,
		 SKW_CMD_SET_SPD_ACTION, spd, total, NULL, 0);
	if (ret)
		skw_err("failed, ret: %d\n", ret);
	else {
		memset(skw_wow_flted, 0, sizeof(skw_wow_flted));
		memcpy(skw_wow_flted, param, len);
	}

err:
	if (ret)
		resp_len += sprintf(resp + resp_len, " %s\n", help);
	else
		resp_len = sprintf(resp, "%s\n", "OK");

	SKW_KFREE(spd);
	return ret;
}

static int skw_iwpriv_keep_alive(struct net_device *dev,
			struct iw_request_info *info,
			union iwreq_data *wrqu, char *extra)
{
	char *param;
	char help[] = "ERROR useage:[idx=0,en=0/1,period=100,flags=0/1,pkt=7c:11]";
	int ret = 0;

	WARN_ON(SKW_KEEP_BUF_SIZE < wrqu->data.length);

	param = SKW_ZALLOC(SKW_KEEP_BUF_SIZE, GFP_KERNEL);
	if (!param) {
		ret = -ENOMEM;
		goto out;
	}

	if (copy_from_user(param, wrqu->data.pointer, sizeof(param))) {
		skw_err("copy failed, length: %d\n",
			wrqu->data.length);

		ret = -EFAULT;
		goto free;
	}

	skw_dbg("cmd: 0x%x, (len: %d)\n",
		info->cmd, wrqu->data.length);
	skw_hex_dump("param:", param, sizeof(param), false);

	ret = skw_keep_active_set(dev, param, sizeof(param));
	if (ret)
		memcpy(extra, help, sizeof(help));
	else
		memcpy(extra, "OK", sizeof("OK"));

	wrqu->data.length = SKW_GET_LEN_512;

	skw_dbg("resp: %s\n", extra);

free:
	SKW_KFREE(param);

out:
	return ret;
}

static int skw_iwpriv_wow_filter(struct net_device *dev,
			struct iw_request_info *info,
			union iwreq_data *wrqu, char *extra)
{
	char param[256];

	WARN_ON(sizeof(param) < wrqu->data.length);

	if (copy_from_user(param, wrqu->data.pointer, sizeof(param))) {
		skw_err("copy failed, length: %d\n",
			wrqu->data.length);

		return -EFAULT;
	}

	param[255] = '\0';

	skw_dbg("cmd: 0x%x, (len: %d)\n",
		info->cmd, wrqu->data.length);
	skw_hex_dump("flt", param, sizeof(param), false);

	skw_wow_filter_set(dev, param, min_t(int, sizeof(param),
			(int)wrqu->data.length), extra);

	wrqu->data.length = SKW_GET_LEN_512;

	skw_dbg("resp: %s\n", extra);
	return 0;
}

static int skw_send_at_cmd(struct skw_core *skw, char *cmd, int cmd_len,
			char *buf, int buf_len)
{
	int ret, len, resp_len, offset;
 	char *command, *resp;

	len = round_up(cmd_len, 4);
	if (len > SKW_SET_LEN_256)
		return -E2BIG;

	command = SKW_ZALLOC(SKW_SET_LEN_512, GFP_KERNEL);
	if (!command) {
		ret = -ENOMEM;
		goto out;
	}

	offset = (long)command & 0x7;
	if (offset) {
		offset = 8 - offset;
		skw_detail("command: %px, offset: %d\n", command, offset);
	}

	resp_len = round_up(buf_len, skw->hw_pdata->align_value);
	resp = SKW_ZALLOC(resp_len, GFP_KERNEL);
	if (!resp) {
		ret = -ENOMEM;
		goto fail_alloc_resp;
	}

	ret = skw_uart_open(skw);
	if (ret < 0)
		goto failed;

	memcpy(command + offset, cmd, cmd_len);
	ret = skw_uart_write(skw, command + offset, len);
	if (ret < 0)
		goto failed;

	ret = skw_uart_read(skw, resp, resp_len);
	if (ret < 0)
		goto failed;

	memcpy(buf, resp, buf_len);
	ret = 0;

failed:
	SKW_KFREE(resp);

fail_alloc_resp:
	SKW_KFREE(command);
out:
	if (ret < 0)
		skw_err("failed: ret: %d\n", ret);

	return ret;
}

static int skw_iwpriv_mode(struct net_device *dev,
			   struct iw_request_info *info,
			   union iwreq_data *wrqu, char *extra)
{
	int i;
	char param[32] = {0};
	struct skw_iface *iface = (struct skw_iface *)netdev_priv(dev);

	struct skw_iw_wireless_mode {
		char *name;
		enum skw_wireless_mode mode;
	} modes[] = {
		{"11B", SKW_WIRELESS_11B},
		{"11G", SKW_WIRELESS_11G},
		{"11A", SKW_WIRELESS_11A},
		{"11N", SKW_WIRELESS_11N},
		{"11AC", SKW_WIRELESS_11AC},
		{"11AX", SKW_WIRELESS_11AX},
		{"11G_ONLY", SKW_WIRELESS_11G_ONLY},
		{"11N_ONLY", SKW_WIRELESS_11N_ONLY},

		/*keep last*/
		{NULL, 0}
	};

	WARN_ON(sizeof(param) < wrqu->data.length);

	if (copy_from_user(param, wrqu->data.pointer, sizeof(param))) {
		skw_err("copy failed, length: %d\n",
			wrqu->data.length);

		return -EFAULT;
	}

	skw_dbg("cmd: 0x%x, %s(len: %d)\n",
		info->cmd, param, wrqu->data.length);

	for (i = 0; modes[i].name; i++) {
		if (!strcmp(modes[i].name, param)) {
			iface->extend.wireless_mode = modes[i].mode;
			return 0;
		}
	}

	return -EINVAL;
}

static int skw_iwpriv_get_mode(struct net_device *dev,
			struct iw_request_info *info,
			union iwreq_data *wrqu, char *extra)
{
	skw_dbg("traced\n");
	return 0;
}

static int skw_iwpriv_help(struct skw_iface *iface, void *param, char *args,
			char *resp, int resp_len)
{
	int len = 0;
	struct skw_iwpriv_cmd *cmd = param;

	len = sprintf(resp, "%s:\n", cmd->help_info);
	cmd++;

	while (cmd->handler) {
		len += sprintf(resp + len, "%-4.4s %s\n", "", cmd->help_info);
		cmd++;
	}

	return 0;
}

static int skw_iwpriv_set_bandcfg(struct skw_iface *iface, void *param,
		char *args, char *resp, int resp_len)
{
	u16 res;
	int ret;

	if (args == NULL)
		return -EINVAL;

	ret = kstrtou16(args, 10, &res);
	if (!ret && res < 3) {
		if (res == 0)
			iface->extend.scan_band_filter = 0;
		else if (res == 1)
			iface->extend.scan_band_filter = BIT(NL80211_BAND_2GHZ);
		else if (res == 2)
			iface->extend.scan_band_filter = BIT(NL80211_BAND_5GHZ);

		sprintf(resp, "ok");
	} else
		sprintf(resp, "failed");

	return ret;
}

static int skw_iwpriv_get_noise(struct skw_iface *iface, void *param,
							char *args, char *resp, int resp_len)
{
	int ret = -1;
	struct skw_station_params params = {0};
	struct skw_get_sta_resp get_sta_resp = {0};
	struct skw_core *skw = NULL;
	struct wiphy *wiphy = NULL;
	struct net_device *dev = NULL;

	skw = iface->skw;
	wiphy = priv_to_wiphy(skw);
	dev = iface->ndev;
	skw_ether_copy(params.mac, iface->addr);

	ret = skw_send_msg(wiphy, dev, SKW_CMD_GET_STA, &params,
						sizeof(params), &get_sta_resp,
						sizeof(struct skw_get_sta_resp));
	if (ret) {
		skw_warn("failed, ret: %d\n", ret);
		return ret;
	}

	skw_dbg("noise %d, signal %d\n", get_sta_resp.noise, get_sta_resp.signal);

	return 0;
}

static int skw_iwpriv_get_bandcfg(struct skw_iface *iface, void *param,
		char *args, char *resp, int resp_len)
{
	if (!iface->extend.scan_band_filter)
		sprintf(resp, "bandcfg=%s", "Auto");
	else if (iface->extend.scan_band_filter & BIT(NL80211_BAND_2GHZ))
		sprintf(resp, "bandcfg=%s", "2G");
	else if (iface->extend.scan_band_filter & BIT(NL80211_BAND_5GHZ))
		sprintf(resp, "bandcfg=%s", "5G");

	return 0;
}

int skw_set_cca_thre_ofdm(struct wiphy *wiphy, struct net_device *dev,
								struct skw_cca_thre_ofdm *p_ofdm)

{
	int ret = 0;
	u16 *plen;
	struct skw_tlv_conf conf;

	ret = skw_tlv_alloc(&conf, 512, GFP_KERNEL);
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

	if (skw_tlv_add(&conf, SKW_MIB_SET_CCA_THRE_OFDM, p_ofdm, sizeof(struct skw_cca_thre_ofdm))) {
		skw_err("add cca thre ofdm tlv failed\n");
		skw_tlv_free(&conf);

	return -EINVAL;
	}

	if (conf.total_len) {
		*plen = conf.total_len;
		ret = skw_send_msg(wiphy, dev, SKW_CMD_SET_MIB, conf.buff,
		conf.total_len, NULL, 0);
	if (ret)
		skw_err("failed, ret: %d\n", ret);

	}

	skw_tlv_free(&conf);

	return ret;
}

int skw_set_cca_thre_11b(struct wiphy *wiphy, struct net_device *dev,
								struct skw_cca_thre_11b *p_cca_11b)

{
	int ret = 0;
	u16 *plen;
	struct skw_tlv_conf conf;

	ret = skw_tlv_alloc(&conf, 512, GFP_KERNEL);
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

	if (skw_tlv_add(&conf, SKW_MIB_SET_CCA_THRE_11B, p_cca_11b, sizeof(struct skw_cca_thre_11b))) {
		skw_err("add cca thre 11b tlv failed\n");
		skw_tlv_free(&conf);

	return -EINVAL;
	}

	if (conf.total_len) {
		*plen = conf.total_len;
		ret = skw_send_msg(wiphy, dev, SKW_CMD_SET_MIB, conf.buff,
		conf.total_len, NULL, 0);
	if (ret)
		skw_err("failed, ret: %d\n", ret);

	}

	skw_tlv_free(&conf);

	return ret;
}

int skw_set_cca_thre_nowifi(struct wiphy *wiphy, struct net_device *dev,
								struct skw_cca_thre_nowifi *p_nowifi)

{
	int ret = 0;
	u16 *plen;
	struct skw_tlv_conf conf;

	ret = skw_tlv_alloc(&conf, 512, GFP_KERNEL);
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

	if (skw_tlv_add(&conf, SKW_MIB_SET_CCA_THRE_NOWIFI, p_nowifi, sizeof(struct skw_cca_thre_nowifi))) {
		skw_err("add cca thre nowifi tlv failed\n");
		skw_tlv_free(&conf);

	return -EINVAL;
	}

	if (conf.total_len) {
		*plen = conf.total_len;
		ret = skw_send_msg(wiphy, dev, SKW_CMD_SET_MIB, conf.buff,
		conf.total_len, NULL, 0);
	if (ret)
		skw_err("failed, ret: %d\n", ret);

	}

	skw_tlv_free(&conf);

	return ret;
}


int skw_set_edca_params(struct wiphy *wiphy, struct net_device *dev,
								struct skw_edca_param_s *p_edca_params)

{
	int ret = 0;
	u16 *plen;
	struct skw_tlv_conf conf;

	ret = skw_tlv_alloc(&conf, 512, GFP_KERNEL);
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

	if (skw_tlv_add(&conf, SKW_MIB_SET_EDCA_PARAM, p_edca_params, sizeof(struct skw_edca_param_s))) {
		skw_err("add max ppdu dur tlv failed\n");
		skw_tlv_free(&conf);

	return -EINVAL;
	}

	if (conf.total_len) {
		*plen = conf.total_len;
		ret = skw_send_msg(wiphy, dev, SKW_CMD_SET_MIB, conf.buff,
		conf.total_len, NULL, 0);
	if (ret)
		skw_err("failed, ret: %d\n", ret);

	}

	skw_tlv_free(&conf);

	return ret;
}

int skw_set_max_ppdu_dur(struct wiphy *wiphy, struct net_device *dev,
									struct skw_max_ppdu_dur *p_mppdu_dur)

{
	int ret = 0;
	u16 *plen;
	struct skw_tlv_conf conf;

	skw_dbg("idx: %d, max ppdu dur %d\n", p_mppdu_dur->idx, p_mppdu_dur->max_ppdu_dur);

	ret = skw_tlv_alloc(&conf, 512, GFP_KERNEL);
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

	if (skw_tlv_add(&conf, SKW_MIB_SET_MAX_PPDU_DUR, p_mppdu_dur, 4)) {
		skw_err("add max ppdu dur tlv failed\n");
		skw_tlv_free(&conf);

	return -EINVAL;
	}

	if (conf.total_len) {
		*plen = conf.total_len;
		ret = skw_send_msg(wiphy, dev, SKW_CMD_SET_MIB, conf.buff,
		conf.total_len, NULL, 0);
	if (ret)
		skw_err("failed, ret: %d\n", ret);

	}

	skw_tlv_free(&conf);

  return ret;
}

int skw_set_force_rts_rate(struct wiphy *wiphy, struct net_device *dev,
									struct skw_force_rts_rate *rate)

{
	int ret = 0;
	u16 *plen;
	struct skw_tlv_conf conf;

	skw_dbg("2.4G rate: %d, 5G rate %d\n", rate->rts_rate_24G, rate->rts_rate_5G);

	ret = skw_tlv_alloc(&conf, 512, GFP_KERNEL);
	if (ret) {
		skw_err("alloc failed\n");
		return ret;
	}

	plen = skw_tlv_reserve(&conf, 2);
	if (!plen) {
		skw_err("reserve force rts rate tlv failed\n");
		skw_tlv_free(&conf);
		return -ENOMEM;
	}

	if (skw_tlv_add(&conf, SKW_MIB_SET_FORCE_RTS_RATE, rate, 4)) {
		skw_err("add force rts rate tlv failed\n");
		skw_tlv_free(&conf);

	return -EINVAL;
	}

	if (conf.total_len) {
		*plen = conf.total_len;
		ret = skw_send_msg(wiphy, dev, SKW_CMD_SET_MIB, conf.buff,
		conf.total_len, NULL, 0);
	if (ret)
		skw_err("failed, ret: %d\n", ret);

	}

	skw_tlv_free(&conf);

  return ret;
}

int skw_set_force_rx_rsp_rate(struct wiphy *wiphy, struct net_device *dev,
									struct skw_force_rx_rsp_rate *rate)

{
	int ret = 0;
	u16 *plen;
	struct skw_tlv_conf conf;

	skw_dbg("11b long rate: %d, 11b short rate %d, ofdm rate %d\n", rate->rx_rsp_rate_11b_long,
			rate->rx_rsp_rate_11b_short, rate->rx_rsp_rate_ofdm);

	ret = skw_tlv_alloc(&conf, 512, GFP_KERNEL);
	if (ret) {
		skw_err("alloc failed\n");
		return ret;
	}

	plen = skw_tlv_reserve(&conf, 2);
	if (!plen) {
		skw_err("reserve force rx rsp rate tlv failed\n");
		skw_tlv_free(&conf);
		return -ENOMEM;
	}

	if (skw_tlv_add(&conf, SKW_MIB_SET_FORCE_RX_RSP_RATE, rate, 4)) {
		skw_err("add force rx rsp rate tlv failed\n");
		skw_tlv_free(&conf);

	return -EINVAL;
	}

	if (conf.total_len) {
		*plen = conf.total_len;
		ret = skw_send_msg(wiphy, dev, SKW_CMD_SET_MIB, conf.buff,
		conf.total_len, NULL, 0);
	if (ret)
		skw_err("failed, ret: %d\n", ret);

	}

	skw_tlv_free(&conf);

  return ret;
}

int skw_set_scan_time_cmd(struct wiphy *wiphy, struct net_device *dev,
									struct skw_set_scan_time *time)

{
	int ret = 0;
	u16 *plen;
	struct skw_tlv_conf conf;

	skw_dbg("active dwell time: %d, bypass active scan auto time %d\n", time->active_dwell_time,
			time->bypass_active_acan_auto_time);

	ret = skw_tlv_alloc(&conf, 512, GFP_KERNEL);
	if (ret) {
		skw_err("alloc failed\n");
		return ret;
	}

	plen = skw_tlv_reserve(&conf, 2);
	if (!plen) {
		skw_err("reserve scan time failed\n");
		skw_tlv_free(&conf);
		return -ENOMEM;
	}

	if (skw_tlv_add(&conf, SKW_MIB_SET_SCAN_TIME, time, 2)) {
		skw_err("add scan time failed\n");
		skw_tlv_free(&conf);

	return -EINVAL;
	}

	if (conf.total_len) {
		*plen = conf.total_len;
		ret = skw_send_msg(wiphy, dev, SKW_CMD_SET_MIB, conf.buff,
		conf.total_len, NULL, 0);
	if (ret)
		skw_err("failed, ret: %d\n", ret);
	}

	skw_tlv_free(&conf);

  return ret;
}

int skw_set_tcp_disconn_wakeup_host(struct wiphy *wiphy, struct net_device *dev,
									struct skw_set_tcpd_wakeup_host *flag)

{
	int ret = 0;
	u16 *plen;
	struct skw_tlv_conf conf;

	skw_dbg("wakeup host:%d\n", flag->enable);

	ret = skw_tlv_alloc(&conf, 512, GFP_KERNEL);
	if (ret) {
		skw_err("alloc failed\n");
		return ret;
	}

	plen = skw_tlv_reserve(&conf, 2);
	if (!plen) {
		skw_err("reserve wakeup host flag failed\n");
		skw_tlv_free(&conf);
		return -ENOMEM;
	}

	if (skw_tlv_add(&conf, SKW_MIB_SET_TCP_DISCONN_WAKEUP_HOST, flag, 2)) {
		skw_err("add wakeup host flag failed\n");
		skw_tlv_free(&conf);

	return -EINVAL;
	}

	if (conf.total_len) {
		*plen = conf.total_len;
		ret = skw_send_msg(wiphy, dev, SKW_CMD_SET_MIB, conf.buff,
		conf.total_len, NULL, 0);
	if (ret)
		skw_err("failed, ret: %d\n", ret);
	}

	skw_tlv_free(&conf);

  return ret;
}

int skw_set_rc_min_rate(struct wiphy *wiphy, struct net_device *dev,
									struct skw_set_rate_control_min_rate *rate)
{
	int ret = 0;
	u16 *plen;
	struct skw_tlv_conf conf;

	skw_dbg("rc min rate:%d\n", rate->rstrict_min_rate);

	ret = skw_tlv_alloc(&conf, 512, GFP_KERNEL);
	if (ret) {
		skw_err("alloc failed\n");
		return ret;
	}

	plen = skw_tlv_reserve(&conf, 2);
	if (!plen) {
		skw_err("reserve rc min rate failed\n");
		skw_tlv_free(&conf);
		return -ENOMEM;
	}

	if (skw_tlv_add(&conf, SKW_MIB_SET_RATE_CTRL_MIN_RATE, rate, 2)) {
		skw_err("add rc min rate failed\n");
		skw_tlv_free(&conf);

	return -EINVAL;
	}

	if (conf.total_len) {
		*plen = conf.total_len;
		ret = skw_send_msg(wiphy, dev, SKW_CMD_SET_MIB, conf.buff,
		conf.total_len, NULL, 0);
	if (ret)
		skw_err("failed, ret: %d\n", ret);
	}

	skw_tlv_free(&conf);

  return ret;
}

int skw_set_rate_control_rate_change(struct wiphy *wiphy, struct net_device *dev,
									struct skw_set_rate_control_rate_change *rate)
{
	int ret = 0;
	u16 *plen;
	struct skw_tlv_conf conf;

	ret = skw_tlv_alloc(&conf, 512, GFP_KERNEL);
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

	if (skw_tlv_add(&conf, SKW_MIB_SET_RATE_CTRL_RATE_CHANGE_PARAM, rate, 2)) {
		skw_err("add failed\n");
		skw_tlv_free(&conf);

	return -EINVAL;
	}

	if (conf.total_len) {
		*plen = conf.total_len;
		ret = skw_send_msg(wiphy, dev, SKW_CMD_SET_MIB, conf.buff,
		conf.total_len, NULL, 0);
	if (ret)
		skw_err("failed, ret: %d\n", ret);
	}

	skw_tlv_free(&conf);

	return ret;
}

int skw_set_rc_spe_rate(struct wiphy *wiphy, struct net_device *dev,
									struct skw_set_rate_control_special_rate *rate)
{
	int ret = 0;
	u16 *plen;
	struct skw_tlv_conf conf;

	ret = skw_tlv_alloc(&conf, 512, GFP_KERNEL);
	if (ret) {
		skw_err("alloc tlv failed\n");
		return ret;
	}

	plen = skw_tlv_reserve(&conf, 2);
	if (!plen) {
		skw_err("reserve tlv failed\n");
		skw_tlv_free(&conf);
		return -ENOMEM;
	}

	if (skw_tlv_add(&conf, SKW_MIB_SET_RATE_CTRL_SPECIAL_FRM_RATE, rate, 2)) {
		skw_err("add tlv failed\n");
		skw_tlv_free(&conf);

	return -EINVAL;
	}

	if (conf.total_len) {
		*plen = conf.total_len;
		ret = skw_send_msg(wiphy, dev, SKW_CMD_SET_MIB, conf.buff,
		conf.total_len, NULL, 0);
	if (ret)
		skw_err("failed, ret: %d\n", ret);
	}

	skw_tlv_free(&conf);

  return ret;
}

static int skw_iwpriv_set_max_ppdu_dur(struct skw_iface *iface, void *param,
	char *args, char *resp, int resp_len)
{
	int ret = 0;
	char *p = NULL;
	struct skw_max_ppdu_dur max_ppdu_dur = {0};

	if (!args)
		return -EINVAL;

	skw_err("\nskw_iwpriv_set_max_ppdu_dur args %s\n", args);

	p = strchr(args, ',');
	if(!p)
	{
		skw_err("idx not found\n");
		return -ENOTSUPP;
	} else {
		skw_err("idx found %s\n", p - 1);
		max_ppdu_dur.idx = simple_strtol(p - 1, NULL, 10);
		if (max_ppdu_dur.idx < 0 || max_ppdu_dur.idx > 5) {
			skw_err("idx out of range\n");
			return -EINVAL;
		}
	}

	p = p + strlen(",");

	if(!p)
	{
		skw_err("mppdu dur not found\n");
		return -ENOTSUPP;
	} else {
		skw_err("mppdu dur found %s\n", p);
		max_ppdu_dur.max_ppdu_dur = simple_strtol(p, NULL, 10);
		switch (max_ppdu_dur.idx) {
			case 0:
				if (max_ppdu_dur.max_ppdu_dur > 0xFFFF) {
					max_ppdu_dur.max_ppdu_dur = 0xFFFF;
					skw_warn("The max ppdu dur of idx 0 is 0xFFFF\n");
				}
				break;
			case 1:
				if (max_ppdu_dur.max_ppdu_dur > 0x7FFF) {
					max_ppdu_dur.max_ppdu_dur = 0x7FFF;
					skw_warn("The max ppdu dur of idx 1 is 0x7FFF\n");
				}
				break;
			case 2:
			case 3:
			case 4:
			case 5:
				if (max_ppdu_dur.max_ppdu_dur > 0x1FFF) {
					max_ppdu_dur.max_ppdu_dur = 0x1FFF;
					skw_warn("The max ppdu dur of idx 1 is 0x1FFF\n");
				}
				break;
			default:
				break;
		}
	}

	skw_err("max ppdu dur idx %d, dur %d\n", max_ppdu_dur.idx, max_ppdu_dur.max_ppdu_dur);

	ret = skw_set_max_ppdu_dur(iface->wdev.wiphy, iface->ndev, &max_ppdu_dur);

	if (!ret ) {
		sprintf(resp, "set max ppdu dur ok ");
	} else
		sprintf(resp, "set max ppdu dur failed");

	return ret;
}

static u16 skw_iwpriv_convert_string_to_u (char *ptr, u8 length)
{
	char *buffer = NULL;
	unsigned long num = 0;
	int ret = 0;

	buffer = kmalloc(length + 1, GFP_KERNEL);
	if (!buffer) {
		skw_err("mem alloc failed\n");
		return -ENOMEM;
	}
	memcpy(buffer, ptr, length);
	buffer[length] = '\0';

	ret = kstrtoul(buffer, 0, &num);
	if (ret == 0) {
		if (num <= 0xFFFF) {
			kfree(buffer);
			return (u16)num;
		} else if (num <= 0xFF) {
			kfree(buffer);
			return (u8)num;
		} else {
			skw_err("tred beyond u8 and u16\n");
			kfree(buffer);
			return -ERANGE;
		}
	} else {
		skw_err("transfer fail\n");
		kfree(buffer);
		return -EINVAL;
	}
}

static u32 skw_iwpriv_convert_string_to_u32(char *ptr, unsigned int length)
{
	if (ptr == NULL || length <= 0) {
		skw_err("Invalid input parameters");
		return -EINVAL;
	}

	if (length >= 2 && ptr[0] == '0' && (ptr[1] == 'x' || ptr[1] == 'X')) {
		char *buffer = NULL;
		unsigned long num = 0;
		int ret = 0;

		buffer = kmalloc(length + 1, GFP_KERNEL);
		if (!buffer) {
			skw_err("mem alloc failed\n");
			return -ENOMEM;
		}
		memcpy(buffer, ptr, length);
		buffer[length] = '\0';

		ret = kstrtoul(buffer, 16, &num);
		if (ret == 0) {
			if (num <= 0xFFFFFFFF) {
			kfree(buffer);
			return (u32)num;
		} else {
			skw_err("value exceeds u32 range");
			kfree(buffer);
			return -ERANGE;
		}
		} else {
			skw_err("hex conversion failed");
			kfree(buffer);
			return -EINVAL;
		}
	} else {
		skw_err("not a valid hex string");
		return -EINVAL;
	}
}

static int skw_iwpriv_set_edca_params(struct skw_iface *iface, void *param,
									char *args, char *resp, int resp_len)
{
	int ret = 0;
	char *p = NULL, *q = NULL;
	struct skw_edca_param_s edca_params = {0};
	u8 parmas_len = 0;

	if (!args)
		return -EINVAL;

	skw_err("skw_iwpriv_set_edca_params args %s\n", args);

	parmas_len = strlen(args);

	if (parmas_len == 1) {
		ret = simple_strtol(args, NULL, 10);
		if (!ret){
			skw_dbg(" not set edca params\n");
			edca_params.enable = 0;
			goto SETPARA;
		} else if (ret == 1){
			skw_err(" need more edca params\n");
			goto SETFAIL;
		} else
			goto SETFAIL;
	} else if (parmas_len > 1){
		p = strchr(args, ',');
		if(!p)
		{
			skw_err("flag not found\n");
			return -ENOTSUPP;
		} else {
			skw_err("params found %s\n", p -1);
			edca_params.enable = simple_strtol(p - 1, NULL, 10);
			if (edca_params.enable != 0 && edca_params.enable != 1) {
				skw_err("flag error %d\n", edca_params.enable);
				return -EINVAL;
			} else {
				if (edca_params.enable == 0) {
					skw_err("not set edca params\n");
					goto SETPARA;
				} else {
					skw_err("start set edca params ...\n");
				}
			}
		}
	}

	/* parse AC_BE parametes */
	/** AciAifn **/
	//p = p + strlen(",");
	q = strchr(p + 1, ',');
	skw_warn("len %d\n",(u8) (q - 1 - p));
	if(!p || !q)
	{
		skw_err("AC_BE AciAifn not found\n");
		return -ENOTSUPP;
	} else {
		//edca_params.ac_best_effort.aci_aifn = simple_strtol(p, NULL, 10);
		edca_params.ac_best_effort.aci_aifn = (u8)skw_iwpriv_convert_string_to_u(p + 1, q - p - 1);
		if (edca_params.ac_best_effort.aci_aifn > 0xFF){
			skw_warn("AC_BE AciAifn limit is 0xFF\n");
			edca_params.ac_best_effort.aci_aifn = 0xFF;
		}
	}
	skw_dbg("AC_BE Set AciAifn %d\n", edca_params.ac_best_effort.aci_aifn);


	//return 0;
	/** EcWminEcWmax **/
	p = q;
	q = strchr(p + 1, ',');
	if(!p || !q)
	{
		skw_err("AC_BE EcWminEcWmax not found\n");
		return -ENOTSUPP;
	} else {
		//edca_params.ac_best_effort.ec_wmin_wmax = simple_strtol(p, NULL, 10);
		edca_params.ac_best_effort.ec_wmin_wmax = (u8)skw_iwpriv_convert_string_to_u(p + 1, q - p - 1);
		if (edca_params.ac_best_effort.ec_wmin_wmax > 0xFF){
			skw_dbg("AC_BE EcWminEcWmax limit is 0xFF\n");
			edca_params.ac_best_effort.ec_wmin_wmax = 0xFF;
		}
	}
	skw_dbg("AC_BE Set EcWminEcWmax %d\n", edca_params.ac_best_effort.ec_wmin_wmax);

	/** TxopLimit **/
	p = q;
	q = strchr(p + 1, ',');
	if(!p || !q)
	{
		skw_err("AC_BE TxopLimit not found\n");
		return -ENOTSUPP;
	} else {
		//edca_params.ac_best_effort.txop_limit = simple_strtol(p, NULL, 10);
		edca_params.ac_best_effort.txop_limit = skw_iwpriv_convert_string_to_u(p + 1, q - p - 1);
		if (edca_params.ac_best_effort.txop_limit > 0xFFFF){
			skw_dbg("AC_BE TxopLimit limit is 0xFF\n");
			edca_params.ac_best_effort.txop_limit = 0xFFFF;
		}
	}
	skw_dbg("AC_BE Set TxopLimit %d\n", edca_params.ac_best_effort.txop_limit);

	/* parse AC_BG parametes */
	/** AciAifn **/
	p = q;
	q = strchr(p + 1, ',');
	if(!p || !q)
	{
		skw_err("AC_BG AciAifn not found\n");
		return -ENOTSUPP;
	} else {
		//edca_params.ac_background.aci_aifn = simple_strtol(p, NULL, 10);
		edca_params.ac_background.aci_aifn = skw_iwpriv_convert_string_to_u(p + 1, q - p - 1);
		if (edca_params.ac_background.aci_aifn > 0xFF){
			skw_warn("AC_BG AciAifn limit is 0xFF\n");
			edca_params.ac_background.aci_aifn = 0xFF;
		}
	}
	skw_err("AC_BG Set AciAifn %d\n", edca_params.ac_background.aci_aifn);

	/** EcWminEcWmax **/
	p = q;
	q = strchr(p + 1, ',');
	if(!p || !q)
	{
		skw_err("AC_BG EcWminEcWmax not found\n");
		return -ENOTSUPP;
	} else {
		//edca_params.ac_background.ec_wmin_wmax = simple_strtol(p, NULL, 10);
		edca_params.ac_background.ec_wmin_wmax = skw_iwpriv_convert_string_to_u(p + 1, q - p - 1);
		if (edca_params.ac_background.ec_wmin_wmax > 0xFF){
			skw_warn("AC_BG EcWminEcWmax limit is 0xFF\n");
			edca_params.ac_background.ec_wmin_wmax = 0xFF;
		}
	}
	skw_err("AC_BG Set EcWminEcWmax %d\n", edca_params.ac_background.ec_wmin_wmax);

	/** TxopLimit **/
	p = q;
	q = strchr(p + 1, ',');
	if(!p || !q)
	{
		skw_err("AC_BG TxopLimit not found\n");
		return -ENOTSUPP;
	} else {
		//edca_params.ac_best_effort.txop_limit = simple_strtol(p, NULL, 10);
		edca_params.ac_background.txop_limit = skw_iwpriv_convert_string_to_u(p + 1, q - p - 1);
		if (edca_params.ac_background.txop_limit > 0xFFFF){
			skw_warn("AC_BG TxopLimit limit is 0xFF\n");
			edca_params.ac_background.txop_limit = 0xFFFF;
		}
	}
	skw_err("AC_BG Set TxopLimit %d\n", edca_params.ac_best_effort.txop_limit);

	/* parse AC_VIDEO parametes */
	/** AciAifn **/
	p = q;
	q = strchr(p + 1, ',');
	if(!p || !q)
	{
		skw_err("AC_VIDEO AciAifn not found\n");
		return -ENOTSUPP;
	} else {
		edca_params.ac_video.aci_aifn = skw_iwpriv_convert_string_to_u(p + 1, q - p - 1);
		if (edca_params.ac_video.aci_aifn > 0xFF){
			skw_warn("AC_VIDEO AciAifn limit is 0xFF\n");
			edca_params.ac_video.aci_aifn = 0xFF;
		}
	}
	skw_err("AC_VIDEO Set AciAifn %d\n", edca_params.ac_video.aci_aifn);

	/** EcWminEcWmax **/
	p = q;
	q = strchr(p + 1, ',');
	if(!p || !q)
	{
		skw_err("AC_VIDEO EcWminEcWmax not found\n");
		return -ENOTSUPP;
	} else {
		edca_params.ac_video.ec_wmin_wmax = skw_iwpriv_convert_string_to_u(p + 1, q - p - 1);
		if (edca_params.ac_video.ec_wmin_wmax > 0xFF){
			skw_warn("AC_VIDEO EcWminEcWmax limit is 0xFF\n");
			edca_params.ac_video.ec_wmin_wmax = 0xFF;
		}
	}
	skw_err("AC_VIDEO Set EcWminEcWmax %d\n", edca_params.ac_video.ec_wmin_wmax);

	/** TxopLimit **/
	p = q;
	q = strchr(p + 1, ',');
	if(!p || !q)
	{
		skw_err("AC_VIDEO TxopLimit not found\n");
		return -ENOTSUPP;
	} else {
		edca_params.ac_video.txop_limit = skw_iwpriv_convert_string_to_u(p + 1, q - p - 1);
		if (edca_params.ac_video.txop_limit > 0xFFFF){
			skw_warn("AC_VIDEO TxopLimit limit is 0xFF\n");
			edca_params.ac_video.txop_limit = 0xFFFF;
		}
	}
	skw_err("AC_VIDEO Set TxopLimit %d\n", edca_params.ac_video.txop_limit);

	/* parse AC_VOICE parametes */
	/** AciAifn **/
	p = q;
	q = strchr(p + 1, ',');
	if(!p || !q)
	{
		skw_err("AC_VOICE AciAifn not found\n");
		return -ENOTSUPP;
	} else {
		edca_params.ac_voice.aci_aifn = skw_iwpriv_convert_string_to_u(p + 1, q - p - 1);
		if (edca_params.ac_voice.aci_aifn > 0xFF){
			skw_warn("AC_VOICE AciAifn limit is 0xFF\n");
			edca_params.ac_voice.aci_aifn = 0xFF;
		}
	}
	skw_err("AC_VOICE Set AciAifn %d\n", edca_params.ac_voice.aci_aifn);

	/** EcWminEcWmax **/
	p = q;
	q = strchr(p + 1, ',');
	if(!p || !q)
	{
		skw_err("AC_VOICE EcWminEcWmax not found\n");
		return -ENOTSUPP;
	} else {
		edca_params.ac_voice.ec_wmin_wmax = skw_iwpriv_convert_string_to_u(p + 1, q - p - 1);
		if (edca_params.ac_voice.ec_wmin_wmax > 0xFF){
			skw_warn("AC_VOICE EcWminEcWmax limit is 0xFF\n");
			edca_params.ac_voice.ec_wmin_wmax = 0xFF;
		}
	}
	skw_err("AC_VOICE Set EcWminEcWmax %d\n", edca_params.ac_voice.ec_wmin_wmax);

	/** TxopLimit **/
	p = q;
	q = strchr(p + 1, ',');
	if(!p)
	{
		skw_err("AC_VOICE TxopLimit not found\n");
		return -ENOTSUPP;
	} else {
		edca_params.ac_voice.txop_limit = simple_strtol(p + 1, NULL, 10);
		if (edca_params.ac_voice.txop_limit > 0xFFFF){
			skw_warn("AC_VOICE TxopLimit limit is 0xFF\n");
			edca_params.ac_voice.txop_limit = 0xFFFF;
		}
	}
	skw_err("AC_VOICE Set TxopLimit %d\n", edca_params.ac_voice.txop_limit);

SETPARA:

	ret = skw_set_edca_params(iface->wdev.wiphy, iface->ndev, &edca_params);

	if (!ret ) {
		sprintf(resp, "set edca params ok ");
	} else
		sprintf(resp, "set edca params failed");

	return ret;

SETFAIL:

	sprintf(resp, "set edca params failed");

	return -EINVAL;

}

static int skw_iwpriv_set_cca_thre_nowifi(struct skw_iface *iface, void *param,
	char *args, char *resp, int resp_len)
{
	int ret = 0;
	char *p = NULL;
	struct skw_cca_thre_nowifi nowifi = {0};
	int temp_val = 0;

	if (!args)
		return -EINVAL;

	skw_err("\n skw_iwpriv_set_cca_thre_nowifi args %s\n", args);

	p = args;
	if(!p)
	{
		skw_err("nowifi not found\n");
		return -ENOTSUPP;
	} else {
		skw_err("nowifi found %s\n", p);
		temp_val = simple_strtol(p, NULL, 10);
		if (temp_val >= 0 || temp_val < -255) {
			skw_warn("The max CCA Thre NOWIFI is 0xFF\n");
			return -EINVAL;
		}
		nowifi.val = 0 - temp_val;
	}

	skw_err("Set CCA Thre NOWIFI %d\n", nowifi.val);

	ret = skw_set_cca_thre_nowifi(iface->wdev.wiphy, iface->ndev, &nowifi);

	if (!ret ) {
		sprintf(resp, "set CCA Thre NOWIFI ok ");
	} else
		sprintf(resp, "set CCA Thre NOWIFI failed");

	return ret;
}

static int skw_iwpriv_set_cca_thre_11b(struct skw_iface *iface, void *param,
	char *args, char *resp, int resp_len)
{
	int ret = 0;
	char *p = NULL;
	struct skw_cca_thre_11b cca_11b = {0};
	int temp_val = 0;

	if (!args)
		return -EINVAL;

	skw_err("\n skw_iwpriv_set_cca_thre_11b args %s\n", args);

	p = args;
	if(!p)
	{
		skw_err("11b not found\n");
		return -ENOTSUPP;
	} else {
		skw_err("11b found %s\n", p);
		temp_val = simple_strtol(p, NULL, 10);
		if (temp_val >= 0 || temp_val < -255) {
			skw_warn("The max CCA Thre 11b is 0xFF\n");
			return -EINVAL;
		}
		cca_11b.val = 0 - temp_val;
	}

	skw_err("Set CCA Thre 11b %d\n", cca_11b.val);

	ret = skw_set_cca_thre_11b(iface->wdev.wiphy, iface->ndev, &cca_11b);

	if (!ret ) {
		sprintf(resp, "set CCA Thre 11b ok ");
	} else
		sprintf(resp, "set CCA Thre 11b failed");

	return ret;
}

static int skw_iwpriv_set_cca_thre_ofdm(struct skw_iface *iface, void *param,
	char *args, char *resp, int resp_len)
{
	int ret = 0;
	char *p = NULL;
	struct skw_cca_thre_ofdm ofdm = {0};
	int temp_val = 0;

	if (!args)
		return -EINVAL;

	skw_warn("\n skw_iwpriv_set_cca_thre_ofdm args %s\n", args);

	p = args;
	if(!p)
	{
		skw_err("ofdm not found\n");
		return -ENOTSUPP;
	} else {
		skw_err("ofdm found %s\n", p);
		temp_val = simple_strtol(p, NULL, 10);
		if (temp_val >= 0 || temp_val < -255) {
			skw_warn("The max CCA Thre ofdm is 0xFF\n");
			return -EINVAL;
		}
		ofdm.val = 0 - temp_val;
	}

	skw_err("Set CCA Thre OFDM %d\n", ofdm.val);

	ret = skw_set_cca_thre_ofdm(iface->wdev.wiphy, iface->ndev, &ofdm);

	if (!ret ) {
		sprintf(resp, "set CCA Thre ofdm ok ");
	} else
		sprintf(resp, "set CCA Thre ofdm failed");

	return ret;
}

int skw_is_value_in_enum(u8 value) {
	switch (value) {
		case LEGA_11B_SHORT_2M:
		case LEGA_11B_SHORT_55M:
		case LEGA_11B_SHORT_11M:
		case LEGA_11B_LONG_1M:
		case LEGA_11B_LONG_2M:
		case LEGA_11B_LONG_55M:
		case LEGA_11B_LONG_11M:
		case OFDM_6M:
		case OFDM_9M:
		case OFDM_12M:
		case OFDM_18M:
		case OFDM_24M:
		case OFDM_36M:
		case OFDM_48M:
		case OFDM_54M:
		case HT_MCS_0:
		case HT_MCS_1:
		case HT_MCS_2:
		case HT_MCS_3:
		case HT_MCS_4:
		case HT_MCS_5:
		case HT_MCS_6:
		case HT_MCS_7:
		case HT_MCS_8:
		case HT_MCS_9:
		case HT_MCS_10:
		case HT_MCS_11:
		case HT_MCS_12:
		case HT_MCS_13:
		case HT_MCS_14:
		case HT_MCS_15:
		case HT_MCS_16:
		case HT_MCS_17:
		case HT_MCS_18:
		case HT_MCS_19:
		case HT_MCS_20:
		case HT_MCS_21:
		case HT_MCS_22:
		case HT_MCS_23:
		case HT_MCS_24:
		case HT_MCS_25:
		case HT_MCS_26:
		case HT_MCS_27:
		case HT_MCS_28:
		case HT_MCS_29:
		case HT_MCS_30:
		case HT_MCS_31:
		case VHT_MCS_0:
		case VHT_MCS_1:
		case VHT_MCS_2:
		case VHT_MCS_3:
		case VHT_MCS_4:
		case VHT_MCS_5:
		case VHT_MCS_6:
		case VHT_MCS_7:
		case VHT_MCS_8:
		case VHT_MCS_9:
		case HE_MCS_0:
		case HE_MCS_1:
		case HE_MCS_2:
		case HE_MCS_3:
		case HE_MCS_4:
		case HE_MCS_5:
		case HE_MCS_6:
		case HE_MCS_7:
		case HE_MCS_8:
		case HE_MCS_9:
		case HE_MCS_10:
		case HE_MCS_11:
		case ER_NDCM_1SS_242TONE_MCS0:
		case ER_NDCM_1SS_242TONE_MCS1:
		case ER_NDCM_1SS_242TONE_MCS2:
		case ER_NDCM_1SS_106TONE_MCS0:
		case ER_DCM_1SS_242TONE_MCS0:
		case ER_DCM_1SS_242TONE_MCS1:
		case ER_DCM_1SS_106TONE_MCS0:
		case NER_DCM_1SS_MCS0:
		case NER_DCM_1SS_MCS1:
		case NER_DCM_1SS_MCS3:
		case NER_DCM_1SS_MCS4:
		case NER_DCM_2SS_MCS0:
		case NER_DCM_2SS_MCS1:
		case NER_DCM_2SS_MCS3:
		case NER_DCM_2SS_MCS4:
			return 1;
		default:
			return 0;
	}
}

static int skw_iwpriv_set_force_rts_rate(struct skw_iface *iface, void *param,
	char *args, char *resp, int resp_len)
{
	int ret = 0;
	char *p = NULL, *q = NULL;
	struct skw_force_rts_rate rts_rate = {0};
	u8 parmas_len = 0, val = 0;

	if (!args)
		return -EINVAL;

	skw_warn("skw_iwpriv_set_force_rts_rate args %s\n", args);

	/* parse rts rate flag */
	parmas_len = strlen(args);

	if (parmas_len == 1) {
		ret = simple_strtol(args, NULL, 10);
		if (!ret){
			skw_warn(" not force set rts rate\n");
			rts_rate.enable = 0;
			goto SETPARA;
		} else if (ret == 1){
			skw_warn(" need more rate params\n");
			goto SETFAIL;
		} else
			goto SETFAIL;
	} else if (parmas_len > 1) {
		p = strchr(args, ',');
		if(!p)
		{
			skw_err("flag not found\n");
			return -ENOTSUPP;
		} else {
			skw_warn("params found %s\n", p -1);
			rts_rate.enable = simple_strtol(p - 1, NULL, 10);
			if (rts_rate.enable != 0 && rts_rate.enable != 1) {
				skw_err("flag error %d\n", rts_rate.enable);
				return -EINVAL;
			} else {
				if (rts_rate.enable == 0) {
					skw_err("not set rts_rate params\n");
					goto SETPARA;
				} else {
					skw_err("start set rts_rate params ...\n");
				}
			}
		}
	}

	q = strchr(p + 1, ',');
	if(!p || !q)
	{
		skw_err("rts rate 2.4G not found\n");
		return -ENOTSUPP;
	} else {
		val = (u8)skw_iwpriv_convert_string_to_u(p + 1, q - p - 1);
		if (skw_is_value_in_enum(val))
				rts_rate.rts_rate_24G = val;
		else {
			skw_warn("invalid 2.4G rate %d\n", val);
			return -EINVAL;
		}
	}
	skw_dbg("rts rate 2.4G: %d\n", rts_rate.rts_rate_24G);

	p = q;
	q = strchr(p + 1, ',');
	if(!p)
	{
		skw_err("rts rate 5G not found\n");
		return -ENOTSUPP;
	} else {
		val = (u8)skw_iwpriv_convert_string_to_u(p + 1, q - p - 1);
		if (skw_is_value_in_enum(val))
				rts_rate.rts_rate_5G = val;
		else {
			skw_warn("invalid 5G rate %d\n", val);
			return -EINVAL;
		}
	}
	skw_dbg("rts_rate_5G: %d\n", rts_rate.rts_rate_5G);

SETPARA:
	ret = skw_set_force_rts_rate(iface->wdev.wiphy, iface->ndev, &rts_rate);

	if (!ret ) {
		sprintf(resp, "set force rts rate ok ");
	} else
		sprintf(resp, "set force rts rate failed");

	return ret;

SETFAIL:

	sprintf(resp, "set force rts rate failed");

	return -EINVAL;
}

static int skw_iwpriv_set_force_rx_rsp_rate(struct skw_iface *iface, void *param,
	char *args, char *resp, int resp_len)
{
	int ret = 0;
	char *p = NULL, *q = NULL;
	struct skw_force_rx_rsp_rate rate = {0};
	u8 parmas_len = 0, val = 0;

	if (!args)
		return -EINVAL;

	skw_warn("skw_iwpriv_set_force_rts_rate args %s\n", args);

	/* parse rts rate flag */
	parmas_len = strlen(args);

	if (parmas_len == 1) {
		ret = simple_strtol(args, NULL, 10);
		if (!ret){
			skw_warn(" not force set rx rsp rate\n");
			goto SETPARA;
		} else if (ret == 1){
			skw_warn(" need more rate params\n");
			goto SETFAIL;
		} else
			goto SETFAIL;
	} else if (parmas_len > 1){
		p = strchr(args, ',');
		if(!p)
		{
			skw_err("flag not found\n");
			return -ENOTSUPP;
		} else {
			skw_warn("params found %s\n", p -1);
			rate.enable = simple_strtol(p - 1, NULL, 10);
			if (rate.enable != 0 && rate.enable != 1) {
				skw_err("flag error %d\n", rate.enable);
				return -EINVAL;
			} else {
				if (rate.enable == 0) {
					skw_err("not set rx rsp rate params\n");
					goto SETPARA;
				} else {
					skw_err("start set rx rsp rate params ...\n");
				}
			}
		}
	}

	q = strchr(p + 1, ',');
	if(!p || !q)
	{
		skw_err("11b long not found\n");
		return -ENOTSUPP;
	} else {
		val = (u8)skw_iwpriv_convert_string_to_u(p + 1, q - p - 1);
		if (skw_is_value_in_enum(val)) {
				rate.rx_rsp_rate_11b_long = val;
		} else {
			skw_warn("invalid 11b long rate %d\n", val);
			return -EINVAL;
		}
	}
	skw_dbg("11b long rate: %d\n", rate.rx_rsp_rate_11b_long);

	p = q;
	q = strchr(p + 1, ',');
	if(!p || !q)
	{
		skw_err("11b short not found\n");
		return -ENOTSUPP;
	} else {
		val = (u8)skw_iwpriv_convert_string_to_u(p + 1, q - p - 1);
		if (skw_is_value_in_enum(val)) {
				rate.rx_rsp_rate_11b_short = val;
		} else {
			skw_warn("invalid 11b short rate %d\n", val);
			return -EINVAL;
		}
	}
	skw_dbg("11b short rate: %d\n", rate.rx_rsp_rate_11b_short);

	p = q;
	q = strchr(p + 1, ',');
	if(!p)
	{
		skw_err("ofdm not found\n");
		return -ENOTSUPP;
	} else {
		val = (u8)skw_iwpriv_convert_string_to_u(p + 1, q - p - 1);
		if (skw_is_value_in_enum(val)) {
			rate.rx_rsp_rate_ofdm = val;
		} else {
			skw_warn("invalid ofdm rate %d\n", val);
			return -EINVAL;
		}
	}
	skw_dbg("ofdm: %d\n", rate.rx_rsp_rate_ofdm);

SETPARA:
	ret = skw_set_force_rx_rsp_rate(iface->wdev.wiphy, iface->ndev, &rate);

	if (!ret ) {
		sprintf(resp, "set force rx rsp rate ok ");
	} else
		sprintf(resp, "set force rx rsp rate failed");

	return ret;

SETFAIL:
	sprintf(resp, "set force rts rate failed");
	return -EINVAL;
}

static int skw_iwpriv_set_scan_time(struct skw_iface *iface, void *param,
	char *args, char *resp, int resp_len)
{
	int ret = 0;
	char *p = NULL, *q = NULL;
	struct skw_set_scan_time time = {0};
	u8 parmas_len = 0;
	u16 val = 0;

	if (!args)
		return -EINVAL;

	skw_warn("skw_iwpriv_set_scan_time args %s\n", args);

	/* parse rts rate flag */
	parmas_len = strlen(args);

	p = args;
	q = strchr(args, ',');
	if(!q)
	{
		skw_err("parameter error\n");
		return -ENOTSUPP;
	} else {
		skw_warn("params found %s\n", p -1);
		val = skw_iwpriv_convert_string_to_u(p, q - p);
		if (val > 0xFF){
			skw_warn("active dwell limit to 0xFF\n");
			time.active_dwell_time = 0xFF;
		} else {
			time.active_dwell_time = val;
		}
	}
	skw_dbg("active dwell time: %d\n", time.active_dwell_time);

	p = q + strlen(",");
	if(!p)
	{
		skw_warn("bypass active scan auto time flag not found\n");
		return -ENOTSUPP;
	} else {
		val = simple_strtol(p, NULL, 10);
		if (val != 0 && val != 1) {
			skw_err("flag error %d\n", val);
			return -EINVAL;
		} else {
			time.bypass_active_acan_auto_time = val;
		}
	}
	skw_dbg("bypass active scan auto time: %d\n", time.bypass_active_acan_auto_time);

	ret = skw_set_scan_time_cmd(iface->wdev.wiphy, iface->ndev, &time);

	if (!ret ) {
		sprintf(resp, "set scan time ok ");
	} else
		sprintf(resp, "set scan time failed");

	return ret;

}

static int skw_iwpriv_set_tcpd_wakeup_host(struct skw_iface *iface, void *param,
	char *args, char *resp, int resp_len)
{
	int ret = 0;
	struct skw_set_tcpd_wakeup_host set_flag = {0};
	u8 parmas_len = 0;

	if (!args)
		return -EINVAL;

	skw_warn("set_tcpd_wakeup_host args %s\n", args);

	parmas_len = strlen(args);

	if (parmas_len == 1) {
		ret = simple_strtol(args, NULL, 10);
		if (!ret){
			skw_dbg("flag: %d\n", ret);
			set_flag.enable = 0;
		} else if (ret == 1){
			skw_dbg("flag: %d\n", ret);
			set_flag.enable = 1;
		} else
			goto SETFAIL;
	} else if (parmas_len > 1){
		skw_err("params error\n");
		goto SETFAIL;
	}

	skw_dbg("wakeup host: %d\n", set_flag.enable);

	ret = skw_set_tcp_disconn_wakeup_host(iface->wdev.wiphy, iface->ndev, &set_flag);

	if (!ret ) {
		sprintf(resp, "set tcp disc wakeup host ok ");
	} else
		sprintf(resp, "set tcp disc wakeup host failed");

	return ret;

SETFAIL:
	sprintf(resp, "set tcp disc wakeup host failed(param error)");
	return ret;
}

static int skw_iwpriv_set_rc_min_rate(struct skw_iface *iface, void *param,
	char *args, char *resp, int resp_len)
{
	int ret = 0;
	struct skw_set_rate_control_min_rate rate = {0};
	u8 parmas_len = 0, val = 0;
	char *p = NULL;

	if (!args)
		return -EINVAL;

	skw_dbg("set_rc_min_rate args %s\n", args);

	parmas_len = strlen(args);
	if (!parmas_len)
		return -EINVAL;

	p = args;
	val = (u8)skw_iwpriv_convert_string_to_u(p, parmas_len);
	if (skw_is_value_in_enum(val)) {
		rate.rstrict_min_rate = val;
	} else {
		skw_dbg("val not valid %d\n",val);
		goto SETFAIL;
	}

	skw_dbg("rc min rate: %d\n", rate.rstrict_min_rate);

	ret = skw_set_rc_min_rate(iface->wdev.wiphy, iface->ndev, &rate);

	if (!ret ) {
		sprintf(resp, "set rc min rate ok ");
	} else
		sprintf(resp, "set set rc min rate failed");

	return ret;

SETFAIL:
	sprintf(resp, "set set rc min rate failed (value not support)");
	return ret;
}

static int skw_iwpriv_set_rc_rate_change(struct skw_iface *iface, void *param,
	char *args, char *resp, int resp_len)
{
	int ret = 0;
	char *p = NULL, *q = NULL;
	struct skw_set_rate_control_rate_change rate = {0};

	if (!args)
		return -EINVAL;

	skw_dbg("set_rc_rate_change args %s\n", args);

	//1/5 up rate class num
	p = args;
	q = strchr(args, ',');
	if(!p || !q)
	{
		skw_err("up rate class num not found\n");
		return -ENOTSUPP;
	} else {
		rate.up_rate_class_num = (u8)skw_iwpriv_convert_string_to_u(p, q - p);
	}
	skw_dbg("up_rate_class_num: %d\n", rate.up_rate_class_num);

	//2/5 down rate class num
	p = q;
	q = strchr(p + 1, ',');
	if(!p || !q)
	{
		skw_err("down rate class num not found\n");
		return -ENOTSUPP;
	} else {
		rate.down_rate_class_num = (u8)skw_iwpriv_convert_string_to_u(p + 1, q - p - 1);
	}
	skw_dbg("down_rate_class_num: %d\n", rate.down_rate_class_num);

	//3/5 hw rty limit
	p = q;
	q = strchr(p + 1, ',');
	if(!p || !q)
	{
		skw_err("hw rty limit not found\n");
		return -ENOTSUPP;
	} else {
		rate.hw_rty_limit = (u8)skw_iwpriv_convert_string_to_u(p + 1, q - p - 1);
	}
	skw_dbg("hw_rty_limit: %d\n", rate.hw_rty_limit);

	//4/5 per rate hw rty limit
	p = q;
	q = strchr(p + 1, ',');
	if(!p || !q)
	{
		skw_err("per rate hw rty limit not found\n");
		return -ENOTSUPP;
	} else {
		rate.per_rate_hw_rty_limit = (u8)skw_iwpriv_convert_string_to_u(p + 1, q - p - 1);
	}
	skw_dbg("per rate hw_rty_limit: %d\n", rate.per_rate_hw_rty_limit);

	//5/5 per rate probe hw rty limit
	p = q;
	q = strchr(p + 1, ',');
	if(!p)
	{
		skw_err("per rate probe hw rty limit not found\n");
		return -ENOTSUPP;
	} else {
		rate.per_rate_probe_hw_rty_limit = (u8)skw_iwpriv_convert_string_to_u(p + 1, q - p - 1);
	}
	skw_dbg("per rate probe hw_rty_limit: %d\n", rate.per_rate_probe_hw_rty_limit);

	ret = skw_set_rate_control_rate_change(iface->wdev.wiphy, iface->ndev, &rate);

	if (!ret ) {
		sprintf(resp, "set force rx rsp rate ok ");
	} else
		sprintf(resp, "set force rx rsp rate failed");

	return ret;
}

static int skw_iwpriv_set_rc_spe_rate(struct skw_iface *iface, void *param,
	char *args, char *resp, int resp_len)
{
	int ret = 0;
	struct skw_set_rate_control_special_rate rate = {0};
	u8 parmas_len = 0, val = 0;
	char *p = NULL;

	if (!args)
		return -EINVAL;

	parmas_len = strlen(args);
	if (!parmas_len)
		return -EINVAL;

	p = args;
	val = (u8)skw_iwpriv_convert_string_to_u(p, parmas_len);
	if (skw_is_value_in_enum(val)) {
		rate.special_frm_rate = val;
	} else {
		skw_dbg("val not valid %d\n",val);
		goto SETFAIL;
	}

	skw_dbg("rc special rate: %d\n", rate.special_frm_rate);

	ret = skw_set_rc_spe_rate(iface->wdev.wiphy, iface->ndev, &rate);

	if (!ret ) {
		sprintf(resp, "set rc special rate ok ");
	} else
		sprintf(resp, "set set rc special rate failed");

	return ret;

SETFAIL:
	sprintf(resp, "set set rc spe rate failed (value not support)");
	return ret;
}
static int skw_generic_tlv_operation(struct wiphy *wiphy, struct net_device *dev,
									void *param, size_t param_len, enum SKW_MIB_ID tlv_type)
{
	int ret = 0;
	u16 *plen;
	struct skw_tlv_conf conf;
	struct skw_tlv_get_assign_addr_rsp resp = {0};

	ret = skw_tlv_alloc(&conf, 512, GFP_KERNEL);
	if (ret) {
		skw_err("alloc tlv failed\n");
		return ret;
	}

	plen = skw_tlv_reserve(&conf, 2);
	if (!plen) {
		skw_err("reserve tlv failed\n");
		skw_tlv_free(&conf);
		return -ENOMEM;
	}

	if (skw_tlv_add(&conf, tlv_type, param, param_len)) {
		skw_err("add tlv failed\n");
		skw_tlv_free(&conf);
		return -EINVAL;
	}

	if (conf.total_len) {
		*plen = conf.total_len;
		if (tlv_type == SKW_MIB_GET_ASSIGN_ADDR_VAL_E) {
			ret = skw_send_msg(wiphy, dev, SKW_CMD_SET_MIB, conf.buff,
			conf.total_len, &resp, sizeof(resp));

			if (ret) {
				skw_err("failed, ret: %d\n", ret);
				goto SETFAIL;
			}
			skw_dbg("read done val: 0x%08x\n", resp.val);
		} else {
			ret = skw_send_msg(wiphy, dev, SKW_CMD_SET_MIB, conf.buff,
			conf.total_len, NULL, 0);

			if (ret) {
				skw_err("failed, ret: %d\n", ret);
				goto SETFAIL;
			}
		}
	}

	SETFAIL:
		skw_tlv_free(&conf);
		return ret;
}

static int skw_set_tx_lifetime(struct wiphy *wiphy, struct net_device *dev, struct skw_tlv_set_tx_lifetime *lifetime)
{
	return skw_generic_tlv_operation(wiphy, dev, lifetime, sizeof(struct skw_tlv_set_tx_lifetime), SKW_MIB_SET_TX_LIFETIME);
}

static int skw_iwpriv_set_tx_lifetime(struct skw_iface *iface, void *param,
	char *args, char *resp, int resp_len)
{
	int ret = 0;
	struct skw_tlv_set_tx_lifetime lftm = {0};
	u8 parmas_len = 0;
	char *p = NULL;

	if (!args)
		return -EINVAL;

	parmas_len = strlen(args);
	if (!parmas_len)
		return -EINVAL;

	p = args;
	lftm.lifetime = skw_iwpriv_convert_string_to_u(p, parmas_len);
	skw_dbg("set tx lifetime: %d\n", lftm.lifetime);

	ret = skw_set_tx_lifetime(iface->wdev.wiphy, iface->ndev, &lftm);

	if (!ret ) {
		sprintf(resp, "set ok ");
	} else
		sprintf(resp, "set failed");

	return ret;
}

static int skw_set_tx_retry_cnt(struct wiphy *wiphy, struct net_device *dev, struct skw_tlv_set_retry_cnt *rtycnt)
{
	return skw_generic_tlv_operation(wiphy, dev, rtycnt, sizeof(struct skw_tlv_set_retry_cnt), SKW_MIB_SET_TX_RETRY_CNT);
}

static int skw_iwpriv_set_tx_retry_cnt(struct skw_iface *iface, void *param,
	char *args, char *resp, int resp_len)
{
	int ret = 0;
	struct skw_tlv_set_retry_cnt cnt = {0};
	u8 parmas_len = 0;
	char *p = NULL;

	if (!args)
		return -EINVAL;

	parmas_len = strlen(args);
	if (!parmas_len)
		return -EINVAL;

	p = args;
	cnt.rtycnt = (u8)skw_iwpriv_convert_string_to_u(p, parmas_len);
	skw_dbg("set tx retry cnt: %d\n", cnt.rtycnt);

	ret = skw_set_tx_retry_cnt(iface->wdev.wiphy, iface->ndev, &cnt);

	if (!ret ) {
		sprintf(resp, "set ok ");
	} else
		sprintf(resp, "set failed");

	return ret;
}

static int skw_set_tx_rts_thrd(struct wiphy *wiphy, struct net_device *dev, struct skw_tlv_set_tx_rts_thrd *thrd)
{
	return skw_generic_tlv_operation(wiphy, dev, thrd, sizeof(struct skw_tlv_set_tx_rts_thrd), SKW_MIB_SET_TX_RTS_THRD);
}

static int skw_iwpriv_set_tx_rts_thrd(struct skw_iface *iface, void *param,
	char *args, char *resp, int resp_len)
{
	int ret = 0;
	struct skw_tlv_set_tx_rts_thrd thrd = {0};
	u8 parmas_len = 0;
	char *p = NULL;

	if (!args)
		return -EINVAL;

	parmas_len = strlen(args);
	if (!parmas_len)
		return -EINVAL;

	p = args;
	thrd.rts_thrd = skw_iwpriv_convert_string_to_u(p, parmas_len);
	skw_dbg("set tx rts thrd: %d\n", thrd.rts_thrd);

	ret = skw_set_tx_rts_thrd(iface->wdev.wiphy, iface->ndev, &thrd);

	if (!ret ) {
		sprintf(resp, "set ok ");
	} else
		sprintf(resp, "set failed");

	return ret;
}

static int skw_set_rx_sepcial_80211_frame(struct wiphy *wiphy, struct net_device *dev, struct skw_tlv_set_rx_special_80211_frame *frm)
{
	return skw_generic_tlv_operation(wiphy, dev, frm, sizeof(struct skw_tlv_set_rx_special_80211_frame), SKW_MIB_SET_FORCE_RX_SPECIAL_80211FRAME);
}

static int skw_iwpriv_set_rx_sepcial_80211_frame(struct skw_iface *iface, void *param,
	char *args, char *resp, int resp_len)
{
	int ret = 0;
	char *p = NULL, *q = NULL;
	struct skw_tlv_set_rx_special_80211_frame frm = {0};
	u8 temp_val = 0;

	if (!args)
		return -EINVAL;

	skw_warn("set_rx_sepcial_80211_frame args %s\n", args);

	p = args;
	q = strchr(args, ',');
	if(!p || !q)
	{
		skw_err("parameter error\n");
		return -ENOTSUPP;
	} else {
		skw_dbg("params found %s\n", p);
		temp_val = simple_strtol(p, NULL, 10);
		if (temp_val != 0 && temp_val != 1) {
			skw_warn("parameter error %d\n", temp_val);
			return -EINVAL;
		}
		frm.en = temp_val;
	}
	skw_dbg("en: %d\n", frm.en);

	p = q;
	q = strchr(p + 1, ',');
	if(!p || !q)
	{
		skw_err("param error\n");
		return -ENOTSUPP;
	} else
		frm.type = (u8)skw_iwpriv_convert_string_to_u(p + 1, q - p - 1);
	skw_dbg("type: %d\n", frm.type);

	p = q;
	q = strchr(p + 1, ',');
	if(!p)
	{
		skw_err("sub type not found\n");
		return -ENOTSUPP;
	} else
		frm.sub_type = (u8)skw_iwpriv_convert_string_to_u(p + 1, q - p - 1);
	skw_dbg("sub type: %d\n",frm.sub_type);

	ret = skw_set_rx_sepcial_80211_frame(iface->wdev.wiphy, iface->ndev, &frm);

	if (!ret ) {
		sprintf(resp, "set ok ");
	} else
		sprintf(resp, "set failed");

	return ret;

}

static int skw_set_rx_update_nav(struct wiphy *wiphy, struct net_device *dev, struct skw_tlv_set_rx_update_nav *nav)
{
	return skw_generic_tlv_operation(wiphy, dev, nav, sizeof(struct skw_tlv_set_rx_update_nav), SKW_MIB_SET_FORCE_RX_UPDATE_NAV);
}

static int skw_iwpriv_set_rx_update_nav(struct skw_iface *iface, void *param,
	char *args, char *resp, int resp_len)
{
	int ret = 0;
	char *p = NULL, *q = NULL;
	struct skw_tlv_set_rx_update_nav nav = {0};
	int temp_val = 0;

	if (!args)
		return -EINVAL;

	skw_dbg("args %s\n", args);

	p = args;
	q = strchr(args, ',');
	if(!p || !q)
	{
		skw_err("parameter error\n");
		return -ENOTSUPP;
	} else {
		skw_dbg("params found %s\n", p);
		temp_val = simple_strtol(p, NULL, 10);
		if (temp_val >= 0 || temp_val < -255) {
			skw_warn("parameter error %d\n", temp_val);
			return -EINVAL;
		}
		nav.intra_rssi = 0x80 | (0 - temp_val);
	}
	skw_dbg("intra rssi: %d\n", nav.intra_rssi);

	p = q;
	q = strchr(p + 1, ',');
	if(!p || !p)
	{
		skw_err("parameter error\n");
		return -ENOTSUPP;
	} else {
		skw_dbg("params found %s\n", p + 1);
		temp_val = simple_strtol(p + 1, NULL, 10);
		if (temp_val >= 0 || temp_val < -255) {
			skw_warn("parameter error %d\n", temp_val);
			return -EINVAL;
		}
		nav.basic_rssi = 0x80 | (0 - temp_val);
	}
	skw_dbg("basic rssi: %d\n", nav.basic_rssi);

	p = q;
	p = q + strlen(",");
	if(!p)
	{
		skw_warn("nav max time not found\n");
		return -ENOTSUPP;
	} else {
		 nav.nav_max_time = simple_strtol(p, NULL, 10);
	}
	skw_dbg("nav max time: %d\n", nav.nav_max_time);

	ret = skw_set_rx_update_nav(iface->wdev.wiphy, iface->ndev, &nav);

	if (!ret ) {
		sprintf(resp, "set ok ");
	} else
		sprintf(resp, "set failed");

	return ret;

}

//TLV 70
static int skw_set_apgo_timap(struct wiphy *wiphy, struct net_device *dev, struct skw_tlv_set_apgo_timap *timap)
{
	return skw_generic_tlv_operation(wiphy, dev, timap, sizeof(struct skw_tlv_set_apgo_timap), SKW_MIB_SET_APGO_TIMMAP);
}

static int skw_iwpriv_set_apgo_timap(struct skw_iface *iface, void *param,
	char *args, char *resp, int resp_len)
{
	int ret = 0;
	char *p = NULL, *q = NULL;
	struct skw_tlv_set_apgo_timap timap = {0};

	if (!args)
		return -EINVAL;

	skw_warn("set_apgo_timap args %s\n", args);

	p = args;
	q = strchr(args, ',');
	if(!p || !q)
	{
		skw_err("parameter error\n");
		return -ENOTSUPP;
	} else
		timap.dtimforce0 = (u8)skw_iwpriv_convert_string_to_u(p, q - p);
	skw_dbg("dtim force0: %d\n", timap.dtimforce0);

	p = q;
	q = strchr(p + 1, ',');
	if(!p || !p)
	{
		skw_err("parameter error\n");
		return -ENOTSUPP;
	} else
		timap.dtimforce1 = (u8)skw_iwpriv_convert_string_to_u(p + 1, q - p - 1);
	skw_dbg("dtim force1: %d\n", timap.dtimforce1);

	p = q;
	q = strchr(p + 1, ',');
	if(!p || !p)
	{
		skw_err("parameter error\n");
		return -ENOTSUPP;
	} else
		timap.timforce0 = (u8)skw_iwpriv_convert_string_to_u(p + 1, q - p - 1);
	skw_dbg("tim force0: %d\n", timap.timforce0);

	p = q;
	q = strchr(p + 1, ',');
	if(!p)
	{
		skw_err("parameter error\n");
		return -ENOTSUPP;
	} else
		 timap.timforce1 = (u8)skw_iwpriv_convert_string_to_u(p + 1, q - p - 1);
	skw_dbg("tim force1: %d\n", timap.timforce1);

	ret = skw_set_apgo_timap(iface->wdev.wiphy, iface->ndev, &timap);

	if (!ret ) {
		sprintf(resp, "set ok ");
	} else
		sprintf(resp, "set failed");

	return ret;

}

//TLV 71
static int skw_set_dbdc_disable(struct wiphy *wiphy, struct net_device *dev, struct skw_tlv_set_dbdc_disable *flag)
{
	return skw_generic_tlv_operation(wiphy, dev, flag, sizeof(struct skw_tlv_set_dbdc_disable), SKW_MIB_SET_DBDC_DISABLE);
}
static int skw_iwpriv_set_dbdc_disable(struct skw_iface *iface, void *param,
	char *args, char *resp, int resp_len)
{
	int ret = 0;
	struct skw_tlv_set_dbdc_disable set_flag = {0};
	u8 parmas_len = 0;

	if (!args)
		return -EINVAL;

	parmas_len = strlen(args);

	if (parmas_len == 1) {
		ret = simple_strtol(args, NULL, 10);
		if (!ret){
			skw_dbg("flag: %d\n", ret);
			set_flag.disable = 0;
		} else if (ret == 1){
			skw_dbg("flag: %d\n", ret);
			set_flag.disable = 1;
		} else
			goto SETFAIL;
	} else if (parmas_len > 1){
		skw_err("params error\n");
		goto SETFAIL;
	}

	skw_dbg("dbdc disable: %d\n", set_flag.disable);

	ret = skw_set_dbdc_disable(iface->wdev.wiphy, iface->ndev, &set_flag);

	if (!ret ) {
		sprintf(resp, "set ok ");
	} else
		sprintf(resp, "set failed");

	return ret;

SETFAIL:
	sprintf(resp, "set failed(param error)");
	return ret;
}

//TLV 150
static int skw_set_assign_address_val(struct wiphy *wiphy, struct net_device *dev, struct skw_tlv_set_assign_addr_val *param)
{
	return skw_generic_tlv_operation(wiphy, dev, param, sizeof(struct skw_tlv_set_assign_addr_val), SKW_MIB_SET_ASSIGN_ADDRESS_VAL);
}

static int skw_iwpriv_set_assign_address_val(struct skw_iface *iface, void *param,
	char *args, char *resp, int resp_len)
{
	int ret = 0;
	char *p = NULL, *q = NULL;
	struct skw_tlv_set_assign_addr_val params = {0};
	u8 parmas_len = 0, remain_len = 0;

	if (!args)
		return -EINVAL;

	parmas_len = strlen(args);
	skw_warn("args %s\n", args);

	p = args;
	q = strchr(args, ',');
	if(!p || !q)
	{
		skw_err("params error\n");
		return -ENOTSUPP;
	} else
		params.addr = skw_iwpriv_convert_string_to_u32(p, q - p);
	skw_dbg("addr: 0x%08x\n", params.addr);

	p = q;
	remain_len = parmas_len - (q - p) - 1;
	if(!p)
	{
		skw_err("param error\n");
		return -ENOTSUPP;
	} else
		params.val = skw_iwpriv_convert_string_to_u32(p + 1, remain_len);
	skw_dbg("val: 0x%08x\n", params.val);

	ret = skw_set_assign_address_val(iface->wdev.wiphy, iface->ndev, &params);

	if (!ret ) {
		sprintf(resp, "set ok ");
	} else
		sprintf(resp, "set failed");

	return ret;
}

//TLV 250
static int skw_read_addr(struct wiphy *wiphy, struct net_device *dev, struct skw_tlv_get_assign_addr *param)
{
	return skw_generic_tlv_operation(wiphy, dev, param, sizeof(struct skw_tlv_get_assign_addr), SKW_MIB_GET_ASSIGN_ADDR_VAL_E);
}

static int skw_iwpriv_read_addr(struct skw_iface *iface, void *param,
	char *args, char *resp, int resp_len)
{
	int ret = 0;
	char *p = NULL;
	struct skw_tlv_get_assign_addr params = {0};
	u8 parmas_len = 0;

	if (!args)
		return -EINVAL;

	parmas_len = strlen(args);
	if (!parmas_len || parmas_len >10)
	{
		skw_err("params error\n");
		return -ENOTSUPP;
	}
	skw_warn("args %s\n", args);

	p = args;
	if(!p)
	{
		skw_err("params error\n");
		return -ENOTSUPP;
	} else
		params.addr = skw_iwpriv_convert_string_to_u32(p, parmas_len);
	skw_dbg("addr: 0x%08x\n", params.addr);

	ret = skw_read_addr(iface->wdev.wiphy, iface->ndev, &params);

	if (!ret ) {
		sprintf(resp, "set ok ");
	} else
		sprintf(resp, "set failed");

	return ret;
}

//TLV 39： ageout thrd
//
static int skw_set_ageout_thrd(struct wiphy *wiphy, struct net_device *dev, struct skw_tlv_set_ageout_thrd *params)
{
	return skw_generic_tlv_operation(wiphy, dev, params, sizeof(struct skw_tlv_set_ageout_thrd), SKW_MIB_SET_AGEOUT_THOLD);
}

static int skw_iwpriv_set_ageout_thrd(struct skw_iface *iface, void *param,
	char *args, char *resp, int resp_len)
{
	int ret = 0;
	char *p = NULL, *q = NULL;
	struct skw_tlv_set_ageout_thrd thrd = {0};
	u16 temp_val = 0;

	if (!args)
		return -EINVAL;

	skw_dbg("args %s\n", args);

	p = args;
	q = strchr(args, ',');
	if (!p || !q) {
		skw_err("param err\n");
		return -ENOTSUPP;
	}
	temp_val = simple_strtol(p, NULL, 10);
	if (temp_val > 0xFFFF) {
		skw_warn("parameter out of range (0 ~ 0xFFFF) %d\n", temp_val);
		thrd.ageout_keep_alive = 0xFFFF;
	} else {
		thrd.ageout_keep_alive  = temp_val;
	}
	skw_dbg("keep_alive %d\n", thrd.ageout_keep_alive);

	p = q;
	q = strchr(p + 1, ',');
	if (!p || !q) {
		skw_err("param err\n");
		return -ENOTSUPP;
	}
	temp_val = simple_strtol(p + 1, NULL, 10);
	if (temp_val > 0xFFFF) {
		skw_warn("parameter out of range (0 ~ 0xFFFF) %d\n", temp_val);
		thrd.ageout_kick_out = 0xFFFF;
	} else {
		thrd.ageout_kick_out  = temp_val;
	}
	skw_dbg("kick_out %d\n", thrd.ageout_kick_out);

	p = q;
	if (!p) {
		skw_warn("param err\n");
		return -ENOTSUPP;
	}
	temp_val = simple_strtol(p + 1, NULL, 10);
	if (temp_val > 0xFFFF) {
		skw_warn("parameter out of range (0 ~ 0xFFFF) %d\n", temp_val);
		thrd.ageout_send_null_itvl = 0xFFFF;
	} else {
		thrd.ageout_send_null_itvl  = temp_val;
	}
	skw_dbg("send_null_itvl: %d\n", thrd.ageout_send_null_itvl);

	ret = skw_set_ageout_thrd(iface->wdev.wiphy, iface->ndev, &thrd);

	if (!ret)
		sprintf(resp, "set ok");
	else
		sprintf(resp, "set failed");

	return ret;

}

//set regd config cmd, no tlv
static int skw_iwpriv_set_regd_config(struct skw_iface *iface, void *param,
	char *args, char *resp, int resp_len)
{
	int ret = 0;
	char *p = NULL, *q = NULL;
	u16 temp_val = 0;
	u8 comma_num = 0;
	int i = 0, rule_idx = 0;

	struct skw_regdom regd = {};
	struct skw_core *skw = NULL;
	struct skw_reg_rule *rule = &regd.rules[0];
	struct wiphy *wiphy;

	wiphy = iface->wdev.wiphy;
	skw = wiphy_priv(wiphy);

	if (!args)
		return -EINVAL;
	skw_dbg("args: %s\n", args);

	p = args;
	q = strchr(args, ',');
	if(!p || !q)
	{
		skw_err("parameter error\n");
		return -ENOTSUPP;
	} else
		regd.nr_reg_rules = (u8)skw_iwpriv_convert_string_to_u(p, q - p);
	skw_dbg("nr_reg_rules: %d\n", regd.nr_reg_rules);

	comma_num = regd.nr_reg_rules * 2;
	skw_dbg("comma num %d\n", comma_num);

	for (i = 0; i < comma_num; i++) {
		p = q;
		q = strchr(p + 1, ',');
		if (!p || !q) {
			skw_warn("param err 1\n");
			return -ENOTSUPP;
		}

		temp_val = (u8)skw_iwpriv_convert_string_to_u(p + 1, q - p - 1);
		skw_dbg("start channel: %d, rule_idx %d\n", temp_val, rule_idx);
		rule[rule_idx].start_channel = temp_val;
		i++;

		if (i < comma_num - 1) {
			p = q;
			q = strchr(p + 1, ',');
			if (!p || !q) {
				skw_warn("param err, i %d\n", i);
				return -ENOTSUPP;
			}
			temp_val = (u8)skw_iwpriv_convert_string_to_u(p + 1, q - p - 1);
			rule[rule_idx].nr_channel = temp_val - rule[rule_idx].start_channel;
			skw_dbg("end chn: %d, rule_idx %d\n", temp_val, rule_idx);
		} else {
			p = q;
			q = strchr(p + 1, ',');
			if(!p)
			{
				skw_err("parameter error\n");
				return -ENOTSUPP;
			}
			temp_val = (u8)skw_iwpriv_convert_string_to_u(p + 1, q - p - 1);
			skw_dbg("end channel: %d, rule_idx %d\n", temp_val, rule_idx);
			rule[rule_idx].nr_channel = temp_val - rule[rule_idx].start_channel;
		}
		rule_idx ++;
	}

	for (i = 0; i < rule_idx; i++) {
		skw_dbg("%d @ %d\n",regd.rules[i].start_channel,
				regd.rules[i].nr_channel);
	}

	ret = skw_msg_xmit(wiphy, 0, SKW_CMD_SET_REGD, &regd,
					sizeof(regd), NULL, 0);

	if (!ret)
		skw_dbg("set regd passed, rules: %d, ret: %d\n", regd.nr_reg_rules, ret);
	else
		skw_warn("failed, rules: %d, ret: %d\n", regd.nr_reg_rules, ret);

	if (!ret)
		sprintf(resp, "set ok");
	else
		sprintf(resp, "set failed");

	return ret;

}

//TLV 83: set er_dcm_rate
static int skw_set_er_dcm_rate(struct wiphy *wiphy, struct net_device *dev, struct skw_tlv_set_er_dcm_rate *params)
{
	return skw_generic_tlv_operation(wiphy, dev, params, sizeof(struct skw_tlv_set_er_dcm_rate), SKW_MIB_SET_RATE_CTRL_ER_DCM_RATE);
}

static int skw_iwpriv_set_er_dcm_rate(struct skw_iface *iface, void *param,
	char *args, char *resp, int resp_len)
{
	int ret = 0;
	char *p = NULL, *q = NULL;
	struct skw_tlv_set_er_dcm_rate rate = {0};
	u16 temp_val = 0;

	if (!args)
		return -EINVAL;

	skw_dbg("args %s\n", args);

	p = args;
	q = strchr(args, ',');
	if (!p || !q) {
		skw_err("param err\n");
		return -ENOTSUPP;
	}
	temp_val = simple_strtol(p, NULL, 10);
	if (temp_val > 0xFF) {
		skw_warn("para out of range (0 ~ 0xFF) %d\n", temp_val);
		rate.er = 0xFF;
	} else {
		rate.er  = temp_val;
	}
	skw_dbg("er rate %d\n", rate.er);

	p = q;
	if (!p) {
		skw_warn("param err\n");
		return -ENOTSUPP;
	}
	temp_val = simple_strtol(p + 1, NULL, 10);
	if (temp_val > 0xFF) {
		skw_warn("para out of range (0 ~ 0xFF) %d\n", temp_val);
		rate.dcm = 0xFF;
	} else {
		rate.dcm  = temp_val;
	}
	skw_dbg("dcm rate: %d\n", rate.dcm);

	ret = skw_set_er_dcm_rate(iface->wdev.wiphy, iface->ndev, &rate);

	if (!ret)
		sprintf(resp, "set ok");
	else
		sprintf(resp, "set failed");

	return ret;
}

//tlv 42
static int skw_set_reported_cqm_interval(struct wiphy *wiphy, struct net_device *dev, struct skw_tlv_set_report_cqm_rssi_low_itvl *params)
{
	return skw_generic_tlv_operation(wiphy, dev, params, sizeof(struct skw_tlv_set_report_cqm_rssi_low_itvl), SKW_MIB_SET_REPORT_CQM_RSSI_LOW_INT);
}

//tlv 54 ~ 58
static int skw_set_ap_new_channel(struct wiphy *wiphy, struct net_device *dev, struct skw_tlv_set_ap_new_channel *params)
{
	return skw_generic_tlv_operation(wiphy, dev, params, sizeof(struct skw_tlv_set_ap_new_channel), SKW_MIB_SET_AP_NEW_CHAN);
}

static int skw_set_tx_retry_limit_en(struct wiphy *wiphy, struct net_device *dev, struct skw_tlv_set_tx_retry_limit_en *params)
{
	return skw_generic_tlv_operation(wiphy, dev, params, sizeof(struct skw_tlv_set_tx_retry_limit_en), SKW_MIB_SET_TX_RETRY_LIMIT_EN);
}

static int skw_partial_twt_sched(struct wiphy *wiphy, struct net_device *dev, struct skw_tlv_set_partial_twt_sched *params)
{
	return skw_generic_tlv_operation(wiphy, dev, params, sizeof(struct skw_tlv_set_partial_twt_sched), SKW_MIB_SET_PARTIAL_TWT_SCHED);
}

static int skw_set_thm_thre(struct wiphy *wiphy, struct net_device *dev, struct skw_tlv_set_thm_thrd *params)
{
	return skw_generic_tlv_operation(wiphy, dev, params, sizeof(struct skw_tlv_set_thm_thrd), SKW_MIB_SET_THM_THRD);
}

static int skw_set_rety_ignore_prot(struct wiphy *wiphy, struct net_device *dev, struct skw_tlv_set_retry_ignore_prot *params)
{
	return skw_generic_tlv_operation(wiphy, dev, params, sizeof(struct skw_tlv_set_retry_ignore_prot), SKW_MIB_SET_RETRY_IGNORE_PROT);
}

extern int skw_set_dot11r_mib(struct wiphy *wiphy, struct net_device *dev, bool enable);
static int skw_iwpriv_set_params(struct skw_iface *iface, void *param,
								char *args, char *resp, int resp_len)
{
	int ret = 0;
	char *p = NULL, *q = NULL;
	u32 params[16] = {0};
	u32 params_num = 0;
	struct skw_tlv_set_ap_new_channel new_chan = {0};
	struct skw_tlv_set_tx_retry_limit_en txr_limit = {0};
	struct skw_tlv_set_report_cqm_rssi_low_itvl itvl = {0};
	struct skw_tlv_set_thm_thrd thrd = {0};
	struct skw_tlv_set_partial_twt_sched twt_params = {0};
	struct skw_tlv_set_retry_ignore_prot ignore_params = {0};

	if (!args)
		return -EINVAL;

	skw_dbg("args %s\n", args);

	p = args;

	while (p) {
		params[params_num] = simple_strtol(p, NULL, 10);
		params_num++;

		q = strchr(p, ',');
		if (!q) {
			break;
		}

		p = q + 1; /* move past the comma */
	}

	if (params_num < 2) {
		skw_warn("params error, at least 2\n");
		return -ENOTSUPP;
	}

	switch (params[0]) {
		case 1:
			if (params_num != 6) {
				skw_warn("params error, need 6 totally\n");
				return -EINVAL;
			}

			new_chan.chan = params[1];
			new_chan.center_chan = params[2];
			new_chan.center_two_chan = params[3];
			new_chan.bw = params[4];
			new_chan.band = params[5];

			ret = skw_set_ap_new_channel(iface->wdev.wiphy, iface->ndev, &new_chan);
			skw_dbg("set ap new chan done\n");

			break;

		case 2:
			if (params_num != 2) {
				skw_warn("params error, need 2 totally\n");
				return -EINVAL;
			}

			ret = skw_set_dot11r_mib(iface->wdev.wiphy, iface->ndev, (bool)params[1]);
			skw_dbg("set 11r mib done\n");
			break;

		case 3:
			if (params_num != 4) {
				skw_warn("params error, need 4 totally\n");
				return -EINVAL;
			}

			txr_limit.short_retry_check_en = !!params[1];
			txr_limit.long_retry_check_en = !!params[2];
			txr_limit.ampdu_retry_check_en = !!params[3];

			ret = skw_set_tx_retry_limit_en(iface->wdev.wiphy, iface->ndev,&txr_limit);
			skw_dbg("set tx retry limit done\n");

			break;

		case 4:
			if (params_num != 3) {
				skw_warn("params error, need 3 totally\n");
				return -EINVAL;
			}

			itvl.report_cqm_low_intvl_min_dur = params[1];
			itvl.report_cqm_low_intvl_max_dur = params[2];

			ret = skw_set_reported_cqm_interval(iface->wdev.wiphy, iface->ndev,&itvl);
			skw_dbg("set report cqm interval done\n");
			break;

		case 5:
			if (params_num != 3) {
				skw_warn("params error, need 3 totally\n");
				return -EINVAL;
			}

			thrd.thm_high_thrd_tx_suspend = (s16)params[1];
			thrd.thm_low_thrd_tx_resume = (s16)params[2];

			ret = skw_set_thm_thre(iface->wdev.wiphy, iface->ndev, &thrd);
			skw_dbg("set thm thre done\n");

			break;

		case 6:
			if (params_num != 8) {
				skw_warn("params error, need 8 totally\n");
				return -EINVAL;
			}

			twt_params.en = params[1];
			twt_params.start_time_l = params[2];
			twt_params.start_time_h = params[3];
			twt_params.interval = params[4];
			twt_params.duration = params[5];
			twt_params.duration_unit = params[6];
			twt_params.sub_type = params[7];

			ret = skw_partial_twt_sched(iface->wdev.wiphy, iface->ndev, &twt_params);
			skw_dbg("set partial twt sched done\n");

			break;

		case 7:
			if (params_num != 2) {
				skw_warn("params error, need 2 totally\n");
				return -EINVAL;
			}

			ignore_params.ignore_flag = params[1];

			ret = skw_set_rety_ignore_prot(iface->wdev.wiphy, iface->ndev, &ignore_params);
			skw_dbg("set retry ignore prot done\n");

			break;

		default:
			return -ENOTSUPP;
	}

	if (!ret)
		snprintf(resp, resp_len, "set ok");
	else
		snprintf(resp, resp_len, "set failed");

	return ret;
}

static struct skw_iwpriv_cmd skw_iwpriv_set_cmds[] = {
	/* keep first */
	{"help", skw_iwpriv_help, "usage"},
	{"bandcfg", skw_iwpriv_set_bandcfg, "bandcfg=0/1/2"},
	{"mppdudur", skw_iwpriv_set_max_ppdu_dur, "mppdudur=0~5,1~65535"},
	{"edca", skw_iwpriv_set_edca_params, "edca=0,x(13 total)"},
	{"ccanowifi", skw_iwpriv_set_cca_thre_nowifi, "ccanowifi=-u8"},
	{"cca11b", skw_iwpriv_set_cca_thre_11b, "cca11b=-u8"},
	{"ccaofdm", skw_iwpriv_set_cca_thre_ofdm, "ccaofdm=-u8"},
	{"rtsrate", skw_iwpriv_set_force_rts_rate, "rtsrate=u8,u8,u8"},
	{"rxrsprate", skw_iwpriv_set_force_rx_rsp_rate, "rxrsprate=u8,u8,u8,u8"},
	{"scantime", skw_iwpriv_set_scan_time, "scantime=u8,u8"},
	{"tcpdwhost", skw_iwpriv_set_tcpd_wakeup_host, "tcpdwhost=u8"},
	{"rcminrate", skw_iwpriv_set_rc_min_rate, "rcminrate=u8"},
	{"rcratechg", skw_iwpriv_set_rc_rate_change, "rcratechg=u8,u8,u8,u8,u8"},
	{"rcsperate", skw_iwpriv_set_rc_spe_rate, "rcsperate=u8"},
	{"txlftm", skw_iwpriv_set_tx_lifetime, "txlftm=u8"},
	{"txrtycnt", skw_iwpriv_set_tx_retry_cnt, "txrtycnt=u8"},
	{"txrtsthrd", skw_iwpriv_set_tx_rts_thrd, "txrtsthrd=u16"},
	{"rxsped11frm", skw_iwpriv_set_rx_sepcial_80211_frame, "rxsped11frm=u8,u8,u8"},
	{"rxupdnav", skw_iwpriv_set_rx_update_nav, "rxupdnav=-u8,-u8,u16"},
	{"apgotimap", skw_iwpriv_set_apgo_timap, "apgotimap=u8,u8,u8,u8"},
	{"dbdcdis", skw_iwpriv_set_dbdc_disable, "dbdcdis=u8"},
	{"addrval", skw_iwpriv_set_assign_address_val, "addrval=0x12345678,0x12345678"},
	{"rdaddr", skw_iwpriv_read_addr, "rdaddr=0x12345678"},
	{"ageout", skw_iwpriv_set_ageout_thrd, "ageout=u16,u16,u16"},
	{"regd", skw_iwpriv_set_regd_config, "regd=u8,u8,u8,u8,u8"},
	{"erdcmr", skw_iwpriv_set_er_dcm_rate, "erdcmr=u8,u8"},
	{"params", skw_iwpriv_set_params, "params=index,u32,u32,u32,u32,..."}, //for tlv42 and 54~57

	/*keep last*/
	{NULL, NULL, NULL}
};

static struct skw_iwpriv_cmd skw_iwpriv_get_cmds[] = {
	/* keep first */
	{"help", skw_iwpriv_help, "usage"},

	{"bandcfg", skw_iwpriv_get_bandcfg, "bandcfg"},
	{"noise", skw_iwpriv_get_noise, "noise"},

	/*keep last*/
	{NULL, NULL, NULL}
};

static struct skw_iwpriv_cmd *skw_iwpriv_cmd_match(struct skw_iwpriv_cmd *cmds,
					const char *key, int key_len)
{
	int i;

	for (i = 0; cmds[i].name; i++) {
		if (!memcmp(cmds[i].name, key, key_len))
			return &cmds[i];
	}

	return NULL;
}

static int skw_iwpriv_set(struct net_device *dev,
			   struct iw_request_info *info,
			   union iwreq_data *wrqu, char *extra)
{
	int ret = 0;
	int key_len;
	char param[128];
	char *token, *args;
	struct skw_iwpriv_cmd *iwpriv_cmd;
	struct skw_iface *iface = (struct skw_iface *)netdev_priv(dev);

	WARN_ON(sizeof(param) < wrqu->data.length);

	if (copy_from_user(param, wrqu->data.pointer, sizeof(param))) {
		skw_err("copy failed, length: %d\n",
			wrqu->data.length);

		return -EFAULT;
	}

	param[127] = '\0';

	skw_dbg("cmd: 0x%x, %s(len: %d)\n",
		info->cmd, param, wrqu->data.length);

	token = strchr(param, '=');
	if (!token) {
		key_len = strlen(param);
		args = NULL;
	} else {
		key_len = token - param;
		args = token + 1;
	}

	iwpriv_cmd = skw_iwpriv_cmd_match(skw_iwpriv_set_cmds, param, key_len);
	if (iwpriv_cmd)
		ret = iwpriv_cmd->handler(iface, iwpriv_cmd, args,
				extra, SKW_GET_LEN_512);
	else
		ret = skw_iwpriv_help(iface, skw_iwpriv_set_cmds, NULL,
				extra, SKW_GET_LEN_512);

	if (ret < 0)
		sprintf(extra, " usage: %s\n", iwpriv_cmd->help_info);

	wrqu->data.length = SKW_GET_LEN_1024;

	skw_dbg("resp: %s\n", extra);

	return 0;
}

static int skw_iwpriv_get(struct net_device *dev,
			   struct iw_request_info *info,
			   union iwreq_data *wrqu, char *extra)
{
	int ret;
	char cmd[128];
	struct skw_iwpriv_cmd *priv_cmd;
	struct skw_iface *iface = (struct skw_iface *)netdev_priv(dev);

	if (copy_from_user(cmd, wrqu->data.pointer, sizeof(cmd))) {
		skw_err("copy failed, length: %d\n",
			wrqu->data.length);

		return -EFAULT;
	}

	skw_dbg("cmd: 0x%x, %s(len: %d)\n", info->cmd, cmd, wrqu->data.length);

	priv_cmd = skw_iwpriv_cmd_match(skw_iwpriv_get_cmds, cmd, strlen(cmd));
	if (priv_cmd)
		ret = priv_cmd->handler(iface, priv_cmd, NULL, extra,
				SKW_GET_LEN_512);
	else
		ret = skw_iwpriv_help(iface, skw_iwpriv_get_cmds, NULL,
				extra, SKW_GET_LEN_512);

	wrqu->data.length = SKW_GET_LEN_512;

	skw_dbg("resp: %s\n", extra);

	return ret;
}

static int skw_iwpriv_at(struct net_device *dev,
			   struct iw_request_info *info,
			   union iwreq_data *wrqu, char *extra)
{
	int ret;
	char cmd[SKW_SET_LEN_256];
	int len = wrqu->data.length;
	struct skw_core *skw = ((struct skw_iface *)netdev_priv(dev))->skw;

	BUG_ON(sizeof(cmd) < len);

	if (copy_from_user(cmd, wrqu->data.pointer, sizeof(cmd))) {
		skw_err("copy failed, length: %d\n", len);

		return -EFAULT;
	}

	skw_dbg("cmd: %s, len: %d\n", cmd, len);

	if (len + 2 > sizeof(cmd))
		return -EINVAL;

	cmd[len - 1] = 0xd;
	cmd[len + 0] = 0xa;
	cmd[len + 1] = 0x0;

	ret = skw_send_at_cmd(skw, cmd, len + 2, extra, SKW_GET_LEN_512);

	wrqu->data.length = SKW_GET_LEN_512;

	skw_dbg("resp: %s", extra);

	return ret;
}

static struct iw_priv_args skw_iw_priv_args[] = {
	{
		SKW_IW_PRIV_SET,
		IW_PRIV_TYPE_CHAR | SKW_SET_LEN_128,
		IW_PRIV_TYPE_CHAR | SKW_GET_LEN_1024,
		"set",
	},
	{
		SKW_IW_PRIV_GET,
		IW_PRIV_TYPE_CHAR | SKW_SET_LEN_128,
		IW_PRIV_TYPE_CHAR | SKW_GET_LEN_512,
		"get",
	},
	{
		SKW_IW_PRIV_AT,
		IW_PRIV_TYPE_CHAR | SKW_SET_LEN_256,
		IW_PRIV_TYPE_CHAR | SKW_GET_LEN_512,
		"at",
	},
	{
		SKW_IW_PRIV_80211MODE,
		IW_PRIV_TYPE_CHAR | SKW_SET_LEN_128,
		IW_PRIV_TYPE_CHAR | SKW_GET_LEN_512,
		"mode",
	},
	{
		SKW_IW_PRIV_GET_80211MODE,
		IW_PRIV_TYPE_CHAR | SKW_SET_LEN_128,
		IW_PRIV_TYPE_CHAR | SKW_GET_LEN_512,
		"get_mode",
	},
	{
		SKW_IW_PRIV_KEEP_ALIVE,
		IW_PRIV_TYPE_CHAR | SKW_SET_LEN_1024,
		IW_PRIV_TYPE_CHAR | SKW_GET_LEN_512,
		"keep_alive",
	},
	{
		SKW_IW_PRIV_WOW_FILTER,
		IW_PRIV_TYPE_CHAR | SKW_SET_LEN_512,
		IW_PRIV_TYPE_CHAR | SKW_GET_LEN_512,
		"wow_filter",
	},
	{0, 0, 0, {0}}
};

static const iw_handler skw_iw_priv_handlers[] = {
	NULL,
	skw_iwpriv_set,
	NULL,
	skw_iwpriv_get,
	NULL,
	skw_iwpriv_at,
	skw_iwpriv_mode,
	skw_iwpriv_get_mode,
	skw_iwpriv_keep_alive,
	skw_iwpriv_wow_filter,
};
#endif

static struct iw_handler_def skw_iw_ops = {
#if 0
	.standard = skw_iw_standard_handlers,
	.num_standard = ARRAY_SIZE(skw_iw_standard_handlers),
	.get_wireless_stats = skw_get_wireless_stats,
#endif

#ifdef CONFIG_WEXT_PRIV
	.private = skw_iw_priv_handlers,
	.num_private = ARRAY_SIZE(skw_iw_priv_handlers),
	.private_args = skw_iw_priv_args,
	.num_private_args = ARRAY_SIZE(skw_iw_priv_args),
#endif
};

const void *skw_iw_handlers(struct wiphy *wiphy)
{
#ifdef CONFIG_WIRELESS_EXT
#ifdef CONFIG_CFG80211_WEXT
	skw_iw_ops.standard = wiphy->wext->standard;
	skw_iw_ops.num_standard = wiphy->wext->num_standard;
	skw_iw_ops.get_wireless_stats = wiphy->wext->get_wireless_stats;
#endif
	return (const void *)&skw_iw_ops;

#else
	skw_info("CONFIG_WIRELESS_EXT disabled\n");
	return NULL;
#endif
}
