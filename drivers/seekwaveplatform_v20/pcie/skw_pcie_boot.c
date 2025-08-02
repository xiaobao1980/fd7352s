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
#include "asm/io.h"
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
#include <linux/gpio.h>
#include <linux/delay.h>
#include <linux/dma-mapping.h>
#include <linux/firmware.h>
#include "skw_edma_drv.h"
#include "skw_pcie_drv.h"
#include "skw_pcie_log.h"
#include "skw_edma_reg.h"


extern u32 last_sent_wifi_cmd[3];
extern u64 last_sent_time;

static int cp_log_status = 0;
extern int send_modem_assert_command(void);
static int skw_check_cp_ready(void);
int skw_pcie_elbi_writeb(unsigned int address, unsigned char value);
int skw_pcie_elbi_writed(unsigned int address, u32 value);
int skw_pcie_slp_feature_en(unsigned int address, unsigned int slp_en);
int skw_pcie_boot_cp(int boot_mode);

int skw_pcie_elbi_writeb(unsigned int address, unsigned char value)
{
	int ret;
	struct wcn_pcie_info *priv = get_pcie_device_info();
	ret=pci_write_config_byte(priv->dev,address, value);
	PCIE_DBG("line:%d (address,value)-(0x%x,0x%x)\n",__LINE__,address, value);
	return ret;
}

int skw_pcie_elbi_writed(unsigned int address, u32 value)
{
	struct wcn_pcie_info *priv = get_pcie_device_info();
	pci_write_config_dword(priv->dev,address, value);
	PCIE_DBG("line:%d (address,value)-(0x%x,0x%x)\n",__LINE__,address, value);
	return value;
}

/*
 *svc_op:0-wifi start, 1-wifi stop, 2-bt start, 3-bt stop
 */
static int send_modem_service_command(u16 service, u16 command)
{
	int ret = 0;
	u16 cmd;
	struct wcn_pcie_info *priv = get_pcie_device_info();
	PCIE_INFO("line:%d (ser,cmd)-(%d,%d)\n",__LINE__, service, command);
	if(command)
		priv->service_state_map&= ~(1<<service);
	//command = 1;
	cmd = (service<<1)|command;
	priv->svc_op = cmd;
	cmd = 1 << cmd;

	if(priv->cp_state != CP_READY){
		PCIE_INFO("cpsts:%s\n",str_cpsts[priv->cp_state]);
		return ret;
	}
	if(cmd>>8)
		ret = skw_pcie_elbi_writeb(SKW_AP2CP_IRQ_REG, cmd & 0xff);
	if(ret || !(cmd&0xff))
		return ret;
	PCIE_INFO("line:%d (ser,cmd)-(%d,0x%x)\n",__LINE__, service, cmd);
	return skw_pcie_elbi_writeb(SKW_AP2CP_IRQ_REG, cmd & 0xff);
}

#if 0
volatile u32 int_cnt = 0;
static u32 dl_req_cnt = 0, std_complete_cnt = 0;
int download_fw_complete_cb(void *context, u64 header, u64 tailed, int node_count)
{
	u32 val;
	u32 i;
	struct edma_chn_info *edma_chp = get_edma_channel_info(0);
	struct wcn_pcie_info *priv= get_pcie_device_info();

	std_complete_cnt += 1;
	PCIE_DBG("1. dl_req_cnt=%d, std_complete_cnt=%d\n", dl_req_cnt, std_complete_cnt);
	if (dl_req_cnt == std_complete_cnt) {
		std_complete_cnt = 0;
		dl_req_cnt = 0;
		int_cnt = 0;
		 PCIE_DBG("2. dl_req_cnt=%d, std_complete_cnt=%d\n", dl_req_cnt, std_complete_cnt);
		//set crc value
		for (i = 0;i < 7;i++) {
			skw_pcie_write32(FW_DATA_CRC_BASE + i * 4, 0);
		}
		if (priv->iram_crc_en) {
			skw_pcie_write32(FW_DATA_CRC_BASE +0x0, priv->iram_crc_offset);//iram crc offset
			skw_pcie_write32(FW_DATA_CRC_BASE +0x4, priv->iram_dl_size);//iram crc size
			skw_pcie_write32(FW_DATA_CRC_BASE +0x8, priv->iram_crc);//iram crc
			val = 3;//iram crc en
		}
		if (priv->dram_crc_en) {
			skw_pcie_write32(FW_DATA_CRC_BASE +0xc, priv->dram_crc_offset);//dram crc offset
			skw_pcie_write32(FW_DATA_CRC_BASE +0x10, priv->dram_dl_size);//dram crc size
			skw_pcie_write32(FW_DATA_CRC_BASE +0x14, priv->dram_crc);//dram crc
			val |= (3<<2);//dram crc en
		}
		if (priv->iram_crc_en || priv->dram_crc_en)
			skw_pcie_write32(FW_DATA_CRC_BASE +0x18, val);

		//set boot addr
		skw_pcie_write32(FW_BOOT_REG_BASE, 0x100000);

		//disable boot chn0 eb
		val = skw_pcie_read32(DMA_CFG(0));
		val &= ~0x1;
		skw_pcie_write32(DMA_CFG(0), val);

		//set dl done
		val = skw_pcie_read32(FW_DL_DONE_REG_BASE);
		val |= 0x3;
		skw_pcie_write32(FW_DL_DONE_REG_BASE, val);
		dma_unmap_single(&priv->dev->dev, edma_chp->map_pld_addr, priv->iram_dl_size, DMA_TO_DEVICE);
		dma_unmap_single(&priv->dev->dev, edma_chp->map_skb_addr, priv->dram_dl_size, DMA_TO_DEVICE);
	}

	if (&priv->edma_blk_dl_done != NULL)
		complete(&priv->edma_blk_dl_done);
	return 0;
}

static int pcie_download_fw(u32 dst_addr, void *send_buf, u32 len)
{
	int i;
	char *buf;
	struct edma_chn_info *edma_chp = get_edma_channel_info(0);
	struct wcn_pcie_info *priv= get_pcie_device_info();
	struct device *dev = &(priv->dev->dev);
	DMA_DST_DSCR_PTR_HIGH_S dst_addr_h8 = {0};
	DMA_DST_DSCR_PTR_LOW_S dst_addr_l32 = {0};


	mutex_lock(&priv->dl_lock);
	buf = dma_alloc_coherent(dev, len, &edma_chp->pld_dma_addr, GFP_KERNEL);
	if (!buf) {
		PCIE_ERR("Alloc Fw sendbuf fail!\n");
		return -ENOMEM;
	}
	memcpy(buf, send_buf, len);
	edma_chp->chn_cfg.direction = EDMA_TX;
	edma_chp->chn_cfg.req_mode = EDMA_STD_MODE;
	edma_chp->chn_cfg.complete_callback = download_fw_complete_cb;
	edma_chp->chn_cfg.trsc_len = 0xffff;

	PCIE_INFO("buf=0x%p, pcieaddr=0x%llx\n", buf, edma_phyaddr_to_pcieaddr(edma_chp->pld_dma_addr));
	for (i = 0; i < len / 0xffff; i++) {
		reinit_completion(&priv->edma_blk_dl_done);
		//src addr
		edma_chp->chn_cfg.header = edma_phyaddr_to_pcieaddr(edma_chp->pld_dma_addr) + i * 0xFFFF;
		edma_channel_init(0, &edma_chp->chn_cfg, NULL);

		//dst addr
		dst_addr_l32.dst_next_dscr_ptr_low = (dst_addr + i * 0xFFFF) & 0xffffffff;
		skw_pcie_write32(DMA_DST_DSCR_PTR_LOW(0), dst_addr_l32.u32);
		dst_addr_h8.dst_next_dscr_ptr_high = 0;
		skw_pcie_write32(DMA_DST_DSCR_PTR_HIGH(0), dst_addr_h8.u32);

		int_cnt++;
		//PCIE_DBG("2. %d: std_complete_cnt=%d, int_cnt=%d\n", __LINE__, std_complete_cnt, int_cnt);
		edma_adma_send(0, NULL, 0, 0);
		//dst req
		skw_pcie_setbit(DMA_DST_REQ(0), BIT(0));
		if (&priv->edma_blk_dl_done != NULL)
			wait_for_completion(&priv->edma_blk_dl_done);
		else
			udelay(5000);
	}
	if (len % 0xffff) {
		reinit_completion(&priv->edma_blk_dl_done);
		edma_chp->chn_cfg.trsc_len = len % 0xffff;
		//src addr
		edma_chp->chn_cfg.header = edma_phyaddr_to_pcieaddr(edma_chp->pld_dma_addr) + i * 0xFFFF;
		edma_channel_init(0, &edma_chp->chn_cfg, NULL);

		//dst addr
		dst_addr_l32.dst_next_dscr_ptr_low = (dst_addr + i * 0xFFFF) & 0xffffffff;
		skw_pcie_write32(DMA_DST_DSCR_PTR_LOW(0), dst_addr_l32.u32);
		dst_addr_h8.dst_next_dscr_ptr_high = 0;
		skw_pcie_write32(DMA_DST_DSCR_PTR_HIGH(0), dst_addr_h8.u32);
		int_cnt++;
		//PCIE_DBG("4. %d: std_complete_cnt=%d, int_cnt=%d\n", __LINE__, std_complete_cnt, int_cnt);
		edma_adma_send(0, NULL, 0, 0);
		//dst req
		skw_pcie_setbit(DMA_DST_REQ(0), BIT(0));
		if (&priv->edma_blk_dl_done != NULL) {
			wait_for_completion(&priv->edma_blk_dl_done);
		}else {
			udelay(5000);
		}
	}
	dma_free_coherent(dev, len, buf, edma_chp->pld_dma_addr);
	mutex_unlock(&priv->dl_lock);
	return 0;
}

#else
static void pcie_download_fw_iram(void *buf, u32 len)
{
	//int i;
	struct wcn_pcie_info *priv= get_pcie_device_info();
	
	//print_hex_dump(KERN_ERR, "fw:", 0, 16, 1, priv->pcimem, 32, 1);
	//print_hex_dump(KERN_ERR, "fw:", 0, 16, 1, priv->pcimem + 0x200000, 32, 1);
#if 1
	memcpy_toio(priv->pcimem + 0x200000, buf, len);
#else
	for (i=0;i<len;i++)
		writeb_relaxed(((char *)buf)[i], (char *)(priv->pcimem + 0x200000 + i));
#endif
}
static void pcie_download_fw_dram(void *buf, u32 len)
{
	u32 val;
	u32 i;
	struct wcn_pcie_info *priv= get_pcie_device_info();

#if 1
	memcpy_toio(priv->pcimem + 0x300000, buf, len);
#else
	for (i=0;i<len;i++)
		writeb_relaxed(((char *)buf)[i], (char *)(priv->pcimem + 0x300000 + i));
#endif
	//set crc value
	for (i = 0;i < 7;i++) {
		skw_pcie_write32(FW_DATA_CRC_BASE + i * 4, 0);
	}
	if (priv->iram_crc_en) {
		skw_pcie_write32(FW_DATA_CRC_BASE +0x0, priv->iram_crc_offset);//iram crc offset
		skw_pcie_write32(FW_DATA_CRC_BASE +0x4, priv->iram_dl_size);//iram crc size
		skw_pcie_write32(FW_DATA_CRC_BASE +0x8, priv->iram_crc);//iram crc
		val = 3;//iram crc en
	}
	if (priv->dram_crc_en) {
		skw_pcie_write32(FW_DATA_CRC_BASE +0xc, priv->dram_crc_offset);//dram crc offset
		skw_pcie_write32(FW_DATA_CRC_BASE +0x10, priv->dram_dl_size);//dram crc size
		skw_pcie_write32(FW_DATA_CRC_BASE +0x14, priv->dram_crc);//dram crc
		val |= (3<<2);//dram crc en
	}
	if (priv->iram_crc_en || priv->dram_crc_en)
		skw_pcie_write32(FW_DATA_CRC_BASE +0x18, val);

	//set boot addr
	skw_pcie_write32(FW_BOOT_REG_BASE, 0x100000);

	//set dl done
	val = skw_pcie_read32(FW_DL_DONE_REG_BASE);
	val |= 0x3;
	skw_pcie_write32(FW_DL_DONE_REG_BASE, val);
}
#endif

int skw_WIFI_service_start(void)
{
	int count=90;
	int ret =0;
	struct wcn_pcie_info *priv= get_pcie_device_info();
	PCIE_INFO("[+],cpsts:%s\n",str_cpsts[priv->cp_state]);
	if (priv->cp_state != CP_READY) {
		while(priv->cp_state != CP_READY && count--)
			msleep(10);
	}
	if (priv->service_state_map & (1<<WIFI_SERVICE))
		return 0;

#ifdef CONFIG_SEEKWAVE_PLD_RELEASE
	//release version close the cP log
	if (!cp_log_status){
		skw_pcie_cp_log(1);
	}
#else
	if (cp_log_status){
		skw_pcie_cp_log(1);
	}
#endif

	skw_reinit_completion(priv->download_done);
	ret= send_modem_service_command(WIFI_SERVICE, SERVICE_START);
	if(!ret)
		ret = skw_check_cp_ready();

	return ret;
}

int skw_WIFI_service_stop(void)
{
	int count=50;
	struct wcn_pcie_info *priv= get_pcie_device_info();
	PCIE_INFO("[+],cpsts:%s\n",str_cpsts[priv->cp_state]);
	if (priv->cp_state != CP_READY) {
		priv->service_state_map &= ~(1<<WIFI_SERVICE);
		while(priv->cp_state != CP_READY && count--)
			msleep(10);
		return 0;
	}
	if (priv->service_state_map & (1<<WIFI_SERVICE))
		return send_modem_service_command(WIFI_SERVICE, SERVICE_STOP);
	return 0;

}

int skw_BT_service_start(void)
{
	int count = 200;
	int ret;
	struct wcn_pcie_info *priv= get_pcie_device_info();
	PCIE_INFO("[+],cpsts:%s\n",str_cpsts[priv->cp_state]);
	if (priv->cp_state != CP_READY) {
		while(priv->cp_state != CP_READY && count--)
			msleep(10);
	}
	if (!count) {
		PCIE_ERR("BT service start timeout\n");
		return -1;
	} else
		PCIE_INFO("cpsts:%s\n",str_cpsts[priv->cp_state]);
	if (priv->service_state_map & (1<<BT_SERVICE))
		return 0;

#ifdef CONFIG_SEEKWAVE_PLD_RELEASE
	//release version close the cP log
	if (!cp_log_status){
		skw_pcie_cp_log(1);
	}
#else
	if (cp_log_status){
		skw_pcie_cp_log(1);
	}
#endif

	skw_reinit_completion(priv->download_done);
	ret = send_modem_service_command(BT_SERVICE, SERVICE_START);
	if(!ret)
		ret = skw_check_cp_ready();

	return ret;
}

int skw_BT_service_stop(void)
{
	int ret = -1;
	struct wcn_pcie_info *priv= get_pcie_device_info();

	PCIE_INFO("[+],cpsts:%s\n", str_cpsts[priv->cp_state]);
	if (priv->cp_state != CP_READY) {
		priv->service_state_map &= ~(1<<BT_SERVICE);
		PCIE_INFO("No need to stop BT\n");
		/**
		 * If CP is not in CP_READY state, the BT port can
		 * close safely.
		 */
		priv->svc_op = BT_STOP;
		return 0;
	}
	if (priv->service_state_map & (1<<BT_SERVICE)) {
		skw_reinit_completion(priv->download_done);
		send_modem_service_command(BT_SERVICE, SERVICE_STOP);
		ret = wait_for_completion_interruptible_timeout(&priv->download_done, msecs_to_jiffies(1500));
		if(ret == -ERESTARTSYS) {
			PCIE_ERR("BT service stop interrupted\n");
			return -1;
		} else if (ret == 0) {
			PCIE_ERR("BT service stop timeout\n");
			return -1;
		}
	} else {
		PCIE_INFO("BT service is not running, abort stop process\n");
	}
	PCIE_INFO("[-],cpsts:%s\n", str_cpsts[priv->cp_state]);
	return 0;
}

int skw_pcie_cp_log(int disable)
{
	int ret =0;
	struct wcn_pcie_info *priv = get_pcie_device_info();
	PCIE_INFO("[+]\n");
	//cp_log_status = disable;
	if(priv->cp_state != CP_READY) {
		PCIE_ERR("[-]cpsts:%s\n", str_cpsts[priv->cp_state]);
		return ret;
	}

	ret =skw_pcie_elbi_writeb(SKWPCIE_AP2CP_SIG1, disable);
	if(ret <0){
		PCIE_ERR("[-]send ap2cp sigreg fail,%d\n", ret);
		return ret;
	}
	skw_pcie_elbi_writeb(SKW_AP2CP_IRQ_REG, 0x20);
	PCIE_INFO("[-]CP log:%s\n", disable?"disable":"enable");
	return ret;
}
int get_log_enable_status(void)
{
	return cp_log_status;
}

int skw_pcie_debug_log_open(void)
{
	PCIE_INFO("enable CP log\n");
	cp_log_status = 0;
	return cp_log_status;
}

int skw_pcie_debug_log_close(void)
{
	PCIE_INFO("disable CP log\n");
	cp_log_status = 1;
	return cp_log_status;
}
int skw_pcie_recovery_disable(int disable)
{
	 struct wcn_pcie_info *priv= get_pcie_device_info();
	 priv->recovery_dis_state = disable;
	 PCIE_INFO("recovery:%s\n", disable?"disable":"enable");
	 return 0;
}

int skw_pcie_recovery_debug_status(void)
{
	 struct wcn_pcie_info *priv= get_pcie_device_info();
	 return priv->recovery_dis_state;
}

int skw_recovery_mode(void)
{
	int ret;

	skw_pcie_rescan_bus();
	//skw_pcie_bind_bt_driver(priv->dev);
	ret = skw_pcie_boot_cp(RECOVERY_BOOT);
	if(ret != 0){
		PCIE_ERR("CP recovery boot fail!!!\n");
		return -1;
	}
	//skw_pcie_bind_wifi_driver(priv->dev);
	PCIE_INFO("Recovery ok\n");
	return 0;
}

int skw_pcie_slp_feature_en(unsigned int address, unsigned int slp_en)
{
	int ret =0;
	//ret = skw_pcie_elbi_writeb()
	if(ret !=0)
	{
		PCIE_ERR("support en write fail ret=%d\n",ret);
		return -1;
	}
	PCIE_INFO("nslp support enable:%d\n", slp_en);
	return 0;
}
/****************************************************************
*Description:
*Func:used the ap boot cp interface;
*Output:the dloader the bin to cp
*Return0:pass; other : fail
*Author:JUNWEI.JIANG
*Date:2023-06-07
****************************************************************/
int skw_pcie_boot_cp(int boot_mode)
{
	int ret =0;
	struct wcn_pcie_info *priv= get_pcie_device_info();
	//struct edma_chn_info *edma_chp = get_edma_channel_info(0);
	skw_pcie_slp_feature_en(priv->boot_data->slp_disable_addr,
			priv->boot_data->slp_disable);
#if 0
	dl_req_cnt = (priv->boot_data->iram_dl_size / 0xffff) + ((!!(priv->boot_data->iram_dl_size % 0xffff)) ? 1 : 0);
	dl_req_cnt += (priv->boot_data->dram_dl_size / 0xffff) + ((!!(priv->boot_data->dram_dl_size % 0xffff)) ? 1 : 0);
	//PCIE_DBG("dl_req_cnt=%d \n", dl_req_cnt);
	//print_hex_dump(KERN_ERR, "PACKET ERR:", 0, 16, 1, boot_data->iram_img_data, 0x100, 1);

	PCIE_INFO("1. PCIe BOOT.DEUBG..LINE %d \n", __LINE__);
	edma_chp->map_skb_addr = dma_map_single(&priv->dev->dev, (void *)priv->boot_data->dram_img_data,
			priv->boot_data->dram_dl_size, DMA_TO_DEVICE);
	//PCIE_DBG("2. PCIe FIRST BOOT... \n");

	edma_chp->map_pld_addr = dma_map_single(&priv->dev->dev, (void *)priv->boot_data->iram_img_data,
			priv->boot_data->iram_dl_size, DMA_TO_DEVICE);
	//PCIE_DBG("3. PCIe FIRST BOOT... \n");
#endif
	if (priv->boot_data->gpio_in != -1)
		skw_pcie_host_irq_init(priv->boot_data->gpio_in);
	skw_reinit_completion(priv->download_done);
	//ret |= pcie_download_fw(priv->boot_data->iram_dl_addr, priv->boot_data->iram_img_data, priv->boot_data->iram_dl_size);
	//ret |= pcie_download_fw(priv->boot_data->dram_dl_addr, priv->boot_data->dram_img_data, priv->boot_data->dram_dl_size);
	skw_pcie_create_loopcheck_thread(5);
	pcie_download_fw_iram(priv->boot_data->iram_img_data, priv->boot_data->iram_dl_size);
	pcie_download_fw_dram(priv->boot_data->dram_img_data, priv->boot_data->dram_dl_size);

	ret |= skw_check_cp_ready();
	if(ret != 0)
		return ret;

	PCIE_INFO("CP ready!!! device attach to PCIe bus\n");
	//skw_pcie_bind_wifi_driver(priv->boot_data->pdev);
	//skw_pcie_bind_bt_driver(priv->boot_data->pdev);

	return 0;
}

int skw_pcie_cp_service_ops(int service_ops)
{
	int ret = -1;
	switch(service_ops)
	{
		case SKW_WIFI_START:
			ret=skw_WIFI_service_start();
			PCIE_INFO("-----WIFI SERIVCE START\n");
		break;
		case SKW_WIFI_STOP:
			ret =skw_WIFI_service_stop();
			PCIE_INFO("----WIFI SERVICE---STOP\n");
		break;
		case SKW_BT_START:
		{
			ret=skw_BT_service_start();
			PCIE_INFO("-----BT SERIVCE --START\n");
		}
		break;
		case SKW_BT_STOP:
			ret =skw_BT_service_stop();
			PCIE_INFO("-----BT SERVICE --STOP\n");
		break;
		default:
			PCIE_ERR("service not support %d !\n", service_ops);
		break;
	}
	return ret;
}

void dump_mem_work(struct work_struct *work)
{
	PCIE_INFO("[+]\n");
	modem_notify_event(DEVICE_BLOCKED_EVENT);
	PCIE_INFO("[-]\n");
}

int skw_boot_loader(struct seekwave_device *boot_data)
{
	int ret =0;
	struct wcn_pcie_info *priv= get_pcie_device_info();
	//struct edma_chn_info *edma_chp = get_edma_channel_info(0);
	priv->boot_data= boot_data;
	if(boot_data->dl_module == RECOVERY_BOOT && boot_data->first_dl_flag) {
		schedule_delayed_work(&priv->skw_pcie_recovery_work , msecs_to_jiffies(2000));
		//skw_recovery_mode();
	}
	PCIE_DBG("iram_size=0x%x, iram_addr:0x%x, dram_size=0x%x, dram_addr=0x%x\n",
		boot_data->iram_dl_size,
		boot_data->iram_dl_addr,
		boot_data->dram_dl_size,
		boot_data->dram_dl_addr);

	PCIE_DBG("iram_img_data=0x%p, dram_img_data:0x%p\n",
		boot_data->iram_img_data,
		boot_data->dram_img_data);

	priv->chip_en = boot_data->chip_en;
	if (!boot_data->first_dl_flag) { // first boot
		skw_pcie_create_loopcheck_thread(5);
		if (boot_data->iram_dl_size && boot_data->dram_dl_size) {
			if (boot_data->chip_en > 0){
				gpio_set_value(boot_data->chip_en, 1);
				priv->chip_en = boot_data->chip_en;
			}
			PCIE_INFO("PCIe FIRST BOOT... \n");
			priv->iram_dl_size = boot_data->iram_dl_size;
			priv->dram_dl_size = boot_data->dram_dl_size;
			priv->iram_crc_offset = boot_data->iram_crc_offset;
			priv->dram_crc_offset = boot_data->dram_crc_offset;
			priv->iram_crc = boot_data->iram_crc_val;
			priv->dram_crc = boot_data->dram_crc_val;
			priv->iram_crc_en = 0;//boot_data->iram_crc_en;
			priv->dram_crc_en = 0;//boot_data->dram_crc_en;
			if (boot_data->gpio_in != -1)
				skw_pcie_host_irq_init(boot_data->gpio_in);

			//skw_pcie_bind_platform_driver(boot_data->pdev);
			//skw_pcie_create_loopcheck_thread(5);
			pcie_download_fw_iram(priv->boot_data->iram_img_data, priv->boot_data->iram_dl_size);
			pcie_download_fw_dram(priv->boot_data->dram_img_data, priv->boot_data->dram_dl_size);

			ret |= skw_check_cp_ready();
			if (!ret) {
				if (priv->chip_en >= 0) {
					skw_pcie_bind_wifi_driver(boot_data->pdev);
					skw_pcie_bind_bt_driver(boot_data->pdev);
				}else{
					PCIE_ERR("chip_en = %d Invalid Pls check HW !!\n", priv->chip_en);
					return -1;
				}
			} else {
				PCIE_ERR("CP not ready, dump memory after 5s...\n");
				schedule_delayed_work(&priv->dump_mem_work , msecs_to_jiffies(5000));
			}
		} else {
			if (cp_boot == 1) {
				PCIE_INFO("Boot from CP without Firmware!!!!\n");
				skw_pcie_bind_wifi_driver(boot_data->pdev);
				skw_pcie_bind_bt_driver(boot_data->pdev);
			} else {
				PCIE_ERR("No Firmware!!!!\n");
				ret = -1;
			}
			return ret;
		}
	} else //start service
		ret = skw_pcie_cp_service_ops(boot_data->service_ops);
	return ret;
}

void reboot_to_change_bt_uart1(char *mode)
{
	struct wcn_pcie_info *priv= get_pcie_device_info();
	struct seekwave_device *boot_data = priv->boot_data;
	u32 *data = (u32 *) &boot_data->iram_img_data[boot_data->head_addr-4];

	if(data[0] & 0x80000000)
		data[0] |=  0x0000008;
	else
		data[0] = 0x80000008;
	//skw_recovery_mode();
	send_modem_assert_command();

}

int skw_reset_bus_dev(void)
{
	struct wcn_pcie_info *priv= get_pcie_device_info();

	if (priv->chip_en >= 0) {
		PCIE_INFO("power up-down chip_en\n");
		gpio_set_value(priv->chip_en,0);
		msleep(50);
		gpio_set_value(priv->chip_en, 1);
	} else
		PCIE_ERR("chip_en is not configured, check \"MODEM_ENABLE_GPIO\" in boot_config.h!!!");

	return 0;
}
void get_bt_antenna_mode(char *mode)
{
	struct wcn_pcie_info *priv= get_pcie_device_info();
	struct seekwave_device *boot_data = priv->boot_data;
	u32 bt_antenna = boot_data->bt_antenna;

	if(bt_antenna==0)
		return;
	bt_antenna--;
	if(!mode)
		return;
	if (bt_antenna)
		sprintf(mode,"bt_antenna : alone\n");
	else
		sprintf(mode,"bt_antenna : share\n");
}

void reboot_to_change_bt_antenna_mode(char *mode)
{
	struct wcn_pcie_info *priv= get_pcie_device_info();
	struct seekwave_device *boot_data = priv->boot_data;
	u32 *data = (u32 *) &boot_data->iram_img_data[boot_data->head_addr-4];
	u32 bt_antenna;

	if(boot_data->bt_antenna == 0)
		return;
	bt_antenna = boot_data->bt_antenna - 1;
		bt_antenna = 1 - bt_antenna;
	data[0] = (bt_antenna) | 0x80000000;
	if(!mode)
		return;
	if (bt_antenna==1) {
		boot_data->bt_antenna = 2;
		sprintf(mode,"bt_antenna : alone\n");
	} else {
		boot_data->bt_antenna = 1;
		sprintf(mode,"bt_antenna : share\n");
	}
	send_modem_assert_command();
}
void *skw_get_bus_dev(void)
{
	struct wcn_pcie_info *priv = get_pcie_device_info();
	return &priv->dev->dev;
}

static int skw_check_cp_ready(void)
{
	struct wcn_pcie_info *priv = get_pcie_device_info();

	PCIE_INFO("check CP-ready Enter!!\n");
	if (wait_for_completion_timeout(&priv->download_done,
		msecs_to_jiffies(3000)) == 0) {
		 PCIE_ERR("check CP-ready time out\n");
		 return -ETIME;
	}
	return 0;
}

