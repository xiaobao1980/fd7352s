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
#include "asm-generic/errno-base.h"
#include "asm/io.h"
#include "linux/compiler.h"
#include "linux/irqreturn.h"
#include "linux/pci.h"
#include "linux/types.h"
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
#include <linux/iopoll.h>
#include <linux/dma-mapping.h>
#include <linux/firmware.h>
#include <linux/fs.h>
#include "skw_edma_drv.h"
#include "skw_pcie_drv.h"
#include "skw_pcie_log.h"
#include "skw_edma_reg.h"
#include "skw_pcie_debugfs.h"
#include "dbgbus.h"

#define SWT6652_V2
//#define SBDRSM_DEBUG

static struct wcn_pcie_info *g_pcie_dev;
int cp_boot = 0;

#if (CONFIG_PCIE_INT_TYPE == INT_MSI)
static int pcie_int = 1;
#elif (CONFIG_PCIE_INT_TYPE == INT_LEGACY_INTX)
static int pcie_int = 2;
#elif (CONFIG_PCIE_INT_TYPE == INT_MSIX)
static int pcie_int = 3;
#endif
module_param(pcie_int, int, S_IRUGO);
module_param(cp_boot, int, S_IRUGO);
MODULE_PARM_DESC(pcie_int, "1-msi, 2-legacy, 3-msix, if no param, msi default");
MODULE_PARM_DESC(cp_boot, "0-ap boot, 1-cp boot, if no param, ap boot default");

extern void skw_pcie_exception_work(struct work_struct *work);

struct wcn_pcie_info *get_pcie_device_info(void)
{
	return g_pcie_dev;
}

static int inline is_msi_irq_wifi_takeover(struct wcn_pcie_info *priv, int irq)
{
	int ch_id;

	if (priv->msix_en == 1) {
		ch_id = irq/2;
	} else
		ch_id = irq;

	if (ch_id == EDMA_WIFI_TX0_FREE_ADDR || ch_id == EDMA_WIFI_TX1_FREE_ADDR
		|| ch_id == EDMA_WIFI_RX0_PKT_ADDR || ch_id == EDMA_WIFI_RX1_PKT_ADDR
		|| ch_id == EDMA_WIFI_RX0_FILTER_DATA_CHN || ch_id == EDMA_WIFI_RX1_FILTER_DATA_CNH
		|| ch_id == EDMA_WIFI_TX0_PACKET_ADDR || ch_id == EDMA_WIFI_TX1_PACKET_ADDR)

		return 1;
	else
		return 0;
}

#if !defined(CONFIG_SKW_MSI_AS_LEGACY) || defined(CONFIG_MSIX_SUPPORT)
static int skw_pcie_msi_irq(int irq, void *arg)
{
	struct wcn_pcie_info *priv = get_pcie_device_info();

	//PCIE_DBG("vector=%d\n", irq);
	irq = *(u16 *)arg;
	PCIE_DBG("irq_num=%d\n", irq);
	//skw_edma_lock_event();
	if (is_msi_irq_wifi_takeover(priv, irq))
		msi_irq_wifi_takeover_handler(irq);
	else
		msi_edma_channel_irq_handler(irq);

	return IRQ_HANDLED;
}
#endif

static int legacy_pcie_irq_handle(struct wcn_pcie_info *priv)
{
	u32 val;

	val = (skw_pcie_read32(0x40190050) & 0xff00) >> 8;
	PCIE_DBG("pcie legacy int sts=0x%x\n", val);
	skw_pcie_write32(0x4019004c, val);
	return IRQ_HANDLED;
}

static irqreturn_t pcie_legacy_irq(int irq, void *arg)
{
	struct wcn_pcie_info *priv = (struct wcn_pcie_info *)arg;

	PCIE_DBG("irq_num=%d\n", irq);
	if (skw_pcie_read32(0x40188004))
		legacy_edma_irq_handle();
	else if (skw_pcie_read32(0x40190050) & 0xff00)
		legacy_pcie_irq_handle(priv);

	return IRQ_HANDLED;
}

static void ib_map(struct wcn_pcie_info *priv, u32 cp_addr, u64 ap_addr, u32 map_size, u32 ibreg_off)
{
	writel_relaxed((ap_addr & 0xffff0000) | (ilog2(map_size) - 1), priv->pciaux + ibreg_off + 4);
	writel_relaxed((ap_addr >> 32) & 0xffffffff, priv->pciaux + ibreg_off + 8);
	writel_relaxed(cp_addr, priv->pciaux + ibreg_off + 0xc);
	writel_relaxed(1, priv->pciaux + ibreg_off + 0);
}

static int ep_address_mapping(struct wcn_pcie_info *priv)
{
	//ib0: map 2M(0x2000000) (0x40000000-0x401fffff)
	ib_map(priv, 0x40000000, priv->mem_pciaddr, 0x200000, IBREG0_OFFSET_ADDR);
	//ib1:IRAM 1M (0x100000-0x1FFFFF)
	ib_map(priv, 0x100000, priv->mem_pciaddr + 0x200000, 0x100000, IBREG1_OFFSET_ADDR);
	//ib2:DRAM 1M (0x20200000-0x202FFFFF)
	ib_map(priv, 0x20200000, priv->mem_pciaddr + 0x300000, 0x100000, IBREG2_OFFSET_ADDR);
	if (priv->dev->device != 0x6316) {
		//ib4:up sys 1M(0x40310000-0x4032FFFF)
		ib_map(priv, 0x40310000, priv->dump_pciaddr + 0x200000, 0x100000, IBREG4_OFFSET_ADDR);
	}
#ifdef SWT6652_V2
	//ob0
	writel_relaxed(31, priv->pciaux + OBREG0_OFFSET_ADDR + 4);
	writel_relaxed(0x00000080, priv->pciaux + OBREG0_OFFSET_ADDR + 8);
	writel_relaxed(0x00000000, priv->pciaux + OBREG0_OFFSET_ADDR + 0xc);
	writel_relaxed(0x00000000, priv->pciaux + OBREG0_OFFSET_ADDR + 0x10);
	writel_relaxed(0xff, priv->pciaux + OBREG0_OFFSET_ADDR + 0x18);
	writel_relaxed(1, priv->pciaux + OBREG0_OFFSET_ADDR + 0);
#else
	//ob0
	writel_relaxed(31, priv->pciaux + OBREG0_OFFSET_ADDR + 4);
	writel_relaxed(0x00000080, priv->pciaux + OBREG0_OFFSET_ADDR + 8);
	writel_relaxed(0x00000000, priv->pciaux + OBREG0_OFFSET_ADDR + 0xc);
	writel_relaxed(0x00000000, priv->pciaux + OBREG0_OFFSET_ADDR + 0x10);
	writel_relaxed(1, priv->pciaux + OBREG0_OFFSET_ADDR + 0);

	//ob1
	writel_relaxed(31, priv->pciaux + OBREG1_OFFSET_ADDR + 4);
	writel_relaxed(0x00000081, priv->pciaux + OBREG1_OFFSET_ADDR + 8);
	writel_relaxed(0x00000000, priv->pciaux + OBREG1_OFFSET_ADDR + 0xc);
	writel_relaxed(0x00000001, priv->pciaux + OBREG1_OFFSET_ADDR + 0x10);
	writel_relaxed(1, priv->pciaux + OBREG1_OFFSET_ADDR + 0);
#endif
	return 0;
}

int skw_pcie_mem_dump(unsigned int system_addr, void *buf,unsigned int len)
{
	struct wcn_pcie_info *priv = get_pcie_device_info();
	u32 addrl16, addrh16;

	addrl16 = system_addr & 0xffff;
	addrh16 = system_addr & 0xffff0000;


	if (!pci_device_is_present(priv->dev)) {
		PCIE_ERR("PCIe link is Down!!!\n");
		return -ENODEV;
	}
	//ib3:2M (0x200000)
	ib_map(priv, addrh16, priv->dump_pciaddr, 0x200000, IBREG3_OFFSET_ADDR);
	memcpy_fromio(buf, priv->pcidump + addrl16, len);

	return 0;
}

u32 skw_pcie_read32(u32 reg_addr)
{
	struct wcn_pcie_info *priv = get_pcie_device_info();
	char *address = priv->pcimem;

	reg_addr -= 0x40000000;
	address += reg_addr;
	rmb();
	return readl_relaxed(address);
}

void skw_pcie_write32(u32 reg_addr, u32 value)
{
	struct wcn_pcie_info *priv = get_pcie_device_info();
	char *address = priv->pcimem;

	reg_addr -= 0x40000000;
	address += reg_addr;
	writel_relaxed(value, address);
	wmb();
}

void skw_pcie_setbit(u32 reg_addr, u32 bits)
{
	int val;
	struct wcn_pcie_info *priv = get_pcie_device_info();
	char *address = priv->pcimem;

	reg_addr -= 0x40000000;
	address += reg_addr;
	val = readl_relaxed(address);
	val |= bits;
	writel_relaxed(val, address);
}

void skw_pcie_clrbit(u32 reg_addr, u32 bits)
{
	int val;
	struct wcn_pcie_info *priv = get_pcie_device_info();
	char *address = priv->pcimem;

	reg_addr -= 0x40000000;
	address += reg_addr;
	val = readl_relaxed(address);
	val &= ~bits;
	writel_relaxed(val, address);
}

u64 edma_phyaddr_to_pcieaddr(u64 phy_addr)
{
	u64 val;

	val = 0x8000000000 + phy_addr;
	return val;
}

u64 edma_virtaddr_to_pcieaddr(void *virt_addr)
{
	u64 val;
	u64 phy_addr;

	phy_addr = virt_to_phys(virt_addr);
	val = 0x8000000000 + phy_addr;
	return val;
}

u64 edma_pcieaddr_to_phyaddr(u64 phy_addr)
{
	u64 val;

	val = phy_addr - 0x8000000000;
	return val;
}

u64 edma_pcieaddr_to_virtaddr(u64 phy_addr)
{
	u64 val;
	u64 virt_addr;

	val = phy_addr - 0x8000000000;
	virt_addr = (u64)phys_to_virt(val);
	return virt_addr;
}

static size_t buffer_dump_swd_len = 0;
u8 swdata_dump[0x2000]; // 8k buffer

ssize_t skw_pcie_swd_read(char __user *buffer, size_t length, loff_t *offset)
{
	size_t bytes_to_read;
	ssize_t bytes_read;

	if (*offset >= buffer_dump_swd_len) {
		return 0;
	}

	bytes_to_read = min(length, buffer_dump_swd_len - (size_t)*offset);

	if (copy_to_user(buffer, swdata_dump + *offset, bytes_to_read)) {
		return -EFAULT;
	}

	*offset += bytes_to_read;
	bytes_read = bytes_to_read;

	return bytes_read;
}

void skw_pcie_swdump(void)
{
	int i, j;
	u32 word;
	u32 sys_cnt;
	sys_grps_t dbgbus;
	char *ptr_dump_swd;
	sys_t *sys_sig_sel;
	pcie_misc_ctrl_0_t misc_ctrl0;
	static char *buffer_dump_swd = NULL;
	struct wcn_pcie_info *priv = get_pcie_device_info();

	if (!pci_device_is_present(priv->dev)) {
		PCIE_ERR("PCIe link is Down!!!\n");
		return;
	}

	if (priv->dev->device == 0x6316) {
		sys_sig_sel = SIG_SEL(6652);
		sys_cnt = sizeof(SIG_SEL(6652))/sizeof(SIG_SEL(6652)[0]);
	} else if (priv->dev->device == 0x6315) {
		sys_sig_sel = SIG_SEL(6652s);
		sys_cnt = sizeof(SIG_SEL(6652s))/sizeof(SIG_SEL(6652s)[0]);
	} else
		return;

	for (i = 0;i < sys_cnt; i++) {
		dbgbus.sys_name[i] = sys_sig_sel[i].sys_name;
		dbgbus.sys_sel[i] = sys_sig_sel[i].sys_sel;
		dbgbus.sig_sel[i] = sys_sig_sel[i].sig_sel;
		dbgbus.sig_cnt[i] = sys_sig_sel[i].sig_cnt;
		buffer_dump_swd_len += dbgbus.sig_cnt[i] * 4 * 3;
	}

	buffer_dump_swd = kzalloc(buffer_dump_swd_len, GFP_KERNEL);
	if (!buffer_dump_swd) {
		PCIE_ERR("failed to alloc mem\n");
		return;
	}
	ptr_dump_swd = buffer_dump_swd ;
	PCIE_INFO("buffer_dump_swd_len:%d\n", buffer_dump_swd_len);

	for (i = 0; i < sys_cnt; i++) {
		PCIE_INFO("======sys: %s(%d), sig_num: %d======\n", dbgbus.sys_name[i], dbgbus.sys_sel[i], dbgbus.sig_cnt[i]);
		for (j = 0; j < dbgbus.sig_cnt[i]; j++) {
			/* sel sys|sig */
			pci_read_config_dword(priv->dev,PCIE_MISC_CTRL_0, &misc_ctrl0.reg_val);
			misc_ctrl0.enable = 1;
			misc_ctrl0.sys_sel = dbgbus.sys_sel[i];
			misc_ctrl0.signals_sel = dbgbus.sig_sel[i][j];
			pci_write_config_dword(priv->dev, PCIE_MISC_CTRL_0, misc_ctrl0.reg_val);
			pci_read_config_dword(priv->dev, PCIE_MISC_STATUS_0, &word);
			PCIE_INFO("sys: %s, sig_sel: %d, word: 0x%08x\n", dbgbus.sys_name[i], dbgbus.sig_sel[i][j], word);

			//write data to buffer
			memcpy(ptr_dump_swd, (char *)&dbgbus.sys_sel[i], 4);
			ptr_dump_swd += 4;
			memcpy(ptr_dump_swd, (char *)&dbgbus.sig_sel[i][j], 4);
			ptr_dump_swd += 4;
			memcpy(ptr_dump_swd, (char *)&word, 4);
			ptr_dump_swd += 4;
		}
	}
	//print_hex_dump(KERN_ERR, "dump_swd:", 0, 16, 1, buffer_dump_swd, buffer_dump_swd_len, 1);
	//recover misc_ctrl0
	pci_read_config_dword(priv->dev,PCIE_MISC_CTRL_0, &misc_ctrl0.reg_val);
	misc_ctrl0.enable = 0;
	pci_write_config_dword(priv->dev, PCIE_MISC_CTRL_0, misc_ctrl0.reg_val);
	memcpy(swdata_dump, buffer_dump_swd, buffer_dump_swd_len);
	kfree(buffer_dump_swd);
}

static void skw_pcie_remove(struct pci_dev *pdev)
{
#ifdef CONFIG_MSIX_SUPPORT
	int i;
#endif
	struct wcn_pcie_info *priv;

	PCIE_INFO("[+]\n");
	priv = (struct wcn_pcie_info *) pci_get_drvdata(pdev);

	if (priv->legacy_en == 1) {
		PCIE_INFO("free INTx int");
		free_irq(priv->irq, (void *)priv);
	}
	if (priv->msi_en == 1) {
		PCIE_INFO("free MSI");
#ifndef CONFIG_SKW_MSI_AS_LEGACY
		for (i = 0; i < priv->irq_num; i++)
			free_irq(priv->irq + i, &priv->msix_vec_idx[i]);
#else
		free_irq(priv->irq, (void *)priv);
#endif
		pci_disable_msi(pdev);
	}
#ifdef CONFIG_MSIX_SUPPORT
	if (priv->msix_en == 1) {
		PCIE_INFO("free MSI-X");
		for (i = 0; i < priv->irq_num; i++)
			free_irq(priv->msix[i].vector, &priv->msix[i].entry);

		pci_disable_msix(pdev);
		kfree(priv->msix);
	}
#endif
	if (priv->boot_data->gpio_in != -1) {
		free_irq(priv->gpio_irq_num, NULL);
		disable_irq_wake(priv->gpio_irq_num);
	}

	PCIE_INFO("deinit edma\n");
	skw_edma_deinit();
	PCIE_INFO("unmap pci\n");
	iounmap(priv->pcimem);
	iounmap(priv->pciaux);
	PCIE_INFO("release pci regions\n");
	pci_release_regions(pdev);
	pci_set_drvdata(pdev, NULL);
	PCIE_INFO("disable pci device\n");
	pci_disable_device(pdev);
	PCIE_INFO("remove loopcheck\n");
	skw_pcie_remove_loopcheck_thread(5);
	PCIE_INFO("[-]\n");
}

int get_service_busy_sts(void)
{
	int ret;
	u32 status;
	struct wcn_pcie_info *priv = get_pcie_device_info();

	ret = readl_poll_timeout(priv->pcimem + 0x108160,
				 status, ((status & WIFI_DO_SUSPEND_MASK) == 0), 10, 2000);
	if (ret) {
		PCIE_ERR("Service doesn't allow suspend!!!\n");
		return -1;
	}

	return 0;
}

int skw_notify_ep_enter_l2(void)
{
	u32 val, status;
	int ret;
	struct wcn_pcie_info *priv = get_pcie_device_info();

	val = skw_pcie_read32(SKW_CP_PMU_SW_REG);
	val &= ~L2_SHAKE_MASK;
	val |= 0xd2;
	skw_pcie_write32(SKW_CP_PMU_SW_REG, val);
	ret = readl_poll_timeout(priv->pcimem + 0x108160,
				 status, ((status & L2_SHAKE_MASK) == 0xd2), 5, 100);
	if (ret) {
		PCIE_ERR("Failed to read SKW_CP_PMU_SW_REG\n");
		return -1;
	}
	/* for cp no edma req */
	mdelay(1);
	return 0;
}

void skw_notify_ep_exit_l2(void)
{
	u32 val;

	val = skw_pcie_read32(SKW_CP_PMU_SW_REG);
	val &= ~L2_SHAKE_MASK;
	skw_pcie_write32(SKW_CP_PMU_SW_REG, val);
}

static int skw_ep_suspend(struct device *dev)
{
	int ret;
#ifndef SWT6652_V2
	int i;
	int pba_entries_num;
	u32 pba_table_offset;
	u8 pba_bir;
	u32 val;
#endif
#ifndef CONFIG_BT_SEEKWAVE
	int i;
#endif

	struct pci_dev *pdev = to_pci_dev(dev);
	struct wcn_pcie_info *priv = pci_get_drvdata(pdev);

	if (!pdev)
		return -ENODEV;

	PCIE_INFO("[+]\n");

	ret = get_service_busy_sts();
	if (ret)
		return -EBUSY;

	/* notify CP enter L2 */
	ret = skw_notify_ep_enter_l2();
	if (ret)
		goto busy;

	/* pause edma */
	ret = skw_edma_pause();
	if (ret) {
		skw_edma_restore();
		goto busy;
	}

#ifndef CONFIG_BT_SEEKWAVE
	/* clr bt host dst node */
	for (i = EDMA_BTACL_PORT; i < EDMA_LOG_PORT+1; i+=2)
		skw_pcie_write32(DMA_NODE_TOT_CNT(i), 0x80000000);
#endif
#ifndef SWT6652_V2
	/* close L1sub */
		/* disable L1SS */
	pci_read_config_dword(pdev, pdev->l1ss + PCI_L1SS_CTL1, &val);
	val &= ~PCI_L1SS_CTL1_L1SS_MASK;
	pci_write_config_dword(pdev, pdev->l1ss + PCI_L1SS_CTL1, val);
		/* disable L1 Entry & CLKREQ */
	pcie_capability_clear_and_set_word(pdev, PCI_EXP_LNKCTL,
					PCI_EXP_LNKCTL_ASPMC | PCI_EXP_LNKCTL_CLKREQ_EN, 0);

	/* clear PBA */
	pci_read_config_dword(pdev, pdev->msix_cap + PCI_MSIX_PBA,
			      &pba_table_offset);
	PCIE_INFO("pdev->msix_cap=0x%x\n", pdev->msix_cap);
	PCIE_INFO("pba_table_offset=0x%x\n", pba_table_offset);
	pba_bir = (u8)(pba_table_offset & PCI_MSIX_PBA_BIR);

	pba_entries_num = (priv->irq_num % 64)?(priv->irq_num/64 + 1):(priv->irq_num/64);
	PCIE_INFO("pba_entries_num=0x%x\n", pba_entries_num);
	PCIE_INFO("priv->irq_num=0x%x\n", priv->irq_num);

	for (i=0;i<pba_entries_num*2;i++) {
		PCIE_INFO("1. pba[%d]=0x%08x\n", i, readl_relaxed(priv->pciaux+ pba_table_offset + i*4));
		writel_relaxed(0, priv->pciaux + pba_table_offset + i*4);
		PCIE_INFO("2. pba[%d]=0x%08x\n", i, readl_relaxed(priv->pciaux+ pba_table_offset + i*4));
	}
#endif
	pci_save_state(to_pci_dev(dev));
	priv->saved_state = pci_store_saved_state(to_pci_dev(dev));
	ret = pci_enable_wake(pdev, PCI_D3hot, 1);
	PCIE_INFO("pci_enable_wake(PCI_D3hot) ret %d\n", ret);
	ret = pci_set_power_state(pdev, PCI_D3hot);
	PCIE_INFO("pci_set_power_state(PCI_D3hot) ret %d\n", ret);

#ifdef SBDRSM_DEBUG
	pci_read_config_dword(pdev, pdev->l1ss + PCI_L1SS_CTL1, &val);
	PCIE_INFO("[PCI_L1SS_CTL1]=0x%x\n", val);
	pcie_capability_read_dword(pdev, PCI_EXP_LNKCTL, &val);
	PCIE_INFO("[PCI_EXP_LNKCTL]=0x%x\n", val);
#endif
	PCIE_INFO("[-]\n");
	return 0;
busy:
	skw_notify_ep_exit_l2();
	return -EBUSY;
}

static int skw_ep_resume(struct device *dev)
{
	int ret;
#ifndef SWT6652_V2
	int i;
	u32 val;
	u32 pba_table_offset;
	int pba_entries_num;
	u8 pba_bir;
#endif
	struct pci_dev *pdev = to_pci_dev(dev);
	struct wcn_pcie_info *priv = pci_get_drvdata(pdev);

	PCIE_INFO("[+]\n");

	if (!pdev) {
		return -ENODEV;
	}

#ifndef SWT6652_V2
	pci_read_config_dword(pdev, pdev->msix_cap + PCI_MSIX_PBA,
			      &pba_table_offset);
	PCIE_INFO("pdev->msix_cap=0x%x\n", pdev->msix_cap);
	PCIE_INFO("pba_table_offset=0x%x\n", pba_table_offset);
	pba_bir = (u8)(pba_table_offset & PCI_MSIX_PBA_BIR);
	pba_entries_num = (priv->irq_num % 64)?(priv->irq_num/64 + 1):(priv->irq_num/64);
	for (i=0;i<pba_entries_num*2;i++) {
		//writel_relaxed(0,priv->pciaux + pba_table_offset + i*4);
		PCIE_INFO("pba[%d]=0x%08x\n", i, readl_relaxed(priv->pciaux + pba_table_offset + i*4));
	}
#endif
	pci_load_and_free_saved_state(to_pci_dev(dev), &priv->saved_state);
#ifdef SBDRSM_DEBUG
	pci_read_config_dword(pdev, pdev->l1ss + PCI_L1SS_CTL1, &val);
	PCIE_INFO("[PCI_L1SS_CTL1]=0x%x\n", val);
	pcie_capability_read_dword(pdev, PCI_EXP_LNKCTL, &val);
	PCIE_INFO("[PCI_EXP_LNKCTL]=0x%x\n", val);
#endif
	pci_restore_state(to_pci_dev(dev));
#ifdef SBDRSM_DEBUG
	pci_read_config_dword(pdev, pdev->l1ss + PCI_L1SS_CTL1, &val);
	PCIE_INFO("[PCI_L1SS_CTL1]=0x%x\n", val);
	pcie_capability_read_dword(pdev, PCI_EXP_LNKCTL, &val);
	PCIE_INFO("[PCI_EXP_LNKCTL]=0x%x\n", val);
#endif
	ret = pci_set_power_state(pdev, PCI_D0);
#ifdef SBDRSM_DEBUG
	pci_read_config_dword(pdev, pdev->l1ss + PCI_L1SS_CTL1, &val);
	PCIE_INFO("[PCI_L1SS_CTL1]=0x%x\n", val);
	pcie_capability_read_dword(pdev, PCI_EXP_LNKCTL, &val);
	PCIE_INFO("[PCI_EXP_LNKCTL]=0x%x\n", val);
#endif
	PCIE_INFO("pci_set_power_state(PCI_D0) ret %d\n", ret);
	ret = pci_enable_wake(pdev, PCI_D0, 0);
#ifdef SBDRSM_DEBUG
	pci_read_config_dword(pdev, pdev->l1ss + PCI_L1SS_CTL1, &val);
	PCIE_INFO("[PCI_L1SS_CTL1]=0x%x\n", val);
	pcie_capability_read_dword(pdev, PCI_EXP_LNKCTL, &val);
	PCIE_INFO("[PCI_EXP_LNKCTL]=0x%x\n", val);
#endif
	PCIE_INFO("pci_enable_wake(PCI_D0) ret %d\n", ret);

	ep_address_mapping(priv);

#ifdef SBDRSM_DEBUG
	pci_read_config_dword(pdev, pdev->l1ss + PCI_L1SS_CTL1, &val);
	PCIE_INFO("[PCI_L1SS_CTL1]=0x%x\n", val);
	pcie_capability_read_dword(pdev, PCI_EXP_LNKCTL, &val);
	PCIE_INFO("[PCI_EXP_LNKCTL]=0x%x\n", val);
#endif
	skw_edma_restore();
	skw_notify_ep_exit_l2();

#ifndef SWT6652_V2
	/* enable L1sub */
	//enable L1SS
	pci_read_config_dword(pdev, pdev->l1ss + PCI_L1SS_CTL1, &val);
	val |= PCI_L1SS_CTL1_L1SS_MASK;
	pci_write_config_dword(pdev, pdev->l1ss + PCI_L1SS_CTL1, val);

	//enable L1 Entry & CLKREQ
	pcie_capability_clear_and_set_word(pdev, PCI_EXP_LNKCTL,
					0,
					PCI_EXP_LNKCTL_ASPMC | PCI_EXP_LNKCTL_CLKREQ_EN);
#endif
#ifdef SBDRSM_DEBUG
	pci_read_config_dword(pdev, pdev->l1ss + PCI_L1SS_CTL1, &val);
	PCIE_INFO("[PCI_L1SS_CTL1]=0x%x\n", val);
	pcie_capability_read_dword(pdev, PCI_EXP_LNKCTL, &val);
	PCIE_INFO("[PCI_EXP_LNKCTL]=0x%x\n", val);
#endif
	PCIE_INFO("[-]\n");
	return 0;
}

irqreturn_t skw_gpio_irq_handler(int irq, void *dev_id) //interrupt
{
	return IRQ_HANDLED;
}

int skw_pcie_host_irq_init(unsigned int irq_gpio_num)
{
	struct wcn_pcie_info *priv = get_pcie_device_info();
	int ret = 0;

	PCIE_INFO("gpio_pewake:%d\n", irq_gpio_num);
	if (irq_gpio_num < 0)
		return -EINVAL;

	priv->gpio_irq_num = gpio_to_irq(irq_gpio_num);
	priv->irq_trigger_type = IRQF_TRIGGER_FALLING;
	if (priv->gpio_irq_num) {
		ret = request_irq(priv->gpio_irq_num, skw_gpio_irq_handler,
				priv->irq_trigger_type | IRQF_ONESHOT, "skw-pewake", NULL);
		if (ret != 0) {
			free_irq(priv->gpio_irq_num, NULL);
			PCIE_ERR("request gpio irq fail ret=%d\n", ret);
			return -1;
		} else {
			PCIE_DBG("gpio request_irq=%d!\n", priv->gpio_irq_num);
		}
	}
	enable_irq_wake(priv->gpio_irq_num);
	return ret;
}

void skw_pcie_rescan_bus(void)
{
	struct wcn_pcie_info *priv = get_pcie_device_info();
	struct pci_bus	*pbus = priv->dev->bus;
	unsigned long timeout = jiffies + msecs_to_jiffies(2000); //timeout 2s
	int timeout_occurred = 0;

	PCIE_INFO("[+]\n");
	while (port_sta_rec[EDMA_BTCMD_PORT] != 0 || port_sta_rec[EDMA_BTACL_PORT] != 0 || \
			port_sta_rec[EDMA_BTAUDIO_PORT] != 0 || port_sta_rec[EDMA_ISOC_PORT] != 0) {
		if (time_after(jiffies, timeout)) {
			PCIE_ERR("BT close timeout 2s\n");
			timeout_occurred = 1;
			break;
		}
		barrier();
	}
	if (!timeout_occurred)
		PCIE_INFO("bt closed\n");
	pci_stop_and_remove_bus_device_locked(priv->dev);
	PCIE_INFO("\n");
	pci_lock_rescan_remove();
	//PCIE_INFO("recv:----chipen_gpio=%d,(%d,%s)\n", priv->chip_en, read, buffer);
	gpio_set_value(priv->chip_en, 0);
	PCIE_INFO("recv:----chipen=%d\n", gpio_get_value(priv->chip_en));
	msleep(50);
	gpio_set_value(priv->chip_en, 1);
	PCIE_INFO("recv:----chipen=%d\n", gpio_get_value(priv->chip_en));
	msleep(100);
	PCIE_INFO("\n");
	pci_rescan_bus(pbus);
	PCIE_INFO("\n");
	pci_unlock_rescan_remove();
	PCIE_INFO("\n");
	PCIE_INFO("[-]\n");
}

void skw_pcie_recovery_work(struct work_struct *work)
{
	int ret;
	//struct wcn_pcie_info *priv = get_pcie_device_info();

	skw_pcie_rescan_bus();

	ret = skw_pcie_boot_cp(RECOVERY_BOOT);
	if(ret!=0){
		PCIE_ERR("CP RESET fail \n");
		return;
	}
	//skw_pcie_bind_wifi_driver(priv->dev);
	PCIE_INFO("SKW PCIe Recovery ok\n");
}

int check_chipid(void)
{
	unsigned int tmp_chipid0;
	unsigned int tmp_chipid1;
	unsigned int tmp_chipid2;
	unsigned int tmp_chipid3;
	struct wcn_pcie_info *priv = get_pcie_device_info();

	tmp_chipid0 =  skw_pcie_read32(SKW_CHIP_ID0);
	tmp_chipid1 =  skw_pcie_read32(SKW_CHIP_ID1);
	tmp_chipid2 =  skw_pcie_read32(SKW_CHIP_ID2);
	tmp_chipid3 =  skw_pcie_read32(SKW_CHIP_ID3);

	memcpy(&priv->chip_id, &tmp_chipid0,4);
	memcpy(&priv->chip_id[1], &tmp_chipid1,4);
	memcpy(&priv->chip_id[2], &tmp_chipid2,4);
	memcpy(&priv->chip_id[3], &tmp_chipid3,4);

	PCIE_INFO("Chip ID:%s\n", (char *)priv->chip_id);
	return 0;
}

static int skw_pcie_legacy_int_init(struct pci_dev *pdev)
{
	int ret = 0;
	struct wcn_pcie_info *priv = get_pcie_device_info();

	ret = request_irq(priv->irq, &pcie_legacy_irq, IRQF_SHARED, DRV_NAME, priv);
	if (ret) {
		PCIE_ERR("request_irq(%d), error %d\n", priv->irq, ret);
		return -1;
	}
	PCIE_INFO("request_irq(%d) ok\n", priv->irq);

	return ret;
}

static int skw_pcie_msi_int_init(struct pci_dev *pdev)
{
	int ret = 0;
	struct wcn_pcie_info *priv = get_pcie_device_info();
#ifndef CONFIG_SKW_MSI_AS_LEGACY
	int i;

	priv->irq_num = pci_msi_vec_count(pdev);
	PCIE_DBG("pci_msix_vec_count ret %d\n", priv->irq_num);

	ret = pci_alloc_irq_vectors(pdev, 1, priv->irq_num, PCI_IRQ_MSI);
#else
	ret = pci_alloc_irq_vectors(pdev, 1, 1, PCI_IRQ_MSI);
#endif
	if (ret < 0) {
		PCIE_ERR("pci_enable_msi_range err=%d\n", ret);
		goto err_out;
	}
#ifndef CONFIG_SKW_MSI_AS_LEGACY
	priv->irq = pdev->irq;
	for (i = 0; i < priv->irq_num; i++) {
		priv->msix_vec_idx[i] = i;
		ret = request_irq(priv->irq + i,
				(irq_handler_t) (&skw_pcie_msi_irq),
				IRQF_SHARED, DRV_NAME, &priv->msix_vec_idx[i]);
		if (ret) {
			PCIE_ERR("request_irq(%d), error %d\n",
				priv->irq + i, ret);
			break;
		}
		PCIE_INFO("request_irq(%d) ok\n", priv->irq + i);
	}
#else /* CONFIG_SKW_MSI_AS_LEGACY */
#if defined(IRQF_SHARED)
	priv->irq = pdev->irq;
	ret = request_irq(pdev->irq, (irq_handler_t) (&pcie_legacy_irq), IRQF_SHARED, DRV_NAME, priv);
#else /* IRQF_SHARED */
	ret = request_irq(pdev->irq, (irq_handler_t) (&pcie_legacy_irq), SA_SHIRQ, DRV_NAME, priv);
#endif /* IRQF_SHARED */
	PCIE_INFO("request_irq(%d) ok\n", pdev->irq);
#endif /* CONFIG_SKW_MSI_AS_LEGACY */

err_out:
	return ret;
}

static int skw_pcie_msix_int_init(struct pci_dev *pdev)
{
	int ret = 0;
#ifdef CONFIG_MSIX_SUPPORT
	int i;
	int vectors;
	struct wcn_pcie_info *priv = get_pcie_device_info();

	vectors = pci_msix_vec_count(pdev);
	PCIE_DBG("vectors=0x%x\n", vectors);
	priv->msix = kzalloc((sizeof(struct msix_entry) * vectors), GFP_KERNEL);
	if (!priv->msix) {
		PCIE_ERR("failed to allocate msi-x vectors!\n");
		ret = -ENOMEM;
		goto err_out;
	}
	for (i = 0; i < vectors; i++)
		priv->msix[i].entry = i;
	priv->irq_num = pci_enable_msix_range(pdev, priv->msix, 1, vectors);
	if (priv->irq_num < 0) {
		PCIE_ERR("pci_enable_msix_range %d err\n", priv->irq_num);
		kfree(priv->msix);
		goto err_out;
	}
	priv->irq = priv->msix[0].vector;

	for (i = 0; i < priv->irq_num; i++) {
		PCIE_DBG("priv->irq=0x%x\n", priv->irq);
		PCIE_DBG("priv->irq_num=0x%x\n", priv->irq_num);
		PCIE_DBG("priv->msix[i].vector=0x%x\n", priv->msix[i].vector);
		ret = request_irq(priv->msix[i].vector,
				(irq_handler_t) (&skw_pcie_msi_irq),
				IRQF_SHARED, DRV_NAME, &priv->msix[i].entry);
		if (ret) {
			PCIE_ERR("request_irq(%d), error %d\n",
				priv->msix[i].vector, ret);
			break;
		}
		PCIE_INFO("request_irq(%d) ok\n", priv->msix[i].vector);
	}
err_out:
#endif /* CONFIG_MSIX_SUPPORT */
	return ret;
}

static int skw_pcie_probe(struct pci_dev *pdev, const struct pci_device_id *pci_id)
{
	struct wcn_pcie_info *priv = get_pcie_device_info();
	unsigned long dump_len, mem_len, aux_len;
	u64 mem_barl = 0, mem_barh = 0;
	int ret = -ENODEV;
	struct platform_device *boot_dev=NULL;
	//int val;

	PCIE_INFO("[+]\n");
	priv->dev = pdev;
	pci_set_drvdata(pdev, priv);

	if (pci_enable_device(pdev)) {
		PCIE_ERR("cannot enable device:%s\n", pci_name(pdev));
		goto err_out;
	}

#ifdef CONFIG_40BIT_DMA
	if (!dma_set_mask(&pdev->dev, DMA_BIT_MASK(40))) {
		PCIE_DBG("40bit DMA mask set\n");
		if (dma_set_coherent_mask(&pdev->dev, DMA_BIT_MASK(40))) {
			PCIE_ERR("40bit coherent DMA mask set failed\n");
			goto err_out;
		}
	}
#else
	if (!dma_set_mask(&pdev->dev, DMA_BIT_MASK(32))) {
		PCIE_DBG("32bit DMA mask set\n");
		if (dma_set_coherent_mask(&pdev->dev, DMA_BIT_MASK(32))) {
			PCIE_ERR("32bit coherent DMA mask set failed\n");
			goto err_out;
		}
	}
#endif
	pci_set_master(pdev);
	ret = pci_request_regions(pdev, DRV_NAME);
	if (ret) {
		PCIE_ERR("Failed to request pci memory regions\n");
		goto err_out;
	}

	priv->dump_start = pci_resource_start(pdev, 4);
	dump_len = pci_resource_len(pdev, 4);
	priv->mem_start = pci_resource_start(pdev, 2);
	mem_len = pci_resource_len(pdev, 2);
	priv->aux_start = pci_resource_start(pdev, 0);
	aux_len = pci_resource_len(pdev, 0);

	pci_read_config_dword(pdev, PCI_BASE_ADDRESS_2, (u32 *)&mem_barl);
	pci_read_config_dword(pdev, PCI_BASE_ADDRESS_3, (u32 *)&mem_barh);
	priv->mem_pciaddr = ((mem_barh << 32) | mem_barl) & ~0xf;
	PCIE_INFO("mem_pciaddr:0x%llx\n", priv->mem_pciaddr);

	pci_read_config_dword(pdev, PCI_BASE_ADDRESS_4, (u32 *)&mem_barl);
	pci_read_config_dword(pdev, PCI_BASE_ADDRESS_5, (u32 *)&mem_barh);
	priv->dump_pciaddr = ((mem_barh << 32) | mem_barl) & ~0xf;
	PCIE_INFO("dump_pciaddr:0x%llx\n", priv->dump_pciaddr);

	priv->pcidump = ioremap(priv->dump_start, dump_len);
	//priv->pcimem = pci_iomap(pdev, 2, mem_len);
	if (!priv->pcidump) {
		PCIE_ERR("%s:Couldn't map region %x[%x]",
			pci_name(pdev), (int)priv->dump_start, (int)dump_len);
		ret = -1;
		goto free_region;
	}

	priv->pcimem = ioremap(priv->mem_start, mem_len);
	//priv->pcimem = pci_iomap(pdev, 2, mem_len);
	if (!priv->pcimem) {
		PCIE_ERR("%s:Couldn't map region %x[%x]",
			pci_name(pdev), (int)priv->mem_start, (int)mem_len);
		ret = -1;
		goto free_memmap0;
	}

	priv->pciaux = ioremap(priv->aux_start, aux_len);
	//priv->pciaux = pci_iomap(pdev, 0, aux_len);
	if (!priv->pciaux) {
		PCIE_ERR("%s:Couldn't map region %x[%x]",
			pci_name(pdev), (int)priv->aux_start, (int)aux_len);
		ret = -1;
		goto free_memmap1;
	}
	PCIE_INFO("BAR(0)(auxmem) (0x%llx 0x%lx)\n", priv->aux_start, aux_len);
	PCIE_INFO("BAR(2)(mem)   [0x%llx 0x%lx)\n", priv->mem_start, mem_len);
	PCIE_INFO("BAR(4)(dump)   [0x%llx 0x%lx)\n", priv->dump_start, dump_len);

	priv->irq = pdev->irq;
	if (pcie_int == 1)
		priv->msi_en = 1;
	else if (pcie_int == 2)
		priv->legacy_en = 1;
	else if (pcie_int == 3)
		priv->msix_en = 1;
	else
		priv->msi_en = 1;

	PCIE_DBG("dev->irq %d\n", pdev->irq);
	PCIE_INFO("legacy %d msi_en %d, msix_en %d\n",
		priv->legacy_en, priv->msi_en, priv->msix_en);

	if (priv->legacy_en == 1) {
		ret = skw_pcie_legacy_int_init(pdev);
		if (ret)
			goto free_memmap2;
	} else if (priv->msi_en == 1) {
		ret = skw_pcie_msi_int_init(pdev);
		if (ret)
			goto free_memmap2;
	} else if (priv->msix_en == 1) {
		ret = skw_pcie_msix_int_init(pdev);
		if (ret)
			goto free_memmap2;
	}
	PCIE_INFO("pcie init ok");
	device_wakeup_enable(&(pdev->dev));
	ep_address_mapping(priv);
	skw_edma_init();
	PCIE_INFO("skw_edma_init ok");
	check_chipid();
	if(priv->cp_state == CP_READY) {
		init_completion(&priv->download_done);
		init_completion(&priv->edma_blk_dl_done);
	}
	skw_pcie_bind_platform_driver(boot_dev);
	//skw_pcie_create_loopcheck_thread(5);
#if 0
	if(priv->cp_state != CP_READY)
		skw_pcie_bind_bt_driver(priv->dev);
#endif
	priv->service_state_map = 0;
	PCIE_INFO("ok\n");
#if 0
	/* fix debug boot issue */
	val = skw_pcie_read32(0x40100030);
	val &= ~0xff00;
	val |= 0x5a00;
	skw_pcie_write32(0x40100030, val);
#endif
	if(priv->cp_state == CP_READY) {
		seekwave_boot_init();
	}
	return 0;


free_memmap2:
	iounmap(priv->pciaux);
free_memmap1:
	iounmap(priv->pcimem);
free_memmap0:
	iounmap(priv->pcidump);
free_region:
	pci_release_regions(pdev);
err_out:
	kfree(priv);

	return ret;
}

const struct dev_pm_ops skw_ep_pm_ops = {
	SET_SYSTEM_SLEEP_PM_OPS(skw_ep_suspend, skw_ep_resume)
};


static struct pci_device_id skw_pcie_tbl[] = {
	{PCI_DEVICE(0x0043, 0x834d)},
	{PCI_DEVICE(0x1FFE, 0x6316)},
	{PCI_DEVICE(0x3FFF, 0x6316)},//XXX
	{PCI_DEVICE(0x1FFE, 0x6315)},
	{}
};
MODULE_DEVICE_TABLE(pci, skw_pcie_tbl);

static struct pci_driver skw_pcie_driver = {
	.name = "skw_pcie",
	.id_table = skw_pcie_tbl,
	.probe = skw_pcie_probe,
	.remove = skw_pcie_remove,
	.driver = {
		.pm = &skw_ep_pm_ops,
	},
};

static int __init skw_pcie_init(void)
{
	int ret = 0;
	struct wcn_pcie_info *priv;
	skw_pcie_debugfs_init();
	skw_pcie_log_level_init();
	PCIE_INFO("[+]\n");
	priv = kzalloc(sizeof(struct wcn_pcie_info), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	g_pcie_dev = priv;

	priv->recovery_dis_state =0;
	INIT_DELAYED_WORK(&priv->skw_pcie_recovery_work, skw_pcie_recovery_work);
	INIT_DELAYED_WORK(&priv->skw_except_work, skw_pcie_exception_work);
	INIT_DELAYED_WORK(&priv->check_dumpdone_work, check_dumpdone_work);
	INIT_DELAYED_WORK(&priv->dump_mem_work, dump_mem_work);
	ret = pci_register_driver(&skw_pcie_driver);
	if(ret)
		PCIE_ERR("pci_register_driver fail %d\n", ret);
	mutex_init(&priv->except_mutex);
	mutex_init(&priv->dl_lock);
	PCIE_INFO("[-]\n");

	return ret;
}

static void __exit skw_pcie_exit(void)
{
	struct wcn_pcie_info *priv = get_pcie_device_info();

	PCIE_INFO("[+]\n");
	seekwave_boot_exit();
	skw_pcie_debugfs_deinit();
	mutex_destroy(&priv->except_mutex);
	mutex_destroy(&priv->dl_lock);
	mutex_destroy(&priv->close_mutex);
	pci_unregister_driver(&skw_pcie_driver);
	cancel_delayed_work_sync(&priv->skw_except_work);
	cancel_delayed_work_sync(&priv->skw_pcie_recovery_work);
	cancel_delayed_work_sync(&priv->check_dumpdone_work);
	cancel_delayed_work_sync(&priv->dump_mem_work);
	if (priv->chip_en >= 0) {
		gpio_set_value(priv->chip_en,0);
		msleep(50);
		gpio_set_value(priv->chip_en, 1);
	} else
		PCIE_ERR("chip_en is not configured, check \"MODEM_ENABLE_GPIO\" in boot_config.h!!!");
	msleep(100);
	skw_pcie_rescan_bus();
	kfree(priv);
	skw_pcie_debugfs_deinit();
	PCIE_INFO("[-]\n");
}

module_init(skw_pcie_init);
module_exit(skw_pcie_exit);
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("seekwave pcie/edma drv");
