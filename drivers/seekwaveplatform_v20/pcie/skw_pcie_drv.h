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

#ifndef __SKW_PCIE_DRV_H__
#define __SKW_PCIE_DRV_H__

#include "asm-generic/int-ll64.h"
#include <linux/pci.h>
#include <linux/platform_device.h>
#include "../skwutil/skw_boot.h"
#include "skw_pcie_log.h"


#define PCIE_INFO	skw_pcie_info
#define PCIE_ERR	skw_pcie_err
#define PCIE_DBG	skw_pcie_dbg

#define DRV_NAME	"skw_pcie"
#define	WIFI_SERVICE	0
#define	BT_SERVICE	1

#define SERVICE_START	0
#define SERVICE_STOP	1

#define SKW_AP2CP_IRQ_REG (0xF80+0x34)

#define SKWPCIE_AP2CP_SIG0	(0xF80+0x10)
#define SKWPCIE_AP2CP_SIG1	(0xF80+0x14)
#define SKWPCIE_AP2CP_SIG2	(0xF80+0x18)
#define SKWPCIE_CP2AP_SIG0	(0xF80+0x1C)

#define PCIE_MISC_CTRL_0 (0xF80+0x10)
#define PCIE_MISC_STATUS_0 (0xF80+0x20)

#define SKW_CHIP_ID0	0x40000000	//SV6160 chip id0
#define SKW_CHIP_ID1	0x40000004	//SV6160 chip id1
#define SKW_CHIP_ID2	0x40000008	//SV6160 chip id2
#define SKW_CHIP_ID3	0x4000000C	//SV6160 chip id3
#define SKW_CHIP_ID_LENGTH	16	//SV6360 chip id lenght

#define SKW_CP_PMU_SW_REG	0x40108160
#define L2_SHAKE_MASK	0xff
#define WIFI_DO_SUSPEND_MASK 0xf00
#define SKW_CP_AON_SW_REG	0x40100030
#define TRACE_SUPPORT_MASK	0xff
#define PCIE_CP_BOOT_WAR_MASK	0xff00

#define IBREG0_OFFSET_ADDR	(0x1000 + (0 * 0x20))
#define IBREG1_OFFSET_ADDR	(0x1000 + (1 * 0x20))
#define IBREG2_OFFSET_ADDR	(0x1000 + (2 * 0x20))
#define IBREG3_OFFSET_ADDR	(0x1000 + (3 * 0x20))
#define OBREG0_OFFSET_ADDR	(0x1000 + (4 * 0x20))
#define OBREG1_OFFSET_ADDR	(0x1000 + (5 * 0x20))
#define IBREG4_OFFSET_ADDR	(0x1000 + (6 * 0x20))
#define IBREG5_OFFSET_ADDR	(0x1000 + (7 * 0x20))

#define FW_DATA_CRC_BASE	0x401EFFE4
#define FW_BOOT_REG_BASE	0x40000144
#define FW_DL_DONE_REG_BASE	0x40000140
#define FW_BOOT_ADDR	0x100000

struct bar_info {
	resource_size_t mmio_start;
	resource_size_t mmio_end;
	resource_size_t mmio_len;
	unsigned long mmio_flags;
	unsigned char *mem;
	unsigned char *vmem;
};

struct dma_buf {
	unsigned long vir;
	unsigned long phy;
	int size;
};

typedef enum {
	CP_READY = 0,
	CP_ASSERT,
	CP_DUMPDONE,
	CP_BLOCK,
} cp_status_t;

typedef enum {
	WIFI_START = 0,
	WIFI_STOP,
	BT_START,
	BT_STOP
} svc_op_t;

typedef union {
	u32 reg_val;
	struct {
		u32 rsv:16;
		u32 signals_sel:8;
		u32 sys_sel:7;
		u32 enable:1;
	};
} __attribute__((packed)) pcie_misc_ctrl_0_t;

struct wcn_pcie_info {
	struct platform_device *rc_pd;
	struct pci_dev *dev;
	struct pci_saved_state *saved_state;
	u64 mem_pciaddr;
	u64 dump_pciaddr;
	int legacy_en;
	int msi_en;
	int msix_en;
	u16 msix_vec_idx[32];
	int irq;
	int irq_num;
	int gpio_irq_num;
	int bar_num;
	u8 __iomem *pcidump;
	u8 __iomem *pcimem;
	u8 __iomem *pciaux;
	u64 mem_start;
	u64 dump_start;
	u64 aux_start;
	struct msix_entry *msix;
	spinlock_t *spin_lock;
	struct mutex except_mutex;
	struct mutex dl_lock;
	struct mutex close_mutex;
	u32 iram_dl_size;
	u32 dram_dl_size;
	u32 iram_crc_offset;
	u32 dram_crc_offset;
	u16 iram_crc;
	u16 dram_crc;
	u32 iram_crc_en;
	u32 dram_crc_en;
	unsigned int irq_trigger_type;
	atomic_t irq_cnt;
	struct completion download_done;
	struct completion edma_blk_dl_done;
	cp_status_t cp_state;
	int chip_en;
	int recovery_dis_state;
	unsigned int chip_id[SKW_CHIP_ID_LENGTH];
	struct seekwave_device *boot_data;
	unsigned int service_state_map;
	struct delayed_work skw_except_work;
	struct delayed_work skw_pcie_recovery_work;
	struct delayed_work check_dumpdone_work;
	struct delayed_work dump_mem_work;
#ifdef CONFIG_BT_SEEKWAVE
	struct work_struct bt_rx_work;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 5, 0)
	struct wakeup_source *ws;
	struct wakeup_source *ws_event;
#else
	struct wake_lock wake_lock;
	struct wake_lock wake_lockevent;
#endif
	svc_op_t svc_op;
};

extern char *str_cpsts[];
extern int cp_boot;
struct wcn_pcie_info *get_pcie_device_info(void);
//char *pcie_bar_vmem(struct wcn_pcie_info *priv, int bar);
int pcie_config_read(struct wcn_pcie_info *priv, int offset, char *buf, int len);
struct wcn_pcie_info *get_wcn_device_info(void);
void skw_pcie_write32(u32 reg_addr, u32 value);
u32 skw_pcie_read32(u32 reg_addr);
void skw_pcie_setbit(u32 reg_addr, u32 bits);
void skw_pcie_clrbit(u32 reg_addr, u32 bits);
u64 edma_phyaddr_to_pcieaddr(u64 addr);
u64 edma_pcieaddr_to_phyaddr(u64 addr);
u64 edma_pcieaddr_to_phyaddr(u64 phy_addr);
u64 edma_pcieaddr_to_virtaddr(u64 phy_addr);
u64 edma_virtaddr_to_pcieaddr(void *virt_addr);
void skw_pcie_rescan_bus(void);
int skw_pcie_boot_cp(int boot_mode);
void reboot_to_change_bt_antenna_mode(char *mode);
void get_bt_antenna_mode(char *mode);
int skw_pcie_recovery_debug_status(void);
int skw_pcie_recovery_disable(int disable);
void reboot_to_change_bt_uart1(char *mode);
int skw_pcie_host_irq_init(unsigned int irq_gpio_num);
int skw_pcie_mem_dump(unsigned int system_addr, void *buf,unsigned int len);
void modem_notify_event(int event);
int skw_pcie_cp_log(int disable);
void skw_pcie_swdump(void);
ssize_t skw_pcie_swd_read(char __user *buffer, size_t length, loff_t *offset);
void dump_mem_work(struct work_struct *work);
#endif
