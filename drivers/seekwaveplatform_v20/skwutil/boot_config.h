/******************************************************************************
 *
 * Copyright(c) 2020-2030  Seekwave Corporation.
 *
 *****************************************************************************/
#ifndef __BOOT_CONFIG_H__
#define __BOOT_CONFIG_H__
#include <linux/types.h>
#include <linux/gpio.h>
#include <linux/delay.h>

#define CONFIG_SEEKWAVE_PLD_RELEASE 1
#define SKW_DUMP_BUFFER_SIZE     1536*1024

#define  MODEM_ENABLE_GPIO   	-1
#define  HOST_WAKEUP_GPIO_IN 	-1
#define  MODEM_WAKEUP_GPIO_OUT  -1
//#define CONFIG_NO_GKI
//#undef CONFIG_OF

//PCIe
/******************************/
//DO NOT MODIFY!!!
#define INT_MSI 1
#define INT_LEGACY_INTX 2
#define INT_MSIX 3
/******************************/
#define CONFIG_MSIX_SUPPORT
#define CONFIG_PCIE_INT_TYPE INT_MSI
#define CONFIG_SKW_MSI_AS_LEGACY
#define CONFIG_40BIT_DMA

//SDIO
//#define CONFIG_SKW_HOST_SUPPORT_SDMA

//#define CONFIG_SEEKWAVE_FIRMWARE_LOAD
#define  SKW_IRAM_FILE_PATH  "SWT6652_IRAM_USB.bin"
#define  SKW_DRAM_FILE_PATH  "SWT6652_DRAM_USB.bin"
#define  SEEKWAVE_NV_NAME   "SEEKWAVE_NV_SWT6652.bin"
//#define  STR_MODE_REINITBUS  1

#if defined(CONFIG_SKW_HOST_SUPPORT_SDMA)
#define TX_DMA_TYPE		TX_SDMA
#else
#define TX_DMA_TYPE		TX_ADMA
#endif

#define MAX_TX_URB_COUNT 3
#define MAX_RX_URB_COUNT 3
#if defined(CONFIG_SKW_HOST_PLATFORM_AMLOGIC)
extern void extern_wifi_set_enable(int is_on);
#elif defined(CONFIG_SKW_HOST_PLATFORM_ALLWINER)
extern void sunxi_wlan_set_power(int on);
#elif defined(CONFIG_SKW_HOST_PLATFORM_ROCKCHIP)
extern int rockchip_wifi_power(int on);
#else
static inline int skw_chip_power_ops(int on) {
	if (MODEM_ENABLE_GPIO < 0)
		return -1;
	if(on){
		printk("skw self controll chip power on !!\n");
	}else{
		printk("skw self controll chip power down !!\n");
	}
	gpio_set_value(MODEM_ENABLE_GPIO, on);
	return 0;
}
#endif

static inline void skw_chip_set_power(int on)
{
#if defined(CONFIG_SKW_HOST_PLATFORM_AMLOGIC)
	extern_wifi_set_enable(on);
#elif defined(CONFIG_SKW_HOST_PLATFORM_ALLWINER)
	sunxi_wlan_set_power(on);
#elif defined(CONFIG_SKW_HOST_PLATFORM_ROCKCHIP)
	rockchip_wifi_power(on);
#else
	skw_chip_power_ops(on);
#endif

}
static inline void skw_chip_power_reset(void)
{
#if defined(CONFIG_SKW_HOST_PLATFORM_AMLOGIC)
	printk("amlogic skw chip power reset !!\n");
	extern_wifi_set_enable(0);
	msleep(50);
	extern_wifi_set_enable(1);
#elif defined(CONFIG_SKW_HOST_PLATFORM_ALLWINER)
	printk("allwinner skw chip power reset !!\n");
	sunxi_wlan_set_power(0);
	msleep(50);
	sunxi_wlan_set_power(1);
#elif defined(CONFIG_SKW_HOST_PLATFORM_ROCKCHIP)
	printk("rockchip skw chip power reset !!\n");
	rockchip_wifi_power(0);
	msleep(50);
	rockchip_wifi_power(1);
#else
	printk("self skw chip power reset !!\n");
	skw_chip_power_ops(0);
	msleep(50);
	skw_chip_power_ops(1);
#endif
}
#endif /* __BOOT_CONFIG_H__ */
