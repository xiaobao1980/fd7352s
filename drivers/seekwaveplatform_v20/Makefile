#
#SeekWave Platform Drivers Makefile
#
#
PWD :=$(shell pwd)
CURFOLDER ?=$(pwd)

ifeq ($(CONFIG_SKW_PCIE),m)
	ccflags-y +=-Idrivers/misc/seekwaveplatform_v20/pcie
endif

#ifdef CONFIG_SEEKWAVE_BSP_DRIVERS_V20
#obj-$(CONFIG_SKW_USB)               += usb/
#obj-$(CONFIG_SKW_PCIE)               += pcie/
#obj-$(CONFIG_SKW_SDIOHAL)           += sdio/
#obj-$(CONFIG_SEEKWAVE_BSP_DRIVERS)  += skwutil/
#endif

ifeq ($(CONFIG_SKW_BT),m)
	ccflags-y += -DCONFIG_BT_SEEKWAVE
	ccflags-y += -DCONFIG_NO_DTS
endif
ifeq ($(CONFIG_NO_DTS),y)
	ccflags-y += -DCONFIG_NO_DTS
endif
ifneq ($(skw_extra_flags),)
	ccflags-y += $(skw_extra_flags) -DSKW_EXT_INC
endif

ifeq ($(CONFIG_SEEKWAVE_PLD_RELEASE),m)
	ccflags-y += -DCONFIG_SEEKWAVE_PLD_RELEASE
endif

#ccflags-y += -DCONFIG_SEEKWAVE_PLD_RELEASE

obj-$(CONFIG_SKW_SDIOHAL) += skw_sdio_v20.o
skw_sdio_v20-y := sdio/skw_sdio_main.o
skw_sdio_v20-y += sdio/skw_sdio_rx.o
skw_sdio_v20-y += sdio/skw_sdio_debugfs.o
skw_sdio_v20-y += sdio/skw_sdio_log.o
skw_sdio_v20-y += skwutil/skw_user_com.o
skw_sdio_v20-y += skwutil/skw_log_to_file.o
skw_sdio_v20-y += skwutil/skw_boot.o

obj-$(CONFIG_SKW_PCIE) += skw_pcie.o
skw_pcie-objs := pcie/skw_pcie_drv.o
skw_pcie-objs += pcie/skw_edma_drv.o
skw_pcie-objs += pcie/skw_pcie_loopcheck.o
skw_pcie-objs += pcie/skw_pcie_boot.o
skw_pcie-objs += pcie/skw_pcie_debugfs.o
skw_pcie-objs += pcie/skw_pcie_log.o
#skw_pcie-objs += pcie/trace.o
skw_pcie-objs += skwutil/skw_user_com.o
skw_pcie-objs += skwutil/skw_log_to_file.o
skw_pcie-objs += skwutil/skw_boot.o

#CFLAGS_trace.o := -I$(src)

obj-$(CONFIG_SKW_USB) += skw_usb_v20.o
skw_usb_v20-y := usb/skw_usb_io.o
skw_usb_v20-y += usb/skw_usb_debugfs.o
skw_usb_v20-y += usb/skw_usb_log.o
#skw_usb_v20-y += ./usb/skw_test.o
skw_usb_v20-y += skwutil/skw_user_com.o
skw_usb_v20-y += skwutil/skw_log_to_file.o
skw_usb_v20-y += skwutil/skw_boot.o

clean:
	@rm -rf *.o *.ko *.mod.c *.order *.a *.builtin .*.cmd .*.d

