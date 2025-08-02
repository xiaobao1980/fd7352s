SKW_SRC_ROOT := $(shell pwd)
SKW_EXTRA_INC := $(SKW_SRC_ROOT)/include/linux/platform_data
SKW_EXTRA_SYMBOLS := $(SKW_SRC_ROOT)/drivers/seekwaveplatform/Module.symvers

ARCH ?= $(shell uname -m)
KSRC ?= /usr/src/linux-headers-$(shell uname -r)
CROSS_COMPILE ?= arm-linux-gnueabi-

.PHONY: skw_bsp skw_wifi skw_bt

all: skw_bsp skw_wifi skw_bt
	echo "done"

skw_wifi: skw_bsp
	make ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) -C $(KSRC) M=$(SKW_SRC_ROOT)/drivers/skwifi modules \
		CONFIG_WLAN_VENDOR_SKW6316=m CONFIG_SKW6316_EDMA=y CONFIG_SKW6316_CALIB_DPD=y CONFIG_SKW6316_VENDOR=y \
		skw_extra_flags="-I$(SKW_EXTRA_INC) -I$(SKW_SRC_ROOT)/drivers/skwifi -include $(SKW_EXTRA_INC)/skw6316_config.h" \
		skw_extra_symbols=$(SKW_EXTRA_SYMBOLS)

skw_bt: skw_bsp
	make CONFIG_SEEKWAVE_BSP_DRIVERS="m" CONFIG_SKW_BT="m" CONFIG_SEEKWAVE_BSP_DRIVERS_V20="y"  skw_extra_flags="-I$(SKW_EXTRA_INC)" ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) -C $(KSRC) $ M=$(SKW_SRC_ROOT)/drivers/skwbt modules

skw_bsp:
	make CONFIG_SEEKWAVE_BSP_DRIVERS="m"  CONFIG_SKW_BT="m" CONFIG_SKW_BSP_UCOM="m" CONFIG_SKW_USB="m" skw_extra_flags="-I$(SKW_EXTRA_INC)" ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) -C $(KSRC) $ M=$(SKW_SRC_ROOT)/drivers/seekwaveplatform modules

clean:
	make ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) -C $(KSRC) M=$(SKW_SRC_ROOT)/drivers/skwifi clean
	make ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) -C $(KSRC) M=$(SKW_SRC_ROOT)/drivers/seekwaveplatform clean
	make ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) -C $(KSRC) M=$(SKW_SRC_ROOT)/drivers/skwbt clean
