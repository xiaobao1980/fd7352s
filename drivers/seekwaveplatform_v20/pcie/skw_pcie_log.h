/******************************************************************************
 *
 * Copyright(c) 2020-2030  Seekwave Corporation.
 *
 *****************************************************************************/
#ifndef __SKW_PCIE_LOG_H__
#define __SKW_PCIE_LOG_H__

#define SKW_PCIE_ERROR	BIT(0)
#define SKW_PCIE_WARNING  BIT(1)
#define SKW_PCIE_INFO	 BIT(2)
#define SKW_PCIE_DEBUG	BIT(3)

#define SKW_PCIE_CMD	  BIT(16)
#define SKW_PCIE_EVENT	BIT(17)
#define SKW_PCIE_SCAN	 BIT(18)
#define SKW_PCIE_TIMER	BIT(19)
#define SKW_PCIE_STATE	BIT(20)

#define SKW_PCIE_PORT0	 BIT(21)
#define SKW_PCIE_PORT1	 BIT(22)
#define SKW_PCIE_PORT2	 BIT(23)
#define SKW_PCIE_PORT3	 BIT(24)
#define SKW_PCIE_PORT4	 BIT(25)
#define SKW_PCIE_PORT5	 BIT(26)
#define SKW_PCIE_PORT6	 BIT(27)
#define SKW_PCIE_PORT7	 BIT(28)
#define SKW_PCIE_SAVELOG	 BIT(29)
#define SKW_PCIE_DUMP	 BIT(31)

unsigned long skw_pcie_log_level(void);

#define skw_pcie_log(level, fmt, ...) \
	do { \
		if (skw_pcie_log_level() & level) \
			pr_err(fmt,  ##__VA_ARGS__); \
	} while (0)

#define skw_pcie_port_log(port_num, fmt, ...) \
	do { \
		if (skw_pcie_log_level() &(SKW_PCIE_PORT0<<port_num)) \
			pr_err(fmt,  ##__VA_ARGS__); \
	} while (0)

#define skw_port_log(port_num,fmt, ...) \
	skw_pcie_log((SKW_PCIE_PORT0<<port_num), "[PORT_LOG] %s: "fmt, __func__, ##__VA_ARGS__)

#define skw_pcie_err(fmt, ...) \
	skw_pcie_log(SKW_PCIE_ERROR, "[SKWPCIE ERROR] %s %d: "fmt, __func__, __LINE__, ##__VA_ARGS__)

#define skw_pcie_warn(fmt, ...) \
	skw_pcie_log(SKW_PCIE_WARNING, "[SKWPCIE WARN] %s: "fmt, __func__, ##__VA_ARGS__)

#define skw_pcie_info(fmt, ...) \
	skw_pcie_log(SKW_PCIE_INFO, "[SKWPCIE INFO] %s %d: "fmt, __func__, __LINE__, ##__VA_ARGS__)

#define skw_pcie_dbg(fmt, ...) \
	skw_pcie_log(SKW_PCIE_DEBUG, "[SKWPCIE DBG] %s %d: "fmt, __func__, __LINE__, ##__VA_ARGS__)

#define skw_pcie_hex_dump(prefix, buf, len) \
	do { \
		if (skw_pcie_log_level() & SKW_PCIE_DUMP) { \
			u8 str[32] = {0};  \
			snprintf(str, sizeof(str), "[SKWPCIE DUMP] %s", prefix); \
			print_hex_dump(KERN_ERR, str, \
				DUMP_PREFIX_OFFSET, 16, 1, buf, len, true); \
		} \
	} while (0)
#if 0
#define skw_pcie_port_log(port_num, fmt, ...) \
	do { \
		if (skw_pcie_log_level() &(SKW_PCIE_PORT0<<port_num)) \
			pr_err("[PORT_LOG] %s:"fmt,__func__,  ##__VA_ARGS__); \
	} while (0)

#endif
int get_log_enable_status(void);
void skw_pcie_log_level_init(void);
int skw_pcie_cp_log(int disable);
int skw_pcie_debug_log_open(void);
int skw_pcie_debug_log_close(void);
#endif

