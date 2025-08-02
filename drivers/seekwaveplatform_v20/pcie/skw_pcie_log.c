/**************************************************************************
 * Copyright(c) 2020-2030  Seekwave Corporation.
 * SEEKWAVE TECH LTD..CO
 *
 *Seekwave Platform the pcie log debug fs
 *FILENAME:skw_pcie_log.c
 *DATE:2022-04-11
 *MODIFY:
 *Author:Jones.Jiang
 **************************************************************************/
#include <linux/uaccess.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include "skw_pcie_drv.h"
#include "skw_edma_drv.h"
#include "skw_pcie_log.h"
#include "skw_pcie_debugfs.h"

extern char firmware_version[];

static unsigned long skw_pcie_dbg_level;

unsigned long skw_pcie_log_level(void)
{
	return skw_pcie_dbg_level;
}

static void skw_pcie_set_log_level(int level)
{
	unsigned long dbg_level;

	dbg_level = skw_pcie_log_level() & 0xffff0000;
	dbg_level |= ((level << 1) - 1);

	xchg(&skw_pcie_dbg_level, dbg_level);
}

static void skw_pcie_enable_func_log(int func, bool enable)
{
	unsigned long dbg_level = skw_pcie_log_level();

	if (enable)
		dbg_level |= func;
	else
		dbg_level &= (~func);

	xchg(&skw_pcie_dbg_level, dbg_level);
}

static int skw_pcie_log_show(struct seq_file *seq, void *data)
{
#define SKW_PCIE_LOG_STATUS(s) (level & (s) ? "enable" : "disable")

	int i;
	u32 level = skw_pcie_log_level();
	u8 *log_name[] = { "NONE", "ERROR", "WARNNING", "INFO", "DEBUG" };

	for (i = 0; i < 5; i++) {
		if (!(level & BIT(i)))
			break;
	}

	seq_printf(seq, "\nlog   level: %s\n", log_name[i]);

	seq_puts(seq, "\n");
	seq_printf(seq, "port0 log: %s\n", SKW_PCIE_LOG_STATUS(SKW_PCIE_PORT0));
	seq_printf(seq, "port1 log: %s\n", SKW_PCIE_LOG_STATUS(SKW_PCIE_PORT1));
	seq_printf(seq, "port2 log: %s\n", SKW_PCIE_LOG_STATUS(SKW_PCIE_PORT2));
	seq_printf(seq, "port3 log: %s\n", SKW_PCIE_LOG_STATUS(SKW_PCIE_PORT3));
	seq_printf(seq, "port4 log: %s\n", SKW_PCIE_LOG_STATUS(SKW_PCIE_PORT4));
	seq_printf(seq, "port5 log: %s\n", SKW_PCIE_LOG_STATUS(SKW_PCIE_PORT5));
	seq_printf(seq, "port6 log: %s\n", SKW_PCIE_LOG_STATUS(SKW_PCIE_PORT6));
	seq_printf(seq, "port7 log: %s\n", SKW_PCIE_LOG_STATUS(SKW_PCIE_PORT7));
	seq_printf(seq, "savelog  : %s\n",
		   SKW_PCIE_LOG_STATUS(SKW_PCIE_SAVELOG));
	seq_printf(seq, "dump  log: %s\n", SKW_PCIE_LOG_STATUS(SKW_PCIE_DUMP));

	return 0;
}

static int skw_pcie_log_open(struct inode *inode, struct file *file)
{
	return single_open(file, &skw_pcie_log_show, inode->i_private);
}

static int skw_pcie_log_control(const char *cmd, bool enable)
{
	if (!strcmp("dump", cmd))
		skw_pcie_enable_func_log(SKW_PCIE_DUMP, enable);
	else if (!strcmp("port0", cmd))
		skw_pcie_enable_func_log(SKW_PCIE_PORT0, enable);
	else if (!strcmp("port1", cmd))
		skw_pcie_enable_func_log(SKW_PCIE_PORT1, enable);
	else if (!strcmp("port2", cmd))
		skw_pcie_enable_func_log(SKW_PCIE_PORT2, enable);
	else if (!strcmp("port3", cmd))
		skw_pcie_enable_func_log(SKW_PCIE_PORT3, enable);
	else if (!strcmp("port4", cmd))
		skw_pcie_enable_func_log(SKW_PCIE_PORT4, enable);
	else if (!strcmp("port5", cmd))
		skw_pcie_enable_func_log(SKW_PCIE_PORT5, enable);
	else if (!strcmp("port6", cmd))
		skw_pcie_enable_func_log(SKW_PCIE_PORT6, enable);
	else if (!strcmp("port7", cmd))
		skw_pcie_enable_func_log(SKW_PCIE_PORT7, enable);
	else if (!strcmp("savelog", cmd))
		skw_pcie_enable_func_log(SKW_PCIE_SAVELOG, enable);
	else if (!strcmp("debug", cmd))
		skw_pcie_set_log_level(SKW_PCIE_DEBUG);
	else if (!strcmp("info", cmd))
		skw_pcie_set_log_level(SKW_PCIE_INFO);
	else if (!strcmp("warn", cmd))
		skw_pcie_set_log_level(SKW_PCIE_WARNING);
	else if (!strcmp("error", cmd))
		skw_pcie_set_log_level(SKW_PCIE_ERROR);
	else
		return -EINVAL;

	return 0;
}

static ssize_t skw_pcie_log_write(struct file *fp, const char __user *buffer,
				  size_t len, loff_t *offset)
{
	int i, idx;
	char cmd[32];
	bool enable = false;

	for (idx = 0, i = 0; i < len; i++) {
		char c;

		if (get_user(c, buffer))
			return -EFAULT;

		switch (c) {
		case ' ':
			break;

		case ':':
			cmd[idx] = 0;
			if (!strcmp("enable", cmd))
				enable = true;
			else
				enable = false;

			idx = 0;
			break;

		case '|':
		case '\0':
		case '\n':
			cmd[idx] = 0;
			skw_pcie_log_control(cmd, enable);
			idx = 0;
			break;

		default:
			cmd[idx++] = c;
			idx %= 32;

			break;
		}

		buffer++;
	}

	return len;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops skw_pcie_log_proc_fops = {
	.proc_open = skw_pcie_log_open,
	.proc_read = seq_read,
	.proc_release = single_release,
	.proc_write = skw_pcie_log_write,
};
#else
static const struct file_operations skw_pcie_log_proc_fops = {
	.owner = THIS_MODULE,
	.open = skw_pcie_log_open,
	.read = seq_read,
	.release = single_release,
	.write = skw_pcie_log_write,
};
#endif

static int skw_version_show(struct seq_file *seq, void *data)
{
	seq_printf(seq, "firmware info: %s\n", firmware_version);
	return 0;
}
static int skw_version_open(struct inode *inode, struct file *file)
{
	return single_open(file, &skw_version_show, inode->i_private);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops skw_version_proc_fops = {
	.proc_open = skw_version_open,
	.proc_read = seq_read,
	.proc_release = single_release,
};
#else
static const struct file_operations skw_version_proc_fops = {
	.owner = THIS_MODULE,
	.open = skw_version_open,
	.read = seq_read,
	.release = single_release,
};
#endif
static int skw_port_statistic_show(struct seq_file *seq, void *data)
{
	char *statistic = kzalloc(2048, GFP_KERNEL);

	skw_get_port_statistic(statistic, 2048);
	seq_printf(seq, "Statistic:\n %s", statistic);
	kfree(statistic);
	return 0;
}
static int skw_port_statistic_open(struct inode *inode, struct file *file)
{
	return single_open(file, &skw_port_statistic_show, inode->i_private);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops skw_port_statistic_proc_fops = {
	.proc_open = skw_port_statistic_open,
	.proc_read = seq_read,
	.proc_release = single_release,
};
#else
static const struct file_operations skw_port_statistic_proc_fops = {
	.owner = THIS_MODULE,
	.open = skw_port_statistic_open,
	.read = seq_read,
	.release = single_release,
};
#endif

static int skw_pcie_recovery_debug_show(struct seq_file *seq, void *data)
{
	if (!skw_pcie_recovery_debug_status())
		seq_printf(seq, "Enabled\n");
	else
		seq_printf(seq, "Disabled\n");

	return 0;
}
static int skw_pcie_recovery_debug_open(struct inode *inode, struct file *file)
{
	return single_open(file, &skw_pcie_recovery_debug_show,
			   inode->i_private);
}

static ssize_t skw_pcie_recovery_debug_write(struct file *fp,
					     const char __user *buffer,
					     size_t len, loff_t *offset)
{
	char cmd[16] = { 0 };

	if (len >= sizeof(cmd))
		return -EINVAL;
	if (copy_from_user(cmd, buffer, len))
		return -EFAULT;

	if (!strncmp("enable", cmd, 6)) {
		skw_pcie_recovery_disable(0);
	} else if (!strncmp("disable", cmd, 7)) {
		skw_pcie_recovery_disable(1);
	}
	return len;
}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops skw_pcie_recovery_proc_fops = {
	.proc_open = skw_pcie_recovery_debug_open,
	.proc_read = seq_read,
	.proc_release = single_release,
	.proc_write = skw_pcie_recovery_debug_write,
};
#else
static const struct file_operations skw_pcie_recovery_proc_fops = {
	.owner = THIS_MODULE,
	.open = skw_pcie_recovery_debug_open,
	.read = seq_read,
	.release = single_release,
	.write = skw_pcie_recovery_debug_write,
};
#endif

static int skw_bluetooth_UART1_open(struct inode *inode, struct file *file)
{
	return single_open(file, NULL, inode->i_private);
}

static ssize_t skw_bluetooth_UART1_write(struct file *fp,
					 const char __user *buffer, size_t len,
					 loff_t *offset)
{
	char cmd[32] = { 0 };

	if (len >= sizeof(cmd))
		return -EINVAL;
	if (copy_from_user(cmd, buffer, len))
		return -EFAULT;
	if (!strncmp("enable", cmd, 6)) {
		memset(cmd, 0, sizeof(cmd));
		reboot_to_change_bt_uart1(cmd);
		printk("%s UART-HCI\n", cmd);
	}
	return len;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops skw_bluetooth_UART1_proc_fops = {
	.proc_open = skw_bluetooth_UART1_open,
	.proc_read = seq_read,
	.proc_release = single_release,
	.proc_write = skw_bluetooth_UART1_write,
};
#else
static const struct file_operations skw_bluetooth_UART1_proc_fops = {
	.owner = THIS_MODULE,
	.open = skw_bluetooth_UART1_open,
	.read = seq_read,
	.release = single_release,
	.write = skw_bluetooth_UART1_write,
};
#endif

static int skw_bluetooth_antenna_show(struct seq_file *seq, void *data)
{
	char result[32];

	memset(result, 0, sizeof(result));
	get_bt_antenna_mode(result);
	if (strlen(result))
		seq_printf(seq, result);

	return 0;
}

static int skw_bluetooth_antenna_open(struct inode *inode, struct file *file)
{
	return single_open(file, &skw_bluetooth_antenna_show, inode->i_private);
}

static ssize_t skw_bluetooth_antenna_write(struct file *fp,
					   const char __user *buffer,
					   size_t len, loff_t *offset)
{
	char cmd[32] = { 0 };

	if (len >= sizeof(cmd))
		return -EINVAL;
	if (copy_from_user(cmd, buffer, len))
		return -EFAULT;
	if (!strncmp("switch", cmd, 6)) {
		memset(cmd, 0, sizeof(cmd));
		reboot_to_change_bt_antenna_mode(cmd);
		printk("%s\n", cmd);
	}
	return len;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops skw_bluetooth_antenna_proc_fops = {
	.proc_open = skw_bluetooth_antenna_open,
	.proc_read = seq_read,
	.proc_release = single_release,
	.proc_write = skw_bluetooth_antenna_write,
};
#else
static const struct file_operations skw_bluetooth_antenna_proc_fops = {
	.owner = THIS_MODULE,
	.open = skw_bluetooth_antenna_open,
	.read = seq_read,
	.release = single_release,
	.write = skw_bluetooth_antenna_write,
};
#endif

static int skw_dump_mem_show(struct seq_file *seq, void *data)
{
	return 0;
}
static int skw_dump_mem_open(struct inode *inode, struct file *file)
{
	return single_open(file, &skw_dump_mem_show, inode->i_private);
}

int skw_pcie_dumpmem(int dump)
{
	int dumpmem_status = dump;
	PCIE_INFO("the dump status =%d\n", dumpmem_status);
	if (dumpmem_status == 1) {
		PCIE_INFO("dump mem start\n");
		modem_notify_event(DEVICE_DUMPMEM_EVENT);
	} else if (dumpmem_status == 0) {
		PCIE_INFO("dump mem stop\n");
	}
	return 0;
}

static ssize_t skw_dump_mem_write(struct file *fp, const char __user *buffer,
				  size_t len, loff_t *offset)
{
	char cmd[16] = { 0 };

	if (len >= sizeof(cmd))
		return -EINVAL;
	if (copy_from_user(cmd, buffer, len))
		return -EFAULT;
	if (!strncmp("dump", cmd, 4))
		skw_pcie_dumpmem(1);
	else if (!strncmp("stop", cmd, 4))
		skw_pcie_dumpmem(0);

	return len;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops skw_dump_mem_proc_fops = {
	.proc_open = skw_dump_mem_open,
	.proc_read = seq_read,
	.proc_release = single_release,
	.proc_write = skw_dump_mem_write,
};
#else
static const struct file_operations skw_dump_mem_proc_fops = {
	.owner = THIS_MODULE,
	.open = skw_dump_mem_open,
	.read = seq_read,
	.release = single_release,
	.write = skw_dump_mem_write,

};
#endif
static ssize_t skw_pcie_swdump_write(struct file *fp, const char __user *buffer,
				     size_t len, loff_t *offset)
{
	char cmd[2] = { 0 };

	if (len > sizeof(cmd))
		return -EINVAL;
	if (copy_from_user(cmd, buffer, len))
		return -EFAULT;
	if (!strncmp("1", cmd, 1))
		skw_pcie_swdump();

	return len;
}

static ssize_t skw_pcie_swdump_read(struct file *fp, char __user *buffer,
				    size_t count, loff_t *pos)
{
	int ret;

	ret = skw_pcie_swd_read(buffer, count, pos);
	return ret;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops skw_pcie_swdump_fops = {
	.proc_read = skw_pcie_swdump_read,
	.proc_write = skw_pcie_swdump_write,
};
#else
static const struct file_operations skw_pcie_swdump_fops = {
	.owner = THIS_MODULE,
	.read = skw_pcie_swdump_read,
	.write = skw_pcie_swdump_write,
};
#endif

void skw_pcie_log_level_init(void)
{
	skw_pcie_set_log_level(SKW_PCIE_INFO);
	skw_pcie_enable_func_log(SKW_PCIE_DUMP, false);
	skw_pcie_enable_func_log(SKW_PCIE_PORT0, false);
	skw_pcie_enable_func_log(SKW_PCIE_PORT1, false);
	skw_pcie_enable_func_log(SKW_PCIE_PORT2, false);
	skw_pcie_enable_func_log(SKW_PCIE_PORT3, false);
	skw_pcie_enable_func_log(SKW_PCIE_PORT4, false);
	skw_pcie_enable_func_log(SKW_PCIE_PORT5, false);
	skw_pcie_enable_func_log(SKW_PCIE_PORT6, false);
	skw_pcie_enable_func_log(SKW_PCIE_SAVELOG, false);
	skw_pcie_enable_func_log(SKW_PCIE_PORT7, false);
	skw_pcie_proc_init_ex("log_level", 0666, &skw_pcie_log_proc_fops, NULL);
	skw_pcie_proc_init_ex("recovery", 0666, &skw_pcie_recovery_proc_fops,
			      NULL);
	skw_pcie_proc_init_ex("Version", 0666, &skw_version_proc_fops, NULL);
	skw_pcie_proc_init_ex("Statistic", 0666, &skw_port_statistic_proc_fops,
			      NULL);
	skw_pcie_proc_init_ex("BT_ANT", 0666, &skw_bluetooth_antenna_proc_fops,
			      NULL);
	skw_pcie_proc_init_ex("BT_UART1", 0666, &skw_bluetooth_UART1_proc_fops,
			      NULL);
	skw_pcie_proc_init_ex("dumpmem", 0666, &skw_dump_mem_proc_fops, NULL);
	skw_pcie_proc_init_ex("swdump", 0666, &skw_pcie_swdump_fops, NULL);
}
