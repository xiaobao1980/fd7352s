/******************************************************************************
 *
 * Copyright(c) 2020-2030  Seekwave Corporation.
 *
 *****************************************************************************/
#ifndef __SKW_PCIE_DEBUGFS_H__
#define __SKW_PCIE_DEBUGFS_H__

#include <linux/fs.h>
#include <linux/debugfs.h>
#include <linux/version.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/seq_file.h>
#include <linux/utsname.h>
#include <generated/utsrelease.h>

int skw_pcie_debugfs_init(void);
void skw_pcie_debugfs_deinit(void);
int skw_pcie_proc_init_ex(const char *name, umode_t mode, const void *fops,
			  void *data);

#endif
