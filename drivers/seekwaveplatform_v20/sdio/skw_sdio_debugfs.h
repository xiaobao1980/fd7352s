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
#ifndef __SKW_SDIO_DEBUGFS_H__
#define __SKW_SDIO_DEBUGFS_H__
#include <linux/fs.h>
#include <linux/debugfs.h>
#include <linux/proc_fs.h>
#include <linux/scatterlist.h>
#include <generated/utsrelease.h>
#include "skw_sdio.h"
int skw_sdio_debugfs_init(void);
void skw_sdio_debugfs_deinit(void);
struct proc_dir_entry *skw_sdio_procfs_file(struct proc_dir_entry *parent,
					    const char *name, umode_t mode,
					    const void *proc_fops, void *data);
int skw_sdio_proc_init_ex(const char *name, umode_t mode, const void *fops,
			  void *data);
#endif
