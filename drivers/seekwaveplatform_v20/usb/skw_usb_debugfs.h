/******************************************************************************
 *
 * Copyright(c) 2020-2030  Seekwave Corporation.
 *
 *****************************************************************************/
#ifndef __SKW_USB_DEBUGFS_H__
#define __SKW_USB_DEBUGFS_H__

#include <linux/fs.h>
#include <linux/debugfs.h>
#include <linux/proc_fs.h>
#include <linux/scatterlist.h>
#include <generated/utsrelease.h>
int skw_usb_proc_init_ex(const char *name, umode_t mode, const void *fops,
			 void *data);
int skw_usb_debugfs_init(void);
void skw_usb_debugfs_deinit(void);

#endif
