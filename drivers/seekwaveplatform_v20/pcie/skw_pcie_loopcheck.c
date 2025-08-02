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
#include "linux/workqueue.h"
#include <linux/platform_device.h>
#include <linux/scatterlist.h>
#include <linux/dma-mapping.h>
#include <linux/version.h>
#include <linux/notifier.h>
#include <linux/semaphore.h>
#include <linux/gpio.h>
#include <linux/pm_runtime.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/err.h>
#include <linux/wait.h>
#include <linux/delay.h>
#include <linux/semaphore.h>
#include "skw_pcie_drv.h"
#include "skw_edma_drv.h"

#define MODEM_OFF  0
#define MODEM_ON	1
#define MODEM_HALT 2

extern struct edma_port edma_ports[MAX_PORT_NUM];
int modem_status;
static struct task_struct *loop_thread;
static int loop_state;
static struct semaphore loop_sem;
static char firmware_version[128];
static int loop_portno;
int send_modem_assert_command(void);
extern u32 last_sent_wifi_cmd[3];
int skw_pcie_elbi_writeb(unsigned int address, unsigned char value);
int skw_pcie_elbi_writed(unsigned int address, u32 value);
static BLOCKING_NOTIFIER_HEAD(modem_notifier_list);
static u8 port_assert_idx[7] = {
	EDMA_AT_PORT,
	EDMA_LOG_PORT,
	EDMA_BTCMD_PORT,
	EDMA_BTAUDIO_PORT,
	EDMA_BTACL_PORT,
	EDMA_ISOC_PORT,
	EDMA_BTLOG_PORT,
};

char *str_cpsts[] = {"READY", "ASSERT", "DUMPDONE", "BLOCK"};

void skw_pcie_setup_service_devices(void)
{
}
void modem_register_notify(struct notifier_block *nb)
{
	blocking_notifier_chain_register(&modem_notifier_list, nb);
}
void modem_unregister_notify(struct notifier_block *nb)
{
	blocking_notifier_chain_unregister(&modem_notifier_list, nb);
}
void modem_notify_event(int event)
{
	blocking_notifier_call_chain(&modem_notifier_list, event, NULL);
}

void skw_pcie_exception_work(struct work_struct *work)
{
	int i=0;
	struct wcn_pcie_info *priv = get_pcie_device_info();

	PCIE_INFO("[+]\n");
	mutex_lock(&priv->except_mutex);
	if(priv->recovery_dis_state == 1) {//recovery disabled
		PCIE_INFO("cpsts=%s\n", str_cpsts[priv->cp_state]);
		PCIE_INFO("[-]Recovery disabled, exit exception\n");
		mutex_unlock(&priv->except_mutex);
		return;
	}

	if(priv->cp_state == CP_ASSERT)	{//assert
		PCIE_INFO("[-]Assert handled before block, exit exception\n");
		mutex_unlock(&priv->except_mutex);
		return;
	}
	priv->cp_state = CP_BLOCK;
	mutex_unlock(&priv->except_mutex);
	modem_notify_event(DEVICE_BLOCKED_EVENT);
	for (i=0; i<MAX_PORT_NUM - 1; i++)
	{
		if(!edma_ports[port_assert_idx[i]].state || edma_ports[port_assert_idx[i]].state==PORT_STATE_CLSE)
			continue;

		edma_ports[port_assert_idx[i]].state = PORT_STATE_ASST;
	}
	recovery_close_all_ports();
	if (priv->chip_en >= 0) {
		priv->service_state_map=0;
		skw_recovery_mode();
	} else {
		PCIE_ERR("chip_en is not configured, CAN'T recovery, check \"MODEM_ENABLE_GPIO\" in boot_config.h!!!");
	}
	PCIE_INFO("[-]\n");
}

/*skw_ap2cp_irq_reg bit4 modem assert*/
int send_modem_assert_command(void)
{
	int ret =0;
	u32 *cmd = last_sent_wifi_cmd;
	struct wcn_pcie_info *priv = get_pcie_device_info();
	unsigned long flags;

	spin_lock_irqsave(priv->spin_lock, flags);
	dump_stack();
	PCIE_INFO("[+], cpsts=%s\n", str_cpsts[priv->cp_state]);
	if(priv->cp_state != CP_READY) {
		spin_unlock_irqrestore(priv->spin_lock, flags);
		return ret;
	}
	priv->cp_state=CP_BLOCK;
	ret =skw_pcie_elbi_writeb(SKW_AP2CP_IRQ_REG, 0x10);
	PCIE_INFO("send assert CP CMD, ret=%d cmd: 0x%x 0x%x 0x%x\n", ret, cmd[0], cmd[1], cmd[2]);
#ifdef CONFIG_SEEKWAVE_PLD_RELEASE
	schedule_delayed_work(&priv->skw_except_work , msecs_to_jiffies(2000));
#else
	if(!priv->recovery_dis_state)
		schedule_delayed_work(&priv->skw_except_work , msecs_to_jiffies(6000));
#endif
	PCIE_INFO("[-]\n");
	spin_unlock_irqrestore(priv->spin_lock, flags);
	return ret;
}

void check_dumpdone_work(struct work_struct *work)
{
	struct edma_port *port = get_edma_port_info(EDMA_LOOPCHECK_PORT);

	if (!completion_done(&port->rx_done)) {
		complete(&port->rx_done);
		PCIE_INFO("force complete the loopcheck rx_done\n");
	}
}

int skw_pcie_loopcheck_entry(void *para)
{
	struct wcn_pcie_info *priv = get_pcie_device_info();
	int portno = *(int *)para;
	int recv_flag = 0;
	char *buffer;
	int read, size;
	int timeout = 100;
	int i;

	PCIE_DBG("\n");
	size = 512;
	buffer = kzalloc(size, GFP_KERNEL);
	while(loop_state && buffer) {
		read = 0;
		memset(buffer,0,size);
		do {
			if(loop_state==0)
				break;
			read = recv_data(portno, buffer, 256);
		} while(!read);

		if(read < 0 || !loop_state) {
			PCIE_DBG("bulkin read_len=%d\n",read);
			break;
		}

		PCIE_INFO("recv(%d): %s\n", read, buffer);

		memcpy(buffer+256, "LOOPCHECK", 9);
		if (read==8 && !strncmp(buffer, "BSPREADY", read)) {
			PCIE_INFO("BSP READY!!!\n");
		} else if (read==9 && !strncmp(buffer, "WIFIREADY", read)) {
			priv->service_state_map |=1;
			complete(&priv->download_done);
			timeout=500;
		} else if (read==6 && !strncmp(buffer, "BTEXIT", read)) {
			complete(&priv->download_done);
		} else if (read==7 && !strncmp(buffer, "BTREADY", read)) {
			priv->service_state_map |=2;
			complete(&priv->download_done);
		} else if (!strncmp(buffer, "BSPASSERT", 9)) {
			PCIE_INFO("BSP ASSERT!!!\n");
			if(priv->cp_state == CP_BLOCK && delayed_work_pending(&priv->skw_except_work)) {
				cancel_delayed_work_sync(&priv->skw_except_work);
				PCIE_INFO("Cancel exception work\n");
			}
			priv->cp_state = CP_ASSERT;//assert
			memset(buffer, 0, read);
			modem_status = MODEM_HALT;
			//show_assert_context();
			modem_notify_event(DEVICE_ASSERT_EVENT);
			if (get_log_enable_status() == 1) {
				if(edma_ports[EDMA_LOG_PORT].state == PORT_STATE_OPEN) {
					schedule_delayed_work(&priv->check_dumpdone_work , msecs_to_jiffies(5000));
					read = recv_data(portno, buffer, 256);
					cancel_delayed_work_sync(&priv->check_dumpdone_work);
					PCIE_INFO("wait 5s to dump assert log ...\n");
					msleep(5000);//wait for CP finishing dump log
				}
			}
			modem_notify_event(DEVICE_DUMPDONE_EVENT);

			for (i=0; i<MAX_PORT_NUM - 1; i++) {
				if((edma_ports[port_assert_idx[i]].state == PORT_STATE_IDLE) ||
							(edma_ports[port_assert_idx[i]].state==PORT_STATE_CLSE))
					continue;
				edma_ports[port_assert_idx[i]].state = PORT_STATE_ASST;
			}

			if(priv->recovery_dis_state) {
				PCIE_INFO("recovery disable, no need to recovery\n");
				break;
			}

			recovery_close_all_ports();
			if (priv->chip_en >= 0)
				recv_flag = 1;
			else
				PCIE_ERR("chip_en is not configured, CAN'T recovery, check \"MODEM_ENABLE_GPIO\" in boot_config.h!!!");
			break;
		} else if (!strncmp("trunk_W", buffer, 7)) {
			complete(&priv->download_done);
			priv->cp_state = CP_READY;
			modem_status = MODEM_ON;
			memset(firmware_version, 0 , sizeof(firmware_version));
			strncpy(firmware_version, buffer, read);
			PCIE_DBG("---debug---,@@Line:%d, Func:%s@@\n", __LINE__, __func__);
			modem_notify_event(DEVICE_BSPREADY_EVENT);
			PCIE_DBG("---debug---,@@Line:%d, Func:%s@@\n", __LINE__, __func__);
			skw_pcie_setup_service_devices();
		} else {
			PCIE_INFO("loopcheck receive string error!!!\n");
		}
		msleep(timeout);
	}

	PCIE_INFO("loopcheck thread is exit\n");
	kfree(buffer);
	up(&loop_sem);
	if (recv_flag == 1) {
		schedule_delayed_work(&priv->skw_pcie_recovery_work , msecs_to_jiffies(100));
		recv_flag = 0;
	}
	return 0;
}

int skw_pcie_create_loopcheck_thread(int portno)
{
	int ret;

	PCIE_INFO("[+]\n");
	loop_thread = NULL;
	modem_status = MODEM_OFF;
	loop_state = 0;
	ret = open_edma_port(portno, NULL, NULL);
	if (ret==0) {
		loop_portno = portno;
		loop_thread = kthread_create(skw_pcie_loopcheck_entry, &loop_portno, "Loopcheck");
	}
	if(loop_thread) {
		loop_state = 1;
		sema_init(&loop_sem, 0);
		wake_up_process(loop_thread);
	}
	PCIE_INFO("[-]\n");
	return 0;
}

/************************************************************************
 *Decription:
 *Author:jiayong.yang
 *Date:2021-05-27
 *Modfiy:
 *
 ********************************************************************* */
int skw_pcie_remove_loopcheck_thread(int portno)
{
	int ret;

	PCIE_INFO("[+]\n");
	if (loop_state && loop_thread) {
		loop_state = 0;
		//close_edma_port(portno);
		ret = down_interruptible(&loop_sem);
		if (ret==0)
			loop_thread = NULL;
	}
	PCIE_INFO("[-]\n");
	return 0;
}
