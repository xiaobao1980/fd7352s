#ifndef __SKW_EDMA_DRV_H_
#define __SKW_EDMA_DRV_H_
#include "skw_pcie_drv.h"
#define EDMA_TX	0
#define EDMA_RX	1

#define EDMA_STD_MODE 0
#define EDMA_LINKLIST_MODE 1

#define	MAX_EDMA_COUNT 32

#define MAX_PORT_NUM	8
#define EDMA_BTCMD_PORT	0
#define EDMA_BTACL_PORT	1
#define EDMA_BTAUDIO_PORT	2
#define EDMA_ISOC_PORT	3
#define EDMA_BTLOG_PORT 4

#define EDMA_LOOPCHECK_PORT	5
#define EDMA_AT_PORT	6
#define EDMA_LOG_PORT	7

#define EDMA_WIFI_RX0_FILTER_DATA_CHN 17
#define EDMA_WIFI_RX1_FILTER_DATA_CNH 18
#define EDMA_WIFI_TX0_PACKET_ADDR 19
#define EDMA_WIFI_TX1_PACKET_ADDR 20
#define EDMA_WIFI_TX0_FREE_ADDR 21
#define EDMA_WIFI_TX1_FREE_ADDR 22
#define EDMA_WIFI_RX0_PKT_ADDR 25
#define EDMA_WIFI_RX1_PKT_ADDR 26

#define BASE_EDMA_CH		0
#define BASE_EDMA_CH_EXT	27

#define PORT_TO_EDMA_TX_CHANNEL(x)     (x>=EDMA_LOG_PORT? ((x-EDMA_LOG_PORT)*2+27):BASE_EDMA_CH + x * 2)
#define PORT_TO_EDMA_RX_CHANNEL(x)     (x>=EDMA_LOG_PORT? ((x-EDMA_LOG_PORT)*2+28): BASE_EDMA_CH + x * 2 + 1)
#define EDMACH2PORTNO(x)               ((x>=BASE_EDMA_CH_EXT)?(((x-BASE_EDMA_CH_EXT)>>1)+EDMA_LOG_PORT):(x - BASE_EDMA_CH)>> 1)

#define EDMA_PORT_BUFFER_SIZE 2048

#define PORT_STATE_IDLE	0
#define PORT_STATE_OPEN	1
#define PORT_STATE_CLSE	2
#define PORT_STATE_ASST	3
#define PORT_STATE_BUSY	4

struct EDMA_HDR {
	u64 data_addr:40;
	u64 rsv0:16;
	u64 tx_int:1;
	u64 rsv1:6;
	u64 done:1;

	u64 next_hdr:40;
	u64 rsv2:8;
	u64 data_len:16;
} __attribute__((packed));
typedef struct EDMA_HDR EDMA_HDR_T;

typedef union  EDMA_ADDR_U {
	struct{
		u64 addr_l32 : 32;
		u64 addr_h8 : 8;
		u64 Reserved_24   : 24;
	};
	u64 u64;
} EDMA_ADDR_T;

struct edma_chn_info {
	struct skw_channel_cfg chn_cfg;
	//u32 n_pld_sz;
	u32 chn_id;
	//void *p_link_hdr;
	//dma_addr_t dma_hdr_handle;
	void *rcv_header_cpu_addr;
	void *rcv_tail_cpu_addr;
	//dma_addr_t map_hdr_addr;
	//dma_addr_t map_pld_addr;
	//dma_addr_t map_skb_addr;
	dma_addr_t pld_dma_addr;
	void *pld_virt_addr;
	dma_addr_t hdr_dma_addr;
	void *hdr_virt_addr;
};

struct edma_port {
	struct platform_device *pdev;
	u8 portno;
	u16 tx_index;
	u16 rx_rp;
	u16 rx_wp;
	struct skw_channel_cfg *rx_line;
	struct skw_channel_cfg *tx_line;
	EDMA_HDR_T *rx_node;
	EDMA_HDR_T *tx_node;
	u8 rx_ch;
	u8 tx_ch;
	u16 rx_size;
	u16 tx_size;
	char *rx_buf_addr;
	rx_submit_fn rx_submit;
	struct task_struct *thread;
	struct semaphore sem;
	void *rx_data;
	int	state;
	struct completion rx_done;
	struct completion tx_done;
	struct mutex rx_mutex;
	u8 rx_int_done;
};
extern u32 port_sta_rec[32];

extern void edma_init(void);
extern void EDMA_IRQPolling(void);
void skw_get_port_statistic(char *buffer, int size);
int  skw_edma_init(void);
void skw_edma_deinit(void);
int msi_edma_channel_irq_handler(int irq_num);
int legacy_edma_irq_handle(void);
int msi_irq_wifi_takeover_handler(int irq_num);
int skw_pcie_bind_wifi_driver(struct platform_device *boot_dev);
int skw_pcie_bind_platform_driver(struct platform_device *boot_dev);
int skw_pcie_bind_bt_driver(struct platform_device *boot_dev);
int skw_pcie_unbind_wifi_driver(struct platform_device *boot_dev);
int skw_pcie_unbind_bt_driver(struct platform_device *boot_dev);
int edma_channel_init(int ch_id, void *channel_config, void *data);
int edma_adma_send(int ch_id, struct scatterlist *sg, int node_cnt, int size);
int submit_list_to_edma_channel(int ch_id, u64 header, int count);
struct edma_chn_info *get_edma_channel_info(int id);
struct edma_port *get_edma_port_info(int portno);
int skw_recovery_mode(void);
int recv_data(int portno, char *buffer, int size);
int send_data(int portno, char *buffer, int size);
int open_edma_port(int portno, void *callback, void *data);
int close_edma_port(int portno);
int skw_pcie_create_loopcheck_thread(int portno);
void modem_unregister_notify(struct notifier_block *nb);
void modem_register_notify(struct notifier_block *nb);
int skw_pcie_remove_loopcheck_thread(int portno);
void skw_edma_lock_event(void);
int skw_edma_pause(void);
void skw_edma_restore(void);
void recovery_close_all_ports(void);
int legacy_irq_wifi_takeover_handler(int ch_id);
void check_dumpdone_work(struct work_struct *work);
#ifdef CONFIG_BT_SEEKWAVE
int bt_rx_prepare(int portno);
#endif
#endif /* __EDMA_DRV_H_ */
