#ifndef _SKW_DMA_REG_H_
#define _SKW_DMA_REG_H_

#define SKW_DMA_BASE 0x40188000

#define DMA_INT_MASK_STS                ( SKW_DMA_BASE + 0x0004 )
#define DMA_REQ_STS                     ( SKW_DMA_BASE + 0x0008 )
#define DMA_PAUSE                       ( SKW_DMA_BASE + 0x0010 )
#define DMA_AXI_OST_NUM                 ( SKW_DMA_BASE + 0x0034 )
#define DMA_PAUSE_DONE                  ( SKW_DMA_BASE + 0x0038 )
#define DMA_DST_RING_NODE_NUM           ( SKW_DMA_BASE + 0x003C )
#define DMA_SRC_RING_NODE_NUM           ( SKW_DMA_BASE + 0x0040 )
#define DMA_INT_TYPE_CFG                ( SKW_DMA_BASE + 0x004C )

#define DMA_SRC_REQ(x)			  ( SKW_DMA_BASE + x*0x80 + 0x0080 + 0x0000 )
#define DMA_SRC_NODE(x)			  ( SKW_DMA_BASE + x*0x80 + 0x0080 + 0x0004 )
#define DMA_DST_REQ(x)			  ( SKW_DMA_BASE + x*0x80 + 0x0080 + 0x0008 )
#define DMA_DST_NODE(x)			  ( SKW_DMA_BASE + x*0x80 + 0x0080 + 0x000C )
#define DMA_SRC_DSCR_PTR_HIGH(x)		  ( SKW_DMA_BASE + x*0x80 + 0x0080 + 0x0010 )
#define DMA_SRC_DSCT_PTR_LOW(x)		  ( SKW_DMA_BASE + x*0x80 + 0x0080 + 0x0014 )
#define DMA_DST_DSCR_PTR_HIGH(x)		  ( SKW_DMA_BASE + x*0x80 + 0x0080 + 0x0018 )
#define DMA_DST_DSCR_PTR_LOW(x)		  ( SKW_DMA_BASE + x*0x80 + 0x0080 + 0x001C )
#define DMA_SRC_INT(x)			  ( SKW_DMA_BASE + x*0x80 + 0x0080 + 0x0020 )
#define DMA_DST_INT(x)			  ( SKW_DMA_BASE + x*0x80 + 0x0080 + 0x0024 )
#define DMA_DST_INT_DSCR_HEAD_LOW(x)	  ( SKW_DMA_BASE + x*0x80 + 0x0080 + 0x0030 )
#define DMA_DST_INT_DSCR_TAIL_LOW(x)	  ( SKW_DMA_BASE + x*0x80 + 0x0080 + 0x0034 )
#define DMA_DST_INT_DSCR_HIGH(x)		  ( SKW_DMA_BASE + x*0x80 + 0x0080 + 0x0038 )
#define DMA_SRC_INT_DSCR_HEAD_LOW(x)	  ( SKW_DMA_BASE + x*0x80 + 0x0080 + 0x0040 )
#define DMA_SRC_INT_DSCR_TAIL_LOW(x)	  ( SKW_DMA_BASE + x*0x80 + 0x0080 + 0x0044 )
#define DMA_SRC_INT_DSCR_HIGH(x)		  ( SKW_DMA_BASE + x*0x80 + 0x0080 + 0x0048 )
#define DMA_NODE_TOT_CNT(x)			  ( SKW_DMA_BASE + x*0x80 + 0x0080 + 0x004C )
#define DMA_CFG(x)				  ( SKW_DMA_BASE + x*0x80 + 0x0080 + 0x0050 )
#define DMA_LEN_CFG(x)			  ( SKW_DMA_BASE + x*0x80 + 0x0080 + 0x0054 )

#define NODE_NUM_OFFSET 16
#define TRANS_LEN_OFFSET 16
#define EDMA_REQ BIT(0)

typedef union {
	unsigned int u32;
	struct {
    u32 src_data_split_en    : 1;
    u32 src_ring_buf_en      : 1;
    u32 Reserved_2                  :20;
    u32 node_num_thr     : 9;
    u32 node_num_thr_en  : 1;
	};
} DMA_SRC_NODE_S;

typedef union {
	unsigned int u32;
	struct {
    u32 dst_data_split_en    : 1;
    u32 dst_ring_buf_en      : 1;
    u32 Reserved_5                  :20;
    u32 dst_node_num_thr     : 9;
    u32 dst_node_num_thr_en  : 1;
	};
} DMA_DST_NODE_S;

 typedef union {
	unsigned int u32;
	struct {
    u32 src_next_dscr_ptr_high  : 8;
    u32 Reserved_6                     :24;
	};
} DMA_SRC_DSCR_PTR_HIGH_S;

typedef union {
	unsigned int u32;
	struct {
    u32 src_next_dscr_ptr_low  :32;
	};
} DMA_SRC_DSCT_PTR_LOW_S;

typedef union {
	unsigned int u32;
	struct {
    u32 Reserved_8                     : 8;
    u32 dst_next_dscr_ptr_high  : 8;
    u32 Reserved_7                     :16;
	};
} DMA_DST_DSCR_PTR_HIGH_S;

typedef union {
	unsigned int u32;
	struct {
    u32 dst_next_dscr_ptr_low  :32;
	};
} DMA_DST_DSCR_PTR_LOW_S;

typedef union {
	unsigned int u32;
	struct {
    u32 src_complete_int_en            : 1;
    u32 src_list_empty_int_en          : 1;
    u32 src_cfg_err_int_en             : 1;
    u32 Reserved_13                    : 1;
    u32 src_cmplt_en_wi_dst_node_done  : 1;
    u32 Reserved_12                    : 3;
    u32 Rsvd_0           : 1;
    u32 Rsvd_2         : 1;
    u32 Rsvd_3            : 1;
    u32 Reserved_11                    : 5;
    u32 src_complete_mask_sts          : 1;
    u32 src_list_empty_mask_sts        : 1;
    u32 Rsvd_4           : 1;
    u32 Reserved_10                    : 5;
    u32 src_complete_int_clr           : 1;
    u32 src_list_empty_int_clr         : 1;
    u32 Rsvd_5            : 1;
    u32 Reserved_9                     : 5;
	};
} DMA_SRC_INT_S;


typedef union {
	unsigned int u32;
	struct {
    u32 dst_complete_int_en            : 1;
    u32 dst_list_empty_int_en          : 1;
    u32 dst_cfg_err_int_en             : 1;
    u32 Reserved_18                           : 1;
    u32 Rsvd_6  : 1;
    u32 Reserved_17                           : 3;
    u32 Rsvd_7           : 1;
    u32 Rsvd_8         : 1;
    u32 Rsvd_9            : 1;
    u32 Reserved_16                           : 5;
    u32 dst_complete_mask_sts          : 1;
    u32 dst_list_empty_mask_sts        : 1;
    u32 Rsvd_10           : 1;
    u32 Reserved_15                           : 5;
    u32 dst_complete_int_clr           : 1;
    u32 dst_list_empty_int_clr         : 1;
    u32 Rsvd_11            : 1;
    u32 Reserved_14                           : 5;
	};
} DMA_DST_INT_S;

typedef union {
	unsigned int u32;
	struct {
    u32 dst_int_dscr_tail_high  : 8;
    u32 dst_int_dscr_head_high  : 8;
    u32 Reserved_23                    : 6;
    u32 dst_node_done_num       :10;
	};
} DMA_DST_INT_DSCR_HIGH_S;

typedef union {
	unsigned int u32;
	struct {
    u32 src_int_dscr_tail_high  : 8;
    u32 src_int_dscr_head_high  : 8;
    u32 Reserved_24                    : 6;
    u32 src_node_done_num       :10;
	};
} DMA_SRC_INT_DSCR_HIGH_S;

typedef union {
	unsigned int u32;
	struct {
    u32 src_tot_node_num      :10;
    u32 Reserved_26                  : 6;
    u32 dst_tot_node_num      :10;
    u32 Reserved_25                  : 5;
    u32 Rsvd_12  : 1;
	};
} DMA_NODE_TOT_CNT_S;

typedef union {
	unsigned int u32;
	struct {
    u32 Rsvd_18               : 1;
    u32 Rsvd_13        : 3;
    u32 Rsvd_14  : 1;
    u32 Reserved_28             : 2;
    u32 dir              : 1;
    u32 endian_mode      : 2;
    u32 priority         : 2;
    u32 Rsvd_15  : 1;
    u32 req_mode         : 1;
    u32 Rsvd_16      : 1;
    u32 Reserved_27             :12;
    u32 Rsvd_17      : 5;
	};
} DMA_CFG_S;

#endif // _SKW_DMA_REG_H_

