/*
 * sv6160_mem_map.h
 * Copyright (C) 2022 cfig <junwei.jiang@seekwavetech.com>
 *
 * Distributed under terms of the MIT license.
 */

#ifndef SV6160_MEM_MAP_H
#define SV6160_MEM_MAP_H

//#define SKW_MAX_BUF_SIZE    0x400 //1K
#define SKW_MAX_BUF_SIZE    0x100 //256B

/*---------------CODE MEM SECTION-------------------------*/
#define CODE_MEM_BASE_ADDR		  0x100000
#define CODE_MEM_SIZE			   0xAB000//488K
/*-------------------------------------------------------*/

/*----------------DATA MEM SECTION-----------------------*/
#define DATA_MEM_BASE_ADDR		  0x20200000
#define DATA_MEM_SIZE			   0x65800
/*-------------------------------------------------------*/

/*----------------CSCB MEM SECTION-----------------------*/
#define CSCB_MEM_BASE_ADDR		  0xE000ED00
#define CSCB_MEM_SIZE			   0x300//0.75K
/*-------------------------------------------------------*/


/*----------------WREG MEM SECTION-----------------------*/
#define WREG_MEM_BASE_ADDR		  0x40820000
#define WREG_MEM_SIZE			   0xC000//16K
/*-------------------------------------------------------*/


/*----------------PHYR MEM SECTION-----------------------*/
#define PHYR_MEM_BASE_ADDR		  0x40830000
#define PHYR_MEM_SIZE			   0x4000//16K
/*-------------------------------------------------------*/


/*----------------SMEM MEM SECTION-----------------------*/
#define SMEM_MEM_BASE_ADDR		  0x40A00000
#define SMEM_MEM_SIZE			   0x86000//352K
/*-------------------------------------------------------*/

/*----------------UMEM MEM SECTION-----------------------*/
#define UMEM_MEM_BASE_ADDR		  0x401E0000
#define UMEM_MEM_SIZE			  0x10000//64K
/*-------------------------------------------------------*/

/*----------------BTDM MEM SECTION-----------------------*/
#define BTDM_MEM_BASE_ADDR		  0x41000000
#define BTDM_MEM_SIZE			   0xC00//1K
/*-------------------------------------------------------*/


/*----------------BTBT MEM SECTION-----------------------*/
#define BTBT_MEM_BASE_ADDR		  0x41000400
#define BTBT_MEM_SIZE			   0x400//1K
/*-------------------------------------------------------*/


/*----------------BTLE MEM SECTION-----------------------*/
#define BTLE_MEM_BASE_ADDR		  0x41000800
#define BTLE_MEM_SIZE			   0x400//1K
/*-------------------------------------------------------*/


/*----------------BTEM MEM SECTION-----------------------*/
#define BTEM_MEM_BASE_ADDR		  0x41010000
#define BTEM_MEM_SIZE			   0x10000//48K
/*-------------------------------------------------------*/

/*----------------SDIO MEM SECTION-----------------------*/
#define SDIO_MEM_BASE_ADDR		  0x401E0000
#define SDIO_MEM_SIZE			   0x800//2K
/*-------------------------------------------------------*/

/*----------------BTGB MEM SECTION-----------------------*/
#define BTGB_MEM_BASE_ADDR		  0x41022000
#define BTGB_MEM_SIZE			   0x40//64B
/*-------------------------------------------------------*/


/*----------------BTRF MEM SECTION-----------------------*/
#define BTRF_MEM_BASE_ADDR		  0x41024000
#define BTRF_MEM_SIZE			   0x510//1K 272B

/*-------------------------------------------------------*/
#define AHB_REG_BASE_ADDR 		0x40000000
#define AHB_REG_SIZE 	 		0x400

#define HIF_EDMA_BASE_ADDR 		40188000
#define HIF_EDMA_SIZE 	 		0x1080
/*-------------------------------------------------------*/
/*-------------------------------------------------------*/



#endif /* !SV6160_MEM_MAP_H */
