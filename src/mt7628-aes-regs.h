/*
 * Driver for Mediatek MT76x8 AES cryptographic accelerator.
 *
 * Copyright (c) 2018 Richard van Schagen <vschagen@cs.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#ifndef __MTK_AES_ENGINE__
#define __MTK_AES_ENGINE__

#define NUM_AES_RX_DESC		128
#define NUM_AES_TX_DESC		128
#define NUM_AES_BYPASS		0

#define RALINK_SYSCTL_BASE	0xB0000000
#define REG_CLKCTRL		((void *)RALINK_SYSCTL_BASE + 0x30)
#define REG_RSTCTRL		((void *)RALINK_SYSCTL_BASE + 0x34)
#define RALINK_CRYPTO_RST	(1<<29)
#define RALINK_CRYPTO_CLK_EN	(1<<29)

#define CRYPTO_MODE_ENC	BIT(0)
#define CRYPTO_MODE_CBC	BIT(1)

/* 1. AES */
#define AES_TX_BASE_PTR0	0x000
#define AES_TX_MAX_CNT0		0x004
#define AES_TX_CTX_IDX0		0x008
#define AES_TX_DTX_IDX0		0x00C

#define AES_RX_BASE_PTR0	0x100
#define AES_RX_MAX_CNT0		0x104
#define AES_RX_CALC_IDX0	0x108
#define AES_RX_DRX_IDX0		0x10C

#define AES_INFO		0x200
#define AES_GLO_CFG		0x204
#define AES_RST_IDX		0x208
#define AES_RST_CFG		(AES_RST_IDX)
#define AES_DLY_INT_CFG		0x20C
#define AES_FREEQ_THRES		0x210
#define AES_INT_STATUS		0x220
#define AES_INT_MASK		0x228

/* ====================================== */
#define AES_PST_DRX_IDX0	(1u<<16)
#define AES_PST_DTX_IDX0	(1u<<0)

#define AES_RX_2B_OFFSET	(1u<<31)
#define AES_RX_ANYBYTE_ALIGN	(1u<<12)
#define AES_DESC_5DW_INFO_EN	(1u<<11)
#define AES_MUTI_ISSUE		(1u<<10)
#define AES_TWO_BUFFER		(1u<<9)
#define AES_32_BYTES		(1u<<8)
#define AES_TX_WB_DDONE		(1u<<6)
#define AES_RX_DMA_BUSY		(1u<<3)
#define AES_TX_DMA_BUSY		(1u<<1)
#define AES_RX_DMA_EN		(1u<<2)
#define AES_TX_DMA_EN		(1u<<0)

#define AES_BT_SIZE_4DWORDS	(0u<<4)
#define AES_BT_SIZE_8DWORDS	(1u<<4)
#define AES_BT_SIZE_16DWORDS	(2u<<4)
#define AES_BT_SIZE_32DWORDS	(3u<<4)

#define AES_RX_COHERENT		(1u<<31)
#define AES_RX_DLY_INT		(1u<<30)
#define AES_TX_COHERENT		(1u<<29)
#define AES_TX_DLY_INT		(1u<<28)
#define AES_RX_DONE_INT0	(1u<<16)
#define AES_TX_DONE_INT0	(1u<<0)

#define AES_MASK_INT_ALL	(AES_RX_DONE_INT0)

#define AES_DLY_INIT_VALUE	0x00000000

/*
 * AES AES_RX Descriptor Format define
 */

#define RX2_DMA_SDL0_GET(_x)		(((_x) >> 16) & 0x3fff)
#define RX2_DMA_SDL0_SET(_x)		(((_x) & 0x3fff) << 16)
#define RX2_DMA_LS0			BIT(30)
#define RX2_DMA_DONE			BIT(31)

#define RX4_DMA_ENC			BIT(2)
#define RX4_DMA_UDV			BIT(3)
#define RX4_DMA_CBC			BIT(4)
#define RX4_DMA_IVR			BIT(5)
#define RX4_DMA_KIU			BIT(6)

struct aes_rxdesc {
	unsigned int SDP0;
	volatile unsigned int rxd_info2;
	unsigned int user_data;
	unsigned int rxd_info4;
	unsigned int IV[4];
} __attribute__((aligned(32)));

/*
 * AES AES_TX Descriptor Format define
 */

#define TX2_DMA_SDL1_SET(_x)		((_x) & 0x3fff)
#define TX2_DMA_LS1			BIT(14)
#define TX2_DMA_SDL0_SET(_x)		(((_x) & 0x3fff) << 16)
#define TX2_DMA_LS0			BIT(30)
#define TX2_DMA_DONE			BIT(31)

#define TX4_DMA_ENC			BIT(2)
#define TX4_DMA_UDV			BIT(3)
#define TX4_DMA_CBC			BIT(4)
#define TX4_DMA_IVR			BIT(5)
#define TX4_DMA_KIU			BIT(6)

#define TX4_DMA_AES_128			0
#define TX4_DMA_AES_192			1
#define TX4_DMA_AES_256			2

struct aes_txdesc {
	unsigned int SDP0;
	volatile unsigned int txd_info2;
	unsigned int SDP1;
	unsigned int txd_info4;
	unsigned int IV[4];
} __attribute__((aligned(32)));


struct mtk_aes_dma {
	struct scatterlist	*sg;
	int			nents;
	size_t			len;
};

#endif

