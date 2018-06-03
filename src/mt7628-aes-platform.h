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

#ifndef __MTK_PLATFORM_H_
#define __MTK_PLATFORM_H_

#include <crypto/aes.h>
#include <crypto/algapi.h>
#include <crypto/internal/skcipher.h>
#include <crypto/scatterwalk.h>
#include <crypto/skcipher.h>
#include <linux/crypto.h>
#include <linux/dma-mapping.h>
#include <linux/interrupt.h>
#include <linux/scatterlist.h>
#include <linux/types.h>

#include "mt7628-aes-regs.h"


#define MTK_REC_NUM		16
#define AES_QUEUE_SIZE		10
#define AES_BUF_ORDER		2

struct mtk_aes_base_ctx;
struct mtk_aes_rec;
struct mtk_cryp;

typedef int (*mtk_aes_fn)(struct mtk_cryp *cryp, struct mtk_aes_rec *aes);

/**
 * struct mtk_aes_rec - AES operation record
 * @cryp:	pointer to Cryptographic device
 * @queue:	crypto request queue
 * @areq:	pointer to async request
 * @done_task:	the tasklet is use in AES interrupt
 * @queue_task:	the tasklet is used to dequeue request
 * @ctx:	pointer to current context
 * @src:	the structure that holds source sg list info
 * @dst:	the structure that holds destination sg list info
 * @aligned_sg:	the scatter list is use to alignment
 * @real_dst:	pointer to the destination sg list
 * @resume:	pointer to resume function
 * @total:	request buffer length
 * @buf:	pointer to page buffer
 * @id:		the current use of ring
 * @flags:	it's describing AES operation state
 * @lock:	the async queue lock
 *
 * Structure used to record AES execution state.
 */
struct mtk_aes_rec {
	struct mtk_cryp *cryp;
	struct crypto_queue queue;
	struct crypto_async_request *areq;
	struct tasklet_struct done_task;
	struct tasklet_struct queue_task;
	struct mtk_aes_base_ctx *ctx;
	struct mtk_aes_dma src;
	struct mtk_aes_dma dst;

	struct scatterlist aligned_sg;
	struct scatterlist *real_dst;

	mtk_aes_fn resume;

	size_t total;
	void *buf;
	dma_addr_t		phy_key;

	u8 id;
	unsigned long flags;
	/* queue lock */
	spinlock_t lock;
};

/**
 * struct mtk_cryp - Cryptographic device
 * @base:	pointer to mapped register I/O base
 * @dev:	pointer to device
 * @clk_cryp:	pointer to crypto clock
 * @irq:	global system and rings IRQ
 * @tx:		pointer to descriptor input-ring
 * @rx:		pointer to descriptor output-ring
 * @src:	Source Scatterlist to be encrypted/decrypted
 * @dst:	Destination Scatterlist for the result of the operation
 *
 * @aes_list:	device list of AES
 *
 * Structure storing cryptographic device information.
 */
struct mtk_cryp {
	void __iomem			*base;
	struct device			*dev;
	struct clk			*clk;
	int				irq;

	struct aes_txdesc		*tx;
	struct aes_rxdesc		*rx;

	unsigned int			aes_tx_front_idx;
	unsigned int			aes_rx_front_idx;
	unsigned int			aes_tx_rear_idx;
	unsigned int			aes_rx_rear_idx;
	dma_addr_t			phy_tx;
	dma_addr_t			phy_rx;

	struct mtk_aes_rec 		*aes[MTK_REC_NUM];
	struct list_head		aes_list;

	struct crypto_skcipher	*fallback;
};

int mtk_cipher_alg_register(struct mtk_cryp *cryp);
void mtk_cipher_alg_release(struct mtk_cryp *cryp);
static irqreturn_t mtk_aes_irq(int irq, void *dev_id);
static void mtk_aes_done_task(unsigned long data);
static void mtk_aes_queue_task(unsigned long data);

#endif

