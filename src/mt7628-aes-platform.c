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

#include <linux/clk.h>
#include <linux/dma-mapping.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/interrupt.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/types.h>
#include <linux/version.h>

#include "mt7628-aes-platform.h"

static void aes_engine_start(struct mtk_cryp *cryp)
{
	u32 AES_glo_cfg = AES_TX_DMA_EN | AES_RX_DMA_EN | AES_TX_WB_DDONE
			| AES_DESC_5DW_INFO_EN | AES_RX_ANYBYTE_ALIGN
			| AES_32_BYTES;

	writel(AES_DLY_INIT_VALUE, cryp->base + AES_DLY_INT_CFG);
	writel(0xffffffff, cryp->base + AES_INT_STATUS);
	writel(AES_MASK_INT_ALL, cryp->base + AES_INT_MASK);

	AES_glo_cfg |= AES_BT_SIZE_16DWORDS;
	writel(AES_glo_cfg, cryp->base + AES_GLO_CFG);
}

static void aes_engine_reset(void)
{
	u32 val;

	val = readl(REG_CLKCTRL);
	val |= RALINK_CRYPTO_CLK_EN;
	writel(val, REG_CLKCTRL);

	udelay(10);

	val = readl(REG_RSTCTRL);
	val |= RALINK_CRYPTO_RST;
	writel(val, REG_RSTCTRL);

	udelay(10);

	val &= ~(RALINK_CRYPTO_RST);
	writel(val, REG_RSTCTRL);

	udelay(100);
}

static void aes_engine_stop(struct mtk_cryp *cryp)
{
	int i;
	u32 regValue;

	regValue = readl(cryp->base + AES_GLO_CFG);
	regValue &= ~(AES_TX_WB_DDONE | AES_RX_DMA_EN | AES_TX_DMA_EN);
	writel(regValue, cryp->base + AES_GLO_CFG);

	/* wait AES stopped */
	for (i = 0; i < 50; i++) {
		msleep(1);
		regValue = readl(cryp->base + AES_GLO_CFG);
		if (!(regValue & (AES_RX_DMA_BUSY | AES_TX_DMA_BUSY)))
			break;
	}

	/* disable AES interrupt */
	writel(0, cryp->base + AES_INT_MASK);
}

/* Allocate Descriptor rings */
static int mtk_aes_engine_desc_init(struct mtk_cryp *cryp)
{
	int i;
	u32 regVal;
	size_t size;

	size = (NUM_AES_TX_DESC * sizeof(struct aes_txdesc));

	cryp->tx = dma_zalloc_coherent(cryp->dev, size,
					&cryp->phy_tx, GFP_KERNEL);
	if (!cryp->tx)
		goto err_cleanup;

	dev_info(cryp->dev, "TX Ring : %08X\n", cryp->phy_tx);

	size = NUM_AES_RX_DESC * sizeof(struct aes_rxdesc);

	cryp->rx = dma_zalloc_coherent(cryp->dev, size,
					&cryp->phy_rx, GFP_KERNEL);
	if (!cryp->rx)
		goto err_cleanup;

	dev_info(cryp->dev, "RX Ring : %08X\n", cryp->phy_rx);

	for (i = 0; i < NUM_AES_TX_DESC; i++)
		cryp->tx[i].txd_info2 |= TX2_DMA_DONE;

	cryp->aes_tx_front_idx = 0;
	cryp->aes_tx_rear_idx = NUM_AES_TX_DESC-1;

	cryp->aes_rx_front_idx = 0;
	cryp->aes_rx_rear_idx = NUM_AES_RX_DESC-1;

	regVal = readl(cryp->base + AES_GLO_CFG);
	regVal &= 0x00000ff0;
	writel(regVal, cryp->base + AES_GLO_CFG);
	regVal = readl(cryp->base + AES_GLO_CFG);

	writel((u32)cryp->phy_tx, cryp->base + AES_TX_BASE_PTR0);
	writel((u32)NUM_AES_TX_DESC, cryp->base + AES_TX_MAX_CNT0);
	writel(0, cryp->base + AES_TX_CTX_IDX0);
	writel(AES_PST_DTX_IDX0, cryp->base + AES_RST_CFG);

	writel((u32)cryp->phy_rx, cryp->base + AES_RX_BASE_PTR0);
	writel((u32)NUM_AES_RX_DESC, cryp->base + AES_RX_MAX_CNT0);
	writel((u32)(NUM_AES_RX_DESC - 1), cryp->base + AES_RX_CALC_IDX0);
	regVal = readl(cryp->base + AES_RX_CALC_IDX0);
	writel(AES_PST_DRX_IDX0, cryp->base + AES_RST_CFG);

	return 0;
err_cleanup:
	return -ENOMEM;
}


static int mtk_aes_record_init(struct mtk_cryp *cryp)
{
	struct mtk_aes_rec **aes = cryp->aes;
	int i, err = -ENOMEM;

	for (i = 0; i < MTK_REC_NUM; i++) {
		aes = kzalloc(sizeof(**aes), GFP_KERNEL);
		if (!aes[i])
			goto err_cleanup;

		aes[i]->buf = (void *)__get_free_pages(GFP_KERNEL,
						AES_BUF_ORDER);
		if (!aes[i]->buf)
			goto err_cleanup;

		aes[i]->cryp = cryp;

		spin_lock_init(&aes[i]->lock);
		crypto_init_queue(&aes[i]->queue, AES_QUEUE_SIZE);

		tasklet_init(&aes[i]->queue_task, mtk_aes_queue_task,
			     (unsigned long)aes);
		tasklet_init(&aes[i]->done_task, mtk_aes_done_task,
			     (unsigned long)aes);
	}

	return 0;

err_cleanup:
	for (; i--; ) {
		free_page((unsigned long)aes[i]->buf);
		kfree(aes[i]);
	}

	return err;
}

static void mtk_aes_record_free(struct mtk_cryp *cryp)
{
	int i;

	for (i = 0; i < MTK_REC_NUM; i++) {
		tasklet_kill(&cryp->aes[i]->done_task);
		tasklet_kill(&cryp->aes[i]->queue_task);

		free_page((unsigned long)cryp->aes[i]->buf);
		kfree(cryp->aes[i]);
	}
}

/* Free Descriptor Rings */
static void mtk_aes_engine_desc_free(struct mtk_cryp *cryp)
{
	size_t	size;

	writel(0, cryp->base + AES_TX_BASE_PTR0);
	writel(0, cryp->base + AES_RX_BASE_PTR0);

	size = NUM_AES_TX_DESC * sizeof(struct aes_txdesc);

	if (cryp->tx) {
		dma_free_coherent(cryp->dev, size, cryp->tx, cryp->phy_tx);
		cryp->tx = NULL;
		cryp->phy_tx = 0;
	}

	size = NUM_AES_TX_DESC * sizeof(struct aes_rxdesc);

	if (cryp->rx) {
		dma_free_coherent(cryp->dev, size, cryp->rx, cryp->phy_rx);
		cryp->rx = NULL;
		cryp->phy_rx = 0;
	}
}

/* Probe using Device Tree; needs helper to force loading on earlier DTS firmware */

static int mt7628_cryp_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct mtk_cryp *cryp;
	struct resource *res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	int ret;

	cryp = devm_kzalloc(dev, sizeof(*cryp), GFP_KERNEL);
	if (!cryp)
		return -ENOMEM;

	cryp->base = devm_ioremap_resource(dev, res);
	if (IS_ERR(cryp->base))
		return PTR_ERR(cryp->base);

	cryp->dev = dev;

	aes_engine_reset(); // force reset and clk enable

	dev_info(dev, "HW verson: %02X\n", readl(cryp->base + AES_INFO) >> 28);

	cryp->irq = platform_get_irq(pdev, 0);
	if (cryp->irq < 0) {
		dev_err(dev, "Cannot get IRQ resource\n");
		return cryp->irq;
	}

	cryp->clk = NULL;

	/* Allocate descriptor rings */

	ret = mtk_aes_engine_desc_init(cryp);
	/* Init records */

	ret = mtk_aes_record_init(cryp);

	/* Register Ciphers */

	ret = mtk_cipher_alg_register(cryp);

	aes_engine_start(cryp); // Start hw engine

	platform_set_drvdata(pdev, cryp);

	dev_info(dev, "Initialized.\n");

	return 0;
}

static int __exit mt7628_cryp_remove(struct platform_device *pdev)
{
	struct mtk_cryp *cryp = platform_get_drvdata(pdev);

	if (!cryp) {
		printk("Remove: no crypto device found");
		return -ENODEV;
	}
	aes_engine_stop(cryp);
	mtk_cipher_alg_release(cryp);
	mtk_aes_engine_desc_free(cryp);
	mtk_aes_record_free(cryp);
	dev_info(cryp->dev, "Unloaded.\n");
	platform_set_drvdata(pdev, NULL);

	return 0;
}

static const struct of_device_id of_crypto_id[] = {
	{ .compatible = "mediatek,mtk-aes" },
	{},
};

MODULE_DEVICE_TABLE(of, of_crypto_id);

static struct platform_driver mt7628_cryp_driver = {
	.probe  = mt7628_cryp_probe,
	.remove = mt7628_cryp_remove,
	.driver = {
		.name           = "mt7628-aes",
		.of_match_table = of_crypto_id,
	},
};

module_platform_driver(mt7628_cryp_driver);

MODULE_AUTHOR("Richard van Schagen <vschagen@cs.com>");
MODULE_DESCRIPTION("MT7628 AES Crypto hardware driver");
MODULE_LICENSE("GPL");


