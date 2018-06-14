/* MT7628 AES Platform Header */
#include <crypto/aes.h>
#include <crypto/scatterwalk.h>
#include <crypto/internal/skcipher.h>

struct aes_rxdesc {
	unsigned int SDP0;
	volatile unsigned int rxd_info2;
	unsigned int user_data;
	unsigned int rxd_info4;
	unsigned int IV[4];
} __attribute__((aligned(32)));

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

struct mtk_crypt;
struct mtk_aes_rec;

typedef int (*mtk_aes_fn)(struct mtk_cryp *cryp, struct mtk_aes_rec *aes);

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
	struct mtk_aes_rec		*rec;

	unsigned int			aes_tx_front_idx;
	unsigned int			aes_rx_front_idx;
	unsigned int			aes_tx_rear_idx;
	unsigned int			aes_rx_rear_idx;
	dma_addr_t			phy_tx;
	dma_addr_t			phy_rx;
	dma_addr_t			phy_rec;

	struct list_head		aes_list;

	spinlock_t			lock;
};


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
	struct mtk_cryp			*cryp;
	struct crypto_queue		queue;
	struct crypto_async_request	*areq;
	struct tasklet_struct		done_task;
	struct tasklet_struct		queue_task;
	struct mtk_aes_base_ctx		*ctx;
	struct mtk_aes_dma		src;
	struct mtk_aes_dma		dst;
	struct mtk_aes_dma		orig_out;
	/* Buffers for copying for unaligned cases */
	struct scatterlist		in_sgl;
	struct scatterlist		out_sgl;
	void				*buf_in;
	void				*buf_out;
	bool                    	sgs_copied;

	mtk_aes_fn 			resume;

	u8 				id;
	unsigned long 			flags;
	/* queue lock */
	spinlock_t 			lock;
};

struct mtk_aes_base_ctx {
	struct mtk_cryp 	*cryp;
	u8			key[AES_MAX_KEY_SIZE];
	u32			keylen;
	dma_addr_t		phy_key;
	struct crypto_skcipher	*fallback;
	mtk_aes_fn 		start;
};

struct mtk_aes_ctx {
	struct mtk_aes_base_ctx	base;

};


struct mtk_aes_reqctx {
	unsigned long		mode;
	u8			*iv;
	unsigned int		count;

};

struct mtk_aes_drv {
	struct list_head	dev_list;
	spinlock_t		lock;
};

static struct mtk_aes_drv mtk_aes = {
	.dev_list = LIST_HEAD_INIT(mtk_aes.dev_list),
	.lock = __SPIN_LOCK_UNLOCKED(mtk_aes.lock),
};


