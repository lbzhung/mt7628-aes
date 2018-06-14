/*
*/
struct mtk_cryp;

static void mtk_aes_done_task(unsigned long data);

static void mtk_aes_queue_task(unsigned long data);

int mtk_cipher_alg_register(struct mtk_cryp *cryp);

void mtk_cipher_alg_release(struct mtk_cryp *cryp);

void mtk_cryp_finish_req(struct mtk_cryp *cryp, int ret);

