// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2019 Intel Corporation. All rights rsvd. */
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/device.h>
#include <linux/io-64-nonatomic-lo-hi.h>
#include <linux/dmaengine.h>
#include <linux/idxd.h>
#include <uapi/linux/idxd.h>
#include "../dmaengine.h"
#include "registers.h"

static inline struct idxd_wq *to_idxd_wq(struct dma_chan *c)
{
	struct idxd_dma_chan *idxd_chan;

	idxd_chan = container_of(c, struct idxd_dma_chan, chan);
	return idxd_chan->wq;
}

void idxd_dma_complete_txd(struct idxd_desc *desc,
			   enum idxd_complete_type comp_type,
			   bool free_desc)
{
	struct idxd_device *idxd = desc->wq->idxd;
	struct dma_async_tx_descriptor *tx;
	struct dmaengine_result res;
	int complete = 1;

	if (desc->completion->status == DSA_COMP_SUCCESS) {
		res.result = DMA_TRANS_NOERROR;
	} else if (desc->completion->status) {
		if (idxd->request_int_handles && comp_type != IDXD_COMPLETE_ABORT &&
		    desc->completion->status == DSA_COMP_INT_HANDLE_INVAL &&
		    idxd_queue_int_handle_resubmit(desc))
			return;
		res.result = DMA_TRANS_WRITE_FAILED;
	} else if (comp_type == IDXD_COMPLETE_ABORT) {
		res.result = DMA_TRANS_ABORTED;
	} else {
		complete = 0;
	}

	tx = &desc->txd;
	if (complete && tx->cookie) {
		dma_cookie_complete(tx);
		dma_descriptor_unmap(tx);
		dmaengine_desc_get_callback_invoke(tx, &res);
		tx->callback = NULL;
		tx->callback_result = NULL;
	}

	if (free_desc)
		idxd_free_desc(desc->wq, desc);
}

static void op_flag_setup(unsigned long flags, u32 *desc_flags)
{
	*desc_flags = IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCR;
	if (flags & DMA_PREP_INTERRUPT)
		*desc_flags |= IDXD_OP_FLAG_RCI;
}

static inline void set_completion_address(struct idxd_desc *desc,
					  u64 *compl_addr)
{
		*compl_addr = desc->compl_dma;
}

static inline void idxd_prep_desc_common(struct idxd_wq *wq,
					 struct dsa_hw_desc *hw, char opcode,
					 u64 addr_f1, u64 addr_f2, u64 len,
					 u64 compl, u32 flags)
{
	hw->flags = flags;
	hw->opcode = opcode;
	hw->src_addr = addr_f1;
	hw->dst_addr = addr_f2;
	hw->xfer_size = len;
	/*
	 * For dedicated WQ, this field is ignored and HW will use the WQCFG.priv
	 * field instead. This field should be set to 1 for kernel descriptors.
	 */
	hw->priv = 1;
	hw->completion_addr = compl;
}

static struct dma_async_tx_descriptor *
idxd_dma_prep_interrupt(struct dma_chan *c, unsigned long flags)
{
	struct idxd_wq *wq = to_idxd_wq(c);
	u32 desc_flags;
	struct idxd_desc *desc;

	if (wq->state != IDXD_WQ_ENABLED)
		return NULL;

	op_flag_setup(flags, &desc_flags);
	desc = idxd_alloc_desc(wq, IDXD_OP_BLOCK);
	if (IS_ERR(desc))
		return NULL;

	idxd_prep_desc_common(wq, desc->hw, DSA_OPCODE_NOOP,
			      0, 0, 0, desc->compl_dma, desc_flags);
	desc->txd.flags = flags;
	return &desc->txd;
}

static struct dma_async_tx_descriptor *
idxd_dma_submit_memcpy(struct dma_chan *c, dma_addr_t dma_dest,
		       dma_addr_t dma_src, size_t len, unsigned long flags)
{
	struct idxd_wq *wq = to_idxd_wq(c);
	u32 desc_flags;
	struct idxd_device *idxd = wq->idxd;
	struct idxd_desc *desc;

	if (wq->state != IDXD_WQ_ENABLED)
		return NULL;

	if (len > idxd->max_xfer_bytes)
		return NULL;

	op_flag_setup(flags, &desc_flags);
	desc = idxd_alloc_desc(wq, IDXD_OP_BLOCK);
	if (IS_ERR(desc))
		return NULL;

	idxd_prep_desc_common(wq, desc->hw, DSA_OPCODE_MEMMOVE,
			      dma_src, dma_dest, len, desc->compl_dma,
			      desc_flags);

	desc->txd.flags = flags;

	return &desc->txd;
}

static int idxd_dma_alloc_chan_resources(struct dma_chan *chan)
{
	struct idxd_wq *wq = to_idxd_wq(chan);
	struct device *dev = &wq->idxd->pdev->dev;

	idxd_wq_get(wq);
	dev_dbg(dev, "%s: client_count: %d\n", __func__,
		idxd_wq_refcount(wq));
	return 0;
}

static void idxd_dma_free_chan_resources(struct dma_chan *chan)
{
	struct idxd_wq *wq = to_idxd_wq(chan);
	struct device *dev = &wq->idxd->pdev->dev;

	idxd_wq_put(wq);
	dev_dbg(dev, "%s: client_count: %d\n", __func__,
		idxd_wq_refcount(wq));
}

static enum dma_status idxd_dma_tx_status(struct dma_chan *dma_chan,
					  dma_cookie_t cookie,
					  struct dma_tx_state *txstate)
{
	return DMA_OUT_OF_ORDER;
}

/*
 * issue_pending() does not need to do anything since tx_submit() does the job
 * already.
 */
static void idxd_dma_issue_pending(struct dma_chan *dma_chan)
{
}

static dma_cookie_t idxd_dma_tx_submit(struct dma_async_tx_descriptor *tx)
{
	struct dma_chan *c = tx->chan;
	struct idxd_wq *wq = to_idxd_wq(c);
	dma_cookie_t cookie;
	int rc;
	struct idxd_desc *desc = container_of(tx, struct idxd_desc, txd);

	cookie = dma_cookie_assign(tx);

	rc = idxd_submit_desc(wq, desc);
	if (rc < 0) {
		idxd_free_desc(wq, desc);
		return rc;
	}

	return cookie;
}

static void idxd_dma_release(struct dma_device *device)
{
	struct idxd_dma_dev *idxd_dma = container_of(device, struct idxd_dma_dev, dma);

	kfree(idxd_dma);
}

int idxd_register_dma_device(struct idxd_device *idxd)
{
	struct idxd_dma_dev *idxd_dma;
	struct dma_device *dma;
	struct device *dev = &idxd->pdev->dev;
	int rc;

	idxd_dma = kzalloc_node(sizeof(*idxd_dma), GFP_KERNEL, dev_to_node(dev));
	if (!idxd_dma)
		return -ENOMEM;

	dma = &idxd_dma->dma;
	INIT_LIST_HEAD(&dma->channels);
	dma->dev = dev;

	dma_cap_set(DMA_INTERRUPT, dma->cap_mask);
	dma_cap_set(DMA_PRIVATE, dma->cap_mask);
	dma_cap_set(DMA_COMPLETION_NO_ORDER, dma->cap_mask);
	dma->device_release = idxd_dma_release;

	dma->device_prep_dma_interrupt = idxd_dma_prep_interrupt;
	if (idxd->hw.opcap.bits[0] & IDXD_OPCAP_MEMMOVE) {
		dma_cap_set(DMA_MEMCPY, dma->cap_mask);
		dma->device_prep_dma_memcpy = idxd_dma_submit_memcpy;
	}

	dma->device_tx_status = idxd_dma_tx_status;
	dma->device_issue_pending = idxd_dma_issue_pending;
	dma->device_alloc_chan_resources = idxd_dma_alloc_chan_resources;
	dma->device_free_chan_resources = idxd_dma_free_chan_resources;

	rc = dma_async_device_register(dma);
	if (rc < 0) {
		kfree(idxd_dma);
		return rc;
	}

	idxd_dma->idxd = idxd;
	/*
	 * This pointer is protected by the refs taken by the dma_chan. It will remain valid
	 * as long as there are outstanding channels.
	 */
	idxd->idxd_dma = idxd_dma;
	return 0;
}

void idxd_unregister_dma_device(struct idxd_device *idxd)
{
	dma_async_device_unregister(&idxd->idxd_dma->dma);
}

static int idxd_register_dma_channel(struct idxd_wq *wq)
{
	struct idxd_device *idxd = wq->idxd;
	struct dma_device *dma = &idxd->idxd_dma->dma;
	struct device *dev = &idxd->pdev->dev;
	struct idxd_dma_chan *idxd_chan;
	struct dma_chan *chan;
	int rc, i;

	idxd_chan = kzalloc_node(sizeof(*idxd_chan), GFP_KERNEL, dev_to_node(dev));
	if (!idxd_chan)
		return -ENOMEM;

	chan = &idxd_chan->chan;
	chan->device = dma;
	list_add_tail(&chan->device_node, &dma->channels);

	for (i = 0; i < wq->num_descs; i++) {
		struct idxd_desc *desc = wq->descs[i];

		dma_async_tx_descriptor_init(&desc->txd, chan);
		desc->txd.tx_submit = idxd_dma_tx_submit;
	}

	rc = dma_async_device_channel_register(dma, chan);
	if (rc < 0) {
		kfree(idxd_chan);
		return rc;
	}

	wq->idxd_chan = idxd_chan;
	idxd_chan->wq = wq;
	get_device(wq_confdev(wq));

	return 0;
}

static void idxd_unregister_dma_channel(struct idxd_wq *wq)
{
	struct idxd_dma_chan *idxd_chan = wq->idxd_chan;
	struct dma_chan *chan = &idxd_chan->chan;
	struct idxd_dma_dev *idxd_dma = wq->idxd->idxd_dma;

	dma_async_device_channel_unregister(&idxd_dma->dma, chan);
	list_del(&chan->device_node);
	kfree(wq->idxd_chan);
	wq->idxd_chan = NULL;
	put_device(wq_confdev(wq));
}

/*
 * ictx is an array based off of accelerator types. enum idxd_type
 * is used as index
 */
static struct idxd_cdev_context ictx[IDXD_TYPE_MAX] = {
	{ .name = "dsa" },
	{ .name = "iax" }
};

static void idxd_cdev_dev_release(struct device *dev)
{
	struct idxd_cdev *idxd_cdev = dev_to_cdev(dev);
	struct idxd_cdev_context *cdev_ctx;
	struct idxd_wq *wq = idxd_cdev->wq;

	cdev_ctx = &ictx[wq->idxd->data->type];
	ida_simple_remove(&cdev_ctx->minor_ida, idxd_cdev->minor);
	kfree(idxd_cdev);
}

static struct device_type idxd_cdev_device_type = {
	.name = "idxd_cdev",
	.release = idxd_cdev_dev_release,
};

static inline struct idxd_cdev *inode_idxd_cdev(struct inode *inode)
{
	struct cdev *cdev = inode->i_cdev;

	return container_of(cdev, struct idxd_cdev, cdev);
}

static inline struct idxd_wq *inode_wq(struct inode *inode)
{
	struct idxd_cdev *idxd_cdev = inode_idxd_cdev(inode);

	return idxd_cdev->wq;
}

static int idxd_cdev_open(struct inode *inode, struct file *filp)
{
	struct idxd_wq *wq;

	wq = inode_wq(inode);
	filp->private_data = wq;

	return 0;
}

static int idxd_cdev_release(struct inode *inode, struct file *filp)
{
	filp->private_data = NULL;
	return 0;
}

#define IDXD_IOCTL_GET_WQ 0
static long idxd_cdev_ioctl(struct file *filp, unsigned int cmd,
					unsigned long arg)
{
	struct idxd_wq *wq = (struct idxd_wq*) filp->private_data;

	switch (cmd) {
		case IDXD_IOCTL_GET_WQ:
			return (long) wq;
		default:
			return -ENOTTY;
	}

	return 0;
}

static const struct file_operations idxd_cdev_fops = {
	.owner = THIS_MODULE,
	.open = idxd_cdev_open,
	.release = idxd_cdev_release,
	.unlocked_ioctl = idxd_cdev_ioctl,
};

static int idxd_wq_add_cdev(struct idxd_wq *wq)
{
	struct idxd_device *idxd = wq->idxd;
	struct idxd_cdev *idxd_cdev;
	struct cdev *cdev;
	struct device *dev;
	struct idxd_cdev_context *cdev_ctx;
	int rc, minor;

	idxd_cdev = kzalloc(sizeof(*idxd_cdev), GFP_KERNEL);
	if (!idxd_cdev)
		return -ENOMEM;

	idxd_cdev->idxd_dev.type = IDXD_DEV_CDEV;
	idxd_cdev->wq = wq;
	cdev = &idxd_cdev->cdev;
	dev = cdev_dev(idxd_cdev);
	cdev_ctx = &ictx[wq->idxd->data->type];
	minor = ida_simple_get(&cdev_ctx->minor_ida, 0, MINORMASK, GFP_KERNEL);
	if (minor < 0) {
		kfree(idxd_cdev);
		return minor;
	}
	idxd_cdev->minor = minor;

	device_initialize(dev);
	dev->parent = wq_confdev(wq);
	dev->bus = &dsa_bus_type;
	dev->type = &idxd_cdev_device_type;
	dev->devt = MKDEV(MAJOR(cdev_ctx->devt), minor);

	rc = dev_set_name(dev, "dma_%s/wq%u.%u", idxd->data->name_prefix, idxd->id, wq->id);
	if (rc < 0)
		goto err;

	wq->idxd_cdev = idxd_cdev;
	cdev_init(cdev, &idxd_cdev_fops);
	rc = cdev_device_add(cdev, dev);
	if (rc) {
		dev_dbg(&wq->idxd->pdev->dev, "cdev_add failed: %d\n", rc);
		goto err;
	}

	return 0;

 err:
	put_device(dev);
	wq->idxd_cdev = NULL;
	return rc;
}

static void idxd_wq_del_cdev(struct idxd_wq *wq)
{
	struct idxd_cdev *idxd_cdev;

	idxd_cdev = wq->idxd_cdev;
	wq->idxd_cdev = NULL;
	cdev_device_del(&idxd_cdev->cdev, cdev_dev(idxd_cdev));
	put_device(cdev_dev(idxd_cdev));
}

static int idxd_dmaengine_drv_probe(struct idxd_dev *idxd_dev)
{
	struct device *dev = &idxd_dev->conf_dev;
	struct idxd_wq *wq = idxd_dev_to_wq(idxd_dev);
	struct idxd_device *idxd = wq->idxd;
	int rc;

	if (idxd->state != IDXD_DEV_ENABLED)
		return -ENXIO;

	mutex_lock(&wq->wq_lock);
	wq->type = IDXD_WQT_KERNEL;

	rc = drv_enable_wq(wq);
	if (rc < 0) {
		dev_dbg(dev, "Enable wq %d failed: %d\n", wq->id, rc);
		rc = -ENXIO;
		goto err;
	}

	/*
	rc = idxd_register_dma_channel(wq);
	if (rc < 0) {
		idxd->cmd_status = IDXD_SCMD_DMA_CHAN_ERR;
		dev_dbg(dev, "Failed to register dma channel\n");
		goto err_dma;
	}
	*/

	rc = idxd_wq_add_cdev(wq);
	if (rc < 0) {
		idxd->cmd_status = IDXD_SCMD_CDEV_ERR;
		goto err_dma;
	}

	idxd->cmd_status = 0;
	mutex_unlock(&wq->wq_lock);
	return 0;

err_dma:
	drv_disable_wq(wq);
err:
	wq->type = IDXD_WQT_NONE;
	mutex_unlock(&wq->wq_lock);
	return rc;
}

static void idxd_dmaengine_drv_remove(struct idxd_dev *idxd_dev)
{
	struct idxd_wq *wq = idxd_dev_to_wq(idxd_dev);

	mutex_lock(&wq->wq_lock);
	idxd_wq_del_cdev(wq);
	__idxd_wq_quiesce(wq);
	//idxd_unregister_dma_channel(wq);
	drv_disable_wq(wq);
	mutex_unlock(&wq->wq_lock);
}

static enum idxd_dev_type dev_types[] = {
	IDXD_DEV_WQ,
	IDXD_DEV_NONE,
};

struct idxd_device_driver idxd_dmaengine_drv = {
	.probe = idxd_dmaengine_drv_probe,
	.remove = idxd_dmaengine_drv_remove,
	.name = "dmaengine",
	.type = dev_types,
};
EXPORT_SYMBOL_GPL(idxd_dmaengine_drv);

int idxd_dma_cdev_register(void)
{
	int rc, i;

	for (i = 0; i < IDXD_TYPE_MAX; i++) {
		ida_init(&ictx[i].minor_ida);
		rc = alloc_chrdev_region(&ictx[i].devt, 0, MINORMASK,
					 ictx[i].name);
		if (rc)
			goto err_free_chrdev_region;
	}

	return 0;

err_free_chrdev_region:
	for (i--; i >= 0; i--)
		unregister_chrdev_region(ictx[i].devt, MINORMASK);

	return rc;
}

void idxd_dma_cdev_remove(void)
{
	int i;

	for (i = 0; i < IDXD_TYPE_MAX; i++) {
		unregister_chrdev_region(ictx[i].devt, MINORMASK);
		ida_destroy(&ictx[i].minor_ida);
	}
}
