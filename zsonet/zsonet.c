#include <linux/interrupt.h>
#include <linux/irqreturn.h>
#include <linux/skbuff.h>
#include <linux/types.h>
#include <linux/dma-mapping.h>
#include <linux/gfp_types.h>
#include <linux/netdevice.h>
#include <linux/mod_devicetable.h>
#include <linux/etherdevice.h>
#include <linux/pci.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <asm/io.h>

#include "zsonet.h"
#include "net/net_debug.h"

#include <linux/spinlock.h>
#include <linux/u64_stats_sync.h>

#define DRV_MODULE_NAME "zsonet"
#define PCI_VENDOR_ID_ZSONET 0x0250
#define PCI_DEVICE_ID_ZSONET 0x250e
#define REG_SIZE 256

#define MIN_ETHERNET_PACKET_SIZE	(ETH_ZLEN - ETH_HLEN)
#define MAX_ETHERNET_PACKET_SIZE	ETH_DATA_LEN
#define MAX_ETHERNET_JUMBO_PACKET_SIZE 9000
#define RX_BUFF_SIZE (1 << 15)
#define TX_BUFF_SIZE (1 << 15)

#define ZSONET_RDL(zp, offset) readl(zp->regview + offset)
#define ZSONET_WRL(zp, offset, val) writel(val, zp->regview + offset)
#define ZSONET_WRW(zp, offset, val) writew(val, zp->regview + offset)

MODULE_AUTHOR("Mateusz Bodziony <mb394086>");
MODULE_DESCRIPTION("Zsonet Driver");
MODULE_LICENSE("GPL");

static const struct pci_device_id zsonet_pci_tbl[] = {
	{PCI_VENDOR_ID_ZSONET, PCI_DEVICE_ID_ZSONET,
	 PCI_ANY_ID, PCI_ANY_ID, 0, 0}
};

struct zsonet_stats {
	u64 packets;
	u64 bytes;
	u64 dropped;
	struct u64_stats_sync  usc;
};



struct zsonet {
	void __iomem		*regview;

	struct net_device	*dev;
	struct pci_dev		*pdev;
	
	void			*buffer_blk[4];
	dma_addr_t		buffer_blk_mapping[4];
	struct sk_buff          *buffer_blk_sk_buff[4];
	u16                     buffer_blk_in_use[4];
	u8                      tx_buffer_index;
	
        void                    *rx_buffer;
	dma_addr_t              rx_buffer_mapping;
	u16                     rx_buffer_position;
	
	u8			mac_addr[8];
	u8                      irq_requested;
	struct napi_struct	napi;
	
	struct zsonet_stats     rx_stats;
	struct zsonet_stats     tx_stats;

	spinlock_t              lock;
	spinlock_t              rx_lock;
	spinlock_t              tx_lock;
};

static void zsonet_setup_buffers(struct zsonet *zp) {
	pr_err("MB - zsonet_setup_buffers");
	unsigned int dev_addr;
	
	for (int i = 0, offset = ZSONET_REG_TX_BUF_0; i < 4; ++i, offset += 4) {
		unsigned int val = *(unsigned int*) &zp->buffer_blk_mapping[i];
		ZSONET_WRL(zp, offset, val);
	}
	dev_addr = *(unsigned int*) &zp->rx_buffer_mapping;
	ZSONET_WRL(zp, ZSONET_REG_RX_BUF, dev_addr);
	ZSONET_WRW(zp, ZSONET_REG_RX_BUF_SIZE, RX_BUFF_SIZE);
}

static void
zsonet_stop_device(struct zsonet *zp)
{
	ZSONET_WRL(zp, ZSONET_REG_ENABLED, 0);
	ZSONET_WRL(zp, ZSONET_REG_INTR_MASK, 0);
}

static void
zsonet_prepare_device(struct zsonet *zp)
{
	u32 mask = 0, enabled = 0;
	if ((mask = ZSONET_RDL(zp, ZSONET_REG_INTR_MASK)) || (enabled = ZSONET_RDL(zp, ZSONET_REG_ENABLED))){
		pr_err("MB - zsonet_prepare_device - was not turned off mask=%d, enabled = %d", mask, enabled);
		zsonet_stop_device(zp);
		wmb();
	}
  
	pr_err("MB - zsonet_prepare_device");
	zsonet_setup_buffers(zp);
	ZSONET_WRL(zp, ZSONET_REG_INTR_STATUS, 0);
	ZSONET_WRL(zp, ZSONET_REG_INTR_MASK, ZSONET_INTR_RX_OK | ZSONET_INTR_TX_OK);
	ZSONET_WRL(zp, ZSONET_REG_ENABLED, 1);
}

static unsigned int readl_from_cyclic_buffer(void *buff, unsigned int offset,
                                             unsigned int len)
{
	pr_err("MB - readl_from_cyclic_buffer");
	unsigned int result = 0;
	if (len - offset >= 4) {
		result = *(unsigned int *) (buff + offset);
	} else {
		int left = len - offset;
		memcpy(&result, buff+offset, left);
		memcpy(&result + left, buff, 4 - left);
	}
	pr_err("MB - readl_from_cyclic_buffer - result %d", result);
	return result;
}

static void read_from_cyclic_buffer(void *dest, const void *buff,
                                    unsigned int offset, unsigned int len,
                                    unsigned int size)
{

	int left = len - offset;
	pr_err("MB - readl_from_cyclic_buffer - left %d - size %d", left, size);
	if (left >= size) {
		memcpy(dest, buff, size);
	} else {
		memcpy(dest, buff+offset, left);
		memcpy(dest + left, buff, size - left);
	}
}

/* static struct sk_buff *zsonet_read_one_without_lock(struct zsonet *zp) */
/* { */
/* 	unsigned int pos, data_len; */
/* 	struct sk_buff *skb; */
	
/* 	pos = zp->rx_buffer_position; */
/* 	data_len = le32_to_cpu(readl_from_cyclic_buffer(zp->rx_buffer, pos, RX_BUFF_SIZE)); */
/* 	pr_err("MB - zsonet_read_one_without_lock - data_len:%u", data_len); */
	
/* 	if (data_len > RX_BUFF_SIZE) { */
/* 		return NULL; */
/* 	} */

/* 	skb = netdev_alloc_skb(zp->dev, data_len); */
/* 	read_from_cyclic_buffer(skb->data, zp->rx_buffer, zp->rx_buffer_position, RX_BUFF_SIZE, data_len); */
/* 	zp->rx_buffer_position += data_len; */
/* 	if (zp->rx_buffer_position >= RX_BUFF_SIZE) */
/* 		zp->rx_buffer_position -= RX_BUFF_SIZE; */

/* 	skb_put(skb, data_len); */
/* 	skb->protocol = eth_type_trans(skb, zp->dev); */
	
/* 	return skb; */
/* } */

static int zsonet_read_one(struct zsonet *zp) {

	unsigned int pos, data_len;
	struct sk_buff *skb;

	pos = zp->rx_buffer_position;
	data_len = le32_to_cpu(readl_from_cyclic_buffer(zp->rx_buffer, pos, RX_BUFF_SIZE));
	pr_err("MB - zsonet_read_one_without_lock - data_len:%u", data_len);

	if (data_len > RX_BUFF_SIZE) {
		pr_err("MB - zsonet_read_one_without_lock - data_len greater than buffer size");
		return 0;
	}
	
	skb = netdev_alloc_skb(zp->dev, data_len);
	if (!skb) {
		pr_err("MB - zsonet_read_one_without_lock - netdev_alloc_skb failed");
		/// packet dropped
		return 0;
	}
	read_from_cyclic_buffer(skb->data, zp->rx_buffer, zp->rx_buffer_position, RX_BUFF_SIZE, data_len);
	zp->rx_buffer_position += data_len;
	if (zp->rx_buffer_position >= RX_BUFF_SIZE)
		zp->rx_buffer_position -= RX_BUFF_SIZE;

	skb_put(skb, data_len);
	skb->protocol = eth_type_trans(skb, zp->dev);
	pr_err("MB - zsonet_read_one_without_lock - netif_rx");
	netif_rx(skb);

	return 1;
}

static int zsonet_rx_poll(struct zsonet *zp, int budget)
{
	int work_done = 0;
	int write_position = ZSONET_RDL(zp, ZSONET_REG_RX_BUF_WRITE_OFFSET);
	pr_err("MB - zsonet_rx_poll - budget %d", budget);
	
	if (!budget) return 0;

	spin_lock(&zp->rx_lock);
	while (zp->rx_buffer_position != write_position) {
		work_done += zsonet_read_one(zp);
		if (work_done == budget)
			break;
	}

	pr_err("MB - zsonet_rx_poll - work_done %d", work_done);

	if (work_done < budget) {
	  unsigned long flags;
	  spin_lock_irqsave(&zp->lock, flags);
	  if (napi_complete_done(&zp->napi, work_done)) {
		  ZSONET_WRL(zp, ZSONET_REG_INTR_MASK, ZSONET_INTR_TX_OK | ZSONET_INTR_RX_OK);
	  }
	  spin_unlock_irqrestore(&zp->lock, flags);
	}
	ZSONET_WRL(zp, ZSONET_REG_RX_BUF_READ_OFFSET, (u32) zp->rx_buffer_position);
	spin_unlock(&zp->rx_lock);

	return work_done;
}

static int zsonet_poll(struct napi_struct *napi, int budget) {
	struct zsonet *zp = container_of(napi, struct zsonet, napi);
	int res = 0;

	res = zsonet_rx_poll(zp, budget);
	// TO DO - co zrobić z utraconymi ramkami//
	return res;
}


static void zsonet_tx_finish(struct zsonet *zp, unsigned int i) {
	unsigned int offset;
	offset = ZSONET_REG_TX_STATUS_0 + i * 4;

	u32 tx_finshed = ZSONET_RDL(zp, offset);
	pr_err("MB - zsonet_tx_finish - tx_finished = %x, flaga - %d, i - %d", tx_finshed,
	       tx_finshed & ZSONET_TX_STATUS_TX_FINISHED, i);
	
	if (tx_finshed & ZSONET_TX_STATUS_TX_FINISHED)
	{
		if (zp->buffer_blk_in_use[i])
		{
			pr_err("MB - zsonet_tx_finish - finished job for tx_num: %d", i);
			zp->tx_stats.packets += 1;
			zp->tx_stats.bytes   +=  zp->buffer_blk_in_use[i];
			zp->buffer_blk_in_use[i] = 0;
			ZSONET_WRL(zp, offset, 0);
		} else {
			ZSONET_WRL(zp, offset, 0);
			pr_err("MB - zsonet_tx_finish - empty_bulk: %d", i);
		}
	}
}

static irqreturn_t
zsonet_interrupt(int irq, void *dev_instance)
{
        pr_err("MB - zsonet_interrupt");
	struct zsonet *zp;
	struct net_device *dev = dev_instance;
	unsigned int status;
	unsigned int mask = ZSONET_INTR_TX_OK;
	
	zp = netdev_priv(dev);

	spin_lock_irq(&zp->lock);
	status = ZSONET_RDL(zp, ZSONET_REG_INTR_STATUS);
	wmb(); rmb();
	ZSONET_WRL(zp, ZSONET_REG_INTR_MASK, 0);
	spin_unlock_irq(&zp->lock);
	
	pr_info("MB - zsonet_interrupt - Status %d", status);
	if  (status & ZSONET_INTR_TX_OK) {
		pr_info("MB - zsonet_interrupt - TX - spin_lock_irq");
		spin_lock(&zp->tx_lock);
		for (int i = 0; i < 4; ++i) {
			zsonet_tx_finish(zp, i);
		}
		if (!zp->buffer_blk_in_use[zp->tx_buffer_index] && netif_queue_stopped(zp->dev)) 
			netif_wake_queue(zp->dev);
		status = status & ~ZSONET_INTR_TX_OK;
		pr_info("MB - zsonet_interrupt - spin_lock_irq - Changing status to %d", status);
		ZSONET_WRL(zp, ZSONET_REG_INTR_STATUS, status);
		spin_unlock(&zp->tx_lock);
		pr_info("MB - zsonet_interrupt - spin_unlock_irq ");
	}

	if (status & ZSONET_INTR_RX_OK) {
	        pr_info("MB - zsonet_interrupt - rx_lock ");
		spin_lock_irq(&zp->lock);
		ZSONET_WRL(zp, ZSONET_REG_INTR_STATUS, status & ~ZSONET_INTR_RX_OK);
		if (napi_schedule_prep(&zp->napi)) {
			__napi_schedule(&zp->napi);
		} else {
			mask |= ZSONET_INTR_RX_OK;
		}		
		spin_unlock_irq(&zp->lock);
	}

	spin_lock_irq(&zp->lock);
	status = ZSONET_RDL(zp, ZSONET_REG_INTR_STATUS);
	wmb(); rmb();
	ZSONET_WRL(zp, ZSONET_REG_INTR_MASK, mask);
	spin_unlock_irq(&zp->lock);
	
	return IRQ_HANDLED;
}



static void
zsonet_get_stats64(struct net_device *dev, struct rtnl_link_stats64 *stats)
{
	struct zsonet *zp = netdev_priv(dev);


	netdev_stats_to_stats64(stats, &dev->stats);

	stats->rx_bytes = zp->rx_stats.bytes;
	stats->rx_packets = zp->rx_stats.packets;
	stats->tx_packets = zp->tx_stats.packets;
	stats->tx_bytes = zp->tx_stats.bytes;
}

static int
zsonet_allocate_tx_buffer_blk(struct zsonet *zp) {
	for (int  i = 0; i < 4; ++i) {
		pr_info("MB - zsonet_allocate_tx_buffer_blk - allocation rx num %d", i);
		
		zp->buffer_blk[i] = dma_alloc_coherent(&zp->pdev->dev, TX_BUFF_SIZE,
						       &zp->buffer_blk_mapping[i], GFP_KERNEL);

		if (!zp->buffer_blk[i])
			return -ENOMEM;
	}

	return 0;
};

static void
zsonet_free_tx_buffer_blk(struct zsonet *zp) {
	for (int  i = 0; i < 4; ++i) {
		if (zp->buffer_blk[i]){
			pr_info("MB - zsonet_free_tx_buffer - %d", i);
			
			dma_free_coherent(&zp->pdev->dev, TX_BUFF_SIZE,
					  zp->buffer_blk[i], zp->buffer_blk_mapping[i]);
			zp->buffer_blk[i] = NULL;
		}
	}
}

static int
zsonet_allocate_rx_buffer_blk(struct zsonet *zp)
{
	pr_info("MB - zsonet_allocate_rx_buffer - allocation rx num");
	zp->rx_buffer = dma_alloc_coherent(&zp->pdev->dev, RX_BUFF_SIZE, &zp->rx_buffer_mapping, GFP_KERNEL);
	if (!zp->rx_buffer)
		return -ENOMEM;
	
	return 0;
}

static void
zsonet_free_rx_buffer(struct zsonet *zp) {
	if (zp->rx_buffer) {
		pr_info("MB - zsonet_free_rx_buffer");
			
		dma_free_coherent(&zp->pdev->dev, RX_BUFF_SIZE,
				  zp->rx_buffer, zp->rx_buffer_mapping);
		zp->rx_buffer = NULL;
	}
}

static void
zsonet_free_mem(struct zsonet *zp) {
	zsonet_free_tx_buffer_blk(zp);
	zsonet_free_rx_buffer(zp);
}


static int
zsonet_alloc_mem(struct zsonet *zp) {
	int err;

	if ((err = zsonet_allocate_tx_buffer_blk(zp)))
		goto alloc_mem_err;
	if ((err = zsonet_allocate_rx_buffer_blk(zp)))
		goto alloc_mem_err;
	return 0;

alloc_mem_err:
	zsonet_free_mem(zp);
	return -ENOMEM;
}


static void zsonet_init_napi(struct zsonet *zp)
{
}


static void zsonet_napi_enable(struct zsonet *zp) {}

static int
zsonet_request_irq(struct zsonet *zp)
{

	int rc = 0, irq = zp->pdev->irq;
	unsigned long flags = 0;


	pr_info("MB - zsonet_request_irq - dev_name %s - irq %d", zp->dev->name, irq);
	
	rc = request_irq(irq, zsonet_interrupt, flags, zp->dev->name, zp->dev);
	if (!rc)
		zp->irq_requested = 1;
	return rc;
}

static void
zsonet_free_irq(struct zsonet *zp)
{
	if (zp->irq_requested) {
		pr_info("MB - zsonet_free_irq");
		free_irq(zp->pdev->irq, zp->dev);
	}
}


static int
zsonet_open(struct net_device *dev)
{
	int rc;
	struct zsonet *zp = netdev_priv(dev);

	pr_err("MB - zsonet_open - netif_carrier_off");
	netif_carrier_off(dev);

	pr_err("MB - zsonet_open - zsonet_init_napi");
	zsonet_init_napi(zp);
	pr_err("MB - zsonet_open - zsonet_napi_enable");
	zsonet_napi_enable(zp);

	pr_err("MB - zsonet_open - zsonet_alloc_mem");
	rc = zsonet_alloc_mem(zp);
	if (rc)
		goto open_err;

	pr_err("MB - zsonet_open - zsonet_request_irq");
	rc = zsonet_request_irq(zp);
	if (rc)
		goto open_err;

	pr_err("MB - zsonet_open - zsonet_prepare_device");
	zsonet_prepare_device(zp);
	pr_err("MB - zsonet_open - netif_carrier_on");
	netif_carrier_on(dev);

	netif_start_queue(dev);

	pr_err("MB - zsonet_open - open");
	return 0;
open_err:
	pr_err("MB - zsonet_open - zsonet_free_irq");
	zsonet_free_irq(zp);
	pr_err("MB - zsonet_open - zsonet_free_mem");
	zsonet_free_mem(zp);
	return rc;
}

static int
zsonet_close(struct net_device *dev)
{
	struct zsonet *zp = netdev_priv(dev);

	/* bnx2_disable_int_sync(bp); */
	/* bnx2_napi_disable(bp); */
	/* netif_tx_disable(dev); */
	/* del_timer_sync(&bp->timer); */
	/* zsonet_shutdown_chip(bp); */
	pr_err("MB - zsonet_close - zsonet_free_irq");
	zsonet_free_irq(zp);
	/* bnx2_free_skbs(bp); */
	pr_err("MB - zsonet_close - zsonet_free_mem");
	zsonet_free_mem(zp);
	/* bnx2_del_napi(bp); */
	/* bp->link_up = 0; */
	netif_carrier_off(zp->dev);
	return 0;
}

#define TX_STATUS_I(zp, i) ZSONET_RDL(zp, (ZSONET_REG_TX_STATUS_0 + (i*4)))

static inline void update_tx_stats(unsigned int size) {
  
}

static netdev_tx_t
zsonet_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	pr_err("MB - zsonet_start_xmit");
	struct zsonet       *zp;
	/* struct netdev_queue *txq; */
	void *               tx_buf = NULL;
	int pos;
	unsigned int         len;
	unsigned int         offset;
	
        zp = netdev_priv(dev);
	len = skb->len;
	

	if (unlikely(len > TX_BUFF_SIZE)) {
		zp->tx_stats.dropped += 1;
		pr_err("MB - zsonet_start_xmit - drop of packet because of exceeding length");
		goto free_skb;
	}	

	spin_lock_irq(&zp->tx_lock);

	pos = zp->tx_buffer_index;
	offset = ZSONET_REG_TX_STATUS_0 + pos * 4;
	pr_err("MB - zsonet_start_xmit - within spin_lock tx_pos %d", pos);
	
	if (zp->buffer_blk_in_use[pos]) {
		/* if(TX_STATUS_I(zp, pos) & ZSONET_TX_STATUS_TX_FINISHED) { */
		/* 	update_tx_stats(zp->buffer_blk_in_use[pos]); */
		/* 	zp->buffer_blk_in_use[pos] = 0; */
		/* 	tx_buf = zp->buffer_blk[pos]; */
		/* } else { */
			pr_err("MB - zsonet_start_xmit - stopping_queue");
			netif_tx_stop_all_queues(dev);
		/* } */
	} else  {
		tx_buf = zp->buffer_blk[pos];
	}

	if (tx_buf) {
		zp->tx_buffer_index += 1;
		if (zp->tx_buffer_index >= 4) zp->tx_buffer_index = 0;
	}
	spin_unlock_irq(&zp->tx_lock);

	if (!tx_buf) {
		pr_err("MB - zsonet_start_xmit - skb_copy_and_csum_dev ");
		return NETDEV_TX_BUSY;
	}
	
	pr_err("MB - zsonet_start_xmit - skb_copy_and_csum_dev ");
	if (len < MIN_ETHERNET_PACKET_SIZE) {
		memset(tx_buf, 0, ETH_ZLEN);
		pr_err("MB - zsonet_start_smit - packet smaller than ethernet");
		
	}
	skb_copy_and_csum_dev(skb, tx_buf);

	pr_err("MB - zsonet_start_xmit - ZSONET_WRL(zp, offset, (len << 16)) - %x ", len<<16);
	spin_lock_irq(&zp->tx_lock);
	zp->buffer_blk_in_use[pos] = max(len, (unsigned int) ETH_ZLEN);
	wmb();	
	ZSONET_WRL(zp, offset, (len << 16));
	spin_unlock_irq(&zp->tx_lock);
	
free_skb:
	pr_err("MB - zsonet_start_xmit - kfree");
	dev_kfree_skb_any(skb);
	return NETDEV_TX_OK;
}



static const struct net_device_ops zsonet_netdev_ops = {
	.ndo_open = zsonet_open,
	.ndo_stop = zsonet_close,
	.ndo_start_xmit = zsonet_start_xmit,
	.ndo_get_stats64 = zsonet_get_stats64
};

static void
zsonet_set_mac(struct zsonet *zp)
{
	for (int i = 0, offset = ZSONET_REG_MAC_0; i < 6; ++i, offset += sizeof(u8)) {
		zp->mac_addr[i] = readb(zp->regview + offset);
		pr_err("MB - zsonet_set_mac i: %d, mac_addr: %d", i, (int) zp->mac_addr[i]);
	}
}

static void ping_dma_mask(struct device *dev) {
	if (dma_set_mask(dev, DMA_BIT_MASK(64)) == 0) {
		pr_err("MB - ping_dma_mask - dma_set_mask 64 available");
	}
	if (dma_set_mask(dev, DMA_BIT_MASK(32)) == 0) {
		pr_err("MB - ping_dma_mask - dma_set_mask 32 available");
	}
	if (dma_set_coherent_mask(dev, DMA_BIT_MASK(64)) == 0) {
		pr_err("MB - ping_dma_mask - dma_set_coherent_mask 64 available");
	}
	if (dma_set_coherent_mask(dev, DMA_BIT_MASK(32)) == 0) {
		pr_err("MB - ping_dma_mask - dma_set_coherent_mask 32 available");
	}
}

static int
zsonet_init_board(struct pci_dev *pdev, struct net_device *dev)
{
	struct zsonet *zp;
	int rc;
	/* u32 reg; */
	/* u64 dma_mask; */

	SET_NETDEV_DEV(dev, &pdev->dev);
	zp = netdev_priv(dev);
	
	pr_err("MB - zsonet_init_board - enable_device");
	rc = pci_enable_device(pdev);
	if (rc) {
		dev_err(&pdev->dev, "Cannot enable PCI device, aborting\n");
		goto err_out;
	}
	
	pr_err("MB - zsonet_init_board - request regions");
	rc = pci_request_io_regions(pdev, DRV_MODULE_NAME);
	if (rc) {
		dev_err(&pdev->dev, "Cannot obtain PCI resources, aborting\n");
		goto err_out_disable;
	}
	
	pr_err("MB - zsonet_init_board - resource flags");
	if (!(pci_resource_flags(pdev, 0) & IORESOURCE_MEM)) {
		dev_err(&pdev->dev,
			"Cannot find PCI device base address, aborting\n");
		rc = -ENODEV;
		goto err_out_release;
	}

	pr_err("MB - zsonet_init_board - set master");
	pci_set_master(pdev);

	zp->pdev = pdev;
	zp->dev = dev;
	
	pr_err("MB - zsonet_init_board - iomap");
	zp->regview = pci_iomap(pdev, 0, REG_SIZE);
	if (!zp->regview) {
		dev_err(&pdev->dev, "Cannot map register space, aborting\n");
		rc = -ENOMEM;
		goto err_out_release;
	}


	ping_dma_mask(&pdev->dev);


	if ((rc = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(32)))) {
		dev_err(&pdev->dev, "Cannot map do DMA\n");
		goto err_out_unmap;
	}
	
	pr_err("MB - zsonet_init_board - zsonet_set_mac");
	zsonet_set_mac(zp);

	pr_err("MB - zsonet_init_board - return 0");
	return 0;
	
err_out_unmap:
	pr_err("MB - zsonet_init_board - unmap");
	pci_iounmap(pdev, zp->regview);
	zp->regview = NULL;
err_out_release:
	pr_err("MB - zsonet_init_board - release_regions");
	pci_release_regions(pdev);
err_out_disable:
	pr_err("MB - zsonet_init_board - disable_device");
	pci_disable_device(pdev);
err_out:
	return rc;
}




static int
zso_init_one(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	struct net_device *dev;
	struct zsonet *zp;
	int rc;

	dev = alloc_etherdev(sizeof(*zp));
	zp = netdev_priv(dev);
	if (!dev)
		return -ENOMEM;
	
	rc = zsonet_init_board(pdev, dev);
	if (rc < 0)
		goto err_free;

	dev->netdev_ops = &zsonet_netdev_ops;
	netif_napi_add(dev, &zp->napi, zsonet_poll);

	pr_err("MB - zso_init_one - pci_set_drvdata\n");
	pci_set_drvdata(pdev, dev);

	pr_err("MB - zso_init_one - eth_hw_adddr_set\n");
	eth_hw_addr_set(dev, zp->mac_addr);

	dev->hw_features = NETIF_F_IP_CSUM | NETIF_F_SG |
		NETIF_F_TSO | NETIF_F_TSO_ECN |
		NETIF_F_RXHASH | NETIF_F_RXCSUM;

	dev->vlan_features = dev->hw_features;
	/* dev->features |= dev->hw_features; */
	
	dev->min_mtu = MIN_ETHERNET_PACKET_SIZE;
	dev->max_mtu = MAX_ETHERNET_JUMBO_PACKET_SIZE;
	
	pr_err("MB - zso_init_one - spin_lock_init\n");
	spin_lock_init(&zp->lock);
	spin_lock_init(&zp->rx_lock);
	spin_lock_init(&zp->tx_lock);

	pr_err("MB - zso_init_one - register_netdev\n");
	if ((rc = register_netdev(dev))) {
		dev_err(&pdev->dev, "Cannot register net device\n");
		goto error;
	}

	netdev_info(dev, "MB - zso_init_one - success");
	return 0;
error:
	pr_err("MB - zso_init_one - error");
	pci_iounmap(pdev, zp->regview);
	zp->regview = NULL;
	pr_err("MB - zso_init_one - release");
	pci_release_regions(pdev);
	pr_err("MB - zso_init_one - disable");
	pci_disable_device(pdev);
err_free:
	/* zsonet_free_statts_blk(dev); */
	free_netdev(dev);
  return rc;
}

static void
zso_remove_one(struct pci_dev *pdev)
{
	struct net_device *dev = pci_get_drvdata(pdev);
	struct zsonet *zp = netdev_priv(dev);

	unregister_netdev(dev);

	pr_err("MB - zso_remove_one - iounmap");
	pci_iounmap(pdev, zp->regview);
	
	pr_err("MB - zso_remove_one - free_net_dev");
	free_netdev(dev);

	pr_err("MB - zso_remove_one - release");
	pci_release_regions(pdev);
	pr_err("MB - zso_remove_one - disable");
	pci_disable_device(pdev);
}

static struct pci_driver zsonet_pci_driver = {
  .name = DRV_MODULE_NAME,
  .id_table = zsonet_pci_tbl,
  .probe = zso_init_one,
  .shutdown = zso_remove_one
};

module_pci_driver(zsonet_pci_driver);
