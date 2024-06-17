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

MODULE_AUTHOR("Mateusz Bodziony <mb394086>");
MODULE_DESCRIPTION("Zsonet Driver");
MODULE_LICENSE("GPL");



#define pr_log(x, ...) 


static const struct pci_device_id zsonet_pci_tbl[] = {
	{PCI_VENDOR_ID_ZSONET, PCI_DEVICE_ID_ZSONET,
	 PCI_ANY_ID, PCI_ANY_ID, 0, 0}
};

static int irq_num;

struct zsonet_stats {
	u64 packets;
	u64 bytes;
	u64 dropped;
	u64 err;
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
	u8                      pending_writes;
	
        void                    *rx_buffer;
	dma_addr_t              rx_buffer_mapping;
	u32                     rx_buffer_position;
	
	u8			mac_addr[8];
	u8                      irq_requested;
	
	struct zsonet_stats     rx_stats;
	struct zsonet_stats     tx_stats;

	spinlock_t              lock;
	spinlock_t              rx_lock;
	spinlock_t              tx_lock;
};

static void zsonet_setup_buffers(struct zsonet *zp) {
	pr_log("MB - zsonet_setup_buffers");
	unsigned int dev_addr;
	
	for (int i = 0, offset = ZSONET_REG_TX_BUF_0; i < 4; ++i, offset += 4) {
		unsigned int val = *(unsigned int*) &zp->buffer_blk_mapping[i];
		pr_log("MB - zsonet_setup_buffer - setting up buffer %d to %lld = %d", i, zp->buffer_blk_mapping[i],
		       val);
		ZSONET_WRL(zp, offset, val);
	}
	dev_addr = zp->rx_buffer_mapping;
	ZSONET_WRL(zp, ZSONET_REG_RX_BUF, dev_addr);
	ZSONET_WRL(zp, ZSONET_REG_RX_BUF_SIZE, RX_BUFF_SIZE);
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
		pr_log("MB - zsonet_prepare_device - was not turned off mask=%d, enabled = %d", mask, enabled);
		zsonet_stop_device(zp);
		wmb();
	}
  
	zsonet_setup_buffers(zp);
	ZSONET_WRL(zp, ZSONET_REG_INTR_STATUS, ~0);
	ZSONET_WRL(zp, ZSONET_REG_INTR_MASK, ZSONET_INTR_RX_OK | ZSONET_INTR_TX_OK);
	ZSONET_WRL(zp, ZSONET_REG_ENABLED, 1);
}



static unsigned int readl_from_cyclic_buffer(void *buff, unsigned int offset,
                                             unsigned int len)
{
	unsigned int result = 0;
	if (len - offset >= 4) {
		result = *(unsigned int *) (buff + offset);
	} else {
		int left = len - offset;
		char *lr = ((char*) &result);
		char *rr = ((char*) &result) + left;
		if (left > 0) {
		  memcpy(lr, buff + offset, left);
		}
		memcpy(rr, buff, 4 - left);
	}

	return result;
}


static void skb_read_from_cyclic_buffer(struct sk_buff *skb, const void *buff,
                                    unsigned int offset, unsigned int len,
                                    unsigned int size)
{

	int left = len - offset;

	if (left >= size) {
	        skb_copy_to_linear_data(skb, buff+offset, size);
	} else {
		skb_copy_to_linear_data(skb, buff+offset, left);
	        skb_copy_to_linear_data_offset(skb, left, buff, size-left);
	}
}

static int zsonet_read_one(struct zsonet *zp) {

	unsigned int pos, data_len;
	struct sk_buff *skb;

	pos = zp->rx_buffer_position;
	unsigned int z = readl_from_cyclic_buffer(zp->rx_buffer, pos, RX_BUFF_SIZE);
	data_len = le32_to_cpu(z);
        data_len = data_len & 0xffff;

	if (data_len > RX_BUFF_SIZE) {
		zp->dev->stats.rx_dropped++;
		/// Device is in an unknown state so it's easiest to assume we need to start
		/// reading from write_offset
		zp->rx_buffer_position = ZSONET_RDL(zp, ZSONET_REG_RX_BUF_WRITE_OFFSET); 
		pr_log("MB - zsonet_read_one - data_len greater than buffer size");
		return 1;
	}


	/* skb = napi_alloc_skb(&zp->napi, data_len); */
	skb = alloc_skb(data_len, GFP_KERNEL);
	if (unlikely(!skb)) {
		pr_log("MB - zsonet_read_one - dropping packet because of memory allocation");
		zp->dev->stats.rx_dropped += 1;
		zp->rx_buffer_position += data_len + 4;
		if (zp->rx_buffer_position >= RX_BUFF_SIZE) zp->rx_buffer_position -= RX_BUFF_SIZE;
		
		return 1;
	}
	
	pos = pos + 4;
	if (pos >= RX_BUFF_SIZE) pos -= RX_BUFF_SIZE;

        skb_read_from_cyclic_buffer(skb, zp->rx_buffer, pos, RX_BUFF_SIZE, data_len);
	pos += data_len;
	if (pos >= RX_BUFF_SIZE)
		pos -= RX_BUFF_SIZE;
	zp->rx_buffer_position = pos;

	skb_put(skb, data_len);
	skb->protocol = eth_type_trans(skb, zp->dev);

        netif_rx(skb);

	zp->rx_stats.packets += 1;
	zp->rx_stats.bytes += data_len + 1;//<Nagłówek też wliczamy	
	return 1;
}

static void zsonet_update_rx_err(struct zsonet *zp) {
	unsigned int missed = ZSONET_RDL(zp, ZSONET_REG_RX_MISSED);
	ZSONET_WRL(zp, ZSONET_REG_RX_MISSED, 0);
	zp->dev->stats.rx_missed_errors += missed;
	
}

static int zsonet_rx_read_many(struct zsonet *zp, int budget)
{
	int work_done = 0;
	if (!budget) return 0;

	spin_lock(&zp->rx_lock);
	int write_position = ZSONET_RDL(zp, ZSONET_REG_RX_BUF_WRITE_OFFSET);
	rmb();
	pr_log("MB - zsonet_rx_poll, rx_read_pos %d, rx_write_pos %d",
			  (u32) zp->rx_buffer_position, write_position);
	while (zp->rx_buffer_position != write_position) {
		work_done += zsonet_read_one(zp);
		write_position = ZSONET_RDL(zp, ZSONET_REG_RX_BUF_WRITE_OFFSET);
		if (work_done == budget)
			break;
	}
	zsonet_update_rx_err(zp);
	
	ZSONET_WRL(zp, ZSONET_REG_RX_BUF_READ_OFFSET, (u32) zp->rx_buffer_position);
	spin_unlock(&zp->rx_lock);

	return work_done;
}


static void zsonet_tx_finish(struct zsonet *zp, unsigned int i) {
	unsigned int offset;
	offset = ZSONET_REG_TX_STATUS_0 + i * 4;

	u32 tx_finshed = ZSONET_RDL(zp, offset);
	pr_log("MB - zsonet_tx_finish - tx_finished = %x, flaga - %d, i - %d", tx_finshed,
	       tx_finshed & ZSONET_TX_STATUS_TX_FINISHED, i);
	
	if (tx_finshed & ZSONET_TX_STATUS_TX_FINISHED)
	{
		if (zp->buffer_blk_in_use[i])
		{
			pr_log("MB - zsonet_tx_finish - finished job for tx_num: %d", i);
			zp->tx_stats.packets += 1;
			zp->tx_stats.bytes   +=  zp->buffer_blk_in_use[i];
			zp->buffer_blk_in_use[i] = 0;
			zp->pending_writes--;
		} else {
			pr_log("MB - zsonet_tx_finish - empty_bulk: %d", i);
		}
	}
}

static irqreturn_t
zsonet_interrupt(int irq, void *dev_instance)
{
	if (irq != irq_num) {
		pr_log("MB - irq is not for this device irq %d", irq);
		return IRQ_NONE;
	}

	struct zsonet *zp;
	struct net_device *dev = dev_instance;
	unsigned int status;
	/* unsigned int mask = ZSONET_INTR_TX_OK; */
	
	zp = netdev_priv(dev);

	spin_lock(&zp->lock);
	status = ZSONET_RDL(zp, ZSONET_REG_INTR_STATUS);
        rmb();
	ZSONET_WRL(zp, ZSONET_REG_INTR_STATUS, ZSONET_INTR_TX_OK | ZSONET_INTR_RX_OK);
	wmb();
	spin_unlock(&zp->lock);
	
	pr_log("MB - zsonet_interrupt - Status %d", status);
	if  (status & ZSONET_INTR_TX_OK) {
		pr_log("MB - zsonet_interrupt - TX - spin_lock_irq");
		spin_lock(&zp->tx_lock);
		for (int i = 0; i < 4; ++i) {
			zsonet_tx_finish(zp, i);
		}
		if (!zp->buffer_blk_in_use[zp->tx_buffer_index] && netif_queue_stopped(zp->dev))
			netif_wake_queue(zp->dev);

		spin_unlock(&zp->tx_lock);
		pr_log("MB - zsonet_interrupt - spin_unlock_irq ");
	}

	pr_log("MB - zsonet_interrupt RX_WRITE_POS = %d RX_BUFF_SIZE %d",
	       ZSONET_RDL(zp, ZSONET_REG_RX_BUF_WRITE_OFFSET), ZSONET_RDL(zp, ZSONET_REG_RX_BUF_SIZE));

	unsigned int has_data = ZSONET_RDL(zp, ZSONET_REG_RX_STATUS) & ZSONET_RX_STATUS_RX_HAS_DATA;
	
	if (has_data || status & ZSONET_INTR_RX_OK) {
	        pr_log("MB - zsonet_interrupt - rx_lock ");
		unsigned int budget = 0xf;
		unsigned int work = zsonet_rx_read_many(zp, budget);
		if (work == budget) {
		  spin_lock(&zp->lock);
		  ZSONET_WRL(zp, ZSONET_REG_INTR_STATUS, ~(ZSONET_INTR_TX_OK | ZSONET_INTR_RX_OK));
		  spin_unlock(&zp->lock);
		}
	}

	return IRQ_HANDLED;
}

static void
zsonet_get_stats64(struct net_device *dev, struct rtnl_link_stats64 *stats)
{
	struct zsonet *zp = netdev_priv(dev);


	netdev_stats_to_stats64(stats, &dev->stats);

	stats->rx_bytes = zp->rx_stats.bytes;
	stats->rx_packets = zp->rx_stats.packets;
	stats->rx_errors += zp->rx_stats.err;
	stats->tx_packets = zp->tx_stats.packets;
	stats->tx_bytes = zp->tx_stats.bytes;
}

static int
zsonet_allocate_tx_buffer_blk(struct zsonet *zp) {
	for (int  i = 0; i < 4; ++i) {
		pr_log("MB - zsonet_allocate_tx_buffer_blk - allocation rx num %d", i);
		
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
			pr_log("MB - zsonet_free_tx_buffer - %d", i);
			
			dma_free_coherent(&zp->pdev->dev, TX_BUFF_SIZE,
					  zp->buffer_blk[i], zp->buffer_blk_mapping[i]);
			zp->buffer_blk[i] = NULL;
		}
	}
}

static int
zsonet_allocate_rx_buffer_blk(struct zsonet *zp)
{
	pr_log("MB - zsonet_allocate_rx_buffer - allocation rx num");
	zp->rx_buffer = dma_alloc_coherent(&zp->pdev->dev, RX_BUFF_SIZE, &zp->rx_buffer_mapping, GFP_KERNEL);
	if (!zp->rx_buffer)
		return -ENOMEM;
	
	return 0;
}

static void
zsonet_free_rx_buffer(struct zsonet *zp) {
	if (zp->rx_buffer) {
		pr_log("MB - zsonet_free_rx_buffer");
			
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


/* static void zsonet_init_napi(struct zsonet *zp) */
/* { */
/* } */


static int
zsonet_request_irq(struct zsonet *zp)
{

	int rc = 0, irq = zp->pdev->irq;
	unsigned long flags = 0;
	irq_num = irq;

	pr_log("MB - zsonet_request_irq - dev_name %s - irq %d", zp->dev->name, irq);
	
	rc = request_irq(irq, zsonet_interrupt, flags, zp->dev->name, zp->dev);
	if (!rc)
		zp->irq_requested = 1;
	return rc;
}

static void
zsonet_free_irq(struct zsonet *zp)
{
	if (zp->irq_requested) {
		pr_log("MB - zsonet_free_irq");
		free_irq(zp->pdev->irq, zp->dev);
	}
}

static int
zsonet_open(struct net_device *dev)
{
	int rc;
	struct zsonet *zp = netdev_priv(dev);

	pr_log("MB - zsonet_open - netif_carrier_off");
	netif_carrier_off(dev);

	pr_log("MB - zsonet_open - zsonet_alloc_mem");
	rc = zsonet_alloc_mem(zp);
	if (rc)
		goto open_err;

	pr_log("MB - zsonet_open - zsonet_request_irq");
	rc = zsonet_request_irq(zp);
	if (rc)
		goto open_err;

	pr_log("MB - zsonet_open - zsonet_prepare_device");
	zsonet_prepare_device(zp);
	pr_log("MB - zsonet_open - netif_carrier_on");
	netif_carrier_on(dev);

	netif_start_queue(dev);

	pr_log("MB - zsonet_open - open");
	return 0;
open_err:
	pr_log("MB - zsonet_open - zsonet_free_irq");
	zsonet_free_irq(zp);
	pr_log("MB - zsonet_open - zsonet_free_mem");
	zsonet_free_mem(zp);
	return rc;
}

static int
zsonet_close(struct net_device *dev){

	struct zsonet *zp = netdev_priv(dev);

	pr_log("MB - zsonet_close - netif_carrier_of");
	netif_carrier_off(dev);

	pr_log("MB - zsonet_close - zsonet_free_irq");
	zsonet_free_irq(zp);
	pr_log("MB - zsonet_close - zsonet_stop_device");
	zsonet_stop_device(zp);
	pr_log("MB - zsonet_close - zsonet_free_mem");
	zsonet_free_mem(zp);

	return 0;
}

#define TX_STATUS_I(zp, i) ZSONET_RDL(zp, (ZSONET_REG_TX_STATUS_0 + (i*4)))

static inline void update_tx_stats(unsigned int size) {
  
}

static netdev_tx_t
zsonet_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	pr_log("MB - zsonet_start_xmit ");

	struct zsonet       *zp;

	void *               tx_buf = NULL;
	int pos;
	unsigned int         len;
	unsigned int         offset;
	
        zp = netdev_priv(dev);
	len = skb->len;
	

	if (unlikely(len > TX_BUFF_SIZE)) {
		zp->dev->stats.tx_dropped++;
		pr_log("MB - zsonet_start_xmit - drop of packet because of exceeding length");
		goto free_skb;
	}

	unsigned long flags;
	spin_lock_irqsave(&zp->tx_lock, flags);

	pos = zp->tx_buffer_index;
	offset = ZSONET_REG_TX_STATUS_0 + pos * 4;
	pr_log("MB - zsonet_start_xmit - within spin_lock tx_pos %d", pos);
	
	if (zp->buffer_blk_in_use[pos]) {
		pr_log("MB - zsonet_start_xmit - stopping_queue - queue full for pos - %d", pos);
			netif_tx_stop_all_queues(dev);
	} else  {
		tx_buf = zp->buffer_blk[pos];
	}

	if (tx_buf) {
		zp->tx_buffer_index += 1;
		if (zp->tx_buffer_index >= 4) zp->tx_buffer_index = 0;
	}
	spin_unlock_irqrestore(&zp->tx_lock, flags);

	if (!tx_buf) {
		pr_log("MB - zsonet_start_xmit - skb_copy_and_csum_dev ");
		return NETDEV_TX_BUSY;
	}
	
	pr_log("MB - zsonet_start_xmit - skb_copy_and_csum_dev ");
	if (len < MIN_ETHERNET_PACKET_SIZE) {
		memset(tx_buf, 0, ETH_ZLEN);
		pr_log("MB - zsonet_start_smit - packet smaller than ethernet");
		
	}
	skb_copy_and_csum_dev(skb, tx_buf);

	spin_lock_irqsave(&zp->tx_lock, flags);
	zp->buffer_blk_in_use[pos] = max(len, (unsigned int) ETH_ZLEN);
	zp->pending_writes++;
	
	wmb();
	len = max(len, (unsigned int) ETH_ZLEN);
	ZSONET_WRL(zp, offset, (len << 16));
	spin_unlock_irqrestore(&zp->tx_lock, flags);
	
free_skb:
	pr_log("MB - zsonet_start_xmit - kfree");
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
		pr_log("MB - zsonet_set_mac i: %d, mac_addr: %d", i, (int) zp->mac_addr[i]);
	}
}

static void ping_dma_mask(struct device *dev) {
	if (dma_set_mask(dev, DMA_BIT_MASK(64)) == 0) {
		pr_log("MB - ping_dma_mask - dma_set_mask 64 available");
	}
	if (dma_set_mask(dev, DMA_BIT_MASK(32)) == 0) {
		pr_log("MB - ping_dma_mask - dma_set_mask 32 available");
	}
	if (dma_set_coherent_mask(dev, DMA_BIT_MASK(64)) == 0) {
		pr_log("MB - ping_dma_mask - dma_set_coherent_mask 64 available");
	}
	if (dma_set_coherent_mask(dev, DMA_BIT_MASK(32)) == 0) {
		pr_log("MB - ping_dma_mask - dma_set_coherent_mask 32 available");
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
	
	pr_log("MB - zsonet_init_board - enable_device");
	rc = pci_enable_device(pdev);
	if (rc) {
		dev_err(&pdev->dev, "Cannot enable PCI device, aborting\n");
		goto err_out;
	}
	
	pr_log("MB - zsonet_init_board - request regions");
	rc = pci_request_regions(pdev, DRV_MODULE_NAME);
	if (rc) {
		dev_err(&pdev->dev, "Cannot obtain PCI resources, aborting\n");
		goto err_out_disable;
	}
	
	pr_log("MB - zsonet_init_board - resource flags");
	if (!(pci_resource_flags(pdev, 0) & IORESOURCE_MEM)) {
		dev_err(&pdev->dev,
			"Cannot find PCI device base address, aborting\n");
		rc = -ENODEV;
		goto err_out_release;
	}

	pr_log("MB - zsonet_init_board - set master");
	pci_set_master(pdev);

	zp->pdev = pdev;
	zp->dev = dev;
	
	pr_log("MB - zsonet_init_board - iomap");
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
	
	pr_log("MB - zsonet_init_board - zsonet_set_mac");
	zsonet_set_mac(zp);

	pr_log("MB - zsonet_init_board - return 0");
	return 0;
	
err_out_unmap:
	pr_log("MB - zsonet_init_board - unmap");
	pci_iounmap(pdev, zp->regview);
	zp->regview = NULL;
err_out_release:
	pr_log("MB - zsonet_init_board - release_regions");
	pci_release_regions(pdev);
err_out_disable:
	pr_log("MB - zsonet_init_board - disable_device");
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
	/* netif_napi_add(dev, &zp->napi, zsonet_poll); */

	pr_log("MB - zso_init_one - pci_set_drvdata\n");
	pci_set_drvdata(pdev, dev);

	pr_log("MB - zso_init_one - eth_hw_adddr_set\n");
	eth_hw_addr_set(dev, zp->mac_addr);


	pr_log("MB - zso_init_one features %lld", dev->features);
	

	dev->min_mtu = MIN_ETHERNET_PACKET_SIZE;
	dev->max_mtu = MAX_ETHERNET_JUMBO_PACKET_SIZE;
	
	pr_log("MB - zso_init_one - spin_lock_init\n");
	spin_lock_init(&zp->lock);
	spin_lock_init(&zp->rx_lock);
	spin_lock_init(&zp->tx_lock);

	pr_log("MB - zso_init_one - register_netdev\n");
	if ((rc = register_netdev(dev))) {
		dev_err(&pdev->dev, "Cannot register net device\n");
		goto error;
	}

	pr_log("MB - zso_init_one - success");
	return 0;
error:
	pr_log("MB - zso_init_one - error");
	pci_iounmap(pdev, zp->regview);
	zp->regview = NULL;
	pr_log("MB - zso_init_one - release");
	pci_release_regions(pdev);
	pr_log("MB - zso_init_one - disable");
	pci_disable_device(pdev);
err_free:

	free_netdev(dev);
  return rc;
}

static void
zsonet_remove_one(struct pci_dev *pdev)
{
	pr_log("MB - zso_remove_one - get_drvdata");
	struct net_device *dev = pci_get_drvdata(pdev);
	if (dev == 0) {
		pr_log("MB - zso_remove_one - drvdata is NULL");
	} else {
		pr_log("MB - zso_remove_one - dev %p dereference", dev);
	}
	struct zsonet *zp = netdev_priv(dev);

	pr_log("MB - zso_remove_one - unregister");
	unregister_netdev(dev);
	

	pr_log("MB - zso_remove_one - iounmap");
	pci_iounmap(pdev, zp->regview);

	pr_log("MB - zso_remove_one - free_net_dev");
	free_netdev(dev);

	pr_log("MB - zso_remove_one - disable");
	pci_disable_device(pdev);
	
	pr_log("MB - zso_remove_one - release");
	pci_release_regions(pdev);
}

static struct pci_driver zsonet_pci_driver = {
  .name = DRV_MODULE_NAME,
  .id_table = zsonet_pci_tbl,
  .probe = zso_init_one,
  .remove = zsonet_remove_one
};

module_pci_driver(zsonet_pci_driver);
