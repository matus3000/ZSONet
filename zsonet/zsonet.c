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
#include <string.h>

#include "zsonet.h"
#include "asm-generic/int-ll64.h"
#include "linux/byteorder/generic.h"
#include "linux/slab.h"

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

struct zsonet_napi {
	struct napi_struct	napi		____cacheline_aligned;
	struct zsonet           *zp;
};

struct zsonet {
	void __iomem		*regview;

	struct net_device	*dev;
	struct pci_dev		*pdev;
	
	void			*buffer_blk[4];
	dma_addr_t		buffer_blk_mapping[4];
	struct sk_buff          *buffer_blk_sk_buff[4];
	u8                      buffer_blk_in_use[4];
	u8                      buffer_blk_position;
	
        void                    *rx_buffer;
	dma_addr_t              rx_buffer_mapping;
	u16                     rx_buffer_position;
	
	u8			mac_addr[8];
	u8                      irq_requested;
	struct zsonet_napi      zsonet_napi;
	int x;
	int y;
};

static void zsonet_setup_buffers(struct zsonet *zp) {
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
zsonet_prepare_device(struct zsonet *zp)
{
	zsonet_setup_buffers(zp);
	ZSONET_WRL(zp, ZSONET_REG_INTR_STATUS, 0);
	ZSONET_WRL(zp, ZSONET_REG_INTR_MASK, ZSONET_INTR_RX_OK | ZSONET_INTR_TX_OK);
	ZSONET_WRL(zp, ZSONET_REG_ENABLED, 1);
}

static void zsonet_free_stats_blk(struct net_device *dev) {}

static unsigned int readl_from_cyclic_buffer(void *buff, unsigned int offset,
                                             unsigned int len)
{
	unsigned int result = 0;
	if (len - offset >= 4) {
		result = *(unsigned int *) (buff + offset);
	} else {
		int left = len - offset;
		memcpy(&result, buff+offset, left);
		memcpy(&result + left, buff, 4 - left);
	}

	return result;
}

static void read_from_cyclic_buffer(void *dest, const void *buff,
                                    unsigned int offset, unsigned int len,
                                    unsigned int size)
{
	int left = len - offset;
	
	if (left >= size) {

	} else {
		memcpy(dest, buff+offset, left);
		memcpy(dest + left, buff, size - left);
	}
}

static struct sk_buff *zsonet_read_one_without_lock(struct zsonet *zp)
{
	unsigned int pos, data_len;
	struct sk_buff *skb;

	pos = zp->rx_buffer_position;
	data_len = le32_to_cpu(readl_from_cyclic_buffer(zp->rx_buffer, pos, RX_BUFF_SIZE));

	if (data_len > RX_BUFF_SIZE)
		return NULL;
	
	skb = netdev_alloc_skb(zp->dev, data_len);
	read_from_cyclic_buffer(skb->data, zp->rx_buffer, zp->rx_buffer_position, RX_BUFF_SIZE, data_len);
	zp->rx_buffer_position += data_len;
	if (zp->rx_buffer_position >= RX_BUFF_SIZE)
		zp->rx_buffer_position -= RX_BUFF_SIZE;

	skb_put(skb, data_len);
	skb->protocol = eth_type_trans(skb, zp->dev);
	
	return skb;
}

static int zsonet_read_one(struct zsonet *zp) {

	unsigned int pos, data_len;
	struct sk_buff *skb;

	pos = zp->rx_buffer_position;
	data_len = le32_to_cpu(readl_from_cyclic_buffer(zp->rx_buffer, pos, RX_BUFF_SIZE));

	if (data_len > RX_BUFF_SIZE)
		return 0;
	
	skb = netdev_alloc_skb(zp->dev, data_len);
	read_from_cyclic_buffer(skb->data, zp->rx_buffer, zp->rx_buffer_position, RX_BUFF_SIZE, data_len);
	zp->rx_buffer_position += data_len;
	if (zp->rx_buffer_position >= RX_BUFF_SIZE)
		zp->rx_buffer_position -= RX_BUFF_SIZE;

	skb_put(skb, data_len);
	skb->protocol = eth_type_trans(skb, zp->dev);
	netif_rx(skb);

	return 1;
}

static int zsonet_rx_poll(struct zsonet *zp, int budget)
{
  int work_done = 0;
  int write_position = ZSONET_RDL(zp, ZSONET_REG_RX_BUF_WRITE_OFFSET);

  if (!budget) return 0;
  
  while (zp->rx_buffer_position != write_position) {
    work_done += zsonet_read_one(zp);
    if (work_done ==  budget)
      break;
  }

  ZSONET_WRL(zp, ZSONET_REG_RX_BUF_READ_OFFSET, (u32) zp->rx_buffer_position);
  return work_done;
}


static void zsonet_tx_finish(struct zsonet *zp, unsigned int i) {
	unsigned int offset;
	offset = ZSONET_REG_TX_STATUS_0 + i * 4;
	u32 tx_finshed = ZSONET_RDL(zp, offset);
	if (tx_finshed | ZSONET_TX_STATUS_TX_FINISHED)
	{
		zp->buffer_blk_in_use[i] = 0;
	}
}

static irqreturn_t
zsonet_interrupt(int irq, void *dev_instance)
{
	pr_info("MB - zsonet_interrupt");
	struct zsonet *zp;
	unsigned int read_position;
	struct sk_buff *skb;

	//*Receive frame *//
	read_position = zp->rx_buffer_position;
	if (true) {
	  u32 rx_status = ZSONET_RDL(zp, ZSONET_REG_RX_STATUS);
	  for (int i = 0; i < 1; ++i) {
		  skb = zsonet_read_one_without_lock(zp);
		  skb->protocol = eth_type_trans (skb, zp->dev);
		  netif_rx(skb);
	  }
	}
	
	return IRQ_HANDLED;
	/* struct bnx2_napi *bnapi = dev_instance; */
	/* struct bnx2 *bp = bnapi->bp; */
	/* struct status_block *sblk = bnapi->status_blk.msi; */

	/* /\* When using INTx, it is possible for the interrupt to arrive */
	/*  * at the CPU before the status block posted prior to the */
	/*  * interrupt. Reading a register will flush the status block. */
	/*  * When using MSI, the MSI message will always complete after */
	/*  * the status block write. */
	/*  *\/ */
	/* if ((sblk->status_idx == bnapi->last_status_idx) && */
	/*     (BNX2_RD(bp, BNX2_PCICFG_MISC_STATUS) & */
	/*      BNX2_PCICFG_MISC_STATUS_INTA_VALUE)) */
	/* 	return IRQ_NONE; */

	/* BNX2_WR(bp, BNX2_PCICFG_INT_ACK_CMD, */
	/* 	BNX2_PCICFG_INT_ACK_CMD_USE_INT_HC_PARAM | */
	/* 	BNX2_PCICFG_INT_ACK_CMD_MASK_INT); */

	/* /\* Read back to deassert IRQ immediately to avoid too many */
	/*  * spurious interrupts. */
	/*  *\/ */
	/* BNX2_RD(bp, BNX2_PCICFG_INT_ACK_CMD); */

	/* /\* Return here if interrupt is shared and is disabled. *\/ */
	/* if (unlikely(atomic_read(&bp->intr_sem) != 0)) */
	/* 	return IRQ_HANDLED; */

	/* if (napi_schedule_prep(&bnapi->napi)) { */
	/* 	bnapi->last_status_idx = sblk->status_idx; */
	/* 	__napi_schedule(&bnapi->napi); */
	/* } */

	/* return IRQ_HANDLED; */
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
	
	rc = request_irq(irq, zsonet_interrupt, flags, zp->dev->name, &zp);
	if (!rc)
		zp->irq_requested = 1;
	return rc;
}

static void
zsonet_free_irq(struct zsonet *zp)
{
	if (zp->irq_requested) {
		pr_info("MB - zsonet_free_irq");
		free_irq(zp->pdev->irq, &zp->zsonet_napi);
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
	pr_err("MB - zsonet_open - netif_start_queue");
	netif_start_queue(dev);
	
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

static netdev_tx_t
zsonet_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	pr_err("MB - zsonet_start_xmit");
	struct zsonet       *zp;
	/* struct netdev_queue *txq; */
	void *               tx_buf;
	int pos;
	unsigned int         len;
	unsigned int         offset;
	unsigned short       short_len;
	
        zp = netdev_priv(dev);
	pos = zp->buffer_blk_position;
	tx_buf = zp->buffer_blk[pos];
	len = skb->len;
	offset = ZSONET_REG_TX_STATUS_0 + pos * 4 + 2;
	
	if (likely(len < TX_BUFF_SIZE)) {
		if (len < MIN_ETHERNET_PACKET_SIZE) {
			pr_err("MB - zsonet_start_smit - packet smaller than ethernet");
		}
		skb_copy_and_csum_dev(skb, tx_buf);
		dev_kfree_skb_any(skb);
	} else {
		pr_err("MB - zsonet_start_xmit - drop of packet");
	}


	wmb();

	short_len = *(unsigned short*)&len;
	ZSONET_WRW(zp, offset, short_len);
	
	/* Synchronizacja TO DO */
	zp->buffer_blk_position = pos + 1;
	/* Synchronizacja TO DO */

	

	
	return NETDEV_TX_OK;
}



static const struct net_device_ops zsonet_netdev_ops = {
	.ndo_open = zsonet_open,
	.ndo_stop = zsonet_close,
	.ndo_start_xmit = zsonet_start_xmit
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
	if (!dev)
		return -ENOMEM;

	rc = zsonet_init_board(pdev, dev);
	if (rc < 0)
		goto err_free;

	dev->netdev_ops = &zsonet_netdev_ops;
	zp = netdev_priv(dev);

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
	zsonet_free_stats_blk(dev);
	free_netdev(dev);
  return rc;
}

static void
zso_remove_one(struct pci_dev *pdev)
{
	struct net_device *dev = pci_get_drvdata(pdev);
	struct zsonet *zp = netdev_priv(dev);

	unregister_netdev(dev);

	/* del_timer_sync(&bp->timer); */
	/* cancel_work_sync(&bp->reset_task); */

	pr_err("MB - zso_remove_one - iounmap");
	pci_iounmap(pdev, zp->regview);

	/* bnx2_free_stats_blk(dev); */
	/* kfree(bp->temp_stats_blk); */

	/* bnx2_release_firmware(bp); */
	
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
