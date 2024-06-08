#include "linux/interrupt.h"
#include "linux/irqreturn.h"
#include "linux/types.h"
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
	void                    *rx_buffer;
	dma_addr_t              rx_buffer_mapping;
	u8			mac_addr[8];
	u8                      irq_requested;
	struct zsonet_napi      zsonet_napi;
	int x;
	int y;
};

static void zsonet_setup_buffers(struct zsonet *zp) {
	unsigned int dev_addr;
	unsigned short buff_size;
	
	for (int i = 0, offset = ZSONET_REG_TX_BUF_0; i < 4; ++i, offset += 4) {
		unsigned int val = *(unsigned int*) &zp->buffer_blk_mapping[i];
		ZSONET_WRL(zp, offset, val);
		ZSONET_WRW(zp, ZSONET_REG_TX_STATUS_0 + i * 4 + 2, TX_BUFF_SIZE);
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

static irqreturn_t
zsonet_interrupt(int irq, void *dev_instance)
{
	pr_info("MB - zsonet_interrupt");
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
	
	rc = request_irq(irq, zsonet_interrupt, flags, zp->dev->name, &zp->zsonet_napi);
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


	netif_carrier_off(dev);

	zsonet_init_napi(zp);
	zsonet_napi_enable(zp);
	
	rc = zsonet_alloc_mem(zp);
	if (rc)
		goto open_err;

	rc = zsonet_request_irq(zp);
	if (rc)
		goto open_err;

	zsonet_prepare_device(zp);

	netif_start_queue(dev);
	
	return 0;
open_err:
	zsonet_free_irq(zp);
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
	zsonet_free_irq(zp);
	/* bnx2_free_skbs(bp); */
	zsonet_free_mem(zp);
	/* bnx2_del_napi(bp); */
	/* bp->link_up = 0; */
	/* netif_carrier_off(bp->dev); */
	return 0;
}


static const struct net_device_ops zsonet_netdev_ops = {
	.ndo_open = zsonet_open,
	.ndo_stop = zsonet_close
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
