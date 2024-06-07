#include "linux/dma-mapping.h"
#include <linux/netdevice.h>
#include <linux/mod_devicetable.h>
#include <linux/etherdevice.h>
#include <linux/pci.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <asm/io.h>

#define DRV_MODULE_NAME "zsonet"
#define PCI_VENDOR_ID_ZSONET 0x0250
#define PCI_DEVICE_ID_ZSONET 0x250e
#define REG_SIZE 256

MODULE_AUTHOR("Mateusz Bodziony <mb394086>");
MODULE_DESCRIPTION("Zsonet Driver");
MODULE_LICENSE("GPL");

static const struct pci_device_id zsonet_pci_tbl[] = {
	{PCI_VENDOR_ID_ZSONET, PCI_DEVICE_ID_ZSONET,
	 PCI_ANY_ID, PCI_ANY_ID, 0, 0}
};

struct zsonet {
	void __iomem		*regview;
	void			*buffer_blk[4];
	dma_addr_t		buffer_blk_mapping[4];
	u8			mac_addr[8];
	int x;
	int y;
};

static void zsonet_free_stats_blk(struct net_device *dev) {}

/* static int zsonet_allocate_buffer_blk(struct net_device *dev) { */
  
/* }; */

static int
zsonet_open(struct net_device *dev)
{
	pr_info("Zsonet Open");
	return 0;
}

static int
zsonet_close(struct net_device *dev)
{
	/* struct zsonet *zp = netdev_priv(dev); */

	/* bnx2_disable_int_sync(bp); */
	/* bnx2_napi_disable(bp); */
	/* netif_tx_disable(dev); */
	/* del_timer_sync(&bp->timer); */
	/* zsonet_shutdown_chip(bp); */
	/* bnx2_free_irq(bp); */
	/* bnx2_free_skbs(bp); */
	/* bnx2_free_mem(bp); */
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
	for (int i = 0, offset = 0; i < 6; ++i, offset += sizeof(u8)) {
		zp->mac_addr[i] = readb(zp->regview + offset);
		pr_err("MB - zsonet_set_mac i: %d, mac_addr: %d", i, (int) zp->mac_addr[i]);
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
	
	pr_err("MB - zsonet_init_board - iomap");
	zp->regview = pci_iomap(pdev, 0, REG_SIZE);
	if (!zp->regview) {
		dev_err(&pdev->dev, "Cannot map register space, aborting\n");
		rc = -ENOMEM;
		goto err_out_release;
	}


	pr_err("MB - zsonet_init_board - dma_set_mask 64");
	if (dma_set_mask(&pdev->dev, DMA_BIT_MASK(64)) != 0) {
		pr_err("MB - zsonet_init_board - dma_set_mask 32");
	} else if ((rc = dma_set_mask(&pdev->dev, DMA_BIT_MASK(32))) != 0) {
		dev_err(&pdev->dev, "System does not support DMA, aborting\n");
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

	pr_err("MB - z");
	
	pci_set_drvdata(pdev, dev);

	rc = -ENOMEM;
	goto error;
	/* eth_hw_addr_set(dev, zp->mac_addr); */

	/* if ((rc = register_netdev(dev))) { */
	/* 	dev_err(&pdev->dev, "Cannot register net device\n"); */
	/* 	goto error; */
	/* } */
  
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
