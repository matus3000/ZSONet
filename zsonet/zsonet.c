#include <linux/netdevice.h>
#include <linux/mod_devicetable.h>
#include <linux/etherdevice.h>
#include <linux/pci.h>
#include <linux/module.h>
#include <linux/printk.h>


#define DRV_MODULE_NAME "zsonet"
#define PCI_VENDOR_ID_ZSONET 0x0250
#define PCI_DEVICE_ID_ZSONET 0x250e

MODULE_AUTHOR("Mateusz Bodziony <mb394086>");
MODULE_DESCRIPTION("Zsonet Driver");
MODULE_LICENSE("GPL");

static const struct pci_device_id zsonet_pci_tbl[] = {
	{PCI_VENDOR_ID_ZSONET, PCI_DEVICE_ID_ZSONET,
	 PCI_ANY_ID, PCI_ANY_ID, 0, 0}
};

struct zsonet {
  int x;
  int y;
};

static void
zsonet_free_stats_blk(struct net_device *dev)
{
  
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

  pr_err("MB - zso_init_one");
  rc = -ENOMEM;
  goto err_free;
  
  return 0;

err_free:
  zsonet_free_stats_blk(dev);
  free_netdev(dev);
  return rc;
}

static void
zso_remove_one(struct pci_dev *pdev)
{

}

static struct pci_driver zsonet_pci_driver = {
  .name = DRV_MODULE_NAME,
  .id_table = zsonet_pci_tbl,
  .probe = zso_init_one,
  .shutdown = zso_remove_one
};

module_pci_driver(zsonet_pci_driver);
