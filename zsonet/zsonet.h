#ifndef ZSONET_H
#define ZSONET_H

/* Section 1: PCI ids */

#define ZSONET_VENDOR_ID 0x0250
#define ZSONET_DEVICE_ID 0x250e

/* Section 2: MMIO registers */

enum zsonet_registers {
    ZSONET_REG_MAC_0 = 0x00,
    ZSONET_REG_MAC_1 = 0x01,
    ZSONET_REG_MAC_2 = 0x02,
    ZSONET_REG_MAC_3 = 0x03,
    ZSONET_REG_MAC_4 = 0x04,
    ZSONET_REG_MAC_5 = 0x05,
    ZSONET_REG_TX_STATUS_0 = 0x10,
    ZSONET_REG_TX_STATUS_1 = 0x14,
    ZSONET_REG_TX_STATUS_2 = 0x18,
    ZSONET_REG_TX_STATUS_3 = 0x1c,
    ZSONET_REG_TX_BUF_0 = 0x20,
    ZSONET_REG_TX_BUF_1 = 0x24,
    ZSONET_REG_TX_BUF_2 = 0x28,
    ZSONET_REG_TX_BUF_3 = 0x2c,
    ZSONET_REG_RX_BUF = 0x30,
    ZSONET_REG_RX_BUF_SIZE = 0x34,
    ZSONET_REG_RX_BUF_READ_OFFSET = 0x38,
    ZSONET_REG_RX_BUF_WRITE_OFFSET = 0x3c,
    ZSONET_REG_RX_STATUS = 0x40,
    ZSONET_REG_RX_MISSED = 0x44,
    ZSONET_REG_INTR_MASK = 0x50,
    ZSONET_REG_INTR_STATUS = 0x54,
    ZSONET_REG_ENABLED = 0x60,
};

enum zsonet_intr {
    ZSONET_INTR_RX_OK = 0x01,
    ZSONET_INTR_TX_OK = 0x02,
};

enum zsonet_rx_status {
    ZSONET_RX_STATUS_RX_HAS_DATA = 0x01,
};

enum zsonet_tx_status {
    ZSONET_TX_STATUS_TX_FINISHED = 0x01,
};

#define ZSONET_BAR_SIZE 0x100

#endif // ZSONET_H
