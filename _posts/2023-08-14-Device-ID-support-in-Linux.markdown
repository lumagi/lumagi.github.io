---
title:  "PCAN Device ID Support in Linux Kernel"
date:   2023-08-14 11:08:00 +0100
categories: [Linux]
tags: [PEAK, PCAN, CAN, udev]
---

When building a test setup with multiple CAN controllers, it is crucial to ensure persistent device names, no matter boot or enumeration order. The PCAN USB-FD devices by Peak do not export a USB serial number, making it difficult to write udev rules to match against them. Instead, the controllers provide a concept called a Device ID. This ID is a 32 bit integer that is stored in the device's flash memory and can be freely set by the user. Notably, a unique ID can be set for each CAN controller, i.e. the ID is not really a device ID but rather a controller ID for devices with multiple controllers. Starting with Linux version 6.3, the kernel now has support for reading & writing the device ID. Additionally, it can be used as a udev match attribute.

# Read & Write Support

The Device ID is called CAN Channel ID in the kernel to reduce the disambiguity mentioned above. It can be read and written with `ethtool`. The byte order is always little endian.

## Reading

Given a PCAN device as can0:
```bash
ethtool -e /sys/class/net/can0
```

## Writing

Given a PCAN device as can0:
```bash
ethtool -E /sys/class/net/can0 <TBA>
```

# udev Support

The kernel exports a custom udev attribute for PCAN CAN controllers:

```bash
ls -l /sys/class/net/can0/peak_usb/can_channel_id
```

The file exports the Device ID attribute as a hex-encoded, little-endian 32 bit integer. The value is read-only, i.e. it can only be set via ethtool. A rule can be written as follows:

```
TBA
```
