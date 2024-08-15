---
layout: post
category: "deprecated"
---


## Continue the whole Story

In the last post, we learn the kernel side details of ths amazing challenge *Secure Storage*. In this post, I will try my best to understand the QEMU device implementation.

You may wonder why this is necessary. In fact, I believe learning how this device organizes the MMIO registers and how this device raise interrupts will help a kernel researcher to better understand the programming of the device driver.

Okay, let's roll.

## SS QEMU device

The author has released the source code of this QEMU device in his [repo](https://github.com/hzqmwne/my-ctf-challenges/blob/master/0CTF_TCTF-2021-Quals/Secure%20Storage/src/ss_device.c). 

Because I am not a QEMU pwner (in fact I don't recognize myself as an eligible pwner as most of my time is spent on reversing challenge T.T), I don't think it is easy to reverse the binary `qemu-system-x86_64` and let's read the source code instead.

### add custom PCI device

Different from the userland agent and kernel module, the open-sourced device code is not covered in the given `Makefile` hence I have no idea how this part of the code gets integrated into the complete QEMU executable.

Luckily, there are many great articles introducing how to add a customized device to QEMU.
- [QEMU internal](https://dangokyo.me/2018/03/28/qemu-internal-pci-device/) from 氷菓; It involves a KITCTF challenge.
- [How to add a new device in QEMU source code](https://stackoverflow.com/questions/28315265/how-to-add-a-new-device-in-qemu-source-code) in stackoverflow, the answer provides great driver + device educational resoruce.
- [A deep dive into QEMU: adding devices](https://airbus-seclab.github.io/qemu_blog/devices.html)
- [How to Design a Prototype Device](https://milokim.gitbooks.io/lbb/content/qemu-how-to-design-a-prototype-device.html)
- [Writing a custom device for QEMU](https://sebastienbourdelin.com/2021/06/16/writing-a-custom-device-for-qemu/). Pictures are great, highly recommended.

Reading through this, you can get below important notes:

1. Edit necessary `Kconfig` and `meson.build` to add customized device into config.
2. `memory_region_init_io` is used to allocate memory region
2. `pci_register_bar` assign the allocated MemoryRegion to the PCI device.
3. `msi_notify` is the helper to raise interrupt

With all these pieces and our accumulated knowledge in host side, we can now learn the internal of this QEMU device.

### register the device

```c++
// -------------------------------------

static void ss_instance_init(Object *obj) {
	SSState *ss = SS(obj);

	BackendStorageType *storage = &ss->storage;
	storage->reset_func = storage_reset;
	storage->read_func = storage_read;
	storage->write_func = storage_write;
}

static void ss_class_init(ObjectClass *class, void *data) {
	DeviceClass *dc = DEVICE_CLASS(class);
	PCIDeviceClass *k = PCI_DEVICE_CLASS(class);
	k->realize = pci_ss_realize;
	k->exit = pci_ss_uninit;
	k->vendor_id = PCI_VENDOR_ID_QEMU;
	k->device_id = SS_DEVICE_ID;
	k->revision = 0x73;
	k->class_id = PCI_CLASS_OTHERS;
	set_bit(DEVICE_CATEGORY_MISC, dc->categories);
}

// -------------------------------------

static void pci_ss_register_types(void) {
	static InterfaceInfo interfaces[] = {
		{ INTERFACE_CONVENTIONAL_PCI_DEVICE },
		{ },
	};

	static const TypeInfo ss_info = {
		.name = TYPE_PCI_SS_DEVICE,
		.parent = TYPE_PCI_DEVICE,
		.instance_size = sizeof(SSState),
		.instance_init = ss_instance_init,
		.class_init = ss_class_init,
		.interfaces = interfaces,
	};

	type_register_static(&ss_info);
}

type_init(pci_ss_register_types)
```

There are tons of macro and helper. In short, it defines `interfaces` and `ss_info` in the `init` function. The `ss_instance_init` function and `ss_class_init` function must be called in initialization stage.

When executing `ss_intance_init`, three function pointers: `storage_reset/read/write` are assigned to fields in `storage` object.

The function `pci_ss_realize` is assigned to `k->realize` field in class initialization.
> Other fields like `exit`, `vendor_id` and `device_id` are also assigned here. These IDs are just same as the value defined in kernel module.

### device realize

```c++
typedef struct BackendStorageType_ BackendStorageType;
struct BackendStorageType_ {
	__attribute__((aligned(SS_DEVICE_BLOCK_SIZE))) unsigned char blocks[SS_DEVICE_BLOCK_COUNT][SS_DEVICE_BLOCK_SIZE];
	void (*reset_func)(BackendStorageType *bs);
	void (*read_func)(BackendStorageType *bs, unsigned int blocknum, void *buf);
	void (*write_func)(BackendStorageType *bs, unsigned int blocknum, const void *buf);
};

typedef struct {
	PCIDevice pdev;
	MemoryRegion mmio;

	QemuMutex status_mutex;
	uint64_t status;

	struct dma_state {
		uint64_t subcmd;
		uint64_t blocknum;
		dma_addr_t paddr;
	} dma;
	QEMUTimer dma_timer;

	BackendStorageType storage;
} SSState;

static void pci_ss_realize(PCIDevice *pdev, Error **errp) {
	SSState *ss = SS(pdev);
	uint8_t *pci_conf = pdev->config;
	BackendStorageType *storage = &ss->storage;

	storage->reset_func(storage);

	pci_config_set_interrupt_pin(pci_conf, 1);
	if (msi_init(pdev, 0, 1, true, false, errp)) {
		return;
	}

	qemu_mutex_init(&ss->status_mutex);
	timer_init_ms(&ss->dma_timer, QEMU_CLOCK_VIRTUAL, ss_dma_timer, ss);

	memory_region_init_io(&ss->mmio, OBJECT(ss), &ss_mmio_ops, ss, "ss-mmio", 1 * MiB);
	pci_register_bar(pdev, 0, PCI_BASE_ADDRESS_SPACE_MEMORY, &ss->mmio);

}
```

It fulfills several tasks.
1. It instantiates the `SSState` object.
2. Calls `reset_func` of backend storage. This will encrypt every blocks.
3. Init timer for follwing DMA handling
4. Allocate MMIO and register the handler, assign to PCI device.

### MMIO handler

```c++
static const MemoryRegionOps ss_mmio_ops = {
	.read = ss_mmio_read,
	.write = ss_mmio_write,
	.endianness = DEVICE_NATIVE_ENDIAN,
		.valid = {
		.min_access_size = 4,
		.max_access_size = 8,
	},
	.impl = {
		.min_access_size = 4,
		.max_access_size = 8,
	},
};
```

The defination covers `read`, `write`, `endianness` and `impl`.

For read handler:

```c++

static uint64_t ss_mmio_read(void *opaque, hwaddr addr, unsigned int size) {
	SSState *ss = (SSState *)opaque;
	uint64_t val = ~0ULL;

	if (size != 8) {
		return val;
	}

	switch (addr) {
		case SS_MMIO_OFFSET_MAGIC:    // magic const
			val = 0x3132303246544330;
			break;
		case SS_MMIO_OFFSET_STATUS:    // device status
			val = ss->status;
			break;
		case SS_MMIO_OFFSET_DMA_BLOCKNUM:    // dma block number
			val = ss->dma.blocknum;
			break;
		case SS_MMIO_OFFSET_DMA_PHYADDR:    // dma physical address
			val = ss->dma.paddr;
			break;
	}

	return val;
}
```

We can easily tell there are four MMIO registers: `MAGIC`, `STATU`, `DMA_BLOCKNUM` and `DMA_PHYADDR`.

For write handler, very similar
```c++
static void ss_mmio_write(void *opaque, hwaddr addr, uint64_t val, unsigned int size) {
	SSState *ss = (SSState *)opaque;

	if (size != 8) {
		return;
	}

	switch (addr) {
		case SS_MMIO_OFFSET_COMMAND:    // command
			ss_handle_cmd(ss, val);
			break;
		case SS_MMIO_OFFSET_DMA_BLOCKNUM:    // dma block number
		case SS_MMIO_OFFSET_DMA_PHYADDR:    // dma physical address
			ss_handle_write_dma_state(ss, addr, val);
			break;
	}
}
```
We can find familar `SS_MMIO_OFFSET_COMMAND` and relevant `ss_handle_cmd` function. Besides, the `ss_handle_write_dma_state` when `blocknum` or `phyaddr` is written.

The command handler is the driver of the device state machine.

```c++
static void ss_handle_cmd(SSState *ss, uint64_t cmd) {
	
	qemu_mutex_lock(&ss->status_mutex);    // to protect status change

	uint64_t main_status = ss->status & SS_STATUS_MASK;
	uint64_t main_cmd = cmd & SS_CMD_MASK;
	uint64_t sub_cmd = cmd & SS_SUBCMD_MASK;


	switch (main_cmd) {
		case SS_CMD_TO_NORMAL:
			if (main_status == SS_STATUS_BUSY) {
				break;
			}
			ss->status = SS_STATUS_NORMAL;
			break;
		case SS_CMD_PREPARE_DMA:

			if (main_status != SS_STATUS_NORMAL) {
				break;
			}
			ss->status = SS_STATUS_DMA_PREPARE;

			break;
		case SS_CMD_START_DMA:
			if (main_status != SS_STATUS_DMA_PREPARE) {
				break;
			}
			ss->status = SS_STATUS_BUSY;
			ss->dma.subcmd = sub_cmd;

			timer_mod(&ss->dma_timer, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + 5);
			break;
	}
	
	qemu_mutex_unlock(&ss->status_mutex);
}
```
The command `SS_CMD_TO_NORMAL` and `SS_CMD_PREPARE_DMA` just switch states. The `SS_CMD_START_DMA` will issue the delayed timer. (This intended delay is used in side-channel attack.)

### DMA handling

The DMA handler is acted by the timer.

```c++
static void ss_dma_timer(void *opaque) {
	SSState *ss = (SSState *)opaque;
	unsigned char buf[SS_DEVICE_BLOCK_SIZE] = {0};
	BackendStorageType *storage = &ss->storage;
	uint64_t subcmd = ss->dma.subcmd;    // prevent TOCTTOU
	uint64_t blocknum = ss->dma.blocknum;
	uint64_t paddr = ss->dma.paddr;
	uint64_t new_status;

	// do check
	if (!(subcmd == SS_SUBCMD_START_DMA_TO_DEVICE || subcmd == SS_SUBCMD_START_DMA_FROM_DEVICE)
			|| !(blocknum <= SS_DEVICE_BLOCK_COUNT)) {    // XXX: vuln! here should be "<", should not be "<="
		new_status = SS_STATUS_DMA_COMPLETE | SS_SUBSTATUS_DMA_COMPLETE_ERROR;
		// error
		goto finish;
	}

	// do dma
	if (subcmd == SS_SUBCMD_START_DMA_TO_DEVICE) {    // device get data from memory
		pci_dma_read(PCI_DEVICE(ss), paddr, buf, SS_DEVICE_BLOCK_SIZE);    // only allow read/write one block once
		storage->write_func(storage, blocknum, buf);
	}
	else if(subcmd == SS_SUBCMD_START_DMA_FROM_DEVICE) {    // device store data into memory
		storage->read_func(storage, blocknum, buf);
		pci_dma_write(PCI_DEVICE(ss), paddr, buf, SS_DEVICE_BLOCK_SIZE);
		//cpu_physical_memory_write(paddr, buf, SS_DEVICE_BLOCK_SIZE);
	}
	new_status = SS_STATUS_DMA_COMPLETE | SS_SUBSTATUS_DMA_COMPLETE_SUCCESS;

finish:
	// raise irq and update status
	qemu_mutex_lock(&ss->status_mutex);    // to protect status change
	ss->status = new_status;
	qemu_mutex_unlock(&ss->status_mutex);
	msi_notify(PCI_DEVICE(ss), 0);    // still raise irq, even error occurs
}
```

The original command mask with `SS_SUBCMD_MASK` is the DMA direction. The acutal interaction between device and kernel is hide in `pci_dma_read` and `pci_dma_write`.

After the `read` or `write` is finished, this device uses `msi_notify` to raise the interrupt.

## Summary

After looking after the host side kernel part, the understanding of the device part is rather straightforward actually. Well, it's easier said than done. I believe I will be suffered when I have to come up with a challenge that involves a "real" hardware device instead of a fake module.