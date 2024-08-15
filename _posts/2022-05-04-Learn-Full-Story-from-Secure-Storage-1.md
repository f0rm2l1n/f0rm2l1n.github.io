---
layout: post
category: "deprecated"
---

## 注

现在回来看，这个内容（包括第二部分）应该丢错题本里比较合适。

## Before the whole Story

The **Secure Storage** challenge is a marvelous amazing full CTF challenge presented in 0CTF/TCTF 2021 competitions. Its intended solution requires the player to
1. find the vulnerability in user land program and gain permission shell
2. find the vulnerability in kernel module and gain root privilege
3. find the vulnerability in the qemu device and escape from it

This challenge makes me understand that the dumb misc drivers are of no sense in the actual world. Hence, after the long pending period, I think there should be some blogs help to learn the full story of this challenge.

Of course, I have no intention to write a complete writeup for this one, there are already wonderful [one](https://mem2019.github.io/jekyll/update/2021/07/06/TCTF2021-Secure-Storage.html) from r3kpig team and the [one](https://github.com/hzqmwne/my-ctf-challenges/tree/master/0CTF_TCTF-2021-Quals/Secure%20Storage) from the author himself.

In another word, I want to learn the internal, the trivials in this challenge, aka, the whole story. There are two posts for fulfilling this expectation: one describing the kernel part and the other describing the device part.

Cool, let's hit the ground.

## SS kernel module

The assigned challenge contains only built binary, of course. As we here focus on learning the knowledge, targetting on source code is a better choice.

In short, the ss driver is a PCI device driver which exposes functionality to user-space through misc interface and mmap memory region. We will learn its code in following parts.

To keep the pace, some pre-knowledge of PCI subsystem is necessary
- Linux Device Drivers, Third Edition. CH12. PCI Drivers
- Kernel Documentation, ["How To Write Linux PCI Drivers"](https://www.kernel.org/doc/Documentation/PCI/pci.txt)

### driver initialization

The author is very expertise to provide different MACRO options: as you can see, even a misc char-based simulation. This is cool as the author can test the module without programming the QEMU device first.

```c++
#define QEMU_VENDOR_ID 0x1234
#define SS_DEVICE_ID 0x7373

// ...

static struct pci_device_id pci_ids[] = {
	{ PCI_DEVICE(QEMU_VENDOR_ID, SS_DEVICE_ID), },
	{ 0, }
};
MODULE_DEVICE_TABLE(pci, pci_ids);

static struct pci_driver pci_drv = {
	.name = DEVICE_NAME,    // this cannot be omitted !
	.id_table = pci_ids,
	.probe    = pci_probe,
	.remove   = pci_remove,
};

// ...

static int __init init_ss_module(void) {
	// major_version = register_chrdev(0, DEVICE_NAME, &fops);
	unsigned int i;
	
	for (i = 0; i < STORAGE_SLOT_COUNT; i++) {
		mutex_init(&storage_slot_lock[i]);

	}
#if SIMULATION
	zerostorage();
	misc_register(&miscdev);
#else
	if (pci_register_driver(&pci_drv) < 0) {
#ifdef DEBUG
		printk(KERN_ERR "pci_register_driver error\n");
#endif
		return 1;
	}
#endif

#ifdef DEBUG
	printk(KERN_ALERT "secure storage module init\n");
#endif
	return 0;
}
```

We here pay our attention to the real case: `pci_register_driver`.
The code above uses `PCI_DEVICE` macro to creates specific `pci_device_id` structure that matches only the `QEMU_VENDOR_ID` and customized `SS_DEVICE_ID`. And the `MODULE_DEVICE_TABLE` is used to export the created `pci_device_id` structure to user space. (to allow hotplug...)

### driver probe

The function `pci_probe` is the called by the PCI core when it has a `struct pci_dev` that is thinks this driver wants to control.

```c++
static int pci_probe(struct pci_dev *dev, const struct pci_device_id *id) {
	int r;
	// create device file at /dev
	misc_register(&miscdev);

	// enable device and map mmio
	r = pci_enable_device(dev);
	if (r < 0) {
		goto error;
	}
	r = pci_request_region(dev, SS_PCI_BAR_MMIO, "ss-mmio");
	if (r != 0) {
		goto error;
	}

	ss_mmio = pci_iomap(dev, SS_PCI_BAR_MMIO, pci_resource_len(dev, SS_PCI_BAR_MMIO));
	if (ss_mmio == NULL) {
		goto error;
	}
	ss_pdev = dev;

	// dma
	pci_set_master(dev);    // important ! must do this to enable dma

	// msi irq
	// https://www.kernel.org/doc/html/latest/PCI/msi-howto.html
	r = pci_alloc_irq_vectors(dev, 1, 1, PCI_IRQ_MSI);
	if (r < 0) {
		goto error;	
	}

	r = request_irq(pci_irq_vector(dev, 0), irq_handler_0, 0, DEVICE_NAME, NULL);
	if (r != 0) {
		goto error;
	}

	// now initialize finished, set device status to normal
	writeq(SS_CMD_TO_NORMAL, ss_mmio + SS_MMIO_OFFSET_COMMAND);
	device_is_idle = true;
	device_irq_occured = false;

	return 0;

error:
	return 1;
}
```

This function finish several tasks:
1. It register misc interface to user land by `misc_register`. This is very common in lots of CTF challenges.
2. It calls `pci_enable_device`. This is necessary for initializing a pci device (wake up the device if it was in suspended state and allocate resources).
3. It calls `pci_request_region` to request and verify the MMIO.

Attention, different from the general helper `request_mem_region`. The `pci_request_region` adopts what people know as PCI BARs.

> To address a PCI device, it must be enabled by being mapped into the system's I/O port address space or memory-mapped address space. The system's firmware (e.g. BIOS) or the operating system program the **Base Address Registers (commonly called BARs)** to inform the device of its resources configuration by writing configuration commands to the PCI controller.
> Each non-bridge PCI device function can implement up to 6 BARs, each of which can respond to different addresses in I/O port and memory-mapped address space. Each BAR **describes a region that is between 16 bytes and 2 gigabytes** in size, located below 4 gigabyte address space limit. If a platform supports the "Above 4G" option in system firmware, 64 bit BARs can be used.

In short, this call of `pci_request_region` marks the PCI region associated with given PCI device + bar being reserved.

4. It calls `pci_iomap`. This create a virtual mapping cookie for a PCI Bar and return the __iomem address to the device BAR.
5. It calls `pci_set_master`. This will enable DMA by setting the bus master bit in the PCI_COMMAND register.
6. It calls `pci_alloc_irq_vectors`. It's recommended refer to the commented link to know that this call will enable MSI capability. Specifically, the code above allocates up 1 interrupt vector for the device.
7. To call `request_irq`, the code calls `pci_irq_vector` to get the IRQ numbers. It intends to bind function `irq_handler_0` to index 0 interrupt.
8. It finally uses `writeq` to write command `SS_CMD_TO_NORMAL` to the device `COMMAND` register.

After all of this, the device is set. Since the PCI core offers great abstraction, the preparation steps are easy to program.

### interrupt handler

The interrupt is how the ss device tells kernel something is happening, and we here take a peek.

```c++
static irqreturn_t irq_handler_0(int irq, void *dev_id) {
#ifdef DEBUG
	printk(KERN_INFO "(irq_handler):  Called\n");
#endif
	device_irq_occured = true;
	wake_up(&wait_for_interrupt);
	return IRQ_HANDLED;
}
```

Actually this handler does nothing seriously: it just write state variable `device_irq_occured` and wake up another thread by `wake_up(&wait_for_interrupt);`.
We can possibly guess the running logic: the host assign some tasks to the device and waits for the finishments. Once the device finishes the task, it adopts the interrupt to tell the host. (we will talk about it later in DMA area)

### device interactions

According to the userland agent, we know the driver offers `ioctl` and `mmap` functions to user program. Before these two, we need to know what will happen when open the interface flip.

```c++
struct storage_slot_info {
	unsigned long slot_index;
	spinlock_t slot_index_lock;
};

static int dev_open(struct inode *inodep, struct file *filep) {
	struct storage_slot_info *info;
	info = (struct storage_slot_info *)kzalloc(sizeof(struct storage_slot_info), GFP_KERNEL);
	if (info == NULL) {
		return -ENOMEM;
	}
	info->slot_index = -1;
	spin_lock_init(&info->slot_index_lock);
	filep->private_data = info;

	return 0;
}
```

Hopefully, the `open` is quite simple.

```c++
#define STORAGE_SLOT_COUNT (16)
static unsigned int storage_slot_reference_count[STORAGE_SLOT_COUNT];
static struct mutex storage_slot_lock[STORAGE_SLOT_COUNT];
// ...
static long dev_ioctl(struct file *filep, unsigned int request, unsigned long data) {
	unsigned long slot_index;
	unsigned long old_slot_index;
	struct storage_slot_info *info;
	switch (request) {    // ioctl request should have special format. here just ignore it
		//case 0x73706f30:
		case 0:    // TODO change the const
			slot_index = data;
			if (slot_index >= STORAGE_SLOT_COUNT) {
				return -EINVAL;
			}

			info = (struct storage_slot_info *)filep->private_data;
			
			mutex_lock(&storage_slot_lock[slot_index]);
			spin_lock(&info->slot_index_lock);

			old_slot_index = info->slot_index;
			if (old_slot_index != -1) {
				spin_unlock(&info->slot_index_lock);
				mutex_unlock(&storage_slot_lock[slot_index]);
				return -EINVAL;
			}

			if (storage_slot_reference_count[slot_index] == 0xffffffff) {
				spin_unlock(&info->slot_index_lock);
				mutex_unlock(&storage_slot_lock[slot_index]);
				return -EPERM;
			}

			storage_slot_reference_count[slot_index] += 1;
			info->slot_index = slot_index;
			
			spin_unlock(&info->slot_index_lock);
			mutex_unlock(&storage_slot_lock[slot_index]);

			break;
		default:
			return -EINVAL;

	}
	return 0;
}
```

The `ioctl` offers only one command: increase the reference count in array `storage_slot_reference_count`. Hence, let's take a look at `mmap`

```c++
#define STORAGE_SLOT_SIZE (16*PAGE_SIZE)

static struct vm_operations_struct dev_mmap_vm_ops = {
	//.open = vma_open,
	//.close = vma_close,
	.fault = vma_fault,
};

static int dev_mmap(struct file *filep, struct vm_area_struct *vma) {
	struct storage_slot_info *info;

	info = (struct storage_slot_info *)filep->private_data;
	spin_lock(&info->slot_index_lock);
	if (info->slot_index == -1) {
		spin_unlock(&info->slot_index_lock);
		return -EPERM;
	}
	spin_unlock(&info->slot_index_lock);

	if (vma->vm_pgoff >= (STORAGE_SLOT_SIZE / PAGE_SIZE)) {    // unsigned long
		return -EINVAL;
	}
	vma->vm_ops = &dev_mmap_vm_ops;
	return 0;
}
```

Again, the code login is rather simple: it just replaces `vma->vm_ops` to allow the function `vma_fault` being called when the device memory is accessed.

The bounday calculation here tells us that the device memory is 16 * 4096 bytes large.

Once this `mmap` is done, the user land agent can dereference the maped address, awaking the fault function.

```c++
static vm_fault_t vma_fault(struct vm_fault *vmf) {
	int offset;    // XXX vuln, offset should be unsigned
	struct page *page;
	struct vm_area_struct *vma;
	struct file *file;
	struct storage_slot_info *info;
    unsigned long slot_index;
    int bitmap_index;    // it should also better be unsigned

	vma = vmf->vma;
	file = vma->vm_file;
	info = (struct storage_slot_info *)file->private_data;
	slot_index = info->slot_index;    // no need to lock here
	offset = ((vmf->address - vma->vm_start) & PAGE_MASK) + (vma->vm_pgoff << PAGE_SHIFT);

	if (offset < (int)STORAGE_SLOT_SIZE) {
        // XXX vuln, because offset is signed int, it can less than zero
		page = vmalloc_to_page(&storage_cache[slot_index][offset]);
		get_page(page);
	}
	else {
		return VM_FAULT_SIGBUS;
	}
	vmf->page = page;

	// prepare data
	mutex_lock(&storage_slot_lock[slot_index]);
	bitmap_index = slot_index * (STORAGE_SLOT_SIZE/PAGE_SIZE) + offset/PAGE_SIZE;
	if (!BITMAP_TEST(storage_cache_page_dirty_bitmap, bitmap_index)) {
		// here, assert PAGE_SIZE == DEVICE_BLOCK_SIZE !!
		if (readblock(bitmap_index, &storage_cache[slot_index][offset]) != 0) {
			mutex_unlock(&storage_slot_lock[slot_index]);
			return VM_FAULT_SIGBUS;
		}
		BITMAP_SET(storage_cache_page_dirty_bitmap, bitmap_index);
	}
	mutex_unlock(&storage_slot_lock[slot_index]);

	return 0;
}
```

Let's ignore the integer overflow bug occurs here. This part of code calculates the address offset in device memory and then fetch the page pointer using `vmalloc_to_page`.

> Attention here, since the module memory is allocated through `vmalloc`, here we must use `vmalloc_to_page` instead of `virt_to_page`. As the address `&storage_cache[slot_index][offset]` is not kernel logic address. Moreover, preparing such a big cache memory is somewhat expensive, but efficient.

After the `page` is setteled, It tries to read data from the device through `readblock`. Before that, it checks the bitmap to make sure this position contains no dirty data (never used before).

```c++
static int readblock(unsigned long blocknum, void *buf) {
	return readwriteblock(blocknum, buf, false);
}

static int writeblock(unsigned long blocknum, void *buf) {
	return readwriteblock(blocknum, buf, true);
}
```

The `readblock` and `writeblock` both uses helper function `readwriteblock`, which is a big one.

```c++
static int readwriteblock(unsigned long blocknum, void *buf, bool iswrite) {
	int result = 0;
	u64 r_status;
	dma_addr_t daddr;
	void *pdaddr;
	int ret;

	// only one process can use the device at same time
	do {
		ret = wait_event_interruptible(wait_for_device_idle, device_is_idle);
	} while (!__atomic_exchange_n(&device_is_idle, false, __ATOMIC_RELAXED));

	if (ret < 0) {    // -ERESTARTSYS
		device_is_idle = true;
		wake_up_interruptible(&wait_for_device_idle);
		result = ret;
		goto finish;
	}
	if (readq(ss_mmio + SS_MMIO_OFFSET_STATUS) != SS_STATUS_NORMAL) {
		device_is_idle = true;
		wake_up_interruptible(&wait_for_device_idle);
		result = 1;
		goto finish;		
	}

	writeq(SS_CMD_PREPARE_DMA, ss_mmio + SS_MMIO_OFFSET_COMMAND);

	pdaddr = dma_alloc_coherent(&(ss_pdev->dev), DEVICE_BLOCK_SIZE, &daddr, GFP_KERNEL);
	if (pdaddr == NULL) {
		result = 0;
		goto finish;
	}
	if (iswrite) {
		memcpy(pdaddr, buf, DEVICE_BLOCK_SIZE);
	}
	writeq(blocknum, ss_mmio + SS_MMIO_OFFSET_DMA_BLOCKNUM);
	writeq(daddr, ss_mmio + SS_MMIO_OFFSET_DMA_PHYADDR);
	writeq(SS_CMD_START_DMA|(iswrite ? SS_SUBCMD_START_DMA_TO_DEVICE : SS_SUBCMD_START_DMA_FROM_DEVICE), ss_mmio + SS_MMIO_OFFSET_COMMAND);

	device_irq_occured = false;
	wait_event(wait_for_interrupt, device_irq_occured);

	while (1) {
		r_status = readq(ss_mmio + SS_MMIO_OFFSET_STATUS);
		if ((r_status & SS_STATUS_MASK) == SS_STATUS_DMA_COMPLETE) {
			break;
		}
	}
	
	writeq(SS_CMD_TO_NORMAL, ss_mmio + SS_MMIO_OFFSET_COMMAND);
	device_is_idle = true;
	wake_up_interruptible(&wait_for_device_idle);    // wake up extract one waiting proeess

	if ((r_status & SS_SUBSTATUS_MASK) == SS_SUBSTATUS_DMA_COMPLETE_SUCCESS) {
		if (!iswrite) {
			memcpy(buf, pdaddr, DEVICE_BLOCK_SIZE);
		}
		result = 0;
	}
	else {
		result = 1;
	}
	
	dma_free_coherent(&(ss_pdev->dev), DEVICE_BLOCK_SIZE, pdaddr, daddr);

finish:
	return result;
}
```

The entire workflow can be concluded as below:
1. Adopt atomic variable as signal to avoid the re-entrancy.

Because `wait_event_interruptible(wait_for_device_idle, device_is_idle)` will wait until the atomic condition `device_is_idle` is set to true. The following `__atomic_exchange_n` will allow only one routine leave the wait loop. 

If the `ret < 0`, which means the wait loop is interrupted, the routine just wakeup other looping routine and leave.

Otherwise the routine will check the device register at `SS_MMIO_OFFSET_STATUS` to make sure the device is in `SS_STATUS_NORMAL` state.

After all these are checked, the routine enters into next step.

2. Prepare DMA

The function first write commmand `SS_CMD_PREPARE_DMA` to tell the device to be prepared. Then it calls `dma_alloc_coherent` to setup DMA mapping. The returned `pdaddr` is the host side virtual address and the `daddr` is the DMA address belonging to device.

If `iswrite` is true, this functino will copy the content to the host address first.

Therefore, this function setup the DMA on device side by writing necessary arguments (block number, DMA address and start DMA command) to device registers.

After all of these, it sleeps to wait the interrupt from device, which is analyzed above. The interrupt based DMA action is quite common in device driver code.

Once the interrupt wake up this routine, it continues to handle remain tasks.

3. Close out works

If `iswrite` is false, which means the device transit data through DMA to `pdaddr`, this function will copy the content to in-memory cache.

Before return, this function release the DMA mappings.


## Conclusions and the BUG exploit

Till now, we understand how this PCI device driver works: it exposes mmap to support device memory mapping. Once a page fault is triggered, it fetch new encryted content from device through coherent DMA.

According to the writeup, we know that there is a integer overflow when calculating the faulting offset. Therefore, the attacker can hack the offset to cause underflow. The official solution is to map the memory of this vulnerable module to userland and hack the indirect function pointer.

For example,

```c++
char *addr2 = mmap(NULL, 0x100000000, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_NORESERVE, fd2, 0;
char *code_addr = addr2+0x100000000-0x4000;   
```

This snippet of code maps size 0x100000000 btyes (256MB) memory from the device memory offset at 0. This system call will not fail because the implementation of `dev_mmap` does not check the map size at all.

Once mapped, it's going to dereference address at `addr2+0x100000000-0x4000;`. When triggering page fault, the erroneous calculation can be shown below:

```c++
// vmf->address - vma->vm_start = 0x100000000-0x4000
// vma->vm_pgoff = 0
// vma->vm_pgoff << PAGE_SHIFT = 0;
// offset = int[0xffffc000 & 0xfffffffffffff000 + 0] = 0xffffc000
offset = ((vmf->address - vma->vm_start) & PAGE_MASK) + (vma->vm_pgoff << PAGE_SHIFT);
```
Hence, the `offset` now is a negative value, the `&storage_cache[slot_index][offset]` will points to the base address of this kernel module.

Of course, to avoid the device place encrypted data into this hacked memory space, the exploitation needs to set this dirty bit first.


```c++
char *addr1 = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd1, 15*4096);
*(long *)(addr1+4096-8) = -1;    // set the bitmap underoverflow pages
```

This snippet map size 4096 bytes of memory from the device memory at offset 15 * 4096 bytes.
> Cannot be larger than 16 * 4096 due to the check in mmap handler code.

After the division with `PAGE_SIZE`, the oversized `offset` is still a negative value here.
```c++
int bitmap_index;

// slot_index is based on the ioctl, assuming 0 here
// bitmap_index = 0 * 16 + 0xfffffffc = 0xfffffffc
bitmap_index = slot_index * (STORAGE_SLOT_SIZE/PAGE_SIZE) + offset/PAGE_SIZE;
```

That is to say, the bitmap value now underflow to the cache value.
```c++
global_storage_cache_manager.storage_cache_page_dirty_bitmap_[-4] == global_storage_cache_manager.storage_cache_[15][STORAGE_SLOT_SIZE - 4]
```

Therefore, below operation can write the bit value with `0xffffffffffffffff` to mark the underflow place as dirty.

```c++
ioctl(fd1, 0, 15);
char *addr1 = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd1, 15*4096);
*(long *)(addr1+4096-8) = -1;    // set the bitmap underoverflow pages
```

As you can tell, there is much interesting kernel knowledge remaining when exploiting this bug. On good example is that the author warns us to use `MAP_SHARED` in these `mmap` system call. Because the `MAP_PRIVATE` will not necessarily map the actual address in `vmf->page = page;` but just copy the memory content and return another private page to userland. This is not acceptable to the exploit since the attacker want to rewrite the actual module pages. The `MAP_SHARED` flag will make sure the prepared page be added into page table.

Besides these, there are more details points when the attacker has to exploit the QEMU through interacting with the device. Seems that there are many black magics when performming DMA memory access.

To sum up, this post simply concludes how this driver works and also unveils the fact that there are many many things in the kernel that need to learn.