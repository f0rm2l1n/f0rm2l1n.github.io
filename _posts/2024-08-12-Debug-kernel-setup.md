---
layout: post
category: "postcate"
---

## 写在开始之前

一般而言，无论是做题还是分析漏洞，我都习惯于将 `nokaslr` 放入内核启动的命令行中。exp 写好后，泄露的 KASLR 偏移也可以借助于改 init 获得 root 权限进而读 `/proc/kallsyms` 去读一个符号地址做减法来验证。

好巧不巧，碰到了一个特殊情况，需要在内核启动之时，即到达用户态 shell 之前，就需要知道 KASLR offset 的场景。那这下，我们该如何做呢？—— 答案如这篇博客的标题：需要调试内核的启动阶段。更准确来说，是调试启动阶段与 KASLR 有关的代码。

如果你有类似需求并且卡住了，可以参考本文，会尽可能不墨迹的给出答案。参考代码版本为 Linux-6.9.3。

## Linux 内核启动 101

### RESET 到 BIOS

给我们熟悉的 QEMU 启动脚本加上 `-S` 选项，再挂上 gdb 便可以体验从按电源键开始的调试

```
-S              freeze CPU at startup (use 'c' to start execution)
```

可以看到，此时我们的 RIP 为 `0xfff0`

```
Remote debugging using : 1234
warning: No executable has been specified and target does not support
determining executable automatically.  Try using the "file" command.
0x000000000000fff0 in ?? ()
```

这个神奇的地址便是 80386 及其后续处理器预定义的 IP 初始值。此外还需要啰嗦的是，于此时的运行处于[实模式](https://en.wikipedia.org/wiki/Real_mode)（real mode）。是需要考虑实模式下的内存分段的。如果我们直接查看目前要运行的指令

```
(remote) gef➤  x/8i $rip
=> 0xfff0:	add    BYTE PTR [rax],al
   0xfff2:	add    BYTE PTR [rax],al
   0xfff4:	add    BYTE PTR [rax],al
   0xfff6:	add    BYTE PTR [rax],al
(remote) gef➤  x/4wx $rip
0xfff0:	0x00000000	0x00000000	0x00000000	0x00000000
```

会看到，啥指令逻辑也没有呀。这里的结局办法是获得 `$cs` 寄存器的值，将其左移 4 位后当 base 并视当前 `$rip` 为 offset 后求出映射

```
(remote) gef➤  p $cs
$1 = 0xf000
(remote) gef➤  p ($cs<<4)+$rip
$2 = (void (*)()) 0xffff0
(remote) gef➤  x/4wx 0xffff0
0xffff0:	0x00e05bea	0x2f3630f0	0x392f3332	0x00fc0039
```

酷，果然发现有非零的东西了。实际上，这里的 `0xffff0` 的物理地址被称作 **reset vector**。每次 CPU reset 都将跳转到这个位置。

但还要额外注意一个点：即便此时启动内核使用的是 `qemu-system-x86_64`，调试器识别的架构为 *"i386:x86-64*。但由于此时的运行处于[实模式](https://en.wikipedia.org/wiki/Real_mode)（real mode）。故 gdb 直接显示的指令译码故而是错误的。

```
(remote) gef➤  x/2i 0xffff0
   0xffff0:	(bad)
   0xffff1:	pop    rbx
```

正确解析的话，会发现刚刚好是一个 `jmp` 指令（没有发现 `gdb` 强制去以当前识别架构外指令的命令，之后再找，先用 python 应急处理一下）

```py
>>> print(disasm(b'\xea\x5b\xe0\x00\xf0\x30\x36\x2f'))
   0:   ea 5b e0 00 f0 30 36    jmp    0x3630:0xf000e05b
   7:   2f                      das
```

这个跳转将以 `0x3630` 作为段选择子去加载基址，由于 gdb 似乎不支持去读 `GDTR` 寄存器的值，所以这里就不去深究，敲一下 *si*，会发现 `$rip` 切到了 `0xe05b`。

```
(remote) gef➤  si
0x000000000000e05b in ?? ()
```

看一下指令

```
(remote) gef➤  x/2gx ($cs<<4)+$rip
0xfe05b:	0x0f0061c83e83662e	0x66d28ed231f03685
```

```py
>>> print(disasm(p64(0x0f0061c83e83662e) + p64(0x66d28ed231f03685)))
   0:   2e 66 83 3e c8          cmp    WORD PTR cs:[esi], 0xffc8
   5:   61                      popa
   6:   00 0f                   add    BYTE PTR [edi], cl
   8:   85 36                   test   DWORD PTR [esi], esi
```

实际上，对于 QEMU + x86_64 架构而言，这里已经就是 BIOS 接管的地方了。

```c
// seabios/src/romlayout.S

/****************************************************************
 * Fixed position entry points
 ****************************************************************/

        // Specify a location in the fixed part of bios area.
        .macro ORG addr
        .section .fixedaddr.\addr
        .endm

        ORG 0xe05b
entry_post:
        cmpl $0, %cs:HaveRunPost                // Check for resume/reboot
        // ...
```

> 如果后续有空打算找一找 bios 的攻击面的话，这里会是一个不错的 entrypoint。考虑到这次的重心是调试内核，这里便就省略

### bootloader

BIOS 的责任是找到可以启动的设备，进而将执行交接给对应的 bootloader。如果用 ubuntu 发行版的话，每次开机显示的 [GNU GRUB](https://www.gnu.org/software/grub/) 便是其 bootloader。

对于 QEMU 默认而言，参考这里: https://stackoverflow.com/questions/68949890/how-does-qemu-emulate-a-kernel-without-a-bootloader

其实现 bootloader 效果的似乎是称为 `fw-cfg` 的神奇组件，这里我们简单管中窥豹，找一下相关地址

```c
// qemu/hw/i386/x86.c
void x86_load_linux(X86MachineState *x86ms,
                    FWCfgState *fw_cfg,
                    int acpi_data_size,
                    bool pvh_enabled)
{
    // ...
    /* kernel protocol version */
    if (ldl_p(header + 0x202) == 0x53726448) {
        protocol = lduw_p(header + 0x206);
    } else
    // ...
    if (protocol < 0x200 || !(header[0x211] & 0x01)) {
        /* Low kernel */
    // ...
    } else if (protocol < 0x202) {
        /* High but ancient kernel */
    } else {
        /* High and recent kernel */
        real_addr    = 0x10000;
        cmdline_addr = 0x20000;
        prot_addr    = 0x100000;
    }
    // ...
    fw_cfg_add_i32(fw_cfg, FW_CFG_CMDLINE_ADDR, cmdline_addr);
    fw_cfg_add_i32(fw_cfg, FW_CFG_CMDLINE_SIZE, strlen(kernel_cmdline) + 1);
    fw_cfg_add_string(fw_cfg, FW_CFG_CMDLINE_DATA, kernel_cmdline);
    // ...
}
```

awesome，现在根据我们超常的大脑模拟猜测，根据这段代码我们可以知道在 bootloader 发挥完作用后，内核代码的实模式部分 0x10000 的实模式地址，并且内核启动的命令行参数会存到 0x20000 地址。

> 更多具体的可以参考内核的 boot 约定：https://github.com/torvalds/linux/blob/v6.9/Documentation/x86/boot.txt#L156

### kernel setup

加载到 0x10000 部分的内容，其实就是内核 setup 部分的代码，简单点说就是 bzImage 开头的部分。

而在 0x10000 + 0x200 的位置，将是实模式下内核的第一条指令，实现跳转到 `start_of_setup`

```
$ gdb arch/x86/boot/setup.elf
...
gef➤  x/i 0x200
   0x200:	jmp    0x26c <start_of_setup>
```

实模式的 setup 部分代码需要完成诸如初始化栈、初始化 bss 等工作，完成后，将跳转到内核启动的 main 函数上

### kernel boot main

看到 main 函数还是非常让人亲切的，即使这是 kernel boot 过程的 `main` 代码。这里的底层逻辑也不赘述，感兴趣的读者可以自行阅读[代码](https://github.com/torvalds/linux/blob/v6.9/arch/x86/boot/main.c#L136)。

```c
void main(void)
{
    // ...
	init_default_io_ops();
    // ...
    copy_boot_params();
    // ...
    console_init();
    if (cmdline_find_option_bool("debug"))
		puts("early console in setup code\n");  // XXX: 这个 boot 阶段的调试可以留意

    /* End of heap check */
	init_heap();    // boot 阶段的堆会是啥样的呢?

    // ...

    /* Do the last things and invoke protected mode */
	go_to_protected_mode();
}
```

到最后，实模式下的任务就已经告一段落，内核启动终于要进入[保护模式](https://zh.wikipedia.org/zh-cn/%E4%BF%9D%E8%AD%B7%E6%A8%A1%E5%BC%8F)。

### kernel protected boot

根据 booting 阶段的规范，我们可以知道保护模式的内核加载在 0x100000 的地址处

```
	    ~                        ~
        |  Protected-mode kernel |
100000  +------------------------+
        |    I/O memory hole     |
0A0000	+------------------------+
        |   Reserved for BIOS    | 
        ~                        ~
        |      Command line      | 
X+10000	+------------------------+
        |       Stack/heap       | 
X+08000	+------------------------+	
        |     Kernel setup       | kernel real-mode code.
        |   Kernel boot sector   | legacy boot sector.
X       +------------------------+
        |      Boot loader       | <- Boot sector entry point
001000	+------------------------+
        |  Reserved for MBR/BIOS |
000800	+------------------------+
        |  Typically used by MBR |
000600	+------------------------+ 
        |      BIOS use only     |
000000	+------------------------+
```

这里直接给出答案，这个地址对应的[代码](https://github.com/torvalds/linux/blob/v6.9/arch/x86/boot/compressed/head_64.S#L83)为 `arch/x86/boot/compressed/head_64.S` 处的 `startup_32`

> 对，即使是启动 64 位内核，也需要先跳到 32 位初始化

这里的调试为了方便，我们可以通过如下方式把保护模式的符号添加给调试器:

- 首先取到保护模式代码的 `.text` 基地址

```
$ readelf -S arch/x86/boot/compressed/vmlinux | grep .text
  [ 3] .text             PROGBITS         0000000000c70240  00c71240
```

- 调试器中通过 `add-symbol-file` 添加符号，别忘了 `0x100000` 的 offset

```
add-symbol-file arch/x86/boot/compressed/vmlinux 0xc70240+0x100000
```

然后，文末就可以下断点开始愉快的调试保护模式的启动代码了

```
(remote) gef➤  b *0x100000
(remote) gef➤  c
(remote) gef➤  x/4i $rip
=> 0x0 <startup_32>:	push   rbx
   0x1 <startup_32+1>:	inc    DWORD PTR [rax]
   0x3 <startup_32+3>:	lock push rbx
   0x5 <startup_32+5>:	inc    DWORD PTR [rax]
```

### 言归正传

为了在启动阶段拿到 KASLR 的值，我们需要关心的函数是 `extract_kernel` 中调用的 `choose_random_location`，[戳](https://github.com/torvalds/linux/blob/v6.9/arch/x86/boot/compressed/misc.c#L486)。这个函数定义于 `arch/x86/boot/compressed/kaslr.c` 下，根据启动参数中是否允许 `kaslr` 来决定是否要为提取内核的虚拟地址加一点随机的偏移。

```c
asmlinkage __visible void *extract_kernel(void *rmode, unsigned char *output)
{
    // ...
	choose_random_location((unsigned long)input_data, input_len,
				(unsigned long *)&output,
				needed_size,
				&virt_addr);
    // ...
}
```

考虑到这篇博客只是为了分享一下调试经历，这里就不咬文嚼字的分析这个代码的具体实现了。为了达到文章开头所提的目的，只需要在这个函数调用处下断点，分析调用完成后 `virt_addr` 的随机值即可～

## 参考材料

- Linux Internal#Booting. [LINK](https://0xax.gitbooks.io/linux-insides/content/Booting/)

- QEMU. [LINK](https://github.com/qemu/qemu)