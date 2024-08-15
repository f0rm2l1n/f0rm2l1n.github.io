---
layout: post
category: "deprecated"
---

## 注

这一篇回忆起来还是有点意思的，当时是给软件安全课程出作业的时候发现数据段的 shellcode 不好使了，进而 dig 总结出的一些文字。

## 原文

Me, yet again, asked to be the TA (Teacher-Assistant) for the software secure courses. Some old materials can be found at
- 2021 version: https://gitee.com/zjuicsr/ssec22spring-stu
- 2020 version: https://gitee.com/zjuicsr/sp20-hw-pub

This year we choose to use the 20.04 Ubuntu as the experiment environment. (maybe docker in the future). We thought, more or less, this means we catch up with the times.

However, this "upgrade" brought out an interesting puzzle on us recently.

## What's wrong with execstack

For the very first homework, one of my colleagues design a challenge like the below (simplified):

```c
char buf[PAGE_SIZE]={'0'};

void func()
{
    char str[20] = {'0'};
    strcpy(str, buf);
}

int main(void)
{
    // ...
    read(0, buf, PAGE_SIZE);
    func();
    // ...
}
```

It is quite obvious that there is a buffer overflow vulnerability in the function `func()` since it tries to copy 4096 bytes into a small 20 bytes size buffer in the stack. Because the program is built with `-no-pie` flag and `execstack` flag, the student can place shellcode into the global `buf` and overflow the return address in `func()` to return to the crafted shellcode, hence achieving code execution.

The author of this challenge successfully verified his intended exploit in his local machine and our remote server (we use docker in the remote). Everything seems to be going well and we release this to the students as scheduled. And then some puzzling things happen. The students keep asking somehing like

"The exploit cannot work out in our local virtual machine but seems to work out in the remote one."

To be honest, I didn't take it seriously when somebody raised this. Until another teacher assistant warns me that there are issues with this problem I aware something went wrong.

Simply speaking, the students find out that the shellcode in the `buf` is not executable because it resides in a not executable page.

```
gdb-peda$ vmmap
Start      End        Perm	Name
0x08048000 0x08049000 r-xp	/home/ssec2022/Desktop/ssec22spring-stu/hw-01/03_bof_again/bof-again
0x08049000 0x0804a000 r--p	/home/ssec2022/Desktop/ssec22spring-stu/hw-01/03_bof_again/bof-again
0x0804a000 0x0804b000 rw-p	/home/ssec2022/Desktop/ssec22spring-stu/hw-01/03_bof_again/bof-again
0xf7dc8000 0xf7de1000 r--p	/usr/lib/i386-linux-gnu/libc-2.31.so
0xf7de1000 0xf7f3c000 r-xp	/usr/lib/i386-linux-gnu/libc-2.31.so
0xf7f3c000 0xf7fb0000 r--p	/usr/lib/i386-linux-gnu/libc-2.31.so
0xf7fb0000 0xf7fb1000 ---p	/usr/lib/i386-linux-gnu/libc-2.31.so
0xf7fb1000 0xf7fb3000 r--p	/usr/lib/i386-linux-gnu/libc-2.31.so
0xf7fb3000 0xf7fb4000 rw-p	/usr/lib/i386-linux-gnu/libc-2.31.so
0xf7fb4000 0xf7fb7000 rw-p	mapped
0xf7fc9000 0xf7fcb000 rw-p	mapped
0xf7fcb000 0xf7fcf000 r--p	[vvar]
0xf7fcf000 0xf7fd1000 r-xp	[vdso]
0xf7fd1000 0xf7fd2000 r--p	/usr/lib/i386-linux-gnu/ld-2.31.so
0xf7fd2000 0xf7ff0000 r-xp	/usr/lib/i386-linux-gnu/ld-2.31.so
0xf7ff0000 0xf7ffb000 r--p	/usr/lib/i386-linux-gnu/ld-2.31.so
0xf7ffc000 0xf7ffd000 r--p	/usr/lib/i386-linux-gnu/ld-2.31.so
0xf7ffd000 0xf7ffe000 rw-p	/usr/lib/i386-linux-gnu/ld-2.31.so
0xfffdd000 0xffffe000 rwxp	[stack]
gdb-peda$ p buf
$1 = "0", '\000' <repeats 98 times>
gdb-peda$ p &buf
$2 = (char (*)[100]) 0x804a040 <buf>
```

As you can see, in the provided virtual machine (Ubuntu 20.04 Virtual Box VM in detail), the global variable `buf` resides in the third address space whose flag is `rw-p`, without the executable `x` flag.
If using Ubuntu 18.04 or the docker environment, this is different.

```
0x8048000 0x8049000 0x000000 r-x /home/lin/playground/ssec22spring-stu/hw-01/03_bof_again/bof-again
0x8049000 0x804a000 0x000000 r-x /home/lin/playground/ssec22spring-stu/hw-01/03_bof_again/bof-again
0x804a000 0x804b000 0x001000 rwx /home/lin/playground/ssec22spring-stu/hw-01/03_bof_again/bof-again
0xf7dce000 0xf7fa3000 0x000000 r-x /lib/i386-linux-gnu/libc-2.27.so
0xf7fa3000 0xf7fa4000 0x1d5000 --- /lib/i386-linux-gnu/libc-2.27.so
0xf7fa4000 0xf7fa6000 0x1d5000 r-x /lib/i386-linux-gnu/libc-2.27.so
0xf7fa6000 0xf7fa7000 0x1d7000 rwx /lib/i386-linux-gnu/libc-2.27.so
0xf7fa7000 0xf7faa000 0x000000 rwx
0xf7fd0000 0xf7fd2000 0x000000 rwx
0xf7fd2000 0xf7fd5000 0x000000 r-- [vvar]
0xf7fd5000 0xf7fd6000 0x000000 r-x [vdso]
0xf7fd6000 0xf7ffc000 0x000000 r-x /lib/i386-linux-gnu/ld-2.27.so
0xf7ffc000 0xf7ffd000 0x025000 r-x /lib/i386-linux-gnu/ld-2.27.so
0xf7ffd000 0xf7ffe000 0x026000 rwx /lib/i386-linux-gnu/ld-2.27.so
0xfffdd000 0xffffe000 0x000000 rwx [stack]
gef➤  p &buf
$1 = (char (*)[100]) 0x804a040 <buf>
```
You will find out that the flag for the `buf` is `rwx`.

This is out of our expectation because we always believed that if turn on `execstack` option, all data segments should be mapped with an executable flag.

Given the fact that the intended solution is not applicable to students' virtual machines, we decided to cancel this problem and bonus those who solve it with ROP techniques instead. We told the student that this is because the environment is different between their machine and remote docker. But sincerely, we didn't figure out where the exact difference is.

Of course, we didn't feel satisfied for closing this challenge and we conducted some "remedial measures".

That is, we tried to use the exactly same `libc` and `ld` in the Ubuntu 20.04 VM, as we believe this flag or mapping issues are probably due to the difference in linking and loading procedure. But sadly we failed.

Below is the command that we used to adopt the same `libc` and `ld` to run the target.

```
LD_PRELOAD=<...>/libc-2.31.so <...>/ld-2.31.so ./bof-again
```

We found that even these two are same, the flag is not match our expectation
```
$ cat /proc/3065/maps 
08048000-08049000 r-xp 00000000 08:05 133858    /home/ssec2022/Desktop/ssec22spring-stu/hw-01/03_bof_again/bof-again
08049000-0804a000 r--p 00000000 08:05 133858    /home/ssec2022/Desktop/ssec22spring-stu/hw-01/03_bof_again/bof-again
0804a000-0804b000 rw-p 00001000 08:05 133858    /home/ssec2022/Desktop/ssec22spring-stu/hw-01/03_bof_again/bof-again    // still not executable page
f7d29000-f7d46000 r--p 00000000 08:05 133885    /home/ssec2022/Desktop/ssec22spring-stu/hw-01/03_bof_again/libc-2.31.so // same libc
f7d46000-f7e9e000 r-xp 0001d000 08:05 133885    /home/ssec2022/Desktop/ssec22spring-stu/hw-01/03_bof_again/libc-2.31.so
f7e9e000-f7f0e000 r--p 00175000 08:05 133885    /home/ssec2022/Desktop/ssec22spring-stu/hw-01/03_bof_again/libc-2.31.so
f7f0e000-f7f10000 r--p 001e4000 08:05 133885    /home/ssec2022/Desktop/ssec22spring-stu/hw-01/03_bof_again/libc-2.31.so
f7f10000-f7f12000 rw-p 001e6000 08:05 133885    /home/ssec2022/Desktop/ssec22spring-stu/hw-01/03_bof_again/libc-2.31.so
f7f12000-f7f16000 rw-p 00000000 00:00 0 
f7f16000-f7f1a000 r--p 00000000 00:00 0         [vvar]
f7f1a000-f7f1c000 r-xp 00000000 00:00 0         [vdso]
f7f1c000-f7f1d000 r--p 00000000 08:05 133884    /home/ssec2022/Desktop/ssec22spring-stu/hw-01/03_bof_again/ld-2.31.so // same ld
f7f1d000-f7f3b000 r-xp 00001000 08:05 133884    /home/ssec2022/Desktop/ssec22spring-stu/hw-01/03_bof_again/ld-2.31.so
f7f3b000-f7f46000 r--p 0001f000 08:05 133884    /home/ssec2022/Desktop/ssec22spring-stu/hw-01/03_bof_again/ld-2.31.so
f7f47000-f7f48000 r--p 0002a000 08:05 133884    /home/ssec2022/Desktop/ssec22spring-stu/hw-01/03_bof_again/ld-2.31.so
f7f48000-f7f49000 rw-p 0002b000 08:05 133884    /home/ssec2022/Desktop/ssec22spring-stu/hw-01/03_bof_again/ld-2.31.so
ffb61000-ffb81000 rwxp 00000000 00:00 0         [stack]
ffb81000-ffb82000 rw-p 00000000 00:00 0 
```

## Dig Deeper

Before disclosing the actual reason, we are going to learn some basics.

### execstack 101

When we do old CTF challenges that related to the shellcode, we can confront this special `execstack` flag. Search the [documentation](https://man7.org/linux/man-pages/man8/execstack.8.html) and I found something like the below.

> Linux has in the past allowed execution of instructions on the stack and there are lots of binaries and shared libraries assuming this behaviour. Furthermore, GCC trampoline code for e.g. nested functions requires executable stack on many architectures. To avoid breaking binaries and shared libraries which need executable stack, ELF binaries and shared libraries now can be marked as requiring executable stack or not requiring it. This marking is done through the p_flags field in the PT_GNU_STACK program header entry.  If the marking is missing, kernel or dynamic linker need to assume it might need executable stack. The marking is done automatically by recent GCC versions (objects using trampolines on the stack are marked as requiring executable stack, all other newly built objects are marked as not requiring it) and linker collects these markings into marking of the whole binary or shared library. The user can override this at assembly time (through --execstack or --noexecstack assembler options), at link time (through -z execstack or -z noexecstack linker options)

In short, since there are cases that need the executable stack, the binaries and shared libraries use `p_flags` field in the *PT_GNU_STACK program header entry* to achieve this.

Okay, talk is cheap, let's see the code in kernel.

```c
static int load_elf_binary(struct linux_binprm *bprm)
{
    // ...
    int executable_stack = EXSTACK_DEFAULT;
    // ...
    for (i = 0; i < loc->elf_ex.e_phnum; i++, elf_ppnt++)
		switch (elf_ppnt->p_type) {
		case PT_GNU_STACK: // HERE
			if (elf_ppnt->p_flags & PF_X)
				executable_stack = EXSTACK_ENABLE_X;
			else
				executable_stack = EXSTACK_DISABLE_X;
			break;

		case PT_LOPROC ... PT_HIPROC:
			retval = arch_elf_pt_proc(&loc->elf_ex, elf_ppnt,
						  bprm->file, false,
						  &arch_state);
			if (retval)
				goto out_free_dentry;
			break;
		}
}
```

As you can see, when this `for` loop parses the `PT_GNU_STACK`, it will write state variable `executable_stack`. This becomes the hint to decide if the stack is mapped to executable.

But before that, there is a interesting state named `READ_IMPLIES_EXEC`.

### READ_IMPLIES_EXEC

Something okay for `read` implies okay for `execute`? This sounds very dangerous but it is quite useful for old machine or firmware dongle.

In the old and familiar kernel, this feature is mainly decided by the blow function.

```c
/*
 * An executable for which elf_read_implies_exec() returns TRUE will
 * have the READ_IMPLIES_EXEC personality flag set automatically.
 */
#define elf_read_implies_exec(ex, executable_stack)	\
	(executable_stack != EXSTACK_DISABLE_X)

#define EXSTACK_DISABLE_X 1	/* Disable executable stacks */
```

The relation can be viewed through following maps

```
*                 CPU: | lacks NX*  | has NX, ia32     | has NX, x86_64 |
* ELF:                 |            |                  |                |
* ---------------------|------------|------------------|----------------|
* missing PT_GNU_STACK | exec-all   | exec-all         | exec-all       |
* PT_GNU_STACK == RWX  | exec-all   | exec-all         | exec-all       |
* PT_GNU_STACK == RW   | exec-none  | exec-none        | exec-none      |
*  exec-all  : all PROT_READ user mappings are executable, except when
*              backed by files on a noexec-filesystem.
*  exec-none : only PROT_EXEC user mappings are executable.
```

That is, except for cases that `PT_GNU_STACK == RW`, the `elf_read_implies_exec` will allow all the `PROT_READ` mapping becomes executable.

### Root Cause

Since we have tried to replace the `ld` and `libc`, we now knew that this unexpected difference may be due to something upper, the kernel should be responsible for that. According to the above knowledge, we just need to find the difference in `READ_IMPLIES_EXEC`.

> That is, although our remote docker uses Ubuntu:20.04 image, the docker will rely on the host kernel version

The kernel version of these different environments.

```
RWX env kernel
5.4.0-100-generic #113-Ubuntu SMP Thu Feb 3 18:43:29 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
RW  env kernel
5.13.0-30-generic #33~20.04.1-Ubuntu SMP Mon Feb 7 14:25:10 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
```
Cool, since the higher kernel is "safer" and don't allow the RWX data segment. After manually checkout the commit history, I found the very critical code there.

```diff
commit 122306117afe4ba202b5e57c61dfbeffc5c41387
Author: Kees Cook <keescook@chromium.org>
Date:   Thu Mar 26 23:48:16 2020 -0700

    x86/elf: Split READ_IMPLIES_EXEC from executable PT_GNU_STACK

    The READ_IMPLIES_EXEC workaround was designed for old toolchains that
    lacked the ELF PT_GNU_STACK marking under the assumption that toolchains
    that couldn't specify executable permission flags for the stack may not
    know how to do it correctly for any memory region.

    This logic is sensible for having ancient binaries coexist in a system
    with possibly NX memory, but was implemented in a way that equated having
    a PT_GNU_STACK marked executable as being as "broken" as lacking the
    PT_GNU_STACK marking entirely. Things like unmarked assembly and stack
    trampolines may cause PT_GNU_STACK to need an executable bit, but they
    do not imply all mappings must be executable.

    This confusion has led to situations where modern programs with explicitly
    marked executable stacks are forced into the READ_IMPLIES_EXEC state when
    no such thing is needed. (And leads to unexpected failures when mmap()ing
    regions of device driver memory that wish to disallow VM_EXEC[1].)

    In looking for other reasons for the READ_IMPLIES_EXEC behavior, Jann
    Horn noted that glibc thread stacks have always been marked RWX (until
    2003 when they started tracking the PT_GNU_STACK flag instead[2]). And
    musl doesn't support executable stacks at all[3]. As such, no breakage
    for multithreaded applications is expected from this change.

    [1] https://lkml.kernel.org/r/20190418055759.GA3155@mellanox.com
    [2] https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=54ee14b3882
    [3] https://lkml.kernel.org/r/20190423192534.GN23599@brightrain.aerifal.cx

    Suggested-by: Hector Marco-Gisbert <hecmargi@upv.es>
    Signed-off-by: Kees Cook <keescook@chromium.org>
    Signed-off-by: Borislav Petkov <bp@suse.de>
    Reviewed-by: Jason Gunthorpe <jgg@mellanox.com>
    Link: https://lkml.kernel.org/r/20200327064820.12602-3-keescook@chromium.org

diff --git a/arch/x86/include/asm/elf.h b/arch/x86/include/asm/elf.h
index ee459d4c3b45..397a1c74433e 100644
--- a/arch/x86/include/asm/elf.h
+++ b/arch/x86/include/asm/elf.h
@@ -288,12 +288,13 @@ extern u32 elf_hwcap2;
  * ELF:                 |            |                  |                |
  * ---------------------|------------|------------------|----------------|
  * missing PT_GNU_STACK | exec-all   | exec-all         | exec-all       |
- * PT_GNU_STACK == RWX  | exec-all   | exec-all         | exec-all       |
+ * PT_GNU_STACK == RWX  | exec-stack | exec-stack       | exec-stack     |
  * PT_GNU_STACK == RW   | exec-none  | exec-none        | exec-none      |
  *
  *  exec-all  : all PROT_READ user mappings are executable, except when
  *              backed by files on a noexec-filesystem.
  *  exec-none : only PROT_EXEC user mappings are executable.
+ *  exec-stack: only the stack and PROT_EXEC user mappings are executable.
  *
  *  *this column has no architectural effect: NX markings are ignored by
  *   hardware, but may have behavioral effects when "wants X" collides with
@@ -302,7 +303,7 @@ extern u32 elf_hwcap2;
  *
  */
 #define elf_read_implies_exec(ex, executable_stack)    \
-       (executable_stack != EXSTACK_DISABLE_X)
+       (executable_stack == EXSTACK_DEFAULT)

 struct task_struct;
```

As the commit message clearly clarified:
```
This confusion has led to situations where modern programs with explicitly
marked executable stacks are forced into the READ_IMPLIES_EXEC state when
no such thing is needed.
```

The older version of kernel enable the READ_IMPLIES_EXEC along with the executable stacks, and this is no longer true for the kernel with this patch.

Or in short, the VM that students use will be set into `exec-stack` state instead of the `exec-all` state so the variable `buf` is resides onto mappings that are not executable.


## Conclusion

I just thought that I was too stupid that first believed that the mapping is built by loader without actually referring to the code. I need to learn this lesson that do not make any stupid assumptions without investigating it.