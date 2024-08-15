---
layout: post
category: "deprecated"
---

## 注

02 主要针对 Syzkaller 的调用描述做了简单介绍，文末就资源型约束的描述做了简单思考。至此，也写过不少 syzlang 描述了，也做过自动生成 syzlang 的研究工作。咋说呢，有一些“去媚”，会发现这种描述方式还是有很多不足的hhh。

## (原文) Background

[Last post](../syzkaller-diving-01.html) we sloppily explored how syzkaller adopts coverage to guide its input mutation. Simply speaking, syzkaller will pick program with new coverage signals and add it to corpus. Next time, syzkaller will choose a program from corpus and then mutates it. Mutations include `splice`, `squashAny`, `insertCall`, `removeCall` and `mutateArg`. 

We know that fuzzing has the advantage of creating unexpected input to fully test the target, i.e. system calls. However, just random arguments may present poor performance when facing system calls and additionally, system calls may have dependency inside, bringing challenges for naive random fuzzer (like [Trinity fuzzer](https://github.com/kernelslacker/trinity)).

To the best of my knowledge, the solution adopted by syzkaller is some kind of milestone here. By learning about it, we can learn about its pros and cons for writing a better fuzzer.

## Model-based solution

File relevant operations (of course, everything is file in Linux) are quite the type we are going to discuss. In fact, if you use Trinity to fuzz file-related system calls like `ioctl` and `fcntl`, it will do not much contribution as this tool always operate (open, rename or delete) a not-existing file.

To make some breakthroughs, syzkaller adopts a solution by modeling this challenge as **producer** and **consumer** scenario.

> Resources represent values that need to be passed from output of one syscall to input of another syscall. For example, close syscall requires an input value (fd) previously returned by open or pipe syscall. To achieve this, fd is declared as a resource. This is a way of modelling dependencies between syscalls, as defining a syscall as the producer of a resource and another syscall as the consumer defines a loose sense of ordering between them. (from [descriptions](https://github.com/google/syzkaller/blob/master/docs/syscall_descriptions_syntax.md))

Cool, we see that syzkaller does not try to totally settle down this problem but cleverly mitigate it by modeling and defining a *loose sense* or ordering. At least with this ordering, a lot of computing resource can be saved because meaningless system calls are avoided.

In following sections, we can have a look from the source code level to learn the details.

### normal files and directories

We take an example by seeing `sys/linux/sys.txt`.

At the very first lines the resources and their initialized values are given
```c
resource fd[int32]: -1
resource fd_dir[fd]: AT_FDCWD

#define AT_FDCWD		-100    /* Special value used to indicate
                                           openat should use the current
                                           working directory. */
```

After that, the descriptions shall define what system call will produce these resources. (quite a lot)

```c
open(file ptr[in, filename], flags flags[open_flags], mode flags[open_mode]) fd
# Just so that we have something that creates fd_dir resources.
open$dir(file ptr[in, filename], flags flags[open_flags], mode flags[open_mode]) fd_dir
openat$dir(fd const[AT_FDCWD], file ptr[in, filename], flags flags[open_flags], mode flags[open_mode]) fd_dir
openat(fd fd_dir[opt], file ptr[in, filename], flags flags[open_flags], mode flags[open_mode]) fd
openat2$dir(fd const[AT_FDCWD], file ptr[in, filename], how ptr[in, open_how], size bytesize[how]) fd_dir
openat2(fd fd_dir[opt], file ptr[in, filename], how ptr[in, open_how], size bytesize[how]) fd
creat(file ptr[in, filename], mode flags[open_mode]) fd

dup(oldfd fd) fd
dup2(oldfd fd, newfd fd) fd
dup3(oldfd fd, newfd fd, flags flags[dup_flags]) fd
```

Cool, at least we now know there are multiple system calls that will return a file descriptor at the end.

We will also look at some system calls that will consume the resources.

```c
close(fd fd)
read(fd fd, buf buffer[out], count len[buf])
pread64(fd fd, buf buffer[out], count len[buf], pos fileoff)
readv(fd fd, vec ptr[in, array[iovec_out]], vlen len[vec])
preadv(fd fd, vec ptr[in, array[iovec_out]], vlen len[vec], off_low int32, off_high int32)
preadv2(fd fd, vec ptr[in, array[iovec_out]], vlen len[vec], off_low int32, off_high int32, flags flags[rwf_flags])
write(fd fd, buf buffer[in], count len[buf])
pwrite64(fd fd, buf buffer[in], count len[buf], pos fileoff)
writev(fd fd, vec ptr[in, array[iovec_in]], vlen len[vec])
pwritev(fd fd, vec ptr[in, array[iovec_in]], vlen len[vec], off_low int32, off_high int32)
pwritev2(fd fd, vec ptr[in, array[iovec_in]], vlen len[vec], off_low int32, off_high int32, flags flags[rwf_flags])
lseek(fd fd, offset fileoff, whence flags[seek_whence])
```

The resouces are regarded as type when writing these system call descriptions, defining the dependency.


### device

In the official docs, we are recommended to read the example of `dev_snd_midi.txt`, which are descriptions of the Linux MIDI interfaces.


```
resource fd_midi[fd]

syz_open_dev$sndmidi(dev ptr[in, string["/dev/snd/midiC#D#"]], id intptr, flags flags[open_flags]) fd_midi
syz_open_dev$dmmidi(dev ptr[in, string["/dev/dmmidi#"]], id intptr, flags flags[open_flags]) fd_midi
syz_open_dev$admmidi(dev ptr[in, string["/dev/admmidi#"]], id intptr, flags flags[open_flags]) fd_midi
syz_open_dev$amidi(dev ptr[in, string["/dev/amidi#"]], id intptr, flags flags[open_flags]) fd_midi
syz_open_dev$midi(dev ptr[in, string["/dev/midi#"]], id intptr, flags flags[open_flags]) fd_midi

write$midi(fd fd_midi, data ptr[in, array[int8]], len bytesize[data])
read$midi(fd fd_midi, data ptr[out, array[int8]], len bytesize[data])
ioctl$SNDRV_RAWMIDI_IOCTL_PVERSION(fd fd_midi, cmd const[SNDRV_RAWMIDI_IOCTL_PVERSION], arg ptr[out, int32])
ioctl$SNDRV_RAWMIDI_IOCTL_INFO(fd fd_midi, cmd const[SNDRV_RAWMIDI_IOCTL_INFO], arg ptr[out, snd_rawmidi_info])
ioctl$SNDRV_RAWMIDI_IOCTL_PARAMS(fd fd_midi, cmd const[SNDRV_RAWMIDI_IOCTL_PARAMS], arg ptr[inout, snd_rawmidi_params])
ioctl$SNDRV_RAWMIDI_IOCTL_STATUS32(fd fd_midi, cmd const[SNDRV_RAWMIDI_IOCTL_STATUS32], arg ptr[inout, snd_rawmidi_status32])
ioctl$SNDRV_RAWMIDI_IOCTL_STATUS64(fd fd_midi, cmd const[SNDRV_RAWMIDI_IOCTL_STATUS64], arg ptr[inout, snd_rawmidi_status64])
ioctl$SNDRV_RAWMIDI_IOCTL_DROP(fd fd_midi, cmd const[SNDRV_RAWMIDI_IOCTL_DROP], arg ptr[in, int32])
ioctl$SNDRV_RAWMIDI_IOCTL_DRAIN(fd fd_midi, cmd const[SNDRV_RAWMIDI_IOCTL_DRAIN], arg ptr[in, int32])

snd_rawmidi_info {
	device			int32
	subdevice		int32
	stream			flags[sndrv_rawmidi_stream, int32]
	card			const[0, int32]
	flags			const[0, int32]
	id			array[const[0, int8], 64]
	name			array[const[0, int8], 80]
	subname			array[const[0, int8], 32]
	subdevices_count	const[0, int32]
	subdevices_avail	const[0, int32]
	reserved		array[const[0, int8], 64]
}

snd_rawmidi_params {
	stream			flags[sndrv_rawmidi_stream, int32]
	buffer_size		intptr
	avail_min		intptr
	no_active_sensing	int32:1
	reserved		array[const[0, int8], 16]
}

snd_rawmidi_status32 {
	stream		flags[sndrv_rawmidi_stream, int32]
	tstamp_sec	const[0, int32]
	tstamp_nsec	const[0, int32]
	avail		const[0, int32]
	xruns		const[0, int32]
	reserved	array[const[0, int8], 16]
}

snd_rawmidi_status64 {
	stream		flags[sndrv_rawmidi_stream, int32]
	rsvd		array[const[0, int8], 4]
	tstamp_sec	const[0, int64]
	tstamp_nsec	const[0, int64]
	avail		const[0, intptr]
	xruns		const[0, intptr]
	reserved	array[const[0, int8], 16]
}

define SNDRV_RAWMIDI_IOCTL_STATUS32	_IOWR('W', 0x20, char[36])
define SNDRV_RAWMIDI_IOCTL_STATUS64	_IOWR('W', 0x20, char[56])

sndrv_rawmidi_stream = SNDRV_RAWMIDI_STREAM_OUTPUT, SNDRV_RAWMIDI_STREAM_INPUT
```

Considering the complexity of device related fuzzing, syzkaller offer different descriptions for different devices. Here, we didn't find `open` system call but `syz_open_dev`, a special wrapper. It is defined in `executor/common_linux.h`

```cpp
if SYZ_EXECUTOR || __NR_syz_open_dev
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

static long syz_open_dev(volatile long a0, volatile long a1, volatile long a2)
{
	if (a0 == 0xc || a0 == 0xb) {
		// syz_open_dev$char(dev const[0xc], major intptr, minor intptr) fd
		// syz_open_dev$block(dev const[0xb], major intptr, minor intptr) fd
		char buf[128];
		sprintf(buf, "/dev/%s/%d:%d", a0 == 0xc ? "char" : "block", (uint8)a1, (uint8)a2);
		return open(buf, O_RDWR, 0);
	} else {
		// syz_open_dev(dev strconst, id intptr, flags flags[open_flags]) fd
		char buf[1024];
		char* hash;
		strncpy(buf, (char*)a0, sizeof(buf) - 1);
		buf[sizeof(buf) - 1] = 0;
		while ((hash = strchr(buf, '#'))) {
			*hash = '0' + (char)(a1 % 10); // 10 devices should be enough for everyone.
			a1 /= 10;
		}
		return open(buf, a2, 0);
	}
}
#endif
```

In this wrapper function, we see that it can be used to specify char device or block device. Additionally, cooperating with `#` identifier, this wrapper function can be used to open *a number of* device. (one `#` for 10 possibly).


### network socket

The socket is also a special file descriptor, we can take an example from syzkaller bluetooth module.

```cpp
resource sock_bt_hci[sock_bt]

syz_init_net_socket$bt_hci(fam const[AF_BLUETOOTH], type const[SOCK_RAW], proto const[BTPROTO_HCI]) sock_bt_hci
bind$bt_hci(fd sock_bt_hci, addr ptr[in, sockaddr_hci], addrlen len[addr])
ioctl$sock_bt_hci(fd sock_bt_hci, cmd flags[bt_hci_ioctl], arg buffer[inout])
ioctl$HCIINQUIRY(fd sock_bt_hci, cmd const[HCIINQUIRY], arg ptr[in, hci_inquiry_req])
setsockopt$bt_hci_HCI_DATA_DIR(fd sock_bt_hci, level const[0], opt const[HCI_DATA_DIR], arg ptr[in, int32], arglen len[arg])
setsockopt$bt_hci_HCI_TIME_STAMP(fd sock_bt_hci, level const[0], opt const[HCI_TIME_STAMP], arg ptr[in, int32], arglen len[arg])
setsockopt$bt_hci_HCI_FILTER(fd sock_bt_hci, level const[0], opt const[HCI_FILTER], arg ptr[in, hci_ufilter], arglen len[arg])
getsockopt$bt_hci(fd sock, level const[0], opt flags[bt_hci_sockopt], arg buffer[out], arglen ptr[inout, len[arg, int32]])
write$bt_hci(fd sock_bt_hci, data ptr[in, vhci_command_pkt], size bytesize[data])

define HCI_EXTERNAL_CONFIG	0x40
define HCI_RAW_DEVICE	0x80
```

Different from normal files and similar to device, the socket creation also requires special wrapper, naming `syz_init_net_socket`.

```cpp
// syz_init_net_socket opens a socket in init net namespace.
// Used for families that can only be created in init net namespace.
static long syz_init_net_socket(volatile long domain, volatile long type, volatile long proto)
{
	int netns = open("/proc/self/ns/net", O_RDONLY);
	if (netns == -1)
		return netns;
	if (setns(kInitNetNsFd, 0))
		return -1;
	int sock = syscall(__NR_socket, domain, type, proto);
	int err = errno;
	if (setns(netns, 0))
		fail("setns(netns) failed");
	close(netns);
	errno = err;
	return sock;
}
#else
```

The special file `/proc/self/ns/net` is the namespace for network support. And the `setns` is used to manipulate this namespace. The wrapper finally calls `socket` system call to create the socket.

## For source code

Okay we know the producer - consumer model and how to use syzlang to describe it. But how syzkaller handles it internally? We can take a peek at how syzkaller consider when deciding a system call.

Simply speaking, syzkaller will check whether or not the program is qualified before complie it. 
```go
// Compile compiles sys description.
func Compile(desc *ast.Description, consts map[string]uint64, target *targets.Target, eh ast.ErrorHandler) *Prog {
/* ... */
	comp.check()
	if comp.errors != 0 {
		return nil
	}
```

This `check` function will do a entire checking, including the resource verification (Here, resouce constructor to be correct).

```go
func (comp *compiler) check() {
	comp.checkTypeValues()
	comp.checkAttributeValues()
	comp.checkUnused()
	comp.checkRecursion()
	comp.checkLenTargets()
	comp.checkConstructors() // THIS ONE !
	comp.checkVarlens()
	comp.checkDupConsts()
}

func (comp *compiler) checkConstructors() {
	ctors := make(map[string]bool)  // resources for which we have ctors
	inputs := make(map[string]bool) // resources which are used as inputs
	checked := make(map[structDir]bool)
	for _, decl := range comp.desc.Nodes {
		switch n := decl.(type) {
		case *ast.Call:
			for _, arg := range n.Args {
				comp.checkTypeCtors(arg.Type, prog.DirIn, true, ctors, inputs, checked)
			}
			if n.Ret != nil {
				comp.checkTypeCtors(n.Ret, prog.DirOut, true, ctors, inputs, checked)
			}
		}
    }
    // The above iterations will build ctors and inputs map
    // And the following one is used to check
	for _, decl := range comp.desc.Nodes {
		switch n := decl.(type) {
		case *ast.Resource:
			name := n.Name.Name
			if !comp.used[name] {
				continue
			}
			if !ctors[name] {
				comp.error(n.Pos, "resource %v can't be created"+
					" (never mentioned as a syscall return value or output argument/field)", name)
			}
			if !inputs[name] {
				comp.error(n.Pos, "resource %v is never used as an input"+
					"(such resources are not useful)", name)
			}
		}
	}
}
```

The sad story is that I cannort find the precise call path from mutating the program to the `check()` function. (From my point of view, why not check the program just after a new system call is inserted? The `insertCall` function and its successor seems never call `check`)

## Summary

In this post, we take a rather quick look at how syzkaller handles the dependency problem. To solve this, syzkaller does not seriously consider all state management but just offer a loose sense of ordering between different system calls (quite a dirty but clever plan). 

After that, we look up the source code to learn the detail of processing normal files, special devices, and network sockets. we also learn that the dependency is ensured by `checkConstructors()` before the program is compiled by syzkaller.

Before ending, I'd like to ask you about the opinions of the "producer-consumer" model offered by syzkaller. Is this the best solution for fuzzing system calls? 

From my own perspective (also with some related papers), we know this solution is easy (for understanding as well as implementation) and takes good effects to find vulnerabilities. However, it ignores the (internal) state of the resources created by some system calls (like `open`). 

> For instance, Syzkaller may emit multiples of open() calls on a file with its old path that has been either renamed (rename())orremoved(unlink()).  -- "Wen Xu, Fuzzing File Systems via Two-Dimensional Input Space Exploration"

The descripton of `rename()` and `unlink()` are presented below

```c
rename(old ptr[in, filename], new ptr[in, filename])
unlink(path ptr[in, filename])
```

As you can see, these two system calls, of course, change the state of the resource. However, it seems that syzkaller doesn't have the ability to further touch these challenges.

Besides, we can take a look at another easy example. When I do [experiments](https://github.com/jinb-park/kfuzz/tree/master/fuzzing-driver) to learn syzkaller, I indeed find that some program generated by syzkaller is not meet my expectation. 

```
r0 = openat$poc_lkm(0xffffffffffffff9c, &(0x7f00000000c0)='/proc/poc_lkm\x00', 0x0, 0x0)
close$poc_lkm(r0)
ioctl$poc_lkm(r0, 0x0, 0x0)
```

As you can see, the syzkaller calls `ioctl` after the relevant descriptor is closed, quite meaningless. The reason for that is very similar to the last example. The syzkaller does no additional treat for `close` system call, which changes the state.

To sum up, there is a tradeoff for offering **loose** relation comparing with **strict** relation. For fuzzing, defining some extent of ordering maybe is okay for some subsystems in the kernel. However, rethinking and optimization may need to be considered when targeting a dedicated module.
