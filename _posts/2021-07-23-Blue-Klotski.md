---
layout: post
category: "deprecated"
---
<!-- ---
layout: post
title: Blue Klotski (CVE-2021-3573) and the story for fixing
subtitle: Anyway I am sorry for everything
tags: [CVE, Kernel]
published: true
--- -->

## 注

这篇博客介绍的是我在 Linux 内核中的第一个 CVE，最开始也是受 [BleedingTooth](https://google.github.io/security-research/pocs/linux/bleedingtooth/writeup.html) 启发开始看蓝牙栈代码的。或许也是一种诅咒？因为第一个漏洞发现的不是那种好利用的溢出啥的，而是跟条件竞争有关，自此就走向了找奇奇怪怪漏洞的不归之路。

## 原文

Recently me and my friends, as Greg KH said, are hammering on the bluetooth stack of the Linux kernel. And luckily, we found some pretty good vulnerability bugs that can lead to code execution.

In this post, I will introduce one typical one: the Blue Klotski (CVE-2021-3573).

## Brief Introduction

The CVE-2021-3573 is one UAF vulnerability caused by race condition when a BT controller is removed. With the *CAP_NET_ADMIN* privilege, an **local attacker** can emulate a fake controller from user space and detach it to trigger the UAF. The attacker can further escalate the privilege by carefully spray the freed objects to achieve arbitrary code execution.

## Bug Details

Before we take a look at these two threads (the USING thread and the FREEING thread), let's audit the `hci_sock_bind()` function.

> Note: the code I refer will take v5.12.0 as the example.

```cpp
static int hci_sock_bind(struct socket *sock, struct sockaddr *addr,
			 int addr_len)
{
...
	switch (haddr.hci_channel) {
	case HCI_CHANNEL_RAW:
		if (hci_pi(sk)->hdev) {
			err = -EALREADY;
			goto done;
		}

		if (haddr.hci_dev != HCI_DEV_NONE) {
			hdev = hci_dev_get(haddr.hci_dev);
			if (!hdev) {
				err = -ENODEV;
				goto done;
			}

			atomic_inc(&hdev->promisc);
		}
...
        hci_pi(sk)->hdev = hdev;
...
}
```

In short, the `hci_sock_bind()` function will fetch the hdev based on the user supplied index, and attach it to the sockets with `hci_pi(sk)->hdev = hdev`. For now, this HCI socket becomes a "bound" socket because it has some connection with the BT controller.

Moreoever, the `hci_dev_get()` function is used to increase the `refcnt` of the `hdev`, keep this in memory because we will use it later.

### USING routine

Once the socket is bound to one controller, the function `hci_sock_bound_ioctl()` is allowed.

```cpp
/* Ioctls that require bound socket */
static int hci_sock_bound_ioctl(struct sock *sk, unsigned int cmd,
				unsigned long arg)
{
	struct hci_dev *hdev = hci_pi(sk)->hdev;

	if (!hdev)
		return -EBADFD;
...
	switch (cmd) {
...

	case HCIGETCONNINFO:
		return hci_get_conn_info(hdev, (void __user *)arg);

	case HCIGETAUTHINFO:
		return hci_get_auth_info(hdev, (void __user *)arg);

	case HCIBLOCKADDR:
		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		return hci_sock_blacklist_add(hdev, (void __user *)arg);

	case HCIUNBLOCKADDR:
		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		return hci_sock_blacklist_del(hdev, (void __user *)arg);
	return -ENOIOCTLCMD;
}
```

There are four commands offered in this function, all these commands have their utitily function to further operate on the linked list in `hdev` object. The very check in top of the `hci_sock_bound_ioctl` will make sure only the bound sockets will be manipulated.

We can see on of these commands, like the `hci_sock_blacklist_add()`.

```c
static int hci_sock_blacklist_add(struct hci_dev *hdev, void __user *arg)
{
	bdaddr_t bdaddr;
	int err;

	if (copy_from_user(&bdaddr, arg, sizeof(bdaddr)))
		return -EFAULT;

	hci_dev_lock(hdev);

	err = hci_bdaddr_list_add(&hdev->blacklist, &bdaddr, BDADDR_BREDR);

	hci_dev_unlock(hdev);

	return err;
}
```

It's a quite simple function: gets the argument from the user pointer, obtains the lock, operates the list and then releases the lock. In short, this function will finally change the hdev->blacklist and add one allocated BT address on it.


### FREEING routine

Normally, the bound socket is expected to drop the bind when the socket is closed. 

```cpp
static int hci_sock_release(struct socket *sock)
{
	hdev = hci_pi(sk)->hdev;
	if (hdev) {
...
		atomic_dec(&hdev->promisc);
		hci_dev_put(hdev);
	}
...
}
```

As you can see, this is highly symmetry to the `hci_sock_bind()`. Just looks quite safe.

However, is this the only place the socket drop the refcnt? The answer is NO. We know that the bound socket means somewhat a connection between the sock and the hardware controller. What if this controller is unplugged? The sock must be aware of this event.

The relevant function is `hci_sock_dev_event()`. When the controller is getting removed, the kernel will awake the `hci_unreigster_dev()` function, which will then call `hci_sock_dev_event()` with `HCI_DEV_UNREG` argument.

```cpp
void hci_sock_dev_event(struct hci_dev *hdev, int event)
{
...
	if (event == HCI_DEV_UNREG) {
		struct sock *sk;

		/* Detach sockets from device */
		read_lock(&hci_sk_list.lock);
		sk_for_each(sk, &hci_sk_list.head) {
			bh_lock_sock_nested(sk);
			if (hci_pi(sk)->hdev == hdev) {
				hci_pi(sk)->hdev = NULL; // {1}
				sk->sk_err = EPIPE;
				sk->sk_state = BT_OPEN;
				sk->sk_state_change(sk);

				hci_dev_put(hdev); // {2}
			}
			bh_unlock_sock(sk);
		}
		read_unlock(&hci_sk_list.lock);
	}
}
```

This function will traverse the list of sockets through `hci_sk_list` and find out the sockets that may bound to the unregistering `hdev`. It will then updates the sock (like `{1}` mark) and drop the refcnt (like `{2}` mark).

The `hdev` object will be ultimately released when the underground driver calls `hci_free_dev()`, which will drop the last refcnt and later to `kfree`.

This abnormal `hdev` refcnt dropping routine is not safe as expected. In fact, it can easily race with the USING routine like below.

```
hci_sock_bound_ioctl thread    |    hci_unregister_dev thread
                               |
                               |
if (!hdev)                     |    
    return -EBADFD;            |    
                               |
                               |    hci_pi(sk)->hdev = NULL;
                               |    ...
                               |    hci_dev_put(hdev);
                               |    ...
                               |    hci_free_dev(hdev);
// UAF, for example            |
hci_dev_lock(hdev);            |
                               |
                               |
```

You can refer to the oss report (https://www.openwall.com/lists/oss-security/2021/06/08/2) for details like POC and crash log.

## The Exploitation

Some readers may begin to complain: race? Hmmmmm... It's not stable and not interesing.

Well, I have to tell you that this race is an exception, for it can be one hundred percent stably triggered. :)

If you read the above kernel code carefully, you will find the trick there.

```cpp
static int hci_sock_blacklist_add(struct hci_dev *hdev, void __user *arg)
{
	bdaddr_t bdaddr;
	int err;

	if (copy_from_user(&bdaddr, arg, sizeof(bdaddr))) // {3}
		return -EFAULT;

```

The `{3}` marked code get its content from userspace, which means we can adopt the [userfaultfd](https://man7.org/linux/man-pages/man2/userfaultfd.2.html) technique to hang this routine. And we can wake it until the `hdev` is already freed to cause the UAF.

The race will be like below.

```
hci_sock_bound_ioctl thread    |    hci_unregister_dev thread
                               |
                               |
if (!hdev)                     |    
    return -EBADFD;            |    
                               |
copy_from_user()               |
____________________________   |
                               |
                               |    hci_pi(sk)->hdev = NULL;
                               |    ...
    userfaultfd hang           |    hci_dev_put(hdev);
                               |    ...
                               |    hci_free_dev(hdev);
____________________________   |
// UAF, for example            |
hci_dev_lock(hdev);            |
                               |
                               |
```

Therefore, with this stable UAF, let's write our exploit.

> To be honest, this is my first time to write one 0-day exploit. Thankfully, this makes no big difference comparing to a CTF challenge.
> BTW, the hci_sock_bound_ioctl() has limited operations hence I choose the hci_sock_sendmsg() as the USING routine in my exploits.

### Leaking

The first question is how to bypass the KASLR. I have been blocked there for a while as I wanted to leak some code/data pointers with some known skills. Like the [OOB read](https://marc.info/?l=linux-bluetooth&m=162174982523451&w=2) in bluetooth I have reported to the community.

After some fail attempts, I choose to do the leaking with the Blue Klotski and it turns out to be totally enough. I just have to find some place that may trigger a kernel WARNING and I can get the pointers I wanted from the printed report.

For instance, one NPD in the workqueue functions.

```
[   17.793908] BUG: kernel NULL pointer dereference, address: 0000000000000000
[   17.794222] #PF: supervisor read access in kernel mode
[   17.794405] #PF: error_code(0x0000) - not-present page
[   17.794637] PGD 0 P4D 0
[   17.794816] Oops: 0000 [#1] SMP NOPTI
[   17.795043] CPU: 0 PID: 119 Comm: exploit Not tainted 5.12.1 #18
[   17.795217] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS rel-1.14.0-0-g155821a1990b-prebuilt.qemu.org 04/01/2014
[   17.795543] RIP: 0010:__queue_work+0xb2/0x3b0
[   17.795728] Code: 8b 03 eb 2f 83 7c 24 04 40 0f 84 ab 01 00 00 49 63 c4 49 8b 9d 08 01 00 00 49 03 1c c6 4c 89 ff e8 73 fb ff ff 48 85 c0 74 d5 <48> 39 030
[   17.796191] RSP: 0018:ffffac4d8021fc20 EFLAGS: 00000086
[   17.796329] RAX: ffff9db3013af400 RBX: 0000000000000000 RCX: 0000000000000000
[   17.796545] RDX: 0000000000000000 RSI: 0000000000000003 RDI: ffffffffbdc4cf10
[   17.796769] RBP: 000000000000000d R08: ffff9db301400040 R09: ffff9db301400000
[   17.796926] R10: 0000000000000000 R11: ffffffffbdc4cf18 R12: 0000000000000000
[   17.797109] R13: ffff9db3021b4c00 R14: ffffffffbdb106a0 R15: ffff9db302260860
[   17.797328] FS:  00007fa9edf9d740(0000) GS:ffff9db33ec00000(0000) knlGS:0000000000000000
[   17.797541] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[   17.797699] CR2: 0000000000000000 CR3: 000000000225c000 CR4: 00000000001006f0
[   17.797939] Call Trace:
[   17.798694]  queue_work_on+0x1b/0x30
[   17.798865]  hci_sock_sendmsg+0x3bc/0x960
[   17.798973]  sock_sendmsg+0x56/0x60
[   17.799081]  sock_write_iter+0x92/0xf0
[   17.799170]  do_iter_readv_writev+0x145/0x1c0
[   17.799303]  do_iter_write+0x7b/0x1a0
[   17.799386]  vfs_writev+0x93/0x160
[   17.799527]  ? hci_sock_bind+0xbe/0x650
[   17.799638]  ? __sys_bind+0x8f/0xe0
[   17.799725]  ? do_writev+0x53/0x120
[   17.799804]  do_writev+0x53/0x120
[   17.799882]  do_syscall_64+0x33/0x40
[   17.799969]  entry_SYSCALL_64_after_hwframe+0x44/0xae
[   17.800186] RIP: 0033:0x7fa9ee08d35d
[   17.800405] Code: 28 89 54 24 1c 48 89 74 24 10 89 7c 24 08 e8 ca 26 f9 ff 8b 54 24 1c 48 8b 74 24 10 41 89 c0 8b 7c 24 08 b8 14 00 00 00 0f 05 <48> 3d 008
[   17.800798] RSP: 002b:00007ffe3c870e00 EFLAGS: 00000293 ORIG_RAX: 0000000000000014
[   17.800969] RAX: ffffffffffffffda RBX: 0000556f50a02f30 RCX: 00007fa9ee08d35d
[   17.801118] RDX: 0000000000000003 RSI: 00007ffe3c870ea0 RDI: 0000000000000005
[   17.801267] RBP: 00007ffe3c870ee0 R08: 0000000000000000 R09: 00007fa9edf87700
[   17.801413] R10: 00007fa9edf879d0 R11: 0000000000000293 R12: 0000556f50a00fe0
[   17.801560] R13: 00007ffe3c870ff0 R14: 0000000000000000 R15: 0000000000000000
[   17.801769] Modules linked in:
[   17.801928] CR2: 0000000000000000
[   17.802233] ---[ end trace 2bbc14e693eb3d8f ]---
[   17.802373] RIP: 0010:__queue_work+0xb2/0x3b0
[   17.802492] Code: 8b 03 eb 2f 83 7c 24 04 40 0f 84 ab 01 00 00 49 63 c4 49 8b 9d 08 01 00 00 49 03 1c c6 4c 89 ff e8 73 fb ff ff 48 85 c0 74 d5 <48> 39 030
[   17.802874] RSP: 0018:ffffac4d8021fc20 EFLAGS: 00000086
[   17.803019] RAX: ffff9db3013af400 RBX: 0000000000000000 RCX: 0000000000000000
[   17.803166] RDX: 0000000000000000 RSI: 0000000000000003 RDI: ffffffffbdc4cf10
[   17.803313] RBP: 000000000000000d R08: ffff9db301400040 R09: ffff9db301400000
[   17.803458] R10: 0000000000000000 R11: ffffffffbdc4cf18 R12: 0000000000000000
[   17.803605] R13: ffff9db3021b4c00 R14: ffffffffbdb106a0 R15: ffff9db302260860
[   17.803753] FS:  00007fa9edf9d740(0000) GS:ffff9db33ec00000(0000) knlGS:0000000000000000
[   17.803921] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[   17.804042] CR2: 0000000000000000 CR3: 000000000225c000 CR4: 00000000001006f0
```

The registers RDI, R11 and R14 seems store some kernel pointers. Taking a look at the System.map, you will find out the R14 is points to the global variable `__per_cpu_offset`. It will help us to calculate the KASLR offset and then bypass the protection.

```
ffffffff825106a0 R __per_cpu_offset
```

### Exploitation

#### RIP hijacking

With the KASLR bypassed, the next target is to hijack the control flow. To achieve this, the simplest thing is to compromise a code pointer (see below). That is, we have to spray the kernel heap to overwrite the released `hdev`. Thankfully, it is a piece of cake to spray as the `hdev` is one `kmalloc-8k` object. The big size makes its cache rather stable and I can easily spray the `hdev` with `setxattr` syscall.

```c
struct hci_dev {
...
	int (*open)(struct hci_dev *hdev);
	int (*close)(struct hci_dev *hdev);
	int (*flush)(struct hci_dev *hdev);
	int (*setup)(struct hci_dev *hdev);
	int (*shutdown)(struct hci_dev *hdev);
	int (*send)(struct hci_dev *hdev, struct sk_buff *skb);
	void (*notify)(struct hci_dev *hdev, unsigned int evt);
	void (*hw_error)(struct hci_dev *hdev, u8 code);
	int (*post_init)(struct hci_dev *hdev);
	int (*set_diag)(struct hci_dev *hdev, bool enable);
	int (*set_bdaddr)(struct hci_dev *hdev, const bdaddr_t *bdaddr);
	void (*cmd_timeout)(struct hci_dev *hdev);
	bool (*prevent_wake)(struct hci_dev *hdev);
};
```

Assuming we can overwrite the entire `hdev` and corrupt the above code pointers, can we achive RIP hijacking? Well. things don't seem to be so simple and these code pointers are used out of the USING routine.

```cpp
static int hci_sock_sendmsg(struct socket *sock, struct msghdr *msg,
			    size_t len)
{
...
	hdev = hci_pi(sk)->hdev;
	if (!hdev) {
		err = -EBADFD;
		goto done;
	}
...
	if (memcpy_from_msg(skb_put(skb, len), msg, len)) {
		err = -EFAULT;
		goto drop;
	}

	hci_skb_pkt_type(skb) = skb->data[0];
	skb_pull(skb, 1);

	if (hci_pi(sk)->channel == HCI_CHANNEL_USER) {
...
	} else if (hci_skb_pkt_type(skb) == HCI_COMMAND_PKT) {
...
		if (ogf == 0x3f) {
			skb_queue_tail(&hdev->raw_q, skb);
			queue_work(hdev->workqueue, &hdev->tx_work); // {4}
		} else {
			/* Stand-alone HCI commands must be flagged as
			 * single-command requests.
			 */
			bt_cb(skb)->hci.req_flags |= HCI_REQ_START;

			skb_queue_tail(&hdev->cmd_q, skb);
			queue_work(hdev->workqueue, &hdev->cmd_work); // {5}
		}
	} else {
		if (!capable(CAP_NET_RAW)) {
			err = -EPERM;
			goto drop;
		}
		
		skb_queue_tail(&hdev->raw_q, skb);
		queue_work(hdev->workqueue, &hdev->tx_work); // {4}
	}
...
}
```

As you can see, the `hci_sock_senmsg()` function doesn't call any code pointers but only uses some data candidates in `hdev`. We may have to compromise the data in `hdev` first and figure out how to affect the control flow.

Which candidate can we exploit? If you are familar with the workqueue in kernel, you may find the answer. Yes, the `work_struct`. The `hci_sock_sendmsg` function, as the handler of `send` syscall, will allocate the `skb` and queue it to corresponding `sk_buff` queues. It will then queue relevant `work_struct` to `hdev->workqueue` to issue these `skb`.

The layout of the `work_struct` is quite juicy.

```cpp
typedef void (*work_func_t)(struct work_struct *work);

struct work_struct {
	atomic_long_t data;
	struct list_head entry;
	work_func_t func;
#ifdef CONFIG_LOCKDEP
	struct lockdep_map lockdep_map;
#endif
};
```

Whoooo, `func` is a code pointer. As we can overwrite the entire `hdev`, we are able to compomise the `func` in either `hdev->cmd_work` or `hdev->tx_work` to allow control flow being controllered.

But I failed again.

This is because the `hdev->workqueue` is already destoryed is the `hci_unregister_dev()` function. The `work_struct` queued into this workqueue will not be scheduled at all.

Wait? didn't I say I can compromise the entire `hdev`? Why just I also compromise the `hdev->workqueue` to allow the planed attack?

It sounds like a plan but not an easy one for I have to leak the adress of one valid `workqueue_struct`. This is not like the KASLR offset leak as the `workqueue_struct` is allocated in the kernel slub caches. I need strong primitive to leak the heap layout and possibly find one living `workqueue_struct`.

After some fail attempts again, I decide to change my mind. I can use the original `hdev->workqueue` pointer to fulfill my want. Although the object it points to is currently destroyed, but we can "spray" the heap to put a new one there. This is the second spray in the exploit and interesting enough, this spray is not aim to overwrite data but provide qualified data.

> The spray for `workqueue_struct` (kmalloc-512 object) is much harder than the `hdev` because there are some other places keeping allocate this size of objects. To achieve the spray I play some sequence tricks and you can refer to the exploits for detail.

Well done, when the `workqueue` pointer is pointing to one living `workqueue_struct`, the `queue_work(hdev->workqueue, ...)` is assumed to be completed successfully. A little frustrated thing is that the `func` pointer in `work_struct` is behind the `workqueue` so we still cannot get the RIP for now. (We have to keep the `workeuque` the same)

It's fine because both the `hci_tx_work` function and the `hci_cmd_work` function will call the `hci_send_frame()`, which will call the `hdev->send(...)`, the code pointer that we can overwrite.

And I failed here again, the third time.

This is because we cannot easily exploit the time when the queued `work_struct` is being scheduled. As I said before, we cannot overwrite the `workqueue` before the `queue_work()` is finished. But we have to overwrite the code pointers before it is used.

```
====> overwrite the hdev
+--+-----------+-----+---------+----------+---------+-----+---------------+
   | workqueue | ... | rx_work | cmd_work | tx_work | ... | code pointers |
+--+-----------+-----+---------+----------+---------+-----+---------------+
```

This unpredictable time window makes the expoit rather unstable: I can rarely spray the `send` code pointer at the right time. What should we do? Is there any hope?

Of course it is, when god closes a door, he opens a window there. :)

The answer I picked is the `delayed_work` in `hci_cmd_work()` function.

```cpp
static void hci_cmd_work(struct work_struct *work)
{
	struct hci_dev *hdev = container_of(work, struct hci_dev, cmd_work);
...
		hdev->sent_cmd = skb_clone(skb, GFP_KERNEL);
		if (hdev->sent_cmd) {
			...
			if (test_bit(HCI_RESET, &hdev->flags))
				cancel_delayed_work(&hdev->cmd_timer);
			else
				schedule_delayed_work(&hdev->cmd_timer,
						      HCI_CMD_TIMEOUT); // {6}
		} else {
			skb_queue_head(&hdev->cmd_q, skb);
			queue_work(hdev->workqueue, &hdev->cmd_work);
		}
```

The `{6}` marked code starts a delayed work to handle the situation where the sent command is failed to receive proper reply in time. The most important thing here is this `HCI_CMD_TIMEOUT` is one predicatable time window.

```cpp
#define HCI_CMD_TIMEOUT		msecs_to_jiffies(2000)	/* 2 seconds */
```

Takine a further look at the `delayed_work` struct, you can find the juicy `work_struct` there.

```cpp
struct delayed_work {
	struct work_struct work;
	struct timer_list timer;

	/* target workqueue and CPU ->timer uses to queue ->work */
	struct workqueue_struct *wq;
	int cpu;
};
```

That is to say, we can wait for a predicatable delay and then start the overwriting to compromise the `work_struct` in the `delayed_work`. This steady time window can boost the success rate of our attack and finally we have our primitive to achieve RIP hijacking.

#### ROP

The ROP story is simpler compared with the above one, but also very interesting. The most interesting part is about the stack pivoting. 

```cpp
/* HCI command timer function */
static void hci_cmd_timeout(struct work_struct *work)
{
	struct hci_dev *hdev = container_of(work, struct hci_dev,
					    cmd_timer.work);
...
	if (hdev->cmd_timeout)
		hdev->cmd_timeout(hdev);
```

In the very first attempt, I stick into the original delay target function `hci_cmd_timeout` and take `hdev->cmd_timeout` as the target code pointer and try to find proper gadgets to pivot the stack to some place I can control. However, almost all pivoting gadgets count on the register rax.

For example, the popular one
```
0xffffffff81e0103f: mov rsp, rax; push r12; ret;
```

But the sad thing is the register rax is not controllable in `hci_cmd_timeout` function. (In fact, the indirect call is achieved by `__x86_indirect_thunk_rax` hence the rax is stored the gadget address).

This problem also makes me suffer for hours. Thanks to my friend @Nop, we finally find one very great pivoting solution.

```
   0xffffffff81060a41 <__efi64_thunk+81>:	mov    rsp,QWORD PTR [rsp+0x18]
   0xffffffff81060a46 <__efi64_thunk+86>:	pop    rbx
   0xffffffff81060a47 <__efi64_thunk+87>:	pop    rbp
   0xffffffff81060a48 <__efi64_thunk+88>:	ret
```

This part of code will update the rsp to the value stored in rsp+0x18. By corrupt the `delay_struct` to function `hci_error_reset` and take the `hdev->hw_error` as the critical code pointer, the `[rsp+0x18]` falls within the `hdev` object I expected.

```cpp
static void hci_error_reset(struct work_struct *work)
{
	struct hci_dev *hdev = container_of(work, struct hci_dev, error_reset);

	BT_DBG("%s", hdev->name);

	if (hdev->hw_error)
		hdev->hw_error(hdev, hdev->hw_error_code);
	else
		bt_dev_err(hdev, "hardware error 0x%2.2x", hdev->hw_error_code);
...
}
```

And the remain job is just standard kernel ROP. For demonstration purpose, I choose to corrupt the `modprobe_path` variable to allow root level arbitary code execution. You can play with this with provided demo.

open source: https://github.com/f0rm2l1n/ExP1oiT5/tree/main/CVE-2021-3573

## Story for patching

How will you guys fix this vulnerability? When I report this CVE, I provide the kernel with below patch.

```diff
---
 net/bluetooth/hci_sock.c | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/net/bluetooth/hci_sock.c b/net/bluetooth/hci_sock.c
index 251b9128f530..eed0dd066e12 100644
--- a/net/bluetooth/hci_sock.c
+++ b/net/bluetooth/hci_sock.c
@@ -762,7 +762,7 @@ void hci_sock_dev_event(struct hci_dev *hdev, int event)
 		/* Detach sockets from device */
 		read_lock(&hci_sk_list.lock);
 		sk_for_each(sk, &hci_sk_list.head) {
-			bh_lock_sock_nested(sk);
+			lock_sock(sk);
 			if (hci_pi(sk)->hdev == hdev) {
 				hci_pi(sk)->hdev = NULL;
 				sk->sk_err = EPIPE;
@@ -771,7 +771,7 @@ void hci_sock_dev_event(struct hci_dev *hdev, int event)
 
 				hci_dev_put(hdev);
 			}
-			bh_unlock_sock(sk);
+			release_sock(sk);
 		}
 		read_unlock(&hci_sk_list.lock);
 	}
-- 
2.30.2
```

From my point of view, the root cause of this BUG is that the device detaching routine drop the refcnt of `hdev` without giving concern that other routine may still use it (`hci_sock_bound_ioctl` and `hci_sock_sendmsg`).

Hence, as the USING routine will use `lock_sock` to defend against the race, I replace the `bh_lock_sock` to `lock_sock` too to serialize these affiars. With this fix, my POC won't cause any KASan report and I think this is a very proper patch.

But I failed, one more time.

Because I am just a noob of the kernel locking mechanism, I just make a huge mistake in this patch: the `lock_sock` here violates the kernel atomoic lock rules and it may lead to dead lock (I really didn't know this when designing the patch T.T).

And what's worse, the kernel community is happy to adopt this patch without much hesitation.

The disaster shows itself about a week after the patch is merged to the mainline. I started to receive email that tells me the patch is ridiculous. The very first one is [Anand K. Mistry](https://github.com/akmistry) from Google Australia, he showed me the report from his computer and explained me the possibility of the dead lock.

After that, more and more developers are start to give their concern. One big reason for that is the syzkaller keeps generating the fuzzing report for this misused lock.

>
> Also, this regression is currently 7th top crashers for syzbot
>

I am just feel too ashamed to bring this trouble XD. Several discussions are raised to solve this and I have to say sorry that I failed to reply with some emails timely because I had to handle the exam week in school. Below are some links you guys can follow to catch up.

https://lore.kernel.org/linux-bluetooth/nycvar.YFH.7.76.2107131924280.8253@cbobk.fhfr.pm/
https://www.spinics.net/lists/linux-bluetooth/msg92649.html
https://marc.info/?l=linux-bluetooth&m=162441276805113&w=2
https://marc.info/?l=linux-bluetooth&m=162653675414330&w=2

The point is this race condition is not an easy fixed one (Check these links to find the intense discussion). Thanks to kernel developer Tetsuo Handa, and the maintainer [Luiz](https://github.com/Vudentz), I think the proper patch will soon be settled down.

You can do your own selection before that: https://lkml.kernel.org/r/05535d35-30d6-28b6-067e-272d01679d24@i-love.sakura.ne.jp

## Conclusion

I've learnt a lot during my first 0-day exploit and all this is just beautiful like an art. 

Of course, this bug is not a very perfect one as it asks CAP_NET_ADMIN privilege and the fullchain requires the attacker to compromise one daemon first.

This is the inherent flaws for exploiting local Linux BT stack. You can to get this privilege to emulate a userspace controller or you have to use a real one. The better vulnerabilities should be like as the [BleedingTooth](https://github.com/google/security-research/tree/master/pocs/linux/bleedingtooth), which requires nothing and can achieve code execution remotely.

That type of bugs will be our utilimate goals.