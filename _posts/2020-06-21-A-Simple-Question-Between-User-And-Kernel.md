---
layout: post
category: "deprecated"
---

## 注

围绕一个简单的小实验：内核释放的页，有可能让用户拿到么？现在回来看，感觉还是有点浅尝辄止，只观察了现象，并没有深入解释为什么会是这样的现象 XD

## 原文

> Hi there, May I ask you a simple question? :P. "Whether or not can an user fetch memory page that is released by the kernel?". Do you have your quick answer in mind?
>
> Well, the answer is "Yes". We will talk about that in this post (3.18 kernel for this time ;D).
>
 
## Kernel Memory Releasing

For clarity, we choose *sla/o/ub dynamic allocator* as our research target, which is widely used in the kernel source code to allocate a small region of memory.

Of course, we need to get familiar with the slab first. Maybe I will write something about that in the future while this time you'd better refer to other blogs, like [this](https://lwn.net/Articles/229984/). Also, you can read the book[^2] by Gorman. At last but not least, I prefer to watch talk[^3] and surf through the source code, which I believe is the most efficient way.

Never mind, suppose you know about what slab is and how that works. Let's get deeper.

Read the source code from `kmem_cache_free()`, we try to seek out where and how a slab page is dropped. 

```c++
// mm/slub.c 
void kmem_cache_free(struct kmem_cache *s, void *x)
{
	s = cache_from_obj(s, x);
	if (!s)
		return;
	slab_free(s, virt_to_head_page(x), x, _RET_IP_);
	trace_kmem_cache_free(_RET_IP_, x);
}
```

Okay, we get the `kmem_cache` struct, which is responsible for organizing slabs. And then `slab_free()` is called.

```c++
// mm/slub.c
/*
 * Fastpath with forced inlining to produce a kfree and kmem_cache_free that
 * can perform fastpath freeing without additional function calls.
 *
 * The fastpath is only possible if we are freeing to the current cpu slab
 * of this processor. This typically the case if we have just allocated
 * the item before.
 *
 * If fastpath is not possible then fall back to __slab_free where we deal
 * with all sorts of special processing.
 */
static __always_inline void slab_free(struct kmem_cache *s,
			struct page *page, void *x, unsigned long addr)
{
	void **object = (void *)x;
	struct kmem_cache_cpu *c;
	unsigned long tid;

	slab_free_hook(s, x);

redo:
	/*
	 * Determine the currently cpus per cpu slab.
	 * The cpu may change afterward. However that does not matter since
	 * data is retrieved via this pointer. If we are on the same cpu
	 * during the cmpxchg then the free will succedd.
	 */
	preempt_disable();
	c = this_cpu_ptr(s->cpu_slab);

	tid = c->tid;
	preempt_enable();

	if (likely(page == c->page)) {
		set_freepointer(s, object, c->freelist);

		if (unlikely(!this_cpu_cmpxchg_double(
				s->cpu_slab->freelist, s->cpu_slab->tid,
				c->freelist, tid,
				object, next_tid(tid)))) {

			note_cmpxchg_failure("slab_free", s, tid);
			goto redo;
		}
		stat(s, FREE_FASTPATH);
	} else
		__slab_free(s, page, x, addr);
} 
```

These two situations will result in calling `__slab_free()` which is what we want. The first is the target slab object does not belong to the current used CPU. (For slub, each CPU has its own discipline) The second is current CPU's `kmem_cache_cpu->page` is pointing another slab page, or to say, the object prepared to be freed in not in the current in-use slab. Instead of just linking the target object in the current slab's freelist, the `__slab_free()` take in charge.

The `__slab_free()` is a long function. For this time's topic, we just explain it in a rough way: First it will obtain the real freelist that in the same slab with the target object. Then it inject the target to the freelist, adjust some metadatas as well. 

What we concerned about here is that when the free object is the last object in this slab, it will lead to a free slab. If below reuirements is fulfilled, the kernel will then discard this slab.
```c++
if (unlikely(!new.inuse && n->nr_partial >= s->min_partial))
    goto slab_empty;
```

Here `new` represents the page structure, while `n` for `kmem_cache_node`, used to store extra partial free slab pages for this slab. If the page is not used anymore (all free) and the number of current partial free slab pages is bigger than the standard, denoted by the `s->min_partial`, the page can then be discarded.

Okay, let's go into page dicarding path, `discard_slab()` as the first one.

```c++
// mm/slub.c
static void discard_slab(struct kmem_cache *s, struct page *page)
{
	dec_slabs_node(s, page_to_nid(page), page->objects);
	free_slab(s, page);
}
```

Cool, this function deals with some data calculation and then enters into `free_slab()`.

```c++
// mm/slub.c
static void free_slab(struct kmem_cache *s, struct page *page)
{
	if (unlikely(s->flags & SLAB_DESTROY_BY_RCU)) {
		struct rcu_head *head;

		if (need_reserve_slab_rcu) {
			int order = compound_order(page);
			int offset = (PAGE_SIZE << order) - s->reserved;

			VM_BUG_ON(s->reserved != sizeof(*head));
			head = page_address(page) + offset;
		} else {
			/*
			 * RCU free overloads the RCU head over the LRU
			 */
			head = (void *)&page->lru;
		}

		call_rcu(head, rcu_free_slab);
	} else
		__free_slab(s, page);
}
```

There are two main branches in `free_slab()`, dependent on whether or not this `kmem_cache` is created with `SLAB_DESTROY_BY_RCU` flag. I hate the RCU kinds of stuff and thankfully, most slabs are created without that horrible flag value.

Anyway, both rcu path and non-rcu path will falls into `__free_slab()` function.

```c++
// mm/slub.c
static void __free_slab(struct kmem_cache *s, struct page *page)
{
	int order = compound_order(page);
	int pages = 1 << order;

	if (kmem_cache_debug(s)) {
		void *p;

		slab_pad_check(s, page);
		for_each_object(p, s, page_address(page),
						page->objects)
			check_object(s, page, p, SLUB_RED_INACTIVE);
	}

	kmemcheck_free_shadow(page, compound_order(page));

	mod_zone_page_state(page_zone(page),
		(s->flags & SLAB_RECLAIM_ACCOUNT) ?
		NR_SLAB_RECLAIMABLE : NR_SLAB_UNRECLAIMABLE,
		-pages);

	__ClearPageSlabPfmemalloc(page);
	__ClearPageSlab(page);

	page_mapcount_reset(page);
	if (current->reclaim_state)
		current->reclaim_state->reclaimed_slab += pages;
	__free_pages(page, order);
	memcg_uncharge_slab(s, order);
}
```

There are several unfamiliar and weird functions. Ignoring the debug function, the kmemcheck support, and functions for adjusting metadata, the `__free_pages()` is what we expected. This function will sequentially call `free_hot_cold_page()` or `__free_pages_ok` depends the `order`.

It's a pity that we won't get into these two functions further, as the Linux Buddy System is a whole mess for me. What we know for now is that the dynamic slab pages shall be returned to the Buddy system through the above code path.

## User Memoy Fetching

Okay, the discarded kernel memory is right there in the Buddy system! As a malicious user, how can we come out with solutions to fetch that page?

Well, roughly thinking, the page we desired is already returned to the system, so if we keep asking for a new page, we can obtain this page one day. 

And the solution, of course, is nothing but spraying.

The are several applicable ways for a user to ask the Buddy system for more memory pages, like `brk`, `shmget` and `remap_file_pages`. However, as the former work has lighten us, `mmap` system call with `MAP_ANONYMOUS` is the most preferred one.

About how `mmap` system call fetch pages from the Buddy system, you can refer to another [blog](./Thorough-Understanding-With-Anonymous-MMAP) of mine for a quick glance. In short, the `mmap` system call will create mapping for the user and the indeed page allocation is handled by Linux page fault handler.

## Experiment

So far so good (bad), we have two paths in hand, one for how the slab page is released (`__free_pages()`) and another for how page fault handler allocates (`__alloc_pages_nodemask()`). The bad news is that these paths are entering into the Linux Buddy system, a really complex one (I mean source code here).

But just remember what is our goal: we just want to figure out if or not the user can fetch the page discarded by the Linux kernel. To figure that out, we can just do a simple experiment.

First we can prepare an easy `misc` Linux driver as below:

```c++
// test.c
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <asm/uaccess.h>
#include <linux/sched.h>
#include <linux/uidgid.h>
#include <linux/miscdevice.h>

#define TEST_IOCTL_ALLOC     0x0101
#define TEST_IOCTL_RELEASE   0x0102
#define TEST_IOCTL_TEST      0x0103

static struct kmem_cache* global_cache;
static char pattern[16];

static int test_open(struct inode* inode, struct file* file)
{
        return 0;
}

static int test_close(struct inode* inode, struct file* file)
{
        return 0;
}

static unsigned long poison_check(void* addr)                                            
{                                                                                      
        int i, confirm = 0;                                                           
        for(i = 0; i < 0x1000; i += 16) {                                              
                if(!memcmp((char*)addr + i, pattern, 16)) {                            
                        confirm = 1;                                                   
                        break;                                                         
                }                                                                      
        }                                                                              
        return confirm;                                                                
}                                                                                      

static long test_ioctl(struct file* file, unsigned long cmd, unsigned long arg)
{
        void* obj;
        unsigned long ret = 0;
        switch(cmd) {
                case TEST_IOCTL_ALLOC:
                        obj = kmem_cache_alloc(global_cache, GFP_KERNEL);
                        if (obj != NULL) {
                            copy_to_user(arg, &obj, sizeof(unsigned long));
                        }
                        else
                                ret = -ENOMEM;
                        break;
                case TEST_IOCTL_RELEASE:
                        kfree((void*)arg);
                        break;
                case TEST_IOCTL_TEST:
                        // obj test user payload if fill
                        ret = poison_check(arg);
                        break;
        }
        return ret;
}

static const struct file_operations test_operations = {
        .owner          = THIS_MODULE,
        .unlocked_ioctl = test_ioctl,
        .open           = test_open,
        .release        = test_close,
};                                            

struct miscdevice test_device = {
        .minor = MISC_DYNAMIC_MINOR,
        .name = "test_misc_device",
        .fops = &test_operations,
};

static int __init test_init(void)
{
        int error;
        error = misc_register(&test_device);
        if (error) {
                pr_err("cant register the misc device.\n");
                return error;
        }

        global_cache = kmem_cache_create("testing", 1400, 0, SLAB_HWCACHE_ALIGN, NULL);
        if (!global_cache) {
                pr_err("cant crate cache.\n");
                misc_deregister(&test_device);
                return -ENOMEM;
        }
        // prepare for pattern
        unsigned int _pattern = 0xdeadbeaf;                                                            
        for(i = 0; i < 4; i++)  
                memcpy((char*)pattern + i * 4, &_pattern, 4)

        pr_info("successfully register the misc device. minor = %d\n", test_device.minor);
        return 0;
}

static void __exit test_exit(void)
{
        kmem_cache_destroy(global_cache);
        misc_deregister(&test_device);
        pr_info("successfully unregister the misc device.\n");
}

module_init(test_init);
module_exit(test_exit);

MODULE_DESCRIPTION("Misc Driver For Test");
MODULE_AUTHOR("f0rm2l1n");
MODULE_LICENSE("GPL");
```

And of course the scripts to interact with this misc device.

```c++
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stropts.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/mman.h>

#define TEST_IOCTL_ALLOC     0x0101
#define TEST_IOCTL_RELEASE   0x0102
#define TEST_IOCTL_TEST      0x0103

#define TEST_BOUNDARY   (8192 * 24)

// 1 page = 4096, then 4096 / 512 = 8 objects
void* maps[TEST_BOUNDARY];

int main(int argc, char* argv[])
{
        if (argc != 2) {
                printf("Usage ./interactive PATH_TO_DEVICE\n");
                return -1;
        }
        int i;
        unsigned int pattern = 0xdeadbeaf;
        int fd = open(argv[1], O_RDONLY);
        if (fd < 0) {
                printf("failed to open device %s\n", argv[1]);
                return -1;
        }
        unsigned long res;
        for(i = 0; i < TEST_BOUNDARY; i++) {
                res = ioctl(fd, TEST_IOCTL_ALLOC, &maps[i]);
                if (res != 0) {
                        perror("ioctl alloc");
                        exit(EXIT_FAILURE);
                }
        }
        // free half
        for(i = 0; i < TEST_BOUNDARY / 2; i++) {
                ioctl(fd, TEST_IOCTL_RELEASE, maps[i]);
        }
        // starts mmap
        for (i = 0; i < 48; i++) {
                // 16 MB a time
                void* addr = mmap(0, 16 * (1024 * 1024), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
                if (addr < 0) {
                        perror("Error in mmap");
                        break;
                }
                // pisoning
                for(unsigned long j = 0; j < (16 * 1024 * 1024); j += 4) {
                        memcpy((char*)addr + j, &pattern, 4);
                }
        }

        printf("start testing\n");
        for(int i = 0; i < TEST_BOUNDARY; i++) {
                if (i % 6400 == 0) printf("test index-%d\n", i);
                unsigned long ret = ioctl(fd, TEST_IOCTL_TEST, maps[i]);
                if (ret != 0) {
                        printf("index-%d successfully leaked..\n", i);
                }
        }
        printf("end testing\n");
        // free remain
        for(i = TEST_BOUNDARY / 2; i < TEST_BOUNDARY; i++)
                ioctl(fd, TEST_IOCTL_RELEASE, maps[i]);

        close(fd);
        return 0;
}
```

So what are we going to do? We develop a `misc` device whose ioctl allows users to indirectly call `kmalloc()` and `kfree()`. Thus the script can create a number of kernel objects in the slab and free parts of them in follow, which results in slab page discarding we mentioned above. After some pages have already been returned to the Buddy system, the script then starts to call `mmap` and asks for lots of large memory pages (16 MB in one time for this example). That is, spraying the Buddy system. Each time the `mmap` returns, the script will write `0xdeadbeaf` pattern to trigger page fault and poison those allocated pages. For verification, we ask the driver to read the freed slab page and find the pattern written in userspace. Once the pattern is identified, the conclusion of successful fetching is confirmed.

Okay! What's the result? Just try out this experiment on your own machine.

P.S. You may need to adjust some parameters to succeed in a large memory circumstance.

## Conclusion

Okay, the question I ask is already settled down. But we do not end now... Why we do this? What will happen if a user can fetch the memory page that kernel has discarded? Thinking about that carefully, the direct answer comes in mind is "leaking". If a hacker can fetch the page used to store kernel data, maybe he can obtain some information to enlarge the attack surface. 

Unfortunately, things won't go that easy. Just remember that whem we call anonymous `mmap`, the page allocate in below way.
```c++
page = alloc_zeroed_user_highpage_movable(vma, address);
```
which is a wrapper below in x86 architecture.
```c++
alloc_page_vma(GFP_HIGHUSER | __GFP_ZERO | movableflags, vma, vaddr)
```

Damn, `__GFP_ZERO`, the page fault handler will erase the entire page when doing page table construction. That is to say, all sensitive data we want just be cleared to zero.

But don't be sad, the fetching is still a strong primitive for hacking the kernel. Just imaging that we have a kernel-level use after free, and the freed object is fetchable in userspace, we can then easily construct malicious fake data structure in our mapped page.

And what is interesting, this attack method has been proposed in Usenix 2014[^4] and named as `ret2dir`. By adopting this attack, the hacker can bypass existing protection including SMEP and SMAP.

But all in all, the basic idea is quite simple: you discard the page, and I want it!

***

[^1]: Slub Allocator. [LINK](https://lwn.net/Articles/229984/)

[^2]: Understanding the Linux Virtual Memory Manager. by Mel Gorman. [LINK](https://www.amazon.com/Understanding-Linux-Virtual-Memory-Manager/dp/0131453483)

[^3]: SL(AUO)B: Kernel Memory Allocator design and philosophy. [LINK](https://www.youtube.com/watch?v=h0VMLXavx30&t=1146s)

[^4]: ret2dir: rethinking Kernel Isolation.
