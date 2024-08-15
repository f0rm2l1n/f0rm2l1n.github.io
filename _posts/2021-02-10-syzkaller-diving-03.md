---
layout: post
category: "deprecated"
---

## 注

如果没记错，当时写 remote coverage 的时候还是比较新的东西，当时使用的也比较少。不像现在，skb 有关的 fuzzing 都已经配备了 remote coverage，像 nfc 的测试也已经支持了。不过，前后台 coverage 的区分和加权似乎没有进一步的解决方案。

## Background

In the very [first post](./syzkaller-diving-01), we talked about the `KCOV` and when we looked up the source code of syzkaller we found some functions related to "remote" `KCOV`. In this post, I will briefly introduce what it is, and how syzkaller adopts it in external USB fuzzing.

## Remote KCOV 101

At early days, part of the definition of `KCOV` is presented below

> Note that kcov does not aim to collect as much coverage as possible. It aims to collect more or less stable coverage that is function of syscall inputs. To achieve this goal *it does not collect coverage in soft/hard interrupts* and instrumentation of some inherently non-deterministic parts of kernel is disabled (e.g. scheduler, locking).

That is to say, `KCOV` selectively collect coverage from dedicated code regions. In another word, the `KCOV`-based fuzzer can miss the guide when entering into code like soft/hard interrupts.

Back to our first post, you can see that `__sanitizer_cov_trace_pc` collects coverage for `current` process, and during the fuzzing loop, this process will interact with `/sys/kernel/debug/kcov` to obtain the coverage. However, in the kernel space, many tasks (above interrupt for example) are handled by a background thread, which does not have essentially user space context. 

This kinda problem will not bother a vanilla system call fuzzer. However, if a security researcher wants to fuzz some other interesting subsystems of the kernel, it indeed leaves a challenge.

To solve this, an extra patch is added, named remote `KCOV`, by syzkaller to fuzz the external USB system (will discuss this later on). The basic of idea is allowing the developer to add dedicated coverage-collect-start mark and coverage-collect-end mark. With these marks, the `KCOV` can be reminded to collect coverage for the background thread and strore the coverage information for the mark specified region. Later on, the user space program can interact with the `/sys/kernel/debug/kcov` and get the collected coverage using special `handle`.

We will look up the source code to understand this. Below comment is quite clearly to form a basic understanding.

```cpp
/*
 * kcov_remote_start() and kcov_remote_stop() can be used to annotate a section
 * of code in a kernel background thread or in a softirq to allow kcov to be
 * used to collect coverage from that part of code.
 *
 * The handle argument of kcov_remote_start() identifies a code section that is
 * used for coverage collection. A userspace process passes this handle to
 * KCOV_REMOTE_ENABLE ioctl to make the used kcov device start collecting
 * coverage for the code section identified by this handle.
 *
 * The usage of these annotations in the kernel code is different depending on
 * the type of the kernel thread whose code is being annotated.
 *
 * For global kernel threads that are spawned in a limited number of instances
 * (e.g. one USB hub_event() worker thread is spawned per USB HCD) and for
 * softirqs, each instance must be assigned a unique 4-byte instance id. The
 * instance id is then combined with a 1-byte subsystem id to get a handle via
 * kcov_remote_handle(subsystem_id, instance_id).
 *
 * For local kernel threads that are spawned from system calls handler when a
 * user interacts with some kernel interface (e.g. vhost workers), a handle is
 * passed from a userspace process as the common_handle field of the
 * kcov_remote_arg struct (note, that the user must generate a handle by using
 * kcov_remote_handle() with KCOV_SUBSYSTEM_COMMON as the subsystem id and an
 * arbitrary 4-byte non-zero number as the instance id). This common handle
 * then gets saved into the task_struct of the process that issued the
 * KCOV_REMOTE_ENABLE ioctl. When this process issues system calls that spawn
 * kernel threads, the common handle must be retrieved via kcov_common_handle()
 * and passed to the spawned threads via custom annotations. Those kernel
 * threads must in turn be annotated with kcov_remote_start(common_handle) and
 * kcov_remote_stop(). All of the threads that are spawned by the same process
 * obtain the same handle, hence the name "common".
 *
 * See Documentation/dev-tools/kcov.rst for more details.
 *
 * Internally, kcov_remote_start() looks up the kcov device associated with the
 * provided handle, allocates an area for coverage collection, and saves the
 * pointers to kcov and area into the current task_struct to allow coverage to
 * be collected via __sanitizer_cov_trace_pc().
 * In turns kcov_remote_stop() clears those pointers from task_struct to stop
 * collecting coverage and copies all collected coverage into the kcov area.
 */
```

Pretty explanatory comment huh? In addition, the content of `Documentation/dev-tools/kcov.rst` can also help.

> This allows to collect coverage from two types of kernel background threads: the global ones, that are spawned during kernel boot in a limited number of instances (e.g. one USB hub_event() worker thread is spawned per USB HCD); and the local ones, that are spawned when a user interacts with some kernel interface (e.g. vhost workers).

Okay, talk is cheap and you may want to see some code example (from the Documentation).

```cpp
int main(int argc, char **argv)
{
    int fd;
    unsigned long *cover, n, i;
    struct kcov_remote_arg *arg;

    fd = open("/sys/kernel/debug/kcov", O_RDWR);
    if (fd == -1)
            perror("open"), exit(1);
    if (ioctl(fd, KCOV_INIT_TRACE, COVER_SIZE))
            perror("ioctl"), exit(1);
    cover = (unsigned long*)mmap(NULL, COVER_SIZE * sizeof(unsigned long),
                                 PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if ((void*)cover == MAP_FAILED)
            perror("mmap"), exit(1);
```

Until here, everything seems the same. You need to open the `KCOV` file, init the trace and map a share buffer. The difference is presented in following code.

```cpp
    /* Enable coverage collection via common handle and from USB bus #1. */
    arg = calloc(1, sizeof(*arg) + sizeof(uint64_t)); // -- +sizeof(uint64_t) means one handler in array
    if (!arg)
            perror("calloc"), exit(1);
    arg->trace_mode = KCOV_TRACE_PC;
    arg->area_size = COVER_SIZE;
    arg->num_handles = 1;
    arg->common_handle = kcov_remote_handle(KCOV_SUBSYSTEM_COMMON,
                                                    KCOV_COMMON_ID);    // register a common handle
    arg->handles[0] = `kcov_remote_handle`(KCOV_SUBSYSTEM_USB,
                                            KCOV_USB_BUS_NUM);          // register a remote handle
    if (ioctl(fd, KCOV_REMOTE_ENABLE, arg))
            perror("ioctl"), free(arg), exit(1);
    free(arg);
```

This code snippet shows us how to prepare remote `kcov_remote_arg` arguments. 

```cpp
struct kcov_remote_arg {
    __u32           trace_mode;
    __u32           area_size;
    __u32           num_handles;
    __aligned_u64   common_handle;  // common handle for local  case;
    __aligned_u64   handles[0];     // remote handle for global case; dynamic array here
};
```

Here, the `KCOV_COMMON_ID` and `KCOV_USB_BUS_NUM` are prepared by the user himself while `KCOV_SUBSYSTEM_COMMON` and `KCOV_SUBSYSTEM_USB` are prepared by the `KCOV`. The `kcov_remote_handle` just splice them into one `u64` variable.

```cpp
// include/uapi/linux/kcov.h
#define KCOV_SUBSYSTEM_COMMON	(0x00ull << 56)
#define KCOV_SUBSYSTEM_USB	(0x01ull << 56)

#define KCOV_SUBSYSTEM_MASK	(0xffull << 56)
#define KCOV_INSTANCE_MASK	(0xffffffffull)

static inline __u64 kcov_remote_handle(__u64 subsys, __u64 inst)
{
	if (subsys & ~KCOV_SUBSYSTEM_MASK || inst & ~KCOV_INSTANCE_MASK) // -- subsystem | instance 
		return 0;
	return subsys | inst;
}
```

> At least we know that we have to define new subsys variable if we want to fuzz other part of code.

We continually look at this example code.

```cpp
    /*
     * Here the user needs to trigger execution of a kernel code section
     * that is either annotated with the common handle, or to trigger some
     * activity on USB bus #1.
     */
    sleep(2);
```

This example doesn't offer us any "trigger" code. Maybe this is the charming part of external fuzzing.

```cpp
    n = __atomic_load_n(&cover[0], __ATOMIC_RELAXED);
    for (i = 0; i < n; i++)
            printf("0x%lx\n", cover[i + 1]);
    if (ioctl(fd, KCOV_DISABLE, 0))
            perror("ioctl"), exit(1);
    if (munmap(cover, COVER_SIZE * sizeof(unsigned long)))
            perror("munmap"), exit(1);
    if (close(fd))
            perror("close"), exit(1);
    return 0;
}
```

The last part of the example is also very alike to the standard `KCOV`: read the shared buffer, use `ioctl` to disable the collection, and unmap the buffer, blabla.

After we take this peek at how userspace code works with the remote `KCOV`, let's see how kernel cooperate with this.

```cpp
static long kcov_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
{
	struct kcov *kcov;
	int res;
	struct kcov_remote_arg *remote_arg = NULL;
	unsigned int remote_num_handles;
	unsigned long remote_arg_size;
	unsigned long flags;

	if (cmd == KCOV_REMOTE_ENABLE) { // special one
		if (get_user(remote_num_handles, (unsigned __user *)(arg +
				offsetof(struct kcov_remote_arg, num_handles))))
			return -EFAULT;
		if (remote_num_handles > KCOV_REMOTE_MAX_HANDLES)
			return -EINVAL;
		remote_arg_size = struct_size(remote_arg, handles,
					remote_num_handles);
		remote_arg = memdup_user((void __user *)arg, remote_arg_size);
		if (IS_ERR(remote_arg))
			return PTR_ERR(remote_arg);
		if (remote_arg->num_handles != remote_num_handles) {
			kfree(remote_arg);
			return -EINVAL;
		}
		arg = (unsigned long)remote_arg; // -- For normal `KCOV_ENABLE`, arg can just be 0
	}

	kcov = filep->private_data;
	spin_lock_irqsave(&kcov->lock, flags);
	res = kcov_ioctl_locked(kcov, cmd, arg); // -- To next level
	spin_unlock_irqrestore(&kcov->lock, flags);

	kfree(remote_arg);

	return res;
}
```

Attenion, for normal `KCOV_ENABLE`, no special arguments are required. But for the `KCOV_REMOTE_ENABLE` part, some code of argument retrieving is essential.

```cpp
static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
			     unsigned long arg)
{
	struct task_struct *t;
	unsigned long size, unused;
	int mode, i;
	struct kcov_remote_arg *remote_arg;
	struct kcov_remote *remote;
	unsigned long flags;

	switch (cmd) {
    /* ... */
	case KCOV_REMOTE_ENABLE:
		if (kcov->mode != KCOV_MODE_INIT || !kcov->area)
			return -EINVAL;
		t = current;
		if (kcov->t != NULL || t->kcov != NULL)
			return -EBUSY;
		remote_arg = (struct kcov_remote_arg *)arg;
		mode = kcov_get_mode(remote_arg->trace_mode);
		if (mode < 0)
			return mode;
		if (remote_arg->area_size > LONG_MAX / sizeof(unsigned long))
			return -EINVAL;
		kcov->mode = mode;
		t->kcov = kcov;
		kcov->t = t;
		kcov->remote = true;
		kcov->remote_size = remote_arg->area_size;
		spin_lock_irqsave(&kcov_remote_lock, flags);
		for (i = 0; i < remote_arg->num_handles; i++) {
			if (!kcov_check_handle(remote_arg->handles[i],
						false, true, false)) {
				spin_unlock_irqrestore(&kcov_remote_lock,
							flags);
				kcov_disable(t, kcov);
				return -EINVAL;
			}
			remote = kcov_remote_add(kcov, remote_arg->handles[i]);
			if (IS_ERR(remote)) {
				spin_unlock_irqrestore(&kcov_remote_lock,
							flags);
				kcov_disable(t, kcov);
				return PTR_ERR(remote);
			}
		}
		if (remote_arg->common_handle) {
			if (!kcov_check_handle(remote_arg->common_handle,
						true, false, false)) {
				spin_unlock_irqrestore(&kcov_remote_lock,
							flags);
				kcov_disable(t, kcov);
				return -EINVAL;
			}
			remote = kcov_remote_add(kcov,
					remote_arg->common_handle);
			if (IS_ERR(remote)) {
				spin_unlock_irqrestore(&kcov_remote_lock,
							flags);
				kcov_disable(t, kcov);
				return PTR_ERR(remote);
			}
			t->kcov_handle = remote_arg->common_handle;
		}
		spin_unlock_irqrestore(&kcov_remote_lock, flags);
		/* Put either in kcov_task_exit() or in KCOV_DISABLE. */
		kcov_get(kcov);
		return 0;
	default:
		return -ENOTTY;
	}
}
```

The `kcov_ioctl_locked` is going to add the coverage collection handler for global threads and local threads. 

For both of them
- assign trace mode (PC or CMP)
- assign `kcov` manager struct to the `task_struct` 
- some essential arguments like `area_size`
- do `kcov_check_handle`
- call `kcov_remote_add`

For local background thread only
- update `task_struct->kcov_handle` with input arguement

We keep going~

```cpp
/*
 * kcov descriptor (one per opened debugfs file).
 * State transitions of the descriptor:
 *  - initial state after open()
 *  - then there must be a single ioctl(KCOV_INIT_TRACE) call
 *  - then, mmap() call (several calls are allowed but not useful)
 *  - then, ioctl(KCOV_ENABLE, arg), where arg is
 *	KCOV_TRACE_PC - to trace only the PCs
 *	or
 *	KCOV_TRACE_CMP - to trace only the comparison operands
 *  - then, ioctl(KCOV_DISABLE) to disable the task.
 * Enabling/disabling ioctls can be repeated (only one task a time allowed).
 */
struct kcov {
	/*
	 * Reference counter. We keep one for:
	 *  - opened file descriptor
	 *  - task with enabled coverage (we can't unwire it from another task)
	 *  - each code section for remote coverage collection
	 */
	refcount_t		refcount;
	/* The lock protects mode, size, area and t. */
	spinlock_t		lock;
	enum kcov_mode		mode;
	/* Size of arena (in long's). */
	unsigned int		size;
	/* Coverage buffer shared with user space. */
	void			*area;
	/* Task for which we collect coverage, or NULL. */
	struct task_struct	*t;
	/* Collecting coverage from remote (background) threads. */
	bool			remote;
	/* Size of remote area (in long's). */
	unsigned int		remote_size;
	/*
	 * Sequence is incremented each time kcov is reenabled, used by
	 * kcov_remote_stop(), see the comment there.
	 */
	int			sequence;
};

struct kcov_remote_area {
	struct list_head	list;
	unsigned int		size;
};

struct kcov_remote {
	u64			handle;
	struct kcov		*kcov;
	struct hlist_node	hnode;
};

// ...

/* Must be called with kcov_remote_lock locked. */
static struct kcov_remote *kcov_remote_add(struct kcov *kcov, u64 handle)
{
	struct kcov_remote *remote;

	if (kcov_remote_find(handle))
		return ERR_PTR(-EEXIST);
	remote = kmalloc(sizeof(*remote), GFP_ATOMIC);
	if (!remote)
		return ERR_PTR(-ENOMEM);
	remote->handle = handle;
	remote->kcov = kcov;
	hash_add(kcov_remote_map, &remote->hnode, handle);
	return remote;
}
```
To add this reomte one, `kcov_remote` will be allocated and added to hash list. The most important candidate of this struct is `remote->handle`.

Cool, so far we are seemed to finish the very first job. We will then see how the special marks `kcov_remote_start()`/`kcov_remote_stop()` work.

```cpp
void kcov_remote_start(u64 handle)
{
	struct task_struct *t = current;
	struct kcov_remote *remote;
	struct kcov *kcov;
	unsigned int mode;
	void *area;
	unsigned int size;
	int sequence;
	unsigned long flags;

	if (WARN_ON(!kcov_check_handle(handle, true, true, true)))
		return;
	if (!in_task() && !in_serving_softirq())
		return;

	local_irq_save(flags);

	/*
	 * Check that kcov_remote_start() is not called twice in background
	 * threads nor called by user tasks (with enabled kcov).
	 */
	mode = READ_ONCE(t->kcov_mode);
	if (WARN_ON(in_task() && kcov_mode_enabled(mode))) {
		local_irq_restore(flags);
		return;
	}
	/*
	 * Check that kcov_remote_start() is not called twice in softirqs.
	 * Note, that kcov_remote_start() can be called from a softirq that
	 * happened while collecting coverage from a background thread.
	 */
	if (WARN_ON(in_serving_softirq() && t->kcov_softirq)) {
		local_irq_restore(flags);
		return;
	}

	spin_lock(&kcov_remote_lock);
	remote = kcov_remote_find(handle);
	if (!remote) {
		spin_unlock_irqrestore(&kcov_remote_lock, flags);
		return;
	}
	kcov_debug("handle = %llx, context: %s\n", handle,
			in_task() ? "task" : "softirq");
	kcov = remote->kcov;
	/* Put in kcov_remote_stop(). */
	kcov_get(kcov);
	/*
	 * Read kcov fields before unlock to prevent races with
	 * KCOV_DISABLE / kcov_remote_reset().
	 */
	mode = kcov->mode;
	sequence = kcov->sequence;
	if (in_task()) {
		size = kcov->remote_size;
		area = kcov_remote_area_get(size);
	} else {
		size = CONFIG_KCOV_IRQ_AREA_SIZE;
		area = this_cpu_ptr(&kcov_percpu_data)->irq_area;
	}
	spin_unlock_irqrestore(&kcov_remote_lock, flags);

	/* Can only happen when in_task(). */
	if (!area) {
		area = vmalloc(size * sizeof(unsigned long));
		if (!area) {
			kcov_put(kcov);
			return;
		}
	}

	local_irq_save(flags);

	/* Reset coverage size. */
	*(u64 *)area = 0;

	if (in_serving_softirq()) {
		kcov_remote_softirq_start(t);
		t->kcov_softirq = 1;
	}
	kcov_start(t, kcov, size, area, mode, sequence);

	local_irq_restore(flags);

}
EXPORT_SYMBOL(kcov_remote_start);
/* ... */
static inline void kcov_remote_start_common(u64 id)
{
	kcov_remote_start(kcov_remote_handle(KCOV_SUBSYSTEM_COMMON, id));
}

static inline void kcov_remote_start_usb(u64 id)
{
	kcov_remote_start(kcov_remote_handle(KCOV_SUBSYSTEM_USB, id));
}
```

What a complex function, the `kcov_remote_start()` will do some basic checking at first. After that, it will use `kcov_remote_find()` to find the essential `kcov_remote` struct, which is added by the above `KCOV_REMOTE_ENABLE` command. If this `ioctl` is not done yet, the `kcov_remote_start()` will return with nothing. Else, it keeps going, retriving the memory `area` for storing coverage. 

Once the `area` is obtained, the biggest challenge is solved. As introduced above, we know that the vanilla `KCOV` cannot collect coverage for background thread because it does not have user process context hence it cannot find the dedicated memory buffer mapped by the userspace `ioctl`.

However, the remote `KCOV` helps the background thread find the buffer by initiatively calling `kcov_remote_start()` with `handle`. The `handle` here will help to find the memory buffer the user allocated.

Cool, assuming we have found the area that user can parse. What about next? How the coverage is collected and managed? 
I draw a graph to demonstrate the relation between different data structures.

![remote_kcov.png](https://i.loli.net/2021/07/21/xMEC9YFLH6dK3qI.png){: .mx-auto.d-block :}

In a nutshell, the being traced background thread, once calling `kcov_remote_start`, will use the `handle` to find the `kcov_remote` struct and get the `kcov` struct. It will be attached to the `task_struct` and a new memory buffer will be created by `vmalloc` to store coverage information.

However, you may wonder another question: if the background thread stores the coverage in its own buffer, how can user thread access and parse it? Let's take a look at stop function.

```cpp
/* See the comment before kcov_remote_start() for usage details. */
void kcov_remote_stop(void)
{
	struct task_struct *t = current;
	struct kcov *kcov;
	unsigned int mode;
	void *area;
	unsigned int size;
	int sequence;
	unsigned long flags;

	if (!in_task() && !in_serving_softirq())
		return;

	local_irq_save(flags);

	mode = READ_ONCE(t->kcov_mode);
	barrier();
	if (!kcov_mode_enabled(mode)) {
		local_irq_restore(flags);
		return;
	}
	/*
	 * When in softirq, check if the corresponding kcov_remote_start()
	 * actually found the remote handle and started collecting coverage.
	 */
	if (in_serving_softirq() && !t->kcov_softirq) {
		local_irq_restore(flags);
		return;
	}
	/* Make sure that kcov_softirq is only set when in softirq. */
	if (WARN_ON(!in_serving_softirq() && t->kcov_softirq)) {
		local_irq_restore(flags);
		return;
	}

	kcov = t->kcov;
	area = t->kcov_area;
	size = t->kcov_size;
	sequence = t->kcov_sequence;

	kcov_stop(t); // -- [1] It will call `kcov_stop` first
	if (in_serving_softirq()) {
		t->kcov_softirq = 0;
		kcov_remote_softirq_stop(t);
	}

	spin_lock(&kcov->lock);
	/*
	 * KCOV_DISABLE could have been called between kcov_remote_start()
	 * and kcov_remote_stop(), hence the sequence check.
	 */
	if (sequence == kcov->sequence && kcov->remote)
		kcov_move_area(kcov->mode, kcov->area, kcov->size, area); // -- [2] An new function will be called
	spin_unlock(&kcov->lock);

	if (in_task()) {
		spin_lock(&kcov_remote_lock);
		kcov_remote_area_put(area, size);
		spin_unlock(&kcov_remote_lock);
	}

	local_irq_restore(flags);

	/* Get in kcov_remote_start(). */
	kcov_put(kcov);
}
EXPORT_SYMBOL(kcov_remote_stop);
```

We can see that this `kcov_remote_stop()` function will first call standard `kcov_stop` to stop the coverage collection.

```cpp
static void kcov_stop(struct task_struct *t)
{
	WRITE_ONCE(t->kcov_mode, KCOV_MODE_DISABLED);
	barrier();
	t->kcov = NULL;
	t->kcov_size = 0;
	t->kcov_area = NULL;
}
```

In addition, it further calls `kcov_move_area()`, which is responsible for "copying" the collected coverage to user mapped memory.

```cpp
static void kcov_move_area(enum kcov_mode mode, void *dst_area,
				unsigned int dst_area_size, void *src_area)
{
	u64 word_size = sizeof(unsigned long);
	u64 count_size, entry_size_log;
	u64 dst_len, src_len;
	void *dst_entries, *src_entries;
	u64 dst_occupied, dst_free, bytes_to_move, entries_moved;

	kcov_debug("%px %u <= %px %lu\n",
		dst_area, dst_area_size, src_area, *(unsigned long *)src_area);

	switch (mode) {
	case KCOV_MODE_TRACE_PC:
		dst_len = READ_ONCE(*(unsigned long *)dst_area);
		src_len = *(unsigned long *)src_area;
		count_size = sizeof(unsigned long);
		entry_size_log = __ilog2_u64(sizeof(unsigned long));
		break;
	case KCOV_MODE_TRACE_CMP:
		dst_len = READ_ONCE(*(u64 *)dst_area);
		src_len = *(u64 *)src_area;
		count_size = sizeof(u64);
		BUILD_BUG_ON(!is_power_of_2(KCOV_WORDS_PER_CMP));
		entry_size_log = __ilog2_u64(sizeof(u64) * KCOV_WORDS_PER_CMP);
		break;
	default:
		WARN_ON(1);
		return;
	}

	/* As arm can't divide u64 integers use log of entry size. */
	if (dst_len > ((dst_area_size * word_size - count_size) >>
				entry_size_log))
		return;
	dst_occupied = count_size + (dst_len << entry_size_log);
	dst_free = dst_area_size * word_size - dst_occupied;
	bytes_to_move = min(dst_free, src_len << entry_size_log);
	dst_entries = dst_area + dst_occupied;
	src_entries = src_area + count_size;
	memcpy(dst_entries, src_entries, bytes_to_move);
	entries_moved = bytes_to_move >> entry_size_log;

	switch (mode) {
	case KCOV_MODE_TRACE_PC:
		WRITE_ONCE(*(unsigned long *)dst_area, dst_len + entries_moved);
		break;
	case KCOV_MODE_TRACE_CMP:
		WRITE_ONCE(*(u64 *)dst_area, dst_len + entries_moved);
		break;
	default:
		break;
	}
}
```

Though this function is a little nagging, it just does a simple job, as demonstrated in the below figure.

![area_move.png](https://i.loli.net/2021/07/21/GEBhoTWPM62eul9.png){: .mx-auto.d-block :}

Once the `kcov_area_move()` is finished, the userspace coverage parising can start. Because this function is protected by `kcov->lock`, multiple handles can cooperate and merge their collected coverage one by one.

One more thing, when calling `kcov_remote_start()`, the `vmalloc` is not necessarily called. In fact, for `in_task()` cases, the `KCOV` may use `kcov_remote_areas` list to cache the buffer for optimization. While for `in_serving_softirq()` cases, the buffer is created in `kcov_init()` function at very early time.

> I don't quite clear about the difference between `in_task()` and `in_serving_softirq()` under remote coverage scenario. It won't bother a lot, the answer may be revealed in the following content, or not. :)

## syzkaller external USB fuzzing

In 2017, the syzkaller team started porting this fantastic tool into external USB fuzzing. The most important building block is the remote `KCOV` we just discussed. Next, we are going to figure out how syzkaller adopts the remote `KCOV` in its guided fuzzing.

### Kernel Side

As the remote `KCOV` now is already merged in the mainline kernel. We can search and find where the `kcov_remote_start` is placed.

**USB**

```cpp
static void hub_event(struct work_struct *work)
{
	struct usb_device *hdev;
	struct usb_interface *intf;
	struct usb_hub *hub;
	struct device *hub_dev;
	u16 hubstatus;
	u16 hubchange;
	int i, ret;

	hub = container_of(work, struct usb_hub, events);
	hdev = hub->hdev;
	hub_dev = hub->intfdev;
	intf = to_usb_interface(hub_dev);

	kcov_remote_start_usb((u64)hdev->bus->busnum);

    /* ..... */

	kcov_remote_stop();
}
```

**vhost**

```cpp
static int vhost_worker(void *data)
{
	struct vhost_dev *dev = data;
	struct vhost_work *work, *work_next;
	struct llist_node *node;

	kthread_use_mm(dev->mm);

	for (;;) {
        /* ..... */
		llist_for_each_entry_safe(work, work_next, node, node) {
			clear_bit(VHOST_WORK_QUEUED, &work->flags);
			__set_current_state(TASK_RUNNING);
			kcov_remote_start_common(dev->kcov_handle);
			work->fn(work);
			kcov_remote_stop();
			if (need_resched())
				schedule();
		}
	}
	kthread_unuse_mm(dev->mm);
	return 0;
}
```

Okay, what we can find out is that `kcov_remote_start_common()/kcov_remote_start_usb()` are paired with `kcov_remote_stop()`. However, as we don't clear about the function of `hub_event` and `vhost_worker`. We cannot tell much difference here.

> If you do some backtrace analysis, you can find the `hub_event` is called as workqueue: `INIT_WORK(&hub->events, hub_event);`. Hence it is always waked by interrupts. (global cases)
> while the `vhost_workes` is called within `vhost_dev_ioctl() -> vhost_dev_set_owner() -> kthread_create()`. Hence it is waked by system calls (local cases)

We will see how syzkaller operates these.

### Fuzzing Side

In the first post of this series, we know how *syz-fuzzer* collectes the coverage. We now back to the old function `cover_enable()`.

```cpp
static void cover_enable(cover_t* cov, bool collect_comps, bool extra)
{
	unsigned int kcov_mode = collect_comps ? KCOV_TRACE_CMP : KCOV_TRACE_PC;
	// The KCOV_ENABLE call should be fatal,
	// but in practice ioctl fails with assorted errors (9, 14, 25),
	// so we use exitf.
	if (!extra) {
		if (ioctl(cov->fd, KCOV_ENABLE, kcov_mode))
			exitf("cover enable write trace failed, mode=%d", kcov_mode);
		return;
	}
	kcov_remote_arg<1> arg = {
	    .trace_mode = kcov_mode,
	    // Coverage buffer size of background threads.
	    .area_size = kExtraCoverSize,
	    .num_handles = 1,
	};
	arg.common_handle = kcov_remote_handle(KCOV_SUBSYSTEM_COMMON, procid + 1);
	arg.handles[0] = kcov_remote_handle(KCOV_SUBSYSTEM_USB, procid + 1);
	if (ioctl(cov->fd, KCOV_REMOTE_ENABLE, &arg))
		exitf("remote cover enable write trace failed");
}
```

As you can see, before the `KCOV_REMOTE_ENABLE` is called, syzkaller just simply prepare arguments. The `num_handles` is set to `1` as only the USB subsystem is concerned. The instance variable is set to `procid + 1` to distinguish between each other.

We then take a look at the descriptions. In fact, the syzkaller defines 6 USB pseudo-syscalls (see [syzlang descriptions](sys/linux/vusb.txt) and [pseudo-syscalls](executor/common_usb.h). These syscalls are summarized in the documentations and presented below

1. `syz_usb_connect` - connects a USB device. Handles all requests to the control endpoint until a `SET_CONFIGURATION` request is received.
2. `syz_usb_connect_ath9k` - connects an `ath9k` USB device. Compared to `syz_usb_connect`, this syscall also handles firmware download requests that happen after `SET_CONFIGURATION` for the `ath9k` driver.
3. `syz_usb_disconnect` - disconnects a USB device.
4. `syz_usb_control_io` - sends or receives a control message over endpoint 0.
5. `syz_usb_ep_write` - sends a message to a non-control endpoint.
6. `syz_usb_ep_read` - receives a message from a non-control endpoint.

We may not so clear with the USB and relevant operations, but we can see that these pseudo-system calls are organized as multiple interactions. (the `connect` itself can have many steps and stages) 

The coverage collected part is almost the same with standard one so no more words here. Until now we know how remote `KCOV` integrates normal `KCOV`. We will try some demo then. 

## Demo 

One of my favorite [syzkaller demo](https://github.com/jinb-park/kfuzz/blob/master/fuzzing-driver/example/lkm/poc_lkm.c) is presented by Jinbum. This time, we will make a little change to transfer it to a remote one.

Check about this: https://github.com/f0rm2l1n/kfuzz.git

The output I get are

```
0xffffffffc000010e => linux-5.8.15/./include/linux/uaccess.h:144
0xffffffff81dfccd1 => linux-5.8.15/lib/usercopy.c:13
0xffffffff81dfcd1c => linux-5.8.15/lib/usercopy.c:13
0xffffffff81dfcd31 => linux-5.8.15/./include/linux/instrumented.h:105
0xffffffff81dfcd50 => linux-5.8.15/lib/usercopy.c:17
0xffffffff81dfcd64 => linux-5.8.15/lib/usercopy.c:20
0xffffffffc0000121 => kcov-remote-example/lkm/remote_lkm.c:39
```

And these match the prediction of mine. (checking, `copy_from_user`, and some part code of the driver). Hope this example show you how to use the remote kcov.

## Conclusion

This time, we take a trip to look through how remote `KCOV` is used to trace the background thread. In a nutshell, global thread (dedicated subsystem handle) and local thread (common handle) are the targets. We also see how syzkaller adopts the remote `KCOV` in its guided fuzzing. (In fact, you can easily set up the environment and run it. HINT: using the `upstream-usb.config`) At last, a dummy demo is provided to help you use the remote `KCOV` to collect coverage from the kernel module. \

Of course, we haven't ported the syzkaller to fuzzing the example driver. To be honest, I don't figure the best way to do this. Is it enough if we just write some system call descriptions (as we use the common handle)? We will know the answer in the future maybe. 
