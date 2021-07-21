---
layout: post
title: Thorough Understanding with Anonymous MMAP
subtitle: Basic of ret2dir
tags: [Kernel]
---

When I spend time exploiting the Linux kernel, I indeed get some tiny pieces of the entire picture about how the Linux memory management work. Of course, it seems enough for some naive heap shaping and spraying, but also confuse me when things get deeper.

This time, I wonder if I can understand the extreme details of *Anonymous MMAP*, which is critical when adopt ret2dir[1] attack. In addition, we are used to call already wrappered functions, like `malloc`, to allocate small size memory. It will just be interesting if we know how things work out inside the libc.

Anyway, let's just start with an easy one (hope so).

## Setup

For simplicity reason, I choose the x86_64 v4.4 Linux kernel version as the target. And QEMU + gdb combination for dynamically analysis of course. If you are not familar with this, you can refer to my [CVE experiments](./Journey-through-old-Linux-kernel-CVEs).

## Walking `mmap`

### `sys_mmap_pgoff`

The architecture-independent entrace of `mmap` is defined as `mmap_pgoff` in *mm/mmap.c*. In our naive experiments (which call `mmap` with only `MAP_PRIVATE | MAP_ANONYMOUS` flags), the tracing of this function is rather simple.

> I will use `/**/` to mark the control flow if possible.


```c++
// mm/mmap.c
SYSCALL_DEFINE6(mmap_pgoff, unsigned long, addr, unsigned long, len,
		unsigned long, prot, unsigned long, flags,
		unsigned long, fd, unsigned long, pgoff)
{
	/* ... */
/**/flags &= ~(MAP_EXECUTABLE | MAP_DENYWRITE);	// From manual, these 2 flags are ignored
/**/retval = vm_mmap_pgoff(file, addr, len, prot, flags, pgoff);
}

```

Well you may ask, What? We don't need *MAP_EXECUTABLE* flag? What about those mmap and shellcode things? Yeah, don't forget we have `PROT_EXEC` as the property flag.

### `vm_mmap_pgoff`

Arguments of this function call is almost no difference with `sys_mmap_pgoff` so we ignore that.

```c++
unsigned long vm_mmap_pgoff(struct file *file, unsigned long addr,
	unsigned long len, unsigned long prot,
	unsigned long flag, unsigned long pgoff)
{
	unsigned long ret;
	struct mm_struct *mm = current->mm;
	unsigned long populate;

/**/ret = security_mmap_file(file, prot, flag);
	if (!ret) {
/**/	down_write(&mm->mmap_sem);
/**/	ret = do_mmap_pgoff(file, addr, len, prot, flag, pgoff,
				    &populate);
/**/	up_write(&mm->mmap_sem);
		if (populate)
			mm_populate(ret, populate);
	}
	return ret;
}
```

Okay, `security_mmap_file()` function is used to do some security check. It inside calls `mmap_prot()` function which will take care when you set `PROT_EXEC` flag.

```c++
static inline unsigned long mmap_prot(struct file *file, unsigned long prot)
{
	/*
	 * Does we have PROT_READ and does the application expect
	 * it to imply PROT_EXEC?  If not, nothing to talk about...
	 */
/**/if ((prot & (PROT_READ | PROT_EXEC)) != PROT_READ)
		return prot;
/**/if (!(current->personality & READ_IMPLIES_EXEC))
/**/	return prot;
	/*
	 * if that's an anonymous mapping, let it.
	 */
	if (!file)
		return prot | PROT_EXEC;
	/*
	....
```

The `RAED_IMPLIES_EXEC` flag is kinda attractive, you can refer to the manual[^2] to figure that out. Later on, we will go through `selinux_mmap_file()` check which will check your whether ot not your request property is valid on the file descriptor you supplied. Consider that our `mmap` intention is rather simple, I will skip that part. For anyone interested about it, refer to [another post](./CVE-2019-9213) of mine.

Let's then go back to `vm_mmap_pgoff()` function after we finish `security_mmap_file()`. It will fisrt call `done_write()` function to handle with the semaphore in `mm_struct`, the enter into `do_mmap_pgoff`. 

> When you find kernel functions start with `do_`, it is a messy one then. In fact, the `do_mmap_pgoff` directly calls `do_mmap`.

The `do_mmap()` is just too long and we may split it for clarity.

```c++
// mm/mmap.c do_mmap part-1
unsigned long do_mmap(struct file *file, unsigned long addr,
			unsigned long len, unsigned long prot,
			unsigned long flags, vm_flags_t vm_flags,
			unsigned long pgoff, unsigned long *populate)
{
	struct mm_struct *mm = current->mm;

	*populate = 0;

	if (!len)
		return -EINVAL;

	/*
	 * Does the application expect PROT_READ to imply PROT_EXEC?
	 *
	 * (the exception is when the underlying filesystem is noexec
	 *  mounted, in which case we dont add PROT_EXEC.)
	 */
/**/if ((prot & PROT_READ) && (current->personality & READ_IMPLIES_EXEC))
		if (!(file && path_noexec(&file->f_path)))
			prot |= PROT_EXEC;

/**/if (!(flags & MAP_FIXED))
		addr = round_hint_to_min(addr);

	/* Careful about overflows.. */
/**/len = PAGE_ALIGN(len);
	if (!len)
		return -ENOMEM;

	/* offset overflow? */
/**/if ((pgoff + (len >> PAGE_SHIFT)) < pgoff)
		return -EOVERFLOW;

	/* Too many mappings? */
/**/if (mm->map_count > sysctl_max_map_count)
		return -ENOMEM;

	/* Obtain the address to map to. we verify (or select) it and ensure
	 * that it represents a valid section of the address space.
	 */
	addr = get_unmapped_area(file, addr, len, pgoff, flags);
	if (offset_in_page(addr))
		return addr;
```

The beginning of this function is nothing about *checking, checking, checking*, nothing really attractive. After these, `do_mmap()` calls `get_unmapped_area()` to obtain the address to map to.

```c++
// mm/mmap.c get_unmapped_area part-1
unsigned long
get_unmapped_area(struct file *file, unsigned long addr, unsigned long len,
		unsigned long pgoff, unsigned long flags)
{
	unsigned long (*get_area)(struct file *, unsigned long,
				  unsigned long, unsigned long, unsigned long);

	unsigned long error = arch_mmap_check(addr, len, flags);
	if (error)
		return error;

	/* Careful about overflows.. */
	if (len > TASK_SIZE) 	// TASK_SIZE = 0x00007ffffffff000 in my debugging
		return -ENOMEM;

/**/get_area = current->mm->get_unmapped_area;
/**/if (file && file->f_op->get_unmapped_area)
/**/	get_area = file->f_op->get_unmapped_area;
/**/addr = get_area(file, addr, len, pgoff, flags);	
	// indirect call to arch-dependent `arch_get_unmapped_area_topdown`

```

The comments of `arch_get_unmapped_area_topdown()` is
> This mmap-allocator allocates new areas top-down from below the stack's low limit (the base):

Okay, what does this mean?

```c++
// arch/x86/kernel/sys_x86_64.c arch_get_unmapped_area_topdown()
unsigned long
arch_get_unmapped_area_topdown(struct file *filp, const unsigned long addr0,
			  const unsigned long len, const unsigned long pgoff,
			  const unsigned long flags)
{
	/* ... */
	/* requesting a specific address */
	if (addr) {
	/* ... */
	}

/**/info.flags = VM_UNMAPPED_AREA_TOPDOWN;
/**/info.length = len;
/**/info.low_limit = PAGE_SIZE; 		// ???
/**/info.high_limit = mm->mmap_base; 	// ???
/**/info.align_mask = 0;
/**/info.align_offset = pgoff << PAGE_SHIFT;
	if (filp) {
		info.align_mask = get_align_mask();
		info.align_offset += get_align_bits();
	}
/**/addr = vm_unmapped_area(&info);
/**/if (!(addr & ~PAGE_MASK))
/**/	return addr;
	VM_BUG_ON(addr != -ENOMEM);

bottomup:
	/*
	 * A failed mmap() very likely causes application failure,
	 * so fall back to the bottom-up function here. This scenario
	 * can happen with large stack limits and large mmap()
	 * allocations.
	 */
	return arch_get_unmapped_area(filp, addr0, len, pgoff, flags);
}
```

Here, `vm_unmapped_area()` will then call `unmapped_area_topdown()`, also a very long and complex function that deals with red-black tree operations. Trace of this function highly depends on the vm states so we just ignore it. Fortunately, there is an summary comment for use to understand what this function does with input `info`.

```c
/*
 * We implement the search by looking for an rbtree node that
 * immediately follows a suitable gap. That is,
 * - gap_start = vma->vm_prev->vm_end <= info->high_limit - length;
 * - gap_end   = vma->vm_start        >= info->low_limit  + length;
 * - gap_end - gap_start >= length
 */

```

Let's go back to `get_unmapped_area()` supposing the indrect call is done, 

```c++
// mm/mmap.c get_unmapped_area part-2

/**/if (IS_ERR_VALUE(addr))
		return addr;

/**/if (addr > TASK_SIZE - len)
		return -ENOMEM;
/**/if (offset_in_page(addr))
		return -EINVAL;

/**/addr = arch_rebalance_pgtables(addr, len);	// empty function for now
/**/error = security_mmap_addr(addr);
/**/return error ? error : addr;
}
```

Before returning, `security_mmap_addr()` will be called to invoke `cap_mmap_addr()` function and `selinux_mmap_addr()` to do extended security check, including capacity, min_addr, etc. After that, we finally get an unmapped area that is satisfying our requirements. We can come back to the `do_mmap()` function.

```c++
// mm/mmap.c do_mmap part-2
	addr = get_unmapped_area(file, addr, len, pgoff, flags);
/**/if (offset_in_page(addr))
		return addr;

	/* Do simple checking here so the lower-level routines won't have
	 * to. we assume access permissions have been handled by the open
	 * of the memory object, so we don't do any here.
	 */
/**/vm_flags |= calc_vm_prot_bits(prot) | calc_vm_flag_bits(flags) |
			mm->def_flags | VM_MAYREAD | VM_MAYWRITE | VM_MAYEXEC;

/**/if (flags & MAP_LOCKED)
/**/	if (!can_do_mlock())
			return -EPERM;

/**/if (mlock_future_check(mm, vm_flags, len))
		return -EAGAIN;

	if (file) {
		/* ... */
	} else {
/**/	switch (flags & MAP_TYPE) {
		case MAP_SHARED:
			if (vm_flags & (VM_GROWSDOWN|VM_GROWSUP))
				return -EINVAL;
			/*
			 * Ignore pgoff.
			 */
			pgoff = 0;
			vm_flags |= VM_SHARED | VM_MAYSHARE;
			break;
/**/	case MAP_PRIVATE:
			/*
			 * Set pgoff according to addr for anon_vma.
			 */
/**/		pgoff = addr >> PAGE_SHIFT;
			break;
		default:
			return -EINVAL;
		}
	}
```

This part of code is easy to go through for we don't require `MAP_LCOKED` and don't apply a file descriptor. We just shift the addr to obtain the `pgoff` variable.

```c++
// mm/mmap.c do_mmap part-3
	/*
	 * Set 'VM_NORESERVE' if we should not account for the
	 * memory use of this mapping.
	 */
/**/if (flags & MAP_NORESERVE) {
		/* ... */
	}

/**/addr = mmap_region(file, addr, len, vm_flags, pgoff);
	if (!IS_ERR_VALUE(addr) &&
	    ((vm_flags & VM_LOCKED) ||
	     (flags & (MAP_POPULATE | MAP_NONBLOCK)) == MAP_POPULATE))
		*populate = len;
	return addr;
}
```

Well, we have an area, we done the check, it's now to create the mapping in `mmap_region` (also a long one).

> This mapping creating also related to current machine states, so the tracing is just for an example. 

```c++
// mm/mmap.c mmap_region part-1
unsigned long mmap_region(struct file *file, unsigned long addr,
		unsigned long len, vm_flags_t vm_flags, unsigned long pgoff)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma, *prev;
	int error;
	struct rb_node **rb_link, *rb_parent;
	unsigned long charged = 0;

	/* Check against address space limit. */
/**/if (!may_expand_vm(mm, len >> PAGE_SHIFT)) {
		/* ... */
	}

	/* Clear old maps */
/**/while (find_vma_links(mm, addr, addr + len, &prev, &rb_link,
			      &rb_parent)) {
		if (do_munmap(mm, addr, len))
			return -ENOMEM;
	}

	/*
	 * Private writable mapping: check memory availability
	 */
/**/if (accountable_mapping(file, vm_flags)) {
/**/	charged = len >> PAGE_SHIFT;	// charged represents page numbers
/**/	if (security_vm_enough_memory_mm(mm, charged))
			return -ENOMEM;
/**/	vm_flags |= VM_ACCOUNT;
	}

	/*
	 * Can we just expand an old mapping?
	 */
/**/vma = vma_merge(mm, prev, addr, addr + len, vm_flags,
			NULL, file, pgoff, NULL, NULL_VM_UFFD_CTX); 	
	if (vma)
		goto out;
```

Since we want `MAP_PRIVATE` memory that also `PROT_WRITE`, we enter into `security_vm_enough_memory_mm()` checking, which calls `cap_vm_enough_memory()` and `selinux_vm_enough_memory()` functions. `__vm_enough_memory()` is called at last. So many contents there we may have a peek in the future.

```c++
// mm/mmap.c mmap_region part-2
	/*
	 * Determine the object being mapped and call the appropriate
	 * specific mapper. the address has already been validated, but
	 * not unmapped, but the maps are removed from the list.
	 */
/**/vma = kmem_cache_zalloc(vm_area_cachep, GFP_KERNEL);
	if (!vma) {
		error = -ENOMEM;
		goto unacct_error;
	}

/**/vma->vm_mm = mm;
/**/vma->vm_start = addr;
/**/vma->vm_end = addr + len;
/**/vma->vm_flags = vm_flags;
/**/vma->vm_page_prot = vm_get_page_prot(vm_flags);
/**/vma->vm_pgoff = pgoff;
/**/INIT_LIST_HEAD(&vma->anon_vma_chain);

	if (file) {
		/* ... */
	} else if (vm_flags & VM_SHARED) {
		/* ... */
	}

/**/vma_link(mm, vma, prev, rb_link, rb_parent);	// link in the red-black tree
	/* Once vma denies write, undo our temporary denial count */
	if (file) {
		/* ... */
	}
/**/file = vma->vm_file;

out:
/**/perf_event_mmap(vma);	// peformace metrics ...

/**/vm_stat_account(mm, vm_flags, file, len >> PAGE_SHIFT); 	// Update states for 'CONFIG_PROC_FS'
	if (vm_flags & VM_LOCKED) {
		if (!((vm_flags & VM_SPECIAL) || is_vm_hugetlb_page(vma) ||
					vma == get_gate_vma(current->mm)))
			mm->locked_vm += (len >> PAGE_SHIFT);
		else
			vma->vm_flags &= VM_LOCKED_CLEAR_MASK;
	}

	if (file)
		uprobe_mmap(vma);

	/*
	 * New (or expanded) vma always get soft dirty status.
	 * Otherwise user-space soft-dirty page tracker won't
	 * be able to distinguish situation when vma area unmapped,
	 * then new mapped in-place (which must be aimed as
	 * a completely new data area).
	 */
/**/vma->vm_flags |= VM_SOFTDIRTY;

/**/vma_set_page_prot(vma);

/**/return addr;

	/* ... */
}

```

The last functions `vma_set_page_prot()` will assign `vma->vm_page_prot`. Before that, the `VM_SOFTDIRTY` flag, as the comment illustates, helps the *user-space soft-dirty page tracker* (what is that anyway?)

Thank goodness, the expected addr now is returned, level by level. We finally get an address in our userland.

## Walking `page fault`

Does everything settle down? Not exactly... As you can see as above, the `mmap_pgoff` just gets a free area and creates mapping for that. Where is the memory page we want? In fact, the real page is not allocated for now, which is one part of the design strategy of Linux memory management. Why bother itself to do the page allocation when the expected pages may not be used recently. So as we want to know the real page of our `mmap`, we have to keep walking, and understand the Linux page fault.

How these tings starts? Consider that we just create mapping and essentials structure like `vm_area_struct`. So the hardware page tables won't keep an record for the address we just obtained. Which means the time we dereference this address, the hardware interrupt controller will catch it and jumps to related handler, page fault handler this time.

In our x86_64 environment, the `do_page_fault()` function is the door. We can just set a breakpoint there, try write a byte to the new address, and restart our dynamic analysis.

```c++
// arch/x86/mm/fault.c do_page_fault
do_page_fault(struct pt_regs *regs, unsigned long error_code)
{
	unsigned long address = read_cr2(); /* Get the faulting address */
	enum ctx_state prev_state;

	/*
	 * We must have this function tagged with __kprobes, notrace and call
	 * read_cr2() before calling anything else. To avoid calling any kind
	 * of tracing machinery before we've observed the CR2 value.
	 *
	 * exception_{enter,exit}() contain all sorts of tracepoints.
	 */

	prev_state = exception_enter();
	__do_page_fault(regs, error_code, address);
	exception_exit(prev_state);
}
```

Seems that we have to look into `__do_page_fault()` then.

```c++
// arch/x86/mm/fault.c __do_page_fault part-1
/*
 * This routine handles page faults.  It determines the address,
 * and the problem, and then passes it off to one of the appropriate
 * routines.
 *
 * This function must have noinline because both callers
 * {,trace_}do_page_fault() have notrace on. Having this an actual function
 * guarantees there's a function trace entry.
 */
static noinline void
__do_page_fault(struct pt_regs *regs, unsigned long error_code,
		unsigned long address)
{
	struct vm_area_struct *vma;
	struct task_struct *tsk;
	struct mm_struct *mm;
	int fault, major = 0;
	unsigned int flags = FAULT_FLAG_ALLOW_RETRY | FAULT_FLAG_KILLABLE;

	tsk = current;
	mm = tsk->mm;

	/*
	 * Detect and handle instructions that would cause a page fault for
	 * both a tracked kernel page and a userspace page.
	 */
	if (kmemcheck_active(regs))
		kmemcheck_hide(regs);
/**/prefetchw(&mm->mmap_sem);

	/* ... skip almost ...*/

	/*
	 * It's safe to allow irq's after cr2 has been saved and the
	 * vmalloc fault has been handled.
	 *
	 * User-mode registers count as a user access even for any
	 * potential system fault or CPU buglet:
	 */
/**/if (user_mode(regs)) {
/**/	local_irq_enable();
/**/	error_code |= PF_USER;
/**/	flags |= FAULT_FLAG_USER;
	} else {
		if (regs->flags & X86_EFLAGS_IF)
			local_irq_enable();
	}

	perf_sw_event(PERF_COUNT_SW_PAGE_FAULTS, 1, regs, address);

/**/if (error_code & PF_WRITE)
/**/	flags |= FAULT_FLAG_WRITE;

```

Because we are facing with userland page fault instead of kernel vmalloc page fault, there are many unrelated codes and I just skip them. The handler will use `user_mode()` function to decide whether or not this fault is from user space (Intenal it will check cs register). Then it will update the `error_code` and `flags`. For I have tried to write a byte so `FAULT_FLAG_WRITE` is also appended.

```c++
// arch/x86/mm/fault.c __do_page_fault part-2
	/*
	 * When running in the kernel we expect faults to occur only to
	 * addresses in user space.  All other faults represent errors in
	 * the kernel and should generate an OOPS.  Unfortunately, in the
	 * case of an erroneous fault occurring in a code path which already
	 * holds mmap_sem we will deadlock attempting to validate the fault
	 * against the address space.  Luckily the kernel only validly
	 * references user space from well defined areas of code, which are
	 * listed in the exceptions table.
	 *
	 * As the vast majority of faults will be valid we will only perform
	 * the source reference check when there is a possibility of a
	 * deadlock. Attempt to lock the address space, if we cannot we then
	 * validate the source. If this is invalid we can skip the address
	 * space check, thus avoiding the deadlock:
	 */
/**/if (unlikely(!down_read_trylock(&mm->mmap_sem))) {
		if ((error_code & PF_USER) == 0 &&
		    !search_exception_tables(regs->ip)) {
			bad_area_nosemaphore(regs, error_code, address);
			return;
		}
retry:
		down_read(&mm->mmap_sem);
/**/} else {
		/*
		 * The above down_read_trylock() might have succeeded in
		 * which case we'll have missed the might_sleep() from
		 * down_read():
		 */
/**/	might_sleep();
	}

/**/vma = find_vma(mm, address);
	if (unlikely(!vma)) {
		bad_area(regs, error_code, address);
		return;
	}
/**/if (likely(vma->vm_start <= address))
		goto good_area;
	if (unlikely(!(vma->vm_flags & VM_GROWSDOWN))) {
	/* ... */
```

The comments of this partrial code is somewhat obscure. Anyway, it just want to avoid situation of deadlock. After that, `find_vma()` will returns the `vm_area_struct` for page fault `address` (red-black tree tricks). If the `address` is inside the `vma` region, the control flow will be guided to `good_area`.

```c++
// arch/x86/mm/fault.c __do_page_fault part-3
	/*
	 * Ok, we have a good vm_area for this memory access, so
	 * we can handle it..
	 */
good_area:
/**/if (unlikely(access_error(error_code, vma))) {
		bad_area_access_error(regs, error_code, address);
		return;
	}

	/*
	 * If for any reason at all we couldn't handle the fault,
	 * make sure we exit gracefully rather than endlessly redo
	 * the fault.  Since we never set FAULT_FLAG_RETRY_NOWAIT, if
	 * we get VM_FAULT_RETRY back, the mmap_sem has been unlocked.
	 */
/**/fault = handle_mm_fault(mm, vma, address, flags);
	major |= fault & VM_FAULT_MAJOR;

```

The `access_error` is worth a glance.

```c++
// arch/x86/mm/fault.c access_error
static inline int
access_error(unsigned long error_code, struct vm_area_struct *vma)
{
/**/if (error_code & PF_WRITE) {
		/* write, present and write, not present: */
/**/	if (unlikely(!(vma->vm_flags & VM_WRITE)))
			return 1;
/**/	return 0;
	}

	/* ... */
}
```

After that, `handle_mm_fault()` will be called.

```c++
// mm/memory.c
/*
 * By the time we get here, we already hold the mm semaphore
 *
 * The mmap_sem may have been released depending on flags and our
 * return value.  See filemap_fault() and __lock_page_or_retry().
 */
int handle_mm_fault(struct mm_struct *mm, struct vm_area_struct *vma,
		    unsigned long address, unsigned int flags)
{
	int ret;

	__set_current_state(TASK_RUNNING);

	count_vm_event(PGFAULT);
	mem_cgroup_count_vm_event(mm, PGFAULT);

	/* do counter updates before entering really critical section. */
	check_sync_rss_stat(current);

	/*
	 * Enable the memcg OOM handling for faults triggered in user
	 * space.  Kernel faults are handled more gracefully.
	 */
	if (flags & FAULT_FLAG_USER)
		mem_cgroup_oom_enable();

	ret = __handle_mm_fault(mm, vma, address, flags);

	if (flags & FAULT_FLAG_USER) {
		mem_cgroup_oom_disable();
                /*
                 * The task may have entered a memcg OOM situation but
                 * if the allocation error was handled gracefully (no
                 * VM_FAULT_OOM), there is no need to kill anything.
                 * Just clean up the OOM state peacefully.
                 */
                if (task_in_memcg_oom(current) && !(ret & VM_FAULT_OOM))
                        mem_cgroup_oom_synchronize(false);
	}

	return ret;
}
```

So many fancy `cgroup` stuffs, for now, we step into `__handle_mm_fault()` function.

```c++
// mm/memory.c __handle_mm_fault part-1
/*
 * By the time we get here, we already hold the mm semaphore
 *
 * The mmap_sem may have been released depending on flags and our
 * return value.  See filemap_fault() and __lock_page_or_retry().
 */
static int __handle_mm_fault(struct mm_struct *mm, struct vm_area_struct *vma,
			     unsigned long address, unsigned int flags)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

/**/if (unlikely(is_vm_hugetlb_page(vma)))
		return hugetlb_fault(mm, vma, address, flags);

/**/pgd = pgd_offset(mm, address);
/**/pud = pud_alloc(mm, pgd, address);
/**/if (!pud)
		return VM_FAULT_OOM;
/**/pmd = pmd_alloc(mm, pud, address);
	if (!pmd)
		return VM_FAULT_OOM;
/**/if (pmd_none(*pmd) && transparent_hugepage_enabled(vma)) {
		int ret = create_huge_pmd(mm, vma, address, pmd, flags);
		if (!(ret & VM_FAULT_FALLBACK))
			return ret;
	} else {
/**/	pmd_t orig_pmd = *pmd;
/**/	int ret;

/**/	barrier();
		if (pmd_trans_huge(orig_pmd)) {
		/* ... */
		}
	}
	/*
	 * Use __pte_alloc instead of pte_alloc_map, because we can't
	 * run pte_offset_map on the pmd, if an huge pmd could
	 * materialize from under us from a different thread.
	 */
	if (unlikely(pmd_none(*pmd)) &&
	    unlikely(__pte_alloc(mm, vma, pmd, address)))
		return VM_FAULT_OOM;
	/* if an huge pmd materialized from under us just retry later */
	if (unlikely(pmd_trans_huge(*pmd)))
		return 0;
	/*
	 * A regular pmd is established and it can't morph into a huge pmd
	 * from under us anymore at this point because we hold the mmap_sem
	 * read mode and khugepaged takes it in write mode. So now it's
	 * safe to run pte_offset_map().
	 */
/**/pte = pte_offset_map(pmd, address);

/**/return handle_pte_fault(mm, vma, address, pte, pmd, flags);
}

```

The page table walking through is an interesting topic, worthing another post to describe. Here we only have to know that a regular pmd (page middle directory) is now created/obtained. And we are ready to fetch the pte and handle the pte fault.

```c++
// mm/memory.c handle_pte_fault part-1
/*
 * These routines also need to handle stuff like marking pages dirty
 * and/or accessed for architectures that don't do it in hardware (most
 * RISC architectures).  The early dirtying is also good on the i386.
 *
 * There is also a hook called "update_mmu_cache()" that architectures
 * with external mmu caches can use to update those (ie the Sparc or
 * PowerPC hashed page tables that act as extended TLBs).
 *
 * We enter with non-exclusive mmap_sem (to exclude vma changes,
 * but allow concurrent faults), and pte mapped but not yet locked.
 * We return with pte unmapped and unlocked.
 *
 * The mmap_sem may have been released depending on flags and our
 * return value.  See filemap_fault() and __lock_page_or_retry().
 */
static int handle_pte_fault(struct mm_struct *mm,
		     struct vm_area_struct *vma, unsigned long address,
		     pte_t *pte, pmd_t *pmd, unsigned int flags)
{
	pte_t entry;
	spinlock_t *ptl;

	/*
	 * some architectures can have larger ptes than wordsize,
	 * e.g.ppc44x-defconfig has CONFIG_PTE_64BIT=y and CONFIG_32BIT=y,
	 * so READ_ONCE or ACCESS_ONCE cannot guarantee atomic accesses.
	 * The code below just needs a consistent view for the ifs and
	 * we later double check anyway with the ptl lock held. So here
	 * a barrier will do.
	 */
/**/entry = *pte;
/**/barrier();
/**/if (!pte_present(entry)) {
/**/	if (pte_none(entry)) {
/**/		if (vma_is_anonymous(vma))
/**/			return do_anonymous_page(mm, vma, address,
							 pte, pmd, flags);
			else
				return do_fault(mm, vma, address, pte, pmd,
						flags, entry);
		}
		return do_swap_page(mm, vma, address,
					pte, pmd, flags, entry);
	}
}
```

Okay, anonymous page falls into `do_anonymous_page()`, make sense.

```c++
// mm/memory.c do_anonymous_page part-1
/*
 * We enter with non-exclusive mmap_sem (to exclude vma changes,
 * but allow concurrent faults), and pte mapped but not yet locked.
 * We return with mmap_sem still held, but pte unmapped and unlocked.
 */
static int do_anonymous_page(struct mm_struct *mm, struct vm_area_struct *vma,
		unsigned long address, pte_t *page_table, pmd_t *pmd,
		unsigned int flags)
{
	struct mem_cgroup *memcg;
	struct page *page;
	spinlock_t *ptl;
	pte_t entry;

/**/pte_unmap(page_table);	// Nop function in x86_64

	/* File mapping without ->vm_ops ? */
/**/if (vma->vm_flags & VM_SHARED)
		return VM_FAULT_SIGBUS;

	/* Check if we need to add a guard page to the stack */
/**/if (check_stack_guard_page(vma, address) < 0) 	
		return VM_FAULT_SIGSEGV;

	/* Use the zero-page for reads */
/**/if (!(flags & FAULT_FLAG_WRITE) && !mm_forbids_zeropage(mm)) {
		/* ... We are doing writing ...*/ 
	}

	/* Allocate our own private page. */
/**/if (unlikely(anon_vma_prepare(vma)))
		goto oom;
/**/page = alloc_zeroed_user_highpage_movable(vma, address);
	if (!page)
		goto oom;

```

`check_stack_guard_page()` shall attract a security researcher, you can look into this blog for details[^3]. `anon_vma_prepare()` function will preapre the `struct anon_vma`, which seems not that important. We enter the `alloc_zeroed_user_highpage_movable()` function (a long name).

> In my memory, HIGHMEM is memory that cannot reference by address, so waht is highpage?

```c++
// include/linux/highmem.h
/**
 * alloc_zeroed_user_highpage_movable - Allocate a zeroed HIGHMEM page for a VMA that the caller knows can move
 * @vma: The VMA the page is to be allocated for
 * @vaddr: The virtual address the page will be inserted into
 *
 * This function will allocate a page for a VMA that the caller knows will
 * be able to migrate in the future using move_pages() or reclaimed
 */
static inline struct page *
alloc_zeroed_user_highpage_movable(struct vm_area_struct *vma,
					unsigned long vaddr)
{
	return __alloc_zeroed_user_highpage(__GFP_MOVABLE, vma, vaddr);
}
``` 

No idea why it has to allocate the page in high memory? Werid...

The function will then call the wrapper below

```c++
#define __alloc_zeroed_user_highpage(movableflags, vma, vaddr) \
	alloc_page_vma(GFP_HIGHUSER | __GFP_ZERO | movableflags, vma, vaddr)
```

And we comes here

```c++
#define alloc_page_vma(gfp_mask, vma, addr)			\
	alloc_pages_vma(gfp_mask, 0, vma, addr, numa_node_id(), false)
```

And there, with gfp = `(GFP_HIGHUSER | __GFP_ZERO | __GFP_MOVABLE)`
```c++
// mm/mempolicy.c alloc_pages_vma part-1
/**
 * 	alloc_pages_vma	- Allocate a page for a VMA.
 *
 * 	@gfp:
 *      %GFP_USER    user allocation.
 *      %GFP_KERNEL  kernel allocations,
 *      %GFP_HIGHMEM highmem/user allocations,
 *      %GFP_FS      allocation should not call back into a file system.
 *      %GFP_ATOMIC  don't sleep.
 *
 *	@order:Order of the GFP allocation.
 * 	@vma:  Pointer to VMA or NULL if not available.
 *	@addr: Virtual Address of the allocation. Must be inside the VMA.
 *	@node: Which node to prefer for allocation (modulo policy).
 *	@hugepage: for hugepages try only the preferred node if possible
 *
 * 	This function allocates a page from the kernel page pool and applies
 *	a NUMA policy associated with the VMA or the current process.
 *	When VMA is not NULL caller must hold down_read on the mmap_sem of the
 *	mm_struct of the VMA to prevent it from going away. Should be used for
 *	all allocations for pages that will be mapped into user space. Returns
 *	NULL when no page can be allocated.
 */
struct page *
alloc_pages_vma(gfp_t gfp, int order, struct vm_area_struct *vma,
		unsigned long addr, int node, bool hugepage)
{
	struct mempolicy *pol;
	struct page *page;
	unsigned int cpuset_mems_cookie;
	struct zonelist *zl;
	nodemask_t *nmask;

retry_cpuset:
/**/pol = get_vma_policy(vma, addr);
/**/cpuset_mems_cookie = read_mems_allowed_begin();

	if (pol->mode == MPOL_INTERLEAVE) {
		/* ... */
	}

	if (unlikely(IS_ENABLED(CONFIG_TRANSPARENT_HUGEPAGE) && hugepage)) {
		/* ... */
	}

/**/nmask = policy_nodemask(gfp, pol);
/**/zl = policy_zonelist(gfp, pol, node);
/**/mpol_cond_put(pol);
/**/page = __alloc_pages_nodemask(gfp, order, zl, nmask);
out:
	if (unlikely(!page && read_mems_allowed_retry(cpuset_mems_cookie)))
		goto retry_cpuset;
	return page;
}
```

Several policy related functions, blabla, ignore, ignore. Let's have a look at `__alloc_pages_nodemask()`. 

```c++
// mm/page_alloc.c __alloc_pages_nodemask part-1
/*
 * This is the 'heart' of the zoned buddy allocator.
 */
struct page *
__alloc_pages_nodemask(gfp_t gfp_mask, unsigned int order,
			struct zonelist *zonelist, nodemask_t *nodemask)
{
	struct zoneref *preferred_zoneref;
	struct page *page = NULL;
	unsigned int cpuset_mems_cookie;
/**/int alloc_flags = ALLOC_WMARK_LOW|ALLOC_CPUSET|ALLOC_FAIR;
	gfp_t alloc_mask; /* The gfp_t that was actually used for allocation */
/**/struct alloc_context ac = {
		.high_zoneidx = gfp_zone(gfp_mask),
		.nodemask = nodemask,
		.migratetype = gfpflags_to_migratetype(gfp_mask),
	};

/**/gfp_mask &= gfp_allowed_mask;

/**/lockdep_trace_alloc(gfp_mask);

/**/might_sleep_if(gfp_mask & __GFP_DIRECT_RECLAIM);

/**/if (should_fail_alloc_page(gfp_mask, order))
		return NULL;

	/*
	 * Check the zones suitable for the gfp_mask contain at least one
	 * valid zone. It's possible to have an empty zonelist as a result
	 * of __GFP_THISNODE and a memoryless node
	 */
/**/if (unlikely(!zonelist->_zonerefs->zone))
		return NULL;

/**/if (IS_ENABLED(CONFIG_CMA) && ac.migratetype == MIGRATE_MOVABLE)
		alloc_flags |= ALLOC_CMA;
```

**This is the 'heart' of the zoned buddy allocator.** This function is an essential one, let's read it step by step.

```c++
// mm/page_alloc.c __alloc_pages_nodemask part-2
retry_cpuset:
/**/cpuset_mems_cookie = read_mems_allowed_begin();

	/* We set it here, as __alloc_pages_slowpath might have changed it */
/**/ac.zonelist = zonelist;

	/* Dirty zone balancing only done in the fast path */
/**/ac.spread_dirty_pages = (gfp_mask & __GFP_WRITE);

	/* The preferred zone is used for statistics later */
/**/preferred_zoneref = first_zones_zonelist(ac.zonelist, ac.high_zoneidx,
				ac.nodemask ? : &cpuset_current_mems_allowed,
				&ac.preferred_zone);
/**/if (!ac.preferred_zone)
		goto out;
/**/ac.classzone_idx = zonelist_zone_idx(preferred_zoneref);

	/* First allocation attempt */
/**/alloc_mask = gfp_mask|__GFP_HARDWALL;
/**/page = get_page_from_freelist(alloc_mask, order, alloc_flags, &ac);

```

Okay, page management also has a freelist? Interesting.

```c++
// mm/page_alloc.c get_page_from_freelist part-1
/*
 * get_page_from_freelist goes through the zonelist trying to allocate
 * a page.
 */
static struct page *
get_page_from_freelist(gfp_t gfp_mask, unsigned int order, int alloc_flags,
						const struct alloc_context *ac)
{
	struct zonelist *zonelist = ac->zonelist;
	struct zoneref *z;
	struct page *page = NULL;
	struct zone *zone;
	int nr_fair_skipped = 0;
	bool zonelist_rescan;

zonelist_scan:
	zonelist_rescan = false;

	/*
	 * Scan zonelist, looking for a zone with enough free.
	 * See also __cpuset_node_allowed() comment in kernel/cpuset.c.
	 */
/**/for_each_zone_zonelist_nodemask(zone, z, zonelist, ac->high_zoneidx,
								ac->nodemask) {
		unsigned long mark;

		if (cpusets_enabled() &&
			(alloc_flags & ALLOC_CPUSET) &&
			!cpuset_zone_allowed(zone, gfp_mask))
				continue;
		/*
		 * Distribute pages in proportion to the individual
		 * zone size to ensure fair page aging.  The zone a
		 * page was allocated in should have no effect on the
		 * time the page has in memory before being reclaimed.
		 */
/**/	if (alloc_flags & ALLOC_FAIR) {
/**/		if (!zone_local(ac->preferred_zone, zone))
				break;
/**/		if (test_bit(ZONE_FAIR_DEPLETED, &zone->flags)) {
				nr_fair_skipped++;
				continue;
			}
		}
```

Here is big comment that I shall list independent.

```c
	/*
	 * When allocating a page cache page for writing, we
	 * want to get it from a zone that is within its dirty
	 * limit, such that no single zone holds more than its
	 * proportional share of globally allowed dirty pages.
	 * The dirty limits take into account the zone's
	 * lowmem reserves and high watermark so that kswapd
	 * should be able to balance it without having to
	 * write pages from its LRU list.
	 *
	 * This may look like it could increase pressure on
	 * lower zones by failing allocations in higher zones
	 * before they are full.  But the pages that do spill
	 * over are limited as the lower zones are protected
	 * by this very same mechanism.  It should not become
	 * a practical burden to them.
	 *
	 * XXX: For now, allow allocations to potentially
	 * exceed the per-zone dirty limit in the slowpath
	 * (spread_dirty_pages unset) before going into reclaim,
	 * which is important when on a NUMA setup the allowed
	 * zones are together not big enough to reach the
	 * global limit.  The proper fix for these situations
	 * will require awareness of zones in the
	 * dirty-throttling and the flusher threads.
	 */
```

Blabla dirty limit? Just remember it and we temporarily don't care.

```c++
// mm/page_alloc.c get_page_from_freelist part-2
/**/	if (ac->spread_dirty_pages && !zone_dirty_ok(zone))
			continue;

/**/	mark = zone->watermark[alloc_flags & ALLOC_WMARK_MASK];
/**/	if (!zone_watermark_ok(zone, order, mark,
				       ac->classzone_idx, alloc_flags)) {
			int ret;

			/* Checked here to keep the fast path fast */
			BUILD_BUG_ON(ALLOC_NO_WATERMARKS < NR_WMARK);
			if (alloc_flags & ALLOC_NO_WATERMARKS)
				goto try_this_zone;

			if (zone_reclaim_mode == 0 ||
			    !zone_allows_reclaim(ac->preferred_zone, zone))
				continue;

			ret = zone_reclaim(zone, gfp_mask, order);
			switch (ret) {
			case ZONE_RECLAIM_NOSCAN:
				/* did not scan */
				continue;
			case ZONE_RECLAIM_FULL:
				/* scanned but unreclaimable */
				continue;
			default:
				/* did we reclaim enough */
/**/			if (zone_watermark_ok(zone, order, mark,
						ac->classzone_idx, alloc_flags))
					goto try_this_zone;

				continue;
			}
		}
try_this_zone:
/**/	page = buffered_rmqueue(ac->preferred_zone, zone, order,
				gfp_mask, alloc_flags, ac->migratetype);
/**/	if (page) {
/**/		if (prep_new_page(page, order, gfp_mask, alloc_flags))
				goto try_this_zone;

			/*
			 * If this is a high-order atomic allocation then check
			 * if the pageblock should be reserved for the future
			 */
			if (unlikely(order && (alloc_flags & ALLOC_HARDER)))
				reserve_highatomic_pageblock(page, zone, order);

/**/		return page;
		}
	}
	/* ... */
}
```

So confusing... when debugging through these unfamilar functions. Hope one day can figure it out.

```c++
//  mm/page_alloc.c __alloc_pages_nodemask part-3
	if (unlikely(!page)) {
		/* ... */
	}

/**/if (kmemcheck_enabled && page)
		kmemcheck_pagealloc_alloc(page, order, gfp_mask);

/**/trace_mm_page_alloc(page, order, alloc_mask, ac.migratetype);

out:
	/*
	 * When updating a task's mems_allowed, it is possible to race with
	 * parallel threads in such a way that an allocation can fail while
	 * the mask is being updated. If a page allocation is about to fail,
	 * check if the cpuset changed during allocation and if so, retry.
	 */
/**/if (unlikely(!page && read_mems_allowed_retry(cpuset_mems_cookie)))
		goto retry_cpuset;

/**/return page;
}
```
At last, a long way when the page if going to return.

```c++
```c++
// mm/memory.c do_anonymous_page part-1
/**/if (!page)
		goto oom;

/**/if (mem_cgroup_try_charge(page, mm, GFP_KERNEL, &memcg))
		goto oom_free_page;

	/*
	 * The memory barrier inside __SetPageUptodate makes sure that
	 * preceeding stores to the page contents become visible before
	 * the set_pte_at() write.
	 */
/**/__SetPageUptodate(page);

/**/entry = mk_pte(page, vma->vm_page_prot);
	if (vma->vm_flags & VM_WRITE)
		entry = pte_mkwrite(pte_mkdirty(entry));

/**/page_table = pte_offset_map_lock(mm, pmd, address, &ptl);
/**/if (!pte_none(*page_table))
		goto release;

	/* Deliver the page fault to userland, check inside PT lock */
/**/if (userfaultfd_missing(vma)) {
		/* ... */
	}

/**/inc_mm_counter_fast(mm, MM_ANONPAGES);
/**/page_add_new_anon_rmap(page, vma, address);
/**/mem_cgroup_commit_charge(page, memcg, false);
/**/lru_cache_add_active_or_unevictable(page, vma);
setpte:
/**/set_pte_at(mm, address, page_table, entry);

	/* No need to invalidate - it was non-present before */
/**/update_mmu_cache(vma, address, page_table);
unlock:
/**/pte_unmap_unlock(page_table, ptl);
	return 0;
release:
	mem_cgroup_cancel_charge(page, memcg);
	page_cache_release(page);
	goto unlock;
oom_free_page:
	page_cache_release(page);
oom:
	return VM_FAULT_OOM;
}
```

Then we come back to `handle_pte_fault` and `handle_mm_fault`, then `__do_page_fault`.... Anyway, after the page table is set, no more page faults shall happen in this address area.

## Misc

### How many pages will page fault return?

During debugging, the `do_page_fault` will be call several times, indicates that it won't allocate the entire pages for the anonymous area but just one page a time. (From observing)

### What about *read* the content?

Notice this part of code.

```c++
// do_anonymous_page
	/* Use the zero-page for reads */
	if (!(flags & FAULT_FLAG_WRITE) && !mm_forbids_zeropage(mm)) {
		entry = pte_mkspecial(pfn_pte(my_zero_pfn(address),
						vma->vm_page_prot));
		page_table = pte_offset_map_lock(mm, pmd, address, &ptl);
		if (!pte_none(*page_table))
			goto unlock;
		/* Deliver the page fault to userland, check inside PT lock */
		if (userfaultfd_missing(vma)) {
			pte_unmap_unlock(page_table, ptl);
			return handle_userfault(vma, address, flags,
						VM_UFFD_MISSING);
		}
		goto setpte;
	}
```

The comments here tells us that if a read page of anonymous area fault occurs, the page fault handler just use the zero-page (see manual that MAP_ANONYMOUS stands for zero initalizing). That's an optimization of handling page fault.

## Conclusion

I bet it's not very interesting debugging and reading Linux source code. Especially the memory management contents. There is a paradox here for you want to get a abstract recognition and starts reading the code. However, so many tedious and complex stuff occurs (Guess that is the reason why we shall learn the old kernel.)

Anyway, we now know that how anonymous mmap is working (generally).

1. `mmap` syscall will deal with the mapping in `vm_area_struct`.

2. `do_page_fault` will catch the access to newly mapped memory, and interact with the buddy system (the critical function is `__alloc_pages_nodemask`) to obtain a real page, then update the page table, set the entry and return. 

In the future, we shall dig deeper and deeper!

***

[^1]: [Deconstructing Kernel Isolation](https://www.blackhat.com/docs/eu-14/materials/eu-14-Kemerlis-Ret2dir-Deconstructing-Kernel-Isolation.pdf)

[^2]: [personality system call](https://man7.org/linux/man-pages/man2/personality.2.html)

[^3]: [stack guard page](https://blogs.gnome.org/markmc/2005/05/11/stack-guard-page/)

