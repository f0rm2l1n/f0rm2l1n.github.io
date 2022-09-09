---
layout: post
title: Kernel Scheduler and Contexts
subtitle: "sharing is a fact of life"
tags: [Kernel]
published: false
---

# Write Before Anything

Since I recently spent my almost time with concurrency issues, I found that **I am just not very familiar with the entire picture**. There are many times that I had to make my assumption based on the function names and their comments, without understanding the internals.

> To some sense, this means the kernel implements great abstration hence we can be free from the bottom layer.

Well, this somewhat work when handling simple situations, but also may lead to unexpected waste of efforts when handling false alarms. Therefore, I want to write a serious blog here to dig deeper about the Linux kernel concurrency.

The structure of this blog may not be fluent because it is much like a lecture note, just hope you don't mind :).


# Random excerpt from classic

I re-read the classic: 1) Operating Systems - Three Easy Pieces and 2) Linux Device Driver v2, to get below excerpts. Skip it if you are not interested.

> In early Linux kernels, there were relatively few sources of concurrency. Symmetric multiprocessing (SMP) systems were not supported by the kernel, and the only cause of concurrent execution was the servicing of hardware interrupts.

We should keep our eyes on the sources of concurrency.

> Race conditions are a result of uncontrolled access to shared data...But, in the computing world, one-in-a-million events can happen every few seconds, and the consequences can be grave.

Very convincing sentence.

> In the modern, hot-pluggable world, your device could simply disappear while you are in the middle of working with it.

This is why our current work focus on use-after-cleanup.

>  If a nonpreemptive uniprocessor system ever went into a spin on a lock, it would spin forever; no other thread would ever be able to obtain the CPU to release the lock...Because of preemption, even if you never expect your code to run on an SMP system, you still need to implement proper locking.

> Any time kernel code holds a spinlock, preemption is disabled on the relevant processor.

This is because the lock is still be held and other thread tries to obtain the lock will accomplish nothing.

> Here’s another scenario: your driver is executing and has just taken out a lock that controls access to its device. While the lock is held, the device issues an interrupt, which causes your interrupt handler to run. The interrupt handler, before accessing the device, must also obtain the lock. Taking out a spinlock in an interrupt handler is a legitimate thing to do; that is one of the reasons that spinlock operations do not sleep. But what happens if the interrupt routine executes in the same processor as the code that took out the lock originally? While the interrupt handler is spinning, the non interrupt code will not be able to run to release the lock. That processor will spin forever... Avoiding this trap requires disabling interrupts (on the local CPU only) while the spinlock is held.

>  You must also call spin_lock_irqsave and spin_unlock_irqrestore in the same function; otherwise, your code may break on some architectures.

This is very interesting that the `flag` variable is put into the function instead of its pointer

> When running in this sort of atomic context, your code is subject to a number of constraints... When you are outside of process context (i.e. in interrupt context), you must observe the following rules:
> - No access to user space is allowed.
> - The `current` pointer is not meaningful in atomic mode and cannot be used since the relevant code has no connection with the process that has been interrupted.
> - No sleeping or scheduling may be performed.

Just remember all these rules.

> To achieve better cache locality whenever possible. Therefore, a timer that reregisters itself always runs on the same CPU.

You can use primitive `add_timer_on` if you prefer another CPU

> An interrupt is simply a signal that the hardware can send when it wants the processor’s attention.

Quite vivid.


raise questions:
1. processes and threads
2. core data structure
3. how schedule works
3.5 preemtable kernel
4. schedule context
5. what is IRQ
6. various of locks

