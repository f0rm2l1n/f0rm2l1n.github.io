---
layout: post
title: How Signal Works inside the Kernel
subtitle: "You'll never wake somebody who pretends to be asleep."
tags: [Kernel]
published: true
---

## Preface

"What will happen if a kernel thread, i.e., the softirq thread receives a terminating signal? Will it die or not?". Recently, perhaps because the research of the kernel concurrency issues is about to drive me crazy, such a question hits me one night. After some quick thinkings, I finally got embarrassed by the complete ignorance of the signal implementation. So this post will try to catch the reader up with the rough details of the signal internal.

## Leveraging signal in user-space

For a user-space C/C++ program, these is a function with prototype `sighandler_t signal(int signum, sighandler_t handler)` that help the programer to register a customized signal handler. You can refer to the manual SIGNAL(2) for the descriptions and below present a simple demo of registerring a handler to handle dividing-zero issue from [stackoverflow](https://stackoverflow.com/questions/39431879/c-handle-signal-sigfpe-and-continue-execution).

> `int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact)` is also a nice choice for registerring or changing handler

```c++
#include <stdio.h>
#include <signal.h>
#include <setjmp.h>
#include <string.h>

jmp_buf fpe;

void handler(int signum)
{
    // Do stuff here then return to execution below
    printf("inside handler\n");
    longjmp(fpe, 1);
}

int main()
{
    volatile int i, j;
    for(i = 0; i < 10; i++) 
    {
        // Call signal handler for SIGFPE
        struct sigaction act;
        struct sigaction oldact;
        memset(&act, 0, sizeof(act));
        act.sa_handler = handler;
        act.sa_flags = SA_NODEFER | SA_NOMASK;
        sigaction(SIGFPE, &act, &oldact);

        if (0 == setjmp(fpe))
        {
            j = i / 0;
            sigaction(SIGFPE, &oldact, &act);
        } else {
            sigaction(SIGFPE, &oldact, &act);
            /* handle SIGFPE */
        }
    }

    printf("After for loop");

    return 0;
}
```

Run this program you will get below output
```
$ ./a.out
inside handler
inside handler
inside handler
inside handler
inside handler
inside handler
inside handler
inside handler
inside handler
inside handler
After for loop
```
Cool, at least you know that the program will not be terminated when dividing zero. But you may wonder what is the `setjmp` and `longjmp`. In short, these two are helpers that glibc provides for error handling. When you call `longjmp` within a registered handler, the control flow will be finally altered as if just return back from the function `setjmp`.
This is the reason why the `for` loop can continue.

> Of course not only the control flow is rewind when calling `longjmp`, the stack is also restored (typically, the stack pointer, possibly the values of other registers and the signal mask. More detailly, Nonvolatile auto variables that are changed between calls to setjmp() and longjmp() are also unpredictable.).

## The kernel part

The signal registeration workflow will finally hit the kernel space via syscall. Inside the kernel code `kernel/signal.c`, there are numbers of system calls exist.

```
(01) restart_syscall
(02) rt_sigprocmask
(03) rt_sigpending
(04) rt_sigtimedwait
(05) kill
(06) pidfd_send_signal
(07) tgkill
(08) tkill
(09) rt_sigqueueinfo
(10) rt_tgsigqueueinfo
(11) signalstack
(12) sigpending
(13) sigprocmask
(14) rt_sigaction
(15) sigaction
(16) sgetmask
(17) ssetmask
(18) signal
(19) pause
(20) rt_sigsuspend
(21) sigsuspend
... (may ignore some) ...
```

Well, we cannot cover all these system calls in this post. If you are interested, you can directly read the source code since all these are not quite long and complex.

> You may find out that there are "similar" system calls that one has the `rt_` prefix while the other is not. Actually, the one with `rt_` prefix is newer and always equipped with new feature (like additional argument). Guess we can it irresponsibly that we can always choose to use the `rt_` prefixed one.

### `signal`

Talk is cheap, just show you the code.

```c
#ifdef __ARCH_WANT_SYS_SIGNAL
/*
 * For backwards compatibility.  Functionality superseded by sigaction.
 */
SYSCALL_DEFINE2(signal, int, sig, __sighandler_t, handler)
{
	struct k_sigaction new_sa, old_sa;
	int ret;

	new_sa.sa.sa_handler = handler;
	new_sa.sa.sa_flags = SA_ONESHOT | SA_NOMASK;
	sigemptyset(&new_sa.sa.sa_mask);

	ret = do_sigaction(sig, &new_sa, &old_sa);

	return ret ? ret : (unsigned long)old_sa.sa.sa_handler;
}
#endif /* __ARCH_WANT_SYS_SIGNAL */
```

This function actually don't do much but act as a wrapper of `do_sigaction` with passing signal and one prepared `k_sigaction` variable.
The `do_sigaction` code is a little complex compared to this interface function and associate with many unfamilair flag masking and unmasking. No matter what, its pseudo-code is shown as below.

```c
int do_sigaction(int sig, struct k_sigaction *act, struct k_sigaction *oact)
{
	struct task_struct *p = current, *t;
	struct k_sigaction *k;
	sigset_t mask;

    // the checking is here
	if (!valid_signal(sig) || sig < 1 || (act && sig_kernel_only(sig)))
		return -EINVAL;

    k = &p->sighand->action[sig-1];

    spin_lock_irq(&p->sighand->siglock);

    /* ... */
    if (oact)
		*oact = *k;
    
    /* ... */
    if (act) {
        /* ... */
        *k = *act;
        /* ... */
    }

    spin_unlock_irq(&p->sighand->siglock);
	return 0;
}
```

That is clear, the purpose of this function is to rewrite the `task_struct->sighand->action[sig-1]` to the newly prepared pointer.

> P.S. `sigaction` or `rt_sigaction` is quite similar to `signal` as they all leverage `do_sigaction` to rewrite the handler.

### signal sending

By quickly searching the pointer dereference expression, you will easily find the spot that seems responsible for returnning the handler.

```c
static void __user *sig_handler(struct task_struct *t, int sig)
{
	return t->sighand->action[sig - 1].sa.sa_handler;
}
```

But wait, who will call this function? And what will happen after this indirect call? A direct jump from the kernel space to the user space? Sounds very weird ehum?
To figure out this, let's just start our debugger and run the above demo program in QEMU.

> P.S. the `sig_handler` is inlined into call site due to the optimization so you perhaps cannot directly put a breakpoint there. By roughly analyzing the calling relation, I put the breakpoint at `send_signal_locked()`.

The stack trace is shown below, which is very self-explanatory.

```c
[#0] Id 1, stopped 0xffffffff810899b8 in send_signal_locked (), reason: BREAKPOINT
──────────────────────────────────────────────────── trace ────
[#0] 0xffffffff810899b8 → send_signal_locked(sig=0x8, info=0xffffc900001ffef0, t=0xffff888003f71d00, type=PIDTYPE_PID)
[#1] 0xffffffff8108a03b → force_sig_info_to_task(info=0xffffc900001ffef0, t=0xffff888003f71d00, handler=HANDLER_CURRENT)
[#2] 0xffffffff8108a998 → force_sig_fault_to_task(sig=<optimized out>, code=<optimized out>, addr=<optimized out>, t=0x7 <fixed_percpu_data+7>)
[#3] 0xffffffff8108a998 → force_sig_fault(sig=<optimized out>, code=<optimized out>, addr=0x0 <fixed_percpu_data>)
[#4] 0xffffffff8102636c → do_trap(trapnr=<optimized out>, signr=<optimized out>, str=<optimized out>, regs=<optimized out>, error_code=<optimized out>, sicode=0x1ffef0, addr=<optimized out>)
[#5] 0xffffffff81de296a → do_error_trap(regs=0xffffc900001fff58, error_code=0x0, str=<optimized out>, trapnr=0x0, signr=0x8, sicode=0x1, addr=0x400c26)
[#6] 0xffffffff81de296a → __exc_divide_error(regs=0xffffc900001fff58)
[#7] 0xffffffff81de296a → exc_divide_error(regs=0xffffc900001fff58)
[#8] 0xffffffff81e00906 → asm_exc_divide_error()
───────────────────────────────────────────────────────────────

Breakpoint 1, send_signal_locked (sig=sig@entry=0x8, info=info@entry=0xffffc900001ffef0, t=t@entry=0xffff888003f71d00, type=type@entry=PIDTYPE_PID) at .../kernel/signal.c:1225
1225		if (info == SEND_SIG_NOINFO) {
gef➤  bt
#0  send_signal_locked (sig=sig@entry=0x8, info=info@entry=0xffffc900001ffef0, t=t@entry=0xffff888003f71d00, type=type@entry=PIDTYPE_PID) at .../kernel/signal.c:1225
#1  0xffffffff8108a03b in force_sig_info_to_task (info=info@entry=0xffffc900001ffef0, t=0xffff888003f71d00, handler=handler@entry=HANDLER_CURRENT) at .../kernel/signal.c:1348
#2  0xffffffff8108a998 in force_sig_fault_to_task (sig=<optimized out>, code=<optimized out>, addr=<optimized out>, t=0x7 <fixed_percpu_data+7>) at .../kernel/signal.c:1719
#3  force_sig_fault (sig=<optimized out>, code=<optimized out>, addr=addr@entry=0x0 <fixed_percpu_data>) at .../kernel/signal.c:1725
#4  0xffffffff8102636c in do_trap (trapnr=<optimized out>, trapnr@entry=0x0, signr=<optimized out>, signr@entry=0x8, str=<optimized out>, regs=<optimized out>, regs@entry=0xffffc900001fff58, error_code=<optimized out>, error_code@entry=0x0, sicode=0x1ffef0, sicode@entry=0x1, addr=<optimized out>) at .../arch/x86/kernel/traps.c:171
#5  0xffffffff81de296a in do_error_trap (regs=0xffffc900001fff58, error_code=0x0, str=<optimized out>, trapnr=0x0, signr=0x8, sicode=0x1, addr=0x400c26) at .../arch/x86/kernel/traps.c:183
#6  __exc_divide_error (regs=0xffffc900001fff58) at .../arch/x86/kernel/traps.c:205
#7  exc_divide_error (regs=0xffffc900001fff58) at .../arch/x86/kernel/traps.c:203
#8  0xffffffff81e00906 in asm_exc_divide_error ()
#9  0x0000000000000000 in ?? ()
```

In short, when the CPU confronts the zero division. The stack trace presents calling history below:
```
asm_exc_divide_error (assembly) -> exc_divide_error -> __exc_divide_error -> do_error_trap -> do_trap -> force_sig_fault -> force_sig_fault_to_task -> force_sig_info_to_task -> send_signal_locked
```

Thereafter, the `send_signal_locked` will call `__send_signal_locked` to actually *send* the signal to the target task, yet again a very big function.
Also, below presents a simplified version.

```c
static int __send_signal_locked(int sig, struct kernel_siginfo *info,
				struct task_struct *t, enum pid_type type, bool force)
{
	/* ... */
    result = TRACE_SIGNAL_IGNORED;
    /* if this signal is ignore-able, just ignore */
	if (!prepare_signal(sig, t, force))
		goto ret;

	pending = (type != PIDTYPE_PID) ? &t->signal->shared_pending : &t->pending;
	/*
	 * Short-circuit ignored signals and support queuing
	 * exactly one non-rt signal, so that we can get more
	 * detailed information about the cause of the signal.
	 */
    /* also known as unreliable signal (<=32) 
     * reliable signal will use queue to manage
     */
	result = TRACE_SIGNAL_ALREADY_PENDING;
	if (legacy_queue(pending, sig))
		goto ret;

	/* ... other corner cases handling ... */

	q = __sigqueue_alloc(sig, t, GFP_ATOMIC, override_rlimit, 0);

	if (q) {
		list_add_tail(&q->list, &pending->list);
		/* ... */
		}
	} else if (!is_si_special(info) &&
		   sig >= SIGRTMIN && info->si_code != SI_USER) {
		/*
		 * Queue overflow, abort.  We may abort if the
		 * signal was rt and sent by user using something
		 * other than kill().
		 */
		result = TRACE_SIGNAL_OVERFLOW_FAIL;
		ret = -EAGAIN;
		goto ret;
	} else {
		/*
		 * This is a silent loss of information.  We still
		 * send the signal, but the *info bits are lost.
		 */
		result = TRACE_SIGNAL_LOSE_INFO;
	}

out_set:
	signalfd_notify(t, sig);
	sigaddset(&pending->signal, sig);

	/* Let multiprocess signals appear after on-going forks */
	if (type > PIDTYPE_TGID) {
		/* ... */
	}

	complete_signal(sig, t, type);
ret:
	trace_signal_generate(sig, info, t, type != PIDTYPE_PID, result);
	return ret;
}
```

The most important adjustment is the state changes to `task->signal->shared_pending / task->pending` (e.g., add the allocated queue to `pending->list`, adding the signal to `pending->signal` via `sigaddset`.)

After the signal is prepared, the `complete_signal` will be called to tell the victim thread to wake up and handle the signal. The simplified routine is like

```
complete_signal -> signal_wake_up -> signal_wake_up_state -> kick_process
```

Notice that the most important state set is happening in `signal_wake_up_state()`.
```c
/*
 * Tell a process that it has a new active signal..
 *
 * NOTE! we rely on the previous spin_lock to
 * lock interrupts for us! We can only be called with
 * "siglock" held, and the local interrupt must
 * have been disabled when that got acquired!
 *
 * No need to set need_resched since signal event passing
 * goes through ->blocked
 */
void signal_wake_up_state(struct task_struct *t, unsigned int state)
{
	lockdep_assert_held(&t->sighand->siglock);

	set_tsk_thread_flag(t, TIF_SIGPENDING); /* remember this flag */

	/*
	 * TASK_WAKEKILL also means wake it up in the stopped/traced/killable
	 * case. We don't check t->state here because there is a race with it
	 * executing another processor and just now entering stopped state.
	 * By using wake_up_state, we ensure the process will wake up and
	 * handle its death signal.
	 */
	if (!wake_up_state(t, state | TASK_INTERRUPTIBLE))
		kick_process(t);
}
```

Bravo, till now, the bitmap of the victim thread is updated, and the signal is prepared and queued.

### all of a sudden (ignore this is okay)

During the debugging, once the division zero instruction is executed, the CPU switches to the handler that is registered in LDT. I thought this switching is just simply PC changing similar to `syscall` instruction.

> P.S. Of course this statement is not accurate enough since `syscall` will not only load the system call entry address but also save RFLAGS, load CS/SS selectors, and updating the privilege level...

To my surprise, after the vulnerable `idiv` is executed, the stack is also changed into kernel context.

```
--- before executing zero division / after executing zero division ---
$rax   : 0x00000000000003 / 0x00000000000003  
$rbx   : 0x00000000400400 / 0x00000000400400  
$rcx   : 0x00000000000000 / 0x00000000000000  
$rdx   : 0x00000000000000 / 0x00000000000000  
$rsp   : 0x007ffe46ded650 / 0xfffffe0000002fd8 < Change
$rbp   : 0x007ffe46ded7a0 / 0x007ffe46ded7a0  
$rsi   : 0x00000000000000 / 0x00000000000000  
$rdi   : 0x000000006bc3a0 / 0x000000006bc3a0  
$rip   : 0x00000000400c26 / 0xffffffff81e008f0 < Change
$r8    : 0x007ffe46ded700 / 0x007ffe46ded700  
$r9    : 0x007ffe46ded7a0 / 0x007ffe46ded7a0  
$r10   : 0x00000000000008 / 0x00000000000008  
$r11   : 0x00000000000206 / 0x00000000000206  
$r12   : 0x00000000401a30 / 0x00000000401a30  
$r13   : 0x00000000000000 / 0x00000000000000  
$r14   : 0x000000006b9018 / 0x000000006b9018  
$r15   : 0x00000000000000 / 0x00000000000000  
```

This bothered me for a while as I cannot figure out how the hardware know which stack to load for handling this exception. Fortunately, I find out the answer in intel specifications (Intel® 64 and IA-32 Architectures Software Developer’s Manual. Chapter 6).

> If the code segment for the handler procedure does not has the same privilege level as the currently executing program or task, , the processor switches to the stack for the handler’s privilege level. 
> 1. Temporarily saves (internally) the current contents of the SS, ESP, EFLAGS, CS, and EIP registers.
> 2. Loads the segment selector and stack pointer for the new stack (that is, the stack for the privilege level being called) from the **TSS** into the SS and ESP registers and switches to the new stack.
> 3. Pushes the temporarily saved SS, ESP, EFLAGS, CS, and EIP values for the
interrupted procedure’s stack onto the new stack.
> 4. Pushes an error code on the new stack (if appropriate).
> 5. Loads the segment selector for the new code segment and the new instruction pointer (from the interrupt gate or trap gate) into the CS and EIP registers, respectively.
> 6. If the call is through an interrupt gate, clears the IF flag in the EFLAGS register.

Yes as you can find out, the stack pointer is loaded from the TSS (Task State Segment). For Linux kernel, it maintains a per-CPU TSS state struct which is always associated with the running task. Hence, for the debugging case, the stack loaded from the TSS is actually the kernel stack of the running demo task.


### signal handling

The acutal signal handling (That is, check if there is any pending signal and preparing the handling stack frame) happens when the victim thread returns to the user mode.

```
exc_divide_error() -> do_error_trap() ... // sending the signal
                   -> irqentry_exit() -> irqentry_exit_to_user_mode() -> exit_to_user_mode_prepare() -> exit_to_user_mode_loop() ...
```

We can find out the signal pending check in `exit_to_user_mode_loop`

```c
static unsigned long exit_to_user_mode_loop(struct pt_regs *regs,
					    unsigned long ti_work)
{
    /* ... */
    if (ti_work & (_TIF_SIGPENDING | _TIF_NOTIFY_SIGNAL))
        arch_do_signal_or_restart(regs);
}
```

`..do_signal..` sounds quite promising for doing the signal. The comment of this function is quite clear.

```c
/*
 * Note that 'init' is a special process: it doesn't get signals it doesn't
 * want to handle. Thus you cannot kill init even with a SIGKILL even by
 * mistake.
 */
void arch_do_signal_or_restart(struct pt_regs *regs)
{
	struct ksignal ksig;

	if (get_signal(&ksig)) {
		/* Whee! Actually deliver the signal.  */
		handle_signal(&ksig, regs); // <-- we find you
		return;
	}

	/* ... */
}
```

Here we won't expand this function `handle_signal` anymore here. If you are interested in that, you can read the [source code](https://elixir.bootlin.com/linux/v6.0-rc4/source/arch/x86/kernel/signal.c#L787) about it.


### Back to our QUESTION

Through a very simple *zero-division* demo, we get a rough picture of how a signal is raised and handled in the kernel world. Now, back to our very first question: what will happen if a kernel thread receives a terminating signal?

Based on our existing accumulations, this question itself is a little peculiar. The signal handling procedure seems taking place when a thread is leaving the kernel space. But as we know, the kernel (background) thread does not have a user space context at all. It is always running in the kernel world hence how the signal is ever handled?

Definitely, something is wrong, or something is missing. To seek the missing piece of truth, let's do another experiment.

That is, I write a simple kernel module to allow the division zero exception to happen in a kernel background thread. Specifically, I choose the timer (softirq) thread as the target. The code snippet is like below.

```c
#include <linux/timer.h>

static struct timer_list gtimer;

static void timer_handler(struct timer_list *t)
{
    volatile int i = 1, j, k = 0;
    j = i / k; // exception
    mod_timer(&gtimer, jiffies + 1 * HZ);
}

// in module initialization
// timer_setup(&gtimer, timer_handler, 0);
// mod_timer(&gtimer, jiffies + 1 * HZ);
```

The kernel log is shown below that this divide error directly cracks the OS and leads to an Oops.

```
[   12.694971] divide error: 0000 [#1] PREEMPT SMP NOPTI
[   12.695862] CPU: 0 PID: 0 Comm: swapper/0 Tainted: G           O      5.19.7 #2
[   12.696305] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS rel-1.14.0-0-g155821a1990b-prebuilt.qemu.org 04/01/2014
[   12.696843] RIP: 0010:timer_handler+0x2f/0x54 [timer_dv]
[   12.698280] Code: 44 24 04 00 00 00 00 c7 44 24 04 01 00 00 00 c7 44 24 08 00 00 00 00 c7 04 24 00 00 00 00 c7 04 24 00 00 00 00 8b 44 24 07
[   12.699177] RSP: 0018:ffffc90000003e94 EFLAGS: 00000292
[   12.700248] RAX: 0000000000000001 RBX: 0000000000000101 RCX: 0000000000000102
[   12.700524] RDX: 0000000000000000 RSI: ffffffffc00000a0 RDI: ffffffffc00023c0
[   12.700792] RBP: dead000000000122 R08: 0000000000000000 R09: 0000000000000000
[   12.701064] R10: 0000000000028000 R11: ffffffffc00000a0 R12: ffff88801f41b940
[   12.701337] R13: ffffffffc00000a0 R14: ffffffffc00000a0 R15: ffffffffc00023c0
[   12.701661] FS:  0000000000000000(0000) GS:ffff88801f400000(0000) knlGS:0000000000000000
[   12.701958] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[   12.702202] CR2: 000000000045a1e0 CR3: 0000000003ee4000 CR4: 00000000000006f0
[   12.702593] Call Trace:
[   12.703483]  <IRQ>
```

Debugging this crash step by step, I found that the signal sending procedure is now different with the user space case.

```c
static nokprobe_inline int
do_trap_no_signal(struct task_struct *tsk, int trapnr, const char *str,
		  struct pt_regs *regs,	long error_code)
{
	if (v8086_mode(regs)) {
		/* ... */
	} else if (!user_mode(regs)) {
        /* it arrives here and finally die() */
		if (fixup_exception(regs, trapnr, error_code, 0))
			return 0;

		tsk->thread.error_code = error_code;
		tsk->thread.trap_nr = trapnr;
		die(str, regs, error_code);
	} else {
		/* ... */
	}

	/* ... */

	return -1;
}
```

Cool, what if there is another exception other than the zero division which allows the `fixup_exception` returns `true` (perhaps means the kernel can handle this). I guess the signal sending will continue as there is a promising handler there.

This experiment is not very fascinating but it shows us that when an exception signal is raised for a kernel background thread, it will be handled, just somewhat differently as it is handled in sending procedure.

So what about the SIGKILL signal? By Googling around, I can give following conclusions:

1. One cannot kill kernel background thread as they are managed entirely by the kernel (always via API like `kthread_run`, `kthread_stop`) [ref](https://www.quora.com/Can-a-kernel-level-thread-kill-terminate-another-kernel-level-thread-via-kill-the-same-mechanism-for-killing-a-user-level-thread)
2. Signals are only delivered when the kernel returns to user mode. Aside from the technical limitation of signal delivery, killing a thread in the middle of kernel code would corrupt the system as the kernel code may be holding an important resource at the time, such as a spin lock or mutex, and killing it would prevent those resources from being released. [ref](https://askubuntu.com/questions/87082/how-do-i-kill-a-kernel-thread-and-do-i-really-want-to-do-so)

Of course, listening to those descriptions is somewhat not enough to persuade us. Let's just kill a kernel thread for testing.

```
# ps aux | grep softirq
   12 root     [ksoftirqd/0]
  124 root     grep softirq
# kill 12
```

Though there are not any error messages, if you keep running `ps` you will find out this kernel thread is still alive. By debugging the whole signal, you can find out this signal is never being added to the victim task.

```c
static int __send_signal_locked(int sig, struct kernel_siginfo *info,
				struct task_struct *t, enum pid_type type, bool force)
{
	struct sigpending *pending;
	struct sigqueue *q;
	int override_rlimit;
	int ret = 0, result;

	lockdep_assert_held(&t->sighand->siglock);

	result = TRACE_SIGNAL_IGNORED;
	if (!prepare_signal(sig, t, force))
		goto ret; // <- the routine returns here
    
    // ...
```
Dig deeper, you can find this function.

```c
static bool sig_task_ignored(struct task_struct *t, int sig, bool force)
{
	void __user *handler;

	handler = sig_handler(t, sig); // returns SIG_IGN

	/* SIGKILL and SIGSTOP may not be sent to the global init */
	if (unlikely(is_global_init(t) && sig_kernel_only(sig)))
		return true;

	if (unlikely(t->signal->flags & SIGNAL_UNKILLABLE) &&
	    handler == SIG_DFL && !(force && sig_kernel_only(sig)))
		return true;

	/* Only allow kernel generated signals to this kthread */
	if (unlikely((t->flags & PF_KTHREAD) &&
		     (handler == SIG_KTHREAD_KERNEL) && !force))
		return true;

	return sig_handler_ignored(handler, sig);
}
```

Since the `sig_handler` returns `SIG_IGN`, this killing signal is just being ignored. In other word, the kernel does not setup killing handler for those background thread so they will not be simply killed by the user space commands.

> Well, I think there can be some other, maybe more obvious conditions check to early return the signal sending.


## Conclusion

In this post, we roughly get a picture of how the signal is handling inside the kernel. That is,
(1) When the signal is raised, the CPU switches to relevant handler to prepare, and send this signal to the victim thread. The handler will also wake up the thread.
(2) When the victim thread is returnning to the user mode, the signal is delivered and handled.

Moreover, a little experiement is taken to explore what will happen if an exception occurs within a kernel background thread: the kernel will `die()` when sending this signal.

We answer our very first question: the background kernel threads will not be terminated even if there is a killing signal sent to them. The reason is that the kernel just registers an ignore-able handler for such a signal.