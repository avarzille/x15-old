/*
 * Copyright (c) 2012-2014 Richard Braun.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <kern/init.h>
#include <kern/macros.h>
#include <kern/param.h>
#include <kern/thread.h>
#include <machine/cpu.h>
#include <machine/pmap.h>
#include <machine/strace.h>
#include <machine/tcb.h>

/*
 * Low level functions.
 */
void __noreturn tcb_context_load(struct tcb *tcb);
void __noreturn tcb_start(void);

struct tcb *tcb_current_ptr __percpu;

int
tcb_init(struct tcb *tcb, void *stack, void (*fn)(void))
{
    void **ptr;
    int error;

    error = pmap_thread_init(thread_from_tcb(tcb));

    if (error) {
        return error;
    }

    tcb->bp = 0;
    tcb->sp = (unsigned long)stack + STACK_SIZE - sizeof(unsigned long);
    tcb->ip = (unsigned long)tcb_start;

    ptr = (void **)tcb->sp;
    *ptr = fn;

    return 0;
}

void __init
tcb_load(struct tcb *tcb)
{
    assert(!cpu_intr_enabled());

    tcb_set_current(tcb);
    tcb_context_load(tcb);
}

void
tcb_trace(const struct tcb *tcb)
{
    strace_show(tcb->ip, tcb->bp);
}
