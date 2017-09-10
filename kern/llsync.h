/*
 * Copyright (c) 2013-2017 Richard Braun.
 * Copyright (c) 2017 Agustina Arzille.
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
 *
 *
 * Preemptable, non-sleeping lockless synchronization.
 */

#ifndef _KERN_LLSYNC_H
#define _KERN_LLSYNC_H

#include <stdbool.h>

#include <kern/atomic.h>
#include <kern/work.h>

/*
 * Safely store a pointer.
 */
#define llsync_store_ptr(ptr, value) atomic_store(&(ptr), value, ATOMIC_RELEASE)

/*
 * Safely load a pointer.
 */
#define llsync_load_ptr(ptr) atomic_load(&(ptr), ATOMIC_CONSUME)

typedef unsigned int llsync_key_t;

llsync_key_t llsync_read_enter(const void *ptr);

void llsync_read_exit(llsync_key_t key);

bool llsync_ready(void);

static inline void
llsync_register(void)
{
}

static inline void
llsync_unregister(void)
{
}

static inline void
llsync_report_context_switch(void)
{
}

void llsync_report_periodic_event(void);

void llsync_defer(struct work *work);

/*
 * Wait for a quiescent state on a specific predicate.
 */
void llsync_wait_for(const void *ptr);

/*
 * Wait for every thread to be in a quiescent state.
 */
void llsync_wait_all(void);

/*
 * The following macro may be called with one argument, in which case
 * it's dispatched as 'llsync_wait_for', or with no arguments, thereby
 * evaluating to 'llsync_wait_all'.
 */
#define llsync_wait(...)                               \
MACRO_BEGIN                                            \
     const void *___p[] = { 0, ##__VA_ARGS__ };        \
     _Static_assert(ARRAY_SIZE(___p) <= 2,             \
       "too many arguments in call to 'llsync_wait'"); \
                                                       \
     if (ARRAY_SIZE(___p) == 1) {                      \
         llsync_wait_all();                            \
     } else {                                          \
         llsync_wait_for(___p[1]);                     \
     }                                                 \
    (void)0;                                           \
MACRO_END

#endif /* _KERN_LLSYNC_H */
