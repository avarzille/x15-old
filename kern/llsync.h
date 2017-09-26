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

void llsync_defer(struct work *work, const void *ptr);

void llsync_wait(const void *ptr);

#endif /* _KERN_LLSYNC_H */
