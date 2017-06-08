/*
 * Copyright (c) 2013-2017 Richard Braun.
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

#ifndef _KERN_MUTEX_I_H
#define _KERN_MUTEX_I_H

#ifndef X15_MUTEX_PI

#include <kern/assert.h>

#include <kern/atomic.h>
#include <kern/mutex_types.h>
#include <kern/thread.h>

#define MUTEX_WAITERS       1
#define MUTEX_FORCE_WAIT    2

static inline uintptr_t
mutex_lock_fast(struct mutex *mutex)
{
    return atomic_cas_acquire(&mutex->owner, 0, (uintptr_t)thread_self());
}

static inline uintptr_t
mutex_unlock_fast(struct mutex *mutex)
{
    return atomic_cas_release(&mutex->owner, (uintptr_t)thread_self(), 0);
}

void mutex_lock_slow(struct mutex *mutex);

void mutex_unlock_slow(struct mutex *mutex);

#endif /* X15_MUTEX_PI */

#endif /* _KERN_MUTEX_I_H */
