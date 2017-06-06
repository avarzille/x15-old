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
 */

#ifndef X15_MUTEX_PI

#include <stdbool.h>
#include <stddef.h>

#include <kern/mutex.h>
#include <kern/mutex_i.h>
#include <kern/sleepq.h>

#define MUTEX_FLAGS_ALL   (MUTEX_WAITERS | MUTEX_LOCKED)

static struct thread *
mutex_owner_thread(uintptr_t owner)
{
    return (struct thread *)(owner & ~MUTEX_FLAGS_ALL);
}
 
/* Modifies the owner word of a mutex so that:
 * - If it's zero: Set ourselves as the new owner.
 * - If it's nonzero:
 *   - If the waiters bit is set, return.
 *   - Otherwise, try to atomically set the lock and waiters bit. If we
 *     succeed, add a reference to the owner thread, and clear the lock bit.
 */

static uintptr_t
mutex_owner_update(struct mutex *mutex, uintptr_t self)
{
    uintptr_t owner, new_owner;

    for (;;) {
        owner = atomic_load(&mutex->owner, ATOMIC_RELAXED);

        if (owner & MUTEX_WAITERS) {
            return owner;
        } else if (owner & MUTEX_LOCKED) {
            cpu_pause();
            continue;
        }

        new_owner = owner == 0 ? self : owner | MUTEX_FLAGS_ALL;
        if (atomic_cas_acquire(&mutex->owner, owner, new_owner) == owner) {
            if (owner != 0) {
                thread_ref((struct thread *)owner);
                atomic_store_release(&mutex->owner, new_owner & ~MUTEX_LOCKED);
            }

            return owner;
        }
    }
}

static inline bool
mutex_owner_eq(struct mutex *mutex, uintptr_t owner)
{
    uintptr_t prev;

    prev = atomic_load(&mutex->owner, ATOMIC_RELAXED);
    owner |= prev & MUTEX_WAITERS;
    return owner == (prev & ~MUTEX_LOCKED);
}

void
mutex_lock_slow(struct mutex *mutex)
{
    struct sleepq *sleepq;
    unsigned long flags;
    uintptr_t owner, self, tmp;

    self = (uintptr_t)thread_self();
    owner = mutex_owner_update(mutex, self);

    if (owner == 0) {
        return;
    }

    for (;;) {
        /* If the owner matches our expectation and it's running, spin */
        if (mutex_owner_eq(mutex, owner)) {
            if (thread_is_running(mutex_owner_thread(owner))) {
                continue;
            }

            break;
        }

        /* Delay the call to 'thread_unref', since it can be a
         * potentially expensive operation, and it puts that waiter
         * at a disadvantage. */

        tmp = mutex_owner_update(mutex, self);

        if ((owner & MUTEX_WAITERS) == 0) {
            /* remove the reference that we added. */
            thread_unref(mutex_owner_thread(owner));
        }

        owner = tmp;
        if (owner == 0) {
            return;
        }
    }

    /* Spinning didn't work - sleep */
    sleepq = sleepq_lend(mutex, false, &flags);

    for (;;) {
        if (mutex_owner_eq(mutex, owner)) {
            sleepq_wait(sleepq, "mutex");
            continue;
        }

        tmp = mutex_owner_update(mutex, self);

        if ((owner & MUTEX_WAITERS) == 0) {
            thread_unref(mutex_owner_thread(owner));
        }

        owner = tmp;
        if (owner == 0) {
            break;
        }
    }

    sleepq_return(sleepq, flags);
}

void
mutex_unlock_slow(struct mutex *mutex)
{
    struct sleepq *sleepq;
    unsigned long flags;
    uintptr_t owner;
    
    for (;;) {
        owner = atomic_load_acquire(&mutex->owner) & ~MUTEX_LOCKED;
        if (atomic_cas_release(&mutex->owner, owner, 0) != owner) {
            cpu_pause();
            continue;
        }
        
        sleepq = sleepq_acquire(mutex, false, &flags);
        if (sleepq != NULL) {
            sleepq_signal(sleepq);
            sleepq_release(sleepq, flags);
        }
        
        return;
    }
}

#endif /* X15_MUTEX_PI */
