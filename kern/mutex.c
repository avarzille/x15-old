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

#ifndef X15_MUTEX_PI

#include <stdbool.h>
#include <stddef.h>

#include <kern/mutex.h>
#include <kern/mutex_i.h>
#include <kern/sleepq.h>

#define MUTEX_FLAGS_ALL   (MUTEX_WAITERS | MUTEX_LOCKED)

static struct thread*
mutex_owner_thread(uintptr_t owner)
{
    return ((struct thread *)(owner & ~MUTEX_FLAGS_ALL));
}

/* Atomically modify the owner of a mutex, so that:
 * - If it's zero: Set ourselves as the new owner.
 * - If it's nonzero: Add a reference to the it and set the contended bit. */

static uintptr_t
mutex_update_owner(struct mutex *mutex, uintptr_t self)
{
    uintptr_t owner, new_owner;

    for (;;) {
        owner = atomic_load_acquire(&mutex->owner);

        if (owner & MUTEX_LOCKED) {
            continue;
        }

        new_owner = owner == 0 ? self : owner | MUTEX_FLAGS_ALL;
        if (atomic_cas_acquire(&mutex->owner, owner, new_owner) == owner) {
            if (owner != 0) {
                thread_ref(mutex_owner_thread(owner));
                /* clear the lock bit */
                atomic_store_release(&mutex->owner,
                                     new_owner & ~MUTEX_LOCKED);
            }

            return owner;
        }
    }
}

void
mutex_lock_slow(struct mutex *mutex)
{
    struct sleepq *sleepq;
    unsigned long flags;
    uintptr_t owner, self;

    self = (uintptr_t)thread_self();
    owner = mutex_update_owner(mutex, self);

    if (owner == 0) {
        return;
    }

    for (;;) {
        /* if the owner matches our expectation, and it's running, spin */
        if ((atomic_load_acquire(&mutex->owner) | MUTEX_FLAGS_ALL) ==
            (owner | MUTEX_FLAGS_ALL)) {
            if (thread_is_running(mutex_owner_thread(owner))) {
                continue;
            }

            break;
        }

        /* the owner changed - unref the old one and retry */
        thread_unref(mutex_owner_thread(owner));
        owner = mutex_update_owner(mutex, self);

        if (owner == 0) {
            return;
        }
    }

    /* spinning didn't work - sleep */
    sleepq = sleepq_lend(mutex, false, &flags);

    for (;;) {
        if ((atomic_load_acquire(&mutex->owner) | MUTEX_FLAGS_ALL) ==
            (owner | MUTEX_FLAGS_ALL)) {
            sleepq_wait(sleepq, "mutex");
            continue;
        }

        thread_unref(mutex_owner_thread(owner));
        owner = mutex_update_owner(mutex, self);
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
        owner = atomic_load_acquire(&mutex->owner);

        if (owner & MUTEX_LOCKED) {
            continue;
        } else if (atomic_cas_acquire(&mutex->owner, owner,
                                      owner | MUTEX_LOCKED) == owner) {
            sleepq = sleepq_acquire(mutex, false, &flags);
            if (sleepq != NULL) {
                sleepq_signal(sleepq);
                sleepq_release(sleepq, flags);
            }

            atomic_store_release(&mutex->owner, 0);
            return;
        }
    }
}

#endif /* X15_MUTEX_PI */
