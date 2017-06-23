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

#include <machine/cpu.h>

static struct thread *
mutex_owner_thread(uintptr_t owner)
{
    return (struct thread *)(owner & ~MUTEX_WAITERS);
}

/*
 * Atomically modify the mutex's owner, so that:
 * - If it's unowned: Set ourselves as the owner.
 * - Otherwise: Set the contended bit if it's not.
 * Returns the owner value previous to the call.
 */

static uintptr_t
mutex_update_owner(struct mutex *mutex, uintptr_t self)
{
    uintptr_t owner, new_owner, ret;

    for (;;) {
        owner = atomic_load(&mutex->owner, ATOMIC_RELAXED);

        if (owner & MUTEX_WAITERS) {
            return owner;
        }

        new_owner = owner <= MUTEX_FORCE_WAIT ?
          self : (owner | MUTEX_WAITERS);

        ret = atomic_cas_acquire(&mutex->owner, owner, new_owner);

        if (ret == owner) {
            return owner;
        }

        cpu_pause();
    }
}

static inline bool
mutex_owner_eq(struct mutex *mutex, uintptr_t owner)
{
    uintptr_t prev;

    prev = atomic_load(&mutex->owner, ATOMIC_RELAXED) & ~MUTEX_WAITERS;
    return prev == (owner & ~MUTEX_WAITERS);
}

void mutex_lock_slow(struct mutex *mutex)
{
    uintptr_t self, owner;
    struct sleepq *sleepq;
    unsigned long flags;

    self = (uintptr_t)thread_self();
    sleepq = sleepq_lend(mutex, false, &flags);
    owner = mutex_update_owner(mutex, self);

    if (owner <= MUTEX_FORCE_WAIT) {
        goto done;
    }

    for (;;) {
        if (mutex_owner_eq(mutex, owner)) {
            if (!thread_is_running(mutex_owner_thread(owner))) {
                sleepq_wait(sleepq, "mutex");
            }

            continue;
        }

        owner = mutex_update_owner(mutex, self | MUTEX_WAITERS);

        if (owner <= MUTEX_FORCE_WAIT) {
            break;
        }
    }

done:
    if (sleepq_empty(sleepq)) {
        atomic_store_release(&mutex->owner, self & ~MUTEX_WAITERS);
    }

    sleepq_return(sleepq, flags);
}

void
mutex_unlock_slow(struct mutex *mutex)
{
    struct sleepq *sleepq;
    unsigned long flags;
    uintptr_t owner;

    atomic_store_release(&mutex->owner, MUTEX_FORCE_WAIT);

    for (;;) {
        owner = atomic_load(&mutex->owner, ATOMIC_RELAXED);

        if (owner != MUTEX_FORCE_WAIT) {
            break;
        }

        sleepq = sleepq_tryacquire(mutex, false, &flags);

        if (sleepq != NULL) {
            sleepq_signal(sleepq);
            sleepq_release(sleepq, flags);
            break;
        }
    }
}

#endif /* X15_MUTEX_PI */

