/*
 * Copyright (c) 2017 Richard Braun.
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

#ifndef _KERN_MUTEX_PLAIN_I_H
#define _KERN_MUTEX_PLAIN_I_H

#include <kern/atomic.h>
#include <kern/error.h>

#define MUTEX_UNLOCKED  0
#define MUTEX_LOCKED    1
#define MUTEX_CONTENDED 2

static inline void
mutex_impl_init(struct mutex *mutex)
{
    mutex->state = MUTEX_UNLOCKED;
}

#define mutex_assert_locked_impl(mutex) \
  assert((mutex)->state != MUTEX_UNLOCKED)

static inline int
mutex_lock_fast(struct mutex *mutex)
{
    unsigned int state;

    state = atomic_cas_acquire(&mutex->state, MUTEX_UNLOCKED, MUTEX_LOCKED);

    if (state == MUTEX_UNLOCKED) {
        return 0;
    }

    return ERROR_BUSY;
}

static inline int
mutex_unlock_fast(struct mutex *mutex)
{
    unsigned int state;

    state = atomic_swap_release(&mutex->state, MUTEX_UNLOCKED);

    if (state == MUTEX_CONTENDED) {
        return ERROR_BUSY;
    }

    return 0;
}

void mutex_lock_slow(struct mutex *mutex);
void mutex_unlock_slow(struct mutex *mutex);

#ifdef X15_MUTEX_IMPL

#include <kern/sleepq.h>
#include <kern/thread.h>

void
mutex_lock_slow(struct mutex *mutex)
{
    unsigned int state;
    struct sleepq *sleepq;
    unsigned long flags;

    sleepq = sleepq_lend(mutex, false, &flags);

    for (;;) {
        state = atomic_swap_release(&mutex->state, MUTEX_CONTENDED);

        if (state == MUTEX_UNLOCKED) {
            break;
        }

        sleepq_wait(sleepq, "mutex");
    }

    if (sleepq_empty(sleepq)) {
        atomic_store(&mutex->state, MUTEX_LOCKED, ATOMIC_RELEASE);
    }

    sleepq_return(sleepq, flags);
}

void
mutex_unlock_slow(struct mutex *mutex)
{
    struct sleepq *sleepq;
    unsigned long flags;

    sleepq = sleepq_acquire(mutex, false, &flags);

    if (sleepq != NULL) {
        sleepq_signal(sleepq);
        sleepq_release(sleepq, flags);
    }
}

#endif /* X15_MUTEX_IMPL */

#endif /* _KERN_MUTEX_PLAIN_I_H */
