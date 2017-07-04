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
 * Mutual exclusion sleep locks.
 *
 * Unlike spin locks, acquiring a mutex may make the calling thread sleep.
 *
 */

#ifndef _KERN_MUTEX_H
#define _KERN_MUTEX_H

#include <kern/mutex_types.h>

#ifdef X15_MUTEX_PI

#ifdef X15_MUTEX_ADAPTIVE
#error "only one of X15_MUTEX_PI and X15_MUTEX_ADAPTIVE may be defined"
#endif /* X15_MUTEX_ADAPTIVE */

#include <kern/mutex/mutex_rt_i.h>

#elif defined(X15_MUTEX_ADAPTIVE)

#include <kern/mutex/mutex_adaptive_i.h>

#else

#include <kern/mutex/mutex_plain_i.h>

#endif /* X15_MUTEX_PI */

#include <kern/thread.h>

/*
 * Initialize a mutex.
 */
static inline void
mutex_init(struct mutex *mutex)
{
    mutex_impl_init(mutex);
}

#define mutex_assert_locked(mutex)   mutex_assert_locked_impl(mutex)

/*
 * Attempt to lock the given mutex.
 *
 * This function may not sleep.
 *
 * Return 0 on success, ERROR_BUSY if the mutex is already locked.
 */
static inline int
mutex_trylock(struct mutex *mutex)
{
    return mutex_lock_fast(mutex);
}

/*
 * Lock a mutex.
 *
 * If the mutex is already locked, the calling thread sleeps until the
 * mutex is unlocked.
 *
 * A mutex can only be locked once.
 */
static inline void
mutex_lock(struct mutex *mutex)
{
    int error;

    error = mutex_lock_fast(mutex);

    if (error) {
        mutex_lock_slow(mutex);
    }
}

/*
 * Unlock a mutex.
 *
 * The mutex must be locked, and must have been locked by the calling
 * thread.
 */
static inline void
mutex_unlock(struct mutex *mutex)
{
    int error;

    error = mutex_unlock_fast(mutex);

    if (error) {
        mutex_unlock_slow(mutex);
    }

    /*
     * If this mutex was used along with a condition variable, wake up
     * a potential pending waiter.
     */
    thread_wakeup_last_cond();
}

#endif /* _KERN_MUTEX_H */
