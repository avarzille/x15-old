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

#ifndef _KERN_MUTEX_RT_I_H
#define _KERN_MUTEX_RT_I_H

#include <kern/rtmutex.h>

static inline void
mutex_impl_init(struct mutex *mutex)
{
    rtmutex_init(&mutex->rtmutex);
}

#define mutex_assert_locked_impl(mutex) \
  rtmutex_assert_locked(&(mutex)->rtmutex)

static inline int
mutex_lock_fast(struct mutex *mutex)
{
    return rtmutex_trylock(&mutex->rtmutex);
}

static inline int
mutex_unlock_fast(struct mutex *mutex)
{
    uintptr_t prev;

    prev = rtmutex_unlock_fast(&mutex->rtmutex);

    if (prev != 0) {
        return ERROR_BUSY;
    }

    return 0;
}

void mutex_lock_slow(struct mutex *mutex);
void mutex_unlock_slow(struct mutex *mutex);

#ifdef X15_MUTEX_IMPL

void
mutex_lock_slow(struct mutex *mutex)
{
    rtmutex_lock_slow(&mutex->rtmutex);
}

void
mutex_unlock_slow(struct mutex *mutex)
{
    rtmutex_unlock_slow(&mutex->rtmutex);
}

#endif /* X15_MUTEX_IMPL */

#endif /* _KERN_MUTEX_RT_I_H */
