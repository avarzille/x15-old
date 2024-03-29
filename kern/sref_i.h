/*
 * Copyright (c) 2014-2017 Richard Braun.
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

#ifndef _KERN_SREF_I_H
#define _KERN_SREF_I_H

#include <stdint.h>

#include <kern/spinlock.h>
#include <kern/work.h>

#define SREF_WEAKREF_DYING  ((uintptr_t)1)
#define SREF_WEAKREF_MASK   (~SREF_WEAKREF_DYING)

/*
 * Weak reference.
 *
 * A weak reference is a pointer to a reference counter in which the
 * least-significant bit is used to indicate whether the counter is
 * "dying", i.e. about to be destroyed. It must be accessed with atomic
 * instructions.
 */
struct sref_weakref {
    uintptr_t addr;
};

#define SREF_QUEUED 0x1
#define SREF_DIRTY  0x2

/*
 * Scalable reference counter.
 *
 * It's tempting to merge the flags into the next member, but since they're
 * not protected by the same lock, store them separately.
 */
struct sref_counter {
    sref_noref_fn_t noref_fn;

    union {
        struct {
            struct sref_counter *next;
            struct spinlock lock;
            int flags;
            unsigned long value;
            struct sref_weakref *weakref;
        };

        struct work work;
    };
};

#endif /* _KERN_SREF_I_H */
