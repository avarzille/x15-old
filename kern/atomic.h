/*
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

#ifndef _KERN_ATOMIC_H
#define _KERN_ATOMIC_H

#include <machine/atomic.h>

/* Supported memory orders */
#define MO_RELAXED   __ATOMIC_RELAXED
#define MO_ACQUIRE   __ATOMIC_ACQUIRE
#define MO_RELEASE   __ATOMIC_RELEASE
#define MO_ACQ_REL   __ATOMIC_ACQ_REL
#define MO_SEQ_CST   __ATOMIC_SEQ_CST

/* Type-generic atomic operations */

#define atomic_fetch_add(ptr, val, mo)   __atomic_fetch_add((ptr), (val), mo)

#define atomic_fetch_sub(ptr, val, mo)   __atomic_fetch_sub((ptr), (val), mo)

#define atomic_fetch_and(ptr, val, mo)   __atomic_fetch_and((ptr), (val), mo)

#define atomic_fetch_or(ptr, val, mo)    __atomic_fetch_or((ptr), (val), mo)

#define atomic_fetch_xor(ptr, val, mo)   __atomic_fetch_xor((ptr), (val), mo)

#define atomic_add(ptr, val, mo)   ((void)__atomic_add_fetch((ptr), (val), mo))

#define atomic_sub(ptr, val, mo)   ((void)__atomic_sub_fetch((ptr), (val), mo))

#define atomic_and(ptr, val, mo)   ((void)__atomic_and_fetch((ptr), (val), mo))

#define atomic_or(ptr, val, mo)    ((void)__atomic_or_fetch((ptr), (val), mo))

#define atomic_xor(ptr, val, mo)   ((void)__atomic_xor_fetch((ptr), (val), mo))

#define atomic_swap(ptr, val, mo)   __atomic_exchange_n((ptr), (val), mo)

/*
 * For compare-and-swap, we deviate a little from the standard, and only
 * return the value before the comparison, leaving it up to the user to
 * determine whether the swap was actually performed or not.
 */
#define atomic_cas(ptr, exp, nval, mo)                            \
MACRO_BEGIN                                                       \
    typeof(*(ptr)) ___exp, ___nval;                               \
                                                                  \
    ___exp = (exp);                                               \
    ___nval = (nval);                                             \
    __atomic_compare_exchange_n((ptr), &___exp, ___nval, 0, mo,   \
                                __ATOMIC_RELAXED);                \
    ___exp;                                                       \
MACRO_END

/*
 * Some architectures may need specific definitions for loads and stores,
 * in order to prevent the compiler from emitting unsupported instructions.
 * As such, we only define these if the arch header didn't already.
 */

#ifndef ARCH_ATOMIC_LOAD
#define atomic_load(ptr, mo)   __atomic_load_n((ptr), mo)
#endif /* ARCH_ATOMIC_LOAD */

#ifndef ARCH_ATOMIC_STORE
#define atomic_store(ptr, val, mo)   __atomic_store_n((ptr), (val), mo)
#endif /* ARCH_ATOMIC_STORE */

/* If no local atomics were defined, alias them to the generic ones */

#ifndef ARCH_HAVE_LOCAL_ATOMICS

#define latomic_cas         atomic_cas
#define latomic_swap        atomic_swap
#define latomic_fetch_add   atomic_fetch_add
#define latomic_add         atomic_add
#define latomic_and         atomic_and
#define latomic_or          atomic_or
#define latomic_xor         atomic_xor

#endif /* ARCH_HAVE_LOCAL_ATOMICS */

#endif /* _KERN_ATOMIC_H */
