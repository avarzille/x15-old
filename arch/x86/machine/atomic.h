/*
 * Copyright (c) 2012-2017 Richard Braun.
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
 * Atomic operations.
 *
 * When referring to atomic operations, "local" means processor-local.
 */

#ifndef _X86_ATOMIC_H
#define _X86_ATOMIC_H

#include <stdint.h>

/*
 * Arithmetic and logical operations.
 * We settle at a memory order of 'acquire-release',
 * since that's enough for us.
 */
#define atomic_fetch_add(ptr, val)   \
    __atomic_fetch_add((ptr), (val), __ATOMIC_ACQ_REL)

#define atomic_add(ptr, val)   \
    ((void) __atomic_add_fetch((ptr), (val), __ATOMIC_ACQ_REL))

#define atomic_fetch_sub(ptr, val)   \
    __atomic_fetch_sub((ptr), (val), __ATOMIC_ACQ_REL)

#define atomic_sub(ptr, val)   \
    ((void) __atomic_sub_fetch((ptr), (val), __ATOMIC_ACQ_REL))

#define atomic_fetch_and(ptr, val)   \
    __atomic_fetch_and((ptr), (val), __ATOMIC_ACQ_REL)

#define atomic_and(ptr, val)   \
    ((void) __atomic_and_fetch((ptr), (val), __ATOMIC_ACQ_REL))

#define atomic_fetch_or(ptr, val)   \
    __atomic_fetch_or((ptr), (val), __ATOMIC_ACQ_REL)

#define atomic_or(ptr, val)   \
    ((void) __atomic_or_fetch((ptr), (val), __ATOMIC_ACQ_REL))

#define atomic_fetch_xor(ptr, val)   \
    __atomic_fetch_xor((ptr), (val), __ATOMIC_ACQ_REL)

#define atomic_xor(ptr, val)   \
    ((void) __atomic_xor_fetch((ptr), (val), __ATOMIC_ACQ_REL))

/*
 * For atomic swap and compare-and-swap, we may select one out of three
 * possible memory orders: acquire, release and sequential consistency.
 */

#define atomic_cas_helper(ptr, exp, nval, mo)                       \
MACRO_BEGIN                                                         \
    typeof(*(ptr)) __exp, __nval;                                   \
                                                                    \
    __exp = (exp);                                                  \
    __nval = (nval);                                                \
    __atomic_compare_exchange_n((ptr), &__exp, __nval, 0,           \
                                __ATOMIC_##mo, __ATOMIC_RELAXED);   \
    __exp;                                                          \
MACRO_END

#define atomic_cas_acq(ptr, exp, nval)   \
    atomic_cas_helper((ptr), (exp), (nval), ACQUIRE)

#define atomic_cas_rel(ptr, exp, nval)   \
    atomic_cas_helper((ptr), (exp), (nval), RELEASE)

#define atomic_cas_cst(ptr, exp, nval)   \
    atomic_cas_helper((ptr), (exp), (nval), SEQ_CST)

#define atomic_swap_helper(ptr, val, mo)   \
    __atomic_exchange_n((ptr), (val), __ATOMIC_##mo)

#define atomic_swap_acq(ptr, val)   \
    atomic_swap_helper((ptr), (val), ACQUIRE)

#define atomic_swap_rel(ptr, val)   \
    atomic_swap_helper((ptr), (val), RELEASE)

#define atomic_swap_cst(ptr, val)   \
    atomic_swap_helper((ptr), (val), SEQ_CST)

#ifdef __LP64__
#  define atomic_load_helper(ptr, mo)   __atomic_load_n((ptr), __ATOMIC_##mo)

#  define atomic_store_helper(ptr, val, mo)   \
       __atomic_store_n((ptr), (val), __ATOMIC##_mo)

#else /* __LP64__ */

/*
 * On x86, the compiler generates either an FP-stack read/write, or an SSE2
 * store/load to implement these 64-bit atomic operations. Since that's not
 * feasible on kernel-land, we fallback to cmpxchg8b. Note that this means
 * that 'atomic_load' cannot be used on a const pointer. However, if it's
 * being accessed by an atomic operation, then it's very likely that it can
 * also be modified, so it should be OK.
 */

#  define atomic_load_helper(ptr, mo)                                   \
MACRO_BEGIN                                                             \
    typeof(*(ptr)) __ret;                                               \
                                                                        \
    if (sizeof (__ret) != 8) {                                          \
        __ret = __atomic_load_n((ptr), __ATOMIC_##mo);                  \
    } else {                                                            \
        /*                                                              \
         * Use an 'unlikely' value, so that the atomic swap isn't       \
         * actually executed most of the time.                          \
         */                                                             \
        __ret = 0xdeadbeefcafe;                                         \
        __atomic_compare_exchange_n((ptr), &__ret, __ret, 0,            \
                                    __ATOMIC_##mo, __ATOMIC_RELAXED);   \
    }                                                                   \
                                                                        \
    __ret;                                                              \
MACRO_END

#  define atomic_store_helper(ptr, val, mo)                            \
MACRO_BEGIN                                                            \
    if (sizeof (*(ptr) != 8)) {                                        \
        __atomic_store_n((ptr), (val), __ATOMIC_##mo);                 \
    } else {                                                           \
        typeof(ptr) __ptr;                                             \
        typeof(val) __val, __exp;                                      \
                                                                       \
        __ptr = (uint64_t *)(ptr);                                     \
        __val = (val);                                                 \
        __exp = *__ptr;                                                \
                                                                       \
        while (!__atomic_compare_exchange_n(__ptr, &__exp, __val, 0,   \
               __ATOMIC_##mo, __ATOMIC_RELAXED)) {                     \
        }                                                              \
                                                                       \
    }                                                                  \
MACRO_END

#endif /* __LP64__ */

#define atomic_load_acq(ptr)   atomic_load_helper((ptr), ACQUIRE)
#define atomic_load_rel(ptr)   atomic_load_helper((ptr), RELEASE)
#define atomic_load_cst(ptr)   atomic_load_helper((ptr), SEQ_CST)

#define atomic_store_acq(ptr, val)   \
    atomic_store_helper((ptr), (val), ACQUIRE)

#define atomic_store_rel(ptr, val)   \
    atomic_store_helper((ptr), (val), RELEASE)

#define atomic_store_cst(ptr, val)   \
    atomic_store_helper((ptr), (val), SEQ_CST)

/*
 * Local atomic operations. These are local to a processor, and can therefore
 * elide the 'lock' prefix.
 */

#define latomic_cas_helper_bwl(ptr, exp, nval, pre, post)   \
MACRO_BEGIN                                                 \
    typeof(*(ptr)) __ret;                                   \
                                                            \
    pre;                                                    \
    asm volatile("cmpxchg %3, %0"                           \
                 : "+m" (*ptr), "=a" (__ret)                \
                 : "1" (exp), "r" (nval)                    \
                 : "memory");                               \
                                                            \
    post;                                                   \
                                                            \
    __ret;                                                  \
MACRO_END

#ifdef __LP64__
#  define latomic_cas_helper   latomic_cas_helper_bwl

#else /* __LP64__ */

/*
 * The compiler unconditionally uses the 'lock' prefix, so we have
 * to implement the CAS operation manually here.
 */

#  define latomic_cas_helper(ptr, exp, nval, pre, post)             \
MACRO_BEGIN                                                         \
    typeof(*(ptr)) __r2;                                            \
                                                                    \
    if (sizeof (__r2) != 8) {                                       \
        __r2 = latomic_cas_helper_bwl(ptr, exp, nval, pre, post);   \
    } else {                                                        \
        uint64_t  __v2;                                             \
                                                                    \
        __r2 = (exp);                                               \
        __v2 = (nval);                                              \
        pre;                                                        \
        asm volatile("cmpxchg8b %0"                                 \
                     : "+m" (*ptr), "+A" (__r2)                     \
                     : "b" ((uint32_t)(__v2 & 0xffffffffu)),        \
                       "c" ((uint32_t)(__v2 >> 32))                 \
                     : "memory");                                   \
        post;                                                       \
                                                                    \
    }                                                               \
                                                                    \
    __r2;                                                           \
MACRO_END

#endif /* __LP64__ */

#define latomic_cas_acq(ptr, exp, nval)   \
    latomic_cas_helper(ptr, exp, nval, barrier(), (void)0)

#define latomic_cas_rel(ptr, exp, nval)   \
    latomic_cas_helper(ptr, exp, nval, (void)0, barrier())

#define latomic_cas_cst(ptr, exp, nval)   \
    latomic_cas_helper(ptr, exp, nval, barrier(), barrier())

#define latomic_swap_helper_bwl(ptr, val, pre, post)   \
MACRO_BEGIN                                            \
    typeof(*(ptr)) __ret;                              \
                                                       \
    pre;                                               \
    asm volatile("xchg %1, %0"                         \
                 : "+m" (*ptr), "=r" (__ret)           \
                 : "1" (val)                           \
                 : "memory");                          \
    post;                                              \
                                                       \
    __ret;                                             \
MACRO_END

#ifdef __LP64__
#  define latomic_swap_helper   latomic_swap_helper_bwl

#else /* __LP64__ */

/* same deal with latomic_swap as with latomic_cas */

#  define latomic_swap_helper(ptr, val, pre, post)                       \
MACRO_BEGIN                                                              \
    typeof(*(ptr)) __r2;                                                 \
                                                                         \
    if (sizeof(__r2) != 8) {                                             \
        __r2 = latomic_swap_helper_bwl(ptr, val, pre, post);             \
    } else {                                                             \
        typeof(__r2) __val;                                              \
        typeof(ptr) __ptr;                                               \
        char __done;                                                     \
                                                                         \
        __ptr = (ptr);                                                   \
        __val = (val);                                                   \
                                                                         \
        do {                                                             \
            pre;                                                         \
            __r2 = *__ptr;                                               \
            asm volatile("cmpxchg8b %0; setz %1"                         \
                         : "+m" (*__ptr), "=a" (__done)                  \
                         : "A" (__r2), "c" ((uint32_t)(__val >> 32)),    \
                           "b" ((uint32_t)(__val & 0xffffffffu))         \
                         : "memory");                                    \
            post;                                                        \
        } while (!__done);                                               \
                                                                         \
    }                                                                    \
    __r2;                                                                \
MACRO_END

#endif /* __LP64__ */

#define latomic_swap_acq(ptr, val)   \
    latomic_swap_helper(ptr, val, barrier(), (void)0)

#define latomic_swap_rel(ptr, val)   \
    latomic_swap_helper(ptr, val, (void)0, barrier())

#define latomic_swap_cst(ptr, val)   \
    latomic_swap_helper(ptr, val, barrier(), barrier())

#define latomic_fetch_add_helper(ptr, val)     \
MACRO_BEGIN                                    \
    typeof(*(ptr)) __ret;                      \
                                               \
    asm volatile("xadd %1, %0"                 \
                 : "+m" (*ptr), "=r" (__ret)   \
                 : "1" (val));                 \
                                               \
    __ret;                                     \
MACRO_END

#define latomic_add_helper(ptr, val, ret)      \
MACRO_BEGIN                                    \
    asm volatile("add %1, %0"                  \
                 : "+m" (*ptr) : "r" (val));   \
    ret;                                       \
MACRO_END

#define latomic_and_helper(ptr, val, ret)      \
MACRO_BEGIN                                    \
    asm volatile("and %1, %0"                  \
                 : "+m" (*ptr) : "r" (val));   \
    ret;                                       \
MACRO_END

#define latomic_or_helper(ptr, val, ret)       \
MACRO_BEGIN                                    \
    asm volatile("or %1, %0"                   \
                 : "+m" (*ptr) : "r" (val));   \
    ret;                                       \
MACRO_END

#define latomic_xor_helper(ptr, val)           \
MACRO_BEGIN                                    \
    asm volatile("xor %1, %0"                  \
                 : "+m" (*ptr) : "r" (val));   \
    ret;                                       \
MACRO_END

#ifdef __LP64__
#  define latomic_fetch_add(ptr, val)   \
       latomic_fetch_add_helper(ptr, val, (void)0)

#  define latomic_add(ptr, val)   \
       latomic_add_helper(ptr, val, (void)0)

#  define latomic_and(ptr, val)   \
       latomic_and_helper(ptr, val, (void)0)

#  define latomic_or(ptr, val)   \
       latomic_or_helper(ptr, val, (void)0)

#  define latomic_xor(ptr, val)   \
       latomic_xor_helper(ptr, val, (void)0)

#else /* __LP64__ */

#  define latomic_op(ptr, val, op, mo, simple)  \
MACRO_BEGIN                                                               \
    typeof(*(ptr)) __r2;                                                  \
    if (sizeof(__r2) != 8) {                                              \
        __r2 = simple(ptr, val);                                          \
    } else {                                                              \
        typeof(ptr) __ptr;                                                \
        typeof(*(ptr)) __val;                                             \
                                                                          \
        __ptr = (ptr);                                                    \
        __val = (val);                                                    \
                                                                          \
        do {                                                              \
            __r2 = *__ptr;                                                \
        } while (atomic_cas_##mo (__ptr, __r2, __r2 op __val) != __r2);   \
    }                                                                     \
                                                                          \
    __r2;                                                                 \
MACRO_END

#  define latomic_fetch_add(ptr, val)   \
       latomic_op(ptr, val, +, cst, latomic_fetch_add_helper)

#  define latomic_add(ptr, val)   \
       ((void) latomic_op(ptr, val, +, acq, latomic_fetch_add_helper))

#  define latomic_and_2(ptr, val)   latomic_and_helper(ptr, val, 0)
#  define latomic_and(ptr, val)   \
       ((void) latomic_op(ptr, val, &, acq, latomic_and_2))

#  define latomic_or_2(ptr, val)   latomic_or_helper(ptr, val, 0)
#  define latomic_or(ptr, val)   \
       ((void) latomic_op(ptr, val, |, acq, latomic_or_2))

#  define latomic_xor_2(ptr, val)   latomic_xor_helper(ptr, val, 0)
#  define latomic_xor(ptr, val)   \
       ((void) latomic_op(ptr, val, ^, acq, latomic_xor_2))

#endif /* __LP64__ */

/* Both x86 and x86_64 can use atomic operations on 64-bit values. */
#define X15_HAVE_64B_ATOMIC

#endif /* _X86_ATOMIC_H */
