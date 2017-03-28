/*
 * Copyright (c) 2012-2017 Richard Braun.
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
 * Architecture-specific atomic operations and definitions.
 *
 * When referring to atomic operations, "local" means processor-local.
 */

#ifndef _X86_ATOMIC_H
#define _X86_ATOMIC_H

#include <machine/mb.h>

#ifdef __LP64__

#define atomic_load(ptr, mo)         __atomic_load_n((ptr), mo)
#define atomic_store(ptr, val, mo)   __atomic_store_n((ptr), (val), mo)

#else /* __LP64__ */

/*
 * On x86, the compiler generates either an FP-stack read/write, or an SSE2
 * store/load to implement these 64-bit atomic operations. Since that's not
 * feasible on kernel-land, we fallback to cmpxchg8b. Note that this means
 * that 'atomic_load' cannot be used on a const pointer. However, if it's
 * being accessed by an atomic operation, then it's very likely that it can
 * also be modified, so it should be OK.
 */

#define atomic_load(ptr, mo)                                              \
MACRO_BEGIN                                                               \
    typeof(*(ptr)) ___ret;                                                \
                                                                          \
    if (sizeof(___ret) != 8) {                                            \
        ___ret = __atomic_load_n((ptr), mo);                              \
    } else {                                                              \
        ___ret = 0;                                                       \
        __atomic_compare_exchange_n((uint64_t *)(ptr), &___ret, ___ret,   \
                                    0, mo, __ATOMIC_RELAXED);             \
    }                                                                     \
                                                                          \
    ___ret;                                                               \
MACRO_END

#define atomic_store(ptr, val, mo)                                        \
MACRO_BEGIN                                                               \
    if (sizeof(*(ptr) != 8)) {                                            \
        __atomic_store_n((ptr), (val), mo);                               \
    } else {                                                              \
        typeof(ptr) ___ptr;                                               \
        typeof(val) ___val, ___exp;                                       \
                                                                          \
        ___ptr = (uint64_t *)(ptr);                                       \
        ___val = (val);                                                   \
        ___exp = *___ptr;                                                 \
                                                                          \
        while (!__atomic_compare_exchange_n(___ptr, &___exp, ___val, 0,   \
               momo, __ATOMIC_RELAXED)) {                                 \
        }                                                                 \
                                                                          \
    }                                                                     \
MACRO_END

#endif /* __LP64__ */

/* notify the generic header that we implemented loads and stores */
#define ATOMIC_LOAD_DEFINED
#define ATOMIC_STORE_DEFINED

#define atomic_mb_pre(mo)   \
  (mo == ATOMIC_ACQUIRE || mo == ATOMIC_ACQ_REL ? mb_load() :   \
      mo == ATOMIC_SEQ_CST ? mb_sync() : (void)0)

#define atomic_mb_post(mo)   \
  (mo == ATOMIC_RELEASE || mo == ATOMIC_ACQ_REL ? mb_store() :   \
      mo == ATOMIC_SEQ_CST ? mb_sync() : (void)0)

#define latomic_cas_helper(ptr, exp, nval, mo)   \
MACRO_BEGIN                                      \
    typeof(*(ptr)) ___ret;                       \
                                                 \
    atomic_mb_pre(mo);                           \
    asm volatile("cmpxchg %3, %0"                \
                 : "+m" (*ptr), "=a" (___ret)    \
                 : "1" (exp), "r" (nval)         \
                 : "memory");                    \
                                                 \
    atomic_mb_post(mo);                          \
    ___ret;                                      \
MACRO_END

#ifdef __LP64__

#define latomic_cas   latomic_cas_helper

  /*
   * atomic_swap is implemented with an 'xchg' instruction, which always
   * implies a lock prefix, so it's pointless to redefine it here.
   */

#define latomic_swap(ptr, val, mo)   \
       __atomic_exchange_n((ptr), (val), mo)

#else /* __LP64__ */

#define latomic_cas(ptr, exp, nval, mo)                        \
MACRO_BEGIN                                                    \
    typeof(*(ptr)) ___r2;                                      \
                                                               \
    if (sizeof(___r2) != 8) {                                  \
        ___r2 = latomic_cas_helper(ptr, exp, nval, mo);        \
    } else {                                                   \
        uint64_t  ___v2;                                       \
                                                               \
        ___r2 = (exp);                                         \
        ___v2 = (nval);                                        \
                                                               \
        atomic_mb_pre(mo);                                     \
        asm volatile("cmpxchg8b %0"                            \
                     : "+m" (*ptr), "+A" (___r2)               \
                     : "b" ((uint32_t)(___v2 & 0xffffffff)),   \
                       "c" ((uint32_t)(___v2 >> 32))           \
                     : "memory");                              \
        atomic_mb_post(mo);                                    \
    }                                                          \
                                                               \
    ___r2;                                                     \
MACRO_END

#define latomic_swap(ptr, val, mo)                                        \
MACRO_BEGIN                                                               \
    typeof(*(ptr)) ___r2;                                                 \
                                                                          \
    if (sizeof(___r2) != 8) {                                             \
        ___r2 = __atomic_exchange_n((ptr), (val), mo);                    \
    } else {                                                              \
        typeof(___r2) ___val;                                             \
        typeof(ptr) ___ptr;                                               \
        char ___done;                                                     \
                                                                          \
        ___ptr = (ptr);                                                   \
        ___val = (val);                                                   \
        atomic_mb_pre(mo);                                                \
                                                                          \
        do {                                                              \
            ___r2 = *___ptr;                                              \
                                                                          \
            asm volatile("cmpxchg8b %0; setz %1"                          \
                         : "+m" (*___ptr), "=a" (___done)                 \
                         : "A" (___r2), "c" ((uint32_t)(___val >> 32)),   \
                           "b" ((uint32_t)(___val & 0xffffffff))          \
                         : "memory");                                     \
                                                                          \
        } while (!___done);                                               \
                                                                          \
        atomic_mb_post(mo);                                               \
    }                                                                     \
    ___r2;                                                                \
MACRO_END

#endif /* __LP64__ */

#define latomic_fetch_add_helper(ptr, val, mo)   \
MACRO_BEGIN                                      \
    typeof(*(ptr)) ___ret;                       \
                                                 \
    atomic_mb_pre(mo);                           \
    asm volatile("xadd %1, %0"                   \
                 : "+m" (*ptr), "=r" (___ret)    \
                 : "1" (val));                   \
                                                 \
    atomic_mb_post(mo);                          \
    ___ret;                                      \
MACRO_END

#define latomic_add_helper(ptr, val, mo, ret)   \
MACRO_BEGIN                                     \
    atomic_mb_pre(mo);                          \
    asm volatile("add %1, %0"                   \
                 : "+m" (*ptr) : "r" (val));    \
    atomic_mb_post(mo);                         \
    ret;                                        \
MACRO_END

#define latomic_and_helper(ptr, val, mo, ret)   \
MACRO_BEGIN                                     \
    atomic_mb_pre(mo);                          \
    asm volatile("and %1, %0"                   \
                 : "+m" (*ptr) : "r" (val));    \
    atomic_mb_post(mo);                         \
    ret;                                        \
MACRO_END

#define latomic_or_helper(ptr, val, mo, ret)   \
MACRO_BEGIN                                    \
    atomic_mb_pre(mo);                         \
    asm volatile("or %1, %0"                   \
                 : "+m" (*ptr) : "r" (val));   \
    atomic_mb_post(mo);                        \
    ret;                                       \
MACRO_END

#define latomic_xor_helper(ptr, val, mo, ret)   \
MACRO_BEGIN                                     \
    atomic_mb_pre(mo);                          \
    asm volatile("xor %1, %0"                   \
                 : "+m" (*ptr) : "r" (val));    \
    atomic_mb_post(mo);                         \
    ret;                                        \
MACRO_END

#ifdef __LP64__

#define latomic_fetch_add(ptr, val, mo)   \
       latomic_fetch_add_helper(ptr, val, mo)

#define latomic_add(ptr, val, mo)   \
       latomic_add_helper(ptr, val, mo, (void)0)

#define latomic_and(ptr, val, mo)   \
       latomic_and_helper(ptr, val, mo, (void)0)

#define latomic_or(ptr, val, mo)   \
       latomic_or_helper(ptr, val, mo, (void)0)

#define latomic_xor(ptr, val, mo)   \
       latomic_xor_helper(ptr, val, mo, (void)0)

#else /* __LP64__ */

#define latomic_op(ptr, val, op, mo, simple)                    \
MACRO_BEGIN                                                     \
    typeof(*(ptr)) ___r3;                                       \
                                                                \
    if (sizeof(___r3) != 8) {                                   \
        ___r3 = simple(ptr, val, mo);                           \
    } else {                                                    \
        typeof(ptr) ___ptr;                                     \
        typeof(*(ptr)) ___val;                                  \
                                                                \
        ___ptr = (ptr);                                         \
        ___val = (val);                                         \
                                                                \
        do {                                                    \
            ___r3 = *___ptr;                                    \
        } while (latomic_cas(___ptr, ___r3,                     \
                             ___r3 op ___val, mo) != ___r3);    \
    }                                                           \
                                                                \
    ___r3;                                                      \
MACRO_END

#define latomic_fetch_add(ptr, val, mo)   \
       latomic_op(ptr, val, +, mo, latomic_fetch_add_helper)

#define latomic_add(ptr, val, mo)   \
       ((void) latomic_op(ptr, val, +, mo, latomic_fetch_add_helper))

#define latomic_and_2(ptr, val, mo)   latomic_and_helper(ptr, val, mo, 0)
#define latomic_and(ptr, val, mo)   \
       ((void) latomic_op(ptr, val, &, mo, latomic_and_2))

#define latomic_or_2(ptr, val, mo)   latomic_or_helper(ptr, val, mo, 0)
#define latomic_or(ptr, val, mo)   \
       ((void) latomic_op(ptr, val, |, mo, latomic_or_2))

#define latomic_xor_2(ptr, val, mo)   latomic_xor_helper(ptr, val, mo, 0)
#define latomic_xor(ptr, val, mo)   \
       ((void) latomic_op(ptr, val, ^, mo, latomic_xor_2))

#endif /* __LP64__ */

/* Both x86 and x86_64 can use atomic operations on 64-bit values */
#define ATOMIC_HAVE_64B_OPS

/* x86 has local atomic operations */
#define ATOMIC_HAVE_LOCAL_OPS

#endif /* _X86_ATOMIC_H */
