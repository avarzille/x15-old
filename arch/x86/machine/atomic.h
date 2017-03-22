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
 * Architecture-specific atomic operations and definitions.
 *
 * When referring to atomic operations, "local" means processor-local.
 */

#ifndef _X86_ATOMIC_H
#define _X86_ATOMIC_H

#ifdef __LP64__
#  define atomic_load(ptr, mo)         __atomic_load_n((ptr), mo)
#  define atomic_store(ptr, val, mo)   __atomic_store_n((ptr), (val), mo)

#else /* __LP64__ */

/*
 * On x86, the compiler generates either an FP-stack read/write, or an SSE2
 * store/load to implement these 64-bit atomic operations. Since that's not
 * feasible on kernel-land, we fallback to cmpxchg8b. Note that this means
 * that 'atomic_load' cannot be used on a const pointer. However, if it's
 * being accessed by an atomic operation, then it's very likely that it can
 * also be modified, so it should be OK.
 */

#  define atomic_load(ptr, mo)                                          \
MACRO_BEGIN                                                             \
    typeof(*(ptr)) __ret;                                               \
                                                                        \
    if (sizeof (__ret) != 8) {                                          \
        __ret = __atomic_load_n((ptr), mo);                             \
    } else {                                                            \
        /*                                                              \
         * Use an 'unlikely' value, so that the atomic swap isn't       \
         * actually executed most of the time.                          \
         */                                                             \
        __ret = 0xdeadbeef;                                             \
        __atomic_compare_exchange_n((uint64_t *)(ptr), &__ret, __ret,   \
                                    0, mo, __ATOMIC_RELAXED);           \
    }                                                                   \
                                                                        \
    __ret;                                                              \
MACRO_END

#  define atomic_store(ptr, val, mo)                                   \
MACRO_BEGIN                                                            \
    if (sizeof (*(ptr) != 8)) {                                        \
        __atomic_store_n((ptr), (val), mo);                            \
    } else {                                                           \
        typeof(ptr) __ptr;                                             \
        typeof(val) __val, __exp;                                      \
                                                                       \
        __ptr = (uint64_t *)(ptr);                                     \
        __val = (val);                                                 \
        __exp = *__ptr;                                                \
                                                                       \
        while (!__atomic_compare_exchange_n(__ptr, &__exp, __val, 0,   \
               momo, __ATOMIC_RELAXED)) {                              \
        }                                                              \
                                                                       \
    }                                                                  \
MACRO_END

#endif /* __LP64__ */

/* notify the generic header that we implemented loads and stores */
#define ARCH_ATOMIC_LOAD
#define ARCH_ATOMIC_STORE

#define mb_pre(mo)   \
  (mo == MO_ACQUIRE || mo == MO_ACQ_REL ? mb_load() :   \
      mo == MO_SEQ_CST ? mb_sync() : (void)0)

#define mb_post(mo)   \
  (mo == MO_RELEASE || mo == MO_ACQ_REL ? mb_store() :   \
      mo == MO_SEQ_CST ? mb_sync() : (void)0)

#define latomic_cas_helper(ptr, exp, nval, mo)              \
MACRO_BEGIN                                                 \
    typeof(*(ptr)) __ret;                                   \
                                                            \
    mb_pre(mo);                                             \
    asm volatile("cmpxchg %3, %0"                           \
                 : "+m" (*ptr), "=a" (__ret)                \
                 : "1" (exp), "r" (nval)                    \
                 : "memory");                               \
                                                            \
    mb_post(mo);                                            \
    __ret;                                                  \
MACRO_END

#ifdef __LP64__
#  define latomic_cas   latomic_cas_helper

  /*
   * atomic_swap is implemented with an 'xchg' instruction, which always
   * implies a lock prefix, so it's pointless to redefine it here.
   */

#  define latomic_swap(ptr, val, mo)   \
       __atomic_exchange_n((ptr), (val), mo)

#else /* __LP64__ */

#  define latomic_cas(ptr, exp, nval, mo)                           \
MACRO_BEGIN                                                         \
    typeof(*(ptr)) __r2;                                            \
                                                                    \
    if (sizeof (__r2) != 8) {                                       \
        __r2 = latomic_cas_helper(ptr, exp, nval, mo);              \
    } else {                                                        \
        uint64_t  __v2;                                             \
                                                                    \
        __r2 = (exp);                                               \
        __v2 = (nval);                                              \
                                                                    \
        mb_pre(mo);                                                 \
        asm volatile("cmpxchg8b %0"                                 \
                     : "+m" (*ptr), "+A" (__r2)                     \
                     : "b" ((uint32_t)(__v2 & 0xffffffffu)),        \
                       "c" ((uint32_t)(__v2 >> 32))                 \
                     : "memory");                                   \
        mb_post(mo);                                                \
    }                                                               \
                                                                    \
    __r2;                                                           \
MACRO_END

#  define latomic_swap(ptr, val, mo)                                     \
MACRO_BEGIN                                                              \
    typeof(*(ptr)) __r2;                                                 \
                                                                         \
    if (sizeof(__r2) != 8) {                                             \
        __r2 = __atomic_exchange_n((ptr), (val), mo);                    \
    } else {                                                             \
        typeof(__r2) __val;                                              \
        typeof(ptr) __ptr;                                               \
        char __done;                                                     \
                                                                         \
        __ptr = (ptr);                                                   \
        __val = (val);                                                   \
        mb_pre(mo);                                                      \
                                                                         \
        do {                                                             \
            __r2 = *__ptr;                                               \
                                                                         \
            asm volatile("cmpxchg8b %0; setz %1"                         \
                         : "+m" (*__ptr), "=a" (__done)                  \
                         : "A" (__r2), "c" ((uint32_t)(__val >> 32)),    \
                           "b" ((uint32_t)(__val & 0xffffffffu))         \
                         : "memory");                                    \
                                                                         \
        } while (!__done);                                               \
                                                                         \
        mb_post(mo);                                                     \
    }                                                                    \
    __r2;                                                                \
MACRO_END

#endif /* __LP64__ */

#define latomic_fetch_add_helper(ptr, val, mo)   \
MACRO_BEGIN                                      \
    typeof(*(ptr)) __ret;                        \
                                                 \
    mb_pre(mo);                                  \
    asm volatile("xadd %1, %0"                   \
                 : "+m" (*ptr), "=r" (__ret)     \
                 : "1" (val));                   \
                                                 \
    mb_post(mo);                                 \
    __ret;                                       \
MACRO_END

#define latomic_add_helper(ptr, val, mo, ret)   \
MACRO_BEGIN                                     \
    mb_pre(mo);                                 \
    asm volatile("add %1, %0"                   \
                 : "+m" (*ptr) : "r" (val));    \
    mb_post(mo);                                \
    ret;                                        \
MACRO_END

#define latomic_and_helper(ptr, val, mo, ret)   \
MACRO_BEGIN                                     \
    mb_pre(mo);                                 \
    asm volatile("and %1, %0"                   \
                 : "+m" (*ptr) : "r" (val));    \
    mb_post(mo);                                \
    ret;                                        \
MACRO_END

#define latomic_or_helper(ptr, val, mo, ret)   \
MACRO_BEGIN                                    \
    mb_pre(mo);                                \
    asm volatile("or %1, %0"                   \
                 : "+m" (*ptr) : "r" (val));   \
    mb_post(mo);                               \
    ret;                                       \
MACRO_END

#define latomic_xor_helper(ptr, val, mo, ret)   \
MACRO_BEGIN                                     \
    mb_pre(mo);                                 \
    asm volatile("xor %1, %0"                   \
                 : "+m" (*ptr) : "r" (val));    \
    mb_post(mo);                                \
    ret;                                        \
MACRO_END

#ifdef __LP64__
#  define latomic_fetch_add(ptr, val, mo)   \
       latomic_fetch_add_helper(ptr, val, mo)

#  define latomic_add(ptr, val, mo)   \
       latomic_add_helper(ptr, val, mo, (void)0)

#  define latomic_and(ptr, val, mo)   \
       latomic_and_helper(ptr, val, mo, (void)0)

#  define latomic_or(ptr, val, mo)   \
       latomic_or_helper(ptr, val, mo, (void)0)

#  define latomic_xor(ptr, val, mo)   \
       latomic_xor_helper(ptr, val, mo, (void)0)

#else /* __LP64__ */

#  define latomic_op(ptr, val, op, mo, simple)                                 \
MACRO_BEGIN                                                                    \
    typeof(*(ptr)) __r3;                                                       \
                                                                               \
    if (sizeof(__r3) != 8) {                                                   \
        __r3 = simple(ptr, val, mo);                                           \
    } else {                                                                   \
        typeof(ptr) __ptr;                                                     \
        typeof(*(ptr)) __val;                                                  \
                                                                               \
        __ptr = (ptr);                                                         \
        __val = (val);                                                         \
                                                                               \
        do {                                                                   \
            __r3 = *__ptr;                                                     \
        } while (latomic_cas (__ptr, __r3, __r3 op __val, mo) != __r3);        \
    }                                                                          \
                                                                               \
    __r3;                                                                      \
MACRO_END

#  define latomic_fetch_add(ptr, val, mo)   \
       latomic_op(ptr, val, +, mo, latomic_fetch_add_helper)

#  define latomic_add(ptr, val, mo)   \
       ((void) latomic_op(ptr, val, +, mo, latomic_fetch_add_helper))

#  define latomic_and_2(ptr, val, mo)   latomic_and_helper(ptr, val, mo, 0)
#  define latomic_and(ptr, val, mo)   \
       ((void) latomic_op(ptr, val, &, mo, latomic_and_2))

#  define latomic_or_2(ptr, val, mo)   latomic_or_helper(ptr, val, mo, 0)
#  define latomic_or(ptr, val, mo)   \
       ((void) latomic_op(ptr, val, |, mo, latomic_or_2))

#  define latomic_xor_2(ptr, val, mo)   latomic_xor_helper(ptr, val, mo, 0)
#  define latomic_xor(ptr, val, mo)   \
       ((void) latomic_op(ptr, val, ^, mo, latomic_xor_2))

#endif /* __LP64__ */

/* Both x86 and x86_64 can use atomic operations on 64-bit values */
#define X15_HAVE_64B_ATOMIC

/* x86 has local atomic operations */
#define X15_HAVE_LOCAL_ATOMICS

#endif /* _X86_ATOMIC_H */
