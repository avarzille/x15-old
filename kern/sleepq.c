/*
 * Copyright (c) 2017 Richard Braun.
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
 * TODO Analyse hash parameters.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <kern/assert.h>
#include <kern/init.h>
#include <kern/kmem.h>
#include <kern/list.h>
#include <kern/macros.h>
#include <kern/param.h>
#include <kern/sleepq.h>
#include <kern/spinlock.h>
#include <kern/thread.h>

struct sleepq_bucket {
    struct spinlock lock;
    struct list list;
} __aligned(CPU_L1_SIZE);

struct sleepq {
    struct sleepq_bucket *bucket;
    struct list node;
    const void *sync_obj;
    struct list waiters;
    struct sleepq *next_free;
};

struct sleepq_waiter {
    struct list node;
    struct thread *thread;
};

#define SLEEPQ_HTABLE_SIZE      128
#define SLEEPQ_COND_HTABLE_SIZE 64

#if !ISP2(SLEEPQ_HTABLE_SIZE) || !ISP2(SLEEPQ_COND_HTABLE_SIZE)
#error hash table size must be a power of two
#endif /* !ISP2(SLEEPQ_HTABLE_SIZE) */

#define SLEEPQ_HTABLE_MASK      (SLEEPQ_HTABLE_SIZE - 1)
#define SLEEPQ_COND_HTABLE_MASK (SLEEPQ_COND_HTABLE_SIZE - 1)

static struct sleepq_bucket sleepq_htable[SLEEPQ_HTABLE_SIZE];
static struct sleepq_bucket sleepq_cond_htable[SLEEPQ_COND_HTABLE_SIZE];

static struct kmem_cache sleepq_cache;

static uintptr_t
sleepq_hash(const void *addr)
{
    return ((uintptr_t)addr >> 8) ^ (uintptr_t)addr;
}

static void
sleepq_waiter_init(struct sleepq_waiter *waiter, struct thread *thread)
{
    waiter->thread = thread;
}

static void
sleepq_waiter_wakeup(struct sleepq_waiter *waiter)
{
    thread_wakeup(waiter->thread);
}

static void
sleepq_assert_init_state(const struct sleepq *sleepq)
{
    assert(sleepq->bucket == NULL);
    assert(sleepq->sync_obj == NULL);
    assert(list_empty(&sleepq->waiters));
    assert(sleepq->next_free == NULL);
}

static void
sleepq_use(struct sleepq *sleepq, const void *sync_obj)
{
    assert(sleepq->sync_obj == NULL);
    sleepq->sync_obj = sync_obj;
}

static void
sleepq_unuse(struct sleepq *sleepq)
{
    assert(sleepq->sync_obj != NULL);
    sleepq->sync_obj = NULL;
}

static bool
sleepq_in_use(const struct sleepq *sleepq)
{
    return sleepq->sync_obj != NULL;
}

static bool
sleepq_in_use_by(const struct sleepq *sleepq, const void *sync_obj)
{
    return sleepq->sync_obj == sync_obj;
}

static void
sleepq_bucket_init(struct sleepq_bucket *bucket)
{
    spinlock_init(&bucket->lock);
    list_init(&bucket->list);
}

static struct sleepq_bucket *
sleepq_bucket_get_cond(const void *sync_obj)
{
    uintptr_t index;

    index = sleepq_hash(sync_obj) & SLEEPQ_COND_HTABLE_MASK;
    assert(index < ARRAY_SIZE(sleepq_cond_htable));
    return &sleepq_cond_htable[index];
}

static struct sleepq_bucket *
sleepq_bucket_get(const void *sync_obj, bool condition)
{
    uintptr_t index;

    if (condition) {
        return sleepq_bucket_get_cond(sync_obj);
    }

    index = sleepq_hash(sync_obj) & SLEEPQ_HTABLE_MASK;
    assert(index < ARRAY_SIZE(sleepq_htable));
    return &sleepq_htable[index];
}

static void
sleepq_bucket_add(struct sleepq_bucket *bucket, struct sleepq *sleepq)
{
    assert(sleepq->bucket == NULL);
    sleepq->bucket = bucket;
    list_insert_tail(&bucket->list, &sleepq->node);
}

static void
sleepq_bucket_remove(struct sleepq_bucket *bucket, struct sleepq *sleepq)
{
    assert(sleepq->bucket == bucket);
    sleepq->bucket = NULL;
    list_remove(&sleepq->node);
}

static struct sleepq *
sleepq_bucket_lookup(const struct sleepq_bucket *bucket, const void *sync_obj)
{
    struct sleepq *sleepq;

    list_for_each_entry(&bucket->list, sleepq, node) {
        if (sleepq_in_use_by(sleepq, sync_obj)) {
            assert(sleepq->bucket == bucket);
            return sleepq;
        }
    }

    return NULL;
}

static void
sleepq_ctor(void *ptr)
{
    struct sleepq *sleepq;

    sleepq = ptr;
    sleepq->bucket = NULL;
    sleepq->sync_obj = NULL;
    list_init(&sleepq->waiters);
    sleepq->next_free = NULL;
}

void __init
sleepq_bootstrap(void)
{
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(sleepq_htable); i++) {
        sleepq_bucket_init(&sleepq_htable[i]);
    }

    for (i = 0; i < ARRAY_SIZE(sleepq_cond_htable); i++) {
        sleepq_bucket_init(&sleepq_cond_htable[i]);
    }
}

void __init
sleepq_setup(void)
{
    kmem_cache_init(&sleepq_cache, "sleepq", sizeof(struct sleepq),
                    CPU_L1_SIZE, sleepq_ctor, 0);
}

struct sleepq *
sleepq_create(void)
{
    struct sleepq *sleepq;

    sleepq = kmem_cache_alloc(&sleepq_cache);

    if (sleepq == NULL) {
        return NULL;
    }

    sleepq_assert_init_state(sleepq);
    return sleepq;
}

void
sleepq_destroy(struct sleepq *sleepq)
{
    sleepq_assert_init_state(sleepq);
    kmem_cache_free(&sleepq_cache, sleepq);
}

struct sleepq *
sleepq_acquire(const void *sync_obj, bool condition, unsigned long *flags)
{
    struct sleepq_bucket *bucket;
    struct sleepq *sleepq;

    assert(sync_obj != NULL);

    bucket = sleepq_bucket_get(sync_obj, condition);

    spinlock_lock_intr_save(&bucket->lock, flags);

    sleepq = sleepq_bucket_lookup(bucket, sync_obj);

    if (sleepq == NULL) {
        spinlock_unlock_intr_restore(&bucket->lock, *flags);
        return NULL;
    }

    return sleepq;
}

void
sleepq_release(struct sleepq *sleepq, unsigned long flags)
{
    spinlock_unlock_intr_restore(&sleepq->bucket->lock, flags);
}

static void
sleepq_push_free(struct sleepq *sleepq, struct sleepq *free_sleepq)
{
    assert(free_sleepq->next_free == NULL);
    free_sleepq->next_free = sleepq->next_free;
    sleepq->next_free = free_sleepq;
}

static struct sleepq *
sleepq_pop_free(struct sleepq *sleepq)
{
    struct sleepq *free_sleepq;

    free_sleepq = sleepq->next_free;

    if (free_sleepq == NULL) {
        return NULL;
    }

    sleepq->next_free = free_sleepq->next_free;
    free_sleepq->next_free = NULL;
    return free_sleepq;
}

struct sleepq *
sleepq_lend(const void *sync_obj, bool condition, unsigned long *flags)
{
    struct sleepq_bucket *bucket;
    struct sleepq *sleepq, *prev;

    assert(sync_obj != NULL);

    sleepq = thread_sleepq_lend();
    sleepq_assert_init_state(sleepq);

    bucket = sleepq_bucket_get(sync_obj, condition);

    spinlock_lock_intr_save(&bucket->lock, flags);

    prev = sleepq_bucket_lookup(bucket, sync_obj);

    if (prev == NULL) {
        sleepq_use(sleepq, sync_obj);
        sleepq_bucket_add(bucket, sleepq);
    } else {
        sleepq_push_free(prev, sleepq);
        sleepq = prev;
    }

    return sleepq;
}

void
sleepq_return(struct sleepq *sleepq, unsigned long flags)
{
    struct sleepq_bucket *bucket;
    struct sleepq *free_sleepq;

    assert(sleepq_in_use(sleepq));

    bucket = sleepq->bucket;
    free_sleepq = sleepq_pop_free(sleepq);

    if (free_sleepq == NULL) {
        sleepq_bucket_remove(bucket, sleepq);
        sleepq_unuse(sleepq);
        free_sleepq = sleepq;
    }

    spinlock_unlock_intr_restore(&bucket->lock, flags);

    sleepq_assert_init_state(free_sleepq);
    thread_sleepq_return(free_sleepq);
}

static void
sleepq_add_waiter(struct sleepq *sleepq, struct sleepq_waiter *waiter)
{
    list_insert_head(&sleepq->waiters, &waiter->node);
}

static void
sleepq_remove_waiter(struct sleepq *sleepq, struct sleepq_waiter *waiter)
{
    (void)sleepq;
    list_remove(&waiter->node);
}

bool
sleepq_empty(const struct sleepq *sleepq)
{
    return list_empty(&sleepq->waiters);
}

void
sleepq_wait(struct sleepq *sleepq, const char *wchan)
{
    struct sleepq_waiter waiter;
    struct thread *thread;

    thread = thread_self();
    sleepq_waiter_init(&waiter, thread);
    sleepq_add_waiter(sleepq, &waiter);

    thread_sleep(&sleepq->bucket->lock, sleepq->sync_obj, wchan);

    sleepq_remove_waiter(sleepq, &waiter);
}

void
sleepq_signal(struct sleepq *sleepq)
{
    struct sleepq_waiter *waiter;

    if (sleepq_empty(sleepq)) {
        return;
    }

    waiter = list_last_entry(&sleepq->waiters, struct sleepq_waiter, node);
    sleepq_waiter_wakeup(waiter);
}
