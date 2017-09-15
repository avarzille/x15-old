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
 */

#include <stdint.h>
#include <kern/clock.h>
#include <kern/percpu.h>
#include <kern/list.h>
#include <kern/llsync.h>
#include <kern/log.h>
#include <kern/macros.h>
#include <kern/spinlock.h>
#include <kern/thread.h>
#include <machine/cpu.h>

struct llsync_node {
    const void *ptr;
    uint64_t tstamp;
};

#define LLSYNC_INVALID_TSTAMP   (~0ull)

/* Number of static nodes in percpu data. */
#define LLSYNC_NUM_NODES   8

struct llsync_cpu_data {
    struct llsync_node nodes[LLSYNC_NUM_NODES];
    unsigned long cnt;
    struct work_queue wc_queue;
    struct list pred_works;
    unsigned int nr_pred_works;
};

#define LLSYNC_FULL_BIT   (1ul << (sizeof (long) * 8 - 1))

static struct llsync_cpu_data llsync_cpu_data __percpu;

struct llsync_waiter {
    struct llsync_work work;
    struct spinlock lock;
    struct thread *waiter;
    int done;
};

static void
llsync_node_reset(struct llsync_node *node)
{
    node->ptr = (const void *)1;
    atomic_store_release(&node->tstamp, LLSYNC_INVALID_TSTAMP);
}

static unsigned long
llsync_inc_nodes(unsigned long *cntp)
{
    unsigned long val, nval;

    while (true) {
        val = atomic_load(cntp, ATOMIC_RELAXED);
        nval = val + 1;

        if (nval == LLSYNC_NUM_NODES) {
            nval |= LLSYNC_FULL_BIT;
        }

        nval = atomic_cas_acquire(cntp, val, nval);
        if (nval == val) {
            return nval;
        }
    }
}

static void
llsync_dec_nodes(unsigned long *cntp)
{
    unsigned long val, nval;

    while (true) {
        val = atomic_load(cntp, ATOMIC_RELAXED);
        nval = val - 1;

        if (nval == LLSYNC_FULL_BIT) {
            nval = 0;
        }

        nval = atomic_cas_release(cntp, val, nval);
        if (nval == val) {
            break;
        }
    }
}

static unsigned long
llsync_cpu_data_cnt(struct llsync_cpu_data *data)
{
    return atomic_load(&data->cnt, ATOMIC_RELAXED);
}

void
llsync_work_init(struct llsync_work *wp, work_fn_t fn, const void *ptr)
{
    work_init(&wp->work, fn);
    wp->ptr = ptr;
    list_node_init(&wp->node);
}

#define LLSYNC_NODE_SHIFT   24

llsync_key_t
llsync_read_enter(const void *ptr)
{
    llsync_key_t ret;
    struct llsync_cpu_data *data;
    unsigned long nv, i;

    ret = cpu_id();
    data = percpu_ptr(llsync_cpu_data, ret);
    nv = llsync_inc_nodes(&data->cnt);

    if (!(nv & LLSYNC_FULL_BIT)) {
        for (i = 0; i < LLSYNC_NUM_NODES; ++i) {
            if (data->nodes[i].tstamp == LLSYNC_INVALID_TSTAMP) {
                atomic_store_release(&data->nodes[i].ptr, ptr);
                data->nodes[i].tstamp = clock_get_time();
                ret |= (llsync_key_t)((i + 1) << LLSYNC_NODE_SHIFT);
                break;
            }
        }
    }

    thread_llsync_read_inc();
    return ret;
}

#define LLSYNC_CPU_MASK   ((1u << LLSYNC_NODE_SHIFT) - 1)

void
llsync_read_exit(llsync_key_t key)
{
    unsigned int cpu, nnode;
    struct llsync_cpu_data *data;

    cpu = key & LLSYNC_CPU_MASK;
    nnode = key >> LLSYNC_NODE_SHIFT;
    data = percpu_ptr(llsync_cpu_data, cpu);

    if (nnode != 0) {
        llsync_node_reset(&data->nodes[nnode - 1]);
    }

    llsync_dec_nodes(&data->cnt);
    thread_llsync_read_dec();
}

static bool llsync_is_ready;

static int __init
llsync_setup(void)
{
    unsigned int i, j;
    struct llsync_cpu_data *data;

    for (i = 0; i < cpu_count(); ++i) {
        data = percpu_ptr(llsync_cpu_data, i);

        for (j = 0; j < LLSYNC_NUM_NODES; ++j) {
            llsync_node_reset(&data->nodes[j]);
        }

        list_init(&data->pred_works);
        work_queue_init(&data->wc_queue);
        data->nr_pred_works = 0;
    }

    llsync_is_ready = true;
    return 0;
}

INIT_OP_DEFINE(llsync_setup,
               INIT_OP_DEP(log_setup, true),
               INIT_OP_DEP(spinlock_setup, true),
               INIT_OP_DEP(work_setup, true),
               INIT_OP_DEP(thread_bootstrap, true));

bool
llsync_ready(void)
{
    return llsync_is_ready;
}

static unsigned long
llsync_poll_pred(struct llsync_work *wp, uint64_t tstamp,
                 struct work_queue *wqueue, unsigned int *nump)
{
    unsigned long ret, cnt;
    struct llsync_cpu_data *data;
    struct llsync_node *node;
    unsigned int i, j;
    bool qstate;

    for (i = 0, ret = 0; i < cpu_count(); ++i) {
        data = percpu_ptr(llsync_cpu_data, i);
        cnt = llsync_cpu_data_cnt(data);

        ret |= cnt;
        if (cnt & LLSYNC_FULL_BIT) {
            continue;
        }

        for (j = 0, qstate = true; j < LLSYNC_NUM_NODES; ++j) {
            node = &data->nodes[j];

            if ((node->ptr == wp->ptr || node->ptr == 0) &&
                (node->tstamp < tstamp)) {

                qstate = false;
                break;
            }
        }

        if (qstate) {
           list_remove(&wp->node);
           (*nump)--;
           work_queue_push(wqueue, &wp->work);
        }
    }

    return ret;
}

static bool
llsync_all_qstate(void)
{
    unsigned int i;
    unsigned long cnt;

    for (i = 0; i < cpu_count(); ++i) {
        cnt = llsync_cpu_data_cnt(percpu_ptr(llsync_cpu_data, i));
        if (cnt != 0) {
            return false;
        }
    }

    return true;
}

void
llsync_report_periodic_event(void)
{
    struct llsync_cpu_data *data;
    unsigned long cnt;
    struct llsync_work *runp, *tmp;
    bool empty;
    uint64_t tstamp;
    struct work_queue wq;

    data = cpu_local_ptr(llsync_cpu_data);
    cnt = 0;
    empty = data->nr_pred_works == 0;
    tstamp = clock_get_time();
    work_queue_init(&wq);

    list_for_each_entry_safe(&data->pred_works, runp, tmp, node) {
        cnt |= llsync_poll_pred(runp, tstamp, &wq, &data->nr_pred_works);
    }

    if ((!empty && cnt == 0) || (empty && llsync_all_qstate())) {
        work_queue_concat(&wq, &data->wc_queue);
        work_queue_init(&data->wc_queue);
    }

    if (work_queue_nr_works(&wq) > 0) {
        work_queue_schedule(&wq, 0);
    }
}

#define LLSYNC_MAX_PRED_WORKS   64

void
llsync_defer(struct llsync_work *work)
{
    unsigned long flags;
    struct llsync_cpu_data *data;

    thread_preempt_disable_intr_save(&flags);
    data = cpu_local_ptr(llsync_cpu_data);

    if (work->ptr == 0 || (data->nr_pred_works >= LLSYNC_MAX_PRED_WORKS)) {
        work_queue_push(&data->wc_queue, &work->work);
    } else {
        list_insert_tail(&data->pred_works, &work->node);
        data->nr_pred_works++;
    }

    thread_preempt_enable_intr_restore(flags);
}

static void
llsync_signal(struct work *work)
{
    struct llsync_waiter *wp;

    wp = structof(work, struct llsync_waiter, work);
    spinlock_lock(&wp->lock);

    if (wp->waiter != NULL) {
        thread_wakeup(wp->waiter);
    }

    spinlock_unlock(&wp->lock);
}

void
llsync_wait(const void *ptr)
{
    struct llsync_waiter w;

    llsync_work_init(&w.work, llsync_signal, ptr);
    w.waiter = thread_self();
    spinlock_init(&w.lock);
    w.done = 0;

    llsync_defer(&w.work);
    spinlock_lock(&w.lock);

    while (!w.done) {
        thread_sleep(&w.lock, ptr, "llsync_wait");
    }

    spinlock_unlock(&w.lock);
}
