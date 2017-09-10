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
};

#define LLSYNC_FULL_BIT   (1ul << (sizeof (long) * 8 - 1))

static struct llsync_cpu_data llsync_cpu_data __percpu;

struct llsync_global_data {
    struct spinlock lock;
    struct work_queue queue;
    bool warned;
    bool ready;
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

#define LLSYNC_CPU_MASK   ((1u << (LLSYNC_NODE_SHIFT + 1)) - 1)

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

void
llsync_wait_for(const void *ptr)
{
    uint64_t tstamp;
    unsigned int i, j;
    unsigned long cnt;
    struct llsync_cpu_data *data;
    struct llsync_node *node;

    tstamp = clock_get_time();

    for (i = 0; i < cpu_count(); ++i) {
        data = percpu_ptr(llsync_cpu_data, i);
        cnt = llsync_cpu_data_cnt(data);

        if (cnt & LLSYNC_FULL_BIT) {
            while (true) {
               /* The percpu data is full. Wait for it to become
                * empty, since there's no way to know for sure if
                * no references are being held for this predicate. */
                cnt = llsync_cpu_data_cnt(data);
                if (!(cnt & LLSYNC_FULL_BIT)) {
                    break;
                }

                cpu_pause();
            }
        } else {
            for (j = 0; j < LLSYNC_NUM_NODES; ++j) {
                node = &data->nodes[j];

                /* Wait for a quiescent state on this predicate. */
                if (node->ptr != ptr && node->ptr != 0) {
                    continue;
                }

                while (node->tstamp < tstamp) {
                    cpu_pause();
                }
            }
        }
    }
}

void
llsync_wait_all(void)
{
    unsigned int i;
    unsigned long cnt;
    struct llsync_cpu_data *data;

    for (i = 0; i < cpu_count(); ++i) {
        data = percpu_ptr(llsync_cpu_data, i);
        cnt = llsync_cpu_data_cnt(data);

        for (; cnt != 0; cnt = llsync_cpu_data_cnt(data)) {
            cpu_pause();
        }
    }
}

static struct llsync_global_data llsync_data;

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
    }

    spinlock_init(&llsync_data.lock);
    work_queue_init(&llsync_data.queue);
    llsync_data.ready = true;
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
    return llsync_data.ready;
}

void
llsync_report_periodic_event(void)
{
    struct llsync_global_data *data;
    unsigned int i;
    bool qstate;
    struct work_queue wq;
    unsigned long cnt;

    data = &llsync_data;

    if (work_queue_nr_works(&data->queue) == 0) {
        return;
    }

    qstate = true;
    work_queue_init(&wq);
    spinlock_lock(&data->lock);

    for (i = 0; i < cpu_count(); ++i) {
        cnt = llsync_cpu_data_cnt(percpu_ptr(llsync_cpu_data, i));

        if (cnt != 0) {
            qstate = false;
            break;
        }
    }

    if (qstate) {
        work_queue_transfer(&wq, &data->queue);
        work_queue_init(&data->queue);
        spinlock_unlock(&data->lock);
        work_queue_schedule(&wq, 0);
    } else {
        spinlock_unlock(&data->lock);
    }
}

/*
 * Number of pending works beyond which to issue a warning.
 */
#define LLSYNC_NR_PENDING_WORKS_WARN 10000

void
llsync_defer(struct work *work)
{
    struct llsync_global_data *data;
    unsigned int nw;

    data = &llsync_data;
    spinlock_lock(&data->lock);
    work_queue_push(&data->queue, work);
    nw = work_queue_nr_works(&data->queue);

    if (nw >= LLSYNC_NR_PENDING_WORKS_WARN && !data->warned) {
        data->warned = true;
        log_warning("llsync: large number of pending works\n");
    }

    spinlock_unlock(&data->lock);
}
