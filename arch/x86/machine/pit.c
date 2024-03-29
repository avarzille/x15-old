/*
 * Copyright (c) 2011, 2012 Richard Braun.
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

#include <kern/assert.h>
#include <kern/init.h>
#include <machine/io.h>
#include <machine/pit.h>

/*
 * I/O ports.
 */
#define PIT_PORT_COUNTER0   0x40
#define PIT_PORT_MODE       0x43

/*
 * Mode control register bits.
 */
#define PIT_MODE_LATCH      0x00
#define PIT_MODE_RATE_GEN   0x04
#define PIT_MODE_RW_LSB     0x10
#define PIT_MODE_RW_MSB     0x20

/*
 * Native timer frequency.
 */
#define PIT_FREQ 1193182

/*
 * Maximum value of a counter.
 */
#define PIT_MAX_COUNT 0xffff

void __init
pit_setup(void)
{
    io_write_byte(PIT_PORT_MODE, PIT_MODE_RATE_GEN | PIT_MODE_RW_LSB
                                 | PIT_MODE_RW_MSB);
    io_write_byte(PIT_PORT_COUNTER0, PIT_MAX_COUNT & 0xff);
    io_write_byte(PIT_PORT_COUNTER0, PIT_MAX_COUNT >> 8);
}

static unsigned int
pit_read(void)
{
    unsigned int low, high;

    io_write_byte(PIT_PORT_MODE, PIT_MODE_LATCH);
    low = io_read_byte(PIT_PORT_COUNTER0);
    high = io_read_byte(PIT_PORT_COUNTER0);
    return (high << 8) | low;
}

void
pit_delay(unsigned long usecs)
{
    long total, prev, count, diff;

    assert(usecs != 0);

    /* TODO Avoid 64-bits conversion if result is known not to overflow */
    total = (long)(((long long)usecs * PIT_FREQ + 999999) / 1000000);
    prev = pit_read();

    do {
        count = pit_read();
        diff = prev - count;
        prev = count;

        if (diff < 0) {
            diff += PIT_MAX_COUNT;
        }

        total -= diff;
    } while (total > 0);
}
