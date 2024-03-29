/*
 * Copyright (c) 2012-2014 Richard Braun.
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

#ifndef _X86_PIC_H
#define _X86_PIC_H

#include <machine/trap.h>

/*
 * Set up the pic module.
 */
void pic_setup(void);

/*
 * Interrupt handlers.
 */
void pic_spurious_intr(struct trap_frame *frame);

#endif /* _X86_PIC_H */
