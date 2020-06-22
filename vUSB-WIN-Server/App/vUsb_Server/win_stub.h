/*
 * Copyright (C) 2013 Daniel Danzberger <ipusb@dd-wrt.com>
 *               2005-2007 Takahiro Hirofuchi
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef WIN_STUB_H
#define WIN_STUB_H

/*
extern int ipusb_use_stderr;
extern int ipusb_use_debug;

extern char err_buf[256];
*/

#define err(fmt, args, ...)	do { \
                sprintf(err_buf, "ERROR: " fmt, ##args); \
} while (0)

#define notice(fmt, args, ...)
#define info(fmt, args, ...)
#define dbg(fmt, args, ...)

extern void dbg_file(const char *fmt, ...);

#endif
