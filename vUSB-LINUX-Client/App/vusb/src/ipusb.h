/*
 * Copyright (C) 2013 Daniel Danzberger <ipusb@dd-wrt.com>
 *               2011 matt mooney <mfm@muteddisk.com>
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

#ifndef __USBIP_H
#define __USBIP_H

#ifdef HAVE_CONFIG_H
#include "../config.h"
#endif

/* ipusb commands */
int ipusb_attach(int argc, char *argv[]);
int ipusb_detach(int argc, char *argv[]);
int ipusb_list(int argc, char *argv[]);
int ipusb_bind(int argc, char *argv[]);
int ipusb_unbind(int argc, char *argv[]);

void ipusb_attach_usage(void);
void ipusb_detach_usage(void);
void ipusb_list_usage(void);
void ipusb_bind_usage(void);
void ipusb_unbind_usage(void);

#endif /* __USBIP_H */
