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

#ifndef _IPUSB_H
#define _IPUSB_H

#define _CRT_SECURE_NO_WARNINGS
#define WINVER 0x0501
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <setupapi.h>
#include <initguid.h>
#include <winioctl.h>

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>

//#include <basetyps.h>
//#include <wtypes.h>

#ifdef _MSC_VER 
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Setupapi.lib")
typedef size_t ssize_t;
#endif

#include "win_stub.h"
#include "ipusb_protocol.h"
#include "ipusb_network.h"
#include "ipusb_common.h"
#include "ipusb_vbus_ui.h"

//#include "ipusbq_task.h"

struct host_devs * show_exported_devices(char *host);
int attach_device(char *hostname, char *busid, volatile bool *stop_cond);

#endif
