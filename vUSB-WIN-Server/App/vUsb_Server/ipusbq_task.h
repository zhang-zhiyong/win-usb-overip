/*
 * Copyright (C) 2013 Daniel Danzberger <ipusb@dd-wrt.com>
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

#ifndef IPUSBQ_TASK_H
#define IPUSBQ_TASK_H

enum ipusb_thread_tasks {
        IPUSB_THREAD_QUERY_HOST,
        IPUSB_THREAD_ATTACH_DEV,
        IPUSB_THREAD_ATTACH_DEV_DONE,
        IPUSB_THREAD_DEATTACH_DEV
};


struct dev_info {
        char path[128];
        char name[64];
        char busid[32];

        /* points to the gui element
         * that represents this device */
        void *item;

        /* points to the thread that handles
         * the current ipusb instance */
        void *instance;

        /* indicates if this device is attached */
        bool attached;
};

#define MAX_DEVS_PER_HOST	8

struct host_devs {
        struct dev_info dev[MAX_DEVS_PER_HOST];
        int n_devs;
        int fail;
};


struct task_info {
        enum ipusb_thread_tasks type;
        char *hostname;
        struct dev_info *dev;
        void *complete_info;
};

#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)

#endif // IPUSBQ_TASK_H
