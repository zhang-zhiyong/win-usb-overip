/*
#include "ipusb_thread.hpp"

#include "ipusb.h"


Usbip_thread :: Usbip_thread(char *_hostname,
                        struct dev_info *_dev,
                        Usbip_task_thread *_task_thread
                        )
        : hostname(_hostname),
        dev(_dev),
        task_thread(_task_thread),
        stop_condition(false)
{
}



void Usbip_thread :: run()
{
        struct task_info *tsk;

        exit_code = attach_device(hostname, dev->busid, &stop_condition);

        tsk = new struct task_info;
        if (unlikely(tsk == NULL)) {
                err("alloc task_info: out of memory");
                return;
        }
        tsk->hostname = hostname;
        tsk->dev = dev;
        tsk->type = IPUSB_THREAD_ATTACH_DEV_DONE;
        task_thread->task_done(tsk, this);

}
*/