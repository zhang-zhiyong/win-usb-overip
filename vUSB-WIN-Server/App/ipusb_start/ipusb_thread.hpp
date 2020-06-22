#ifndef IPUSB_THREAD_HPP
#define IPUSB_THREAD_HPP

//#include <QThread>
//#include <QMutex>
#include <list>

//#include "ipusbq_task.h"
#include "ipusb_task_thread.hpp"

using namespace std;

/*
class Usbip_thread : public QThread
{
public:
        Usbip_thread(char *host,
                        struct dev_info *dev,
                        Usbip_task_thread *task_thread
                        );

        inline int get_exit_code() const
        {
                return exit_code;
        }

        inline void set_stop_condition()
        {
                stop_condition = true;
        }

protected:
        void run();

private:
        char *hostname;
        struct dev_info *dev;
        QMutex *tasks_done_list_lock;
        list<struct task_info *> *tasks_done_list;
        Usbip_task_thread *task_thread;

        int exit_code;
        volatile bool stop_condition;
};
*/
#endif // IPUSB_THREAD_HPP
