#ifndef IPUSB_THREAD_H
#define IPUSB_THREAD_H

#include <list>

//#include <QWaitCondition>
//#include <QMutex>
//#include <QThread>

//#include "ipusbq_task.h"

using namespace std;

/*
class Usbip_task_thread : public QThread
{
public:
        Usbip_task_thread(QMutex *lock, list<struct task_info *> *tasks_done);

        char * add_task(enum ipusb_thread_tasks,
                        char *hostname,
                        struct dev_info *busid
                        );
        void task_done(struct task_info *, void *rc);


protected:
        void run();

private:
        #define TASKS_MAX	2
        list<struct task_info *> tasks;
        QMutex task_list_lock;

        QMutex *tasks_done_list_lock;
        list<struct task_info *> *tasks_done_list;

        QWaitCondition sleep_con;
        QMutex sleep_lock;
};
*/
#endif // IPUSB_THREAD_H
