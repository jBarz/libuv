#ifndef UV_OS390_EPOLL_H_
#define UV_OS390_EPOLL_H_

#include <inttypes.h>
#include <poll.h>
#include <pthread.h>

#define EPOLL_CTL_ADD 		1
#define EPOLL_CTL_DEL 		2
#define EPOLL_CTL_MOD 		3
#define EPOLL_CTL_ADD_MSGQ 	4
#define MAX_EPOLL_INSTANCES 	256
#define MAX_ITEMS_PER_EPOLL 	1024

typedef union epoll_data {
    int          fd;
} epoll_data_t;

struct epoll_event {
    uint32_t     events;      /* Epoll events */
    epoll_data_t data;        /* User data variable */
};

struct _epoll_list{
   struct pollfd items[MAX_ITEMS_PER_EPOLL];
   struct pollfd *aio;
   int size;
   pthread_mutex_t lock;
};

int epoll_create1(int flags);
int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);
int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout);
int epoll_pwait(int epfd, struct epoll_event *events, int maxevents, int timeout, int sigmask);
int epoll_file_close(int fd);

#endif

