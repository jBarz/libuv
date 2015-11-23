#ifndef UV_OS390_EPOLL_H_
#define UV_OS390_EPOLL_H_

#include <inttypes.h>
#include <poll.h>

#define EPOLL_CTL_ADD 1
#define EPOLL_CTL_DEL 2
#define EPOLL_CTL_MOD 3
#define MAX_EPOLL_INSTANCES 256
#define MAX_ITEMS_PER_EPOLL 1024

enum EPOLL_EVENTS
{
EPOLLIN = 0x001,
#define EPOLLIN EPOLLIN
EPOLLPRI = 0x002,
#define EPOLLPRI EPOLLPRI
EPOLLOUT = 0x004,
#define EPOLLOUT EPOLLOUT
EPOLLRDNORM = 0x040,
#define EPOLLRDNORM EPOLLRDNORM
EPOLLRDBAND = 0x080,
#define EPOLLRDBAND EPOLLRDBAND
EPOLLWRNORM = 0x100,
#define EPOLLWRNORM EPOLLWRNORM
EPOLLWRBAND = 0x200,
#define EPOLLWRBAND EPOLLWRBAND
EPOLLMSG = 0x400,
#define EPOLLMSG EPOLLMSG
EPOLLERR = 0x008,
#define EPOLLERR EPOLLERR
EPOLLHUP = 0x010,
#define EPOLLHUP EPOLLHUP
EPOLLONESHOT = (1 << 30),
#define EPOLLONESHOT EPOLLONESHOT
EPOLLET = (1 << 31)
#define EPOLLET EPOLLET
};


typedef union epoll_data {
    //void        *ptr;
    int          fd;
    //uint32_t     u32;
    //uint64_t     u64;
} epoll_data_t;

struct epoll_event {
    uint32_t     events;      /* Epoll events */
    epoll_data_t data;        /* User data variable */
};

struct _epoll_list{
   int size;
   struct pollfd items[MAX_ITEMS_PER_EPOLL];
};

int epoll_create1(int flags);
int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);
int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout);
int epoll_pwait(int epfd, struct epoll_event *events, int maxevents, int timeout, int sigmask);
int epoll_file_close(int fd);

#endif
