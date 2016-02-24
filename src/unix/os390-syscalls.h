#ifndef UV_OS390_SYSCALL_H_
#define UV_OS390_SYSCALL_H_

#include "os390-epoll.h"

# define UV__O_CLOEXEC        0x80000
#define UV__EPOLL_CLOEXEC     UV__O_CLOEXEC
#define UV__EPOLL_CTL_ADD     1
#define UV__EPOLL_CTL_DEL     2
#define UV__EPOLL_CTL_MOD     3
#define UV__EPOLL_CTL_ADD_MSGQ    4

#define UV__EPOLLIN           1
#define UV__EPOLLOUT          4
#define UV__EPOLLERR          8
#define UV__EPOLLHUP          16
#define UV__EPOLLONESHOT      0x40000000
#define UV__EPOLLET           0x80000000

struct uv__epoll_event {
  uint32_t events;
  uint32_t data;
};

#endif
