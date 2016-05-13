#ifndef UV_OS390_SYSCALL_H_
#define UV_OS390_SYSCALL_H_

#include "os390-epoll.h"

# define UV__O_CLOEXEC        0x80000
#define UV__EPOLL_CLOEXEC     UV__O_CLOEXEC
#define UV__EPOLL_CTL_ADD     1
#define UV__EPOLL_CTL_DEL     2
#define UV__EPOLL_CTL_MOD     3
#define UV__EPOLL_CTL_ADD_MSGQ    4

struct uv__epoll_event {
  uint32_t events;
  uint32_t data;
};

#endif
