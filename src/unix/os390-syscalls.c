#include "os390-epoll.h"
#include "os390-syscalls.h"
#include <errno.h>

int uv__epoll_create(int size) {
  return errno = ENOSYS, -1;
}

int uv__epoll_create1(int flags) {
  return epoll_create1(flags);
}

int uv__epoll_ctl(int epfd, int op, int fd, struct uv__epoll_event* events) {
    return epoll_ctl(epfd, op, fd, (struct epoll_event*)events);
}


int uv__epoll_wait(int epfd, struct uv__epoll_event* events, int nevents, int timeout) {
    return epoll_wait(epfd, (struct epoll_event*)events, nevents, timeout);
}

int uv__epoll_pwait(int epfd, struct epoll_event *events, int maxevents, int timeout, int sigmask) {
  return errno = ENOSYS, -1;
}
