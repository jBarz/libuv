/* Copyright libuv project contributors. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */


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
