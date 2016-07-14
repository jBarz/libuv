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


#ifndef UV_OS390_SYSCALL_H_
#define UV_OS390_SYSCALL_H_

#include "uv.h"
#include "os390-epoll.h"
#include <dirent.h>

# define UV__O_CLOEXEC            0x80000
#define UV__EPOLL_CLOEXEC         UV__O_CLOEXEC
#define UV__EPOLL_CTL_ADD         1
#define UV__EPOLL_CTL_DEL         2
#define UV__EPOLL_CTL_MOD         3
#define UV__EPOLL_CTL_ADD_MSGQ    4

#define uv__async_connect uv__zos_aio_connect
#define uv__async_write(req, stream, buf, len) \
        uv__zos_aio_write(req, stream, buf, len, 0)
#define uv__async_writev(req, stream, buf, len) \
        uv__zos_aio_write(req, stream, buf, len, 1)
#define uv__async_read(stream, buf, len) \
        uv__zos_aio_read(stream, &buf, &len)

struct uv__epoll_event {
  uint32_t events;
  uint32_t data;
};

/* posix aio interface */
int uv__zos_aio_connect(uv_connect_t *req, uv_stream_t *str,
                         const struct sockaddr* addr,
                         unsigned int addrlen);

int uv__zos_aio_write(uv_write_t *req, uv_stream_t *str,
                         char *buf, int len, int vec);

int uv__zos_aio_read(uv_stream_t *str,
                     char **buf, unsigned long *len);

#endif /* UV_OS390_SYSCALL_H_ */
