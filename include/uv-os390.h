/* Copyright Joyent, Inc. and other Node contributors. All rights reserved.
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

#ifndef UV_MVS_H
#define UV_MVS_H

#define _AIO_OS390
#include <aio.h>
#define SIG_AIO_READ  SIGUSR1           /* Signal used for aio_read            */
#define SIG_AIO_WRITE SIGUSR2		/* Signal used for aio_write           */


#define UV_PLATFORM_FS_EVENT_FIELDS                                           \
  void* watchers[2];                                                          \
  int wd;                                                                     \

#define UV_TCP_PRIVATE_PLATFORM_FIELDS                                        \
    int is_bound;							      \

#define UV_PLATFORM_WRITE_FIELDS                                              \
    struct aiocb aio_write;							      

#define UV_STREAM_PRIVATE_PLATFORM_FIELDS				      \
    struct aiocb aio_read;

#define UV_PLATFORM_CONNECT_FIELDS				              \
    struct aiocb aio_connect;                                                 \

#define UV_IO_PRIVATE_PLATFORM_FIELDS					      \
    struct aiocb *aio_read, *aio_write;
   

#endif /* UV_MVS_H */
