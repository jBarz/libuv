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
#include <sys/msg.h>

#define AIO_MSG_READ 1
#define AIO_MSG_WRITE 2
#define AIO_MSG_ACCEPT 3

#define UV__ZAIO_READING 1
#define UV__ZAIO_WRITING 2

#if defined(__64BIT__)
#define ZASYNC BPX4AIO
#else
#define ZASYNC BPX1AIO
#endif

struct AioMsg{         /* The I/O Complete Message                */
        long int mm_type;   /* Msg type: used for type of I/O    */
        void *mm_ptr; /* Msg text: identifies the client   */
};

struct AioAcceptCb{
  struct aiocb aioCb;
  struct AioMsg aioMsg;
  void *stream;
};

#define UV_PLATFORM_FS_EVENT_FIELDS                                           \
  void* watchers[2];                                                          \
  int wd;                                                                     \

#define UV_PLATFORM_LOOP_FIELDS                                               \
    int msgqid;							      \

#define UV_TCP_PRIVATE_PLATFORM_FIELDS                                        \
    int is_bound;							      \
    int accept_count;							      \
    struct AioAcceptCb *aio_accepts;                                          \
    struct AioAcceptCb *aio_accept_active;                                                    \

#define UV_PLATFORM_WRITE_FIELDS                                              \
    struct aiocb aio_write;                                                   \
    struct AioMsg aio_write_msg;                                               \

#define UV_STREAM_PRIVATE_PLATFORM_FIELDS				      \
    struct aiocb aio_read;                                                    \
    struct aiocb aio_cancel;                                                    \
    struct AioMsg aio_read_msg;                                               \
    struct AioMsg aio_cancel_msg;                                            \
    int aio_status;                                                          \

#define UV_PLATFORM_CONNECT_FIELDS				              \
    struct aiocb aio_connect;                                                 \
    struct AioMsg aio_connect_msg;                                            \

#define UV_IO_PRIVATE_PLATFORM_FIELDS					      \
    struct aiocb *aio_read, *aio_write;
   

#endif /* UV_MVS_H */
