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

#ifndef UV_MVS_H
#define UV_MVS_H

#define _AIO_OS390
#include <aio.h>
#include <sys/msg.h>

#define AIO_MSG_READ 	  1
#define AIO_MSG_WRITE 	2
#define AIO_MSG_ACCEPT 	3
#define AIO_MSG_CONNECT 4

#if defined(__64BIT__)
#define ZASYNC BPX4AIO
#else
#define ZASYNC BPX1AIO
#endif

struct AioMsg {         /* The I/O Complete Message          */
  long int mm_type;   	/* Msg type: used for type of I/O    */
  void *mm_ptr; 		    /* Msg text: identifies the handle   */
};

#define UV_PLATFORM_LOOP_FIELDS     				\
  int msgqid;

#define UV_TCP_PRIVATE_PLATFORM_FIELDS			\
  int is_bound;                             \
  int is_listening;

#define UV_PLATFORM_WRITE_FIELDS	      		\
  struct aiocb aio_write;		            		\
  struct AioMsg aio_write_msg;

#define UV_STREAM_PRIVATE_PLATFORM_FIELDS		\
  struct aiocb aio_read;	            			\
  struct aiocb aio_cancel;		           		\
  struct AioMsg aio_read_msg;				        \
  struct AioMsg aio_cancel_msg;			        \
  int last_op_rv;                           \
  uv_buf_t bufsml;

#define UV_PLATFORM_CONNECT_FIELDS		    	\
  struct aiocb aio_connect;				          \
  struct AioMsg aio_connect_msg;

#define UV_IO_PRIVATE_PLATFORM_FIELDS       \

#endif /* UV_MVS_H */
