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

#include "uv.h"
#include "internal.h"

#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>


static int maybe_new_socket(uv_tcp_t* handle, int domain, int flags) {
  int sockfd;
  int err;

  if (domain == AF_UNSPEC || uv__stream_fd(handle) != -1) {
    handle->flags |= flags;
    return 0;
  }

  err = uv__socket(domain, SOCK_STREAM, 0);

  if (err < 0)
    return err;
  sockfd = err;

  err = uv__stream_open((uv_stream_t*) handle, sockfd, flags);
  if (err) {
    uv__close(sockfd);
    return err;
  }

  return 0;
}


int uv_tcp_init_ex(uv_loop_t* loop, uv_tcp_t* tcp, unsigned int flags) {
  int domain;

  /* Use the lower 8 bits for the domain */
  domain = flags & 0xFF;
  if (domain != AF_INET && domain != AF_INET6 && domain != AF_UNSPEC)
    return -EINVAL;

  if (flags & ~0xFF)
    return -EINVAL;

#if defined(__MVS__)
  tcp->aio_accepts = NULL;
#endif

  uv__stream_init(loop, (uv_stream_t*)tcp, UV_TCP);

  /* If anything fails beyond this point we need to remove the handle from
   * the handle queue, since it was added by uv__handle_init in uv_stream_init.
   */

  if (domain != AF_UNSPEC) {
    int err = maybe_new_socket(tcp, domain, 0);
    if (err) {
      QUEUE_REMOVE(&tcp->handle_queue);
      return err;
    }
  }

  return 0;
}


int uv_tcp_init(uv_loop_t* loop, uv_tcp_t* tcp) {
  return uv_tcp_init_ex(loop, tcp, AF_UNSPEC);
}


int uv__tcp_bind(uv_tcp_t* tcp,
                 const struct sockaddr* addr,
                 unsigned int addrlen,
                 unsigned int flags) {
  int err;
  int on;

  /* Cannot set IPv6-only mode on non-IPv6 socket. */
  if ((flags & UV_TCP_IPV6ONLY) && addr->sa_family != AF_INET6)
    return -EINVAL;

  err = maybe_new_socket(tcp,
                         addr->sa_family,
                         UV_STREAM_READABLE | UV_STREAM_WRITABLE);
  if (err)
    return err;

  on = 1;
  if (setsockopt(tcp->io_watcher.fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)))
    return -errno;

#ifdef IPV6_V6ONLY
  if (addr->sa_family == AF_INET6) {
    on = (flags & UV_TCP_IPV6ONLY) != 0;
    if (setsockopt(tcp->io_watcher.fd,
                   IPPROTO_IPV6,
                   IPV6_V6ONLY,
                   &on,
                   sizeof on) == -1) {
#ifdef __MVS__
// bug in zOS returning setting the wrong error code
      return UV_EINVAL;
#endif
      return -errno;
    }
  }
#endif

  errno = 0;
  if (bind(tcp->io_watcher.fd, addr, addrlen) && errno != EADDRINUSE) {
    if (errno == EAFNOSUPPORT)
      /* OSX, other BSDs and SunoS fail with EAFNOSUPPORT when binding a
       * socket created with AF_INET to an AF_INET6 address or vice versa. */
      return -EINVAL;
    return -errno;
  }
  tcp->delayed_error = -errno;

  if (addr->sa_family == AF_INET6)
    tcp->flags |= UV_HANDLE_IPV6;

#ifdef __MVS__
  tcp->is_bound = 1;
#endif

  return 0;
}


int uv__tcp_connect(uv_connect_t* req,
                    uv_tcp_t* handle,
                    const struct sockaddr* addr,
                    unsigned int addrlen,
                    uv_connect_cb cb) {
  int err;
  int r = -1;

  assert(handle->type == UV_TCP);

  if (handle->connect_req != NULL)
    return -EALREADY;  /* FIXME(bnoordhuis) -EINVAL or maybe -EBUSY. */

  err = maybe_new_socket(handle,
                         addr->sa_family,
                         UV_STREAM_READABLE | UV_STREAM_WRITABLE);
  if (err)
    return err;

  handle->delayed_error = 0;

  do
  {
#if defined(__MVS__)
    int rv, rc, rsn;
    memset(&req->aio_connect, 0, sizeof(struct aiocb));
    req->aio_connect.aio_fildes = uv__stream_fd(handle);
    req->aio_connect.aio_notifytype = AIO_MSGQ;
    req->aio_connect.aio_cmd = AIO_CONNECT;
    req->aio_connect.aio_cflags |= AIO_OK2COMPIMD;
    req->aio_connect.aio_msgev_qid = handle->loop->msgqid;
    req->aio_connect_msg.mm_type = AIO_MSG_CONNECT;
    req->aio_connect_msg.mm_ptr = req;
    req->aio_connect.aio_msgev_addr = &req->aio_connect_msg;
    req->aio_connect.aio_msgev_size = sizeof(req->aio_connect_msg.mm_ptr);
    req->aio_connect.aio_sockaddrlen = addrlen;
    req->aio_connect.aio_sockaddrptr = (struct sockaddr_in*)uv__malloc(addrlen);
    if (req->aio_connect.aio_sockaddrptr != NULL) {
      memcpy(req->aio_connect.aio_sockaddrptr, addr, addrlen);
      ZASYNC(sizeof(req->aio_connect), &req->aio_connect, &rv, &rc, &rsn);
      //printf("JBAR issued aio_connect for fd=%d , rv=%d, rc=%d, rsn=%d\n", req->aio_connect.aio_fildes, rv, rc, rsn);
      if(rv < 0) {
        r = rv;
        errno = rc;
      }
      else if(rv == 0){
	/* connect has not happened immediately 
	   wait for notification */
        r = -1;
        errno = EINPROGRESS;
        handle->aio_status |= UV__ZAIO_WRITING;
      }
      else if(rv == 1) {
	/* do nothing. Just as if connect() succeeded */
        r = 1;
      }
    }
#else
    r = connect(uv__stream_fd(handle), addr, addrlen);
#endif
  }
  while (r == -1 && errno == EINTR);

  if (r == -1) {
    if (errno == EINPROGRESS)
      ; /* not an error */
    else if (errno == ECONNREFUSED)
    /* If we get a ECONNREFUSED wait until the next tick to report the
     * error. Solaris wants to report immediately--other unixes want to
     * wait.
     */
      handle->delayed_error = -errno;
    else
      return -errno;
  }

  uv__req_init(handle->loop, req, UV_CONNECT);
  req->cb = cb;
  req->handle = (uv_stream_t*) handle;
  QUEUE_INIT(&req->queue);
  handle->connect_req = req;

#if defined(__MVS__)
  if (r == 1)
    /* the aio connect succeeded immediately. Ready for io */
    uv__io_feed(handle->loop, &handle->io_watcher);
#else
  uv__io_start(handle->loop, &handle->io_watcher, POLLOUT);
#endif

  if (handle->delayed_error)
    uv__io_feed(handle->loop, &handle->io_watcher);

  return 0;
}


int uv_tcp_open(uv_tcp_t* handle, uv_os_sock_t sock) {
  int err;

#if !defined(__MVS__)
  err = uv__nonblock(sock, 1);
  if (err)
    return err;
#endif

  return uv__stream_open((uv_stream_t*)handle, sock, 
				  UV_STREAM_READABLE 
				| UV_STREAM_WRITABLE
#if 0
				| UV_STREAM_BLOCKING
#endif
				);
}


int uv_tcp_getsockname(const uv_tcp_t* handle,
                       struct sockaddr* name,
                       int* namelen) {
  socklen_t socklen;

  if (handle->delayed_error)
    return handle->delayed_error;

  if (uv__stream_fd(handle) < 0)
    return -EINVAL;  /* FIXME(bnoordhuis) -EBADF */

  /* sizeof(socklen_t) != sizeof(int) on some systems. */
  socklen = (socklen_t) *namelen;

  if (getsockname(uv__stream_fd(handle), name, &socklen))
    return -errno;

  *namelen = (int) socklen;
  return 0;
}


int uv_tcp_getpeername(const uv_tcp_t* handle,
                       struct sockaddr* name,
                       int* namelen) {
  socklen_t socklen;

  if (handle->delayed_error)
    return handle->delayed_error;

  if (uv__stream_fd(handle) < 0)
    return -EINVAL;  /* FIXME(bnoordhuis) -EBADF */

  /* sizeof(socklen_t) != sizeof(int) on some systems. */
  socklen = (socklen_t) *namelen;

  if (getpeername(uv__stream_fd(handle), name, &socklen))
    return -errno;

  *namelen = (int) socklen;
  return 0;
}


int uv_tcp_listen(uv_tcp_t* tcp, int backlog, uv_connection_cb cb) {
  static int single_accept = -1;
  int err;

  if (tcp->delayed_error)
    return tcp->delayed_error;

  if (single_accept == -1) {
    const char* val = getenv("UV_TCP_SINGLE_ACCEPT");
    single_accept = (val != NULL && atoi(val) != 0);  /* Off by default. */
  }

  if (single_accept)
    tcp->flags |= UV_TCP_SINGLE_ACCEPT;

  err = maybe_new_socket(tcp, AF_INET, UV_STREAM_READABLE);
  if (err)
    return err;

#ifdef __MVS__
  /* on zOS the listen call does not bind automatically if the socket is unbound
  ** Hence the manual binding to an arbitrary port is required to be done manually */

  errno = 0;
  if (tcp->is_bound != 1)
  {
    struct sockaddr_in saddr;
    unsigned namelen = sizeof saddr;
    memset(&saddr, 0, sizeof saddr);
/*
    saddr.sin_port=0;
    saddr.sin_addr.s_addr = INADDR_ANY;
*/
    saddr.sin_family = AF_INET;
    if( bind(tcp->io_watcher.fd, (struct sockaddr*)&saddr, sizeof saddr)) {
      if (errno == EAFNOSUPPORT)
        return -EINVAL;
      return -errno;
    }
    tcp->is_bound = 1;
  }
#endif

  if (listen(tcp->io_watcher.fd, backlog))
    return -errno;
  tcp->connection_cb = cb;

  /* Start listening for connections. */
  tcp->io_watcher.cb = uv__server_io;

#if defined(__MVS__)
  int numberOfAioAccepts = backlog <= 0 ? 1 : backlog;
  tcp->aio_accepts = (struct AioAcceptCb*)uv__malloc(numberOfAioAccepts * sizeof(struct AioAcceptCb));
  memset(tcp->aio_accepts, 0, numberOfAioAccepts * sizeof(struct AioAcceptCb));

  for (int i = 0; i < numberOfAioAccepts; ++i) {
    tcp->aio_accepts[i].aioCb.aio_fildes = tcp->io_watcher.fd;
    tcp->aio_accepts[i].aioCb.aio_notifytype = AIO_MSGQ;
    tcp->aio_accepts[i].aioCb.aio_cmd = AIO_ACCEPT;
    tcp->aio_accepts[i].aioCb.aio_msgev_qid = tcp->loop->msgqid;
    tcp->aio_accepts[i].aioMsg.mm_type = AIO_MSG_ACCEPT;
    tcp->aio_accepts[i].aioMsg.mm_ptr = &tcp->aio_accepts[i];

    tcp->aio_accepts[i].aioCb.aio_msgev_addr = &tcp->aio_accepts[i].aioMsg;
    tcp->aio_accepts[i].aioCb.aio_msgev_size = sizeof(tcp->aio_accepts[i].aioMsg.mm_ptr);
    tcp->aio_accepts[i].stream = tcp;
    int rv, rc, rsn;
    ZASYNC(sizeof(struct aiocb), &tcp->aio_accepts[i].aioCb, &rv, &rc, &rsn);
    //printf("JBAR issued aio_accept for fd=%d , rv=%d, rc=%d, rsn=%d\n", tcp->aio_accepts[i].aioCb.aio_fildes, rv, rc, rsn);
    if (rv == -1)
      return -rc;
    else
      tcp->accept_count++;
  }
#else
  uv__io_start(tcp->loop, &tcp->io_watcher, POLLIN);
#endif

  return 0;
}


int uv__tcp_nodelay(int fd, int on) {
#if !defined(__MVS__)
  if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on)))
    return -errno;
#endif
  return 0;
}


int uv__tcp_keepalive(int fd, int on, unsigned int delay) {
  if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on)))
    return -errno;

#ifdef TCP_KEEPIDLE
  if (on && setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &delay, sizeof(delay)))
    return -errno;
#endif

  /* Solaris/SmartOS, if you don't support keep-alive,
   * then don't advertise it in your system headers...
   */
  /* FIXME(bnoordhuis) That's possibly because sizeof(delay) should be 1. */
#if defined(TCP_KEEPALIVE) && !defined(__sun)
  if (on && setsockopt(fd, IPPROTO_TCP, TCP_KEEPALIVE, &delay, sizeof(delay)))
    return -errno;
#endif

  return 0;
}


int uv_tcp_nodelay(uv_tcp_t* handle, int on) {
  int err;

  if (uv__stream_fd(handle) != -1) {
    err = uv__tcp_nodelay(uv__stream_fd(handle), on);
    if (err)
      return err;
  }

  if (on)
    handle->flags |= UV_TCP_NODELAY;
  else
    handle->flags &= ~UV_TCP_NODELAY;

  return 0;
}


int uv_tcp_keepalive(uv_tcp_t* handle, int on, unsigned int delay) {
  int err;

  if (uv__stream_fd(handle) != -1) {
    err =uv__tcp_keepalive(uv__stream_fd(handle), on, delay);
    if (err)
      return err;
  }

  if (on)
    handle->flags |= UV_TCP_KEEPALIVE;
  else
    handle->flags &= ~UV_TCP_KEEPALIVE;

  /* TODO Store delay if uv__stream_fd(handle) == -1 but don't want to enlarge
   *      uv_tcp_t with an int that's almost never used...
   */

  return 0;
}


int uv_tcp_simultaneous_accepts(uv_tcp_t* handle, int enable) {
  if (enable)
    handle->flags &= ~UV_TCP_SINGLE_ACCEPT;
  else
    handle->flags |= UV_TCP_SINGLE_ACCEPT;
  return 0;
}


void uv__tcp_close(uv_tcp_t* handle) {
  uv__stream_close((uv_stream_t*)handle);

#if defined(__MVS__)  
  free(handle->aio_accepts);
#endif
}
