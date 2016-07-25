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

#include "internal.h"
#include "os390-syscalls.h"
#include <sys/ioctl.h>
#include <net/if.h>
#include <utmpx.h>
#include <sys/time.h>
#include <sys/ps.h>
#include "//'SYS1.SAMPLIB(CSRSIC)'"

#define CVT_PTR           0x10
#define CSD_OFFSET        0x294

/* 
    Long-term average CPU service used by this logical partition,
    in millions of service units per hour. If this value is above
    the partition's defined capacity, the partition will be capped.
    It is calculated using the physical CPU adjustment factor
    (RCTPCPUA) so it may not match other measures of service which
    are based on the logical CPU adjustment factor. It is available
    if the hardware supports LPAR cluster.
*/
#define RCTLACS_OFFSET    0xC4

/* 32-bit count of alive CPUs. This includes both CPs and IFAs */
#define CSD_NUMBER_ONLINE_CPUS        0xD4

/* ADDRESS OF SYSTEM RESOURCES MANAGER (SRM) CONTROL TABLE */
#define CVTOPCTP_OFFSET   0x25C

/* Address of the RCT table */
#define RMCTRCT_OFFSET    0xE4

/* "V(IARMRRCE)" - ADDRESS OF THE RSM CONTROL AND ENUMERATION AREA. */
#define CVTRCEP_OFFSET    0x490

/* 
    NUMBER OF FRAMES CURRENTLY AVAILABLE TO SYSTEM. 
    EXCLUDED ARE FRAMES BACKING PERM STORAGE, FRAMES OFFLINE, AND BAD FRAMES
*/
#define RCEPOOL_OFFSET    0x004

/* TOTAL NUMBER OF FRAMES CURRENTLY ON ALL AVAILABLE FRAME QUEUES. */
#define RCEAFC_OFFSET     0x088

typedef unsigned data_area_ptr_assign_type;

typedef union {
  struct {
#if defined(_LP64)
    data_area_ptr_assign_type lower;
#endif
    data_area_ptr_assign_type assign;
  };
  char* deref;
} data_area_ptr; 


int uv__platform_loop_init(uv_loop_t* loop) {
  int fd;

  fd = epoll_create1(UV__EPOLL_CLOEXEC);

  if (fd != -1)
    uv__cloexec(fd, 1);

  loop->backend_fd = fd;

  if (fd == -1)
    return -errno;

  loop->msgqid = msgget( IPC_PRIVATE, IPC_CREAT + S_IRUSR + S_IWUSR );

  assert(loop->msgqid != -1);
  if (loop->msgqid == -1)
    return -errno;

  int events = POLLIN;	
  epoll_ctl(loop->backend_fd, UV__EPOLL_CTL_ADD_MSGQ, loop->msgqid, &events);

  return 0;
}

void uv__platform_loop_delete(uv_loop_t* loop) {

  if (loop->msgqid > 0) {
    msgctl(loop->msgqid, IPC_RMID, NULL);
    epoll_ctl(loop->backend_fd, UV__EPOLL_CTL_DEL, loop->msgqid, NULL);
    loop->msgqid = -1;
  }

  loop->backend_fd = -1;
}

uint64_t uv__hrtime(uv_clocktype_t type) {
  struct timeval t;
  gettimeofday(&t, NULL);
  uint64_t s = t.tv_sec ;
  s *= 1000000000;
  s += (t.tv_usec*1000);
  return s;
}

int uv_exepath(char* buffer, size_t* size) {
  size_t len;
  char var[] = "EXE_PATH";

  if (buffer == NULL || size == NULL || *size == 0)
    return -EINVAL;

  char *exe_path=__getenv(var);
  if (exe_path == NULL)
    return -EINVAL;

  len = strlen(exe_path);
  *size = len > *size - 1 ? *size - 1 : len ;
  memcpy(buffer, exe_path, *size);
  buffer[*size] = '\0';

  return 0;
}

uint64_t uv_get_free_memory(void) {
  data_area_ptr cvt = {0};
  data_area_ptr rcep = {0};
  cvt.assign = *(data_area_ptr_assign_type*)(CVT_PTR);
  rcep.assign = *(data_area_ptr_assign_type*)(cvt.deref + CVTRCEP_OFFSET);
  uint64_t freeram = *((uint64_t*)(rcep.deref + RCEAFC_OFFSET)) * 4;
  return freeram;
}

uint64_t uv_get_total_memory(void) {
  data_area_ptr cvt = {0};
  data_area_ptr rcep = {0};
  cvt.assign = *(data_area_ptr_assign_type*)(CVT_PTR);
  rcep.assign = *(data_area_ptr_assign_type*)(cvt.deref + CVTRCEP_OFFSET);
  uint64_t totalram = *((uint64_t*)(rcep.deref + RCEPOOL_OFFSET)) * 4;
  return totalram;
}

int uv_resident_set_memory(size_t* rss) {
  W_PSPROC buf;

  memset(&buf, 0x00, sizeof(buf));
  if(w_getpsent(0, &buf, sizeof(W_PSPROC)) == -1)
    return -EINVAL;

  *rss = buf.ps_size;
  return 0;
}

int uv_uptime(double* uptime) {
  struct utmpx u ;
  struct utmpx *v;

  u.ut_type = BOOT_TIME;
  v = getutxid(&u);
  if (v==NULL)
    return -1;
  time64_t t;
  *uptime = difftime64( time64(&t), v->ut_tv.tv_sec);
  return 0;
}

int uv_cpu_info(uv_cpu_info_t** cpu_infos, int* count) {
  uv_cpu_info_t* cpu_info;
  int result;
  int idx;
  siv1v2 info;
  data_area_ptr cvt = {0};
  data_area_ptr csd = {0};
  data_area_ptr rmctrct = {0};
  data_area_ptr cvtopctp = {0};
  int cpu_usage_avg;

  cvt.assign = *(data_area_ptr_assign_type*)(CVT_PTR);

  csd.assign = *((data_area_ptr_assign_type *) (cvt.deref + CSD_OFFSET));
  cvtopctp.assign = *((data_area_ptr_assign_type *) (cvt.deref + CVTOPCTP_OFFSET));
  rmctrct.assign = *((data_area_ptr_assign_type *) (cvtopctp.deref + RMCTRCT_OFFSET));

  *count = *((int*) (csd.deref + CSD_NUMBER_ONLINE_CPUS));
  cpu_usage_avg = *((unsigned short int*) (rmctrct.deref + RCTLACS_OFFSET));

  *cpu_infos = (uv_cpu_info_t*) uv__malloc(*count * sizeof(uv_cpu_info_t));
  if (!*cpu_infos)
    return -ENOMEM;

  cpu_info = *cpu_infos;
  idx = 0;
  while (idx < *count) {

    cpu_info->speed = *(int*)(info.siv1v2si22v1.si22v1cpucapability);
    cpu_info->model = malloc(17);
    memset(cpu_info->model, '\0', 17);
    memcpy(cpu_info->model, info.siv1v2si11v1.si11v1cpcmodel, 16);
    cpu_info->cpu_times.user = cpu_usage_avg;
    cpu_info->cpu_times.sys = 0;
    cpu_info->cpu_times.idle = 0;
    cpu_info->cpu_times.irq = 0;
    cpu_info->cpu_times.nice = 0;
    cpu_info++;
    idx++;
  }

  return 0;
}

void uv_free_cpu_info(uv_cpu_info_t* cpu_infos, int count) {
  int i;

  for (i = 0; i < count; ++i) {
    uv__free(cpu_infos[i].model);
  }

  uv__free(cpu_infos);
}

static int uv__interface_addresses_v6(uv_interface_address_t** addresses,
    int* count) {
  uv_interface_address_t* address;
  int sockfd;
  int size = 16384;
  __net_ifconf6header_t ifc;
  __net_ifconf6entry_t *ifr, *p, flg;

  *count = 0;

  if (0 > (sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP))) {
    return -errno;
  }

  ifc.__nif6h_version = 1;
  ifc.__nif6h_buflen = size;
  ifc.__nif6h_buffer = (char*)uv__malloc(size);;

  if (ioctl(sockfd, SIOCGIFCONF6, &ifc) == -1) {
    SAVE_ERRNO(uv__close(sockfd));
    return -errno;
  }


#define MAX(a,b) (((a)>(b))?(a):(b))
#define ADDR_SIZE(p) MAX((p).sin6_len, sizeof(p))

  *count = ifc.__nif6h_entries;

  /* Alloc the return interface structs */
  *addresses = (uv_interface_address_t*)
    uv__malloc(*count * sizeof(uv_interface_address_t));
  if (!(*addresses)) {
    uv__close(sockfd);
    return -ENOMEM;
  }
  address = *addresses;

  ifr = (__net_ifconf6entry_t*)(ifc.__nif6h_buffer);
  while ((char*)ifr < (char*)ifc.__nif6h_buffer + ifc.__nif6h_buflen) {
    p = ifr;
    ifr = (__net_ifconf6entry_t*)((char*)ifr + ifc.__nif6h_entrylen);

    if (!(p->__nif6e_addr.sin6_family == AF_INET6 ||
          p->__nif6e_addr.sin6_family == AF_INET))
      continue;

    if (!(p->__nif6e_flags & _NIF6E_FLAGS_ON_LINK_ACTIVE))
      continue;

    /* All conditions above must match count loop */

    address->name = uv__strdup(p->__nif6e_name);

    if (p->__nif6e_addr.sin6_family == AF_INET6) {
      address->address.address6 = *((struct sockaddr_in6*) &p->__nif6e_addr);
    } else {
      address->address.address4 = *((struct sockaddr_in*) &p->__nif6e_addr);
    }

    /* TODO: Retrieve netmask using SIOCGIFNETMASK ioctl */

    address->is_internal = flg.__nif6e_flags & _NIF6E_FLAGS_LOOPBACK ? 1 : 0;

    address++;
  }

#undef ADDR_SIZE
#undef MAX

  uv__close(sockfd);
  return 0;
}

int uv_interface_addresses(uv_interface_address_t** addresses,
    int* count) {
  uv_interface_address_t* address;
  int sockfd;
  int size = 16384;
  struct ifconf ifc;
  struct ifreq *ifr, *p, flg;

  /* get the ipv6 addresses first */
  uv_interface_address_t *addresses_v6;
  int count_v6;
  uv__interface_addresses_v6(&addresses_v6, &count_v6);

  /* now get the ipv4 addresses */
  *count = 0;

  if (0 > (sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP))) {
    return -errno;
  }

  ifc.ifc_req = (struct ifreq*)uv__malloc(size);
  ifc.ifc_len = size;
  if (ioctl(sockfd, SIOCGIFCONF, &ifc) == -1) {
    SAVE_ERRNO(uv__close(sockfd));
    return -errno;
  }

#define MAX(a,b) (((a)>(b))?(a):(b))
#define ADDR_SIZE(p) MAX((p).sa_len, sizeof(p))

  /* Count all up and running ipv4/ipv6 addresses */
  ifr = ifc.ifc_req;
  while ((char*)ifr < (char*)ifc.ifc_req + ifc.ifc_len) {
    p = ifr;
    ifr = (struct ifreq*)
      ((char*)ifr + sizeof(ifr->ifr_name) + ADDR_SIZE(ifr->ifr_addr));

    if (!(p->ifr_addr.sa_family == AF_INET6 ||
          p->ifr_addr.sa_family == AF_INET))
      continue;

    memcpy(flg.ifr_name, p->ifr_name, sizeof(flg.ifr_name));
    if (ioctl(sockfd, SIOCGIFFLAGS, &flg) == -1) {
      SAVE_ERRNO(uv__close(sockfd));
      return -errno;
    }

    if (!(flg.ifr_flags & IFF_UP && flg.ifr_flags & IFF_RUNNING))
      continue;

    (*count)++;
  }

  /* Alloc the return interface structs */
  *addresses = (uv_interface_address_t*)
    uv__malloc((*count + count_v6) * sizeof(uv_interface_address_t));
  if (!(*addresses)) {
    uv__close(sockfd);
    return -ENOMEM;
  }
  address = *addresses;

  /* copy over the ipv6 addresses */
  memcpy(address, addresses_v6, count_v6 * sizeof(uv_interface_address_t));
  address += count_v6;
  *count += count_v6;
  free(addresses_v6);

  ifr = ifc.ifc_req;
  while ((char*)ifr < (char*)ifc.ifc_req + ifc.ifc_len) {
    p = ifr;
    ifr = (struct ifreq*)
      ((char*)ifr + sizeof(ifr->ifr_name) + ADDR_SIZE(ifr->ifr_addr));

    if (!(p->ifr_addr.sa_family == AF_INET6 ||
          p->ifr_addr.sa_family == AF_INET))
      continue;

    memcpy(flg.ifr_name, p->ifr_name, sizeof(flg.ifr_name));
    if (ioctl(sockfd, SIOCGIFFLAGS, &flg) == -1) {
      uv__close(sockfd);
      return -ENOSYS;
    }

    if (!(flg.ifr_flags & IFF_UP && flg.ifr_flags & IFF_RUNNING))
      continue;

    /* All conditions above must match count loop */

    address->name = uv__strdup(p->ifr_name);

    if (p->ifr_addr.sa_family == AF_INET6) {
      address->address.address6 = *((struct sockaddr_in6*) &p->ifr_addr);
    } else {
      address->address.address4 = *((struct sockaddr_in*) &p->ifr_addr);
    }

    /* TODO: Retrieve netmask using SIOCGIFNETMASK ioctl */

    address->is_internal = flg.ifr_flags & IFF_LOOPBACK ? 1 : 0;

    address++;
  }

#undef ADDR_SIZE
#undef MAX

  uv__close(sockfd);
  return 0;
}

void uv_free_interface_addresses(uv_interface_address_t* addresses,
                                 int count) {
  int i;
  for (i = 0; i < count; ++i) {
    uv__free(addresses[i].name);
  }
  uv__free(addresses);
}

void uv__platform_invalidate_fd(uv_loop_t* loop, int fd) {
  struct epoll_event* events;
  struct epoll_event dummy;
  uintptr_t i;
  uintptr_t nfds;

  assert(loop->watchers != NULL);

  events = (struct epoll_event*) loop->watchers[loop->nwatchers];
  nfds = (uintptr_t) loop->watchers[loop->nwatchers + 1];
  if (events != NULL)
    /* Invalidate events with same file descriptor */
    for (i = 0; i < nfds; i++)
      if ((int) events[i].data.fd == fd)
        events[i].data.fd = -1;

  /* Remove the file descriptor from the epoll.
   * This avoids a problem where the same file description remains open
   * in another process, causing repeated junk epoll events.
   *
   * We pass in a dummy epoll_event, to work around a bug in old kernels.
   */
  if (loop->backend_fd >= 0) {
    epoll_ctl(loop->backend_fd, UV__EPOLL_CTL_DEL, fd, &dummy);
  }
}

int uv__io_check_fd(uv_loop_t* loop, int fd) {
  struct pollfd p[1];
  int rv;

  p[0].fd = fd;
  p[0].events = POLLIN;

  do
    rv = poll(p, 1, 0);
  while (rv == -1 && errno == EINTR);

  if (rv == -1)
    abort();

  if (p[0].revents & POLLNVAL)
    return -1;

  return 0;
}

void uv__fs_event_close(uv_fs_event_t* handle) {
  UNREACHABLE();
}

int uv_fs_event_init(uv_loop_t* loop, uv_fs_event_t* handle) {
  uv__handle_init(loop, (uv_handle_t*)handle, UV_FS_EVENT);
  return 0;
}

int uv_fs_event_start(uv_fs_event_t* handle,
    uv_fs_event_cb cb,
    const char* filename,
    unsigned int flags) {
  return -ENOSYS;
}

int uv_fs_event_stop(uv_fs_event_t* handle) {
  return -ENOSYS;
}

static int async_message(uv_loop_t* loop) {

  int nevents = 0;

  /* first collect all messages */
  struct AioMsg msgin[1024];
  for(int i = 0; i < 1024; ++i) {
    int msglen =  msgrcv(loop->msgqid, &msgin[i], sizeof(msgin[i].mm_ptr), 0, IPC_NOWAIT );
    if (msglen == -1) {
      break;
    }
    assert(msgin[i].mm_type == AIO_MSG_READ || msgin[i].mm_type == AIO_MSG_WRITE || msgin[i].mm_type == AIO_MSG_ACCEPT || msgin[i].mm_type == AIO_MSG_CONNECT);
    ++nevents;
  }

  /* now process them */
  for(int i = 0; i < nevents; ++i)
  {
    if(msgin[i].mm_type == AIO_MSG_READ)
    {
      int flags = 0;
      uv__io_t *watcher;
      uv_tcp_t* stream;

      watcher = (uv__io_t*)msgin[i].mm_ptr;
      stream = container_of(watcher, uv_stream_t, io_watcher);


      if (stream->flags & UV_CLOSING || aio_error(&stream->aio_read) == ECANCELED)
        continue;

      if (stream->flags & UV_STREAM_READ_EOF || stream->aio_read.aio_rc == ECANCELED)
        flags = POLLHUP;	// we have already read eof. So hangup */ 
      else
        flags = POLLIN;

      if(!(stream->flags & UV_CLOSING))
        watcher->cb(loop, watcher, flags);


      if(QUEUE_EMPTY(&stream->write_queue) && stream->shutdown_req)
        uv__io_feed(loop, watcher);

    }
    else if(msgin[i].mm_type == AIO_MSG_ACCEPT)
    {
      int flags=0;
      uv__io_t *watcher;
      uv_tcp_t* stream;

      watcher = (uv__io_t*)msgin[i].mm_ptr;
      stream = container_of(watcher, uv_stream_t, io_watcher);

      if(stream->flags & UV_STREAM_READ_EOF || stream->aio_read.aio_rc == ECANCELED)
        flags = POLLHUP;	// we have already read eof. So hangup */ 
      else
        flags = POLLIN;

      if(stream->flags & UV_CLOSING)
        continue;

      stream->last_op_rv = 1;
      watcher->cb(loop, watcher, flags);
        
    }
    else if(msgin[i].mm_type == AIO_MSG_WRITE)
    {
      int flags=0;
      uv_write_t *req = (uv_write_t*)msgin[i].mm_ptr;
      uv__io_t *watcher = &req->handle->io_watcher;
      int fd = req->aio_write.aio_fildes;


      if (req->handle->flags & UV_CLOSING ||  req->aio_write.aio_rc == ECANCELED)
        continue;
      
      if ((req->handle->flags & UV_CLOSING) && !(uv__io_active(&req->handle->io_watcher, POLLIN)))
        flags = POLLHUP;
      else
        flags = POLLOUT;

      watcher->cb(loop, watcher, flags);
      continue;
    }
    else if(msgin[i].mm_type == AIO_MSG_CONNECT)
    {
      int flags=0;
      int error;

      uv_connect_t *req = (uv_connect_t*)msgin[i].mm_ptr;
      uv__io_t *watcher = &req->handle->io_watcher;
      int fd = req->aio_connect.aio_fildes;

      if ((req->handle->flags & UV_CLOSING) && !(uv__io_active(&req->handle->io_watcher, POLLIN)))
        flags = POLLHUP;
      else
        flags = POLLOUT;

      if (req->handle->flags & UV_CLOSING)
        continue;

      error = 0;
      error = aio_error(&req->aio_connect);
      if(error)
        req->handle->delayed_error = -error;

      free(req->aio_connect.aio_sockaddrptr);
      watcher->cb(loop, watcher, flags);

      if(QUEUE_EMPTY(&req->handle->write_queue) && req->handle->shutdown_req)
        uv__io_feed(loop, watcher);

      continue;
    }
    else {
      assert(0 && "unexpected message\n");
    }

  }
  return nevents;
}

void uv__io_poll(uv_loop_t* loop, int timeout) {
  /* A bug in kernels < 2.6.37 makes timeouts larger than ~30 minutes
   * effectively infinite on 32 bits architectures.  To avoid blocking
   * indefinitely, we cap the timeout and poll again if necessary.
   *
   * Note that "30 minutes" is a simplification because it depends on
   * the value of CONFIG_HZ.  The magic constant assumes CONFIG_HZ=1200,
   * that being the largest value I have seen in the wild (and only once.)
   */
  static const int max_safe_timeout = 1789569;
  struct epoll_event events[1024];
  struct epoll_event* pe;
  struct epoll_event e;
  int real_timeout;
  QUEUE* q;
  uv__io_t* w;
  sigset_t sigset;
  uint64_t sigmask;
  uint64_t base;
  int count;
  int nfds=0;
  int fd;
  int op;
  int i;

  if (loop->nfds == 0) {
    assert(QUEUE_EMPTY(&loop->watcher_queue));
    return;
  }

  while (!QUEUE_EMPTY(&loop->watcher_queue)) {
    q = QUEUE_HEAD(&loop->watcher_queue);
    QUEUE_REMOVE(q);
    QUEUE_INIT(q);
    w = QUEUE_DATA(q, uv__io_t, watcher_queue);

    assert(w->pevents != 0);
    assert(w->fd >= 0);

    uv_stream_t *stream= container_of(w, uv_stream_t, io_watcher);
    if(stream->flags & UV_STREAM_BLOCKING) {

      if(w->pevents & POLLIN && !stream->connect_req) {

        if(stream->type == UV_TCP && ((uv_tcp_t*)stream)->is_listening) {

          /* Take care of last synchronous op first */
          if(stream->last_op_rv == 1) {
            w->cb(loop, w, POLLIN);
            timeout = 0;
          }
          else if(stream->last_op_rv == -1) {
            w->cb(loop, w, POLLIN | POLLHUP);
            timeout = 0;
          }

          /* poll if neccessary */
          if(w->pevents & POLLIN && !(w->events & POLLIN))
            uv__zos_aio_acceptpoll(stream, 0);

        }
        else if(stream->flags & UV_STREAM_READING) {
          /* Take care of last synchronous op first */
          if(stream->last_op_rv == 1) {
            w->cb(loop, w, POLLIN);
            timeout = 0;
          }
          else if(stream->last_op_rv == -1) {
            w->cb(loop, w, POLLIN | POLLHUP);
            timeout = 0;
          }

          if(w->pevents & POLLIN && !(w->events & POLLIN))
            uv__zos_aio_readpoll(stream, 0);

          if(stream->last_op_rv == -1) {
            w->cb(loop, w, POLLIN | POLLHUP);
            timeout = 0;
          }
        }
      }

    }
    else {

      assert(w->fd < (int) loop->nwatchers);

      e.events = w->pevents;
      e.data.fd = w->fd;

      if (w->events == 0)
        op = UV__EPOLL_CTL_ADD;
      else
        op = UV__EPOLL_CTL_MOD;

      /* XXX Future optimization: do EPOLL_CTL_MOD lazily if we stop watching
       * events, skip the syscall and squelch the events after epoll_wait().
       */
      if (epoll_ctl(loop->backend_fd, op, w->fd, &e)) {
        if (errno != EEXIST)
          abort();

        assert(op == UV__EPOLL_CTL_ADD);

        /* XXX Future optimization: do EPOLL_CTL_MOD lazily if we stop watching
         * events, skip the syscall and squelch the events after epoll_wait().
         */
        if (epoll_ctl(loop->backend_fd, op, w->fd, &e)) {
          if (errno != EEXIST)
            abort();

          assert(op == UV__EPOLL_CTL_ADD);

          /* We've reactivated a file descriptor that's been watched before. */
          if (epoll_ctl(loop->backend_fd, UV__EPOLL_CTL_MOD, w->fd, &e))
            abort();
        }
      }
    }

    w->events = w->pevents;
  }

  sigmask = 0;
  if (loop->flags & UV_LOOP_BLOCK_SIGPROF) {
    sigemptyset(&sigset);
    sigaddset(&sigset, SIGPROF);
    sigmask |= 1 << (SIGPROF - 1);
  }

  assert(timeout >= -1);
  base = loop->time;
  count = 48; /* Benchmarks suggest this gives the best throughput. */
  real_timeout = timeout;
  int nevents = 0;

  for (;;) {


    /* See the comment for max_safe_timeout for an explanation of why
     * this is necessary.  Executive summary: kernel bug workaround.
     */
    if (sizeof(int32_t) == sizeof(long) && timeout >= max_safe_timeout)
      timeout = max_safe_timeout;

    nfds = epoll_wait(loop->backend_fd,
        events,
        ARRAY_SIZE(events),
        timeout);

    /* Update loop->time unconditionally. It's tempting to skip the update when
     * timeout == 0 (i.e. non-blocking poll) but there is no guarantee that the
     * operating system didn't reschedule our process while in the syscall.
     */
    base = loop->time;
    SAVE_ERRNO(uv__update_time(loop));

    if (nfds == 0) {
      assert(timeout != -1);

      timeout = real_timeout - timeout;
      if (timeout > 0)
        continue;

      return;
    }

    if (nfds == -1) {

      if (errno != EINTR)
        abort();

      if (timeout == -1)
        continue;

      if (timeout == 0)
        return;

      /* Interrupted by a signal. Update timeout and poll again. */
      goto update_timeout;
    }


    assert(loop->watchers != NULL);
    loop->watchers[loop->nwatchers] = (void*) events;
    loop->watchers[loop->nwatchers + 1] = (void*) (uintptr_t) nfds;
    for (i = 0; i < nfds; i++) {
      pe = events + i;
      fd = pe->data.fd;

      /* Skip invalidated events, see uv__platform_invalidate_fd */
      if (fd == -1)
        continue;

      if (fd == loop->msgqid) {
        nevents += async_message(loop);
        continue;
      }

      assert(fd >= 0);
      assert((unsigned) fd < loop->nwatchers);

      w = loop->watchers[fd];

      if (w == NULL) {
        /* File descriptor that we've stopped watching, disarm it.
         *
         * Ignore all errors because we may be racing with another thread
         * when the file descriptor is closed.
         */
        epoll_ctl(loop->backend_fd, UV__EPOLL_CTL_DEL, fd, pe);
        continue;
      }

      /* Give users only events they're interested in. Prevents spurious
       * callbacks when previous callback invocation in this loop has stopped
       * the current watcher. Also, filters out events that users has not
       * requested us to watch.
       */
      pe->events &= w->pevents | POLLERR | POLLHUP;

      /* Work around an epoll quirk where it sometimes reports just the
       * EPOLLERR or EPOLLHUP event.  In order to force the event loop to
       * move forward, we merge in the read/write events that the watcher
       * is interested in; uv__read() and uv__write() will then deal with
       * the error or hangup in the usual fashion.
       *
       * Note to self: happens when epoll reports EPOLLIN|EPOLLHUP, the user
       * reads the available data, calls uv_read_stop(), then sometime later
       * calls uv_read_start() again.  By then, libuv has forgotten about the
       * hangup and the kernel won't report EPOLLIN again because there's
       * nothing left to read.  If anything, libuv is to blame here.  The
       * current hack is just a quick bandaid; to properly fix it, libuv
       * needs to remember the error/hangup event.  We should get that for
       * free when we switch over to edge-triggered I/O.
       */
      if (pe->events == POLLERR || pe->events == POLLHUP)
        pe->events |= w->pevents & (POLLIN | POLLOUT);

      if (pe->events != 0) {
        w->cb(loop, w, pe->events);
        nevents++;
      }
    }
    loop->watchers[loop->nwatchers] = NULL;
    loop->watchers[loop->nwatchers + 1] = NULL;

    if (nevents != 0) {
      if (nfds == ARRAY_SIZE(events) && --count != 0) {
        /* Poll for more events but don't block this time. */
        timeout = 0;
        continue;
      }
      return;
    }

    if (timeout == 0)
      return;

    if (timeout == -1)
      continue;

update_timeout:
    assert(timeout > 0);

    real_timeout -= (loop->time - base);
    if (real_timeout <= 0)
      return;

    timeout = real_timeout;
  }
}

int uv__zos_aio_write(uv_write_t *req, uv_stream_t *stream, char *buf, int len, int vector) {
  int err;
  int byteswritten;
  int rv, rc, rsn;

  if(!(stream->flags & UV_STREAM_BLOCKING))
    if(vector)
      return writev(uv__stream_fd(stream), buf, len);
    else
      return write(uv__stream_fd(stream), buf, len);
    

  err = aio_error(&req->aio_write);

  if(err == EINPROGRESS) {
    errno = EWOULDBLOCK;
    return -1;
  }
    
  if(err != 0) {
    errno = err;
    return -1;
  }

  byteswritten = aio_return(&req->aio_write);
  if(byteswritten) {
    memset(&req->aio_write, 0, sizeof(struct aiocb));
    return byteswritten;
  }

  memset(&req->aio_write, 0, sizeof(struct aiocb));
  req->aio_write.aio_fildes = uv__stream_fd(stream);
  req->aio_write.aio_notifytype = AIO_MSGQ;
  req->aio_write.aio_cflags |= AIO_OK2COMPIMD; 
  req->aio_write_msg.mm_type = AIO_MSG_WRITE;
  req->aio_write_msg.mm_ptr = req;
  req->aio_write.aio_msgev_addr = &req->aio_write_msg;
  req->aio_write.aio_msgev_size = sizeof(req->aio_write_msg.mm_ptr);
  if(vector) {
    /* vector */
    req->aio_write.aio_cmd = AIO_WRITEV;
    req->aio_write.aio_buf = buf;
    req->aio_write.aio_nbytes = len;
  } else {
    req->aio_write.aio_cmd = AIO_WRITE;
    req->aio_write.aio_buf = buf;
    req->aio_write.aio_nbytes = len;
  }
  req->aio_write.aio_msgev_qid = stream->loop->msgqid;

  if(req->aio_write.aio_nbytes == 0) 
    return 0;

  ZASYNC(sizeof(req->aio_write), &req->aio_write, &rv, &rc, &rsn);
  if(rv == 0) {                                                   
   /* Asynchronous write */                                    
    errno = EWOULDBLOCK;
    return -1;
  }
  else if(rv == -1) {                                           
    memset(&req->aio_write, 0, sizeof(struct aiocb));
    errno = rc;
    return -1;
  }                                                             
  else if(rv == 1) {                                                        
    /* Synchronous write or failure */                          
    byteswritten = aio_return(&req->aio_write);
    memset(&req->aio_write, 0, sizeof(struct aiocb));
  }                                                             

  return byteswritten;
}

int uv__zos_aio_connect(uv_connect_t *req, uv_stream_t *stream, const struct sockaddr* addr, unsigned int addrlen) {
  memset(&req->aio_connect, 0, sizeof(struct aiocb));
  req->aio_connect.aio_fildes = uv__stream_fd(stream);
  req->aio_connect.aio_notifytype = AIO_MSGQ;
  req->aio_connect.aio_cmd = AIO_CONNECT;
  req->aio_connect.aio_msgev_qid = stream->loop->msgqid;
  req->aio_connect_msg.mm_type = AIO_MSG_CONNECT;
  req->aio_connect_msg.mm_ptr = req;
  req->aio_connect.aio_msgev_addr = &req->aio_connect_msg;
  req->aio_connect.aio_msgev_size = sizeof(req->aio_connect_msg.mm_ptr);
  req->aio_connect.aio_sockaddrlen = addrlen;
  req->aio_connect.aio_sockaddrptr = (struct sockaddr_in*)uv__malloc(addrlen);
  int rv, rc, rsn;
  if (req->aio_connect.aio_sockaddrptr != NULL) {
    memcpy(req->aio_connect.aio_sockaddrptr, addr, addrlen);
    ZASYNC(sizeof(req->aio_connect), &req->aio_connect, &rv, &rc, &rsn);
    if(rv < 0) {
      errno = rc;
      return -1;
    }
    else if(rv == 0){
      /* connect has not happened immediately
     wait for notification */
      errno = EINPROGRESS;
      return -1;
    }
    else if(rv == 1) {
      /* do nothing. Just as if connect() succeeded */
      return 0;
    }
  }

  return -1;
}

static int uv__zos_aio_acceptpoll(uv_stream_t *stream, int compimd) {
  int rv, rc, rsn;

  memset(&stream->aio_read , 0, sizeof(struct aiocb));
  stream->aio_read.aio_fildes = stream->io_watcher.fd;
  stream->aio_read.aio_notifytype = AIO_MSGQ;
  stream->aio_read.aio_cmd = AIO_ACCEPT;
  stream->aio_read.aio_cflags |= compimd ? AIO_OK2COMPIMD : 0; 
  stream->aio_read.aio_msgev_qid = stream->loop->msgqid;
  stream->aio_read_msg.mm_type = AIO_MSG_ACCEPT;
  stream->aio_read_msg.mm_ptr = &stream->io_watcher;
  stream->aio_read.aio_msgev_addr = &stream->aio_read_msg;
  stream->aio_read.aio_msgev_size = sizeof(stream->aio_read_msg.mm_ptr);
  ZASYNC(sizeof(struct aiocb), &stream->aio_read, &rv, &rc, &rsn);

  stream->last_op_rv = rv;

  errno = rc;
  return rv;
}

int uv__zos_aio_accept(uv_stream_t *stream) {
  /* - Must be able to be called multiple times */

  int err;

  if(!(stream->flags & UV_STREAM_BLOCKING))
    return uv__accept(uv__stream_fd(stream));

  if(stream->last_op_rv == 0)
    err = -EWOULDBLOCK;
  else if(stream->aio_read.aio_rc == EINPROGRESS)
    err = -EWOULDBLOCK;
  else if(stream->aio_read.aio_rv == -1)
    err = -stream->aio_read.aio_rc;
  else
    err = stream->aio_read.aio_rv;

  uv__zos_aio_acceptpoll(stream, 1);
  return err;
}

int uv__zos_aio_read(uv_stream_t *stream, char **buf, unsigned long *len) {
  int err;

  if(!(stream->flags & UV_STREAM_BLOCKING)){
    return read(uv__stream_fd(stream), *buf, *len);
  }

  err = aio_error(&stream->aio_read);

  if(err == EINPROGRESS) {
    errno = EWOULDBLOCK;
    return -1;
  }
  else if(err != 0) {
    errno = err;
    return -1;
  }

  err = aio_return(&stream->aio_read);

  if(stream->bufsml.len > 0) {
    uv_buf_t newbuf;
    stream->alloc_cb((uv_handle_t*)stream, err, &newbuf);

    /* if this assert starts failing, we need to account for the user asking
       for less bytes than what we read into bufsml 
       May be temporarily store it somewhere and return it in the next call? */
    assert(newbuf.len >= err);

    memcpy(newbuf.base, stream->bufsml.base, err);
    *buf = newbuf.base;
    *len = newbuf.len;
    free(stream->bufsml.base);
    stream->bufsml.len = 0;
  }
  else {
    *buf = stream->aio_read.aio_buf;
    *len = 64 * 1024;
  }

  uv__zos_aio_readpoll(stream, err < *len ? 0 : 1);
  return err;
}

static int uv__zos_aio_readpoll(uv_stream_t *stream, int compimd) {
  int rv, rc, rsn;

  memset(&stream->aio_read, 0, sizeof(struct aiocb));
  stream->aio_read.aio_fildes = uv__stream_fd(stream);
  stream->aio_read.aio_notifytype = AIO_MSGQ;
  stream->aio_read.aio_cflags |= compimd ? AIO_OK2COMPIMD : 0; 
  stream->aio_read.aio_cmd = AIO_READ;
  stream->aio_read.aio_msgev_qid = stream->loop->msgqid;
  stream->aio_read_msg.mm_type = AIO_MSG_READ;
  stream->aio_read_msg.mm_ptr = &stream->io_watcher;
  stream->aio_read.aio_msgev_addr = &stream->aio_read_msg;
  stream->aio_read.aio_msgev_size = sizeof(stream->aio_read_msg.mm_ptr);
  if(stream->bufsml.len > 0) {
    stream->aio_read.aio_buf = stream->bufsml.base;
    stream->aio_read.aio_offset = 0;
    stream->aio_read.aio_nbytes = stream->bufsml.len;
  }
  else {
    uv_buf_t buf;
    stream->alloc_cb((uv_handle_t*)stream, 64 * 1024, &buf);
    stream->aio_read.aio_buf = buf.base;
    stream->aio_read.aio_offset = 0;
    stream->aio_read.aio_nbytes = buf.len;
  }

  ZASYNC(sizeof(stream->aio_read), &stream->aio_read, &rv, &rc, &rsn);

  stream->last_op_rv = rv;

  errno = rc;
  return rv;
}

int uv__asyncio_zos_cancel(uv_stream_t *stream) {

  if(!(stream->flags & UV_STREAM_BLOCKING))
    return 0;

  struct aiocb aio_cancel;
  memset(&aio_cancel, 0, sizeof(struct aiocb));
  aio_cancel.aio_fildes = uv__stream_fd(stream);
  aio_cancel.aio_notifytype = AIO_MSGQ;
  aio_cancel.aio_cmd = AIO_CANCEL;
  aio_cancel.aio_buf = NULL;
  aio_cancel.aio_nbytes = 0;
  int rv, rc, rsn;
  do {
    ZASYNC(sizeof(aio_cancel), &aio_cancel, &rv, &rc, &rsn);
  } while(aio_cancel.aio_rv == 1 || aio_cancel.aio_rv == 2);

  return 0;
}

void uv_loadavg(double avg[3]) {
  avg[0] = 0;
  avg[1] = 0;
  avg[2] = 0;
}

char** uv_setup_args(int argc, char** argv) {
  return argv;
}

int uv_set_process_title(const char* title) {
  return 0;
}

int uv_get_process_title(char* buffer, size_t size) {
  if (size > 0)
    buffer[0] = '\0';
  return 0;
}
