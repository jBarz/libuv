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
#include <sys/ioctl.h>
#include <net/if.h>
#include <utmpx.h>
#include <unistd.h>
#include <sys/ps.h>
#include <builtins.h>
#include <termios.h>
#include <sys/msg.h>
#if defined(__clang__)
#include "csrsic.h"
#else
#include "//'SYS1.SAMPLIB(CSRSIC)'"
#endif

#define CVT_PTR           0x10
#define PSA_PTR           0x00
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

/* Address of system resources manager (SRM) control table */
#define CVTOPCTP_OFFSET   0x25C

/* Address of the RCT table */
#define RMCTRCT_OFFSET    0xE4

/* Address of the rsm control and enumeration area. */
#define CVTRCEP_OFFSET    0x490

/*
    Number of frames currently available to system.
    Excluded are frames backing perm storage, frames offline, and bad frames.
*/
#define RCEPOOL_OFFSET    0x004

/* Total number of frames currently on all available frame queues. */
#define RCEAFC_OFFSET     0x088

/* CPC model length from the CSRSI Service. */
#define CPCMODEL_LENGTH   16

/* Pointer to the home (current) ASCB. */
#define PSAAOLD           0x224

/* Pointer to rsm address space block extension. */
#define ASCBRSME          0x16C

/*
    NUMBER OF FRAMES CURRENTLY IN USE BY THIS ADDRESS SPACE.
    It does not include 2G frames.
*/
#define RAXFMCT           0x2C

/* Thread Entry constants */
#define PGTH_CURRENT  1
#define PGTH_LEN      26
#define PGTHAPATH     0x20
#pragma linkage(BPX4GTH, OS)
#pragma linkage(BPX1GTH, OS)

/* TOD Clock resolution in nanoseconds */
#define TOD_RES 4.096

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


void uv_loadavg(double avg[3]) {
  /* TODO: implement the following */
  avg[0] = 0;
  avg[1] = 0;
  avg[2] = 0;
}


int uv__platform_loop_init(uv_loop_t* loop) {
  uv__os390_epoll* ep;

  ep = epoll_create1(0);
  loop->ep = ep;
  if (ep == NULL)
    return UV__ERR(errno);

  return 0;
}


void uv__platform_loop_delete(uv_loop_t* loop) {
  if (loop->ep != NULL) {
    epoll_queue_close(loop->ep);
    loop->ep = NULL;
  }
}


uint64_t uv__hrtime(uv_clocktype_t type) {
  unsigned long long timestamp;
  __stckf(&timestamp);
  /* Convert to nanoseconds */
  return timestamp / TOD_RES;
}


/*
    Get the exe path using the thread entry information
    in the address space.
*/
static int getexe(const int pid, char* buf, size_t len) {
  struct {
    int pid;
    int thid[2];
    char accesspid;
    char accessthid;
    char asid[2];
    char loginname[8];
    char flag;
    char len;
  } Input_data;

  union {
    struct {
      char gthb[4];
      int pid;
      int thid[2];
      char accesspid;
      char accessthid[3];
      int lenused;
      int offsetProcess;
      int offsetConTTY;
      int offsetPath;
      int offsetCommand;
      int offsetFileData;
      int offsetThread;
    } Output_data;
    char buf[2048];
  } Output_buf;

  struct Output_path_type {
    char gthe[4];
    short int len;
    char path[1024];
  };

  int Input_length;
  int Output_length;
  void* Input_address;
  void* Output_address;
  struct Output_path_type* Output_path;
  int rv;
  int rc;
  int rsn;

  Input_length = PGTH_LEN;
  Output_length = sizeof(Output_buf);
  Output_address = &Output_buf;
  Input_address = &Input_data;
  memset(&Input_data, 0, sizeof Input_data);
  Input_data.flag |= PGTHAPATH;
  Input_data.pid = pid;
  Input_data.accesspid = PGTH_CURRENT;

#ifdef _LP64
  BPX4GTH(&Input_length,
          &Input_address,
          &Output_length,
          &Output_address,
          &rv,
          &rc,
          &rsn);
#else
  BPX1GTH(&Input_length,
          &Input_address,
          &Output_length,
          &Output_address,
          &rv,
          &rc,
          &rsn);
#endif

  if (rv == -1) {
    errno = rc;
    return -1;
  }

  /* Check highest byte to ensure data availability */
  assert(((Output_buf.Output_data.offsetPath >>24) & 0xFF) == 'A');

  /* Get the offset from the lowest 3 bytes */
  Output_path = (char*)(&Output_buf) +
                (Output_buf.Output_data.offsetPath & 0x00FFFFFF);

  if (Output_path->len >= len) {
    errno = ENOBUFS;
    return -1;
  }

  strncpy(buf, Output_path->path, len);

  return 0;
}


/*
 * We could use a static buffer for the path manipulations that we need outside
 * of the function, but this function could be called by multiple consumers and
 * we don't want to potentially create a race condition in the use of snprintf.
 * There is no direct way of getting the exe path in zOS - either through /procfs
 * or through some libc APIs. The below approach is to parse the argv[0]'s pattern
 * and use it in conjunction with PATH environment variable to craft one.
 */
int uv_exepath(char* buffer, size_t* size) {
  int res;
  char args[PATH_MAX];
  char abspath[PATH_MAX];
  size_t abspath_size;
  int pid;

  if (buffer == NULL || size == NULL || *size == 0)
    return UV_EINVAL;

  pid = getpid();
  res = getexe(pid, args, sizeof(args));
  if (res < 0)
    return UV_EINVAL;

  /*
   * Possibilities for args:
   * i) an absolute path such as: /home/user/myprojects/nodejs/node
   * ii) a relative path such as: ./node or ../myprojects/nodejs/node
   * iii) a bare filename such as "node", after exporting PATH variable
   *     to its location.
   */

  /* Case i) and ii) absolute or relative paths */
  if (strchr(args, '/') != NULL) {
    if (realpath(args, abspath) != abspath)
      return UV__ERR(errno);

    abspath_size = strlen(abspath);

    *size -= 1;
    if (*size > abspath_size)
      *size = abspath_size;

    memcpy(buffer, abspath, *size);
    buffer[*size] = '\0';

    return 0;
  } else {
    /* Case iii). Search PATH environment variable */
    char trypath[PATH_MAX];
    char* clonedpath = NULL;
    char* token = NULL;
    char* path = getenv("PATH");

    if (path == NULL)
      return UV_EINVAL;

    clonedpath = uv__strdup(path);
    if (clonedpath == NULL)
      return UV_ENOMEM;

    token = strtok(clonedpath, ":");
    while (token != NULL) {
      snprintf(trypath, sizeof(trypath) - 1, "%s/%s", token, args);
      if (realpath(trypath, abspath) == abspath) {
        /* Check the match is executable */
        if (access(abspath, X_OK) == 0) {
          abspath_size = strlen(abspath);

          *size -= 1;
          if (*size > abspath_size)
            *size = abspath_size;

          memcpy(buffer, abspath, *size);
          buffer[*size] = '\0';

          uv__free(clonedpath);
          return 0;
        }
      }
      token = strtok(NULL, ":");
    }
    uv__free(clonedpath);

    /* Out of tokens (path entries), and no match found */
    return UV_EINVAL;
  }
}


uint64_t uv_get_free_memory(void) {
  uint64_t freeram;

  data_area_ptr cvt = {0};
  data_area_ptr rcep = {0};
  cvt.assign = *(data_area_ptr_assign_type*)(CVT_PTR);
  rcep.assign = *(data_area_ptr_assign_type*)(cvt.deref + CVTRCEP_OFFSET);
  freeram = *((uint64_t*)(rcep.deref + RCEAFC_OFFSET)) * 4;
  return freeram;
}


uint64_t uv_get_total_memory(void) {
  uint64_t totalram;

  data_area_ptr cvt = {0};
  data_area_ptr rcep = {0};
  cvt.assign = *(data_area_ptr_assign_type*)(CVT_PTR);
  rcep.assign = *(data_area_ptr_assign_type*)(cvt.deref + CVTRCEP_OFFSET);
  totalram = *((uint64_t*)(rcep.deref + RCEPOOL_OFFSET)) * 4;
  return totalram;
}


int uv_resident_set_memory(size_t* rss) {
  char* psa;
  char* ascb;
  char* rax;
  size_t nframes;

  psa = PSA_PTR;
  ascb  = *(char* __ptr32 *)(psa + PSAAOLD);
  rax = *(char* __ptr32 *)(ascb + ASCBRSME);
  nframes = *(unsigned int*)(rax + RAXFMCT);

  *rss = nframes * sysconf(_SC_PAGESIZE);
  return 0;
}


int uv_uptime(double* uptime) {
  struct utmpx u ;
  struct utmpx *v;
  time64_t t;

  u.ut_type = BOOT_TIME;
  v = getutxid(&u);
  if (v == NULL)
    return -1;
  *uptime = difftime64(time64(&t), v->ut_tv.tv_sec);
  return 0;
}


int uv_cpu_info(uv_cpu_info_t** cpu_infos, int* count) {
  uv_cpu_info_t* cpu_info;
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

  *cpu_infos = uv__malloc(*count * sizeof(uv_cpu_info_t));
  if (!*cpu_infos)
    return UV_ENOMEM;

  cpu_info = *cpu_infos;
  idx = 0;
  while (idx < *count) {
    cpu_info->speed = *(int*)(info.siv1v2si22v1.si22v1cpucapability);
    cpu_info->model = uv__malloc(CPCMODEL_LENGTH + 1);
    memset(cpu_info->model, '\0', CPCMODEL_LENGTH + 1);
    memcpy(cpu_info->model, info.siv1v2si11v1.si11v1cpcmodel, CPCMODEL_LENGTH);
    cpu_info->cpu_times.user = cpu_usage_avg;
    /* TODO: implement the following */
    cpu_info->cpu_times.sys = 0;
    cpu_info->cpu_times.idle = 0;
    cpu_info->cpu_times.irq = 0;
    cpu_info->cpu_times.nice = 0;
    ++cpu_info;
    ++idx;
  }

  return 0;
}


void uv_free_cpu_info(uv_cpu_info_t* cpu_infos, int count) {
  for (int i = 0; i < count; ++i)
    uv__free(cpu_infos[i].model);
  uv__free(cpu_infos);
}


static int uv__interface_addresses_v6(uv_interface_address_t** addresses,
                                      int* count) {
  uv_interface_address_t* address;
  int sockfd;
  int maxsize;
  __net_ifconf6header_t ifc;
  __net_ifconf6entry_t* ifr;
  __net_ifconf6entry_t* p;
  __net_ifconf6entry_t flg;

  *count = 0;
  /* Assume maximum buffer size allowable */
  maxsize = 16384;

  if (0 > (sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)))
    return UV__ERR(errno);

  ifc.__nif6h_version = 1;
  ifc.__nif6h_buflen = maxsize;
  ifc.__nif6h_buffer = uv__calloc(1, maxsize);;

  if (ioctl(sockfd, SIOCGIFCONF6, &ifc) == -1) {
    uv__close(sockfd);
    return UV__ERR(errno);
  }


  *count = 0;
  ifr = (__net_ifconf6entry_t*)(ifc.__nif6h_buffer);
  while ((char*)ifr < (char*)ifc.__nif6h_buffer + ifc.__nif6h_buflen) {
    p = ifr;
    ifr = (__net_ifconf6entry_t*)((char*)ifr + ifc.__nif6h_entrylen);

    if (!(p->__nif6e_addr.sin6_family == AF_INET6 ||
          p->__nif6e_addr.sin6_family == AF_INET))
      continue;

    if (!(p->__nif6e_flags & _NIF6E_FLAGS_ON_LINK_ACTIVE))
      continue;

    ++(*count);
  }

  /* Alloc the return interface structs */
  *addresses = uv__malloc(*count * sizeof(uv_interface_address_t));
  if (!(*addresses)) {
    uv__close(sockfd);
    return UV_ENOMEM;
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

    if (p->__nif6e_addr.sin6_family == AF_INET6)
      address->address.address6 = *((struct sockaddr_in6*) &p->__nif6e_addr);
    else
      address->address.address4 = *((struct sockaddr_in*) &p->__nif6e_addr);

    /* TODO: Retrieve netmask using SIOCGIFNETMASK ioctl */

    address->is_internal = flg.__nif6e_flags & _NIF6E_FLAGS_LOOPBACK ? 1 : 0;

    address++;
  }

  uv__close(sockfd);
  return 0;
}


int uv_interface_addresses(uv_interface_address_t** addresses, int* count) {
  uv_interface_address_t* address;
  int sockfd;
  int maxsize;
  struct ifconf ifc;
  struct ifreq flg;
  struct ifreq* ifr;
  struct ifreq* p;
  int count_v6;

  /* get the ipv6 addresses first */
  uv_interface_address_t* addresses_v6;
  uv__interface_addresses_v6(&addresses_v6, &count_v6);

  /* now get the ipv4 addresses */
  *count = 0;

  /* Assume maximum buffer size allowable */
  maxsize = 16384;

  sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
  if (0 > sockfd)
    return UV__ERR(errno);

  ifc.ifc_req = uv__calloc(1, maxsize);
  ifc.ifc_len = maxsize;
  if (ioctl(sockfd, SIOCGIFCONF, &ifc) == -1) {
    uv__close(sockfd);
    return UV__ERR(errno);
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
      uv__close(sockfd);
      return UV__ERR(errno);
    }

    if (!(flg.ifr_flags & IFF_UP && flg.ifr_flags & IFF_RUNNING))
      continue;

    (*count)++;
  }

  /* Alloc the return interface structs */
  *addresses = uv__malloc((*count + count_v6) *
                          sizeof(uv_interface_address_t));

  if (!(*addresses)) {
    uv__close(sockfd);
    return UV_ENOMEM;
  }
  address = *addresses;

  /* copy over the ipv6 addresses */
  memcpy(address, addresses_v6, count_v6 * sizeof(uv_interface_address_t));
  address += count_v6;
  *count += count_v6;
  uv__free(addresses_v6);

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
      return UV_ENOSYS;
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
  for (i = 0; i < count; ++i)
    uv__free(addresses[i].name);
  uv__free(addresses);
}


void uv__platform_invalidate_fd(uv_loop_t* loop, int fd) {
  struct epoll_event* events;
  struct epoll_event dummy;
  struct aiocb aio_cancel;
  uintptr_t i;
  uintptr_t nfds;
  int rv;
  int rc;
  int rsn;

  assert(loop->watchers != NULL);

  events = (struct epoll_event*) loop->watchers[loop->nwatchers];
  nfds = (uintptr_t) loop->watchers[loop->nwatchers + 1];
  if (events != NULL)
    /* Invalidate events with same file descriptor */
    for (i = 0; i < nfds; i++)
      if ((int) events[i].fd == fd)
        events[i].fd = -1;

  memset(&aio_cancel, 0, sizeof(aio_cancel));
  aio_cancel.aio_cmd = AIO_CANCEL;
  aio_cancel.aio_fildes = fd;
  aio_cancel.aio_cflags = AIO_CANCELNONOTIFY;
  BPX4AIO(sizeof(aio_cancel), &aio_cancel, &rv, &rc, &rsn);
printf("JBAR BPX4AIO Cancel fd=%d\n", fd);

  /* Remove the file descriptor from the epoll. */
  if (loop->ep != NULL)
    epoll_ctl(loop->ep, UV__EPOLL_CTL_DEL, fd, &dummy);
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
  uv_fs_event_stop(handle);
}


int uv_fs_event_init(uv_loop_t* loop, uv_fs_event_t* handle) {
  uv__handle_init(loop, (uv_handle_t*)handle, UV_FS_EVENT);
  return 0;
}


int uv_fs_event_start(uv_fs_event_t* handle, uv_fs_event_cb cb,
                      const char* filename, unsigned int flags) {
  uv__os390_epoll* ep;
  _RFIS reg_struct;
  char* path;
  int rc;

  if (uv__is_active(handle))
    return UV_EINVAL;

  ep = handle->loop->ep;
  assert(ep->msg_queue != -1);

  reg_struct.__rfis_cmd  = _RFIS_REG;
  reg_struct.__rfis_qid  = ep->msg_queue;
  reg_struct.__rfis_type = 1;
  memcpy(reg_struct.__rfis_utok, &handle, sizeof(handle));

  path = uv__strdup(filename);
  if (path == NULL)
    return UV_ENOMEM;

  rc = __w_pioctl(path, _IOCC_REGFILEINT, sizeof(reg_struct), &reg_struct);
  if (rc != 0)
    return UV__ERR(errno);

  uv__handle_start(handle);
  handle->path = path;
  handle->cb = cb;
  memcpy(handle->rfis_rftok, reg_struct.__rfis_rftok,
         sizeof(handle->rfis_rftok));

  return 0;
}


int uv_fs_event_stop(uv_fs_event_t* handle) {
  uv__os390_epoll* ep;
  _RFIS reg_struct;
  int rc;

  if (!uv__is_active(handle))
    return 0;

  ep = handle->loop->ep;
  assert(ep->msg_queue != -1);

  reg_struct.__rfis_cmd  = _RFIS_UNREG;
  reg_struct.__rfis_qid  = ep->msg_queue;
  reg_struct.__rfis_type = 1;
  memcpy(reg_struct.__rfis_rftok, handle->rfis_rftok,
         sizeof(handle->rfis_rftok));

  /* 
   * This call will take "/" as the path argument in case we
   * don't care to supply the correct path. The system will simply
   * ignore it.
   */
  rc = __w_pioctl("/", _IOCC_REGFILEINT, sizeof(reg_struct), &reg_struct);
  if (rc != 0 && errno != EALREADY && errno != ENOENT)
    abort();

  uv__handle_stop(handle);

  return 0;
}


static int fs_event_message(_RFIM* msg) {
  uv_fs_event_t* handle;
  int events;

  events = 0;
  if (msg->__rfim_event == _RFIM_ATTR || msg->__rfim_event == _RFIM_WRITE)
    events = UV_CHANGE;
  else if (msg->__rfim_event == _RFIM_RENAME)
    events = UV_RENAME;
  else
    /* Some event that we are not interested in. */
    return -1;

  handle = *(uv_fs_event_t**)(msg->__rfim_utok);
  handle->cb(handle, uv__basename_r(handle->path), events, 0);
  return 0;
}


static void uv__os390_alloc(uv_handle_t* handle,
                            size_t size, uv_buf_t* buf) {
  uv_stream_t* s;
  struct aiocb* aio_read;
  uv__io_t* w;

  s = (uv_stream_t*)handle;
  w = &s->io_watcher;
  aio_read = &w->aio;
  buf->base = (char*)aio_read->aio_buf;
  buf->len = aio_read->aio_nbytes;
}


static int aio_accept_message(struct aiocb *aio) {
  uv__io_t *watcher;
  uv_stream_t *handle;
  uv_alloc_cb alloc_cb;
  QUEUE* q;
  int events;
  int fd; 

  watcher = container_of(aio, uv__io_t, aio);
  handle = container_of(watcher, uv_stream_t, io_watcher);

  events = POLLIN;
  if (aio->aio_rv == -1)
    events = POLLERR;

  /* Give users only events they're interested in. Prevents spurious
   * callbacks when previous callback invocation in this loop has stopped
   * the current watcher. Also, filters out events that users has not
   * requested us to watch.
   */
  events &= watcher->pevents | POLLERR;
  if (events == POLLERR)
    events |= watcher->pevents & (POLLIN | POLLOUT);

  /* File descriptor that we've stopped watching, ignore */
  if (watcher->fd == -1 || handle->loop->watchers[watcher->fd] == NULL)
    return 0;

  /* Call callback */
  watcher->cb(handle->loop, watcher, events);
  return 0;
}


static int aio_read_message(struct aiocb *aio) {
  uv__io_t *watcher;
  uv_stream_t *handle;
  uv_alloc_cb alloc_cb;
  QUEUE* q;
  int events;
  int fd; 

  watcher = container_of(aio, uv__io_t, aio);
  handle = container_of(watcher, uv_stream_t, io_watcher);

  /* File descriptor that we've stopped reading, ignore */
  if (watcher->fd == -1 || handle->loop->watchers[watcher->fd] == NULL)
    return -1;

  events = POLLIN;
  if (aio->aio_rv == -1)
    events = POLLERR;

  /* Give users only events they're interested in. Prevents spurious
   * callbacks when previous callback invocation in this loop has stopped
   * the current watcher. Also, filters out events that users has not
   * requested us to watch.
   */
  events &= watcher->pevents | POLLERR;
  if (events == POLLERR)
    events |= watcher->pevents & (POLLIN | POLLOUT);

  /* Call callback */
  watcher->cb(handle->loop, watcher, events);
  return 0;
}


static int aio_connect_message(struct aiocb* aio) {
  uv_connect_t* req;
  uv_stream_t* handle;
  uv__io_t* w;
  QUEUE* q;
  int events;
  int fd; 

  req = container_of(aio, uv_connect_t, aio);
  handle = req->handle;
  w = &handle->io_watcher;
  
  events = POLLOUT;
  if (aio->aio_rv == -1)
    events = POLLERR;

  /* Clear aio structure now that we are handling it */
  uv__free(aio->aio_sockaddrptr);
  memset(aio, 0, sizeof(*aio));

  /* Give users only events they're interested in. Prevents spurious
   * callbacks when previous callback invocation in this loop has stopped
   * the current watcher. Also, filters out events that users has not
   * requested us to watch.
   */
  events &= w->pevents | POLLERR;
  if (events == POLLERR)
    events |= w->pevents & (POLLIN | POLLOUT);

  /* File descriptor that we've stopped watching, ignore */
  if (w->fd == -1 || handle->loop->watchers[w->fd] == NULL)
    return 0;

  /* Call callback */
  w->cb(handle->loop, w, events);

  if (w->events & POLLOUT && w->fd >= 0)
    w->cb(handle->loop, w, events);

  return 0;
}


static int aio_shutdown_message(struct aiocb* aio) {
  uv_shutdown_t* req;
  uv_stream_t* handle;
  uv__io_t* w;
  QUEUE* q;
  int events;
  struct {
    long int type;
    void* aio;
  } aiomsg;

  req = container_of(aio, uv_shutdown_t, aio);
  handle = req->handle;
  w = &handle->io_watcher;
printf("JBAR shutdown message fd=%d\n", w->fd);
  
  events = POLLOUT;
  if (aio->aio_rv == -1)
    events = POLLERR;

  /* Give users only events they're interested in. Prevents spurious
   * callbacks when previous callback invocation in this loop has stopped
   * the current watcher. Also, filters out events that users has not
   * requested us to watch.
   */
  events &= w->pevents | POLLERR;
  if (events == POLLERR)
    events |= w->pevents & (POLLIN | POLLOUT);

  /* File descriptor that we've stopped watching, ignore */
  if (w->fd == -1 || handle->loop->watchers[w->fd] == NULL)
    return 0;

  /* Call callback */
  w->cb(handle->loop, w, events);
  return 0;
}


static int aio_write_message(struct aiocb* aio) {
  uv_write_t* req;
  uv_stream_t* handle;
  uv__io_t* w;
  QUEUE* q;
  int events;
  struct {
    long int type;
    void* aio;
  } aiomsg;

  req = container_of(aio, uv_write_t, aio);
  handle = req->handle;
  w = &handle->io_watcher;
printf("JBAR write message fd=%d\n", w->fd);
  
  events = POLLOUT;
  if (aio->aio_rv == -1)
    events = POLLERR;

  /* Give users only events they're interested in. Prevents spurious
   * callbacks when previous callback invocation in this loop has stopped
   * the current watcher. Also, filters out events that users has not
   * requested us to watch.
   */
  events &= w->pevents | POLLERR;
  if (events == POLLERR)
    events |= w->pevents & (POLLIN | POLLOUT);

  /* File descriptor that we've stopped watching, ignore */
  if (w->fd == -1 || handle->loop->watchers[w->fd] == NULL)
    return 0;

  /* Call callback */
  w->cb(handle->loop, w, events);

  if (w->events & POLLOUT && w->fd >= 0)
    w->cb(handle->loop, w, events);

  return 0;
}


static int message_handler(void* ptr) {
  union msgtype {
    long int type;
    _RFIM rfim;
    struct {
      long int type;
      struct aiocb* aio;
    } aiomsg;
  };

  union msgtype* msg = (union msgtype*)ptr;
  if (msg->type == SIGIO) {
    if (msg->aiomsg.aio->aio_cmd == AIO_WRITE) {
      if (msg->aiomsg.aio->aio_buf == NULL)
        return aio_shutdown_message(msg->aiomsg.aio);
      else
        return aio_write_message(msg->aiomsg.aio);
    }
    else if (msg->aiomsg.aio->aio_cmd == AIO_WRITEV) 
      return aio_write_message(msg->aiomsg.aio);
    else if (msg->aiomsg.aio->aio_cmd == AIO_CONNECT)
      return aio_connect_message(msg->aiomsg.aio);
    else if (msg->aiomsg.aio->aio_cmd == AIO_ACCEPT)
      return aio_accept_message(msg->aiomsg.aio);
    else if (msg->aiomsg.aio->aio_cmd == AIO_READ)
      return aio_read_message(msg->aiomsg.aio);
  } else {
    /* File interest event */
    return fs_event_message(&msg->rfim);
  }
}


static int process_message_queue(uv__os390_epoll* ep, int nlimit) {
  int nevents;
  int msglen;
  int nmsgs;
  union {
    long int type;
    _RFIM rfim;
    struct {
      long int type;
      struct aiocb* aio;
    } aiomsg;
  } msgs[nlimit];

  nmsgs = 0;
  for (;;) {
    msglen = msgrcv(ep->msg_queue, &msgs[nmsgs], sizeof(msgs[nmsgs]), 0, IPC_NOWAIT);
    if (msglen == -1 && errno == EINTR)
      break;
    if (msglen == -1 && errno != ENOMSG)
      abort();
    if (msglen == -1 || ++nmsgs >= ARRAY_SIZE(msgs))
      break;
  }

  nevents = 0;
  for (int i = 0; i < nmsgs; ++i)
    if (message_handler(&msgs[i]) == 0)
      ++nevents;

  return nevents;
}


void uv__io_poll(uv_loop_t* loop, int timeout) {
  struct epoll_event events[128];
  union {
    long int type;
    _RFIM rfim;
    struct {
      long int type;
      struct aiocb* aio;
    } aiomsg;
  } msg;
  struct epoll_event* pe;
  struct epoll_event e;
  uv__os390_epoll* ep;
  int real_timeout;
  QUEUE aioq;
  QUEUE* q;
  uv__io_t* w;
  uint64_t base;
  int count;
  int nfds;
  int fd;
  int op;
  int i;
printf("JBAR iopoll timeout=%d\n", timeout);

  if (loop->nfds == 0) {
    assert(QUEUE_EMPTY(&loop->watcher_queue));
    return;
  }

  ep = loop->ep;
  QUEUE_INIT(&aioq);
  while (!QUEUE_EMPTY(&loop->watcher_queue)) {
    uv_stream_t* stream;

    q = QUEUE_HEAD(&loop->watcher_queue);
    QUEUE_REMOVE(q);
    QUEUE_INIT(q);
    w = QUEUE_DATA(q, uv__io_t, watcher_queue);

    assert(w->pevents != 0);
    assert(w->fd >= 0);

    stream = container_of(w, uv_stream_t, io_watcher);

    assert(w->fd < (int) loop->nwatchers);

    if (stream->type == UV_TCP) {
      /* Don't use epoll. The write and connect calls have already been
       * dispatched via BPX4AIO. Wait for them to pop up on message queue.
       */
      QUEUE_INSERT_TAIL(&aioq, &w->watcher_queue);

    } else {
      /* Register this event to be polled. */
      e.events = w->pevents;
      e.fd = w->fd;

      if (w->events == 0)
        op = UV__EPOLL_CTL_ADD;
      else
        op = UV__EPOLL_CTL_MOD;

      /* XXX Future optimization: do EPOLL_CTL_MOD lazily if we stop watching
       * events, skip the syscall and squelch the events after epoll_wait().
       */
      if (epoll_ctl(loop->ep, op, w->fd, &e)) {
        if (errno != EEXIST)
          abort();

        assert(op == UV__EPOLL_CTL_ADD);

        /* We've reactivated a file descriptor that's been watched before. */
        if (epoll_ctl(loop->ep, UV__EPOLL_CTL_MOD, w->fd, &e))
          abort();
      }
    }

    w->events = w->pevents;
  }

  assert(timeout >= -1);
  base = loop->time;
  count = 48; /* Benchmarks suggest this gives the best throughput. */
  real_timeout = timeout;
  int nevents = 0;
  int interrupted;

  nfds = 0;
  for (;;) {

    interrupted = 0;
    if (!QUEUE_EMPTY(&aioq)) {
     
      interrupted = 1;
      while (!QUEUE_EMPTY(&aioq)) {
        uv_stream_t* stream;

        q = QUEUE_HEAD(&aioq);
        QUEUE_REMOVE(q);
        QUEUE_INIT(q);
        w = QUEUE_DATA(q, uv__io_t, watcher_queue);
        stream = container_of(w, uv_stream_t, io_watcher);

        if (w->pevents & POLLOUT) {
          if (stream->connect_req != NULL) {
            if (stream->connect_req->aio.aio_cmd != AIO_CONNECT) {
              /* This is a connect event that had synchronous success. */
              stream->connect_req->aio.aio_cmd = AIO_CONNECT;
              msg.aiomsg.type = SIGIO;
              msg.aiomsg.aio = &stream->connect_req->aio;
              if (message_handler(&msg) == 0)
                ++nevents;
            }
          }

          /* This is a shutdown request waiting to be dispatched. */
          if (stream->shutdown_req != NULL && QUEUE_EMPTY(&stream->write_queue)) {
            stream->shutdown_req->aio.aio_cmd = AIO_WRITE;
            msg.aiomsg.type = SIGIO;
            msg.aiomsg.aio = &stream->shutdown_req->aio;
            if (message_handler(&msg) == 0)
              ++nevents;
          }
        }

        if (w->pevents & POLLIN) {
          /* This is a read request weaiting to be dispatched. */
          w->aio.aio_cmd = stream->flags & UV_STREAM_READING ? AIO_READ : AIO_ACCEPT;
          w->aio.aio_fildes = w->fd;
          w->aio.aio_notifytype = AIO_MSGQ;
          w->aio.aio_msgev_qid = ep->msg_queue;
          msg.aiomsg.type = SIGIO;
          msg.aiomsg.aio = &w->aio;
          if (message_handler(&msg) == 0)
            ++nevents;
        }
      }
    }

    /* We have acheived activity on indefinite timeout. Done. */
    if (timeout == -1 && nevents > 0)
      return;

    /* Drain message queue before polling. */
    nevents += process_message_queue(ep, 8192 * 4);

    /* We have acheived activity on indefinite timeout. Done. */
    if (timeout == -1 && nevents > 0)
      return;

    nfds = epoll_wait(loop->ep, events, ARRAY_SIZE(events), timeout);
    if (nfds == -1 && errno == EINTR)
      interrupted = 1;

    /* Update loop->time unconditionally. It's tempting to skip the update when
     * timeout == 0 (i.e. non-blocking poll) but there is no guarantee that the
     * operating system didn't reschedule our process while in the syscall.
     */
    uv__update_time(loop);
    if (nfds == 0) {
      assert(timeout != -1);

      /* No wait poll returned without activity. */
      if (timeout == 0)
        return;

      /* We may have been inside the system call for longer than |timeout|
       * milliseconds so we need to update the timestamp to avoid drift.
       */
      goto update_timeout;
    }

    if (nfds == -1) {

      /* Error from poll. */
      if (!interrupted)
        abort();

      /* Signal interruption during indefinite wait. */
      if (timeout == -1)
        continue;

      /* Signal interruption during no wait. */
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
      fd = pe->fd;

      /* Skip invalidated events, see uv__platform_invalidate_fd */
      if (fd == -1)
        continue;

      if (fd == ep->msg_queue) {
        nevents += process_message_queue(ep, 1024);
      } else {
        assert(fd >= 0);
        assert((unsigned) fd < loop->nwatchers);

        w = loop->watchers[fd];

        if (w == NULL) {
          /* File descriptor that we've stopped watching, disarm it.
           *
           * Ignore all errors because we may be racing with another thread
           * when the file descriptor is closed.
           */
          epoll_ctl(loop->ep, UV__EPOLL_CTL_DEL, fd, pe);
          continue;
        }

        /* Give users only events they're interested in. Prevents spurious
         * callbacks when previous callback invocation in this loop has stopped
         * the current watcher. Also, filters out events that users has not
         * requested us to watch.
         */
        pe->events &= w->pevents | POLLERR | POLLHUP;

        if (pe->events == POLLERR || pe->events == POLLHUP)
          pe->events |= w->pevents & (POLLIN | POLLOUT);

        if (pe->events != 0) {
          w->cb(loop, w, pe->events);
          nevents++;
        }
      }
    }
    loop->watchers[loop->nwatchers] = NULL;
    loop->watchers[loop->nwatchers + 1] = NULL;

    if (nevents != 0) {
      /* Too much activity. Handle more events without blocking. */
      if (nfds == ARRAY_SIZE(events) && --count != 0) {
        timeout = 0;
        continue;
      }

      /* Handled all active events. */
      return;
    }

    /* Stale events found without blocking. */
    if (timeout == 0)
      return;

    /* Stale events found while waiting indefinitely. */
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

void uv__set_process_title(const char* title) {
  /* do nothing */
}

int uv__io_fork(uv_loop_t* loop) {
  /* 
    Nullify the msg queue but don't close it because
    it is still being used by the parent.
  */
  loop->ep = NULL;

  uv__platform_loop_delete(loop);
  return uv__platform_loop_init(loop);
}


int uv__os390_connect(uv_connect_t* req, uv_stream_t* handle,
                      const struct sockaddr* addr, unsigned int addrlen) {
  struct sockaddr_storage* addr_storage;
  struct aiocb* aio_connect;
  uv__io_t* w;
  uv__os390_epoll* ep;
  int rv;
  int rc;
  int rsn;
 
  w = &handle->io_watcher;
  ep = handle->loop->ep;
  aio_connect = &req->aio;
  memset(aio_connect, 0, sizeof(*aio_connect));
  aio_connect->aio_fildes = w->fd;
  aio_connect->aio_notifytype = AIO_MSGQ;
  aio_connect->aio_cflags |= AIO_OK2COMPIMD;
  aio_connect->aio_cflags |= AIO_TCBAFFINITY;
  aio_connect->aio_cmd = AIO_CONNECT;
  aio_connect->aio_msgev_qid = ep->msg_queue;

  /* Allocate memory to hold the address information.
   * This will be freed in aio_connect_message after receiving
   * notification from message queue.
   */
  addr_storage = uv__malloc(sizeof(*addr_storage));
  if (addr_storage == NULL)
    return -1;
  memcpy(addr_storage, addr, addrlen);
  aio_connect->aio_sockaddrptr = (struct sockaddr_in*)addr_storage;
  aio_connect->aio_sockaddrlen = addrlen;

  BPX4AIO(sizeof(req->aio), &req->aio, &rv, &rc, &rsn);
printf("JBAR BPX4AIO connect rv=%d,rc=%d,rsn=%d\n", rv, rc, rsn);
  if (rv == 0) {
    errno = EINPROGRESS;
    return -1;
  } else if (rv == 1) {
    aio_connect->aio_cmd = 0;
    return 0;
  } else {
    errno = rc;
    return -1;
  }
}


int uv__os390_accept(uv_stream_t *handle) {
  uv__io_t* w;
  struct aiocb* aio_accept;
  int previous_rv;
  int rv;
  int rc;
  int rsn;

  if (handle->type != UV_TCP)
    return uv__accept(uv__stream_fd(handle));

  w = &handle->io_watcher;
  aio_accept = &w->aio;
  if (aio_accept->aio_rc == EINPROGRESS)
    return -EWOULDBLOCK;

  if (aio_accept->aio_cflags & AIO_OK2COMPIMD) {
    /* This is a notification. */
    aio_accept->aio_cflags &= ~AIO_OK2COMPIMD;
    if (aio_accept->aio_rv == -1)
      return -aio_accept->aio_rc;
    return aio_accept->aio_rv;
  }

  aio_accept->aio_cflags |= AIO_OK2COMPIMD;
  aio_accept->aio_cflags |= AIO_TCBAFFINITY;
  BPX4AIO(sizeof(*aio_accept), aio_accept, &rv, &rc, &rsn);
  if (rv == -1) {
    /* Error. */
    aio_accept->aio_cflags &= ~AIO_OK2COMPIMD;
    return -rc;
  } else if (rv == 0) {
    return -EWOULDBLOCK;
  }

  /* Synchronous call. */
  aio_accept->aio_cflags &= ~AIO_OK2COMPIMD;
  return aio_accept->aio_rv;

}


int uv__os390_read(uv_stream_t* handle, void* buf, int len) {
  uv__os390_epoll* ep;
  struct aiocb* aio_read;
  uv__io_t* w;
  int rv;
  int rc;
  int rsn;

  if (handle->type != UV_TCP)
    return read(uv__stream_fd(handle), buf, len);

  ep = handle->loop->ep;
  w = &handle->io_watcher;
  aio_read = &w->aio;
  if (aio_read->aio_rc == EINPROGRESS) {
    /* The read request is in process. */
    errno = EINPROGRESS;
    return -1;
  } else if (aio_read->aio_buf != NULL) {
    /* The notification has been received. */
    assert(buf == aio_read->aio_buf);
    assert(len == aio_read->aio_nbytes);
    aio_read->aio_buf = NULL;
    aio_read->aio_nbytes = 0;
    handle->alloc_cb = (uv_alloc_cb*)(w->stream_alloc_cb);
    w->stream_alloc_cb = NULL;
    if (aio_read->aio_rv == -1)
      errno = aio_read->aio_rc;
    return aio_read->aio_rv;
  }

  /* A new read request first needs to be dispatched. */
  aio_read->aio_buf = buf;
  aio_read->aio_nbytes = len;
  aio_read->aio_cflags |= AIO_OK2COMPIMD;
  aio_read->aio_cflags |= AIO_TCBAFFINITY;
  BPX4AIO(sizeof(*aio_read), aio_read, &rv, &rc, &rsn);
printf("JBAR BPX4AIO read fd=%d rv=%d,rc=%d,rsn=%d\n", w->fd, rv, rc, rsn);

  if (rv != 0) {
    /* Synchronous result. */
    aio_read->aio_cflags &= ~AIO_OK2COMPIMD;
    aio_read->aio_buf = NULL;
    aio_read->aio_nbytes = 0;
    if (rv == -1)
      errno = rc;
    return rv == 1 ? aio_read->aio_rv : -1;
  }

  /* Asynchronous read in progress. */
  w->stream_alloc_cb = handle->alloc_cb;
  handle->alloc_cb = uv__os390_alloc;
  errno = EINPROGRESS;
  return -1;

}


static int os390_write(int cmd, uv_write_t* req,
                       uv_stream_t* handle,
                       void* buf, int len) {
  struct aiocb* aio_write;
  uv__io_t* w;
  uv__os390_epoll* ep;
  int rv;
  int rc;
  int rsn;

  aio_write = &req->aio;
  if (aio_write->aio_cmd != 0) {
    /* This write request has already been dispatched. */
    if (aio_write->aio_rc == EINPROGRESS) {
      errno = EWOULDBLOCK;
      return -1;
    } else if (aio_write->aio_rv < 0) {
      aio_write->aio_cmd = 0;
      errno = aio_write->aio_rc;
      return -1;
    } else {
      aio_write->aio_cmd = 0;
      return aio_write->aio_rv;
    }
  }

  w = &handle->io_watcher;
  ep = handle->loop->ep;
  memset(aio_write, 0, sizeof(*aio_write));
  aio_write->aio_fildes = w->fd;
  aio_write->aio_notifytype = AIO_MSGQ;
  aio_write->aio_cflags |= AIO_OK2COMPIMD;
  aio_write->aio_cflags |= AIO_TCBAFFINITY;
  aio_write->aio_cmd = cmd;
  aio_write->aio_msgev_qid = ep->msg_queue;
  aio_write->aio_buf = buf;
  aio_write->aio_nbytes = len;

  BPX4AIO(sizeof(*aio_write), aio_write, &rv, &rc, &rsn);
printf("JBAR BPX4AIO write on fd=%d rv=%d,rc=%d,rsn=%d\n", w->fd, rv, rc, rsn);
  if (rv == -1) {
    aio_write->aio_cmd = 0;
    errno = rc;
    return -1;
  } else if (rv == 1) {
    /* Synchronous write. */
    aio_write->aio_cmd = 0;
    return aio_write->aio_rv;
  }
 
  /* Asynchronous write. Nothing written yet. */
  return 0;
}


int uv__os390_write(uv_write_t* req, uv_stream_t* handle,
                    void* buf, int len) {
  /* Zero length is not allowed using BPX4AIO. So do it synchronously. */
  if (handle->type != UV_TCP || len == 0)
    return write(handle->io_watcher.fd, buf, len);

  return os390_write(AIO_WRITE, req, handle, buf, len);
}


int uv__os390_writev(uv_write_t* req, uv_stream_t* handle,
                     const struct iovec* buf, int iovcnt) {
  if (handle->type != UV_TCP)
    return writev(handle->io_watcher.fd, buf, iovcnt);

  return os390_write(AIO_WRITEV, req, handle, (void*)buf, iovcnt);
}
