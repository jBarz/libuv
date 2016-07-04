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


#include "uv.h"
#include "internal.h"
#include "os390-syscalls.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <unistd.h>
#include <fcntl.h>
#include <libgen.h>
#include <sys/ps.h>
#include <utmpx.h>
#include <poll.h>
#include <ctype.h>
#include <limits.h>
#include <strings.h>
#include <xti.h>

#include "//'SYS1.SAMPLIB(CSRSIC)'"

#define RDWR_BUF_SIZE   4096
#define EQ(a,b)         (strcmp(a,b) == 0)


#define CVT_PTR         0x10
#define CVTEXT2_OFFSET  0x148
#define CVTLDTO_OFFSET  0x38
static int MAX_JOBS =   1024;
#define ASCB_OFFSET     0x234
#define EPOCH_CONVERTER 2208988800ll                   /* MVS TOD is in 1/4096 usecs since 1900. UTC is since 1970. This is the conversion number in seconds */

#define PROC_STR_OFFSET   0xAC
#define INIT_STR_OFFSET   0xB0
#define ASCBEJST_OFFSET   0x40
#define ASCBEATT_OFFSET   0x128
#define ASCBSRBT_OFFSET   0xC8
#define NEXT_ASCB_OFFSET  0x04
#define CPU_COUNT_OFFSET  0x0A
#define MEMORY_OFFSET     0x358

#define ASCBASSB_OFFSET   0x150       /* POINTER TO ADDRESS SPACE SECONDARY BLOCK */
#define ASSBASST_OFFSET   0x160       /* Additional SRB Service Time. CPU time is accumulated here for this address space's Preemptable SRBs and for Client Related SRBs for which this address space is the client. Format: TOD Clock */

#define CVTASMVT_OFFSET   0x2C0
#define ASMSLOTS_OFFSET   0x70        /* Count of total local slots in all open local page data sets: signed int on 4 */
#define ASMVSC_OFFSET     0x74        /* Count of total local slots allocated to VIO private area pages: signed int on 4 bytes */
#define ASMNVSC_OFFSET    0x78        /* Count of total local slots allocated to non-VIO private area pages: signed int on 4 bytes */
#define ASMERRS_OFFSET    0x7C        /* Count of bad slots found on local data sets during normal operations */
#define ASCMTCBPT_OFFSET  0xA4        /* Address of ASM TCB */
#define ASMTASCB_OFFSET   0xB4        /* Address of ASCB for address space in which ILRTMRLG is running */
#define ASMLSYSI_OFFSET   0x490       /* System token for last dataset that protection was bypassed for during IPL */

#define CVTRCEP_OFFSET    0x490       /* "V(IARMRRCE)" - ADDRESS OF THE RSM CONTROL AND ENUMERATION AREA. */
#define RCEPOOL_OFFSET    0x4         /* NUMBER OF FRAMES CURRENTLY AVAILABLE TO SYSTEM. EXCLUDED ARE FRAMES BACKING PERM STORAGE, FRAMES OFFLINE, AND BAD FRAMES */
#define RCEBELPL_OFFSET   0x8         /* THE SAME AS RCEPOOL EXCEPT THAT ONLY FRAMES BELOW 16M REAL ARE COUNTED. */
#define RCETOTPI_OFFSET   0x44        /* TOTAL NUMBER OF PAGES PAGED-IN EXCLUDING SWAP-IN, VIO, AND HIPERSPACE PAGE-INS. */
#define RCEVIOPI_OFFSET   0x54        /* TOTAL NUMBER OF VIO PAGES PAGED-IN EXCLUDING SWAP-IN. */
#define RCETOTPO_OFFSET   0x58        /* TOTAL NUMBER OF PAGES PAGED-OUT EXCLUDING SWAP-OUT, VIO PAGE-OUT, VIO MOVEOUT, AND HIPERSPACE PAGES */
#define RCEVIOPO_OFFSET   0x64        /* TOTAL NUMBER OF VIO PAGES (EXCLUDES SWAP-OUT) MOVED-OUT OR PAGED-OUT. */
#define RCEAFC_OFFSET     0x88        /* TOTAL NUMBER OF FRAMES CURRENTLY ON ALL AVAILABLE FRAME QUEUES. */
#define RCEHSPRW_OFFSET   0x1FC       /* TOTAL NUMBER OF HIPERSPACE PAGES WRITTEN TO REAL STORAGE */


#define CSD_OFFSET                    0x294
#define CSD_CPU_ALIVE                 0x18        /* CPU alive data on double word boundary for compare and swap */
#define CSD_CPUS_MANIPULATED_BY_WLM   0x28        /* CSD_CPUS_MANIPULATED_BY_WLM */
#define CSD_NUMBER_ONLINE_CPUS        0xD4        /* 32-bit count of alive CPUs. This includes both CPs and IFAs */
#define CSD_NUMBER_ONLINE_IFAS        0x104       /* IFAs online */
#define CVTOSLV3_OFFSET               0x4F3       /* Indicates the presence of some hardware functions */
#define CVTLPARC_MASK                 0x20        /* Mask for finding out whether the machine is part of an LPAR cluster or not */


#define CVTOPCTP_OFFSET   0x25C       /* ADDRESS OF SYSTEM RESOURCES MANAGER (SRM) CONTROL TABLE */
#define RMCTRCT_OFFSET    0xE4        /* Address of the RCT table */
#define RCVAFQA_OFFSET    0x3C        /* Available frame average */
#define RCVFXIOP_OFFSET   0x80        /* AVG % OF TOTAL FRAMES THAT ARE FIXED OR IN I/O */
#define RCVAFQC_OFFSET    0x54        /* Available frame accumulator */
#define RCVCTMC_OFFSET    0x34        /* Sample intervals count */
#define RCVCPUA_OFFSET    0x38        /* CPU USAGE AVERAGE */
#define RCVCPUAA_OFFSET   0x40        /* CP+IFA usage average */
#define RCVCPUAC_OFFSET   0x44        /* RCVCPUAC CP+IFA usage accumulator */
#define RCVCPUC_OFFSET    0x4C        /* CPU USAGE ACCUMULATOR */

#define RCVSRBS_OFFSET    0xB8        /* Accumulated Workload Management SRB Service for entire system. It is accumulated by WM1 and reset and used by RM3 */
#define RCVTCBS_OFFSET    0xBC        /* Accumulated Workload Management TCB Service for entire system. It is accumulated by WM1 and reset and used by RM3 */
#define RCTLACS_OFFSET    0xC4        /* Long-term average CPU service used by this logical partition, in millions of service units per hour. If this value is above the partition's defined capacity, the partition will be capped. It is calculated using the physical CPU adjustment factor (RCTPCPUA) so it may not match other measures of service which are based on the logical CPU adjustment factor. It is available if the hardware supports LPAR cluster */
#define RCTPCPUA_OFFSET   0xD4        /* Physical CPU adjustment factor (i.e. adjustment factor for converting CPU time to equivalent service in basic-mode with all processors online). */

typedef unsigned DATA_AREA_PTR_ASSIGN_TYPE;

typedef union _DATA_AREA_PTR {
  struct {
#if defined(_LP64)
    DATA_AREA_PTR_ASSIGN_TYPE lower;
#endif
    DATA_AREA_PTR_ASSIGN_TYPE assign;
  };
  char* deref;
} DATA_AREA_PTR; 

typedef struct _SystemProcessorInfo {
  unsigned long int mask_cpu_alive;               /* CSD_CPU_ALIVE */
  unsigned long int mask_cpu_wlm;                 /* CSD_CPUS_MANIPULATED_BY_WLM */
  int               online_cpus;                  /* CSD_NUMBER_ONLINE_CPUS */
  int               online_ifas;                  /* CSD_NUMBER_ONLINE_IFAS */
  int               lpar_clustering;              /* TRUE IF LPAR CLUSTERING IS PRESENT. FALSE OTHERWISE */

  short int         sample_intervals_count;       /* RCVCTMC_OFFSET */
  short int         frame_average;                /* RCVAFQA_OFFSET */
  int               frame_accumulator;            /* RCVAFQC_OFFSET */
  short int         io_fixed_percentage;          /* RCVFXIOP_OFFSET */
  short int         cpu_usage_average;            /* RCVCPUA_OFFSET */
  short int         cpu_ifa_usage_average;        /* RCVCPUAA_OFFSET */
  int               cpu_usage_accumulator;        /* RCVCPUC_OFFSET */
  int               cpu_ifa_usage_accumulator;    /* RCVCPUAC_OFFSET */

  int               srb_service;                  /* RCVSRBS_OFFSET */
  int               tcb_service;                  /* RCVTCBS_OFFSET */
  int               lpar_service;                 /* RCTLACS_OFFSET */
  double            lpar_capacity;                /* calculated     */
  int               phy_cpu_factor;               /* RCTPCPUA_OFFSET */
  double            utilization;                  /* calculated     */


} SystemProcessorInfo;

void getSystemProcessorInfo(SystemProcessorInfo *result, DATA_AREA_PTR cvt) {
  char status_word;
  DATA_AREA_PTR csd = {0}, rmctrct = {0}, cvtopctp = {0};
  csd.assign 			= *((DATA_AREA_PTR_ASSIGN_TYPE *) (cvt.deref + CSD_OFFSET));
  cvtopctp.assign 		= *((DATA_AREA_PTR_ASSIGN_TYPE *) (cvt.deref + CVTOPCTP_OFFSET));
  rmctrct.assign 			= *((DATA_AREA_PTR_ASSIGN_TYPE *) (cvtopctp.deref + RMCTRCT_OFFSET));

  result->online_cpus    		= *((int*) (csd.deref + CSD_NUMBER_ONLINE_CPUS));
  result->cpu_usage_average       = *((unsigned short int*) (rmctrct.deref + RCTLACS_OFFSET));
#if 0
  result->mask_cpu_alive = *((int*) (ptr + CSD_CPU_ALIVE));
  result->mask_cpu_wlm   = *((int*) (ptr + CSD_CPUS_MANIPULATED_BY_WLM));
  result->online_ifas    = *((int*) (ptr + CSD_NUMBER_ONLINE_IFAS));

  status_word = *((char*) (cvt + CVTOSLV3_OFFSET));
  if (status_word & CVTLPARC_MASK) result->lpar_clustering = 1;
  else result->lpar_clustering = 0;

  ptr = *((char **) (cvt + CVTOPCTP_OFFSET));
  ptr = *((char **) (ptr + RMCTRCT_OFFSET));
  result->sample_intervals_count           = *((unsigned short int*) (ptr + RCVCTMC_OFFSET));
  result->cpu_ifa_usage_average           = *((unsigned short int*) (ptr + RCVCPUAA_OFFSET));
  result->cpu_usage_accumulator           = *((int*) (ptr + RCVCPUC_OFFSET));
  result->cpu_ifa_usage_accumulator       = *((int*) (ptr + RCVCPUAC_OFFSET));

  result->frame_average                   = *((unsigned short int*) (ptr + RCVAFQA_OFFSET));
  result->frame_accumulator               = *((int*) (ptr + RCVAFQC_OFFSET));
  result->io_fixed_percentage             = *((unsigned short int*) (ptr + RCVFXIOP_OFFSET));

  result->srb_service                     = *((int*) (ptr + RCVSRBS_OFFSET));
  result->tcb_service                     = *((int*) (ptr + RCVTCBS_OFFSET));
  result->lpar_service                    = *((int*) (ptr + RCTLACS_OFFSET));
  result->phy_cpu_factor                  = *((int*) (ptr + RCTPCPUA_OFFSET));

  result->lpar_capacity                   = 16000000/result->phy_cpu_factor;
  result->lpar_capacity                   = result->lpar_capacity*(result->online_cpus + result->online_ifas);
  result->lpar_capacity                   = result->lpar_capacity*3600.0/1000000.0;
  result->utilization                     = (result->lpar_service/result->lpar_capacity)*100;
#endif
}

static int getIndividualCapabilities(char * buffer, int proc_nr) {
  int i;
  unsigned short int cap;
  buffer += 2*proc_nr;
  memcpy(&cap,buffer,2);
  return cap;
}


static int getZOSCPUCapability(si22v1 *result, int cpu_nr) {
  int si22v1cpucapability;
  int individual_cpucapability;
  memcpy(&(si22v1cpucapability),result->si22v1cpucapability,4);

  individual_cpucapability =  getIndividualCapabilities((char *)&(result->si22v1mpcpucapafs),cpu_nr);

  return (si22v1cpucapability + individual_cpucapability);
}


static int invokesiv1v2(siv1v2 *info) {

  int ret_code;
  int request = CSRSI_REQUEST_V2CPC_LPAR | CSRSI_REQUEST_V1CPC_MACHINE;
  memset(info,'\x0',sizeof(info));

  CSRSI(request,
      0x1040,
      info,
      &ret_code);

  if (ret_code == CSRSI_BADINFOAREALEN)
  {
    memset(info,'\x0',sizeof(*info));
    CSRSI(request,
        0x2040,
        info,
        &ret_code);
  }

  if (ret_code == CSRSI_BADINFOAREALEN)
  {
    memset(info,'\x0',sizeof(*info));
    CSRSI(request,
        0x3040,
        info,
        &ret_code);
  }

  if (ret_code == CSRSI_BADINFOAREALEN)
  {
    memset(info,'\x0',sizeof(*info));
    CSRSI(request,
        0x4040,
        info,
        &ret_code);
  }


  if (ret_code != CSRSI_SUCCESS)
  {
    memset(info,'\x0',sizeof(*info));
    return 0;
  }

  return 1;

}

int uv__platform_loop_init(uv_loop_t* loop) {
  int fd;

  fd = uv__epoll_create1(UV__EPOLL_CLOEXEC);

  if (fd == -1 && (errno == ENOSYS || errno == EINVAL)) {
    fd = uv__epoll_create(256);

    if (fd != -1)
      uv__cloexec(fd, 1);
  }

  loop->backend_fd = fd;

  if (fd == -1)
    return -errno;

  loop->msgqid = msgget( IPC_PRIVATE, IPC_CREAT + S_IRUSR + S_IWUSR );

  if (loop->msgqid == -1)
    return -errno;

  int events = POLLIN;	
  uv__epoll_ctl(loop->backend_fd, UV__EPOLL_CTL_ADD_MSGQ, loop->msgqid, &events);

  return 0;
}



void uv__platform_loop_delete(uv_loop_t* loop) {

  if (loop->msgqid > 0) {
    msgctl(loop->msgqid, IPC_RMID, NULL);
    uv__epoll_ctl(loop->backend_fd, UV__EPOLL_CTL_DEL, loop->msgqid, NULL);
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


/*
 * We could use a static buffer for the path manipulations that we need outside
 * of the function, but this function could be called by multiple consumers and
 * we don't want to potentially create a race condition in the use of snprintf.
 * There is no direct way of getting the exe path in AIX - either through /procfs
 * or through some libc APIs. The below approach is to parse the argv[0]'s pattern
 * and use it in conjunction with PATH environment variable to craft one.
 */
int uv_exepath(char* buffer, size_t* size) {
  int res;
  char args[PATH_MAX];
  char abspath[PATH_MAX];
  size_t abspath_size;

  if (buffer == NULL || size == NULL || *size == 0)
    return -EINVAL;

  char *exe_path=__getenv("EXE_PATH");
  if (exe_path == NULL) 
    return -EINVAL;
  strncpy(args,  exe_path, PATH_MAX-1);

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
      return -errno;

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
    char *clonedpath = NULL;
    char *token = NULL;
    char *path = getenv("PATH");

    if (path == NULL)
      return -EINVAL;

    clonedpath = uv__strdup(path);
    if (clonedpath == NULL)
      return -ENOMEM;

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
    return -EINVAL;
  }
}


uint64_t uv_get_free_memory(void) {
  DATA_AREA_PTR cvt = {0};
  DATA_AREA_PTR rcep = {0};
  cvt.assign = *(DATA_AREA_PTR_ASSIGN_TYPE*)(CVT_PTR);
  rcep.assign = *(DATA_AREA_PTR_ASSIGN_TYPE*)(cvt.deref + CVTRCEP_OFFSET);
  uint64_t freeram = *((uint64_t*)(rcep.deref + RCEAFC_OFFSET)) * 4;
  return freeram;
}


uint64_t uv_get_total_memory(void) {
  DATA_AREA_PTR cvt = {0};
  DATA_AREA_PTR rcep = {0};
  cvt.assign = *(DATA_AREA_PTR_ASSIGN_TYPE*)(CVT_PTR);
  rcep.assign = *(DATA_AREA_PTR_ASSIGN_TYPE*)(cvt.deref + CVTRCEP_OFFSET);
  uint64_t totalram = *((uint64_t*)(rcep.deref + RCEPOOL_OFFSET)) * 4;
  return totalram;
}


void uv_loadavg(double avg[3]) {
  avg[0] = 0;
  avg[1] = 0;
  avg[2] = 0;
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


void uv__fs_event_close(uv_fs_event_t* handle) {
  UNREACHABLE();
}


char** uv_setup_args(int argc, char** argv) {
  return argv;
}


int uv_set_process_title(const char* title) {
  return 0;
}


int uv_get_process_title(char* buffer, size_t size) {
  if (size > 0) {
    buffer[0] = '\0';
  }
  return 0;
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
  u.ut_type = BOOT_TIME;
  struct utmpx *v;
  v = getutxid(&u);
  if (v==NULL)
    return -1;
  time64_t t;
  *uptime = difftime64( time64(&t), v->ut_tv.tv_sec);
  return 0;
}


int uv_cpu_info(uv_cpu_info_t** cpu_infos, int* count) {
  uv_cpu_info_t* cpu_info;
  int result, ncpus, idx = 0;


  siv1v2 info;
  DATA_AREA_PTR cvt = {0};
  cvt.assign = *(DATA_AREA_PTR_ASSIGN_TYPE*)(CVT_PTR);
  SystemProcessorInfo zos_proc;
  getSystemProcessorInfo(&zos_proc, cvt);
#ifndef _LP64
  if (!invokesiv1v2(&info))
    return -ENOSYS;
#endif

  *count = ncpus = zos_proc.online_cpus;

  *cpu_infos = (uv_cpu_info_t*) uv__malloc(ncpus * sizeof(uv_cpu_info_t));
  if (!*cpu_infos) {
    return -ENOMEM;
  }


  cpu_info = *cpu_infos;
  while (idx < ncpus) {

    cpu_info->speed = *(int*)(info.siv1v2si22v1.si22v1cpucapability);
    cpu_info->model = malloc(17);
    memset(cpu_info->model, '\0', 17);
    memcpy(cpu_info->model, info.siv1v2si11v1.si11v1cpcmodel, 16);
    cpu_info->cpu_times.user = zos_proc.cpu_usage_average;
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
  struct uv__epoll_event* events;
  struct uv__epoll_event dummy;
  uintptr_t i;
  uintptr_t nfds;

  assert(loop->watchers != NULL);

  events = (struct uv__epoll_event*) loop->watchers[loop->nwatchers];
  nfds = (uintptr_t) loop->watchers[loop->nwatchers + 1];
  if (events != NULL)
    /* Invalidate events with same file descriptor */
    for (i = 0; i < nfds; i++)
      if ((int) events[i].data == fd)
        events[i].data = -1;

  /* Remove the file descriptor from the epoll.
   * This avoids a problem where the same file description remains open
   * in another process, causing repeated junk epoll events.
   *
   * We pass in a dummy epoll_event, to work around a bug in old kernels.
   */
  if (loop->backend_fd >= 0) {
    uv__epoll_ctl(loop->backend_fd, UV__EPOLL_CTL_DEL, fd, &dummy);
  }
}

int uv__io_check_fd(uv_loop_t* loop, int fd) {

  struct pollfd p[1];
  p[0].fd = fd;
  p[0].events = 0 | POLLIN;

  if (poll(p, 1, 0) == -1)
    abort();

  if (p[0].revents & POLLNVAL)
    return -1;

  return 0;
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


      if (stream->flags & UV_STREAM_READ_EOF || stream->aio_read.aio_rc == ECANCELED)
        flags = POLLHUP;	// we have already read eof. So hangup */ 
      else
        flags = POLLIN;

      if(!(stream->flags & UV_CLOSING))
        watcher->cb(loop, watcher, flags);

      memset(&stream->aio_read, 0, sizeof(struct aiocb));
#if 0
      if(QUEUE_EMPTY(&stream->write_queue) && stream->shutdown_req)
        uv__io_feed(loop, watcher);
#endif

      if((stream->flags & UV_STREAM_READ_PARTIAL) && !(stream->flags & UV_CLOSING)) {
        uv__io_stop(loop, watcher, POLLIN);
        uv__io_start(loop, watcher, POLLIN);

      }

      continue;
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

      if(!(stream->flags & UV_CLOSING))
        watcher->cb(loop, watcher, flags);

      if(stream->accepted_fd != -1)
        memset(&stream->aio_read, 0, sizeof(struct aiocb));
      continue;
    }
    else if(msgin[i].mm_type == AIO_MSG_WRITE)
    {
      int flags=0;
      uv_write_t *req = (uv_write_t*)msgin[i].mm_ptr;
      uv__io_t *watcher = &req->handle->io_watcher;
      int fd = req->aio_write.aio_fildes;


      //printf("JBAR AIO_MSG_WRITE fd=%d\n", uv__stream_fd(req->handle));
      if (req->handle->flags & UV_CLOSING ||  req->aio_write.aio_rc == ECANCELED)
        continue;
      
      if ((req->handle->flags & UV_CLOSING) && !(uv__io_active(&req->handle->io_watcher, POLLIN)))
        flags = POLLHUP;
      else
        flags = POLLOUT;


      watcher->cb(loop, watcher, flags);
      memset(&req->aio_write, 0, sizeof(struct aiocb));
      continue;
    }
    else if(msgin[i].mm_type == AIO_MSG_CONNECT)
    {
      int flags=0;
      uv_connect_t *req = (uv_connect_t*)msgin[i].mm_ptr;
      uv__io_t *watcher = &req->handle->io_watcher;
      int fd = req->aio_connect.aio_fildes;

      if ((req->handle->flags & UV_CLOSING) && !(uv__io_active(&req->handle->io_watcher, POLLIN)))
        flags = POLLHUP;
      else
        flags = POLLOUT;

      if (req->handle->flags & UV_CLOSING)
        continue;

      watcher->cb(loop, watcher, flags);
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
  struct uv__epoll_event events[1024];
  struct uv__epoll_event* pe;
  struct uv__epoll_event e;
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
    if(stream->type == UV_TCP) {

      if((w->pevents & POLLIN) && !(stream->flags & UV_STREAM_READING) && stream->aio_read.aio_fildes == 0) {
        if(uv__asyncio_zos_accept(stream) != 0)
          timeout = 0;
      }

      if((w->pevents & POLLIN) && (stream->flags & UV_STREAM_READING) && stream->aio_read.aio_fildes == 0) {
        stream->aio_read.aio_fildes = uv__stream_fd(stream);
        stream->aio_read.aio_notifytype = AIO_MSGQ;
        stream->aio_read.aio_cmd = AIO_READ;
        stream->aio_read.aio_msgev_qid = stream->loop->msgqid;
        stream->aio_read_msg.mm_type = AIO_MSG_READ;
        stream->aio_read_msg.mm_ptr = &stream->io_watcher;
        stream->aio_read.aio_msgev_addr = &stream->aio_read_msg;
        stream->aio_read.aio_msgev_size = sizeof(stream->aio_read_msg.mm_ptr);
        if(stream->flags & UV_STREAM_READ_PARTIAL) {
          uv_buf_t buf;
          stream->alloc_cb((uv_handle_t*)stream, 64 * 1024, &buf);
          stream->aio_read.aio_buf = buf.base;
          stream->aio_read.aio_offset = 0;
          stream->aio_read.aio_nbytes = buf.len;
        }
        else {
          stream->aio_read.aio_buf = stream->bufsml;
          stream->aio_read.aio_offset = 0;
          stream->aio_read.aio_nbytes = sizeof(stream->bufsml);
        }

        int rv, rc, rsn;
        ZASYNC(sizeof(stream->aio_read), &stream->aio_read, &rv, &rc, &rsn);
        if (rv == -1) {
          stream->aio_read.aio_rv = rv;
          stream->aio_read.aio_rc = rc;
          w->cb(loop, w, POLLHUP);
          timeout = 0;
        }
      }

      if((w->pevents & POLLOUT) && !stream->connect_req) {
        if(uv__asyncio_zos_write(stream) != 0)
          timeout = 0;
      }
    }
    else {

      assert(w->fd < (int) loop->nwatchers);

      e.events = w->pevents;
      e.data = w->fd;

      if (w->events == 0)
        op = UV__EPOLL_CTL_ADD;
      else
        op = UV__EPOLL_CTL_MOD;

      /* XXX Future optimization: do EPOLL_CTL_MOD lazily if we stop watching
       * events, skip the syscall and squelch the events after epoll_wait().
       */
      if (uv__epoll_ctl(loop->backend_fd, op, w->fd, &e)) {
        if (errno != EEXIST)
          abort();

        assert(op == UV__EPOLL_CTL_ADD);

        /* We've reactivated a file descriptor that's been watched before. */
        if (uv__epoll_ctl(loop->backend_fd, UV__EPOLL_CTL_MOD, w->fd, &e))
          abort();
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

    nfds = uv__epoll_wait(loop->backend_fd,
        events,
        ARRAY_SIZE(events),
        timeout);

    /* Update loop->time unconditionally. It's tempting to skip the update when
     * timeout == 0 (i.e. non-blocking poll) but there is no guarantee that the
     * operating system didn't reschedule our process while in the syscall.
     */
#ifdef __MVS__
    base = loop->time;
#endif
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
      fd = pe->data;

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
        uv__epoll_ctl(loop->backend_fd, UV__EPOLL_CTL_DEL, fd, pe);
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

int uv__asyncio_zos_write(uv_stream_t *stream) {
  uv_write_t *req = NULL;
  if(!QUEUE_EMPTY(&stream->write_queue)) {
    QUEUE* q = QUEUE_HEAD(&stream->write_queue);
    req = QUEUE_DATA(q, uv_write_t, queue);
    if(req->aio_write.aio_fildes != 0)
      req = NULL;
  }
  else if(stream->flags & UV_STREAM_SHUTTING) {
    uv__io_feed(stream->loop, &stream->io_watcher);
    return -1;
  }

  if(!req)
    return 0;

  int iovmax, iovcnt;
  iovmax = uv__getiovmax();

  /* Limit iov count to avoid EINVALs from writev() */
  if (iovcnt > iovmax)
    iovcnt = iovmax;

  uv_buf_t* buf = &(req->bufs[req->write_index]);
  req->aio_write.aio_fildes = uv__stream_fd(stream);
  req->aio_write.aio_notifytype = AIO_MSGQ;
  req->aio_write.aio_cflags |= AIO_OK2COMPIMD; 
  req->aio_write_msg.mm_type = AIO_MSG_WRITE;
  req->aio_write_msg.mm_ptr = req;
  req->aio_write.aio_msgev_addr = &req->aio_write_msg;
  req->aio_write.aio_msgev_size = sizeof(req->aio_write_msg.mm_ptr);
  if(req->nbufs > 1) {
    /* vector */
    req->aio_write.aio_cmd = AIO_WRITEV;
    req->aio_write.aio_buf = &(req->bufs[req->write_index]);
    iovcnt = req->nbufs - req->write_index;
    if (iovcnt > iovmax)
      iovcnt = iovmax;
    req->aio_write.aio_nbytes = iovcnt;
  } else {
    req->aio_write.aio_cmd = AIO_WRITE;
    req->aio_write.aio_buf = buf->base;
    req->aio_write.aio_nbytes = buf->len;
  }
  req->aio_write.aio_msgev_qid = stream->loop->msgqid;

  if(req->aio_write.aio_nbytes == 0) 
    return 1;

  int rv, rc, rsn;
  ZASYNC(sizeof(req->aio_write), &req->aio_write, &rv, &rc, &rsn);
  if(rv == 0)                                                   
   /* Asynchronous write */                                    
    uv__io_start(stream->loop, &stream->io_watcher, POLLOUT);
  else if(rv == -1) {                                           
   req->aio_write.aio_rv = rv;                                 
   req->aio_write.aio_rc = rc;                                 
  }                                                             
  else {                                                        
   /* Synchronous write or failure */                          
   //uv__write(stream);                                          
    uv__io_feed(stream->loop, &stream->io_watcher);             
  }                                                             


#if 0
  if (rv == -1) {
    req->aio_write.aio_rv = rv;
    req->aio_write.aio_rc = rc;
    stream->io_watcher.cb(stream->loop, &stream->io_watcher, POLLHUP);
  }
  else if(rv == 0)
    uv__io_start(stream->loop, &stream->io_watcher, POLLOUT);
  else if(rv == 1) 
    //if(uv__io_active(&stream->io_watcher, POLLOUT))
      //stream->io_watcher.cb(stream->loop, &stream->io_watcher, POLLOUT);
      uv__io_feed(stream->loop, &stream->io_watcher);
#endif

  return rv;
}

int uv__asyncio_zos_accept(uv_stream_t *stream) {
  stream->aio_read.aio_fildes = stream->io_watcher.fd;
  stream->aio_read.aio_notifytype = AIO_MSGQ;
  stream->aio_read.aio_cmd = AIO_ACCEPT;
  stream->aio_read.aio_msgev_qid = stream->loop->msgqid;
  stream->aio_read_msg.mm_type = AIO_MSG_ACCEPT;
  stream->aio_read_msg.mm_ptr = &stream->io_watcher;

  stream->aio_read.aio_msgev_addr = &stream->aio_read_msg;
  stream->aio_read.aio_msgev_size = sizeof(stream->aio_read_msg.mm_ptr);
  int rv, rc, rsn;
  ZASYNC(sizeof(struct aiocb), &stream->aio_read, &rv, &rc, &rsn);
  if(rv == -1) {                                           
   stream->aio_read.aio_rv = rv;                                 
   stream->aio_read.aio_rc = rc;                                 
  }

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
