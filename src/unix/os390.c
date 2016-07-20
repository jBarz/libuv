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

#define CVT_PTR           0x10

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
int uv_exepath(char* buffer, size_t* size) {
  size_t len;

  if (buffer == NULL || size == NULL || *size == 0)
    return -EINVAL;

  char *exe_path=__getenv("EXE_PATH");
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
  if (size > 0)
    buffer[0] = '\0';
  return 0;
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

