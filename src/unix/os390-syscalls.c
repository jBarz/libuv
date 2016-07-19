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
#include <string.h>
#include <stdlib.h>

int alphasort(const void *a, const void *b) {

  return strcoll( (*(const struct dirent **)a)->d_name, 
                  (*(const struct dirent **)b)->d_name );
}

int scandir(const char *dirp, struct dirent ***namelist,
            int (*filter)(const struct dirent *),
            int (*compar)(const struct dirent **, const struct dirent **)) {
  struct dirent **nl = NULL, **next_nl;
  struct dirent *dirent;
  size_t count = 0;
  size_t allocated = 0;
  DIR *dir;

  dir = opendir(dirp);
  if (!dir)
    return -1;

  while (1) {
    dirent = readdir(dir);
    if (!dirent)
      break;
    if (!filter || filter(dirent)) {
      struct dirent *copy;
      copy = malloc(sizeof(*copy));
      if (!copy)
        goto cleanup_fail;
      memcpy(copy, dirent, sizeof(*copy));

      if (count == allocated) {
        if (allocated == 0)
          allocated = 15;
        else
          allocated *= 2;
        next_nl = realloc(nl, allocated);
        if (!next_nl) {
          free(copy);
          goto cleanup_fail;
        }
        nl = next_nl;
      }

      nl[count++] = copy;
    }
  }

  qsort(nl, count, sizeof(struct dirent *),
      (int (*)(const void *, const void *))compar);

  closedir(dir);

  *namelist = nl;
  return count;

cleanup_fail:
  while (count) {
    dirent = nl[--count];
    free(dirent);
  }
  free(nl);
  closedir(dir);
  errno = ENOMEM;
  return -1;
}

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
