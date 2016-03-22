Binary file ./.git/objects/pack/pack-1f36de567c2181cdc25dfde188f6004000a9621a.pack matches
./ChangeLog:* win: include "malloc.h" (Cheng Zhao)
./ChangeLog:* win: remove unnecessary malloc.h
./docs/src/migration_010_100.rst:    uv_loop_t* loop = malloc(sizeof *loop);
./docs/src/migration_010_100.rst:        return uv_buf_init(malloc(size), size);
./docs/src/migration_010_100.rst:        buf->base = malloc(size);
./docs/src/misc.rst:.. c:type:: void* (*uv_malloc_func)(size_t size)
./docs/src/misc.rst:        Replacement function for :man:`malloc(3)`.
./docs/src/misc.rst:.. c:function:: int uv_replace_allocator(uv_malloc_func malloc_func, uv_realloc_func realloc_func, uv_calloc_func calloc_func, uv_free_func free_func)
./docs/src/misc.rst:    Override the use of the standard library's :man:`malloc(3)`,
./include/uv.h:typedef void* (*uv_malloc_func)(size_t size);
./include/uv.h:UV_EXTERN int uv_replace_allocator(uv_malloc_func malloc_func,
./m4/libuv-check-flags.m4:    [malloc], ,
./m4/libuv-check-flags.m4:    [void * __attribute__((malloc)) my_alloc(int n);],
./samples/socks5-proxy/defs.h:void *xmalloc(size_t size);
./samples/socks5-proxy/server.c:      xmalloc((ipv4_naddrs + ipv6_naddrs) * sizeof(state->servers[0]));
./samples/socks5-proxy/server.c:  cx = xmalloc(sizeof(*cx));
./samples/socks5-proxy/util.c:void *xmalloc(size_t size) {
./samples/socks5-proxy/util.c:  ptr = malloc(size);
./src/threadpool.c:    threads = uv__malloc(nthreads * sizeof(threads[0]));
./src/unix/aix.c:  p = uv__malloc(siz);
./src/unix/aix.c:    p = uv__malloc(siz);
./src/unix/aix.c:  ps_cpus = (perfstat_cpu_t*) uv__malloc(ncpus * sizeof(perfstat_cpu_t));
./src/unix/aix.c:  *cpu_infos = (uv_cpu_info_t*) uv__malloc(ncpus * sizeof(uv_cpu_info_t));
./src/unix/aix.c:  ifc.ifc_req = (struct ifreq*)uv__malloc(size);
./src/unix/aix.c:    uv__malloc(*count * sizeof(uv_interface_address_t));
./src/unix/android-ifaddrs.c:        l_buffer = uv__malloc(l_size);
./src/unix/android-ifaddrs.c:    NetlinkList *l_item = uv__malloc(sizeof(NetlinkList));
./src/unix/android-ifaddrs.c:    l_entry = uv__malloc(sizeof(struct ifaddrs) + sizeof(int) + l_nameSize + l_addrSize + l_dataSize);
./src/unix/android-ifaddrs.c:    l_entry = uv__malloc(sizeof(struct ifaddrs) + l_nameSize + l_addrSize);
./src/unix/core.c:    buf = uv__malloc(bufsize);
./src/unix/darwin.c:  *cpu_infos = uv__malloc(numcpus * sizeof(**cpu_infos));
./src/unix/darwin.c:  *addresses = uv__malloc(*count * sizeof(**addresses));
./src/unix/freebsd.c:  *cpu_infos = uv__malloc(numcpus * sizeof(**cpu_infos));
./src/unix/freebsd.c:  cp_times = uv__malloc(size);
./src/unix/freebsd.c:  *addresses = uv__malloc(*count * sizeof(**addresses));
./src/unix/fs.c:      req->path = uv__malloc(path_len + new_path_len);                        \
./src/unix/fs.c:            copy = malloc(sizeof(*copy));
./src/unix/fs.c:  buf = uv__malloc(len + 1);
./src/unix/fs.c:    req->bufs = uv__malloc(nbufs * sizeof(*bufs));
./src/unix/fs.c:    req->bufs = uv__malloc(nbufs * sizeof(*bufs));
./src/unix/fsevents.c:      event = uv__malloc(sizeof(*event) + len);
./src/unix/fsevents.c:    paths = uv__malloc(sizeof(*paths) * path_count);
./src/unix/fsevents.c:  item = uv__malloc(sizeof(*item));
./src/unix/fsevents.c:  handle->cf_cb = uv__malloc(sizeof(*handle->cf_cb));
./src/unix/fsevents.c:    goto fail_cf_cb_malloc;
./src/unix/fsevents.c:fail_cf_cb_malloc:
./src/unix/getaddrinfo.c:  buf = uv__malloc(hostname_len + service_len + hints_len);
./src/unix/linux-core.c:  *addresses = uv__malloc(*count * sizeof(**addresses));
./src/unix/linux-inotify.c:  w = uv__malloc(sizeof(*w) + strlen(path) + 1);
./src/unix/netbsd.c:  cp_times = uv__malloc(size);
./src/unix/netbsd.c:  *cpu_infos = uv__malloc(numcpus * sizeof(**cpu_infos));
./src/unix/netbsd.c:  *addresses = uv__malloc(*count * sizeof(**addresses));
./src/unix/openbsd.c:  *cpu_infos = uv__malloc(numcpus * sizeof(**cpu_infos));
./src/unix/openbsd.c:  *addresses = uv__malloc(*count * sizeof(**addresses));
./src/unix/process.c:  pipes = uv__malloc(stdio_count * sizeof(*pipes));
./src/unix/proctitle.c:  new_argv = uv__malloc(size);
./src/unix/stream.c:   * NOTE: do it ahead of malloc below to allocate enough space for fd_sets
./src/unix/stream.c:  s = uv__malloc(sizeof(*s) + sread_sz + swrite_sz);
./src/unix/stream.c:    goto failed_malloc;
./src/unix/stream.c:failed_malloc:
./src/unix/stream.c:    queued_fds = uv__malloc((queue_size - 1) * sizeof(*queued_fds->fds) +
./src/unix/stream.c:    req->bufs = uv__malloc(nbufs * sizeof(bufs[0]));
./src/unix/sunos.c:  *cpu_infos = uv__malloc(lookup_instance * sizeof(**cpu_infos));
./src/unix/sunos.c:  *addresses = uv__malloc(*count * sizeof(**addresses));
./src/unix/tcp.c:    req->aio_connect.aio_sockaddrptr = (struct sockaddr_in*)malloc(addrlen);
./src/unix/tcp.c:  tcp->aio_accepts = (struct AioAcceptCb*)malloc(numberOfAioAccepts * sizeof(struct AioAcceptCb));
./src/unix/thread.c:  ctx = uv__malloc(sizeof(*ctx));
./src/unix/udp.c:    req->bufs = uv__malloc(nbufs * sizeof(bufs[0]));
./src/unix/os390-epoll.c:    struct _epoll_list* p = (struct _epoll_list*)malloc(sizeof(struct _epoll_list));
./src/unix/os390.c:	*cpu_infos = (uv_cpu_info_t*) uv__malloc(ncpus * sizeof(uv_cpu_info_t));
./src/unix/os390.c:	ifc.ifc_req = (struct ifreq*)uv__malloc(size);
./src/unix/os390.c:		uv__malloc(*count * sizeof(uv_interface_address_t));
Binary file ./src/unix/.os390.c.swp matches
Binary file ./src/unix/.stream.c.swp matches
Binary file ./src/unix/.core.c.swp matches
Binary file ./src/unix/.os390-epoll.c.swp matches
./src/uv-common.c:#include <stdlib.h> /* malloc */
./src/uv-common.c:# include <malloc.h> /* malloc */
./src/uv-common.c:  uv_malloc_func local_malloc;
./src/uv-common.c:  malloc,
./src/uv-common.c:  char* m = uv__malloc(len);
./src/uv-common.c:  m = uv__malloc(len + 1);
./src/uv-common.c:void* uv__malloc(size_t size) {
./src/uv-common.c:  return uv__allocator.local_malloc(size);
./src/uv-common.c:int uv_replace_allocator(uv_malloc_func malloc_func,
./src/uv-common.c:  if (malloc_func == NULL || realloc_func == NULL ||
./src/uv-common.c:  uv__allocator.local_malloc = malloc_func;
./src/uv-common.c:  loop = uv__malloc(sizeof(*loop));
./src/uv-common.h:void* uv__malloc(size_t size);
./src/win/fs-event.c:  *relpath = uv__malloc((MAX_PATH + 1) * sizeof(WCHAR));
./src/win/fs-event.c:    uv_fatal_error(ERROR_OUTOFMEMORY, "uv__malloc");
./src/win/fs-event.c:      *dir = (WCHAR*)uv__malloc((MAX_PATH + 1) * sizeof(WCHAR));
./src/win/fs-event.c:        uv_fatal_error(ERROR_OUTOFMEMORY, "uv__malloc");
./src/win/fs-event.c:      *dir = (WCHAR*)uv__malloc((i + 1) * sizeof(WCHAR));
./src/win/fs-event.c:        uv_fatal_error(ERROR_OUTOFMEMORY, "uv__malloc");
./src/win/fs-event.c:    *file = (WCHAR*)uv__malloc((len - i) * sizeof(WCHAR));
./src/win/fs-event.c:      uv_fatal_error(ERROR_OUTOFMEMORY, "uv__malloc");
./src/win/fs-event.c:    uv_fatal_error(ERROR_OUTOFMEMORY, "uv__malloc");
./src/win/fs-event.c:  pathw = (WCHAR*)uv__malloc(name_size);
./src/win/fs-event.c:    uv_fatal_error(ERROR_OUTOFMEMORY, "uv__malloc");
./src/win/fs-event.c:    handle->buffer = (char*)uv__malloc(uv_directory_watcher_buffer_size);
./src/win/fs-event.c:    uv_fatal_error(ERROR_OUTOFMEMORY, "uv__malloc");
./src/win/fs-event.c:              filenamew = (WCHAR*)uv__malloc(size * sizeof(WCHAR));
./src/win/fs-event.c:                uv_fatal_error(ERROR_OUTOFMEMORY, "uv__malloc");
./src/win/fs-event.c:                long_filenamew = (WCHAR*)uv__malloc(size * sizeof(WCHAR));
./src/win/fs-event.c:                  uv_fatal_error(ERROR_OUTOFMEMORY, "uv__malloc");
./src/win/fs-event.c:              filename = (char*)uv__malloc(size + 1);
./src/win/fs-event.c:                uv_fatal_error(ERROR_OUTOFMEMORY, "uv__malloc");
./src/win/fs.c:  buf = (char*) uv__malloc(buf_sz);
./src/win/fs.c:    target = (char*) uv__malloc(target_len + 1);
./src/win/fs.c:      dirent = uv__malloc(sizeof *dirent + utf8_len);
./src/win/fs.c:  char* buf = (char*) uv__malloc(buf_size);
./src/win/fs.c:    uv_fatal_error(ERROR_OUTOFMEMORY, "uv__malloc");
./src/win/fs.c:  buffer = (REPARSE_DATA_BUFFER*)uv__malloc(needed_buf_size);
./src/win/fs.c:    uv_fatal_error(ERROR_OUTOFMEMORY, "uv__malloc");
./src/win/fs.c:    req->fs.info.bufs = uv__malloc(nbufs * sizeof(*bufs));
./src/win/fs.c:    req->fs.info.bufs = uv__malloc(nbufs * sizeof(*bufs));
./src/win/getaddrinfo.c:    alloc_ptr = (char*)uv__malloc(addrinfo_len);
./src/win/getaddrinfo.c:  alloc_ptr = (char*)uv__malloc(nodesize + servicesize + hintssize);
./src/win/pipe.c:    uv__malloc(sizeof(uv_pipe_accept_t) * handle->pipe.serv.pending_instances);
./src/win/pipe.c:    uv_fatal_error(ERROR_OUTOFMEMORY, "uv__malloc");
./src/win/pipe.c:  handle->name = (WCHAR*)uv__malloc(nameSize);
./src/win/pipe.c:    uv_fatal_error(ERROR_OUTOFMEMORY, "uv__malloc");
./src/win/pipe.c:  handle->name = (WCHAR*)uv__malloc(nameSize);
./src/win/pipe.c:    uv_fatal_error(ERROR_OUTOFMEMORY, "uv__malloc");
./src/win/pipe.c:        ipc_header_req = (uv_write_t*)uv__malloc(sizeof(uv_write_t));
./src/win/pipe.c:          uv_fatal_error(ERROR_OUTOFMEMORY, "uv__malloc");
./src/win/pipe.c:  item = (uv__ipc_queue_item_t*) uv__malloc(sizeof(*item));
./src/win/pipe.c:    uv_fatal_error(ERROR_OUTOFMEMORY, "uv__malloc");
./src/win/pipe.c:  pipe->pipe.conn.eof_timer = (uv_timer_t*) uv__malloc(sizeof *pipe->pipe.conn.eof_timer);
./src/win/pipe.c:    name_info = uv__malloc(name_size);
./src/win/process-stdio.c:  buffer = (BYTE*) uv__malloc(CHILD_STDIO_SIZE(count));
./src/win/process.c:#include <malloc.h>    /* alloca */
./src/win/process.c:  ws = (WCHAR*) uv__malloc(ws_len * sizeof(WCHAR));
./src/win/process.c:  result = result_pos = (WCHAR*)uv__malloc(sizeof(WCHAR) *
./src/win/process.c:  dst = (WCHAR*) uv__malloc(dst_len * sizeof(WCHAR));
./src/win/process.c:  temp_buffer = (WCHAR*) uv__malloc(temp_buffer_len * sizeof(WCHAR));
./src/win/process.c:  dst_copy = (WCHAR*)uv__malloc(env_len * sizeof(WCHAR));
./src/win/process.c:  dst = uv__malloc((1+env_len) * sizeof(WCHAR));
./src/win/process.c:    cwd = (WCHAR*) uv__malloc(cwd_len * sizeof(WCHAR));
./src/win/process.c:    alloc_path = (WCHAR*) uv__malloc(path_len * sizeof(WCHAR));
./src/win/tcp.c:      uv__malloc(uv_simultaneous_server_accepts * sizeof(uv_tcp_accept_t));
./src/win/tcp.c:      uv_fatal_error(ERROR_OUTOFMEMORY, "uv__malloc");
./src/win/thread.c:  ctx = uv__malloc(sizeof(*ctx));
./src/win/util.c:  utf16_buffer = (WCHAR*) uv__malloc(sizeof(WCHAR) * utf16_buffer_len);
./src/win/util.c:  title_w = (WCHAR*)uv__malloc(sizeof(WCHAR) * length);
./src/win/util.c:    uv_fatal_error(ERROR_OUTOFMEMORY, "uv__malloc");
./src/win/util.c:  process_title = (char*)uv__malloc(length);
./src/win/util.c:    uv_fatal_error(ERROR_OUTOFMEMORY, "uv__malloc");
./src/win/util.c:  BYTE* malloced_buffer = NULL;
./src/win/util.c:    uv__free(malloced_buffer);
./src/win/util.c:    buffer = malloced_buffer = (BYTE*) uv__malloc(buffer_size);
./src/win/util.c:    if (malloced_buffer == NULL) {
./src/win/util.c:        uv__free(malloced_buffer);
./src/win/util.c:  uv__free(malloced_buffer);
./src/win/util.c:  uv__free(malloced_buffer);
./src/win/util.c:  sppi = uv__malloc(sppi_size);
./src/win/util.c:    cpu_info->model = uv__malloc(len + 1);
./src/win/util.c:        win_address_buf = uv__malloc(win_address_buf_size);
./src/win/util.c:        uv_address_buf = uv__malloc(1);
./src/win/util.c:  uv_address_buf = uv__malloc(uv_address_buf_size);
Binary file ./src/.uv-common.h.swp matches
./test/benchmark-ping-pongs.c:    ab = malloc(size + sizeof(*ab));
./test/benchmark-ping-pongs.c:  req = malloc(sizeof *req);
./test/benchmark-ping-pongs.c:  pinger = malloc(sizeof(*pinger));
./test/benchmark-million-async.c:  container = malloc(sizeof(*container));
./test/benchmark-pump.c:    stream = (uv_stream_t*)malloc(sizeof(uv_tcp_t));
./test/benchmark-pump.c:    stream = (uv_stream_t*)malloc(sizeof(uv_pipe_t));
./test/benchmark-pump.c:  req = (req_list_t*) malloc(sizeof *req);
./test/benchmark-pump.c:    ab = malloc(size + sizeof(*ab));
./test/blackhole-server.c:  conn = malloc(sizeof *conn);
./test/dns-server.c:  wr = (write_req_t*) malloc(sizeof *wr);
./test/dns-server.c:  wr->buf.base = (char*)malloc(WRITE_BUF_LEN);
./test/dns-server.c:    req = malloc(sizeof *req);
./test/dns-server.c:  buf->base = malloc(suggested_size);
./test/dns-server.c:  handle = (dnshandle*) malloc(sizeof *handle);
./test/echo-server.c:    sreq = malloc(sizeof* sreq);
./test/echo-server.c:  wr = (write_req_t*) malloc(sizeof *wr);
./test/echo-server.c:  buf->base = malloc(suggested_size);
./test/echo-server.c:    stream = malloc(sizeof(uv_tcp_t));
./test/echo-server.c:    stream = malloc(sizeof(uv_pipe_t));
./test/echo-server.c:  req = malloc(sizeof(*req));
./test/test-udp-send-and-recv.c:  req = malloc(sizeof *req);
./test/test-callback-stack.c:  buf->base = malloc(size);
./test/test-fs.c:  iovs = malloc(sizeof(*iovs) * iovcount);
./test/test-fs.c:  buffer = malloc(sizeof(test_buf) * iovcount);
./test/test-fs.c:  iovs = malloc(sizeof(*iovs) * iovcount);
./test/test-fs.c:  buffer = malloc(sizeof(test_buf) * iovcount);
./test/test-threadpool-cancel.c:    req = malloc(sizeof(*req));
./test/test-tcp-writealot.c:  buf->base = malloc(size);
./test/test-ipc.c:    conn = malloc(sizeof(*conn));
./test/test-ipc.c:  buf->base = malloc(suggested_size);
./test/test-ipc.c:    conn = malloc(sizeof(*conn));
./test/test-ipc.c:  buf->base = malloc(suggested_size);
./test/test-ipc.c:  conn = malloc(sizeof(*conn));
./test/test-multiple-listen.c:  uv_connect_t* connect_req = malloc(sizeof *connect_req);
./test/test-thread.c:  loop = malloc(sizeof *loop);
./test/test-tcp-create-socket-early.c:  handle = malloc(sizeof(*handle));
./test/test-spawn.c:        str = malloc(1 * sizeof(WCHAR));
./test/test-spawn.c:        str = malloc((name_len+1+len) * sizeof(WCHAR));
./test/test-stdio-over-pipes.c:      req = malloc(sizeof(*req));
./test/test-stdio-over-pipes.c:  buf->base = malloc(suggested_size);
./test/test-signal-multiple-loops.c:    loop = malloc(sizeof(*loop));
./test/test-shutdown-eof.c:  buf->base = malloc(size);
./test/benchmark-million-timers.c:  timers = malloc(NUM_TIMERS * sizeof(timers[0]));
./test/benchmark-multi-accept.c:  storage = malloc(sizeof(*storage));
./test/benchmark-tcp-write-batch.c:  write_reqs = malloc(sizeof(*write_reqs) * NUM_WRITE_REQS);
./test/runner-win.c:#include <malloc.h>
./test/test-delayed-accept.c:  buf->base = malloc(size);
./test/test-delayed-accept.c:  uv_tcp_t* accepted_handle = (uv_tcp_t*)malloc(sizeof *accepted_handle);
./test/test-delayed-accept.c:  timer_handle = (uv_timer_t*)malloc(sizeof *timer_handle);
./test/test-delayed-accept.c:  uv_tcp_t* server = (uv_tcp_t*)malloc(sizeof *server);
./test/test-delayed-accept.c:  uv_tcp_t* client = (uv_tcp_t*)malloc(sizeof *client);
./test/test-delayed-accept.c:  uv_connect_t* connect_req = malloc(sizeof *connect_req);
Binary file ./test/.nfs000000000101d6e300000174 matches
./test/test-getaddrinfo.c:  getaddrinfo_handle = (uv_getaddrinfo_t*)malloc(sizeof(uv_getaddrinfo_t));
./test/test-getaddrinfo.c:    data = (int*)malloc(sizeof(int));
./test/test-getsockname.c:  buf->base = malloc(suggested_size);
./test/test-getsockname.c:  req = (uv_shutdown_t*) malloc(sizeof *req);
./test/test-getsockname.c:  handle = malloc(sizeof(*handle));
./test/test-ping-pong.c:  buf->base = malloc(size);
./test/test-ping-pong.c:  req = malloc(sizeof(*req));
./test/test-ping-pong.c:  pinger = malloc(sizeof(*pinger));
./test/test-ping-pong.c:  pinger = malloc(sizeof(*pinger));
./test/test-ping-pong.c:  pinger = (pinger_t*)malloc(sizeof(*pinger));
./test/test-tcp-close.c:    req = malloc(sizeof *req);
./test/test-poll.c:  context = (connection_context_t*) malloc(sizeof *context);
./test/test-poll.c:  context = (server_context_t*) malloc(sizeof *context);
