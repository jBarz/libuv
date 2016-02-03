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
#include "task.h"

static uv_timer_t timer_handle;

static void timer_cb(uv_timer_t* handle) {
printf("JBAR: in timer_cb\n");
  ASSERT(handle);
}


static uv_work_t work_req;

static void work_cb(uv_work_t* req) {
printf("JBAR: in work_cb\n");
  ASSERT(req);
}

static void after_work_cb(uv_work_t* req, int status) {
printf("JBAR: in after_work_cb\n");
  ASSERT(req);
  ASSERT(status == 0);
}


TEST_IMPL(loop_alive) {
  int r;
  ASSERT(!uv_loop_alive(uv_default_loop()));

  /* loops with handles are alive */
printf("JBAR %s:%d\n", __FILE__, __LINE__);
  uv_timer_init(uv_default_loop(), &timer_handle);
  uv_timer_start(&timer_handle, timer_cb, 100, 0);
  ASSERT(uv_loop_alive(uv_default_loop()));

printf("JBAR %s:%d\n", __FILE__, __LINE__);
  r = uv_run(uv_default_loop(), UV_RUN_DEFAULT);
  ASSERT(r == 0);
  ASSERT(!uv_loop_alive(uv_default_loop()));

  /* loops with requests are alive */
printf("JBAR %s:%d\n", __FILE__, __LINE__);
  r = uv_queue_work(uv_default_loop(), &work_req, work_cb, after_work_cb);
  ASSERT(r == 0);
  ASSERT(uv_loop_alive(uv_default_loop()));

printf("JBAR %s:%d\n", __FILE__, __LINE__);
  r = uv_run(uv_default_loop(), UV_RUN_DEFAULT);
  ASSERT(r == 0);
  ASSERT(!uv_loop_alive(uv_default_loop()));

  return 0;
}
