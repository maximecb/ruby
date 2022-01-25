#include "ruby/ruby.h"
#include "ruby/thread.h"
#include "ruby/thread_native.h"

static void*
native_sleep_callback(void *data)
{
    struct timeval *timeval = data;
    select(0, NULL, NULL, NULL, timeval);

    return NULL;
}


static VALUE
thread_runnable_sleep(VALUE thread, VALUE timeout)
{
    struct timeval timeval;

    if (NIL_P(timeout)) {
	rb_raise(rb_eArgError, "timeout must be non nil");
    }

    timeval = rb_time_interval(timeout);

    rb_thread_call_without_gvl(native_sleep_callback, &timeval, RUBY_UBF_IO, NULL);

    return Qnil;
}

struct loop_ctl {
    int notify_fd;
    volatile int stop;
};

static void *
do_loop(void *p)
{
    struct loop_ctl *ctl = p;

    /* tell the waiting process they can interrupt us, now */
    ssize_t err = write(ctl->notify_fd, "", 1);
    if (err == -1) rb_bug("write error");

    while (!ctl->stop) {
        struct timeval tv = { 0, 10000 };
        select(0, NULL, NULL, NULL, &tv);
    }
    return 0;
}

static void
stop_set(void *p)
{
    struct loop_ctl *ctl = p;

    ctl->stop = 1;
}

static VALUE
thread_ubf_async_safe(VALUE thread, VALUE notify_fd)
{
    struct loop_ctl ctl;

    ctl.notify_fd = NUM2INT(notify_fd);
    ctl.stop = 0;

    rb_nogvl(do_loop, &ctl, stop_set, &ctl, RB_NOGVL_UBF_ASYNC_SAFE);
    return Qnil;
}

void
ex_callback(uint32_t e, struct gvl_hook_event_args args) {
    fprintf(stderr, "calling callback\n");
}

static gvl_hook_t * single_hook = NULL;

static VALUE
thread_register_gvl_callback(VALUE thread) {
    single_hook = rb_gvl_event_new(*ex_callback, RUBY_INTERNAL_EVENT_GVL_ACQUIRE_ENTER);

    return Qnil;
}

static VALUE
thread_unregister_gvl_callback(VALUE thread) {
    if (single_hook) {
        rb_gvl_event_delete(single_hook);
        single_hook = NULL;
    }

    return Qnil;
}

static VALUE
thread_call_gvl_callback(VALUE thread) {
    rb_gvl_execute_hooks(RUBY_INTERNAL_EVENT_GVL_ACQUIRE_ENTER, 1);
    return Qnil;
}

static VALUE
thread_register_and_unregister_gvl_callback(VALUE thread) {
    gvl_hook_t * hooks[5];
    for (int i = 0; i < 5; i++) {
        hooks[i] = rb_gvl_event_new(*ex_callback, RUBY_INTERNAL_EVENT_GVL_ACQUIRE_ENTER);
    }

    if (!rb_gvl_event_delete(hooks[4])) return Qfalse;
    if (!rb_gvl_event_delete(hooks[0])) return Qfalse;
    if (!rb_gvl_event_delete(hooks[3])) return Qfalse;
    if (!rb_gvl_event_delete(hooks[2])) return Qfalse;
    if (!rb_gvl_event_delete(hooks[1])) return Qfalse;
    return Qtrue;
}

void
Init_call_without_gvl(void)
{
    VALUE mBug = rb_define_module("Bug");
    VALUE klass = rb_define_module_under(mBug, "Thread");
    rb_define_singleton_method(klass, "runnable_sleep", thread_runnable_sleep, 1);
    rb_define_singleton_method(klass, "ubf_async_safe", thread_ubf_async_safe, 1);
    rb_define_singleton_method(klass, "register_callback", thread_register_gvl_callback, 0);
    rb_define_singleton_method(klass, "unregister_callback", thread_unregister_gvl_callback, 0);
    rb_define_singleton_method(klass, "register_and_unregister_callbacks", thread_register_and_unregister_gvl_callback, 0);
    rb_define_singleton_method(klass, "call_callbacks", thread_call_gvl_callback, 0);
}
