#include "ruby.h"
#include "ruby/encoding.h"

VALUE rb_fstring(VALUE str);

VALUE
bug_s_fstring(VALUE self, VALUE str)
{
    return rb_fstring(str);
}

VALUE
bug_s_rb_enc_interned_str_windows_31_j(VALUE self)
{
    return rb_enc_interned_str("foo", 3, rb_enc_from_index(11 /* Windows-31-J */));
}

void
Init_string_fstring(VALUE klass)
{
    rb_define_singleton_method(klass, "fstring", bug_s_fstring, 1);
    rb_define_singleton_method(klass, "rb_enc_interned_str_windows_31_j", bug_s_rb_enc_interned_str_windows_31_j, 0);
}
