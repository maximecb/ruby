#include "ruby.h"
#include "ruby/memory_view.h"

#define STRUCT_ALIGNOF(T, result) do { \
    struct S { char _; T t; }; \
    (result) = (int)offsetof(struct S, t); \
} while(0)

static ID id_str;
static VALUE sym_format;
static VALUE sym_native_size_p;
static VALUE sym_offset;
static VALUE sym_size;
static VALUE sym_repeat;
static VALUE sym_obj;
static VALUE sym_len;
static VALUE sym_readonly;
static VALUE sym_format;
static VALUE sym_item_size;
static VALUE sym_ndim;
static VALUE sym_shape;
static VALUE sym_strides;
static VALUE sym_sub_offsets;
static VALUE sym_endianness;
static VALUE sym_little_endian;
static VALUE sym_big_endian;

static VALUE exported_objects;

static int
exportable_string_get_memory_view(VALUE obj, rb_memory_view_t *view, int flags)
{
    VALUE str = rb_ivar_get(obj, id_str);
    rb_memory_view_init_as_byte_array(view, obj, RSTRING_PTR(str), RSTRING_LEN(str), true);

    VALUE count = rb_hash_lookup2(exported_objects, obj, INT2FIX(0));
    count = rb_funcall(count, '+', 1, INT2FIX(1));
    rb_hash_aset(exported_objects, obj, count);

    return 1;
}

static int
exportable_string_release_memory_view(VALUE obj, rb_memory_view_t *view)
{
    VALUE count = rb_hash_lookup2(exported_objects, obj, INT2FIX(0));
    if (INT2FIX(1) == count) {
        rb_hash_delete(exported_objects, obj);
    }
    else if (INT2FIX(0) == count) {
        rb_raise(rb_eRuntimeError, "Duplicated releasing of a memory view has been occurred for %"PRIsVALUE, obj);
    }
    else {
        count = rb_funcall(count, '-', 1, INT2FIX(1));
        rb_hash_aset(exported_objects, obj, count);
    }

    return 1;
}

static int
exportable_string_memory_view_available_p(VALUE obj)
{
    return Qtrue;
}

static const rb_memory_view_entry_t exportable_string_memory_view_entry = {
    exportable_string_get_memory_view,
    exportable_string_release_memory_view,
    exportable_string_memory_view_available_p
};

static VALUE
memory_view_available_p(VALUE mod, VALUE obj)
{
    return rb_memory_view_available_p(obj) ? Qtrue : Qfalse;
}

static VALUE
memory_view_register(VALUE mod, VALUE obj)
{
    return rb_memory_view_register(obj, &exportable_string_memory_view_entry) ? Qtrue : Qfalse;
}

static VALUE
memory_view_item_size_from_format(VALUE mod, VALUE format)
{
    const char *c_str = NULL;
    if (!NIL_P(format))
        c_str = StringValueCStr(format);
    const char *err = NULL;
    ssize_t item_size = rb_memory_view_item_size_from_format(c_str, &err);
    if (!err)
        return rb_assoc_new(SSIZET2NUM(item_size), Qnil);
    else
        return rb_assoc_new(SSIZET2NUM(item_size), rb_str_new_cstr(err));
}

static VALUE
memory_view_parse_item_format(VALUE mod, VALUE format)
{
    const char *c_str = NULL;
    if (!NIL_P(format))
        c_str = StringValueCStr(format);
    const char *err = NULL;

    rb_memory_view_item_component_t *members;
    ssize_t n_members;
    ssize_t item_size = rb_memory_view_parse_item_format(c_str, &members, &n_members, &err);

    VALUE result = rb_ary_new_capa(3);
    rb_ary_push(result, SSIZET2NUM(item_size));

    if (!err) {
        VALUE ary = rb_ary_new_capa(n_members);
        ssize_t i;
        for (i = 0; i < n_members; ++i) {
            VALUE member = rb_hash_new();
            rb_hash_aset(member, sym_format, rb_str_new(&members[i].format, 1));
            rb_hash_aset(member, sym_native_size_p, members[i].native_size_p ? Qtrue : Qfalse);
            rb_hash_aset(member, sym_endianness, members[i].little_endian_p ? sym_little_endian : sym_big_endian);
            rb_hash_aset(member, sym_offset, SSIZET2NUM(members[i].offset));
            rb_hash_aset(member, sym_size, SSIZET2NUM(members[i].size));
            rb_hash_aset(member, sym_repeat, SSIZET2NUM(members[i].repeat));
            rb_ary_push(ary, member);
        }
        xfree(members);
        rb_ary_push(result, ary);
        rb_ary_push(result, Qnil);
    }
    else {
        rb_ary_push(result, Qnil); // members
        rb_ary_push(result, rb_str_new_cstr(err));
    }

    return result;
}

static VALUE
memory_view_get_memory_view_info(VALUE mod, VALUE obj)
{
    rb_memory_view_t view;

    if (!rb_memory_view_get(obj, &view, 0)) {
        return Qnil;
    }

    VALUE hash = rb_hash_new();
    rb_hash_aset(hash, sym_obj, view.obj);
    rb_hash_aset(hash, sym_len, SSIZET2NUM(view.len));
    rb_hash_aset(hash, sym_readonly, view.readonly ? Qtrue : Qfalse);
    rb_hash_aset(hash, sym_format, view.format ? rb_str_new_cstr(view.format) : Qnil);
    rb_hash_aset(hash, sym_item_size, SSIZET2NUM(view.item_size));
    rb_hash_aset(hash, sym_ndim, SSIZET2NUM(view.ndim));

    if (view.shape) {
        VALUE shape = rb_ary_new_capa(view.ndim);
        rb_hash_aset(hash, sym_shape, shape);
    }
    else {
        rb_hash_aset(hash, sym_shape, Qnil);
    }

    if (view.strides) {
        VALUE strides = rb_ary_new_capa(view.ndim);
        rb_hash_aset(hash, sym_strides, strides);
    }
    else {
        rb_hash_aset(hash, sym_strides, Qnil);
    }

    if (view.sub_offsets) {
        VALUE sub_offsets = rb_ary_new_capa(view.ndim);
        rb_hash_aset(hash, sym_sub_offsets, sub_offsets);
    }
    else {
        rb_hash_aset(hash, sym_sub_offsets, Qnil);
    }

    rb_memory_view_release(&view);

    return hash;
}

static VALUE
memory_view_fill_contiguous_strides(VALUE mod, VALUE ndim_v, VALUE item_size_v, VALUE shape_v, VALUE row_major_p)
{
    int i, ndim = FIX2INT(ndim_v);

    Check_Type(shape_v, T_ARRAY);
    ssize_t *shape = ALLOC_N(ssize_t, ndim);
    for (i = 0; i < ndim; ++i) {
        shape[i] = NUM2SSIZET(RARRAY_AREF(shape_v, i));
    }

    ssize_t *strides = ALLOC_N(ssize_t, ndim);
    rb_memory_view_fill_contiguous_strides(ndim, NUM2SSIZET(item_size_v), shape, RTEST(row_major_p), strides);

    VALUE result = rb_ary_new_capa(ndim);
    for (i = 0; i < ndim; ++i) {
        rb_ary_push(result, SSIZET2NUM(strides[i]));
    }

    xfree(strides);
    xfree(shape);

    return result;
}

static VALUE
expstr_initialize(VALUE obj, VALUE s)
{
    rb_ivar_set(obj, id_str, s);
    return Qnil;
}

static int
mdview_get_memory_view(VALUE obj, rb_memory_view_t *view, int flags)
{
    VALUE buf_v = rb_ivar_get(obj, id_str);
    VALUE shape_v = rb_ivar_get(obj, SYM2ID(sym_shape));
    VALUE strides_v = rb_ivar_get(obj, SYM2ID(sym_strides));

    ssize_t i, ndim = RARRAY_LEN(shape_v);
    ssize_t *shape = ALLOC_N(ssize_t, ndim);
    ssize_t *strides = NULL;
    if (!NIL_P(strides_v)) {
        if (RARRAY_LEN(strides_v) != ndim) {
            rb_raise(rb_eArgError, "strides has an invalid dimension");
        }

        strides = ALLOC_N(ssize_t, ndim);
        for (i = 0; i < ndim; ++i) {
            shape[i] = NUM2SSIZET(RARRAY_AREF(shape_v, i));
            strides[i] = NUM2SSIZET(RARRAY_AREF(strides_v, i));
        }
    }
    else {
        for (i = 0; i < ndim; ++i) {
            shape[i] = NUM2SSIZET(RARRAY_AREF(shape_v, i));
        }
    }

    rb_memory_view_init_as_byte_array(view, obj, RSTRING_PTR(buf_v), RSTRING_LEN(buf_v), true);
    view->format = "l";
    view->item_size = sizeof(long);
    view->ndim = ndim;
    view->shape = shape;
    view->strides = strides;

    VALUE count = rb_hash_lookup2(exported_objects, obj, INT2FIX(0));
    count = rb_funcall(count, '+', 1, INT2FIX(1));
    rb_hash_aset(exported_objects, obj, count);

    return 1;
}

static int
mdview_release_memory_view(VALUE obj, rb_memory_view_t *view)
{
    VALUE count = rb_hash_lookup2(exported_objects, obj, INT2FIX(0));
    if (INT2FIX(1) == count) {
        rb_hash_delete(exported_objects, obj);
    }
    else if (INT2FIX(0) == count) {
        rb_raise(rb_eRuntimeError, "Duplicated releasing of a memory view has been occurred for %"PRIsVALUE, obj);
    }
    else {
        count = rb_funcall(count, '-', 1, INT2FIX(1));
        rb_hash_aset(exported_objects, obj, count);
    }

    return 1;
}

static int
mdview_memory_view_available_p(VALUE obj)
{
    return true;
}

static const rb_memory_view_entry_t mdview_memory_view_entry = {
    mdview_get_memory_view,
    mdview_release_memory_view,
    mdview_memory_view_available_p
};

static VALUE
mdview_initialize(VALUE obj, VALUE buf, VALUE shape, VALUE strides)
{
    Check_Type(buf, T_STRING);
    Check_Type(shape, T_ARRAY);
    if (!NIL_P(strides)) Check_Type(strides, T_ARRAY);

    rb_ivar_set(obj, id_str, buf);
    rb_ivar_set(obj, SYM2ID(sym_shape), shape);
    rb_ivar_set(obj, SYM2ID(sym_strides), strides);
    return Qnil;
}

static VALUE
mdview_aref(VALUE obj, VALUE indices_v)
{
    Check_Type(indices_v, T_ARRAY);

    rb_memory_view_t view;
    if (!rb_memory_view_get(obj, &view, 0)) {
        rb_raise(rb_eRuntimeError, "rb_memory_view_get: failed");
    }

    if (RARRAY_LEN(indices_v) != view.ndim) {
        rb_raise(rb_eKeyError, "Indices has an invalid dimension");
    }

    VALUE buf_indices;
    ssize_t *indices = ALLOCV_N(ssize_t, buf_indices, view.ndim);

    ssize_t i;
    for (i = 0; i < view.ndim; ++i) {
        indices[i] = NUM2SSIZET(RARRAY_AREF(indices_v, i));
    }

    char *ptr = rb_memory_view_get_item_pointer(&view, indices);
    ALLOCV_END(buf_indices);

    long x = *(long *)ptr;
    VALUE result = LONG2FIX(x);
    rb_memory_view_release(&view);

    return result;
}

void
Init_memory_view(void)
{
    VALUE mMemoryViewTestUtils = rb_define_module("MemoryViewTestUtils");

    rb_define_module_function(mMemoryViewTestUtils, "available?", memory_view_available_p, 1);
    rb_define_module_function(mMemoryViewTestUtils, "register", memory_view_register, 1);
    rb_define_module_function(mMemoryViewTestUtils, "item_size_from_format", memory_view_item_size_from_format, 1);
    rb_define_module_function(mMemoryViewTestUtils, "parse_item_format", memory_view_parse_item_format, 1);
    rb_define_module_function(mMemoryViewTestUtils, "get_memory_view_info", memory_view_get_memory_view_info, 1);
    rb_define_module_function(mMemoryViewTestUtils, "fill_contiguous_strides", memory_view_fill_contiguous_strides, 4);

    VALUE cExportableString = rb_define_class_under(mMemoryViewTestUtils, "ExportableString", rb_cObject);
    rb_define_method(cExportableString, "initialize", expstr_initialize, 1);
    rb_memory_view_register(cExportableString, &exportable_string_memory_view_entry);

    VALUE cMDView = rb_define_class_under(mMemoryViewTestUtils, "MultiDimensionalView", rb_cObject);
    rb_define_method(cMDView, "initialize", mdview_initialize, 3);
    rb_define_method(cMDView, "[]", mdview_aref, 1);
    rb_memory_view_register(cMDView, &mdview_memory_view_entry);

    id_str = rb_intern("__str__");
    sym_format = ID2SYM(rb_intern("format"));
    sym_native_size_p = ID2SYM(rb_intern("native_size_p"));
    sym_offset = ID2SYM(rb_intern("offset"));
    sym_size = ID2SYM(rb_intern("size"));
    sym_repeat = ID2SYM(rb_intern("repeat"));
    sym_obj = ID2SYM(rb_intern("obj"));
    sym_len = ID2SYM(rb_intern("len"));
    sym_readonly = ID2SYM(rb_intern("readonly"));
    sym_format = ID2SYM(rb_intern("format"));
    sym_item_size = ID2SYM(rb_intern("item_size"));
    sym_ndim = ID2SYM(rb_intern("ndim"));
    sym_shape = ID2SYM(rb_intern("shape"));
    sym_strides = ID2SYM(rb_intern("strides"));
    sym_sub_offsets = ID2SYM(rb_intern("sub_offsets"));
    sym_endianness = ID2SYM(rb_intern("endianness"));
    sym_little_endian = ID2SYM(rb_intern("little_endian"));
    sym_big_endian = ID2SYM(rb_intern("big_endian"));

#ifdef WORDS_BIGENDIAN
    rb_const_set(mMemoryViewTestUtils, rb_intern("NATIVE_ENDIAN"), sym_big_endian);
#else
    rb_const_set(mMemoryViewTestUtils, rb_intern("NATIVE_ENDIAN"), sym_little_endian);
#endif

#define DEF_ALIGNMENT_CONST(type, TYPE) do { \
    int alignment; \
    STRUCT_ALIGNOF(type, alignment); \
    rb_const_set(mMemoryViewTestUtils, rb_intern(#TYPE "_ALIGNMENT"), INT2FIX(alignment)); \
} while(0)

    DEF_ALIGNMENT_CONST(short, SHORT);
    DEF_ALIGNMENT_CONST(int, INT);
    DEF_ALIGNMENT_CONST(long, LONG);
    DEF_ALIGNMENT_CONST(LONG_LONG, LONG_LONG);
    DEF_ALIGNMENT_CONST(int16_t, INT16);
    DEF_ALIGNMENT_CONST(int32_t, INT32);
    DEF_ALIGNMENT_CONST(int64_t, INT64);
    DEF_ALIGNMENT_CONST(intptr_t, INTPTR);
    DEF_ALIGNMENT_CONST(float, FLOAT);
    DEF_ALIGNMENT_CONST(double, DOUBLE);

#undef DEF_ALIGNMENT_CONST

    exported_objects = rb_hash_new();
    rb_gc_register_mark_object(exported_objects);
}
