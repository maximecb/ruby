// YJIT combined compilation unit. This setup allows spreading functions
// across different files without having to worry about putting things
// in headers and prefixing function names.

#include "internal.h"
#include "vm_core.h"
#include "vm_callinfo.h"
#include "builtin.h"
#include "insns.inc"
#include "insns_info.inc"
#include "vm_sync.h"
#include "yjit.h"

#ifndef YJIT_CHECK_MODE
# define YJIT_CHECK_MODE 0
#endif

// >= 1: print when output code invalidation happens
// >= 2: dump list of instructions when regions compile
#ifndef YJIT_DUMP_MODE
# define YJIT_DUMP_MODE 0
#endif

#if defined(__x86_64__) && !defined(_WIN32)
# define PLATFORM_SUPPORTED_P 1
#else
# define PLATFORM_SUPPORTED_P 0
#endif

// USE_MJIT comes from configure options
#define JIT_ENABLED USE_MJIT

// Check if we need to include YJIT in the build
#if JIT_ENABLED && PLATFORM_SUPPORTED_P

#include "yjit_asm.c"

// Code block into which we write machine code
static codeblock_t block;
static codeblock_t *cb = NULL;

// Code block into which we write out-of-line machine code
static codeblock_t outline_block;
static codeblock_t *ocb = NULL;

// NOTE: We can trust that uint8_t has no "padding bits" since the C spec
// guarantees it. Wording about padding bits is more explicit in C11 compared
// to C99. See C11 7.20.1.1p2. All this is to say we have _some_ standards backing to
// use a Rust `* u8` to represent a C `* uint8_t`.
//
// If we don't want to trust that we can interpreter the C standard correctly, we
// could outsource that work to the Rust standard library by sticking to fundamental
// types in C such as int, long, etc. and use `std::os::raw::c_long` and friends on
// the Rust side.
//
// What's up with the long prefix? The "rb_" part is to apease `make leaked-globals`
// which runs on upstream CI. The rationale for the check is unclear to Alan as
// we build with `-fvisibility=hidden` so only explicitly marked functions end
// up as public symbols in libruby.so. Perhaps the check is for the static
// libruby and or general namspacing hygiene? Alan admits his bias towards ELF
// platforms and newer compilers.
//
// The "_yjit_" part is for trying to be informative. We might want different
// suffixes for symbols meant for Rust and symbols meant for broader CRuby.
uint8_t *
rb_yjit_alloc_exec_mem(uint32_t mem_size)
{
    // It's a diff minimization move to wrap instead of rename to export.
    return alloc_exec_mem(mem_size);
}

unsigned int
rb_iseq_encoded_size(const rb_iseq_t *iseq)
{
    return iseq->body->iseq_size;
}

// TODO(alan): consider using an opaque pointer for the payload rather than a void pointer
void *
rb_iseq_get_yjit_payload(const rb_iseq_t *iseq)
{
    RUBY_ASSERT_ALWAYS(IMEMO_TYPE_P(iseq, imemo_iseq));
    return iseq->body->yjit_payload;
}

void
rb_iseq_set_yjit_payload(const rb_iseq_t *iseq, void *payload)
{
    RUBY_ASSERT_ALWAYS(IMEMO_TYPE_P(iseq, imemo_iseq));
    RUBY_ASSERT_ALWAYS(NULL == iseq->body->yjit_payload);
    iseq->body->yjit_payload = payload;
}

// Get the PC for a given index in an iseq
VALUE *
rb_iseq_pc_at_idx(const rb_iseq_t *iseq, uint32_t insn_idx)
{
    RUBY_ASSERT_ALWAYS(IMEMO_TYPE_P(iseq, imemo_iseq));
    RUBY_ASSERT_ALWAYS(insn_idx < iseq->body->iseq_size);
    VALUE *encoded = iseq->body->iseq_encoded;
    VALUE *pc = &encoded[insn_idx];
    return pc;
}

int
rb_iseq_opcode_at_pc(const rb_iseq_t *iseq, const VALUE *pc)
{
    // YJIT should only use iseqs after AST to bytecode compilation
    RUBY_ASSERT_ALWAYS(FL_TEST_RAW((VALUE)iseq, ISEQ_TRANSLATED));

    const VALUE at_pc = *pc;
    return rb_vm_insn_addr2opcode((const void *)at_pc);
}

#if YJIT_STATS
// Comments for generated code
struct yjit_comment {
    uint32_t offset;
    const char *comment;
};

typedef rb_darray(struct yjit_comment) yjit_comment_array_t;
static yjit_comment_array_t yjit_code_comments;

// Counters for generated code
#define YJIT_DECLARE_COUNTERS(...) struct rb_yjit_runtime_counters { \
    int64_t __VA_ARGS__; \
}; \
static char yjit_counter_names[] = #__VA_ARGS__;

YJIT_DECLARE_COUNTERS(
    exec_instruction,

    send_keywords,
    send_kw_splat,
    send_args_splat,
    send_block_arg,
    send_ivar_set_method,
    send_zsuper_method,
    send_undef_method,
    send_optimized_method,
    send_optimized_method_send,
    send_optimized_method_call,
    send_optimized_method_block_call,
    send_missing_method,
    send_bmethod,
    send_refined_method,
    send_cfunc_ruby_array_varg,
    send_cfunc_argc_mismatch,
    send_cfunc_toomany_args,
    send_cfunc_tracing,
    send_cfunc_kwargs,
    send_attrset_kwargs,
    send_iseq_tailcall,
    send_iseq_arity_error,
    send_iseq_only_keywords,
    send_iseq_kwargs_req_and_opt_missing,
    send_iseq_kwargs_mismatch,
    send_iseq_complex_callee,
    send_not_implemented_method,
    send_getter_arity,
    send_se_cf_overflow,
    send_se_protected_check_failed,

    traced_cfunc_return,

    invokesuper_me_changed,
    invokesuper_block,

    leave_se_interrupt,
    leave_interp_return,
    leave_start_pc_non_zero,

    getivar_se_self_not_heap,
    getivar_idx_out_of_range,
    getivar_megamorphic,

    setivar_se_self_not_heap,
    setivar_idx_out_of_range,
    setivar_val_heapobject,
    setivar_name_not_mapped,
    setivar_not_object,
    setivar_frozen,

    oaref_argc_not_one,
    oaref_arg_not_fixnum,

    opt_getinlinecache_miss,

    binding_allocations,
    binding_set,

    vm_insns_count,
    compiled_iseq_count,
    compiled_block_count,
    compilation_failure,

    exit_from_branch_stub,

    invalidation_count,
    invalidate_method_lookup,
    invalidate_bop_redefined,
    invalidate_ractor_spawn,
    invalidate_constant_state_bump,
    invalidate_constant_ic_fill,

    constant_state_bumps,

    expandarray_splat,
    expandarray_postarg,
    expandarray_not_array,
    expandarray_rhs_too_small,

    gbpp_block_param_modified,
    gbpp_block_handler_not_iseq,

    // Member with known name for iterating over counters
    last_member
)

static struct rb_yjit_runtime_counters yjit_runtime_counters = { 0 };
#undef YJIT_DECLARE_COUNTERS

#endif // YJIT_STATS

// The number of bytes counting from the beginning of the inline code block
// that should not be changed. After patching for global invalidation, no one
// should make changes to the invalidated code region anymore. This is used to
// break out of invalidation race when there are multiple ractors.
static uint32_t yjit_codepage_frozen_bytes = 0;

#include "yjit_utils.c"
#include "yjit_core.c"
#include "yjit_iface.c"

#endif // if JIT_ENABLED && PLATFORM_SUPPORTED_P
