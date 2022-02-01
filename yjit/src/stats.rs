//! Everything related to the collection of runtime stats in YJIT
//! See the stats feature and the --yjit-stats command-line option

use crate::cruby::*;
use crate::options::*;

// Maxime says: I added a stats feature so we can conditionally
// enable/disable the stats code:
// #[cfg(feature = "stats")]

// TODO
//extern const int rb_vm_max_insn_name_size;

// YJIT exit counts for each instruction type
static mut EXIT_OP_COUNT: [u64; VM_INSTRUCTION_SIZE] = [0; VM_INSTRUCTION_SIZE];

// Macro to declare the stat counters
macro_rules! make_counters {
    ($($counter_name:ident),+) => {
        // Struct containing the counter values
        #[derive(Default, Debug)]
        struct Counters { $($counter_name: u64),+ }

        // Counter names constant
        const COUNTER_NAMES: &'static [&'static str] = &[ $(stringify!($counter_name)),+ ];

        // Global counters instance, initialized to zero
        static mut COUNTERS: Counters = Counters { $($counter_name: 0),+ };
    }
}

/// Macro to increment a counter by name
macro_rules! incr_counter {
    // Unsafe is ok here because options are initialized
    // once before any Ruby code executes
    ($counter_name:ident) => {
        unsafe {
            COUNTERS.$counter_name += 1
        }
    };
}
pub(crate) use incr_counter;

// Declare all the counters we track
make_counters!(
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
    gbpp_block_handler_not_iseq
);



/*
// Primitive called in yjit.rb. Export all YJIT statistics as a Ruby hash.
static VALUE
get_yjit_stats(rb_execution_context_t *ec, VALUE self)
{
    // Return Qnil if YJIT isn't enabled
    if (cb == NULL) {
        return Qnil;
    }

    VALUE hash = rb_hash_new();

    RB_VM_LOCK_ENTER();

    {
        VALUE key = ID2SYM(rb_intern("inline_code_size"));
        VALUE value = LL2NUM((long long)cb->write_pos);
        rb_hash_aset(hash, key, value);

        key = ID2SYM(rb_intern("outlined_code_size"));
        value = LL2NUM((long long)ocb->write_pos);
        rb_hash_aset(hash, key, value);
    }

#if YJIT_STATS
    if (rb_yjit_opts.gen_stats) {
        // Indicate that the complete set of stats is available
        rb_hash_aset(hash, ID2SYM(rb_intern("all_stats")), Qtrue);

        int64_t *counter_reader = (int64_t *)&yjit_runtime_counters;
        int64_t *counter_reader_end = &yjit_runtime_counters.last_member;

        // For each counter in yjit_counter_names, add that counter as
        // a key/value pair.

        // Iterate through comma separated counter name list
        char *name_reader = yjit_counter_names;
        char *counter_name_end = yjit_counter_names + sizeof(yjit_counter_names);
        while (name_reader < counter_name_end && counter_reader < counter_reader_end) {
            if (*name_reader == ',' || *name_reader == ' ') {
                name_reader++;
                continue;
            }

            // Compute length of counter name
            int name_len;
            char *name_end;
            {
                name_end = strchr(name_reader, ',');
                if (name_end == NULL) break;
                name_len = (int)(name_end - name_reader);
            }

            // Put counter into hash
            VALUE key = ID2SYM(rb_intern2(name_reader, name_len));
            VALUE value = LL2NUM((long long)*counter_reader);
            rb_hash_aset(hash, key, value);

            counter_reader++;
            name_reader = name_end;
        }

        // For each entry in exit_op_count, add a stats entry with key "exit_INSTRUCTION_NAME"
        // and the value is the count of side exits for that instruction.

        char key_string[rb_vm_max_insn_name_size + 6]; // Leave room for "exit_" and a final NUL
        for (int i = 0; i < VM_INSTRUCTION_SIZE; i++) {
            const char *i_name = insn_name(i); // Look up Ruby's NUL-terminated insn name string
            snprintf(key_string, rb_vm_max_insn_name_size + 6, "%s%s", "exit_", i_name);

            VALUE key = ID2SYM(rb_intern(key_string));
            VALUE value = LL2NUM((long long)exit_op_count[i]);
            rb_hash_aset(hash, key, value);
        }
    }
#endif

    RB_VM_LOCK_LEAVE();

    return hash;
}
*/




// Primitive called in yjit.rb. Zero out all the counters.
#[no_mangle]
pub extern "C" fn reset_stats_bang(ec: EcPtr, ruby_self: VALUE) -> VALUE {
    unsafe {
        EXIT_OP_COUNT = [0; VM_INSTRUCTION_SIZE];
        COUNTERS = Counters::default();
    }

    todo!(); // missing Qnil const
    //return Qnil;
}








/*
#if YJIT_STATS

// Increment a profiling counter with counter_name
#define GEN_COUNTER_INC(cb, counter_name) _gen_counter_inc(cb, &(yjit_runtime_counters . counter_name))
static void
_gen_counter_inc(codeblock_t *cb, int64_t *counter)
{
    if (!rb_yjit_opts.gen_stats) return;

    // Use REG1 because there might be return value in REG0
    mov(cb, REG1, const_ptr_opnd(counter));
    cb_write_lock_prefix(cb); // for ractors.
    add(cb, mem_opnd(64, REG1, 0), imm_opnd(1));
}

// Increment a counter then take an existing side exit.
#define COUNTED_EXIT(jit, side_exit, counter_name) _counted_side_exit(jit, side_exit, &(yjit_runtime_counters . counter_name))
static uint8_t *
_counted_side_exit(jitstate_t* jit, uint8_t *existing_side_exit, int64_t *counter)
{
    if (!rb_yjit_opts.gen_stats) return existing_side_exit;

    uint8_t *start = cb_get_ptr(jit->ocb, jit->ocb->write_pos);
    _gen_counter_inc(jit->ocb, counter);
    jmp_ptr(jit->ocb, existing_side_exit);
    return start;
}

#else

#define GEN_COUNTER_INC(cb, counter_name) ((void)0)
#define COUNTED_EXIT(jit, side_exit, counter_name) side_exit

#endif // if YJIT_STATS
*/




#[no_mangle]
pub extern "C" fn rb_yjit_collect_vm_usage_insn() {
    incr_counter!(vm_insns_count);
}

/*
void
rb_yjit_collect_binding_alloc(void)
{
    yjit_runtime_counters.binding_allocations++;
}

void
rb_yjit_collect_binding_set(void)
{
    yjit_runtime_counters.binding_set++;
}

static const VALUE *
yjit_count_side_exit_op(const VALUE *exit_pc)
{
    int insn = rb_vm_insn_addr2opcode((const void *)*exit_pc);
    exit_op_count[insn]++;
    return exit_pc; // This function must return exit_pc!
}
*/