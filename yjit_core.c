// This file is a fragment of the yjit.o compilation unit. See yjit.c.
#include "internal.h"
#include "vm_sync.h"
#include "builtin.h"

#include "yjit.h"
#include "yjit_asm.h"
#include "yjit_iface.h"
#include "yjit_core.h"
#include "yjit_codegen.h"

// For exiting from YJIT frame from branch_stub_hit().
// Filled by gen_code_for_exit_from_stub().
static uint8_t *code_for_exit_from_stub = NULL;

static void yjit_free_block(block_t *block);

// Remove all references to a block then free it.
static void
yjit_free_block(block_t *block)
{
    /*
    yjit_unlink_method_lookup_dependency(block);
    yjit_block_assumptions_free(block);

    // Remove this block from the predecessor's targets
    rb_darray_for(block->incoming, incoming_idx) {
        // Branch from the predecessor to us
        branch_t *pred_branch = rb_darray_get(block->incoming, incoming_idx);

        // If this is us, nullify the target block
        for (size_t succ_idx = 0; succ_idx < 2; succ_idx++) {
            if (pred_branch->blocks[succ_idx] == block) {
                pred_branch->blocks[succ_idx] = NULL;
            }
        }
    }

    // For each outgoing branch
    rb_darray_for(block->outgoing, branch_idx) {
        branch_t *out_branch = rb_darray_get(block->outgoing, branch_idx);

        // For each successor block
        for (size_t succ_idx = 0; succ_idx < 2; succ_idx++) {
            block_t *succ = out_branch->blocks[succ_idx];

            if (succ == NULL)
                continue;

            // Remove this block from the successor's incoming list
            rb_darray_for(succ->incoming, incoming_idx) {
                branch_t *pred_branch = rb_darray_get(succ->incoming, incoming_idx);
                if (pred_branch == out_branch) {
                    rb_darray_remove_unordered(succ->incoming, incoming_idx);
                    break;
                }
            }
        }

        // Free the outgoing branch entry
        free(out_branch);
    }

    rb_darray_free(block->incoming);
    rb_darray_free(block->outgoing);
    rb_darray_free(block->gc_object_offsets);

    free(block);
    */
}

// Invalidate one specific block version
static void
invalidate_block_version(block_t *block)
{
    // TODO: take the VM lock and call into the Rust code here?

    /*
    ASSERT_vm_locking();

    // TODO: want to assert that all other ractors are stopped here. Can't patch
    // machine code that some other thread is running.

    verify_blockid(block->blockid);

    const rb_iseq_t *iseq = block->blockid.iseq;

    //fprintf(stderr, "invalidating block (%p, %d)\n", block->blockid.iseq, block->blockid.idx);
    //fprintf(stderr, "block=%p\n", block);

    // Remove this block from the version array
    rb_yjit_block_array_t versions = yjit_get_version_array(iseq, block->blockid.idx);
    block_array_remove(versions, block);

    // Get a pointer to the generated code for this block
    uint8_t *code_ptr = block->start_addr;

    // Make the the start of the block do an exit. This handles OOM situations
    // and some cases where we can't efficiently patch incoming branches.
    // Do this first, since in case there is a fallthrough branch into this
    // block, the patching loop below can overwrite the start of the block.
    // In those situations, there is hopefully no jumps to the start of the block
    // after patching as the start of the block would be in the middle of something
    // generated by branch_t::gen_fn.
    {
        RUBY_ASSERT_ALWAYS(block->entry_exit && "block invalidation requires an exit");
        if (block->entry_exit == block->start_addr) {
            // Some blocks exit on entry. Patching a jump to the entry at the
            // entry makes an infinite loop.
        }
        else if (block->start_addr >= cb_get_ptr(cb, yjit_codepage_frozen_bytes)) { // Don't patch frozen code region
            // Patch in a jump to block->entry_exit.
            uint32_t cur_pos = cb->write_pos;
            cb_set_write_ptr(cb, block->start_addr);
            jmp_ptr(cb, block->entry_exit);
            RUBY_ASSERT_ALWAYS(cb_get_ptr(cb, cb->write_pos) < block->end_addr && "invalidation wrote past end of block");
            cb_set_pos(cb, cur_pos);
        }
    }

    // For each incoming branch
    rb_darray_for(block->incoming, incoming_idx) {
        branch_t *branch = rb_darray_get(block->incoming, incoming_idx);
        uint32_t target_idx = (branch->dst_addrs[0] == code_ptr)? 0:1;
        RUBY_ASSERT(branch->dst_addrs[target_idx] == code_ptr);
        RUBY_ASSERT(branch->blocks[target_idx] == block);

        // Mark this target as being a stub
        branch->blocks[target_idx] = NULL;

        // Don't patch frozen code region
        if (branch->start_addr < cb_get_ptr(cb, yjit_codepage_frozen_bytes)) {
            continue;
        }

        // Create a stub for this branch target
        uint8_t *branch_target = get_branch_target(
            block->blockid,
            &block->ctx,
            branch,
            target_idx
        );

        if (!branch_target) {
            // We were unable to generate a stub (e.g. OOM). Use the block's
            // exit instead of a stub for the block. It's important that we
            // still patch the branch in this situation so stubs are unique
            // to branches. Think about what could go wrong if we run out of
            // memory in the middle of this loop.
            branch_target = block->entry_exit;
        }

        branch->dst_addrs[target_idx] = branch_target;

        // Check if the invalidated block immediately follows
        bool target_next = (block->start_addr == branch->end_addr);

        if (target_next) {
            // The new block will no longer be adjacent.
            // Note that we could be enlarging the branch and writing into the
            // start of the block being invalidated.
            branch->shape = SHAPE_DEFAULT;
        }

        // Rewrite the branch with the new jump target address
        regenerate_branch(cb, branch);

        if (target_next && branch->end_addr > block->end_addr) {
            fprintf(stderr, "branch_block_idx=%u block_idx=%u over=%ld block_size=%ld\n",
                branch->block->blockid.idx,
                block->blockid.idx,
                branch->end_addr - block->end_addr,
                block->end_addr - block->start_addr);
            //yjit_print_iseq(branch->block->blockid.iseq);
            rb_bug("yjit invalidate rewrote branch past end of invalidated block");
        }
    }

    // Clear out the JIT func so that we can recompile later and so the
    // interpreter will run the iseq

#if JIT_ENABLED
    // Only clear the jit_func when we're invalidating the JIT entry block.
    // We only support compiling iseqs from index 0 right now.  So entry
    // points will always have an instruction index of 0.  We'll need to
    // change this in the future when we support optional parameters because
    // they enter the function with a non-zero PC
    if (block->blockid.idx == 0) {
        iseq->body->jit_func = 0;
    }
#endif

    // TODO:
    // May want to recompile a new entry point (for interpreter entry blocks)
    // This isn't necessary for correctness

    // FIXME:
    // Call continuation addresses on the stack can also be atomically replaced by jumps going to the stub.

    yjit_free_block(block);

#if YJIT_STATS
    yjit_runtime_counters.invalidation_count++;
#endif

    cb_mark_all_executable(ocb);
    cb_mark_all_executable(cb);

    // fprintf(stderr, "invalidation done\n");
    */
}
