/*
// Align the current write position to a multiple of bytes
static uint8_t *align_ptr(uint8_t *ptr, uint32_t multiple)
{
    // Compute the pointer modulo the given alignment boundary
    uint32_t rem = ((uint32_t)(uintptr_t)ptr) % multiple;

    // If the pointer is already aligned, stop
    if (rem == 0)
        return ptr;

    // Pad the pointer by the necessary amount to align it
    uint32_t pad = multiple - rem;

    return ptr + pad;
}
*/

/*
// For debugging. Print the disassembly of an iseq.
RBIMPL_ATTR_MAYBE_UNUSED()
static void
yjit_print_iseq(const rb_iseq_t *iseq)
{
    char *ptr;
    long len;
    VALUE disassembly = rb_iseq_disasm(iseq);
    RSTRING_GETMEM(disassembly, ptr, len);
    fprintf(stderr, "%.*s\n", (int)len, ptr);
}
*/

/*
// Save caller-save registers on the stack before a C call
static void
push_regs(codeblock_t *cb)
{
    push(cb, RAX);
    push(cb, RCX);
    push(cb, RDX);
    push(cb, RSI);
    push(cb, RDI);
    push(cb, R8);
    push(cb, R9);
    push(cb, R10);
    push(cb, R11);
    pushfq(cb);
}

// Restore caller-save registers from the after a C call
static void
pop_regs(codeblock_t *cb)
{
    popfq(cb);
    pop(cb, R11);
    pop(cb, R10);
    pop(cb, R9);
    pop(cb, R8);
    pop(cb, RDI);
    pop(cb, RSI);
    pop(cb, RDX);
    pop(cb, RCX);
    pop(cb, RAX);
}

static void
print_int_cfun(int64_t val)
{
    fprintf(stderr, "%lld\n", (long long int)val);
}

RBIMPL_ATTR_MAYBE_UNUSED()
static void
print_int(codeblock_t *cb, x86opnd_t opnd)
{
    push_regs(cb);

    if (opnd.num_bits < 64 && opnd.type != OPND_IMM)
        movsx(cb, RDI, opnd);
    else
        mov(cb, RDI, opnd);

    // Call the print function
    mov(cb, RAX, const_ptr_opnd((void*)&print_int_cfun));
    call(cb, RAX);

    pop_regs(cb);
}

static void
print_ptr_cfun(void *val)
{
    fprintf(stderr, "%p\n", val);
}

RBIMPL_ATTR_MAYBE_UNUSED()
static void
print_ptr(codeblock_t *cb, x86opnd_t opnd)
{
    assert (opnd.num_bits == 64);

    push_regs(cb);

    mov(cb, RDI, opnd);
    mov(cb, RAX, const_ptr_opnd((void*)&print_ptr_cfun));
    call(cb, RAX);

    pop_regs(cb);
}

static void
print_str_cfun(const char *str)
{
    fprintf(stderr, "%s\n", str);
}

// Print a constant string to stdout
static void
print_str(codeblock_t *cb, const char *str)
{
    //as.comment("printStr(\"" ~ str ~ "\")");
    size_t len = strlen(str);

    push_regs(cb);

    // Load the string address and jump over the string data
    lea(cb, RDI, mem_opnd(8, RIP, 5));
    jmp32(cb, (int32_t)len + 1);

    // Write the string chars and a null terminator
    for (size_t i = 0; i < len; ++i)
        cb_write_byte(cb, (uint8_t)str[i]);
    cb_write_byte(cb, 0);

    // Call the print function
    mov(cb, RAX, const_ptr_opnd((void*)&print_str_cfun));
    call(cb, RAX);

    pop_regs(cb);
}
*/

// TODO: maybe add some tests of the utils functions here?