#[cfg(test)]

use crate::asm::x86_64::*;



/// just as a sandbox for playing around
#[test]
fn sandbox() {
}




/*
// Print the bytes in a code block
void print_bytes(codeblock_t* cb)
{
    for (uint32_t i = 0; i < cb->write_pos; ++i)
    {
        printf("%02X", (int)*cb_get_ptr(cb, i));
    }

    printf("\n");
}

// Check that the code block contains the given sequence of bytes
void check_bytes(codeblock_t* cb, const char* bytes)
{
    printf("checking encoding: %s\n", bytes);

    size_t len = strlen(bytes);
    assert (len % 2 == 0);
    size_t num_bytes = len / 2;

    if (cb->write_pos != num_bytes)
    {
        fprintf(stderr, "incorrect encoding length, expected %ld, got %d\n",
            num_bytes,
            cb->write_pos
        );
        printf("%s\n", bytes);
        print_bytes(cb);
        exit(-1);
    }

    for (uint32_t i = 0; i < num_bytes; ++i)
    {
        char byte_str[] = {0, 0, 0, 0};
        strncpy(byte_str, bytes + (2 * i), 2);
        char* endptr;
        long int byte = strtol(byte_str, &endptr, 16);

        uint8_t cb_byte = *cb_get_ptr(cb, i);

        if (cb_byte != byte)
        {
            fprintf(stderr, "incorrect encoding at position %d, expected %02X, got %02X\n",
                i,
                (int)byte,
                (int)cb_byte
            );
            printf("%s\n", bytes);
            print_bytes(cb);
            exit(-1);
        }
    }
}

void run_assembler_tests(void)
{
    printf("Running assembler tests\n");

    codeblock_t cb_obj;
    codeblock_t* cb = &cb_obj;
    uint8_t* mem_block = alloc_exec_mem(4096);
    cb_init(cb, mem_block, 4096);

    // add
    cb_set_pos(cb, 0); add(cb, CL, imm_opnd(3)); check_bytes(cb, "80C103");
    cb_set_pos(cb, 0); add(cb, CL, BL); check_bytes(cb, "00D9");
    cb_set_pos(cb, 0); add(cb, CL, SPL); check_bytes(cb, "4000E1");
    cb_set_pos(cb, 0); add(cb, CX, BX); check_bytes(cb, "6601D9");
    cb_set_pos(cb, 0); add(cb, RAX, RBX); check_bytes(cb, "4801D8");
    cb_set_pos(cb, 0); add(cb, ECX, EDX); check_bytes(cb, "01D1");
    cb_set_pos(cb, 0); add(cb, RDX, R14); check_bytes(cb, "4C01F2");
    cb_set_pos(cb, 0); add(cb, mem_opnd(64, RAX, 0), RDX); check_bytes(cb, "480110");
    cb_set_pos(cb, 0); add(cb, RDX, mem_opnd(64, RAX, 0)); check_bytes(cb, "480310");
    cb_set_pos(cb, 0); add(cb, RDX, mem_opnd(64, RAX, 8)); check_bytes(cb, "48035008");
    cb_set_pos(cb, 0); add(cb, RDX, mem_opnd(64, RAX, 255)); check_bytes(cb, "480390FF000000");
    cb_set_pos(cb, 0); add(cb, mem_opnd(64, RAX, 127), imm_opnd(255)); check_bytes(cb, "4881407FFF000000");
    cb_set_pos(cb, 0); add(cb, mem_opnd(32, RAX, 0), EDX); check_bytes(cb, "0110");
    cb_set_pos(cb, 0); add(cb, RSP, imm_opnd(8)); check_bytes(cb, "4883C408");
    cb_set_pos(cb, 0); add(cb, ECX, imm_opnd(8)); check_bytes(cb, "83C108");
    cb_set_pos(cb, 0); add(cb, ECX, imm_opnd(255)); check_bytes(cb, "81C1FF000000");

    // and
    cb_set_pos(cb, 0); and(cb, EBP, R12D); check_bytes(cb, "4421E5");
    cb_set_pos(cb, 0); and(cb, mem_opnd(64, RAX, 0), imm_opnd(0x08)); check_bytes(cb, "48832008");

    // call
    {
        cb_set_pos(cb, 0);
        uint32_t fn_label = cb_new_label(cb, "foo");
        call_label(cb, fn_label);
        cb_link_labels(cb);
        check_bytes(cb, "E8FBFFFFFF");
    }
    cb_set_pos(cb, 0); call(cb, RAX); check_bytes(cb, "FFD0");
    cb_set_pos(cb, 0); call(cb, mem_opnd(64, RSP, 8)); check_bytes(cb, "FF542408");

    // cmovcc
    cb_set_pos(cb, 0); cmovg(cb, ESI, EDI); check_bytes(cb, "0F4FF7");
    cb_set_pos(cb, 0); cmovg(cb, ESI, mem_opnd(32, RBP, 12)); check_bytes(cb, "0F4F750C");
    cb_set_pos(cb, 0); cmovl(cb, EAX, ECX); check_bytes(cb, "0F4CC1");
    cb_set_pos(cb, 0); cmovl(cb, RBX, RBP); check_bytes(cb, "480F4CDD");
    cb_set_pos(cb, 0); cmovle(cb, ESI, mem_opnd(32, RSP, 4)); check_bytes(cb, "0F4E742404");

    // cmp
    cb_set_pos(cb, 0); cmp(cb, CL, DL); check_bytes(cb, "38D1");
    cb_set_pos(cb, 0); cmp(cb, ECX, EDI); check_bytes(cb, "39F9");
    cb_set_pos(cb, 0); cmp(cb, RDX, mem_opnd(64, R12, 0)); check_bytes(cb, "493B1424");
    cb_set_pos(cb, 0); cmp(cb, RAX, imm_opnd(2)); check_bytes(cb, "4883F802");

    // cqo
    cb_set_pos(cb, 0); cqo(cb); check_bytes(cb, "4899");

    // div
    /*
    test(
        delegate void (CodeBlock cb) { cb.div(X86Opnd(EDX)); },
        "F7F2"
    );
    test(
        delegate void (CodeBlock cb) { cb.div(X86Opnd(32, RSP, -12)); },
        "F77424F4"
    );
    */

    // jcc to label
    {
        cb_set_pos(cb, 0);
        uint32_t loop_label = cb_new_label(cb, "loop");
        jge_label(cb, loop_label);
        cb_link_labels(cb);
        check_bytes(cb, "0F8DFAFFFFFF");
    }
    {
        cb_set_pos(cb, 0);
        uint32_t loop_label = cb_new_label(cb, "loop");
        jo_label(cb, loop_label);
        cb_link_labels(cb);
        check_bytes(cb, "0F80FAFFFFFF");
    }

    // jmp to label
    {
        cb_set_pos(cb, 0);
        uint32_t loop_label = cb_new_label(cb, "loop");
        jmp_label(cb, loop_label);
        cb_link_labels(cb);
        check_bytes(cb, "E9FBFFFFFF");
    }

    // jmp with RM operand
    cb_set_pos(cb, 0); jmp_rm(cb, R12); check_bytes(cb, "41FFE4");

    // lea
    cb_set_pos(cb, 0); lea(cb, RDX, mem_opnd(64, RCX, 8)); check_bytes(cb, "488D5108");
    cb_set_pos(cb, 0); lea(cb, RAX, mem_opnd(8, RIP, 0)); check_bytes(cb, "488D0500000000");
    cb_set_pos(cb, 0); lea(cb, RAX, mem_opnd(8, RIP, 5)); check_bytes(cb, "488D0505000000");
    cb_set_pos(cb, 0); lea(cb, RDI, mem_opnd(8, RIP, 5)); check_bytes(cb, "488D3D05000000");

    // mov
    cb_set_pos(cb, 0); mov(cb, EAX, imm_opnd(7)); check_bytes(cb, "B807000000");
    cb_set_pos(cb, 0); mov(cb, EAX, imm_opnd(-3)); check_bytes(cb, "B8FDFFFFFF");
    cb_set_pos(cb, 0); mov(cb, R15, imm_opnd(3)); check_bytes(cb, "41BF03000000");
    cb_set_pos(cb, 0); mov(cb, EAX, EBX); check_bytes(cb, "89D8");
    cb_set_pos(cb, 0); mov(cb, EAX, ECX); check_bytes(cb, "89C8");
    cb_set_pos(cb, 0); mov(cb, EDX, mem_opnd(32, RBX, 128)); check_bytes(cb, "8B9380000000");

    // Test `mov rax, 3` => `mov eax, 3` optimization
    cb_set_pos(cb, 0); mov(cb, R8, imm_opnd(0x34)); check_bytes(cb, "41B834000000");
    cb_set_pos(cb, 0); mov(cb, R8, imm_opnd(0x80000000)); check_bytes(cb, "49B80000008000000000");
    cb_set_pos(cb, 0); mov(cb, R8, imm_opnd(-1)); check_bytes(cb, "49B8FFFFFFFFFFFFFFFF");

    cb_set_pos(cb, 0); mov(cb, RAX, imm_opnd(0x34)); check_bytes(cb, "B834000000");
    cb_set_pos(cb, 0); mov(cb, RAX, imm_opnd(0x80000000)); check_bytes(cb, "48B80000008000000000");
    cb_set_pos(cb, 0); mov(cb, RAX, imm_opnd(-52)); check_bytes(cb, "48B8CCFFFFFFFFFFFFFF");
    cb_set_pos(cb, 0); mov(cb, RAX, imm_opnd(-1)); check_bytes(cb, "48B8FFFFFFFFFFFFFFFF");
    /*
    test(
        delegate void (CodeBlock cb) { cb.mov(X86Opnd(AL), X86Opnd(8, RCX, 0, 1, RDX)); },
        "8A0411"
    );
    */
    cb_set_pos(cb, 0); mov(cb, CL, R9B); check_bytes(cb, "4488C9");
    cb_set_pos(cb, 0); mov(cb, RBX, RAX); check_bytes(cb, "4889C3");
    cb_set_pos(cb, 0); mov(cb, RDI, RBX); check_bytes(cb, "4889DF");
    cb_set_pos(cb, 0); mov(cb, SIL, imm_opnd(11)); check_bytes(cb, "40B60B");
    cb_set_pos(cb, 0); mov(cb, mem_opnd(8, RSP, 0), imm_opnd(-3)); check_bytes(cb, "C60424FD");
    cb_set_pos(cb, 0); mov(cb, mem_opnd(64, RDI, 8), imm_opnd(1)); check_bytes(cb, "48C7470801000000");

    // movsx
    cb_set_pos(cb, 0); movsx(cb, AX, AL); check_bytes(cb, "660FBEC0");
    cb_set_pos(cb, 0); movsx(cb, EDX, AL); check_bytes(cb, "0FBED0");
    cb_set_pos(cb, 0); movsx(cb, RAX, BL); check_bytes(cb, "480FBEC3");
    cb_set_pos(cb, 0); movsx(cb, ECX, AX); check_bytes(cb, "0FBFC8");
    cb_set_pos(cb, 0); movsx(cb, R11, CL); check_bytes(cb, "4C0FBED9");
    cb_set_pos(cb, 0); movsx(cb, R10, mem_opnd(32, RSP, 12)); check_bytes(cb, "4C6354240C");
    cb_set_pos(cb, 0); movsx(cb, RAX, mem_opnd(8, RSP, 0)); check_bytes(cb, "480FBE0424");

    // neg
    cb_set_pos(cb, 0); neg(cb, RAX); check_bytes(cb, "48F7D8");

    // nop
    cb_set_pos(cb, 0); nop(cb, 1); check_bytes(cb, "90");

    // not
    cb_set_pos(cb, 0); not(cb, AX); check_bytes(cb, "66F7D0");
    cb_set_pos(cb, 0); not(cb, EAX); check_bytes(cb, "F7D0");
    cb_set_pos(cb, 0); not(cb, mem_opnd(64, R12, 0)); check_bytes(cb, "49F71424");
    cb_set_pos(cb, 0); not(cb, mem_opnd(32, RSP, 301)); check_bytes(cb, "F794242D010000");
    cb_set_pos(cb, 0); not(cb, mem_opnd(32, RSP, 0)); check_bytes(cb, "F71424");
    cb_set_pos(cb, 0); not(cb, mem_opnd(32, RSP, 3)); check_bytes(cb, "F7542403");
    cb_set_pos(cb, 0); not(cb, mem_opnd(32, RBP, 0)); check_bytes(cb, "F75500");
    cb_set_pos(cb, 0); not(cb, mem_opnd(32, RBP, 13)); check_bytes(cb, "F7550D");
    cb_set_pos(cb, 0); not(cb, RAX); check_bytes(cb, "48F7D0");
    cb_set_pos(cb, 0); not(cb, R11); check_bytes(cb, "49F7D3");
    cb_set_pos(cb, 0); not(cb, mem_opnd(32, RAX, 0)); check_bytes(cb, "F710");
    cb_set_pos(cb, 0); not(cb, mem_opnd(32, RSI, 0)); check_bytes(cb, "F716");
    cb_set_pos(cb, 0); not(cb, mem_opnd(32, RDI, 0)); check_bytes(cb, "F717");
    cb_set_pos(cb, 0); not(cb, mem_opnd(32, RDX, 55)); check_bytes(cb, "F75237");
    cb_set_pos(cb, 0); not(cb, mem_opnd(32, RDX, 1337)); check_bytes(cb, "F79239050000");
    cb_set_pos(cb, 0); not(cb, mem_opnd(32, RDX, -55)); check_bytes(cb, "F752C9");
    cb_set_pos(cb, 0); not(cb, mem_opnd(32, RDX, -555)); check_bytes(cb, "F792D5FDFFFF");
    /*
    test(
        delegate void (CodeBlock cb) { cb.not(X86Opnd(32, RAX, 0, 1, RBX)); },
        "F71418"
    );
    test(
        delegate void (CodeBlock cb) { cb.not(X86Opnd(32, RAX, 0, 1, R12)); },
        "42F71420"
    );
    test(
        delegate void (CodeBlock cb) { cb.not(X86Opnd(32, R15, 0, 1, R12)); },
        "43F71427"
    );
    test(
        delegate void (CodeBlock cb) { cb.not(X86Opnd(32, R15, 5, 1, R12)); },
        "43F7542705"
    );
    test(
        delegate void (CodeBlock cb) { cb.not(X86Opnd(32, R15, 5, 8, R12)); },
        "43F754E705"
    );
    test(
        delegate void (CodeBlock cb) { cb.not(X86Opnd(32, R15, 5, 8, R13)); },
        "43F754EF05"
    );
    test(
        delegate void (CodeBlock cb) { cb.not(X86Opnd(32, R12, 5, 4, R9)); },
        "43F7548C05"
    );
    test(
        delegate void (CodeBlock cb) { cb.not(X86Opnd(32, R12, 301, 4, R9)); },
        "43F7948C2D010000"
    );
    test(
        delegate void (CodeBlock cb) { cb.not(X86Opnd(32, RAX, 5, 4, RDX)); },
        "F7549005"
    );
    test(
        delegate void (CodeBlock cb) { cb.not(X86Opnd(64, RAX, 0, 2, RDX)); },
        "48F71450"
    );
    test(
        delegate void (CodeBlock cb) { cb.not(X86Opnd(32, RSP, 0, 1, RBX)); },
        "F7141C"
    );
    test(
        delegate void (CodeBlock cb) { cb.not(X86Opnd(32, RSP, 3, 1, RBX)); },
        "F7541C03"
    );
    test(
        delegate void (CodeBlock cb) { cb.not(X86Opnd(32, RBP, 13, 1, RDX)); },
        "F754150D"
    );
    */

    // or
    cb_set_pos(cb, 0); or(cb, EDX, ESI); check_bytes(cb, "09F2");

    // pop
    cb_set_pos(cb, 0); pop(cb, RAX); check_bytes(cb, "58");
    cb_set_pos(cb, 0); pop(cb, RBX); check_bytes(cb, "5B");
    cb_set_pos(cb, 0); pop(cb, RSP); check_bytes(cb, "5C");
    cb_set_pos(cb, 0); pop(cb, RBP); check_bytes(cb, "5D");
    cb_set_pos(cb, 0); pop(cb, R12); check_bytes(cb, "415C");
    cb_set_pos(cb, 0); pop(cb, mem_opnd(64, RAX, 0)); check_bytes(cb, "8F00");
    cb_set_pos(cb, 0); pop(cb, mem_opnd(64, R8, 0)); check_bytes(cb, "418F00");
    cb_set_pos(cb, 0); pop(cb, mem_opnd(64, R8, 3)); check_bytes(cb, "418F4003");
    cb_set_pos(cb, 0); pop(cb, mem_opnd_sib(64, RAX, RCX, 8, 3)); check_bytes(cb, "8F44C803");
    cb_set_pos(cb, 0); pop(cb, mem_opnd_sib(64, R8, RCX, 8, 3)); check_bytes(cb, "418F44C803");

    // push
    cb_set_pos(cb, 0); push(cb, RAX); check_bytes(cb, "50");
    cb_set_pos(cb, 0); push(cb, RBX); check_bytes(cb, "53");
    cb_set_pos(cb, 0); push(cb, R12); check_bytes(cb, "4154");
    cb_set_pos(cb, 0); push(cb, mem_opnd(64, RAX, 0)); check_bytes(cb, "FF30");
    cb_set_pos(cb, 0); push(cb, mem_opnd(64, R8, 0)); check_bytes(cb, "41FF30");
    cb_set_pos(cb, 0); push(cb, mem_opnd(64, R8, 3)); check_bytes(cb, "41FF7003");
    cb_set_pos(cb, 0); push(cb, mem_opnd_sib(64, RAX, RCX, 8, 3)); check_bytes(cb, "FF74C803");
    cb_set_pos(cb, 0); push(cb, mem_opnd_sib(64, R8, RCX, 8, 3)); check_bytes(cb, "41FF74C803");

    // ret
    cb_set_pos(cb, 0); ret(cb); check_bytes(cb, "C3");

    // sal
    cb_set_pos(cb, 0); sal(cb, CX, imm_opnd(1)); check_bytes(cb, "66D1E1");
    cb_set_pos(cb, 0); sal(cb, ECX, imm_opnd(1)); check_bytes(cb, "D1E1");
    cb_set_pos(cb, 0); sal(cb, EBP, imm_opnd(5)); check_bytes(cb, "C1E505");
    cb_set_pos(cb, 0); sal(cb, mem_opnd(32, RSP, 68), imm_opnd(1)); check_bytes(cb, "D1642444");

    // sar
    cb_set_pos(cb, 0); sar(cb, EDX, imm_opnd(1)); check_bytes(cb, "D1FA");

    // shr
    cb_set_pos(cb, 0); shr(cb, R14, imm_opnd(7)); check_bytes(cb, "49C1EE07");

    /*
    // sqrtsd
    test(
        delegate void (CodeBlock cb) { cb.sqrtsd(X86Opnd(XMM2), X86Opnd(XMM6)); },
        "F20F51D6"
    );
    */

    // sub
    cb_set_pos(cb, 0); sub(cb, EAX, imm_opnd(1)); check_bytes(cb, "83E801");
    cb_set_pos(cb, 0); sub(cb, RAX, imm_opnd(2)); check_bytes(cb, "4883E802");

    // test
    cb_set_pos(cb, 0); test(cb, AL, AL); check_bytes(cb, "84C0");
    cb_set_pos(cb, 0); test(cb, AX, AX); check_bytes(cb, "6685C0");
    cb_set_pos(cb, 0); test(cb, CL, imm_opnd(8)); check_bytes(cb, "F6C108");
    cb_set_pos(cb, 0); test(cb, DL, imm_opnd(7)); check_bytes(cb, "F6C207");
    cb_set_pos(cb, 0); test(cb, RCX, imm_opnd(8)); check_bytes(cb, "F6C108");
    cb_set_pos(cb, 0); test(cb, mem_opnd(8, RDX, 8), imm_opnd(8)); check_bytes(cb, "F6420808");
    cb_set_pos(cb, 0); test(cb, mem_opnd(8, RDX, 8), imm_opnd(255)); check_bytes(cb, "F64208FF");
    cb_set_pos(cb, 0); test(cb, DX, imm_opnd(0xFFFF)); check_bytes(cb, "66F7C2FFFF");
    cb_set_pos(cb, 0); test(cb, mem_opnd(16, RDX, 8), imm_opnd(0xFFFF)); check_bytes(cb, "66F74208FFFF");
    cb_set_pos(cb, 0); test(cb, mem_opnd(8, RSI, 0), imm_opnd(1)); check_bytes(cb, "F60601");
    cb_set_pos(cb, 0); test(cb, mem_opnd(8, RSI, 16), imm_opnd(1)); check_bytes(cb, "F6461001");
    cb_set_pos(cb, 0); test(cb, mem_opnd(8, RSI, -16), imm_opnd(1)); check_bytes(cb, "F646F001");
    cb_set_pos(cb, 0); test(cb, mem_opnd(32, RSI, 64), EAX); check_bytes(cb, "854640");
    cb_set_pos(cb, 0); test(cb, mem_opnd(64, RDI, 42), RAX); check_bytes(cb, "4885472A");
    cb_set_pos(cb, 0); test(cb, RAX, RAX); check_bytes(cb, "4885C0");
    cb_set_pos(cb, 0); test(cb, RAX, RSI); check_bytes(cb, "4885F0");
    cb_set_pos(cb, 0); test(cb, mem_opnd(64, RSI, 64), imm_opnd(~0x08)); check_bytes(cb, "48F74640F7FFFFFF");

    // xchg
    cb_set_pos(cb, 0); xchg(cb, RAX, RCX); check_bytes(cb, "4891");
    cb_set_pos(cb, 0); xchg(cb, RAX, R13); check_bytes(cb, "4995");
    cb_set_pos(cb, 0); xchg(cb, RCX, RBX); check_bytes(cb, "4887D9");
    cb_set_pos(cb, 0); xchg(cb, R9, R15); check_bytes(cb, "4D87F9");

    // xor
    cb_set_pos(cb, 0); xor(cb, EAX, EAX); check_bytes(cb, "31C0");

    printf("Assembler tests done\n");
}
*/

/*
void assert_equal(int expected, int actual)
{
    if (expected != actual) {
        fprintf(stderr, "expected %d, got %d\n", expected, actual);
        exit(-1);
    }
}

void run_runtime_tests(void)
{
    printf("Running runtime tests\n");

    codeblock_t codeblock;
    codeblock_t* cb = &codeblock;

    uint8_t* mem_block = alloc_exec_mem(4096);
    cb_init(cb, mem_block, 4096);

    int (*function)(void);
    function = (int (*)(void))mem_block;

    #define TEST(BODY) cb_set_pos(cb, 0); BODY ret(cb); cb_mark_all_executable(cb); assert_equal(7, function());

    // add
    TEST({ mov(cb, RAX, imm_opnd(0)); add(cb, RAX, imm_opnd(7)); })
    TEST({ mov(cb, RAX, imm_opnd(0)); mov(cb, RCX, imm_opnd(7)); add(cb, RAX, RCX); })

    // and
    TEST({ mov(cb, RAX, imm_opnd(31)); and(cb, RAX, imm_opnd(7)); })
    TEST({ mov(cb, RAX, imm_opnd(31)); mov(cb, RCX, imm_opnd(7)); and(cb, RAX, RCX); })

    // or
    TEST({ mov(cb, RAX, imm_opnd(3)); or(cb, RAX, imm_opnd(4)); })
    TEST({ mov(cb, RAX, imm_opnd(3)); mov(cb, RCX, imm_opnd(4)); or(cb, RAX, RCX); })

    // push/pop
    TEST({ mov(cb, RCX, imm_opnd(7)); push(cb, RCX); pop(cb, RAX); })

    // shr
    TEST({ mov(cb, RAX, imm_opnd(31)); shr(cb, RAX, imm_opnd(2)); })

    // sub
    TEST({ mov(cb, RAX, imm_opnd(12)); sub(cb, RAX, imm_opnd(5)); })
    TEST({ mov(cb, RAX, imm_opnd(12)); mov(cb, RCX, imm_opnd(5)); sub(cb, RAX, RCX); })

    // xor
    TEST({ mov(cb, RAX, imm_opnd(13)); xor(cb, RAX, imm_opnd(10)); })
    TEST({ mov(cb, RAX, imm_opnd(13)); mov(cb, RCX, imm_opnd(10)); xor(cb, RAX, RCX); })

    #undef TEST

    printf("Runtime tests done\n");
}

int main(int argc, char** argv)
{
    run_assembler_tests();
    run_runtime_tests();

    return 0;
}
*/

















#[test]
#[cfg(feature = "disassembly")]
fn basic_capstone_usage() -> Result<(), capstone::Error> {
    // Test drive Capstone with simple input
    extern crate capstone;
    use capstone::prelude::*;
    let cs = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64)
        .syntax(arch::x86::ArchSyntax::Intel)
        .build()?;

    let insns = cs.disasm_all(&[0xCC], 0x1000)?;

    match insns.as_ref() {
        [insn] => {
            assert_eq!(Some("int3"), insn.mnemonic());
            Ok(())
        }
        _ => Err(capstone::Error::CustomError(
            "expected to disassemble to int3",
        )),
    }
}



/*
#[cfg(test)]
mod tests {
    use crate::asm::x64::*;

    impl Assembler {
        fn byte_string(&self) -> String {
            self.encoded()
                .into_iter()
                .map(|byte| format!("{:02x}", byte))
                .collect::<Vec<_>>()
                .join(" ")
        }
    }

    macro_rules! test_encoding {
        ($bytes:literal $($disasm:literal, $mnemonic:ident ($args:expr))+) => {{
            let mut asm = Assembler::new();

            $( asm.$mnemonic($args); )*

            assert_eq!($bytes, asm.byte_string());

            // In case we have a disassembler, compare against a disassembly expectation
            #[cfg(feature = "disassembly")]
            {
                extern crate capstone;
                use capstone::prelude::*;
                let cs = Capstone::new()
                    .x86()
                    .mode(arch::x86::ArchMode::Mode64)
                    .syntax(arch::x86::ArchSyntax::Intel)
                    .build()
                    .expect("Failed to create Capstone object");

                let insns = cs
                    .disasm_all(asm.encoded(), 0x1000)
                    .expect("Failed to disassemble");

                let mut insn_idx = 0;
                $(
                    match insns.as_ref().get(insn_idx).map(|insn| (insn.mnemonic(), insn.op_str())) {
                        Some((Some(mnemonic), op_str)) => {
                            let mut capstone_disasm = mnemonic.to_owned();
                            if let Some(op_str) = op_str {
                                capstone_disasm.push_str(" ");
                                capstone_disasm.push_str(op_str);
                            }
                            assert_eq!($disasm, capstone_disasm, "instruction_index={}", insn_idx);
                        },
                        _ => panic!("Failed to disassemble to a instruction at instruction_index={}", insn_idx),
                    };
                    insn_idx += 1;
                    let _ = insn_idx; // Address unused warning from the last iteration
                )*

            }
        }};
    }

    /*
    #[test]
    fn reg_to_reg_movs() {
        let mut asm = Assembler::new();

        // 64b
        asm.mov(RAX.into(), RBX.into());
        asm.mov(R8.into(), RBX.into());
        asm.mov(RDI.into(), R14.into());
        asm.mov(R13.into(), R15.into());

        // 32b
        asm.mov(EBP.into(), EDI.into());
        asm.mov(R8D.into(), EBX.into());
        asm.mov(EBP.into(), R9D.into());
        asm.mov(R8D.into(), R11D.into());

        // 16b (panics at the moment)
        // asm.mov(AX.into(), CX.into());

        let bytes = asm.byte_string();
        assert_eq!(
            "48 8b c3 4c 8b c3 49 8b fe 4d 8b ef 8b ef 44 8b c3 41 8b e9 45 8b c3",
            bytes
        );
    }

    #[test]
    fn sar() {
        let mut asm = Assembler::new();

        // 64b
        asm.sar(RAX.into(), 1.into());
        asm.sar(R9.into(), 1.into());

        // 32b
        asm.sar(RDI.into(), 1.into());
        asm.sar(R10D.into(), 1.into());

        // TODO: write panic tests

        assert_eq!("48 d1 f8 49 d1 f9 48 d1 ff 41 d1 fa", asm.byte_string());
    }
    */

    #[test]
    fn shl_and_sal() {
        test_encoding!(
            "48 c1 e0 02 48 d1 e1 49 d1 e7 49 c1 e3 03 49 d1 e4 49 c1 e4 02 49 d1 e5 49 c1 e5 03"
            "shl rax, 2",  shl((RAX, 2))
            "shl rcx, 1",  shl((RCX, 1))

            "shl r15, 1",  shl((R15, 1))
            "shl r11, 3",  shl((R11, 3))

            "shl r12, 1",  shl((R12, 1))
            "shl r12, 2",  shl((R12, 2))

            "shl r13, 1",  shl((R13, 1))
            "shl r13, 3",  shl((R13, 3))
        );
    }

    #[test]
    fn test() {
        // reg64, imm32
        test_encoding!(
            "48 a9 ff ff ff 7f 49 f7 c3 fe ca ab 0f 48 f7 c7 02 35 54 f0 49 f7 c0 ff ff ff ff"
            "test rax, 0x7fffffff",  test((RAX, i32::MAX))
            "test r11, 0xfabcafe",   test((R11, 0xFABCAFE))
            "test rdi, -0xfabcafe",  test((RDI, -0xFABCAFE))
            "test r8, -1",           test((R8, -1))
        );

        // reg32, imm32
        test_encoding!(
            "f7 c7 ff ff ff ff 41 f7 c1 fe ca ab 0f f7 c7 ef be ad de 41 f7 c1 ff ff ff ff"
            "test edi, 0xffffffff", test((EDI, u32::MAX))
            "test r9d, 0xfabcafe", test((R9D, 0xFABCAFE))
            "test edi, 0xdeadbeef", test((EDI, 0xDEADBEEF))
            "test r9d, 0xffffffff", test((R9D, u32::MAX))
        );

        // reg64, reg64
        test_encoding!(
            "48 85 d0 4c 85 d9 49 85 dc 4d 85 f7"
            "test rax, rdx", test((RAX, RDX))
            "test rcx, r11", test((RCX, R11))
            "test r12, rbx", test((R12, RBX))
            "test r15, r14", test((R15, R14))
        );

        // reg32, reg32
        test_encoding!(
            "85 d0 44 85 d9 41 85 dc 45 85 f7"
            "test eax, edx", test((EAX, EDX))
            "test ecx, r11d", test((ECX, R11D))
            "test r12d, ebx", test((R12D, EBX))
            "test r15d, r14d", test((R15D, R14D))
        )

        // TODO: write panic tests
    }

    #[test]
    fn test_rmm_r() {
        test_encoding!(
            "48 85 40 80"
            "test qword ptr [rax - 0x80], rax",
            test((mem64(RAX, i8::MIN.into()), RAX))
        );

        test_encoding!(
            "49 85 44 24 80"
            "test qword ptr [r12 - 0x80], rax",
            test((mem64(R12, i8::MIN.into()), RAX))
        );

        test_encoding!(
            "4d 85 6d 80"
            "test qword ptr [r13 - 0x80], r13",
            test((mem64(R13, i8::MIN.into()), R13))
        );

        // FIXME: Buggy encoding. These registers require a REX prefix.
        test_encoding!(
            "84 f0 84 f8 84 e8 84 e0"
            "test al, sil", test((AL, SIL))
            "test al, dil", test((AL, DIL))
            "test al, bpl", test((AL, BPL))
            "test al, spl", test((AL, SPL))
        );
    }

    #[test]
    fn test_with_memory() {
        test_encoding!(
            "48 f7 40 80 ff ff ff 7f"
            "test qword ptr [rax - 0x80], 0x7fffffff",
            test((mem64(RAX, i8::MIN.into()), i32::MAX))
        );

        test_encoding!(
            "49 f7 45 7f ff ff ff 7f"
            "test qword ptr [r13 + 0x7f], 0x7fffffff",
            test((mem64(R13, i8::MAX.into()), i32::MAX))
        );

        test_encoding!(
            "48 f7 44 24 80 00 00 00 80"
            "test qword ptr [rsp - 0x80], -0x80000000",
            test((mem64(RSP, i8::MIN.into()), i32::MIN))
        );

        // RSP, RBP, R12 and R13 are special because the lower part of their regiser id
        // are escape codes in the ModR/M byte.
        test_encoding!(
            "48 f7 04 24 ff ff ff 7f 49 f7 04 24 00 00 00 80 \
             48 f7 45 00 ff ff ff 7f 49 f7 45 00 00 00 00 80"

            "test qword ptr [rsp], 0x7fffffff", test((mem64(RSP, 0), i32::MAX))
            "test qword ptr [r12], -0x80000000", test((mem64(R12, 0), i32::MIN))

            "test qword ptr [rbp], 0x7fffffff", test((mem64(RBP, 0), i32::MAX))
            "test qword ptr [r13], -0x80000000", test((mem64(R13, 0), i32::MIN))
        );

        test_encoding!(
            "49 f7 84 24 80 00 00 00 01 00 00 00"
            "test qword ptr [r12 + 0x80], 1",
            test((mem64(R12, 1 + i32::from(i8::MAX)), 1))
        );

        test_encoding!(
            "48 f7 84 24 7f ff ff ff fe ca ab 0f"
            "test qword ptr [rsp - 0x81], 0xfabcafe",
            test((mem64(RSP, i32::from(i8::MIN) - 1), 0xfabcafe))
        );
    }

    #[test]
    fn push() {
        test_encoding!(
            "50 41 54 41 55"
            "push rax", push(RAX)
            "push r12", push(R12)
            "push r13", push(R13)
        );
    }

    #[test]
    fn pop() {
        test_encoding!(
            "58 41 5c 41 5d"
            "pop rax", pop(RAX)
            "pop r12", pop(R12)
            "pop r13", pop(R13)
        );
    }

    #[test]
    fn randoms() {
        test_encoding!(
            "ff e0 41 ff e0 ff 21 41 ff 63 f6"
            "jmp rax", jmp(RAX)
            "jmp r8", jmp(R8)
            "jmp qword ptr [rcx]", jmp(mem64(RCX, 0))
            "jmp qword ptr [r11 - 0xa]", jmp(mem64(R11, -0xa))
        );

        test_encoding!(
            "f6 d0 f7 d0 48 f7 d0 49 f7 d0"
            "not al", not(AL)
            "not eax", not(EAX)
            "not rax", not(RAX)
            "not r8", not(R8)
        );

        test_encoding!(
            "ff d0 41 ff d0 ff 11 41 ff 53 f6"
            "call rax", call(RAX)
            "call r8", call(R8)
            "call qword ptr [rcx]", call(mem64(RCX, 0))
            "call qword ptr [r11 - 0xa]", call(mem64(R11, -0xa))
        );
    }

    #[test]
    fn mov() {
        test_encoding!(
            "b0 00 b8 fe ca ab 0f 41 b8 fe ca ab 0f 48 b8 ff ff ff ff ff ff ff ff 49 bf 00 00 00 00 01 00 00 00"
            "mov al, 0", mov((AL, 0))
            "mov eax, 0xfabcafe", mov((EAX, 0xfabcafe))
            "mov r8d, 0xfabcafe", mov((R8D, 0xfabcafe))
            "movabs rax, 0xffffffffffffffff", mov((RAX, u64::MAX))
            "movabs r15, 0x100000000", mov((R15, u64::from(u32::MAX)+1))
        );
    }

    #[test]
    fn mov_load_8b() {
        test_encoding!(
            "45 88 bf 00 ff ff ff"

            "mov byte ptr [r15 - 0x100], r15b", mov((mem8(R15, -0x100), R15B))
        );
    }

    #[test]
    #[cfg(feature = "disassembly")]
    fn basic_capstone_usage() -> Result<(), capstone::Error> {
        // Test drive Capstone with simple input
        extern crate capstone;
        use capstone::prelude::*;
        let cs = Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .syntax(arch::x86::ArchSyntax::Intel)
            .build()?;

        let insns = cs.disasm_all(&[0xCC], 0x1000)?;

        match insns.as_ref() {
            [insn] => {
                assert_eq!(Some("int3"), insn.mnemonic());
                Ok(())
            }
            _ => Err(capstone::Error::CustomError(
                "expected to disassemble to int3",
            )),
        }
    }
}
*/