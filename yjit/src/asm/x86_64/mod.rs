// Reference to an ASM label
struct LabelRef
{
    // Position in the code block where the label reference exists
    pos: usize,

    // Label which this refers to
    label_idx: usize,
}

/*
// Block of executable memory into which instructions can be written
typedef struct CodeBlock
{
    // Memory block
    // Users are advised to not use this directly.
    uint8_t *mem_block_;

    // Memory block size
    uint32_t mem_size;

    // Current writing position
    uint32_t write_pos;

    // Table of registered label addresses
    uint32_t label_addrs[MAX_LABELS];

    // Table of registered label names
    // Note that these should be constant strings only
    const char *label_names[MAX_LABELS];

    // References to labels
    labelref_t label_refs[MAX_LABEL_REFS];

    // Number of labels registeered
    uint32_t num_labels;

    // Number of references to labels
    uint32_t num_refs;


    // Keep track of the current aligned write position.
    // Used for changing protection when writing to the JIT buffer
    uint32_t current_aligned_write_pos;

    // Set if the assembler is unable to output some instructions,
    // for example, when there is not enough space or when a jump
    // target is too far away.
    bool dropped_bytes;

    // Flag to enable or disable comments
    bool has_asm;


} codeblock_t;

// 1 is not aligned so this won't match any pages
#define ALIGNED_WRITE_POSITION_NONE 1

enum OpndType
{
    OPND_NONE,
    OPND_REG,
    OPND_IMM,
    OPND_MEM
};

enum RegType
{
    REG_GP,
    REG_FP,
    REG_XMM,
    REG_IP
};

typedef struct X86Reg
{
    // Register type
    uint8_t reg_type;

    // Register index number
    uint8_t reg_no;

} x86reg_t;

typedef struct X86Mem
{
    /// Base register number
    uint8_t base_reg_no;

    /// Index register number
    uint8_t idx_reg_no;

    /// SIB scale exponent value (power of two, two bits)
    uint8_t scale_exp;

    /// Has index register flag
    bool has_idx;

    // TODO: should this be here, or should we have an extra operand type?
    /// IP-relative addressing flag
    bool is_iprel;

    /// Constant displacement from the base, not scaled
    int32_t disp;

} x86mem_t;

typedef struct X86Opnd
{
    // Operand type
    uint8_t type;

    // Size in bits
    uint16_t num_bits;

    union
    {
        // Register operand
        x86reg_t reg;

        // Memory operand
        x86mem_t mem;

        // Signed immediate value
        int64_t imm;

        // Unsigned immediate value
        uint64_t unsig_imm;
    } as;

} x86opnd_t;

// Dummy none/null operand
static const x86opnd_t NO_OPND = { OPND_NONE, 0, .as.imm = 0 };

// Instruction pointer
static const x86opnd_t RIP = { OPND_REG, 64, .as.reg = { REG_IP, 5 }};

// 64-bit GP registers
static const x86opnd_t RAX = { OPND_REG, 64, .as.reg = { REG_GP, 0 }};
static const x86opnd_t RCX = { OPND_REG, 64, .as.reg = { REG_GP, 1 }};
static const x86opnd_t RDX = { OPND_REG, 64, .as.reg = { REG_GP, 2 }};
static const x86opnd_t RBX = { OPND_REG, 64, .as.reg = { REG_GP, 3 }};
static const x86opnd_t RSP = { OPND_REG, 64, .as.reg = { REG_GP, 4 }};
static const x86opnd_t RBP = { OPND_REG, 64, .as.reg = { REG_GP, 5 }};
static const x86opnd_t RSI = { OPND_REG, 64, .as.reg = { REG_GP, 6 }};
static const x86opnd_t RDI = { OPND_REG, 64, .as.reg = { REG_GP, 7 }};
static const x86opnd_t R8  = { OPND_REG, 64, .as.reg = { REG_GP, 8 }};
static const x86opnd_t R9  = { OPND_REG, 64, .as.reg = { REG_GP, 9 }};
static const x86opnd_t R10 = { OPND_REG, 64, .as.reg = { REG_GP, 10 }};
static const x86opnd_t R11 = { OPND_REG, 64, .as.reg = { REG_GP, 11 }};
static const x86opnd_t R12 = { OPND_REG, 64, .as.reg = { REG_GP, 12 }};
static const x86opnd_t R13 = { OPND_REG, 64, .as.reg = { REG_GP, 13 }};
static const x86opnd_t R14 = { OPND_REG, 64, .as.reg = { REG_GP, 14 }};
static const x86opnd_t R15 = { OPND_REG, 64, .as.reg = { REG_GP, 15 }};

// 32-bit GP registers
static const x86opnd_t EAX  = { OPND_REG, 32, .as.reg = { REG_GP, 0 }};
static const x86opnd_t ECX  = { OPND_REG, 32, .as.reg = { REG_GP, 1 }};
static const x86opnd_t EDX  = { OPND_REG, 32, .as.reg = { REG_GP, 2 }};
static const x86opnd_t EBX  = { OPND_REG, 32, .as.reg = { REG_GP, 3 }};
static const x86opnd_t ESP  = { OPND_REG, 32, .as.reg = { REG_GP, 4 }};
static const x86opnd_t EBP  = { OPND_REG, 32, .as.reg = { REG_GP, 5 }};
static const x86opnd_t ESI  = { OPND_REG, 32, .as.reg = { REG_GP, 6 }};
static const x86opnd_t EDI  = { OPND_REG, 32, .as.reg = { REG_GP, 7 }};
static const x86opnd_t R8D  = { OPND_REG, 32, .as.reg = { REG_GP, 8 }};
static const x86opnd_t R9D  = { OPND_REG, 32, .as.reg = { REG_GP, 9 }};
static const x86opnd_t R10D = { OPND_REG, 32, .as.reg = { REG_GP, 10 }};
static const x86opnd_t R11D = { OPND_REG, 32, .as.reg = { REG_GP, 11 }};
static const x86opnd_t R12D = { OPND_REG, 32, .as.reg = { REG_GP, 12 }};
static const x86opnd_t R13D = { OPND_REG, 32, .as.reg = { REG_GP, 13 }};
static const x86opnd_t R14D = { OPND_REG, 32, .as.reg = { REG_GP, 14 }};
static const x86opnd_t R15D = { OPND_REG, 32, .as.reg = { REG_GP, 15 }};

// 16-bit GP registers
static const x86opnd_t AX   = { OPND_REG, 16, .as.reg = { REG_GP, 0 }};
static const x86opnd_t CX   = { OPND_REG, 16, .as.reg = { REG_GP, 1 }};
static const x86opnd_t DX   = { OPND_REG, 16, .as.reg = { REG_GP, 2 }};
static const x86opnd_t BX   = { OPND_REG, 16, .as.reg = { REG_GP, 3 }};
static const x86opnd_t SP   = { OPND_REG, 16, .as.reg = { REG_GP, 4 }};
static const x86opnd_t BP   = { OPND_REG, 16, .as.reg = { REG_GP, 5 }};
static const x86opnd_t SI   = { OPND_REG, 16, .as.reg = { REG_GP, 6 }};
static const x86opnd_t DI   = { OPND_REG, 16, .as.reg = { REG_GP, 7 }};
static const x86opnd_t R8W  = { OPND_REG, 16, .as.reg = { REG_GP, 8 }};
static const x86opnd_t R9W  = { OPND_REG, 16, .as.reg = { REG_GP, 9 }};
static const x86opnd_t R10W = { OPND_REG, 16, .as.reg = { REG_GP, 10 }};
static const x86opnd_t R11W = { OPND_REG, 16, .as.reg = { REG_GP, 11 }};
static const x86opnd_t R12W = { OPND_REG, 16, .as.reg = { REG_GP, 12 }};
static const x86opnd_t R13W = { OPND_REG, 16, .as.reg = { REG_GP, 13 }};
static const x86opnd_t R14W = { OPND_REG, 16, .as.reg = { REG_GP, 14 }};
static const x86opnd_t R15W = { OPND_REG, 16, .as.reg = { REG_GP, 15 }};

// 8-bit GP registers
static const x86opnd_t AL   = { OPND_REG, 8, .as.reg = { REG_GP, 0 }};
static const x86opnd_t CL   = { OPND_REG, 8, .as.reg = { REG_GP, 1 }};
static const x86opnd_t DL   = { OPND_REG, 8, .as.reg = { REG_GP, 2 }};
static const x86opnd_t BL   = { OPND_REG, 8, .as.reg = { REG_GP, 3 }};
static const x86opnd_t SPL  = { OPND_REG, 8, .as.reg = { REG_GP, 4 }};
static const x86opnd_t BPL  = { OPND_REG, 8, .as.reg = { REG_GP, 5 }};
static const x86opnd_t SIL  = { OPND_REG, 8, .as.reg = { REG_GP, 6 }};
static const x86opnd_t DIL  = { OPND_REG, 8, .as.reg = { REG_GP, 7 }};
static const x86opnd_t R8B  = { OPND_REG, 8, .as.reg = { REG_GP, 8 }};
static const x86opnd_t R9B  = { OPND_REG, 8, .as.reg = { REG_GP, 9 }};
static const x86opnd_t R10B = { OPND_REG, 8, .as.reg = { REG_GP, 10 }};
static const x86opnd_t R11B = { OPND_REG, 8, .as.reg = { REG_GP, 11 }};
static const x86opnd_t R12B = { OPND_REG, 8, .as.reg = { REG_GP, 12 }};
static const x86opnd_t R13B = { OPND_REG, 8, .as.reg = { REG_GP, 13 }};
static const x86opnd_t R14B = { OPND_REG, 8, .as.reg = { REG_GP, 14 }};
static const x86opnd_t R15B = { OPND_REG, 8, .as.reg = { REG_GP, 15 }};

// C argument registers
#define NUM_C_ARG_REGS 6
#define C_ARG_REGS ( (x86opnd_t[]){ RDI, RSI, RDX, RCX, R8, R9 } )

// Compute the number of bits needed to store a signed or unsigned value
static uint32_t sig_imm_size(int64_t imm);
static uint32_t unsig_imm_size(uint64_t imm);

// Memory operand with base register and displacement/offset
static x86opnd_t mem_opnd(uint32_t num_bits, x86opnd_t base_reg, int32_t disp);

// Scale-index-base memory operand
//static x86opnd_t mem_opnd_sib(uint32_t num_bits, x86opnd_t base_reg, x86opnd_t index_reg, int32_t scale, int32_t disp);

// Immediate number operand
static x86opnd_t imm_opnd(int64_t val);

// Constant pointer operand
static x86opnd_t const_ptr_opnd(const void *ptr);

// Struct member operand
#define member_opnd(base_reg, struct_type, member_name) mem_opnd( \
    8 * sizeof(((struct_type*)0)->member_name), \
    base_reg,                                   \
    offsetof(struct_type, member_name)          \
)

// Struct member operand with an array index
#define member_opnd_idx(base_reg, struct_type, member_name, idx) mem_opnd( \
    8 * sizeof(((struct_type*)0)->member_name[0]),     \
    base_reg,                                       \
    (offsetof(struct_type, member_name) +           \
     sizeof(((struct_type*)0)->member_name[0]) * idx)  \
)
*/
