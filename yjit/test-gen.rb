# frozen_string_literal: true
# This is a script that uses nasm(1) to generate tests
# for this assembler.
require 'tempfile'

INPUT_PATTERN = %r{(?<mnemonic>[a-z]+) (?<op1>r/m|reg|imm)?(?:, (?<op2>r/m|reg|imm))?}

input = ARGV.join(' ')
insn_form = INPUT_PATTERN.match(input) do |match|
  match.named_captures.fetch_values('mnemonic', 'op1', 'op2')
end

raise "Failed to parse desired instrution form
Usage: asm-test-gen.rb %r{#{INPUT_PATTERN.source}}
" unless insn_form

mnemonic, op1, op2 = insn_form

ALL_REGS = %w(
    al   ax   eax  rax
    cl   cx   ecx  rcx
    dl   dx   edx  rdx
    bl   bx   ebx  rbx
    spl  sp   esp  rsp
    bpl  bp   ebp  rbp
    sil  si   esi  rsi
    dil  di   edi  rdi
    r8b  r8w  r8d  r8
    r9b  r9w  r9d  r9
    r10b r10w r10d r10
    r11b r11w r11d r11
    r12b r12w r12d r12
    r13b r13w r13d r13
    r14b r14w r14d r14
    r15b r15w r15d r15
)

last_idx = ALL_REGS.length-1
REG8  = ALL_REGS.values_at(*0.step(by: 4, to: last_idx)).freeze
REG32 = ALL_REGS.values_at(*2.step(by: 4, to: last_idx)).freeze
REG64 = ALL_REGS.values_at(*3.step(by: 4, to: last_idx)).freeze

# Only reg+disp forms for now
sizes = %w(qword dword byte)
MEM_EXAMPLES = REG64.flat_map.with_index do |reg, idx|
  size = sizes[idx%3]
  "#{size} ptr [#{reg} + 0x4]"
end

def instance(operand_type)
  case operand_type
  when "r/m"
    REG8 + REG32 + REG64 + MEM_EXAMPLES
  when "reg"
    REG8 + REG32 + REG64
  when "imm"
    %w(0 -1 0xddcafe)
  else
    []
  end
end

asm_lines = instance(op1).flat_map do |lhs|
  rhs_instances = instance(op2)
  if rhs_instances.empty?
    "#{mnemonic} #{lhs}"
  else
    instance(op2).map do |rhs|
      "#{mnemonic} #{lhs}, #{rhs}"
    end
  end
end

asm_lines = []
rust_asm_lines = []

counter = 1
REG8.flat_map do |reg|
  REG64.flat_map do |base|
    sign = counter % 2 == 1 ? '+' : '-'
    disp = counter < 10 ? counter : "0x" + counter.to_s(16)
    disp_lit = sign == '-' ? "#{sign}#{disp}" : disp
    asm_lines << "#{mnemonic} byte [#{base} #{sign} #{disp}], #{reg}"
    rust_asm_lines << "#{mnemonic}((mem8(#{base.upcase}, #{disp_lit}), #{reg.upcase}))"


    counter += 1
  end
end

puts rust_asm_lines

START_MARKER = "start_marker"
END_MARKER = "end_marker"

Tempfile.open(%w(asm .S)) do |asm_file|
  asm_file.puts(%Q(db "#{START_MARKER}"))
  asm_file.puts(asm_lines.map { |line| line.sub(' ptr', '') })
  asm_file.puts(%Q(db "#{END_MARKER}"))
  asm_file.flush

  File.read(asm_file.path).each_line.with_index do |line, idx|
    puts "#{(idx+1).to_s.rjust(4)}: #{line}"
  end

  Tempfile.open(%w(output o)) do |elf|
    `nasm -felf64 -o #{elf.path} #{asm_file.path}`
    raise "nasm failed to assemble" unless $?.success?

    bytes = File.binread(elf.path)
    start = bytes.index(START_MARKER)
    raise "failed to find marker" unless start
    start += START_MARKER.length

    one_past_end = bytes.index(END_MARKER, start)

    puts "bytes are:"
    bytes = bytes[(start...one_past_end)].bytes.map { |b| b.to_s(16).rjust(2, "0") }

    bytes.each_slice(25) do |slice|
      puts slice.join(" ") + " \\"
    end
    puts

    asm_lines.zip(rust_asm_lines) do |asm, rust_asm|
      puts %Q{"#{asm}", #{rust_asm}}
    end
  end
end
