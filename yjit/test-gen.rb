# frozen_string_literal: true
require 'tempfile'

START_MARKER = "start_marker"
END_MARKER = "end_marker"

Tempfile.open(%w(asm asm)) do |asm_file|
  asm_file.puts <<~ASM
    db "#{START_MARKER}"
    cmovge rax, r15
    pop rsp
    mov qword [rax - 0xa], 0xfabcafe
    mov dword [r12], -1
    db "#{END_MARKER}"
  ASM
  asm_file.flush

  Tempfile.open(%w(output o)) do |elf|
    `nasm -felf64 -o #{elf.path} #{asm_file.path}`
    raise "nasm failed to assemble" unless $?.success?

    bytes = File.binread(elf.path)
    start = bytes.index(START_MARKER)
    raise "failed to find marker" unless start
    start += START_MARKER.length

    one_past_end = bytes.index(END_MARKER, start)

    puts "bytes are:"
    puts bytes[(start...one_past_end)].bytes.map { |b| b.to_s(16).rjust(2, "0") }.join(" ")
  end
end
