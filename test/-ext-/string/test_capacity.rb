# frozen_string_literal: true
require 'test/unit'
require '-test-/string'
require 'rbconfig/sizeof'

class Test_StringCapacity < Test::Unit::TestCase
  def test_capacity_embedded
    assert_equal GC::INTERNAL_CONSTANTS[:RVALUE_SIZE] - embed_header_size - 1, capa('foo')
    assert_equal max_embed_len, capa('1' * max_embed_len)
    assert_equal max_embed_len, capa('1' * (max_embed_len - 1))
  end

  def test_capacity_shared
    assert_equal 0, capa(:abcdefghijklmnopqrstuvwxyz.to_s)
  end

  def test_capacity_normal
    assert_equal max_embed_len + 1, capa('1' * (max_embed_len + 1))
    if GC.using_rvargc?
      assert_equal 1000, capa('1' * 1000)
    else
      assert_equal 128, capa('1' * 128)
    end
  end

  def test_s_new_capacity
    assert_equal("", String.new(capacity: 1000))
    assert_equal(String, String.new(capacity: 1000).class)
    assert_equal(10000, capa(String.new(capacity: 10000)))

    assert_equal("", String.new(capacity: -1000))
    assert_equal(capa(String.new(capacity: -10000)), capa(String.new(capacity: -1000)))
  end

  def test_io_read
    s = String.new(capacity: 1000)
    open(__FILE__) {|f|f.read(1024*1024, s)}
    assert_equal(1024*1024, capa(s))
    open(__FILE__) {|f|s = f.read(1024*1024)}
    assert_operator(capa(s), :<=, s.bytesize+4096)
  end

  def test_literal_capacity
    s =
      if GC.using_rvargc?
        s = eval(%{
          # frozen_string_literal: true
          "#{"a" * GC::INTERNAL_CONSTANTS[:RVARGC_MAX_ALLOCATE_SIZE]}"
        })
      else
        "I am testing string literal capacity"
      end
    assert_equal(s.length, capa(s))
  end

  def test_capacity_frozen
    s = String.new("I am testing", capacity: 1000)
    s << "fstring capacity"
    s.freeze
    assert_equal(s.length, capa(s))
  end

  def test_capacity_fstring
    s = String.new("I am testing", capacity: 1000)
    s <<
      if GC.using_rvargc?
        "a" * GC::INTERNAL_CONSTANTS[:RVARGC_MAX_ALLOCATE_SIZE]
      else
        "fstring capacity"
      end
    s = -s
    assert_equal(s.length, capa(s))
  end

  private

  def capa(str)
    Bug::String.capacity(str)
  end

  def embed_header_size
    if GC.using_rvargc?
      2 * RbConfig::SIZEOF['void*'] + RbConfig::SIZEOF['short']
    else
      2 * RbConfig::SIZEOF['void*']
    end
  end

  def max_embed_len
    GC::INTERNAL_CONSTANTS[:RVARGC_MAX_ALLOCATE_SIZE] - embed_header_size - 1
  end
end
