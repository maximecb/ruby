#!/usr/bin/env ruby
require 'open3'
require 'tempfile'
require 'test/unit'

class TestLLDBInit < Test::Unit::TestCase
  def assert_rp(expr, pattern, message=nil)
    Tempfile.create('lldb') do |tf|
      tf.puts <<eom
target create ./miniruby
command script import -r misc/lldb_cruby.py
b rb_inspect
run -e'p #{expr}'
rp obj
eom
      tf.flush
      o, s = Open3.capture2('lldb', '-b', '-s', tf.path)
      assert_true s.success?, message
      assert_match pattern, o, message
    end
  end

  def test_rp_object
    assert_rp 'Object.new', 'T_OBJECT'
  end

  def test_rp_regex
    assert_rp '/foo/', /\(Regex\) ->src {/
    assert_rp '/foo/', /T_STRING: .* = "foo"/
  end

  def test_rp_symbol
    assert_rp ':abcde', /T_SYMBOL: \(\h+\)/
  end

  def test_rp_string
    assert_rp '"abc"', /T_STRING: .* = "abc"/
    assert_rp "\"\u3042\"", /T_STRING: .* "\u3042"/
    assert_rp '"' + "\u3042"*10 + '"', /T_STRING: .* = "#{"\u3042" * 10}"/
  end
end
