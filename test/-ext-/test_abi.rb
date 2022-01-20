# frozen_string_literal: true

class TestABI < Test::Unit::TestCase
  def test_require_lib_with_incorrect_abi_on_dev_ruby
    omit "ABI is not checked" unless abi_checking_enabled?

    err = assert_raise(LoadError) { require "-test-/abi" }
    assert_match(/ABI version of binary is incompatible with this Ruby/, err.message)
  end

  def test_require_lib_with_incorrect_abi_on_release_ruby
    omit "ABI is enforced" if abi_checking_enabled?

    assert_nothing_raised { require "-test-/abi" }
  end

  private

  def abi_checking_enabled?
    RUBY_PATCHLEVEL < 0 && !(RUBY_PLATFORM =~ /mswin|mingw/)
  end
end
