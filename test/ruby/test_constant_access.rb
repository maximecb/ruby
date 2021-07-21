# frozen_string_literal: false
require 'test/unit'

module ExampleModule
  module Nested
    FOO = "foo"
  end
end

class TestConstantAccess < Test::Unit::TestCase
  def test_referencing_constants
    constant_values = perform do
      ExampleModule::Nested::FOO
    end

    assert_equal(constant_values, [ExampleModule, ExampleModule::Nested, ExampleModule::Nested::FOO])
  end

  def test_setting_constants
    constant_values = perform do
      eval <<~RUBY
        ExampleModule::Nested::BAR = "bar"
      RUBY
    end

    assert_equal(constant_values, [ExampleModule, ExampleModule::Nested, ExampleModule::Nested::BAR])
  end

  def test_reopening_module
    eval <<~RUBY
      module TestReopeningModule
      end
    RUBY

    constant_values = perform do
      eval <<~RUBY
        module TestReopeningModule
        end
      RUBY
    end

    assert_equal(constant_values, [TestReopeningModule])
  end

  def test_reopening_class
    eval <<~RUBY
      class TestReopeningClass
      end
    RUBY

    constant_values = perform do
      eval <<~RUBY
        class TestReopeningClass
        end
      RUBY
    end

    assert_equal(constant_values, [TestReopeningClass])
  end

  def test_const_get
    constant_values = perform do
      Object.const_get("::ExampleModule::Nested::FOO")
    end

    assert_equal(constant_values, [Object, ExampleModule, ExampleModule::Nested, ExampleModule::Nested::FOO])
  end

  def test_const_set
    constant_values = perform do
      ExampleModule.const_set(:BAR, "bar")
    end

    assert_equal(constant_values, [ExampleModule, ExampleModule::BAR])
  end

  private

  def perform
    constant_values = []

    TracePoint.new(:constant_access) { |trace_point|
      constant_values << trace_point.constant_value
    }.enable { yield }

    constant_values
  end
end
