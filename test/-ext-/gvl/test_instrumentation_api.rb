# frozen_string_literal: false
class TestGVLInstrumentation < Test::Unit::TestCase
  def test_gvl_instrumentation
    require '-test-/gvl/instrumentation'
    Bug::GVLInstrumentation.reset_counters
    Bug::GVLInstrumentation::register_callback

    begin
      threads = 5.times.map { Thread.new { sleep 0.05; 1 + 1; sleep 0.02 } }
      threads.each(&:join)
      Bug::GVLInstrumentation.counters.each do |c|
        assert_predicate c,:nonzero?
      end
    ensure
      Bug::GVLInstrumentation::unregister_callback
    end
  end

  def test_gvl_instrumentation_unregister
    require '-test-/gvl/instrumentation'
    assert Bug::GVLInstrumentation::register_and_unregister_callbacks
  end
end

