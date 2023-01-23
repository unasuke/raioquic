# frozen_string_literal: true

require "test_helper"

class TestRaioquicQuicRecoveryQuicRttMonitor < Minitest::Test
  Recovery = ::Raioquic::Quic::Recovery

  def test_monitor # rubocop:disable Metrics/MethodLength
    monitor = Recovery::QuicRttMonitor.new

    assert_equal false, monitor.is_rtt_increasing(rtt: 10, now: 1000)
    assert_equal [10, 0.0, 0.0, 0.0, 0.0], monitor.samples
    assert_equal false, monitor.ready

    # not take into account
    assert_equal false, monitor.is_rtt_increasing(rtt: 11, now: 1000)
    assert_equal [10, 0.0, 0.0, 0.0, 0.0], monitor.samples
    assert_equal false, monitor.ready

    assert_equal false, monitor.is_rtt_increasing(rtt: 11, now: 1001)
    assert_equal [10, 11, 0.0, 0.0, 0.0], monitor.samples
    assert_equal false, monitor.ready

    assert_equal false, monitor.is_rtt_increasing(rtt: 12, now: 1002)
    assert_equal [10, 11, 12, 0.0, 0.0], monitor.samples
    assert_equal false, monitor.ready

    assert_equal false, monitor.is_rtt_increasing(rtt: 13, now: 1003)
    assert_equal [10, 11, 12, 13, 0.0], monitor.samples
    assert_equal false, monitor.ready

    # we now have enough sampels
    assert_equal false, monitor.is_rtt_increasing(rtt: 14, now: 1004)
    assert_equal [10, 11, 12, 13, 14], monitor.samples
    assert monitor.ready

    assert_equal false, monitor.is_rtt_increasing(rtt: 20, now: 1005)
    assert_equal 0, monitor.increases

    assert_equal false, monitor.is_rtt_increasing(rtt: 30, now: 1006)
    assert_equal 0, monitor.increases

    assert_equal false, monitor.is_rtt_increasing(rtt: 40, now: 1007)
    assert_equal 0, monitor.increases

    assert_equal false, monitor.is_rtt_increasing(rtt: 50, now: 1008)
    assert_equal 0, monitor.increases

    assert_equal false, monitor.is_rtt_increasing(rtt: 60, now: 1009)
    assert_equal 1, monitor.increases

    assert_equal false, monitor.is_rtt_increasing(rtt: 70, now: 1010)
    assert_equal 2, monitor.increases

    assert_equal false, monitor.is_rtt_increasing(rtt: 80, now: 1011)
    assert_equal 3, monitor.increases

    assert_equal false, monitor.is_rtt_increasing(rtt: 90, now: 1012)
    assert_equal 4, monitor.increases

    assert monitor.is_rtt_increasing(rtt: 100, now: 1013)
    assert_equal 5, monitor.increases
  end
end
