# frozen_string_literal: true

require "test_helper"

class TestRaioquicQuicRecoveryQuicPacketPacer < Minitest::Test
  Recovery = ::Raioquic::Quic::Recovery

  def setup
    @pacer = Recovery::QuicPacketPacer.new
  end

  def test_no_measurement
    assert_nil @pacer.next_send_time(now: 0.0)
    @pacer.update_after_send(now: 0.0)

    assert_nil @pacer.next_send_time(now: 0.0)
    @pacer.update_after_send(now: 0.0)
  end

  def test_with_measurement
    assert_nil @pacer.next_send_time(now: 0.0)
    @pacer.update_after_send(now: 0.0)

    @pacer.update_rate(congestion_window: 1280000, smoothed_rtt: 0.05)
    assert_in_delta 0.0008, @pacer.bucket_max
    assert_in_delta 0.0, @pacer.bucket_time
    assert_in_delta 0.00005, @pacer.packet_time

    # 16 packets
    16.times do
      assert_nil @pacer.next_send_time(now: 1.0)
      @pacer.update_after_send(now: 1.0)
    end
    assert_in_delta 1.00005, @pacer.next_send_time(now: 1.0), 0.0001

    # 2 pakcets
    2.times do
      assert_nil @pacer.next_send_time(now: 1.00005)
      @pacer.update_after_send(now: 1.00005)
    end
    assert_in_delta 1.0001, @pacer.next_send_time(now: 1.00005), 0.0001

    # 1 packet
    assert_nil @pacer.next_send_time(now: 1.0001)
    @pacer.update_after_send(now: 1.0001)
    assert_in_delta 1.00015, @pacer.next_send_time(now: 1.0001), 0.0001

    # 2 packets
    2.times do
      assert_nil @pacer.next_send_time(now: 1.00015)
      @pacer.update_after_send(now: 1.00015)
    end
    assert_in_delta 1.0002, @pacer.next_send_time(now: 1.00015), 0.0001
  end
end
