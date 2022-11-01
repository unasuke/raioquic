# frozen_string_literal: true

require "test_helper"

class TestRaioquicQuicPacket < Minitest::Test
  def setup
    @packet = Raioquic::Quic::Packet.new
  end

  def test_decode_packet_number
    (0...256).each do |i|
      assert_equal i, @packet.decode_packet_number(truncated: i, num_bits: 8, expected: 0)
    end

    assert_equal 256, @packet.decode_packet_number(truncated: 0, num_bits: 8, expected: 128)
    (1...256).each do |i|
      assert_equal i, @packet.decode_packet_number(truncated: i, num_bits: 8, expected: 128)
    end

    assert_equal 256, @packet.decode_packet_number(truncated: 0, num_bits: 8, expected: 129)
    assert_equal 257, @packet.decode_packet_number(truncated: 1, num_bits: 8, expected: 129)
    (2...256).each do |i|
      assert_equal i, @packet.decode_packet_number(truncated: i, num_bits: 8, expected: 129)
    end

    (0...128).each do |i|
      assert_equal 256 + i, @packet.decode_packet_number(truncated: i, num_bits: 8, expected: 256)
    end
    (129...256).each do |i|
      assert_equal i, @packet.decode_packet_number(truncated: i, num_bits: 8, expected: 256)
    end
  end

  def test_pull_empty
  end

  def test_pull_initiali_client
  end

  def test_pull_initial_client_truncated
  end

  def test_pull_initial_server
  end

  def test_pull_retry
  end

  def test_pull_retry_draft_29
  end

  def test_pull_version_negotiation
  end

  def test_pull_long_header_dcid_too_long
  end

  def test_pull_long_header_scid_too_long
  end

  def test_pull_long_header_no_fixed_bit
  end

  def test_pull_long_header_too_short
  end

  def test_pull_short_header
  end

  def test_pull_short_header_no_fixed_bit
  end

  def test_encode_quic_version_negotiation
  end
end
