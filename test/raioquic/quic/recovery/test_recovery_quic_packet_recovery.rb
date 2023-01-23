# frozen_string_literal: true

require "test_helper"

class TestRaioquicQuicRecoveryQuicPacketRecovery < Minitest::Test
  Recovery = ::Raioquic::Quic::Recovery

  def setup
    @initial_space = Recovery::QuicPacketSpace.new
    @handshake_space = Recovery::QuicPacketSpace.new
    @one_rtt_space = Recovery::QuicPacketSpace.new

    @recovery = Recovery::QuicPacketRecovery.new(initial_rtt: 0.1, peer_completed_address_validation: true, send_probe: -> {})
    @recovery.spaces = [
      @initial_space,
      @handshake_space,
      @one_rtt_space,
    ]
  end

  def test_discard_space
    @recovery.discard_space(space: @initial_space) # what's this?
  end

  def test_on_ack_received_ack_eliciting
    packet = ::Raioquic::Quic::PacketBuilder::QuicSentPacket.new.tap do |sent_packet|
      sent_packet.epoch = ::Raioquic::TLS::Epoch::ONE_RTT
      sent_packet.in_flight = true
      sent_packet.is_ack_eliciting = true
      sent_packet.is_crypto_packet = false
      sent_packet.packet_number = 0
      sent_packet.packet_type = ::Raioquic::Quic::Packet::PACKET_TYPE_ONE_RTT
      sent_packet.sent_bytes = 1280
      sent_packet.sent_time = 0.0
    end
    space = @one_rtt_space

    # packet sent
    @recovery.on_packet_sent(packet: packet, space: space)
    assert_equal 1280, @recovery.bytes_in_flight
    assert_equal 1, space.ack_eliciting_in_flight
    assert_equal 1, space.sent_packets.length

    # packet ack'd
    @recovery.on_ack_received(
      space: space, ack_rangeset: ::Raioquic::Quic::Rangeset.new(ranges: [0...1]), ack_delay: 0.0, now: 10.0,
    )
    assert_equal 0, @recovery.bytes_in_flight
    assert_equal 0, space.ack_eliciting_in_flight
    assert_equal 0, space.sent_packets.length

    # check RTT
    assert @recovery.rtt_initialized
    assert_in_delta 10.0, @recovery.rtt_latest
    assert_in_delta 10.0, @recovery.rtt_min
    assert_in_delta 10.0, @recovery.rtt_smoothed
  end

  def test_on_ack_received_non_ack_eliciting
    packet = ::Raioquic::Quic::PacketBuilder::QuicSentPacket.new.tap do |sent_packet|
      sent_packet.epoch = ::Raioquic::TLS::Epoch::ONE_RTT
      sent_packet.in_flight = true
      sent_packet.is_ack_eliciting = false
      sent_packet.is_crypto_packet = false
      sent_packet.packet_number = 0
      sent_packet.packet_type = ::Raioquic::Quic::Packet::PACKET_TYPE_ONE_RTT
      sent_packet.sent_bytes = 1280
      sent_packet.sent_time = 123.45
    end
    space = @one_rtt_space

    # packet sent
    @recovery.on_packet_sent(packet: packet, space: space)
    assert_equal 1280, @recovery.bytes_in_flight
    assert_equal 0, space.ack_eliciting_in_flight
    assert_equal 1, space.sent_packets.length

    # packet ack'd
    @recovery.on_ack_received(
      space: space, ack_rangeset: ::Raioquic::Quic::Rangeset.new(ranges: [0...1]), ack_delay: 0.0, now: 10.0,
    )
    assert_equal 0, @recovery.bytes_in_flight
    assert_equal 0, space.ack_eliciting_in_flight
    assert_equal 0, space.sent_packets.length

    # check RTT
    assert_equal false, @recovery.rtt_initialized
    assert_in_delta 0.0, @recovery.rtt_latest
    assert_equal Float::INFINITY, @recovery.rtt_min
    assert_in_delta 0.0, @recovery.rtt_smoothed
  end

  def test_on_packet_lost_crypto
    packet = ::Raioquic::Quic::PacketBuilder::QuicSentPacket.new.tap do |sent_packet|
      sent_packet.epoch = ::Raioquic::TLS::Epoch::INITIAL
      sent_packet.in_flight = true
      sent_packet.is_ack_eliciting = true
      sent_packet.is_crypto_packet = true
      sent_packet.packet_number = 0
      sent_packet.packet_type = ::Raioquic::Quic::Packet::PACKET_TYPE_INITIAL
      sent_packet.sent_bytes = 1280
      sent_packet.sent_time = 0.0
    end
    space = @initial_space

    @recovery.on_packet_sent(packet: packet, space: space)
    assert_equal 1280, @recovery.bytes_in_flight
    assert_equal 1, space.ack_eliciting_in_flight
    assert_equal 1, space.sent_packets.length

    @recovery.detect_loss(space: space, now: 1.0)
    assert_equal 0, @recovery.bytes_in_flight
    assert_equal 0, space.ack_eliciting_in_flight
    assert_equal 0, space.sent_packets.length
  end
end
