# frozen_string_literal: true

require "test_helper"

class TestRaioquicQuicPacketBuilder < Minitest::Test
  # Packet = Raioquic::Quic::Packet
  def create_builder(is_client: false)
    Raioquic::Quic::PacketBuilder::QuicPacketBuilder.new(
      host_cid: "\x00" * 8,
      is_client: is_client,
      packet_number: 0,
      peer_cid: "\x00" * 8,
      peer_token: "",
      spin_bit: false,
      version: ::Raioquic::Quic::Packet::QuicProtocolVersion::VERSION_1,
    )
  end

  def create_crypto
    crypto = ::Raioquic::Quic::Crypto::CryptoPair.new
    crypto.setup_initial(
      cid: "\x00" * 8, is_client: true, version: ::Raioquic::Quic::Packet::QuicProtocolVersion::VERSION_1,
    )
    crypto
  end

  def test_long_header_empty
    builder = create_builder
    crypto = create_crypto

    builder.start_packet(packet_type: ::Raioquic::Quic::Packet::PACKET_TYPE_INITIAL, crypto: crypto)
    assert_equal 1236, builder.remaining_flight_space
    assert builder.packet_is_empty
  end

  def test_long_header_padding
    builder = create_builder(is_client: true)
    crypto = create_crypto

    builder.start_packet(packet_type: ::Raioquic::Quic::Packet::PACKET_TYPE_INITIAL, crypto: crypto)
    assert_equal 1236, builder.remaining_flight_space
    buf = builder.start_frame(frame_type: ::Raioquic::Quic::Packet::QuicFrameType::CRYPTO)
    buf.push_bytes("\x00" * 100)
    assert_equal false, builder.packet_is_empty

    builder.start_packet(packet_type: ::Raioquic::Quic::Packet::PACKET_TYPE_INITIAL, crypto: crypto)
    assert builder.packet_is_empty

    datagrams, packets = builder.flush
    assert_equal 1, datagrams.length
    assert_equal 1280, datagrams[0].bytesize
    sent_packet = ::Raioquic::Quic::PacketBuilder::QuicSentPacket.new.tap do |p|
      p.epoch = ::Raioquic::TLS::Epoch::INITIAL
      p.in_flight = true
      p.is_ack_eliciting = true
      p.is_crypto_packet = true
      p.packet_number = 0
      p.packet_type = ::Raioquic::Quic::Packet::PACKET_TYPE_INITIAL
      p.sent_bytes = 1280
      p.quic_logger_frames = []
    end
    assert_equal [sent_packet], packets
    assert_equal 1, builder.packet_number
  end

  def test_long_header_initial_client_2 # rubocop:disable Metrics/MethodLength
    builder = create_builder(is_client: true)
    crypto = create_crypto

    builder.start_packet(packet_type: ::Raioquic::Quic::Packet::PACKET_TYPE_INITIAL, crypto: crypto)
    assert_equal 1236, builder.remaining_flight_space
    buf = builder.start_frame(frame_type: ::Raioquic::Quic::Packet::QuicFrameType::CRYPTO)
    buf.push_bytes("\x00" * builder.remaining_flight_space)
    assert_equal false, builder.packet_is_empty

    builder.start_packet(packet_type: ::Raioquic::Quic::Packet::PACKET_TYPE_INITIAL, crypto: crypto)
    assert_equal 1236, builder.remaining_flight_space
    buf = builder.start_frame(frame_type: ::Raioquic::Quic::Packet::QuicFrameType::CRYPTO)
    buf.push_bytes("\x00" * 100)
    assert_equal false, builder.packet_is_empty

    builder.start_packet(packet_type: ::Raioquic::Quic::Packet::PACKET_TYPE_INITIAL, crypto: crypto)
    assert builder.packet_is_empty

    datagrams, packets = builder.flush
    assert_equal 2, datagrams.length
    assert_equal 1280, datagrams[0].bytesize
    assert_equal 1280, datagrams[1].bytesize
    sent_packet1 = ::Raioquic::Quic::PacketBuilder::QuicSentPacket.new.tap do |p|
      p.epoch = ::Raioquic::TLS::Epoch::INITIAL
      p.in_flight = true
      p.is_ack_eliciting = true
      p.is_crypto_packet = true
      p.packet_number = 0
      p.packet_type = ::Raioquic::Quic::Packet::PACKET_TYPE_INITIAL
      p.sent_bytes = 1280
      p.quic_logger_frames = []
    end
    sent_packet2 = ::Raioquic::Quic::PacketBuilder::QuicSentPacket.new.tap do |p|
      p.epoch = ::Raioquic::TLS::Epoch::INITIAL
      p.in_flight = true
      p.is_ack_eliciting = true
      p.is_crypto_packet = true
      p.packet_number = 1
      p.packet_type = ::Raioquic::Quic::Packet::PACKET_TYPE_INITIAL
      p.sent_bytes = 1280
      p.quic_logger_frames = []
    end
    assert_equal [sent_packet1, sent_packet2], packets
  end

  def test_long_header_initial_server
    builder = create_builder
    crypto = create_crypto

    builder.start_packet(packet_type: ::Raioquic::Quic::Packet::PACKET_TYPE_INITIAL, crypto: crypto)
    assert_equal 1236, builder.remaining_flight_space
    buf = builder.start_frame(frame_type: ::Raioquic::Quic::Packet::QuicFrameType::CRYPTO)
    buf.push_bytes("\x00" * 100)
    assert_equal false, builder.packet_is_empty

    builder.start_packet(packet_type: ::Raioquic::Quic::Packet::PACKET_TYPE_INITIAL, crypto: crypto)
    assert builder.packet_is_empty

    datagrams, packets = builder.flush
    assert_equal 1, datagrams.length
    assert_equal 145, datagrams[0].bytesize
    sent_packet = ::Raioquic::Quic::PacketBuilder::QuicSentPacket.new.tap do |p|
      p.epoch = ::Raioquic::TLS::Epoch::INITIAL
      p.in_flight = true
      p.is_ack_eliciting = true
      p.is_crypto_packet = true
      p.packet_number = 0
      p.packet_type = ::Raioquic::Quic::Packet::PACKET_TYPE_INITIAL
      p.sent_bytes = 145
      p.quic_logger_frames = []
    end
    assert_equal [sent_packet], packets
    assert_equal 1, builder.packet_number
  end

  def test_long_header_ping_only
    builder = create_builder
    crypto = create_crypto

    builder.start_packet(packet_type: ::Raioquic::Quic::Packet::PACKET_TYPE_HANDSHAKE, crypto: crypto)
    builder.start_frame(frame_type: ::Raioquic::Quic::Packet::QuicFrameType::PING)
    assert_equal false, builder.packet_is_empty

    datagrams, packets = builder.flush
    assert_equal 1, datagrams.length
    assert_equal 45, datagrams[0].bytesize
    sent_packet = ::Raioquic::Quic::PacketBuilder::QuicSentPacket.new.tap do |p|
      p.epoch = ::Raioquic::TLS::Epoch::HANDSHAKE
      p.in_flight = true
      p.is_ack_eliciting = true
      p.is_crypto_packet = false
      p.packet_number = 0
      p.packet_type = ::Raioquic::Quic::Packet::PACKET_TYPE_HANDSHAKE
      p.sent_bytes = 45
      p.quic_logger_frames = []
    end
    assert_equal [sent_packet], packets
  end

  def test_long_header_then_short_header # rubocop:disable Metrics/MethodLength
    builder = create_builder
    crypto = create_crypto

    builder.start_packet(packet_type: ::Raioquic::Quic::Packet::PACKET_TYPE_INITIAL, crypto: crypto)
    assert_equal 1236, builder.remaining_flight_space
    buf = builder.start_frame(frame_type: ::Raioquic::Quic::Packet::QuicFrameType::CRYPTO)
    buf.push_bytes("\x00" * builder.remaining_flight_space)
    assert_equal false, builder.packet_is_empty

    builder.start_packet(packet_type: ::Raioquic::Quic::Packet::PACKET_TYPE_INITIAL, crypto: crypto)
    assert builder.packet_is_empty

    builder.start_packet(packet_type: ::Raioquic::Quic::Packet::PACKET_TYPE_ONE_RTT, crypto: crypto)
    assert_equal 1253, builder.remaining_flight_space
    buf = builder.start_frame(frame_type: ::Raioquic::Quic::Packet::QuicFrameType::STREAM_BASE)
    buf.push_bytes("\x00" * builder.remaining_flight_space)
    assert_equal false, builder.packet_is_empty

    builder.start_packet(packet_type: ::Raioquic::Quic::Packet::PACKET_TYPE_ONE_RTT, crypto: crypto)
    assert builder.packet_is_empty

    datagrams, packets = builder.flush
    assert_equal 2, datagrams.length
    assert_equal 1280, datagrams[0].bytesize
    assert_equal 1280, datagrams[1].bytesize
    sent_packet1 = ::Raioquic::Quic::PacketBuilder::QuicSentPacket.new.tap do |p|
      p.epoch = ::Raioquic::TLS::Epoch::INITIAL
      p.in_flight = true
      p.is_ack_eliciting = true
      p.is_crypto_packet = true
      p.packet_number = 0
      p.packet_type = ::Raioquic::Quic::Packet::PACKET_TYPE_INITIAL
      p.sent_bytes = 1280
      p.quic_logger_frames = []
    end
    sent_packet2 = ::Raioquic::Quic::PacketBuilder::QuicSentPacket.new.tap do |p|
      p.epoch = ::Raioquic::TLS::Epoch::ONE_RTT
      p.in_flight = true
      p.is_ack_eliciting = true
      p.is_crypto_packet = false
      p.packet_number = 1
      p.packet_type = ::Raioquic::Quic::Packet::PACKET_TYPE_ONE_RTT
      p.sent_bytes = 1280
      p.quic_logger_frames = []
    end
    assert_equal [sent_packet1, sent_packet2], packets
  end

  def test_long_header_then_long_header # rubocop:disable Metrics/MethodLength
    builder = create_builder
    crypto = create_crypto

    builder.start_packet(packet_type: ::Raioquic::Quic::Packet::PACKET_TYPE_INITIAL, crypto: crypto)
    assert_equal 1236, builder.remaining_flight_space
    buf = builder.start_frame(frame_type: ::Raioquic::Quic::Packet::QuicFrameType::CRYPTO)
    buf.push_bytes("\x00" * 199)
    assert_equal false, builder.packet_is_empty

    builder.start_packet(packet_type: ::Raioquic::Quic::Packet::PACKET_TYPE_HANDSHAKE, crypto: crypto)
    assert_equal 993, builder.remaining_flight_space
    buf = builder.start_frame(frame_type: ::Raioquic::Quic::Packet::QuicFrameType::CRYPTO)
    buf.push_bytes("\x00" * 299)
    assert_equal false, builder.packet_is_empty

    builder.start_packet(packet_type: ::Raioquic::Quic::Packet::PACKET_TYPE_ONE_RTT, crypto: crypto)
    assert_equal 666, builder.remaining_flight_space
    buf = builder.start_frame(frame_type: ::Raioquic::Quic::Packet::QuicFrameType::CRYPTO)
    buf.push_bytes("\x00" * 299)
    assert_equal false, builder.packet_is_empty

    datagrams, packets = builder.flush
    assert_equal 1, datagrams.length
    assert_equal 914, datagrams[0].bytesize
    sent_packet1 = ::Raioquic::Quic::PacketBuilder::QuicSentPacket.new.tap do |p|
      p.epoch = ::Raioquic::TLS::Epoch::INITIAL
      p.in_flight = true
      p.is_ack_eliciting = true
      p.is_crypto_packet = true
      p.packet_number = 0
      p.packet_type = ::Raioquic::Quic::Packet::PACKET_TYPE_INITIAL
      p.sent_bytes = 244
      p.quic_logger_frames = []
    end
    sent_packet2 = ::Raioquic::Quic::PacketBuilder::QuicSentPacket.new.tap do |p|
      p.epoch = ::Raioquic::TLS::Epoch::HANDSHAKE
      p.in_flight = true
      p.is_ack_eliciting = true
      p.is_crypto_packet = true
      p.packet_number = 1
      p.packet_type = ::Raioquic::Quic::Packet::PACKET_TYPE_HANDSHAKE
      p.sent_bytes = 343
      p.quic_logger_frames = []
    end
    sent_packet3 = ::Raioquic::Quic::PacketBuilder::QuicSentPacket.new.tap do |p|
      p.epoch = ::Raioquic::TLS::Epoch::ONE_RTT
      p.in_flight = true
      p.is_ack_eliciting = true
      p.is_crypto_packet = true
      p.packet_number =  2
      p.packet_type = ::Raioquic::Quic::Packet::PACKET_TYPE_ONE_RTT
      p.sent_bytes = 327
      p.quic_logger_frames = []
    end
    assert_equal [sent_packet1, sent_packet2, sent_packet3], packets
    assert_equal 3, builder.packet_number
  end

  def test_short_header_empty
    builder = create_builder
    crypto = create_crypto

    builder.start_packet(packet_type: ::Raioquic::Quic::Packet::PACKET_TYPE_ONE_RTT, crypto: crypto)
    assert_equal 1253, builder.remaining_flight_space
    assert builder.packet_is_empty

    datagrams, packets = builder.flush
    assert_empty datagrams
    assert_empty packets
    assert_equal 0, builder.packet_number
  end

  def test_short_header_padding
    builder = create_builder
    crypto = create_crypto

    builder.start_packet(packet_type: ::Raioquic::Quic::Packet::PACKET_TYPE_ONE_RTT, crypto: crypto)
    assert_equal 1253, builder.remaining_flight_space
    buf = builder.start_frame(frame_type: ::Raioquic::Quic::Packet::QuicFrameType::CRYPTO)
    buf.push_bytes("\x00" * builder.remaining_flight_space)
    assert_equal false, builder.packet_is_empty

    datagrams, packets = builder.flush
    assert_equal 1, datagrams.length
    assert_equal 1280, datagrams[0].bytesize
    sent_packet = ::Raioquic::Quic::PacketBuilder::QuicSentPacket.new.tap do |p|
      p.epoch = ::Raioquic::TLS::Epoch::ONE_RTT
      p.in_flight = true
      p.is_ack_eliciting = true
      p.is_crypto_packet = true
      p.packet_number = 0
      p.packet_type = ::Raioquic::Quic::Packet::PACKET_TYPE_ONE_RTT
      p.sent_bytes = 1280
      p.quic_logger_frames = []
    end
    assert_equal [sent_packet], packets
    assert_equal 1, builder.packet_number
  end

  def test_short_header_max_flight_bytes
    builder = create_builder
    builder.max_flight_bytes = 1000

    crypto = create_crypto

    builder.start_packet(packet_type: ::Raioquic::Quic::Packet::PACKET_TYPE_ONE_RTT, crypto: crypto)
    assert_equal 973, builder.remaining_flight_space
    buf = builder.start_frame(frame_type: ::Raioquic::Quic::Packet::QuicFrameType::CRYPTO)
    buf.push_bytes("\x00" * builder.remaining_flight_space)
    assert_equal false, builder.packet_is_empty

    assert_raises ::Raioquic::Quic::PacketBuilder::QuicPacketBuilderStop do # rubocop:disable Minitest/AssertRaisesCompoundBody
      builder.start_packet(packet_type: ::Raioquic::Quic::Packet::PACKET_TYPE_ONE_RTT, crypto: crypto)
      builder.start_frame(frame_type: ::Raioquic::Quic::Packet::QuicFrameType::CRYPTO)
    end

    datagrams, packets = builder.flush
    assert_equal 1, datagrams.length
    assert_equal 1000, datagrams[0].bytesize
    sent_packet = ::Raioquic::Quic::PacketBuilder::QuicSentPacket.new.tap do |p|
      p.epoch = ::Raioquic::TLS::Epoch::ONE_RTT
      p.in_flight = true
      p.is_ack_eliciting = true
      p.is_crypto_packet = true
      p.packet_number = 0
      p.packet_type = ::Raioquic::Quic::Packet::PACKET_TYPE_ONE_RTT
      p.sent_bytes = 1000
      p.quic_logger_frames = []
    end
    assert_equal [sent_packet], packets
    assert_equal 1, builder.packet_number
  end

  def test_short_header_max_flight_bytes_zero
    builder = create_builder
    builder.max_flight_bytes = 0

    crypto = create_crypto

    assert_raises ::Raioquic::Quic::PacketBuilder::QuicPacketBuilderStop do # rubocop:disable Minitest/AssertRaisesCompoundBody
      builder.start_packet(packet_type: ::Raioquic::Quic::Packet::PACKET_TYPE_ONE_RTT, crypto: crypto)
      builder.start_frame(frame_type: ::Raioquic::Quic::Packet::QuicFrameType::CRYPTO)
    end

    datagrams, _packets = builder.flush
    assert_empty datagrams
    assert_equal 0, builder.packet_number
  end

  def test_short_header_max_flight_bytes_zero_ack
    builder = create_builder
    builder.max_flight_bytes = 0

    crypto = create_crypto

    builder.start_packet(packet_type: ::Raioquic::Quic::Packet::PACKET_TYPE_ONE_RTT, crypto: crypto)
    buf = builder.start_frame(frame_type: ::Raioquic::Quic::Packet::QuicFrameType::ACK)
    buf.push_bytes("\x00" * 64)

    assert_raises ::Raioquic::Quic::PacketBuilder::QuicPacketBuilderStop do # rubocop:disable Minitest/AssertRaisesCompoundBody
      builder.start_packet(packet_type: ::Raioquic::Quic::Packet::PACKET_TYPE_ONE_RTT, crypto: crypto)
      builder.start_frame(frame_type: ::Raioquic::Quic::Packet::QuicFrameType::CRYPTO)
    end

    datagrams, packets = builder.flush
    assert_equal 1, datagrams.length
    assert_equal 92, datagrams[0].bytesize
    sent_packet = ::Raioquic::Quic::PacketBuilder::QuicSentPacket.new.tap do |p|
      p.epoch = ::Raioquic::TLS::Epoch::ONE_RTT
      p.in_flight = false
      p.is_ack_eliciting = false
      p.is_crypto_packet = false
      p.packet_number = 0
      p.packet_type = ::Raioquic::Quic::Packet::PACKET_TYPE_ONE_RTT
      p.sent_bytes = 92
      p.quic_logger_frames = []
    end
    assert_equal [sent_packet], packets
    assert_equal 1, builder.packet_number
  end

  # max_total_bytes doesn't allow any packets.
  def test_short_header_max_total_bytes_1
    builder = create_builder
    builder.max_total_bytes = 11

    crypto = create_crypto

    assert_raises ::Raioquic::Quic::PacketBuilder::QuicPacketBuilderStop do
      builder.start_packet(packet_type: ::Raioquic::Quic::Packet::PACKET_TYPE_ONE_RTT, crypto: crypto)
    end

    datagrams, packets = builder.flush
    assert_empty datagrams
    assert_empty packets
    assert_equal 0, builder.packet_number
  end

  def test_short_header_max_total_bytes_2
    builder = create_builder
    builder.max_total_bytes = 800

    crypto = create_crypto

    builder.start_packet(packet_type: ::Raioquic::Quic::Packet::PACKET_TYPE_ONE_RTT, crypto: crypto)
    assert_equal 773, builder.remaining_flight_space
    buf = builder.start_frame(frame_type: ::Raioquic::Quic::Packet::QuicFrameType::CRYPTO)
    buf.push_bytes("\x00" * builder.remaining_flight_space)
    assert_equal false, builder.packet_is_empty

    assert_raises ::Raioquic::Quic::PacketBuilder::QuicPacketBuilderStop do
      builder.start_packet(packet_type: ::Raioquic::Quic::Packet::PACKET_TYPE_ONE_RTT, crypto: crypto)
    end

    datagrams, packets = builder.flush
    assert_equal 1, datagrams.length
    assert_equal 800, datagrams[0].bytesize
    sent_packet = ::Raioquic::Quic::PacketBuilder::QuicSentPacket.new.tap do |p|
      p.epoch = ::Raioquic::TLS::Epoch::ONE_RTT
      p.in_flight = true
      p.is_ack_eliciting = true
      p.is_crypto_packet = true
      p.packet_number = 0
      p.packet_type = ::Raioquic::Quic::Packet::PACKET_TYPE_ONE_RTT
      p.sent_bytes = 800
      p.quic_logger_frames = []
    end
    assert_equal [sent_packet], packets
    assert_equal 1, builder.packet_number
  end

  def test_short_header_max_total_bytes_3 # rubocop:disable Metrics/MethodLength
    builder = create_builder
    builder.max_total_bytes = 2000

    crypto = create_crypto

    builder.start_packet(packet_type: ::Raioquic::Quic::Packet::PACKET_TYPE_ONE_RTT, crypto: crypto)
    assert_equal 1253, builder.remaining_flight_space
    buf = builder.start_frame(frame_type: ::Raioquic::Quic::Packet::QuicFrameType::CRYPTO)
    buf.push_bytes("\x00" * builder.remaining_flight_space)
    assert_equal false, builder.packet_is_empty

    builder.start_packet(packet_type: ::Raioquic::Quic::Packet::PACKET_TYPE_ONE_RTT, crypto: crypto)
    assert_equal 693, builder.remaining_flight_space
    buf = builder.start_frame(frame_type: ::Raioquic::Quic::Packet::QuicFrameType::CRYPTO)
    buf.push_bytes("\x00" * builder.remaining_flight_space)
    assert_equal false, builder.packet_is_empty

    assert_raises ::Raioquic::Quic::PacketBuilder::QuicPacketBuilderStop do
      builder.start_packet(packet_type: ::Raioquic::Quic::Packet::PACKET_TYPE_ONE_RTT, crypto: crypto)
    end

    datagrams, packets = builder.flush
    assert_equal 2, datagrams.length
    assert_equal 1280, datagrams[0].bytesize
    assert_equal 720, datagrams[1].bytesize
    sent_packet1 = ::Raioquic::Quic::PacketBuilder::QuicSentPacket.new.tap do |p|
      p.epoch = ::Raioquic::TLS::Epoch::ONE_RTT
      p.in_flight = true
      p.is_ack_eliciting = true
      p.is_crypto_packet = true
      p.packet_number = 0
      p.packet_type = ::Raioquic::Quic::Packet::PACKET_TYPE_ONE_RTT
      p.sent_bytes = 1280
      p.quic_logger_frames = []
    end
    sent_packet2 = ::Raioquic::Quic::PacketBuilder::QuicSentPacket.new.tap do |p|
      p.epoch = ::Raioquic::TLS::Epoch::ONE_RTT
      p.in_flight = true
      p.is_ack_eliciting = true
      p.is_crypto_packet = true
      p.packet_number = 1
      p.packet_type = ::Raioquic::Quic::Packet::PACKET_TYPE_ONE_RTT
      p.sent_bytes = 720
      p.quic_logger_frames = []
    end
    assert_equal [sent_packet1, sent_packet2], packets
    assert_equal 2, builder.packet_number
  end

  def test_short_header_ping_only
    builder = create_builder
    crypto = create_crypto

    builder.start_packet(packet_type: ::Raioquic::Quic::Packet::PACKET_TYPE_ONE_RTT, crypto: crypto)
    builder.start_frame(frame_type: ::Raioquic::Quic::Packet::QuicFrameType::PING)
    assert_equal false, builder.packet_is_empty

    datagrams, packets = builder.flush
    assert_equal 1, datagrams.length
    assert_equal 29, datagrams[0].bytesize
    sent_packet = ::Raioquic::Quic::PacketBuilder::QuicSentPacket.new.tap do |p|
      p.epoch = ::Raioquic::TLS::Epoch::ONE_RTT
      p.in_flight = true
      p.is_ack_eliciting = true
      p.is_crypto_packet = false
      p.packet_number = 0
      p.packet_type = ::Raioquic::Quic::Packet::PACKET_TYPE_ONE_RTT
      p.sent_bytes = 29
      p.quic_logger_frames = []
    end
    assert_equal [sent_packet], packets
  end
end
