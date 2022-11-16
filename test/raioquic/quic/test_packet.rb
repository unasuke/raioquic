# frozen_string_literal: true

require "test_helper"

class TestRaioquicQuicPacket < Minitest::Test
  Packet = Raioquic::Quic::Packet

  def test_decode_packet_number
    (0...256).each do |i|
      assert_equal i, Packet.decode_packet_number(truncated: i, num_bits: 8, expected: 0)
    end

    assert_equal 256, Packet.decode_packet_number(truncated: 0, num_bits: 8, expected: 128)
    (1...256).each do |i|
      assert_equal i, Packet.decode_packet_number(truncated: i, num_bits: 8, expected: 128)
    end

    assert_equal 256, Packet.decode_packet_number(truncated: 0, num_bits: 8, expected: 129)
    assert_equal 257, Packet.decode_packet_number(truncated: 1, num_bits: 8, expected: 129)
    (2...256).each do |i|
      assert_equal i, Packet.decode_packet_number(truncated: i, num_bits: 8, expected: 129)
    end

    (0...128).each do |i|
      assert_equal 256 + i, Packet.decode_packet_number(truncated: i, num_bits: 8, expected: 256)
    end
    (129...256).each do |i|
      assert_equal i, Packet.decode_packet_number(truncated: i, num_bits: 8, expected: 256)
    end
  end

  def test_pull_empty
    buf = Raioquic::Buffer.new(data: "")
    assert_raises Raioquic::Buffer::BufferReadError do
      Packet.pull_quic_header(buf: buf, host_cid_length: 8)
    end
  end

  def test_pull_initiali_client
    buf = Raioquic::Buffer.new(data: File.read("test/samples/initial_client.bin"))
    header = Packet.pull_quic_header(buf: buf, host_cid_length: 8)
    assert_equal true, header.is_long_header
    assert_equal Raioquic::Quic::Packet::QuicProtocolVersion::VERSION_1, header.version
    assert_equal Raioquic::Quic::Packet::PACKET_TYPE_INITIAL, header.packet_type
    assert_equal ["858b39368b8e3c6e"].pack("H*"), header.destination_cid
    assert_equal "", header.source_cid # TODO
    assert_equal "", header.token
    assert_equal "", header.integrity_tag
    assert_equal 1262, header.rest_length
    assert_equal 18, buf.tell
  end

  def test_pull_initial_client_truncated
    buf = Raioquic::Buffer.new(data: File.read("test/samples/initial_client.bin")[0..100])
    assert_raises Raioquic::ValueError, "Packet payload is truncated" do
      Packet.pull_quic_header(buf: buf, host_cid_length: 8)
    end
  end

  def test_pull_initial_server
    buf = Raioquic::Buffer.new(data: File.read("test/samples/initial_server.bin"))
    header = Packet.pull_quic_header(buf: buf, host_cid_length: 8)
    assert_equal true, header.is_long_header
    assert_equal Raioquic::Quic::Packet::QuicProtocolVersion::VERSION_1, header.version
    assert_equal Raioquic::Quic::Packet::PACKET_TYPE_INITIAL, header.packet_type
    assert_equal "", header.destination_cid
    assert_equal ["195c68344e28d479"].pack("H*"), header.source_cid
    assert_equal "", header.token
    assert_equal "", header.integrity_tag
    assert_equal 184, header.rest_length
    assert_equal 18, buf.tell
  end

  def test_pull_retry
    skip "crypto libs did not migrtated"
    original_destination_cid = ["fbbd219b7363b64b"].pack("H*")
    data = File.read("test/samples/retry.bin")
    header = Packet.pull_quic_header(buf: buf, host_cid_length: 8)
    assert_equal true, header.is_long_header
    assert_equal Raioquic::Quic::QuicProtocolVersion::VERSION_1, header.version
    assert_equal Raioquic::Quic::Packet::PACKET_TYPE_RETRY, header.packet_type
    assert_equal ["e9d146d8d14cb28e"].pack("H*"), header.destination_cid # TODO:
    assert_equal ["0b0a205a648fcf82d85f128b67bbe08053e6"].pack("H*"), header.source_cid
    assert_equal [
      "44397a35d698393c134b08a932737859f446d3aadd00ed81540c8d8de172" +
        "906d3e7a111b503f9729b8928e7528f9a86a4581f9ebb4cb3b53c283661e" +
        "8530741a99192ee56914c5626998ec0f"
      ].pack("H*"), header.token
    assert_equal ["4620aafd42f1d630588b27575a12da5c"].pack("H*"), header.integrity_tag
    assert_equal 0, header.rest_length
    assert_qeual 125, buf.tell

    encoded = encode_quic_retry(
      version: header.version,
      source_cid: header.source_cid,
      destination_cid: header.destination_cid,
      original_destination_cid: original_destination_cid,
      retry_token: header.token
    )
    # TODO: bob.bin
    assert_equal data, encoded
  end

  def test_pull_retry_draft_29
    # skip
  end

  def test_pull_version_negotiation
    buf = Raioquic::Buffer.new(data: File.read("test/samples/version_negotiation.bin"))
    header = Packet.pull_quic_header(buf: buf, host_cid_length: 8)
    assert_equal true, header.is_long_header
    assert_equal Raioquic::Quic::Packet::QuicProtocolVersion::NEGOTIATION, header.version
    assert_nil header.packet_type
    assert_equal ["9aac5a49ba87a849"].pack("H*"), header.destination_cid
    assert_equal ["f92f4336fa951ba1"].pack("H*"), header.source_cid
    assert_equal "", header.token
    assert_equal "", header.integrity_tag
    assert_equal 8, header.rest_length
    assert_equal 23, buf.tell
    versions = []
    while !buf.eof do
      versions << buf.pull_uint32 while !buf.eof
    end
    assert_equal [0x45474716, Raioquic::Quic::Packet::QuicProtocolVersion::VERSION_1], versions
  end

  def test_pull_long_header_dcid_too_long
    buf = Raioquic::Buffer.new(data: [<<~DATA].pack("H*"))
      c6ff000016150000000000000000000000000000000000000000000000401c514f99ec4bbf1f7a30f9b0c94fef717f1c1d07fec24c99a864da7ede
    DATA
    assert_raises Raioquic::ValueError, "Destination CID is too long (21 bytes)" do
      Packet.pull_quic_header(buf: buf, host_cid_length: 8)
    end
  end

  def test_pull_long_header_scid_too_long
    buf = Raioquic::Buffer.new(data: [<<~DATA].pack("H*"))
      c2ff000016001500000000000000000000000000000000000000000000401cfcee99ec4bbf1f7a30f9b0c9417b8c263cdd8cc972a4439d68a46320
    DATA
    assert_raises Raioquic::ValueError, "Source CID is too long (21 bytes)" do
      Packet.pull_quic_header(buf: buf, host_cid_length: 8)
    end
  end

  def test_pull_long_header_no_fixed_bit
    buf = Raioquic::Buffer.new(data: "\x80\xff\x00\x00\x11\x00\x00")
    assert_raises Raioquic::ValueError, "Packet fixed bit is zero" do
      Packet.pull_quic_header(buf: buf, host_cid_length: 8)
    end
  end

  def test_pull_long_header_too_short
    buf = Raioquic::Buffer.new(data: "\xc0\x00")
    assert_raises Raioquic::Buffer::BufferReadError do
      Packet.pull_quic_header(buf: buf, host_cid_length: 8)
    end
  end

  def test_pull_short_header
    buf = Raioquic::Buffer.new(data: File.read("test/samples/short_header.bin"))
    header = Packet.pull_quic_header(buf: buf, host_cid_length: 8)
    assert_equal false, header.is_long_header
    assert_nil header.version
    assert_equal 0x50, header.packet_type
    assert_equal ["f45aa7b59c0e1ad6"].pack("H*"), header.destination_cid
    assert_equal "", header.source_cid
    assert_equal "", header.token
    assert_equal "", header.integrity_tag
    assert_equal 12, header.rest_length
    assert_equal 9, buf.tell
  end

  def test_pull_short_header_no_fixed_bit
    buf = Raioquic::Buffer.new(data: "\x00")
    assert_raises Raioquic::ValueError, "Packer fixed bit is zero" do
      Packet.pull_quic_header(buf: buf, host_cid_length: 8)
    end
  end

  def test_encode_quic_version_negotiation
    data = Packet.encode_quic_version_negotiation(
      destination_cid: ["9aac5a49ba87a849"].pack("H*"),
      source_cid: ["f92f4336fa951ba1"].pack("H*"),
      supported_versions: [0x45474716, Raioquic::Quic::Packet::QuicProtocolVersion::VERSION_1]
    )
    expected_data = File.read("test/samples/version_negotiation.bin")
    expected_data.force_encoding(Encoding::ASCII_8BIT)
    assert_equal expected_data[1..], data[1..]
  end

  def test_params
    data = [
      "010267100210cc2fd6e7d97a53ab5be85b28d75c8008030247e404048005fff" +
      "a05048000ffff06048000ffff0801060a01030b0119"
    ].pack("H*")

    buf = Raioquic::Buffer.new(data: data)
    params = Packet.pull_quic_transport_parameters(buf)
    assert_equal QuicTransportParameters(), params

    buf = Raioquic::Buffer.new(capacity: data.length)
    Packet.push_quic_transport_parameters(buf: buf, params: params)
    assert_equal data.length, buf.data.length
  end

  def test_params_disable_active_migration
    data = ["0c00"].pack("H*")
    buf  = Raioquic::Buffer.new(data: data)

    params = Packet.pull_quic_transport_parameters(buf)
    quicparams = Raioquic::Quic::Packet::QuicTransportParameters.new.tap do |p|
      p.disable_active_migration = true
    end
    assert_equal quicparams, params

    buf = Raioquic::Buffer.new(capacity: data.size)
    Packet.push_quic_transport_parameters(buf: buf, params: params)
    assert_equal data, buf.data
  end

  def test_params_preferred_address
    skip "buffer read error"
    data = [<<~BIN].pack("H*")
      0d3b8ba27b8611532400890200000000f03c91fffe69a45411531262c4518d63013f0c287ed3573efa9095603746b2e02d45480ba6643e5c6e7d48ecb4
    BIN

    buf = Raioquic::Buffer.new(data: data)
    params = Packet.pull_quic_transport_parameters(buf)
    assert_equal QuicTransportParameters(), params # TODO:

    buf = Raioquic::Buffer.new(capacity: 1000)
    Packet.push_quic_transport_parameters(buf: buf, params: params)
    assert_equal data, buf.data
  end

  def test_params_unknown
    data = ["8000ff000100"].pack("H*")
    buf = Raioquic::Buffer.new(data: data)
    params = Packet.pull_quic_transport_parameters(buf)
    assert_equal Raioquic::Quic::Packet::QuicTransportParameters.new(), params
  end

  def test_preferred_address_ipv4_only
    data = [
      "8ba27b8611530000000000000000000000000000000000001262c4518d6" +
        "3013f0c287ed3573efa9095603746b2e02d45480ba6643e5c6e7d48ecb4"
    ].pack("H*").force_encoding(Encoding::ASCII_8BIT)

    buf = Raioquic::Buffer.new(data: data)
    preferred_address = Packet.pull_quic_preferred_address(buf)
    preferred_addr = Raioquic::Quic::Packet::QuicPreferredAddress.new.tap do |address|
      address[:ipv4_address] = { host: IPAddr.new("139.162.123.134"), port: 4435 }
      address[:ipv6_address] = nil
      address[:connection_id] = ["62c4518d63013f0c287ed3573efa90956037"].pack("H*")
      address[:stateless_reset_token] = ["46b2e02d45480ba6643e5c6e7d48ecb4"].pack("H*")
    end
    assert_equal preferred_addr, preferred_address

    buf = Raioquic::Buffer.new(data: data)
    Packet.push_quic_preferred_address(buf: buf, preferred_address: preferred_address)
    assert_equal data, buf.data
  end

  def test_preferred_address_ipv6_only
    data = [
      "0000000000002400890200000000f03c91fffe69a45411531262c4518d63013" +
        "f0c287ed3573efa9095603746b2e02d45480ba6643e5c6e7d48ecb4"
    ].pack("H*").force_encoding(Encoding::ASCII_8BIT)

    buf = Raioquic::Buffer.new(data: data)
    preferred_address = Packet.pull_quic_preferred_address(buf)
    expected = Raioquic::Quic::Packet::QuicPreferredAddress.new.tap do |address|
      address[:ipv4_address] = nil
      address[:ipv6_address] = { host: IPAddr.new("2400:8902::f03c:91ff:fe69:a454"), port: 4435 }
      address[:connection_id] = ["62c4518d63013f0c287ed3573efa90956037"].pack("H*")
      address[:stateless_reset_token] = ["46b2e02d45480ba6643e5c6e7d48ecb4"].pack("H*")
    end
    assert_equal expected, preferred_address

    buf = Raioquic::Buffer.new(capacity: data.length)
    Packet.push_quic_preferred_address(buf: buf, preferred_address: preferred_address)
    assert_equal data, buf.data
  end

  def test_ack_frame
    data = "\x00\x02\x00\x00"
    buf = Raioquic::Buffer.new(data: data)
    rangeset, delay = Packet.pull_ack_frame(buf)
    assert_equal [0...1], rangeset.list
    assert_equal 2, delay

    buf = Raioquic::Buffer.new(capacity: data.length)
    Packet.push_ack_frame(buf: buf, rangeset: rangeset, delay: delay)
    assert_equal data, buf.data
  end

  def test_ack_frame_with_one_range_2
    data = "\x05\x02\x01\x00\x00\x03"
    buf = Raioquic::Buffer.new(data: data)
    rangeset, delay = Packet.pull_ack_frame(buf)
    assert_equal [0...4, 5...6], rangeset.list
    assert_equal 2, delay
    buf = Raioquic::Buffer.new(capacity: data.length)
    Packet.push_ack_frame(buf: buf, rangeset: rangeset, delay: delay)
    assert_equal data, buf.data
  end

  def test_ack_frame_with_one_range_3
    data = "\x05\x02\x01\x00\x01\x02"
    buf = Raioquic::Buffer.new(data: data)
    rangeset, delay = Packet.pull_ack_frame(buf)
    assert_equal [0...3, 5...6], rangeset.list
    assert_equal 2, delay
    buf = Raioquic::Buffer.new(capacity: data.length)
    Packet.push_ack_frame(buf: buf, rangeset: rangeset, delay: delay)
    assert_equal data, buf.data
  end

  def test_ack_frame_with_two_ranges
    data = "\x04\x02\x02\x00\x00\x00\x00\x00"
    buf = Raioquic::Buffer.new(data: data)
    rangeset, delay = Packet.pull_ack_frame(buf)
    assert_equal [0...1, 2...3, 4...5], rangeset.list
    assert_equal 2, delay
    buf = Raioquic::Buffer.new(capacity: data.length)
    Packet.push_ack_frame(buf: buf, rangeset: rangeset, delay: delay)
    assert_equal data, buf.data
  end
end
