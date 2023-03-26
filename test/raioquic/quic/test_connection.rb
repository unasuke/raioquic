
# frozen_string_literal: true

require "test_helper"

class TestRaioquicQuicConnection < Minitest::Test
  i_suck_and_my_tests_are_order_dependent!
  CLIENT_ADDR = ["1.2.3.4", 1234]
  SERVER_ADDR = ["2.3.4.5", 4433]
  TICK = 0.05 #seconds

  class SessionTicketStore
    def initialize
      @tickets = {}
    end

    def add(ticket)
      @tickets[ticket.ticket] = ticket
    end

    def pop(label)
      @tickets.delete(label)
    end
  end

  def client_receive_context(client, epoch=::Raioquic::TLS::Epoch::ONE_RTT)
    return ::Raioquic::Quic::Connection::QuicReceiveContext.new.tap do |ctx|
      ctx.epoch = epoch
      ctx.host_cid = client.host_cid
      ctx.network_path = client.network_paths[0]
      ctx.quic_logger_frames = []
      ctx.time = Time.now.to_f
    end
  end

  def consume_events(connection)
    while 1
      event = connection.next_event
      break unless event
    end
  end

  def create_standalone_client(**client_option)
    client = ::Raioquic::Quic::Connection::QuicConnection.new(
      configuration: ::Raioquic::Quic::QuicConfiguration.new(is_client: true, quic_logger: ::Raioquic::Quic::Logger::QuicFileLogger.new(path: "log"), **client_option),
    )
    client.ack_delay = 0

    # kick-off handshake
    client.connect(addr: SERVER_ADDR, now: Time.now.to_f)
    assert_equal 1, drop(client)
    return client
  end

  def datagram_sizes(items)
    items.map { |i| i[0].bytesize }
  end

  def client_and_server(
    client_kwargs: {},
    client_options: {},
    client_patch: ->(_) {},
    handshake: true,
    server_kwargs: {},
    server_certfile: Utils::SERVER_CERTFILE,
    server_keyfile: Utils::SERVER_KEYFILE,
    server_options: {},
    server_patch: ->(_) {}
  )
    client_configuration = ::Raioquic::Quic::QuicConfiguration.new(is_client: true, quic_logger: ::Raioquic::Quic::Logger::QuicFileLogger.new(path: "log"), **client_options)
    client_configuration.load_verify_locations(cafile: Utils::SERVER_CACERTFILE)
    client = ::Raioquic::Quic::Connection::QuicConnection.new(
      configuration: client_configuration, **client_kwargs,
    )
    client.ack_delay = 0
    disable_packet_pacing(client)
    client_patch.call(client)

    server_configuration = ::Raioquic::Quic::QuicConfiguration.new(is_client: false, quic_logger: ::Raioquic::Quic::Logger::QuicFileLogger.new(path: "log"), **server_options)
    server_configuration.load_cert_chain(server_certfile, server_keyfile)
    server = ::Raioquic::Quic::Connection::QuicConnection.new(
      configuration: server_configuration,
      original_destination_connection_id: client.original_destination_connection_id,
      **server_kwargs,
    )
    server.ack_delay = 0
    disable_packet_pacing(server)
    server_patch.call(server)

    # perform handshake
    if handshake
      puts "HANDSHAKE in client_and_server"
      client.connect(addr: SERVER_ADDR, now: Time.now.to_f)
      3.times { roundtrip(client, server) }
    end

    yield client, server

    # close
    client.configuration.quic_logger.end_trace(client.quic_logger)
    server.configuration.quic_logger.end_trace(server.quic_logger)
    client.close
    server.close
  end

  class DummyPacketPacing < ::Raioquic::Quic::Recovery::QuicPacketPacer
    def next_send_time(now)
      return nil
    end
  end

  def disable_packet_pacing(connection)
    connection.loss.pacer = DummyPacketPacing.new
  end

  def encode_transport_parameters(parameters)
    buf = ::Raioquic::Buffer.new(capacity: 512)
    ::Raioquic::Quic::Packet.push_quic_transport_parameters(buf: buf, params: parameters)
    return buf.data
  end

  def sequence_numbers(connection_ids)
    connection_ids.map { |conn| conn.sequence_number }
  end

  # Drop datagrams from `sender`.
  def drop(sender)
    sender.datagrams_to_send(now: Time.now.to_f).length
  end

  # Send datagrams from `sender` to `receiver` and back.
  def roundtrip(sender, receiver)
    [transfer(sender, receiver), transfer(receiver, sender)]
  end

  # Send datagrams from `sender` to `receiver`.
  def transfer(sender, receiver)
    datagrams = 0
    from_addr = sender.is_client ? CLIENT_ADDR : SERVER_ADDR
    sender.datagrams_to_send(now: Time.now.to_f).each do |data, _addr|
      puts "transfer====datagrams: #{datagrams}"
      datagrams += 1
      receiver.receive_datagram(data: data, addr: from_addr, now: Time.now.to_f)
    end
    return datagrams
  end

  # Check handshake completed.
  def check_handshake(client, server, alpn_protocol = nil)
    event = client.next_event
    assert_equal ::Raioquic::Quic::Event::ProtocolNegotiated, event.class
    assert_equal alpn_protocol, event.alpn_protocol
    event = client.next_event
    assert_equal ::Raioquic::Quic::Event::HandshakeCompleted, event.class
    assert_equal alpn_protocol, event.alpn_protocol
    assert_equal false, event.early_data_accepted
    assert_equal false, event.session_resumed
    7.times { assert_equal ::Raioquic::Quic::Event::ConnectionIdIssued, client.next_event.class }
    assert_nil client.next_event

    # pp server.events
    event = server.next_event
    assert_equal ::Raioquic::Quic::Event::ProtocolNegotiated, event.class
    assert_equal alpn_protocol, event.alpn_protocol
    event = server.next_event
    assert_equal ::Raioquic::Quic::Event::HandshakeCompleted, event.class
    assert_equal alpn_protocol, event.alpn_protocol
    puts "session resumed called"
    7.times { |i| puts i; assert_equal ::Raioquic::Quic::Event::ConnectionIdIssued, server.next_event.class }
    assert_nil server.next_event
  end

  def test_connect
    client_and_server do |client, server|
      # check handshake completed
      check_handshake(client, server)

      # check each endpoint has available connection IDs for the peer
      assert_equal [1, 2, 3, 4, 5, 6, 7], sequence_numbers(client.peer_cid_available)
      assert_equal [1, 2, 3, 4, 5, 6, 7], sequence_numbers(server.peer_cid_available)

      # client closes the connection
      client.close
      assert_equal 1, transfer(client, server)

      # check connection closes on the client side
      client.handle_timer(now: client.get_timer)
      event = client.next_event
      assert_equal ::Raioquic::Quic::Event::ConnectionTerminated, event.class
      assert_equal ::Raioquic::Quic::Packet::QuicErrorCode::NO_ERROR, event.error_code
      assert_equal nil, event.frame_type
      assert_equal "", event.reason_phrase
      assert_nil client.next_event

      # check connection closes on the server side
      server.handle_timer(now: server.get_timer)
      event = server.next_event
      assert_equal ::Raioquic::Quic::Event::ConnectionTerminated, event.class
      assert_equal ::Raioquic::Quic::Packet::QuicErrorCode::NO_ERROR, event.error_code
      assert_equal nil, event.frame_type
      assert_equal "", event.reason_phrase
      assert_nil server.next_event

      # check client log
      # TODO: test logging

      # check server log
      # TODO: test logging
    end
  end

  def test_connect_with_alpn
    client_and_server(
      client_options: { alpn_protocols: %w[h3-25 hq-25] },
      server_options: { alpn_protocols: %w[hq-25] },
    ) do |client, server|
      # check handshake completed
      check_handshake(client, server, "hq-25")
    end
  end

  def test_connect_with_secrets_log
    skip "logging is not implemented yet"

    client_log_file = StringIO.new
    server_log_file = StringIO.new
    client_and_server(
      client_options: { secrets_log_file: client_log_file },
      server_options: { secrets_log_file: server_log_file },
    ) do |client, server|
      # check handshake completed
      check_handshake(client, server)

      # check secrets were logged
      client_log = client_log_file.read
      server_log = server_log_file.read
      assert_equal client_log, server_log
      labels = client_log.split("\n").map { |l| l.split(" ")[0] }
      assert_equal [
        "SERVER_HANDSHAKE_TRAFFIC_SECRET",
        "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
        "SERVER_TRAFFIC_SECRET_0",
        "CLIENT_TRAFFIC_SECRET_0",
      ], labels
    end
  end

  def test_connect_with_cert_chain
    client_and_server(server_certfile: Utils::SERVER_CERTFILE_WITH_CHAIN) do |client, server|
      # check handshake completed
      check_handshake(client, server)
    end
  end

  def test_connect_with_cipher_suite_aes128
    client_and_server(client_options: { cipher_suites: [::Raioquic::TLS::CipherSuite::AES_128_GCM_SHA256] }) do |client, server|
      # check handshake completed
      check_handshake(client, server)

      # check selected cipher suite
      assert_equal ::Raioquic::TLS::CipherSuite::AES_128_GCM_SHA256, client.tls.key_schedule.cipher_suite
      assert_equal ::Raioquic::TLS::CipherSuite::AES_128_GCM_SHA256, server.tls.key_schedule.cipher_suite
    end
  end

  def test_connect_with_cipher_suite_aes256
    client_and_server(client_options: { cipher_suites: [::Raioquic::TLS::CipherSuite::AES_256_GCM_SHA384] }) do |client, server|
      # check handshake completed
      check_handshake(client, server)

      # check selected cipher suite
      assert_equal ::Raioquic::TLS::CipherSuite::AES_256_GCM_SHA384, client.tls.key_schedule.cipher_suite
      assert_equal ::Raioquic::TLS::CipherSuite::AES_256_GCM_SHA384, server.tls.key_schedule.cipher_suite
    end
  end

  def test_connect_with_cipher_suite_chacha20
    skip "chacha20 is not supported yet"

    client_and_server(client_options: { cipher_suites: [::Raioquic::TLS::CipherSuite::CHACHA20_POLY1305_SHA256] }) do |client, server|
      # check handshake completed
      check_handshake(client, server)

      # check selected cipher suite
      assert_equal ::Raioquic::TLS::CipherSuite::CHACHA20_POLY1305_SHA256, client.tls.key_schedule.cipher_suite
      assert_equal ::Raioquic::TLS::CipherSuite::CHACHA20_POLY1305_SHA256, server.tls.key_schedule.cipher_suite
    end
  end

  # Check connection is established even in the client's INITIAL is lost.
  #
  # The client's PTO fires, triggering retransmission.
  def test_connect_with_loss_1
    client_configuration = ::Raioquic::Quic::QuicConfiguration.new(is_client: true, quic_logger: ::Raioquic::Quic::Logger::QuicFileLogger.new(path: "log"))
    client_configuration.load_verify_locations(cafile: Utils::SERVER_CACERTFILE)

    client = ::Raioquic::Quic::Connection::QuicConnection.new(configuration: client_configuration)
    client.ack_delay = 0

    server_configuration = ::Raioquic::Quic::QuicConfiguration.new(is_client: false, quic_logger: ::Raioquic::Quic::Logger::QuicFileLogger.new(path: "log"))
    server_configuration.load_cert_chain(Utils::SERVER_CERTFILE, Utils::SERVER_KEYFILE)

    server = ::Raioquic::Quic::Connection::QuicConnection.new(
      configuration: server_configuration,
      original_destination_connection_id: client.original_destination_connection_id,
    )
    server.ack_delay = 0

    # client sends INITIAL
    now = 0.0
    client.connect(addr: SERVER_ADDR, now: now)
    items = client.datagrams_to_send(now: now)
    assert_equal [1280], datagram_sizes(items)
    assert_equal 0.2, client.get_timer

    # INITIAL is lost
    now = client.get_timer
    client.handle_timer(now: now)
    # binding.b
    items = client.datagrams_to_send(now: now)
    assert_equal [1280], datagram_sizes(items)
    assert_in_delta 0.6, client.get_timer

    # server receives INITIAL, sends INITIAL + HANDSHAKE
    now += TICK
    server.receive_datagram(data: items[0][0], addr: CLIENT_ADDR, now: now)
    items = server.datagrams_to_send(now: now)
    assert_equal [1280, 1068], datagram_sizes(items) # TODO: FIXME!
    assert_in_delta 0.45, server.get_timer
    assert_equal 1, server.loss.spaces[0].sent_packets.length
    assert_equal 2, server.loss.spaces[1].sent_packets.length
    assert_equal ::Raioquic::Quic::Event::ProtocolNegotiated, server.next_event.class
    assert_nil server.next_event

    # handshake continues normally
    now += TICK
    client.receive_datagram(data: items[0][0], addr: SERVER_ADDR, now: now)
    client.receive_datagram(data: items[1][0], addr: SERVER_ADDR, now: now)
    items = client.datagrams_to_send(now: now)
    assert_equal [376], datagram_sizes(items) # TODO: FIXME!
    assert_in_delta 0.625, client.get_timer
    assert_equal ::Raioquic::Quic::Event::ProtocolNegotiated, client.next_event.class
    assert_equal ::Raioquic::Quic::Event::HandshakeCompleted, client.next_event.class
    assert_equal ::Raioquic::Quic::Event::ConnectionIdIssued, client.next_event.class

    now += TICK
    server.receive_datagram(data: items[0][0], addr: CLIENT_ADDR, now: now)
    items = server.datagrams_to_send(now: now)
    client.configuration.quic_logger.end_trace(client.quic_logger)
    server.configuration.quic_logger.end_trace(server.quic_logger)
    assert_equal [229], datagram_sizes(items) # TODO: FIXME!
    assert_in_delta 0.625, server.get_timer
    assert_equal 0, server.loss.spaces[0].sent_packets.length
    assert_equal 0, server.loss.spaces[1].sent_packets.length
    assert_equal ::Raioquic::Quic::Event::HandshakeCompleted, server.next_event.class
    assert_equal ::Raioquic::Quic::Event::ConnectionIdIssued, server.next_event.class

    now += TICK
    client.receive_datagram(data: items[0][0], addr: SERVER_ADDR, now: now)
    items = client.datagrams_to_send(now: now)
    assert_equal [32], datagram_sizes(items)
    assert_in_delta 60.4, client.get_timer # idle timeout
  end

  # Check connection is established even in the server's INITIAL is lost.
  #
  # The client receives HANDSHAKE packets before it has the corresponding keys
  # and decides to retransmit its own CRYPTO to speedup handshake completion.
  def test_connect_with_loss_2
    client_configuration = ::Raioquic::Quic::QuicConfiguration.new(is_client: true)
    client_configuration.load_verify_locations(cafile: Utils::SERVER_CACERTFILE)

    client = ::Raioquic::Quic::Connection::QuicConnection.new(configuration: client_configuration)
    client.ack_delay = 0

    server_configuration = ::Raioquic::Quic::QuicConfiguration.new(is_client: false)
    server_configuration.load_cert_chain(Utils::SERVER_CERTFILE, Utils::SERVER_KEYFILE)

    server = ::Raioquic::Quic::Connection::QuicConnection.new(
      configuration: server_configuration,
      original_destination_connection_id: client.original_destination_connection_id,
    )
    server.ack_delay = 0

    # client sends INITIAL
    now = 0.0
    client.connect(addr: SERVER_ADDR, now: now)
    items = client.datagrams_to_send(now: now)
    assert_equal [1280], datagram_sizes(items)
    assert_equal 0.2, client.get_timer

    # server receives INITIAL, sends INITIAL + HANDSHAKE but first datagram is lost
    now += TICK
    server.receive_datagram(data: items[0][0], addr: CLIENT_ADDR, now: now)
    items = server.datagrams_to_send(now: now)
    assert_equal [1280, 1068], datagram_sizes(items) # TODO: FIXME!
    assert_in_delta 0.25, server.get_timer
    assert_equal 1, server.loss.spaces[0].sent_packets.length
    assert_equal 2, server.loss.spaces[1].sent_packets.length
    assert_equal ::Raioquic::Quic::Event::ProtocolNegotiated, server.next_event.class
    assert_nil server.next_event

    # client only receives second datagram, retransmits INITIAL
    now += TICK
    client.receive_datagram(data: items[1][0], addr: SERVER_ADDR, now: now)
    items = client.datagrams_to_send(now: now)
    assert_equal [1280], datagram_sizes(items)
    assert_in_delta 0.3, client.get_timer
    assert_nil client.next_event

    # server receives duplicate INITIAL, retransmits INITIAL + HANDSHAKE
    now += TICK
    server.receive_datagram(data: items[0][0], addr: CLIENT_ADDR, now: now)
    items = server.datagrams_to_send(now: now)
    assert_equal [1280, 1068], datagram_sizes(items)
    assert_in_delta 0.35, server.get_timer
    assert_equal 1, server.loss.spaces[0].sent_packets.length
    assert_equal 2, server.loss.spaces[1].sent_packets.length

    # handshake continues normally
    now += TICK
    client.receive_datagram(data: items[0][0], addr: SERVER_ADDR, now: now)
    client.receive_datagram(data: items[1][0], addr: SERVER_ADDR, now: now)
    items = client.datagrams_to_send(now: now)
    assert_equal [376], datagram_sizes(items)
    assert_in_delta 0.525, client.get_timer
    assert_equal ::Raioquic::Quic::Event::ProtocolNegotiated, client.next_event.class
    assert_equal ::Raioquic::Quic::Event::HandshakeCompleted, client.next_event.class
    assert_equal ::Raioquic::Quic::Event::ConnectionIdIssued, client.next_event.class

    now += TICK
    server.receive_datagram(data: items[0][0], addr: CLIENT_ADDR, now: now)
    items = server.datagrams_to_send(now: now)
    assert_equal [229], datagram_sizes(items)
    assert_in_delta 0.525, server.get_timer
    assert_equal 0, server.loss.spaces[0].sent_packets.length
    assert_equal 0, server.loss.spaces[1].sent_packets.length
    assert_equal ::Raioquic::Quic::Event::HandshakeCompleted, server.next_event.class
    assert_equal ::Raioquic::Quic::Event::ConnectionIdIssued, server.next_event.class

    now += TICK
    client.receive_datagram(data: items[0][0], addr: SERVER_ADDR, now: now)
    items = client.datagrams_to_send(now: now)
    assert_equal [32], datagram_sizes(items)
    assert_in_delta 60.3, client.get_timer # idle timeout
  end

  # Check connection is established even in the server's INITIAL + HANDSHAKE are lost.
  #
  # The server receives duplicate CRYPTO and decides to retransmit its own CRYPTO to speedup handshake completion.
  def test_connect_with_loss_3
    client_configuration = ::Raioquic::Quic::QuicConfiguration.new(is_client: true)
    client_configuration.load_verify_locations(cafile: Utils::SERVER_CACERTFILE)

    client = ::Raioquic::Quic::Connection::QuicConnection.new(configuration: client_configuration)
    client.ack_delay = 0

    server_configuration = ::Raioquic::Quic::QuicConfiguration.new(is_client: false)
    server_configuration.load_cert_chain(Utils::SERVER_CERTFILE, Utils::SERVER_KEYFILE)

    server = ::Raioquic::Quic::Connection::QuicConnection.new(
      configuration: server_configuration,
      original_destination_connection_id: client.original_destination_connection_id,
    )
    server.ack_delay = 0

    # client sends INITIAL
    now = 0.0
    client.connect(addr: SERVER_ADDR, now: now)
    items = client.datagrams_to_send(now: now)
    assert_equal [1280], datagram_sizes(items)
    assert_equal 0.2, client.get_timer

    # server receives INITIAL, sends INITIAL + HANDSHAKE
    now += TICK
    server.receive_datagram(data: items[0][0], addr: CLIENT_ADDR, now: now)
    items = server.datagrams_to_send(now: now)
    assert_equal [1280, 1068], datagram_sizes(items) # TODO: FIXME!
    assert_in_delta 0.25, server.get_timer
    assert_equal 1, server.loss.spaces[0].sent_packets.length
    assert_equal 2, server.loss.spaces[1].sent_packets.length
    assert_equal ::Raioquic::Quic::Event::ProtocolNegotiated, server.next_event.class
    assert_nil server.next_event

    # INITIAL + HANDSHAKE are lost, client retransmits INITIAL
    now = client.get_timer
    client.handle_timer(now: now)
    items = client.datagrams_to_send(now: now)
    assert_equal [1280], datagram_sizes(items)
    assert_in_delta 0.6, client.get_timer
    assert_nil client.next_event

    # server receives duplicate INITIAL, retransmits INITIAL + HANDSHAKE
    now += TICK
    server.receive_datagram(data: items[0][0], addr: CLIENT_ADDR, now: now)
    items = server.datagrams_to_send(now: now)
    assert_equal [1280, 1068], datagram_sizes(items)
    assert_in_delta 0.45, server.get_timer
    assert_equal 1, server.loss.spaces[0].sent_packets.length
    assert_equal 2, server.loss.spaces[1].sent_packets.length

    # handshake continues normally
    now += TICK
    client.receive_datagram(data: items[0][0], addr: SERVER_ADDR, now: now)
    client.receive_datagram(data: items[1][0], addr: SERVER_ADDR, now: now)
    items = client.datagrams_to_send(now: now)
    assert_equal [376], datagram_sizes(items)
    assert_in_delta 0.625, client.get_timer
    assert_equal ::Raioquic::Quic::Event::ProtocolNegotiated, client.next_event.class
    assert_equal ::Raioquic::Quic::Event::HandshakeCompleted, client.next_event.class
    assert_equal ::Raioquic::Quic::Event::ConnectionIdIssued, client.next_event.class

    now += TICK
    server.receive_datagram(data: items[0][0], addr: CLIENT_ADDR, now: now)
    items = server.datagrams_to_send(now: now)
    assert_equal [229], datagram_sizes(items)
    assert_in_delta 0.625, server.get_timer
    assert_equal 0, server.loss.spaces[0].sent_packets.length
    assert_equal 0, server.loss.spaces[1].sent_packets.length
    assert_equal ::Raioquic::Quic::Event::HandshakeCompleted, server.next_event.class
    assert_equal ::Raioquic::Quic::Event::ConnectionIdIssued, server.next_event.class

    now += TICK
    client.receive_datagram(data: items[0][0], addr: SERVER_ADDR, now: now)
    items = client.datagrams_to_send(now: now)
    assert_equal [32], datagram_sizes(items)
    assert_in_delta 60.4, client.get_timer # idle timeout
  end

  # Check connection is established even in the server's HANDSHAKE is lost.
  def test_connect_with_loss_4
    client_configuration = ::Raioquic::Quic::QuicConfiguration.new(is_client: true, quic_logger: ::Raioquic::Quic::Logger::QuicFileLogger.new(path: "log"))
    client_configuration.load_verify_locations(cafile: Utils::SERVER_CACERTFILE)

    client = ::Raioquic::Quic::Connection::QuicConnection.new(configuration: client_configuration)
    client.ack_delay = 0

    server_configuration = ::Raioquic::Quic::QuicConfiguration.new(is_client: false, quic_logger: ::Raioquic::Quic::Logger::QuicFileLogger.new(path: "log"))
    server_configuration.load_cert_chain(Utils::SERVER_CERTFILE, Utils::SERVER_KEYFILE)

    server = ::Raioquic::Quic::Connection::QuicConnection.new(
      configuration: server_configuration,
      original_destination_connection_id: client.original_destination_connection_id,
    )
    server.ack_delay = 0

    # client sends INITIAL
    now = 0.0
    client.connect(addr: SERVER_ADDR, now: now)
    items = client.datagrams_to_send(now: now)
    assert_equal [1280], datagram_sizes(items)
    assert_equal 0.2, client.get_timer

    # server receives INITIAL, sends INITIAL + HANDSHAKE, but second datagram is lost
    now += TICK
    server.receive_datagram(data: items[0][0], addr: CLIENT_ADDR, now: now)
    items = server.datagrams_to_send(now: now)
    assert_equal [1280, 1068], datagram_sizes(items)
    assert_in_delta 0.25, server.get_timer
    assert_equal 1, server.loss.spaces[0].sent_packets.length
    assert_equal 2, server.loss.spaces[1].sent_packets.length
    assert_equal ::Raioquic::Quic::Event::ProtocolNegotiated, server.next_event.class
    assert_nil server.next_event

    # client only receives first datagram and sends ACKS
    now += TICK
    client.receive_datagram(data: items[0][0], addr: SERVER_ADDR, now: now)
    items = client.datagrams_to_send(now: now)
    assert_equal [97], datagram_sizes(items)
    assert_in_delta 0.325, client.get_timer
    assert_equal ::Raioquic::Quic::Event::ProtocolNegotiated, client.next_event.class
    assert_nil client.next_event

    # client PTO - HANDSHAKE PING
    now = client.get_timer
    client.handle_timer(now: now)
    items = client.datagrams_to_send(now: now)
    assert_equal [45], datagram_sizes(items)
    assert_in_delta 0.975, client.get_timer

    # server receives PING, discards INITIAL and sends ACK
    now += TICK
    server.receive_datagram(data: items[0][0], addr: CLIENT_ADDR, now: now)
    items = server.datagrams_to_send(now: now)
    client.configuration.quic_logger.end_trace(client.quic_logger)
    server.configuration.quic_logger.end_trace(server.quic_logger)
    assert_equal [48], datagram_sizes(items)
    assert_in_delta 0.25, server.get_timer
    assert_equal 0, server.loss.spaces[0].sent_packets.length
    assert_equal 3, server.loss.spaces[1].sent_packets.length
    assert_nil server.next_event

    # ACKs are lost, server retransmits HANDSHAKE
    now = server.get_timer
    server.handle_timer(now: now)
    items = server.datagrams_to_send(now: now)
    assert_equal [1280, 892], datagram_sizes(items)
    assert_in_delta 0.65, server.get_timer
    assert_equal 0, server.loss.spaces[0].sent_packets.length
    assert_equal 3, server.loss.spaces[1].sent_packets.length
    assert_nil server.next_event

    # handshake continues normally
    now += TICK
    client.receive_datagram(data: items[0][0], addr: SERVER_ADDR, now: now)
    client.receive_datagram(data: items[1][0], addr: SERVER_ADDR, now: now)
    items = client.datagrams_to_send(now: now)
    assert_equal [329], datagram_sizes(items)
    assert_in_delta 0.95, client.get_timer
    assert_equal ::Raioquic::Quic::Event::HandshakeCompleted, client.next_event.class
    assert_equal ::Raioquic::Quic::Event::ConnectionIdIssued, client.next_event.class

    now += TICK
    server.receive_datagram(data: items[0][0], addr: CLIENT_ADDR, now: now)
    items = server.datagrams_to_send(now: now)
    assert_equal [229], datagram_sizes(items)
    assert_in_delta 0.675, server.get_timer
    assert_equal ::Raioquic::Quic::Event::HandshakeCompleted, server.next_event.class
    assert_equal ::Raioquic::Quic::Event::ConnectionIdIssued, server.next_event.class

    now += TICK
    client.receive_datagram(data: items[0][0], addr: SERVER_ADDR, now: now)
    items = client.datagrams_to_send(now: now)
    assert_equal [32], datagram_sizes(items)
    assert_in_delta 60.4, client.get_timer # idle timeout
  end

  # Check connection is established even in the server's HANDSHAKE_DONE is lost.
  def test_connect_with_loss_5
    client_configuration = ::Raioquic::Quic::QuicConfiguration.new(is_client: true)
    client_configuration.load_verify_locations(cafile: Utils::SERVER_CACERTFILE)

    client = ::Raioquic::Quic::Connection::QuicConnection.new(configuration: client_configuration)
    client.ack_delay = 0

    server_configuration = ::Raioquic::Quic::QuicConfiguration.new(is_client: false)
    server_configuration.load_cert_chain(Utils::SERVER_CERTFILE, Utils::SERVER_KEYFILE)

    server = ::Raioquic::Quic::Connection::QuicConnection.new(
      configuration: server_configuration,
      original_destination_connection_id: client.original_destination_connection_id,
    )
    server.ack_delay = 0

    # client sends INITIAL
    now = 0.0
    client.connect(addr: SERVER_ADDR, now: now)
    items = client.datagrams_to_send(now: now)
    assert_equal [1280], datagram_sizes(items)
    assert_equal 0.2, client.get_timer

    # server receives INITIAL, sends INITIAL + HANDSHAKE
    now += TICK
    server.receive_datagram(data: items[0][0], addr: CLIENT_ADDR, now: now)
    items = server.datagrams_to_send(now: now)
    assert_equal [1280, 1068], datagram_sizes(items)
    assert_in_delta 0.25, server.get_timer
    assert_equal 1, server.loss.spaces[0].sent_packets.length
    assert_equal 2, server.loss.spaces[1].sent_packets.length
    assert_equal ::Raioquic::Quic::Event::ProtocolNegotiated, server.next_event.class
    assert_nil server.next_event

    # client receives INITIAL + HANDSHAKE
    now += TICK
    client.receive_datagram(data: items[0][0], addr: CLIENT_ADDR, now: now)
    client.receive_datagram(data: items[1][0], addr: CLIENT_ADDR, now: now)
    items = client.datagrams_to_send(now: now)
    assert_equal [376], datagram_sizes(items)
    assert_in_delta 0.425, client.get_timer
    assert_equal ::Raioquic::Quic::Event::ProtocolNegotiated, client.next_event.class
    assert_equal ::Raioquic::Quic::Event::HandshakeCompleted, client.next_event.class
    assert_equal ::Raioquic::Quic::Event::ConnectionIdIssued, client.next_event.class


    # server completes handshake, but HANDSHAKE_DONE is lost
    now += TICK
    server.receive_datagram(data: items[0][0], addr: CLIENT_ADDR, now: now)
    items = server.datagrams_to_send(now: now)
    assert_equal [229], datagram_sizes(items)
    assert_in_delta 0.425, server.get_timer
    assert_equal 0, server.loss.spaces[0].sent_packets.length
    assert_equal 0, server.loss.spaces[1].sent_packets.length
    assert_equal ::Raioquic::Quic::Event::HandshakeCompleted, server.next_event.class
    assert_equal ::Raioquic::Quic::Event::ConnectionIdIssued, server.next_event.class

    # server PTO - 1-RTT PING
    now = server.get_timer
    server.handle_timer(now: now)
    items = server.datagrams_to_send(now: now)
    assert_equal [29], datagram_sizes(items)
    assert_in_delta 0.975, server.get_timer

    # client receives PING, sends ACK
    now += TICK
    client.receive_datagram(data: items[0][0], addr: SERVER_ADDR, now: now)
    items = client.datagrams_to_send(now: now)
    assert_equal [32], datagram_sizes(items)
    assert_in_delta 0.425, client.get_timer

    # server receives ACK, retransmits HANDSHAKE_DONE
    now += TICK
    assert_equal false, server.handshake_done_pending
    server.receive_datagram(data: items[0][0], addr: CLIENT_ADDR, now: now)
    assert server.handshake_done_pending
    items = server.datagrams_to_send(now: now)
    assert_equal false, server.handshake_done_pending
    assert_equal [224], datagram_sizes(items)
  end

  def test_connect_with_no_transport_parameters
    # Patch client's TLS initialization to clear TLS extensions.
    patch = lambda do |client|
      ::Raioquic::Quic::Connection::QuicConnection.class_exec do
        alias_method :orig_initialize_connection, :initialize_connection
        define_method(:initialize_connection) do |*args|
          send(:orig_initialize_connection, *args)
          @tls.handshake_extensions = []
        end
      end
    end
    client_and_server(client_patch: patch) do |_client, server|
      assert_equal "No QUIC transport parameters received", server.close_event.reason_phrase
    end

    # teardown
    ::Raioquic::Quic::Connection::QuicConnection.class_exec do
      alias_method :initialize_connection, :orig_initialize_connection
    end
  end

  def test_connect_with_quantum_readiness
    client_and_server(client_options: { quantum_readiness_test: true }) do |client, server|
      stream_id = client.get_next_available_stream_id
      client.send_stream_data(stream_id: stream_id, data: "hello")
      assert_equal [1, 1], roundtrip(client, server)

      received = nil
      while true
        event = server.next_event
        if event.class == ::Raioquic::Quic::Event::StreamDataReceived
          received = event.data
        elsif event.nil?
          break
        end
      end
      assert_equal "hello", received
    end
  end

  def test_connect_with_0rtt
    client_ticket = nil
    ticket_store = SessionTicketStore.new

    save_session_ticket = lambda do |ticket|
      client_ticket = ticket
    end

    client_and_server(
      client_kwargs: { session_ticket_handler: save_session_ticket },
      server_kwargs: { session_ticket_handler: ticket_store.method(:add) },
    ) do |client, server|
      # pass
    end

    client_and_server(
      client_options: { session_ticket: client_ticket },
      server_kwargs: { session_ticket_fetcher: ticket_store.method(:pop) },
      handshake: false,
    ) do |client, server|
      client.connect(addr: SERVER_ADDR, now: Time.now.to_f)
      stream_id = client.get_next_available_stream_id
      client.send_stream_data(stream_id: stream_id, data: "hello")

      assert_equal [2, 1], roundtrip(client, server)

      event = server.next_event
      assert_equal ::Raioquic::Quic::Event::ProtocolNegotiated, event.class

      event = server.next_event
      assert_equal ::Raioquic::Quic::Event::StreamDataReceived, event.class
      assert_equal "hello", event.data
    end
  end

  def test_connect_with_0rtt_bad_max_early_data
    client_ticket = nil
    ticket_store = SessionTicketStore.new

    # Patch server's TLS initialization to set an invalid max_early_data value.
    patch = lambda do |server|
      ::Raioquic::Quic::Connection::QuicConnection.class_exec do
        alias_method :orig_initialize_connection, :initialize_connection
        define_method(:initialize_connection) do |*args|
          send(:orig_initialize_connection, *args)
          @tls.instance_eval { @max_early_data = 12345 }
        end
      end
    end

    save_session_ticket = lambda do |ticket|
      client_ticket = ticket
    end

    client_and_server(
      client_kwargs: { session_ticket_handler: save_session_ticket },
      server_kwargs: { session_ticket_handler: ticket_store.method(:add) },
      server_patch: patch,
    ) do |client, server|
      # check handshake failed
      event = client.next_event
      assert_nil event
    end

  ensure
    # teardown
    ::Raioquic::Quic::Connection::QuicConnection.class_exec do
      alias_method :initialize_connection, :orig_initialize_connection
    end
  end

  def test_change_connection_id
    client_and_server do |client, server|
      assert_equal [1, 2, 3, 4, 5, 6, 7], sequence_numbers(client.peer_cid_available)

      # the client changes connection ID
      client.change_connection_id
      # client.configuration.quic_logger.end_trace(client.quic_logger)
      # server.configuration.quic_logger.end_trace(server.quic_logger)
      assert_equal 1, transfer(client, server)
      assert_equal [2, 3, 4, 5, 6, 7], sequence_numbers(client.peer_cid_available)

      # the server provides a new connection ID
      assert_equal 1, transfer(server, client)
      client.configuration.quic_logger.end_trace(client.quic_logger)
      server.configuration.quic_logger.end_trace(server.quic_logger)
      assert_equal [2, 3, 4, 5, 6, 7, 8], sequence_numbers(client.peer_cid_available)
    end
  end

  def test_change_connection_id_retransmit_new_connection_id
    client_and_server do |client, server|
      assert_equal [1, 2, 3, 4, 5, 6, 7], sequence_numbers(client.peer_cid_available)

      # the client changes connection ID
      client.change_connection_id
      assert_equal 1, transfer(client, server)
      assert_equal [2, 3, 4, 5, 6, 7], sequence_numbers(client.peer_cid_available)

      # the server provides a new connection ID, NEW_CONNECTION_ID is lost
      assert_equal 1, drop(server)
      assert_equal [2, 3, 4, 5, 6, 7], sequence_numbers(client.peer_cid_available)

      # NEW_CONNECTION_ID is retransmitted
      server.send(:on_new_connection_id_delivery,
        delivery: ::Raioquic::Quic::PacketBuilder::QuicDeliveryState::LOST,
        connection_id: server.host_cids[-1],
      )
      assert_equal 1, transfer(server, client)
      assert_equal [2, 3, 4, 5, 6, 7, 8], sequence_numbers(client.peer_cid_available)
    end
  end

  def test_change_connection_id_retransmit_retire_connection_id
    client_and_server do |client, server|
      assert_equal [1, 2, 3, 4, 5, 6, 7], sequence_numbers(client.peer_cid_available)

      # the client changes connection ID, RETIRE_CONNECTION_ID is lost
      client.change_connection_id
      assert_equal 1, drop(client)
      assert_equal [2, 3, 4, 5, 6, 7], sequence_numbers(client.peer_cid_available)

      # RETIRE_CONNECTION_ID is retransmitted
      client.send(:on_retire_connection_id_delivery,
        delivery: ::Raioquic::Quic::PacketBuilder::QuicDeliveryState::LOST,
        sequence_number: 0,
      )
      assert_equal 1, transfer(client, server)

      # the server provides a new connection ID
      assert_equal 1, transfer(server, client)
      assert_equal [2, 3, 4, 5, 6, 7, 8], sequence_numbers(client.peer_cid_available)
    end
  end

  def test_get_next_available_stream_id
    client_and_server do |client, server|
      # client
      stream_id = client.get_next_available_stream_id
      assert_equal 0, stream_id
      client.send_stream_data(stream_id: stream_id, data: "hello")

      stream_id = client.get_next_available_stream_id
      assert_equal 4, stream_id
      client.send_stream_data(stream_id: stream_id, data: "hello")

      stream_id = client.get_next_available_stream_id(is_unidirectional: true)
      assert_equal 2, stream_id
      client.send_stream_data(stream_id: stream_id, data: "hello")

      stream_id = client.get_next_available_stream_id(is_unidirectional: true)
      assert_equal 6, stream_id
      client.send_stream_data(stream_id: stream_id, data: "hello")

      # server
      stream_id = server.get_next_available_stream_id
      assert_equal 1, stream_id
      server.send_stream_data(stream_id: stream_id, data: "hello")

      stream_id = server.get_next_available_stream_id
      assert_equal 5, stream_id
      server.send_stream_data(stream_id: stream_id, data: "hello")

      stream_id = server.get_next_available_stream_id(is_unidirectional: true)
      assert_equal 3, stream_id
      server.send_stream_data(stream_id: stream_id, data: "hello")

      stream_id = server.get_next_available_stream_id(is_unidirectional: true)
      assert_equal 7, stream_id
      server.send_stream_data(stream_id: stream_id, data: "hello")
    end
  end

  def test_datagram_frame
    # payload which exactly fills an entire packet
    payload = "Z" * 1250

    client_and_server(client_options: { max_datagram_frame_size: 65536 }, server_options: { max_datagram_frame_size: 65536 }) do |client, server|
      # check handshake completed
      check_handshake(client, server)

      # queue 20 datagrams
      20.times { client.send_datagram_frame(payload) }

      # client can only 11 datagrams are sent due to congestion control
      assert_equal 11, transfer(client, server)
      11.times do
        event = server.next_event
        assert_equal ::Raioquic::Quic::Event::DatagramFrameReceived, event.class
        assert_equal payload, event.data
      end

      # server sends ACK
      assert_equal 1, transfer(server, client)

      # client sends remaining datagrams
      assert_equal 9, transfer(client, server)
      9.times do
        event = server.next_event
        assert_equal ::Raioquic::Quic::Event::DatagramFrameReceived, event.class
        assert_equal payload, event.data
      end
    end
  end

  def test_decryption_error
    client_and_server do |client, server|
      # mess with encryption key
      server.cryptos[::Raioquic::TLS::Epoch::ONE_RTT].send.setup(
        cipher_suite: ::Raioquic::TLS::CipherSuite::AES_128_GCM_SHA256,
        secret: "\x00" * 48,
        version: server.version,
      )

      # server sends close
      server.close(error_code: ::Raioquic::Quic::Packet::QuicErrorCode::NO_ERROR)
      server.datagrams_to_send(now: Time.now.to_f).each do |data, _addr|
        client.receive_datagram(data: data, addr: SERVER_ADDR, now: Time.now.to_f)
      end
    end
  end

  def test_tls_error
    # Patch the client's TLS initialization to send invalid TLS version.
    patch = lambda do |server|
      ::Raioquic::Quic::Connection::QuicConnection.class_exec do
        alias_method :orig_initialize_connection, :initialize_connection
        define_method(:initialize_connection) do |*args|
          send(:orig_initialize_connection, *args)
          @tls.instance_eval { @supported_versions = [0x7f1c] } # version 1.3 DRAFT 28
        end
      end
    end

    # handshake fails
    client_and_server(client_patch: patch) do |_client, server|
      timer_at = server.get_timer
      server.handle_timer(now: timer_at)

      event = server.next_event
      assert_equal ::Raioquic::Quic::Event::ConnectionTerminated, event.class
      assert_equal 326, event.error_code
      assert_equal ::Raioquic::Quic::Packet::QuicFrameType::CRYPTO, event.frame_type
      assert_equal "No supported protocol version", event.reason_phrase
    end

  ensure
    # teardown
    ::Raioquic::Quic::Connection::QuicConnection.class_exec do
      alias_method :initialize_connection, :orig_initialize_connection
    end
  end

  def test_receive_datagram_garbage
    client = create_standalone_client

    datagram = ["c00000000080"].pack("H*")
    client.receive_datagram(data: datagram, addr: SERVER_ADDR, now: Time.now.to_f)
  end

  def test_receive_datagram_reserved_bits_non_zero
    client = create_standalone_client
    # skip "overriding"
    builder = ::Raioquic::Quic::PacketBuilder::QuicPacketBuilder.new(
      host_cid: client.peer_cid.cid,
      is_client: false,
      peer_cid: client.host_cid,
      version: client.version,
    )

    ::Raioquic::Quic::Crypto::CryptoPair.class_eval do
      alias_method :orig_encrypt_packet, :encrypt_packet
      define_method(:encrypt_packet) do |**args|
        # mess with reserved bits
        args[:plain_header][0] = [args[:plain_header][0].unpack1("C*") | 0x0c].pack("C*")
        return public_send(
          :orig_encrypt_packet,
          plain_header: args[:plain_header],
          plain_payload: args[:plain_payload],
          packet_number: args[:packet_number],
        )
      end
    end
    crypto = ::Raioquic::Quic::Crypto::CryptoPair.new
    crypto.setup_initial(cid: client.peer_cid.cid, is_client: false, version: client.version)

    builder.start_packet(packet_type: ::Raioquic::Quic::Packet::PACKET_TYPE_INITIAL, crypto: crypto)
    buf = builder.start_frame(frame_type: ::Raioquic::Quic::Packet::QuicFrameType::PADDING)
    buf.push_bytes("\x00" * builder.remaining_flight_space)

    builder.flush[0].each do |datagram|
      client.receive_datagram(data: datagram, addr: SERVER_ADDR, now: Time.now.to_f)
    end
    assert_equal 1, drop(client)
    assert_equal ::Raioquic::Quic::Event::ConnectionTerminated.new.tap { |ev|
      ev.error_code = ::Raioquic::Quic::Packet::QuicErrorCode::PROTOCOL_VIOLATION
      ev.frame_type = ::Raioquic::Quic::Packet::QuicFrameType::PADDING
      ev.reason_phrase = "Reserved bits must be zero"
    }, client.close_event
  ensure
    ::Raioquic::Quic::Crypto::CryptoPair.class_eval do
      alias_method :encrypt_packet, :orig_encrypt_packet
    end
  end

  def test_receive_datagram_wrong_version
    client = create_standalone_client

    builder = ::Raioquic::Quic::PacketBuilder::QuicPacketBuilder.new(
      host_cid: client.peer_cid.cid,
      is_client: false,
      peer_cid: client.host_cid,
      version: 0xff00011, # DRAFT_16
    )
    crypto = ::Raioquic::Quic::Crypto::CryptoPair.new
    crypto.setup_initial(cid: client.peer_cid.cid, is_client: false, version: client.version)
    builder.start_packet(packet_type: ::Raioquic::Quic::Packet::PACKET_TYPE_INITIAL, crypto: crypto)
    buf = builder.start_frame(frame_type: ::Raioquic::Quic::Packet::QuicFrameType::PADDING)
    buf.push_bytes("\x00" * builder.remaining_flight_space)

    builder.flush[0].each { |datagram| client.receive_datagram(data: datagram, addr: SERVER_ADDR, now: Time.now.to_f) }
    assert_equal 0, drop(client)
  end

  def test_receive_datagram_retry
    client = create_standalone_client

    client.receive_datagram(
      data: ::Raioquic::Quic::Packet.encode_quic_retry(
        version: client.version,
        source_cid: ["85abb547bf28be97"].pack("H*"),
        destination_cid: client.host_cid,
        original_destination_cid: client.peer_cid.cid,
        retry_token: "\x00" * 16,
      ),
      addr: SERVER_ADDR,
      now: Time.now.to_f,
    )
    assert_equal 1, drop(client)
  end

  def test_receive_datagram_retry_wrong_destination_cid
    client = create_standalone_client

    client.receive_datagram(
      data: ::Raioquic::Quic::Packet.encode_quic_retry(
        version: client.version,
        source_cid: ["85abb547bf28be97"].pack("H*"),
        destination_cid: client.host_cid,
        original_destination_cid: ["c98343fe8f5f0ff4"].pack("H*"),
        retry_token: "\x00" * 16,
      ),
      addr: SERVER_ADDR,
      now: Time.now.to_f,
    )
    assert_equal 0, drop(client)
  end

  def test_receive_datagram_retry_wrong_integrity_tag
    client = create_standalone_client

    client.receive_datagram(
      data: ::Raioquic::Quic::Packet.encode_quic_retry(
        version: client.version,
        source_cid: ["85abb547bf28be97"].pack("H*"),
        destination_cid: client.host_cid,
        original_destination_cid: client.peer_cid.cid,
        retry_token: "\x00" * 16,
      )[0...-16] + "\x00" * 16, # TODO: right?
      addr: SERVER_ADDR,
      now: Time.now.to_f,
    )
    assert_equal 0, drop(client)
  end

  def test_handle_ack_frame_ecn
    client = create_standalone_client

    client.send(
      :handle_ack_frame,
      context: client_receive_context(client),
      frame_type: ::Raioquic::Quic::Packet::QuicFrameType::ACK_ECN,
      buf: ::Raioquic::Buffer.new(data: "\x00\x02\x00\x00\x00\x00\x00"),
    )
  end

  def test_handle_connection_close_frame
    client_and_server do |client, server|
      server.close(
        error_code: ::Raioquic::Quic::Packet::QuicErrorCode::PROTOCOL_VIOLATION,
        frame_type: ::Raioquic::Quic::Packet::QuicFrameType::ACK,
        reason_phrase: "illegal ACK frame",
      )
      assert_equal [1, 0], roundtrip(server, client)

      assert_equal ::Raioquic::Quic::Event::ConnectionTerminated.new.tap { |ev|
        ev.error_code = ::Raioquic::Quic::Packet::QuicErrorCode::PROTOCOL_VIOLATION
        ev.frame_type = ::Raioquic::Quic::Packet::QuicFrameType::ACK
        ev.reason_phrase = "illegal ACK frame"
      }, client.close_event
    end
  end

  def test_handle_connection_close_frame_app
    client_and_server do |client, server|
      server.close(
        error_code: ::Raioquic::Quic::Packet::QuicErrorCode::NO_ERROR,
        reason_phrase: "goodbye",
      )
      assert_equal [1, 0], roundtrip(server, client)
      assert_equal ::Raioquic::Quic::Event::ConnectionTerminated.new.tap { |ev|
        ev.error_code = ::Raioquic::Quic::Packet::QuicErrorCode::NO_ERROR
        ev.frame_type = nil
        ev.reason_phrase = "goodbye"
      }, client.close_event
    end
  end

  def test_handle_connection_close_frame_app_not_utf8
    client = create_standalone_client

    client.send(
      :handle_connection_close_frame,
      context: client_receive_context(client),
      frame_type: ::Raioquic::Quic::Packet::QuicFrameType::APPLICATION_CLOSE,
      buf: ::Raioquic::Buffer.new(data: ["0008676f6f6462798200"].pack("H*")),
    )
    assert_equal ::Raioquic::Quic::Event::ConnectionTerminated.new.tap { |ev|
      ev.error_code = ::Raioquic::Quic::Packet::QuicErrorCode::NO_ERROR
      ev.frame_type = nil
      ev.reason_phrase = ""
    }, client.close_event
  end

  def test_handle_crypto_frame_over_largest_offset
    client_and_server do |client, _server|
      # client receives offset + length > 2^62 - 1
      cm = assert_raises ::Raioquic::Quic::Connection::QuicConnectionError do
        client.send(
          :handle_crypto_frame,
          context: client_receive_context(client),
          frame_type: ::Raioquic::Quic::Packet::QuicFrameType::CRYPTO,
          buf: ::Raioquic::Buffer.new(
            data: ::Raioquic::Buffer.encode_uint_var(::Raioquic::Buffer::UINT_VAR_MAX) + ::Raioquic::Buffer.encode_uint_var(1)
          ),
        )
      end
      assert_equal ::Raioquic::Quic::Packet::QuicErrorCode::FRAME_ENCODING_ERROR, cm.exception.error_code
      assert_equal ::Raioquic::Quic::Packet::QuicFrameType::CRYPTO, cm.frame_type
      assert_equal "offset + length cannot exceed 2^62 - 1", cm.reason_phrase
    end
  end

  def test_handle_data_blocked_frame
    client_and_server do |client, _server|
      # client received DATA_BLOCKED: 12345
      client.send(
        :handle_data_blocked_frame,
        context: client_receive_context(client),
        frame_type: ::Raioquic::Quic::Packet::QuicFrameType::DATA_BLOCKED,
        buf: ::Raioquic::Buffer.new(data: ::Raioquic::Buffer.encode_uint_var(12345)),
      )
    end
  end

  def test_handle_datagram_frame
    client = create_standalone_client(max_datagram_frame_size: 6)

    client.send(
      :handle_datagram_frame,
      context: client_receive_context(client),
      frame_type: ::Raioquic::Quic::Packet::QuicFrameType::DATAGRAM,
      buf: ::Raioquic::Buffer.new(data: "hello"),
    )
    assert_equal ::Raioquic::Quic::Event::DatagramFrameReceived.new.tap { |ev|
      ev.data = "hello"
    }, client.next_event
  end

  def test_handle_datagram_frame_not_allowed
    client = create_standalone_client(max_datagram_frame_size: nil)
    cm = assert_raises ::Raioquic::Quic::Connection::QuicConnectionError do
      client.send(
        :handle_datagram_frame,
        context: client_receive_context(client),
        frame_type: ::Raioquic::Quic::Packet::QuicFrameType::DATAGRAM,
        buf: ::Raioquic::Buffer.new(data: "hello"),
      )
    end
    assert_equal ::Raioquic::Quic::Packet::QuicErrorCode::PROTOCOL_VIOLATION, cm.error_code
    assert_equal ::Raioquic::Quic::Packet::QuicFrameType::DATAGRAM, cm.frame_type
    assert_equal "Unexpected DATAGRAM frame", cm.reason_phrase
  end

  def test_handle_datagram_frame_too_large
    client = create_standalone_client(max_datagram_frame_size: 5)
    cm = assert_raises ::Raioquic::Quic::Connection::QuicConnectionError do
      client.send(
        :handle_datagram_frame,
        context: client_receive_context(client),
        frame_type: ::Raioquic::Quic::Packet::QuicFrameType::DATAGRAM,
        buf: ::Raioquic::Buffer.new(data: "hello"),
      )
    end
    assert_equal ::Raioquic::Quic::Packet::QuicErrorCode::PROTOCOL_VIOLATION, cm.error_code
    assert_equal ::Raioquic::Quic::Packet::QuicFrameType::DATAGRAM, cm.frame_type
    assert_equal "Unexpected DATAGRAM frame", cm.reason_phrase
  end

  def test_handle_datagram_frame_with_length
    client = create_standalone_client(max_datagram_frame_size: 7)

    client.send(
      :handle_datagram_frame,
      context: client_receive_context(client),
      frame_type: ::Raioquic::Quic::Packet::QuicFrameType::DATAGRAM_WITH_LENGTH,
      buf: ::Raioquic::Buffer.new(data: "\x05hellojunk"),
    )
    assert_equal ::Raioquic::Quic::Event::DatagramFrameReceived.new.tap { |ev| ev.data = "hello" }, client.next_event
  end

  def test_handle_datagram_frame_with_length_not_allowed
    client = create_standalone_client(max_datagram_frame_size: nil)

    cm = assert_raises ::Raioquic::Quic::Connection::QuicConnectionError do
      client.send(
        :handle_datagram_frame,
        context: client_receive_context(client),
        frame_type: ::Raioquic::Quic::Packet::QuicFrameType::DATAGRAM_WITH_LENGTH,
        buf: ::Raioquic::Buffer.new(data: "\x05hellojunk"),
      )
    end
    assert_equal ::Raioquic::Quic::Packet::QuicErrorCode::PROTOCOL_VIOLATION, cm.error_code
    assert_equal ::Raioquic::Quic::Packet::QuicFrameType::DATAGRAM_WITH_LENGTH, cm.frame_type
    assert_equal "Unexpected DATAGRAM frame", cm.reason_phrase
  end

  def test_handle_handshake_done_not_allowed
    client_and_server do |_client, server|
      # server receives HANDSHAKE_DONE frame
      cm = assert_raises ::Raioquic::Quic::Connection::QuicConnectionError do
        server.send(
          :handle_handshake_done_frame,
          context: client_receive_context(server),
          frame_type: ::Raioquic::Quic::Packet::QuicFrameType::HANDSHAKE_DONE,
          buf: ::Raioquic::Buffer.new(data: ""),
        )
      end
      assert_equal ::Raioquic::Quic::Packet::QuicErrorCode::PROTOCOL_VIOLATION, cm.error_code
      assert_equal ::Raioquic::Quic::Packet::QuicFrameType::HANDSHAKE_DONE, cm.frame_type
      assert_equal "Clients must not send HANDSHAKE_DONE frames", cm.reason_phrase
    end
  end

  def test_handle_max_data_frame
    client_and_server do |client, _server|
      assert_equal 1048576, client.remote_max_data

      # client receives MAX_DATA raising limit
      client.send(
        :handle_max_data_frame,
        context: client_receive_context(client),
        frame_type: ::Raioquic::Quic::Packet::QuicFrameType::MAX_DATA,
        buf: ::Raioquic::Buffer.new(data: ::Raioquic::Buffer.encode_uint_var(1048577))
      )
      assert_equal 1048577, client.remote_max_data
    end
  end

  def test_handle_max_stream_data_frame
    client_and_server do |client, _server|
      # client creates bidirectional stream 0
      stream = client.send(:get_or_create_stream_for_send, 0)
      assert_equal 1048576, stream.max_stream_data_remote

      # client receives MAX_STREAM_DATA raising limit
      client.send(
        :handle_max_stream_data_frame,
        context: client_receive_context(client),
        frame_type: ::Raioquic::Quic::Packet::QuicFrameType::MAX_STREAM_DATA,
        buf: ::Raioquic::Buffer.new(data: "\x00" + ::Raioquic::Buffer.encode_uint_var(1048577)),
      )
      assert_equal 1048577, stream.max_stream_data_remote

      # client receives MAX_STREAM_DATA lowering limit
      client.send(
        :handle_max_stream_data_frame,
        context: client_receive_context(client),
        frame_type: ::Raioquic::Quic::Packet::QuicFrameType::MAX_STREAM_DATA,
        buf: ::Raioquic::Buffer.new(data: "\x00" + ::Raioquic::Buffer.encode_uint_var(1048575)),
      )
      assert_equal 1048577, stream.max_stream_data_remote
    end
  end

  def test_handle_max_stream_data_frame_receive_only
    client_and_server do |client, server|
      # server creates unidirectional stream 3
      server.send_stream_data(stream_id: 3, data: "hello")

      # client receives MAX_STREAM_DATA: 3, 1
      cm = assert_raises ::Raioquic::Quic::Connection::QuicConnectionError do
        client.send(
          :handle_max_stream_data_frame,
          context: client_receive_context(client),
          frame_type: ::Raioquic::Quic::Packet::QuicFrameType::MAX_STREAM_DATA,
          buf: ::Raioquic::Buffer.new(data: "\x03\x01"),
        )
      end
      assert_equal ::Raioquic::Quic::Packet::QuicErrorCode::STREAM_STATE_ERROR, cm.error_code
      assert_equal ::Raioquic::Quic::Packet::QuicFrameType::MAX_STREAM_DATA, cm.frame_type
      assert_equal "Stream is receive-only", cm.reason_phrase
    end
  end

  def test_handle_max_streams_bidi_frame
    client_and_server do |client, _server|
      assert_equal 128, client.remote_max_streams_bidi

      # client receives MAX_STREAMS_BIDI raising limit
      client.send(
        :handle_max_streams_bidi_frame,
        context: client_receive_context(client),
        frame_type: ::Raioquic::Quic::Packet::QuicFrameType::MAX_STREAMS_BIDI,
        buf: ::Raioquic::Buffer.new(data: ::Raioquic::Buffer.encode_uint_var(129)),
      )
      assert_equal 129, client.remote_max_streams_bidi

      # client receives invalid MAX_STREAMS_BIDI
      cm = assert_raises ::Raioquic::Quic::Connection::QuicConnectionError do
        client.send(
          :handle_max_streams_bidi_frame,
          context: client_receive_context(client),
          frame_type: ::Raioquic::Quic::Packet::QuicFrameType::MAX_STREAMS_BIDI,
          buf: ::Raioquic::Buffer.new(data: ::Raioquic::Buffer.encode_uint_var(::Raioquic::Quic::Connection::STREAM_COUNT_MAX + 1)),
        )
      end
      assert_equal ::Raioquic::Quic::Packet::QuicErrorCode::FRAME_ENCODING_ERROR, cm.error_code
      assert_equal ::Raioquic::Quic::Packet::QuicFrameType::MAX_STREAMS_BIDI, cm.frame_type
      assert_equal "Maximum Streams cannot exceed 2^60", cm.reason_phrase
    end
  end

  def test_handle_max_streams_uni_frame
    client_and_server do |client, _server|
      assert_equal 128, client.remote_max_streams_uni

      # client receives MAX_STREAMS_UNI raising limit
      client.send(
        :handle_max_streams_uni_frame,
        context: client_receive_context(client),
        frame_type: ::Raioquic::Quic::Packet::QuicFrameType::MAX_STREAMS_UNI,
        buf: ::Raioquic::Buffer.new(data: ::Raioquic::Buffer.encode_uint_var(129)),
      )
      assert_equal 129, client.remote_max_streams_uni

      # client receives MAX_STREAMS_UNI raising limit
      client.send(
        :handle_max_streams_uni_frame,
        context: client_receive_context(client),
        frame_type: ::Raioquic::Quic::Packet::QuicFrameType::MAX_STREAMS_UNI,
        buf: ::Raioquic::Buffer.new(data: ::Raioquic::Buffer.encode_uint_var(127)),
      )
      assert_equal 129, client.remote_max_streams_uni

      # client receives invalid MAX_STREAMS_UNI
      cm = assert_raises ::Raioquic::Quic::Connection::QuicConnectionError do
        client.send(
          :handle_max_streams_uni_frame,
          context: client_receive_context(client),
          frame_type: ::Raioquic::Quic::Packet::QuicFrameType::MAX_STREAMS_UNI,
          buf: ::Raioquic::Buffer.new(data: ::Raioquic::Buffer.encode_uint_var(::Raioquic::Quic::Connection::STREAM_COUNT_MAX + 1)),
        )
      end
      assert_equal ::Raioquic::Quic::Packet::QuicErrorCode::FRAME_ENCODING_ERROR, cm.error_code
      assert_equal ::Raioquic::Quic::Packet::QuicFrameType::MAX_STREAMS_UNI, cm.frame_type
      assert_equal "Maximum Streams cannot exceed 2^60", cm.reason_phrase
    end
  end

  def test_handle_new_connection_id_duplicate
    client_and_server do |client, _server|
      buf = ::Raioquic::Buffer.new(capacity: 100)
      buf.push_uint_var(7)  # sequence_number
      buf.push_uint_var(0)  # retire_prior_to
      buf.push_uint_var(8)
      buf.push_bytes("\x00" * 8)
      buf.push_bytes("\x00" * 16)
      buf.seek(0)

      # client receives NEW_CONNECTION_ID
      client.send(
        :handle_new_connection_id_frame,
        context: client_receive_context(client),
        frame_type: ::Raioquic::Quic::Packet::QuicFrameType::NEW_CONNECTION_ID,
        buf: buf,
      )
      assert_equal 0, client.peer_cid.sequence_number
      assert_equal [1, 2, 3, 4, 5, 6, 7], sequence_numbers(client.peer_cid_available)
    end
  end

  def test_handle_new_connection_id_over_limit
    client_and_server do |client, _server|
      buf = ::Raioquic::Buffer.new(capacity: 100)
      buf.push_uint_var(8)  # sequence_number
      buf.push_uint_var(0)  # retire_prior_to
      buf.push_uint_var(8)
      buf.push_bytes("\x00" * 8)
      buf.push_bytes("\x00" * 16)
      buf.seek(0)

      # client receives NEW_CONNECTION_ID
      cm = assert_raises ::Raioquic::Quic::Connection::QuicConnectionError do
        client.send(
          :handle_new_connection_id_frame,
          context: client_receive_context(client),
          frame_type: ::Raioquic::Quic::Packet::QuicFrameType::NEW_CONNECTION_ID,
          buf: buf,
        )
      end
      assert_equal ::Raioquic::Quic::Packet::QuicErrorCode::CONNECTION_ID_LIMIT_ERROR, cm.error_code
      assert_equal ::Raioquic::Quic::Packet::QuicFrameType::NEW_CONNECTION_ID, cm.frame_type
      assert_equal "Too many active connection IDs", cm.reason_phrase
    end
  end

  def test_handle_new_connection_id_with_retire_prior_to
    client_and_server do |client, _server|
      buf = ::Raioquic::Buffer.new(capacity: 42)
      buf.push_uint_var(8)  # sequence_number
      buf.push_uint_var(2)  # retire_prior_to
      buf.push_uint_var(8)
      buf.push_bytes("\x00" * 8)
      buf.push_bytes("\x00" * 16)
      buf.seek(0)

      # client receives NEW_CONNECTION_ID
      client.send(
        :handle_new_connection_id_frame,
        context: client_receive_context(client),
        frame_type: ::Raioquic::Quic::Packet::QuicFrameType::NEW_CONNECTION_ID,
        buf: buf,
      )
      assert_equal 2, client.peer_cid.sequence_number
      assert_equal [3, 4, 5, 6, 7, 8], sequence_numbers(client.peer_cid_available)
    end
  end

  def test_handle_new_connection_id_with_connection_id_invalid
    client_and_server do |client, _server|
      buf = ::Raioquic::Buffer.new(capacity: 100)
      buf.push_uint_var(8)  # sequence_number
      buf.push_uint_var(2)  # retire_prior_to
      buf.push_uint_var(21)
      buf.push_bytes("\x00" * 21)
      buf.push_bytes("\x00" * 16)
      buf.seek(0)

      # client receives NEW_CONNECTION_ID
      cm = assert_raises ::Raioquic::Quic::Connection::QuicConnectionError do
        client.send(
          :handle_new_connection_id_frame,
          context: client_receive_context(client),
          frame_type: ::Raioquic::Quic::Packet::QuicFrameType::NEW_CONNECTION_ID,
          buf: buf,
        )
      end
      assert_equal ::Raioquic::Quic::Packet::QuicErrorCode::FRAME_ENCODING_ERROR, cm.error_code
      assert_equal ::Raioquic::Quic::Packet::QuicFrameType::NEW_CONNECTION_ID, cm.frame_type
      assert_equal "Length must be greater than 0 and less than 20", cm.reason_phrase
    end
  end

  def test_handle_new_connection_id_with_retire_prior_to_invalid
    client_and_server do |client, _server|
      buf = ::Raioquic::Buffer.new(capacity: 100)
      buf.push_uint_var(8)  # sequence_number
      buf.push_uint_var(9)  # retire_prior_to
      buf.push_uint_var(8)
      buf.push_bytes("\x00" * 8)
      buf.push_bytes("\x00" * 16)
      buf.seek(0)

      # client receives NEW_CONNECTION_ID
      cm = assert_raises ::Raioquic::Quic::Connection::QuicConnectionError do
        client.send(:handle_new_connection_id_frame,
          context: client_receive_context(client),
          frame_type: ::Raioquic::Quic::Packet::QuicFrameType::NEW_CONNECTION_ID,
          buf: buf,
        )
      end
      assert_equal ::Raioquic::Quic::Packet::QuicErrorCode::PROTOCOL_VIOLATION, cm.error_code
      assert_equal ::Raioquic::Quic::Packet::QuicFrameType::NEW_CONNECTION_ID, cm.frame_type
      assert_equal "Retire Prior To is greater than Sequence Number", cm.reason_phrase
    end
  end

  def test_handle_new_token_frame
    client_and_server do |client, _server|
      client.send(
        :handle_new_token_frame,
        context: client_receive_context(client),
        frame_type: ::Raioquic::Quic::Packet::QuicFrameType::NEW_TOKEN,
        buf: ::Raioquic::Buffer.new(data: ["080102030405060708"].pack("H*")),
      )
    end
  end

  def test_handle_new_token_frame_from_client
    client_and_server do |client, server|
      # server receives NEW_TOKEN
      cm = assert_raises ::Raioquic::Quic::Connection::QuicConnectionError do
        server.send(
          :handle_new_token_frame,
          context: client_receive_context(client),
          frame_type: ::Raioquic::Quic::Packet::QuicFrameType::NEW_TOKEN,
          buf: ::Raioquic::Buffer.new(data: ["080102030405060708"].pack("H*")),
        )
      end
      assert_equal ::Raioquic::Quic::Packet::QuicErrorCode::PROTOCOL_VIOLATION, cm.error_code
      assert_equal ::Raioquic::Quic::Packet::QuicFrameType::NEW_TOKEN, cm.frame_type
      assert_equal "Clients must not send NEW_TOKEN frames", cm.reason_phrase
    end
  end

  def test_handle_path_challenge_frame
    client_and_server do |client, server|
      # client changes address and sends some data
      client.send_stream_data(stream_id: 0, data: "01234567")
      client.datagrams_to_send(now: Time.now.to_f).each do |data, _addr|
        server.receive_datagram(data: data, addr: ["1.2.3.4", 2345], now: Time.now.to_f)
      end

      # check paths
      assert_equal 2, server.network_paths.length
      assert_equal ["1.2.3.4", 2345], server.network_paths[0].addr
      assert_equal false, !!server.network_paths[0].is_validated
      assert_equal ["1.2.3.4", 1234], server.network_paths[1].addr
      assert server.network_paths[1].is_validated

      # server sends PATH_CHALLENGE and receives PATH_RESPONSE
      server.datagrams_to_send(now: Time.now.to_f).each do |data, _addr|
        client.receive_datagram(data: data, addr: SERVER_ADDR, now: Time.now.to_f)
      end
      client.datagrams_to_send(now: Time.now.to_f).each do |data, _addr|
        server.receive_datagram(data: data, addr: ["1.2.3.4", 2345], now: Time.now.to_f)
      end

      # check paths
      assert_equal ["1.2.3.4", 2345], server.network_paths[0].addr
      assert server.network_paths[0].is_validated
      assert_equal ["1.2.3.4", 1234], server.network_paths[1].addr
      assert server.network_paths[1].is_validated
    end
  end

  def test_handle_path_response_frame_bad
    client_and_server do |client, server|
      # server receives unsolicited PATH_RESPONSE
      cm = assert_raises ::Raioquic::Quic::Connection::QuicConnectionError do
        server.send(
          :handle_path_response_frame,
          context: client_receive_context(client),
          frame_type: ::Raioquic::Quic::Packet::QuicFrameType::PATH_RESPONSE,
          buf: ::Raioquic::Buffer.new(data: "\x11\x22\x33\x44\x55\x66\x77\x88"),
        )
      end
      assert_equal ::Raioquic::Quic::Packet::QuicErrorCode::PROTOCOL_VIOLATION, cm.error_code
      assert_equal ::Raioquic::Quic::Packet::QuicFrameType::PATH_RESPONSE, cm.frame_type
    end
  end

  def test_handle_padding_frame
    client = create_standalone_client

    # no more padding
    buf = ::Raioquic::Buffer.new(data: "")
    client.send(
      :handle_padding_frame,
      context: client_receive_context(client),
      frame_type: ::Raioquic::Quic::Packet::QuicFrameType::PADDING,
      buf: buf,
    )
    assert_equal 0, buf.tell

    # padding until end
    buf = ::Raioquic::Buffer.new(data: ("\x00" * 10))
    client.send(
      :handle_padding_frame,
      context: client_receive_context(client),
      frame_type: ::Raioquic::Quic::Packet::QuicFrameType::PADDING,
      buf: buf,
    )
    assert_equal 10, buf.tell

    # padding then something else
    buf = ::Raioquic::Buffer.new(data: ("\x00" * 10) + "\x01")
    client.send(
      :handle_padding_frame,
      context: client_receive_context(client),
      frame_type: ::Raioquic::Quic::Packet::QuicFrameType::PADDING,
      buf: buf,
    )
    assert_equal 10, buf.tell
  end

  def test_handle_reset_stream_frame
    stream_id = 0
    client_and_server do |client, server|
      # client creates bidirectional stream
      client.send_stream_data(stream_id: stream_id, data: "hello")
      consume_events(client)

      # client receives RESET_STREAM
      client.send(
        :handle_reset_stream_frame,
        context: client_receive_context(client),
        frame_type: ::Raioquic::Quic::Packet::QuicFrameType::RESET_STREAM,
        buf: ::Raioquic::Buffer.new(
          data: ::Raioquic::Buffer.encode_uint_var(stream_id) +
            ::Raioquic::Buffer.encode_uint_var(::Raioquic::Quic::Packet::QuicErrorCode::INTERNAL_ERROR) +
            ::Raioquic::Buffer.encode_uint_var(0),
        ),
      )
      event = client.next_event
      assert_equal ::Raioquic::Quic::Event::StreamReset, event.class
      assert_equal ::Raioquic::Quic::Packet::QuicErrorCode::INTERNAL_ERROR, event.error_code
      assert_equal stream_id, event.stream_id
    end
  end

  def test_handle_reset_stream_frame_final_size_error
    stream_id = 0
    client_and_server do |client, server|
      # client creates bidirectional stream
      client.send_stream_data(stream_id: stream_id, data: "hello")
      consume_events(client)

      # client receives RESET_STREAM at offset 8
      client.send(
        :handle_reset_stream_frame,
        context: client_receive_context(client),
        frame_type: ::Raioquic::Quic::Packet::QuicFrameType::RESET_STREAM,
        buf: ::Raioquic::Buffer.new(
          data: ::Raioquic::Buffer.encode_uint_var(stream_id) +
            ::Raioquic::Buffer.encode_uint_var(::Raioquic::Quic::Packet::QuicErrorCode::NO_ERROR) +
            ::Raioquic::Buffer.encode_uint_var(8),
        ),
      )
      event = client.next_event
      assert_equal ::Raioquic::Quic::Event::StreamReset, event.class
      assert_equal ::Raioquic::Quic::Packet::QuicErrorCode::NO_ERROR, event.error_code
      assert_equal stream_id, event.stream_id

      # client receives RESET_STREAM at offset 5
      cm = assert_raises ::Raioquic::Quic::Connection::QuicConnectionError do
        client.send(
          :handle_reset_stream_frame,
          context: client_receive_context(client),
          frame_type: ::Raioquic::Quic::Packet::QuicFrameType::RESET_STREAM,
            buf: ::Raioquic::Buffer.new(
              data: ::Raioquic::Buffer.encode_uint_var(stream_id) +
                ::Raioquic::Buffer.encode_uint_var(::Raioquic::Quic::Packet::QuicErrorCode::NO_ERROR) +
                ::Raioquic::Buffer.encode_uint_var(5),
            ),
        )
      end
      assert_equal ::Raioquic::Quic::Packet::QuicErrorCode::FINAL_SIZE_ERROR, cm.error_code
      assert_equal ::Raioquic::Quic::Packet::QuicFrameType::RESET_STREAM, cm.frame_type
      assert_equal "Cannot change final size", cm.reason_phrase
    end
  end

  def test_handle_reset_stream_frame_over_max_data
    stream_id = 0
    client_and_server do |client, server|
      # client creates bidirectional stream
      client.send_stream_data(stream_id: stream_id, data: "hello")
      consume_events(client)

      # artificially raise received data counter
      client.local_max_data.used = client.local_max_data.value

      # client receives RESET_STREAM frame
      cm = assert_raises ::Raioquic::Quic::Connection::QuicConnectionError do
        client.send(
          :handle_reset_stream_frame,
          context: client_receive_context(client),
          frame_type: ::Raioquic::Quic::Packet::QuicFrameType::RESET_STREAM,
          buf: ::Raioquic::Buffer.new(
            data: ::Raioquic::Buffer.encode_uint_var(stream_id) +
              ::Raioquic::Buffer.encode_uint_var(::Raioquic::Quic::Packet::QuicErrorCode::NO_ERROR) +
              ::Raioquic::Buffer.encode_uint_var(1),
          )
        )
      end
      assert_equal ::Raioquic::Quic::Packet::QuicErrorCode::FLOW_CONTROL_ERROR, cm.error_code
      assert_equal ::Raioquic::Quic::Packet::QuicFrameType::RESET_STREAM, cm.frame_type
      assert_equal "Over connection data limit", cm.reason_phrase
    end
  end

  def test_handle_reset_stream_frame_over_max_stream_data
    stream_id = 0
    client_and_server do |client, server|
      # client creates bidirectional stream
      client.send_stream_data(stream_id: stream_id, data: "hello")
      consume_events(client)

      # client receives STREAM frame
      cm = assert_raises ::Raioquic::Quic::Connection::QuicConnectionError do
        client.send(
          :handle_reset_stream_frame,
          context: client_receive_context(client),
          frame_type: ::Raioquic::Quic::Packet::QuicFrameType::RESET_STREAM,
          buf: ::Raioquic::Buffer.new(
            data: ::Raioquic::Buffer.encode_uint_var(stream_id) +
              ::Raioquic::Buffer.encode_uint_var(::Raioquic::Quic::Packet::QuicErrorCode::NO_ERROR) +
              ::Raioquic::Buffer.encode_uint_var(client.local_max_stream_data_bidi_local + 1),
          )
        )
      end
      assert_equal ::Raioquic::Quic::Packet::QuicErrorCode::FLOW_CONTROL_ERROR, cm.error_code
      assert_equal ::Raioquic::Quic::Packet::QuicFrameType::RESET_STREAM, cm.frame_type
      assert_equal "Over stream data limit", cm.reason_phrase
    end
  end

  def test_handle_reset_stream_frame_send_only
    client_and_server do |client, _server|
      # client creates unidirectional stream 2
      client.send_stream_data(stream_id: 2, data: "hello")

      # client receives RESET_STREAM
      cm = assert_raises ::Raioquic::Quic::Connection::QuicConnectionError do
        client.send(
          :handle_reset_stream_frame,
          context: client_receive_context(client),
          frame_type: ::Raioquic::Quic::Packet::QuicFrameType::RESET_STREAM,
          buf: ::Raioquic::Buffer.new(data: ["021100"].pack("H*")),
        )
      end
      assert_equal ::Raioquic::Quic::Packet::QuicErrorCode::STREAM_STATE_ERROR, cm.error_code
      assert_equal ::Raioquic::Quic::Packet::QuicFrameType::RESET_STREAM, cm.frame_type
      assert_equal "Stream is send-only", cm.reason_phrase
    end
  end

  def test_handle_reset_stream_frame_twice
    stream_id = 3
    reset_stream_data = ::Raioquic::Buffer.encode_uint_var(::Raioquic::Quic::Packet::QuicFrameType::RESET_STREAM) +
      ::Raioquic::Buffer.encode_uint_var(stream_id) +
      ::Raioquic::Buffer.encode_uint_var(::Raioquic::Quic::Packet::QuicErrorCode::INTERNAL_ERROR) +
      ::Raioquic::Buffer.encode_uint_var(0)

    client_and_server do |client, server|
      # server creates unidirectional stream
      server.send_stream_data(stream_id: stream_id, data: "hello")
      roundtrip(server, client)
      consume_events(client)

      # client receives RESET_STREAM
      client.send(:payload_received, context: client_receive_context(client), plain: reset_stream_data)

      event = client.next_event
      assert_equal ::Raioquic::Quic::Event::StreamReset, event.class
      assert_equal ::Raioquic::Quic::Packet::QuicErrorCode::INTERNAL_ERROR, event.error_code
      assert_equal stream_id, event.stream_id

      # stream gets discarded
      assert_equal 0, drop(client)

      # client receives RESET_STREAM again
      client.send(:payload_received, context: client_receive_context(client), plain: reset_stream_data)

      event = client.next_event
      assert_nil event
    end
  end

  def test_handle_retire_connection_id_frame
    client_and_server do |client, _server|
      assert_equal [0, 1, 2, 3, 4, 5, 6, 7], sequence_numbers(client.host_cids)

      # client receives RETIRE_CONNECTION_ID
      client.send(
        :handle_retire_connection_id_frame,
        context: client_receive_context(client),
        frame_type: ::Raioquic::Quic::Packet::QuicFrameType::RETIRE_CONNECTION_ID,
        buf: ::Raioquic::Buffer.new(data: "\x02"),
      )
      assert_equal [0, 1, 3, 4, 5, 6, 7, 8], sequence_numbers(client.host_cids)
    end
  end

  def test_handle_retire_connection_id_frame_current_cid
    client_and_server do |client, _server|
      assert_equal [0, 1, 2, 3, 4, 5, 6, 7], sequence_numbers(client.host_cids)

      # client receives RETIRE_CONNECTION_ID for the current CID
      cm = assert_raises ::Raioquic::Quic::Connection::QuicConnectionError do
        client.send(
          :handle_retire_connection_id_frame,
          context: client_receive_context(client),
          frame_type: ::Raioquic::Quic::Packet::QuicFrameType::RETIRE_CONNECTION_ID,
          buf: ::Raioquic::Buffer.new(data: "\x00"),
        )
      end
      assert_equal ::Raioquic::Quic::Packet::QuicErrorCode::PROTOCOL_VIOLATION, cm.error_code
      assert_equal ::Raioquic::Quic::Packet::QuicFrameType::RETIRE_CONNECTION_ID, cm.frame_type
      assert_equal "Cannot retire current connection ID", cm.reason_phrase
      assert_equal [0, 1, 2, 3, 4, 5, 6, 7], sequence_numbers(client.host_cids)
    end
  end

  def test_handle_retire_connection_id_frame_invalid_sequence_number
    client_and_server do |client, _server|
      assert_equal [0, 1, 2, 3, 4, 5, 6, 7], sequence_numbers(client.host_cids)

      # client receives RETIRE_CONNECTION_ID
      cm = assert_raises ::Raioquic::Quic::Connection::QuicConnectionError do
        client.send(
          :handle_retire_connection_id_frame,
          context: client_receive_context(client),
          frame_type: ::Raioquic::Quic::Packet::QuicFrameType::RETIRE_CONNECTION_ID,
          buf: ::Raioquic::Buffer.new(data: "\x08"),
        )
      end
      assert_equal ::Raioquic::Quic::Packet::QuicErrorCode::PROTOCOL_VIOLATION, cm.error_code
      assert_equal ::Raioquic::Quic::Packet::QuicFrameType::RETIRE_CONNECTION_ID, cm.frame_type
      assert_equal "Cannot retire unknown connection ID", cm.reason_phrase
      assert_equal [0, 1, 2, 3, 4, 5, 6, 7], sequence_numbers(client.host_cids)
    end
  end

  def test_handle_stop_sending_frame
    client_and_server do |client, _server|
      # client creates bidirectional stream 0
      client.send_stream_data(stream_id: 0, data: "hello")

      # client receives STOP_SENDING
      client.send(
        :handle_stop_sending_frame,
        context: client_receive_context(client),
        frame_type: ::Raioquic::Quic::Packet::QuicFrameType::STOP_SENDING,
        buf: ::Raioquic::Buffer.new(data: "\x00\x11"),
      )
    end
  end

  def test_handle_stop_sending_frame_receive_only
    client_and_server do |client, server|
      # client creates unidirectional stream 3
      server.send_stream_data(stream_id: 3, data: "hello")

      # client receives STOP_SENDING
      cm = assert_raises ::Raioquic::Quic::Connection::QuicConnectionError do
        client.send(
          :handle_stop_sending_frame,
          context: client_receive_context(client),
          frame_type: ::Raioquic::Quic::Packet::QuicFrameType::STOP_SENDING,
          buf: ::Raioquic::Buffer.new(data: "\x03\x11"),
        )
      end
      assert_equal ::Raioquic::Quic::Packet::QuicErrorCode::STREAM_STATE_ERROR, cm.error_code
      assert_equal ::Raioquic::Quic::Packet::QuicFrameType::STOP_SENDING, cm.frame_type
      assert_equal "Stream is receive-only", cm.reason_phrase
    end
  end

  def test_handle_stream_frame_final_size_error
    client_and_server do |client, _server|
      frame_type = ::Raioquic::Quic::Packet::QuicFrameType::STREAM_BASE | 7
      stream_id = 1

      # client receives FIN at offset 8
      client.send(
        :handle_stream_frame,
        context: client_receive_context(client),
        frame_type: frame_type,
        buf: ::Raioquic::Buffer.new(
          data: ::Raioquic::Buffer.encode_uint_var(stream_id) +
            ::Raioquic::Buffer.encode_uint_var(8) +
            ::Raioquic::Buffer.encode_uint_var(0),
        ),
      )

      # client receives FIN at offset 5
      cm = assert_raises ::Raioquic::Quic::Connection::QuicConnectionError do
        client.send(
          :handle_stream_frame,
          context: client_receive_context(client),
          frame_type: frame_type,
          buf: ::Raioquic::Buffer.new(
            data: ::Raioquic::Buffer.encode_uint_var(stream_id) +
              ::Raioquic::Buffer.encode_uint_var(5) +
              ::Raioquic::Buffer.encode_uint_var(0),
          ),
        )
      end
      assert_equal ::Raioquic::Quic::Packet::QuicErrorCode::FINAL_SIZE_ERROR, cm.error_code
      assert_equal frame_type, cm.frame_type
      assert_equal "Cannot change final size", cm.reason_phrase
    end
  end

  def test_handle_stream_frame_over_largest_offset
    client_and_server do |client, _server|
      # client receives offset + length > 2^62 - 1
      frame_type = ::Raioquic::Quic::Packet::QuicFrameType::STREAM_BASE | 6
      stream_id = 6
      cm = assert_raises ::Raioquic::Quic::Connection::QuicConnectionError do
        client.send(
          :handle_stream_frame,
          context: client_receive_context(client),
          frame_type: frame_type,
          buf: ::Raioquic::Buffer.new(
            data: ::Raioquic::Buffer.encode_uint_var(stream_id) +
              ::Raioquic::Buffer.encode_uint_var(::Raioquic::Buffer::UINT_VAR_MAX) +
              ::Raioquic::Buffer.encode_uint_var(1)
          )
        )
      end
      assert_equal ::Raioquic::Quic::Packet::QuicErrorCode::FRAME_ENCODING_ERROR, cm.error_code
      assert_equal frame_type, cm.frame_type
      assert_equal "offset + length cannot exceed 2^62 - 1", cm.reason_phrase
    end
  end

  def test_handle_stream_frame_over_max_data
    client_and_server do |client, _server|
      # artificially raise received data counter
      client.local_max_data.used = client.local_max_data.value

      # client receives STREAM frame
      frame_type = ::Raioquic::Quic::Packet::QuicFrameType::STREAM_BASE | 4
      stream_id = 1
      cm = assert_raises ::Raioquic::Quic::Connection::QuicConnectionError do
        client.send(
          :handle_stream_frame,
          context: client_receive_context(client),
          frame_type: frame_type,
          buf: ::Raioquic::Buffer.new(data: ::Raioquic::Buffer.encode_uint_var(stream_id) + ::Raioquic::Buffer.encode_uint_var(1)),
        )
      end
      assert_equal ::Raioquic::Quic::Packet::QuicErrorCode::FLOW_CONTROL_ERROR, cm.error_code
      assert_equal frame_type, cm.frame_type
      assert_equal "Over connection data limit", cm.reason_phrase
    end
  end

  def test_handle_stream_frame_over_max_stream_data
    client_and_server do |client, _server|
      # client receives STREAM frame
      frame_type = ::Raioquic::Quic::Packet::QuicFrameType::STREAM_BASE | 4
      stream_id = 1
      cm = assert_raises ::Raioquic::Quic::Connection::QuicConnectionError do
        client.send(
          :handle_stream_frame,
          context: client_receive_context(client),
          frame_type: frame_type,
          buf: ::Raioquic::Buffer.new(
            data: ::Raioquic::Buffer.encode_uint_var(stream_id) +
              ::Raioquic::Buffer.encode_uint_var(client.local_max_stream_data_bidi_remote + 1),
          ),
        )
      end
      assert_equal ::Raioquic::Quic::Packet::QuicErrorCode::FLOW_CONTROL_ERROR, cm.error_code
      assert_equal frame_type, cm.frame_type
      assert_equal "Over stream data limit", cm.reason_phrase
    end
  end

  def test_handle_stream_frame_over_max_streams
    client_and_server do |client, _server|
      # client receives STREAM frame
      cm = assert_raises ::Raioquic::Quic::Connection::QuicConnectionError do
        client.send(
          :handle_stream_frame,
          context: client_receive_context(client),
          frame_type: ::Raioquic::Quic::Packet::QuicFrameType::STREAM_BASE,
          buf: ::Raioquic::Buffer.new(
            data: ::Raioquic::Buffer.encode_uint_var(client.local_max_stream_data_uni * 4 + 3),
          ),
        )
      end
      assert_equal ::Raioquic::Quic::Packet::QuicErrorCode::STREAM_LIMIT_ERROR, cm.error_code
      assert_equal ::Raioquic::Quic::Packet::QuicFrameType::STREAM_BASE, cm.frame_type
      assert_equal "Too many streams open", cm.reason_phrase
    end
  end

  def test_handle_stream_frame_send_only
    client_and_server do |client, _server|
      # client creates unidirectional stream 2
      client.send_stream_data(stream_id: 2, data: "hello")

      # client receives STREAM frame
      cm = assert_raises ::Raioquic::Quic::Connection::QuicConnectionError do
        client.send(
          :handle_stream_frame,
          context: client_receive_context(client),
          frame_type: ::Raioquic::Quic::Packet::QuicFrameType::STREAM_BASE,
          buf: ::Raioquic::Buffer.new(data: "\x02"),
        )
      end
      assert_equal ::Raioquic::Quic::Packet::QuicErrorCode::STREAM_STATE_ERROR, cm.error_code
      assert_equal ::Raioquic::Quic::Packet::QuicFrameType::STREAM_BASE, cm.frame_type
      assert_equal "Stream is send-only", cm.reason_phrase
    end
  end

  def test_handle_stream_frame_wrong_initiator
    client_and_server do |client, _server|
      # client receives STREAM frame
      cm = assert_raises ::Raioquic::Quic::Connection::QuicConnectionError do
        client.send(
          :handle_stream_frame,
          context: client_receive_context(client),
          frame_type: ::Raioquic::Quic::Packet::QuicFrameType::STREAM_BASE,
          buf: ::Raioquic::Buffer.new(data: "\x00"),
        )
      end
      assert_equal ::Raioquic::Quic::Packet::QuicErrorCode::STREAM_STATE_ERROR, cm.error_code
      assert_equal ::Raioquic::Quic::Packet::QuicFrameType::STREAM_BASE, cm.frame_type
      assert_equal "Wrong stream initiator", cm.reason_phrase
    end
  end

  def test_handle_stream_data_blocked_frame
    client_and_server do |client, _server|
      # client creates bidirectional stream 0
      client.send_stream_data(stream_id: 0, data: "hello")

      # client receives STREAM_DATA_BLOCKED
      client.send(
        :handle_stream_data_blocked_frame,
        context: client_receive_context(client),
        frame_type: ::Raioquic::Quic::Packet::QuicFrameType::STREAM_DATA_BLOCKED,
        buf: ::Raioquic::Buffer.new(data: "\x00\x01"),
      )
    end
  end

  def test_handle_stream_data_blocked_frame_send_only
    client_and_server do |client, _server|
      # client creates unidirectional stream 2
      client.send_stream_data(stream_id: 2, data: "hello")

      # client receives STREAM_DATA_BLOCKED
      cm = assert_raises ::Raioquic::Quic::Connection::QuicConnectionError do
        client.send(
          :handle_stream_data_blocked_frame,
          context: client_receive_context(client),
          frame_type: ::Raioquic::Quic::Packet::QuicFrameType::STREAM_DATA_BLOCKED,
          buf: ::Raioquic::Buffer.new(data: "\x02\x01"),
        )
      end
      assert_equal ::Raioquic::Quic::Packet::QuicErrorCode::STREAM_STATE_ERROR, cm.error_code
      assert_equal ::Raioquic::Quic::Packet::QuicFrameType::STREAM_DATA_BLOCKED, cm.frame_type
      assert_equal "Stream is send-only", cm.reason_phrase
    end
  end

  def test_handle_streams_blocked_uni_frame
    client_and_server do |client, _server|
      # client receives STREAMS_BLOCKED_UNI: 0
      client.send(
        :handle_streams_blocked_frame,
        context: client_receive_context(client),
        frame_type: ::Raioquic::Quic::Packet::QuicFrameType::STREAMS_BLOCKED_UNI,
        buf: ::Raioquic::Buffer.new(data: "\x00"),
      )

      # client receives invalid STREAMS_BLOCKED_UNI
      cm = assert_raises ::Raioquic::Quic::Connection::QuicConnectionError do
        client.send(
          :handle_streams_blocked_frame,
          context: client_receive_context(client),
          frame_type: ::Raioquic::Quic::Packet::QuicFrameType::STREAMS_BLOCKED_UNI,
          buf: ::Raioquic::Buffer.new(data: ::Raioquic::Buffer.encode_uint_var(::Raioquic::Quic::Connection::STREAM_COUNT_MAX + 1)),
        )
      end
      assert_equal ::Raioquic::Quic::Packet::QuicErrorCode::FRAME_ENCODING_ERROR, cm.error_code
      assert_equal ::Raioquic::Quic::Packet::QuicFrameType::STREAMS_BLOCKED_UNI, cm.frame_type
      assert_equal "Maximum Streams cannot exceed 2^60", cm.reason_phrase
    end
  end

  def test_parse_transport_parameters
    client = create_standalone_client

    data = encode_transport_parameters(
      ::Raioquic::Quic::Packet::QuicTransportParameters.new.tap { |tp|
        tp.original_destination_connection_id = client.original_destination_connection_id
      }
    )
    client.send(:parse_transport_parameters, data: data)
  end

  def test_parse_transport_parameters_malformed
    client = create_standalone_client

    cm = assert_raises ::Raioquic::Quic::Connection::QuicConnectionError do
      client.send(:parse_transport_parameters, data: "0")
    end
    assert_equal ::Raioquic::Quic::Packet::QuicErrorCode::TRANSPORT_PARAMETER_ERROR, cm.error_code
    assert_equal ::Raioquic::Quic::Packet::QuicFrameType::CRYPTO, cm.frame_type
    assert_equal "Could not parse QUIC transport parameters", cm.reason_phrase
  end

  def test_parse_transport_parameters_with_bad_ack_delay_exponent
    client = create_standalone_client

    data = encode_transport_parameters(
      ::Raioquic::Quic::Packet::QuicTransportParameters.new.tap { |tp|
        tp.ack_delay_exponent = 21
        tp.original_destination_connection_id = client.original_destination_connection_id
      }
    )

    cm = assert_raises ::Raioquic::Quic::Connection::QuicConnectionError do
      client.send(:parse_transport_parameters, data: data)
    end
    assert_equal ::Raioquic::Quic::Packet::QuicErrorCode::TRANSPORT_PARAMETER_ERROR, cm.error_code
    assert_equal ::Raioquic::Quic::Packet::QuicFrameType::CRYPTO, cm.frame_type
    assert_equal "ack_delay_exponent must be <= 20", cm.reason_phrase
  end

  def test_parse_transport_parameters_with_bad_active_connection_id_limit
    client = create_standalone_client

    [0, 1].each do |active_connection_id_limit|
      data = encode_transport_parameters(
        ::Raioquic::Quic::Packet::QuicTransportParameters.new.tap { |tp|
          tp.active_connection_id_limit = active_connection_id_limit
          tp.original_destination_connection_id = client.original_destination_connection_id
        }
      )

      cm = assert_raises ::Raioquic::Quic::Connection::QuicConnectionError do
        client.send(:parse_transport_parameters, data: data)
      end
      assert_equal ::Raioquic::Quic::Packet::QuicErrorCode::TRANSPORT_PARAMETER_ERROR, cm.error_code
      assert_equal ::Raioquic::Quic::Packet::QuicFrameType::CRYPTO, cm.frame_type
      assert_equal "active_connection_id_limit must be no less than 2", cm.reason_phrase
    end
  end

  def test_parse_transport_parameters_with_bad_max_ack_delay
    client = create_standalone_client

    data = encode_transport_parameters(
      ::Raioquic::Quic::Packet::QuicTransportParameters.new.tap { |tp|
        tp.max_ack_delay = 2**14
        tp.original_destination_connection_id = client.original_destination_connection_id
      }
    )

    cm = assert_raises ::Raioquic::Quic::Connection::QuicConnectionError do
      client.send(:parse_transport_parameters, data: data)
    end
    assert_equal ::Raioquic::Quic::Packet::QuicErrorCode::TRANSPORT_PARAMETER_ERROR, cm.error_code
    assert_equal ::Raioquic::Quic::Packet::QuicFrameType::CRYPTO, cm.frame_type
    assert_equal "max_ack_delay must be < 2^14", cm.reason_phrase
  end

  def test_parse_transport_parameters_with_bad_max_udp_payload_size
    client = create_standalone_client

    data = encode_transport_parameters(
      ::Raioquic::Quic::Packet::QuicTransportParameters.new.tap { |tp|
        tp.max_udp_payload_size = 1199
        tp.original_destination_connection_id = client.original_destination_connection_id
      }
    )

    cm = assert_raises ::Raioquic::Quic::Connection::QuicConnectionError do
      client.send(:parse_transport_parameters, data: data)
    end
    assert_equal ::Raioquic::Quic::Packet::QuicErrorCode::TRANSPORT_PARAMETER_ERROR, cm.error_code
    assert_equal ::Raioquic::Quic::Packet::QuicFrameType::CRYPTO, cm.frame_type
    assert_equal "max_udp_payload_size must be >= 1200", cm.reason_phrase
  end

  def test_parse_transport_parameters_with_bad_initial_source_connection_id
    client = create_standalone_client
    client.initial_source_connection_id = ["0011223344556677"].pack("H*")

    data = encode_transport_parameters(
      ::Raioquic::Quic::Packet::QuicTransportParameters.new.tap { |tp|
        tp.initial_source_connection_id = ["1122334455667788"].pack("H*")
        tp.original_destination_connection_id = client.original_destination_connection_id
      }
    )

    cm = assert_raises ::Raioquic::Quic::Connection::QuicConnectionError do
      client.send(:parse_transport_parameters, data: data)
    end
    assert_equal ::Raioquic::Quic::Packet::QuicErrorCode::TRANSPORT_PARAMETER_ERROR, cm.error_code
    assert_equal ::Raioquic::Quic::Packet::QuicFrameType::CRYPTO, cm.frame_type
    assert_equal "initial_source_connection_id does not match", cm.reason_phrase
  end

  def test_parse_transport_parameters_with_server_only_payload
    server_configuration = ::Raioquic::Quic::QuicConfiguration.new(
      is_client: false, quic_logger: nil,
    )
    server_configuration.load_cert_chain(Utils::SERVER_CERTFILE, Utils::SERVER_KEYFILE)
    server = ::Raioquic::Quic::Connection::QuicConnection.new(configuration: server_configuration, original_destination_connection_id: "\x00" * 8)

    [0, 1].each do |active_connection_id_limit|
      data = encode_transport_parameters(
        ::Raioquic::Quic::Packet::QuicTransportParameters.new.tap { |tp|
          tp.active_connection_id_limit = active_connection_id_limit
          tp.original_destination_connection_id = "\x00" * 8
        }
      )
      cm = assert_raises ::Raioquic::Quic::Connection::QuicConnectionError do
        server.send(:parse_transport_parameters, data: data)
      end
      assert_equal ::Raioquic::Quic::Packet::QuicErrorCode::TRANSPORT_PARAMETER_ERROR, cm.error_code
      assert_equal ::Raioquic::Quic::Packet::QuicFrameType::CRYPTO, cm.frame_type
      assert_equal "original_destination_connection_id is not allowed for clients", cm.reason_phrase
    end
  end

  def test_payload_received_empty
    client_and_server do |client, _server|
      # client receives empty payload
      cm = assert_raises ::Raioquic::Quic::Connection::QuicConnectionError do
        client.send(:payload_received, context: client_receive_context(client), plain: "")
      end
      assert_equal ::Raioquic::Quic::Packet::QuicErrorCode::PROTOCOL_VIOLATION, cm.error_code
      assert_equal ::Raioquic::Quic::Packet::QuicFrameType::PADDING, cm.frame_type
      assert_equal "Packet contains no frames", cm.reason_phrase
    end
  end

  def test_payload_received_padding_only
    client_and_server do |client, _server|
      # client receives padding only
      is_ack_eliciting, is_probing = client.send(:payload_received, context: client_receive_context(client), plain: "\x00" * 1200)
      assert_equal false, is_ack_eliciting
      assert is_probing
    end
  end

  def test_payload_received_unknown_frame
    client_and_server do |client, _server|
      # client receives unknown frame
      cm = assert_raises ::Raioquic::Quic::Connection::QuicConnectionError do
        client.send(:payload_received, context: client_receive_context(client), plain: "\x1f")
      end
      assert_equal ::Raioquic::Quic::Packet::QuicErrorCode::PROTOCOL_VIOLATION, cm.error_code
      assert_equal 0x1f, cm.frame_type
      assert_equal "Unknown frame type", cm.reason_phrase
    end
  end

  def test_payload_received_unexpected_frame
    client_and_server do |client, _server|
      # client receives CRYPTO frame in 0-RTT
      cm = assert_raises ::Raioquic::Quic::Connection::QuicConnectionError do
        client.send(
          :payload_received,
          context: client_receive_context(client, ::Raioquic::TLS::Epoch::ZERO_RTT),
          plain: "\x06",
        )
      end
      assert_equal ::Raioquic::Quic::Packet::QuicErrorCode::PROTOCOL_VIOLATION, cm.error_code
      assert_equal ::Raioquic::Quic::Packet::QuicFrameType::CRYPTO, cm.frame_type
      assert_equal "Unexpected frame type", cm.reason_phrase
    end
  end

  def test_payload_received_malformed_frame
    client_and_server do |client, _server|
      # client receives malformed TRANSPORT_CLOSE frame
      cm = assert_raises ::Raioquic::Quic::Connection::QuicConnectionError do
        client.send(:payload_received, context: client_receive_context(client), plain: "\x1c\x00\x01")
      end
      assert_equal ::Raioquic::Quic::Packet::QuicErrorCode::FRAME_ENCODING_ERROR, cm.error_code
      assert_equal 0x1c, cm.frame_type
      assert_equal "Failed to parse frame", cm.reason_phrase
    end
  end

  def test_send_max_data_blocked_by_cc
    client_and_server do |client, server|
      # check cngestion control
      assert_equal 0, client.loss.bytes_in_flight
      assert_equal 14303, client.loss.congestion_window

      # artificially raise received data counter
      # client.local_max_data_used = client.local_max_data # no method on original
      assert_equal 1048576, server.remote_max_data

      # artificially raise bytes in flight
      client.loss.cc.bytes_in_flight = 14303

      # MAX_DATA is not sent due to congestion control
      assert_equal 0, drop(client)
    end
  end

  def test_send_max_data_retransmit
    client_and_server do |client, server|
      # artificially raise received data counter
      client.local_max_data.used = client.local_max_data.value
      assert_equal 1048576, client.local_max_data.sent
      assert_equal 1048576, client.local_max_data.used
      assert_equal 1048576, client.local_max_data.value
      assert_equal 1048576, server.remote_max_data

      # MAX_DATA is sent and lost
      assert_equal 1, drop(client)
      assert_equal 2097152, client.local_max_data.sent
      assert_equal 1048576, client.local_max_data.used
      assert_equal 2097152, client.local_max_data.value
      assert_equal 1048576, server.remote_max_data

      # MAX_DATA loss is detected
      client.send(
        :on_connection_limit_delivery,
        delivery: ::Raioquic::Quic::PacketBuilder::QuicDeliveryState::LOST,
        limit: client.local_max_data,
      )
      assert_equal 0, client.local_max_data.sent
      assert_equal 1048576, client.local_max_data.used
      assert_equal 2097152, client.local_max_data.value

      # MAX_DATA is retransmitted and acked
      assert_equal [1, 1], roundtrip(client, server)
      assert_equal 2097152, client.local_max_data.sent
      assert_equal 1048576, client.local_max_data.used
      assert_equal 2097152, client.local_max_data.value
      assert_equal 2097152, server.remote_max_data
    end
  end

  def test_send_max_stream_data_retransmit
    client_and_server do |client, server|
      # client creates bidirectional stream 0
      stream = client.send(:get_or_create_stream_for_send, 0)
      client.send_stream_data(stream_id: 0, data: "hello")
      assert_equal 1048576, stream.max_stream_data_local
      assert_equal 1048576, stream.max_stream_data_local_sent
      assert_equal [1, 1], roundtrip(client, server)

      # server just sends data, just before raising MAX_STREAM_DATA
      server.send_stream_data(stream_id: 0, data: "Z" * 524288) # 1048576 // 2
      10.times { roundtrip(server, client) }
      assert_equal 1048576, stream.max_stream_data_local
      assert_equal 1048576, stream.max_stream_data_local_sent

      # server sends one more bytes
      server.send_stream_data(stream_id: 0, data: "Z")
      assert_equal 1, transfer(server, client)

      # MAX_STREAM_DATA is sent and lost
      assert_equal 1, drop(client)
      assert_equal 2097152, stream.max_stream_data_local
      assert_equal 2097152, stream.max_stream_data_local_sent
      client.send(:on_max_stream_data_delivery, delivery: ::Raioquic::Quic::PacketBuilder::QuicDeliveryState::LOST, stream: stream)
      assert_equal 2097152, stream.max_stream_data_local
      assert_equal 0, stream.max_stream_data_local_sent

      # MAX_DATA is retransmitted and acked
      assert_equal [1, 1], roundtrip(client, server)
      assert_equal 2097152, stream.max_stream_data_local
      assert_equal 2097152, stream.max_stream_data_local_sent
    end
  end

  def test_send_max_streams_retransmit
    client_and_server do |client, server|
      # client opens 65 streams
      client.send_stream_data(stream_id: 4 * 64, data: "Z")
      assert_equal 1, transfer(client, server)
      assert_equal 128, client.remote_max_streams_bidi
      assert_equal 128, server.local_max_streams_bidi.sent
      assert_equal 65, server.local_max_streams_bidi.used
      assert_equal 128, server.local_max_streams_bidi.value

      # MAX_STREAMS is sent and lost
      assert_equal 1, drop(server)
      assert_equal 128, client.remote_max_streams_bidi
      assert_equal 256, server.local_max_streams_bidi.sent
      assert_equal 65, server.local_max_streams_bidi.used
      assert_equal 256, server.local_max_streams_bidi.value

      # MAX_STREAMS loss is detected
      server.send(:on_connection_limit_delivery, delivery: ::Raioquic::Quic::PacketBuilder::QuicDeliveryState::LOST, limit: server.local_max_streams_bidi)
      assert_equal 128, client.remote_max_streams_bidi
      assert_equal 0, server.local_max_streams_bidi.sent
      assert_equal 65, server.local_max_streams_bidi.used
      assert_equal 256, server.local_max_streams_bidi.value

      # NAX_STREAMS is retransmitted and acked
      assert_equal [1, 1], roundtrip(server, client)
      assert_equal 256, client.remote_max_streams_bidi
      assert_equal 256, server.local_max_streams_bidi.sent
      assert_equal 65, server.local_max_streams_bidi.used
      assert_equal 256, server.local_max_streams_bidi.value
    end
  end

  def test_send_ping
    client_and_server do |client, server|
      consume_events(client)

      # client sends ping, server ACKs it
      client.send_ping(12345)
      assert_equal [1, 1], roundtrip(client, server)

      # check event
      event = client.next_event
      assert_equal ::Raioquic::Quic::Event::PingAcknowledged, event.class
      assert_equal 12345, event.uid
    end
  end

  def test_send_ping_retransmit
    client_and_server do |client, server|
      consume_events(client)

      # client sends another ping, PING is lost
      client.send_ping(12345)
      assert_equal 1, drop(client)

      # PING is retransmitted and acked
      client.send(:on_ping_delivery, delivery: ::Raioquic::Quic::PacketBuilder::QuicDeliveryState::LOST, uids: [12345])
      assert_equal [1, 1], roundtrip(client, server)

      # check event
      event = client.next_event
      assert_equal ::Raioquic::Quic::Event::PingAcknowledged, event.class
      assert_equal 12345, event.uid
    end
  end

  def test_send_reset_stream
    client_and_server do |client, server|
      # client creates bidirectional stream
      client.send_stream_data(stream_id: 0, data: "hello")
      assert_equal [1, 1], roundtrip(client, server)

      # client resets stream
      client.reset_stream(stream_id: 0, error_code: ::Raioquic::Quic::Packet::QuicErrorCode::NO_ERROR)
      assert_equal [1, 1], roundtrip(client, server)
    end
  end

  def test_send_stop_sending
    client_and_server do |client, server|
      # check handshake completed
      check_handshake(client, server)

      # client creates bidirectional stream
      client.send_stream_data(stream_id: 0, data: "hello")
      assert_equal [1, 1], roundtrip(client, server)

      # client sends STOP_SENDING frame
      client.stop_stream(stream_id: 0, error_code: ::Raioquic::Quic::Packet::QuicErrorCode::NO_ERROR)
      assert_equal [1, 1], roundtrip(client, server)

      # client receives STREAM_RESET frame
      event = client.next_event
      assert_equal ::Raioquic::Quic::Event::StreamReset, event.class
      assert_equal ::Raioquic::Quic::Packet::QuicErrorCode::NO_ERROR, event.error_code
      assert_equal 0, event.stream_id
    end
  end

  def test_send_stop_sending_uni_stream
    client_and_server do |client, server|
      # check handshake completed
      check_handshake(client, server)

      # client sends STOP_SENDING frame
      cm = assert_raises ::Raioquic::ValueError do
        client.stop_stream(stream_id: 2, error_code: ::Raioquic::Quic::Packet::QuicErrorCode::NO_ERROR)
      end
      assert_equal "Cannot stop receiving on a local-initiated unidirectional stream", cm.message
    end
  end

  def test_send_stop_sending_unknown_stream
    client_and_server do |client, server|
      # check handshake completed
      check_handshake(client, server)

      # client sends STOP_SENDING frame
      cm = assert_raises ::Raioquic::ValueError do
        client.stop_stream(stream_id: 0, error_code: ::Raioquic::Quic::Packet::QuicErrorCode::NO_ERROR)
      end
      assert_equal "Cannot stop receiving on an unknown stream", cm.message
    end
  end

  def test_send_stream_data_over_max_streams_bidi
    client_and_server do |client, server|
      # create streams
      128.times do |i|
        stream_id = i * 4
        client.send_stream_data(stream_id: stream_id, data: "")
        assert_equal false, client.streams[stream_id].is_blocked
      end
      assert_equal 0, client.streams_blocked_bidi
      assert_equal 0, client.streams_blocked_uni
      assert_equal [0, 0], roundtrip(client, server)

      # create one too many -> STREAMS_BLOCKED
      stream_id = 128 * 4
      client.send_stream_data(stream_id: stream_id, data: "")
      assert client.streams[stream_id].is_blocked
      assert_equal 1, client.streams_blocked_bidi
      assert_equal 0, client.streams_blocked_uni
      assert_equal [1, 1], roundtrip(client, server)

      # peer raises max streams
      client.handle_max_streams_bidi_frame(
        context: client_receive_context(client),
        frame_type: ::Raioquic::Quic::Packet::QuicFrameType::MAX_STREAMS_BIDI,
        buf: ::Raioquic::Buffer.new(data: ::Raioquic::Buffer.encode_uint_var(129))
      )
      assert_equal false, client.streams[stream_id].is_blocked
    end
  end

  def test_send_stream_data_over_max_streams_uni
    client_and_server do |client, server|
      # create streams
      128.times do |i|
        stream_id = i * 4 + 2
        client.send_stream_data(stream_id: stream_id, data: "")
        assert_equal false, client.streams[stream_id].is_blocked
      end
      assert_equal 0, client.streams_blocked_bidi
      assert_equal 0, client.streams_blocked_uni
      assert_equal [0, 0], roundtrip(client, server)

      # create one too many -> STREAMS_BLOCKED
      stream_id = 128 * 4 + 2
      client.send_stream_data(stream_id: stream_id, data: "")
      assert client.streams[stream_id].is_blocked
      assert_equal 0, client.streams_blocked_bidi
      assert_equal 1, client.streams_blocked_uni
      assert_equal [1, 1], roundtrip(client, server)

      # peer raises max streams
      client.handle_max_streams_bidi_frame(
        context: client_receive_context(client),
        frame_type: ::Raioquic::Quic::Packet::QuicFrameType::MAX_STREAMS_UNI,
        buf: ::Raioquic::Buffer.new(data: ::Raioquic::Buffer.encode_uint_var(129))
      )
      assert_equal false, client.streams[stream_id].is_blocked
    end
  end

  def test_send_stream_data_peer_initiated
    client_and_server do |client, server|
      # server creates bidirectional stream
      server.send_stream_data(stream_id: 1, data: "hello")
      assert_equal [1, 1], roundtrip(server, client)

      # server creates unidirectional stream
      server.send_stream_data(stream_id: 3, data: "hello")
      assert_equal [1, 1], roundtrip(server, client)

      # client creates bidirectional stream
      client.send_stream_data(stream_id: 0, data: "hello")
      assert_equal [1, 1], roundtrip(client, server)

      # client sends data on server-initiated bidirectional stream
      client.send_stream_data(stream_id: 1, data: "hello")
      assert_equal [1, 1], roundtrip(client, server)

      # client creates unidirectional stream
      client.send_stream_data(stream_id: 2, data: "hello")
      assert_equal [1, 1], roundtrip(client, server)

      # client tries to reset server-initiated unidirectional stream
      cm = assert_raises ::Raioquic::ValueError do
        client.reset_stream(stream_id: 3, error_code: ::Raioquic::Quic::Packet::QuicErrorCode::NO_ERROR)
      end
      assert_equal "Cannot send data on unknown peer-initiated stream", cm.message

      # client tries to reset unknown server-initiated bidirectional stream
      cm = assert_raises ::Raioquic::ValueError do
        client.reset_stream(stream_id: 5, error_code: ::Raioquic::Quic::Packet::QuicErrorCode::NO_ERROR)
      end
      assert_equal "Cannot send data on unknown peer-initiated stream", cm.message

      # client tries to send data on unknown peer-initiated stream
      cm = assert_raises ::Raioquic::ValueError do
        client.send_stream_data(stream_id: 3, data: "")
      end
      assert_equal "Cannot send data on peer-initiated unidirectional stream", cm.message

      # client tries to send data on unknown server-initiated bidirectional stream
      cm = assert_raises ::Raioquic::ValueError do
        client.send_stream_data(stream_id: 5, data: "")
      end
      assert_equal "Cannot send data on unknown peer-initiated stream", cm.message
    end
  end

  def test_stream_direction
    client_and_server do |client, server|
      [0, 4, 8].each do |off|
        # Client-Initiated, Bidirectional
        assert client.send(:stream_can_receive, off)
        assert client.send(:stream_can_send, off)
        assert server.send(:stream_can_receive, off)
        assert server.send(:stream_can_send, off)

        # Server-Initiated, Bidirectional
        assert client.send(:stream_can_receive, off + 1)
        assert client.send(:stream_can_send, off + 1)
        assert server.send(:stream_can_receive, off + 1)
        assert server.send(:stream_can_send, off + 1)

        # Client-Initiated, Unidirectional
        assert client.send(:stream_can_receive, off + 2)
        assert client.send(:stream_can_send, off + 2)
        assert server.send(:stream_can_receive, off + 2)
        assert server.send(:stream_can_send, off + 2)

        # Server-Initiated, Unidirectional
        assert client.send(:stream_can_receive, off + 3)
        assert client.send(:stream_can_send, off + 3)
        assert server.send(:stream_can_receive, off + 3)
        assert server.send(:stream_can_send, off + 3)
      end
    end
  end

  def test_version_negotiation_fail
    client = create_standalone_client

    # no common version, no retry
    client.receive_datagram(
      data: ::Raioquic::Quic::Packet.encode_quic_version_negotiation(
        source_cid: client.peer_cid.cid,
        destination_cid: client.host_cid,
        supported_versions: [0xff000011], # DRAFT 16
      ),
      addr: SERVER_ADDR,
      now: Time.now.to_f,
    )
    assert_equal 0, drop(client)

    event = client.next_event
    assert_equal ::Raioquic::Quic::Event::ConnectionTerminated, event.class
    assert_equal ::Raioquic::Quic::Packet::QuicErrorCode::INTERNAL_ERROR, event.error_code
    assert_equal ::Raioquic::Quic::Packet::QuicFrameType::PADDING, event.frame_type
    assert_equal "Could not find a common protocol version", event.reason_phrase
  end

  def test_version_negotiation_ignore
    client = create_standalone_client

    # version negotiation contains the client's version
    client.receive_datagram(
      data: ::Raioquic::Quic::Packet.encode_quic_version_negotiation(
        source_cid: client.peer_cid.cid,
        destination_cid: client.host_cid,
        supported_versions: [client.version],
        ),
      addr: SERVER_ADDR,
      now: Time.now.to_f,
      )
    assert_equal 0, drop(client)
  end

  def test_version_negotiation_ok
    client = create_standalone_client

    # find a common version, retry
    client.receive_datagram(
      data: ::Raioquic::Quic::Packet.encode_quic_version_negotiation(
        source_cid: client.peer_cid.cid,
        destination_cid: client.host_cid,
        supported_versions: [::Raioquic::Quic::Packet::QuicProtocolVersion::VERSION_1], # TODO: check this.
        ),
      addr: SERVER_ADDR,
      now: Time.now.to_f,
      )
    assert_equal 1, drop(client)
  end

  def test_write_connection_close_early
    skip "logger testing"

    client = create_standalone_client

    builder = ::Raioquic::Quic::PacketBuilder::QuicPacketBuilder.new(
      host_cid: client.host_cid,
      is_client: true,
      peer_cid: client.peer_cid.cid,
      version: client.version,
    )
    crypro = ::Raioquic::Quic::Crypto::CryptoPair.new
    crypro.setup_initial(cid: client.host_cid, is_client: true, version: client.version)
    builder.start_packet(packet_type: ::Raioquic::Quic::Packet::PACKET_TYPE_INITIAL, crypro: crypro)
    client.send(
      :write_connection_close_frame,
      builder: builder, epoch: ::Raioquic::TLS::Epoch::INITIAL, error_code: 123, frame_type: nil, reason_phrase: "some reason",
    )
  end

  def test_can_send
    path = ::Raioquic::Quic::Connection::QuicNetworkPath.new.tap do |np|
      np.addr = ["1.2.3.4", 1234]
    end
    assert_equal false, !!path.is_validated

    # initially, cannot send any data
    assert path.can_send(0)
    assert_equal false, path.can_send(1)

    # receive some data
    path.bytes_received += 1
    assert path.can_send(0)
    assert path.can_send(1)
    assert path.can_send(2)
    assert path.can_send(3)
    assert_equal false, path.can_send(4)

    # send some data
    path.bytes_sent += 3
    assert path.can_send(0)
    assert_equal false, path.can_send(1)
  end
end
