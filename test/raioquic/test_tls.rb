# frozen_string_literal: true

require "test_helper"

# rubocop:disable Metrics/MethodLength, Metrics/BlockLength
class TestRaioquicTLS < Minitest::Test
  TLS = ::Raioquic::TLS # for shorthand

  CERTIFICATE_DATA = File.binread("test/samples/tls_certificate.bin").then do |cert|
    len = cert.length
    cert[11...(len - 2)]
  end
  CERTIFICATE_VARIFY_SIGNATURE = File.binread("test/samples/tls_certificate_verify.bin")[8..]

  CLIENT_QUIC_TRANSPORT_PARAMETERS = [
    "ff0000110031000500048010000000060004801000000007000480100000000" \
    "4000481000000000100024258000800024064000a00010a"
  ].pack("H*")

  SERVER_QUIC_TRANSPORT_PARAMETERS = [
    "ff00001104ff000011004500050004801000000006000480100000000700048" \
    "010000000040004810000000001000242580002001000000000000000000000" \
    "000000000000000800024064000a00010a"
  ].pack("H*")

  SERVER_QUIC_TRANSPORT_PARAMETERS_2 = [
    "0057000600048000ffff000500048000ffff00020010c5ac410fbdd4fe6e2c1" \
    "42279f231e8e0000a000103000400048005fffa000b000119000100026710ff" \
    "42000c5c067f27e39321c63e28e7c90003000247e40008000106"
  ].pack("H*")

  SERVER_QUIC_TRANSPORT_PARAMETERS_3 = [
    "0054000200100dcb50a442513295b4679baf04cb5effff8a0009c8afe72a6397" \
    "255407000600048000ffff0008000106000400048005fffa000500048000ffff" \
    "0003000247e4000a000103000100026710000b000119"
  ].pack("H*")

  def create_buffers
    {
      TLS::Epoch::INITIAL => ::Raioquic::Buffer.new(capacity: 4096),
      TLS::Epoch::HANDSHAKE => ::Raioquic::Buffer.new(capacity: 4096),
      TLS::Epoch::ONE_RTT => ::Raioquic::Buffer.new(capacity: 4096),
    }
  end

  def merge_buffers(buffers)
    buffers.values.inject(+"") do |data, buffer|
      data << buffer.data.force_encoding(Encoding::ASCII_8BIT)
    end
  end

  def reset_buffers(buffers)
    buffers.each_value do |buffer|
      buffer.seek(0)
    end
  end

  def test_pull_block_truncated
    buf = ::Raioquic::Buffer.new(capacity: 0)
    assert_raises ::Raioquic::Buffer::BufferReadError do
      TLS.pull_block(buf: buf, capacity: 1)
    end
  end

  def create_client(alpn_protocols: [], cadata: nil, cafile: Utils::SERVER_CACERTFILE, **kwargs)
    client = TLS::Context.new(
      alpn_protocols: alpn_protocols,
      cadata: cadata,
      cafile: cafile,
      is_client: true,
      **kwargs,
    )
    client.handshake_extensions = [
      [TLS::ExtensionType::QUIC_TRANSPORT_PARAMETERS, CLIENT_QUIC_TRANSPORT_PARAMETERS]
    ]
    assert_equal TLS::State::CLIENT_HANDSHAKE_START, client.state
    return client
  end

  def create_server(alpn_protocols: [], **kwargs)
    configuration = ::Raioquic::Quic::QuicConfiguration.new(is_client: false)
    configuration.load_cert_chain(Utils::SERVER_CERTFILE, Utils::SERVER_KEYFILE)

    server = TLS::Context.new(
      alpn_protocols: alpn_protocols,
      is_client: false,
      max_early_data: 0xffffffff,
      **kwargs,
    )
    server.certificate = configuration.certificate
    server.certificate_private_key = configuration.private_key
    server.handshake_extensions = [
      [TLS::ExtensionType::QUIC_TRANSPORT_PARAMETERS, SERVER_QUIC_TRANSPORT_PARAMETERS]
    ]
    assert_equal TLS::State::SERVER_EXPECT_CLIENT_HELLO, server.state
    return server
  end

  def test_client_unexpected_message
    client = create_client

    client.state = TLS::State::CLIENT_EXPECT_SERVER_HELLO
    assert_raises TLS::AlertUnexpectedMessage do
      client.handle_message(input_data: "\x00\x00\x00\x00", output_buf: create_buffers)
    end

    client.state = TLS::State::CLIENT_EXPECT_ENCRYPTED_EXTENSIONS
    assert_raises TLS::AlertUnexpectedMessage do
      client.handle_message(input_data: "\x00\x00\x00\x00", output_buf: create_buffers)
    end

    client.state = TLS::State::CLIENT_EXPECT_CERTIFICATE_REQUEST_OR_CERTIFICATE
    assert_raises TLS::AlertUnexpectedMessage do
      client.handle_message(input_data: "\x00\x00\x00\x00", output_buf: create_buffers)
    end

    client.state = TLS::State::CLIENT_EXPECT_CERTIFICATE_VERIFY
    assert_raises TLS::AlertUnexpectedMessage do
      client.handle_message(input_data: "\x00\x00\x00\x00", output_buf: create_buffers)
    end

    client.state = TLS::State::CLIENT_EXPECT_FINISHED
    assert_raises TLS::AlertUnexpectedMessage do
      client.handle_message(input_data: "\x00\x00\x00\x00", output_buf: create_buffers)
    end

    client.state = TLS::State::CLIENT_POST_HANDSHAKE
    assert_raises TLS::AlertUnexpectedMessage do
      client.handle_message(input_data: "\x00\x00\x00\x00", output_buf: create_buffers)
    end
  end

  def test_client_bad_certificate_verify_data
    client = create_client
    server = create_server

    # send client hello
    client_buf = create_buffers
    client.handle_message(input_data: "", output_buf: client_buf)
    assert_equal TLS::State::CLIENT_EXPECT_SERVER_HELLO, client.state
    server_input = merge_buffers(client_buf)
    reset_buffers(client_buf)

    # handle client hello
    # send server hello, encrypted extensions, certificate, certificate verify, finished
    server_buf = create_buffers
    server.handle_message(input_data: server_input, output_buf: server_buf)
    assert_equal TLS::State::SERVER_EXPECT_FINISHED, server.state
    # binding.irb
    client_input = merge_buffers(server_buf)
    reset_buffers(server_buf)

    # mess with certificate verify
    cl = client_input.length
    client_input = client_input[0...(cl - 56)] + ("\x00" * 4) + client_input[(cl - 52)..]

    # handle server hello, encrypted extensions, certificate, certificate verify, finished
    assert_raises TLS::AlertDecryptError do
      client.handle_message(input_data: client_input, output_buf: client_buf)
    end
  end

  def test_client_bad_finished_verify_data
    client = create_client
    server = create_server

    # send client hello
    client_buf = create_buffers
    client.handle_message(input_data: "", output_buf: client_buf)
    assert_equal TLS::State::CLIENT_EXPECT_SERVER_HELLO, client.state
    server_input = merge_buffers(client_buf)
    reset_buffers(client_buf)

    # handle client hello
    # send server hello, encrypted extensions, certificate, certificate verify, finished
    server_buf = create_buffers
    server.handle_message(input_data: server_input, output_buf: server_buf)
    assert_equal TLS::State::SERVER_EXPECT_FINISHED, server.state
    client_input = merge_buffers(server_buf)
    reset_buffers(server_buf)

    # mess with finished verify data
    client_input = client_input[0...(client_input.length - 4)] + ("\x00" * 4)

    # handle server hello, encrypted extensions, certificate, certificate verify, finished
    assert_raises TLS::AlertDecryptError do
      client.handle_message(input_data: client_input, output_buf: client_buf)
    end
  end

  def test_server_unexpected_message
    server = create_server

    server.state = TLS::State::SERVER_EXPECT_CLIENT_HELLO
    assert_raises TLS::AlertUnexpectedMessage do
      server.handle_message(input_data: "\x00\x00\x00\x00", output_buf: nil)
    end

    server.state = TLS::State::SERVER_EXPECT_FINISHED
    assert_raises TLS::AlertUnexpectedMessage do
      server.handle_message(input_data: "\x00\x00\x00\x00", output_buf: nil)
    end

    server.state = TLS::State::SERVER_POST_HANDSHAKE
    assert_raises TLS::AlertUnexpectedMessage do
      server.handle_message(input_data: "\x00\x00\x00\x00", output_buf: nil)
    end
  end

  def _server_fail_hello(client, server)
    # sned client hello
    client_buf = create_buffers
    client.handle_message(input_data: "", output_buf: client_buf)
    assert_equal TLS::State::CLIENT_EXPECT_SERVER_HELLO, client.state
    server_input = merge_buffers(client_buf)
    reset_buffers(client_buf)

    # handle client hello
    server_buf = create_buffers
    server.handle_message(input_data: server_input, output_buf: server_buf)
  end

  def test_server_unsupported_cipher_suite
    client = create_client(cipher_suites: [TLS::CipherSuite::AES_128_GCM_SHA256])
    server = create_server(cipher_suites: [TLS::CipherSuite::AES_256_GCM_SHA384])

    assert_raises TLS::AlertHandshakeFailure, "No supporteds cipher suite" do
      _server_fail_hello(client, server)
    end
  end

  def test_server_unsupported_signature_algorithm
    client = create_client
    client.signature_algorithms = [TLS::SignatureAlgorithm::ED448]

    server = create_server

    assert_raises TLS::AlertHandshakeFailure, "No supported signature algorithm" do
      _server_fail_hello(client, server)
    end
  end

  def test_server_unsupported_version
    client = create_client
    client.supported_versions = [TLS::TLS_VERSION_1_2]

    server = create_server

    assert_raises TLS::AlertProtocolVersion do
      _server_fail_hello(client, server)
    end
  end

  def test_server_bad_finished_verify_data
    client = create_client
    server = create_server

    # send client hello
    client_buf = create_buffers
    client.handle_message(input_data: "", output_buf: client_buf)
    assert_equal TLS::State::CLIENT_EXPECT_SERVER_HELLO, client.state
    server_input = merge_buffers(client_buf)
    reset_buffers(client_buf)

    # handle client hello
    # send server hello, encrypted extensions, certificate, certificate verify, finished
    server_buf = create_buffers
    server.handle_message(input_data: server_input, output_buf: server_buf)
    assert_equal TLS::State::SERVER_EXPECT_FINISHED, server.state
    client_input = merge_buffers(server_buf)
    reset_buffers(server_buf)

    # handle server hello, encrypted extensions, certificate, certificate verify, finished
    # send finished
    client.handle_message(input_data: client_input, output_buf: client_buf)
    assert_equal TLS::State::CLIENT_POST_HANDSHAKE, client.state
    server_input = merge_buffers(client_buf)
    reset_buffers(client_buf)

    # mess with finished verify data
    server_input = server_input[0...(server_input.length - 4)] + ("\x00" * 4)

    # handle finished
    assert_raises TLS::AlertDecryptError do
      server.handle_message(input_data: server_input, output_buf: server_buf)
    end
  end

  def _handshake(client, server)
    # send client hello
    client_buf = create_buffers
    client.handle_message(input_data: "", output_buf: client_buf)
    assert_equal TLS::State::CLIENT_EXPECT_SERVER_HELLO, client.state
    server_input = merge_buffers(client_buf)
    assert server_input.bytesize >= 181
    assert server_input.bytesize <= 358
    reset_buffers(client_buf)

    # handle client hello
    # send server hello, encrypted extensions, certificate, certificate verify, finished, (session ticket)
    server_buf = create_buffers
    server.handle_message(input_data: server_input, output_buf: server_buf)
    assert_equal TLS::State::SERVER_EXPECT_FINISHED, server.state
    client_input = merge_buffers(server_buf)
    assert client_input.bytesize >= 587
    assert client_input.bytesize <= 2316
    reset_buffers(server_buf)

    # handle server hello, encrypted extensions, certificate, certificate verify, finished, (session ticket)
    # send finished
    client.handle_message(input_data: client_input, output_buf: client_buf)
    assert_equal TLS::State::CLIENT_POST_HANDSHAKE, client.state
    server_input = merge_buffers(client_buf)
    assert_equal 52, server_input.bytesize
    reset_buffers(client_buf)

    # handle finished
    server.handle_message(input_data: server_input, output_buf: server_buf)
    assert_equal TLS::State::SERVER_POST_HANDSHAKE, server.state
    client_input = merge_buffers(server_buf)
    assert_equal 0, client_input.bytesize

    # check keys match
    assert_equal server.enc_key, client.dec_key
    assert_equal server.dec_key, client.enc_key

    # check cipher suite
    assert_equal TLS::CipherSuite::AES_256_GCM_SHA384, client.key_schedule.cipher_suite
    assert_equal TLS::CipherSuite::AES_256_GCM_SHA384, server.key_schedule.cipher_suite
  end

  def test_handshake
    client = create_client
    server = create_server

    _handshake(client, server)

    # check ALPN matches
    assert_nil client.alpn_negotiated
    assert_nil server.alpn_negotiated
  end

  def _test_handshake_with_certificate(certificate, private_key)
    server = create_server
    server.certificate = certificate
    server.certificate_private_key = private_key

    client = create_client(
      cadata: server.certificate.to_pem,
      cafile: nil,
    )

    _handshake(client, server)

    # check ALPN matches
    assert_nil client.alpn_negotiated
    assert_nil server.alpn_negotiated
  end

  def test_handshake_with_ec_certificate
    cert = Utils.generate_ec_certificate(common_name: "example.com")
    _test_handshake_with_certificate(cert[0], cert[1])
  end

  def test_handshake_with_ed25519_certificate
    skip "ED25519 is not supoported"
    # will raise NotImplementedError
    cert = Utils.generate_ed25519_certificate
    _test_handshake_with_certificate(cert[0], cert[1])
  end

  def test_handshake_with_ed448_certificate
    skip "ED448 is not supoported"
    # will raise NotImplementedError
    cert = Utils.generate_ed448_certificate
    _test_handshake_with_certificate(cert[0], cert[1])
  end

  def test_handshake_with_alpn
    client = create_client(alpn_protocols: ["hq-20"])
    server = create_server(alpn_protocols: %w[hq-20 h3-20])

    _handshake(client, server)

    # check ALPN matches
    assert_equal "hq-20", client.alpn_negotiated
    assert_equal "hq-20", server.alpn_negotiated
  end

  def test_handshake_with_alpn_fail
    client = create_client(alpn_protocols: ["hq-20"])
    server = create_server(alpn_protocols: ["h3-20"])

    assert_raises TLS::AlertHandshakeFailure, "No common ALPN protocols" do
      _handshake(client, server)
    end
  end

  def test_handshake_with_rsa_pkcs1_sha256_signature
    client = create_client
    client.signature_algorithms = [TLS::SignatureAlgorithm::RSA_PKCS1_SHA256]
    server = create_server

    _handshake(client, server)
  end

  def test_handshake_with_certificate_error
    client = create_client(cafile: nil)
    server = create_server

    assert_raises TLS::AlertBadCertificate do
      _handshake(client, server)
    end
  end

  def test_handshake_with_certificate_no_verify
    client = create_client(cafile: nil, verify_mode: OpenSSL::SSL::VERIFY_NONE)
    server = create_server

    _handshake(client, server)
  end

  def test_handshake_with_grease_group
    client = create_client
    client.supported_groups = [TLS::Group::GREASE, TLS::Group::SECP256R1]
    server = create_server

    _handshake(client, server)
  end

  def test_handshake_with_x25519
    skip "X25519 is not supported"

    client = create_client
    client.supported_groups = [TLS::Group::X25519]
    server = create_server

    _handshake(client, server)
  end

  def test_handshake_with_x448
    skip "X448 is not supported"

    client = create_client
    client.supported_groups = [TLS::Group::X448]
    server = create_server

    _handshake(client, server)
  end

  def test_session_ticket
    client_tickets = []
    server_tickets = []

    client_new_ticket = lambda do |ticket|
      client_tickets << ticket
    end

    server_get_ticket = lambda do |label|
      server_tickets.each do |t|
        return t if t.ticket == label
      end
      nil
    end

    server_new_ticket = lambda do |ticket|
      server_tickets << ticket
    end

    first_handshake = lambda do
      client = create_client
      client.new_session_ticket_cb = client_new_ticket

      server = create_server
      server.new_session_ticket_cb = server_new_ticket

      _handshake(client, server)

      # check session resumption was not used
      assert_equal false, client.session_resumed
      assert_equal false, server.session_resumed

      # check tickets match
      assert_equal 1, client_tickets.length
      assert_equal 1, server_tickets.length
      assert_equal client_tickets[0].ticket, server_tickets[0].ticket
      assert_equal client_tickets[0].resumption_secret, server_tickets[0].resumption_secret
    end

    second_handshake = lambda do
      client = create_client
      client.session_ticket = client_tickets[0]

      server = create_server
      server.get_session_ticket_cb = server_get_ticket

      # send client hello with pre_shared_key
      client_buf = create_buffers
      client.handle_message(input_data: "", output_buf: client_buf)
      assert_equal TLS::State::CLIENT_EXPECT_SERVER_HELLO, client.state
      server_input = merge_buffers(client_buf)

      # Different assertion value from aioquic. The behavior from the difference of supported signature algorithms.
      assert server_input.bytesize >= 351

      assert server_input.bytesize <= 483
      reset_buffers(client_buf)

      # handle client hello
      # send server hello, encrypted extentions, finished
      server_buf = create_buffers
      server.handle_message(input_data: server_input, output_buf: server_buf)
      assert_equal TLS::State::SERVER_EXPECT_FINISHED, server.state
      client_input = merge_buffers(server_buf)
      assert_equal 275, client_input.bytesize
      reset_buffers(server_buf)

      # handle server hello, encrypted extensions, certificate, certificate verify, finished
      # send finished
      client.handle_message(input_data: client_input, output_buf: client_buf)
      assert_equal TLS::State::CLIENT_POST_HANDSHAKE, client.state
      server_input = merge_buffers(client_buf)
      assert_equal 52, server_input.bytesize
      reset_buffers(server_buf)

      # handle finished
      # send new_session_ticket
      server.handle_message(input_data: server_input, output_buf: server_buf)
      assert_equal TLS::State::SERVER_POST_HANDSHAKE, server.state
      client_input = merge_buffers(server_buf)
      assert_equal 0, client_input.bytesize
      reset_buffers(server_buf)

      # check keys match
      assert_equal client.dec_key, server.enc_key
      assert_equal server.dec_key, client.enc_key

      # check session resumption was used
      assert client.session_resumed
      assert server.session_resumed
    end

    second_handshake_bad_binder = lambda do
      client = create_client
      client.session_ticket = client_tickets[0]

      server = create_server
      server.get_session_ticket_cb = server_get_ticket

      # send client hello with pre_shared_key
      client_buf = create_buffers
      client.handle_message(input_data: "", output_buf: client_buf)
      assert_equal TLS::State::CLIENT_EXPECT_SERVER_HELLO, client.state
      server_input = merge_buffers(client_buf)

      # Different assertion value from aioquic. The behavior from the difference of supported signature algorithms.
      assert server_input.bytesize >= 351

      assert server_input.bytesize <= 483
      reset_buffers(client_buf)

      # tamper with binder
      server_input = server_input[0...(server_input.length - 4)] + ("\x00" * 4)

      # handle client hello
      # send server hello, encrypted extensions, finished
      server_buf = create_buffers
      assert_raises TLS::AlertHandshakeFailure do
        server.handle_message(input_data: server_input, output_buf: server_buf)
      end
    end

    second_handshake_bad_pre_shared_key = lambda do
      client = create_client
      client.session_ticket = client_tickets[0]

      server = create_server
      server.get_session_ticket_cb = server_get_ticket

      # send client hello with pre_shared_key
      client_buf = create_buffers
      client.handle_message(input_data: "", output_buf: client_buf)
      assert_equal TLS::State::CLIENT_EXPECT_SERVER_HELLO, client.state
      server_input = merge_buffers(client_buf)

      # Different assertion value from aioquic. The behavior from the difference of supported signature algorithms.
      assert server_input.bytesize >= 351

      assert server_input.bytesize <= 483
      reset_buffers(client_buf)

      # handle client hello
      # send server hello, encrypted extensions, finished
      server_buf = create_buffers
      server.handle_message(input_data: server_input, output_buf: server_buf)
      assert_equal TLS::State::SERVER_EXPECT_FINISHED, server.state

      # tamper with pre_shared_key index
      buf = server_buf[TLS::Epoch::INITIAL]
      buf.seek(buf.tell - 1)
      buf.push_uint8(1)
      client_input = merge_buffers(server_buf)
      assert_equal 275, client_input.bytesize
      reset_buffers(server_buf)

      # handle server hello and bomb
      assert_raises TLS::AlertIllegalParameter do
        client.handle_message(input_data: client_input, output_buf: client_buf)
      end
    end

    first_handshake.call
    second_handshake.call
    second_handshake_bad_binder.call
    second_handshake_bad_pre_shared_key.call
  end

  def test_pull_client_hello
    buf = ::Raioquic::Buffer.new(data: File.read("test/samples/tls_client_hello.bin"))
    hello = TLS.pull_client_hello(buf)
    assert buf.eof

    assert_equal ["18b2b23bf3e44b5d52ccfe7aecbc5ff14eadc3d349fabf804d71f165ae76e7d5"].pack("H*"), hello.random
    assert_equal ["9aee82a2d186c1cb32a329d9dcfe004a1a438ad0485a53c6bfcf55c132a23235"].pack("H*"), hello.legacy_session_id
    assert_equal [
      TLS::CipherSuite::AES_256_GCM_SHA384,
      TLS::CipherSuite::AES_128_GCM_SHA256,
      TLS::CipherSuite::CHACHA20_POLY1305_SHA256,
    ], hello.cipher_suites
    assert_equal [TLS::CompressionMethod::NULL], hello.legacy_compression_methods

    # extensions
    assert_nil hello.alpn_protocols
    assert_equal [
      [
        TLS::Group::SECP256R1,
        [
          "047bfea344467535054263b75def60cffa82405a211b68d1eb8d1d944e67aef8" \
          "93c7665a5473d032cfaf22a73da28eb4aacae0017ed12557b5791f98a1e84f15" \
          "b0"
        ].pack("H*")
      ]
    ], hello.key_share
    assert_equal [TLS::PskKeyExchangeMode::PSK_DHE_KE], hello.psk_key_exchange_modes
    assert_nil hello.server_name
    assert_equal [
      TLS::SignatureAlgorithm::RSA_PSS_RSAE_SHA256,
      TLS::SignatureAlgorithm::ECDSA_SECP256R1_SHA256,
      TLS::SignatureAlgorithm::RSA_PKCS1_SHA256,
      TLS::SignatureAlgorithm::RSA_PKCS1_SHA1,
    ], hello.signature_algorithms
    assert_equal [TLS::Group::SECP256R1], hello.supported_groups
    assert_equal [
      TLS::TLS_VERSION_1_3,
      TLS::TLS_VERSION_1_3_DRAFT_28,
      TLS::TLS_VERSION_1_3_DRAFT_27,
      TLS::TLS_VERSION_1_3_DRAFT_26,
    ], hello.supported_versions

    assert_equal [
      [
        TLS::ExtensionType::QUIC_TRANSPORT_PARAMETERS_DRAFT,
        CLIENT_QUIC_TRANSPORT_PARAMETERS
      ]
    ], hello.other_extensions
  end

  def test_pull_client_hello_with_alpn
    buf = ::Raioquic::Buffer.new(data: File.read("test/samples/tls_client_hello_with_alpn.bin"))
    hello = TLS.pull_client_hello(buf)
    assert buf.eof

    assert_equal ["ed575c6fbd599c4dfaabd003dca6e860ccdb0e1782c1af02e57bf27cb6479b76"].pack("H*"), hello.random
    assert_equal "", hello.legacy_session_id
    assert_equal [
      TLS::CipherSuite::AES_128_GCM_SHA256,
      TLS::CipherSuite::AES_256_GCM_SHA384,
      TLS::CipherSuite::CHACHA20_POLY1305_SHA256,
      TLS::CipherSuite::EMPTY_RENEGOTIATION_INFO_SCSV,
    ], hello.cipher_suites
    assert_equal [TLS::CompressionMethod::NULL], hello.legacy_compression_methods

    # extensions
    assert_equal ["h3-19"], hello.alpn_protocols
    assert_equal false, hello.early_data
    assert_equal [
      [
        TLS::Group::SECP256R1,
        [
          "048842315c437bb0ce2929c816fee4e942ec5cb6db6a6b9bf622680188ebb0d4" \
          "b652e69033f71686aa01cbc79155866e264c9f33f45aa16b0dfa10a222e3a669" \
          "22"
        ].pack("H*")
      ]
    ], hello.key_share
    assert_equal [TLS::PskKeyExchangeMode::PSK_DHE_KE], hello.psk_key_exchange_modes
    assert_equal "cloudflare-quic.com", hello.server_name
    assert_equal [
      TLS::SignatureAlgorithm::ECDSA_SECP256R1_SHA256,
      TLS::SignatureAlgorithm::ECDSA_SECP384R1_SHA384,
      TLS::SignatureAlgorithm::ECDSA_SECP521R1_SHA512,
      TLS::SignatureAlgorithm::ED25519,
      TLS::SignatureAlgorithm::ED448,
      TLS::SignatureAlgorithm::RSA_PSS_PSS_SHA256,
      TLS::SignatureAlgorithm::RSA_PSS_PSS_SHA384,
      TLS::SignatureAlgorithm::RSA_PSS_PSS_SHA512,
      TLS::SignatureAlgorithm::RSA_PSS_RSAE_SHA256,
      TLS::SignatureAlgorithm::RSA_PSS_RSAE_SHA384,
      TLS::SignatureAlgorithm::RSA_PSS_RSAE_SHA512,
      TLS::SignatureAlgorithm::RSA_PKCS1_SHA256,
      TLS::SignatureAlgorithm::RSA_PKCS1_SHA384,
      TLS::SignatureAlgorithm::RSA_PKCS1_SHA512,
    ], hello.signature_algorithms
    assert_equal [
      TLS::Group::SECP256R1,
      TLS::Group::X25519,
      TLS::Group::SECP384R1,
      TLS::Group::SECP521R1,
    ], hello.supported_groups
    assert_equal [TLS::TLS_VERSION_1_3], hello.supported_versions

    # serialize
    buf = ::Raioquic::Buffer.new(capacity: 1000)
    TLS.push_client_hello(buf: buf, hello: hello)
    assert_equal File.read("test/samples/tls_client_hello_with_alpn.bin").bytesize, buf.data.bytesize
  end

  def test_pull_client_hello_with_psk
    tls_client_hello_with_psk = File.binread("test/samples/tls_client_hello_with_psk.bin")
    buf = ::Raioquic::Buffer.new(data: tls_client_hello_with_psk)
    hello = TLS.pull_client_hello(buf)

    assert hello.early_data
    assert_equal TLS::OfferedPsks.new.tap { |psk|
      psk.identities = [
        [
          [
            "fab3dc7d79f35ea53e9adf21150e601591a750b80cde0cd167fef6e0cdbc032a" \
            "c4161fc5c5b66679de49524bd5624c50d71ba3e650780a4bfe402d6a06a00525" \
            "0b5dc52085233b69d0dd13924cc5c713a396784ecafc59f5ea73c1585d79621b" \
            "8a94e4f2291b17427d5185abf4a994fca74ee7a7f993a950c71003fc7cf8"
          ].pack("H*"),
          2067156378,
        ]
      ]
      psk.binders = [
        [
          "1788ad43fdff37cfc628f24b6ce7c8c76180705380da17da32811b5bae4e78" \
          "d7aaaf65a9b713872f2bb28818ca1a6b01"
        ].pack("H*")
      ]
    }, hello.pre_shared_key
    assert buf.eof

    # serialize
    buf = ::Raioquic::Buffer.new(capacity: 1000)
    TLS.push_client_hello(buf: buf, hello: hello)
    assert_equal tls_client_hello_with_psk, buf.data
  end

  def test_pull_client_hello_with_sni
    tls_client_hello_with_sni = File.binread("test/samples/tls_client_hello_with_sni.bin")
    buf = ::Raioquic::Buffer.new(data: tls_client_hello_with_sni)
    hello = TLS.pull_client_hello(buf)
    assert buf.eof

    assert_equal ["987d8934140b0a42cc5545071f3f9f7f61963d7b6404eb674c8dbe513604346b"].pack("H*"), hello.random
    assert_equal ["26b19bdd30dbf751015a3a16e13bd59002dfe420b799d2a5cd5e11b8fa7bcb66"].pack("H*"), hello.legacy_session_id
    assert_equal [
      TLS::CipherSuite::AES_256_GCM_SHA384,
      TLS::CipherSuite::AES_128_GCM_SHA256,
      TLS::CipherSuite::CHACHA20_POLY1305_SHA256,

    ], hello.cipher_suites
    assert_equal [TLS::CompressionMethod::NULL], hello.legacy_compression_methods

    # extensions
    assert_nil hello.alpn_protocols
    assert_equal [
      [
        TLS::Group::SECP256R1,
        [
          "04b62d70f907c814cd65d0f73b8b991f06b70c77153f548410a191d2b19764a2" \
          "ecc06065a480efa9e1f10c8da6e737d5bfc04be3f773e20a0c997f51b5621280" \
          "40"
        ].pack("H*")
      ]
    ], hello.key_share
    assert_equal [TLS::PskKeyExchangeMode::PSK_DHE_KE], hello.psk_key_exchange_modes
    assert_equal [
      TLS::SignatureAlgorithm::RSA_PSS_RSAE_SHA256,
      TLS::SignatureAlgorithm::ECDSA_SECP256R1_SHA256,
      TLS::SignatureAlgorithm::RSA_PKCS1_SHA256,
      TLS::SignatureAlgorithm::RSA_PKCS1_SHA1,
    ], hello.signature_algorithms
    assert_equal [TLS::Group::SECP256R1], hello.supported_groups
    assert_equal [
      TLS::TLS_VERSION_1_3,
      TLS::TLS_VERSION_1_3_DRAFT_28,
      TLS::TLS_VERSION_1_3_DRAFT_27,
      TLS::TLS_VERSION_1_3_DRAFT_26,
    ], hello.supported_versions
    assert_equal [
      [
        TLS::ExtensionType::QUIC_TRANSPORT_PARAMETERS_DRAFT,
        CLIENT_QUIC_TRANSPORT_PARAMETERS
      ]
    ], hello.other_extensions

    # serialize
    buf = ::Raioquic::Buffer.new(capacity: 1000)
    TLS.push_client_hello(buf: buf, hello: hello)
    assert_equal tls_client_hello_with_sni, buf.data
  end

  def test_push_client_hello
    hello = TLS::ClientHello.new.tap do |client|
      client.random = ["18b2b23bf3e44b5d52ccfe7aecbc5ff14eadc3d349fabf804d71f165ae76e7d5"].pack("H*")
      client.legacy_session_id = ["9aee82a2d186c1cb32a329d9dcfe004a1a438ad0485a53c6bfcf55c132a23235"].pack("H*")
      client.cipher_suites = [
        TLS::CipherSuite::AES_256_GCM_SHA384,
        TLS::CipherSuite::AES_128_GCM_SHA256,
        TLS::CipherSuite::CHACHA20_POLY1305_SHA256,
      ]
      client.legacy_compression_methods = [TLS::CompressionMethod::NULL]
      client.key_share = [
        [
          TLS::Group::SECP256R1,
          [
            "047bfea344467535054263b75def60cffa82405a211b68d1eb8d1d944e67aef8" \
            "93c7665a5473d032cfaf22a73da28eb4aacae0017ed12557b5791f98a1e84f15" \
            "b0"
          ].pack("H*")
        ]
      ]
      client.psk_key_exchange_modes = [TLS::PskKeyExchangeMode::PSK_DHE_KE]
      client.signature_algorithms = [
        TLS::SignatureAlgorithm::RSA_PSS_RSAE_SHA256,
        TLS::SignatureAlgorithm::ECDSA_SECP256R1_SHA256,
        TLS::SignatureAlgorithm::RSA_PKCS1_SHA256,
        TLS::SignatureAlgorithm::RSA_PKCS1_SHA1,
      ]
      client.supported_groups = [TLS::Group::SECP256R1]
      client.supported_versions = [
        TLS::TLS_VERSION_1_3,
        TLS::TLS_VERSION_1_3_DRAFT_28,
        TLS::TLS_VERSION_1_3_DRAFT_27,
        TLS::TLS_VERSION_1_3_DRAFT_26,
      ]
      client.other_extensions = [
        [
          TLS::ExtensionType::QUIC_TRANSPORT_PARAMETERS_DRAFT,
          CLIENT_QUIC_TRANSPORT_PARAMETERS
        ]
      ]
    end

    buf = ::Raioquic::Buffer.new(capacity: 1000)
    TLS.push_client_hello(buf: buf, hello: hello)
    assert_equal File.binread("test/samples/tls_client_hello.bin"), buf.data
  end

  def test_pull_server_hello
    buf = ::Raioquic::Buffer.new(data: File.read("test/samples/tls_server_hello.bin"))
    hello = TLS.pull_server_hello(buf)
    assert buf.eof

    assert_equal ["ada85271d19680c615ea7336519e3fdf6f1e26f3b1075ee1de96ffa8884e8280"].pack("H*"), hello.random
    assert_equal ["9aee82a2d186c1cb32a329d9dcfe004a1a438ad0485a53c6bfcf55c132a23235"].pack("H*"), hello.legacy_session_id
    assert_equal TLS::CipherSuite::AES_256_GCM_SHA384, hello.cipher_suite
    assert_equal TLS::CompressionMethod::NULL, hello.compression_method
    assert_equal [
      TLS::Group::SECP256R1,
      [
        "048b27d0282242d84b7fcc02a9c4f13eca0329e3c7029aa34a33794e6e7ba189" \
        "5cca1c503bf0378ac6937c354912116ff3251026bca1958d7f387316c83ae6cf" \
        "b2"
      ].pack("H*")
    ], hello.key_share
    assert_nil hello.pre_shared_key
    assert_equal TLS::TLS_VERSION_1_3, hello.supported_version
  end

  def test_pull_server_hello_with_psk
    tls_server_hello_with_psk = File.binread("test/samples/tls_server_hello_with_psk.bin")
    buf = ::Raioquic::Buffer.new(data: tls_server_hello_with_psk)
    hello = TLS.pull_server_hello(buf)
    assert buf.eof

    assert_equal ["ccbaaf04fc1bd5143b2cc6b97520cf37d91470dbfc8127131a7bf0f941e3a137"].pack("H*"), hello.random
    assert_equal ["9483e7e895d0f4cec17086b0849601c0632662cd764e828f2f892f4c4b7771b0"].pack("H*"), hello.legacy_session_id
    assert_equal TLS::CipherSuite::AES_256_GCM_SHA384, hello.cipher_suite
    assert_equal TLS::CompressionMethod::NULL, hello.compression_method
    assert_equal [
      TLS::Group::SECP256R1,
      [
        "0485d7cecbebfc548fc657bf51b8e8da842a4056b164a27f7702ca318c16e488" \
        "18b6409593b15c6649d6f459387a53128b164178adc840179aad01d36ce95d62" \
        "76"
      ].pack("H*")
    ], hello.key_share
    assert_equal 0, hello.pre_shared_key
    assert_equal TLS::TLS_VERSION_1_3, hello.supported_version

    # serialize
    buf = ::Raioquic::Buffer.new(capacity: 1000)
    TLS.push_server_hello(buf: buf, hello: hello)
    assert_equal tls_server_hello_with_psk, buf.data
  end

  def test_pull_server_hello_with_unknown_extension
    tls_server_hello_with_unknown_extension = File.binread("test/samples/tls_server_hello_with_unknown_extension.bin")
    buf = ::Raioquic::Buffer.new(data: tls_server_hello_with_unknown_extension)
    hello = TLS.pull_server_hello(buf)
    assert buf.eof

    assert_equal TLS::ServerHello.new.tap { |server|
      server.random = ["ada85271d19680c615ea7336519e3fdf6f1e26f3b1075ee1de96ffa8884e8280"].pack("H*")
      server.legacy_session_id = ["9aee82a2d186c1cb32a329d9dcfe004a1a438ad0485a53c6bfcf55c132a23235"].pack("H*")
      server.cipher_suite = TLS::CipherSuite::AES_256_GCM_SHA384
      server.compression_method = TLS::CompressionMethod::NULL
      server.key_share = [
        TLS::Group::SECP256R1,
        [
          "048b27d0282242d84b7fcc02a9c4f13eca0329e3c7029aa34a33794e6e7ba189" \
          "5cca1c503bf0378ac6937c354912116ff3251026bca1958d7f387316c83ae6cf" \
          "b2"
        ].pack("H*")
      ]
      server.supported_version = TLS::TLS_VERSION_1_3
      server.other_extensions = [[12345, "foo"]]
    }, hello

    # serialize
    buf = ::Raioquic::Buffer.new(capacity: 1000)
    TLS.push_server_hello(buf: buf, hello: hello)
    assert_equal tls_server_hello_with_unknown_extension, buf.data
  end

  def test_push_server_hello
    hello = TLS::ServerHello.new.tap do |server|
      server.random = ["ada85271d19680c615ea7336519e3fdf6f1e26f3b1075ee1de96ffa8884e8280"].pack("H*")
      server.legacy_session_id = ["9aee82a2d186c1cb32a329d9dcfe004a1a438ad0485a53c6bfcf55c132a23235"].pack("H*")
      server.cipher_suite = TLS::CipherSuite::AES_256_GCM_SHA384
      server.key_share = [
        TLS::Group::SECP256R1,
        [
          "048b27d0282242d84b7fcc02a9c4f13eca0329e3c7029aa34a33794e6e7ba189" \
          "5cca1c503bf0378ac6937c354912116ff3251026bca1958d7f387316c83ae6cf" \
          "b2"
        ].pack("H*")
      ]
      server.supported_version = TLS::TLS_VERSION_1_3
    end

    buf = ::Raioquic::Buffer.new(capacity: 1000)
    TLS.push_server_hello(buf: buf, hello: hello)
    assert_equal File.binread("test/samples/tls_server_hello.bin"), buf.data
  end

  def test_pull_new_session_ticket
    tls_new_session_ticket = File.binread("test/samples/tls_new_session_ticket.bin")
    buf = ::Raioquic::Buffer.new(data: tls_new_session_ticket)
    new_session_ticket = TLS.pull_new_session_ticket(buf)
    assert new_session_ticket
    assert buf.eof

    assert_equal TLS::NewSessionTicket.new.tap { |ticket|
      ticket.ticket_lifetime = 86400
      ticket.ticket_age_add = 3303452425
      ticket.ticket_nonce = ""
      ticket.ticket = ["dbe6f1a77a78c0426bfa607cd0d02b350247d90618704709596beda7e962cc81"].pack("H*")
      ticket.max_early_data_size = 0xffffffff
      ticket.other_extensions = []
    }, new_session_ticket

    # serialize
    buf = ::Raioquic::Buffer.new(capacity: 100)
    TLS.push_new_session_ticket(buf: buf, new_session_ticket: new_session_ticket)
    assert_equal tls_new_session_ticket, buf.data
  end

  def test_pull_new_session_ticket_with_unknown_extension
    tls_new_session_ticket_with_unknown_extension = File.binread("test/samples/tls_new_session_ticket_with_unknown_extension.bin")
    buf = ::Raioquic::Buffer.new(data: tls_new_session_ticket_with_unknown_extension)
    new_session_ticket = TLS.pull_new_session_ticket(buf)
    assert new_session_ticket
    assert buf.eof

    assert_equal TLS::NewSessionTicket.new.tap { |ticket|
      ticket.ticket_lifetime = 86400
      ticket.ticket_age_add = 3303452425
      ticket.ticket_nonce = ""
      ticket.ticket = ["dbe6f1a77a78c0426bfa607cd0d02b350247d90618704709596beda7e962cc81"].pack("H*")
      ticket.max_early_data_size = 0xffffffff
      ticket.other_extensions = [[12345, "foo"]]
    }, new_session_ticket

    # serialize
    buf = ::Raioquic::Buffer.new(capacity: 1000)
    TLS.push_new_session_ticket(buf: buf, new_session_ticket: new_session_ticket)
    assert_equal tls_new_session_ticket_with_unknown_extension, buf.data
  end

  def test_encrypted_extensions
    tls_encrypted_extensions = File.read("test/samples/tls_encrypted_extensions.bin")
    buf = ::Raioquic::Buffer.new(data: tls_encrypted_extensions)
    extensions = TLS.pull_encrypted_extensions(buf)
    assert extensions
    assert buf.eof

    assert_equal TLS::EncryptedExtensions.new.tap { |ex|
      ex.other_extensions = [[
        TLS::ExtensionType::QUIC_TRANSPORT_PARAMETERS_DRAFT,
        SERVER_QUIC_TRANSPORT_PARAMETERS
      ]]
    }, extensions

    # serialize
    buf = ::Raioquic::Buffer.new(capacity: 100)
    TLS.push_encrypted_extensions(buf: buf, extensions: extensions)
    assert_equal tls_encrypted_extensions, buf.data
  end

  def test_encrypted_extensions_with_alpn
    buf = ::Raioquic::Buffer.new(data: File.read("test/samples/tls_encrypted_extensions_with_alpn.bin"))
    extensions = TLS.pull_encrypted_extensions(buf)
    assert buf.eof

    assert_equal TLS::EncryptedExtensions.new.tap { |ex|
      ex.alpn_protocol = "hq-20"
      ex.other_extensions = [
        [TLS::ExtensionType::SERVER_NAME, ""],
        [TLS::ExtensionType::QUIC_TRANSPORT_PARAMETERS_DRAFT, SERVER_QUIC_TRANSPORT_PARAMETERS_2]
      ]
    }, extensions

    # serialze
    buf = ::Raioquic::Buffer.new(capacity: 115)
    TLS.push_encrypted_extensions(buf: buf, extensions: extensions)
    assert buf.eof
  end

  def test_pull_encrypted_extensions_with_alpn_and_early_data
    buf = ::Raioquic::Buffer.new(data: File.read("test/samples/tls_encrypted_extensions_with_alpn_and_early_data.bin"))
    extensions = TLS.pull_encrypted_extensions(buf)
    assert extensions
    assert buf.eof

    assert_equal TLS::EncryptedExtensions.new.tap { |ex|
      ex.alpn_protocol = "hq-20"
      ex.early_data = true
      ex.other_extensions = [
        [TLS::ExtensionType::SERVER_NAME, ""],
        [TLS::ExtensionType::QUIC_TRANSPORT_PARAMETERS_DRAFT, SERVER_QUIC_TRANSPORT_PARAMETERS_3],
      ]
    }, extensions

    # serialize
    buf = ::Raioquic::Buffer.new(capacity: 116)
    TLS.push_encrypted_extensions(buf: buf, extensions: extensions)
    assert buf.eof
  end

  def test_pull_certificate
    buf = ::Raioquic::Buffer.new(data: File.read("test/samples/tls_certificate.bin"))
    certificate = TLS.pull_certificate(buf)
    assert certificate

    assert_equal "", certificate.request_context
    assert_equal [[CERTIFICATE_DATA, ""]], certificate.certificates
  end

  def test_push_certificate
    certificate = TLS::Certificate.new.tap do |cert|
      cert.request_context = ""
      cert.certificates = [[CERTIFICATE_DATA, ""]]
    end

    buf = ::Raioquic::Buffer.new(capacity: 1600)
    TLS.push_certificate(buf: buf, certificate: certificate)
    assert_equal File.read("test/samples/tls_certificate.bin"), buf.data
  end

  def test_pull_certificate_verify
    buf = ::Raioquic::Buffer.new(data: File.read("test/samples/tls_certificate_verify.bin"))
    verify = TLS.pull_certificate_verify(buf)
    assert buf.eof

    assert_equal TLS::SignatureAlgorithm::RSA_PSS_RSAE_SHA256, verify.algorithm
    assert_equal CERTIFICATE_VARIFY_SIGNATURE, verify.signature
  end

  def test_push_certificate_verify
    verify = TLS::CertificateVerify.new.tap do |v|
      v.algorithm = TLS::SignatureAlgorithm::RSA_PSS_RSAE_SHA256
      v.signature = CERTIFICATE_VARIFY_SIGNATURE
    end

    buf = ::Raioquic::Buffer.new(capacity: 400)
    TLS.push_certificate_verify(buf: buf, verify: verify)
    assert_equal File.read("test/samples/tls_certificate_verify.bin"), buf.data
  end

  def test_pull_finished
    buf = ::Raioquic::Buffer.new(data: File.read("test/samples/tls_finished.bin"))
    finished = TLS.pull_finished(buf)
    assert buf.eof

    assert_equal ["f157923234ff9a4921aadb2e0ec7b1a30fce73fb9ec0c4276f9af268f408ec68"].pack("H*"), finished.verify_data
  end

  def test_push_finished
    finished = TLS::Finished.new.tap do |f|
      f.verify_data = ["f157923234ff9a4921aadb2e0ec7b1a30fce73fb9ec0c4276f9af268f408ec68"].pack("H*")
    end

    buf = ::Raioquic::Buffer.new(capacity: 128)
    TLS.push_finished(buf: buf, finished: finished)
    assert_equal File.read("test/samples/tls_finished.bin"), buf.data
  end

  def test_verify_certificate_chain
    certificate = TLS.load_pem_x509_certificates(File.read(Utils::SERVER_CERTFILE))[0]
    Time.stub :now, certificate.not_before do
      assert_raises TLS::AlertBadCertificate, "unable to get local issuer certificate" do
        TLS.verify_certificate(certificate: certificate, server_name: "localhost")
      end

      assert TLS.verify_certificate(cafile: Utils::SERVER_CACERTFILE, certificate: certificate, server_name: "localhost")
    end
  end

  def test_verify_certificate_chain_self_signed
    certificate, = Utils.generate_ec_certificate(common_name: "localhost", curve: "prime256v1")

    Time.stub :now, certificate.not_before do
      assert_raises TLS::AlertBadCertificate do
        TLS.verify_certificate(certificate: certificate, server_name: "localhost")
      end

      assert TLS.verify_certificate(cadata: certificate.to_pem, certificate: certificate, server_name: "localhost")
    end
  end

  def test_verify_dates
    certificate, = Utils.generate_ec_certificate(common_name: "example.com", curve: "prime256v1")
    cadata = certificate.to_pem

    # too early
    Time.stub :now, certificate.not_before - 1 do
      err = assert_raises TLS::AlertCertificateExpired do
        TLS.verify_certificate(cadata: cadata, certificate: certificate, server_name: "example.com")
      end
      assert_equal "Certificate is not valid yet", err.message
    end

    Time.stub :now, certificate.not_before do
      assert TLS.verify_certificate(cadata: cadata, certificate: certificate, server_name: "example.com")
    end

    Time.stub :now, certificate.not_after do
      assert TLS.verify_certificate(cadata: cadata, certificate: certificate, server_name: "example.com")
    end

    # to late
    Time.stub :now, certificate.not_after + 1 do
      err = assert_raises TLS::AlertCertificateExpired do
        TLS.verify_certificate(cadata: cadata, certificate: certificate, server_name: "example.com")
      end
      assert_equal "Certificate is no longer valid", err.message
    end
  end

  def test_verify_subject
    certificate, = Utils.generate_ec_certificate(common_name: "example.com", curve: "prime256v1")
    cadata = certificate.to_pem

    Time.stub :now, certificate.not_before do
      assert TLS.verify_certificate(cadata: cadata, certificate: certificate, server_name: "example.com")

      err = assert_raises TLS::AlertBadCertificate do
        TLS.verify_certificate(cadata: cadata, certificate: certificate, server_name: "test.example.com")
      end
      assert_equal "hostname 'test.example.com' doesn't match 'example.com'", err.message

      err = assert_raises TLS::AlertBadCertificate do
        TLS.verify_certificate(cadata: cadata, certificate: certificate, server_name: "acme.com")
      end
      assert_equal "hostname 'acme.com' doesn't match 'example.com'", err.message
    end
  end

  def test_verify_subject_with_subjaltname
    certificate, = Utils.generate_ec_certificate(common_name: "example.com", curve: "prime256v1", alternative_names: ["*.example.com", "example.com"])
    cadata = certificate.to_pem

    Time.stub :now, certificate.not_before do
      assert TLS.verify_certificate(cadata: cadata, certificate: certificate, server_name: "example.com")
      assert TLS.verify_certificate(cadata: cadata, certificate: certificate, server_name: "test.example.com")

      err = assert_raises TLS::AlertBadCertificate do
        TLS.verify_certificate(cadata: cadata, certificate: certificate, server_name: "acme.com")
      end
      assert_equal "hostname 'acme.com' doesn't match 'example.com'", err.message # cannnot contain subjAltName in exception message yet...
    end
  end
end
# rubocop:enable Metrics/MethodLength, Metrics/BlockLength
