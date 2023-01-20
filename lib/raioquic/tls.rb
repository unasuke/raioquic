# frozen_string_literal: true

require "openssl"
require "certifi"
require "tttls1.3"
require_relative "core_ext"

module Raioquic
  # Raioquic::TLS
  # Migrated from auiquic/src/aioquic/tls.py
  module TLS
    TLS_VERSION_1_2 = 0x0303
    TLS_VERSION_1_3 = 0x0304
    TLS_VERSION_1_3_DRAFT_28 = 0x7f1c
    TLS_VERSION_1_3_DRAFT_27 = 0x7f1b
    TLS_VERSION_1_3_DRAFT_26 = 0x7f1a

    class AlertDescription
      CLOSE_NOTIFY = 0
      UNEXPECTED_MESSAGE = 10
      BAD_RECORD_MAC = 20
      RECORD_OVERFLOW = 22
      HANDSHAKE_FAILURE = 40
      BAD_CERTIFICATE = 42
      UNSUPPORTED_CERTIFICATE = 43
      CERTIFICATE_REVOKED = 44
      CERTIFICATE_EXPIRED = 45
      CERTIFICATE_UNKNOWN = 46
      ILLEGAL_PARAMETER = 47
      UNKNOWN_CA = 48
      ACCESS_DENIED = 49
      DECODE_ERROR = 50
      DECRYPT_ERROR = 51
      PROTOCOL_VERSION = 70
      INSUFFICIENT_SECURITY = 71
      INTERNAL_ERROR = 80
      INAPPROPRIATE_FALLBACK = 86
      USER_CANCELED = 90
      MISSING_EXTENSION = 109
      UNSUPPORTED_EXTENSION = 110
      UNRECOGNIZED_NAME = 112
      BAD_CERTIFICATE_STATUS_RESPONSE = 113
      UNKNOWN_PSK_IDENTITY = 115
      CERTIFICATE_REQUIRED = 116
      NO_APPLICATION_PROTOCOL = 120
    end

    class Alert < StandardError
    end

    class AlertBadCertificate < Alert
      def description
        AlertDescription::BAD_CERTIFICATE
      end
    end

    class AlertCertificateExpired < Alert
      def description
        AlertDescription::CERTIFICATE_EXPIRED
      end
    end

    class AlertDecryptError < Alert
      def description
        AlertDescription::DECRYPT_ERROR
      end
    end

    class AlertHandshakeFailure < Alert
      def description
        AlertDescription::HANDSHAKE_FAILURE
      end
    end

    class AlertIllegalParameter < Alert
      def description
        AlertDescription::ILLEGAL_PARAMETER
      end
    end

    class AlertInternalError < Alert
      def description
        AlertDescription::INTERNAL_ERROR
      end
    end

    class AlertProtocolVersion < Alert
      def description
        AlertDescription::PROTOCOL_VERSION
      end
    end

    class AlertUnexpectedMessage < Alert
      def description
        AlertDescription::UNEXPECTED_MESSAGE
      end
    end

    class Direction
      DECRYPT = 0
      ENCRYPT = 1
    end

    class Epoch
      INITIAL = 0
      ZERO_RTT = 1
      HANDSHAKE = 2
      ONE_RTT = 3
    end

    class State
      CLIENT_HANDSHAKE_START = 0
      CLIENT_EXPECT_SERVER_HELLO = 1
      CLIENT_EXPECT_ENCRYPTED_EXTENSIONS = 2
      CLIENT_EXPECT_CERTIFICATE_REQUEST_OR_CERTIFICATE = 3
      CLIENT_EXPECT_CERTIFICATE_CERTIFICATE = 4
      CLIENT_EXPECT_CERTIFICATE_VERIFY = 5
      CLIENT_EXPECT_FINISHED = 6
      CLIENT_POST_HANDSHAKE = 7

      SERVER_EXPECT_CLIENT_HELLO = 8
      SERVER_EXPECT_FINISHED = 9
      SERVER_POST_HANDSHAKE = 10
    end

    # Load a PEM-encoded private key
    def self.load_pem_private_key(data, password = nil)
      OpenSSL::PKey.read(data, password)
    end

    # Load a chain of PEM-encoded X509 certificates
    def self.load_pem_x509_certificates(data)
      boundary = "-----END CERTIFICATE-----\n"
      certificates = []
      data.split(boundary).each do |chunk|
        certificates << OpenSSL::X509::Certificate.new(chunk+boundary)
      end
      return certificates
    end

    def self.load_der_x509_certificate(certificate)
      OpenSSL::X509::Certificate.new(certificate)
    end

    def self.verify_certificate(certificate:, chain: [], server_name: nil, cadata: nil, cafile: nil, capath: nil)
      now = Time.now
      raise AlertCertificateExpired, "Certificate is not valid yet" if now < certificate.not_before
      raise AlertCertificateExpired, "Certificate is no longer valid" if now > certificate.not_after

      if server_name
        unless OpenSSL::SSL.verify_certificate_identity(certificate, server_name)
          raise AlertBadCertificate, "hostname '#{server_name}' doesn't match '#{certificate.subject.to_a.find { |a| a[0] == "CN" }[1]}'"
        end
      end

      store = OpenSSL::X509::Store.new
      store.add_file(Certifi.where)

      load_pem_x509_certificates(cadata).each { |cert| store.add_cert(cert) } if cadata
      store.add_file(cafile) if cafile
      store.add_path(capath) if capath

      ctx = OpenSSL::X509::StoreContext.new(store, certificate, chain.compact)
      raise AlertBadCertificate, ctx.error_string unless ctx.verify

      true
    end

    class CipherSuite
      AES_128_GCM_SHA256 = 0x1301
      AES_256_GCM_SHA384 = 0x1302
      CHACHA20_POLY1305_SHA256 = 0x1303
      EMPTY_RENEGOTIATION_INFO_SCSV = 0x00ff
    end

    class CompressionMethod
      NULL = 0
    end

    class ExtensionType
      SERVER_NAME = 0
      STATUS_REQUEST = 5
      SUPPORTED_GROUPS = 10
      SIGNATURE_ALGORITHMS = 13
      ALPN = 16
      COMPRESS_CERTIFICATE = 27
      PRE_SHARED_KEY = 41
      EARLY_DATA = 42
      SUPPORTED_VERSIONS = 43
      COOKIE = 44
      PSK_KEY_EXCHANGE_MODES = 45
      KEY_SHARE = 51
      QUIC_TRANSPORT_PARAMETERS = 0x0039
      QUIC_TRANSPORT_PARAMETERS_DRAFT = 0xffa5
      ENCRYPTED_SERVER_NAME = 65486
    end

    class Group
      SECP256R1 = 0x0017
      SECP384R1 = 0x0018
      SECP521R1 = 0x0019
      X25519 = 0x001d
      X448 = 0x001e
      GREASE = 0xaaaa
    end

    class HandshakeType
      CLIENT_HELLO = 1
      SERVER_HELLO = 2
      NEW_SESSION_TICKET = 4
      END_OF_EARLY_DATA = 5
      ENCRYPTED_EXTENSIONS = 8
      CERTIFICATE = 11
      CERTIFICATE_REQUEST = 13
      CERTIFICATE_VERIFY = 15
      FINISHED = 20
      KEY_UPDATE = 24
      COMPRESSED_CERTIFICATE = 25
      MESSAGE_HASH = 254
    end

    class PskKeyExchangeMode
      PSK_KE = 0
      PSK_DHE_KE = 1
    end

    class SignatureAlgorithm
      ECDSA_SECP256R1_SHA256 = 0x0403
      ECDSA_SECP384R1_SHA384 = 0x0503
      ECDSA_SECP521R1_SHA512 = 0x0603
      ED25519 = 0x0807 # unsupported in current ruby?
      ED448 = 0x0808 # unsupported in current ruby?
      RSA_PKCS1_SHA256 = 0x0401
      RSA_PKCS1_SHA384 = 0x0501
      RSA_PKCS1_SHA512 = 0x0601
      RSA_PSS_PSS_SHA256 = 0x0809
      RSA_PSS_PSS_SHA384 = 0x080a
      RSA_PSS_PSS_SHA512 = 0x080b
      RSA_PSS_RSAE_SHA256 = 0x0804
      RSA_PSS_RSAE_SHA384 = 0x0805
      RSA_PSS_RSAE_SHA512 = 0x0806

      # legacy
      RSA_PKCS1_SHA1 = 0x0201 # unsupported in current ruby?
      SHA1_DSA = 0x0202 # unsupported in current ruby?
      ECDSA_SHA1 = 0x0203 # unsupported in current ruby?
    end

    def self.pull_block(buf:, capacity:)
      bytes = buf.pull_bytes(capacity)
      length = bytes.bytes_to_int
      ends = buf.tell + length
      yield length
      raise RuntimeError unless buf.tell == ends
    end

    def self.push_block(buf:, capacity:)
      start = buf.tell + capacity
      buf.seek(start)
      yield
      ends = buf.tell
      length = ends - start
      buf.seek(start - capacity)
      buf.push_bytes(length.to_bytes(capacity))
      buf.seek(ends)
    end

    def self.pull_list(buf:, capacity:, func:)
      items = []
      pull_block(buf: buf, capacity: capacity) do |length|
        ends = buf.tell + length
        while buf.tell < ends # rubocop:disable Style/WhileUntilModifier
          items.append(func.call)
        end
      end
      items
    end

    def self.push_list(buf:, capacity:, func:, values:)
      push_block(buf: buf, capacity: capacity) do
        values.each { |value| func.call(value) }
      end
    end

    # Pull an opaque value prefixed by a length
    def self.pull_opaque(buf:, capacity:)
      bytes = ""
      pull_block(buf: buf, capacity: capacity) do |length|
        bytes = buf.pull_bytes(length)
      end
      return bytes
    end

    # Push an opaque value prefix by a length.
    def self.push_opaque(buf:, capacity:, value:)
      push_block(buf: buf, capacity: capacity) do
        buf.push_bytes(value)
      end
    end

    def self.push_extension(buf:, extension_type:)
      buf.push_uint16(extension_type)
      push_block(buf: buf, capacity: 2) do
        yield if block_given?
      end
    end

    def self.pull_key_share(buf:)
      group = buf.pull_uint16
      data = pull_opaque(buf: buf, capacity: 2)
      return [group, data]
    end

    def self.push_key_share(buf:, value:)
      buf.push_uint16(value[0])
      push_opaque(buf: buf, capacity: 2, value: value[1])
    end

    def self.pull_alpn_protocol(buf:)
      return pull_opaque(buf: buf, capacity: 1)
    end

    def self.push_alpn_protocol(buf:, protocol:)
      push_opaque(buf: buf, capacity: 1, value: protocol)
    end

    def self.pull_psk_identity(buf:)
      identity = pull_opaque(buf: buf, capacity: 2)
      obfuscated_ticket_age = buf.pull_uint32
      return [identity, obfuscated_ticket_age]
    end

    def self.push_psk_identity(buf:, entry:)
      push_opaque(buf: buf, capacity: 2, value: entry[0])
      buf.push_uint32(entry[1])
    end

    def self.pull_psk_binder(buf:)
      pull_opaque(buf: buf, capacity: 1)
    end

    def self.push_psk_binder(buf:, binder:)
      push_opaque(buf: buf, capacity: 1, value: binder)
    end

    OfferedPsks = _ = Struct.new( # rubocop:disable Naming/ConstantName
      :identities,
      :binders,
    )

    ClientHello = _ = Struct.new( # rubocop:disable Naming/ConstantName
      :random,
      :legacy_session_id,
      :cipher_suites,
      :legacy_compression_methods,
      :alpn_protocols,
      :early_data,
      :key_share,
      :pre_shared_key,
      :psk_key_exchange_modes,
      :server_name,
      :signature_algorithms,
      :supported_groups,
      :supported_versions,
      :other_extensions,
    )

    def self.pull_client_hello(buf)
      raise RuntimeError unless buf.pull_uint8 == HandshakeType::CLIENT_HELLO

      hello = ClientHello.new
      pull_block(buf: buf, capacity: 3) do # rubocop:disable Metrics/BlockLength
        raise RuntimeError unless buf.pull_uint16 == TLS_VERSION_1_2

        hello.random = buf.pull_bytes(32)
        hello.legacy_session_id = pull_opaque(buf: buf, capacity: 1)
        hello.cipher_suites = pull_list(buf: buf, capacity: 2, func: buf.method(:pull_uint16))
        hello.legacy_compression_methods = pull_list(buf: buf, capacity: 1, func: buf.method(:pull_uint8))
        hello.early_data = false
        hello.other_extensions = []

        after_psk = false
        pull_extension = lambda do
          raise RuntimeError if after_psk

          extension_type = buf.pull_uint16
          extension_length = buf.pull_uint16
          case extension_type
          when ExtensionType::KEY_SHARE
            hello.key_share = pull_list(buf: buf, capacity: 2, func: -> { pull_key_share(buf: buf) })
          when ExtensionType::SUPPORTED_VERSIONS
            hello.supported_versions = pull_list(buf: buf, capacity: 1, func: buf.method(:pull_uint16))
          when ExtensionType::SIGNATURE_ALGORITHMS
            hello.signature_algorithms = pull_list(buf: buf, capacity: 2, func: buf.method(:pull_uint16))
          when ExtensionType::SUPPORTED_GROUPS
            hello.supported_groups = pull_list(buf: buf, capacity: 2, func: buf.method(:pull_uint16))
          when ExtensionType::PSK_KEY_EXCHANGE_MODES
            hello.psk_key_exchange_modes = pull_list(buf: buf, capacity: 1, func: buf.method(:pull_uint8))
          when ExtensionType::SERVER_NAME
            pull_block(buf: buf, capacity: 2) do
              raise RuntimeError unless buf.pull_uint8 == 0
              hello.server_name = pull_opaque(buf: buf, capacity: 2)
            end
          when ExtensionType::ALPN
            hello.alpn_protocols = pull_list(buf: buf, capacity: 2, func: -> { pull_alpn_protocol(buf: buf) })
          when ExtensionType::EARLY_DATA
            hello.early_data = true
          when ExtensionType::PRE_SHARED_KEY
            hello.pre_shared_key = OfferedPsks.new.tap do |op|
              op.identities = pull_list(buf: buf, capacity: 2, func: -> { pull_psk_identity(buf: buf) })
              op.binders = pull_list(buf: buf, capacity: 2, func: -> { pull_psk_binder(buf: buf) })
            end
            after_psk = true
          else
            hello.other_extensions << [extension_type, buf.pull_bytes(extension_length)]
          end
        end
        pull_list(buf: buf, capacity: 2, func: pull_extension)
      end

      return hello
    end

    def self.push_client_hello(buf:, hello:)
      buf.push_uint8(HandshakeType::CLIENT_HELLO)
      push_block(buf: buf, capacity: 3) do
        buf.push_uint16(TLS_VERSION_1_2)
        buf.push_bytes(hello.random)
        push_opaque(buf: buf, capacity: 1, value: hello.legacy_session_id)
        push_list(buf: buf, capacity: 2, func: buf.method(:push_uint16), values: hello.cipher_suites)
        push_list(buf: buf, capacity: 1, func: buf.method(:push_uint8), values: hello.legacy_compression_methods)

        # extensions
        push_block(buf: buf, capacity: 2) do
          push_extension(buf: buf, extension_type: ExtensionType::KEY_SHARE) do
            push_list(buf: buf, capacity: 2, func: ->(val) { push_key_share(buf: buf, value: val) }, values: hello.key_share)
          end

          push_extension(buf: buf, extension_type: ExtensionType::SUPPORTED_VERSIONS) do
            push_list(buf: buf, capacity: 1, func: buf.method(:push_uint16), values: hello.supported_versions)
          end

          push_extension(buf: buf, extension_type: ExtensionType::SIGNATURE_ALGORITHMS) do
            push_list(buf: buf, capacity: 2, func: buf.method(:push_uint16), values: hello.signature_algorithms)
          end

          push_extension(buf: buf, extension_type: ExtensionType::SUPPORTED_GROUPS) do
            push_list(buf: buf, capacity: 2, func: buf.method(:push_uint16), values: hello.supported_groups)
          end

          if hello.psk_key_exchange_modes
            push_extension(buf: buf, extension_type: ExtensionType::PSK_KEY_EXCHANGE_MODES) do
              push_list(buf: buf, capacity: 1, func: buf.method(:push_uint8), values: hello.psk_key_exchange_modes)
            end
          end

          if hello.server_name
            push_extension(buf: buf, extension_type: ExtensionType::SERVER_NAME) do
              push_block(buf: buf, capacity: 2) do
                buf.push_uint8(0)
                push_opaque(buf: buf, capacity: 2, value: hello.server_name)
              end
            end
          end

          if hello.alpn_protocols && hello.alpn_protocols.length > 0
            push_extension(buf: buf, extension_type: ExtensionType::ALPN) do
              push_list(buf: buf, capacity: 2, func: ->(proto) { push_alpn_protocol(buf: buf, protocol: proto) }, values: hello.alpn_protocols)
            end
          end

          hello.other_extensions.each do |extension|
            push_extension(buf: buf, extension_type: extension[0]) do
              buf.push_bytes(extension[1])
            end
          end

          if hello.early_data
            push_extension(buf: buf, extension_type: ExtensionType::EARLY_DATA) do
              # pass
            end
          end

          if hello.pre_shared_key
            push_extension(buf: buf, extension_type: ExtensionType::PRE_SHARED_KEY) do
              push_list(buf: buf, capacity: 2, func: ->(val) { push_psk_identity(buf: buf, entry: val) }, values: hello.pre_shared_key.identities)
              push_list(buf: buf, capacity: 2, func: ->(val) { push_psk_binder(buf: buf, binder: val) }, values: hello.pre_shared_key.binders)
            end
          end
        end
      end
    end

    ServerHello = _ = Struct.new( # rubocop:disable Naming/ConstantName
      :random,
      :legacy_session_id,
      :cipher_suite,
      :compression_method,
      :key_share,
      :pre_shared_key,
      :supported_version,
      :other_extensions,
    )

    def self.pull_server_hello(buf)
      raise RuntimeError unless buf.pull_uint8 == HandshakeType::SERVER_HELLO

      hello = ServerHello.new
      pull_block(buf: buf, capacity: 3) do
        raise RuntimeError unless buf.pull_uint16 == TLS_VERSION_1_2

        hello.random = buf.pull_bytes(32)
        hello.legacy_session_id = pull_opaque(buf: buf, capacity: 1)
        hello.cipher_suite = buf.pull_uint16
        hello.compression_method = buf.pull_uint8
        hello.other_extensions = []

        pull_extension = lambda do
          extension_type = buf.pull_uint16
          extension_length = buf.pull_uint16
          case extension_type
          when ExtensionType::SUPPORTED_VERSIONS
            hello.supported_version = buf.pull_uint16
          when ExtensionType::KEY_SHARE
            hello.key_share = pull_key_share(buf: buf)
          when ExtensionType::PRE_SHARED_KEY
            hello.pre_shared_key = buf.pull_uint16
          else
            hello.other_extensions << [extension_type, buf.pull_bytes(extension_length)]
          end
        end

        pull_list(buf: buf, capacity: 2, func: pull_extension)
      end

      return hello
    end

    def self.push_server_hello(buf:, hello:)
      hello.compression_method ||= CompressionMethod::NULL
      hello.other_extensions ||= []

      buf.push_uint8(HandshakeType::SERVER_HELLO)
      push_block(buf: buf, capacity: 3) do # rubocop:disable Metrics/BlockLength
        buf.push_uint16(TLS_VERSION_1_2)
        buf.push_bytes(hello.random)

        push_opaque(buf: buf, capacity: 1, value: hello.legacy_session_id)
        buf.push_uint16(hello.cipher_suite)
        buf.push_uint8(hello.compression_method)

        # extensions
        push_block(buf: buf, capacity: 2) do
          if hello.supported_version
            push_extension(buf: buf, extension_type: ExtensionType::SUPPORTED_VERSIONS) do
              buf.push_uint16(hello.supported_version)
            end
          end

          if hello.key_share
            push_extension(buf: buf, extension_type: ExtensionType::KEY_SHARE) do
              push_key_share(buf: buf, value: hello.key_share)
            end
          end

          if hello.pre_shared_key
            push_extension(buf: buf, extension_type: ExtensionType::PRE_SHARED_KEY) do
              buf.push_uint16(hello.pre_shared_key)
            end
          end

          hello.other_extensions.each do |extension|
            push_extension(buf: buf, extension_type: extension[0]) do
              buf.push_bytes(extension[1])
            end
          end
        end
      end
    end

    NewSessionTicket = _ = Struct.new( # rubocop:disable Naming/ConstantName
      :ticket_lifetime,
      :ticket_age_add,
      :ticket_nonce,
      :ticket,
      :max_early_data_size,
      :other_extensions,
    )

    def self.pull_new_session_ticket(buf)
      new_session_ticket = NewSessionTicket.new
      new_session_ticket.other_extensions = []

      raise RuntimeError unless buf.pull_uint8 == HandshakeType::NEW_SESSION_TICKET

      pull_block(buf: buf, capacity: 3) do
        new_session_ticket.ticket_lifetime = buf.pull_uint32
        new_session_ticket.ticket_age_add = buf.pull_uint32
        new_session_ticket.ticket_nonce = pull_opaque(buf: buf, capacity: 1)
        new_session_ticket.ticket = pull_opaque(buf: buf, capacity: 2)

        pull_extension = lambda do
          extension_type = buf.pull_uint16
          extension_length = buf.pull_uint16
          if extension_type == ExtensionType::EARLY_DATA
            new_session_ticket.max_early_data_size = buf.pull_uint32
          else
            new_session_ticket.other_extensions << [extension_type, buf.pull_bytes(extension_length)]
          end
        end

        pull_list(buf: buf, capacity: 2, func: pull_extension)
      end

      return new_session_ticket
    end

    def self.push_new_session_ticket(buf:, new_session_ticket:)
      buf.push_uint8(HandshakeType::NEW_SESSION_TICKET)
      push_block(buf: buf, capacity: 3) do
        buf.push_uint32(new_session_ticket.ticket_lifetime)
        buf.push_uint32(new_session_ticket.ticket_age_add)
        push_opaque(buf: buf, capacity: 1, value: new_session_ticket.ticket_nonce)
        push_opaque(buf: buf, capacity: 2, value: new_session_ticket.ticket)

        push_block(buf: buf, capacity: 2) do
          if new_session_ticket.max_early_data_size
            push_extension(buf: buf, extension_type: ExtensionType::EARLY_DATA) do
              buf.push_uint32(new_session_ticket.max_early_data_size)
            end
          end

          new_session_ticket.other_extensions.each do |extension|
            push_extension(buf: buf, extension_type: extension[0]) do
              buf.push_bytes(extension[1])
            end
          end
        end
      end
    end

    EncryptedExtensions = _ = Struct.new( # rubocop:disable Naming/ConstantName
      :alpn_protocol,
      :early_data,
      :other_extensions,
    )

    def self.pull_encrypted_extensions(buf)
      extensions = EncryptedExtensions.new
      extensions.other_extensions = []

      raise RuntimeError unless buf.pull_uint8 == HandshakeType::ENCRYPTED_EXTENSIONS

      pull_block(buf: buf, capacity: 3) do
        pull_extensions = lambda do
          extension_type = buf.pull_uint16
          extension_length = buf.pull_uint16

          case extension_type
          when ExtensionType::ALPN
            extensions.alpn_protocol = pull_list(buf: buf, capacity: 2, func: -> { pull_alpn_protocol(buf: buf) })[0]
          when ExtensionType::EARLY_DATA
            extensions.early_data = true
          else
            extensions.other_extensions << [extension_type, buf.pull_bytes(extension_length)]
          end
        end

        pull_list(buf: buf, capacity: 2, func: pull_extensions)
      end
      return extensions
    end

    def self.push_encrypted_extensions(buf:, extensions:)
      buf.push_uint8(HandshakeType::ENCRYPTED_EXTENSIONS)
      push_block(buf: buf, capacity: 3) do
        push_block(buf: buf, capacity: 2) do
          if extensions.alpn_protocol
            push_extension(buf: buf, extension_type: ExtensionType::ALPN) do
              push_list(buf: buf, capacity: 2, func: ->(val) { push_alpn_protocol(buf: buf, protocol: val) }, values: [extensions.alpn_protocol])
            end
          end

          if extensions.early_data
            push_extension(buf: buf, extension_type: ExtensionType::EARLY_DATA) do
              # pass
            end
          end

          extensions.other_extensions.each do |extension|
            push_extension(buf: buf, extension_type: extension[0]) do
              buf.push_bytes(extension[1])
            end
          end
        end
      end
    end

    Certificate = _ = Struct.new( # rubocop:disable Naming/ConstantName
      :request_context,
      :certificates,
    )

    def self.pull_certificate(buf)
      certificate = Certificate.new

      raise RuntimeError unless buf.pull_uint8 == HandshakeType::CERTIFICATE

      pull_block(buf: buf, capacity: 3) do
        certificate.request_context = pull_opaque(buf: buf, capacity: 1)

        pull_certificate_entry = lambda do
          data = pull_opaque(buf: buf, capacity: 3)
          extensions = pull_opaque(buf: buf, capacity: 2)
          return [data, extensions]
        end

        certificate.certificates = pull_list(buf: buf, capacity: 3, func: pull_certificate_entry)
      end

      return certificate
    end

    def self.push_certificate(buf:, certificate:)
      buf.push_uint8(HandshakeType::CERTIFICATE)
      push_block(buf: buf, capacity: 3) do
        push_opaque(buf: buf, capacity: 1, value: certificate.request_context)

        push_certificate_entry = lambda do |entry|
          push_opaque(buf: buf, capacity: 3,  value: entry[0])
          push_opaque(buf: buf, capacity: 2,  value: entry[1])
        end
        push_list(buf: buf, capacity: 3, func: push_certificate_entry, values: certificate.certificates)
      end
    end

    CertificateVerify = _ = Struct.new( # rubocop:disable Naming/ConstantName
      :algorithm,
      :signature,
    )

    def self.pull_certificate_verify(buf)
      raise RuntimeError unless buf.pull_uint8 == HandshakeType::CERTIFICATE_VERIFY

      certificate_verify = CertificateVerify.new
      pull_block(buf: buf, capacity: 3) do
        certificate_verify.algorithm = buf.pull_uint16
        certificate_verify.signature = pull_opaque(buf: buf, capacity: 2)
      end

      return certificate_verify
    end

    def self.push_certificate_verify(buf:, verify:)
      buf.push_uint8(HandshakeType::CERTIFICATE_VERIFY)
      push_block(buf: buf, capacity: 3) do
        buf.push_uint16(verify.algorithm)
        push_opaque(buf: buf, capacity: 2, value: verify.signature)
      end
    end

    Finished = _ = Struct.new( # rubocop:disable Naming/ConstantName
      :verify_data,
    )

    def self.pull_finished(buf)
      raise RuntimeError unless buf.pull_uint8 == HandshakeType::FINISHED

      return Finished.new.tap do |f|
        f.verify_data = pull_opaque(buf: buf, capacity: 3)
      end
    end

    def self.push_finished(buf:, finished:)
      buf.push_uint8(HandshakeType::FINISHED)
      push_opaque(buf: buf, capacity: 3, value: finished.verify_data)
    end

    class KeySchedule
      attr_reader :cipher_suite
      attr_accessor :generation
      attr_reader :hash

      def initialize(cipher_suite)
        @algorithm = TLS.cipher_suite_hash(cipher_suite)
        @cipher_suite = cipher_suite
        @generation = 0
        @hash = @algorithm.new
        @hash_empty_value = @hash.dup.digest("")
        @secret = "\x00" * @hash.digest_length
      end

      def certificate_verify_data(context_string)
        fin = @hash.dup.digest
        ("\x20" * 64) + context_string + "\x00" + fin
      end

      def finished_verify_data(secret)
        hmac_key = TTTLS13::KeySchedule.hkdf_expand_label(secret, "finished", "", @hash.digest_length, @hash.name)
        OpenSSL::HMAC.digest(@hash.name, hmac_key, @hash.dup.digest)
      end

      def derive_secret(label)
        TTTLS13::KeySchedule.hkdf_expand_label(@secret, label, @hash.dup.digest, @hash.digest_length, @hash.name)
      end

      def extract(key_material = nil)
        key_material = "\x00" * @hash.digest_length unless key_material

        if @generation > 0
          @secret = TTTLS13::KeySchedule.hkdf_expand_label(@secret, "derived", @hash_empty_value, @hash.digest_length, @hash.name)
        end
        @generation += 1
        @secret = OpenSSL::HMAC.digest(@hash.name, @secret, key_material)
      end

      def update_hash(data)
        @hash.update(data)
      end
    end

    class KeyScheduleProxy
      def initialize(cipher_suites)
        @schedules = cipher_suites.inject({}) do |hash, cipher_suite|
          hash[cipher_suite] = KeySchedule.new(cipher_suite)
          hash
        end
      end

      def extract(key_material = nil)
        @schedules.each_value { |schedule| schedule.extract(key_material) }
      end

      def select(cipher_suite)
        @schedules[cipher_suite]
      end

      def update_hash(data)
        @schedules.each_value { |schedule| schedule.update_hash(data) }
      end
    end

    CIPHER_SUITES = {
      CipherSuite::AES_128_GCM_SHA256 => OpenSSL::Digest::SHA256,
      CipherSuite::AES_256_GCM_SHA384 => OpenSSL::Digest::SHA384,
      CipherSuite::CHACHA20_POLY1305_SHA256 => OpenSSL::Digest::SHA256,
    }.freeze

    SIGNATURE_ALGORITHMS = {
      SignatureAlgorithm::ECDSA_SECP256R1_SHA256 => [nil, OpenSSL::Digest::SHA256],
      SignatureAlgorithm::ECDSA_SECP384R1_SHA384 => [nil, OpenSSL::Digest::SHA384],
      SignatureAlgorithm::ECDSA_SECP521R1_SHA512 => [nil, OpenSSL::Digest::SHA512],
      # SignatureAlgorithm::RSA_PKCS1_SHA1 => [nil, OpenSSL::Digest::SHA1], # TODO: unsupported?
      SignatureAlgorithm::RSA_PKCS1_SHA256 => [:pss, OpenSSL::Digest::SHA256],
      SignatureAlgorithm::RSA_PKCS1_SHA384 => [:pss, OpenSSL::Digest::SHA384],
      SignatureAlgorithm::RSA_PKCS1_SHA512 => [:pss, OpenSSL::Digest::SHA512],
      SignatureAlgorithm::RSA_PSS_RSAE_SHA256 => [:pss, OpenSSL::Digest::SHA256],
      SignatureAlgorithm::RSA_PSS_RSAE_SHA384 => [:pss, OpenSSL::Digest::SHA384],
      SignatureAlgorithm::RSA_PSS_RSAE_SHA512 => [:pss, OpenSSL::Digest::SHA512],
    }.freeze

    GROUP_TO_CURVE = {
      Group::SECP256R1 => "prime256v1",
      Group::SECP384R1 => "secp384r1",
      Group::SECP521R1 => "secp521r1",
    }.freeze

    CURVE_TO_GROUP = GROUP_TO_CURVE.invert.freeze

    def self.cipher_suite_hash(cipher_suite)
      CIPHER_SUITES[cipher_suite]
    end

    def self.decode_public_key(key_share)
      case key_share[0]
      when Group::X25519
        OpenSSL::PKey.read(key_share[1])
      when Group::X448
        raise "X448 did not support yet."
      else
        if GROUP_TO_CURVE.has_key?(key_share[0])
          group = OpenSSL::PKey::EC::Group.new(GROUP_TO_CURVE[key_share[0]])
          OpenSSL::PKey::EC::Point.new(group, key_share[1])
        end
      end
    end

    # NOTE: X25519, X448 are not supported
    def self.encode_public_key(public_key)
      if public_key.respond_to?(:oid) && public_key.oid == "X25519"
        [Group::X25519, public_key.public_to_der]
      else
        [CURVE_TO_GROUP[public_key.group.curve_name], public_key.to_octet_string(:uncompressed)]
      end
    end

    def self.negotiate(supported: , offered: nil, exc: nil)
      if offered
        supported.each do |c|
          return c if offered.include?(c)
        end
      end

      raise exc if exc

      return nil
    end

    def self.signature_algorithm_params(signature_algorithm)
      raise NotImplementedError
    end

    def self.push_message(key_schedule:, buf:)
      hash_start = buf.tell
      yield
      key_schedule.update_hash(buf.data_slice(start: hash_start, ends: buf.tell))
    end

    SessionTicket = _ = Struct.new( # rubocop:disable Naming/ConstantName
      :age_add,
      :cipher_suite,
      :not_valid_after,
      :not_valid_before,
      :resumption_secret,
      :server_name,
      :ticket,
      :max_early_data_size,
      :other_extensions,
    ) do
      def is_valid
        now = Time.now
        now >= not_valid_before && now <= not_valid_after
      end

      def obfuscated_age
        age = (Time.now - not_valid_before) * 1000
        return (age + age_add) % (1 << 32)
      end
    end

    class Context
      attr_reader :session_resumed
      attr_reader :enc_key
      attr_reader :dec_key
      attr_reader :key_schedule
      attr_reader :alpn_negotiated
      attr_accessor :state
      attr_accessor :handshake_extensions
      attr_accessor :certificate
      attr_accessor :certificate_private_key
      attr_accessor :supported_groups
      attr_accessor :supported_versions
      attr_accessor :signature_algorithms
      attr_accessor :new_session_ticket_cb
      attr_accessor :get_session_ticket_cb
      attr_accessor :session_ticket

      def initialize(is_client:, alpn_protocols: [], cadata: nil, cafile: nil, capath: nil, cipher_suites: nil, logger: nil, max_early_data: nil, server_name: nil, verify_mode: nil) # rubocop:disable Layout/LineLength, Metrics/MethodLength
        @alpn_protocols = alpn_protocols
        @cadata = cadata
        @cafile = cafile
        @capath = capath
        @certificate = nil
        @certificate_chain = []
        @certificate_private_key = nil
        @handshake_extensions = []
        @max_early_data = max_early_data
        @session_ticket = nil
        @server_name = server_name
        @verify_mode = if verify_mode
                         verify_mode
                       else
                         is_client ? OpenSSL::SSL::VERIFY_PEER : OpenSSL::SSL::VERIFY_NONE
                       end
        @alpn_cb = nil
        @get_session_ticket_cb = nil
        @new_session_ticket_cb = nil
        @update_traffic_key_cb = lambda { |direction, epoch, cipher_suite, secret| nil }
        @cipher_suites =
          cipher_suites || [
            CipherSuite::AES_256_GCM_SHA384,
            CipherSuite::AES_128_GCM_SHA256,
            CipherSuite::CHACHA20_POLY1305_SHA256,
          ]
        @legacy_compression_methods = [CompressionMethod::NULL]
        @psk_key_exchange_modes = [PskKeyExchangeMode::PSK_DHE_KE]
        @signature_algorithms = [
          SignatureAlgorithm::RSA_PSS_RSAE_SHA256,
          SignatureAlgorithm::ECDSA_SECP256R1_SHA256,
          SignatureAlgorithm::RSA_PKCS1_SHA256,
          SignatureAlgorithm::RSA_PKCS1_SHA1,
        ]
        @supported_groups = [Group::SECP256R1]
        @supported_versions = [TLS_VERSION_1_3]

        # state
        @alpn_negotiated = nil
        @early_data_accepted = false
        @key_schedule = nil
        @key_schedule_psk = nil
        @received_extensions = nil
        @key_schedule_proxy = nil
        @new_session_ticket = nil
        @peer_certificate = nil
        @peer_certificate_chain = []
        @receive_buffer = ""
        @session_resumed = false
        @enc_key = nil
        @dec_key = nil
        @logger = logger
        @ec_key = nil
        @ec_private_key = nil
        @x25519_private_key = nil
        @x448_private_key = nil

        if is_client
          @client_random = Random.urandom(32)
          @legacy_session_id = ""
          @state = State::CLIENT_HANDSHAKE_START
        else
          @client_random = nil
          @legacy_session_id = nil
          @state = State::SERVER_EXPECT_CLIENT_HELLO
        end
        self
      end

      def handle_message(input_data:, output_buf:)
        if @state == State::CLIENT_HANDSHAKE_START
          client_send_hello(output_buf[Epoch::INITIAL])
          return
        end

        @receive_buffer += input_data
        while @receive_buffer.bytesize >= 4
          # determine message length
          message_type = @receive_buffer[0].bytes_to_int
          message_length = 4 + @receive_buffer[1...4].bytes_to_int

          # check message is complete
          break if @receive_buffer.bytesize < message_length

          message = @receive_buffer[0...message_length]
          @receive_buffer = @receive_buffer[message_length..-1]

          input_buf = Buffer.new(data: message)

          # client status
          case @state
          when State::CLIENT_EXPECT_SERVER_HELLO
            if message_type == HandshakeType::SERVER_HELLO
              client_handle_hello(input_buf: input_buf, output_buf: output_buf[Epoch::INITIAL])
            else
              raise AlertUnexpectedMessage
            end
          when State::CLIENT_EXPECT_ENCRYPTED_EXTENSIONS
            if message_type == HandshakeType::ENCRYPTED_EXTENSIONS
              client_handle_encrypted_extensions(input_buf)
            else
              raise AlertUnexpectedMessage
            end
          when State::CLIENT_EXPECT_CERTIFICATE_REQUEST_OR_CERTIFICATE
            if message_type == HandshakeType::CERTIFICATE
              client_handle_certificate(input_buf)
            else
              # FIXME: handle certificate request
              raise AlertUnexpectedMessage
            end
          when State::CLIENT_EXPECT_CERTIFICATE_VERIFY
            if message_type == HandshakeType::CERTIFICATE_VERIFY
              client_handle_certificate_verify(input_buf)
            else
              raise AlertUnexpectedMessage
            end
          when State::CLIENT_EXPECT_FINISHED
            if message_type == HandshakeType::FINISHED
              client_handle_finished(input_buf: input_buf, output_buf: output_buf[Epoch::HANDSHAKE])
            else
              raise AlertUnexpectedMessage
            end
          when State::CLIENT_POST_HANDSHAKE
            if message_type == HandshakeType::NEW_SESSION_TICKET
              client_handle_new_session_ticket(input_buf)
            else
              raise AlertUnexpectedMessage
            end

          # server state
          when State::SERVER_EXPECT_CLIENT_HELLO
            if message_type == HandshakeType::CLIENT_HELLO
              server_handle_hello(
                input_buf: input_buf,
                initial_buf: output_buf[Epoch::INITIAL],
                handshake_buf: output_buf[Epoch::HANDSHAKE],
                onertt_buf: output_buf[Epoch::ONE_RTT],
              )
            else
              raise AlertUnexpectedMessage
            end
          when State::SERVER_EXPECT_FINISHED
            if message_type == HandshakeType::FINISHED
              server_handle_finished(input_buf: input_buf, output_buf: output_buf[Epoch::ONE_RTT])
            else
              raise AlertUnexpectedMessage
            end
          when State::SERVER_POST_HANDSHAKE
            raise AlertUnexpectedMessage
          end
        end
      end

      def build_session_ticket(new_session_ticket:, other_extensions:)
        resumption_master_secret = @key_schedule&.derive_secret("res master")
        resumption_secret = TTTLS13::KeySchedule.hkdf_expand_label(
          resumption_master_secret, "resumption", new_session_ticket.ticket_nonce, @key_schedule.hash.digest_length, @key_schedule.hash.name
        )

        timestamp = Time.now
        return SessionTicket.new.tap do |ticket|
          ticket.age_add = new_session_ticket.ticket_age_add
          ticket.cipher_suite = @key_schedule.cipher_suite
          ticket.max_early_data_size = new_session_ticket.max_early_data_size
          ticket.not_valid_after = timestamp + new_session_ticket.ticket_lifetime
          ticket.not_valid_before = timestamp
          ticket.other_extensions = other_extensions
          ticket.resumption_secret = resumption_secret
          ticket.server_name = @server_name
          ticket.ticket = new_session_ticket.ticket
        end
      end

      def client_send_hello(output_buf)
        key_share = []
        supported_groups = []

        @supported_groups.each do |group|
          case group
          when Group::SECP256R1
            ec = OpenSSL::PKey::EC.generate(GROUP_TO_CURVE[Group::SECP256R1])
            @ec_key = ec
            @ec_private_key = ec.private_key
            key_share << TLS.encode_public_key(ec.public_key)
            supported_groups << Group::SECP256R1
          when Group::X25519
            raise "unsupported"
          when Group::X448
            raise "unsupported"
          when Group::GREASE
            key_share << [Group::GREASE, '\x00']
            supported_groups << Group::GREASE
          end
        end
        raise RuntimeError if key_share.size == 0

        hello = ClientHello.new.tap do |h|
          h.random = @client_random
          h.legacy_session_id = @legacy_session_id
          h.cipher_suites = @cipher_suites
          h.legacy_compression_methods = @legacy_compression_methods
          h.alpn_protocols = @alpn_protocols
          h.early_data = false
          h.key_share = key_share
          h.psk_key_exchange_modes = (@session_ticket || !!@new_session_ticket_cb) ? @psk_key_exchange_modes : nil
          h.server_name = @server_name
          h.signature_algorithms = @signature_algorithms
          h.supported_groups = supported_groups
          h.supported_versions = @supported_versions
          h.other_extensions = @handshake_extensions
        end

        # PSK
        if @session_ticket && @session_ticket.is_valid
          @key_schedule_psk = KeySchedule.new(@session_ticket.cipher_suite)
          @key_schedule_psk.extract(@session_ticket.resumption_secret)
          binder_key = @key_schedule_psk.derive_secret("res binder")
          binder_length = @key_schedule_psk.hash.digest_length

          # update hello
          hello.early_data = true if @session_ticket.max_early_data_size
          hello.pre_shared_key = OfferedPsks.new.tap { |psks|
            psks.identities = [[@session_ticket.ticket, @session_ticket.obfuscated_age]]
            psks.binders = ["\x00" * binder_length]
          }

          # serialize hello withouit binder
          tmp_buf = Buffer.new(capacity: 1024)
          TLS.push_client_hello(buf: tmp_buf, hello: hello)

          # calculate binder
          hash_offset = tmp_buf.tell - binder_length - 3
          @key_schedule_psk.update_hash(tmp_buf.data_slice(start: 0, ends: hash_offset))
          binder = @key_schedule_psk.finished_verify_data(binder_key)
          hello.pre_shared_key.binders[0] = binder
          @key_schedule_psk.update_hash(tmp_buf.data_slice(start: hash_offset, ends: hash_offset + 3) + binder)

          # calculate early data key
          if hello.early_data
            early_key = @key_schedule_psk.derive_secret("c e traffic")
            @update_traffic_key_cb.call(Direction::ENCRYPT, Epoch::ZERO_RTT, @key_schedule_psk.cipher_suite, early_key)
          end
        end

        @key_schedule_proxy = KeyScheduleProxy.new(@cipher_suites)
        @key_schedule_proxy.extract(nil)

        TLS.push_message(key_schedule: @key_schedule_proxy, buf: output_buf) do
          TLS.push_client_hello(buf: output_buf, hello: hello)
        end
        set_state(State::CLIENT_EXPECT_SERVER_HELLO)
      end

      def client_handle_hello(input_buf:, output_buf:)
        peer_hello = TLS.pull_server_hello(input_buf)

        cipher_suite = TLS.negotiate(supported: @cipher_suites, offered: [peer_hello.cipher_suite], exc: AlertHandshakeFailure)

        raise RuntimeError unless @legacy_compression_methods.include?(peer_hello.compression_method)
        raise RuntimeError unless @supported_versions.include?(peer_hello.supported_version)

        # select key schedule
        if peer_hello.pre_shared_key
          if @key_schedule_psk.nil? || peer_hello.pre_shared_key != 0 || cipher_suite != @key_schedule_psk.cipher_suite
            raise AlertIllegalParameter
          end

          @key_schedule = @key_schedule_psk
          @session_resumed = true
        else
          @key_schedule = @key_schedule_proxy.select(cipher_suite)
        end

        @key_schedule_psk = nil
        @key_schedule_proxy = nil

        # perform key exchange
        peer_public_key = TLS.decode_public_key(peer_hello.key_share)
        shared_key = nil

        # X25519 nad X448 is not supported yet
        if peer_public_key.is_a?(OpenSSL::PKey::EC::Point) && @ec_key && peer_public_key.group.curve_name == @ec_key.group.curve_name
          shared_key = @ec_key.dh_compute_key(peer_public_key)
        else
          raise "Did not support yet"
        end
        raise RuntimeError unless shared_key

        @key_schedule.update_hash(input_buf.data)
        @key_schedule.extract(shared_key)

        setup_traffic_protection(Direction::DECRYPT, Epoch::HANDSHAKE, "s hs traffic")

        set_state(State::CLIENT_EXPECT_ENCRYPTED_EXTENSIONS)
      end

      def client_handle_encrypted_extensions(input_buf)
        encrypted_extensions = TLS.pull_encrypted_extensions(input_buf)

        @alpn_negotiated = encrypted_extensions.alpn_protocol
        @early_data_accepted = encrypted_extensions.early_data
        @received_extensions = encrypted_extensions.other_extensions
        @alpn_cb.call(@alpn_negotiated) if @alpn_cb

        setup_traffic_protection(Direction::ENCRYPT, Epoch::HANDSHAKE, "c hs traffic")
        @key_schedule.update_hash(input_buf.data)

        # if the server accepted our PSK we are done, other we want its certificate
        if @session_resumed
          set_state(State::CLIENT_EXPECT_FINISHED)
        else
          set_state(State::CLIENT_EXPECT_CERTIFICATE_REQUEST_OR_CERTIFICATE)
        end
      end

      def client_handle_certificate(input_buf)
        certificate = TLS.pull_certificate(input_buf)

        @peer_certificate = TLS.load_der_x509_certificate(certificate.certificates[0][0])
        @peer_certificate_chain = certificate.certificates.map.with_index do |cert, i|
          next if i == 0

          TLS.load_der_x509_certificate(cert[0])
        end

        @key_schedule.update_hash(input_buf.data)
        set_state(State::CLIENT_EXPECT_CERTIFICATE_VERIFY)
      end

      def client_handle_certificate_verify(input_buf)
        verify = TLS.pull_certificate_verify(input_buf)
        raise RuntimeError unless @signature_algorithms.include?(verify.algorithm)

        # check signature
        begin
          result = verify_with_params(
            cert: @peer_certificate,
            signature_algorithm: verify.algorithm,
            signature: verify.signature,
            verify_data: @key_schedule.certificate_verify_data("TLS 1.3, server CertificateVerify"),
          )
          raise AlertDecryptError unless result
        rescue OpenSSL::PKey::PKeyError
          raise AlertDecryptError
        end

        # check certificate
        if @verify_mode != OpenSSL::SSL::VERIFY_NONE
          TLS.verify_certificate(
            cadata: @cadata,
            cafile: @cafile,
            capath: @capath,
            certificate: @peer_certificate,
            chain: @peer_certificate_chain,
            server_name: @server_name,
          )
        end

        @key_schedule.update_hash(input_buf.data)
        set_state(State::CLIENT_EXPECT_FINISHED)
      end

      def client_handle_finished(input_buf:, output_buf:)
        finished = TLS.pull_finished(input_buf)

        # check verify data
        expected_verify_data = @key_schedule.finished_verify_data(@dec_key)
        raise AlertDecryptError if finished.verify_data != expected_verify_data

        @key_schedule.update_hash(input_buf.data)

        # prepare traffic keys
        raise RuntimeError unless @key_schedule.generation == 2

        @key_schedule.extract(nil)
        setup_traffic_protection(Direction::DECRYPT, Epoch::ONE_RTT, "s ap traffic")
        next_enc_key = @key_schedule.derive_secret("c ap traffic")

        # send finished
        TLS.push_message(key_schedule: @key_schedule, buf: output_buf) do
          TLS.push_finished(buf: output_buf, finished: Finished.new.tap { |f| f.verify_data = @key_schedule.finished_verify_data(@enc_key) })
        end

        # commit traffic key
        @enc_key = next_enc_key
        @update_traffic_key_cb.call(Direction::ENCRYPT, Epoch::ONE_RTT, @key_schedule.cipher_suite, @enc_key)
        set_state(State::CLIENT_POST_HANDSHAKE)
      end

      def client_handle_new_session_ticket(input_buf)
        new_session_ticket = TLS.pull_new_session_ticket(input_buf)

        # notify application
        if @new_session_ticket_cb
          ticket = build_session_ticket(new_session_ticket: new_session_ticket, other_extensions: @received_extensions)
          @new_session_ticket_cb.call(ticket)
        end
      end

      def server_handle_hello(input_buf:, initial_buf:, handshake_buf:, onertt_buf:)
        peer_hello = TLS.pull_client_hello(input_buf)

        # determine applicable signature algorithms
        signature_algorithms = if @certificate_private_key.is_a?(OpenSSL::PKey::RSA)
                                 [
                                   SignatureAlgorithm::RSA_PSS_RSAE_SHA256,
                                   SignatureAlgorithm::RSA_PKCS1_SHA256,
                                   SignatureAlgorithm::RSA_PKCS1_SHA1,
                                 ]
                               elsif @certificate_private_key.is_a?(OpenSSL::PKey::EC) && @certificate_private_key.group.curve_name == "prime256v1"
                                 [SignatureAlgorithm::ECDSA_SECP256R1_SHA256]
                               #  elsif @certificate_private_key.is_a?(:ed25519) # TODO: https://github.com/ruby/openssl/pull/329
                               #    [SignatureAlgorithm::ED25519]
                               #  elsif @certificate_private_key.is_a?(:ed448)
                               #    [SignatureAlgorithm::ED448]
                               else
                                 []
                               end
        # negotiate parameters
        cipher_suite = TLS.negotiate(supported: @cipher_suites, offered: peer_hello.cipher_suites, exc: AlertHandshakeFailure)
        compression_method = TLS.negotiate(supported: @legacy_compression_methods, offered: peer_hello.legacy_compression_methods, exc: AlertHandshakeFailure)
        psk_key_exchange_mode = TLS.negotiate(supported: @psk_key_exchange_modes, offered: peer_hello.psk_key_exchange_modes)
        signature_algorithm = TLS.negotiate(supported: signature_algorithms, offered: peer_hello.signature_algorithms, exc: AlertHandshakeFailure)
        supported_version = TLS.negotiate(supported: @supported_versions, offered: peer_hello.supported_versions, exc: AlertProtocolVersion)

        # negotiate alpn
        @alpn_negotiated = TLS.negotiate(supported: @alpn_protocols, offered: peer_hello.alpn_protocols, exc: AlertHandshakeFailure) unless @alpn_protocols.empty?
        @alpn_cb.call(@alpn_negotiated) if @alpn_cb

        @client_random = peer_hello.random
        @server_random = Random.urandom(32)
        @legacy_session_id = peer_hello.legacy_session_id
        @received_extensions = peer_hello.other_extensions

        # select key schedule
        pre_shared_key = nil
        if @get_session_ticket_cb &&
           psk_key_exchange_mode &&
           peer_hello.pre_shared_key &&
           peer_hello.pre_shared_key.identities.size == 1 &&
           peer_hello.pre_shared_key.binders.size == 1
          # ask application to find session ticket
          identity = peer_hello.pre_shared_key.identities[0]
          session_ticket = @get_session_ticket_cb.call(identity[0])

          # validate session ticket
          if session_ticket && session_ticket.is_valid && session_ticket.cipher_suite == cipher_suite
            @key_schedule = KeySchedule.new(cipher_suite)
            @key_schedule.extract(session_ticket.resumption_secret)

            binder_key = @key_schedule.derive_secret("res binder")
            binder_length = @key_schedule.hash.digest_length

            hash_offset = input_buf.tell - binder_length - 3
            binder = input_buf.data_slice(start: hash_offset + 3, ends: hash_offset + 3 + binder_length)

            @key_schedule.update_hash(input_buf.data_slice(start: 0, ends: hash_offset))
            expected_binder = @key_schedule.finished_verify_data(binder_key)

            raise AlertHandshakeFailure if binder != expected_binder

            @key_schedule.update_hash(input_buf.data_slice(start: hash_offset, ends: hash_offset + 3 + binder_length))
            @session_resumed = true

            # calculate early data key
            if peer_hello.early_data
              early_key = @key_schedule.derive_secret("c e traffic")
              @early_data_accepted = true
              @update_traffic_key_cb.call(Direction::DECRYPT, Epoch::ZERO_RTT, @key_schedule.cipher_suite, early_key)
            end
            pre_shared_key = 0
          end
        end

        # if PSK is not used, initialize key schedule
        if pre_shared_key.nil?
          @key_schedule = KeySchedule.new(cipher_suite)
          @key_schedule.extract(nil)
          @key_schedule.update_hash(input_buf.data)
        end

        # perform key exchange
        public_key = nil
        shared_key = nil
        peer_hello.key_share.each do |key_share|
          peer_public_key = TLS.decode_public_key(key_share)
          case peer_public_key
          when OpenSSL::PKey::EC::Point
            @ec_key = OpenSSL::PKey::EC.generate(GROUP_TO_CURVE[key_share[0]])
            @ec_private_key = @ec_key.private_key
            public_key = @ec_key.public_key
            shared_key = @ec_key.dh_compute_key(peer_public_key)
          end
        end
        raise RuntimeError unless shared_key

        # send hello
        hello = ServerHello.new.tap do |h|
          h.random = @server_random
          h.legacy_session_id = @legacy_session_id
          h.cipher_suite = cipher_suite
          h.compression_method = compression_method
          h.key_share = TLS.encode_public_key(public_key)
          h.pre_shared_key = pre_shared_key
          h.supported_version = supported_version
          h.other_extensions = []
        end
        TLS.push_message(key_schedule: @key_schedule, buf: initial_buf) do
          TLS.push_server_hello(buf: initial_buf, hello: hello)
        end
        @key_schedule.extract(shared_key)

        setup_traffic_protection(Direction::ENCRYPT, Epoch::HANDSHAKE, "s hs traffic")
        setup_traffic_protection(Direction::DECRYPT, Epoch::HANDSHAKE, "c hs traffic")

        # send encrypted extensions
        TLS.push_message(key_schedule: @key_schedule, buf: handshake_buf) do
          ext = EncryptedExtensions.new.tap do |e|
            e.alpn_protocol = @alpn_negotiated
            e.early_data = @early_data_accepted
            e.other_extensions = @handshake_extensions
          end
          TLS.push_encrypted_extensions(buf: handshake_buf, extensions: ext)
        end

        unless pre_shared_key
          # send certificate
          TLS.push_message(key_schedule: @key_schedule, buf: handshake_buf) do
            cert = Certificate.new.tap do |c|
              c.request_context = ""
              c.certificates = ([@certificate]+@certificate_chain).map { |x| [x.to_der, ""] }
            end
            TLS.push_certificate(buf: handshake_buf, certificate: cert)
          end

          # send certificate verify
          signature = sign_with_params(
            priv_key: @certificate_private_key,
            signature_algorithm: signature_algorithm,
            verify_data: @key_schedule.certificate_verify_data("TLS 1.3, server CertificateVerify"),
          )

          TLS.push_message(key_schedule: @key_schedule, buf: handshake_buf) do
            verify = CertificateVerify.new.tap do |cv|
              cv.algorithm = signature_algorithm
              cv.signature = signature
            end
            TLS.push_certificate_verify(buf: handshake_buf, verify: verify)
          end
        end

        # send finished
        TLS.push_message(key_schedule: @key_schedule, buf: handshake_buf) do
          finished = Finished.new.tap do |f|
            f.verify_data = @key_schedule.finished_verify_data(@enc_key)
          end
          TLS.push_finished(buf: handshake_buf, finished: finished)
        end

        # prepare traffic keys
        raise RuntimeError unless @key_schedule.generation == 2

        @key_schedule.extract(nil)
        setup_traffic_protection(Direction::ENCRYPT, Epoch::ONE_RTT, "s ap traffic")
        @next_dec_key = @key_schedule.derive_secret("c ap traffic")

        # anticipate client's FINISHED as we don't use client auth
        @expected_verify_data = @key_schedule.finished_verify_data(@dec_key)
        buf = Buffer.new(capacity: 64)
        TLS.push_finished(buf: buf, finished: Finished.new.tap { |f| f.verify_data = @expected_verify_data })
        @key_schedule.update_hash(buf.data)

        # create a new session ticket
        if @new_session_ticket_cb && psk_key_exchange_mode
          @new_session_ticket = NewSessionTicket.new.tap do |session_ticket|
            session_ticket.ticket_lifetime = 86400
            session_ticket.ticket_age_add = Random.urandom(4).unpack1("I")
            session_ticket.ticket_nonce = ""
            session_ticket.ticket = Random.urandom(64)
            session_ticket.max_early_data_size = @max_early_data
            session_ticket.other_extensions = []
          end

          # send message
          TLS.push_new_session_ticket(buf: onertt_buf, new_session_ticket: @new_session_ticket)

          # notify application
          ticket = build_session_ticket(new_session_ticket: @new_session_ticket, other_extensions: @handshake_extensions)
          @new_session_ticket_cb.call(ticket)
        end

        set_state(State::SERVER_EXPECT_FINISHED)
      end

      def server_handle_finished(input_buf:, output_buf:)
        finished = TLS.pull_finished(input_buf)

        # ckeck verify data
        raise AlertDecryptError if finished.verify_data != @expected_verify_data

        # commit traffic key
        @dec_key = @next_dec_key
        @next_dec_key = nil
        @update_traffic_key_cb.call(Direction::DECRYPT, Epoch::ONE_RTT, @key_schedule.cipher_suite, @dec_key)
        set_state(State::SERVER_POST_HANDSHAKE)
      end

      def setup_traffic_protection(direction, epoch, label)
        key = @key_schedule.derive_secret(label)

        if direction == Direction::ENCRYPT
          @enc_key = key
        else
          @dec_key = key
        end
        @update_traffic_key_cb.call(direction, epoch, @key_schedule.cipher_suite, key)
      end

      def set_state(state)
        # TODO: logger
        @state = state
      end

      def sign_with_params(priv_key:, signature_algorithm:, verify_data:)
        case signature_algorithm
        when SignatureAlgorithm::RSA_PKCS1_SHA256,
          SignatureAlgorithm::RSA_PSS_RSAE_SHA256,
          SignatureAlgorithm::RSA_PSS_PSS_SHA256
          priv_key.sign_pss("SHA256", verify_data, salt_length: :digest, mgf1_hash: "SHA256")
        when SignatureAlgorithm::RSA_PKCS1_SHA384,
          SignatureAlgorithm::RSA_PSS_RSAE_SHA384,
          SignatureAlgorithm::RSA_PSS_PSS_SHA384
          priv_key.sign_pss("SHA384", verify_data, salt_length: :digest, mgf1_hash: "SHA384")
        when SignatureAlgorithm::RSA_PKCS1_SHA512,
          SignatureAlgorithm::RSA_PSS_RSAE_SHA512,
          SignatureAlgorithm::RSA_PSS_PSS_SHA512
          priv_key.sign_pss("SHA512", verify_data, salt_length: :digest, mgf1_hash: "SHA512")
        when SignatureAlgorithm::ECDSA_SECP256R1_SHA256
          priv_key.sign("SHA256", verify_data)
        when SignatureAlgorithm::ECDSA_SECP384R1_SHA384
          priv_key.sign("SHA384", verify_data)
        when SignatureAlgorithm::ECDSA_SECP521R1_SHA512
          priv_key.sign("SHA512", verify_data)
        else
          raise RuntimeError
        end
      end

      def verify_with_params(cert:, signature_algorithm:, signature:, verify_data:)
        case signature_algorithm
        when SignatureAlgorithm::RSA_PKCS1_SHA256,
          SignatureAlgorithm::RSA_PSS_RSAE_SHA256,
          SignatureAlgorithm::RSA_PSS_PSS_SHA256
          cert.public_key.verify_pss("SHA256", signature, verify_data, salt_length: :auto, mgf1_hash: "SHA256")
        when SignatureAlgorithm::RSA_PKCS1_SHA384,
          SignatureAlgorithm::RSA_PSS_RSAE_SHA384,
          SignatureAlgorithm::RSA_PSS_PSS_SHA384
          cert.public_key.verify_pss("SHA384", signature, verify_data, salt_length: :auto, mgf1_hash: "SHA384")
        when SignatureAlgorithm::RSA_PKCS1_SHA512,
          SignatureAlgorithm::RSA_PSS_RSAE_SHA512,
          SignatureAlgorithm::RSA_PSS_PSS_SHA512
          cert.public_key.verify_pss("SHA512", signature, verify_data, salt_length: :auto, mgf1_hash: "SHA512")
        when SignatureAlgorithm::ECDSA_SECP256R1_SHA256
          cert.public_key.verify("SHA256", signature, verify_data)
        when SignatureAlgorithm::ECDSA_SECP384R1_SHA384
          cert.public_key.verify("SHA384", signature, verify_data)
        when SignatureAlgorithm::ECDSA_SECP521R1_SHA512
          cert.public_key.verify("SHA512", signature, verify_data)
        else
          raise RuntimeError
        end
      end
    end
  end
end
