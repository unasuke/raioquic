# frozen_string_literal: true

require "openssl"

module Raioquic
  # Raioquic::TLS
  # Migrated from auiquic/src/aioquic/tls.py
  module TLS
    TLS_VERSION_2_2 = 0x0303
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

    def pull_block(buf:, capacity:)
      raise NotImplementedError
    end
    module_function :pull_block

    def push_block(buf:, capacity:)
      raise NotImplementedError
    end
    module_function :push_block

    class CipherSuite
      AES_128_GCM_SHA256 = 0x1301
      AES_256_GCM_SHA384 = 0x1302
      CHACHA20_POLY1305_SHA256 = 0x1303
      EMPTY_RENEGOTIATION_INFO_SCSV = 0x00ff
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
      ED25519 = 0x0807
      ED448 = 0x0808
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
      RSA_PKCS1_SHA1 = 0x0201
      SHA1_DSA = 0x0202
      ECDSA_SHA1 = 0x0203
    end

    # CIPHER_SUITES = {
    #   AES_128_GCM_SHA256 => 'SHA256',
    #   AES_256_GCM_SHA384 => 'SHA384',
    #   CHACHA20_POLY1305_SHA256 => 'SHA256',
    # }.freeze
  end
end
