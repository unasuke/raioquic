# frozen_string_literal: true

require "openssl"

module Raioquic
  module Quic
    # Raioquic::Quic::Configuration
    # Migrated from aioquic/src/aioquic/quic/configuration.py
    # A QUIC configration
    class QuicConfiguration
      attr_accessor :alpn_protocols
      attr_accessor :connection_id_length
      attr_accessor :idle_timeout
      attr_accessor :is_client
      attr_accessor :max_data
      attr_accessor :max_stream_data
      attr_accessor :quic_logger
      attr_accessor :secrets_log_file
      attr_accessor :server_name
      attr_accessor :session_ticket
      attr_accessor :cadata
      attr_accessor :cafile
      attr_accessor :capath
      attr_accessor :certificate
      attr_accessor :certificate_chain
      attr_accessor :cipher_suites
      attr_accessor :initial_rtt
      attr_accessor :max_datagram_frame_size
      attr_accessor :private_key
      attr_accessor :quantam_readiness_test
      attr_accessor :supported_versions
      attr_accessor :verify_mode

      def initialize(**kwargs)
        @alpn_protocols = kwargs[:alpn_protocols]
        @connection_id_length = kwargs[:connection_id_length] || 8
        @idle_timeout = kwargs[:idle_timeout] || 60.0
        @is_client = kwargs[:is_client] || true
        @max_data = kwargs[:max_data] || 1048576
        @max_stream_data = kwargs[:max_stream_data] || 1048576
        @quic_logger = kwargs[:quic_logger]
        @secrets_log_file = kwargs[:secrets_log_file]
        @server_name = kwargs[:server_name]
        @session_ticket = kwargs[:session_ticket]
        @cadata = kwargs[:cadata]
        @cafile = kwargs[:cafile]
        @capath = kwargs[:capath]
        @certificate = kwargs[:certificate]
        @certificate_chain = kwargs[:certificate_chain]
        @cipher_suites = kwargs[:cipher_suites]
        @initial_rtt = kwargs[:initial_rtt] || 0.1
        @max_datagram_frame_size = kwargs[:max_datagram_frame_size]
        @private_key = kwargs[:private_key]
        @quantam_readiness_test = kwargs[:quantam_readiness_test] || false
        @supported_versions = kwargs[:supported_versions] || [Packet::QuicProtocolVersion::VERSION_1]
        @verify_mode = kwargs[:verify_mode]
      end

      # Load a private key and the corresponding certificate.
      def load_cert_chain(certfile, keyfile = nil, password = nil)
        boundary = "-----BEGIN PRIVATE KEY-----\n"
        cert_body = File.read(certfile)
        certs = OpenSSL::X509::Certificate.load(cert_body)

        if certs.length > 1
          @certificate = certs[0]
          @certificate_chain = certs[1..]
        else
          @certificate = certs[0]
        end
        @private_key = OpenSSL::PKey.read(cert_body) if cert_body.include?(boundary)

        if keyfile
          @private_key = OpenSSL::PKey.read(File.read(keyfile), password)
        end
      end

      def load_verify_locations
        raise NotImplementedError
      end
    end
  end
end
