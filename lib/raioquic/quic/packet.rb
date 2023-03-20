# frozen_string_literal: true

require_relative "../buffer"
require_relative "rangeset"
require_relative "../crypto/aesgcm"
require "socket"
require "ipaddr"

module Raioquic
  module Quic
    # Raioquic::Quic::Packet
    # Migrated from aioquic/src/aioquic/quic/packet.py
    class Packet
      PACKET_LONG_HEADER = 0x80
      PACKET_FIXED_BIT = 0x40
      PACKET_SPIN_BIT = 0x20

      PACKET_TYPE_INITIAL = PACKET_LONG_HEADER | PACKET_FIXED_BIT | 0x00
      PACKET_TYPE_ZERO_RTT = PACKET_LONG_HEADER | PACKET_FIXED_BIT | 0x10
      PACKET_TYPE_HANDSHAKE = PACKET_LONG_HEADER | PACKET_FIXED_BIT | 0x20
      PACKET_TYPE_RETRY = PACKET_LONG_HEADER | PACKET_FIXED_BIT | 0x30
      PACKET_TYPE_ONE_RTT = PACKET_FIXED_BIT
      PACKET_TYPE_MASK = 0xf0

      CONNECTION_ID_MAX_SIZE = 20
      PACKET_NUMBER_MAX_SIZE = 4
      RETRY_AEAD_KEY_VERSION_1 = ["be0c690b9f66575a1d766b54e368c84e"].pack("H*") # https://www.rfc-editor.org/rfc/rfc9001.html#section-5.8
      RETRY_AEAD_NONCE_VERSION_1 = ["461599d35d632bf2239825bb"].pack("H*") # https://www.rfc-editor.org/rfc/rfc9001.html#section-5.8
      RETRY_INTEGRITY_TAG_SIZE = 16
      STATELESS_RESET_TOKEN_SIZE = 16

      class QuicErrorCode
        NO_ERROR = 0x0
        INTERNAL_ERROR = 0x1
        CONNECTION_REFUSED = 0x2
        FLOW_CONTROL_ERROR = 0x3
        STREAM_LIMIT_ERROR = 0x4
        STREAM_STATE_ERROR = 0x5
        FINAL_SIZE_ERROR = 0x6
        FRAME_ENCODING_ERROR = 0x7
        TRANSPORT_PARAMETER_ERROR = 0x8
        CONNECTION_ID_LIMIT_ERROR = 0x9
        PROTOCOL_VIOLATION = 0xa
        INVALID_TOKEN = 0xb
        APPLICATION_ERROR = 0xc
        CRYPTO_BUFFER_EXCEEDED = 0xd
        KEY_UPDATE_ERROR = 0xe
        AEAD_LIMIT_REACHED = 0xf
        CRYPTO_ERROR = 0x100
      end

      class QuicProtocolVersion
        NEGOTIATION = 0x0
        VERSION_1 = 0x00000001
      end

      class QuicHeader
        attr_accessor :is_long_header
        attr_accessor :version
        attr_accessor :packet_type
        attr_accessor :destination_cid
        attr_accessor :source_cid
        attr_accessor :token
        attr_accessor :integrity_tag
        attr_accessor :rest_length
      end

      # Recover a packet number from a truncated packet number.
      # See: Appendix A - Sample Packet Number Decoding Algorithm
      def self.decode_packet_number(truncated:, num_bits:, expected:)
        window = 1 << num_bits
        half_window = (window / 2).floor
        candidate = (expected & ~(window - 1)) | truncated

        if candidate <= expected - half_window && candidate < (1 << 62) - window
          candidate + window
        elsif candidate > expected + half_window && candidate >= window
          candidate - window
        else
          candidate
        end
      end

      # Calculate the integrity tag for a RETRY packet.
      def self.get_retry_integrity_tag(packet_without_tag:, original_destination_cid:)
        buf = Buffer.new(capacity: 1 + original_destination_cid.size + packet_without_tag.size)
        buf.push_uint8(original_destination_cid.size)
        buf.push_bytes(original_destination_cid)
        buf.push_bytes(packet_without_tag)
        aead_key = RETRY_AEAD_KEY_VERSION_1
        aead_nonce = RETRY_AEAD_NONCE_VERSION_1
        aead = ::Raioquic::Crypto::AESGCM.new(aead_key)
        integrity_tag = aead.encrypt(nonce: aead_nonce, data: "", associated_data: buf.data)
        raise RuntimeError if integrity_tag.length != RETRY_INTEGRITY_TAG_SIZE

        integrity_tag
      end

      def self.get_spin_bit(first_byte)
        (first_byte.unpack1("C") & PACKET_SPIN_BIT) != 0
      end

      def self.is_draft_version(_version)
        return false # raioquic drops draft version's implementation
      end

      def self.is_long_header(first_byte)
        (first_byte & PACKET_LONG_HEADER) != 0
      end

      def self.pull_quic_header(buf:, host_cid_length:) # rubocop:disable Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity, Metrics/MethodLength
        first_byte = buf.pull_uint8
        integrity_tag = ""
        token = ""

        if is_long_header(first_byte)
          version = buf.pull_uint32
          destination_cid_length = buf.pull_uint8
          raise ValueError, "Destination CID is too long (#{destination_cid_length} bytes)" if destination_cid_length > CONNECTION_ID_MAX_SIZE

          destination_cid = buf.pull_bytes(destination_cid_length)
          source_cid_length = buf.pull_uint8
          raise ValueError, "Souce CID is too long (#{source_cid_length} bytes)" if source_cid_length > CONNECTION_ID_MAX_SIZE

          source_cid = buf.pull_bytes(source_cid_length)

          if version == QuicProtocolVersion::NEGOTIATION
            packet_type = nil
            rest_length = buf.capacity - buf.tell
          else
            raise ValueError, "Packet fixed bit is zero" if (first_byte & PACKET_FIXED_BIT) == 0

            packet_type = first_byte & PACKET_TYPE_MASK
            # rubocop:disable Style/CaseLikeIf
            if packet_type == PACKET_TYPE_INITIAL
              token_length = buf.pull_uint_var
              token = buf.pull_bytes(token_length)
              rest_length = buf.pull_uint_var
            elsif packet_type == PACKET_TYPE_RETRY
              token_length = buf.capacity - buf.tell - RETRY_INTEGRITY_TAG_SIZE
              token = buf.pull_bytes(token_length)
              integrity_tag = buf.pull_bytes(RETRY_INTEGRITY_TAG_SIZE)
              rest_length = 0
            else
              rest_length = buf.pull_uint_var
            end

            # check remainder length
            raise ValueError, "Packet payload is truncated" if rest_length > buf.capacity - buf.tell
          end

          return QuicHeader.new.tap do |hdr|
            hdr.is_long_header = true
            hdr.version = version
            hdr.packet_type = packet_type
            hdr.destination_cid = destination_cid
            hdr.source_cid = source_cid
            hdr.token = token
            hdr.integrity_tag = integrity_tag
            hdr.rest_length = rest_length
          end
        else
          # short header packet
          raise ValueError, "Packet fixed bit is zero" if (first_byte & PACKET_FIXED_BIT) == 0

          packet_type = first_byte & PACKET_TYPE_MASK
          destination_cid = buf.pull_bytes(host_cid_length)

          return QuicHeader.new.tap do |hdr|
            hdr.is_long_header = false
            hdr.version = nil
            hdr.packet_type = packet_type
            hdr.destination_cid = destination_cid
            hdr.source_cid = ""
            hdr.token = ""
            hdr.integrity_tag = integrity_tag
            hdr.rest_length = buf.capacity - buf.tell
          end
        end
      end

      def self.encode_quic_retry(version:, source_cid:, destination_cid:, original_destination_cid:, retry_token:)
        buf = Buffer.new(capacity: 7 + destination_cid.size + source_cid.size + retry_token.size + RETRY_INTEGRITY_TAG_SIZE)
        buf.push_uint8(PACKET_TYPE_RETRY)
        buf.push_uint32(version)
        buf.push_uint8(destination_cid.length)
        buf.push_bytes(destination_cid)
        buf.push_uint8(source_cid.length)
        buf.push_bytes(source_cid)
        buf.push_bytes(retry_token)
        buf.push_bytes(get_retry_integrity_tag(packet_without_tag: buf.data, original_destination_cid: original_destination_cid))

        return buf.data
      end

      def self.encode_quic_version_negotiation(source_cid:, destination_cid:, supported_versions:)
        buf = Buffer.new(capacity: 7 + destination_cid.length + source_cid.length + (4 * supported_versions.length))
        buf.push_uint8(get_urandom_byte | PACKET_LONG_HEADER)
        buf.push_uint32(QuicProtocolVersion::NEGOTIATION)
        buf.push_uint8(destination_cid.length)
        buf.push_bytes(destination_cid)
        buf.push_uint8(source_cid.length)
        buf.push_bytes(source_cid)
        supported_versions.each do |version|
          buf.push_uint32(version)
        end
        buf.data
      end

      # private
      def self.get_urandom_byte
        Random.urandom(1)[0].unpack1("C")
      end
      private_class_method :get_urandom_byte

      QuicPreferredAddress = _ = Struct.new( # rubocop:disable Naming/ConstantName
        :ipv4_address,
        :ipv6_address,
        :connection_id,
        :stateless_reset_token,
      )

      QuicTransportParameters = _ = Struct.new( # rubocop:disable Naming/ConstantName
        :original_destination_connection_id,
        :max_idle_timeout,
        :stateless_reset_token,
        :max_udp_payload_size,
        :initial_max_data,
        :initial_max_stream_data_bidi_local,
        :initial_max_stream_data_bidi_remote,
        :initial_max_stream_data_uni,
        :initial_max_streams_bidi,
        :initial_max_streams_uni,
        :ack_delay_exponent,
        :max_ack_delay,
        :disable_active_migration,
        :preferred_address,
        :active_connection_id_limit,
        :initial_source_connection_id,
        :retry_source_connection_id,
        :max_datagram_frame_size,
        :quantum_readiness,
      )

      PARAMS = {
        0x00 => { name: :original_destination_connection_id, type: :bytes },
        0x01 => { name: :max_idle_timeout, type: :int },
        0x02 => { name: :stateless_reset_token, type: :bytes },
        0x03 => { name: :max_udp_payload_size, type: :int },
        0x04 => { name: :initial_max_data, type: :int },
        0x05 => { name: :initial_max_stream_data_bidi_local, type: :int },
        0x06 => { name: :initial_max_stream_data_bidi_remote, type: :int },
        0x07 => { name: :initial_max_stream_data_uni, type: :int },
        0x08 => { name: :initial_max_streams_bidi, type: :int },
        0x09 => { name: :initial_max_streams_uni, type: :int },
        0x0a => { name: :ack_delay_exponent, type: :int },
        0x0b => { name: :max_ack_delay, type: :int },
        0x0c => { name: :disable_active_migration, type: :bool },
        0x0d => { name: :preferred_address, type: :quicpreferredaddress },
        0x0e => { name: :active_connection_id_limit, type: :int },
        0x0f => { name: :initial_source_connection_id, type: :bytes },
        0x10 => { name: :retry_source_connection_id, type: :bytes },
        # extensions
        0x0020 => { name: :max_datagram_frame_size, type: :int },
        0x0c37 => { name: :quantum_readiness, type: :bytes },
      }.freeze

      def self.pull_quic_preferred_address(buf)
        ipv4_address = nil
        ipv4_host = buf.pull_bytes(4)
        ipv4_port = buf.pull_uint16

        # rubocop:disable Style/IfUnlessModifier
        if ipv4_host != "\x00\x00\x00\x00"
          ipv4_address = { host: IPAddr.new_ntoh(ipv4_host), port: ipv4_port }
        end

        ipv6_address = nil
        ipv6_host = buf.pull_bytes(16)
        ipv6_port = buf.pull_uint16

        if ipv6_host != "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
          ipv6_address = { host: IPAddr.new_ntoh(ipv6_host), port: ipv6_port }
        end
        # rubocop:enable Style/IfUnlessModifier

        connection_id_length = buf.pull_uint8
        connection_id = buf.pull_bytes(connection_id_length)
        stateless_reset_token = buf.pull_bytes(16)

        QuicPreferredAddress.new.tap do |addr|
          addr.ipv4_address = ipv4_address
          addr.ipv6_address = ipv6_address
          addr.connection_id = connection_id
          addr.stateless_reset_token = stateless_reset_token
        end
      end

      def self.push_quic_preferred_address(buf:, preferred_address:)
        if preferred_address[:ipv4_address]
          buf.push_bytes(preferred_address[:ipv4_address][:host].hton)
          buf.push_uint16(preferred_address[:ipv4_address][:port])
        else
          buf.push_bytes("\x00\x00\x00\x00\x00\x00")
        end

        if preferred_address[:ipv6_address]
          buf.push_bytes(preferred_address[:ipv6_address][:host].hton)
          buf.push_uint16(preferred_address[:ipv6_address][:port])
        else
          buf.push_bytes("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
        end

        buf.push_uint8(preferred_address[:connection_id].bytesize)
        buf.push_bytes(preferred_address[:connection_id])
        buf.push_bytes(preferred_address[:stateless_reset_token])
      end

      def self.pull_quic_transport_parameters(buf) # rubocop:disable Metrics/PerceivedComplexity
        params = QuicTransportParameters.new
        while !buf.eof # rubocop:disable Style/NegatedWhile
          param_id = buf.pull_uint_var
          param_len = buf.pull_uint_var
          param_start = buf.tell
          if PARAMS.key? param_id
            param = PARAMS[param_id]
            # rubocop:disable Style/ConditionalAssignment
            if    param[:type] == :int
              params[param[:name]] = buf.pull_uint_var
            elsif param[:type] == :bytes
              params[param[:name]] = buf.pull_bytes(param_len)
            elsif param[:type] == :quicpreferredaddress
              params[param[:name]] = pull_quic_preferred_address(buf)
            else
              params[param[:name]] = true
            end
            # rubocop:enable Style/ConditionalAssignment
          else
            # skip unknown parameter
            buf.pull_bytes(param_len)
          end
          raise RuntimeError if buf.tell != param_start + param_len
        end
        params
      end

      def self.push_quic_transport_parameters(buf:, params:)
        PARAMS.each do |param_id, param_obj|
          param_value = params[param_obj[:name]]
          if param_value # rubocop:disable Style/Next
            param_buf = Buffer.new(capacity: 65536)
            # aaaa
            if param_obj[:type] == :int
              param_buf.push_uint_var(param_value)
            elsif param_obj[:type] == :bytes
              param_buf.push_bytes(param_value.to_s)
            elsif param_obj[:type] == :quicpreferredaddress
              push_quic_preferred_address(buf: param_buf, preferred_address: param_value)
            end
            # rubocop:enable Style/CaseLikeIf
            buf.push_uint_var(param_id)
            buf.push_uint_var(param_buf.tell)
            buf.push_bytes(param_buf.data)
          end
        end
      end

      class QuicFrameType
        PADDING = 0x00
        PING = 0x01
        ACK = 0x02
        ACK_ECN = 0x03
        RESET_STREAM = 0x04
        STOP_SENDING = 0x05
        CRYPTO = 0x06
        NEW_TOKEN = 0x07
        STREAM_BASE = 0x08
        MAX_DATA = 0x10
        MAX_STREAM_DATA = 0x11
        MAX_STREAMS_BIDI = 0x12
        MAX_STREAMS_UNI = 0x13
        DATA_BLOCKED = 0x14
        STREAM_DATA_BLOCKED = 0x15
        STREAMS_BLOCKED_BIDI = 0x16
        STREAMS_BLOCKED_UNI = 0x17
        NEW_CONNECTION_ID = 0x18
        RETIRE_CONNECTION_ID = 0x19
        PATH_CHALLENGE = 0x1A
        PATH_RESPONSE = 0x1B
        TRANSPORT_CLOSE = 0x1C
        APPLICATION_CLOSE = 0x1D
        HANDSHAKE_DONE = 0x1E
        DATAGRAM = 0x30
        DATAGRAM_WITH_LENGTH = 0x31
      end

      NON_ACK_ELICITING_FRAME_TYPES = [
        QuicFrameType::ACK,
        QuicFrameType::ACK_ECN,
        QuicFrameType::PADDING,
        QuicFrameType::TRANSPORT_CLOSE,
        QuicFrameType::APPLICATION_CLOSE,
      ].freeze
      NON_IN_FLIGHT_FRAME_TYPES = [
        QuicFrameType::ACK,
        QuicFrameType::ACK_ECN,
        QuicFrameType::TRANSPORT_CLOSE,
        QuicFrameType::APPLICATION_CLOSE,
      ].freeze
      PROBING_FRAME_TYPES = [
        QuicFrameType::PATH_CHALLENGE,
        QuicFrameType::PATH_RESPONSE,
        QuicFrameType::PADDING,
        QuicFrameType::NEW_CONNECTION_ID,
      ].freeze

      QuicResetStreamFrame = _ = Struct.new( # rubocop:disable Naming/ConstantName
        :error_code,
        :final_size,
        :stream_id,
      )

      QuicStopSendingFrame = _ = Struct.new( # rubocop:disable Naming/ConstantName
        :error_code,
        :stream_id,
      )

      QuicStreamFrame = _ = Struct.new( # rubocop:disable Naming/ConstantName
        :data,
        :fin,
        :offset,
      )

      def self.pull_ack_frame(buf)
        rangeset = Rangeset.new
        ends = buf.pull_uint_var # largeset acknowledged
        delay = buf.pull_uint_var
        ack_range_count = buf.pull_uint_var
        ack_count = buf.pull_uint_var # first ack range
        rangeset.add(ends - ack_count, ends + 1)
        ends -= ack_count
        ack_range_count.times do
          ends -= buf.pull_uint_var + 2
          ack_count = buf.pull_uint_var
          rangeset.add(ends - ack_count, ends + 1)
          ends -= ack_count
        end
        [rangeset, delay]
      end

      def self.push_ack_frame(buf:, rangeset:, delay:)
        ranges = rangeset.length
        index = ranges - 1
        r = rangeset.list[index]
        buf.push_uint_var(r.last - 1)
        buf.push_uint_var(delay)
        buf.push_uint_var(index)
        buf.push_uint_var(r.last - 1 - r.first)
        start = r.first
        while index > 0
          index -= 1
          r = rangeset.list[index]
          buf.push_uint_var(start - r.last - 1)
          buf.push_uint_var(r.last - r.first - 1)
          start = r.first
        end
        return ranges
      end
    end
  end
end
