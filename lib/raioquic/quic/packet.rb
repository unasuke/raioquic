# frozen_string_literal: tru

module Raioquic
  module Quic
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
      RETRY_AEAD_KEY_VERSION_1 = "" # TODO: https://www.rfc-editor.org/rfc/rfc9001.html#section-5.8
      RETRY_AEAD_NONCE_VERSION_1 = "" # TODO: https://www.rfc-editor.org/rfc/rfc9001.html#section-5.8
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

      def decode_packet_number()
        raise NotImplementedError        
      end

      def get_retry_integrity_tag()
        raise NotImplementedError        
      end

      def get_spin_bit
        raise NotImplementedError
      end

      def is_draft_version
        raise NotImplementedError # raioquic drops draft version's implementation
      end

      def pull_quic_header
        raise NotImplementedError
      end

      def encode_quic_retry
        raise NotImplementedError
      end

      def encode_quic_version_negotiation
        raise NotImplementedError
      end

      class QuicPreferredAddress
        attr_accessor :ipv4_addresses
        attr_accessor :ipv6_addresses
        attr_accessor :connection_id
        attr_accessor :stateless_reset_token
      end

      class QuicTransportParameters
        attr_accessor :original_destication_connection_id
        attr_accessor :max_idle_timeout
        attr_accessor :stateless_reset_token
        attr_accessor :max_udp_payload_size
        attr_accessor :initial_max_data
        attr_accessor :initial_max_stream_data_bidi_local
        attr_accessor :initial_max_stream_data_bidi_remote
        attr_accessor :initial_max_stream_data_uni
        attr_accessor :initial_max_streams_bidi
        attr_accessor :initial_max_streams_uni
        attr_accessor :ack_delay_exponent
        attr_accessor :max_ack_delay
        attr_accessor :disable_active_migration
        attr_accessor :preferred_address
        attr_accessor :active_connection_id_limit
        attr_accessor :initial_source_connection_id
        attr_accessor :retry_source_connection_id
        attr_accessor :max_datagram_frame_size
        attr_accessor :quantum_readiness
      end

      PARAMS = {
        # TODO:
      }

      def pull_quic_preferred_address
        raise NotImplementedError
      end

      def push_quic_preferred_address
        raise NotImplementedError
      end
      
      def pull_quic_transport_parameters
        raise NotImplementedError
      end

      def push_quic_transport_parameters
        raise NotImplementedError
      end

      class QuicFrameType
        PADDING = 0x00
        PING = 0x10
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

      NON_ACK_ELICITING_FRAME_TYPES = [] # TODO:
      NON_IN_FLIGHT_FRAME_TYPES = [] # TODO:
      PROBING_FRAME_TYPES = [] # TODO:
      
      class QuicResetStreamFrame
        attr_accessor :error_code
        attr_accessor :final_size
        attr_accessor :stream_id
      end

      class QuicStopSendingFrame
        attr_accessor :error_code
        attr_accessor :stream_id
      end

      class QuicStreamFrame
        attr_accessor :data
        attr_accessor :fin
        attr_accessor :offset
      end

      def pull_ack_frame
        raise NotImplementedError
      end

      def push_ack_frame
        raise NotImplementedError
      end
    end
  end
end
