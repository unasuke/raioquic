# frozen_string_literal: true

module Raioquic
  module Quic
    class PacketBuilder
      class QuicDeliveryState
        ACKED = 0
        LOST = 1
        EXPIRED = 2
      end

      class QuicSentPacket
        attr_accessor :epoch
        attr_accessor :in_flight
        attr_accessor :is_ack_eliciting
        attr_accessor :is_crypto_packet
        attr_accessor :packet_number
        attr_accessor :packet_type
        attr_accessor :sent_time
        attr_accessor :sent_bytes
      end

      # Helper for building QUIC packets.
      class QuicPacketBuilder
        attr_accessor :packet_number

        # Helper for building QUIC packets.
        def initialize(host_cid:, peer_cid:, version:, is_client:, packet_number:, peer_token:, quic_logger:, spin_bit: false)
          raise NotImplementedError
        end

        def packet_is_empty
          raise NotImplementedError
        end

        def remaining_buffer_space
          raise NotImplementedError
        end

        def remaining_flight_space
          raise NotImplementedError
        end

        def flush
          raise NotImplementedError
        end

        def start_frame
          raise NotImplementedError
        end

        def start_packet
          raise NotImplementedError
        end

        def end_packet
          raise NotImplementedError
        end

        def flush_current_datagram
          raise NotImplementedError
        end
      end
    end
  end
end
