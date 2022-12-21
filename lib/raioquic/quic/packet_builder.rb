# frozen_string_literal: true

require_relative "../buffer"
require_relative "../tls"
require_relative "packet"

module Raioquic
  module Quic
    class PacketBuilder
      PACKET_MAX_SIZE = 1280
      PACKET_LENGTH_SEND_SIZE = 2
      PACKET_NUMBER_SEND_SIZE = 2

      class QuicDeliveryState
        ACKED = 0
        LOST = 1
        EXPIRED = 2
      end

      QuicSentPacket = _ = Struct.new( # rubocop:disable Naming/ConstantName
        :epoch,
        :in_flight,
        :is_ack_eliciting,
        :is_crypto_packet,
        :packet_number,
        :packet_type,
        :sent_time,
        :sent_bytes,
        :delivery_handlers,
        :quic_logger_frames,
      )

      QuicPacketBuilderStop = Class.new(StandardError)

      # Helper for building QUIC packets.
      class QuicPacketBuilder
        attr_reader :packet_number
        attr_accessor :max_flight_bytes
        attr_accessor :max_total_bytes

        # Helper for building QUIC packets.
        def initialize(host_cid:, peer_cid:, version:, is_client:, packet_number:, peer_token:, quic_logger: nil, spin_bit: false)
          @max_flight_bytes = nil
          @max_total_bytes = nil
          @quic_logger_frames = nil

          @host_cid = host_cid
          @is_client = is_client
          @peer_cid = peer_cid
          @peer_token = peer_token
          @quic_logger = quic_logger
          @spin_bit = spin_bit
          @version = version

          @datagrams = []
          @datagram_flight_bytes = 0
          @datagram_init = true
          @packets = []
          @flight_bytes = 0
          @total_bytes = 0

          @header_size = 0
          @packet = nil
          @packet_crypto = nil
          @packet_long_header = false
          @packet_number = packet_number
          @packet_start = 0
          @packet_type = 0

          @buffer = Buffer.new(capacity: PACKET_MAX_SIZE)
          @buffer_capacity = PACKET_MAX_SIZE
          @flight_capacity = PACKET_MAX_SIZE
        end

        # Returns true if the current packet is empty
        def packet_is_empty
          raise RuntimeError unless @packet

          packet_size = @buffer.tell - @packet_start
          return packet_size <= @header_size
        end

        # Returns the remaining number of bytes which can be used in the current packet.
        def remaining_buffer_space
          @buffer_capacity - @buffer.tell - @packet_crypto.aead_tag_size
        end

        # Returns the remaining number of bytes which can be used in the current packet
        def remaining_flight_space
          @flight_capacity - @buffer.tell - @packet_crypto.aead_tag_size
        end

        # Returns the assembled datagrams
        def flush
          end_packet if @packet

          flush_current_datagram
          datagrams = @datagrams
          packets = @packets
          @datagrams = []
          @packets = []
          return [datagrams, packets]
        end

        # Starts a new frame.
        def start_frame(frame_type:, capacity: 1, handler: nil, handler_args: []) # rubocop:disable Metrics/CyclomaticComplexity
          if remaining_buffer_space < capacity || (
            !Quic::Packet::NON_IN_FLIGHT_FRAME_TYPES.include?(frame_type) && remaining_flight_space < capacity
          )
            raise QuicPacketBuilderStop
          end

          @buffer.push_uint_var(frame_type)
          @packet.is_ack_eliciting = true unless Quic::Packet::NON_ACK_ELICITING_FRAME_TYPES.include?(frame_type)
          @packet.in_flight = true unless Quic::Packet::NON_IN_FLIGHT_FRAME_TYPES.include?(frame_type)
          @packet.is_crypto_packet = true if frame_type == Quic::Packet::QuicFrameType::CRYPTO
          if handler
            @packet.delivery_handlers.append(handler, handler_args) # TODO: what's this?
          end
          return @buffer
        end

        # Starts a new packet.
        def start_packet(packet_type:, crypto:) # rubocop:disable Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity, Metrics/MethodLength
          buf = @buffer

          # finish previous datagrams
          end_packet if @packet

          # if there is too little space remaining, start a new datagram
          # FIXME: the limit is arbitrary! (from aioquic)
          packet_start = buf.tell
          if @buffer_capacity - packet_start < 128
            flush_current_datagram
            packet_start = 0
          end

          # initialize datagram if needed
          # rubocop:disable Style/IfUnlessModifier
          if @datagram_init
            unless @max_total_bytes.nil?
              remaining_total_bytes = @max_total_bytes - @total_bytes
              if remaining_total_bytes < @buffer_capacity
                @buffer_capacity = remaining_total_bytes
              end
            end

            @flight_capacity = @buffer_capacity
            unless @max_flight_bytes.nil?
              remaining_flight_bytes = @max_flight_bytes - @flight_bytes
              if remaining_flight_bytes < @flight_capacity
                @flight_capacity = remaining_flight_bytes
              end
            end
            @datagram_flight_bytes = 0
            @datagram_init = false
          end
          # rubocop:enable Style/IfUnlessModifier

          # calculate header size
          packet_long_header = Quic::Packet.is_long_header(packet_type)
          if packet_long_header
            header_size = 11 + @peer_cid.length + @host_cid.length
            if (packet_type & Quic::Packet::PACKET_TYPE_MASK) == Quic::Packet::PACKET_TYPE_INITIAL
              token_length = @peer_token.length
              header_size += Buffer.size_uint_var(token_length) + token_length
            end
          else
            header_size = 3 + @peer_cid.length
          end

          # check we have enough space
          raise QuicPacketBuilderStop if packet_start + header_size >= @buffer_capacity

          # determine ack epoch
          # rubocop:disable Style/CaseLikeIf
          epoch = if packet_type == Quic::Packet::PACKET_TYPE_INITIAL
                    TLS::Epoch::INITIAL
                  elsif packet_type == Quic::Packet::PACKET_TYPE_HANDSHAKE
                    TLS::Epoch::HANDSHAKE
                  else
                    TLS::Epoch::ONE_RTT
                  end
          # rubocop:enable Style/CaseLikeIf

          @header_size = header_size
          @packet = QuicSentPacket.new.tap do |p|
            p.epoch = epoch
            p.in_flight = false
            p.is_ack_eliciting = false
            p.is_crypto_packet = false
            p.packet_number = @packet_number
            p.packet_type = packet_type
            p.quic_logger_frames = [] # TODO: ?
          end
          @packet_crypto = crypto
          @packet_long_header = packet_long_header
          @packet_start = packet_start
          @packet_type = packet_type
          @quic_logger_frames = @packet.quic_logger_frames

          buf.seek(@packet_start + @header_size)
        end

        # Ends the current packet.
        def end_packet # rubocop:disable Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity, Metrics/MethodLength
          buf = @buffer
          packet_size = buf.tell - @packet_start

          if packet_size > @header_size
            # padding to ensure sufficient sample size
            padding_size = Quic::Packet::PACKET_NUMBER_MAX_SIZE - PACKET_NUMBER_SEND_SIZE + @header_size - packet_size

            # padding for initial datagram
            if @is_client && @packet_type == Quic::Packet::PACKET_TYPE_INITIAL && @packet.is_ack_eliciting && remaining_flight_space && remaining_flight_space > padding_size # rubocop:disable Layout/LineLength
              padding_size = remaining_flight_space
            end

            if padding_size > 0
              buf.push_bytes("\x00" * padding_size)
              packet_size += padding_size
              @packet.in_flight = true

              # log frame
              if @quic_logger
                @packet.quic_logger_frames.append(@quic_logger.encode_padding_frame) # TODO: ?
              end
            end

            # write header
            # rubocop:disable Style/IdenticalConditionalBranches
            if @packet_long_header
              length = packet_size - @header_size + PACKET_NUMBER_SEND_SIZE + @packet_crypto.aead_tag_size
              buf.seek(@packet_start)
              buf.push_uint8(@packet_type | (PACKET_NUMBER_SEND_SIZE - 1))
              buf.push_uint32(@version)
              buf.push_uint8(@peer_cid.length)
              buf.push_bytes(@peer_cid)
              buf.push_uint8(@host_cid.length)
              buf.push_bytes(@host_cid)
              if @packet_type & Quic::Packet::PACKET_TYPE_MASK == Quic::Packet::PACKET_TYPE_INITIAL
                buf.push_uint_var(@peer_token.length)
                buf.push_bytes(@peer_token)
              end
              buf.push_uint16(length | 0x4000)
              buf.push_uint16(@packet_number & 0xffff)
            else
              buf.seek(@packet_start)
              buf.push_uint8(@packet_type | ((@spin_bit ? 1 : 0) << 5) | (@packet_crypto.key_phase << 2) | (PACKET_NUMBER_SEND_SIZE - 1))
              buf.push_bytes(@peer_cid)
              buf.push_uint16(@packet_number & 0xffff)
            end
            # rubocop:enable Style/IdenticalConditionalBranches

            # encrypt in place
            plain = buf.data_slice(start: @packet_start, ends: @packet_start + packet_size)
            buf.seek(@packet_start)
            buf.push_bytes(
              @packet_crypto.encrypt_packet(
                plain_header: plain[0...@header_size].force_encoding(Encoding::ASCII_8BIT),
                plain_payload: plain[@header_size...packet_size].force_encoding(Encoding::ASCII_8BIT),
                packet_number: @packet_number,
              ),
            )
            @packet.sent_bytes = buf.tell - @packet_start
            @packets << @packet

            @datagram_flight_bytes += @packet.sent_bytes if @packet.in_flight
            flush_current_datagram unless @packet_long_header
            @packet_number += 1
          else # packet_size > @header_size
            # "cancel" the packet
            buf.seek(@packet_start)
          end

          @packet = nil
          @quic_logger_frames = nil
        end

        def flush_current_datagram
          datagram_bytes = @buffer.tell
          if datagram_bytes > 0 # rubocop:disable Style/GuardClause
            @datagrams << @buffer.data
            @flight_bytes += @datagram_flight_bytes
            @total_bytes += datagram_bytes
            @datagram_init = true
            @buffer.seek(0)
          end
        end
      end
    end
  end
end
