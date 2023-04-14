# frozen_string_literal: true

require "set"

module Raioquic
  module Quic
    module Connection
      CRYPTO_BUFFER_SIZE = 16384
      EPOCH_SHORTCUTS = {
        "I" => TLS::Epoch::INITIAL,
        "H" => TLS::Epoch::HANDSHAKE,
        "0" => TLS::Epoch::ZERO_RTT,
        "1" => TLS::Epoch::ONE_RTT,
      }
      MAX_EARLY_DATA = 0xffffffff
      SECRETS_LABELS = [
        [
          nil,
          "CLIENT_EARLY_TRAFFIC_SECRET",
          "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
          "CLIENT_TRAFFIC_SECRET_0",
        ],
        [
          nil,
          nil,
          "SERVER_HANDSHAKE_TRAFFIC_SECRET",
          "SERVER_TRAFFIC_SECRET_0",
        ]
      ]
      STREAM_FLAGS = 0x07
      STREAM_COUNT_MAX = 0x1000000000000000
      UDP_HEADER_SIZE = 8

      # frame sizes
      ACK_FRAME_CAPACITY = 64 # FIXME: this is arbitrary!
      APPLICATION_CLOSE_FRAME_CAPACITY = 1 + (2 * Buffer::UINT_VAR_MAX_SIZE) # + reason length
      CONNECTION_LIMIT_FRAME_CAPACITY = 1 + Buffer::UINT_VAR_MAX_SIZE
      HANDSHAKE_DONE_FRAME_CAPACITY = 1
      MAX_STREAM_DATA_FRAME_CAPACITY = 1 + (2 * Buffer::UINT_VAR_MAX_SIZE)
      NEW_CONNECTION_ID_FRAME_CAPACITY = (
        1 + (2 * Buffer::UINT_VAR_MAX_SIZE) + 1 + Packet::CONNECTION_ID_MAX_SIZE + Packet::STATELESS_RESET_TOKEN_SIZE
      )
      PATH_CHALLENGE_FRAME_CAPACITY = 1 + 8
      PATH_RESPONSE_FRAME_CAPACITY = 1 + 8
      PING_FRAME_CAPACITY = 1
      RESET_STREAM_FRAME_CAPACITY = 1 + (3 * Buffer::UINT_VAR_MAX_SIZE)
      RETIRE_CONNECTION_ID_CAPACITY = 1 + Buffer::UINT_VAR_MAX_SIZE
      STOP_SENDING_FRAME_CAPACITY = 1 + (2 * Buffer::UINT_VAR_MAX_SIZE)
      STREAMS_BLOCKED_CAPACITY = 1 + Buffer::UINT_VAR_MAX_SIZE
      TRANSPORT_CLOSE_FLAME_CAPACITY = 1 + (3 * Buffer::UINT_VAR_MAX_SIZE) # + reason length

      def self.epochs(shortcut)
        shortcut.each_char.map do |s|
          EPOCH_SHORTCUTS[s]
        end.sort
      end

      def self.dump_cid(cid)
        cid.unpack1("H*")
      end

      def self.get_epoch(packet_type)
        case packet_type
        when Quic::Packet::PACKET_TYPE_INITIAL
          TLS::Epoch::INITIAL
        when Quic::Packet::PACKET_TYPE_ZERO_RTT
          TLS::Epoch::ZERO_RTT
        when Quic::Packet::PACKET_TYPE_HANDSHAKE
          TLS::Epoch::HANDSHAKE
        else
          TLS::Epoch::ONE_RTT
        end
      end

      def self.get_transport_parameters_extension(version)
        if Quic::Packet.is_draft_version(version)
          TLS::ExtensionType::QUIC_TRANSPORT_PARAMETERS_DRAFT
        else
          TLS::ExtensionType::QUIC_TRANSPORT_PARAMETERS
        end
      end

      # Returns true if the stream is client initiated.
      def self.stream_is_client_initiated(stream_id)
        stream_id & 1 == 0
      end

      # Returns true if the stream is unidirectional.
      def self.stream_is_unidirectional(stream_id)
        stream_id & 2 != 0
      end

      class Limit
        attr_reader :frame_type
        attr_reader :name
        attr_accessor :used
        attr_accessor :sent
        attr_accessor :value

        def initialize(frame_type:, name:, value:)
          @frame_type = frame_type
          @name = name
          @sent = value
          @used = 0
          @value = value
        end
      end

      class QuicConnectionError < StandardError # TODO: Raioquic::Error
        attr_accessor :error_code
        attr_accessor :frame_type
        attr_accessor :reason_phrase
      end

      # TODO: Use logger with formatter
      # class QuicConnectionAdapter
      #   def process(msd:, kwargs:)
      #   end
      # end

      QuicConnectionId = _ = Struct.new(
        :cid,
        :sequence_number,
        :stateless_reset_token,
        :was_sent,
      )

      class QuicConnectionState
        FIRSTFLIGHT = 0
        CONNECTED = 1
        CLOSING = 2
        DRAINING = 3
        TERMINATED = 4
      end

      QuicNetworkPath = _ = Struct.new(
        :addr,
        :bytes_received,
        :bytes_sent,
        :is_validated,
        :local_challenge,
        :remote_challenge,
      ) do
        def initialize(**)
          super
          self.bytes_sent ||= 0
          self.bytes_received ||= 0
        end

        def can_send(size)
          self.is_validated || (self.bytes_sent + size) <= 3 * self.bytes_received
        end
      end

      QuicReceiveContext = _ = Struct.new(
        :epoch,
        :host_cid,
        :network_path,
        :quic_logger_frames,
        :time,
      )

      END_STATES = [
        QuicConnectionState::CLOSING,
        QuicConnectionState::DRAINING,
        QuicConnectionState::TERMINATED,
      ].freeze

      # A QUIC connection.
      #
      # The state machine is driven by three kinds of sources:
      #
      # - the API user requesting data to be send out (see `connect`,
      #   `reset_stream`, `send_ping`, `send_datagram_frame` and `send_stream_data`)
      # - data being received from the network (see `receive_datagram`)
      # - a timer firing (see `handle_timer`)
      #
      # param configuration: The QUIC configuration to use.
      class QuicConnection
        attr_reader :configuration
        attr_reader :loss
        attr_reader :peer_cid_available
        attr_reader :host_cid
        attr_reader :host_cids
        attr_reader :version
        attr_reader :network_paths
        attr_reader :peer_cid
        attr_reader :local_max_stream_data_uni
        attr_reader :remote_max_streams_uni
        attr_reader :remote_max_streams_bidi
        attr_reader :local_max_data
        attr_reader :remote_max_data
        attr_reader :streams
        attr_reader :cryptos
        attr_reader :close_event
        attr_reader :local_max_stream_data_bidi_remote
        attr_reader :local_max_stream_data_bidi_local
        attr_reader :local_max_streams_bidi
        attr_reader :tls
        attr_reader :events
        attr_reader :quic_logger
        attr_reader :handshake_done_pending
        attr_accessor :original_destination_connection_id
        attr_accessor :ack_delay
        attr_accessor :is_client
        attr_accessor :initial_source_connection_id # TODO: did not used?

        attr_reader :events # TODO: remove

        def initialize(
          configuration:,
          original_destination_connection_id: nil,
          retry_source_connection_id: nil,
          session_ticket_fetcher: nil,
          session_ticket_handler: nil
        )
          # binding.irb
          if configuration.is_client
            raise ArgumentError, "Cannot set original_destination_connection_id for a client" if original_destination_connection_id
            raise ArgumentError, "Cannot set retry_source_connection_id for a client" if retry_source_connection_id
          else
            raise ArgumentError, "SSL certificate is required for a server" unless configuration.certificate
            raise ArgumentError, "SSL private key is required for a server" unless configuration.private_key
          end

          # configuration
          @configuration = configuration
          @is_client = configuration.is_client

          @ack_delay = Recovery::K_GRANULARITY
          @close_at = nil
          @close_event = nil
          @connect_called = false
          @cryptos = {}
          @crypto_buffers = {}
          @crypto_retransmitted = false
          @crypto_streams = {}
          @events = []
          @handshake_complete = false
          @handshake_confirmed = false
          @host_cids = [
            QuicConnectionId.new.tap do |conn|
              conn.cid = Random.urandom(@configuration.connection_id_length)
              conn.sequence_number = 0
              conn.stateless_reset_token = @is_client ? nil : Random.urandom(16)
              conn.was_sent = true
            end
          ]
          @host_cid = @host_cids[0].cid
          @host_cid_seq = 1
          @local_ack_delay_exponent = 3
          @local_active_connection_id_limit = 8
          @local_initial_source_connection_id = @host_cids[0].cid
          @local_max_data = Limit.new(
            frame_type: Packet::QuicFrameType::MAX_DATA,
            name: "max_data",
            value: configuration.max_data,
          )
          @local_max_stream_data_bidi_local = @configuration.max_stream_data
          @local_max_stream_data_bidi_remote = @configuration.max_stream_data
          @local_max_stream_data_uni = @configuration.max_stream_data
          @local_max_streams_bidi = Limit.new(
            frame_type: Packet::QuicFrameType::MAX_STREAMS_BIDI,
            name: "max_streams_bidi",
            value: 128,
          )
          @local_max_streams_uni = Limit.new(
            frame_type: Packet::QuicFrameType::MAX_STREAMS_UNI,
            name: "max_streams_uni",
            value: 128,
          )
          @loss_at = nil
          @network_paths = []
          @pacing_at = nil
          @packet_number = 0
          @parameters_received = false
          @peer_cid = QuicConnectionId.new.tap do |cid|
            cid.cid = Random.urandom(@configuration.connection_id_length)
            cid.sequence_number = nil
          end
          @peer_cid_available = []
          @peer_cid_sequence_numbers = Set.new([0])
          @peer_token = ""
          @quic_logger = nil
          @remote_ack_delay_exponent = 3
          @remote_active_connection_id_limit = 2
          @remote_initial_source_connection_id = nil
          @remote_max_idle_timeout = 0.0 # seconds
          @remote_max_data = 0
          @remote_max_data_used = 0
          @remote_max_datagram_frame_size = nil
          @remote_max_stream_data_bidi_local = 0
          @remote_max_stream_data_bidi_remote = 0
          @remote_max_stream_data_uni = 0
          @remote_max_streams_bidi = 0
          @remote_max_streams_uni = 0
          @retry_count = 0
          @retry_source_connection_id = retry_source_connection_id
          @spaces = {}
          @spin_bit = false
          @spin_highest_pn = 0
          @state = QuicConnectionState::FIRSTFLIGHT
          @streams = {}
          @streams_blocked_bidi = []
          @streams_blocked_uni = []
          @streams_finished = Set.new
          @version = nil
          @version_negotiation_count = 0

          @original_destination_connection_id = \
            @is_client ? @peer_cid.cid : original_destination_connection_id

          @logger = nil # TODO: logging
          if @configuration.quic_logger
            @quic_logger = @configuration.quic_logger.start_trace(
              is_client: @configuration.is_client,
              odcid: @original_destination_connection_id,
            )
          end

          # loss recovery
          @loss = Quic::Recovery::QuicPacketRecovery.new(
            initial_rtt: @configuration.initial_rtt,
            peer_completed_address_validation: !@is_client,
            quic_logger: @quic_logger,
            send_probe: method(:send_probe),
            logger: nil,
          )

          # things to send
          @close_pending = false
          @datagrams_pending = [] # TODO: deque
          @handshake_done_pending = false
          @ping_pending = []
          @probe_pending = false
          @retire_connection_ids = []
          @streams_blocked_pending = false

          # callbacks
          @session_ticket_fetcher = session_ticket_fetcher
          @session_ticket_handler = session_ticket_handler

          # frame handlers
          @frame_handlers = {
            0x00 => [:handle_padding_frame, Connection.epochs("IH01")],
            0x01 => [:handle_ping_frame, Connection.epochs("IH01")],
            0x02 => [:handle_ack_frame, Connection.epochs("IH1")],
            0x03 => [:handle_ack_frame, Connection.epochs("IH1")],
            0x04 => [:handle_reset_stream_frame, Connection.epochs("01")],
            0x05 => [:handle_stop_sending_frame, Connection.epochs("01")],
            0x06 => [:handle_crypto_frame, Connection.epochs("IH1")],
            0x07 => [:handle_new_token_frame, Connection.epochs("1")],
            0x08 => [:handle_stream_frame, Connection.epochs("01")],
            0x09 => [:handle_stream_frame, Connection.epochs("01")],
            0x0a => [:handle_stream_frame, Connection.epochs("01")],
            0x0b => [:handle_stream_frame, Connection.epochs("01")],
            0x0c => [:handle_stream_frame, Connection.epochs("01")],
            0x0d => [:handle_stream_frame, Connection.epochs("01")],
            0x0e => [:handle_stream_frame, Connection.epochs("01")],
            0x0f => [:handle_stream_frame, Connection.epochs("01")],
            0x10 => [:handle_max_data_frame, Connection.epochs("01")],
            0x11 => [:handle_max_stream_data_frame, Connection.epochs("01")],
            0x12 => [:handle_max_streams_bidi_frame, Connection.epochs("01")],
            0x13 => [:handle_max_streams_uni_frame, Connection.epochs("01")],
            0x14 => [:handle_data_blocked_frame, Connection.epochs("01")],
            0x15 => [:handle_stream_data_blocked_frame, Connection.epochs("01")],
            0x16 => [:handle_streams_blocked_frame, Connection.epochs("01")],
            0x17 => [:handle_streams_blocked_frame, Connection.epochs("01")],
            0x18 => [:handle_new_connection_id_frame, Connection.epochs("01")],
            0x19 => [:handle_retire_connection_id_frame, Connection.epochs("01")],
            0x1a => [:handle_path_challenge_frame, Connection.epochs("01")],
            0x1b => [:handle_path_response_frame, Connection.epochs("01")],
            0x1c => [:handle_connection_close_frame, Connection.epochs("IH01")],
            0x1d => [:handle_connection_close_frame, Connection.epochs("01")],
            0x1e => [:handle_handshake_done_frame, Connection.epochs("1")],
            0x30 => [:handle_datagram_frame, Connection.epochs("01")],
            0x31 => [:handle_datagram_frame, Connection.epochs("01")],
          }
        end

        # Switch to the next available connection ID ans retire the previous one.
        #
        # After calling this method call `datagrams_to_send` to retrieve data which needs to be sent.
        def change_connection_id
          if @peer_cid_available
            # retire precious CID
            retire_peer_cid(@peer_cid)

            # assign new CID
            consume_peer_cid
          end
        end

        # Close the connection.
        #
        # param error_code: An error code indication why the connection is being closed.
        # param reason_phrase: A human-readable explanation of why the connection is being closed.
        def close(error_code: Quic::Packet::QuicErrorCode::NO_ERROR, frame_type: nil, reason_phrase: "")
          puts "close called (server)" unless @is_client
          puts reason_phrase unless @is_client
          if @close_event.nil? && !END_STATES.include?(@state)
            @close_event = Quic::Event::ConnectionTerminated.new.tap do |error|
              error.error_code = error_code
              error.frame_type = frame_type
              error.reason_phrase = reason_phrase
            end
            @close_pending = true
          end
        end

        # Initiate the TLS handshake.
        #
        # This method can only be called for clients and a single time.
        #
        # After calling this method call `datagrams_to_send` to retrieve data which needs to be sent.
        #
        # param addr: The network address of the remote peer
        # param now: The current time.
        def connect(addr:, now:)
          raise "`connect` can only be called for clients and a single time" if !@is_client && @connect_called

          @connect_called = true
          # np = QuicNetworkPath.new.tap { |n| n.addr = addr; n.is_validated = true; }
          # @network_paths = [np]
          @network_paths = [QuicNetworkPath.new.tap { |n| n.addr = addr; n.is_validated = true; }]
          @version = @configuration.supported_versions[0]
          _connect(now: now)
        end

        # Return a list of `[data, addr]` array of datagrams which need to be sent, and the network address to which they need to be sent.
        #
        # After calling this method call `get_timer` to know when the next timer needs to be set.
        #
        # param now: The current time.
        def datagrams_to_send(now:)
          puts "datagrams_to_send called (server)" unless @is_client
          puts "datagrams_to_send called (client)" if @is_client
          network_path = @network_paths[0]

          return [] if END_STATES.include?(@state)

          # build datagrams
          builder = Quic::PacketBuilder::QuicPacketBuilder.new(
            host_cid: @host_cid,
            is_client: @is_client,
            packet_number: @packet_number,
            peer_cid: @peer_cid.cid,
            peer_token: @peer_token,
            quic_logger: @quic_logger,
            spin_bit: @spin_bit,
            version: @version,
          )
          if @close_pending
            puts "datagrams_to_send close_pending: true (server)" unless @is_client
            epoch_packet_types = []
            unless @handshake_confirmed
              epoch_packet_types += [
                [TLS::Epoch::INITIAL, Quic::Packet::PACKET_TYPE_INITIAL],
                [TLS::Epoch::HANDSHAKE, Quic::Packet::PACKET_TYPE_HANDSHAKE]
              ]
            end
            epoch_packet_types += [[TLS::Epoch::ONE_RTT, Quic::Packet::PACKET_TYPE_ONE_RTT]]
            epoch_packet_types.each do |epoch, packet_type|
              crypto = @cryptos[epoch]
              # binding.irb
              next unless crypto&.send&.is_valid

              # binding.irb unless @is_client
              puts "PacketBuilder#start_packet called from datagrams_to_send"
              builder.start_packet(packet_type: packet_type, crypto: crypto)
              # binding.irb
              write_connection_close_frame(
                builder: builder,
                epoch: epoch,
                error_code: @close_event.error_code,
                frame_type: @close_event.frame_type,
                reason_phrase: @close_event.reason_phrase,
              )
            end
            # TODO: logger "Connection close sent"
            @close_pending = true
            close_begin(is_initiator: true, now: now)
          else
            # congestion control
            builder.max_flight_bytes = @loss.congestion_window - @loss.bytes_in_flight
            if @probe_pending && builder.max_flight_bytes < Quic::PacketBuilder::PACKET_MAX_SIZE
              builder.max_flight_bytes = Quic::PacketBuilder::PACKET_MAX_SIZE
            end
            puts "**** builder.max_flight_bytes: #{builder.max_flight_bytes}"

            # limit data on un-validated network paths
            builder.max_total_bytes = (network_path.bytes_received * 3) - network_path.bytes_sent unless network_path.is_validated

            begin
              unless @handshake_confirmed
                [TLS::Epoch::INITIAL, TLS::Epoch::HANDSHAKE].each do |epoch|
                  puts "write_handshake called by datagrams_to_send"
                  write_handshake(builder: builder, epoch: epoch, now: now)
                end
              end
              puts "write_application called by datagrams_to_send"
              write_application(builder: builder, network_path: network_path, now: now)
            rescue Quic::PacketBuilder::QuicPacketBuilderStop
              # pass
            end
          end

          datagrams, packets = builder.flush
          puts "flushed datagrams #{datagrams.length}"

          if datagrams
            @packet_number = builder.packet_number

            # register packets
            sent_handshake = false
            packets.each do |packet|
              packet.sent_time = now
              @loss.on_packet_sent(packet: packet, space: @spaces[packet.epoch])
              sent_handshake = true if packet.epoch == TLS::Epoch::HANDSHAKE

              # log packet
              if @quic_logger
                @quic_logger.log_event(
                  category: "transport",
                  event: "packet_sent",
                  data: {
                    frames: packet.quic_logger_frames,
                    header: {
                      packet_number: packet.packet_number,
                      packet_type: @quic_logger.packet_type(packet.packet_type),
                      scid: ( Quic::Packet.is_long_header(packet.packet_type) ? Connection.dump_cid(@host_cid) : ""),
                      dcid: Connection.dump_cid(@peer_cid.cid),
                    },
                    raw: { length: packet.sent_bytes },
                  },
                )
              end
            end

            # check if we can discard initial keys
            if sent_handshake && @is_client
              discard_epoch(TLS::Epoch::INITIAL)
            end
          end

          # return datagrams to send and the destination network address
          ret = []
          datagrams.each do |datagram|
            payload_length = datagram.bytesize
            network_path.bytes_sent += payload_length
            ret << [datagram, network_path.addr]

            if @quic_logger
              if payload_length == 238
                puts "hraf"
              end
              @quic_logger.log_event(
                category: "transport",
                event: "datagrams_sent",
                data: {
                  count: 1,
                  raw: [{ length: UDP_HEADER_SIZE + payload_length, payload_length: payload_length }],
                },
              )
            end
          end

          puts "ret length #{ret.length}"
          return ret
        end

        # Return the stream ID for the next stream created by this endpoint.
        def get_next_available_stream_id(is_unidirectional: false)
          uni_int = is_unidirectional ? 1 : 0
          client_int = @is_client ? 0 : 1
          stream_id = (uni_int << 1) | client_int
          while @streams.keys.include?(stream_id) || @streams_finished.include?(stream_id)
            stream_id += 4
          end
          return stream_id
        end

        # Return the time at which the timer should fire or nil if no timer is needed.
        def get_timer
          timer_at = @close_at
          unless END_STATES.include?(@state)
            # ack timer
            @loss.spaces.each do |space|
              timer_at = space.ack_at if space.ack_at && space.ack_at < timer_at
            end

            # loss detection timer
            @loss_at = @loss.get_loss_detection_time
            timer_at = @loss_at if @loss_at && @loss_at < timer_at

            # pacing timer
            timer_at = @pacing_at if @pacing_at && @pacing_at < timer_at
          end

          return timer_at
        end

        # Handle the timer.
        #
        # After calling this method call `datagram_to_send` to retrieve data which needs to be sent.
        #
        # param now: The current timer.
        def handle_timer(now:)
          # binding.b
          # enf of closing period or idle timeout
          if now >= @close_at
            @close_event ||= Quic::Event::ConnectionTerminated.new.tap do |event|
              event.error_code = Quic::Packet::QuicErrorCode::INTERNAL_ERROR
              event.frame_type = Quic::Packet::QuicFrameType::PADDING
              event.reason_phrase = "Ide timeout"
            end
            close_end
            return
          end

          # loss detection timeout
          if @loss_at && now >= @loss_at
            # TODO: logger "Loss detection triggered"
            @loss.on_loss_detection_timeout(now: now)
          end
        end

        # Retrieve the next event from the event buffer.
        #
        # Returns `nil` if there are no buffered events.
        def next_event
          # binding.irb unless @is_client
          @events.shift
        rescue StandardError
          return nil
        end

        # Handle an incoming datagram.
        #
        # After calling this method call `datagrams_to_send` to retrieve data which needs to be sent.
        #
        # param data: The datagram which was received.
        # param addr: The network address from which the datagram was received.
        # param now: The current time.
        def receive_datagram(data:, addr:, now:)
          puts "receive_datagram called (server)" unless @is_client
          puts "receive_datagram called (client)" if @is_client
          # stop handling packets when closing
          return if END_STATES.include?(@state)

          # log datagram
          if @quic_logger
            @quic_logger.log_event(
              category: "transport",
              event: "datagrams_received",
              data: {
                count: 1,
                raw: [{ length: UDP_HEADER_SIZE + data.bytesize, payload_length: data.bytesize }],
              },
            )
          end

          # for servers. arm the idle timeout on the first datagram
          @close_at ||= now + @configuration.idle_timeout

          buf = Buffer.new(data: data)
          header = nil
          until buf.eof
            start_off = buf.tell
            begin
              header = Quic::Packet.pull_quic_header(buf: buf, host_cid_length: @configuration.connection_id_length)
            rescue ValueError
              if @quic_logger
                @quic_logger.log_event(
                  category: "transport",
                  event: "packet_dropped",
                  data: {
                    trigger: "header_parse_error",
                    raw: { length: buf.capacity - start_off },
                  },
                )
              end
              return
            end

            # check destination CID matches
            destination_cid_seq = nil
            @host_cids.each do |connection_id|
              if header.destination_cid == connection_id.cid
                destination_cid_seq = connection_id.sequence_number
                break
              end
            end

            if @is_client && destination_cid_seq.nil?
              if @quic_logger
                @quic_logger.log_event(
                  category: "transport",
                  event: "packet_dropped",
                  data: { trigger: "unknown_connection_id" },
                )
              end
              return
            end

            # check protocol version
            if @is_client &&
               @state == QuicConnectionState::FIRSTFLIGHT &&
               header.version == Quic::Packet::QuicProtocolVersion::NEGOTIATION &&
               @version_negotiation_count == 0
              # version negotiation
              versions = []

              versions << buf.pull_uint32 until buf.eof

              if @quic_logger
                @quic_logger.log_event(
                  category: "transport",
                  event: "packet_received",
                  data: {
                    frames: [],
                    header: {
                      packet_type: "version_negotiation",
                      scid: Connection.dump_cid(header.source_cid),
                      dcid: Connection.dump_cid(header.destination_cid),
                    },
                    raw: { length: buf.tell - start_off },
                  },
                )
              end

              if versions.include?(@version)
                # TODO: logging
                return
              end

              common = @configuration.supported_versions & versions # TODO: correct?
              if common.empty?
                # TODO: logging
                @close_event = Quic::Event::ConnectionTerminated.new.tap do |event|
                  event.error_code = Quic::Packet::QuicErrorCode::INTERNAL_ERROR
                  event.frame_type = Quic::Packet::QuicFrameType::PADDING
                  event.reason_phrase = "Could not find a common protocol version"
                end
                close_end
                return
              end

              @packet_number = 0
              @version = Quic::Packet::QuicProtocolVersion::VERSION_1 # TODO: check version
              @version_negotiation_count += 1
              _connect(now: now)
              return
            elsif header.version && !@configuration.supported_versions.include?(header.version)
              # unsupported version
              if @quic_logger
                @quic_logger.log_event(
                  category: "transport",
                  event: "packet_dropped",
                  data: { trigger: "unsupported_version" },
                )
              end
              return
            end

            # handle retry packet
            # binding.irb
            if header.packet_type == Quic::Packet::PACKET_TYPE_RETRY
              puts "&*(*(&*(&*(&*(&*(&*()*)(*)*()*()&*(&^*()))))))"
              tag = Quic::Packet.get_retry_integrity_tag(
                packet_without_tag: buf.data_slice(
                  start: start_off,
                  ends: buf.tell - Quic::Packet::RETRY_INTEGRITY_TAG_SIZE,
                ),
                original_destination_cid: @peer_cid.cid,
                )
              if @is_client && @retry_count.zero? && header.destination_cid == @host_cid && header.integrity_tag == tag
                if @quic_logger
                  @quic_logger.log_event(
                    category: "transport",
                    event: "packet_received",
                    data: {
                      frames: [],
                      header: {
                        packet_type: "retry",
                        scid: Connection.dump_cid(header.source_cid),
                        dcid: Connection.dump_cid(header.destination_cid),
                      },
                      raw: { length: buf.tell - start_off },
                    },
                  )
                end
                @peer_cid.cid = header.source_cid
                @peer_token = header.token
                @retry_count += 1
                @retry_source_connection_id = header.source_cid
                _connect(now: now)
              else
                # unexpected or invalid retry packet
                if @quic_logger
                  @quic_logger.log_event(
                    category: "transport",
                    event: "packet_dropped",
                    data: { trigger: "unexpected_packet" },
                  )
                end
                return
              end
            end

            network_path = find_network_path(addr)

            # server initialization
            if !@is_client && @state == QuicConnectionState::FIRSTFLIGHT
              raise "first packet must be initial" unless header.packet_type == Quic::Packet::PACKET_TYPE_INITIAL

              @network_paths = [network_path]
              @version = Quic::Packet::QuicProtocolVersion::VERSION_1 # TODO: version
              initialize_connection(header.destination_cid)
            end

            # determine crypto and packet space
            epoch = Connection.get_epoch(header.packet_type)
            crypto = @cryptos[epoch]
            space = if epoch == TLS::Epoch::ZERO_RTT
                      @spaces[TLS::Epoch::ONE_RTT]
                    else
                      @spaces[epoch]
                    end

            # decrypt packet
            encrypted_off = buf.tell - start_off
            end_off = buf.tell + header.rest_length
            buf.seek(end_off)

            begin
              plain_header, plain_payload, packet_number = crypto.decrypt_packet(
                packet: data[start_off...end_off], encrypted_offset: encrypted_off, expected_packet_number: space.expected_packet_number,
              )
            rescue ArgumentError # TODO: KeyUnavailableError
              @quic_logger&.log_event(category: "transport", event: "packet_dropped", data: { trigger: "key_unavailable" })

              # if a client receives HANDSHAKE or 1-RTT packets before it has handshake keys, it can assume that the server's INITIAL was lost
              if @is_client && [TLS::Epoch::HANDSHAKE, TLS::Epoch::ONE_RTT].include?(epoch) && !@crypto_retransmitted
                @loss.reschedule_data(now: now)
                @crypto_retransmitted = true
              end
              next
            rescue Quic::Crypto::CryptoError, OpenSSL::Cipher::CipherError # TODO: raise CryptoError from crypto module
              @quic_logger&.log_event(category: "transport", event: "packet_dropped", data: { trigger: "payload_decrypt_error" })
              next
            end

            # check reserved bits
            reserved_mask = header.is_long_header ? 0x0c : 0x18
            if plain_header[0].unpack1("C*") & reserved_mask != 0
              close(
                error_code: Quic::Packet::QuicErrorCode::PROTOCOL_VIOLATION,
                frame_type: Quic::Packet::QuicFrameType::PADDING,
                reason_phrase: "Reserved bits must be zero",
              )
            end

            # log packet
            quic_logger_frames = []
            puts "INIT  QUIC_LOGGER_FRAMES #{quic_logger_frames.object_id}"
            if @quic_logger
              @quic_logger.log_event(
                category: "transport",
                event: "packet_received",
                data: {
                  frames: quic_logger_frames,
                  header: {
                    packet_number: packet_number,
                    packet_type: @quic_logger.packet_type(header.packet_type),
                    dcid: Connection.dump_cid(header.destination_cid),
                    scid: Connection.dump_cid(header.source_cid),
                  },
                  raw: { length: end_off - start_off },
                },
              )
            end

            # raise expected packet number
            space.expected_packet_number = packet_number + 1 if packet_number > space.expected_packet_number

            # discard initial keys and packet space
            discard_epoch(TLS::Epoch::INITIAL) if !@is_client && epoch == TLS::Epoch::HANDSHAKE

            # update status
            if @peer_cid.sequence_number.nil?
              @peer_cid.cid = header.source_cid
              @peer_cid.sequence_number = 0
            end

            if @state == Quic::Connection::QuicConnectionState::FIRSTFLIGHT
              @remote_initial_source_connection_id = header.source_cid
              set_state(Quic::Connection::QuicConnectionState::CONNECTED)
            end

            # update spin bit
            if !header.is_long_header && packet_number > @spin_highest_pn
              spin_bit = Quic::Packet.get_spin_bit(plain_header[0])
              @spin_bit = if @is_client
                            !spin_bit
                          else
                            spin_bit
                          end
              @spin_highest_pn = packet_number
              @quic_logger&.log_event(category: "connectivity", event: "spin_bit_updated", data: { state: @spin_bit })
            end

            # handle payload
            context = Quic::Connection::QuicReceiveContext.new.tap do |ctx|
              ctx.epoch = epoch
              ctx.host_cid = header.destination_cid
              ctx.network_path = network_path
              ctx.quic_logger_frames = quic_logger_frames
              ctx.time = now
            end
            puts "CONTEXT CREATE #{context.quic_logger_frames.object_id}"

            begin
              puts "payload_received will be call" unless @is_client
              is_ack_eliciting, is_probing = payload_received(context: context, plain: plain_payload)
            rescue QuicConnectionError => err
              # TODO: logging
              close(error_code: err.error_code, frame_type: err.frame_type, reason_phrase: err.reason_phrase)
            end
            return if END_STATES.include?(@state) || @close_pending

            # update idle timeout
            @close_at = now + @configuration.idle_timeout

            # handle migration
            if !@is_client && context.host_cid != @host_cid && epoch == TLS::Epoch::ONE_RTT
              # TODO: logging
              # raise RuntimeError
              @host_cid = context.host_cid
              change_connection_id
            end

            # update network path
            if !network_path.is_validated && epoch == TLS::Epoch::HANDSHAKE
              # TODO: logging
              network_path.is_validated = true
            end
            network_path.bytes_received += end_off - start_off
            @network_paths << network_path unless @network_paths.include?(network_path)
            idx = @network_paths.index(network_path)
            if idx && idx > 0 && !is_probing && packet_number > space.largest_received_packet
              # TODO: logging
              @network_paths.delete_at(idx)
              @network_paths.insert(0, network_path)
            end

            # record packet as received
            unless space.discarded
              if packet_number > space.largest_received_packet
                space.largest_received_packet = packet_number
                space.largest_received_time = now
              end
              space.ack_queue.add(packet_number)
              space.ack_at = now + @ack_delay if is_ack_eliciting && space.ack_at.nil?
            end
          end
        end

        # Request an update of the encryption kyes.
        def request_key_update
          raise "cannot change key before handshake compeletes" unless @handshake_complete
          @cryptos[TLS::Epoch::ONE_RTT].update_key
        end

        # Abruptly terminate the sending part of a stream.
        #
        # param stream_id: The stream's ID.
        # param error_code: An error code inidicating why the stream is being reset.
        def reset_stream(stream_id:, error_code:)
          stream = get_or_create_stream_for_send(stream_id)
          stream.sender.reset(error_code: error_code)
        end

        # Send a PING frame to the peer.
        #
        # param: uid: A unique ID for this PING.
        def send_ping(uid)
          @ping_pending.append(uid)
        end

        # Send a DATAGRAM frame.
        #
        # param data: The data to be sent.
        def send_datagram_frame(data)
          @datagrams_pending.append(data)
        end

        # Send data on the specific stream.
        #
        # param stream_id: The stream's ID.
        # param data: The data to be sent.
        # param end_stream: If set to `true`, the FIN bit will be set.
        def send_stream_data(stream_id:, data:, end_stream: false)
          stream = get_or_create_stream_for_send(stream_id)
          stream.sender.write(data: data, end_stream: end_stream)
        end

        # Request termination of the receiveing part of a stream.
        #
        # param stream_id: The stream's ID.
        # param error_code: An error code indicatig why the stream is being stopped.
        def stop_stream(stream_id:, error_code:)
          raise ValueError, "Cannot stop receiving on a local-initiated unidirectional stream" unless stream_can_receive(stream_id)

          stream = @streams[stream_id]
          raise ValueError, "Cannot stop receiving on an unknown stream" unless stream

          stream.receiver.stop(error_code: error_code)
        end

        # Callback which is invoked by the TLS engine when ALPN negotiation completes.
        private def alpn_handler(alpn_protocol)
          # binding.irb
          @events.append(Event::ProtocolNegotiated.new.tap { |e| e.alpn_protocol = alpn_protocol })
        end

        # Check the specified strem can receive data or raises a QuicConnectionError.
        private def assert_stream_can_receive(frame_type:, stream_id:)
          unless stream_can_receive(stream_id)
            err = QuicConnectionError.new.tap do |e|
              e.error_code = Quic::Packet::QuicErrorCode::STREAM_STATE_ERROR
              e.frame_type = frame_type
              e.reason_phrase = "Stream is send-only"
            end
            raise err
          end
        end

        # Check the specified strem can send data or raises a QuicConnectionError.
        private def assert_stream_can_send(frame_type:, stream_id:)
          unless stream_can_send(stream_id)
            err = QuicConnectionError.new.tap do |e|
              e.error_code = Quic::Packet::QuicErrorCode::STREAM_STATE_ERROR
              e.frame_type = frame_type
              e.reason_phrase = "Stream is receive-only"
            end
            raise err
          end
        end

        # Update the destination connection ID by taking the next available connection ID provided by the peer.
        private def consume_peer_cid
          @peer_cid = @peer_cid_available.delete_at(0)
          # TODO: logging
        end

        # Begin the close procedure.
        private def close_begin(is_initiator:, now:)
          @close_at = now + (3 * @loss.get_probe_timeout)
          if is_initiator
            set_state(QuicConnectionState::CLOSING)
          else
            set_state(QuicConnectionState::DRAINING)
          end
        end

        # End the close procedure.
        private def close_end
          @close_at = nil
          @spaces.keys.each do |epoch|
            discard_epoch(epoch)
          end
          @events << @close_event
          set_state(QuicConnectionState::TERMINATED)
          # "signal log end"
          if @quic_logger
            @configuration.quic_logger.end_trace(@quic_logger)
            @quic_logger = nil
          end
        end

        # Start the client handshake.
        private def _connect(now:)
          raise unless @is_client

          @close_at = now + @configuration.idle_timeout
          initialize_connection(@peer_cid.cid)

          @tls.handle_message(input_data: "", output_buf: @crypto_buffers)
          push_crypto_data
        end

        private def discard_epoch(epoch)
          unless @spaces[epoch].discarded
            # TODO: logger
            @cryptos[epoch].teardown
            @loss.discard_space(space: @spaces[epoch])
            @spaces[epoch].discarded = true
          end
        end

        private def find_network_path(addr)
          # check existing network paths
          @network_paths.each do |network_path|
            return network_path if network_path.addr == addr
          end

          # new network path
          network_path = QuicNetworkPath.new.tap { |n| n.addr = addr; n.bytes_received = 0; }
          # TODO: logging
          return network_path
        end

        # Get or create a stream in response to a received frame.
        private def get_or_create_stream(frame_type:, stream_id:)
          raise Quic::Stream::StreamFinishedError if @streams_finished.include?(stream_id)

          stream = @streams[stream_id]
          unless stream
            # check initiator
            puts "@@@@@@@@@@@@@@@@@@@@@@ #{stream}"
            if Connection.stream_is_client_initiated(stream_id || 0) == @is_client
              # binding.irb
              err = QuicConnectionError.new.tap do |e|
                e.error_code = Quic::Packet::QuicErrorCode::STREAM_STATE_ERROR
                e.frame_type = frame_type
                e.reason_phrase = "Wrong stream initiator"
              end
              raise err
            end

            # determine limits
            if Connection.stream_is_unidirectional(stream_id)
              max_stream_data_local = @local_max_stream_data_uni
              max_stream_data_remote = 0
              max_streams = @local_max_streams_uni
            else
              max_stream_data_local = @local_max_stream_data_bidi_local
              max_stream_data_remote = @remote_max_stream_data_bidi_local
              max_streams = @local_max_streams_bidi
            end

            # check max streams
            stream_count = (stream_id.floor(4)) + 1
            if stream_count > max_streams.value
              err = QuicConnectionError.new.tap do |e|
                e.error_code = Quic::Packet::QuicErrorCode::STREAM_LIMIT_ERROR
                e.frame_type = frame_type
                e.reason_phrase = "Too many streams open"
              end
              raise err
            elsif stream_count > max_streams.used
              max_streams.used = stream_count
            end

            # create stream
            # TODO: logger
            stream = @streams[stream_id] = Stream::QuicStream.new(
              stream_id: stream_id,
              max_stream_data_local: max_stream_data_local,
              max_stream_data_remote: max_stream_data_remote,
              writable: !Connection.stream_is_unidirectional(stream_id),
            )
          end
          return stream
        end

        # Get or create a QUIC stream in order to send datra to the peer.
        #
        # This always occurs as a result of an API call.
        private def get_or_create_stream_for_send(stream_id)
          raise ValueError, "Cannot send data on peer-initiated unidirectional stream" unless stream_can_send(stream_id)

          stream = @streams[stream_id]
          unless stream
            # check initiator
            raise ValueError, "Cannot send data on unknown peer-initiated stream" if Connection.stream_is_client_initiated(stream_id) != @is_client

            # determine limits
            if Connection.stream_is_unidirectional(stream_id)
              max_stream_data_local = 0
              max_stream_data_remote = @remote_max_stream_data_uni
              max_streams = @remote_max_streams_uni
              streams_blocked = @streams_blocked_uni
            else
              max_stream_data_local = @local_max_stream_data_bidi_local
              max_stream_data_remote = @remote_max_stream_data_bidi_remote
              max_streams = @remote_max_streams_bidi
              streams_blocked = @streams_blocked_bidi
            end

            # create stream
            stream = @streams[stream_id] = Stream::QuicStream.new(
              stream_id: stream_id,
              max_stream_data_local: max_stream_data_local,
              max_stream_data_remote: max_stream_data_remote,
              readable: !Connection.stream_is_unidirectional(stream_id),
            )

            # mark stream as blocked if needed
            if stream_id.floor(4) >= max_streams
              stream.is_blocked = true
              streams_blocked << stream
              @streams_blocked_pending = true
            end
          end
          return stream
        end

        private def handle_session_ticket(session_ticket)
          if session_ticket.max_early_data_size && session_ticket.max_early_data_size != MAX_EARLY_DATA
            err = QuicConnectionError.new.tap do |e|
              e.error_code = Quic::Packet::QuicErrorCode::PROTOCOL_VIOLATION
              e.frame_type = Quic::Packet::QuicFrameType::CRYPTO
              e.reason_phrase = "Invalid max_early_data value #{session_ticket.max_early_data_size}"
            end
            raise err
          end
          @session_ticket_handler&.call(session_ticket)
        end

        private def initialize_connection(peer_cid)
          # TLS
          @tls = TLS::Context.new(
            alpn_protocols: @configuration.alpn_protocols,
            cadata: @configuration.cadata,
            cafile: @configuration.cafile,
            capath: @configuration.capath,
            cipher_suites: @configuration.cipher_suites,
            is_client: @is_client,
            logger: @logger,
            max_early_data: (@is_client ? nil : MAX_EARLY_DATA),
            server_name: @configuration.server_name,
            verify_mode: @configuration.verify_mode,
          )
          @tls.certificate = @configuration.certificate
          @tls.certificate_chain = @configuration.certificate_chain
          @tls.certificate_private_key = @configuration.private_key
          @tls.handshake_extensions = [[Connection.get_transport_parameters_extension(@version), serialize_transport_parameters]]

          # TLS session resumption
          session_ticket = @configuration.session_ticket
          if @is_client && session_ticket && session_ticket.is_valid && session_ticket.server_name == @configuration.server_name
            @tls.session_ticket = @configuration.session_ticket

            # parse saved QUIC transport parameters - for 0-RTT
            if session_ticket.max_early_data_size == MAX_EARLY_DATA
              session_ticket.other_extensions.each do |ext_type, ext_data|
                if ext_type == Connection.get_transport_parameters_extension(@version)
                  parse_transport_parameters(data: ext_data, from_session_ticket: true)
                  break
                end
              end
            end
          end

          # TLS callbacks
          @tls.alpn_cb = method(:alpn_handler)
          @tls.get_session_ticket_cb = @session_ticket_fetcher if @session_ticket_fetcher
          @tls.new_session_ticket_cb = method(:handle_session_ticket) if @session_ticket_handler
          @tls.update_traffic_key_cb = method(:update_traffic_key)
          # binding.irb

          # packet spaces
          create_crypto_pair = lambda do |epoch|
            eopch_name = %w(initial 0rtt handshake 1rtt)[epoch]
            secret_names = ["server_#{eopch_name}_secret", "client_#{eopch_name}_secret"]
            recv_secret_name = secret_names[@is_client ? 0 : 1]
            send_secret_name = secret_names[@is_client ? 1 : 0]
            # TODO: keylog
            return Crypto::CryptoPair.new(
              recv_setup_cb: ->(trigger) { log_key_updated(key_type: recv_secret_name, trigger: trigger) },
              recv_teardown_cb: ->(trigger) { log_key_retired(key_type: recv_secret_name, trigger: trigger) },
              send_setup_cb: ->(trigger) { log_key_updated(key_type: send_secret_name, trigger: trigger) },
              send_teardown_cb: ->(trigger) { log_key_retired(key_type: send_secret_name, trigger: trigger) },
            )
          end

          @cryptos = [TLS::Epoch::INITIAL, TLS::Epoch::ZERO_RTT, TLS::Epoch::HANDSHAKE, TLS::Epoch::ONE_RTT].inject({}) do |hash, epoch|
            hash[epoch] = create_crypto_pair.call(epoch)
            hash
          end
          @crypto_buffers = {
            TLS::Epoch::INITIAL => Buffer.new(capacity: CRYPTO_BUFFER_SIZE),
            TLS::Epoch::HANDSHAKE => Buffer.new(capacity: CRYPTO_BUFFER_SIZE),
            TLS::Epoch::ONE_RTT => Buffer.new(capacity: CRYPTO_BUFFER_SIZE),
          }
          @crypto_streams = {
            TLS::Epoch::INITIAL => Stream::QuicStream.new,
            TLS::Epoch::HANDSHAKE => Stream::QuicStream.new,
            TLS::Epoch::ONE_RTT => Stream::QuicStream.new,
          }
          @spaces = {
            TLS::Epoch::INITIAL => Recovery::QuicPacketSpace.new,
            TLS::Epoch::HANDSHAKE => Recovery::QuicPacketSpace.new,
            TLS::Epoch::ONE_RTT => Recovery::QuicPacketSpace.new,
          }

          @cryptos[TLS::Epoch::INITIAL].setup_initial(cid: peer_cid, is_client: @is_client, version: @version)
          @loss.spaces = @spaces.values
        end

        # Handle an ACK frame.
        private def handle_ack_frame(context:, frame_type:, buf:)
          ack_rangeset, ack_delay_encoded = Quic::Packet.pull_ack_frame(buf)
          if frame_type == Quic::Packet::QuicFrameType::ACK_ECN
            3.times { buf.pull_uint_var }
          end
          ack_delay = (ack_delay_encoded << @remote_ack_delay_exponent) / 1000000

          if @quic_logger
            context.quic_logger_frames << @quic_logger.encode_ack_frame(ranges: ack_rangeset, delay: ack_delay)
          end

          # check whether per completed address validation
          if !@loss.peer_completed_address_validation && [TLS::Epoch::HANDSHAKE, TLS::Epoch::ONE_RTT].include?(context.epoch)
            @loss.peer_completed_address_validation = true
          end

          @loss.on_ack_received(space: @spaces[context.epoch], ack_rangeset: ack_rangeset, ack_delay: ack_delay, now: context.time)
        end

        # Handle a CONNECTION_CLOSE frame.
        private def handle_connection_close_frame(context:, frame_type:, buf:)
          error_code = buf.pull_uint_var
          if frame_type == Quic::Packet::QuicFrameType::TRANSPORT_CLOSE
            frame_type = buf.pull_uint_var
          else
            frame_type = nil
          end
          reason_length = buf.pull_uint_var
          begin
            reason_phrase = buf.pull_bytes(reason_length).encode(Encoding::UTF_8)
          rescue EncodingError
            reason_phrase = ""
          end

          # log frame
          if @quic_logger
            context.quic_logger_frames << @quic_logger.encode_connection_close_frame(error_code: error_code, frame_type: frame_type, reason_phrase: reason_phrase)
          end

          unless @close_event
            @close_event = Event::ConnectionTerminated.new.tap do |event|
              event.error_code = error_code
              event.frame_type = frame_type
              event.reason_phrase = reason_phrase
            end
            close_begin(is_initiator: false, now: context.time)
          end
        end

        # Handle a CRYPTO frame.
        private def handle_crypto_frame(context:, frame_type:, buf:)
          # binding.b
          offset = buf.pull_uint_var
          length = buf.pull_uint_var
          if offset + length > Buffer::UINT_VAR_MAX
            err = QuicConnectionError.new.tap do |e|
              e.error_code = Quic::Packet::QuicErrorCode::FRAME_ENCODING_ERROR
              e.frame_type = frame_type
              e.reason_phrase = "offset + length cannot exceed 2^62 - 1"
            end
            raise err
          end
          frame = Quic::Packet::QuicStreamFrame.new.tap do |f|
            f.offset = offset
            f.data = buf.pull_bytes(length)
          end

          # log frame
          if @quic_logger
            puts "ENCODE_CRYPTO_FRAME CONTEXT #{context.quic_logger_frames.object_id}"
            context.quic_logger_frames << @quic_logger.encode_crypto_frame(frame: frame)
          end

          stream = @crypto_streams[context.epoch]
          event = stream.receiver.handle_frame(frame: frame)
          if event
            # pass data to TLS layer
            begin
              # binding.irb
              @tls.handle_message(input_data: event.data, output_buf: @crypto_buffers)
              push_crypto_data
            rescue TLS::Alert => e
              error = QuicConnectionError.new.tap do |err|
                err.error_code = Quic::Packet::QuicErrorCode::CRYPTO_ERROR + e.description
                err.frame_type = frame_type
                err.reason_phrase = e.message
              end
              raise error
            end

            # parse transport parameters
            if !@parameters_received && @tls.received_extensions
              @tls.received_extensions.each do |ext_type, ext_data|
                if ext_type == Connection.get_transport_parameters_extension(@version)
                  parse_transport_parameters(data: ext_data)
                  @parameters_received = true
                  break
                end
              end
              unless @parameters_received
                err = QuicConnectionError.new.tap do |e|
                  e.error_code = Quic::Packet::QuicErrorCode::CRYPTO_ERROR + TLS::AlertDescription::MISSING_EXTENSION
                  e.frame_type = frame_type
                  e.reason_phrase = "No QUIC transport parameters received"
                end
                raise err
              end
            end

            # update current epoch
            # binding.irb unless @is_client
            if !@handshake_complete && [TLS::State::CLIENT_POST_HANDSHAKE, TLS::State::SERVER_POST_HANDSHAKE].include?(@tls.state)
              puts "handshake complete!" unless @is_client
              @handshake_complete = true

              # for servers, the handshake is now confirmed
              unless @is_client
                discard_epoch(TLS::Epoch::HANDSHAKE)
                @handshake_confirmed = true
                @handshake_done_pending = true
              end
              replenish_connection_ids
              @events.append(
                Event::HandshakeCompleted.new.tap do |ev|
                  ev.alpn_protocol = @tls.alpn_negotiated
                  ev.early_data_accepted = !!@tls.early_data_accepted
                  ev.session_resumed = @tls.session_resumed
                end
              )
              unblock_streams(false)
              unblock_streams(true)
              # TODO: logger
            end
          else
            # TODO: logger

            # if a server receives duplicate CRYPTO in an INITIAL packet, it can assume the client did not receive the server's CRYPTO
            if !@is_client && context.epoch == TLS::Epoch::INITIAL && !@crypto_retransmitted
              @loss.reschedule_data(now: context.time)
              @crypto_retransmitted = true
            end
          end
        end

        # Handle a DATA_BLOCKED frame.
        private def handle_data_blocked_frame(context:, frame_type:, buf:)
          limit = buf.pull_uint_var

          # log frame
          if @quic_logger
            context.quic_logger_frames << @quic_logger.encode_data_blocked_frame(limit: limit)
          end
        end

        # Handle a DATAGRAM frmae.
        private def handle_datagram_frame(context:, frame_type:, buf:)
          start = buf.tell
          if frame_type == Quic::Packet::QuicFrameType::DATAGRAM_WITH_LENGTH
            length = buf.pull_uint_var
          else
            length = buf.capacity - start
          end
          data = buf.pull_bytes(length)

          # log frame
          if @quic_logger
            context.quic_logger_frames << @quic_logger.encode_datagram_frame(length: length)
          end

          # check frame is allowed
          if !@configuration.max_datagram_frame_size || buf.tell - start >= @configuration.max_datagram_frame_size
            err = QuicConnectionError.new.tap do |e|
              e.error_code = Quic::Packet::QuicErrorCode::PROTOCOL_VIOLATION
              e.frame_type = frame_type
              e.reason_phrase = "Unexpected DATAGRAM frame"
            end
            raise err
          end
          @events.append(Event::DatagramFrameReceived.new.tap { |e| e.data = data })
        end

        # Handle a HANDSHAKE_DONE frame.
        private def handle_handshake_done_frame(context:, frame_type:, buf:)
          # log frame
          context.quic_logger_frames << @quic_logger.encode_handshake_done_frame if @quic_logger

          unless @is_client
            err = QuicConnectionError.new.tap do |e|
              e.error_code = Quic::Packet::QuicErrorCode::PROTOCOL_VIOLATION
              e.frame_type = frame_type
              e.reason_phrase = "Clients must not send HANDSHAKE_DONE frames"
            end
            raise err
          end

          # for clients. the handshake is now confirmed
          unless @handshake_confirmed
            discard_epoch(TLS::Epoch::HANDSHAKE)
            @handshake_confirmed = true
            @loss.peer_completed_address_validation = true
          end
        end

        # Handle a MAX_DATA frame.
        #
        # This adjusts the total amount of we can send to the peer.
        private def handle_max_data_frame(context:, frame_type:, buf:)
          max_data = buf.pull_uint_var
          # log frame
          context.quic_logger_frames << @quic_logger.encode_connection_limit_frame(frame_type: frame_type, maximum: max_data) if @quic_logger

          if max_data > @remote_max_data
            # TODO: logging
            @remote_max_data = max_data
          end
        end

        # Handle a MAX_STREAM_DATA frame.
        #
        # This adjusts the total amount of we can send on a specific stream.
        private def handle_max_stream_data_frame(context:, frame_type:, buf:)
          stream_id = buf.pull_uint_var
          max_stream_data = buf.pull_uint_var

          # log frame
          context.quic_logger_frames << @quic_logger.encode_max_stream_data_frame(maximum: max_stream_data, stream_id: stream_id) if @quic_logger

          # check stream direction
          assert_stream_can_send(frame_type: frame_type, stream_id: stream_id)

          stream = get_or_create_stream(frame_type: frame_type, stream_id: stream_id)
          if max_stream_data > stream.max_stream_data_remote
            # TODO: logging
            stream.max_stream_data_remote = max_stream_data
          end
        end

        # Handle a MAX_STREAMS_BIDI frame.
        #
        # This raises number of bidirectional streams we can initiate to the peer.
        private def handle_max_streams_bidi_frame(context:, frame_type:, buf:)
          max_streams = buf.pull_uint_var
          if max_streams > STREAM_COUNT_MAX
            err = QuicConnectionError.new.tap do |e|
              e.error_code = Quic::Packet::QuicErrorCode::FRAME_ENCODING_ERROR
              e.frame_type = frame_type
              e.reason_phrase = "Maximum Streams cannot exceed 2^60"
            end
            raise err
          end

          # log frame
          context.quic_logger_frames << @quic_logger.encode_connection_limit_frame(frame_type: frame_type, maximum: max_streams) if @quic_logger

          if max_streams > @remote_max_streams_bidi
            # TODO: logging
            @remote_max_streams_bidi = max_streams
            unblock_streams(false)
          end
        end

        # Handle a MAX_STREAMS_UNI frame.
        #
        # This raises number of unidirectional streams we can initiate to the peer.
        private def handle_max_streams_uni_frame(context:, frame_type:, buf:)
          max_streams = buf.pull_uint_var
          if max_streams > STREAM_COUNT_MAX
            err = QuicConnectionError.new.tap do |e|
              e.error_code = Quic::Packet::QuicErrorCode::FRAME_ENCODING_ERROR
              e.frame_type = frame_type
              e.reason_phrase = "Maximum Streams cannot exceed 2^60"
            end
            raise err
          end

          # log frame
          context.quic_logger_frames << @quic_logger.encode_connection_limit_frame(frame_type: frame_type, maximum: max_streams) if @quic_logger

          if max_streams > @remote_max_streams_uni
            # TODO: logging
            @remote_max_streams_uni = max_streams
            unblock_streams(true)
          end
        end

        # Handle a NEW_CONNECTION_ID frame.
        private def handle_new_connection_id_frame(context:, frame_type:, buf:)
          sequence_number = buf.pull_uint_var
          retire_prior_to = buf.pull_uint_var
          length = buf.pull_uint8
          connection_id = buf.pull_bytes(length)
          stateless_reset_token = buf.pull_bytes(Quic::Packet::STATELESS_RESET_TOKEN_SIZE)
          if !connection_id || connection_id.bytesize > Quic::Packet::CONNECTION_ID_MAX_SIZE
            err = QuicConnectionError.new.tap do |e|
              e.error_code = Quic::Packet::QuicErrorCode::FRAME_ENCODING_ERROR
              e.frame_type = frame_type
              e.reason_phrase = "Length must be greater than 0 and less than 20"
            end
            raise err
          end

          # log frame
          context.quic_logger_frames << @quic_logger.encode_new_connection_id_frame(
            connection_id: connection_id,
            retire_prior_to: retire_prior_to,
            sequence_number: sequence_number,
            stateless_reset_token: stateless_reset_token,
          ) if @quic_logger

          # sanity check
          if retire_prior_to > sequence_number
            err = QuicConnectionError.new.tap do |e|
              e.error_code = Quic::Packet::QuicErrorCode::PROTOCOL_VIOLATION
              e.frame_type = frame_type
              e.reason_phrase = "Retire Prior To is greater than Sequence Number"
            end
            raise err
          end

          # determine which CIDs to retire
          change_cid = false
          retire = @peer_cid_available.filter { |c| c.sequence_number < retire_prior_to }
          if @peer_cid.sequence_number < retire_prior_to
            change_cid = true
            retire.insert(0, @peer_cid)
          end

          # update available CIDs
          @peer_cid_available = @peer_cid_available.filter { |c| c.sequence_number >= retire_prior_to }
          unless @peer_cid_sequence_numbers.include?(sequence_number)
            @peer_cid_available.append(
              QuicConnectionId.new.tap do |conn|
                conn.cid = connection_id
                conn.sequence_number = sequence_number
                conn.stateless_reset_token = stateless_reset_token
              end
            )
            @peer_cid_sequence_numbers.add(sequence_number)
          end

          # retire previous CIDs
          retire.each { |quic_connection_id| retire_peer_cid(quic_connection_id) }

          # assign new CID if we retired the active one
          consume_peer_cid if change_cid

          # check number of active connection IDs, including the selected one
          if 1 + @peer_cid_available.length > @local_active_connection_id_limit
            err = QuicConnectionError.new.tap do |e|
              e.error_code = Quic::Packet::QuicErrorCode::CONNECTION_ID_LIMIT_ERROR
              e.frame_type = frame_type
              e.reason_phrase = "Too many active connection IDs"
            end
            raise err
          end
        end

        # Handle a NEW_TOKEN frame.
        private def handle_new_token_frame(context:, frame_type:, buf:)
          length = buf.pull_uint_var
          token = buf.pull_bytes(length)

          # log frame
          context.quic_logger_frames << @quic_logger.encode_new_token_frame(token: token) if @quic_logger

          unless @is_client
            err = QuicConnectionError.new.tap do |e|
              e.error_code = Quic::Packet::QuicErrorCode::PROTOCOL_VIOLATION
              e.frame_type = frame_type
              e.reason_phrase = "Clients must not send NEW_TOKEN frames"
            end
            raise err
          end
        end

        # Handle a PADDING frame.
        private def handle_padding_frame(context:, frame_type:, buf:)
          pos = buf.tell
          # consume padding
          buf.data_slice(start: pos, ends: buf.capacity).each_byte do |byte|
            break if byte != 0 # 0x00
            pos += 1
          end
          buf.seek(pos)
          # log frame
          context.quic_logger_frames << @quic_logger.encode_padding_frame if @quic_logger
        end

        # Handle a PATH_CHALLENGE frame.
        private def handle_path_challenge_frame(context:, frame_type:, buf:)
          data = buf.pull_bytes(8)
          # log frame
          context.quic_logger_frames << @quic_logger.encode_path_challenge_frame(data: data) if @quic_logger
          context.network_path.remote_challenge = data
        end

        # Handle a PATH_RESPONSE frame.
        private def handle_path_response_frame(context:, frame_type:, buf:)
          data = buf.pull_bytes(8)
          # log frame
          context.quic_logger_frames << @quic_logger.encode_path_response_frame(data: data) if @quic_logger

          if data != context.network_path.local_challenge
            err = QuicConnectionError.new.tap do |e|
              e.error_code = Quic::Packet::QuicErrorCode::PROTOCOL_VIOLATION
              e.frame_type = frame_type
              e.reason_phrase = "Response does not match challenge"
            end
            raise err
          end
          # TODO: logging
          context.network_path.is_validated = true
        end

        # Handle a PING frame.
        private def handle_ping_frame(context:, frame_type:, buf:)
          # log frame
          context.quic_logger_frames << @quic_logger.encode_ping_frame if @quic_logger
        end

        # Handle a RESET_STREAM frame.
        private def handle_reset_stream_frame(context:, frame_type:, buf:)
          stream_id = buf.pull_uint_var
          error_code = buf.pull_uint_var
          final_size = buf.pull_uint_var

          # log frame
          if @quic_logger
            context.quic_logger_frames << @quic_logger.encode_reset_stream_frame(error_code: error_code, final_size: final_size, stream_id: stream_id)
          end

          # check stream direction
          assert_stream_can_receive(frame_type: frame_type, stream_id: stream_id)

          # check flow-control limits
          stream = get_or_create_stream(frame_type: frame_type, stream_id: stream_id)
          if final_size > stream.max_stream_data_local
            err = QuicConnectionError.new.tap do |e|
              e.error_code = Quic::Packet::QuicErrorCode::FLOW_CONTROL_ERROR
              e.frame_type = frame_type
              e.reason_phrase = "Over stream data limit"
            end
            raise err
          end
          newly_received = [0, final_size - stream.receiver.highest_offset].max
          if @local_max_data.used + newly_received > @local_max_data.value
            err = QuicConnectionError.new.tap do |e|
              e.error_code = Quic::Packet::QuicErrorCode::FLOW_CONTROL_ERROR
              e.frame_type = frame_type
              e.reason_phrase = "Over connection data limit"
            end
            raise err
          end

          # process reset
          # TODO: logging
          begin
            event = stream.receiver.handle_reset(final_size: final_size, error_code: error_code)
          rescue Stream::FinalSizeError => error
            err = QuicConnectionError.new.tap do |e|
              e.error_code = Quic::Packet::QuicErrorCode::FINAL_SIZE_ERROR
              e.frame_type = frame_type
              e.reason_phrase = error.message
            end
            raise err
          end
          @events.append(event) if event
          @local_max_data.used += newly_received
        end

        # Handle a RETIRE_CONNECTION_ID frame.
        private def handle_retire_connection_id_frame(context:, frame_type:, buf:)
          sequence_number = buf.pull_uint_var

          # log frame
          context.quic_logger_frames << @quic_logger.encode_retire_connection_id_frame(sequence_number: sequence_number) if @quic_logger

          if sequence_number >= @host_cid_seq
            err = QuicConnectionError.new.tap do |e|
              e.error_code = Quic::Packet::QuicErrorCode::PROTOCOL_VIOLATION
              e.frame_type = frame_type
              e.reason_phrase = "Cannot retire unknown connection ID"
            end
            raise err
          end

          # find the connection ID by sequence number
          @host_cids.each_with_index do |connection_id, i|
            if connection_id.sequence_number == sequence_number
              if connection_id.cid == context.host_cid
                err = QuicConnectionError.new.tap do |e|
                  e.error_code = Quic::Packet::QuicErrorCode::PROTOCOL_VIOLATION
                  e.frame_type = frame_type
                  e.reason_phrase = "Cannot retire current connection ID"
                end
                raise err
              end
              # TODO: logging
              @host_cids.delete_at(i)
              @events.append(
                Event::ConnectionIdRetired.new.tap do |ev|
                  ev.connection_id = connection_id.cid
                end
              )
              break
            end
          end
          # issue a new connection ID
          replenish_connection_ids
        end

        # Handle a STOP_SENDING frame.
        private def handle_stop_sending_frame(context:, frame_type:, buf:)
          stream_id = buf.pull_uint_var
          error_code = buf.pull_uint_var # application error code

          # log frame
          context.quic_logger_frames << @quic_logger.encode_stop_sending_frame(error_code: error_code, stream_id: stream_id) if @quic_logger

          # check stream direction
          assert_stream_can_send(frame_type: frame_type, stream_id: stream_id)

          # reset the stream
          stream = get_or_create_stream(frame_type: frame_type, stream_id: stream_id)
          stream.sender.reset(error_code: Quic::Packet::QuicErrorCode::NO_ERROR)
        end

        # Handle a STREAM frame.
        private def handle_stream_frame(context:, frame_type:, buf:)
          stream_id = buf.pull_uint_var
          offset = if frame_type & 4 != 0
                     buf.pull_uint_var
                   else
                     0
                   end
          length = if frame_type & 2 != 0
                     buf.pull_uint_var
                   else
                     buf.capacity - buf.tell
                   end
          if offset + length > Buffer::UINT_VAR_MAX
            err = QuicConnectionError.new.tap do |e|
              e.error_code = Quic::Packet::QuicErrorCode::FRAME_ENCODING_ERROR
              e.frame_type = frame_type
              e.reason_phrase = "offset + length cannot exceed 2^62 - 1"
            end
            raise err
          end
          frame = Quic::Packet::QuicStreamFrame.new.tap do |f|
            f.offset = offset
            f.data = buf.pull_bytes(length)
            f.fin = ((frame_type & 1) == 1)
          end

          # log frame
          context.quic_logger_frames << @quic_logger.encode_stream_frame(frame: frame, stream_id: stream_id) if @quic_logger

          # check stream direction
          assert_stream_can_receive(frame_type: frame_type, stream_id: stream_id)

          # check flow-control limits
          stream = get_or_create_stream(frame_type: frame_type, stream_id: stream_id)
          if offset + length > stream.max_stream_data_local
            err = QuicConnectionError.new.tap do |e|
              e.error_code = Quic::Packet::QuicErrorCode::FLOW_CONTROL_ERROR
              e.frame_type = frame_type
              e.reason_phrase = "Over stream data limit"
            end
            raise err
          end
          newly_received = [0, offset + length - stream.receiver.highest_offset].max
          if @local_max_data.used + newly_received > @local_max_data.value
            err = QuicConnectionError.new.tap do |e|
              e.error_code = Quic::Packet::QuicErrorCode::FLOW_CONTROL_ERROR
              e.frame_type = frame_type
              e.reason_phrase = "Over connection data limit"
            end
            raise err
          end

          # process data
          begin
            event = stream.receiver.handle_frame(frame: frame)
          rescue Stream::FinalSizeError => error
            err = QuicConnectionError.new.tap do |e|
              e.error_code = Quic::Packet::QuicErrorCode::FINAL_SIZE_ERROR
              e.frame_type = frame_type
              e.reason_phrase = error.message
            end
            raise err
          end
          @events.append(event) if event
          @local_max_data.used += newly_received
        end

        # Handle a STREAM_DATA_BLOCKED frame.
        private def handle_stream_data_blocked_frame(context:, frame_type:, buf:)
          stream_id = buf.pull_uint_var
          limit = buf.pull_uint_var

          # log frame
          context.quic_logger_frames << @quic_logger.encode_stream_data_blocked_frame(limit: limit, stream_id: stream_id)

          # check stream direction
          assert_stream_can_receive(frame_type: frame_type, stream_id: stream_id)

          get_or_create_stream(frame_type: frame_type, stream_id: stream_id)
        end

        # Handle a STREAMS_BLOCKED frame.
        private def handle_streams_blocked_frame(context:, frame_type:, buf:)
          limit = buf.pull_uint_var
          if limit > STREAM_COUNT_MAX
            err = QuicConnectionError.new.tap do |e|
              e.error_code = Quic::Packet::QuicErrorCode::FRAME_ENCODING_ERROR
              e.frame_type = frame_type
              e.reason_phrase = "Maximum Streams cannot exceed 2^60"
            end
            raise err
          end

          # log frame
          context.quic_logger_frames << @quic_logger.encode_streams_blocked_frame(
            is_unidirectional: (frame_type == Quic::Packet::QuicFrameType::STREAMS_BLOCKED_UNI),
            limit: limit,
          ) if @quic_logger
        end

        # Log a key retirement.
        private def log_key_retired(key_type:, trigger:)
          # binding.irb
          @quic_logger&.log_event(category: "security", event: "key_retired", data: { key_type: key_type, trigger: trigger })
        end

        # Log a key update
        private def log_key_updated(key_type:, trigger:)
          @quic_logger&.log_event(category: "security", event: "key_updated", data: { key_type: key_type, trigger: trigger })
        end

        # Callback when an ACK frame is acknowledged or lost.
        private def on_ack_delivery(delivery:, space:, highest_acked:)
          if delivery == Quic::PacketBuilder::QuicDeliveryState::ACKED
            space.ack_queue.subtract(0, highest_acked + 1)
          end
        end

        # Callback when a MAX_DATA or MAX_STREAMS frame is acknowledged or lost.
        private def on_connection_limit_delivery(delivery:, limit:)
          limit.sent = 0 if delivery != Quic::PacketBuilder::QuicDeliveryState::ACKED
        end

        # Callback when a HANDSHAKE_DONE frame is acknowledged or lost.
        private def on_handshake_done_delivery(delivery:)
          @handshake_done_pending = true if delivery != Quic::PacketBuilder::QuicDeliveryState::ACKED
        end

        # Callback when a MAX_STREAM_DATA frame is acknowleged or loss.
        private def on_max_stream_data_delivery(delivery:, stream:)
          stream.max_stream_data_local_sent = 0 if delivery != Quic::PacketBuilder::QuicDeliveryState::ACKED
        end

        # Callback when a NEW_CONNECTION_ID frame is acknowledged or loss.
        private def on_new_connection_id_delivery(delivery:, connection_id:)
          connection_id.was_sent = false if delivery != Quic::PacketBuilder::QuicDeliveryState::ACKED
        end

        # Callback when a PING frame is acknowledged or lost.
        private def on_ping_delivery(delivery:, uids:)
          if delivery == Quic::PacketBuilder::QuicDeliveryState::ACKED
            # TODO: logging
            uids.each do |uid|
              @events.append(Event::PingAcknowledged.new.tap { |e| e.uid = uid })
            end
          else
            @ping_pending += uids
          end
        end

        # Callback when a RETIRE_CONNECTION_ID frame is acknowledged or lost.
        private def on_retire_connection_id_delivery(delivery:, sequence_number:)
          @retire_connection_ids.append(sequence_number) if delivery != Quic::PacketBuilder::QuicDeliveryState::ACKED
        end

        # Handle a QUIC packet payload.
        private def payload_received(context:, plain:)
          buf = Buffer.new(data: plain)

          frame_found = false
          is_ack_eliciting = false
          is_probing = nil
          pp plain
          until buf.eof
            frame_type = buf.pull_uint_var

            # check frame type is known
            frame_handler, frame_epochs = @frame_handlers[frame_type]
            # puts "frame_type #{frame_handler}" unless @is_client
            if frame_handler.nil?
              err = QuicConnectionError.new.tap do |e|
                e.error_code = Quic::Packet::QuicErrorCode::PROTOCOL_VIOLATION
                e.frame_type = frame_type
                e.reason_phrase = "Unknown frame type"
              end
              raise err
            end

            # check frame is allowed for the epoch
            unless frame_epochs.include?(context.epoch)
              err = QuicConnectionError.new.tap do |e|
                e.error_code = Quic::Packet::QuicErrorCode::PROTOCOL_VIOLATION
                e.frame_type = frame_type
                e.reason_phrase = "Unexpected frame type"
              end
              raise err
            end

            # handle the frame
            begin
              # binding.irb if frame_type == :handle_max_data_frame
              method(frame_handler).call(context: context, frame_type: frame_type, buf: buf)
            rescue Buffer::BufferReadError
              # binding.irb
              err = QuicConnectionError.new.tap do |e|
                e.error_code = Quic::Packet::QuicErrorCode::FRAME_ENCODING_ERROR
                e.frame_type = frame_type
                e.reason_phrase = "Failed to parse frame"
              end
              raise err
            rescue Quic::Stream::StreamFinishedError
              # we lack the state for the stream, ignore the frame
            end

            # update ACK only / probing flags
            frame_found = true

            unless Quic::Packet::NON_ACK_ELICITING_FRAME_TYPES.include?(frame_type)
              is_ack_eliciting = true
            end

            if !Quic::Packet::PROBING_FRAME_TYPES.include?(frame_type)
              is_probing = false
            elsif is_probing.nil?
              is_probing = true
            end
          end

          unless frame_found
            err = QuicConnectionError.new.tap do |e|
              e.error_code = Quic::Packet::QuicErrorCode::PROTOCOL_VIOLATION
              e.frame_type = Quic::Packet::QuicFrameType::PADDING
              e.reason_phrase = "Packet contains no frames"
            end
            raise err
          end
          return [is_ack_eliciting, is_probing]
        end

        # Generate new connection IDs.
        private def replenish_connection_ids
          while @host_cids.length < [8, @remote_active_connection_id_limit.to_i].min
            @host_cids.append(
              QuicConnectionId.new.tap do |conn|
                conn.cid = Random.urandom(@configuration.connection_id_length)
                conn.sequence_number = @host_cid_seq
                conn.stateless_reset_token = Random.urandom(16)
              end
            )
            @host_cid_seq += 1
          end
        end

        # Retire a destication connection ID.
        private def retire_peer_cid(connection_id)
          # TODO: logger
          @retire_connection_ids.append(connection_id.sequence_number)
        end

        private def push_crypto_data
          @crypto_buffers.each do |epoch, buf|
            @crypto_streams[epoch].sender.write(data: buf.data)
            buf.seek(0)
          end
        end

        private def send_probe
          @probe_pending = true
        end

        # Parse and apply remote transport parameters.
        #
        # `from_session_ticket` is `true` when restoring saved transport parameters, and `false` when handling received transport parameters.
        private def parse_transport_parameters(data:, from_session_ticket: false)
          begin
            quic_transport_parameters = Quic::Packet.pull_quic_transport_parameters(Buffer.new(data: data))
          rescue ::Raioquic::ValueError, ::Raioquic::Buffer::BufferReadError
            err = QuicConnectionError.new.tap do |e|
              e.error_code = Quic::Packet::QuicErrorCode::TRANSPORT_PARAMETER_ERROR
              e.frame_type = Quic::Packet::QuicFrameType::CRYPTO
              e.reason_phrase = "Could not parse QUIC transport parameters"
            end
            raise err
          end

          # log event
          if @quic_logger && !from_session_ticket
            @quic_logger.log_event(
              category: "transport",
              event: "parameters_set",
              data: @quic_logger.encode_transport_parameters(owner: "remote", parameters: quic_transport_parameters),
            )
          end

          # validate remote parameters
          unless @is_client
            %w[original_destination_connection_id preferred_address retry_source_connection_id stateless_reset_token].each do |att|
              if quic_transport_parameters[att]
                err = QuicConnectionError.new.tap do |e|
                  e.error_code = Quic::Packet::QuicErrorCode::TRANSPORT_PARAMETER_ERROR
                  e.frame_type = Quic::Packet::QuicFrameType::CRYPTO
                  e.reason_phrase = "#{att} is not allowed for clients"
                end
                raise err
              end
            end
          end

          unless from_session_ticket
            if quic_transport_parameters.initial_source_connection_id != @remote_initial_source_connection_id
              err = QuicConnectionError.new.tap do |e|
                e.error_code = Quic::Packet::QuicErrorCode::TRANSPORT_PARAMETER_ERROR
                e.frame_type = Quic::Packet::QuicFrameType::CRYPTO
                e.reason_phrase = "initial_source_connection_id does not match"
              end
              raise err
            end

            if @is_client && quic_transport_parameters.original_destination_connection_id != @original_destination_connection_id
              err = QuicConnectionError.new.tap do |e|
                e.error_code = Quic::Packet::QuicErrorCode::TRANSPORT_PARAMETER_ERROR
                e.frame_type = Quic::Packet::QuicFrameType::CRYPTO
                e.reason_phrase = "original_source_connection_id does not match"
              end
              raise err
            end

            if @is_client && quic_transport_parameters.retry_source_connection_id != @retry_source_connection_id
              err = QuicConnectionError.new.tap do |e|
                e.error_code = Quic::Packet::QuicErrorCode::TRANSPORT_PARAMETER_ERROR
                e.frame_type = Quic::Packet::QuicFrameType::CRYPTO
                e.reason_phrase = "retry_source_connection_id does not match"
              end
              raise err
            end

            if quic_transport_parameters.active_connection_id_limit && quic_transport_parameters.active_connection_id_limit.to_i < 2
              err = QuicConnectionError.new.tap do |e|
                e.error_code = Quic::Packet::QuicErrorCode::TRANSPORT_PARAMETER_ERROR
                e.frame_type = Quic::Packet::QuicFrameType::CRYPTO
                e.reason_phrase = "active_connection_id_limit must be no less than 2"
              end
              raise err
            end

            if quic_transport_parameters.ack_delay_exponent && quic_transport_parameters.ack_delay_exponent > 20
              err = QuicConnectionError.new.tap do |e|
                e.error_code = Quic::Packet::QuicErrorCode::TRANSPORT_PARAMETER_ERROR
                e.frame_type = Quic::Packet::QuicFrameType::CRYPTO
                e.reason_phrase = "ack_delay_exponent must be <= 20"
              end
              raise err
            end

            if quic_transport_parameters.max_ack_delay && quic_transport_parameters.max_ack_delay >= 2**14
              err = QuicConnectionError.new.tap do |e|
                e.error_code = Quic::Packet::QuicErrorCode::TRANSPORT_PARAMETER_ERROR
                e.frame_type = Quic::Packet::QuicFrameType::CRYPTO
                e.reason_phrase = "max_ack_delay must be < 2^14"
              end
              raise err
            end

            if quic_transport_parameters.max_udp_payload_size && quic_transport_parameters.max_udp_payload_size < 1200
              err = QuicConnectionError.new.tap do |e|
                e.error_code = Quic::Packet::QuicErrorCode::TRANSPORT_PARAMETER_ERROR
                e.frame_type = Quic::Packet::QuicFrameType::CRYPTO
                e.reason_phrase = "max_udp_payload_size must be >= 1200"
              end
              raise err
            end
          end

          # store remote parameters
          unless from_session_ticket
            # TODO: check original implementation
            @remote_ack_delay_exponent = quic_transport_parameters.ack_delay_exponent if quic_transport_parameters.ack_delay_exponent
            @loss.max_ack_delay = quic_transport_parameters.max_ack_delay / 1000.0 if quic_transport_parameters.max_ack_delay

            if @is_client && @peer_cid.sequence_number == 0 && quic_transport_parameters.stateless_reset_token
              @peer_cid.stateless_reset_token = quic_transport_parameters.stateless_reset_token
            end
          end

          if quic_transport_parameters.active_connection_id_limit
            @remote_active_connection_id_limit = quic_transport_parameters.active_connection_id_limit.to_i
          end

          if quic_transport_parameters.max_idle_timeout
            @remote_max_idle_timeout = quic_transport_parameters.max_idle_timeout / 1000.0
          end

          @remote_max_datagram_frame_size = quic_transport_parameters.max_datagram_frame_size

          %w[max_data max_stream_data_bidi_local max_stream_data_bidi_remote max_stream_data_uni max_streams_bidi max_streams_uni].each do |param|
            value = quic_transport_parameters["initial_#{param}"]
            instance_variable_set("@remote_#{param}", value) if value
          end
        end

        private def serialize_transport_parameters
          quic_transport_parameters = Quic::Packet::QuicTransportParameters.new.tap do |param|
            param.ack_delay_exponent = @local_ack_delay_exponent
            param.active_connection_id_limit = @local_active_connection_id_limit
            param.max_idle_timeout = (@configuration.idle_timeout * 1000).to_i
            param.initial_max_data = @local_max_data.value
            param.initial_max_stream_data_bidi_local = @local_max_stream_data_bidi_local
            param.initial_max_stream_data_bidi_remote = @local_max_stream_data_bidi_remote
            param.initial_max_stream_data_uni = @local_max_stream_data_uni
            param.initial_max_streams_bidi = @local_max_streams_bidi.value
            param.initial_max_streams_uni = @local_max_streams_uni.value
            param.initial_source_connection_id = @local_initial_source_connection_id
            param.max_ack_delay = 25
            param.max_datagram_frame_size = @configuration.max_datagram_frame_size
            param.quantum_readiness = @configuration.quantam_readiness_test ? "Q" * 1200 : nil
            param.stateless_reset_token = @host_cids[0].stateless_reset_token
          end
          unless @is_client
            quic_transport_parameters.original_destination_connection_id = @original_destination_connection_id
            quic_transport_parameters.retry_source_connection_id = @retry_source_connection_id
          end

          # log event
          if @quic_logger
            @quic_logger.log_event(
              category: "transport",
              event: "parameters_set",
              data: @quic_logger.encode_transport_parameters(owner: "local", parameters: quic_transport_parameters)
            )
          end

          buf = Buffer.new(capacity: 3 * Quic::PacketBuilder::PACKET_MAX_SIZE)
          Quic::Packet.push_quic_transport_parameters(buf: buf, params: quic_transport_parameters)
          return buf.data
        end

        private def set_state(state)
          # TODO: logging
          @state = state
        end

        private def stream_can_receive(stream_id)
          Connection.stream_is_client_initiated(stream_id) != @is_client || !Connection.stream_is_unidirectional(stream_id)
        end

        private def stream_can_send(stream_id)
          Connection.stream_is_client_initiated(stream_id) == @is_client || !Connection.stream_is_unidirectional(stream_id)
        end

        private def unblock_streams(is_unidirectional)
          if is_unidirectional
            max_stream_data_remote = @remote_max_stream_data_uni
            max_streams = @remote_max_streams_uni
            streams_blocked = @streams_blocked_uni
          else
            max_stream_data_remote = @remote_max_stream_data_bidi_remote
            max_streams = @remote_max_streams_bidi
            streams_blocked = @streams_blocked_bidi
          end

          while streams_blocked && streams_blocked[0] && streams_blocked[0].stream_id.div(4) < max_streams
            stream = streams_blocked.delete_at(0)
            stream.is_blocked = false
            stream.max_stream_data_remote = max_stream_data_remote
          end

          @streams_blocked_pending = false if !@streams_blocked_bidi && !@streams_blocked_uni
        end

        # Callback which is invoked by the TLS engine when new traffic keys are available.
        private def update_traffic_key(direction:, epoch:, cipher_suite:, secret:)
          secrets_log_file = @configuration.secrets_log_file
          if secrets_log_file
            # TODO: logging to file
          end
          crypto = @cryptos[epoch]
          if direction == TLS::Direction::ENCRYPT
            crypto.send.setup(cipher_suite: cipher_suite, secret: secret, version: @version)
          else
            crypto.recv.setup(cipher_suite: cipher_suite, secret: secret, version: @version)
          end
        end

        private def write_application(builder:, network_path:, now:)
          # binding.b
          puts "write_application called (client)" if @is_client
          puts "write_application called (server)" unless @is_client
          crypto_stream = nil
          if @cryptos[TLS::Epoch::ONE_RTT].send.is_valid
            crypto = @cryptos[TLS::Epoch::ONE_RTT]
            crypto_stream = @crypto_streams[TLS::Epoch::ONE_RTT]
            packet_type = Quic::Packet::PACKET_TYPE_ONE_RTT
          elsif @cryptos[TLS::Epoch::ZERO_RTT].send.is_valid
            crypto = @cryptos[TLS::Epoch::ZERO_RTT]
            packet_type = Quic::Packet::PACKET_TYPE_ZERO_RTT
          else
            return
          end
          space = @spaces[TLS::Epoch::ONE_RTT]

          c = -1
          while true
            c += 1
            puts "while loop #{c}"
            # binding.b
            # binding.irb unless @is_client
            # apply pacing, except if we have ACKs to send
            if space.ack_at.nil? || space.ack_at >= now
              @pacing_at = @loss.pacer.next_send_time(now: now)
              puts "!!!!break!!!!" if @pacing_at
              break if @pacing_at
            end
            puts "PacketBuilder#start_packet called from write_application"
            pp packet_type
            # binding.b
            builder.start_packet(packet_type: packet_type, crypto: crypto)

            if @handshake_complete
              # ACK
              write_ack_frame(builder: builder, space: space, now: now) if space.ack_at && space.ack_at <= now

              # HANDSHAKE_DONE
              if @handshake_done_pending
                write_handshake_done_frame(builder: builder)
                @handshake_done_pending = false
              end

              # PATH CHALLENGE
              if !network_path.is_validated && network_path.local_challenge.nil?
                challenge = Random.urandom(8)
                write_path_challenge_frame(builder: builder, challenge: challenge)
                network_path.local_challenge = challenge
              end

              # PATH RESPONSE
              if network_path.remote_challenge
                write_path_response_frame(builder: builder, challenge: network_path.remote_challenge)
                network_path.remote_challenge = nil
              end

              # NEW_CONNECTION_ID
              pp @host_cids unless @is_client
              @host_cids.each do |connection_id|
                pp connection_id unless @is_client
                unless connection_id.was_sent
                  puts "write_new_connection_id write_application" unless @is_client
                  write_new_connection_id_frame(builder: builder, connection_id: connection_id)
                end
                # write_new_connection_id_frame(builder: builder, connection_id: connection_id) unless connection_id.was_sent
              end

              # RETIRE_CONNECTION_ID
              @retire_connection_ids.each do |sequence_number|
                write_retire_connection_id_frame(builder: builder, sequence_number: sequence_number)
              end
              @retire_connection_ids.clear

              # STREAMS_BLOCKED
              if @streams_blocked_pending
                if @streams_blocked_bidi
                  write_streams_blocked_frame(
                    builder: builder, frame_type: Quic::Packet::QuicFrameType::STREAMS_BLOCKED_BIDI, limit: @remote_max_streams_bidi,
                  )
                end
                if @streams_blocked_uni
                  write_streams_blocked_frame(
                    builder: builder, frame_type: Quic::Packet::QuicFrameType::STREAMS_BLOCKED_UNI, limit: @remote_max_streams_uni,
                  )
                end
                @streams_blocked_pending = false
              end

              # MAX_DATA and MAX_STREAMS
              write_connection_limits(builder: builder, space: space)
            end

            # stream-level limits
            @streams.each_value { |stream| write_stream_limits(builder: builder, space: space, stream: stream) }

            # PING (user-request)
            if @ping_pending.size > 0
              write_ping_frame(builder: builder, uids: @ping_pending)
              @ping_pending.clear
            end

            # PING (probe)
            if @probe_pending
              write_ping_frame(builder: builder, comment: "probe")
              @probe_pending = false
            end

            # CRYPTO
            if crypto_stream && !crypto_stream.sender.buffer_is_empty
              write_crypto_frame(builder: builder, space: space, stream: crypto_stream)
            end

            # DATAGRAM
            while @datagrams_pending.length > 0
              begin
                write_datagram_frame(builder: builder, data: @datagrams_pending[0], frame_type: Quic::Packet::QuicFrameType::DATAGRAM_WITH_LENGTH)
                @datagrams_pending.pop
              rescue Quic::PacketBuilder::QuicPacketBuilderStop
                puts "!!!!stop break!!!!"
                break
              end
            end

            @streams.each_value do |stream|
              # if the stream is finished, discard it
              if stream.is_finished
                # TODO: logging
                @streams.delete(stream.stream_id)
                @streams_finished << stream.stream_id
                next
              end

              # STOP_SENDING
              write_stop_sending_frame(builder: builder, stream: stream) if stream.receiver.stop_pending

              if stream.sender.reset_pending
                # RESET_STREAM
                write_reset_stream_frame(builder: builder, stream: stream)
              elsif !stream.is_blocked && !stream.sender.buffer_is_empty
                # STREAM
                @remote_max_data_used += write_stream_frame(
                  builder: builder,
                  space: space,
                  stream: stream,
                  max_offset: [stream.sender.highest_offset + @remote_max_data - @remote_max_data_used, stream.max_stream_data_remote].min,
                )
              end
            end
            # puts "builder.packer_is_emprty: #{builder.packet_is_empty}"
            if builder.packet_is_empty
              puts "!!!!empty break!!!!"
              break
            else
              @loss.pacer.update_after_send(now: now)
            end
          end
        end

        private def write_handshake(builder:, epoch:, now:)
          crypto = @cryptos[epoch]
          return unless crypto.send.is_valid

          crypto_stream = @crypto_streams[epoch]
          space = @spaces[epoch]

          while true
            if epoch == TLS::Epoch::INITIAL
              packet_type = Quic::Packet::PACKET_TYPE_INITIAL
            else
              packet_type = Quic::Packet::PACKET_TYPE_HANDSHAKE
            end
            puts "PacketBuilder#start_packet called from write_handshake"
            builder.start_packet(packet_type: packet_type, crypto: crypto)

            # ACK
            write_ack_frame(builder: builder, space: space, now: now) if space.ack_at

            # CRYPTO
            unless crypto_stream.sender.buffer_is_empty
              if write_crypto_frame(builder: builder, space: space, stream: crypto_stream)
                @probe_pending = false
              end
            end

            # PING (probe)
            if @probe_pending && !@handshake_complete && (epoch == TLS::Epoch::HANDSHAKE || !@cryptos[TLS::Epoch::HANDSHAKE].send.is_valid)
              write_ping_frame(builder: builder, comment: "probe")
              @probe_pending = false
            end

            break if builder.packet_is_empty
          end
        end

        private def write_ack_frame(builder:, space:, now:)
          # calculate AKC delay
          ack_delay = now - space.largest_received_time
          ack_delay_encoded = (ack_delay * 1000000).to_i >> @local_ack_delay_exponent

          buf = builder.start_frame(
            frame_type: Quic::Packet::QuicFrameType::ACK,
            capacity: ACK_FRAME_CAPACITY,
            handler: method(:on_ack_delivery),
            handler_args: [space, space.largest_received_packet],
          )
          ranges = Quic::Packet.push_ack_frame(buf: buf, rangeset: space.ack_queue, delay: ack_delay_encoded)
          space.ack_at = nil

          # log frame
          builder.quic_logger_frames << @quic_logger.encode_ack_frame(ranges: space.ack_queue, delay: ack_delay) if @quic_logger

          # check if we need to trigger an ACK-of-ACK
          write_ping_frame(builder: builder, comment: "ACK-of-ACK trigger") if ranges > 1 && builder.packet_number % 8 == 0
        end

        private def write_connection_close_frame(builder:, epoch:, error_code:, frame_type: nil, reason_phrase: "")
          # convert application-level close to transport-level close in early stages
          ec = error_code
          ft = frame_type
          rp = reason_phrase
          if frame_type.nil? && [TLS::Epoch::INITIAL, TLS::Epoch::HANDSHAKE].include?(epoch)
            ec = Quic::Packet::QuicErrorCode::APPLICATION_ERROR
            ft = Quic::Packet::QuicFrameType::PADDING
            rp = ""
          end
          reason_bytes = rp # encode to utf8 bytes in original code
          # binding.irb if reason_bytes.nil?
          reason_length = reason_bytes.bytesize

          unless ft
            buf = builder.start_frame(
              frame_type: Quic::Packet::QuicFrameType::APPLICATION_CLOSE, capacity: APPLICATION_CLOSE_FRAME_CAPACITY + reason_length,
            )
            buf.push_uint_var(ec)
            buf.push_uint_var(reason_length)
            buf.push_bytes(reason_bytes)
          else
            buf = builder.start_frame(
              frame_type: Quic::Packet::QuicFrameType::TRANSPORT_CLOSE, capacity: TRANSPORT_CLOSE_FLAME_CAPACITY + reason_length,
            )
            buf.push_uint_var(ec)
            buf.push_uint_var(ft)
            buf.push_uint_var(reason_length)
            buf.push_bytes(reason_bytes)
          end
          # log frame
          if @quic_logger
            builder.quic_logger_frames << @quic_logger.encode_connection_close_frame(error_code: error_code, frame_type: frame_type, reason_phrase: reason_phrase)
          end
        end

        # Raise MAX_DATA or MAX_STREAMS if needed.
        private def write_connection_limits(builder:, space:)
          [@local_max_data, @local_max_streams_bidi, @local_max_streams_uni].each do |limit|
            if limit.used * 2 > limit.value
              limit.value *= 2
              # TODO: logging
            end
            if limit.value != limit.sent
              buf = builder.start_frame(
                frame_type: limit.frame_type,
                capacity: CONNECTION_LIMIT_FRAME_CAPACITY,
                handler: method(:on_connection_limit_delivery),
                handler_args: [limit, nil],
              )
              buf.push_uint_var(limit.value)
              limit.sent = limit.value

              # log frame
              builder.quic_logger_frames << @quic_logger.encode_connection_limit_frame(frame_type: limit.frame_type, maximum: limit.value) if @quic_logger
            end
          end
        end

        private def write_crypto_frame(builder:, space:, stream:)
          # binding.b
          frame_overhead = 3 + Buffer.size_uint_var(stream.sender.next_offset)
          frame = stream.sender.get_frame(max_size: builder.remaining_flight_space - frame_overhead)
          if frame
            buf = builder.start_frame(
              frame_type: Quic::Packet::QuicFrameType::CRYPTO,
              capacity: frame_overhead,
              handler: stream.sender.method(:on_data_delivery),
              handler_args: [frame.offset, frame.offset + frame.data.bytesize],
            )
            buf.push_uint_var(frame.offset)
            buf.push_uint16(frame.data.bytesize | 0x4000)
            buf.push_bytes(frame.data)

            # log frame
            builder.quic_logger_frames << @quic_logger.encode_crypto_frame(frame: frame) if @quic_logger

            return true
          end
          return false
        end

        # Write a DATAGRAM frame.
        #
        # Returns true if the frame was processed, false otherwise.
        private def write_datagram_frame(builder:, data:, frame_type:)
          raise RuntimeError unless frame_type == Quic::Packet::QuicFrameType::DATAGRAM_WITH_LENGTH

          length = data&.bytesize || 0
          frame_size = 1 + Buffer.size_uint_var(length) + length

          buf = builder.start_frame(frame_type: frame_type, capacity: frame_size)
          buf.push_uint_var(length)
          buf.push_bytes(data)

          # log frame
          builder.quic_logger_frames << @quic_logger.encode_datagram_frame(length: length) if @quic_logger

          return true
        end

        private def write_handshake_done_frame(builder:)
          builder.start_frame(
            frame_type: Quic::Packet::QuicFrameType::HANDSHAKE_DONE,
            capacity: HANDSHAKE_DONE_FRAME_CAPACITY,
            handler: method(:on_handshake_done_delivery),
          )

          # log frame
          builder.quic_logger_frames << @quic_logger.encode_handshake_done_frame if @quic_logger
        end

        private def write_new_connection_id_frame(builder:, connection_id:)
          puts "write_new_connection_id_frame (server)" unless @is_client
          retire_prior_to = 0 # FIXME: from original

          buf = builder.start_frame(
            frame_type: Quic::Packet::QuicFrameType::NEW_CONNECTION_ID,
            capacity: NEW_CONNECTION_ID_FRAME_CAPACITY,
            handler: method(:on_new_connection_id_delivery),
            handler_args: [connection_id],
          )
          buf.push_uint_var(connection_id.sequence_number)
          buf.push_uint_var(retire_prior_to)
          buf.push_uint8(connection_id.cid.bytesize)
          buf.push_bytes(connection_id.cid)
          buf.push_bytes(connection_id.stateless_reset_token)

          connection_id.was_sent = true
          @events.append(Event::ConnectionIdIssued.new.tap { |e| e.connection_id = connection_id.cid })

          # log frame
          if @quic_logger
            builder.quic_logger_frames << @quic_logger.encode_new_connection_id_frame(
              connection_id: connection_id.cid,
              retire_prior_to: retire_prior_to,
              sequence_number: connection_id.sequence_number,
              stateless_reset_token: connection_id.stateless_reset_token,
            )
          end
        end

        private def write_path_challenge_frame(builder:, challenge:)
          buf = builder.start_frame(
            frame_type: Quic::Packet::QuicFrameType::PATH_CHALLENGE,
            capacity: PATH_CHALLENGE_FRAME_CAPACITY,
          )
          buf.push_bytes(challenge)

          # log frame
          builder.quic_logger_frames << @quic_logger.encode_path_challenge_frame(data: challenge) if @quic_logger
        end

        private def write_path_response_frame(builder:, challenge:)
          buf = builder.start_frame(
            frame_type: Quic::Packet::QuicFrameType::PATH_RESPONSE,
            capacity: PATH_RESPONSE_FRAME_CAPACITY,
          )
          buf.push_bytes(challenge)

          # log frame
          builder.quic_logger_frames << @quic_logger.encode_path_response_frame(data: challenge) if @quic_logger
        end

        private def write_ping_frame(builder:, uids: [], comment: "")
          builder.start_frame(
            frame_type: Quic::Packet::QuicFrameType::PING,
            capacity: PING_FRAME_CAPACITY,
            handler: method(:on_ping_delivery),
            handler_args: [uids.dup],
          )

          # log frame
          builder.quic_logger_frames << @quic_logger.encode_ping_frame if @quic_logger
        end

        private def write_reset_stream_frame(builder:, stream:)
          buf = builder.start_frame(
            frame_type: Quic::Packet::QuicFrameType::RESET_STREAM,
            capacity: RESET_STREAM_FRAME_CAPACITY,
            handler: stream.sender.method(:on_reset_delivery),
          )
          frame = stream.sender.get_reset_frame
          buf.push_uint_var(frame.stream_id)
          buf.push_uint_var(frame.error_code)
          buf.push_uint_var(frame.final_size)
        
          # log frame
          if @quic_logger
            builder.quic_logger_frames << @quic_logger.encode_reset_stream_frame(error_code: frame.error_code, final_size: frame.final_size, stream_id: frame.stream_id)
          end
        end

        private def write_retire_connection_id_frame(builder:, sequence_number:)
          buf = builder.start_frame(
            frame_type: Quic::Packet::QuicFrameType::RETIRE_CONNECTION_ID,
            capacity: RETIRE_CONNECTION_ID_CAPACITY,
            handler: method(:on_retire_connection_id_delivery),
            handler_args: [sequence_number],
          )
          buf.push_uint_var(sequence_number)

          # log frame
          builder.quic_logger_frames << @quic_logger.encode_retire_connection_id_frame(sequence_number: sequence_number) if @quic_logger
        end

        private def write_stop_sending_frame(builder:, stream:)
          buf = builder.start_frame(
            frame_type: Quic::Packet::QuicFrameType::STOP_SENDING,
            capacity: STOP_SENDING_FRAME_CAPACITY,
            handler: stream.receiver.method(:on_stop_sending_delivery),
          )
          frame = stream.receiver.get_stop_frame
          buf.push_uint_var(frame.stream_id)
          buf.push_uint_var(frame.error_code)

          # log frame
          builder.quic_logger_frames << @quic_logger.encode_stop_sending_frame(error_code: frame.error_code, stream_id: frame.stream_id) if @quic_logger
        end

        private def write_stream_frame(builder:, space:, stream:, max_offset:)
          # the frame data size is constrained by our peer's MAX_DATA and the space available in the current packet
          frame_overhead = 3 +
            Buffer.size_uint_var(stream.stream_id) +
            (stream.sender.next_offset ? Buffer.size_uint_var(stream.sender.next_offset) : 0)
          previous_send_highest = stream.sender.highest_offset
          frame = stream.sender.get_frame(max_size: builder.remaining_flight_space - frame_overhead, max_offset: max_offset)

          if frame
            frame_type = Quic::Packet::QuicFrameType::STREAM_BASE | 2 # length
            frame_type = frame_type | 4 if frame.offset
            frame_type = frame_type | 1 if frame.fin
            buf = builder.start_frame(
              frame_type: frame_type,
              capacity: frame_overhead,
              handler: stream.sender.method(:on_data_delivery),
              handler_args: [frame.offset, frame.offset + frame.data.bytesize],
            )
            buf.push_uint_var(stream.stream_id)
            buf.push_uint_var(frame.offset) if frame.offset
            buf.push_uint16(frame.data.bytesize | 0x4000)
            buf.push_bytes(frame.data)

            # log frame
            builder.quic_logger_frames << @quic_logger.encode_stream_frame(frame: frame, stream_id: stream.stream_id) if @quic_logger

            return stream.sender.highest_offset - previous_send_highest
          else
            return 0
          end
        end

        # Raise MAX_STREAM_DATA if needed.
        #
        # The only case where `stream.max_stream_data_local` is zero is for locally created unidirectional streams.
        # We skip such streams to avoid spurious logging.
        private def write_stream_limits(builder:, space:, stream:)
          if stream.max_stream_data_local > 0 && stream.receiver.highest_offset * 2 > stream.max_stream_data_local
            # binding.irb if stream.max_stream_data_local > 1000
            stream.max_stream_data_local *= 2
            # TODO: logging
          end

          if stream.max_stream_data_local_sent != stream.max_stream_data_local
            buf = builder.start_frame(
              frame_type: Quic::Packet::QuicFrameType::MAX_STREAM_DATA,
              capacity: MAX_STREAM_DATA_FRAME_CAPACITY,
              handler: method(:on_max_stream_data_delivery),
              handler_args: [stream],
            )
            buf.push_uint_var(stream.stream_id)
            buf.push_uint_var(stream.max_stream_data_local)
            stream.max_stream_data_local_sent = stream.max_stream_data_local

            # log frame
            if @quic_logger
              builder.quic_logger_frames << @quic_logger.encode_max_stream_data_frame(maximum: stream.max_stream_data_local, stream_id: stream.stream_id)
            end
          end
        end

        private def write_streams_blocked_frame(builder:, frame_type:, limit:)
          buf = builder.start_frame(frame_type: frame_type, capacity: STREAMS_BLOCKED_CAPACITY)
          buf.push_uint_var(limit)

          # log frame
          if @quic_logger
            builder.quic_logger_frames << @quic_logger.encode_streams_blocked_frame(
              is_unidirectional: (frame_type == Quic::Packet::QuicFrameType::STREAMS_BLOCKED_UNI),
              limit: limit,
            )
          end
        end
      end
    end
  end
end
