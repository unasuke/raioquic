# frozen_string_literal: true

module Raioquic
  module Quic
    module Recovery
      # loss detection
      K_PACKET_THRESHOLD = 3
      K_GRANULARITY = 0.001 # seconds
      K_TIME_THRESHOLD = 9 / 8.0
      K_MICRO_SECOND = 0.000001
      K_SECOND = 1.0

      # congestion control
      K_MAX_DATAGRAM_SIZE = 1280
      K_INITIAL_WINDOW = 10 * K_MAX_DATAGRAM_SIZE
      K_MINIMUM_WINDOW = 2 * K_MAX_DATAGRAM_SIZE
      K_LOSS_REDUCTION_FACTOR = 0.5

      # QuicPacketSpace
      class QuicPacketSpace
        attr_accessor :sent_packets
        attr_accessor :ack_at
        attr_accessor :ack_eliciting_in_flight
        attr_accessor :loss_time
        attr_accessor :largest_acked_packet
        attr_accessor :expected_packet_number
        attr_accessor :largest_received_packet
        attr_accessor :largest_received_time
        attr_accessor :ack_queue
        attr_accessor :discarded

        def initialize
          @ack_at = nil
          @ack_queue = Rangeset.new
          @discarded = false
          @expected_packet_number = 0
          @largest_received_packet = -1
          @largest_received_time = nil

          # sent packets and loss
          @ack_eliciting_in_flight = 0
          @largest_acked_packet = 0
          @loss_time = nil
          @sent_packets = {}
        end
      end

      # QuicPacketPacer
      class QuicPacketPacer
        attr_reader :bucket_max
        attr_reader :bucket_time
        attr_reader :packet_time

        def initialize
          @bucket_max = 0.0
          @bucket_time = 0.0
          @evaluation_time = 0.0
          @packet_time = nil
        end

        def next_send_time(now:)
          if @packet_time
            update_bucket(now: now)
            return now + @packet_time if @bucket_time <= 0.0
          end
          return nil
        end

        def update_after_send(now:)
          if @packet_time # rubocop:disable Style/GuardClause
            update_bucket(now: now)
            if @bucket_time < @packet_time
              @bucket_time = 0.0
            else
              @bucket_time -= @packet_time
            end
          end
        end

        def update_bucket(now:)
          if now > @evaluation_time # rubocop:disable Style/GuardClause
            @bucket_time = [@bucket_time + (now - @evaluation_time), @bucket_max].min
            @evaluation_time = now
          end
        end

        def update_rate(congestion_window:, smoothed_rtt:)
          pacing_rate = congestion_window / [smoothed_rtt, K_MICRO_SECOND].max
          @packet_time = [K_MICRO_SECOND, [K_MAX_DATAGRAM_SIZE / pacing_rate, K_SECOND].min].max

          @bucket_max = [2 * K_MAX_DATAGRAM_SIZE, [(congestion_window / 4).floor(1), 16 * K_MAX_DATAGRAM_SIZE].min].max / pacing_rate

          @bucket_time = @bucket_max if @bucket_time > @bucket_max
        end
      end

      # New Reno congestion control.
      class QuicCongestionControl
        attr_reader :bytes_in_flight
        attr_reader :congestion_window
        attr_reader :ssthresh

        def initialize
          @bytes_in_flight = 0
          @congestion_window = K_INITIAL_WINDOW
          @congestion_recovery_start_time = 0.0
          @congestion_stash = 0
          @rtt_monitor = QuicRttMonitor.new
          @ssthresh = nil
        end

        def on_packet_acked(packet:)
          @bytes_in_flight -= packet.sent_bytes

          # don't increase window in congestion recovery
          return if packet.sent_time <= @congestion_recovery_start_time

          if @ssthresh.nil? || @congestion_window < @ssthresh
            # slow start
            @congestion_window += packet.sent_bytes
          else
            # congestion avoidance
            @congestion_stash += packet.sent_bytes
            count = (@congestion_stash / @congestion_window.to_f).floor(1)
            if count > 0.0
              @congestion_stash -= count * @congestion_window
              @congestion_window += count * K_MAX_DATAGRAM_SIZE
            end
          end
        end

        def on_packet_sent(packet:)
          @bytes_in_flight += packet.sent_bytes
        end

        def on_packets_expired(packets:)
          packets.each { |packet| @bytes_in_flight -= packet.sent_bytes }
        end

        def on_packets_lost(packets:, now:)
          lost_largest_time = 0.0
          packets.each do |packet|
            @bytes_in_flight -= packet.sent_bytes
            lost_largest_time = packet.sent_time
          end

          # start a new congestion event if packet was sent after the
          # start of the previous congestioon recovery period.
          if lost_largest_time > @congestion_recovery_start_time # rubocop:disable Style/GuardClause
            @congestion_recovery_start_time = now
            @congestion_window = [(@congestion_window * K_LOSS_REDUCTION_FACTOR).to_i, K_MINIMUM_WINDOW].max
            @ssthresh = @congestion_window
          end
          # TODO: collapse congestion window if persistent congestion (from aioquic)
        end

        def on_rtt_measurement(latest_rtt:, now:)
          if @ssthresh.nil? && @rtt_monitor.is_rtt_increasing(rtt: latest_rtt, now: now) # rubocop:disable Style/GuardClause
            @ssthresh = @congestion_window
          end
        end
      end

      # Packet loss and congestion controller.
      class QuicPacketRecovery
        attr_reader :rtt_initialized
        attr_reader :rtt_latest
        attr_reader :rtt_min
        attr_reader :rtt_smoothed

        attr_accessor :spaces
        attr_accessor :peer_completed_address_validation
        attr_accessor :pacer
        attr_accessor :max_ack_delay

        def initialize(initial_rtt:, peer_completed_address_validation:, send_probe: nil, logger: nil, quic_logger: nil)
          @max_ack_delay = 0.025
          @peer_completed_address_validation = peer_completed_address_validation
          @spaces = []

          # callbacks
          @logger = logger
          @quic_logger = quic_logger
          @send_probe = send_probe

          # loss detection
          @pto_count = 0
          @rtt_initial = initial_rtt
          @rtt_initialized = false
          @rtt_latest = 0.0
          @rtt_min = Float::INFINITY
          @rtt_smoothed = 0.0
          @rtt_variance = 0.0
          @time_of_last_sent_ack_eliciting_packet = 0.0

          # congestion control
          @cc = QuicCongestionControl.new
          @pacer = QuicPacketPacer.new
        end

        def bytes_in_flight = @cc.bytes_in_flight

        def congestion_window = @cc.congestion_window

        def discard_space(space:)
          raise ArgumentError unless @spaces.include?(space)

          @cc.on_packets_expired(packets: space.sent_packets.values.filter(&:in_flight))
          space.sent_packets.clear
          space.ack_at = nil
          space.ack_eliciting_in_flight = 0
          space.loss_time = nil

          # rest PTO count
          @pto_count = 0

          # TODO: logger
        end

        def get_loss_detection_time
          # loss timer
          loss_space = get_loss_space
          return loss_space.loss_time if loss_space

          # packet timer
          if !peer_completed_address_validation || @spaces.sum(&:ack_eliciting_in_flight) > 0
            timeout = get_probe_timeout * (2**@pto_count)
            return @time_of_last_sent_ack_eliciting_packet + timeout
          end

          return nil
        end

        def get_probe_timeout
          return 2 * @rtt_initial unless @rtt_initialized

          return @rtt_smoothed + [4 * @rtt_variance, K_GRANULARITY].max + @max_ack_delay
        end

        # Update metrics as the result of an ACK being received.
        def on_ack_received(space:, ack_rangeset:, ack_delay:, now:) # rubocop:disable Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity, Metrics/MethodLength
          is_ack_eliciting = false
          largest_acked = ack_rangeset.bounds.last - 1
          largest_newly_acked = nil
          largest_sent_time = nil
          log_rtt = nil

          space.largest_acked_packet = largest_acked if largest_acked > space.largest_acked_packet

          space.sent_packets.keys.sort.each do |packet_number|
            break if packet_number > largest_acked

            if ack_rangeset.in?(packet_number) # rubocop:disable Style/Next
              packet = space.sent_packets.delete(packet_number)

              if packet.is_ack_eliciting
                is_ack_eliciting = true
                space.ack_eliciting_in_flight -= 1
              end

              @cc.on_packet_acked(packet: packet) if packet.in_flight

              largest_newly_acked = packet_number
              largest_sent_time = packet.sent_time

              # trigger callbacks
              packet.delivery_handlers&.each do |handler|
                # TODO: hmm...
                delivery = Quic::PacketBuilder::QuicDeliveryState::ACKED
                case handler[0]&.name
                when :on_data_delivery
                  handler[0].call(delivery: delivery, start: handler[1][0], stop: handler[1][1])
                when :on_ack_delivery
                  handler[0].call(delivery: delivery, space: handler[1][0], highest_acked: handler[1][1])
                when :on_new_connection_id_delivery
                  handler[0].call(delivery: delivery, connection_id: handler[1][0])
                when :on_handshake_done_delivery, :on_reset_delivery, :on_stop_sending_delivery
                  handler[0].call(delivery: delivery)
                when :on_ping_delivery
                  handler[0].call(delivery: delivery, uids: handler[1][0])
                when :on_connection_limit_delivery
                  handler[0].call(delivery: delivery, limit: handler[1][0])
                when :on_retire_connection_id_delivery
                  handler[0].call(delivery: delivery, sequence_number: handler[1][0])
                else
                  raise NotImplementedError, handler[0]
                end
              end
            end
          end

          return if largest_newly_acked.nil?

          if largest_acked == largest_newly_acked && is_ack_eliciting
            latest_rtt = now - largest_sent_time
            log_rtt = true

            # limit ACK delay to max_ack_delay
            ack_delay = [ack_delay, @max_ack_delay].min

            # update RTT estimate, which cannot be < 1 ms
            @rtt_latest = [latest_rtt, 0.001].max
            @rtt_min = @rtt_latest if @rtt_latest < @rtt_min
            @rtt_latest -= ack_delay if @rtt_latest > @rtt_min + ack_delay

            if !@rtt_initialized # rubocop:disable Style/NegatedIfElseCondition
              @rtt_initialized = true
              @rtt_variance = latest_rtt / 2.0
              @rtt_smoothed = latest_rtt
            else
              @rtt_variance = (3.0 / 4.0 * @rtt_variance) + (1 / 4 * (@rtt_min - @rtt_latest).abs)
              @rtt_smoothed - (7.0 / 8.0 * @rtt_smoothed) + (1 / 8 * @rtt_latest)
            end

            # inform congestion controller
            @cc.on_rtt_measurement(latest_rtt: latest_rtt, now: now)
            @pacer.update_rate(congestion_window: @cc.congestion_window, smoothed_rtt: @rtt_smoothed)
          else
            log_rtt = false
          end

          detect_loss(space: space, now: now)

          # reset PTO count
          @pto_count = 0

          log_metrics_updated(log_rtt) if @quic_logger
        end

        def on_loss_detection_timeout(now:)
          loss_space = get_loss_space
          if loss_space
            detect_loss(space: loss_space, now: now)
          else
            @pto_count += 1
            reschedule_data(now: now)
          end
        end

        def on_packet_sent(packet:, space:)
          space.sent_packets[packet.packet_number] = packet

          space.ack_eliciting_in_flight += 1 if packet.is_ack_eliciting

          if packet.in_flight # rubocop:disable Style/GuardClause
            @time_of_last_sent_ack_eliciting_packet = packet.sent_time if packet.is_ack_eliciting

            # add packet to bytes in flight
            @cc.on_packet_sent(packet: packet)
            log_metrics_updated if @quic_logger
          end
        end

        # Schedule some data for retransmission.
        def reschedule_data(now:)
          # if there is any outstanding CRYPTO, retransmit it
          crypto_scheduled = false
          @spaces.each do |space|
            packets = space.sent_packets.values.filter(&:is_crypto_packet)
            unless packets.empty?
              on_packets_lost(packets: packets, space: space, now: now)
              crypto_scheduled = true
            end
          end

          # TODO: logger debug if crypto_scheduled && @logger

          # ensure an ACK-eliciting packet is sent
          @send_probe&.call
        end

        # Check whether any packets should be declared lost.
        def detect_loss(space:, now:) # rubocop:disable Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity
          loss_delay = K_TIME_THRESHOLD * (@rtt_initialized ? [@rtt_latest, @rtt_smoothed].max : @rtt_initial)
          packet_threshold = space.largest_acked_packet - K_PACKET_THRESHOLD
          time_threshold = now - loss_delay

          lost_packets = []
          space.loss_time = nil

          space.sent_packets.each do |packet_number, packet|
            break if packet_number > space.largest_acked_packet

            if packet_number <= packet_threshold || packet.sent_time <= time_threshold
              lost_packets << packet
            else
              packet_loss_time = packet.sent_time + loss_delay
              space.loss_time = packet_loss_time.to_f if space.loss_time.nil? || space.loss_time > packet_loss_time
            end
          end
          on_packets_lost(packets: lost_packets, space: space, now: now)
        end

        def get_loss_space
          loss_space = nil
          @spaces.each do |space|
            loss_space = space if space.loss_time && (loss_space.nil? || space.loss_time < loss_space.loss_time)
          end
          return loss_space
        end

        def log_metrics_updated(log_rtt = false) # rubocop:disable Style/OptionalBooleanParameter
          data = {
            bytes_in_flight: @cc.bytes_in_flight,
            cwnd: @cc.congestion_window,
          }
          data[:ssthresh] = @cc.ssthresh if @cc.ssthresh
          if log_rtt # rubocop:disable Style/GuardClause
            data[:latest_rtt] = @quic_logger&.encode_time(@rtt_latest)
            data[:min_rtt] = @quic_logger&.encode_time(@rtt_min)
            data[:smoothed_rtt] = @quic_logger&.encode_time(@rtt_smoothed)
            data[:rtt_variance] = @quic_logger&.encode_time(@rtt_variance)
          end

          @quic_logger&.log_event(category: "recovery", event: "metrics_updated", data: data)
        end

        def on_packets_lost(packets:, space:, now:) # rubocop:disable Metrics/CyclomaticComplexity
          lost_packets_cc = []
          packets.each do |packet|
            space.sent_packets.delete(packet.packet_number)

            lost_packets_cc << packet if packet.in_flight
            space.ack_eliciting_in_flight -= 1 if packet.is_ack_eliciting

            if @quic_logger
              @quic_logger.log_event(
                category: "recovery",
                event: "packet_lost",
                data: {
                  type: @quic_logger.packet_type(packet.packet_type),
                  packet_number: packet.packet_number,
                },
              )
            end

            # trigger callbacks
            packet.delivery_handlers&.each do |handler|
              # TODO: hmm...
              case handler[0]&.name
              when :on_data_delivery
                handler[0].call(delivery: Quic::PacketBuilder::QuicDeliveryState::LOST, start: handler[1][0], stop: handler[1][1])
              when :on_ack_delivery
                handler[0].call(delivery: Quic::PacketBuilder::QuicDeliveryState::LOST, space: handler[1][0], highest_acked: handler[1][1])
              when :on_handshake_done_delivery
                handler[0].call(delivery: Quic::PacketBuilder::QuicDeliveryState::LOST)
              when :on_new_connection_id_delivery
                handler[0].call(delivery: Quic::PacketBuilder::QuicDeliveryState::LOST, connection_id: handler[1][0])
              when :on_connection_limit_delivery
                handler[0].call(delivery: Quic::PacketBuilder::QuicDeliveryState::LOST, limit: handler[1][0])
              else
                raise NotImplementedError, handler[0]
              end
            end
          end

          # inform congestion controller
          if lost_packets_cc # rubocop:disable Style/GuardClause
            @cc.on_packets_lost(packets: lost_packets_cc, now: now)
            @pacer.update_rate(congestion_window: @cc.congestion_window, smoothed_rtt: @rtt_smoothed)
            log_metrics_updated if @quic_logger
          end
        end
      end

      # Roundtrip time monitor for HyStart.
      class QuicRttMonitor
        attr_reader :samples
        attr_reader :ready
        attr_reader :increases

        def initialize
          @increases = 0
          @last_time = nil
          @ready = false
          @size = 5
          @filtered_min = nil
          @sample_idx = 0
          @sample_max = nil
          @sample_min = nil
          @sample_time = 0.0
          @samples = @size.times.map { 0.0 }
        end

        def add_rtt(rtt:)
          @samples[@sample_idx] = rtt
          @sample_idx += 1

          if @sample_idx >= @size
            @sample_idx = 0
            @ready = true
          end

          if @ready # rubocop:disable Style/GuardClause
            @sample_max = @samples[0]
            @sample_min = @samples[0]
            @samples[1..].each do |sample|
              @sample_min = sample if sample < @sample_min
              @sample_max = sample if sample > @sample_max
            end
          end
        end

        def is_rtt_increasing(rtt:, now:) # rubocop:disable Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity
          if now > @sample_time + K_GRANULARITY
            add_rtt(rtt: rtt)
            @sample_time = now

            if @ready
              @filtered_min = @sample_max if @filtered_min.nil? || @filtered_min > @sample_max

              delta = @sample_min - @filtered_min
              if delta * 4 >= @filtered_min
                @increases += 1
                return true if @increases >= @size # rubocop:disable Metrics/BlockNesting
              elsif delta > 0
                @increases = 0
              end
            end
          end
          return false
        end
      end
    end
  end
end
