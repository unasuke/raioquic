# frozen_string_literal: true

module Raioquic
  module Quic
    module Stream
      class FinalSizeError < StandardError
      end

      class StreamFinishedError < StandardError
      end

      # The receive part of a QUIC stream.
      #
      # It finishes:
      # - immediately for a send-only stream
      # - upon reception of a aSTREAM_RESET frame
      # - upon reception of a data frame with the FIN bit set
      class QuicStreamReceiver
        attr_reader :is_finished
        attr_reader :buffer
        attr_reader :ranges
        attr_reader :buffer_start
        attr_reader :highest_offset
        attr_reader :stop_pending

        def initialize(stream_id: nil, readable: false) # rubocop:disable Lint/UnusedMethodArgument
          @highest_offset = 0 # the highest offset ever seen
          @is_finished = false
          @stop_pending = false
          @buffer = +""
          @buffer_start = 0 # the offset for the start of the buffer
          @final_size = nil
          @ranges = Quic::Rangeset.new(ranges: [])
          @stream_id = stream_id
          @stop_error_code = nil
        end

        def get_stop_frame
          @stop_pending = false
          return Quic::Packet::QuicStopSendingFrame.new.tap do |frame|
            frame.error_code = @stop_error_code
            frame.stream_id = @stream_id
          end
        end

        # Handle a frame of received data.
        def handle_frame(frame:) # rubocop:disable Metrics/CyclomaticComplexity, Metrics/MethodLength, Metrics/PerceivedComplexity
          pos = frame.offset - @buffer_start
          count = frame.data.bytesize
          frame_end = frame.offset + count

          # we should receive no more data beyond FIN!
          if @final_size
            raise FinalSizeError, "Data received beyond final size" if frame_end > @final_size
            raise FinalSizeError, "Cannot change final size" if frame.fin && frame_end != @final_size
          end

          @final_size = frame_end if frame.fin
          @highest_offset = frame_end if frame_end > @highest_offset
          # binding.b

          # fast path: new in-order chunk
          if pos == 0 && count > 1 && @buffer.empty?
            @buffer_start += count
            # all data up to the FIN has been received, we're done receiving
            @is_finished = true if frame.fin

            return Quic::Event::StreamDataReceived.new.tap do |event|
              event.data = frame.data
              event.end_stream = !!frame.fin # rubocop:disable Style/DoubleNegation ensure true/false
              event.stream_id = @stream_id
            end
          end

          # discard duplicate data
          if pos < 0
            frame.data = frame.data[-pos..] || ""
            frame.offset -= pos
            pos = 0
            count = frame.data.bytesize
          end

          # marked received range
          @ranges.add(frame.offset, frame_end) if frame_end > frame.offset

          # add new data
          gap = pos - @buffer.bytesize
          @buffer += "\x00" * gap if gap > 0
          @buffer[pos...(pos + count)] = frame.data

          # return data from the front of the buffer
          data = pull_data
          end_stream = @buffer_start == @final_size
          if end_stream
            # all data up to the FIN has been received, we're done receiving
            @is_finished = true
          end

          if !data.empty? || end_stream # rubocop:disable Style/GuardClause
            return Quic::Event::StreamDataReceived.new.tap do |event|
              event.data = data
              event.end_stream = end_stream
              event.stream_id = @stream_id
            end
          else
            return nil
          end
        end

        # Handle an abrupt termination of the receiving part of the QUIC stream.
        def handle_reset(finai_size:, error_code: Quic::Packet::QuicErrorCode::NO_ERROR)
          raise FinalSizeError, "Cannot change final size" if @final_size && finai_size != @final_size

          # we are done receiving
          @final_size = finai_size
          @is_finished = true
          return Quic::Event::StreamReset.new.tap do |reset|
            reset.error_code = error_code
            reset.stream_id = @stream_id
          end
        end

        # Callback when a STOP_SENDING is ACK'd.
        def on_stop_sending_delivery(delivery:)
          @stop_pending = true if delivery != Quic::PacketBuilder::QuicDeliveryState::ACKED
        end

        # Request the peer stop sending data on the QUIC stream.
        def stop(error_code: Quic::Packet::QuicErrorCode::NO_ERROR)
          @stop_error_code = error_code
          @stop_pending = true
        end

        # Remove data from the front of the buffer.
        def pull_data
          has_data_to_read = nil
          begin
            has_data_to_read = @ranges.list[0].first == @buffer_start
          rescue IndexError, NoMethodError
            has_data_to_read = false
          end
          return "" unless has_data_to_read

          r = @ranges.shift
          pos = r.last - r.first
          data = @buffer[...pos]
          @buffer[...pos] = ""
          @buffer_start = r.last
          return data
        end
      end

      # The send part of a QUIC stream.
      #
      # It finishes:
      # - immediately for a receive-only stream
      # - upon acknowledgement of a STREAM_RESET frame
      # - upon acknowledgement of a data frame with the FIN bit set
      class QuicStreamSender
        attr_reader :is_finished
        attr_reader :buffer
        attr_reader :highest_offset
        attr_reader :pending
        attr_reader :buffer_is_empty
        attr_reader :reset_pending

        def initialize(stream_id: nil, writable:)
          @buffer_is_empty = true
          @highest_offset = 0
          @is_finished = !writable
          @reset_pending = false

          @acked = Rangeset.new
          @buffer = ""
          @buffer_fin = nil
          @buffer_start = 0 # the offset for the start of the buffer
          @buffer_stop = 0 # the offset for the stop of the buffer
          @pending = Rangeset.new
          @pending_eof = false
          @reset_error_code = nil
          @stream_id = stream_id
        end

        # The offset for the next frame to send.
        #
        # This is used to determine the space needed for the frame's `offset` field.
        def next_offset
          return @pending.list[0].first
        rescue IndexError, NoMethodError
          return @buffer_stop
        end

        # Get a frame of data to send.
        def get_frame(max_size:, max_offset: nil) # rubocop:disable Metrics/CyclomaticComplexity, Metrics/MethodLength, Metrics/PerceivedComplexity
          # get the first pending data range
          r = nil
          begin
            raise IndexError if @pending.list.empty?

            r = @pending.list[0]
          rescue IndexError
            if @pending_eof
              # FIN only
              @pending_eof = false
              return Quic::Packet::QuicStreamFrame.new.tap do |frame|
                frame.fin = true
                frame.offset = @buffer_fin
                frame.data = ""
              end
            end
            @buffer_is_empty = true
            return nil
          end

          # apply flow control
          start = r.first
          stop = [r.last, start + max_size].min
          stop = max_offset if max_offset && stop > max_offset
          return nil if stop <= start

          # create frame
          frame = Quic::Packet::QuicStreamFrame.new.tap do |f|
            f.data = @buffer[(start - @buffer_start)...(stop - @buffer_start)] || ""
            f.offset = start
            f.fin = false
          end
          @pending.subtract(start, stop)

          # track the highest offset ever sent
          @highest_offset = stop if stop > @highest_offset

          # if the buffer is empty and EOF was written, set the FIN bit
          if @buffer_fin == stop
            frame.fin = true
            @pending_eof = false
          end

          return frame
        end

        def get_reset_frame
          @reset_pending = false
          return Quic::Packet::QuicResetStreamFrame.new.tap do |frame|
            frame.error_code = @reset_error_code
            frame.final_size = @highest_offset
            frame.stream_id = @stream_id
          end
        end

        # Callback when sent data is ACK'd
        def on_data_delivery(delivery:, start:, stop:)
          @buffer_is_empty = false
          if delivery == Quic::PacketBuilder::QuicDeliveryState::ACKED
            if stop > start
              @acked.add(start, stop)
              first_range = @acked.list[0]
              if first_range.first == @buffer_start
                size = first_range.last - first_range.first
                @acked.shift
                @buffer_start += size
                @buffer[..size] = ""
              end
            end

            if @buffer_start == @buffer_fin
              # all data up to the FIN has been ACK'd, we're done sending
              @is_finished = true
            end
          else
            @pending.add(start, stop) if stop > start
            if stop == @buffer_fin
              # @send_buffer_empty = false # doesn't used?
              @pending_eof = true
            end
          end
        end

        # Callback when a reset is ACK'd.
        def on_reset_delivery(delivery:)
          if delivery == Quic::PacketBuilder::QuicDeliveryState::ACKED
            # the reset has been ACK'd, we're done sending
            @is_finished = true
          else
            @reset_pending = true
          end
        end

        # Abruptly terminate the sending part of the QUIC stream.
        def reset(error_code:)
          raise RuntimeError if @reset_error_code # cannot call reset() more than once

          @reset_error_code = error_code
          @reset_pending = true
        end

        # Write some data bytes to the QUIC stream.
        def write(data:, end_stream: false)
          raise RuntimeError if @buffer_fin # cannnot call write() after FIN
          raise RuntimeError if @reset_error_code # cannot call write() after reset()

          size = data.bytesize
          if size > 0
            @buffer_is_empty = false
            @pending.add(@buffer_stop, @buffer_stop + size)
            @buffer += data
            @buffer_stop += size
          end

          if end_stream # rubocop:disable Style/GuardClause
            @buffer_is_empty = false
            @buffer_fin = @buffer_stop
            @pending_eof = true
          end
        end
      end

      # Represent QUIC Stream
      class QuicStream
        attr_reader :receiver
        attr_reader :sender

        def initialize(stream_id: nil, max_stream_data_local: 0, max_stream_data_remote: 0, readable: true, writable: true)
          @is_blocked = false
          @max_stream_data_local = max_stream_data_local
          @max_stream_data_local_sent = max_stream_data_local
          @max_stream_data_remote = max_stream_data_remote
          @receiver = QuicStreamReceiver.new(stream_id: stream_id, readable: readable)
          @sender = QuicStreamSender.new(stream_id: stream_id, writable: writable)
          @stream_id = stream_id
        end

        def is_finished
          @receiver.is_finished && @sender.is_finished
        end
      end
    end
  end
end
