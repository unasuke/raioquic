# frozen_string_literal: true

require "json"

module Raioquic
  module Quic
    module Logger
      QLOG_VERSION = "0.3"

      # A QUIC event trace.
      #
      # Events are logged in the format defined by qlog.
      #
      # See:
      # - https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema-02
      # - https://datatracker.ietf.org/doc/html/draft-marx-quic-qlog-quic-events
      # - https://datatracker.ietf.org/doc/html/draft-marx-quic-qlog-h3-events
      class QuicLoggerTrace
        PACKET_TYPE_NAMES = {
          Quic::Packet::PACKET_TYPE_INITIAL => "initial",
          Quic::Packet::PACKET_TYPE_HANDSHAKE => "handshake",
          Quic::Packet::PACKET_TYPE_ZERO_RTT => "0RTT",
          Quic::Packet::PACKET_TYPE_ONE_RTT => "1RTT",
          Quic::Packet::PACKET_TYPE_RETRY => "retry",
        }

        attr_reader :is_client

        def initialize(is_client:, odcid:)
          @odcid = odcid
          @events = []
          @is_client = is_client
          @vantage_point = {
            name: "raioquic(aioquic porting)",
            type: (is_client ? "client" : "server"),
          }
        end

        def encode_ack_frame(ranges:, delay:)
          {
            ack_delay: encode_time(delay),
            acked_ranges: ranges.list.map { |x| [x.first, x.last - 1] },
            frame_type: "ack",
          }
        end

        def encode_connection_close_frame(error_code:, frame_type: nil, reason_phrase:)
          attrs = {
            error_code: error_code,
            error_space: (frame_type ? "transport" : "application"),
            frame_type: "connection_close",
            raw_error_code: error_code,
            reason: reason_phrase,
          }
          attrs[:trigger_frame_type] = frame_type if frame_type
          attrs
        end

        def encode_connection_limit_frame(frame_type:, maximum:)
          if frame_type == Quic::Packet::QuicFrameType::MAX_DATA
            { frame_type: "max_data", maximum: maximum }
          else
            {
              frame_type: "max_streams",
              maximum: maximum,
              stream_type: (frame_type == Quic::Packet::QuicFrameType::MAX_STREAMS_UNI ? "unidirectional" : "bidirectional"),
            }
          end
        end

        def encode_crypto_frame(frame:)
          {
            frame_type: "crypto",
            length: frame.data.bytesize,
            offset: frame.offset,
          }
        end

        def encode_data_blocked_frame(limit:)
          { frame_type: "data_blocked", limit: limit }
        end

        def encode_datagram_frame(length:)
          { frame_type: "datagram", length: length }
        end

        def encode_handshake_done_frame
          { frame_type: "handshake_done" }
        end

        def encode_max_stream_data_frame(maximum:, stream_id:)
          {
            frame_type: "max_stream_data",
            maximum: maximum,
            stream_id: stream_id,
          }
        end

        def encode_new_connection_id_frame(connection_id:, retire_prior_to:, sequence_number:, stateless_reset_token:)
          {
            connection_id: connection_id.unpack1("H*"),
            frame_type: "new_connection_id",
            length: connection_id.bytesize,
            reset_token: stateless_reset_token.unpack1("H*"),
            retire_prior_to: retire_prior_to,
            sequence_number: sequence_number,
          }
        end

        def encode_new_token_frame(token:)
          {
            frame_type: "new_token",
            length: token.bytesize,
            token: token.unpack1("H*"),
          }
        end

        def encode_padding_frame
          { frame_type: "padding" }
        end

        def encode_path_challenge_frame(data:)
          { frame_type: "path_challenge", data: data.unpack1("H*") }
        end

        def encode_path_response_frame(data:)
          { frame_type: "path_response", data: data.unpack1("H*") }
        end

        def encode_ping_frame
          { frame_type: "ping" }
        end

        def encode_reset_stream_frame(error_code:, final_size:, stream_id:)
          {
            error_code: error_code,
            final_size: final_size,
            frame_type: "reset_stream",
            stream_id: stream_id,
          }
        end

        def encode_retire_connection_id_frame(sequence_number:)
          {
            frame_type: "retire_connection_id",
            sequence_number: sequence_number,
          }
        end

        def encode_stream_data_blocked_frame(limit:, stream_id:)
          {
            frame_type: "stream_data_blocked",
            limit: limit,
            stream_id: stream_id,
          }
        end

        def encode_stop_sending_frame(error_code:, stream_id:)
          {
            frame_type: "stop_sending",
            error_code: error_code,
            stream_id: stream_id,
          }
        end

        def encode_stream_frame(frame:, stream_id:)
          {
            fin: frame.fin,
            frame_type: "stream",
            length: frame.data.bytesize,
            offset: frame.offset,
            stream_id: stream_id,
          }
        end

        def encode_streams_blocked_frame(is_unidirectional:, limit:)
          {
            frame_type: "streams_blocked",
            limit: limit,
            stream_type: (is_unidirectional ? "unidirectional" : "bidirectional"),
          }
        end

        # Convert a time to milliseconds.
        def encode_time(seconds)
          seconds * 1000
        end

        def encode_transport_parameters(owner:, parameters:)
          data = { owner: owner }
          parameters.each_pair do |key, value|
            if value.is_a?(TrueClass) || value.is_a?(FalseClass) || value.is_a?(Integer)
              data[key] = value
            elsif value.is_a?(String)
              data[key] = value.unpack1("H*")
            end
          end
          data
        end

        def packet_type(packet_type)
          PACKET_TYPE_NAMES[packet_type & Quic::Packet::PACKET_TYPE_MASK] || "1RTT"
        end

        def log_event(category:, event:, data:)
          @events << {
            data: data,
            name: "#{category}:#{event}",
            time: encode_time(Time.now.to_f),
          }
        end

        # Return the trace as a dictionary which can be written as JSON.
        def to_dict
          {
            common_fields: {
              ODCID: @odcid.unpack1("H*"),
            },
            events: @events,
            vantage_point: @vantage_point,
          }
        end
      end

      class QuicLogger
        def initialize
          @traces = []
        end

        def start_trace(is_client:, odcid:)
          @trace = QuicLoggerTrace.new(is_client: is_client, odcid: odcid)
          @traces << @trace
          @trace
        end

        def to_dict
          {
            qlog_format: "JSON",
            qlog_version: QLOG_VERSION,
            traces: @traces.map(&:to_dict),
          }
        end
      end

      # A QUIC event logger which writes one trace per file.
      class QuicFileLogger < QuicLogger
        def initialize(path:)
          raise ValueError, "QUIC log output directory #{path} does not exist" unless File.directory?(path)

          @path = path # TODO: path check
          super()
        end

        def end_trace(trace)
          return unless trace
          trace_dict = trace.to_dict
          trace_type = trace.is_client ? "client" : "server"
          trace_path = File.join(@path, trace_dict[:common_fields][:ODCID] + "_#{trace_type}.qlog")
          File.write(
            trace_path,
            JSON.generate({
              qlog_format: "JSON",
              qlog_version: QLOG_VERSION,
              traces: [trace_dict],
            }))
            idx = @traces.find_index(trace)
            @traces.delete_at(idx) if idx
        end
      end
    end
  end
end
