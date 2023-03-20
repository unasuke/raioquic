# frozen_string_literal: true

module Raioquic
  module Quic
    module Event
      # Base class for QUIC events.
      # Should be implement by Struct?
      class QuicEvent
        def ==(other)
          return false if self.class != other.class

          return false if instance_variables != other.instance_variables

          return instance_variables.all? { |iver| instance_variable_get(iver) == other.instance_variable_get(iver) }
        end
      end

      class ConnectionIdIssued < QuicEvent
        attr_accessor :connection_id
      end

      class ConnectionIdRetired < QuicEvent
        attr_accessor :connection_id
      end

      # The ConnectionTerminated event is fired when the QUIC connection is terminated.
      class ConnectionTerminated < QuicEvent
        attr_accessor :error_code     # The error code which was specified when closing the connection.
        attr_accessor :frame_type     # The frame type which caused the connection to be closed, or `None`.
        attr_accessor :reason_phrase  # The human-readable reason for which the connection was closed.
      end

      # The DatagramFrameReceived event is fired when a DATAGRAM frame is received.
      class DatagramFrameReceived < QuicEvent
        attr_accessor :data # The data which was received.
      end

      # The HandshakeCompleted event is fired when the TLS handshake completes.
      class HandshakeCompleted < QuicEvent
        attr_accessor :alpn_protocol        # The protocol which was negotiated using ALPN, or `nil`.
        attr_accessor :early_data_accepted  # WHether early (0-RTT) data was accepted by the remote peer.
        attr_accessor :session_resumed      # Whether a TLS session was resumed.
      end

      # The PingAcknowledged event is fired when a PING frame is acknowledged.
      class PingAcknowledged < QuicEvent
        attr_accessor :uid # The unique ID of the PING.
      end

      # The ProtocolNegotiated event is fired when when ALPN negotiation completes.
      class ProtocolNegotiated < QuicEvent
        attr_accessor :alpn_protocol # The protocol which was negotiated using ALPN, or `nil`.
      end

      # The StreamDataReceived event is fired whenever data is received on a stream.
      class StreamDataReceived < QuicEvent
        attr_accessor :data       # The data which was received.
        attr_accessor :end_stream # Whether the STREAM frame has the FIN bit set.
        attr_accessor :stream_id  # The ID of the stream the data was received for.
      end

      # The StreamReset event is fired when the remote peer resets a stream.
      class StreamReset < QuicEvent
        attr_accessor :error_code # The error code that triggered the reset.
        attr_accessor :stream_id  # The ID of the stream that was reset.
      end
    end
  end
end
