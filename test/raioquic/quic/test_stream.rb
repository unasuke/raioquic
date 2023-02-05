# frozen_string_literal: true

require "test_helper"

class TestRaioquicQuicStream < Minitest::Test
  Stream = ::Raioquic::Quic::Stream

  def test_receiver_empty
    stream = Stream::QuicStream.new(stream_id: 2)
    assert_equal "", stream.receiver.buffer
    assert_empty stream.receiver.ranges.list
    assert_equal 0, stream.receiver.buffer_start

    # empty
    frame = ::Raioquic::Quic::Packet::QuicStreamFrame.new.tap do |f|
      f.offset = 0
      f.data = ""
    end
    assert_nil stream.receiver.handle_frame(frame: frame)
    assert_empty stream.receiver.ranges.list
    assert_equal 0, stream.receiver.buffer_start
  end

  def test_receiver_ordered
    stream = Stream::QuicStream.new(stream_id: 0)

    # add data at start
    received = Raioquic::Quic::Event::StreamDataReceived.new.tap do |event|
      event.data = "01234567"
      event.end_stream = false
      event.stream_id = 0
    end
    frame = Raioquic::Quic::Packet::QuicStreamFrame.new.tap do |f|
      f.offset = 0
      f.data = "01234567"
    end

    assert_equal received, stream.receiver.handle_frame(frame: frame)
    assert_equal "", stream.receiver.buffer
    assert_empty stream.receiver.ranges.list
    assert_equal 8, stream.receiver.buffer_start
    assert_equal 8, stream.receiver.highest_offset
    assert_equal false, stream.receiver.is_finished

    # add more data
    received2 = Raioquic::Quic::Event::StreamDataReceived.new.tap do |event|
      event.data = "89012345"
      event.end_stream = false
      event.stream_id = 0
    end
    frame2 = Raioquic::Quic::Packet::QuicStreamFrame.new.tap do |f|
      f.offset = 8
      f.data = "89012345"
    end
    assert_equal received2, stream.receiver.handle_frame(frame: frame2)
    assert_equal "", stream.receiver.buffer
    assert_empty stream.receiver.ranges.list
    assert_equal 16, stream.receiver.buffer_start
    assert_equal 16, stream.receiver.highest_offset
    assert_equal false, stream.receiver.is_finished

    # add data and fin
    received3 = Raioquic::Quic::Event::StreamDataReceived.new.tap do |event|
      event.data = "67890123"
      event.end_stream = true
      event.stream_id = 0
    end
    frame3 = Raioquic::Quic::Packet::QuicStreamFrame.new.tap do |f|
      f.offset = 16
      f.data = "67890123"
      f.fin = true
    end
    assert_equal received3, stream.receiver.handle_frame(frame: frame3)
    assert_equal "", stream.receiver.buffer
    assert_empty stream.receiver.ranges.list
    assert_equal 24, stream.receiver.buffer_start
    assert_equal 24, stream.receiver.highest_offset
    assert stream.receiver.is_finished
  end

  def test_receiver_unordered
    stream = Stream::QuicStream.new(stream_id: 0)

    # add data at offset 8
    frame = ::Raioquic::Quic::Packet::QuicStreamFrame.new.tap do |f|
      f.offset = 8
      f.data = "89012345"
    end
    assert_nil stream.receiver.handle_frame(frame: frame)
    assert_equal "\x00\x00\x00\x00\x00\x00\x00\x0089012345", stream.receiver.buffer
    assert_equal 0, stream.receiver.buffer_start
    assert_equal 16, stream.receiver.highest_offset

    # add data at offset 0
    frame2 = ::Raioquic::Quic::Packet::QuicStreamFrame.new.tap do |f|
      f.offset = 0
      f.data = "01234567"
    end
    received = Raioquic::Quic::Event::StreamDataReceived.new.tap do |event|
      event.data = "0123456789012345"
      event.end_stream = false
      event.stream_id = 0
    end
    assert_equal received, stream.receiver.handle_frame(frame: frame2)
    assert_equal "", stream.receiver.buffer
    assert_empty stream.receiver.ranges.list
    assert_equal 16, stream.receiver.buffer_start
    assert_equal 16, stream.receiver.highest_offset
  end

  def test_receiver_offset_only
    stream = Stream::QuicStream.new(stream_id: 0)

    # add data at offset 0
    frame = ::Raioquic::Quic::Packet::QuicStreamFrame.new.tap do |f|
      f.offset = 0
      f.data = ""
    end
    assert_nil stream.receiver.handle_frame(frame: frame)
    assert_equal "", stream.receiver.buffer
    assert_empty stream.receiver.ranges.list
    assert_equal 0, stream.receiver.buffer_start
    assert_equal 0, stream.receiver.highest_offset

    # add data at offset 8
    frame2 = ::Raioquic::Quic::Packet::QuicStreamFrame.new.tap do |f|
      f.offset = 8
      f.data = ""
    end
    assert_nil stream.receiver.handle_frame(frame: frame2)
    assert_equal "\x00\x00\x00\x00\x00\x00\x00\x00", stream.receiver.buffer
    assert_empty stream.receiver.ranges.list
    assert_equal 0, stream.receiver.buffer_start
    assert_equal 8, stream.receiver.highest_offset
  end

  def test_receiver_already_fully_consumed
    stream = Stream::QuicStream.new(stream_id: 0)

    # add data at offset 0
    frame = ::Raioquic::Quic::Packet::QuicStreamFrame.new.tap do |f|
      f.offset = 0
      f.data = "01234567"
    end
    received = ::Raioquic::Quic::Event::StreamDataReceived.new.tap do |event|
      event.data = "01234567"
      event.end_stream = false
      event.stream_id = 0
    end
    assert_equal received, stream.receiver.handle_frame(frame: frame)
    assert_equal "", stream.receiver.buffer
    assert_empty stream.receiver.ranges.list
    assert_equal 8, stream.receiver.buffer_start

    # add data again at offse 0
    frame2 = ::Raioquic::Quic::Packet::QuicStreamFrame.new.tap do |f|
      f.offset = 0
      f.data = "01234567"
    end
    assert_nil stream.receiver.handle_frame(frame: frame2)
    assert_equal "", stream.receiver.buffer
    assert_empty stream.receiver.ranges.list
    assert_equal 8, stream.receiver.buffer_start

    # add data again at offset 0
    frame3 = ::Raioquic::Quic::Packet::QuicStreamFrame.new.tap do |f|
      f.offset = 0
      f.data = "01"
    end
    assert_nil stream.receiver.handle_frame(frame: frame3)
    assert_equal "", stream.receiver.buffer
    assert_empty stream.receiver.ranges.list
    assert_equal 8, stream.receiver.buffer_start
  end

  def test_receiver_already_partially_consumed
    stream = Stream::QuicStream.new(stream_id: 0)

    frame = ::Raioquic::Quic::Packet::QuicStreamFrame.new.tap do |f|
      f.offset = 0
      f.data = "01234567"
    end
    received = ::Raioquic::Quic::Event::StreamDataReceived.new.tap do |event|
      event.data = "01234567"
      event.end_stream = false
      event.stream_id = 0
    end
    assert_equal received, stream.receiver.handle_frame(frame: frame)

    frame2 = ::Raioquic::Quic::Packet::QuicStreamFrame.new.tap do |f|
      f.offset = 0
      f.data = "0123456789012345"
    end
    received2 = ::Raioquic::Quic::Event::StreamDataReceived.new.tap do |event|
      event.data = "89012345"
      event.end_stream = false
      event.stream_id = 0
    end
    assert_equal received2, stream.receiver.handle_frame(frame: frame2)
    assert_equal "", stream.receiver.buffer
    assert_empty stream.receiver.ranges.list
    assert_equal 16, stream.receiver.buffer_start
  end

  def test_receiver_already_partially_consumed_2
    stream = Stream::QuicStream.new(stream_id: 0)

    frame = ::Raioquic::Quic::Packet::QuicStreamFrame.new.tap do |f|
      f.offset = 0
      f.data = "01234567"
    end
    received = ::Raioquic::Quic::Event::StreamDataReceived.new.tap do |event|
      event.data = "01234567"
      event.end_stream = false
      event.stream_id = 0
    end
    assert_equal received, stream.receiver.handle_frame(frame: frame)

    frame2 = ::Raioquic::Quic::Packet::QuicStreamFrame.new.tap do |f|
      f.offset = 16
      f.data = "abcdefgh"
    end
    assert_nil stream.receiver.handle_frame(frame: frame2)

    frame3 = ::Raioquic::Quic::Packet::QuicStreamFrame.new.tap do |f|
      f.offset = 2
      f.data = "23456789012345"
    end
    received3 = ::Raioquic::Quic::Event::StreamDataReceived.new.tap do |event|
      event.data = "89012345abcdefgh"
      event.end_stream = false
      event.stream_id = 0
    end
    assert_equal received3, stream.receiver.handle_frame(frame: frame3)
    assert_equal "", stream.receiver.buffer
    assert_empty stream.receiver.ranges.list
    assert_equal 24, stream.receiver.buffer_start
  end

  def test_receiver_fin
    stream = Stream::QuicStream.new(stream_id: 0)

    frame = ::Raioquic::Quic::Packet::QuicStreamFrame.new.tap do |f|
      f.offset = 0
      f.data = "01234567"
    end
    received = ::Raioquic::Quic::Event::StreamDataReceived.new.tap do |event|
      event.data = "01234567"
      event.end_stream = false
      event.stream_id = 0
    end
    assert_equal received, stream.receiver.handle_frame(frame: frame)

    frame2 = ::Raioquic::Quic::Packet::QuicStreamFrame.new.tap do |f|
      f.offset = 8
      f.data = "89012345"
      f.fin = true
    end
    received2 = ::Raioquic::Quic::Event::StreamDataReceived.new.tap do |event|
      event.data = "89012345"
      event.end_stream = true
      event.stream_id = 0
    end
    assert_equal received2, stream.receiver.handle_frame(frame: frame2)
  end

  def test_receiver_fin_out_of_order
    stream = Stream::QuicStream.new(stream_id: 0)

    # add data at offset 8 with FIN
    frame = ::Raioquic::Quic::Packet::QuicStreamFrame.new.tap do |f|
      f.offset = 8
      f.data = "89012345"
      f.fin = true
    end
    assert_nil stream.receiver.handle_frame(frame: frame)
    assert_equal 16, stream.receiver.highest_offset
    assert_equal false, stream.receiver.is_finished

    # add data at offset 0
    frame2 = ::Raioquic::Quic::Packet::QuicStreamFrame.new.tap do |f|
      f.offset = 0
      f.data = "01234567"
    end
    received2 = ::Raioquic::Quic::Event::StreamDataReceived.new.tap do |event|
      event.data = "0123456789012345"
      event.end_stream = true
      event.stream_id = 0
    end
    assert_equal received2, stream.receiver.handle_frame(frame: frame2)
    assert_equal 16, stream.receiver.highest_offset
    assert stream.receiver.is_finished
  end

  def test_receiver_fin_then_data
    stream = Stream::QuicStream.new(stream_id: 0)
    frame = ::Raioquic::Quic::Packet::QuicStreamFrame.new.tap do |f|
      f.offset = 0
      f.data = "0123"
      f.fin = true
    end
    stream.receiver.handle_frame(frame: frame)

    # data beyond final size
    frame2 = ::Raioquic::Quic::Packet::QuicStreamFrame.new.tap do |f|
      f.offset = 0
      f.data = "01234567"
    end
    ex = assert_raises Stream::FinalSizeError do
      stream.receiver.handle_frame(frame: frame2)
    end
    assert_equal "Data received beyond final size", ex.message

    # final size would be lawered
    frame3 = ::Raioquic::Quic::Packet::QuicStreamFrame.new.tap do |f|
      f.offset = 0
      f.data = "01"
      f.fin = true
    end
    ex2 = assert_raises Stream::FinalSizeError do
      stream.receiver.handle_frame(frame: frame3)
    end
    assert_equal "Cannot change final size", ex2.message
  end

  def test_receiver_fin_twice
    stream = Stream::QuicStream.new(stream_id: 0)

    frame = ::Raioquic::Quic::Packet::QuicStreamFrame.new.tap do |f|
      f.offset = 0
      f.data = "01234567"
    end
    received = ::Raioquic::Quic::Event::StreamDataReceived.new.tap do |event|
      event.data = "01234567"
      event.end_stream = false
      event.stream_id = 0
    end
    assert_equal received, stream.receiver.handle_frame(frame: frame)

    frame2 = ::Raioquic::Quic::Packet::QuicStreamFrame.new.tap do |f|
      f.offset = 8
      f.data = "89012345"
      f.fin = true
    end
    received2 = ::Raioquic::Quic::Event::StreamDataReceived.new.tap do |event|
      event.data = "89012345"
      event.end_stream = true
      event.stream_id = 0
    end
    assert_equal received2, stream.receiver.handle_frame(frame: frame2)

    frame3 = ::Raioquic::Quic::Packet::QuicStreamFrame.new.tap do |f|
      f.offset = 8
      f.data = "89012345"
      f.fin = true
    end
    received3 = ::Raioquic::Quic::Event::StreamDataReceived.new.tap do |event|
      event.data = ""
      event.end_stream = true
      event.stream_id = 0
    end
    assert_equal received3, stream.receiver.handle_frame(frame: frame3)
  end

  def test_receiver_fin_without_data
    stream = Stream::QuicStream.new(stream_id: 0)
    frame = ::Raioquic::Quic::Packet::QuicStreamFrame.new.tap do |f|
      f.offset = 0
      f.data = ""
      f.fin = true
    end
    received = ::Raioquic::Quic::Event::StreamDataReceived.new.tap do |event|
      event.data = ""
      event.end_stream = true
      event.stream_id = 0
    end
    assert_equal received, stream.receiver.handle_frame(frame: frame)
  end

  def test_receiver_reset
    stream = Stream::QuicStream.new(stream_id: 0)

    reset = ::Raioquic::Quic::Event::StreamReset.new.tap do |event|
      event.error_code = ::Raioquic::Quic::Packet::QuicErrorCode::NO_ERROR
      event.stream_id = 0
    end
    assert_equal reset, stream.receiver.handle_reset(finai_size: 4)
    assert stream.receiver.is_finished
  end

  def test_receiver_reset_after_fin
    stream = Stream::QuicStream.new(stream_id: 0)

    frame = ::Raioquic::Quic::Packet::QuicStreamFrame.new.tap do |f|
      f.offset = 0
      f.data = "0123"
      f.fin = true
    end
    stream.receiver.handle_frame(frame: frame)

    reset = ::Raioquic::Quic::Event::StreamReset.new.tap do |event|
      event.error_code = ::Raioquic::Quic::Packet::QuicErrorCode::NO_ERROR
      event.stream_id = 0
    end
    assert_equal reset, stream.receiver.handle_reset(finai_size: 4)
  end

  def test_receiver_reset_twice
    stream = Stream::QuicStream.new(stream_id: 0)

    reset = ::Raioquic::Quic::Event::StreamReset.new.tap do |event|
      event.error_code = ::Raioquic::Quic::Packet::QuicErrorCode::NO_ERROR
      event.stream_id = 0
    end
    assert_equal reset, stream.receiver.handle_reset(finai_size: 4)
    assert_equal reset, stream.receiver.handle_reset(finai_size: 4)
  end

  def test_receiver_reset_twice_final_size_error
    stream = Stream::QuicStream.new(stream_id: 0)

    reset = ::Raioquic::Quic::Event::StreamReset.new.tap do |event|
      event.error_code = ::Raioquic::Quic::Packet::QuicErrorCode::NO_ERROR
      event.stream_id = 0
    end
    assert_equal reset, stream.receiver.handle_reset(finai_size: 4)

    ex = assert_raises ::Raioquic::Quic::Stream::FinalSizeError do
      stream.receiver.handle_reset(finai_size: 5)
    end
    assert_equal "Cannot change final size", ex.message
  end

  def test_receiver_stop
    stream = Stream::QuicStream.new

    # stop is requested
    stream.receiver.stop(error_code: ::Raioquic::Quic::Packet::QuicErrorCode::NO_ERROR)
    assert stream.receiver.stop_pending

    # stop is sent
    frame = stream.receiver.get_stop_frame
    assert_equal ::Raioquic::Quic::Packet::QuicErrorCode::NO_ERROR, frame.error_code
    assert_equal false, stream.receiver.stop_pending

    # stop is acknowledged
    stream.receiver.on_stop_sending_delivery(delivery: ::Raioquic::Quic::PacketBuilder::QuicDeliveryState::ACKED)
    assert_equal false, stream.receiver.stop_pending
  end

  def test_receiver_stop_lost
    stream = Stream::QuicStream.new

    # stop is requested
    stream.receiver.stop(error_code: ::Raioquic::Quic::Packet::QuicErrorCode::NO_ERROR)
    assert stream.receiver.stop_pending

    # stop is sent
    frame = stream.receiver.get_stop_frame
    assert_equal ::Raioquic::Quic::Packet::QuicErrorCode::NO_ERROR, frame.error_code
    assert_equal false, stream.receiver.stop_pending

    # stop is lost
    stream.receiver.on_stop_sending_delivery(delivery: ::Raioquic::Quic::PacketBuilder::QuicDeliveryState::LOST)
    assert stream.receiver.stop_pending

    # stop is sent agein
    frame = stream.receiver.get_stop_frame
    assert_equal ::Raioquic::Quic::Packet::QuicErrorCode::NO_ERROR, frame.error_code
    assert_equal false, stream.receiver.stop_pending

    # stop is acknowledged
    stream.receiver.on_stop_sending_delivery(delivery: ::Raioquic::Quic::PacketBuilder::QuicDeliveryState::ACKED)
    assert_equal false, stream.receiver.stop_pending
  end

  def test_sender_data
    stream = Stream::QuicStream.new
    assert_equal 0, stream.sender.next_offset

    # nothing to send yet
    frame = stream.sender.get_frame(max_size: 8)
    assert_nil frame

    # write data
    stream.sender.write(data: "0123456789012345")
    assert_equal [0...16], stream.sender.pending.list
    assert_equal 0, stream.sender.next_offset

    # send a chunk
    frame = stream.sender.get_frame(max_size: 8)
    assert_equal "01234567", frame.data
    assert_equal false, frame.fin
    assert_equal 0, frame.offset
    assert_equal [8...16], stream.sender.pending.list
    assert_equal 8, stream.sender.next_offset

    # send another chunk
    frame = stream.sender.get_frame(max_size: 8)
    assert_equal "89012345", frame.data
    assert_equal false, frame.fin
    assert_equal 8, frame.offset
    assert_empty stream.sender.pending.list
    assert_equal 16, stream.sender.next_offset

    # nothing more to send
    frame = stream.sender.get_frame(max_size: 8)
    assert_nil frame
    assert_empty stream.sender.pending.list
    assert_equal 16, stream.sender.next_offset

    # first chunk gets acknowledged
    stream.sender.on_data_delivery(delivery: ::Raioquic::Quic::PacketBuilder::QuicDeliveryState::ACKED, start: 0, stop: 8)
    assert_equal false, stream.sender.is_finished

    # second chunk gets acknowledged
    stream.sender.on_data_delivery(delivery: ::Raioquic::Quic::PacketBuilder::QuicDeliveryState::ACKED, start: 8, stop: 16)
    assert_equal false, stream.sender.is_finished
  end

  def test_sender_data_and_fin
    stream = Stream::QuicStream.new

    # nothing to send yet
    frame = stream.sender.get_frame(max_size: 8)
    assert_nil frame

    # write data and EOF
    stream.sender.write(data: "0123456789012345", end_stream: true)
    assert_equal [0...16], stream.sender.pending.list
    assert_equal 0, stream.sender.next_offset

    # send a chunk
    frame = stream.sender.get_frame(max_size: 8)
    assert_equal "01234567", frame.data
    assert_equal false, frame.fin
    assert_equal 0, frame.offset
    assert_equal 8, stream.sender.next_offset

    # send another chunk
    frame = stream.sender.get_frame(max_size: 8)
    assert_equal "89012345", frame.data
    assert frame.fin
    assert_equal 8, frame.offset
    assert_equal 16, stream.sender.next_offset

    # nothing more to send
    frame = stream.sender.get_frame(max_size: 8)
    assert_nil frame
    assert_equal 16, stream.sender.next_offset

    # first chunk gets acknowledged
    stream.sender.on_data_delivery(delivery: ::Raioquic::Quic::PacketBuilder::QuicDeliveryState::ACKED, start: 0, stop: 8)
    assert_equal false, stream.sender.is_finished

    # second chunk gets acknowledged
    stream.sender.on_data_delivery(delivery: ::Raioquic::Quic::PacketBuilder::QuicDeliveryState::ACKED, start: 8, stop: 16)
    assert stream.sender.is_finished
  end

  def test_sender_data_and_fin_ack_out_of_order
    stream = Stream::QuicStream.new

    # nothing to send yet
    frame = stream.sender.get_frame(max_size: 8)
    assert_nil frame

    # write data and EOF
    stream.sender.write(data: "0123456789012345", end_stream: true)
    assert_equal [0...16], stream.sender.pending.list
    assert_equal 0, stream.sender.next_offset

    # send a chunk
    frame = stream.sender.get_frame(max_size: 8)
    assert_equal "01234567", frame.data
    assert_equal false, frame.fin
    assert_equal 0, frame.offset
    assert_equal 8, stream.sender.next_offset

    # send another chunk
    frame = stream.sender.get_frame(max_size: 8)
    assert_equal "89012345", frame.data
    assert frame.fin
    assert_equal 8, frame.offset
    assert_equal 16, stream.sender.next_offset

    # nothing more to send
    frame = stream.sender.get_frame(max_size: 8)
    assert_nil frame
    assert_equal 16, stream.sender.next_offset

    # second chunk gets acknowledged
    stream.sender.on_data_delivery(delivery: ::Raioquic::Quic::PacketBuilder::QuicDeliveryState::ACKED, start: 8, stop: 16)
    assert_equal false, stream.sender.is_finished

    # first chunk gets acknowledged
    stream.sender.on_data_delivery(delivery: ::Raioquic::Quic::PacketBuilder::QuicDeliveryState::ACKED, start: 0, stop: 8)
    assert stream.sender.is_finished
  end

  def test_sender_data_lost
    stream = Stream::QuicStream.new

    # nothing to send yet
    frame = stream.sender.get_frame(max_size: 8)
    assert_nil frame

    # write data and EOF
    stream.sender.write(data: "0123456789012345", end_stream: true)
    assert_equal [0...16], stream.sender.pending.list
    assert_equal 0, stream.sender.next_offset

    # send a chunk
    frame = ::Raioquic::Quic::Packet::QuicStreamFrame.new.tap do |f|
      f.data = "01234567"
      f.fin = false
      f.offset = 0
    end
    assert_equal frame, stream.sender.get_frame(max_size: 8)
    assert_equal "01234567", frame.data
    assert_equal [8...16], stream.sender.pending.list
    assert_equal 8, stream.sender.next_offset

    # send another chunk
    frame = ::Raioquic::Quic::Packet::QuicStreamFrame.new.tap do |f|
      f.data = "89012345"
      f.fin = true
      f.offset = 8
    end
    assert_equal frame, stream.sender.get_frame(max_size: 8)
    assert_empty stream.sender.pending.list
    assert_equal 16, stream.sender.next_offset

    # nothing more to send
    assert_nil stream.sender.get_frame(max_size: 8)
    assert_empty stream.sender.pending.list
    assert_equal 16, stream.sender.next_offset

    # a chunk gets lost
    stream.sender.on_data_delivery(delivery: ::Raioquic::Quic::PacketBuilder::QuicDeliveryState::LOST, start: 0, stop: 8)
    assert_equal [0...8], stream.sender.pending.list
    assert_equal 0, stream.sender.next_offset

    # send chunk again
    frame = ::Raioquic::Quic::Packet::QuicStreamFrame.new.tap do |f|
      f.data = "01234567"
      f.fin = false
      f.offset = 0
    end
    assert_equal frame, stream.sender.get_frame(max_size: 8)
    assert_empty stream.sender.pending.list
    assert_equal 16, stream.sender.next_offset
  end

  def test_sender_data_lost_fin
    stream = Stream::QuicStream.new

    # nothing to send yet
    frame = stream.sender.get_frame(max_size: 8)
    assert_nil frame

    # write data and EOF
    stream.sender.write(data: "0123456789012345", end_stream: true)
    assert_equal [0...16], stream.sender.pending.list
    assert_equal 0, stream.sender.next_offset

    # send a chunk
    frame = ::Raioquic::Quic::Packet::QuicStreamFrame.new.tap do |f|
      f.data = "01234567"
      f.fin = false
      f.offset = 0
    end
    assert_equal frame, stream.sender.get_frame(max_size: 8)
    assert_equal "01234567", frame.data
    assert_equal [8...16], stream.sender.pending.list
    assert_equal 8, stream.sender.next_offset

    # send another chunk
    frame = ::Raioquic::Quic::Packet::QuicStreamFrame.new.tap do |f|
      f.data = "89012345"
      f.fin = true
      f.offset = 8
    end
    assert_equal frame, stream.sender.get_frame(max_size: 8)
    assert_empty stream.sender.pending.list
    assert_equal 16, stream.sender.next_offset

    # nothing more to send
    assert_nil stream.sender.get_frame(max_size: 8)
    assert_empty stream.sender.pending.list
    assert_equal 16, stream.sender.next_offset

    # a chunk gets lost
    stream.sender.on_data_delivery(delivery: ::Raioquic::Quic::PacketBuilder::QuicDeliveryState::LOST, start: 8, stop: 16)
    assert_equal [8...16], stream.sender.pending.list
    assert_equal 8, stream.sender.next_offset

    # send chunk again
    frame = ::Raioquic::Quic::Packet::QuicStreamFrame.new.tap do |f|
      f.data = "89012345"
      f.fin = true
      f.offset = 8
    end
    assert_equal frame, stream.sender.get_frame(max_size: 8)
    assert_empty stream.sender.pending.list
    assert_equal 16, stream.sender.next_offset

    # both chunks gets acknowledged
    stream.sender.on_data_delivery(delivery: ::Raioquic::Quic::PacketBuilder::QuicDeliveryState::ACKED, start: 0, stop: 16)
    assert stream.sender.is_finished
  end

  def test_sender_blocked
    stream = Stream::QuicStream.new
    max_offset = 12

    # nothing to send yet
    frame = stream.sender.get_frame(max_size: 8, max_offset: max_offset)
    assert_nil frame
    assert_empty stream.sender.pending.list
    assert_equal 0, stream.sender.next_offset

    # write data, send a chunk
    stream.sender.write(data: "0123456789012345")
    frame = stream.sender.get_frame(max_size: 8)
    assert_equal "01234567", frame.data
    assert_equal false, frame.fin
    assert_equal 0, frame.offset
    assert_equal [8...16], stream.sender.pending.list
    assert_equal 8, stream.sender.next_offset

    # send is limited by peer
    frame = stream.sender.get_frame(max_size: 8, max_offset: max_offset)
    assert_equal "8901", frame.data
    assert_equal false, frame.fin
    assert_equal 8, frame.offset
    assert_equal [12...16], stream.sender.pending.list
    assert_equal 12, stream.sender.next_offset

    # unable to send, blocked
    frame = stream.sender.get_frame(max_size: 8, max_offset: max_offset)
    assert_nil frame
    assert_equal [12...16], stream.sender.pending.list
    assert_equal 12, stream.sender.next_offset

    # write more data, still blocked
    stream.sender.write(data: "abcdefgh")
    frame = stream.sender.get_frame(max_size: 8, max_offset: max_offset)
    assert_nil frame
    assert_equal [12...24], stream.sender.pending.list
    assert_equal 12, stream.sender.next_offset

    # peer raises limit, send some data
    max_offset += 8
    frame = stream.sender.get_frame(max_size: 8, max_offset: max_offset)
    assert_equal "2345abcd", frame.data
    assert_equal false, frame.fin
    assert_equal 12, frame.offset
    assert_equal [20...24], stream.sender.pending.list
    assert_equal 20, stream.sender.next_offset

    # peer raises limit agein, send remaining data
    max_offset += 8
    frame = stream.sender.get_frame(max_size: 8, max_offset: max_offset)
    assert_equal "efgh", frame.data
    assert_equal false, frame.fin
    assert_equal 20, frame.offset
    assert_empty stream.sender.pending.list
    assert_equal 24, stream.sender.next_offset

    # nothing more to send
    frame = stream.sender.get_frame(max_size: 8, max_offset: max_offset)
    assert_nil frame
  end

  def test_sender_fin_only
    stream = Stream::QuicStream.new

    # nothing to send yet
    assert stream.sender.buffer_is_empty
    frame = stream.sender.get_frame(max_size: 8)
    assert_nil frame

    # write EOF
    stream.sender.write(data: "", end_stream: true)
    assert_equal false, stream.sender.buffer_is_empty
    frame = stream.sender.get_frame(max_size: 8)
    assert_equal "", frame.data
    assert frame.fin
    assert_equal 0, frame.offset

    # nothing more to send
    assert_equal false, stream.sender.buffer_is_empty # FIXME: ? (from aioquic)
    frame = stream.sender.get_frame(max_size: 8)
    assert_nil frame
    assert stream.sender.buffer_is_empty
  end

  # same as test_sender_fin_only?
  def test_sender_fin_only_despite_blocked
    stream = Stream::QuicStream.new

    # nothing to send yet
    assert stream.sender.buffer_is_empty
    frame = stream.sender.get_frame(max_size: 8)
    assert_nil frame

    # write EOF
    stream.sender.write(data: "", end_stream: true)
    assert_equal false, stream.sender.buffer_is_empty
    frame = stream.sender.get_frame(max_size: 8)
    assert_equal "", frame.data
    assert frame.fin
    assert_equal 0, frame.offset

    # nothing more to send
    assert_equal false, stream.sender.buffer_is_empty # FIXME: ? (from aioquic)
    frame = stream.sender.get_frame(max_size: 8)
    assert_nil frame
    assert stream.sender.buffer_is_empty
  end

  def test_sender_reset
    stream = Stream::QuicStream.new

    # reset is requested
    stream.sender.reset(error_code: ::Raioquic::Quic::Packet::QuicErrorCode::NO_ERROR)
    assert stream.sender.reset_pending

    # reset is sent
    reset = stream.sender.get_reset_frame
    assert_equal ::Raioquic::Quic::Packet::QuicErrorCode::NO_ERROR, reset.error_code
    assert_equal 0, reset.final_size
    assert_equal false, stream.sender.reset_pending
    assert_equal false, stream.sender.is_finished

    # reset is acknowledged
    stream.sender.on_reset_delivery(delivery: ::Raioquic::Quic::PacketBuilder::QuicDeliveryState::ACKED)
    assert_equal false, stream.sender.reset_pending
    assert stream.sender.is_finished
  end

  def test_sender_reset_lost
    stream = Stream::QuicStream.new

    # reset is requested
    stream.sender.reset(error_code: ::Raioquic::Quic::Packet::QuicErrorCode::NO_ERROR)
    assert stream.sender.reset_pending

    # reset is sent
    reset = stream.sender.get_reset_frame
    assert_equal ::Raioquic::Quic::Packet::QuicErrorCode::NO_ERROR, reset.error_code
    assert_equal 0, reset.final_size
    assert_equal false, stream.sender.reset_pending

    # reset is lost
    stream.sender.on_reset_delivery(delivery: ::Raioquic::Quic::PacketBuilder::QuicDeliveryState::LOST)
    assert stream.sender.reset_pending
    assert_equal false, stream.sender.is_finished

    # reset is sent agein
    reset = stream.sender.get_reset_frame
    assert_equal ::Raioquic::Quic::Packet::QuicErrorCode::NO_ERROR, reset.error_code
    assert_equal 0, reset.final_size
    assert_equal false, stream.sender.reset_pending

    # reset is acknowledged
    stream.sender.on_reset_delivery(delivery: ::Raioquic::Quic::PacketBuilder::QuicDeliveryState::ACKED)
    assert_equal false, stream.sender.reset_pending
    assert stream.sender.is_finished
  end
end
