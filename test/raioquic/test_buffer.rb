# frozen_string_literal: true

require "test_helper"

class TestRaioquicBuffer < Minitest::Test
  def test_data_slice
    buf = Raioquic::Buffer.new(data: "\x08\x07\x06\x05\x04\x03\x02\x01")
    assert_equal "\x08\x07\x06\x05\x04\x03\x02\x01", buf.data_slice(start: 0, ends: 8)
    assert_equal "\x07\x06", buf.data_slice(start: 1, ends: 3)
    assert_raises Raioquic::Buffer::BufferReaderError do
      buf.data_slice(start: -1, ends: 3)
    end
    assert_raises Raioquic::Buffer::BufferReaderError do
      buf.data_slice(start: 0, ends: 9)
    end
    assert_raises Raioquic::Buffer::BufferReaderError do
      buf.data_slice(start: 1, ends: 0)
    end
  end

  def test_pull_bytes
  end

  def test_pull_bytes_negative
  end

  def test_pull_bytes_truncated
  end

  def test_pull_bytes_zero
  end

  def test_pull_uint8
  end

  def test_pull_uint8_truncated
  end

  def test_pull_uint16
  end

  def test_pull_uint16_truncated
  end

  def test_pull_uint32
  end

  def test_pull_uint32_truncated
  end

  def test_pull_uint64
  end

  def test_pull_uint64_truncated
  end

  def test_push_bytes
  end

  def test_push_bytes_truncated
  end

  def test_push_bytes_zero
  end

  def test_push_uint8
  end

  def test_push_uint16
  end

  def test_push_uint32
  end

  def test_push_uint64
  end

  def test_seek
  end
end
