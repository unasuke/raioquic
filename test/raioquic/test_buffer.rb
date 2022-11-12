# frozen_string_literal: true

require "test_helper"

class TestRaioquicBuffer < Minitest::Test
  def test_data_slice
    buf = Raioquic::Buffer.new(data: "\x08\x07\x06\x05\x04\x03\x02\x01")
    assert_equal "\x08\x07\x06\x05\x04\x03\x02\x01", buf.data_slice(start: 0, ends: 8)
    assert_equal "\x07\x06", buf.data_slice(start: 1, ends: 3)
    assert_raises Raioquic::Buffer::BufferReadError do
      buf.data_slice(start: -1, ends: 3)
    end
    assert_raises Raioquic::Buffer::BufferReadError do
      buf.data_slice(start: 0, ends: 9)
    end
    assert_raises Raioquic::Buffer::BufferReadError do
      buf.data_slice(start: 1, ends: 0)
    end
  end

  def test_pull_bytes
    buf = Raioquic::Buffer.new(data: "\x08\x07\x06\x05\x04\x03\x02\x01")
    assert_equal "\x08\x07\x06", buf.pull_bytes(3)
  end

  def test_pull_bytes_negative
    buf = Raioquic::Buffer.new(data: "\x08\x07\x06\x05\x04\x03\x02\x01")
    assert_raises Raioquic::Buffer::BufferReadError do
      buf.pull_bytes(-1)
    end
  end

  def test_pull_bytes_truncated
    buf = Raioquic::Buffer.new(capacity: 0)
    assert_raises Raioquic::Buffer::BufferReadError do
      buf.pull_bytes(2)
    end
    assert_equal 0, buf.tell
  end

  def test_pull_bytes_zero
    buf = Raioquic::Buffer.new(data: "\x08\x07\x06\x05\x04\x03\x02\x01")
    assert_equal "", buf.pull_bytes(0)
  end

  def test_pull_uint8
    buf = Raioquic::Buffer.new(data: "\x08\x07\x06\x05\x04\x03\x02\x01")
    assert_equal 0x08, buf.pull_uint8
    assert_equal 1, buf.tell
  end

  def test_pull_uint8_truncated
    buf = Raioquic::Buffer.new(capacity: 0)
    assert_raises Raioquic::Buffer::BufferReadError do
      buf.pull_uint8
    end
    assert_equal 0, buf.tell
  end

  def test_pull_uint16
    buf = Raioquic::Buffer.new(data: "\x08\x07\x06\x05\x04\x03\x02\x01")
    assert_equal 0x0807, buf.pull_uint16
    assert_equal 2, buf.tell
  end

  def test_pull_uint16_truncated
    buf = Raioquic::Buffer.new(capacity: 1)
    assert_raises Raioquic::Buffer::BufferReadError do
      buf.pull_uint16
    end
    assert_equal 0, buf.tell
  end

  def test_pull_uint32
    buf = Raioquic::Buffer.new(data: "\x08\x07\x06\x05\x04\x03\x02\x01")
    assert_equal 0x08070605, buf.pull_uint32
    assert_equal 4, buf.tell
  end

  def test_pull_uint32_truncated
    buf = Raioquic::Buffer.new(capacity: 3)
    assert_raises Raioquic::Buffer::BufferReadError do
      buf.pull_uint32
    end
    assert_equal 0, buf.tell
  end

  def test_pull_uint64
    buf = Raioquic::Buffer.new(data: "\x08\x07\x06\x05\x04\x03\x02\x01")
    assert_equal 0x0807060504030201, buf.pull_uint64
    assert_equal 8, buf.tell
  end

  def test_pull_uint64_truncated
    buf = Raioquic::Buffer.new(capacity: 7)
    assert_raises Raioquic::Buffer::BufferReadError do
      buf.pull_uint64
    end
    assert_equal 0, buf.tell
  end

  def test_push_bytes
    buf = Raioquic::Buffer.new(capacity: 3)
    buf.push_bytes("\x08\x07\x06")
    assert_equal "\x08\x07\x06", buf.data
    assert_equal 3, buf.tell
  end

  def test_push_bytes_truncated
    buf = Raioquic::Buffer.new(capacity: 3)
    assert_raises Raioquic::Buffer::BufferWriteError do
      buf.push_bytes("\x08\x07\x06\x05")
    end
    assert_equal 0, buf.tell
  end

  def test_push_bytes_zero
    buf = Raioquic::Buffer.new(capacity: 3)
    buf.push_bytes("")
    assert_equal "", buf.data
    assert_equal 0, buf.tell
  end

  def test_push_uint8
    buf = Raioquic::Buffer.new(capacity: 1)
    buf.push_uint8(0x08)
    assert_equal "\x08", buf.data
    assert_equal 1, buf.tell
  end

  def test_push_uint16
    buf = Raioquic::Buffer.new(capacity: 2)
    buf.push_uint16(0x0807)
    assert_equal "\x08\x07", buf.data
    assert_equal 2, buf.tell
  end

  def test_push_uint32
    buf = Raioquic::Buffer.new(capacity: 4)
    buf.push_uint32(0x08070605)
    assert_equal "\x08\x07\x06\x05", buf.data
    assert_equal 4, buf.tell
  end

  def test_push_uint64
    buf = Raioquic::Buffer.new(capacity: 8)
    buf.push_uint64(0x0807060504030201)
    assert_equal "\x08\x07\x06\x05\x04\x03\x02\x01", buf.data
    assert_equal 8, buf.tell
  end

  def test_seek
    buf = Raioquic::Buffer.new(data: "01234567")
    assert_equal false, buf.eof
    assert_equal 0, buf.tell

    buf.seek(4)
    assert_equal false, buf.eof
    assert_equal 4, buf.tell

    buf.seek(8)
    assert_equal true, buf.eof
    assert_equal 8, buf.tell

    assert_raises Raioquic::Buffer::BufferReadError do
      buf.seek(-1)
    end
    assert_equal 8, buf.tell

    assert_raises Raioquic::Buffer::BufferReadError do
      buf.seek(9)
    end
    assert_equal 8, buf.tell
  end

  def roundtrip(data, value)
    data = (+data).force_encoding(Encoding::ASCII_8BIT)
    buf = Raioquic::Buffer.new(data: data)
    assert_equal value, buf.pull_uint_var
    assert_equal data.size, buf.tell

    buf = Raioquic::Buffer.new(capacity: 8)
    buf.push_uint_var(value)
    assert_equal data, buf.data
  end

  def test_uint_var
    # 1 byte
    roundtrip("\x00", 0)
    roundtrip("\x01", 1)
    roundtrip("\x25", 37)
    roundtrip("\x3f", 63)

    # 2 bytes
    roundtrip("\x7b\xbd", 15293)
    roundtrip("\x7f\xff", 16383)

    # 4 bytes
    roundtrip("\x9d\x7f\x3e\x7d", 494878333)
    roundtrip("\xbf\xff\xff\xff", 1073741823)

    # 8 bytes
    roundtrip("\xc2\x19\x7c\x5e\xff\x14\xe8\x8c", 151288809941952652)
    roundtrip("\xff\xff\xff\xff\xff\xff\xff\xff", 4611686018427387903)
  end

  def test_pull_uint_var_truncated
    buf = Raioquic::Buffer.new(capacity: 8)
    assert_raises Raioquic::Buffer::BufferReadError do
      buf.pull_uint_var
    end

    buf = Raioquic::Buffer.new(data: "\xff")
    assert_raises Raioquic::Buffer::BufferReadError do
      buf.pull_uint_var
    end
  end

  def test_push_uint_var_too_big
    buf = Raioquic::Buffer.new(capacity: 8)
    assert_raises Raioquic::Buffer::ValueError, "Integer is too big for a variable-length integer" do
      buf.push_uint_var(4611686018427387904)
    end
  end

  def test_size_uint_var
    buf = Raioquic::Buffer.new
    assert_equal 1, buf.size_uint_var(1)
    assert_equal 2, buf.size_uint_var(16383)
    assert_equal 4, buf.size_uint_var(1073741823)
    assert_equal 8, buf.size_uint_var(4611686018427387903)
    assert_raises Raioquic::Buffer::ValueError, "Integer is too big for a variable-length integer" do
      buf.size_uint_var(4611686018427387904)
    end
  end
end
