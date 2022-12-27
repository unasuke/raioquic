# coding: ASCII-8BIT
# frozen_string_literal: true

require "test_helper"
require "raioquic/core_ext"

class TestRaioquicCoreExt < Minitest::Test
  def test_string_bytes_to_int
    assert_equal 0,        "".bytes_to_int
    assert_equal 3,        "\x03".bytes_to_int
    assert_equal 15,       "\x0f".bytes_to_int
    assert_equal 16,       "\x00\x10".bytes_to_int
    assert_equal 64512,    "\xfc\x00".bytes_to_int
    assert_equal 66051,    "\x01\x02\x03".bytes_to_int
    assert_equal 16909060, "\x01\x02\x03\x04".bytes_to_int

    assert_raises ArgumentError do
      "\x01\x02\x03\x04\x05".bytes_to_int
    end
  end

  def test_integer_to_bytes
    assert_equal "", 0.to_bytes(0)
    assert_equal "\x00", 0.to_bytes(1)
    assert_equal "\x00\x00", 0.to_bytes(2)
    assert_equal "\x03", 3.to_bytes(1)
    assert_equal "\x0f", 15.to_bytes(1)
    assert_equal "\x00\x10", 16.to_bytes(2)
    assert_equal "\xfc\x00", 64512.to_bytes(2)
    assert_equal "\x01\x02\x03", 66051.to_bytes(3)
    assert_equal "\x01\x02\x03\x04", 16909060.to_bytes(4)

    assert_raises ArgumentError do
      4328719365.to_bytes(5)
    end
  end
end
