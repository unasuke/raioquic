# frozen_string_literal: true

require "test_helper"
require "raioquic/core_ext"

class TestRaioquicCoreExt < Minitest::Test
  def test_bytes_to_int
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
end
