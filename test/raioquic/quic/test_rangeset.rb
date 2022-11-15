# frozen_string_literal: true

require "test_helper"

class TestRaioquicQuicRangeset < Minitest::Test
  Rangeset = ::Raioquic::Quic::Rangeset

  def test_add_single_duplicate
    rangeset = Rangeset.new

    rangeset.add(0)
    assert_equal [0...1], rangeset.list

    rangeset.add(0)
    assert_equal [0...1], rangeset.list
  end

  def test_add_single_ordered
    rangeset = Rangeset.new

    rangeset.add(0)
    assert_equal [0...1], rangeset.list

    rangeset.add(1)
    assert_equal [0...2], rangeset.list

    rangeset.add(2)
    assert_equal [0...3], rangeset.list
  end

  def test_add_single_merge
    rangeset = Rangeset.new

    rangeset.add(0)
    assert_equal [0...1], rangeset.list

    rangeset.add(2)
    assert_equal [0...1, 2...3], rangeset.list

    rangeset.add(1)
    assert_equal [0...3], rangeset.list
  end

  def test_add_single_reverse
    rangeset = Rangeset.new

    rangeset.add(2)
    assert_equal [2...3], rangeset.list

    rangeset.add(1)
    assert_equal [1...3], rangeset.list

    rangeset.add(0)
    assert_equal [0...3], rangeset.list
  end

  def test_add_range_ordered
    rangeset = Rangeset.new

    rangeset.add(0, 2)
    assert_equal [0...2], rangeset.list

    rangeset.add(2, 4)
    assert_equal [0...4], rangeset.list

    rangeset.add(4, 6)
    assert_equal [0...6], rangeset.list
  end

  def test_add_range_merge
    rangeset = Rangeset.new

    rangeset.add(0, 2)
    assert_equal [0...2], rangeset.list

    rangeset.add(3, 5)
    assert_equal [0...2, 3...5], rangeset.list

    rangeset.add(2, 3)
    assert_equal [0...5], rangeset.list
  end

  def test_add_range_overlap
    rangeset = Rangeset.new

    rangeset.add(0, 2)
    assert_equal [0...2], rangeset.list

    rangeset.add(3, 5)
    assert_equal [0...2, 3...5], rangeset.list

    rangeset.add(1, 5)
    assert_equal [0...5], rangeset.list
  end

  def test_add_range_overlap_2
    rangeset = Rangeset.new

    rangeset.add(2, 4)
    rangeset.add(6, 8)
    rangeset.add(10, 12)
    rangeset.add(16, 18)
    assert_equal [2...4, 6...8, 10...12, 16...18], rangeset.list

    rangeset.add(1, 15)
    assert_equal [1...15, 16...18], rangeset.list
  end

  def test_add_range_reverse
    rangeset = Rangeset.new

    rangeset.add(6, 8)
    assert_equal [6...8], rangeset.list

    rangeset.add(3, 5)
    assert_equal [3...5, 6...8], rangeset.list

    rangeset.add(0, 2)
    assert_equal [0...2, 3...5, 6...8], rangeset.list
  end

  def test_add_range_unordered_contiguous
    rangeset = Rangeset.new

    rangeset.add(0, 2)
    assert_equal [0...2], rangeset.list

    rangeset.add(4, 6)
    assert_equal [0...2, 4...6], rangeset.list

    rangeset.add(2, 4)
    assert_equal [0...6], rangeset.list
  end

  def test_add_range_unordered_sparse
    rangeset = Rangeset.new

    rangeset.add(0, 2)
    assert_equal [0...2], rangeset.list

    rangeset.add(6, 8)
    assert_equal [0...2, 6...8], rangeset.list

    rangeset.add(3, 5)
    assert_equal [0...2, 3...5, 6...8], rangeset.list
  end

  def test_subtract
    rangeset = Rangeset.new

    rangeset.add(0, 10)
    rangeset.add(20, 30)

    rangeset.subtract(0, 3)
    assert_equal [3...10, 20...30], rangeset.list
  end

  def test_subtract_no_change
    rangeset = Rangeset.new

    rangeset.add(5, 10)
    rangeset.add(15, 20)
    rangeset.add(25, 30)

    rangeset.subtract(0, 5)
    assert_equal [5...10, 15...20, 25...30], rangeset.list

    rangeset.subtract(10, 15)
    assert_equal [5...10, 15...20, 25...30], rangeset.list
  end

  def test_subtract_overlap
    rangeset = Rangeset.new
    rangeset.add(1, 4)
    rangeset.add(6, 8)
    rangeset.add(10, 20)
    rangeset.add(30, 40)
    assert_equal [1...4, 6...8, 10...20, 30...40], rangeset.list

    rangeset.subtract(0, 2)
    assert_equal [2...4, 6...8, 10...20, 30...40], rangeset.list

    rangeset.subtract(3, 11)
    assert_equal [2...3, 11...20, 30...40], rangeset.list
  end

  def test_rangeset_split
    rangeset = Rangeset.new
    rangeset.add(0, 10)

    rangeset.subtract(2, 5)
    assert_equal [0...2, 5...10], rangeset.list
  end

  def test_contains
    rangeset = Rangeset.new
    assert_equal false, rangeset.in?(0)

    rangeset = Rangeset.new(ranges: [0...1])
    assert_equal true, rangeset.in?(0)
    assert_equal false, rangeset.in?(1)

    rangeset = Rangeset.new(ranges: [0...1, 3...6])
    assert_equal true, rangeset.in?(0)
    assert_equal false, rangeset.in?(1)
    assert_equal false, rangeset.in?(2)
    assert_equal true, rangeset.in?(3)
    assert_equal true, rangeset.in?(4)
    assert_equal true, rangeset.in?(5)
    assert_equal false, rangeset.in?(6)
  end

  def test_eq
    r0 = Rangeset.new(ranges: [0...1])
    r1 = Rangeset.new(ranges: [1...2, 3...4])
    r2 = Rangeset.new(ranges: [3...4, 1...2])

    assert_equal true, r0 == r0
    assert_equal false, r0 == r1
    assert_equal false, r0 == 0

    assert_equal true, r1 == r1
    assert_equal false, r1 == r0
    assert_equal true, r1 == r2
    assert_equal false, r1 == 0

    assert_equal true, r2 == r2
    assert_equal true, r2 == r1
    assert_equal false, r2 == r0
    assert_equal false, r2 == 0
  end

  def test_len
    rangeset = Rangeset.new
    assert_equal 0, rangeset.length

    rangeset = Rangeset.new(ranges: [0...1])
    assert_equal 1, rangeset.length
  end

  def test_pop
    rangeset = Rangeset.new(ranges: [1...2, 3...4])
    r = rangeset.shift
    assert_equal 1...2, r
    assert_equal [3...4], rangeset.list
  end
end
