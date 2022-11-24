# frozen_string_literal: true

require "stringio"
require "forwardable"

module Raioquic
  # Raioquic::Buffer
  # Migrated from auiquic/src/aioquic/buffer.py
  class Buffer
    extend Forwardable

    BufferReadError = Class.new(StandardError)
    BufferWriteError = Class.new(StandardError)

    UINT_VAR_MAX_SIZE = 8

    def_delegator :@buffer, :eof, :eof
    def_delegator :@buffer, :tell, :tell

    attr_reader :capacity

    # Encode a variable-length unsigned integer.
    def self.encode_uint_var(value)
      buf = new(capacity: UINT_VAR_MAX_SIZE)
      buf.push_uint_var(value)
      buf.data
    end

    def initialize(capacity: nil, data: "")
      @position = 0 # bytes count
      @buffer = StringIO.open(+data, "rb+:ASCII-8bit:ASCII-8BIT")
      @capacity = capacity || @buffer.size
    end

    def dealloc
      # empty
    end

    def data
      @buffer.string
    end

    def seek(offset)
      check_read_bounds(offset)
      @buffer.seek(offset)
    rescue Errno::EINVAL
      raise BufferReadError
    end

    # def capacity
    #   @capacity
    # end

    # NOTE: "end" is reserved keyword in Ruby
    def data_slice(start:, ends:)
      orig_str = @buffer.string

      raise BufferReadError, "Read out of bounds" if start < 0 || @buffer.size < start || ends < 0 || @buffer.size < ends || ends < start

      orig_str.byteslice(start, ends - start)
    end

    # Pull bytes.
    def pull_bytes(length)
      raise BufferReadError if @buffer.size < 1

      @buffer.read(length)
    rescue EOFError, ArgumentError
      raise BufferReadError
    end

    # Pull an 8-bit unsigned integer.
    def pull_uint8
      @buffer.readpartial(1).unpack1("C")
    rescue EOFError
      raise BufferReadError
    end

    # Pull a 16-bit unsigned integer.
    def pull_uint16
      @buffer.readpartial(2).unpack1("n")
    rescue EOFError
      raise BufferReadError
    end

    # Pull a 32-bit unsigned integer.
    def pull_uint32
      @buffer.readpartial(4).unpack1("N")
    rescue EOFError
      raise BufferReadError
    end

    # Pull a 64-bit unsigned integer.
    def pull_uint64
      @buffer.readpartial(8).unpack1("Q>")
    rescue EOFError
      raise BufferReadError
    end

    # Pull a QUIC variable-length unsigned integer.
    def pull_uint_var
      check_read_bounds(1)
      first = pull_uint8
      case first >> 6
      when 0
        first & 0x3f
      when 1
        check_read_bounds(1)
        second = pull_uint8
        ((first & 0x3f) << 8) | (second)
      when 2
        check_read_bounds(3)
        second = pull_uint8
        third = pull_uint8
        forth = pull_uint8
        ((first & 0x3f) << 24) | (second << 16) | (third << 8) | forth
      else
        check_read_bounds(7)
        b2 = pull_uint8
        b3 = pull_uint8
        b4 = pull_uint8
        b5 = pull_uint8
        b6 = pull_uint8
        b7 = pull_uint8
        b8 = pull_uint8
        ((first & 0x3f) << 56) | (b2 << 48) | (b3 << 40) | (b4 << 32) | (b5 << 24) | (b6 << 16) | (b7 << 8) | b8
      end
    end

    def push_bytes(value)
      raise BufferWriteError if value.bytesize > [@buffer.size, @capacity].max

      @buffer << value
    end

    def push_uint8(value)
      @buffer << [value].pack("C")
    end

    def push_uint16(value)
      @buffer << [value].pack("n")
    end

    def push_uint32(value)
      @buffer << [value].pack("N")
    end

    def push_uint64(value)
      @buffer << [value].pack("Q>")
    end

    def push_uint_var(value)
      if value <= 0x3f
        check_read_bounds(1)
        push_uint8(value)
      elsif value <= 0x3fff
        check_read_bounds(2)
        push_uint8((value >> 8) | 0x40)
        push_uint8(value & 0xff)
      elsif value <= 0x3fffffff
        check_read_bounds(4)
        push_uint8((value >> 24) | 0x80)
        push_uint8((value >> 16) & 0xff)
        push_uint8((value >> 8) & 0xff)
        push_uint8(value)
      elsif value <= 0x3fffffffffffffff
        check_read_bounds(8)
        push_uint8((value >> 56) | 0xc0)
        push_uint8((value >> 48) & 0xff)
        push_uint8((value >> 40) & 0xff)
        push_uint8((value >> 32) & 0xff)
        push_uint8((value >> 24) & 0xff)
        push_uint8((value >> 16) & 0xff)
        push_uint8((value >> 8) & 0xff)
        push_uint8(value & 0xff)
      else
        raise ValueError, "Integer is too big for a variable-length integer"
      end
    end

    # Return the number of bytes required to encode the given value
    # as a QUIC variable-length unsigned integer.
    def size_uint_var(value)
      if value <= 0x3f # rubocop:disable Style/GuardClause
        return 1
      elsif value <= 0x3fff
        return 2
      elsif value <= 0x3fffffff
        return 4
      elsif value <= 0x3fffffffffffffff
        return 8
      else
        raise ValueError, "Integer is too big for a variable-length integer"
      end
    end

    private def check_read_bounds(length)
      raise BufferReadError, "Read out of bounds" if [@buffer.size, @capacity].max < length
    end
  end
end
