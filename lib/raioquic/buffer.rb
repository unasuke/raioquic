# frozen_string_literal: true

module Raioquic
  class Buffer
    BufferReaderError = Class.new(StandardError)

    def initialize(capacity: nil, data: nil)
      @position = 0 # bytes count
      @buffer = IO::Buffer.for(data)
    end

    def dealloc
      @buffer.free
    end

    # NOTE: "end" is reserved keyword in Ruby
    def data_slice(start:, ends:)
      if start < 0 || @buffer.size < start || ends < 0 || @buffer.size < ends || ends < start
        raise BufferReaderError, "Read out of bounds"
      end

      @buffer.slice(start, ends - start).get_string
    end

    def eof
      @buffer.size == @position
    end

    def seek
    end

    def tell
    end

    def pull_bytes(length:)
    end

    def pull_uint8
    end

    def pull_uint16
    end

    def pull_uint32
    end

    def pull_uint64
    end

    def pull_unit_var
    end

    def push_bytes(value:)
    end

    def push_uint8(value:)
    end

    def push_uint16(value:)
    end

    def push_uint32(value:)
    end

    def push_uint64(value:)
    end

    def push_uint_var(value:)
    end

    def encode_uint_var(value:)
    end

    # Return the number of bytes required to encode the given value
    # as a QUIC variable-length unsigned integer.
    def size_uint_var(value:)
      if value <= 0x3f
        return 1
      elsif value <= 0x3fff
        return 2
      elsif value <= 0x3fffffff
        return 4
      elsif value <= 0x3fffffffffffffff
        return 8
      else
        raise ArgumentError, "Integer is too big for a variable-length integer"
      end
    end
  end
end
