# frozen_string_literal: true

# CoreExt (like active support)
class String
  # Convert big endian bytes to integer (unsigned, up to 4 byte)
  def bytes_to_int
    case bytesize
    when 0
      0
    when 1
      ("\x00" + self).unpack1("n*").to_i # rubocop:disable Style/StringConcatenation
    when 2
      unpack1("n*").to_i
    when 3
      ("\x00" + self).unpack1("N*").to_i # rubocop:disable Style/StringConcatenation
    when 4
      unpack1("N*").to_i
    else
      raise ArgumentError, "#{bytesize} bytes is not supported"
    end
  end
end
