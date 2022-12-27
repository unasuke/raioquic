# frozen_string_literal: true

# CoreExt (like active support)

# CoreExt for String class
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

# CoreExt for Integer class
class Integer
  # Convert integer to specific byte size string (unsigned, big endian)
  def to_bytes(bytesize) # rubocop:disable Metrics/CyclomaticComplexity
    raise ArgumentError if self > 4294967295 # 5 bytes

    template = case bytesize
               when 0
                 nil
               when 1
                 "C*"
               when 2
                 "n*"
               when 3..4
                 "N*"
               else
                 raise ArgumentError, "#{bytesize} bytes is too big"
               end
    return "" if template.nil?

    [self].pack(template).then do |str|
      if bytesize == 3
        str.byteslice(1, 3).to_s
      else
        str
      end
    end
  end
end
