# frozen_string_literal: true

require_relative "raioquic/version"
require_relative "raioquic/buffer"
require_relative "raioquic/quic"
require_relative "raioquic/crypto"

module Raioquic
  class Error < StandardError; end
  # Your code goes here...
  class ValueError < Error; end
end
