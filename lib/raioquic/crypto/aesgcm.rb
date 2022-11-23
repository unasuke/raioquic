# frozen_string_literal: true

require_relative "backend/aead"

module Raioquic
  module Crypto
    class AESGCM
      attr_reader :key

      MAX_SIZE = 2**31 - 1
      OverflowError = Class.new(StandardError)

      def initialize(key)
        raise TypeError unless key.is_a? String
        raise ValueError, "AESGCM key must be 128, 192, or 256 bits." unless [16, 24, 32].include?(key.length)
        @key = key
      end

      def self.generate_key(bit_length)
        raise TypeError, "bit_length must be an integer" unless bit_length.is_a? Integer
        raise ValueError, "bit_length must be 128, 192, or 256" unless [128, 192, 256].include?(bit_length)
        Random.urandom(bit_length / 8)
      end

      def encrypt(nonce:, data:, associated_data: "")
        if data.length > MAX_SIZE || associated_data&.length > MAX_SIZE
          raise OverflowError, "Data or associated data too long. Max 2**31 - 1 bytes"
        end

        check_nonce(nonce)
        validate_length(nonce: nonce, data: data)

        Backend::Aead.encrypt(cipher: self, key: @key, nonce: nonce, data: data, associated_data: [associated_data], tag_length: 16)
      end

      def decrypt(nonce:, data:, associated_data: "")
        Backend::Aead.decrypt(cipher: self, key: @key, nonce: nonce, data: data, associated_data: [associated_data], tag_length: 16)
      end

      private def validate_length(nonce:, data:)
        l_val = 15 - nonce.length
        raise ValueError, "Data too long for nonce" if 2 * (8 * l_val) < data.length
      end

      private def check_nonce(nonce)
        raise ValueError, "Nonce must be 12 bytes" if nonce.length != 12
      end
    end
  end
end
