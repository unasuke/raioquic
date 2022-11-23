# frozen_string_literal: true

require "openssl"

module Raioquic
  module Crypto
    # Raioquic's Crypto::Backend is only OpenSSL
    module Backend
      class Aead
        def self.aead_cipher_name(cipher)
          case cipher
          # when ChaCha20Poly1305
          # when AESCCM
          #   "aes-#{cipher.key.length}-ccm"
          when ::Raioquic::Crypto::AESGCM
            "aes-#{cipher.key.length * 8}-gcm"
          else
            raise RuntimeError
          end
        end
        private_class_method :aead_cipher_name

        def self.encrypt(cipher:, key:, nonce:, data:, associated_data: [], tag_length:)
          cipher_name = aead_cipher_name(cipher)
          cipher = OpenSSL::Cipher.new(cipher_name)
          cipher.encrypt
          cipher.key = key
          cipher.iv = nonce
          cipher.auth_data = associated_data.join
          encrypted = cipher.update(data) + cipher.final
          tag = cipher.auth_tag(tag_length)
          return encrypted + tag
        end

        def self.decrypt(cipher:, key:, nonce:, data:, associated_data: [], tag_length:)
          cipher_name = aead_cipher_name(cipher)
          cipher = OpenSSL::Cipher.new(cipher_name)
          tag = data.slice(-tag_length, tag_length)
          encryped = data.slice(0, data.length - tag_length)
          cipher.decrypt
          cipher.key = key
          cipher.iv = nonce
          cipher.auth_tag = tag
          cipher.auth_data = associated_data.join
          decrypted = cipher.update(encryped) + cipher.final
          return decrypted
        end
      end
    end
  end
end
