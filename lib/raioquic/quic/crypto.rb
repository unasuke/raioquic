# frozen_string_literal: true

require_relative "../crypto"
require_relative "packet"
require "tttls1.3"
require "openssl"

module Raioquic
  module Quic
    # Raioquic::Quic::Crypto
    # Migrated from these files
    #  - aioquic/src/aioquic/quic/crypto.py
    #  - aioquic/src/aioquic/_crypto.c
    module Crypto
      INITIAL_CIPHER_SUITE = nil
      AEAD_KEY_LENGTH_MAX = 32
      AEAD_NONCE_LENGTH = 12
      AEAD_TAG_LENGTH = 16
      PACKET_LENGTH_MAX = 1500
      PACKET_NUMBER_LENGTH_MAX = 4
      SAMPLE_LENGTH = 16
      INITIAL_SALT_VERSION_1 = ["38762cf7f55934b34d179ae6a4c80cadccbb7f0a"].pack("H*")

      # class CryptoError < ::StandardError; end
      CryptoError = Class.new(StandardError)

      def derive_key_iv_hp(_cipher_suite, secret)
        # TODO: implement on TLS module
        [
          TTTLS13::KeySchedule.hkdf_expand_label(secret, "quic key", "", 16, "SHA256"),
          TTTLS13::KeySchedule.hkdf_expand_label(secret, "quic iv", "", 12, "SHA256"),
          TTTLS13::KeySchedule.hkdf_expand_label(secret, "quic hp", "", 16, "SHA256"),
        ]
      end
      module_function :derive_key_iv_hp

      def xor_str(a, b) # rubocop:disable Naming/MethodParameterName
        a.unpack("C*").zip(b.unpack("C*")).map { |x, y| x ^ y }.pack("C*")
      end
      module_function :xor_str

      class NoCallback; end # rubocop:disable Lint/EmptyClass

      # CryptoContext
      # represent sender or receiver crypto context
      class CryptoContext
        attr_reader :aead
        attr_reader :key_phase
        attr_reader :secret

        def initialize(key_phase: 0, setup_cb: NoCallback.new, teardown_cb: NoCallback.new)
          @aead = nil
          @cipher_suite = nil
          @hp = nil
          @key_phase = key_phase
          @secret = nil
          @version = nil
          @setup_cb = setup_cb
          @teardown_cb = teardown_cb
        end

        def decrypt_packet(packet:, encrypted_offset:, expected_packet_number:)
          raise ArgumentError unless @aead # TODO: KeyUnavailableError

          # header protection
          plain_header, packet_number, = @hp.remove(packet: packet, encrypted_offset: encrypted_offset)
          first_byte = plain_header[0].unpack1("C*")

          # packet number
          pn_length = (first_byte & 0x03) + 1
          packet_number = Packet.decode_packet_number(truncated: packet_number, num_bits: pn_length * 8, expected: expected_packet_number)

          # detect key phase change
          crypto = self
          unless Packet.is_long_header(first_byte)
            key_phase = (first_byte & 4) >> 2
            crypto = next_key_phase if key_phase != @key_phase
          end
          payload = crypto.aead.decrypt(data: packet[plain_header.length..], associated_data: plain_header, packet_number: packet_number)

          return [plain_header, payload, packet_number, crypto != self]
        end

        def encrypt_packet(plain_header:, plain_payload:, packet_number:)
          raise RuntimeError unless is_valid

          protected_payload = @aead.encrypt(data: plain_payload, associated_data: plain_header, packet_number: packet_number)
          return @hp.apply(plain_header: plain_header, protected_payload: protected_payload)
        end

        def is_valid
          !!@aead
        end

        def setup(cipher_suite:, secret:, version:)
          hp_cipher_name = "aes-128-ecb" # TODO: hardcode
          _aead_cipher_name = OpenSSL::Digest.new("SHA256") # TODO: hardcode

          key, iv, hp = ::Raioquic::Quic::Crypto.derive_key_iv_hp(cipher_suite, secret)
          # binding.b
          @aead = AEAD.new(cipher_name: "aes-128-gcm", key: key, iv: iv) # TODO: hardcode
          @cipher_suite = cipher_suite
          @hp = HeaderProtection.new(cipher_name: hp_cipher_name, key: hp)
          @secret = secret
          @version = version
        end

        def teardown; end

        def apply_key_phase(crypto, _trigger)
          @aead = crypto.aead
          @key_phase = crypto.key_phase
          @secret = crypto.secret
        end

        def next_key_phase
          crypto = self.class.new(key_phase: (@key_phase.zero? ? 1 : 0))
          crypto.setup(
            cipher_suite: "aes-128-gcm", # TODO: hardcode
            secret: TTTLS13::KeySchedule.hkdf_expand_label(@secret, "quic ku", "", 32, "SHA256"),
            version: Packet::QuicProtocolVersion::VERSION_1,
          )
          return crypto
        end
      end

      # CryptoPair
      # store sender and receiver crypto context object
      class CryptoPair
        attr_reader :recv
        attr_reader :send
        attr_reader :aead_tag_size

        def initialize(recv_setup_cb: NoCallback.new, recv_teardown_cb: NoCallback.new, send_setup_cb: NoCallback.new, send_teardown_cb: NoCallback.new) # rubocop:disable Layout/LineLength
          @aead_tag_size = 16
          @recv = CryptoContext.new(setup_cb: recv_setup_cb, teardown_cb: recv_teardown_cb)
          @send = CryptoContext.new(setup_cb: send_setup_cb, teardown_cb: send_teardown_cb)
          @update_key_requested = false
        end

        def decrypt_packet(packet:, encrypted_offset:, expected_packet_number:)
          plain_header, payload, packe_number, need_update_key = @recv.decrypt_packet(
            packet: packet, encrypted_offset: encrypted_offset, expected_packet_number: expected_packet_number,
          )
          _update_key("remote_update") if need_update_key

          return [plain_header, payload, packe_number]
        end

        def encrypt_packet(plain_header:, plain_payload:, packet_number:)
          _update_key("local_update") if @update_key_requested

          return @send.encrypt_packet(plain_header: plain_header, plain_payload: plain_payload, packet_number: packet_number)
        end

        def setup_initial(cid:, is_client:, version:)
          if is_client
            recv_label = "server in"
            send_label = "client in"
          else
            recv_label = "client in"
            send_label = "server in"

          end
          initial_salt = INITIAL_SALT_VERSION_1
          # algorithm = TLS.cipher_suite_hash(INITIAL_CIPHER_SUITE) TODO: impleement on tls module
          algorithm = OpenSSL::Digest.new("SHA256")
          # initial_secret = hkdf_extract(algorithm, initial_salt, cid) TODO: implement on tls module
          initial_secret = OpenSSL::HMAC.digest(algorithm, initial_salt, cid)
          @recv.setup(
            cipher_suite: INITIAL_CIPHER_SUITE,
            secret: TTTLS13::KeySchedule.hkdf_expand_label(initial_secret, recv_label, "", 32, "SHA256"),
            version: version,
          )
          @send.setup(
            cipher_suite: INITIAL_CIPHER_SUITE,
            secret: TTTLS13::KeySchedule.hkdf_expand_label(initial_secret, send_label, "", 32, "SHA256"),
            version: version,
          )
        end

        def teardown; end

        def key_phase
          if @update_key_requested
            @recv.key_phase.zero? ? 1 : 0
          else
            @recv.key_phase
          end
        end

        def update_key
          @update_key_requested = true
        end

        def _update_key(trigger)
          # binding.irb
          @recv.apply_key_phase(@recv.next_key_phase, trigger)
          @send.apply_key_phase(@send.next_key_phase, trigger)
          @update_key_requested = false
        end
      end

      # HeaderProtection
      # remove/apply QUIC header protection
      class HeaderProtection
        def initialize(cipher_name:, key:)
          @cipher = OpenSSL::Cipher.new(cipher_name)
          @cipher.encrypt
          @cipher.key = key
          @key = key
          @mask = "\x00" * 31
          @zero = "\x00" * 5
        end

        def apply(plain_header:, protected_payload:)
          pn_length = (plain_header[0].unpack1("C*") & 0x03) + 1
          pn_offset = plain_header.length - pn_length
          mask(protected_payload.slice((PACKET_NUMBER_LENGTH_MAX - pn_length)..-1)[0, SAMPLE_LENGTH])
          buffer = plain_header + protected_payload
          if buffer[0].unpack1("C*") & 0x80 != 0 # rubocop:disable Style/NegatedIfElseCondition, Style/ConditionalAssignment
            buffer[0] = Crypto.xor_str(buffer[0], [@mask[0].unpack1("C*") & 0x0f].pack("C*"))
          else
            buffer[0] = Crypto.xor_str(buffer[0], [@mask[0].unpack1("C*") & 0x1f].pack("C*"))
          end
          pn_length.times do |i|
            buffer[pn_offset + i] = Crypto.xor_str(buffer[pn_offset + i], @mask[1 + i])
          end
          return buffer
        end

        def remove(packet:, encrypted_offset:)
          mask(packet.slice(encrypted_offset + PACKET_NUMBER_LENGTH_MAX, SAMPLE_LENGTH))
          buffer = packet.dup.slice(0, encrypted_offset + PACKET_NUMBER_LENGTH_MAX)
          if buffer[0].unpack1("C*") & 0x80 != 0 # rubocop:disable Style/NegatedIfElseCondition, Style/ConditionalAssignment
            buffer[0] = Crypto.xor_str(buffer[0], [@mask[0].unpack1("C*") & 0x0f].pack("C*"))
          else
            buffer[0] = Crypto.xor_str(buffer[0], [@mask[0].unpack1("C*") & 0x1f].pack("C*"))
          end
          pn_length = (buffer[0].unpack1("C*") & 0x03) + 1
          pn_truncated = 0
          pn_length.times do |i|
            buffer[encrypted_offset + i] = Crypto.xor_str(buffer[encrypted_offset + i], @mask[1 + i])
            pn_truncated = buffer[encrypted_offset + i].unpack1("C*") | (pn_truncated << 8)
          end
          [buffer.slice(0, encrypted_offset + pn_length), pn_truncated]
        end

        private def mask(sample)
          # if chacha20 TODO: chacha20
          @mask = @cipher.update(sample) + @cipher.final
        end
      end

      # AEAD
      # encrypt/dectypt AEAD
      class AEAD
        def initialize(cipher_name:, key:, iv:) # rubocop:disable Naming/MethodParameterName
          @cipher = OpenSSL::Cipher.new(cipher_name)
          @cipher_name = cipher_name
          @key = key
          @iv = iv
        end

        def decrypt(data:, associated_data:, packet_number:)
          raise CryptoError, "Invalid payload length" if data.length < AEAD_TAG_LENGTH || data.length > PACKET_LENGTH_MAX

          nonce = @iv.dup
          8.times do |i|
            nonce[AEAD_NONCE_LENGTH - 1 - i] = Crypto.xor_str(nonce[AEAD_NONCE_LENGTH - 1 - i], [packet_number >> (8 * i)].pack("C*"))
          end
          @cipher.decrypt
          @cipher.key = @key
          @cipher.iv = nonce
          @cipher.auth_tag = data.slice(data.length - AEAD_TAG_LENGTH, AEAD_TAG_LENGTH)
          @cipher.auth_data = associated_data
          decrypted = @cipher.update(data.slice(0...(data.length - AEAD_TAG_LENGTH))) + @cipher.final
          return decrypted
        end

        def encrypt(data:, associated_data:, packet_number:)
          raise CryptoError, "Invalid payload length" if data.length > PACKET_LENGTH_MAX

          nonce = @iv.dup
          8.times do |i|
            nonce[AEAD_NONCE_LENGTH - 1 - i] = Crypto.xor_str(nonce[AEAD_NONCE_LENGTH - 1 - i], [packet_number >> (8 * i)].pack("C*"))
          end

          @cipher.encrypt
          @cipher.key = @key
          @cipher.iv = nonce
          @cipher.auth_data = associated_data
          encrypted = @cipher.update(data) + @cipher.final
          return encrypted + @cipher.auth_tag
        end
      end
    end
  end
end
