# frozen_string_literal: true

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "raioquic"
require "debug"
require "openssl"
require "securerandom"

require "minitest/autorun"
require "minitest/reporters"

Minitest::Reporters.use! Minitest::Reporters::DefaultReporter.new

module Utils
  SERVER_CACERTFILE = File.join(File.expand_path(__dir__), "samples", "pycacert.pem")
  SERVER_CERTFILE = File.join(File.expand_path(__dir__), "samples", "ssl_cert.pem")
  SERVER_CERTFILE_WITH_CHAIN = File.join(File.expand_path(__dir__), "samples", "ssl_cert_with_chain.pem")
  SERVER_KEYFILE = File.join(File.expand_path(__dir__), "samples", "ssl_key.pem")
  SERVER_COMBINEDFILE = File.join(File.expand_path(__dir__), "samples", "ssl_combined.pem")

  def self.generate_certificate(alternative_names: [], common_name: nil, hash_algorithm: nil, key: nil)
    subject = issuer = OpenSSL::X509::Name.new([["CN", common_name]])

    cert = OpenSSL::X509::Certificate.new
    cert.subject = subject
    cert.issuer = issuer
    cert.public_key = key
    cert.serial = SecureRandom.random_number(1 << 128)
    cert.not_before = Time.now
    cert.not_after = Time.now + (60 * 60 * 24 * 10) # 10 days after
    unless alternative_names.empty?
      cert.add_extension OpenSSL::X509::ExtensionFactory.new.create_ext("subjectAltName", alternative_names.map { |alt| "DNS:#{alt}" }.join(","))
    end
    cert.sign(key, hash_algorithm)
    return [cert, key]
  end

  # secp256r1 is same as prime256v1
  # see also RFC 4492 Appendix A
  # https://datatracker.ietf.org/doc/rfc4492/
  def self.generate_ec_certificate(common_name:, alternative_names: [], curve: "prime256v1")
    key = OpenSSL::PKey::EC.generate(curve)
    return generate_certificate(alternative_names: alternative_names, common_name: common_name, hash_algorithm: "SHA256", key: key)
  end

  def self.generate_ed25519_certificate(common_name:, alternative_names: [])
    # In python implementation, hash algorithm for sign is 'None'. But in ruby, sign with 'nil' digest is wrong, it raises exception.
    # I cannnot find correct hash algorithm name for sign to ED25519 and ED448 certificate.
    raise NotImplementedError, "ED25519 is not supported"
  end

  def self.generate_ed448_certificate(common_name:, alternative_names: [])
    # In python implementation, hash algorithm for sign is 'None'. But in ruby, sign with 'nil' digest is wrong, it raises exception.
    # I cannnot find correct hash algorithm name for sign to ED25519 and ED448 certificate.
    raise NotImplementedError, "ED448 is not supported"
  end
end
