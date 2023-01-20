# frozen_string_literal: true

require "openssl"

# Generate key pair illustrated in RFC 8448.
# https://datatracker.ietf.org/doc/html/rfc8448
#
# In OpenSSL 3 environtment, openssl gem did not support OpenSSL::PKey::RSA#set_key, OpenSSL::PKey::RSA#set_factors,
# and OpenSSL::PKey::RSA#set_crt_params because PKey object made immutable from OpenSSL 3.
# Run this script in OpenSSL 1 env (like a container), get key pair with PEM format,
# then read in OpenSSL 3 env by OpenSSL::Pkey.read method and so on.

rfc8448_rsa_pkey_moduls = <<~MODULUS.split.map(&:hex).map(&:chr).join
  b4 bb 49 8f 82 79 30 3d 98 08 36 39 9b 36 c6 98
  8c 0c 68 de 55 e1 bd b8 26 d3 90 1a 24 61 ea fd
  2d e4 9a 91 d0 15 ab bc 9a 95 13 7a ce 6c 1a f1
  9e aa 6a f9 8c 7c ed 43 12 09 98 e1 87 a8 0e e0
  cc b0 52 4b 1b 01 8c 3e 0b 63 26 4d 44 9a 6d 38
  e2 2a 5f da 43 08 46 74 80 30 53 0e f0 46 1c 8c
  a9 d9 ef bf ae 8e a6 d1 d0 3e 2b d1 93 ef f0 ab
  9a 80 02 c4 74 28 a6 d3 5a 8d 88 d7 9f 7f 1e 3f
MODULUS

rfc8448_rsa_pkey_public_exponent = <<~EXPONENT.split.map(&:hex).map(&:chr).join
  01 00 01
EXPONENT

rfc8448_rsa_pkey_private_exponent = <<~EXPONENT.split.map(&:hex).map(&:chr).join
  04 de a7 05 d4 3a 6e a7 20 9d d8 07 21 11 a8 3c
  81 e3 22 a5 92 78 b3 34 80 64 1e af 7c 0a 69 85
  b8 e3 1c 44 f6 de 62 e1 b4 c2 30 9f 61 26 e7 7b
  7c 41 e9 23 31 4b bf a3 88 13 05 dc 12 17 f1 6c
  81 9c e5 38 e9 22 f3 69 82 8d 0e 57 19 5d 8c 84
  88 46 02 07 b2 fa a7 26 bc f7 08 bb d7 db 7f 67
  9f 89 34 92 fc 2a 62 2e 08 97 0a ac 44 1c e4 e0
  c3 08 8d f2 5a e6 79 23 3d f8 a3 bd a2 ff 99 41
EXPONENT

rfc8448_rsa_pkey_prime1 = <<~PRIME1.split.map(&:hex).map(&:chr).join
  e4 35 fb 7c c8 37 37 75 6d ac ea 96 ab 7f 59 a2
  cc 10 69 db 7d eb 19 0e 17 e3 3a 53 2b 27 3f 30
  a3 27 aa 0a aa bc 58 cd 67 46 6a f9 84 5f ad c6
  75 fe 09 4a f9 2c 4b d1 f2 c1 bc 33 dd 2e 05 15
PRIME1

rfc8448_rsa_pkey_prime2 = <<~PRIME2.split.map(&:hex).map(&:chr).join
  ca bd 3b c0 e0 43 86 64 c8 d4 cc 9f 99 97 7a 94
  d9 bb fe ad 8e 43 87 0a ba e3 f7 eb 8b 4e 0e ee
  8a f1 d9 b4 71 9b a6 19 6c f2 cb ba ee eb f8 b3
  49 0a fe 9e 9f fa 74 a8 8a a5 1f c6 45 62 93 03
PRIME2

rfc8448_rsa_pkey_exponent1 = <<~EXPONENT1.split.map(&:hex).map(&:chr).join
  3f 57 34 5c 27 fe 1b 68 7e 6e 76 16 27 b7 8b 1b
  82 64 33 dd 76 0f a0 be a6 a6 ac f3 94 90 aa 1b
  47 cd a4 86 9d 68 f5 84 dd 5b 50 29 bd 32 09 3b
  82 58 66 1f e7 15 02 5e 5d 70 a4 5a 08 d3 d3 19
EXPONENT1

rfc8448_rsa_pkey_exponent2 = <<~EXPONENT2.split.map(&:hex).map(&:chr).join
  18 3d a0 13 63 bd 2f 28 85 ca cb dc 99 64 bf 47
  64 f1 51 76 36 f8 64 01 28 6f 71 89 3c 52 cc fe
  40 a6 c2 3d 0d 08 6b 47 c6 fb 10 d8 fd 10 41 e0
  4d ef 7e 9a 40 ce 95 7c 41 77 94 e1 04 12 d1 39
EXPONENT2

rfc8448_rsa_pkey_coefficient = <<~COEF.split.map(&:hex).map(&:chr).join
  83 9c a9 a0 85 e4 28 6b 2c 90 e4 66 99 7a 2c 68
  1f 21 33 9a a3 47 78 14 e4 de c1 18 33 05 0e d5
  0d d1 3c c0 38 04 8a 43 c5 9b 2a cc 41 68 89 c0
  37 66 5f e5 af a6 05 96 9f 8c 01 df a5 ca 96 9d
COEF

rsa_cert = OpenSSL::PKey::RSA.new
rsa_cert.set_key(
  OpenSSL::BN.new(rfc8448_rsa_pkey_moduls, 2),
  OpenSSL::BN.new(rfc8448_rsa_pkey_public_exponent, 2),
  OpenSSL::BN.new(rfc8448_rsa_pkey_private_exponent, 2),
)
rsa_cert.set_factors(
  OpenSSL::BN.new(rfc8448_rsa_pkey_prime1, 2),
  OpenSSL::BN.new(rfc8448_rsa_pkey_prime2, 2),
)
rsa_cert.set_crt_params(
  OpenSSL::BN.new(rfc8448_rsa_pkey_exponent1, 2),
  OpenSSL::BN.new(rfc8448_rsa_pkey_exponent2, 2),
  OpenSSL::BN.new(rfc8448_rsa_pkey_coefficient, 2),
)

File.write("rfc8448.pem", rsa_cert.to_pem)
