# frozen_string_literal: true

require "test_helper"

class TestRaioquicQuicCrypto < Minitest::Test
  LONG_CLIENT_PACKET_NUMBER = 2
  LONG_CLIENT_PLAIN_HEADER = ["c300000001088394c8f03e5157080000449e00000002"].pack("H*")
  LONG_CLIENT_PLAIN_PAYLOAD = [
    "060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e868" \
    "04fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578" \
    "616d706c652e636f6dff01000100000a00080006001d00170018001000070005" \
    "04616c706e000500050100000000003300260024001d00209370b2c9caa47fba" \
    "baf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b000302030400" \
    "0d0010000e0403050306030203080408050806002d00020101001c0002400100" \
    "3900320408ffffffffffffffff05048000ffff07048000ffff08011001048000" \
    "75300901100f088394c8f03e51570806048000ffff"
  ].pack("H*") + ("\x00" * 917)
  LONG_CLIENT_ENCRYPTED_PACKET = [
    "c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11" \
    "d242b123dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f399" \
    "1c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c" \
    "8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df6212" \
    "30c83711b39343fa028cea7f7fb5ff89eac2308249a02252155e2347b63d58c5" \
    "457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c208" \
    "4dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec" \
    "4e15daf8500a6ef69ec4e3feb6b1d98e610ac8b7ec3faf6ad760b7bad1db4ba3" \
    "485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db" \
    "059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c" \
    "7b4378e846d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f8" \
    "9937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556" \
    "be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c74" \
    "68449a13d8e3b95811a198f3491de3e7fe942b330407abf82a4ed7c1b311663a" \
    "c69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00" \
    "f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632" \
    "291d6a418211cc2962e20fe47feb3edf330f2c603a9d48c0fcb5699dbfe58964" \
    "25c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd" \
    "14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ff" \
    "ef132eef2fa09346aee33c28eb130ff28f5b766953334113211996d20011a198" \
    "e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009dd" \
    "c324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73" \
    "203a4a13e96f5432ec0fd4a1ee65accdd5e3904df54c1da510b0ff20dcc0c77f" \
    "cb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450e" \
    "fc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03ade" \
    "a2e1fbc5aa463d08ca19896d2bf59a071b851e6c239052172f296bfb5e724047" \
    "90a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2" \
    "162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f4" \
    "40591f355e12d439ff150aab7613499dbd49adabc8676eef023b15b65bfc5ca0" \
    "6948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e" \
    "8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0" \
    "be79e2fb8f5d5fbbe2e30ecadd220723c8c0aea8078cdfcb3868263ff8f09400" \
    "54da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab" \
    "760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9" \
    "f96f3ca9ec1dde434da7d2d392b905ddf3d1f9af93d1af5950bd493f5aa731b4" \
    "056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd4684064" \
    "7e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241" \
    "e221af44860018ab0856972e194cd934"
  ].pack("H*")

  # https://datatracker.ietf.org/doc/html/rfc9001#appendix-A.3
  LONG_SERVER_PACKET_NUMBER = 1
  LONG_SERVER_PLAIN_HEADER = ["c1000000010008f067a5502a4262b50040750001"].pack("H*")
  LONG_SERVER_PLAIN_PAYLOAD = [
    "02000000000600405a020000560303eefce7f7b37ba1d1632e96677825ddf739" \
    "88cfc79825df566dc5430b9a045a1200130100002e00330024001d00209d3c94" \
    "0d89690b84d08a60993c144eca684d1081287c834d5311bcf32bb9da1a002b00" \
    "020304"
  ].pack("H*")
  LONG_SERVER_ENCRYPTED_PACKET = [
    "cf000000010008f067a5502a4262b5004075c0d95a482cd0991cd25b0aac406a" \
    "5816b6394100f37a1c69797554780bb38cc5a99f5ede4cf73c3ec2493a1839b3" \
    "dbcba3f6ea46c5b7684df3548e7ddeb9c3bf9c73cc3f3bded74b562bfb19fb84" \
    "022f8ef4cdd93795d77d06edbb7aaf2f58891850abbdca3d20398c276456cbc4" \
    "2158407dd074ee"
  ].pack("H*")

  SHORT_SERVER_PACKET_NUMBER = 3
  SHORT_SERVER_PLAIN_HEADER = ["41b01fd24a586a9cf30003"].pack("H*")
  SHORT_SERVER_PLAIN_PAYLOAD = [
    "06003904000035000151805a4bebf5000020b098c8dc4183e4c182572e10ac3e" \
    "2b88897e0524c8461847548bd2dffa2c0ae60008002a0004ffffffff"
  ].pack("H*")
  SHORT_SERVER_ENCRYPTED_PACKET = [
    "5db01fd24a586a9cf33dec094aaec6d6b4b7a5e15f5a3f05d06cf1ad0355c19d" \
    "cce0807eecf7bf1c844a66e1ecd1f74b2a2d69bfd25d217833edd973246597bd" \
    "5107ea15cb1e210045396afa602fe23432f4ab24ce251b"
  ].pack("H*")

  def create_crypto(is_client:)
    pair = ::Raioquic::Quic::Crypto::CryptoPair.new
    pair.setup_initial(
      cid: ["8394c8f03e515708"].pack("H*"),
      is_client: is_client,
      version: ::Raioquic::Quic::Packet::QuicProtocolVersion::VERSION_1,
    )
    return pair
  end

  def test_derive_key_iv_hp
    # client
    secret = ["c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea"].pack("H*")

    key, iv, hp = ::Raioquic::Quic::Crypto.derive_key_iv_hp(::Raioquic::Quic::Crypto::INITIAL_CIPHER_SUITE, secret)
    assert_equal ["1f369613dd76d5467730efcbe3b1a22d"].pack("H*"), key
    assert_equal ["fa044b2f42a3fd3b46fb255c"].pack("H*"), iv
    assert_equal ["9f50449e04a0e810283a1e9933adedd2"].pack("H*"), hp

    # server
    secret = ["3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b"].pack("H*")

    key, iv, hp = ::Raioquic::Quic::Crypto.derive_key_iv_hp(::Raioquic::Quic::Crypto::INITIAL_CIPHER_SUITE, secret)
    assert_equal ["cf3a5331653c364c88f0f379b6067e37"].pack("H*"), key
    assert_equal ["0ac1493ca1905853b0bba03e"].pack("H*"), iv
    assert_equal ["c206b8d9b9f0f37644430b490eeaa314"].pack("H*"), hp
  end

  def test_derive_key_iv_hp_chacha20
    skip "ChaCha20 not implemented yet"
  end

  def test_decrypt_chacha20
    skip "ChaCha20 not implemented yet"
  end

  def test_decrypt_long_client
    pair = create_crypto(is_client: false)
    plain_header, plain_payload, packet_number = pair.decrypt_packet(
      packet: LONG_CLIENT_ENCRYPTED_PACKET, encrypted_offset: 18, expected_packet_number: 0,
    )
    assert_equal LONG_CLIENT_PLAIN_HEADER, plain_header
    assert_equal LONG_CLIENT_PLAIN_PAYLOAD, plain_payload
    assert_equal LONG_CLIENT_PACKET_NUMBER, packet_number
  end

  def test_decrypt_long_server
    pair = create_crypto(is_client: true)
    plain_header, plain_payload, packet_number = pair.decrypt_packet(
      packet: LONG_SERVER_ENCRYPTED_PACKET, encrypted_offset: 18, expected_packet_number: 0,
    )
    assert_equal LONG_SERVER_PLAIN_HEADER, plain_header
    assert_equal LONG_SERVER_PLAIN_PAYLOAD, plain_payload
    assert_equal LONG_SERVER_PACKET_NUMBER, packet_number
  end

  def test_decrypt_no_key
    pair = Raioquic::Quic::Crypto::CryptoPair.new
    assert_raises ArgumentError do # TODO: KeyUnavailableError
      pair.decrypt_packet(packet: LONG_SERVER_ENCRYPTED_PACKET, encrypted_offset: 18, expected_packet_number: 0)
    end
  end

  def test_decrypt_short_server
    pair = Raioquic::Quic::Crypto::CryptoPair.new
    pair.recv.setup(
      cipher_suite: Raioquic::Quic::Crypto::INITIAL_CIPHER_SUITE,
      secret: ["310281977cb8c1c1c1212d784b2d29e5a6489e23de848d370a5a2f9537f3a100"].pack("H*"),
      version: Raioquic::Quic::Packet::QuicProtocolVersion::VERSION_1,
    )
    plain_header, plain_payload, packet_number = pair.decrypt_packet(
      packet: SHORT_SERVER_ENCRYPTED_PACKET, encrypted_offset: 9, expected_packet_number: 0,
    )
    assert_equal SHORT_SERVER_PLAIN_HEADER, plain_header
    assert_equal SHORT_SERVER_PLAIN_PAYLOAD, plain_payload
    assert_equal SHORT_SERVER_PACKET_NUMBER, packet_number
  end

  def test_encrypt_chacha20
    skip "ChaCha20 not implemented yet"
  end

  def test_encrypt_long_client
    pair = create_crypto(is_client: true)
    packet = pair.encrypt_packet(
      plain_header: LONG_CLIENT_PLAIN_HEADER, plain_payload: LONG_CLIENT_PLAIN_PAYLOAD, packet_number: LONG_CLIENT_PACKET_NUMBER,
    )
    assert_equal LONG_CLIENT_ENCRYPTED_PACKET, packet
  end

  def test_encrypt_long_server
    pair = create_crypto(is_client: false)
    packet = pair.encrypt_packet(
      plain_header: LONG_SERVER_PLAIN_HEADER, plain_payload: LONG_SERVER_PLAIN_PAYLOAD, packet_number: LONG_SERVER_PACKET_NUMBER,
    )
    assert_equal LONG_SERVER_ENCRYPTED_PACKET, packet
  end

  def test_encrypt_short_server
    pair = Raioquic::Quic::Crypto::CryptoPair.new
    pair.send.setup(
      cipher_suite: Raioquic::Quic::Crypto::INITIAL_CIPHER_SUITE,
      secret: ["310281977cb8c1c1c1212d784b2d29e5a6489e23de848d370a5a2f9537f3a100"].pack("H*"),
      version: Raioquic::Quic::Packet::QuicProtocolVersion::VERSION_1,
    )
    packet = pair.encrypt_packet(
      plain_header: SHORT_SERVER_PLAIN_HEADER, plain_payload: SHORT_SERVER_PLAIN_PAYLOAD, packet_number: SHORT_SERVER_PACKET_NUMBER,
    )
    assert_equal SHORT_SERVER_ENCRYPTED_PACKET, packet
  end

  def test_key_update # rubocop:disable Metrics/MethodLength
    pair1 = create_crypto(is_client: true)
    pair2 = create_crypto(is_client: false)

    create_packet = lambda do |key_phase, packet_number|
      buf = Raioquic::Buffer.new(capacity: 100)
      buf.push_uint8(::Raioquic::Quic::Packet::PACKET_FIXED_BIT | (key_phase << 2) | 1)
      buf.push_bytes(["8394c8f03e515708"].pack("H*"))
      buf.push_uint16(packet_number)
      return [buf.data, "\x00\x01\x02\x03"]
    end

    send = lambda do |sender, receiver, packet_number|
      plain_header, plain_payload = create_packet.call(sender.key_phase, packet_number)
      encrypted = sender.encrypt_packet(plain_header: plain_header, plain_payload: plain_payload, packet_number: packet_number)
      recov_header, recov_payload, recov_packet_number = receiver.decrypt_packet(
        packet: encrypted, encrypted_offset: plain_header.length - 2, expected_packet_number: 0,
      )
      assert_equal plain_header, recov_header
      assert_equal plain_payload, recov_payload
      assert_equal recov_packet_number, packet_number
    end

    send.call(pair1, pair2, 0)
    send.call(pair2, pair1, 0)
    assert_equal 0, pair1.key_phase
    assert_equal 0, pair2.key_phase

    pair1.update_key

    send.call(pair1, pair2, 1)
    send.call(pair2, pair1, 1)
    assert_equal 1, pair1.key_phase
    assert_equal 1, pair2.key_phase

    pair2.update_key

    send.call(pair2, pair1, 2)
    send.call(pair1, pair2, 2)
    assert_equal 0, pair1.key_phase
    assert_equal 0, pair2.key_phase

    pair1.update_key

    send.call(pair2, pair1, 3)
    send.call(pair1, pair2, 3)
    assert_equal 1, pair1.key_phase
    assert_equal 1, pair2.key_phase
  end
end
