# frozen_string_literal: true

require "test_helper"

class TestRaioquicCryptoAESGCM < Minitest::Test
  AESGCM = ::Raioquic::Crypto::AESGCM

  class FakeData
    def length
      2**31
    end
  end

  def test_data_too_large
    key = AESGCM.generate_key(128)
    aesgcm = AESGCM.new(key)
    nonce = "0" * 12
    assert_raises ::Raioquic::Crypto::AESGCM::OverflowError do
      aesgcm.encrypt(nonce: nonce, data: FakeData.new, associated_data: "")
    end
    assert_raises ::Raioquic::Crypto::AESGCM::OverflowError do
      aesgcm.encrypt(nonce: nonce, data: "", associated_data: FakeData.new)
    end
  end

  def test_invalid_nonce_length
    key = AESGCM.generate_key(128)
    aesgcm = AESGCM.new(key)
    [7, 129].each do |length|
      assert_raises ::Raioquic::ValueError do
        aesgcm.encrypt(nonce: "\x00" * length, data: "hi")
      end
    end
  end

  def test_bad_key
    assert_raises TypeError do
      AESGCM.new(Object.new)
    end
    assert_raises ::Raioquic::ValueError do
      AESGCM.new("0" * 31)
    end
  end

  def test_bad_generate_key
    assert_raises TypeError do
      AESGCM.generate_key(Object.new)
    end
    assert_raises ::Raioquic::ValueError do
      AESGCM.generate_key(129)
    end
  end

  def test_associated_data_none_equal_to_empty_bytestring
    key = AESGCM.generate_key(128)
    aesgcm = AESGCM.new(key)
    nonce = Random.urandom(12)
    ct1 = aesgcm.encrypt(nonce: nonce, data: "some_data")
    ct2 = aesgcm.encrypt(nonce: nonce, data: "some_data", associated_data: "")
    assert_equal ct1, ct2
    pt1 = aesgcm.decrypt(nonce: nonce, data: ct1)
    pt2 = aesgcm.decrypt(nonce: nonce, data: ct2, associated_data: "")
    assert_equal pt1, pt2
  end

  def test_buffer_protocol
    key = AESGCM.generate_key(128)
    aesgcm = AESGCM.new(key)
    pt = "encrypt me"
    ad = "additional"
    nonce = Random.urandom(12)
    ct = aesgcm.encrypt(nonce: nonce, data: pt, associated_data: ad)
    computed_pt = aesgcm.decrypt(nonce: nonce, data: ct, associated_data: ad)
    assert_equal computed_pt, pt
  end
end
