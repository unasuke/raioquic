# frozen_string_literal: true

require "test_helper"

class TestRaioquicQuicPacket < Minitest::Test
  def test_decode_packet_number
  end

  def test_pull_empty
  end

  def test_pull_initiali_client
  end

  def test_pull_initial_client_truncated
  end

  def test_pull_initial_server
  end

  def test_pull_retry
  end

  def test_pull_retry_draft_29
  end

  def test_pull_version_negotiation
  end

  def test_pull_long_header_dcid_too_long
  end

  def test_pull_long_header_scid_too_long
  end

  def test_pull_long_header_no_fixed_bit
  end

  def test_pull_long_header_too_short
  end

  def test_pull_short_header
  end

  def test_pull_short_header_no_fixed_bit
  end

  def test_encode_quic_version_negotiation
  end
end
