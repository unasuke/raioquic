require "raioquic"
require "socket"

HOST = ["0.0.0.0", 4433]

conf = Raioquic::Quic::QuicConfiguration.new(is_client: true)
conf.load_verify_locations(cafile: "localhost-unasuke-dev.crt")
client = Raioquic::Quic::Connection::QuicConnection.new(configuration: conf)
client.connect(addr: HOST, now: Time.now.to_f)
s = UDPSocket.new
s.connect("0.0.0.0", 4433)

# handshake
3.times do
  client.datagrams_to_send(now: Time.now.to_f).each do |data, addr|
    # pp data
    s.send(data, 0)
  end
  data, addr = s.recvfrom(65536)
  client.receive_datagram(data: data, addr: HOST, now: Time.now.to_f)
  # puts("()()()()()()()()()(()()")
  # pp client.events
  while ev = client.next_event
    pp ev
  end
end

stream_id = client.get_next_available_stream_id

2.times do
  client.send_stream_data(stream_id: stream_id, data: "hello")
  client.datagrams_to_send(now: Time.now.to_f).each do |data, addr|
    # pp data
    s.send(data, 0)
  end
  data, addr = s.recvfrom(65536)
  client.receive_datagram(data: data, addr: HOST, now: Time.now.to_f)
  while ev = client.next_event
    pp ev
  end
end
client.close
