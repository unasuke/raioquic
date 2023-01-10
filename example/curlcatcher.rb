require 'socket'

host = ENV.fetch("HOST", "0.0.0.0")
port = ENV.fetch("PORT", 8080).to_i

socket = UDPSocket.new
socket.bind(host, port)

puts "server start"
loop do
  begin
    raw, addr = socket.recvmsg_nonblock(1000)
  rescue IO::WaitReadable
    retry
  end

  puts raw.unpack1("H*") + "\n=============\n" if raw
end
