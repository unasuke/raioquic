import socket
import time

from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic import packet
from aioquic.buffer import Buffer
from aioquic.quic.events import HandshakeCompleted

if __name__ == '__main__':
    conf = QuicConfiguration(is_client=True)
    conf.load_verify_locations(cafile="localhost-unasuke-dev.crt")
    client = QuicConnection(configuration=conf)
    client.connect(addr=("0.0.0.0", 4433), now=time.time())
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(("0.0.0.0", 4433))
        # handshake
        for i in range(3):
          for data, addr in client.datagrams_to_send(now=time.time()):
            s.sendall(data)
          data, addr = s.recvfrom(65536)
          client.receive_datagram(data=data, addr=addr, now=time.time())
          print(client.next_event())

        stream_id = client.get_next_available_stream_id
        for i in range(2):
          client.send_stream_data(0, b"hello")
          for data, addr in client.datagrams_to_send(now=time.time()):
            s.sendall(data)
          data, addr = s.recvfrom(655536)
          client.receive_datagram(data=data, addr=addr, now=time.time())
        client.close()


        # while True:
        #     event = client.next_event()
        #     # print(event)
        #     if event == None:
        #       # print("AAAAAAAAAAAAAAAAAAA")
        #       stream = client._get_or_create_stream_for_send(stream_id=0)
        #       client.send_stream_data(0, b"hello")
        #       continue
        #     else:
        #       data, addr = s.recvfrom(655536)
        #       client.receive_datagram(data=data, addr=addr, now=time.time())
        #     for data, addr in client.datagrams_to_send(now=time.time()):
        #         s.sendall(data)
