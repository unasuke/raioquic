import socket
import time

from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import StreamDataReceived
from aioquic.quic import packet
from aioquic.buffer import Buffer

if __name__ == '__main__':
    conf = QuicConfiguration(is_client=False)
    conf.load_cert_chain(certfile="localhost-unasuke-dev.crt", keyfile="key.pem")
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(("0.0.0.0", 4433))
    connections = {}

    while True:
        data, client_addr = server_socket.recvfrom(65536)
        header = packet.pull_quic_header(Buffer(data=data), conf.connection_id_length)
        connection = connections.get(header.destination_cid)
        if connection is None and header.packet_type == packet.PACKET_TYPE_INITIAL:
            conn = QuicConnection(configuration=conf, original_destination_connection_id=header.destination_cid)
            connections[conn.host_cid] = conn
        if conn is not None:
            conn.receive_datagram(data=data, addr=client_addr, now=time.time())
            while True:
              event = conn.next_event()
              if event == None:
                  break
              print(event)
              if type(event) == StreamDataReceived and event.data == b"hello":
                  conn.send_stream_data(event.stream_id, b"hello")
            for data, addr in conn.datagrams_to_send(now=time.time()):
                server_socket.sendto(data, addr)
