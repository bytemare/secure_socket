#!/usr/bin/env python3

from socket import socket, AF_UNIX, SOCK_STREAM, SOL_SOCKET
from time import sleep

sleep(2)

SO_PASSCRED = 16

with socket(AF_UNIX, SOCK_STREAM) as s:
    s.setsockopt(SOL_SOCKET, SO_PASSCRED, 1)
    s.connect('/tmp/sock_secure_socket')

    print("Client sends 'Hello secure_socket'")
    s.sendall(b'Hello secure_socket')
    data = s.recv(1024)

print('Client received : ' + str(data))