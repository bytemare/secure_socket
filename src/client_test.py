#!/usr/bin/env python3

from socket import socket, AF_UNIX, SOCK_STREAM, SOL_SOCKET

SO_PASSCRED = 16 # Pulled from /usr/include/asm-generic/socket.h


with socket(AF_UNIX, SOCK_STREAM) as s:
    s.setsockopt(SOL_SOCKET, SO_PASSCRED, 1)
    s.connect('/tmp/sock_secure_socket')

    s.sendall(b'Hello secure_socket\n')
    print("data sent\n")
    data = s.recv(1024)

print('Received : ', repr(data))