#!/usr/bin/python

import socket

s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

# Simply print the packet. This will be printed in Python Bytes Object form.
while True:
	print(s.recvfrom(65565))
