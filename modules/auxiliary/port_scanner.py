#!/usr/bin/env python
# encoding: utf-8
import nmap
from core.Option import *
from protocol.tcp.TCPClient import TCPClient


class Exploit(TCPClient):
    __info__ = {
        "name": "nmap_scan_port",
        "description": "nmap_scan_port",
        "authors": (
            "jiushi",
        ),
        "references": (
             "www.422926799.github.io"
             "www.422926799.github.io"
        ),

    }

    rhost = IPOption("", "Target IP")

    def __init__(self):
        self.end_flag = "<"

    def run(self):
        rhost = self.rhost
        print('[+] Port scanning...')
        print('[+] RHOST {}'.format(rhost))
        host = '{}'.format(rhost)
        ports = '0-1024'
        nm = nmap.PortScanner()
        nm.scan(host, ports)
        for i in range(1, 1024):
            try:
                state = nm[host]['tcp'][int(i)]['state']
                print('[+]{}:{}'.format(host, i), state)
            except:
                pass
