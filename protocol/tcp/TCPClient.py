#!/usr/bin/env python
# encoding: utf-8
# Copyright 2018, The RouterSploit Framework (RSF) by Threat9 All rights reserved.
import socket
from core.Exploit import Exploit, Protocol
from core.Option import BoolOption
from core.Printer import print_status, print_error
from core.Utils import is_ipv4, is_ipv6
TCP_SOCKET_TIMEOUT = 10.0


class BaseTCPClient(object):
    """ TCP Client provides methods to handle communication with TCP server """

    def __init__(self, tcp_target: str, tcp_port: int, verbosity: bool=False) -> None:
        """ TCP client constructor
        :param str tcp_target: target TCP server ip address
        :param int tcp_port: target TCP server port
        :param bool verbosity: display verbose output
        :return None:
        """
        self.tcp_target = tcp_target
        self.tcp_port = tcp_port
        self.verbosity = verbosity
        self.peer = "{}:{}".format(self.tcp_target, self.tcp_port)
        if is_ipv4(self.tcp_target):
            self.tcp_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        elif is_ipv6(self.tcp_target):
            self.tcp_client = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        else:
            print_error("Target address is not valid IPv4 nor IPv6 address", verbose=self.verbosity)
            return None
        self.tcp_client.settimeout(TCP_SOCKET_TIMEOUT)

    def connect(self) -> bool:
        """ Connect to TCP server
        :return bool: True if connection was successful, False otherwise
        """
        try:
            self.tcp_client.connect((self.tcp_target, self.tcp_port))
            print_status(self.peer, "TCP Connection established", verbose=self.verbosity)
            return True
        except Exception as error_code:
            print_error(self.peer, "TCP Error while connecting to the server", error_code, verbose=self.verbosity)
        return False

    def send(self, data: bytes) -> bool:
        """ Send data to TCP server
        :param bytes data: data that should be sent to TCP server
        :return bool: True if sending data was successful, False otherwise
        """
        try:
            self.tcp_client.send(data)
            return True
        except Exception as error_code:
            print_error(self.peer, "TCP Error while sending data", error_code, verbose=self.verbosity)
        return False

    def receive(self, num: int) -> bytes:
        """ Receive data from TCP server
        :param int num: number of bytes that should be received from the server
        :return bytes: data that was received from the server
        """
        try:
            response = self.tcp_client.recv(num)
            return response
        except Exception as error_code:
            print_error(self.peer, "TCP Error while receiving data", error_code, verbose=self.verbosity)
        return None

    def receive_all(self, num: int) -> bytes:
        """ Receive all data sent by the server
        :param int num: number of total bytes that should be received
        :return bytes: data that was received from the server
        """
        try:
            response = b""
            received = 0
            while received < num:
                tmp = self.tcp_client.recv(num - received)
                if tmp:
                    received += len(tmp)
                    response += tmp
                else:
                    break
            return response
        except Exception as error_code:
            print_error(self.peer, "TCP Error while receiving all data", error_code, verbose=self.verbosity)
        return None

    def close(self) -> bool:
        """ Close connection to TCP server
        :return bool: True if closing connection was successful, False otherwise
        """
        try:
            self.tcp_client.close()
            return True
        except Exception as error_code:
            print_error(self.peer, "TCP Error while closing tcp socket", error_code, verbose=self.verbosity)
        return False


class TCPClient(Exploit):
    """ TCP Client exploit """
    target_protocol = Protocol.TCP
    verbosity = BoolOption(True, "Enable verbose output? (true/false)")

    def tcp_create(self, target: str=None, port: int=None) -> BaseTCPClient:
        """ Creates TCP client
        :param str target: target TCP server ip address
        :param int port: target TCP server port
        :return BaseTCPClient: TCP client object
        """
        tcp_target = target if target else self.target
        tcp_port = port if port else self.port
        tcp_client = BaseTCPClient(tcp_target, tcp_port, verbosity=self.verbosity)
        return tcp_client
