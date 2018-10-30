#!/usr/bin/env python
# encoding: utf-8
# Copyright 2018, The RouterSploit Framework (RSF) by Threat9 All rights reserved.
import socket
from core.Exploit import Exploit, Protocol
from core.Option import BoolOption
from core.Printer import print_error
from core.Utils import is_ipv4, is_ipv6
UDP_SOCKET_TIMEOUT = 10.0


class BaseUDPClient(object):
    """ UDP Client provides methods to handle communication with UDP server """

    def __init__(self, udp_target: str, udp_port: int, verbosity: bool=False) -> None:
        """ UDP client constructor
        :param str udp_target: target UDP server ip address
        :param int udp_port: target UDP server port
        :param bool verbosity: display verbose output
        :return None:
        """
        self.udp_target = udp_target
        self.udp_port = udp_port
        self.verbosity = verbosity
        self.peer = "{}:{}".format(self.udp_target, self.udp_port)
        if is_ipv4(self.udp_target):
            self.udp_client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        elif is_ipv6(self.udp_target):
            self.udp_client = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        else:
            print_error("Target address is not valid IPv4 nor IPv6 address", verbose=self.verbosity)
            return None
        self.udp_client.settimeout(UDP_SOCKET_TIMEOUT)

    def send(self, data: bytes) -> bool:
        """ Send UDP data
        :param bytes data: data that should be sent to the server
        :return bool: True if data was sent, False otherwise
        """
        try:
            self.udp_client.sendto(data, (self.udp_target, self.udp_port))
            return True
        except Exception as err:
            print_error(self.peer, "Error while sending data", err, verbose=self.verbosity)
        return False

    def receive(self, num: int) -> bytes:
        """ Receive UDP data
        :param int num: number of bytes that should received from the server
        :return bytes: bytes received from the server
        """
        try:
            response = self.udp_client.recv(num)
            return response
        except Exception as err:
            print_error(self.peer, "Error while receiving data", err, verbose=self.verbosity)
        return None

    def close(self) -> bool:
        """ Close UDP connection
        :return bool: True if connection was closed successful, False otherwise
        """
        try:
            self.udp_client.close()
            return True
        except Exception as err:
            print_error(self.peer, "Error while closing udp socket", err, verbose=self.verbosity)
        return False


class UDPClient(Exploit):
    """ UDP Client exploit """
    target_protocol = Protocol.UDP
    verbosity = BoolOption(True, "Enable verbose output: true/false")

    def udp_create(self, target: str=None, port: int=None) -> BaseUDPClient:
        """ Create UDP client
        :param str target: target UDP server ip address
        :param int port: target UDP server port
        :return UDPCli: UDP client object
        """
        udp_target = target if target else self.target
        udp_port = port if port else self.port
        udp_client = BaseUDPClient(udp_target, udp_port, verbosity=self.verbosity)
        return udp_client
