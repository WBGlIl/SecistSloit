#!/usr/bin/env python
# encoding: utf-8
# Copyright 2018, The RouterSploit Framework (RSF) by Threat9 All rights reserved.
from pysnmp.entity.rfc3413.oneliner import cmdgen
from core.Exploit import Exploit, Protocol
from core.Printer import print_error, print_success
from core.Option import BoolOption
SNMP_TIMEOUT = 15.0


class BaseSNMPClient(object):
    """ SNMP Client provides methods to handle communication with SNMP server """

    def __init__(self, snmp_target: str, snmp_port: int, verbosity: bool=False) -> None:
        """ SNMP client constructor
        :param str snmp_target: target SNMP server ip address
        :param port snmp_port: target SNMP server port
        :param bool verbosity: display verbose output
        :return None:
        """
        self.snmp_target = snmp_target
        self.snmp_port = snmp_port
        self.verbosity = verbosity
        self.peer = "{}:{}".format(self.snmp_target, self.snmp_port)

    def get(self, community_string: str, oid: str, version: int=1, retries: int=0) -> bytes:
        """ Get OID from SNMP server
        :param str community_string: SNMP server communit string
        :param str oid: SNMP server oid
        :param int version: SNMP protocol version
        :param int retries: number of retries
        :return bytes: SNMP server response
        """
        cmd_generator = cmdgen.CommandGenerator()
        try:
            error_indication, error_status, error_index, var_binds = cmd_generator.getCmd(cmdgen.CommunityData(community_string, mpModel=version), cmdgen.UdpTransportTarget((self.snmp_target, self.snmp_port), timeout=SNMP_TIMEOUT, retries=retries), oid)
        except Exception as error_code:
            print_error(self.peer, "SNMP Error while accessing server", error_code, verbose=self.verbosity)
            return None
        if error_indication or error_status:
            print_error(self.peer, "SNMP Invalid community string: '{}'".format(community_string), verbose=self.verbosity)
        else:
            print_success(self.peer, "SNMP Valid community string found: '{}'".format(community_string), verbose=self.verbosity)
            return var_binds
        return None


class SNMPClient(BaseSNMPClient):
    """ Create SNMP Exploit """
    target_protocol = Protocol.SNMP
    verbosity = BoolOption(True, "Enable verbose output? (true/false): ")

    def snmp_create(self, target: str=None, port: int=None) -> BaseSNMPClient:
        """ Create SNMP client
        :param str target: target SNMP server ip address
        :param int port: target SNMP server port
        :return SNMPCli: SNMP client object
        """
        snmp_target = target if target else self.target
        snmp_port = port if port else self.port
        snmp_client = BaseSNMPClient(snmp_target, snmp_port, verbosity=self.verbosity)
        return snmp_client
