#!/usr/bin/env python
# encoding: utf-8
# Copyright 2018, The RouterSploit Framework (RSF) by Threat9 All rights reserved.
import os
import importlib
from collections import namedtuple
from struct import pack
from future.utils import with_metaclass
from core.Exploit import BaseExploit, ExploitOptionsAggregator
from core.Option import IPOption, PortOption, StringOption
from core.Exceptions import OptionValidationError
from core.Printer import print_info, print_error, print_status, print_success
from core.Utils import random_text
architectures = namedtuple("ArchitectureType", ["ARMLE", "MIPSBE", "MIPSLE", "X86", "X64", "PERL", "PHP", "PYTHON"])
architectures_wrapper = architectures(ARMLE="armle", MIPSBE="mipele", MIPSLE="mipsle", X86="x86", X64="x64", PERL="perl", PHP="php", PYTHON="python")
payload_handler = namedtuple("PayloadHandlers", ["BIND_TCP", "REVERSE_TCP"])
payload_handler_wrapper = payload_handler(BIND_TCP="bind_tcp", REVERSE_TCP="reverse_tcp")
ARCH_ELF_HEADERS = {
    architectures_wrapper.ARMLE: (
        b"\x7f\x45\x4c\x46\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x02\x00\x28\x00\x01\x00\x00\x00\x54\x80\x00\x00\x34\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x34\x00\x20\x00\x01\x00\x00\x00"
        b"\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00"
        b"\x00\x80\x00\x00\xef\xbe\xad\xde\xef\xbe\xad\xde\x07\x00\x00\x00"
        b"\x00\x10\x00\x00"
    ),
    architectures_wrapper.MIPSBE: (
        b"\x7f\x45\x4c\x46\x01\x02\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x02\x00\x08\x00\x00\x00\x01\x00\x40\x00\x54\x00\x00\x00\x34"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x34\x00\x20\x00\x01\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x40\x00\x00"
        b"\x00\x40\x00\x00\xde\xad\xbe\xef\xde\xad\xbe\xef\x00\x00\x00\x07"
        b"\x00\x00\x10\x00"
    ),
    architectures_wrapper.MIPSLE: (
        b"\x7f\x45\x4c\x46\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x02\x00\x08\x00\x01\x00\x00\x00\x54\x00\x40\x00\x34\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x34\x00\x20\x00\x01\x00\x00\x00"
        b"\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00"
        b"\x00\x00\x40\x00\xef\xbe\xad\xde\xef\xbe\xad\xde\x07\x00\x00\x00"
        b"\x00\x10\x00\x00"
    ),
    architectures_wrapper.X86: (
        b"\x7f\x45\x4c\x46\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x02\x00\x03\x00\x01\x00\x00\x00\x54\x80\x04\x08\x34\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x34\x00\x20\x00\x01\x00\x00\x00"
        b"\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x80\x04\x08"
        b"\x00\x80\x04\x08\xef\xbe\xad\xde\xef\xbe\xad\xde\x07\x00\x00\x00"
        b"\x00\x10\x00\x00"
    ),
    architectures_wrapper.X64: (
        b"\x7f\x45\x4c\x46\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x02\x00\x3e\x00\x01\x00\x00\x00\x78\x00\x40\x00\x00\x00\x00\x00"
        b"\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x40\x00\x38\x00\x01\x00\x00\x00\x00\x00\x00\x00"
        b"\x01\x00\x00\x00\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00"
        b"\x41\x41\x41\x41\x41\x41\x41\x41\x42\x42\x42\x42\x42\x42\x42\x42"
        b"\x00\x10\x00\x00\x00\x00\x00\x00"
    )
}


class ReverseTCPPayloadMixin(with_metaclass(ExploitOptionsAggregator, object)):
    handler = payload_handler_wrapper.REVERSE_TCP
    lhost = IPOption('', 'Connect-back IP Address')
    lport = PortOption(5555, 'Connect-back TCP Port')


class BindTCPPayloadMixin(with_metaclass(ExploitOptionsAggregator, object)):
    handler = payload_handler_wrapper.BIND_TCP
    rport = PortOption(5555, 'Bind Port')


class BasePayload(BaseExploit):
    architecture = None
    handler = None
    encoder = StringOption("", "Encoder")
    fmt = None

    def __init__(self):
        if self.handler not in payload_handler_wrapper:
            raise OptionValidationError("Please use one of valid handlers: {}".format(payload_handler_wrapper._fields))

    def generate(self):
        raise OptionValidationError("Please implement generate method")

    def run(self):
        raise OptionValidationError("Please implement run method")

    def get_encoders(self):
        path = "modules/encoders/{}".format(self.architecture)
        encoders = []
        try:
            files = os.listdir(path)
        except FileNotFoundError:
            return []
        for f in files:
            if not f.startswith("__") and f.endswith(".py"):
                encoder = f.replace(".py", "")
                module_path = "{}/{}".format(path, encoder).replace("/", ".")
                module = getattr(importlib.import_module(module_path), "Encoder")
                encoders.append(("{}/{}".format(self.architecture, encoder), module._Encoder__info__["name"], module._Encoder__info__["description"],))
        return encoders

    @staticmethod
    def get_encoder(encoder):
        module_path = "modules/encoders/{}".format(encoder).replace("/", ".")
        try:
            module = getattr(importlib.import_module(module_path), "Encoder")
        except ImportError:
            return None
        return module()


class ArchitectureSpecificPayload(BasePayload):
    output = StringOption("python", "Output type: ELF/C/Python")
    file_path = StringOption("/tmp/{}".format(random_text(8)), "Output file to write")

    def __init__(self):
        super(ArchitectureSpecificPayload, self).__init__()
        if self.architecture not in architectures_wrapper:
            raise OptionValidationError("Please use one of valid architectures: {}".format(architectures_wrapper._fields))
        self.header = ARCH_ELF_HEADERS[self.architecture]
        self.big_endian = True if self.architecture.endswith("be") else False

    def run(self):
        print_status("Generating payload")
        try:
            data = self.generate()
        except OptionValidationError as error_code:
            print_error(error_code)
            return
        if self.output == "elf" or self.output == "ELF":
            with open(self.file_path, "wb+") as f:
                print_status("Building ELF payload")
                content = self.generate_elf(data)
                print_success("Saving file: {}".format(self.file_path))
                f.write(content)
        elif self.output == "c" or self.output == "C":
            print_status("Building payload for C")
            content = self.generate_c(data)
            print_info(content)
        elif self.output == "python" or self.output == "Python":
            print_status("Building payload for Python")
            content = self.generate_python(data)
            print_info(content)
        else:
            raise OptionValidationError("No such option as {}".format(self.output))
        return content

    def generate_elf(self, data):
        elf = self.header + data
        if elf[4] == 1:  # ELFCLASS32 - 32 bit
            if self.big_endian:
                p_filesz = pack(">L", len(elf))
                p_memsz = pack(">L", len(elf) + len(data))
            else:
                p_filesz = pack("<L", len(elf))
                p_memsz = pack("<L", len(elf) + len(data))
            content = elf[:0x44] + p_filesz + p_memsz + elf[0x4c:]
        elif elf[4] == 2:  # ELFCLASS64 - 64 bit
            if self.big_endian:
                p_filesz = pack(">Q", len(elf))
                p_memsz = pack(">Q", len(elf) + len(data))
            else:
                p_filesz = pack("<Q", len(elf))
                p_memsz = pack("<Q", len(elf) + len(data))
            content = elf[:0x60] + p_filesz + p_memsz + elf[0x70:]
        return content

    @staticmethod
    def generate_c(data):
        resource = "unsigned char shell_code[] = {\n    \""
        for index, x in enumerate(data):
            if index % 15 == 0 and index != 0:
                resource += "\"\n    \""
            resource += "\\x%02x" % x
        resource += "\"\n};"
        return resource

    @staticmethod
    def generate_python(data):
        resource = "payload = (\n    \""
        for index, x in enumerate(data):
            if index % 15 == 0 and index != 0:
                resource += "\"\n    \""
            resource += "\\x%02x" % x
        resource += "\"\n)"
        return resource


class GenericPayload(BasePayload):
    def run(self):
        print_status("Generating payload")
        payload = self.generate()
        if self.encoder:
            payload = self.encoder.encode(payload)
        if self.fmt:
            payload = self.fmt.format(payload)
        print_info(payload)
        return payload
