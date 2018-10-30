#!/usr/bin/env python
# encoding: utf-8
# Copyright 2018, The RouterSploit Framework (RSF) by Threat9 All rights reserved.
import re
import os
import importlib
import string
import random
import operator
from functools import wraps
import modules as routersploit_module
from core.Exceptions import StandardException
from core.Printer import print_info, print_error
MODULES_DIR = routersploit_module.__path__[0]


def random_text(length: int, alpha: str=string.ascii_letters + string.digits) -> str:
    """ Generates random string text
    :param int length: length of text to generate
    :param str alpha: string of all possible characters to choose from
    :return str: generated random string of specified size
    """
    return "".join(random.choice(alpha) for _ in range(length))


def is_ipv4(address: str) -> bool:
    """ Checks if given address is valid IPv4 address
    :param str address: IP address to check
    :return bool: True if address is valid IPv4 address, False otherwise
    """
    regexp = "^(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
    if re.match(regexp, address):
        return True
    else:
        return False


def is_ipv6(address: str) -> bool:
    """ Checks if given address is valid IPv4 address
    :param str address: IP address to check
    :return bool: True if address is valid IPv4 address, False otherwise
    """
    regexp = "^(?:(?:[0-9A-Fa-f]{1,4}:){6}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|::(?:[0-9A-Fa-f]{1,4}:){5}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){4}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){3}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,2}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){2}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,3}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}:(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,4}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,5}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}|(?:(?:[0-9A-Fa-f]{1,4}:){,6}[0-9A-Fa-f]{1,4})?::)%.*$"
    if re.match(regexp, address):
        return True
    else:
        return False


def convert_ip(address: str) -> bytes:
    """ Converts IP to bytes
    :param str address: IP address that should be converted to bytes
    :return bytes: IP converted to bytes format
    """
    resource = b""
    for i in address.split("."):
        resource += bytes([int(i)])
    return resource


def convert_port(port: int) -> bytes:
    """ Converts Port to bytes
    :param int port: port that should be conveted to bytes
    :return bytes: port converted to bytes format
    """
    resource = "%.4x" % int(port)
    return bytes.fromhex(resource)


def index_modules(modules_directory: str=MODULES_DIR) -> list:
    """ Returns list of all exploits modules
    :param str modules_directory: path to modules directory
    :return list: list of found modules
    """
    modules = []
    for root, directory, files in os.walk(modules_directory):
        _, package, root = root.rpartition("modules/".replace("/", os.sep))
        root = root.replace(os.sep, ".")
        files = filter(lambda x: not x.startswith("__") and x.startswith(".py"), files)
        modules.extend(map(lambda x: ".".join((root, os.path.splitext(x)[0])), files))
    return modules


def index_exploit(path: str):
    """ Imports exploit module
    :param str path: absolute path to exploit e.g. modules.exploits.asus_auth_bypass
    :return: exploit module or error
    """
    try:
        module = importlib.import_module(path)
        if hasattr(module, "Payload"):
            return getattr(module, "Payload")
        elif hasattr(module, "Encoder"):
            return getattr(module, "Encoder")
        elif hasattr(module, "Exploit"):
            return getattr(module, "Exploit")
        else:
            raise ImportError("No module named {}".format(path))
    except (ImportError, AttributeError, KeyError) as error_message:
        raise StandardException("Error during load '{}'\n\nError: {}\n\nIt should be valid path to the module, Use <Tab> key multiple time for completion".format(humanize_path(path), error_message))


def module_iterator(module_directory: str=MODULES_DIR) -> list:
    """ Iterates over valid modules
    :param str module_directory: path to modules directory
    :return list: list of found modules
    """
    module = index_modules(module_directory)
    module = map(lambda x: "".join(["modules.", x]), module)
    for path in module:
        yield index_exploit(path)


def pythonize_path(path: str) -> str:
    """ Replaces argument to valid python dotted notation.
    ex. foo/bar/baz -> foo.bar.baz
    :param str path: path to pythonize
    :return str: pythonize path
    """
    return path.replace("/", ".")


def humanize_path(path: str) -> str:
    """ Replace python dotted path to directory-like one.
    ex. foo.bar.baz -> foo/bar/baz
    :param str path: path to humanize
    :return str: humanized path
    """
    return path.replace(".", "/")


def require_module(fun):
    """ Checks if module is loaded.
    Decorator that checks if any module is activated
    before executing command specific to modules (ex. 'run').
    """
    @wraps(fun)
    def wrapper(self, *args, **kwargs):
        if not self.current_module:
            print_error("You have to activate any module with 'use' command.")
            return
        return fun(self, *args, **kwargs)

    try:
        name = "require_module"
        wrapper.__decorators__.append(name)
    except AttributeError:
        wrapper.__decorators__ = name
    return wrapper


def stop_after(space_number):
    """ Decorator that determines when to stop tab-completion
    Decorator that tells command specific complete function
    ex. "complete_use") when to stop tab-completion.
    Decorator counts number of spaces (' ') in line in order
    to determine when to stop.
    ex. "use exploits/dlink/specific_module " -> stop complete after 2 spaces
        "set rhost " -> stop completing after 2 spaces
        "run " -> stop after 1 space
    :param space_number: number of spaces (' ') after which tab-completion should stop
    :return:
    """
    def outer_wrapper(wrapped_function):
        @wraps(wrapped_function)
        def wrapper(self, *args, **kwargs):
            try:
                if args[1].count(" ") == space_number:
                    return []
            except Exception as error_code:
                print_info(error_code)
            return wrapped_function(self, *args, **kwargs)
        return wrapper
    return outer_wrapper


def lookup_vendor(address: str) -> str:
    """ Lookups vendor (manufacturer) based on MAC address
    :param str address: MAC address to lookup
    :return str: vendor name from oui.dat database
    """
    address = address.upper().replace(":", "")
    path = "resources/vendors/out.dat"
    with open(path, "r") as f:
        for line in f.readlines():
            line = line.strip()
            if line == "" or line[0] == "#":
                continue
            mac, name = line.split(" ", 1)
            if address.startswith(mac):
                return name
    return None


class Version(object):
    def __init__(self, value):
        self.value = str(value)

    def __set__(self, value):
        self.value = value

    def __lt__(self, other):
        if self._compare_version(self.value, other.value) < 0:
            return True
        else:
            return False

    def __le__(self, other):
        if self._compare_version(self.value, other.value) <= 0:
            return True
        else:
            return False

    def __eq__(self, other):
        return self.value == other.value

    def __ne__(self, other):
        return self.value != other.value

    def __gt__(self, other):
        if self._compare_version(self.value, other.value) > 0:
            return True
        else:
            return False

    def __ge__(self, other):
        if self._compare_version(self.value, other.value) >= 0:
            return True
        else:
            return False

    @staticmethod
    def _compare_version(version1, version2):
        """ Version comparision
        :param Version version1:
        :param Version version2:
        :return int:
        if version1 < version2 then -1
        if version1 == version2 then 0
        if version1 > version2 then 1
        """
        arr1 = re.sub("\D", ".", str(version1)).split(".")
        arr2 = re.sub("\D", ".", str(version2)).split(".")
        if operator.eq(arr1, arr2):
            return 0
        elif operator.gt(arr1, arr2):
            return 1
        elif operator.lt(arr1, arr2):
            return -1


def detect_file_content(content: str, f: str="/etc/passwd") -> bool:
    """ Detect specific file content in content
    :param str content: file content that should be analyzed
    :param str f: file that the content should be compared with
    :return bool: True if the content was recognized, False otherwise
    """
    if f in ["/etc/passwd", "/etc/shadow"]:
        if re.findall(r"(root|[aA]dmin):.*?:.*?:.*?:.*?:.*?:", content):
            return True
        else:
            return False
