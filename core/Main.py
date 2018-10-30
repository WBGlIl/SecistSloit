#!/usr/bin/env python
# encoding: utf-8
# Copyright 2018, The RouterSploit Framework (RSF) by Threat9 All rights reserved.
import atexit
import itertools
import os
import sys
import traceback
from collections import Counter
from future.builtins import input
from core.Exceptions import StandardException
from core.Utils import *
from core.Printer import *
from core.Exploit import GLOBAL_OPTS
from core.Payloads import BasePayload
from prompt_toolkit import *
platform = sys.platform


class BaseInterpreter(object):
    def __init__(self):
        self.setup()
        if platform == "linux" or platform == "darwin":
            os.system('clear')
        elif platform == "window":
            os.system('cls')
        self.banner = ""

    def setup(self):
        """ Initialization of third-party libraries
        Setting interpreter history.
        Setting appropriate completer function.
        :return:
        """
        pass


class Interpreter(BaseInterpreter):
    global_help = """Global commands:
        help                        Print this help menu
        use <module>                Select a module for usage
        exec <shell command> <args> Execute a command in a shell
        search <search term>        Search for appropriate module
        exit                        Exit SecistSploit"""
    module_help = """Module commands:
        run                                 Run the selected module with the given options
        back                                De-select the current module
        set <option name> <option value>    Set an option for the selected module
        setg <option name> <option value>   Set an option for all of the modules
        unsetg <option name>                Unset option that was set globally
        show [info|options|devices]         Print information, options, or target devices for a module
        check                               Check if a given target is vulnerable to a selected module's exploit"""

    def __init__(self):
        super(Interpreter, self).__init__()
        PrinterThread.start()

