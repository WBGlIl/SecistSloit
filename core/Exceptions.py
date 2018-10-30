#!/usr/bin/env python
# encoding: utf-8
# Copyright 2018, The RouterSploit Framework (RSF) by Threat9 All rights reserved.


class StandardException(Exception):
    def __init__(self, message: str=""):
        super(StandardException, self).__init__(message)


class OptionValidationError(StandardException):
    pass


class StopThreadPoolExecution(StandardException):
    pass
