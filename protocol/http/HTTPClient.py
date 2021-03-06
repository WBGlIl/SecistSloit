#!/usr/bin/env python
# encoding: utf-8
# Copyright 2018, The RouterSploit Framework (RSF) by Threat9 All rights reserved.
import socket
import requests
import urllib3
from core.Exploit import Exploit, Protocol
from core.Option import BoolOption
from core.Printer import print_error
urllib3.disable_warnings(urllib3.exceptions.InsecurePlatformWarning)
HTTP_TIMEOUT = 30.0


class HTTPClient(Exploit):
    """ HTTP Client provides methods to handle communication with HTTP server """
    target_protocol = Protocol.HTTP
    verbosity = BoolOption(True, "Enable verbose output? (true/false): ")
    ssl = BoolOption(False, "Enable ssl connection? (true/false): ")

    def http_request(self, method: str, path: str, session: requests=requests, **kwargs) -> requests.Response:
        """ Requests HTTP resource
        :param str method: method that should be issued e.g. GET, POST
        :param str path: path to the resource that should be requested
        :param requests session: session manager that should be used
        :param kwargs: kwargs passed to request method
        :return Response: Response object
        """
        if self.ssl:
            url = "https://"
        else:
            url = "http://"
        url += "{}:{}{}".format(self.target, self.port, path)
        kwargs.setdefault("timeout", HTTP_TIMEOUT)
        kwargs.setdefault("verify", False)
        kwargs.setdefault("allow_redirects", False)
        try:
            return getattr(session, method.lower())(url, **kwargs)
        except (requests.exceptions.MissingSchema, requests.exceptions.InvalidSchema):
            print_error("Invalid URL format: {}".format(url), verbose=self.verbosity)
        except requests.exceptions.ConnectionError:
            print_error("Connection error: {}".format(url), verbose=self.verbosity)
        except requests.RequestException as error_code:
            print_error(error_code, verbose=self.verbosity)
        except socket.error as error_code:
            print_error(error_code, verbose=self.verbosity)
        except KeyboardInterrupt:
            print_error("Module has been stopped", verbose=self.verbosity)
        return None

    def get_target_url(self, path: str="") -> str:
        """ Get target URL
        :param str path: path to http server resource
        :return str: full target url with correct schema
        """
        if self.ssl:
            url = "https://"
        else:
            url = "http://"
        url += "{}:{}{}".format(self.target, self.port, path)
        return url

    def http_test_connect(self) -> bool:
        """ Test connection to HTTP server
        :return bool: True if test connection was successful, False otherwise
        """
        response = self.http_request(method="GET", path="/")
        if response:
            return True
        else:
            return False
