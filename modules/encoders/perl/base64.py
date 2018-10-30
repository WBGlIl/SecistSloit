#!/usr/bin/env python
# encoding: utf-8
# RouterSploit module, Copyright reserved.
import base64
from core.Encoders import BaseEncoder
from core.Payloads import architectures_wrapper


class Encoder(BaseEncoder):
    __info__ = {
        "name": "Perl Base64 Encoder",
        "description": "Module encodes PERL payload to Base64 format.",
        "authors": (
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
    }
    architecture = architectures_wrapper.PERL

    def encode(self, payload):
        encoded_payload = str(base64.b64encode(bytes(payload, "utf-8")), "utf-8")
        return "use MIME::Base64;eval(decode_base64('{}'));".format(encoded_payload)
