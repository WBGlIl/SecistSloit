#!/usr/bin/env python
# encoding: utf-8
# RouterSploit module, Copyright reserved.
from core.Encoders import BaseEncoder
from core.Payloads import architectures_wrapper


class Encoder(BaseEncoder):
    __info__ = {
        "name": "Perl Hex Encoder",
        "description": "Module encodes PHP payload to Hex format.",
        "authors": (
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
    }

    architecture = architectures_wrapper.PHP

    def encode(self, payload):
        encoded_payload = bytes(payload, "utf-8").hex()
        return "eval(pack('H*','{}'));".format(encoded_payload)
