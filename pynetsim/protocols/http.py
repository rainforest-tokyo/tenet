# Copyright (C) 2017 Jason Jones.
# This file is part of 'PyNetSim' - https://github.com/arbor-jjones/pynetsim
# See the file 'LICENSE' for copying permission.

import re
import socket
import logging
import select
import datetime

import pynetsim.protocols.tcp as tcp
import pynetsim.lib.core as core

log = logging.getLogger(__name__)

class HTTP(tcp.TCP):

    name = "http"
    recv_buffer = ""

    http_regex = re.compile(r"^(get|put|options|post)[ \t]+[^ \t]+[ \t]+HTTP/", flags=re.IGNORECASE)
    http_response = """HTTP/1.1 {} OK
Date: {}
Server: {}
Content-Length: {}
Content-Type: text/html; charset=iso-8859-1
Connection: close

{}
"""

    def run(self):
        # Select Honey
        config_info = core.get_honey_list()
        honey_info = config_info["http"][0]

        # Connect to Honey
        honey_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        log.debug( "Connect Honey {}:{}".format(honey_info["ip"],honey_info["port"]) )
        honey_socket.connect((honey_info["ip"],honey_info["port"]))

        # Send recv
        recv_data = self.recv()
        if recv_data != None :
            self.recv_buffer = recv_data
        honey_socket.send( self.recv_buffer )
        response = honey_socket.recv( 4096*10 )
        self.send( response )

        honey_socket.close()
        self.socket.close()
        log.debug( "Close Honey {}:{}".format(honey_info["ip"],honey_info["port"]) )

    def recv(self):
        s = select.select([self.socket], [], [], 1)
        if s[0]:
            data = self.socket.recv(self.recv_size)
        else:
            data = None
        return data

    @classmethod
    def guess_protocol_from_payload(cls, payload, config, addr):
        """
        Iterates through known protocols to see if the payload is recognized

        :param payload: raw payload received from a connection 
        :return: Protocol object
        """
        identified_protocol = tcp.TCP
        if payload and cls.http_regex.match(payload.decode('utf-8', errors="ignore")):
            identified_protocol = HTTP

            cls.recv_buffer = payload
#            for protocol in cls.get_known_protocols(config):
#                log.debug("Checking for {}".format(protocol))
#                protocol_class = core.find_protocol_class(protocol)
#                new_protocol = protocol_class.guess_protocol_from_payload(payload, config, addr)
#                log.debug(new_protocol)
#                if new_protocol != identified_protocol:
#                    log.debug("New sub-protocol detected: {}".format(new_protocol.name))
#                    identified_protocol = new_protocol
#                    break
        return identified_protocol
