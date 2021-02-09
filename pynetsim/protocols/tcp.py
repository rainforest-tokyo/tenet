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

from pynetsim.protocols.protocol import BotWhisperer

log = logging.getLogger(__name__)

class TCP(BotWhisperer):

    name = "tcp"

    def run(self):
        # Select Honey
        honey_info = core.HoneyList["telnet"][0]

        # Connect to Honey
        honey_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        log.debug( "Connect Honey {}:{}".format(honey_info["ip"],honey_info["port"]) )
        honey_socket.connect((honey_info["ip"],honey_info["port"]))

        # recv banner
        response = honey_socket.recv( 4096*10 )
        log.debug( response )
        self.send( response )

        while True:
            # Attacker -> Honey
            log.debug("Attacker -> Honey")
            request = self.recv()
            if request != None :
                log.debug( request )
                honey_socket.send( request )
                log.debug("Return recv")

            # Honey -> Attacker
            log.debug("Honey -> Attacker")
            response = honey_socket.recv( 4096*10 )
            log.debug( response )
            self.send( response )
        log.debug("Exit Loop")

        honey_socket.close()
        self.socket.close()

    def recv(self):
        s = select.select([self.socket], [], [], 1)
        if s[0]:
            data = self.socket.recv(self.recv_size)
        else:
            data = None
        return data
#        load = None
#        while not load:
#            s = select.select([self.socket], [], [], 10)
#            if s[0]:
#                load = self.socket.recv(self.recv_size)
#        return load
