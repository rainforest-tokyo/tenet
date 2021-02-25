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

class TELNET(BotWhisperer):

    name = "telnet"

    def run(self):
        # Select Honey
        config_info = core.get_honey_list()
        honey_info = config_info["telnet"][0]

        # Connect to Honey
        honey_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        log.debug( "Connect Honey {}:{}".format(honey_info["ip"],honey_info["port"]) )
        honey_socket.connect((honey_info["ip"],honey_info["port"]))

        # recv banner
        response = honey_socket.recv( 4096*10 )
        #log.debug( response )
        self.send( response )

        # Initial
        while True:
            # Attacker -> Honey
            #log.debug("Initial: Attacker -> Honey")
            request = self.recv()
            if request != None :
                #log.debug( request )
                honey_socket.send( request )
                #log.debug("Return recv")

            # Honey -> Attacker
            #log.debug("Initial: Honey -> Attacker")
            response = honey_socket.recv( 4096*10 )
            #log.debug( response )
            self.send( response )
            try :
                if "login:" in response.decode('utf-8') :
                    break
            except :
                pass

        # Login
        buffer = None
        while True:
            while True:
                # Attacker -> Honey
                #log.debug("Login: Attacker -> Honey")
                request = self.recv()
                if request == None :
                    continue
                if buffer == None :
                    buffer = request
                else :
                    buffer += request

                if "\r" not in buffer.decode('utf-8') :
                    continue

                #log.debug( buffer )
                honey_socket.send( buffer )
                #log.debug("Return recv")
                buffer = None

                # Honey -> Attacker
                #log.debug("Login: Honey -> Attacker")
                response = honey_socket.recv( 4096*10 )
                #log.debug( response )
                self.send( response )
                try :
                    if "\r\n" in response.decode('utf-8') :
                        break
                except :
                    pass

            # Login After
            #log.debug("Login After: Honey -> Attacker")
            response = honey_socket.recv( 4096*10 )
            #log.debug( response )
            self.send( response )

            # Password
            buffer = None
            while True:
                # Attacker -> Honey
                #log.debug("Password: Attacker -> Honey")
                request = self.recv()
                if request == None :
                    continue
                if buffer == None :
                    buffer = request
                else :
                    buffer += request

                if "\r" not in buffer.decode('utf-8') :
                    continue

                #log.debug( buffer )
                honey_socket.send( buffer )
                #log.debug("Return recv")
                buffer = None

                # Honey -> Attacker
                #log.debug("Password: Honey -> Attacker")
                response = honey_socket.recv( 4096*10 )
                #log.debug( response )
                self.send( response )

                try :
                    if "\r\n" in response.decode('utf-8') :
                        break
                except :
                    pass

            # Banner
            banner = ""
            while True:
                #log.debug("Banner: Honey -> Attacker")
                response = honey_socket.recv( 4096*10 )
                #log.debug( response )
                self.send( response )

                try :
                    banner += response.decode('utf-8')
                    if "$" in response.decode('utf-8') :
                        break
                    elif ">" in response.decode('utf-8') :
                        break
                    elif "#" in response.decode('utf-8') :
                        break
                    elif "Login incorrect" in response.decode('utf-8') :
                        break
                except :
                    pass

            if "$" in banner :
                break
            elif ">" in banner :
                break
            elif "#" in banner :
                break

            while True:
                #log.debug("Banner: Honey -> Attacker")
                response = honey_socket.recv( 4096*10 )
                #log.debug( response )
                self.send( response )

                try :
                    if "login:" in response.decode('utf-8') :
                        break
                except :
                    pass

        # Command
        buffer = None
        while True:
            # Attacker -> Honey
            request = self.recv()
            if request == None :
                s = select.select([honey_socket], [], [], 1)
                if s[0]:
                    # Honey -> Attacker
                    #log.debug("Command: Honey -> Attacker")
                    response = honey_socket.recv( 4096*10 )
                    #log.debug( response )
                    if len(response.decode('utf-8')) == 0 :
                        break
                    self.send( response )
                continue
            if buffer == None :
                buffer = request
            else :
                buffer += request

            if "\r" not in buffer.decode('utf-8') :
                continue

            #log.debug("Command: Attacker -> Honey")
            #log.debug( buffer )
            honey_socket.send( buffer )
            #log.debug("Return recv")
            buffer = None

        log.debug("Exit Loop")
        print("Exit Loop")

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
