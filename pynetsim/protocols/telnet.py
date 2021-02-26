# Copyright (C) 2017 Jason Jones.
# This file is part of 'PyNetSim' - https://github.com/arbor-jjones/pynetsim
# See the file 'LICENSE' for copying permission.

import re
import socket
import logging
import select
import datetime
import threading

import pynetsim.protocols.tcp as tcp
import pynetsim.lib.core as core

from pynetsim.protocols.protocol import BotWhisperer

log = logging.getLogger(__name__)

class TELNET(BotWhisperer):

    name = "telnet"

    def from_attacker(self, honey_socket):
        buffer = None
        while self.active:
            request = self.recv()
            if request == None :
                continue

            try :
                if buffer == None :
                    buffer = request.decode('utf-8')
                else :
                    buffer += request.decode('utf-8')

                honey_socket.send( request )
                if "exit" in buffer : 
                    break 
            except :
                honey_socket.send( request )

        self.active = False

    def to_attacker(self, honey_socket):
        buffer = None
        while self.active:
            try :
                response = honey_socket.recv( 4096*10 )
            except :
                    break 

            if response == None :
                continue

            try :
                if buffer == None :
                    buffer = response.decode('utf-8')
                else :
                    buffer += response.decode('utf-8')

                self.send( response )
                if "Login timed out" in buffer : 
                    break 
            except :
                self.send( response )

        self.active = False

    def run(self):
        # Select Honey
        config_info = core.get_honey_list()
        honey_info = config_info["telnet"][0]

        # Connect to Honey
        honey_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        log.debug( "Connect Honey {}:{}".format(honey_info["ip"],honey_info["port"]) )
        honey_socket.connect((honey_info["ip"],honey_info["port"]))
        honey_socket.settimeout(60.0)

        self.active = True

        # Start Thread
        log.debug("Start Thread")
        print("Start Thread")
        thread1 = threading.Thread(target=self.from_attacker, args=(honey_socket,))
        thread2 = threading.Thread(target=self.to_attacker, args=(honey_socket,))

        thread1.start()
        thread2.start()

        thread1.join()
        thread2.join()

        log.debug("Exit Loop")
        print("Exit Loop")

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
#        load = None
#        while not load:
#            s = select.select([self.socket], [], [], 10)
#            if s[0]:
#                load = self.socket.recv(self.recv_size)
#        return load
