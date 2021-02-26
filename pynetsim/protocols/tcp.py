# Copyright (C) 2017 Jason Jones.
# This file is part of 'PyNetSim' - https://github.com/arbor-jjones/pynetsim
# See the file 'LICENSE' for copying permission.

import re
import socket
import logging
import select
import datetime

#import pynetsim.protocols.tcp as tcp
import pynetsim.lib.core as core

from pynetsim.protocols.protocol import BotWhisperer

log = logging.getLogger(__name__)

class TCP(BotWhisperer):

    name = "tcp"
