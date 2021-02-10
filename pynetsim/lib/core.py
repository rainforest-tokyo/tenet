# Copyright (C) 2017 Jason Jones.
# This file is part of 'PyNetSim' - https://github.com/arbor-jjones/pynetsim
# See the file 'LICENSE' for copying permission.
import time
import yaml
import importlib
import logging
import logging.handlers
import pprint

import dpkt.ssl

import pynetsim.lib.conf as conf

log = logging.getLogger(__name__)

gConf     = None
HoneyList = None

def init_conf( conf_filename ) :
    global gConf
    global HoneyList
    gConf = conf.ConfigObject(conf_filename)
    HoneyList = yaml.load(open(gConf.get("honey").get("conf_file", "honey_info.yaml")), Loader=yaml.FullLoader)

def init_logging(logger_name, log_level=logging.DEBUG, log_file=None):
    """
    Simple logging initialization
    
    :param logger_name: logger name to initialize
    :param log_level: log level to be enabled
    :param log_file: output to a file
    :return: None
    """
    logger = logging.getLogger(logger_name)
    logger.setLevel(log_level)
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("[%(asctime)s] [%(name)s] [%(levelname)s] %(message)s"))
    logger.addHandler(handler)
    if log_file:
        fhandler = logging.handlers.TimedRotatingFileHandler(log_file, when='D')
        fhandler.setFormatter(logging.Formatter("[%(asctime)s] [%(name)s] [%(levelname)s] %(message)s"))
        logger.addHandler(fhandler)


def get_config():
    global gConf
    """
    Parse pynetsim configuration file 
    
    :return: ConfigObject
    """
    #return conf.ConfigObject()
    return gConf

def wait():
    """
    Waits for a keyboard interrupt to signal a shutdown
    
    :return: None
    """

    while True:
        try:
            time.sleep(300)
        except KeyboardInterrupt:
            log.info("Keyboard Interrupt received, shutting down")
            break


def find_protocol_class(protocol):
    """
    Locate the protocol class in a module
    
    :param protocol: name of protocol module
    :return: BotWhisperer subclass to handle the protocol
    """
    from pynetsim.protocols.protocol import BotWhisperer

    protocol_class = None
    proto_mod = importlib.import_module("pynetsim.protocols.{}".format(protocol))
    for member in dir(proto_mod):
        if member == "BotWhisperer":
            continue
        if type(getattr(proto_mod, member)) == type(object) and issubclass(getattr(proto_mod, member), BotWhisperer):
            protocol_class = getattr(proto_mod, member)
            break
    return protocol_class


def is_tls_hello(payload):
    """
    Checks to see if the payload is a proper TLS Client Hello message to alert the listener ht
    :param payload: Packet payload
    :return: Boolean to indicate whether or not this is a TLS Client Hello
    """
    is_tls = False
    try:
        tls_record = dpkt.ssl.TLSRecord(payload)
        tls_handshake = dpkt.ssl.TLSHandshake(tls_record.data)
        pprint.pprint(tls_handshake.data)
        if isinstance(tls_handshake.data, dpkt.ssl.TLSClientHello):
            is_tls = True
            for ext_val, ext_data in tls_handshake.data.extensions:
                if ext_val == 0:
                    log.debug("TLS SNI name: {}".format(ext_data[5:]))
                    break
    except Exception as e:
        pass
    return is_tls

