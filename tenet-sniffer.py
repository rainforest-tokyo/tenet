# -*- coding: utf-8 -*-

import os
import sys
import json
import base64
import socket
import string
import binascii
import datetime

import dpkt, pcap

import argparse

def common_tcp_data( ip ) :
    tcp = ip.data
    src = ip.src
    dst = ip.dst
    src_a = socket.inet_ntoa(src)
    dst_a = socket.inet_ntoa(dst)

    source_info = "%s:%d"%(src_a, tcp.sport)

    return { "destination_ip": dst_a, "destination_port": tcp.dport,
             "source_ip": src_a, "source_port": tcp.sport }

def parse_tcp_tls( ip, tcp_buffer ) :
    TLS_HANDSHAKE = 22

    records, bytes_used = dpkt.ssl.tls_multi_factory(tcp_buffer)
    results = []
    for record in records:
        if record.type != TLS_HANDSHAKE:
            continue
        if len(record.data) == 0:
            continue
        client_hello = bytearray(record.data)
        if client_hello[0] != 1:
            # We only want client HELLO
            continue
    return ""

def parse_tcp_http( ip, tcp_buffer ) :
    datas = dpkt.http.Request(tcp_buffer)
    return str(datas)

def parse_tcp_telnet( ip, tcp_buffer ) :
    datas = dpkt.telnet.strip_options(tcp_buffer)
    tmp = []
    for item in datas[0] :
        tmp.append( item.decode() )
    return "\\n".join(tmp)

def parse_udp_stun( ip, udp_buffer ) :
    datas = dpkt.stun.parse_attrs(udp_buffer)
    print(datas)

def detect_tcp( ip, tcp_info ) :
    result = common_tcp_data( ip )
    result["timestamp"] = str(datetime.datetime.utcfromtimestamp(tcp_info["start_time"]))
    result["connect_time"] = str(datetime.datetime.utcfromtimestamp(tcp_info["end_time"]))
    result["duration"] = tcp_info["end_time"]-tcp_info["start_time"]
    result["payload"] = base64.b64encode(tcp_info["buffer"]).decode()

    try :
        ret_data = parse_tcp_http( ip, tcp_info["buffer"] )
        result["app_proto"] = "http"
        result["payload_printable"] = ret_data
        return result
    except :
        pass

    try :
        parse_tcp_tls( ip, tcp_info["buffer"] )
        result["app_proto"] = "ssl"
        return result
    except :
        pass

    try :
        ret_data = parse_tcp_telnet( ip, tcp_info["buffer"] )
        result["app_proto"] = "telnet"
        result["payload_printable"] = ret_data
        return result
    except :
        pass

def main( device, pcap_option, pcap_file, output_file ) :
    packet_buffer = {}

    if pcap_file != None :
        print( pcap_file )
        pc = dpkt.pcap.Reader(open(pcap_file,'rb'))
    else :
        print( device )
        #pc = pcap.pcap( )
        pc = pcap.pcap( device, promisc=True, immediate=True )
        if pcap_option != None :
            pc.setfilter( 'host %s'%(pcap_option) )
        print( "Device Name:", pc.name, "|Filter:",pc.filter )

    for t,buf in pc :
        # Packetの取得
        eth = dpkt.ethernet.Ethernet(buf)

        # IPプロトコル確認
        if type(eth.data) != dpkt.ip.IP:
            continue

        ip = eth.data
        #TCPデータ
        if type(ip.data) == dpkt.tcp.TCP:
            tcp = ip.data
            fin_flag = int(( tcp.flags & dpkt.tcp.TH_FIN ) != 0)
            syn_flag = int(( tcp.flags & dpkt.tcp.TH_SYN ) != 0)
            rst_flag = int(( tcp.flags & dpkt.tcp.TH_RST ) != 0)
            psh_flag = int(( tcp.flags & dpkt.tcp.TH_PUSH) != 0)
            ack_flag = int(( tcp.flags & dpkt.tcp.TH_ACK ) != 0)
            urg_flag = int(( tcp.flags & dpkt.tcp.TH_URG ) != 0)

            src = ip.src
            dst = ip.dst
            src_a = socket.inet_ntoa(src)
            dst_a = socket.inet_ntoa(dst)

            source_info = "%s:%d"%(src_a, tcp.sport)

            if syn_flag == 1 and ack_flag == 0 :
                if source_info not in packet_buffer :
                    packet_buffer[source_info] = {"start_time": t, "end_time": None, "buffer": None}
                continue

            if source_info not in packet_buffer :
                continue

            if fin_flag == 0 :
                if packet_buffer[source_info]["buffer"] == None :
                    packet_buffer[source_info]["buffer"] = tcp.data
                else :
                    packet_buffer[source_info]["buffer"] += tcp.data
                continue
            else :
                packet_buffer[source_info]["end_time"] = t
                tcp_info = packet_buffer[source_info]
                del packet_buffer[source_info]

                result = detect_tcp( ip, tcp_info )
                print(result, flush=True)

                dt_now = datetime.datetime.now()
                filename = dt_now.strftime( output_file )
                f = open(filename, 'a')
                json.dump(result, f)
                f.write( '\n' )
                f.close()

        elif type(ip.data) == dpkt.udp.UDP:
            udp = ip.data
            if len(udp.data) != 0:
                continue

            print(udp)
            try :
                parse_udp_stun( ip, tcp )
                print("parse_udp_stun")
                continue
            except :
                pass
        elif type(ip.data) == dpkt.icmp.ICMP:
            icmp = ip.data
            if len(icmp.data) != 0:
                continue

            print(icmp)
            print("icmp")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='sniffer')
    parser.add_argument('-i', '--interface', help='target device')
    parser.add_argument('-t', '--target', help='target host')
    parser.add_argument('-r', '--read', help='pcapファイル名')
    parser.add_argument('-o', '--output', help='出力ファイル名 ', default="/iot_honey/logs/rfpf_%Y%m%d.json")

    args = parser.parse_args()

    if args.read != None :
        main( None, None, args.read, args.output )
    else :
        main( args.interface, args.target, None, args.output )

