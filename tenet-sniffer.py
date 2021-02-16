# -*- coding: utf-8 -*-

import os
import sys
import socket
import string
import binascii

import dpkt, pcap

import argparse

def parse_tcp_http( ip, tcp_buffer ) :
    datas = dpkt.http.Request(tcp_buffer)
    print(datas)

def parse_tcp_telnet( ip, tcp_buffer ) :
    datas = dpkt.telnet.strip_options(tcp_buffer)
    print(datas)

def parse_udp_stun( ip, udp_buffer ) :
    datas = dpkt.stun.parse_attrs(udp_buffer)
    print(datas)

def detect_tcp( ip, tcp_buffer ) :
    try :
        parse_tcp_http( ip, tcp_buffer )
        print("parse_tcp_http")
        return
    except :
        pass

    try :
        parse_tcp_telnet( ip, tcp_buffer )
        print("parse_tcp_telnet")
        return
    except :
        pass

def main( pcap_option, pcap_file ) :
    packet_buffer = {}

    if pcap_file != None :
        pc = dpkt.pcap.Reader(open(pcap_file,'rb'))
    else :
        pc = pcap.pcap()
        pc.setfilter( pcap_option )

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
                    packet_buffer[source_info] = None
                continue

            if source_info not in packet_buffer :
                continue

            if fin_flag == 0 :
                if packet_buffer[source_info] == None :
                    packet_buffer[source_info] = tcp.data
                else :
                    packet_buffer[source_info] += tcp.data
                continue
            else :
                tcp_buffer = packet_buffer[source_info]
                del packet_buffer[source_info]

                detect_tcp( ip, tcp_buffer )
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
    parser.add_argument('-r', '--read', help='pcapファイル名')
    parser.add_argument('-o', '--output', help='出力ファイル名')

    args = parser.parse_args()
    if args.read != None :
        main( None, args.read )
    else :
        main( 'host 192.168.11.31', None )

