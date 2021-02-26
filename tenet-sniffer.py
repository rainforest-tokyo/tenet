#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import re
import sys
import json
import uuid
import base64
import socket
import string
import binascii
import datetime

import dpkt, pcap

import argparse
import urllib.parse

def common_tcp_data( ip ) :
    tcp = ip.data
    src = ip.src
    dst = ip.dst
    src_a = socket.inet_ntoa(src)
    dst_a = socket.inet_ntoa(dst)

    # TCP情報収集
    tcp_data = {}
    tcp_data["seq"] = tcp.seq
    tcp_data["seq_raw"] = tcp.seq
    tcp_data["window_size_value"] = tcp.win
    tcp_data["window_size"] = tcp.win
    tcp_data["window_size_scalefactor"] = tcp.win

    return { "uuid": str(uuid.uuid4()), "destination_ip": dst_a, "destination_port": tcp.dport,
            "source_ip": src_a, "source_port": tcp.sport, "tcp":tcp_data }

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
    cmd_list = ["wget","curl","rm","chmod","busybox","mv","ps","kill","xargs","iptables","grep","pkill","netstat","pgrep",
            "chattr","service","systemctl","crontab","apt","apt-get","unhide","ufw","userdel","adduser","useradd"]
    pattern = "https?://[\w/:%#\$&\?\(\)~\.=\+\-]+"

    http = dpkt.http.Request(tcp_buffer)
    
    # HTTP情報収集
    http_data = {}
    http_data["http_http_request_method"] = http.method
    http_data["http_http_request_uri"] = http.uri
    http_data["http_http_request_version"] = "HTTP/"+http.version
    http_data["http_http_request"] = True
    http_data["http_http_request_number"] = "1"
    for key in http.headers :
        http_data["http_http_"+key] = http.headers[key]
    #http_data["http_http_request_full_uri"] = "http://"+http_data["http_http_host"]+"/"+http_data["http_http_request_uri"]
    http_data["http_http_request_full_uri"] = "http:/"+os.path.join(http_data["http_http_host"],http_data["http_http_request_uri"])

    http_data["http_http_params"] = urllib.parse.urlparse(http_data["http_http_request_full_uri"]).query
    http_data["http_http_body"] = http.body.decode('utf-8')

    # URIの分割
    dirname, basename = os.path.split(http_data["http_http_request_uri"])
    #http_data["http_http_request_uri_detail"] = {"urlpath": dirname, "resourcename": basename}
    http_data["http_http_request_uri_urlpath"]      = dirname
    http_data["http_http_request_uri_resourcename"] = basename

    # 攻撃で利用されるコマンド文字列の検索
    http_data["http_http_cmd"] = []

    check_target = http_data["http_http_params"]+" "+http_data["http_http_body"]
    for cmd in cmd_list :
        if (cmd in check_target) :
            http_data["http_http_cmd"].append( cmd )

    # ダウンロードURLの抽出
    http_data["http_http_download"] = re.findall(pattern, check_target )

    # ダウンロードURLの分解
    http_data["http_http_download_detail"] = []
    for url in http_data["http_http_download"] :
        u_parse = urllib.parse.urlparse(url)
        result = { 
                "method"      : u_parse.scheme, 
                "domain"      : u_parse.netloc, 
                "path"        : u_parse.path, 
                "params"      : u_parse.params, 
                "query"       : u_parse.query, 
                "query_detail": [] }
        result["query_detail"] = urllib.parse.parse_qs(u_parse.query)
        http_data["http_http_download_detail"].append(result["query_detail"])

    return str(http), http_data

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
    try :
        result["payload"] = base64.b64encode(tcp_info["buffer"]).decode()
    except :
        result["payload"] = "base64 except"

    try :
        ret_data, http_data = parse_tcp_http( ip, tcp_info["buffer"] )
        result["app_proto"] = "http"
        result["payload_printable"] = ret_data
        result["http"] = http_data
        return result
    except :
        import traceback
        traceback.print_exc()

    try :
        parse_tcp_tls( ip, tcp_info["buffer"] )
        result["app_proto"] = "ssl"
        return result
    except :
        import traceback
        traceback.print_exc()

    try :
        ret_data = parse_tcp_telnet( ip, tcp_info["buffer"] )
        result["app_proto"] = "telnet"
        result["payload_printable"] = ret_data
        return result
    except :
        import traceback
        traceback.print_exc()
#        pass

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
                if result == None :
                    continue
                print(result, flush=True)

                dt_now = datetime.datetime.now()
                if output_file != None :
                    filename = dt_now.strftime( output_file )
                    f = open(filename, 'a')
                    json.dump(result, f)
                    f.write( '\n' )
                    f.close()
                else :
                    print( json.dumps(result) )

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
    parser.add_argument('-t', '--target', help='target host 1.1.1.1 or 2.2.2.2')
    parser.add_argument('-r', '--read', help='pcapファイル名')
    parser.add_argument('-o', '--output', help='出力ファイル名 ', default="/iot_honey/logs/rfpf_%Y%m%d.json")

    args = parser.parse_args()

    if args.read != None :
        main( None, None, args.read, args.output )
    else :
        main( args.interface, args.target, None, args.output )
#        main( args.interface, args.target, None, None )

