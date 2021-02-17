#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import re
import copy
import json
import magic
import base64
import bashlex
import hashlib
import datetime
import argparse
import requests
import subprocess

import urllib.parse
from datetime import datetime, timedelta

gSaveDir = '/iot_honey/malware/'

gLogFile = ""
gShellResultList = {}

def exec_subprocess(cmd: str) -> (str, str, int):
    child = subprocess.Popen(cmd, shell=True,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = child.communicate()
    rt = child.returncode
    return stdout.decode(), stderr.decode(), rt

def debug_shell(dw_info, filename) :
    cmd_list = ["wget","curl","rm","chmod","busybox","mv","ps","kill","xargs","iptables","grep","pkill","netstat","pgrep",
            "chattr","service","systemctl","crontab","apt","apt-get","unhide","ufw","userdel","adduser","useradd"]
    cmd_list_nop = ["sleep","echo","cat","history"]

    tmp_file = "rainforest_debug"
    pattern = "https?://[\w/:%#\$&\?\(\)~\.=\+\-]+"

    with open(filename) as f:
        s = f.read()

    with open(tmp_file, mode='w') as f:
        f.write('shopt -s expand_aliases;')
        for cmd in cmd_list :
            f.write('alias %s="_%s"; '%(cmd,cmd))
        f.write('\n')
        for cmd in cmd_list_nop :
            f.write('alias %s="_%s"; '%(cmd,cmd))
        f.write('\n')

        f.write(s)

    with open(tmp_file) as f:
        s = f.read()

    #stdout, stderr, rt = exec_subprocess( "bash -uvx "+tmp_file )
    stdout, stderr, rt = exec_subprocess( "bash -ux "+tmp_file )
    for line in stderr.split("\n") :
        if ("+" in line) and ("alias" not in line) :
            line = line.replace("+","").strip()
            line = line.replace("_","")
            cmd = line.split(" ")[0]
            dw_info["cmd_log"].append( line )
            if (cmd in cmd_list) or (cmd in cmd_list_nop) :
                if (("wget" in line) or ("curl" in line) or ("busybox" in line)) :
                    url_list = re.findall(pattern, line )
                    dw_info["url_list"].extend( url_list )

    os.remove(tmp_file)

def downloader( result ) :
    global gSaveDir

    for url in result["url_list"] :
        info = {}
        dt_now = datetime.now()
        info["url"] = url
        try :
            # HTTPリクエスト
            response = requests.get(url, timeout=(10.0))
            info["datetime"] = dt_now.strftime('%Y-%m-%d %H:%M:%S')
            info["status_code"] = response.status_code
            if info["status_code"] == 200 :
                info["md5_hash"] = hashlib.md5(response.content).hexdigest()
                info["sha-1_hash"] = hashlib.sha1(response.content).hexdigest()
                info["sha-256_hash"] = hashlib.sha256(response.content).hexdigest()
                save_dir = os.path.join(gSaveDir, info["sha-256_hash"][0:2], info["sha-256_hash"][2:4])
                os.makedirs(save_dir, exist_ok=True)
                info["filepath"]= os.path.join(save_dir,info["sha-256_hash"])
                if os.path.exists( info["filepath"]) == False :
                    with open(info["filepath"], "wb") as fout:
                        fout.write(response.content)
                info["file_format"] = magic.from_file(info["filepath"])
        except :
            info["status_code"] = "Exception"

        result["contents"].append( info )

def parse_shell( data, shell_str ) :
    global gShellResultList

    pattern = "https?://[\w/:%#\$&\?\(\)~\.=\+\-]+"
    result = {}
    if data != None :
        result["uuid"] = data["uuid"]
        try :
            result["src_ip"] = data["source_ip"]
        except :
            result["source_ip"] = data["src_ip"]
        try :
            result["destination_port"] = data["destination_port"]
        except :
            result["destination_port"] = data["dest_port"]
        result["timestamp"] = data["timestamp"]
    result["command_list"] = []
    result["url_list"] = []
    result["contents"] = []
    result["download_shell"] = []
    tmp_cmd_str = ""
    cmd_list = []
    try :
        shell_str = shell_str.replace("`","  ")
        shell_str = shell_str.replace("'$","  ")
        cmd_list = list(bashlex.split( shell_str ))
    except :
        print("#### list(bashlex.split( shell_str )) #### ")
        print(shell_str)
        pass

    # 侵入で実行されたコマンド一覧取得
    for item in cmd_list :
        if item == ";" :
            tmp_cmd_str = tmp_cmd_str.strip()
            result["command_list"].append( tmp_cmd_str )
            url_list = re.findall(pattern, tmp_cmd_str )
            result["url_list"].extend( url_list )
            tmp_cmd_str = ""
        else :
            tmp_cmd_str += item+" "
    if tmp_cmd_str != "" :
        result["command_list"].append( tmp_cmd_str )
        url_list = re.findall(pattern, tmp_cmd_str )
        result["url_list"].extend( url_list )

    # 検体のダウンロード処理
    downloader( result )

    return result

def tenet_loader( filename ) :
    global gLogFile
    global gShellResultList

    with open( filename ) as f:
        for s_line in f:
            try :
                data = json.loads( s_line )
            except :
                continue

            if data['payload_printable'] == None :
                continue

            if ("wget" in data['payload_printable']) or ("curl" in data['payload_printable']) :
                decode_str = urllib.parse.unquote(data['payload_printable'])
                decode_str = decode_str.replace("+"," ")
                decode_str = decode_str.replace("${IFS}"," ")
                decode_str = decode_str.replace("\\r\\n","\n")
                decode_str = decode_str.replace("\\n","\n")

                shell_str = ""
                try :
                    shell_str = decode_str.split(';',1)[1]
                except :
                    pass

                if shell_str == "" :
                    try :
                        shell_str = decode_str.split('.getRuntime.exec"',1)[1]
                    except :
                        pass

                if shell_str == "" :
                    try :
                        shell_str = decode_str.split('/20',1)[1]
                    except :
                        print("=[Split Exeption]==========================")
                        print(decode_str, flush=True)
                        pass

                if shell_str != "" :
                    shell_str_hash = hashlib.sha256(shell_str.encode('utf-8')).hexdigest()
                    # 既にデータを取得したコマンドか確認する
                    if shell_str_hash in gShellResultList :
                        print( "既に登録 :"+shell_str_hash )
                        result = copy.copy( gShellResultList[shell_str_hash] )
                        if data != None :
                            result["uuid"] = data["uuid"]
                            result["src_ip"] = data["src_ip"]
                            result["dest_port"] = data["dest_port"]
                            result["timestamp"] = data["timestamp"]
                    else :
                        print( "新規登録 :"+shell_str_hash )
                        # 侵入の攻撃のパース
                        result = parse_shell( data, shell_str )
                        for content in result["contents"] :
                            if content["status_code"] != 200 :
                                 continue

                            # DropされたShellの解析
                            if "text" in content["file_format"] :
                                dw_info = {}
                                dw_info["md5_hash"] = content["md5_hash"]
                                dw_info["sha-1_hash"] = content["sha-1_hash"]
                                dw_info["sha-256_hash"] = content["sha-256_hash"]
                                dw_info["url_list"] = []
                                dw_info["contents"] = []
                                with open(content["filepath"]) as f:
                                    dw_info["code"] = f.read().strip()

                                dw_info["cmd_log"] = []
                                debug_shell(dw_info, content["filepath"])
                                downloader( dw_info )

                                result["download_shell"].append(dw_info)

                        result["shell_hash"] = shell_str_hash
                        gShellResultList[shell_str_hash] = result
                        os.system("ls | grep -v -E '*.py' | xargs rm -r")

                    # Write Log
                    gLogFile.write(json.dumps(result))
                    gLogFile.write("\n")
                    gLogFile.flush()
                    #exit()

#    print("===========================")
#   print(json.dumps(result,indent=4))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Downloader')
    parser.add_argument('-l', '--logfile', default='', help='logfile')

    args = parser.parse_args()

    log_filename = args.logfile
    if log_filename == "" :
        dt_now = datetime.now()
        dt_now = dt_now - timedelta(days=1)
        #log_filename = dt_now.strftime('/var/log/autonapt/rfpf_%Y%m%d.json')
        log_filename = dt_now.strftime('/iot_honey/logs/rfpf_%Y%m%d.json')
    print("Target File : %s"%(log_filename), flush=True)
    if os.path.isfile(log_filename) == False :
        print("File not found : %s"%(log_filename), flush=True)
        exit()

    gLogFile = open(log_filename.replace("rfpf_","rfdl_"), "w")
    tenet_loader( log_filename )
    gLogFile.close()

