#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import time
import json
import magic
import shutil
import datetime
import pyinotify
import subprocess

from filehash import FileHash

# 監視対象ディレクトリを指定する
target_dir = '/iot_honey/home/'

gSaveDir = '/iot_honey/logs/'
gSaveMalwareDir = '/iot_honey/malware/'

class Handler(pyinotify.ProcessEvent):
    # イベント通知を受け取るモノ。
    # process_フラグ名(self, event)　って関数を用意しておけばいいみたいね。

    def process_IN_CREATE(self, event):
        filepath =  event.pathname

    def process_IN_DELETE(self, event):
        filepath =  event.pathname

    def process_IN_CLOSE_WRITE(self, event):
        filepath =  event.pathname

    def process_IN_ATTRIB(self, event):
        filepath =  event.pathname
        if os.path.isdir(filepath) == True :
            return

        if os.access(filepath,os.X_OK) :
            os.chmod( filepath, 0o600 )

            now = datetime.datetime.now()
            hasher = FileHash('md5')            
            md5 = hasher.hash_file( filepath )
            hasher = FileHash('sha1')            
            sha1 = hasher.hash_file( filepath )
            hasher = FileHash()            
            sha256 = hasher.hash_file( filepath )

            save_dir = os.path.join(gSaveMalwareDir, sha256[0:2], sha256[2:4])
            os.makedirs(save_dir, exist_ok=True)
            save_filepath = os.path.join(save_dir,sha256)
            shutil.move(filepath, save_filepath)

            log = { "datetime":now.strftime('%Y/%m/%d %H:%M:%S'), 
                    "path": filepath, 
                    "md5_hash": md5, 
                    "sha-1_hash": sha1, 
                    "sha-256_hash": sha256, 
                    "file_format": magic.from_file(save_filepath), 
                    "filepath": save_filepath }

            f_filename = now.strftime('%Y%m%d')
            #f_save_dir = os.path.join(gSaveDir, f_filename[0:6], f_filename[6:8])
            f_save_dir = os.path.join(gSaveDir)
            os.makedirs(f_save_dir, exist_ok=True)
            f_filename = os.path.join( f_save_dir, "rfch_"+f_filename+".log" )
            f = open( f_filename, "a")
            f.write(json.dumps(log)+"\n")
            f.close()

    def process_default(self, event):
        pass

if __name__ == '__main__':
    wm = pyinotify.WatchManager()

    # 監視スレッドを作って、走らせる。
    #  Handler()の()に注意。インスタンスを渡します。
    notifier = pyinotify.ThreadedNotifier(wm, Handler())

    # 監視するイベントの種類
    #  フラグの意味は後述する表を参照。
    #mask = pyinotify.IN_CREATE | pyinotify.IN_DELETE | pyinotify.IN_MODIFY | pyinotify.IN_CLOSE_WRITE | pyinotify.IN_ATTRIB
    mask = pyinotify.IN_CREATE | pyinotify.IN_DELETE | pyinotify.IN_CLOSE_WRITE | pyinotify.IN_ATTRIB

    # 監視対象の追加
    wm.add_watch(target_dir, mask, rec=True)

    notifier.loop()
    #notifier.stop()

