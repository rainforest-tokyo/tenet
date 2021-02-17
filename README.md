# README #

1. プロトコル判定ツール
2. スニファーツール

sudo apt install libpcap

### プロトコル判定ツール ###

* ToDo

  

### スニファーツール ###

* Liveでのパケット解析とpcapファイルの解析機能がある

* Live

  * python3 tenet-sniffer.py -i ens160 -o /iot_honey/logs/test_%Y%m%d.json

  * デバイス：ens160のsnifferを実行し、結果を/iot_honey/logs/test_%Y%m%d.jsonに保存する

    * %Y%m%dはパケットを受信したhost OSの時間情報

      ```
      {
        "destination_ip": "192.168.11.31",
        "destination_port": 80,
        "source_ip": "192.168.11.40",
        "source_port": 59914,
        "timestamp": "2021-02-16 07:38:10.246280",
        "connect_time": "2021-02-16 07:38:10.250764",
        "duration": 0.004484415054321289,
        "payload": "R0VUIC8gSFRUUC8xLjENCkhvc3Q6IDE5Mi4xNjguMTEuMzENClVzZXItQWdlbnQ6IGN1cmwvNy43MS4xDQpBY2NlcHQ6ICovKg0KDQo=",
        "app_proto": "http",
        "payload_printable": "GET / HTTP/1.1\r\nhost: 192.168.11.31\r\nuser-agent: curl/7.71.1\r\naccept: */*\r\n\r\n"
      }
      ```

      

* Pcap

  * python3 tenet-sniffer.py -r /home/develop/test_data/telnet.pcap -o /iot_honey/logs/telnet_%Y%m%d.json

  * デバイス：ens160のsnifferを実行し、結果を/iot_honey/logs/telnet_%Y%m%d.jsonに保存する

    ```
    {
      "destination_ip": "127.0.0.1",
      "destination_port": 23,
      "source_ip": "127.0.0.1",
      "source_port": 58294,
      "timestamp": "2021-02-16 00:36:34.041106",
      "connect_time": "2021-02-16 00:37:03.409744",
      "duration": 29.368638038635254,
      "payload": "//0D//sY//sf//sg//sh//si//sn//0F//wj//ofAIgAJv/w//ogADM4NDAwLDM4NDAw//D/+icA//D/+hgAeHRlcm3/8P/8Af/9AWRldmVsb3ANAHBhc3N3b3JkDQBscw0AY2QgL2V0Yw0AdG91Y2ggL3RtCWENAHJtIC90bQlhDQBleGl0DQA=",
      "app_proto": "telnet",
      "payload_printable": "develop\\npassword\\nls\\ncd /etc\\ntouch /tm\ta\\nrm /tm\ta\\nexit"
    }
    ```

    
