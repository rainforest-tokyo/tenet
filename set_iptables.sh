#

# iptables nat ルールの削除
# sudo iptables -t nat -L --line-numbers
# sudo iptables -t nat --delete PREROUTING <number>

# 設定の確認
# iptables -n -t nat -L

# 133.34.157.65 or 133.34.157.66 or 133.34.157.67
iptables -t nat -I PREROUTING --in-interface enp0s25 -p tcp -j REDIRECT -d 133.34.157.65 --to-port 10001
iptables -t nat -I PREROUTING --in-interface enp0s25 -p tcp -j REDIRECT -d 133.34.157.66 --to-port 10002
iptables -t nat -I PREROUTING --in-interface enp0s25 -p tcp -j REDIRECT -d 133.34.157.67 --to-port 10003

