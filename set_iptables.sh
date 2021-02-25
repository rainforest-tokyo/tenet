#
# 133.34.157.65 or 133.34.157.66 or 133.34.157.67

iptables -t nat -I PREROUTING --in-interface enp0s25 -p tcp -j REDIRECT -d 133.34.157.65 --to-port 10001
#iptables -t nat -I PREROUTING --in-interface enp0s25 -p tcp -j REDIRECT -d 133.34.157.66 --to-port 10002
#iptables -t nat -I PREROUTING --in-interface enp0s25 -p tcp -j REDIRECT -d 133.34.157.67 --to-port 10003

