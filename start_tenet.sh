#

nohup python3 tenet.py -c tenet_amd.conf > /tmp/amd_out.log &
nohup python3 tenet.py -c tenet_arm.conf > /tmp/arm_out.log &
nohup python3 tenet.py -c tenet_mips.conf > /tmp/mips_out.log &

