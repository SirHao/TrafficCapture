make clean
make 
rmmod slimx
insmod slimx.ko
cat /proc/devices | grep slimx
tail -f /var/log/kern.log


