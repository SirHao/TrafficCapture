## Traffic  Capture

version:  0.0.1

功能：实现了一个内核模块，监听用户感兴趣的TCP连接，统计过去1s内的这条连接发包数量（收包后续更新）

主要逻辑：

+ Netfilter实现对流量拦截
+ 字符设备的 ioctl与用户态通信（使用户设置感兴趣的流量、获取收发包数）
+ 基于hlist实现的hashtable

test文件：

+ ``client.c/server.c``负责生成流量进行传输
+ ``traffic_capture_test.c``负责调用ioctl与Slimx通信

#### usage

部署

```
./deploy.sh  #部署内核模块
mknod /dev/slimx c $(mainID) $(secID) #主设备号可以在/proc/devices中查看，次设备号通常为0
```

启动测试流量

```
./test/server
./test/client
```

监听流量

修改traffic_capture_test.c 的代码内的dst_ip dst_port local_port

```
./test/traffic_capture_test
```





