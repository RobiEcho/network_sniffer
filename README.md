### 网络抓包并统计

使用 `libpcap` 库实现网络抓包，并统计数据流量。

在根目录以下命令构建项目：
```c
mkdir build
cd build
cmake ..
make
```
生成可执行文件 `network_sniffer`

执行：
```c
./network_sniffer
```
开始抓包

按下`ctrl + C`，停止抓包并保存统计数据到`.txt`文件里
