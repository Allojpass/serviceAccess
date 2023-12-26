# SEU算力网络小组服务调度模块
## 功能清单
1. 使用water包在router节点上创建并初始化tun隧道。  
2. 从tun隧道中获取到应用程序发出的tcp SYN首包。  
3. 使用google的gopacket解析该数据包获得tcp四元组信息。  
4. 与chord环通信获取当前首包的Gvip所对应的服务信息（包括服务的状态信息以及每个服务的实际Lsip）。  
5. 运行选优算法获取最终选择结果，删除对应的iptables连接追踪表表项，并下发iptables的DNAT规则。  
6. 将首包重新写入tun隧道，并经过iptables转换发往最终目的地。  

## 流程图示
![image](https://github.com/Allojpass/serviceAccess/assets/47267069/d96d29b7-6255-4235-9902-7e4f7ee9a2fe)
服务调用场景图  
![image](https://github.com/Allojpass/serviceAccess/assets/47267069/d7c082f0-9a50-45e9-a306-1dc58c6950ae)
算力路由节点处理数据包流程图  

## 部署方式
（保证linux系统能够支持tun隧道，安装好golang环境）
1. 使用 apt install conntrack 安装操作连接追踪表所需要的包。  
2. 上传文件到router节点上对应的文件夹下并使用 chmod 777 文件名 指令修改权限。
3. 使用 ./文件名 指令运行该程序。
