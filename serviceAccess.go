package main

import (
	"encoding/json"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/songgao/water"
	"io"
	"log"
	"math"
	"math/rand"
	"net/http"
	_ "net/http/pprof"
	"os/exec"
	"strconv"
	"time"
)

// 轮询的计数
var times map[string]int = make(map[string]int)

// 与Chord环交互服务信息的结构体
type ServiceInformation struct {
	Gvip            string `json:"Gvip"`
	ServiceInstance []struct {
		Lsip        string  `json:"Lsip"`
		Frequency   float64 `json:"frequency"`
		Latency     float64 `json:"latency"`
		SuccessRate float64 `json:"success_rate"`
	} `json:"Service_instance"`
	Sname string `json:"Sname"`
}

// 带宽信息结构体
type bindwidthMsg struct {
	Lsip     string
	Bindwith float64
}

// 延迟信息结构体
type delayMsg struct {
	Lsip  string
	Delay float64
}

func main() {
	go func() {
		log.Println(http.ListenAndServe(":26998", nil))
	}()
	//服务端口映射表
	hashMap := make(map[string]string)
	//服务类型判断的映射表
	statusMap := make(map[string]string)
	//带宽敏感型服务的静态映射表
	bindwidthMap := make(map[string][]bindwidthMsg)
	//时延敏感型服务的静态映射表
	delayMap := make(map[string][]delayMsg)
	//初始化端口映射表，根据不同的应用以及部署关系需要做出一些调整
	initMap(hashMap)
	//初始化选优相关的映射表
	initStatusMap(statusMap, bindwidthMap, delayMap)

	//利用water包创建tun的操作符
	ifce, err := water.New(water.Config{
		DeviceType: water.TUN,
		PlatformSpecificParams: water.PlatformSpecificParams{
			Name: "tun0",
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Interface Name: %s\n", ifce.Name())

	//添加tun的网段地址，这里应该设置为GVIP的范围
	dstCmd := "ip addr add 10.212.0.1/16 dev " + ifce.Name()
	log.Println(dstCmd)
	cmd1 := exec.Command("/bin/sh", "-c", dstCmd)
	_, cmd1Err := cmd1.CombinedOutput()
	if cmd1Err != nil {
		log.Fatalf("cmd.Run() failed with %s\n", cmd1Err)
	}

	//将tun设备挂载进操作系统
	dstCmd = "ip link set dev " + ifce.Name() + " up"
	log.Println(dstCmd)
	cmd2 := exec.Command("/bin/sh", "-c", dstCmd)
	_, cmd2Err := cmd2.CombinedOutput()
	if cmd2Err != nil {
		log.Fatalf("cmd.Run() failed with %s\n", cmd2Err)
	}

	//查看当前的网卡状态，可以通过控制台观察tun接口是否启动成功
	cmd3 := exec.Command("ifconfig")
	cmd3Out, cmd3Err := cmd3.CombinedOutput()
	log.Printf("combined out:\n%s\n", string(cmd3Out))
	if cmd3Err != nil {
		log.Fatalf("cmd.Run() failed with %s\n", cmd3Err)
	}

	//存放读取到的数据包的字节数组
	packet := make([]byte, 4096)

	//for循环开始用不停地处理目前到达本节点的数据包
	for {
		//读取进入tun接口的数据包，n为数据包长度
		n, err := ifce.Read(packet)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("%d", n)
		log.Printf("Packet Received: % x\n", packet[:n])

		// 解析一个数据包，这里使用的是google的gopacket
		//这里的layers.LayerTypeIPv4是指从数据包的什么协议层面开始解析，由于是tun接口送进来的数据包
		//所以应该是只有ip报文的内容了，如果从以太网开始解析则会解析失败，TAP接口则应当从以太网开始
		myPacketData := gopacket.NewPacket(packet, layers.LayerTypeIPv4, gopacket.Default)
		// 遍历该数据包中所有的头部信息然后打印出来
		for _, layer := range myPacketData.Layers() {
			log.Println("PACKET LAYER:", layer.LayerType())
		}
		//解析ip信息，并生成操作ip数据头的ip对象
		ipLayer := myPacketData.Layer(layers.LayerTypeIPv4)
		ip, _ := ipLayer.(*layers.IPv4)
		if ipLayer != nil {
			log.Printf("This is a IP packet!")
			log.Printf("From src ip address %d to dst ip address %d\n", ip.SrcIP, ip.DstIP)
		}
		// 解析TCP报头
		tcpLayer := myPacketData.Layer(layers.LayerTypeTCP)
		//如果该数据包中包含TCP层，则继续进行处理
		if tcpLayer != nil {
			log.Println("This is a TCP packet!")
			// 获取操作实际TCP数据的对象
			tcp, _ := tcpLayer.(*layers.TCP)
			//判断是否是首包
			if tcp.SYN {
				log.Printf("From src port %d to dst port %d\n", tcp.SrcPort, tcp.DstPort)

				//删除首包第一次经过连接追踪表时的表项，使后面下发的NAT规则能够正常应用于重新发送进入Linux网络协议栈的首包
				//如果不删除该表项，那么NAT规则的修改不会应用于已经被记录过的流
				dstCmd = "conntrack -D -p tcp --src " + ip.SrcIP.String() + " --dst " + ip.DstIP.String() + " --sport " + strconv.Itoa(int(tcp.SrcPort)) + " --dport " + strconv.Itoa(int(tcp.DstPort))
				log.Println(dstCmd)
				cmd4 := exec.Command("/bin/sh", "-c", dstCmd)
				cmd4out, cmd4Err := cmd4.CombinedOutput()
				log.Printf("combined out:\n%s\n", string(cmd4out))
				if cmd4Err != nil {
					log.Printf("cmd.Run() failed with %s\n", cmd4Err)
				}

				//选优函数，在该函数中从Chord环获取对应的服务状态信息以及可能的网络状态信息并选出具体的Lsip
				Lsip := choiceService(ip.DstIP.String(), strconv.Itoa(int(tcp.DstPort)), statusMap, bindwidthMap, delayMap)

				//这里进行了两个部分的转换，通过iptables规则转换了ip和端口，然后下载
				dstCmd = "iptables -t nat -I PREROUTING -d " + ip.DstIP.String() + " -s " + ip.SrcIP.String() + " -p tcp --dport " + strconv.Itoa(int(tcp.DstPort)) + " --sport " + strconv.Itoa(int(tcp.SrcPort)) + " -j DNAT --to-destination " + Lsip + ":" + hashMap[strconv.Itoa(int(tcp.DstPort))]
				log.Println(dstCmd)
				cmd5 := exec.Command("/bin/sh", "-c", dstCmd)
				_, cmd5Err := cmd5.CombinedOutput()
				if cmd5Err != nil {
					log.Printf("cmd.Run() failed with %s\n", cmd5Err)
				}

			}
		}
		//向tun接口写入数据包，让数据包重新进入Linux网络协议栈，从而能够经过iptables的NAT转换
		ifce.Write(packet[0:n])
		log.Printf("This packet has been sent!\n")

	}

}

// 该哈希表是用来做跨集群的应用的端口映射，因为k8s需要以nodeport方式对外提供访问的话需要微服务的端口处于特定范围之间，所以可以针对不同应用进行端口的映射减少对应用程序修改
func initMap(hashMap map[string]string) {
	hashMap["5000"] = "32001"
	hashMap["9555"] = "32002"
	hashMap["7070"] = "32003"
	hashMap["5050"] = "32004"
	hashMap["7000"] = "32005"
	hashMap["50052"] = "32006"
	hashMap["3550"] = "32007"
	hashMap["8080"] = "32008"
	hashMap["6379"] = "32009"
	hashMap["50051"] = "32010"
}

// 初始化状态映射表
func initStatusMap(statusMap map[string]string, bandwidthMap map[string][]bindwidthMsg, delayMap map[string][]delayMsg) {
	//带宽敏感型映射表
	bandwidthMap = make(map[string][]bindwidthMsg)
	bindwidthArray := make([]bindwidthMsg, 0, 0)
	bindwidthArray = append(bindwidthArray, bindwidthMsg{
		Lsip:     "192.168.20.159",
		Bindwith: 2048,
	})
	bindwidthArray = append(bindwidthArray, bindwidthMsg{
		Lsip:     "192.168.30.183",
		Bindwith: 1024,
	})
	bandwidthMap["9555"] = bindwidthArray
	//时延敏感型映射表
	delayMap = make(map[string][]delayMsg)
	delayArray := make([]delayMsg, 0, 0)
	delayArray = append(delayArray, delayMsg{
		Lsip:  "192.168.10.84",
		Delay: 0.632,
	})
	delayArray = append(delayArray, delayMsg{
		Lsip:  "192.168.20.159",
		Delay: 0.817,
	})
	delayMap["50052"] = delayArray
	//类型映射表，用来判断当前端口对应的服务属于什么类型，并去查找对应
	statusMap["9555"] = "Bindwidth sensitive"
	statusMap["50052"] = "Delay sensitive"
}

// 进行Lsip选择的函数，也就是选优算法的位置
func choiceService(gvip string, port string, statusMap map[string]string, bandwidthMap map[string][]bindwidthMsg, delayMap map[string][]delayMsg) string {
	var Lsip string
	var data ServiceInformation
	resp, err := http.Get("http://127.0.0.1:5000/services/servicestate?gvip=" + gvip)
	if err != nil {
		log.Println("Failed to get Lsip and service status information!")
	} else {
		log.Println("Success to get Lsip and service status information!")
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	bodystr := string(body)
	if err := json.Unmarshal([]byte(bodystr), &data); err == nil {
		Lsip = choiceServiceByKind(data, port, statusMap, bandwidthMap, delayMap)
		log.Println("Lsip is", Lsip)
	} else {
		log.Println("Some error occur during converting json", err)
	}
	return Lsip
}

// 轮询选择
func roundRobin(data ServiceInformation) string {
	length := len(data.ServiceInstance)
	var Lsip string
	if value, ok := times[data.Sname]; ok == true {
		value++
		newValue := value % length
		Lsip = data.ServiceInstance[newValue].Lsip
		times[data.Sname] = newValue
	} else {
		Lsip = data.ServiceInstance[0].Lsip
		times[data.Sname] = 0
	}
	return Lsip
}

// 随机选择
func random(data ServiceInformation) string {
	//根据时间生成随机数
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	//控制生成随机数的范围为[0,服务实例数量+1),生成的数为区间内的整数
	number := r.Intn(len(data.ServiceInstance) + 1)
	return data.ServiceInstance[number].Lsip
}

// 根据服务类型进行选择
func choiceServiceByKind(data ServiceInformation, port string, statusMap map[string]string, bandwidthMap map[string][]bindwidthMsg, delayMap map[string][]delayMsg) string {
	log.Println(port)
	kind := statusMap[port]
	ansMap := make(map[string]interface{})
	first := true
	//预选阶段，先根据服务实例的响应成功率和特定的阈值去预选一遍当前的服务实例，把能够满足基本要求的服务实例筛选出来
	serviceInstance := data.ServiceInstance
	var Lsip string = data.ServiceInstance[0].Lsip
	for i := 0; i < len(serviceInstance); i++ {
		if serviceInstance[i].SuccessRate >= 0.95 {
			ansMap[serviceInstance[i].Lsip] = 0
			if first {
				Lsip = serviceInstance[i].Lsip
				first = false
			}
		}
	}
	//优选阶段
	switch kind {
	//服务成功率作为过滤条件，然后尽可能选择带宽最大的作为最后的选择结果
	case "Bindwidth sensitive":
		log.Println("This is a bindwidth sensitive service!")
		bindwidthMsgArray := bandwidthMap[port]
		var maxBindWidth float64 = 0
		for i := 0; i < len(bindwidthMsgArray); i++ {
			if _, ok := ansMap[bindwidthMsgArray[i].Lsip]; ok && bindwidthMsgArray[i].Bindwith > maxBindWidth {
				maxBindWidth = bindwidthMsgArray[i].Bindwith
				Lsip = bindwidthMsgArray[i].Lsip
			}
		}

	//服务成功率作为过滤条件，传输时延加上计算时延作为最终的时延敏感型服务的判断标准
	case "Delay sensitive":
		log.Println("This is a delay sensitive service!")
		delayMsgArray := delayMap[port]
		var minDelay float64 = math.MaxFloat64
		for i := 0; i < len(delayMsgArray); i++ {
			if _, ok := ansMap[delayMsgArray[i].Lsip]; ok && delayMsgArray[i].Delay < minDelay {
				minDelay = delayMsgArray[i].Delay
				Lsip = delayMsgArray[i].Lsip
			}
		}
	}
	return Lsip
}
