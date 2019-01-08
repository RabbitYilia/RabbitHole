package main

import (
	"bufio"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"hash"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var IfIPv6Map map[string]string
var IfIPv4Map map[string]string
var IfMacMap map[string]net.HardwareAddr
var IfnameHandle map[string]*pcap.Handle
var Srcv6Map []net.IP
var Srcv4Map []net.IP
var Dstv6Map []net.IP
var Dstv4Map []net.IP
var md5Ctx hash.Hash
var RxPacket chan gopacket.Packet
var TxPacket chan gopacket.Packet
var RunFlag bool
var RunChannel chan int

var PacketBuffer map[string][]string
var PacketTimestamp map[string]string
var PacketCount map[string]int
var PacketTotal map[string]int

func main() {
	RunFlag = true
	Dstv6Map = []net.IP{}
	Dstv4Map = []net.IP{}
	Srcv6Map = []net.IP{}
	Srcv4Map = []net.IP{}
	RxPacket = make(chan gopacket.Packet, 65535)
	TxPacket = make(chan gopacket.Packet, 65535)
	RunChannel = make(chan int, 65535)
	IfIPv6Map = make(map[string]string)
	IfIPv4Map = make(map[string]string)
	IfMacMap = make(map[string]net.HardwareAddr)
	IfnameHandle = make(map[string]*pcap.Handle)
	PacketBuffer = make(map[string][]string)
	PacketTimestamp = make(map[string]string)
	PacketCount = make(map[string]int)
	PacketTotal = make(map[string]int)
	md5Ctx = md5.New()

	SeekInterfaces()
	for _, handle := range IfnameHandle {
		go ListenInterfaces(handle)
	}
	go ProcessRX()
	go CleanBuffer()
	ReadPeer()
	CheckConnection()
	ProcessTX()
	ProgramExit()
}
func ProcessTX() {
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{}
	options.ComputeChecksums = true
	for RunFlag {
		input := GetInput("Msg")
		if input == "" {
			RunFlag = false
			break
		}
		err := buffer.Clear()
		if err != nil {
			log.Fatal(err)
		}

		SplitedMsgs := make(map[string]string)
		piece := 0
		for input != "" {
			piece += 1
			if len(input) < 10 {
				SplitedMsgs[strconv.Itoa(piece)] = input
				input = ""
			} else {
				thislen := RandInt(1, len(input))
				SplitedMsgs[strconv.Itoa(piece)] = input[:thislen]
				input = input[thislen:]
			}
		}

		Timestamp := strconv.FormatInt(time.Now().UnixNano(), 10)
		md5Ctx.Write([]byte(input + time.Now().String()))
		MD5Sum := hex.EncodeToString(md5Ctx.Sum(nil))
		md5Ctx.Reset()

		for thispiece, piecedmsg := range SplitedMsgs {
			var DstIP, SrcIP net.IP
			var TxIface string
			switch RandInt(0, 1) {
			case 0:
				if len(Dstv4Map) != 0 {
					DstIP = Dstv4Map[RandInt(0, len(Dstv4Map)-1)]
					SrcIP = Srcv4Map[RandInt(0, len(Srcv4Map)-1)]
					TxIface = IfIPv4Map[SrcIP.String()]
				} else {
					DstIP = Dstv6Map[RandInt(0, len(Dstv6Map)-1)]
					SrcIP = Srcv6Map[RandInt(0, len(Srcv6Map)-1)]
					TxIface = IfIPv6Map[SrcIP.String()]
				}
			case 1:
				if len(Dstv6Map) != 0 {
					DstIP = Dstv6Map[RandInt(0, len(Dstv6Map)-1)]
					SrcIP = Srcv6Map[RandInt(0, len(Srcv6Map)-1)]
					TxIface = IfIPv6Map[SrcIP.String()]
				} else {
					DstIP = Dstv4Map[RandInt(0, len(Dstv4Map)-1)]
					SrcIP = Srcv4Map[RandInt(0, len(Srcv4Map)-1)]
					TxIface = IfIPv4Map[SrcIP.String()]
				}
			}

			SrcPort := RandInt(1, 65535)
			DstPort := RandInt(1, 65535)

			TXData := make(map[string]string)
			TXData["DstIP"] = DstIP.String()
			TXData["SrcIP"] = SrcIP.String()
			TXData["TTL"] = "10"
			TXData["Piece"] = strconv.Itoa(piece)
			TXData["thisPiece"] = thispiece
			TXData["Timestamp"] = Timestamp
			TXData["MD5sum"] = MD5Sum
			TXData["Piecedmsg"] = piecedmsg
			TXJson, err := json.Marshal(TXData)
			if err != nil {
				log.Fatal(err)
			}

			UDPLayer := &layers.UDP{}
			UDPLayer.SrcPort = layers.UDPPort(SrcPort)
			UDPLayer.DstPort = layers.UDPPort(DstPort)
			UDPLayer.Length = uint16(len(TXJson) + 8)

			if strings.Contains(DstIP.String(), ",") {
				EtherLayer := &layers.Ethernet{}
				EtherLayer.SrcMAC = IfMacMap[TxIface]
				EtherLayer.DstMAC = net.HardwareAddr{0xBD, 0xBD, 0xBD, 0xBD, 0xBD, 0xBD}
				EtherLayer.EthernetType = layers.EthernetTypeIPv4

				ipv4Layer := &layers.IPv4{}
				ipv4Layer.SrcIP = SrcIP
				ipv4Layer.DstIP = DstIP
				ipv4Layer.Version = uint8(4)
				ipv4Layer.TTL = uint8(64)
				ipv4Layer.Checksum = uint16(0)
				ipv4Layer.Protocol = layers.IPProtocolUDP
				ipv4Layer.IHL = uint8(5)
				ipv4Layer.Length = uint16(UDPLayer.Length + 20)
				UDPLayer.SetNetworkLayerForChecksum(ipv4Layer)
				gopacket.SerializeLayers(buffer, options, EtherLayer, ipv4Layer, UDPLayer, gopacket.Payload(TXJson))
			} else {
				EtherLayer := &layers.Ethernet{}
				EtherLayer.SrcMAC = IfMacMap[TxIface]
				EtherLayer.DstMAC = net.HardwareAddr{0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB}
				EtherLayer.EthernetType = layers.EthernetTypeIPv6

				ipv6Layer := &layers.IPv6{}
				ipv6Layer.SrcIP = SrcIP
				ipv6Layer.DstIP = DstIP
				ipv6Layer.Version = uint8(6)
				ipv6Layer.HopLimit = uint8(64)
				ipv6Layer.Length = uint16(UDPLayer.Length)
				ipv6Layer.NextHeader = layers.IPProtocolUDP
				UDPLayer.SetNetworkLayerForChecksum(ipv6Layer)
				gopacket.SerializeLayers(buffer, options, EtherLayer, ipv6Layer, UDPLayer, gopacket.Payload(TXJson))
			}
			err = IfnameHandle[TxIface].WritePacketData(buffer.Bytes())
			if err != nil {
				log.Fatal(err)
			}
		}
	}
}

func CheckConnection() {
	if len(Srcv4Map) == 0 {
		Dstv4Map = []net.IP{}
	}
	if len(Srcv6Map) == 0 {
		Dstv6Map = []net.IP{}
	}
	if len(Dstv4Map) == 0 && len(Dstv6Map) == 0 {
		log.Fatal("No Route to Dst")
	}
}

func ReadPeer() {
	Config := make(map[string]string)
	if FileExists("config.json") {
		contents, err := ioutil.ReadFile("config.json")
		if err != nil {
			log.Fatal(err)
		}
		err = json.Unmarshal(contents, &Config)
		if err != nil {
			log.Fatal(err)
		}
		//NetworkPWD = Config["NetworkPWD"]
		PeerAddrStr := Config["PeerAddr"]
		PeerAddr := strings.Split(PeerAddrStr, ",")
		for _, Addr := range PeerAddr {
			thisIP := net.ParseIP(Addr)
			if strings.Contains(Addr, ".") {
				Dstv4Map = append(Dstv4Map, thisIP)
			} else {
				Dstv6Map = append(Dstv6Map, thisIP)
			}
		}
	} else {
		//NetworkPWD = GetInput("network password")
		//Config["NetworkPWD"] = NetworkPWD
		for {
			Input := GetInput("Dst IP")
			thisIP := net.ParseIP(Input)
			if Input == "" || thisIP == nil {
				break
			}
			Config["PeerAddr"] += Input + ","
			if strings.Contains(Input, ".") {
				Dstv4Map = append(Dstv4Map, thisIP)
			} else {
				Dstv6Map = append(Dstv6Map, thisIP)
			}
		}
		Config["PeerAddr"] = strings.TrimRight(Config["PeerAddr"], ",")
		ConfJson, err := json.Marshal(Config)
		if err != nil {
			log.Fatal(err)
		}
		err = ioutil.WriteFile("config.json", ConfJson, 0644)
		if err != nil {
			log.Fatal(err)
		}
	}

}

func ProcessRX() {
	RunChannel <- 1
	for RunFlag {
		Packet := <-RxPacket
		var SrcIP net.IP
		//var SrcPort, DstPort string
		var LayerAfterNetwork layers.IPProtocol
		var Payload []byte
		NetworkLayer := Packet.NetworkLayer()
		if NetworkLayer == nil {
			continue
		}
		switch NetworkLayer.LayerType() {
		case layers.LayerTypeIPv4:
			IPv4Hdr := NetworkLayer.(*layers.IPv4)
			SrcIP = IPv4Hdr.SrcIP
			//DstIP = IPv4Hdr.DstIP
			LayerAfterNetwork = IPv4Hdr.Protocol
		case layers.LayerTypeIPv6:
			IPv6Hdr := NetworkLayer.(*layers.IPv6)
			SrcIP = IPv6Hdr.SrcIP
			//DstIP = IPv6Hdr.DstIP
			LayerAfterNetwork = IPv6Hdr.NextHeader
		}
		switch LayerAfterNetwork.LayerType() {
		case layers.LayerTypeUDP:
			UDPLayer := Packet.TransportLayer().(*layers.UDP)
			//SrcPort = UDPLayer.SrcPort.String()
			//DstPort = UDPLayer.DstPort.String()
			Payload = UDPLayer.Payload
		case layers.LayerTypeTCP:
			TCPLayer := Packet.TransportLayer().(*layers.TCP)
			//SrcPort = TCPLayer.SrcPort.String()
			//DstPort = TCPLayer.DstPort.String()
			Payload = TCPLayer.Payload
		default:
			continue
		}
		if len(Payload) == 0 {
			continue
		}
		// Ignore packet from myself
		if IfIPv6Map[SrcIP.String()] != "" || IfIPv4Map[SrcIP.String()] != "" {
			continue
		}
		//
		RXdata := make(map[string]string)
		err := json.Unmarshal(Payload, &RXdata)
		if err == nil {
			SrcIP := RXdata["SrcIP"]
			DstIP := RXdata["DstIP"]
			MD5Sum := RXdata["MD5sum"]
			Piece := RXdata["Piece"]
			thispiece := RXdata["thisPiece"]
			Piecedmsg := RXdata["Piecedmsg"]
			packetint, err := strconv.Atoi(thispiece)
			if err != nil {
				continue
			}
			log.Printf("[%s][%s/%s] %s => %s", MD5Sum, thispiece, Piece, SrcIP, DstIP)
			DataBuffer, ok := PacketBuffer[MD5Sum]
			if !ok {
				if PacketCount[MD5Sum] == -1 {
					continue
				}
				PacketTimestamp[MD5Sum] = RXdata["Timestamp"]
				Pieceint, err := strconv.Atoi(Piece)
				if err != nil {
					continue
				}
				PacketBuffer[MD5Sum] = make([]string, Pieceint+1)
				PacketCount[MD5Sum] = 1
				PacketTotal[MD5Sum] = Pieceint
				PacketBuffer[MD5Sum][packetint] = Piecedmsg
				if PacketCount[MD5Sum] == PacketTotal[MD5Sum] {
					DataStr := ""
					for i := 1; i <= PacketTotal[MD5Sum]; i++ {
						DataStr += PacketBuffer[MD5Sum][i]
					}
					log.Printf("[%s][FULL] %s => %s = %s\n", MD5Sum, SrcIP, DstIP, DataStr)
					delete(PacketBuffer, MD5Sum)
					PacketCount[MD5Sum] = -1
					delete(PacketTotal, MD5Sum)
				}
			} else {
				if DataBuffer[packetint] != Piecedmsg {
					DataBuffer[packetint] = Piecedmsg
					PacketCount[MD5Sum] += 1
				}
				if PacketCount[MD5Sum] == PacketTotal[MD5Sum] {
					DataStr := ""
					for i := 1; i <= PacketTotal[MD5Sum]; i++ {
						DataStr += DataBuffer[i]
					}
					log.Printf("[%s][FULL] %s => %s = %s\n", MD5Sum, SrcIP, DstIP, DataStr)
					delete(PacketBuffer, MD5Sum)
					PacketCount[MD5Sum] = -1
					delete(PacketTotal, MD5Sum)
				}
			}
		}
	}
	<-RunChannel
}
func ProgramExit() {
	for RunFlag {
		time.Sleep(30 * time.Second)
	}
	ExitPacket := gopacket.NewPacket([]byte{10, 20, 30}, layers.LayerTypeEthernet, gopacket.Lazy)
	RxPacket <- ExitPacket
	for len(RunChannel) > 1 {
		time.Sleep(30 * time.Second)
	}
	for Ifname, handle := range IfnameHandle {
		delete(IfnameHandle, Ifname)
		handle.Close()
	}
	close(RunChannel)
	close(RxPacket)
}

func ListenInterfaces(handle *pcap.Handle) {
	src := gopacket.NewPacketSource(handle, handle.LinkType()).Packets()
	RunChannel <- 1
	for RunFlag {
		Packet := <-src
		RxPacket <- Packet
	}
	<-RunChannel
	close(src)
}

func SeekInterfaces() {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		log.Fatal(err)
	}

	_, localnet192, _ := net.ParseCIDR("192.168.0.0/16")
	_, localnet172, _ := net.ParseCIDR("172.16.0.0/12")
	_, localnet10, _ := net.ParseCIDR("10.0.0.0/8")

	for _, device := range devices {
		listenFlag := false
		var mac net.HardwareAddr
		for _, address := range device.Addresses {
			if localnet10.Contains(address.IP) || localnet172.Contains(address.IP) || localnet192.Contains(address.IP) {
				continue
			}
			if address.IP.IsLoopback() || !address.IP.IsGlobalUnicast() || address.IP.IsUnspecified() {
				continue
			}
			for _, inter := range interfaces {
				addrs, err := inter.Addrs()
				if err != nil {
					log.Fatal(err)
				}
				for _, addr := range addrs {
					if strings.Split(addr.String(), "/")[0] == address.IP.String() {
						mac = inter.HardwareAddr
					}
				}
			}
			listenFlag = true
			log.Printf("Listen on:%s@%s\n", address.IP.String(), device.Description)
			if strings.Contains(strings.Split(address.IP.String(), "/")[0], ".") {
				IfIPv4Map[address.IP.String()] = device.Name
				Srcv4Map = append(Srcv4Map, address.IP)
			} else {
				IfIPv6Map[address.IP.String()] = device.Name
				Srcv6Map = append(Srcv6Map, address.IP)
			}
		}
		if listenFlag == true {
			handle, err := pcap.OpenLive(device.Name, 65536, true, 30)
			if err != nil {
				log.Fatal(err)
			}
			IfMacMap[device.Name] = mac
			IfnameHandle[device.Name] = handle
		}
	}
}

func FileExists(path string) bool {
	_, err := os.Stat(path)
	if err != nil {
		if os.IsExist(err) {
			return true
		}
		return false
	}
	return true
}

func GetInput(tip string) string {
	for {
		log.Println("Please input " + tip + ":")
		inputReader := bufio.NewReader(os.Stdin)
		input, err := inputReader.ReadString('\n')
		if err != nil {
			log.Fatal(err)
		}
		input = strings.Trim(input, "\n")
		input = strings.Trim(input, "\r")
		if input == "" {
			break
		}
		return input
	}
	return ""
}

func RandInt(min, max int) int {
	rand.Seed(time.Now().UnixNano() * rand.Int63n(100))
	return min + rand.Intn(max-min+1)
}

func CleanBuffer() {
	for {
		TimeOutTime := time.Now().UnixNano() + 10*time.Second.Nanoseconds()
		for MD5Sum, TimestampStr := range PacketTimestamp {
			Timestamp, err := strconv.ParseInt(TimestampStr, 10, 64)
			if err != nil {
				log.Fatal(err)
				delete(PacketTimestamp, MD5Sum)
				delete(PacketCount, MD5Sum)
			}
			if Timestamp < TimeOutTime {
				delete(PacketTimestamp, MD5Sum)
				delete(PacketCount, MD5Sum)
			}
		}
		time.Sleep(10 * time.Second)
	}
}
