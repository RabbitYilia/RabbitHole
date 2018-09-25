package main

import (
	"bufio"
	"bytes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"hash"
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
	aead "golang.org/x/crypto/chacha20poly1305"
)

var AddressKey map[string]string
var AddressPoolv6 []string
var AddressPoolv4 []string
var NetworkPWD string
var MyPWD string
var v6only bool
var md5Ctx hash.Hash
var PacketBuffer map[string][]string
var PacketTimestamp map[string]string
var PacketCount map[string]int
var PacketTotal map[string]int

func main() {
	PacketBuffer = make(map[string][]string)
	PacketTimestamp = make(map[string]string)
	PacketCount = make(map[string]int)
	PacketTotal = make(map[string]int)
	md5Ctx = md5.New()
	v6only = false
	AddressKey = make(map[string]string)
	//init Address Pool
	NetworkPWD = "password"
	MyPWD = "password"
	AddMyAddress("dddd:1234:5678::2", NetworkPWD)
	AddMyAddress("dddd:1234:5678::3", NetworkPWD)
	AddMyAddress("dddd:1234:5678::4", NetworkPWD)
	AddMyAddress("dddd:1234:5678::5", NetworkPWD)
	AddMyAddress("192.168.168.2", NetworkPWD)
	AddMyAddress("192.168.168.3", NetworkPWD)
	AddMyAddress("192.168.168.4", NetworkPWD)
	AddMyAddress("192.168.168.5", NetworkPWD)
	handle := IfSelect()

	if v6only {
		filterv6(handle)
	}
	go CleanBuffer()
	go recv(handle)
	dst := GetInput("dstip")
	if dst == "" {
		handle.Close()
		return
	}
	dstkey := GetInput("dstkey")
	if dstkey == "" {
		handle.Close()
		return
	}
	ciper, err := gerateAEAD(dstkey)
	if err != nil {
		log.Fatal(err)
	}
	for {
		SrcIP := ""
		if !v6only {
			for _, IPv4 := range AddressPoolv4 {
				SrcIP += IPv4 + ","
			}
		}
		for _, IPv6 := range AddressPoolv6 {
			SrcIP += IPv6 + ","
		}

		PreSlicedData := ciper.Seal(nil, geratenonce(), []byte(GetInput("data")), nil)
		if len(PreSlicedData) == 0 {
			break
		}
		Timestamp := strconv.FormatInt(time.Now().UnixNano(), 10)
		MD5Sum := GetMD5Str(PreSlicedData)
		TotalPieceInt, SlicedData := SliceData(PreSlicedData)
		TotalPiece := strconv.Itoa(TotalPieceInt)
		for ThisPiece, PiecedMsg := range SlicedData {
			TXdata := make(map[string]string)
			TXdata["TotalPiece"] = TotalPiece
			TXdata["SrcIP"] = SrcIP
			TXdata["ThisPiece"] = ThisPiece
			TXdata["Timestamp"] = Timestamp
			TXdata["MD5Sum"] = MD5Sum
			TXdata["PiecedMsg"] = PiecedMsg
			TXdata["DstIP"] = dst
			TXdata["TTL"] = strconv.Itoa(RandInt(1, 10))
			TXHandleDirectly(handle, TXdata["DstIP"], TXdata)
		}
	}
	defer handle.Close()
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
func TXHandleDirectly(handle *pcap.Handle, dstliststr string, TXdata map[string]string) {
	ciper, err := gerateAEAD(NetworkPWD)
	if err != nil {
		log.Fatal(err)
	}
	TXdata["TTL"] = "1"
	SendJson, err := json.Marshal(TXdata)
	if err != nil {
		log.Fatal(err)
	}
	SendJson = ciper.Seal(nil, geratenonce(), SendJson, nil)
	dstlist := strings.Split(dstliststr, ",")
	dst := dstlist[RandInt(0, len(dstlist)-1)]
	var outgoingPacket []byte
	if IsIPv6Addr(dst) {
		if len(AddressPoolv6) < 1 {
			log.Println("No V6 addr to use,ignore.")
			return
		}
		srcAddr := AddressPoolv6[RandInt(0, len(AddressPoolv6)-1)]
		outgoingPacket = MakePacketv6(SendJson, srcAddr, dst)
	} else {
		if len(AddressPoolv4) < 1 {
			log.Println("No V4 addr to use,ignore.")
			return
		}
		srcAddr := AddressPoolv4[RandInt(0, len(AddressPoolv4)-1)]
		outgoingPacket = MakePacketv4(SendJson, srcAddr, dst)
	}
	err = handle.WritePacketData(outgoingPacket)
	if err != nil {
		log.Fatal(err)
	}

}

func recv(handle *pcap.Handle) {
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	RXdata := make(map[string]string)
	var Payload []byte
	ciper, err := gerateAEAD(NetworkPWD)
	if err != nil {
		log.Fatal(err)
	}
	for packet := range packetSource.Packets() {
		ipv6Layer := packet.Layer(layers.LayerTypeIPv6)
		if ipv6Layer != nil {
			ipv6, _ := ipv6Layer.(*layers.IPv6)
			_, ok := AddressKey[ipv6.DstIP.String()]
			if !ok {
				//Not Mine
			} else {
				Payload = ipv6Layer.LayerPayload()[8:]
				log.Printf("From %s to %s\n", ipv6.SrcIP, ipv6.DstIP)
			}
		}
		ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
		if ipv4Layer != nil {
			ipv4, _ := ipv4Layer.(*layers.IPv4)
			_, ok := AddressKey[ipv4.DstIP.String()]
			if !ok {
				//Not Mine
			} else {
				Payload = ipv4Layer.LayerPayload()[8:]
				log.Printf("From %s to %s\n", ipv4.SrcIP, ipv4.DstIP)
			}
		}
		Payload, err = ciper.Open(nil, geratenonce(), Payload, nil)
		if err != nil {
			return
		}
		err := json.Unmarshal(Payload, &RXdata)
		if err != nil {
			continue
		}
		if RXdata["TTL"] == "1" {
			ProcessRXData(RXdata)
		}
	}
}
func ProcessRXData(RXdata map[string]string) {
	PacketCountInt, ok := PacketCount[RXdata["MD5Sum"]]
	if ok && PacketCountInt == -1 {
		//ignore unexpect packet
		return
	}
	ciper, err := gerateAEAD(MyPWD)
	if err != nil {
		return
	}
	DataBuffer, ok := PacketBuffer[RXdata["MD5Sum"]]
	if !ok {
		PacketTimestamp[RXdata["MD5Sum"]] = RXdata["Timestamp"]
		thistotal, err := strconv.Atoi(RXdata["TotalPiece"])
		if err != nil {
			return
		}
		packetint, err := strconv.Atoi(RXdata["ThisPiece"])
		if err != nil {
			return
		}

		var thisbuffer []string
		thisbuffer = make([]string, thistotal+1)
		PacketBuffer[RXdata["MD5Sum"]] = thisbuffer
		PacketCount[RXdata["MD5Sum"]] = 1
		PacketTotal[RXdata["MD5Sum"]] = thistotal
		PacketBuffer[RXdata["MD5Sum"]][packetint] = RXdata["PiecedMsg"]
		if PacketCount[RXdata["MD5Sum"]] == PacketTotal[RXdata["MD5Sum"]] {
			DataStr := ""
			for i := 1; i <= PacketTotal[RXdata["MD5Sum"]]; i++ {
				DataStr += PacketBuffer[RXdata["MD5Sum"]][i]
			}
			ByteData, err := hex.DecodeString(DataStr)
			if err != nil {
				return
			}
			ByteData, err = ciper.Open(nil, geratenonce(), ByteData, nil)
			if err != nil {
				return
			}
			log.Println("Msg-From:" + RXdata["SrcIP"])
			log.Println(string(ByteData))
			delete(PacketBuffer, RXdata["MD5Sum"])
			PacketCount[RXdata["MD5Sum"]] = -1
			delete(PacketTotal, RXdata["MD5Sum"])
		}
	} else {
		PacketInt, err := strconv.Atoi(RXdata["ThisPiece"])
		if err != nil {
			return
		}
		DataBuffer[PacketInt] = RXdata["PiecedMsg"]
		PacketCount[RXdata["MD5Sum"]] += 1
		if PacketCount[RXdata["MD5Sum"]] == PacketTotal[RXdata["MD5Sum"]] {
			DataStr := ""
			for i := 1; i <= PacketTotal[RXdata["MD5Sum"]]; i++ {
				DataStr += PacketBuffer[RXdata["MD5Sum"]][i]
			}
			ByteData, err := hex.DecodeString(DataStr)
			if err != nil {
				return
			}
			ByteData, err = ciper.Open(nil, geratenonce(), ByteData, nil)
			if err != nil {
				return
			}
			log.Println("Msg-From:" + RXdata["SrcIP"])
			log.Println(string(ByteData))
			delete(PacketBuffer, RXdata["MD5Sum"])
			PacketCount[RXdata["MD5Sum"]] = -1
			delete(PacketTotal, RXdata["MD5Sum"])
		}
	}
}
func GetMD5Str(data []byte) string {
	md5Ctx.Reset()
	md5Ctx.Write(data)
	return hex.EncodeToString(md5Ctx.Sum(nil))
}

func SliceData(data []byte) (int, map[string]string) {
	TotalPiece := 0
	DataStr := hex.EncodeToString(data)
	SplitedMsgs := make(map[string]string)
	for {
		TotalPiece += 1
		if len(DataStr) < 10 {
			SplitedMsgs[strconv.Itoa(TotalPiece)] = DataStr
			break
		}
		ThisLen := RandInt(1, len(DataStr))
		SplitedMsgs[strconv.Itoa(TotalPiece)] = DataStr[:ThisLen]
		DataStr = DataStr[ThisLen:]
	}
	return TotalPiece, SplitedMsgs
}

func MakePacketv4(data []byte, SrcIPv4 string, DstIPv4 string) []byte {
	var options gopacket.SerializeOptions
	SrcPort := RandInt(1, 65535)
	DstPort := RandInt(1, 65535)
	buffer := gopacket.NewSerializeBuffer()
	//IPv4 Layer
	ipv4Layer := &layers.IPv4{}
	ipv4Layer.SrcIP = net.ParseIP(SrcIPv4)
	ipv4Layer.DstIP = net.ParseIP(DstIPv4)
	ipv4Layer.Version = uint8(4)
	ipv4Layer.TTL = uint8(64)
	ipv4Layer.Checksum = uint16(0)
	//ipv4Layer. = uint16(len(data) + 8)
	ipv4Layer.Protocol = layers.IPProtocolUDP
	ipv4Layer.IHL = uint8(5)
	ipv4Layer.Length = uint16(len(data) + 28)
	v4buffer := gopacket.NewSerializeBuffer()
	ipv4Layer.SerializeTo(v4buffer, options)
	v4package := v4buffer.Bytes()
	ipv4Layer.Checksum = checkSum(v4package[:20])
	//EtherNet Layer
	EtherLayer := &layers.Ethernet{}
	EtherLayer.SrcMAC = net.HardwareAddr{0x00, 0xAA, 0xFA, 0xAA, 0xFF, 0xAA}
	EtherLayer.DstMAC = net.HardwareAddr{0xBD, 0xBD, 0xBD, 0xBD, 0xBD, 0xBD}
	EtherLayer.EthernetType = layers.EthernetTypeIPv4
	//UDP Layer
	UDPLayer := &layers.UDP{}
	UDPLayer.SrcPort = layers.UDPPort(SrcPort)
	UDPLayer.DstPort = layers.UDPPort(DstPort)
	UDPLayer.Length = uint16(len(data))
	FakeHeader := makeUDPFakeHeader(SrcIPv4, DstIPv4, ipv4Layer.Length, SrcPort, DstPort, UDPLayer.Length)
	FakeHeaderbyte, err := hex.DecodeString(FakeHeader)
	if err != nil {
		log.Fatal(err)
	}
	UDPLayer.Checksum = checkSum(FakeHeaderbyte)
	gopacket.SerializeLayers(buffer, options, EtherLayer, ipv4Layer, UDPLayer, gopacket.Payload(data))
	outgoingPacket := buffer.Bytes()
	return outgoingPacket
}

func MakePacketv6(data []byte, SrcIPv6 string, DstIPv6 string) []byte {
	var options gopacket.SerializeOptions
	SrcPort := RandInt(1, 65535)
	DstPort := RandInt(1, 65535)
	buffer := gopacket.NewSerializeBuffer()
	//IPv6 Layer
	ipv6Layer := &layers.IPv6{}
	ipv6Layer.SrcIP = net.ParseIP(SrcIPv6)
	ipv6Layer.DstIP = net.ParseIP(DstIPv6)
	ipv6Layer.Version = uint8(6)
	ipv6Layer.HopLimit = uint8(64)
	ipv6Layer.Length = uint16(len(data) + 8)
	ipv6Layer.NextHeader = layers.IPProtocolUDP
	//EtherNet Layer
	EtherLayer := &layers.Ethernet{}
	EtherLayer.SrcMAC = net.HardwareAddr{0x00, 0xAA, 0xFA, 0xAA, 0xFF, 0xAA}
	EtherLayer.DstMAC = net.HardwareAddr{0xBD, 0xBD, 0xBD, 0xBD, 0xBD, 0xBD}
	EtherLayer.EthernetType = layers.EthernetTypeIPv6
	//UDP Layer
	UDPLayer := &layers.UDP{}
	UDPLayer.SrcPort = layers.UDPPort(SrcPort)
	UDPLayer.DstPort = layers.UDPPort(DstPort)
	UDPLayer.Length = uint16(len(data))
	FakeHeader := makeUDPFakeHeader(SrcIPv6, DstIPv6, ipv6Layer.Length, SrcPort, DstPort, UDPLayer.Length)
	FakeHeaderbyte, err := hex.DecodeString(FakeHeader)
	if err != nil {
		log.Fatal(err)
	}
	UDPLayer.Checksum = checkSum(FakeHeaderbyte)
	gopacket.SerializeLayers(buffer, options, EtherLayer, ipv6Layer, UDPLayer, gopacket.Payload(data))
	outgoingPacket := buffer.Bytes()
	return outgoingPacket
}

func RandInt(min, max int) int {
	rand.Seed(time.Now().UnixNano() * rand.Int63n(100))
	return min + rand.Intn(max-min+1)
}

func makeUDPFakeHeader(SrcIP string, DstIP string, iplen uint16, SrcPort int, DstPort int, udplen uint16) string {
	UDPFakeHeader := ""
	FakeUDPSrc, err := net.ParseIP(SrcIP).MarshalText()
	if err != nil {
		log.Fatal(err)
	}
	FakeUDPDst, err := net.ParseIP(DstIP).MarshalText()
	if err != nil {
		log.Fatal(err)
	}
	var convbuffer bytes.Buffer
	err = binary.Write(&convbuffer, binary.BigEndian, uint8(0))
	if err != nil {
		log.Fatal(err)
	}
	UDPFakeHeader += hex.EncodeToString(FakeUDPSrc)
	UDPFakeHeader += hex.EncodeToString(FakeUDPDst)
	UDPFakeHeader += hex.EncodeToString(convbuffer.Bytes())
	convbuffer.Reset()
	err = binary.Write(&convbuffer, binary.LittleEndian, uint8(17))
	if err != nil {
		log.Fatal(err)
	}
	UDPFakeHeader += hex.EncodeToString(convbuffer.Bytes())
	convbuffer.Reset()
	err = binary.Write(&convbuffer, binary.LittleEndian, iplen)
	if err != nil {
		log.Fatal(err)
	}
	UDPFakeHeader += hex.EncodeToString(convbuffer.Bytes())
	convbuffer.Reset()
	err = binary.Write(&convbuffer, binary.LittleEndian, uint16(SrcPort))
	if err != nil {
		log.Fatal(err)
	}
	UDPFakeHeader += hex.EncodeToString(convbuffer.Bytes())
	convbuffer.Reset()
	err = binary.Write(&convbuffer, binary.LittleEndian, uint16(DstPort))
	if err != nil {
		log.Fatal(err)
	}
	UDPFakeHeader += hex.EncodeToString(convbuffer.Bytes())
	convbuffer.Reset()
	err = binary.Write(&convbuffer, binary.LittleEndian, udplen)
	if err != nil {
		log.Fatal(err)
	}
	UDPFakeHeader += hex.EncodeToString(convbuffer.Bytes())
	convbuffer.Reset()
	err = binary.Write(&convbuffer, binary.LittleEndian, uint16(0))
	if err != nil {
		log.Fatal(err)
	}
	UDPFakeHeader += hex.EncodeToString(convbuffer.Bytes())
	convbuffer.Reset()
	return UDPFakeHeader
}

func checkSum(msg []byte) uint16 {
	sum := 0
	for n := 1; n < len(msg)-1; n += 2 {
		sum += int(msg[n])*256 + int(msg[n+1])
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum += (sum >> 16)
	var ans = uint16(^sum)
	return ans
}

func AddMyAddress(addr string, key string) {
	if IsIPv6Addr(addr) {
		AddressPoolv6 = append(AddressPoolv6, addr)
		AddressKey[addr] = key
	} else {
		AddressPoolv4 = append(AddressPoolv4, addr)
		AddressKey[addr] = key
	}
}

func IsIPv6Addr(address string) bool {
	return strings.Count(address, ":") >= 2
}

func IfSelect() *pcap.Handle {
	// Find all devices
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	ifmap := make(map[string]string)
	devmap := make(map[string]pcap.Interface)
	num := 1
	log.Println("Interface Found:")
	for _, device := range devices {
		log.Println(strconv.Itoa(num) + "-" + device.Description)
		ifmap[strconv.Itoa(num)] = device.Name
		devmap[device.Name] = device
		num += 1
	}
	//Select Listen Interface
	var selectediface string
	for {
		log.Println("Please Select Interface Number:")
		inputReader := bufio.NewReader(os.Stdin)
		input, err := inputReader.ReadString('\n')
		input = strings.Trim(input, "\n")
		input = strings.Trim(input, "\r")
		if err != nil {
			log.Fatal(err)
		}
		ifname, ok := ifmap[input]
		if !ok {
			continue
		} else {
			selectediface = ifname
			break
		}
	}

	//Add Listen Addr
	ifaceaddr := devmap[selectediface].Addresses
	for addr := range ifaceaddr {
		thisaddr := ifaceaddr[addr].IP.String()
		if !IsIPv6Addr(thisaddr) && v6only {
			continue
		}
		AddMyAddress(thisaddr, NetworkPWD)
		log.Println("Listen on :" + thisaddr)
	}

	handle, err := pcap.OpenLive(selectediface, 40960, true, time.Millisecond)
	if err != nil {
		log.Fatal(err)
	}
	return handle
}

func filterv6(handle *pcap.Handle) {
	err := handle.SetBPFFilter("ip6")
	if err != nil {
		log.Fatal(err)
	}
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

func gerateAEAD(password string) (AEAD cipher.AEAD, err error) {
	hash := sha256.New()
	hash.Write([]byte(password))
	return aead.New(hash.Sum(nil))
}

func geratenonce() []byte {
	hash := sha256.New()
	hash.Write([]byte(strconv.Itoa(int(time.Now().Unix()/300) * 300)))
	return hash.Sum(nil)[:12]
}
