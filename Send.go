package main

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"log"
	"math/rand"
	"net"
	"strings"
	"time"
)

func SendText(input string) {
	md5Ctx := md5.New()
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{}
	options.ComputeChecksums = true
	SplitedMsgs := make(map[uint]string)
	piece := uint(0)
	for input != "" {
		piece += 1
		if len(input) < 10 {
			SplitedMsgs[piece] = input
			input = ""
		} else {
			thislen := RandInt(1, len(input))
			SplitedMsgs[piece] = input[:thislen]
			input = input[thislen:]
		}
	}

	md5Ctx.Write([]byte(input + time.Now().String()))
	MD5Sum := hex.EncodeToString(md5Ctx.Sum(nil))
	md5Ctx.Reset()
	for thispiece, piecedmsg := range SplitedMsgs {
		var DstIP, SrcIP net.IP
		SrcPort := RandInt(1, 65535)
		DstPort := RandInt(1, 65535)
		switch RandInt(0, 1) {
		case 0:
			if len(Dstv4Map) != 0 {
				DstIP = Dstv4Map[RandInt(0, len(Dstv4Map)-1)]
				SrcIP = Srcv4Map[RandInt(0, len(Srcv4Map)-1)]
			} else {
				DstIP = Dstv6Map[RandInt(0, len(Dstv6Map)-1)]
				SrcIP = Srcv6Map[RandInt(0, len(Srcv6Map)-1)]
			}
		case 1:
			if len(Dstv6Map) != 0 {
				DstIP = Dstv6Map[RandInt(0, len(Dstv6Map)-1)]
				SrcIP = Srcv6Map[RandInt(0, len(Srcv6Map)-1)]
			} else {
				DstIP = Dstv4Map[RandInt(0, len(Dstv4Map)-1)]
				SrcIP = Srcv4Map[RandInt(0, len(Srcv4Map)-1)]
			}
		}
		Packet := Protocol{SrcIP: SrcIP.String(), DstIP: DstIP.String(), MD5Sum: MD5Sum, TotalPiece: piece, PieceNo: thispiece, PieceData: piecedmsg}
		TXJson, err := json.Marshal(Packet)
		if err != nil {
			log.Fatal(err)
		}
		UDPLayer := &layers.UDP{}
		UDPLayer.SrcPort = layers.UDPPort(SrcPort)
		UDPLayer.DstPort = layers.UDPPort(DstPort)
		UDPLayer.Length = uint16(len(TXJson) + 8)
		TXDevice := IPDevice[SrcIP.String()]
		if strings.Contains(DstIP.String(), ".") {
			//EtherNet Layer
			EtherLayer := &layers.Ethernet{}
			EtherLayer.SrcMAC,_ = net.ParseMAC(TXDevice.DeviceMAC)
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
			gopacket.SerializeLayers(buffer, options, EtherLayer,ipv4Layer, UDPLayer, gopacket.Payload(TXJson))
		} else {
			//EtherNet Layer
			EtherLayer := &layers.Ethernet{}
			EtherLayer.SrcMAC,_ = net.ParseMAC(TXDevice.DeviceMAC)
			EtherLayer.DstMAC = net.HardwareAddr{0xBD, 0xBD, 0xBD, 0xBD, 0xBD, 0xBD}
			EtherLayer.EthernetType = layers.EthernetTypeIPv6
			ipv6Layer := &layers.IPv6{}
			ipv6Layer.SrcIP = SrcIP
			ipv6Layer.DstIP = DstIP
			ipv6Layer.Version = uint8(6)
			ipv6Layer.HopLimit = uint8(64)
			ipv6Layer.Length = uint16(UDPLayer.Length)
			ipv6Layer.NextHeader = layers.IPProtocolUDP
			UDPLayer.SetNetworkLayerForChecksum(ipv6Layer)
			gopacket.SerializeLayers(buffer, options,EtherLayer, ipv6Layer, UDPLayer, gopacket.Payload(TXJson))
		}

		log.Println(Packet)
		err=TXDevice.DeviceHandle.WritePacketData(buffer.Bytes())
		if(err!=nil){
			log.Println(err)
		}
	}
}

func RandInt(min, max int) int {
	rand.Seed(time.Now().UnixNano() * rand.Int63n(100))
	return min + rand.Intn(max-min+1)
}
