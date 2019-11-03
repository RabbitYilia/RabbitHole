package main

import (
	"bufio"
	"github.com/google/gopacket"
	"log"
	"net"
	"os"
	"strings"
)

var Srcv6Map []net.IP
var Srcv4Map []net.IP
var Dstv6Map []net.IP
var Dstv4Map []net.IP

var ListenDev []Device

func main() {
	Init()
	ListenDev = AskListenDevice()
	for devnum, Device := range ListenDev {
		for _, IP := range Device.DeviceIP {
			IPStr := IP.String()
			IPDevice[IPStr] = &ListenDev[devnum]
			if strings.Contains(strings.Split(IPStr, "/")[0], ".") {
				Srcv4Map = append(Srcv4Map, net.ParseIP(strings.Split(IPStr, "/")[0]))
			} else {
				Srcv6Map = append(Srcv6Map, net.ParseIP(strings.Split(IPStr, "/")[0]))
			}
		}
	}
	Setup()
	for DevNum, _ := range ListenDev {
		ListenDev[DevNum].OpenDev()
	}
	for {
		Data := GetInput("MSG")
		if Data == "" {
			break
		}
		SendText(Data)
	}
}

func Init() {
	ProtocolBuffer = make(map[string][]string)
	ProtocolBufferCount = make(map[string]uint)
	IPDevice = make(map[string]*Device)
	PXChan = make(chan gopacket.Packet, 65535)
	go PX()
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
